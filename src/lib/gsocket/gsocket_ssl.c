/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "smartdns/lib/gsocket.h"
#include "smartdns/lib/hashtable.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

/* QUIC SSL object types */
enum ssl_type {
	SSL_TYPE_NORMAL = 0,      /* Regular TLS */
	SSL_TYPE_QUIC_LISTENER,   /* QUIC listener */
	SSL_TYPE_QUIC_CONNECTION, /* QUIC connection */
	SSL_TYPE_QUIC_STREAM      /* QUIC stream */
};

struct ssl_io_ctx {
	SSL_CTX *ssl_ctx; /* Shared Context */
	SSL *ssl;         /* Connection Instance */
	int is_server;
	enum ssl_type ssl_type;    /* Type of SSL object for QUIC */
	struct gsocket_io *io_ptr; /* Back pointer to self for BIO */
	unsigned char *spki_hash;
	size_t spki_len;
	int reuse_session;
	char *cached_host;
	int cached_port;
	int enable_0rtt;
	int early_data_sent;
	int anti_replay;
	unsigned char *alpn_protos;
	size_t alpn_protos_len;

	/* Error Reporting */
	unsigned long last_error_code; /* OpenSSL error code */
	char error_msg[256];           /* Human-readable error message */
};

/* Session Cache Entry */
struct gsocket_ssl_session {
	char *key;
	SSL_SESSION *session;
	struct hlist_node node;
	struct list_head lru_node;
};

struct gsocket_ssl_ctx_cache {
	struct hash_table ht;
	struct list_head lru_list;
	unsigned int current_size;
	unsigned int max_size;
	pthread_mutex_t lock;
};

static void _free_session_cache(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	struct gsocket_ssl_ctx_cache *cache = (struct gsocket_ssl_ctx_cache *)ptr;
	if (!cache) {
		return;
	}

	int i;
	struct gsocket_ssl_session *sess;
	struct hlist_node *tmp;

	pthread_mutex_lock(&cache->lock);
	hash_table_for_each_safe(cache->ht, i, tmp, sess, node)
	{
		hash_del(&sess->node);
		list_del(&sess->lru_node);
		SSL_SESSION_free(sess->session);
		free(sess->key);
		free(sess);
	}
	hash_table_free(cache->ht, free);
	pthread_mutex_unlock(&cache->lock);
	pthread_mutex_destroy(&cache->lock);
	free(cache);
}

static int _gs_session_cache_idx = -1;
static void _init_gs_session_cache_idx(void)
{
	_gs_session_cache_idx = SSL_CTX_get_ex_new_index(0, "gsocket_session_cache", NULL, NULL, _free_session_cache);
}

static int _get_gs_ex_index(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;
	pthread_once(&once, _init_gs_session_cache_idx);
	return _gs_session_cache_idx;
}

static struct gsocket_ssl_ctx_cache *_get_session_cache(SSL_CTX *ctx)
{
	int idx = _get_gs_ex_index();
	struct gsocket_ssl_ctx_cache *cache = (struct gsocket_ssl_ctx_cache *)SSL_CTX_get_ex_data(ctx, idx);
	if (!cache) {
		cache = calloc(1, sizeof(struct gsocket_ssl_ctx_cache));
		if (!cache) {
			return NULL;
		}
		hash_table_init(cache->ht, 7); /* 128 buckets */
		INIT_LIST_HEAD(&cache->lru_list);
		cache->max_size = 100; /* Default size limit */
		pthread_mutex_init(&cache->lock, NULL);
		if (SSL_CTX_set_ex_data(ctx, idx, cache) == 0) {
			/* Failed to set ex_data, OpenSSL doesn't have a way to report error here easily
			   without freeing cache. */
			_free_session_cache(NULL, cache, NULL, idx, 0, NULL);
			return NULL;
		}
	}
	return cache;
}

static SSL_SESSION *_session_cache_get(SSL_CTX *ctx, const char *key)
{
	struct gsocket_ssl_ctx_cache *cache = _get_session_cache(ctx);
	if (!cache) {
		return NULL;
	}
	uint32_t h = hash_string(key);
	struct gsocket_ssl_session *sess;
	SSL_SESSION *s = NULL;

	pthread_mutex_lock(&cache->lock);
	hash_table_for_each_possible(cache->ht, sess, node, h)
	{
		if (strcmp(sess->key, key) == 0) {
			SSL_SESSION_up_ref(sess->session);
			s = sess->session;
			/* Move to MRU position */
			list_move(&sess->lru_node, &cache->lru_list);
			break;
		}
	}
	pthread_mutex_unlock(&cache->lock);
	return s;
}

static void _session_cache_set(SSL_CTX *ctx, const char *key, SSL_SESSION *session)
{
	if (!session) {
		return;
	}
	struct gsocket_ssl_ctx_cache *cache = _get_session_cache(ctx);
	if (!cache) {
		return;
	}
	uint32_t h = hash_string(key);
	struct gsocket_ssl_session *sess;

	pthread_mutex_lock(&cache->lock);
	hash_table_for_each_possible(cache->ht, sess, node, h)
	{
		if (strcmp(sess->key, key) == 0) {
			SSL_SESSION_free(sess->session);
			sess->session = session;
			/* Move to MRU position */
			list_move(&sess->lru_node, &cache->lru_list);
			pthread_mutex_unlock(&cache->lock);
			return;
		}
	}

	/* Check size limit and evict LRU if needed */
	if (cache->max_size > 0 && cache->current_size >= cache->max_size) {
		struct gsocket_ssl_session *oldest = list_last_entry(&cache->lru_list, struct gsocket_ssl_session, lru_node);
		hash_del(&oldest->node);
		list_del(&oldest->lru_node);
		SSL_SESSION_free(oldest->session);
		free(oldest->key);
		free(oldest);
		cache->current_size--;
	}

	sess = calloc(1, sizeof(struct gsocket_ssl_session));
	if (!sess) {
		goto err;
	}
	sess->key = strdup(key);
	if (!sess->key) {
		goto err;
	}
	sess->session = session;
	hash_table_add(cache->ht, &sess->node, h);
	list_add(&sess->lru_node, &cache->lru_list);
	cache->current_size++;
	pthread_mutex_unlock(&cache->lock);
	return;

err:
	if (sess) {
		free(sess);
	}
	pthread_mutex_unlock(&cache->lock);
}

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
/* QUIC BIO data structure to track peer address */
struct bio_quic_data {
	struct gsocket_io *io;
	int is_server;
	struct sockaddr_storage peer;
	socklen_t peer_len;
};
#endif

/* Custom BIO to bridge OpenSSL -> GSocket Lower Layer */
static int _bio_gs_write(BIO *b, const char *buf, int len)
{
	struct gsocket_io *io = BIO_get_data(b);
	if (!io || !io->lower || !io->lower->send) {
		return -1;
	}

	int ret = io->lower->send(io->lower, buf, len, MSG_NOSIGNAL);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		BIO_set_retry_write(b);
	}
	return ret;
}

static int _bio_gs_read(BIO *b, char *buf, int len)
{
	struct gsocket_io *io = BIO_get_data(b);
	if (!io || !io->lower || !io->lower->recv) {
		return -1;
	}

	int ret = io->lower->recv(io->lower, buf, len, 0);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		BIO_set_retry_read(b);
	} else if (ret == 0) {
		/* EOF - connection closed, don't set retry */
		BIO_clear_retry_flags(b);
	}
	return ret;
}

static long _bio_gs_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	/* Minimal implementation */
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	default:
		return 0;
	}
}

static int _bio_gs_create(BIO *b)
{
	BIO_set_init(b, 1);
	return 1;
}

static int _bio_gs_destroy(BIO *b)
{
	return 1;
}

/* Define Generic Method */
static BIO_METHOD *_gs_bio_method = NULL;
static pthread_once_t _gs_bio_once = PTHREAD_ONCE_INIT;

static void _init_gs_bio_method(void)
{
	_gs_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | 0x80, "gsocket_bio");
	BIO_meth_set_write(_gs_bio_method, _bio_gs_write);
	BIO_meth_set_read(_gs_bio_method, _bio_gs_read);
	BIO_meth_set_ctrl(_gs_bio_method, _bio_gs_ctrl);
	BIO_meth_set_create(_gs_bio_method, _bio_gs_create);
	BIO_meth_set_destroy(_gs_bio_method, _bio_gs_destroy);
}

__attribute__((destructor)) static void _cleanup_gs_bio_method(void)
{
	if (_gs_bio_method) {
		BIO_meth_free(_gs_bio_method);
		_gs_bio_method = NULL;
	}
}

static BIO_METHOD *get_gs_bio_method(void)
{
	pthread_once(&_gs_bio_once, _init_gs_bio_method);
	return _gs_bio_method;
}

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
static BIO_METHOD *_gs_quic_bio_method = NULL;
static pthread_once_t _gs_quic_bio_once = PTHREAD_ONCE_INIT;

/* Helper functions for send/recv */
static inline ssize_t _bio_quic_send_one(struct bio_quic_data *data, const void *buf, size_t len, BIO_ADDR *peer)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;

	if (peer) {
		if (BIO_ADDR_family(peer) == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
			sin->sin_family = AF_INET;
			sin->sin_port = htons(BIO_ADDR_rawport(peer));
			size_t l = sizeof(sin->sin_addr);
			BIO_ADDR_rawaddress(peer, &sin->sin_addr, &l);
			salen = sizeof(struct sockaddr_in);
			sa = (struct sockaddr *)sin;
		} else if (BIO_ADDR_family(peer) == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(BIO_ADDR_rawport(peer));
			size_t l = sizeof(sin6->sin6_addr);
			BIO_ADDR_rawaddress(peer, &sin6->sin6_addr, &l);
			salen = sizeof(struct sockaddr_in6);
			sa = (struct sockaddr *)sin6;
		}
	} else if (data->is_server) {
		sa = (struct sockaddr *)&data->peer;
		salen = data->peer_len;
	}

	if (data->is_server) {
		if (!data->io->lower->sendto) {
			return -1;
		}
		if (sa) {
			return data->io->lower->sendto(data->io->lower, buf, len, 0, sa, salen);
		} else {
			/* No address? */
			return -1;
		}
	} else {
		if (!data->io->lower->send) {
			return -1;
		}
		return data->io->lower->send(data->io->lower, buf, len, 0);
	}
}

static inline ssize_t _bio_quic_recv_one(struct bio_quic_data *data, void *buf, size_t len, BIO_ADDR *peer)
{
	ssize_t ret;

	/* Use recvfrom if available to get peer address (needed for both server and client) */
	if (data->io->lower->recvfrom) {
		data->peer_len = sizeof(data->peer);
		ret = data->io->lower->recvfrom(data->io->lower, buf, len, 0, (struct sockaddr *)&data->peer, &data->peer_len);

		/* Set peer address in BIO_MSG for OpenSSL */
		if (ret > 0 && peer) {
			BIO_ADDR_clear(peer);
			if (data->peer.ss_family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)&data->peer;
				BIO_ADDR_rawmake(peer, AF_INET, &sin->sin_addr, sizeof(sin->sin_addr), ntohs(sin->sin_port));
			} else if (data->peer.ss_family == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&data->peer;
				BIO_ADDR_rawmake(peer, AF_INET6, &sin6->sin6_addr, sizeof(sin6->sin6_addr), ntohs(sin6->sin6_port));
			}
		}
	} else if (data->io->lower->recv) {
		ret = data->io->lower->recv(data->io->lower, buf, len, 0);
	} else {

		return -1;
	}
	return ret;
}

static int _bio_gs_quic_write(BIO *b, const char *buf, int len)
{
	struct bio_quic_data *data = (struct bio_quic_data *)BIO_get_data(b);
	if (!data || !data->io || !data->io->lower) {
		return -1;
	}

	int ret = _bio_quic_send_one(data, buf, len, NULL);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		BIO_set_retry_write(b);
	}
	return ret;
}

static int _bio_gs_quic_read(BIO *b, char *buf, int len)
{
	struct bio_quic_data *data = (struct bio_quic_data *)BIO_get_data(b);
	if (!data || !data->io || !data->io->lower) {
		return -1;
	}

	int ret = _bio_quic_recv_one(data, buf, len, NULL);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		BIO_set_retry_read(b);
	}
	return ret;
}

static int _bio_gs_sendmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags,
							size_t *msgs_processed);
static int _bio_gs_recvmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags,
							size_t *msgs_processed);
static long _bio_gs_ctrl_dgram(BIO *b, int cmd, long num, void *ptr);
static int _bio_gs_quic_destroy(BIO *b);

static void _init_gs_quic_bio_method(void)
{
	_gs_quic_bio_method = BIO_meth_new(BIO_TYPE_DGRAM, "gsocket_quic_bio");
	if (!_gs_quic_bio_method) {
		return;
	}
	BIO_meth_set_write(_gs_quic_bio_method, _bio_gs_quic_write);
	BIO_meth_set_read(_gs_quic_bio_method, _bio_gs_quic_read);
	BIO_meth_set_sendmmsg(_gs_quic_bio_method, _bio_gs_sendmmsg);
	BIO_meth_set_recvmmsg(_gs_quic_bio_method, _bio_gs_recvmmsg);
	BIO_meth_set_ctrl(_gs_quic_bio_method, _bio_gs_ctrl_dgram);
	BIO_meth_set_create(_gs_quic_bio_method, _bio_gs_create);
	BIO_meth_set_destroy(_gs_quic_bio_method, _bio_gs_quic_destroy);
}

__attribute__((destructor)) static void _cleanup_gs_quic_bio_method(void)
{
	if (_gs_quic_bio_method) {
		BIO_meth_free(_gs_quic_bio_method);
		_gs_quic_bio_method = NULL;
	}
}

static BIO_METHOD *get_gs_quic_bio_method(void)
{
	pthread_once(&_gs_quic_bio_once, _init_gs_quic_bio_method);
	return _gs_quic_bio_method;
}

static int _bio_gs_sendmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags, size_t *msgs_processed)
{
	struct bio_quic_data *data = (struct bio_quic_data *)BIO_get_data(b);
	if (!data || !data->io || !data->io->lower) {
		return 0;
	}

	size_t processed = 0;
	int total_len = 0;
	for (size_t i = 0; i < num_msg; i++) {
		BIO_MSG *m = &msg[i];
		ssize_t ret = _bio_quic_send_one(data, m->data, m->data_len, m->peer);

		if (ret < 0) {
			if (processed == 0) {
				total_len = 0;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* OpenSSL expects 1 (success) if we simply have no buffer space but didn't error */
				if (processed == 0) {
					*msgs_processed = 0;
					return 1;
				}
				break;
			}
			ERR_raise(ERR_LIB_SYS, errno);
			return 0;
		}

		total_len += ret;
		processed++;
	}

	*msgs_processed = processed;
	return total_len;
}

static int _bio_gs_recvmmsg(BIO *b, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags, size_t *msgs_processed)
{

	struct bio_quic_data *data = (struct bio_quic_data *)BIO_get_data(b);
	if (!data || !data->io || !data->io->lower) {
		return 0;
	}

	size_t processed = 0;
	int total_len = 0;
	for (size_t i = 0; i < num_msg; i++) {
		BIO_MSG *m = &msg[i];
		ssize_t ret = _bio_quic_recv_one(data, m->data, m->data_len, m->peer);
		if (ret < 0) {
			if (processed == 0) {
				// ERR_raise(ERR_LIB_SYS, errno); // Don't raise error for EAGAIN
				total_len = 0;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* OpenSSL expects 1 (success) if we simply have no data but didn't error */
				if (processed == 0) {

					*msgs_processed = 0;
					return 1;
				}
				break;
			}
			return 0;
		}

		m->data_len = ret;
		total_len += ret;
		processed++;
	}

	*msgs_processed = processed;
	return total_len; // Can be 0 if nothing processed
}

static long _bio_gs_ctrl_dgram(BIO *b, int cmd, long num, void *ptr)
{
	struct bio_quic_data *data = (struct bio_quic_data *)BIO_get_data(b);

	switch (cmd) {
	case BIO_CTRL_DGRAM_GET_MTU:
	case BIO_CTRL_DGRAM_QUERY_MTU:
	case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
		return 1200;
	case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
		return 28; // IPv4(20) + UDP(8)
	case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
		return 1;
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_CTRL_DGRAM_SET_CONNECTED:
		if (ptr != NULL) {
			// data->connected = 1;
			/* ptr is expected to be BIO_ADDR* usually used by OpenSSL DGRAM */
			// BIO_ADDR_copy(data->peer, (BIO_ADDR *)ptr);
			// We need to convert BIO_ADDR to sockaddr_storage
			if (BIO_ADDR_family((BIO_ADDR *)ptr) == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)&data->peer;
				sin->sin_family = AF_INET;
				sin->sin_port = htons(BIO_ADDR_rawport((BIO_ADDR *)ptr));
				size_t l = sizeof(sin->sin_addr);
				BIO_ADDR_rawaddress((BIO_ADDR *)ptr, &sin->sin_addr, &l);
			} else if (BIO_ADDR_family((BIO_ADDR *)ptr) == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&data->peer;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = htons(BIO_ADDR_rawport((BIO_ADDR *)ptr));
				size_t l = sizeof(sin6->sin6_addr);
				BIO_ADDR_rawaddress((BIO_ADDR *)ptr, &sin6->sin6_addr, &l);
			}
		} else {
			// data->connected = 0;
			memset(&data->peer, 0, sizeof(data->peer));
		}
		return 1;
	case BIO_CTRL_DGRAM_SET_PEER:
		if (ptr) {
			if (BIO_ADDR_family((BIO_ADDR *)ptr) == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)&data->peer;
				sin->sin_family = AF_INET;
				sin->sin_port = htons(BIO_ADDR_rawport((BIO_ADDR *)ptr));
				size_t l = 0;
				BIO_ADDR_rawaddress((BIO_ADDR *)ptr, &sin->sin_addr, &l);
			} else if (BIO_ADDR_family((BIO_ADDR *)ptr) == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&data->peer;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = htons(BIO_ADDR_rawport((BIO_ADDR *)ptr));
				size_t l = 0;
				BIO_ADDR_rawaddress((BIO_ADDR *)ptr, &sin6->sin6_addr, &l);
			}
		}
		return 1;
	case BIO_CTRL_DGRAM_GET_PEER:
		if (data && ptr) {
			BIO_ADDR *peer = (BIO_ADDR *)ptr;
			BIO_ADDR_clear(peer);
			if (data->peer.ss_family == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)&data->peer;
				BIO_ADDR_rawmake(peer, AF_INET, &sin->sin_addr, sizeof(sin->sin_addr), ntohs(sin->sin_port));
			} else if (data->peer.ss_family == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&data->peer;
				BIO_ADDR_rawmake(peer, AF_INET6, &sin6->sin6_addr, sizeof(sin6->sin6_addr), ntohs(sin6->sin6_port));
			}
			return 1;
		}
		return 0;
	default:
		return 0;
	}
}

static int _bio_gs_quic_destroy(BIO *b)
{
	struct bio_quic_data *data = (struct bio_quic_data *)BIO_get_data(b);
	if (data) {
		free(data);
	}
	return 1;
}
#endif

/* SSL Layer Impl */

static int _ssl_check_spki(struct ssl_io_ctx *ctx)
{
	if (ctx->spki_hash == NULL || ctx->spki_len == 0) {
		return 0; // No check needed
	}

	X509 *cert = SSL_get_peer_certificate(ctx->ssl);
	if (!cert) {
		return -1; // No cert to verify?
	}

	/* Extract Public Key */
	X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(cert);
	if (!pubkey) {
		X509_free(cert);
		return -1;
	}

	unsigned char *p = NULL;
	int len = i2d_X509_PUBKEY(pubkey, &p);
	if (len <= 0 || !p) {
		X509_free(cert);
		return -1;
	}

	/* Calculate SHA256 of SPKI */
	unsigned char hash[SHA256_DIGEST_LENGTH];
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, p, len);
	EVP_DigestFinal_ex(mdctx, hash, NULL);
	EVP_MD_CTX_free(mdctx);
#else
	SHA256((unsigned char *)p, len, hash);
#endif
	OPENSSL_free(p);
	X509_free(cert);

	/* Compare with expected */
	if (ctx->spki_len == SHA256_DIGEST_LENGTH) {
		if (memcmp(ctx->spki_hash, hash, SHA256_DIGEST_LENGTH) == 0) {
			return 0;
		}
	}

	return -1;
}

static int _ssl_listen(struct gsocket_io *io, int backlog)
{
	struct ssl_io_ctx *ctx = io->ctx;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
		/* QUIC listener doesn't need a real listen() on the FD if it's UDP,
		   but we need to CALL SSL_listen to activate the listener state. */
		if (!SSL_listen(ctx->ssl)) {
			return -1;
		}
		return 0;
	}
#endif
	if (io->lower && io->lower->listen) {
		return io->lower->listen(io->lower, backlog);
	}
	return -1;
}

static int _ssl_handshake(struct gsocket_io *io)
{
	struct ssl_io_ctx *ctx = io->ctx;

	if (io->lower && io->lower->handshake) {
		int res = io->lower->handshake(io->lower);
		if (res != GSOCKET_HANDSHAKE_DONE) {
			return res;
		}
	}
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
		/* For QUIC Listener, handshake is always "done" - it just waits for connections */
		if (ctx->ssl_type == SSL_TYPE_QUIC_LISTENER) {
			return GSOCKET_HANDSHAKE_DONE;
		}

		/* For QUIC connections/streams, drive the event loop */
		SSL_handle_events(ctx->ssl);

		if (SSL_is_init_finished(ctx->ssl)) {
			return GSOCKET_HANDSHAKE_DONE;
		}
		if (SSL_get_accept_stream_queue_len(ctx->ssl) > 0) {
			return GSOCKET_HANDSHAKE_DONE;
		}
	}
#endif

	int ret = SSL_do_handshake(ctx->ssl);
	if (ret == 1) {
		/* Handshake Done - Perform SPKI Check if needed */
		if (_ssl_check_spki(ctx) != 0) {
			/* Verification Failed */
			return GSOCKET_HANDSHAKE_ERR;
		}
		if (ctx->reuse_session && ctx->cached_host && !SSL_session_reused(ctx->ssl)) {
			char key[2048];
			snprintf(key, sizeof(key), "%s:%d", ctx->cached_host, ctx->cached_port);
			_session_cache_set(ctx->ssl_ctx, key, SSL_get1_session(ctx->ssl));
		}
		return GSOCKET_HANDSHAKE_DONE;
	}

	int err = SSL_get_error(ctx->ssl, ret);
	if (err == SSL_ERROR_WANT_READ) {
		return GSOCKET_HANDSHAKE_WANT_READ;
	} else if (err == SSL_ERROR_WANT_WRITE) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	/* Log error if desired */
	unsigned long last_err = ERR_get_error();

	/* Store error code and message */
	ctx->last_error_code = last_err;
	if (last_err != 0) {
		ERR_error_string_n(last_err, ctx->error_msg, sizeof(ctx->error_msg) - 1);
	} else if (err == SSL_ERROR_SYSCALL) {
		if (errno != 0) {
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "syscall error: %s", strerror(errno));
		} else if (ret == 0) {
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "unexpected EOF (connection reset by peer)");
		} else {
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "unknown syscall error");
		}
	} else if (err == SSL_ERROR_SSL) {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "SSL protocol error");
	} else if (err == SSL_ERROR_ZERO_RETURN) {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "SSL connection closed cleanly");
	} else {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "SSL error code: %d", err);
	}
	ctx->error_msg[sizeof(ctx->error_msg) - 1] = '\0';

	/* Map OpenSSL error to errno */
	if (err == SSL_ERROR_SYSCALL) {
		/* errno is already set by the system call */
		if (errno == 0 && ret == 0) {
			errno = ECONNRESET; /* Unexpected EOF */
		}
	} else if (err == SSL_ERROR_SSL) {
		errno = EPROTO; /* Protocol error */
	} else {
		errno = EIO; /* General I/O error */
	}

	return GSOCKET_HANDSHAKE_ERR;
}

static ssize_t _ssl_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct ssl_io_ctx *ctx = io->ctx;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
		SSL_handle_events(ctx->ssl);
	}
#endif
	size_t readbytes = 0;
	int ret;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	int is_quic = 0;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl_type != SSL_TYPE_NORMAL) {
		is_quic = 1;
	}
#endif
	if (!is_quic && ctx->is_server && !SSL_is_init_finished(ctx->ssl)) {
		ret = SSL_read_early_data(ctx->ssl, buf, len, &readbytes);
		if (ret == SSL_READ_EARLY_DATA_SUCCESS) {
			return (ssize_t)readbytes;
		}
		/* If it's FINISH or ERROR, we fall through to normal read which will finish handshake */
	}
#endif

	ret = SSL_read_ex(ctx->ssl, buf, len, &readbytes);
	if (ret > 0) {
		return (ssize_t)readbytes;
	}

	int err = SSL_get_error(ctx->ssl, ret);
	if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
		errno = EAGAIN;
		return -1;
	}
	if (err == SSL_ERROR_ZERO_RETURN) {
		errno = EPIPE;
		return 0; // EOF
	}
	if (err == SSL_ERROR_SYSCALL) {
		if (errno == 0) {
			errno = EIO;
		}
	} else if (err == SSL_ERROR_SSL) {
		errno = EPROTO;
	} else {
		errno = EIO;
	}
	return -1;
}

static ssize_t _ssl_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct ssl_io_ctx *ctx = io->ctx;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
		SSL_handle_events(ctx->ssl);
	}
#endif
	int is_quic = 0;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl_type != SSL_TYPE_NORMAL) {
		is_quic = 1;
	}
#endif

	size_t written = 0;
	uint64_t ssl_flags = 0;
#ifdef SSL_WRITE_FLAG_CONCLUDE
	if (is_quic && (flags & GS_MSG_FIN)) {
		ssl_flags |= SSL_WRITE_FLAG_CONCLUDE;
	}
#endif

	int ret;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	if (!is_quic && ctx->enable_0rtt && !ctx->early_data_sent && !SSL_is_init_finished(ctx->ssl)) {
		ret = SSL_write_early_data(ctx->ssl, buf, len, &written);
		if (ret == 1) {
			ctx->early_data_sent = 1;
			return (ssize_t)written;
		}
		int err = SSL_get_error(ctx->ssl, ret);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		}
	}
#endif

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ssl_flags) {
		ret = SSL_write_ex2(ctx->ssl, buf, len, ssl_flags, &written);
	} else {
		ret = SSL_write_ex(ctx->ssl, buf, len, &written);
	}
#else
	ret = SSL_write_ex(ctx->ssl, buf, len, &written);
#endif

	if (ret > 0) {
		return (ssize_t)written;
	}

	int err = SSL_get_error(ctx->ssl, ret);
	switch (err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		break;
	case SSL_ERROR_SYSCALL:
		if (errno == 0) {
			errno = EIO;
		}
		break;
	case SSL_ERROR_ZERO_RETURN:
		errno = EPIPE;
		break;
	case SSL_ERROR_SSL:
		errno = EPROTO;
		break;
	default:
		errno = EIO;
		break;
	}
	return -1;
}

static ssize_t _ssl_recvfrom(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
							 socklen_t *addrlen)
{
	ssize_t ret = _ssl_recv(io, buf, len, flags);
	if (ret >= 0 && src_addr && addrlen) {
		if (io->lower && io->lower->getpeername) {
			io->lower->getpeername(io->lower, src_addr, addrlen);
		}
	}
	return ret;
}

static ssize_t _ssl_sendto(struct gsocket_io *io, const void *buf, size_t len, int flags,
						   const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return _ssl_send(io, buf, len, flags);
}

static ssize_t _ssl_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct ssl_io_ctx *ctx = io->ctx;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
		SSL_handle_events(ctx->ssl);
	}
#endif
	size_t total_read = 0;
	for (int i = 0; i < (int)msg->msg_iovlen; i++) {
		size_t readbytes = 0;
		int ret = SSL_read_ex(ctx->ssl, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, &readbytes);
		if (ret > 0) {
			total_read += readbytes;
			if (readbytes < msg->msg_iov[i].iov_len) {
				break;
			}
		} else {
			if (total_read > 0) {
				return total_read;
			}
			int err = SSL_get_error(ctx->ssl, ret);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				errno = EAGAIN;
			} else if (err == SSL_ERROR_ZERO_RETURN) {
				return 0;
			}
			return -1;
		}
	}
	return total_read;
}

static ssize_t _ssl_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	struct ssl_io_ctx *ctx = io->ctx;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
		SSL_handle_events(ctx->ssl);
	}
#endif
	size_t total_written = 0;
	uint64_t ssl_flags = 0;
#ifdef SSL_WRITE_FLAG_CONCLUDE
	if (flags & GS_MSG_FIN) {
		ssl_flags |= SSL_WRITE_FLAG_CONCLUDE;
	}
#endif

	for (int i = 0; i < (int)msg->msg_iovlen; i++) {
		size_t written = 0;
		int ret;

		uint64_t current_flags = (i == (int)msg->msg_iovlen - 1) ? ssl_flags : 0;

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
		if (current_flags) {
			ret = SSL_write_ex2(ctx->ssl, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, current_flags, &written);
		} else {
			ret = SSL_write_ex(ctx->ssl, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, &written);
		}
#else
		ret = SSL_write_ex(ctx->ssl, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, &written);
#endif

		if (ret > 0) {
			total_written += written;
			if (written < msg->msg_iov[i].iov_len) {
				break;
			}
		} else {
			if (total_written > 0) {
				return total_written;
			}
			int err = SSL_get_error(ctx->ssl, ret);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				errno = EAGAIN;
			}
			return -1;
		}
	}
	return total_written;
}

/* Pass-through control functions */
static int _ssl_close(struct gsocket_io *io)
{
	struct ssl_io_ctx *ctx = io->ctx;
	/* For QUIC stream/connection, don't call SSL_shutdown as it may trigger network I/O
	   which requires access to lower layer that may not be available during cleanup */
	if (ctx->ssl_type != SSL_TYPE_QUIC_STREAM && ctx->ssl_type != SSL_TYPE_QUIC_CONNECTION) {
		SSL_shutdown(ctx->ssl);
	}
	/* Only close lower for Listener and traditional TLS, not for QUIC connection/stream */
	if (io->lower && io->lower->close) {
		if (ctx->ssl_type == SSL_TYPE_QUIC_LISTENER || ctx->ssl_type == SSL_TYPE_NORMAL) {
			io->lower->close(io->lower);
		}
	}
	return 0;
}

static void _ssl_free(struct gsocket_io *io)
{
	struct ssl_io_ctx *ctx = io->ctx;
	SSL_free(ctx->ssl);
	if (ctx->cached_host) {
		free(ctx->cached_host);
	}
	if (ctx->spki_hash) {
		free(ctx->spki_hash);
	}
	if (ctx->alpn_protos) {
		free(ctx->alpn_protos);
	}
	/* Don't free ctx->ssl_ctx, it's shared/owned by user */
	/* Don't free io->lower - gsocket_free() will traverse and free all layers automatically */
	free(ctx);
	free(io);
}

static int _ssl_connect(struct gsocket_io *io, const char *host, int port)
{
	struct ssl_io_ctx *ctx = io->ctx;
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	if (ctx && ctx->ssl && SSL_is_quic(ctx->ssl) && !ctx->is_server) {
		/* Set explicit auto-stream mode */
		SSL_set_default_stream_mode(ctx->ssl, SSL_DEFAULT_STREAM_MODE_NONE);
	}
#endif

	/* Set SNI if host is not an IP */
	struct sockaddr_storage tmp_addr;
	struct sockaddr_in *addr4 = (struct sockaddr_in *)&tmp_addr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&tmp_addr;

	if (host && host[0] && inet_pton(AF_INET, host, &addr4->sin_addr) != 1 &&
		inet_pton(AF_INET6, host, &addr6->sin6_addr) != 1) {
		SSL_set_tlsext_host_name(ctx->ssl, host);
	}

	if (io->lower && io->lower->connect) {
		int ret = io->lower->connect(io->lower, host, port);
		if (ret == 0 && ctx->reuse_session && host && host[0]) {
			char *new_host = strdup(host);
			if (new_host) {
				if (ctx->cached_host) {
					free(ctx->cached_host);
				}
				ctx->cached_host = new_host;
				ctx->cached_port = port;
				char key[512];
				snprintf(key, sizeof(key), "%s:%d", host, port);
				SSL_SESSION *s = _session_cache_get(ctx->ssl_ctx, key);
				if (s) {
					SSL_set_session(ctx->ssl, s);
					SSL_SESSION_free(s);
				}
			}
		}
		return ret;
	}
	return 0;
}

static int _ssl_get_fd(struct gsocket_io *io)
{
	if (io->lower && io->lower->get_fd) {
		return io->lower->get_fd(io->lower);
	}
	return -1;
}

static int _ssl_parse_alpn_protos(const char *protos, size_t protos_len, unsigned char **out, size_t *outlen)
{
	if (protos_len == 0) {
		return -1;
	}

	/* Max length estimate */
	unsigned char *buf = malloc(protos_len + 10);
	if (!buf) {
		return -1;
	}

	unsigned char *p = buf;
	const char *start = protos;
	const char *end = protos + protos_len;

	while (start < end) {
		const char *sep = memchr(start, ',', end - start);
		const char *token_end = sep ? sep : end;
		size_t token_len = token_end - start;

		if (token_len > 255) {
			free(buf);
			return -1;
		}

		*p++ = (unsigned char)token_len;
		memcpy(p, start, token_len);
		p += token_len;

		if (sep) {
			start = sep + 1;
		} else {
			break;
		}
	}

	*out = buf;
	*outlen = p - buf;
	return 0;
}

static int _ssl_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
							   unsigned int inlen, void *arg)
{
	struct gsocket_io *io = (struct gsocket_io *)SSL_get_app_data(ssl);
	if (!io || !io->ctx) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	struct ssl_io_ctx *ctx = io->ctx;
	if (ctx->alpn_protos && ctx->alpn_protos_len > 0) {
		int ret =
			SSL_select_next_proto((unsigned char **)out, outlen, ctx->alpn_protos, ctx->alpn_protos_len, in, inlen);
		if (ret != OPENSSL_NPN_NEGOTIATED) {
			return SSL_TLSEXT_ERR_NOACK;
		}
		return SSL_TLSEXT_ERR_OK;
	}

	return SSL_TLSEXT_ERR_NOACK;
}

static int _ssl_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	struct ssl_io_ctx *ctx = io->ctx;
	if (level == SOL_SSL) {
		switch (optname) {
		case SO_SSL_SNI:
			if (optval && optlen > 0) {
				// Ensure null termination or copy
				char *host = (char *)malloc(optlen + 1);
				if (!host) {
					return -1;
				}
				memcpy(host, optval, optlen);
				host[optlen] = 0;
				SSL_set_tlsext_host_name(ctx->ssl, host);
				free(host);
				return 0;
			}
			break;
		case SO_SSL_VERIFY:
			if (optlen >= sizeof(int)) {
				int verify_mode = *(int *)optval;
				if (verify_mode) {
					SSL_set_verify(ctx->ssl, SSL_VERIFY_PEER, NULL);
				} else {
					SSL_set_verify(ctx->ssl, SSL_VERIFY_NONE, NULL);
				}
				return 0;
			}
			break;
		case SO_SSL_SPKI:
			if (optval && optlen > 0) {
				unsigned char *new_spki = (unsigned char *)malloc(optlen);
				if (!new_spki) {
					return -1;
				}
				if (ctx->spki_hash) {
					free(ctx->spki_hash);
				}
				ctx->spki_hash = new_spki;
				memcpy(ctx->spki_hash, optval, optlen);
				ctx->spki_len = optlen;
				return 0;
			}
			break;
		case SO_SSL_ALPN:
			/* User provides ALPN in string format "h2,http/1.1" */
			if (optval && optlen > 0) {
				unsigned char *protos = NULL;
				size_t protos_len = 0;
				if (_ssl_parse_alpn_protos((const char *)optval, optlen, &protos, &protos_len) != 0) {
					return -1;
				}

				if (ctx->is_server) {
					if (ctx->alpn_protos) {
						free(ctx->alpn_protos);
					}
					ctx->alpn_protos = protos;
					ctx->alpn_protos_len = protos_len;
					SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx, _ssl_alpn_select_cb, NULL);

					/* Workaround removed: SSL re-creation is dangerous and unnecessary if callback is in CTX */

				} else {
					if (SSL_set_alpn_protos(ctx->ssl, protos, protos_len) != 0) { // 0 is success
						free(protos);
						return -1;
					}
					free(protos);
				}
				return 0;
			}
			break;
		case SO_SSL_VERIFY_HOSTNAME:
		case SO_SSL_ADD_VERIFY_HOSTNAME:
			if (optval && optlen > 0) {
				// Ensure null termination or copy
				char *host = (char *)malloc(optlen + 1);
				if (!host) {
					return -1;
				}
				memcpy(host, optval, optlen);
				host[optlen] = 0;

				// Enable Hostname/IP Verification
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
				struct sockaddr_in sa4;
				struct sockaddr_in6 sa6;
				X509_VERIFY_PARAM *param = SSL_get0_param(ctx->ssl);

				if (inet_pton(AF_INET, host, &sa4.sin_addr) == 1) {
					X509_VERIFY_PARAM_set1_ip(param, (unsigned char *)&sa4.sin_addr, sizeof(sa4.sin_addr));
				} else if (inet_pton(AF_INET6, host, &sa6.sin6_addr) == 1) {
					X509_VERIFY_PARAM_set1_ip(param, (unsigned char *)&sa6.sin6_addr, sizeof(sa6.sin6_addr));
				} else {
					X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
					if (optname == SO_SSL_VERIFY_HOSTNAME) {
						X509_VERIFY_PARAM_set1_host(param, host, 0);
					} else {
						X509_VERIFY_PARAM_add1_host(param, host, 0);
					}
				}
#endif

				free(host);
				return 0;
			}
			break;
		case SO_SSL_SESSION:
			if (optval && optlen == sizeof(void *)) {
				SSL_set_session(ctx->ssl, *(SSL_SESSION **)optval);
				return 0;
			}
			break;
		case SO_SSL_SESSION_REUSE:
			if (optlen >= sizeof(int)) {
				ctx->reuse_session = *(int *)optval;
				return 0;
			}
			break;
		case SO_SSL_SESSION_CACHE_SIZE:
			if (optlen >= sizeof(int)) {
				struct gsocket_ssl_ctx_cache *cache = _get_session_cache(ctx->ssl_ctx);
				pthread_mutex_lock(&cache->lock);
				cache->max_size = *(int *)optval;
				while (cache->max_size > 0 && cache->current_size > cache->max_size) {
					struct gsocket_ssl_session *oldest =
						list_last_entry(&cache->lru_list, struct gsocket_ssl_session, lru_node);
					hash_del(&oldest->node);
					list_del(&oldest->lru_node);
					SSL_SESSION_free(oldest->session);
					free(oldest->key);
					free(oldest);
					cache->current_size--;
				}
				pthread_mutex_unlock(&cache->lock);
				return 0;
			}
			break;
		case SO_SSL_0RTT:
			if (optlen >= sizeof(int)) {
				ctx->enable_0rtt = *(int *)optval;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
				if (ctx->is_server) {
					/* On server side, we must enable it on CTX */
					SSL_CTX_set_max_early_data(ctx->ssl_ctx, 16384);
				}
#endif
				return 0;
			}
			break;
		case SO_SSL_0RTT_ANTI_REPLAY:
			if (optlen >= sizeof(int)) {
				ctx->anti_replay = *(int *)optval;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
				if (!ctx->anti_replay) {
					SSL_set_options(ctx->ssl, SSL_OP_NO_ANTI_REPLAY);
				} else {
					SSL_clear_options(ctx->ssl, SSL_OP_NO_ANTI_REPLAY);
				}
#endif
				return 0;
			}
			break;
		default:
			break;
		}
		return -1;
	}

	if (io->lower && io->lower->setsockopt) {
		return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}

static int _ssl_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct ssl_io_ctx *ctx = io->ctx;
	if (level == SOL_SSL) {
		switch (optname) {
		case SO_SSL_GET_SESSION:
			if (optval && optlen && *optlen >= sizeof(void *)) {
				*(SSL_SESSION **)optval = SSL_get1_session(ctx->ssl);
				*optlen = sizeof(void *);
				return 0;
			}
			break;
		case SO_SSL_SESSION_CACHE_SIZE:
			if (optval && optlen && *optlen >= sizeof(int)) {
				struct gsocket_ssl_ctx_cache *cache = _get_session_cache(ctx->ssl_ctx);
				pthread_mutex_lock(&cache->lock);
				*(int *)optval = cache->max_size;
				pthread_mutex_unlock(&cache->lock);
				*optlen = sizeof(int);
				return 0;
			}
			break;
		case SO_SSL_0RTT:
			if (optval && optlen && *optlen >= sizeof(int)) {
				*(int *)optval = ctx->enable_0rtt;
				*optlen = sizeof(int);
				return 0;
			}
			break;
		case SO_SSL_0RTT_ANTI_REPLAY:
			if (optval && optlen && *optlen >= sizeof(int)) {
				*(int *)optval = ctx->anti_replay;
				*optlen = sizeof(int);
				return 0;
			}
			break;
		case SO_SSL_ALPN:
			if (optval && optlen && *optlen > 0) {
				const unsigned char *data = NULL;
				unsigned int len = 0;
				SSL_get0_alpn_selected(ctx->ssl, &data, &len);
				if (data && len > 0) {
					if (*optlen > len) {
						memcpy(optval, data, len);
						((char *)optval)[len] = 0;
						*optlen = len;
					} else {
						memcpy(optval, data, *optlen - 1);
						((char *)optval)[*optlen - 1] = 0;
					}
					return 0;
				}
				*optlen = 0;
				return 0;
			}
			break;
		default:
			break;
		}
		return -1;
	}

	if (io->lower && io->lower->getsockopt) {
		return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}

static int _ssl_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (io->lower && io->lower->getsockname) {
		return io->lower->getsockname(io->lower, addr, len);
	}
	return -1;
}

static int _ssl_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (io->lower && io->lower->getpeername) {
		return io->lower->getpeername(io->lower, addr, len);
	}
	return -1;
}

/* Helper Constructor */
/* QUIC Support Macros */
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
#define HAS_QUIC 1
#endif

/* Forward declaration of private helper */
static struct gsocket_io *gsocket_io_ssl_create_internal(SSL *ssl, int is_server, int owns_ssl);

static struct gsocket_io *_ssl_open_stream(struct gsocket_io *io)
{
#ifdef HAS_QUIC
	struct ssl_io_ctx *ctx = io->ctx;
	if (!ctx || !ctx->ssl) {
		return NULL;
	}

	/* OpenSSL QUIC: Create new stream from connection SSL */
	SSL *stream_ssl = SSL_new_stream(ctx->ssl, 0);
	if (!stream_ssl) {
		return NULL;
	}

	struct gsocket_io *stream_io = gsocket_io_ssl_create_internal(stream_ssl, ctx->is_server, 1);
	if (!stream_io) {
		SSL_free(stream_ssl);
		return NULL;
	}

	if (stream_io && stream_io->ctx) {
		((struct ssl_io_ctx *)stream_io->ctx)->ssl_type = SSL_TYPE_QUIC_STREAM;
		/* Stream doesn't need lower - all I/O via QUIC engine */
	}

	return stream_io;
#else
	return NULL;
#endif
}

static int _ssl_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms)
{
#ifdef HAS_QUIC
	if (count <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Build SSL_POLL_ITEM array on heap to avoid stack overflow */
	SSL_POLL_ITEM *ssl_items = calloc(count, sizeof(SSL_POLL_ITEM));
	if (!ssl_items) {
		errno = ENOMEM;
		return -1;
	}

	/* Prepare poll items */
	struct ssl_io_ctx *io_ctx = io->ctx;

	/* For QUIC, call SSL_handle_events first to process any pending network I/O */
	if (io_ctx && io_ctx->ssl && SSL_is_quic(io_ctx->ssl)) {
		SSL_handle_events(io_ctx->ssl);
	}

	for (int i = 0; i < count; i++) {
		if (items[i].stream) {
			struct gsocket_io *layer = gsocket_get_top_layer(items[i].stream);
			struct ssl_io_ctx *ctx = NULL;
			while (layer) {
				if (layer->stream_poll == _ssl_stream_poll) {
					ctx = layer->ctx;
					break;
				}
				layer = layer->lower;
			}

			if (ctx) {
				if (ctx->ssl) {
					ssl_items[i].desc = SSL_as_poll_descriptor(ctx->ssl);
					ssl_items[i].events = 0;

					/* Check if we have buffered data (decrypted) ready to read */
					if (SSL_pending(ctx->ssl) > 0) {
						/* Force readable so we don't sleep in poll */
						ssl_items[i].events |= SSL_POLL_EVENT_R;
					}

					/* For QUIC listener, monitor for new connection arrivals */
					if (ctx->ssl_type == SSL_TYPE_QUIC_LISTENER) {
						/* Monitor for incoming connection events */
						if (items[i].events & EPOLLIN) {
							ssl_items[i].events |= SSL_POLL_EVENT_IC; /* Incoming Connection */
						}
					}
					/* For QUIC connection itself (not a stream), monitor for new stream arrivals */
					else if (ctx->ssl_type == SSL_TYPE_QUIC_CONNECTION && io_ctx && ctx->ssl == io_ctx->ssl) {
						/* Monitor for incoming stream events */
						if (items[i].events & EPOLLIN) {
							ssl_items[i].events |= SSL_POLL_EVENT_ISB; /* Incoming Stream Bidirectional */
						}
					} else {
						/* For streams, monitor normal read/write */
						if (items[i].events & EPOLLIN) {
							ssl_items[i].events |= SSL_POLL_EVENT_R;
						}
						if (items[i].events & EPOLLOUT) {
							ssl_items[i].events |= SSL_POLL_EVENT_W;
						}
					}
				}
			}
		}
		items[i].revents = 0;
	}

	/* Call SSL_poll with timeout */
	struct timeval tv = {0, 0};
	struct timeval *tvp = NULL;
	if (timeout_ms >= 0) {
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;
		tvp = &tv;
	}

	size_t result_count = 0;
	int ret = SSL_poll(ssl_items, count, sizeof(SSL_POLL_ITEM), tvp, 0, &result_count);
	/* Convert results */
	if (ret >= 0) {
		for (int i = 0; i < count; i++) {
			int has_pending = 0;
			struct gsocket_io *layer = items[i].stream ? gsocket_get_top_layer(items[i].stream) : NULL;
			struct ssl_io_ctx *ctx = NULL;
			while (layer) {
				if (layer->stream_poll == _ssl_stream_poll) {
					ctx = layer->ctx;
					break;
				}
				layer = layer->lower;
			}

			if (ctx) {
				/* Drive the event loop for this connection/stream */
				if (ctx->ssl && SSL_is_quic(ctx->ssl)) {
					SSL_handle_events(ctx->ssl);
				}

				if (ctx->ssl) {
					/* Check data pending */
					if (SSL_pending(ctx->ssl) > 0) {
						has_pending = 1; /* Note: manual intervention to prevent blocked reads */
					}
					/* Check new streams pending (for connection object) */
					if (ctx->ssl_type == SSL_TYPE_QUIC_CONNECTION) {
						if (SSL_get_accept_stream_queue_len(ctx->ssl) > 0) {
							has_pending = 1;
						}
					}
				}
			}

			if ((ssl_items[i].revents & SSL_POLL_EVENT_R) || has_pending) {
				items[i].revents |= EPOLLIN;
			}
			if (ssl_items[i].revents & SSL_POLL_EVENT_W) {
				items[i].revents |= EPOLLOUT;
			}
			/* New connection arrival on listener */
			if (ssl_items[i].revents & SSL_POLL_EVENT_IC) {
				items[i].revents |= EPOLLIN; /* Signal as readable for accept */
			}
			/* New stream arrival on connection */
			if (ssl_items[i].revents & SSL_POLL_EVENT_ISB) {
				items[i].revents |= EPOLLIN; /* Signal as readable for accept */
			}
			/* Exceptions or Errors */
			if (ssl_items[i].revents & (SSL_POLL_EVENT_F | SSL_POLL_EVENT_ISU)) {
				items[i].revents |= EPOLLERR;
			}

			/* If we manually resolved EPOLLIN/EPOLLOUT during mapping despite ret=0, guarantee > 0 ret */
			if (items[i].revents && ret == 0) {
				ret = 1;
			}
		}
	}

	free(ssl_items);
	return ret;
#else
	errno = ENOTSUP;
	return -1;
#endif
}

/* Helper Constructor */
static struct gsocket_io *_ssl_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	struct ssl_io_ctx *ctx = io->ctx;
	if (ctx && ctx->is_server && ctx->ssl && SSL_is_quic(ctx->ssl)) {
		/* Drive the QUIC engine */
		SSL_handle_events(ctx->ssl);

		SSL *new_ssl = NULL;

		/* Accept based on SSL object type */
		if (ctx->ssl_type == SSL_TYPE_QUIC_LISTENER) {
			/* Listener can only accept connections */
			new_ssl = SSL_accept_connection(ctx->ssl, 0);
			if (new_ssl) {
				/* Set non-blocking mode for the connection */
				SSL_set_blocking_mode(new_ssl, 0);
				/* Create IO wrapper for the connection */
				struct gsocket_io *conn_io = gsocket_io_ssl_create_internal(new_ssl, 1, 1);
				if (conn_io && conn_io->ctx) {
					((struct ssl_io_ctx *)conn_io->ctx)->ssl_type = SSL_TYPE_QUIC_CONNECTION;
					/* Inherit ALPN config from listener */
					if (ctx->alpn_protos) {
						((struct ssl_io_ctx *)conn_io->ctx)->alpn_protos = malloc(ctx->alpn_protos_len);
						memcpy(((struct ssl_io_ctx *)conn_io->ctx)->alpn_protos, ctx->alpn_protos,
							   ctx->alpn_protos_len);
						((struct ssl_io_ctx *)conn_io->ctx)->alpn_protos_len = ctx->alpn_protos_len;
					}

					/* NOTE: Don't set conn_io->lower - QUIC connections don't need it.
					   All I/O is handled by OpenSSL QUIC engine. Setting it causes double-free. */

					/* Automatically enable multi-stream mode for QUIC */
					SSL_set_default_stream_mode(new_ssl, SSL_DEFAULT_STREAM_MODE_NONE);
				}
				return conn_io;
			}
		} else if (ctx->ssl_type == SSL_TYPE_QUIC_CONNECTION) {
			/* Connection can accept streams */
			new_ssl = SSL_accept_stream(ctx->ssl, 0);
			if (new_ssl) {
				/* Create IO wrapper for the stream */
				struct gsocket_io *stream_io = gsocket_io_ssl_create_internal(new_ssl, 1, 1);
				if (stream_io && stream_io->ctx) {
					((struct ssl_io_ctx *)stream_io->ctx)->ssl_type = SSL_TYPE_QUIC_STREAM;
					/* Stream doesn't need lower - all I/O via QUIC engine */
				}
				return stream_io;
			}
		}

		/* If no new object, return NULL with EAGAIN */
		errno = EAGAIN;
		return NULL;
	}
#endif

	if (!io->lower || !io->lower->accept) {
		return NULL;
	}

	struct gsocket_io *client_lower = io->lower->accept(io->lower, addr, addrlen);
	if (!client_lower) {
		return NULL;
	}

#if !defined(OSSL_QUIC1_VERSION) || defined(OPENSSL_NO_QUIC)
	struct ssl_io_ctx *ctx = io->ctx;
#endif
	if (!ctx || !ctx->ssl_ctx) {
		if (client_lower->free) {
			client_lower->free(client_lower);
		}
		return NULL;
	}

	struct gsocket_io *client_ssl_io = gsocket_io_ssl_new(ctx->ssl_ctx, 1);
	if (!client_ssl_io) {
		if (client_lower->free) {
			client_lower->free(client_lower);
		}
		return NULL;
	}

	client_ssl_io->lower = client_lower;

	// Inheritance: Copy configuration from parent context
	if (client_ssl_io->ctx && ctx) {
		struct ssl_io_ctx *new_ctx = client_ssl_io->ctx;
		new_ctx->reuse_session = ctx->reuse_session;
		new_ctx->enable_0rtt = ctx->enable_0rtt;

		if (ctx->alpn_protos) {
			new_ctx->alpn_protos = malloc(ctx->alpn_protos_len);
			if (new_ctx->alpn_protos) {
				memcpy(new_ctx->alpn_protos, ctx->alpn_protos, ctx->alpn_protos_len);
				new_ctx->alpn_protos_len = ctx->alpn_protos_len;
			}
		}

		if (ctx->spki_hash) {
			new_ctx->spki_hash = malloc(ctx->spki_len);
			if (new_ctx->spki_hash) {
				memcpy(new_ctx->spki_hash, ctx->spki_hash, ctx->spki_len);
				new_ctx->spki_len = ctx->spki_len;
			}
		}
	}

	return client_ssl_io;
}

static int _ssl_get_poll_events(struct gsocket_io *io)
{
#ifdef HAS_QUIC
	struct ssl_io_ctx *ctx = io->ctx;
	if (!ctx || !ctx->ssl) {
		return EPOLLIN;
	}

	/* Only for QUIC connections/listeners, check what network I/O is needed */
	if (SSL_is_quic(ctx->ssl)) {
		int events = 0;
		if (SSL_net_read_desired(ctx->ssl)) {
			events |= EPOLLIN;
		}
		if (SSL_net_write_desired(ctx->ssl)) {
			events |= EPOLLOUT;
		}
		return events ? events : (int)EPOLLIN;
	}
#endif
	return (int)EPOLLIN; /* For non-QUIC, always monitor read */
}

static int _ssl_get_error(struct gsocket_io *io, void *err_struct)
{
	struct ssl_io_ctx *ctx = (struct ssl_io_ctx *)io->ctx;
	struct gsocket_error *err = (struct gsocket_error *)err_struct;

	err->layer = SOL_SSL;
	err->error_code = (int)ctx->last_error_code;
	err->errno_val = errno;
	strncpy(err->message, ctx->error_msg, sizeof(err->message) - 1);
	err->message[sizeof(err->message) - 1] = '\0';

	return 0;
}

static struct gsocket_io *gsocket_io_ssl_create_internal(SSL *ssl, int is_server, int owns_ssl)
{
	struct gsocket_io *io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		return NULL;
	}
	struct ssl_io_ctx *ctx = calloc(1, sizeof(struct ssl_io_ctx));
	if (!ctx) {
		goto err;
	}

	ctx->ssl = ssl;
	/* Store back-pointer for callbacks */
	SSL_set_app_data(ssl, io);

	ctx->is_server = is_server;
	ctx->ssl_type = SSL_TYPE_NORMAL;
	ctx->io_ptr = io;
	io->ctx = ctx;
	io->recv = _ssl_recv;
	io->send = _ssl_send;
	io->recvfrom = _ssl_recvfrom;
	io->sendto = _ssl_sendto;
	io->recvmsg = _ssl_recvmsg;
	io->sendmsg = _ssl_sendmsg;
	io->handshake = _ssl_handshake;
	io->connect = _ssl_connect;
	io->close = _ssl_close;
	io->free = _ssl_free;
	io->open_stream = _ssl_open_stream;
	io->stream_poll = _ssl_stream_poll;
	io->get_fd = _ssl_get_fd;
	io->accept = _ssl_accept;
	io->get_poll_events = _ssl_get_poll_events;
	io->setsockopt = _ssl_setsockopt;
	io->getsockopt = _ssl_getsockopt;
	io->getsockopt = _ssl_getsockopt;
	io->getsockname = _ssl_getsockname;
	io->getpeername = _ssl_getpeername;
	io->get_error = _ssl_get_error;

	return io;

err:
	if (ctx) {
		free(ctx);
	}
	if (io) {
		free(io);
	}
	return NULL;
}

struct gsocket_io *gsocket_io_ssl_new(void *ssl_ctx_void, int is_server)
{
	SSL_CTX *ssl_ctx = (SSL_CTX *)ssl_ctx_void;
	SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		return NULL;
	}

	/* Enforce TLS 1.2 and TLS 1.3+ */
	SSL_set_options(ssl, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	if (is_server) {
		SSL_set_accept_state(ssl);
	} else {
		SSL_set_connect_state(ssl);
	}

	struct gsocket_io *io = gsocket_io_ssl_create_internal(ssl, is_server, 1);
	if (!io) {
		SSL_free(ssl);
		return NULL;
	}

	/* This is a Connection, so we attach the Transport BIO */
	BIO *bio = BIO_new(get_gs_bio_method());
	if (!bio) {
		io->free(io);
		return NULL;
	}
	BIO_set_data(bio, io);
	SSL_set_bio(ssl, bio, bio);

	/* Save ctx reference? */
	if (io->ctx) {
		((struct ssl_io_ctx *)io->ctx)->ssl_ctx = ssl_ctx;
	}

	return io;
}

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
struct gsocket_io *gsocket_io_ssl_quic_new(void *ssl_ctx_void, int is_server)
{
	SSL_CTX *ssl_ctx = (SSL_CTX *)ssl_ctx_void;
	SSL *ssl = NULL;
	struct gsocket_io *io = NULL;
	struct ssl_io_ctx *ctx = NULL;
	struct bio_quic_data *bio_data = NULL;
	BIO *bio = NULL;

	if (is_server) {
		/* Server: use SSL_new_listener */
		ssl = SSL_new_listener(ssl_ctx, 0);
	} else {
		/* Client: use SSL_new and set connect state */
		ssl = SSL_new(ssl_ctx);
		if (ssl) {
			SSL_set_connect_state(ssl);
		}
	}

	if (ssl) {
		SSL_set_blocking_mode(ssl, 0);
	}

	if (!ssl) {
		return NULL;
	}

	/* Enforce TLS 1.2 and TLS 1.3+ */
	SSL_set_options(ssl, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

	/* Set SSL to non-blocking mode for QUIC */
	SSL_set_blocking_mode(ssl, 0);

	io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		goto err;
	}
	ctx = calloc(1, sizeof(struct ssl_io_ctx));
	if (!ctx) {
		goto err;
	}

	ctx->ssl = ssl;
	ctx->is_server = is_server;
	ctx->ssl_ctx = ssl_ctx;
	ctx->ssl_type = is_server ? SSL_TYPE_QUIC_LISTENER : SSL_TYPE_QUIC_CONNECTION;
	ctx->io_ptr = io;
	io->ctx = ctx;
	SSL_set_app_data(ssl, io);

	io->recv = _ssl_recv;
	io->send = _ssl_send;
	io->recvfrom = _ssl_recvfrom;
	io->sendto = _ssl_sendto;
	io->handshake = _ssl_handshake;
	io->connect = _ssl_connect;
	io->close = _ssl_close;
	io->free = _ssl_free;
	io->get_fd = _ssl_get_fd;
	io->stream_poll = _ssl_stream_poll;
	io->accept = _ssl_accept;
	io->open_stream = _ssl_open_stream;
	io->setsockopt = _ssl_setsockopt;
	io->getsockopt = _ssl_getsockopt;
	io->getsockname = _ssl_getsockname;
	io->getpeername = _ssl_getpeername;
	io->get_error = _ssl_get_error;
	io->listen = _ssl_listen;

	/* Create BIO with quic data */
	bio_data = calloc(1, sizeof(struct bio_quic_data));
	if (!bio_data) {
		goto err;
	}
	bio_data->io = io;
	bio_data->is_server = is_server;
	bio_data->peer_len = 0;

	bio = BIO_new(get_gs_quic_bio_method());
	if (!bio) {
		goto err;
	}
	BIO_set_data(bio, bio_data);
	BIO_set_init(bio, 1);
	SSL_set_bio(ssl, bio, bio);

	return io;

err:
	if (bio_data) {
		free(bio_data);
	}
	if (ctx) {
		free(ctx);
	}
	if (io) {
		free(io);
	}
	if (ssl) {
		SSL_free(ssl);
	}
	return NULL;
}

#else
struct gsocket_io *gsocket_io_ssl_quic_new(void *ssl_ctx_void, int is_server)
{
	return NULL;
}
#endif
