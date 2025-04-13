/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#define _GNU_SOURCE

#include "client_tls.h"
#include "client_quic.h"
#include "client_socket.h"
#include "client_tcp.h"
#include "server_info.h"

#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

static ssize_t _ssl_read_ext(struct dns_server_info *server, SSL *ssl, void *buff, int num)
{
	ssize_t ret = 0;
	if (server == NULL || buff == NULL || ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}
	pthread_mutex_lock(&server->lock);
	ret = SSL_read(ssl, buff, num);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

static ssize_t _ssl_write_ext2(struct dns_server_info *server, SSL *ssl, const void *buff, int num, uint64_t flags)
{
	ssize_t ret = 0;
	size_t written = 0;
	if (server == NULL || buff == NULL || ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
#ifdef OSSL_QUIC1_VERSION
	ret = SSL_write_ex2(ssl, buff, num, flags, &written);
#else
	ret = SSL_write_ex(ssl, buff, num, &written);
#endif
	pthread_mutex_unlock(&server->lock);

	if (ret <= 0) {
		return ret;
	}

	return written;
}

int _ssl_shutdown(struct dns_server_info *server)
{
	int ret = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	ret = SSL_shutdown(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

static int _ssl_get_error_ext(struct dns_server_info *server, SSL *ssl, int ret)
{
	int err = 0;
	if (server == NULL || ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	err = SSL_get_error(ssl, ret);
	pthread_mutex_unlock(&server->lock);
	return err;
}

static int _ssl_get_error(struct dns_server_info *server, int ret)
{
	return _ssl_get_error_ext(server, server->ssl, ret);
}

static int _ssl_do_handshake(struct dns_server_info *server)
{
	int err = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	err = SSL_do_handshake(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return err;
}

static int _ssl_session_reused(struct dns_server_info *server)
{
	int err = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	err = SSL_session_reused(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return err;
}

static SSL_SESSION *_ssl_get1_session(struct dns_server_info *server)
{
	SSL_SESSION *ret = NULL;
	if (server == NULL || server->ssl == NULL) {
		return NULL;
	}

	pthread_mutex_lock(&server->lock);
	ret = SSL_get1_session(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

int dns_client_spki_decode(const char *spki, unsigned char *spki_data_out, int spki_data_out_max_len)
{
	int spki_data_len = -1;

	spki_data_len = SSL_base64_decode(spki, spki_data_out, spki_data_out_max_len);

	if (spki_data_len != SHA256_DIGEST_LENGTH) {
		return -1;
	}

	return spki_data_len;
}

static char *_dns_client_server_get_tls_host_verify(struct dns_server_info *server_info)
{
	char *tls_host_verify = NULL;

	switch (server_info->type) {
	case DNS_SERVER_UDP: {
	} break;
	case DNS_SERVER_HTTP3:
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_https = &server_info->flags.https;
		tls_host_verify = flag_https->tls_host_verify;
	} break;
	case DNS_SERVER_QUIC:
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &server_info->flags.tls;
		tls_host_verify = flag_tls->tls_host_verify;
	} break;
	case DNS_SERVER_TCP:
		break;
	case DNS_SERVER_MDNS:
		break;
	default:
		return NULL;
		break;
	}

	if (tls_host_verify) {
		if (tls_host_verify[0] == '\0') {
			return NULL;
		}
	}

	return tls_host_verify;
}

static char *_dns_client_server_get_spki(struct dns_server_info *server_info, int *spki_len)
{
	*spki_len = 0;
	char *spki = NULL;
	switch (server_info->type) {
	case DNS_SERVER_UDP: {
	} break;
	case DNS_SERVER_HTTP3:
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_https = &server_info->flags.https;
		spki = flag_https->spki;
		*spki_len = flag_https->spi_len;
	} break;
	case DNS_SERVER_QUIC:
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &server_info->flags.tls;
		spki = flag_tls->spki;
		*spki_len = flag_tls->spi_len;
	} break;
	case DNS_SERVER_TCP:
		break;
	case DNS_SERVER_MDNS:
		break;
	default:
		return NULL;
		break;
	}

	if (*spki_len <= 0) {
		return NULL;
	}

	return spki;
}

static int _dns_client_set_trusted_cert(SSL_CTX *ssl_ctx)
{
	char *cafile = NULL;
	char *capath = NULL;
	int cert_path_set = 0;

	if (ssl_ctx == NULL) {
		return -1;
	}

	if (dns_conf.ca_file[0]) {
		cafile = dns_conf.ca_file;
	}

	if (dns_conf.ca_path[0]) {
		capath = dns_conf.ca_path;
	}

	if (cafile == NULL && capath == NULL) {
		if (SSL_CTX_set_default_verify_paths(ssl_ctx)) {
			cert_path_set = 1;
		}

		const STACK_OF(X509_NAME) *cas = SSL_CTX_get_client_CA_list(ssl_ctx);
		if (cas && sk_X509_NAME_num(cas) == 0) {
			cafile = "/etc/ssl/certs/ca-certificates.crt";
			capath = "/etc/ssl/certs";
			cert_path_set = 0;
		}
	}

	if (cert_path_set == 0) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, cafile, capath) == 0) {
			tlog(TLOG_WARN, "load certificate from %s:%s failed.", cafile, capath);
			return -1;
		}
	}

	return 0;
}

SSL_CTX *_ssl_ctx_get(int is_quic)
{
	SSL_CTX **ssl_ctx = NULL;
	pthread_mutex_lock(&client.server_list_lock);
	if (is_quic) {
		ssl_ctx = &client.ssl_quic_ctx;
	} else {
		ssl_ctx = &client.ssl_ctx;
	}

	if (*ssl_ctx) {
		pthread_mutex_unlock(&client.server_list_lock);
		return *ssl_ctx;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#if (OPENSSL_VERSION_NUMBER >= 0x30200000L)
	if (is_quic) {
		*ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_method());
	} else {
		*ssl_ctx = SSL_CTX_new(TLS_client_method());
	}
#else
	if (is_quic) {
		return NULL;
	}
	*ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif
#else
	*ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif

	if (*ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

	SSL_CTX_set_options(*ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	SSL_CTX_set_session_cache_mode(*ssl_ctx, SSL_SESS_CACHE_CLIENT);
	SSL_CTX_sess_set_cache_size(*ssl_ctx, DNS_MAX_SERVERS);
	if (_dns_client_set_trusted_cert(*ssl_ctx) != 0) {
		SSL_CTX_set_verify(*ssl_ctx, SSL_VERIFY_NONE, NULL);
		client.ssl_verify_skip = 1;
	}

	pthread_mutex_unlock(&client.server_list_lock);
	return *ssl_ctx;
errout:
	if (*ssl_ctx) {
		SSL_CTX_free(*ssl_ctx);
	}

	*ssl_ctx = NULL;
	pthread_mutex_unlock(&client.server_list_lock);

	return NULL;
}

int _dns_client_create_socket_tls(struct dns_server_info *server_info, const char *hostname, const char *alpn)
{
	int fd = 0;
	struct epoll_event event;
	SSL *ssl = NULL;
	struct proxy_conn *proxy = NULL;

	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;
	int ret = -1;

	if (server_info->ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "create ssl ctx failed, %s", server_info->ip);
		goto errout;
	}

	if (server_info->proxy_name[0] != '\0') {
		proxy = proxy_conn_new(server_info->proxy_name, server_info->ip, server_info->port, 0, 1);
		if (proxy == NULL) {
			tlog(TLOG_ERROR, "create proxy failed, %s, proxy: %s", server_info->ip, server_info->proxy_name);
			goto errout;
		}
		fd = proxy_conn_get_fd(proxy);
	} else {
		fd = socket(server_info->ai_family, SOCK_STREAM, 0);
	}

	if (server_info->flags.ifname[0] != '\0') {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		safe_strncpy(ifr.ifr_name, server_info->flags.ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
			tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
			goto errout;
		}
	}

	ssl = SSL_new(server_info->ssl_ctx);
	if (ssl == NULL) {
		tlog(TLOG_ERROR, "new ssl failed, %s", server_info->ip);
		goto errout;
	}

	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	if (server_info->so_mark >= 0) {
		unsigned int so_mark = server_info->so_mark;
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
			tlog(TLOG_DEBUG, "set socket mark failed, %s", strerror(errno));
		}
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &yes, sizeof(yes)) != 0) {
		tlog(TLOG_DEBUG, "enable TCP fast open failed.");
	}

	// ? this cause ssl crash ?
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, &yes, sizeof(yes));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &yes, sizeof(yes));
	set_sock_keepalive(fd, 30, 3, 5);
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
	}

	if (proxy) {
		ret = proxy_conn_connect(proxy);
	} else {
		ret = connect(fd, &server_info->addr, server_info->ai_addrlen);
	}

	if (ret != 0) {
		if (errno != EINPROGRESS) {
			tlog(TLOG_DEBUG, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	SSL_set_connect_state(ssl);
	if (SSL_set_fd(ssl, fd) == 0) {
		tlog(TLOG_ERROR, "ssl set fd failed.");
		goto errout;
	}

	/* reuse ssl session */
	if (server_info->ssl_session) {
		SSL_set_session(ssl, server_info->ssl_session);
	}

	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
	if (hostname && hostname[0] != 0) {
		SSL_set_tlsext_host_name(ssl, hostname);
	}

	if (alpn && alpn[0] != 0) {
		uint8_t alpn_data[DNS_MAX_ALPN_LEN];
		int32_t alpn_len = strnlen(alpn, DNS_MAX_ALPN_LEN - 1);
		alpn_data[0] = alpn_len;
		memcpy(alpn_data + 1, alpn, alpn_len);
		alpn_len++;
		if (SSL_set_alpn_protos(ssl, alpn_data, alpn_len)) {
			tlog(TLOG_INFO, "SSL_set_alpn_protos failed.");
			goto errout;
		}
	}

	if (server_info->ssl) {
		SSL_free(server_info->ssl);
		server_info->ssl = NULL;
	}

	server_info->fd = fd;
	server_info->ssl = ssl;
	server_info->ssl_write_len = -1;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	server_info->proxy = proxy;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		goto errout;
	}

	tlog(TLOG_DEBUG, "tls server %s connecting.\n", server_info->ip);

	return 0;
errout:
	if (server_info->fd > 0) {
		server_info->fd = -1;
	}

	if (server_info->ssl) {
		server_info->ssl = NULL;
	}

	server_info->status = DNS_SERVER_STATUS_INIT;

	if (fd > 0 && proxy == NULL) {
		close(fd);
	}

	if (ssl) {
		SSL_free(ssl);
	}

	if (proxy) {
		proxy_conn_free(proxy);
	}

	return -1;
}

int _dns_client_socket_ssl_send_ext(struct dns_server_info *server, SSL *ssl, const void *buf, int num, uint64_t flags)
{
	int ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (num < 0) {
		errno = EINVAL;
		return -1;
	}

	ret = _ssl_write_ext2(server, ssl, buf, num, flags);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error_ext(server, ssl, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_SSL: {
		char buff[256];
		ssl_err = ERR_get_error();
		int ssl_reason = ERR_GET_REASON(ssl_err);
		if (ssl_reason == SSL_R_UNINITIALIZED || ssl_reason == SSL_R_PROTOCOL_IS_SHUTDOWN ||
			ssl_reason == SSL_R_BAD_LENGTH || ssl_reason == SSL_R_SHUTDOWN_WHILE_IN_INIT ||
			ssl_reason == SSL_R_BAD_WRITE_RETRY) {
			errno = EAGAIN;
			return -1;
		}

		tlog(TLOG_ERROR, "server %s SSL write fail error: %s", server->ip, ERR_error_string(ssl_err, buff));
		errno = EFAULT;
		ret = -1;
	} break;
	case SSL_ERROR_SYSCALL:
		tlog(TLOG_DEBUG, "SSL syscall failed, %s", strerror(errno));
		return ret;
	default:
		errno = EFAULT;
		ret = -1;
		break;
	}

	return ret;
}

int _dns_client_socket_ssl_recv_ext(struct dns_server_info *server, SSL *ssl, void *buf, int num)
{
	ssize_t ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (ssl == NULL) {
		errno = EFAULT;
		return -1;
	}

	ret = _ssl_read_ext(server, ssl, buf, num);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error_ext(server, ssl, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_SSL: {
		char buff[256];

		ssl_err = ERR_get_error();
		int ssl_reason = ERR_GET_REASON(ssl_err);
		if (ssl_reason == SSL_R_UNINITIALIZED) {
			errno = EAGAIN;
			return -1;
		}

		if (ssl_reason == SSL_R_SHUTDOWN_WHILE_IN_INIT || ssl_reason == SSL_R_PROTOCOL_IS_SHUTDOWN) {
			return 0;
		}

#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
		if (ssl_reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
			return 0;
		}
#endif

		tlog(TLOG_ERROR, "server %s SSL read fail error: %s", server->ip, ERR_error_string(ssl_err, buff));
		errno = EFAULT;
		ret = -1;
	} break;
	case SSL_ERROR_SYSCALL:
		if (errno == 0) {
			return 0;
		}

		ret = -1;
		return ret;
	default:
		errno = EFAULT;
		ret = -1;
		break;
	}

	return ret;
}

int _dns_client_socket_ssl_send(struct dns_server_info *server, const void *buf, int num)
{
	return _dns_client_socket_ssl_send_ext(server, server->ssl, buf, num, 0);
}

int _dns_client_socket_ssl_recv(struct dns_server_info *server, void *buf, int num)
{
	return _dns_client_socket_ssl_recv_ext(server, server->ssl, buf, num);
}

int _dns_client_ssl_poll_event(struct dns_server_info *server_info, int ssl_ret)
{
	struct epoll_event fd_event;

	memset(&fd_event, 0, sizeof(fd_event));

	if (ssl_ret == SSL_ERROR_WANT_READ) {
		fd_event.events = EPOLLIN;
	} else if (ssl_ret == SSL_ERROR_WANT_WRITE) {
		fd_event.events = EPOLLOUT | EPOLLIN;
	} else {
		goto errout;
	}

	if (server_info->fd < 0) {
		goto errout;
	}

	fd_event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &fd_event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static inline int _dns_client_to_hex(int c)
{
	if (c > 0x9) {
		return 'A' + c - 0xA;
	}

	return '0' + c;
}

static int _dns_client_tls_matchName(const char *host, const char *pattern, int size)
{
	int match = -1;
	int i = 0;
	int j = 0;

	while (i < size && host[j] != '\0') {
		if (toupper(pattern[i]) == toupper(host[j])) {
			i++;
			j++;
			continue;
		}
		if (pattern[i] == '*') {
			while (host[j] != '.' && host[j] != '\0') {
				j++;
			}
			i++;
			continue;
		}
		break;
	}

	if (i == size && host[j] == '\0') {
		match = 0;
	}

	return match;
}

static int _dns_client_tls_get_cert_CN(X509 *cert, char *cn, int max_cn_len)
{
	X509_NAME *cert_name = NULL;

	cert_name = X509_get_subject_name(cert);
	if (cert_name == NULL) {
		tlog(TLOG_ERROR, "get subject name failed.");
		goto errout;
	}

	if (X509_NAME_get_text_by_NID(cert_name, NID_commonName, cn, max_cn_len) == -1) {
		tlog(TLOG_ERROR, "cannot found x509 name");
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _dns_client_verify_common_name(struct dns_server_info *server_info, X509 *cert, char *peer_CN)
{
	char *tls_host_verify = NULL;
	GENERAL_NAMES *alt_names = NULL;
	int i = 0;

	/* check tls host */
	tls_host_verify = _dns_client_server_get_tls_host_verify(server_info);
	if (tls_host_verify == NULL) {
		return 0;
	}

	if (tls_host_verify) {
		if (_dns_client_tls_matchName(tls_host_verify, peer_CN, strnlen(peer_CN, DNS_MAX_CNAME_LEN)) == 0) {
			return 0;
		}
	}

	alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (alt_names == NULL) {
		goto errout;
	}

	/* found subject alt name */
	for (i = 0; i < sk_GENERAL_NAME_num(alt_names); i++) {
		GENERAL_NAME *name = sk_GENERAL_NAME_value(alt_names, i);
		if (name == NULL) {
			continue;
		}
		switch (name->type) {
		case GEN_DNS: {
			ASN1_IA5STRING *dns = name->d.dNSName;
			if (dns == NULL) {
				continue;
			}

			tlog(TLOG_DEBUG, "peer SAN: %s", dns->data);
			if (_dns_client_tls_matchName(tls_host_verify, (char *)dns->data, dns->length) == 0) {
				tlog(TLOG_DEBUG, "peer SAN match: %s", dns->data);
				GENERAL_NAMES_free(alt_names);
				return 0;
			}
		} break;
		case GEN_IPADD:
			break;
		default:
			break;
		}
	}

errout:
	tlog(TLOG_WARN, "server %s CN is invalid, peer CN: %s, expect CN: %s", server_info->ip, peer_CN, tls_host_verify);
	server_info->prohibit = 1;
	if (alt_names) {
		GENERAL_NAMES_free(alt_names);
	}
	return -1;
}

static int _dns_client_tls_verify(struct dns_server_info *server_info)
{
	X509 *cert = NULL;
	X509_PUBKEY *pubkey = NULL;
	char peer_CN[256];
	char cert_fingerprint[256];
	int i = 0;
	int key_len = 0;
	unsigned char *key_data = NULL;
	unsigned char *key_data_tmp = NULL;
	unsigned char *key_sha256 = NULL;
	char *spki = NULL;
	int spki_len = 0;

	if (server_info->ssl == NULL) {
		return -1;
	}

	pthread_mutex_lock(&server_info->lock);
	cert = SSL_get_peer_certificate(server_info->ssl);
	if (cert == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		tlog(TLOG_ERROR, "get peer certificate failed.");
		return -1;
	}

	if (server_info->skip_check_cert == 0) {
		long res = SSL_get_verify_result(server_info->ssl);
		if (res != X509_V_OK) {
			pthread_mutex_unlock(&server_info->lock);
			peer_CN[0] = '\0';
			_dns_client_tls_get_cert_CN(cert, peer_CN, sizeof(peer_CN));
			tlog(TLOG_WARN, "peer server %s certificate verify failed, %s", server_info->ip,
				 X509_verify_cert_error_string(res));
			tlog(TLOG_WARN, "peer CN: %s", peer_CN);
			goto errout;
		}
	}
	pthread_mutex_unlock(&server_info->lock);

	if (_dns_client_tls_get_cert_CN(cert, peer_CN, sizeof(peer_CN)) != 0) {
		tlog(TLOG_ERROR, "get cert CN failed.");
		goto errout;
	}

	tlog(TLOG_DEBUG, "peer CN: %s", peer_CN);

	if (_dns_client_verify_common_name(server_info, cert, peer_CN) != 0) {
		goto errout;
	}

	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL) {
		tlog(TLOG_ERROR, "get pub key failed.");
		goto errout;
	}

	/* get spki pin */
	key_len = i2d_X509_PUBKEY(pubkey, NULL);
	if (key_len <= 0) {
		tlog(TLOG_ERROR, "get x509 public key failed.");
		goto errout;
	}

	key_data = OPENSSL_malloc(key_len);
	key_data_tmp = key_data;
	if (key_data == NULL) {
		tlog(TLOG_ERROR, "malloc memory failed.");
		goto errout;
	}

	i2d_X509_PUBKEY(pubkey, &key_data_tmp);

	/* Get the SHA256 value of SPKI */
	key_sha256 = SSL_SHA256(key_data, key_len, NULL);
	if (key_sha256 == NULL) {
		tlog(TLOG_ERROR, "get sha256 failed.");
		goto errout;
	}

	char *ptr = cert_fingerprint;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		*ptr = _dns_client_to_hex(key_sha256[i] >> 4 & 0xF);
		ptr++;
		*ptr = _dns_client_to_hex(key_sha256[i] & 0xF);
		ptr++;
		*ptr = ':';
		ptr++;
	}
	ptr--;
	*ptr = 0;
	tlog(TLOG_DEBUG, "cert SPKI pin(%s): %s", "sha256", cert_fingerprint);

	spki = _dns_client_server_get_spki(server_info, &spki_len);
	if (spki && spki_len > 0 && spki_len <= SHA256_DIGEST_LENGTH) {
		/* check SPKI */
		if (memcmp(spki, key_sha256, spki_len) != 0) {
			tlog(TLOG_INFO, "server %s cert spki is invalid", server_info->ip);
			goto errout;
		} else {
			tlog(TLOG_DEBUG, "server %s cert spki verify succeed", server_info->ip);
		}
	}

	OPENSSL_free(key_data);
	X509_free(cert);
	return 0;

errout:
	if (key_data) {
		OPENSSL_free(key_data);
	}

	if (cert) {
		X509_free(cert);
	}

	return -1;
}

int _dns_client_process_tls(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int ret = -1;
	struct epoll_event fd_event;
	int ssl_ret = 0;

	if (unlikely(server_info->ssl == NULL)) {
		tlog(TLOG_ERROR, "ssl is invalid, server %s", server_info->ip);
		goto errout;
	}

	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		/* do SSL hand shake */
		ret = _ssl_do_handshake(server_info);
		if (ret <= 0) {
			memset(&fd_event, 0, sizeof(fd_event));
			ssl_ret = _ssl_get_error(server_info, ret);
			if (_dns_client_ssl_poll_event(server_info, ssl_ret) == 0) {
				return 0;
			}

			if (ssl_ret != SSL_ERROR_SYSCALL) {
				unsigned long ssl_err = ERR_get_error();
				int ssl_reason = ERR_GET_REASON(ssl_err);
				tlog(TLOG_WARN, "Handshake with %s failed, error no: %s(%d, %d, %d)\n", server_info->ip,
					 ERR_reason_error_string(ssl_err), ret, ssl_ret, ssl_reason);
				goto errout;
			}

			if (errno != ENETUNREACH) {
				tlog(TLOG_WARN, "Handshake with %s failed, %s", server_info->ip, strerror(errno));
			}
			goto errout;
		}

		tlog(TLOG_DEBUG, "remote server %s:%d connected\n", server_info->ip, server_info->port);
		/* Was the stored session reused? */
		if (_ssl_session_reused(server_info)) {
			tlog(TLOG_DEBUG, "reused session");
		} else {
			tlog(TLOG_DEBUG, "new session");
			pthread_mutex_lock(&server_info->lock);
			if (server_info->ssl_session) {
				/* free session */
				SSL_SESSION_free(server_info->ssl_session);
				server_info->ssl_session = NULL;
			}

			if (_dns_client_tls_verify(server_info) != 0) {
				tlog(TLOG_WARN, "peer %s verify failed.", server_info->ip);
				pthread_mutex_unlock(&server_info->lock);
				goto errout;
			}

			/* save ssl session for next request */
			server_info->ssl_session = _ssl_get1_session(server_info);
			pthread_mutex_unlock(&server_info->lock);
		}

		server_info->status = DNS_SERVER_STATUS_CONNECTED;
		memset(&fd_event, 0, sizeof(fd_event));
		fd_event.events = EPOLLIN | EPOLLOUT;
		fd_event.data.ptr = server_info;
		if (server_info->fd > 0) {
			if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &fd_event) != 0) {
				tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
				goto errout;
			}
		}

		event->events = EPOLLOUT;
	}

	if (server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
/* QUIC */
#ifdef OSSL_QUIC1_VERSION
		return _dns_client_process_quic(server_info, event, now);
#else
		tlog(TLOG_ERROR, "quic/http3 is not supported.");
		goto errout;
#endif
	}

	return _dns_client_process_tcp(server_info, event, now);
errout:
	pthread_mutex_lock(&server_info->lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&server_info->lock);

	return -1;
}

int _dns_client_send_tls(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	int send_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	if (len > sizeof(inpacket_data) - 2) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	/* TCP query format
	 * | len (short) | dns query data |
	 */
	*((unsigned short *)(inpacket)) = htons(len);
	memcpy(inpacket + 2, packet, len);
	len += 2;

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, len);
	}

	if (server_info->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	send_len = _dns_client_socket_ssl_send(server_info, inpacket, len);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, len);
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, len - send_len);
	}

	return 0;
}