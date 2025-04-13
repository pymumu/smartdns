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

#include "smartdns/http_parse.h"
#include "smartdns/util.h"

#include "client_http3.h"
#include "client_quic.h"
#include "client_socket.h"
#include "client_tls.h"
#include "conn_stream.h"
#include "server_info.h"

#include <net/if.h>
#include <netinet/ip.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

#ifdef OSSL_QUIC1_VERSION
static int _dns_client_quic_bio_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags,
										 size_t *msgs_processed)
{
	struct dns_server_info *server_info = NULL;
	int total_len = 0;
	int len = 0;
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);

	server_info = (struct dns_server_info *)BIO_get_data(bio);
	if (server_info == NULL) {
		tlog(TLOG_ERROR, "server info is null, %s", server_info->ip);
		return 0;
	}

	*msgs_processed = 0;
	for (size_t i = 0; i < num_msg; i++) {
		len = proxy_conn_recvfrom(server_info->proxy, msg[i].data, msg[i].data_len, 0, (struct sockaddr *)&from,
								  &from_len);
		if (len < 0) {
			if (*msgs_processed == 0) {
				ERR_raise(ERR_LIB_SYS, errno);
				total_len = 0;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}

			tlog(TLOG_ERROR, "recvmsg failed, %s", strerror(errno));
			return 0;
		}

		msg[i].data_len = len;
		total_len += len;
		*msgs_processed += 1;
	}

	return total_len;
}

static int _dns_client_quic_bio_sendmmsg(BIO *bio, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags,
										 size_t *msgs_processed)
{
	struct dns_server_info *server_info = NULL;
	int total_len = 0;
	int len = 0;
	const struct sockaddr *addr = NULL;
	socklen_t addrlen = 0;

	*msgs_processed = 0;
	server_info = (struct dns_server_info *)BIO_get_data(bio);
	if (server_info == NULL) {
		tlog(TLOG_ERROR, "server info is null, %s", server_info->ip);
		return 0;
	}

	addr = &server_info->addr;
	addrlen = server_info->ai_addrlen;
	for (size_t i = 0; i < num_msg; i++) {
		len = proxy_conn_sendto(server_info->proxy, msg[i].data, msg[i].data_len, 0, addr, addrlen);
		if (len < 0) {
			if (*msgs_processed == 0) {
				ERR_raise(ERR_LIB_SYS, errno);
				total_len = 0;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}

			tlog(TLOG_ERROR, "sendmsg failed, %s", strerror(errno));
			return 0;
		}

		total_len += len;
		*msgs_processed += 1;
	}

	return total_len;
}

static long _dns_client_quic_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	struct dns_server_info *server_info = NULL;
	long ret = 0;

	server_info = (struct dns_server_info *)BIO_get_data(bio);
	if (server_info == NULL) {
		tlog(TLOG_ERROR, "server info is null.");
		return -1;
	}

	switch (cmd) {
	case BIO_CTRL_DGRAM_GET_MTU:
		break;
	default:
		break;
	}

	return ret;
}

static int _dns_client_setup_quic_ssl_bio(struct dns_server_info *server_info, SSL *ssl, int fd,
										  struct proxy_conn *proxy)
{
	BIO_METHOD *bio_method_alloc = NULL;
	BIO_METHOD *bio_method = server_info->bio_method;
	BIO *udp_socket_bio = NULL;

	if (ssl == NULL) {
		tlog(TLOG_ERROR, "ssl is null, %s", server_info->ip);
		return -1;
	}

	if (proxy == NULL) {
		if (SSL_set_fd(ssl, fd) == 0) {
			tlog(TLOG_ERROR, "ssl set fd failed.");
			goto errout;
		}

		return 0;
	}

	if (bio_method == NULL) {
		bio_method_alloc = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "udp-proxy");
		if (bio_method_alloc == NULL) {
			tlog(TLOG_ERROR, "create bio method failed.");
			goto errout;
		}

		bio_method = bio_method_alloc;
		BIO_meth_set_sendmmsg(bio_method, _dns_client_quic_bio_sendmmsg);
		BIO_meth_set_recvmmsg(bio_method, _dns_client_quic_bio_recvmmsg);
		BIO_meth_set_ctrl(bio_method, _dns_client_quic_bio_ctrl);
	}

	udp_socket_bio = BIO_new(bio_method);
	if (udp_socket_bio == NULL) {
		tlog(TLOG_ERROR, "create udp_socket_bio failed.");
		goto errout;
	}
	BIO_set_data(udp_socket_bio, (void *)server_info);
	BIO_set_init(udp_socket_bio, 1);

	SSL_set_bio(ssl, udp_socket_bio, udp_socket_bio);
	server_info->bio_method = bio_method;

	return 0;

errout:
	if (bio_method_alloc) {
		BIO_meth_free(bio_method_alloc);
	}

	if (udp_socket_bio) {
		BIO_free(udp_socket_bio);
	}

	return -1;
}

#endif

int _dns_client_create_socket_quic(struct dns_server_info *server_info, const char *hostname, const char *alpn)
{
#ifdef OSSL_QUIC1_VERSION
	int fd = 0;
	unsigned char alpn_data[DNS_MAX_ALPN_LEN];
	int32_t alpn_len = 0;
	struct epoll_event event;
	SSL *ssl = NULL;
	struct proxy_conn *proxy = NULL;
	int ret = -1;

	if (server_info->ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "create ssl ctx failed, %s", server_info->ip);
		goto errout;
	}

	if (server_info->proxy_name[0] != '\0') {
		proxy = proxy_conn_new(server_info->proxy_name, server_info->ip, server_info->port, 1, 1);
		if (proxy == NULL) {
			tlog(TLOG_ERROR, "create proxy failed, %s, proxy: %s", server_info->ip, server_info->proxy_name);
			goto errout;
		}
		fd = proxy_conn_get_fd(proxy);
	} else {
		fd = socket(server_info->ai_family, SOCK_DGRAM, IPPROTO_UDP);
	}

	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	ssl = SSL_new(server_info->ssl_ctx);
	if (ssl == NULL) {
		tlog(TLOG_ERROR, "new ssl failed, %s", server_info->ip);
		goto errout;
	}

	if (server_info->so_mark >= 0) {
		unsigned int so_mark = server_info->so_mark;
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
			tlog(TLOG_DEBUG, "set socket mark failed, %s", strerror(errno));
		}
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

	SSL_set_blocking_mode(ssl, 0);
	SSL_set_default_stream_mode(ssl, SSL_DEFAULT_STREAM_MODE_NONE);
	if (_dns_client_setup_quic_ssl_bio(server_info, ssl, fd, proxy) != 0) {
		tlog(TLOG_ERROR, "ssl set fd failed.");
		goto errout;
	}

	SSL_set_connect_state(ssl);
	/* reuse ssl session */
	if (server_info->ssl_session) {
		SSL_set_session(ssl, server_info->ssl_session);
	}

	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
	if (hostname[0] != 0) {
		SSL_set_tlsext_host_name(ssl, hostname);
	}

	SSL_set1_host(ssl, hostname);

	if (alpn == NULL) {
		tlog(TLOG_INFO, "alpn is null.");
		goto errout;
	}

	alpn_len = strnlen(alpn, DNS_MAX_ALPN_LEN - 1);
	alpn_data[0] = alpn_len;
	memcpy(alpn_data + 1, alpn, alpn_len);
	alpn_len++;

	if (SSL_set_alpn_protos(ssl, alpn_data, alpn_len)) {
		tlog(TLOG_INFO, "SSL_set_alpn_protos failed.");
		goto errout;
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

	tlog(TLOG_DEBUG, "quic server %s connecting.\n", server_info->ip);

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
#else
	return -1;
#endif
}

#ifdef OSSL_QUIC1_VERSION
static int _dns_client_process_quic_poll(struct dns_server_info *server_info)
{
	LIST_HEAD(processed_list);
	static int MAX_POLL_ITEM_COUNT = 128;
	SSL_POLL_ITEM poll_items[MAX_POLL_ITEM_COUNT];
	memset(poll_items, 0, sizeof(poll_items));
	static const struct timeval nz_timeout = {0, 0};
	int poll_ret = 0;
	int ret = 0;
	struct dns_conn_stream *conn_stream = NULL;
	struct dns_conn_stream *tmp = NULL;

	while (true) {
		int poll_item_count = 0;
		size_t poll_process_count = 0;
		size_t poll_retcount = 0;

		pthread_mutex_lock(&server_info->lock);
		list_for_each_entry_safe(conn_stream, tmp, &server_info->conn_stream_list, server_list)
		{
			if (conn_stream->quic_stream == NULL) {
				continue;
			}

			if (poll_item_count >= MAX_POLL_ITEM_COUNT) {
				break;
			}

			poll_items[poll_item_count].desc = SSL_as_poll_descriptor(conn_stream->quic_stream);
			poll_items[poll_item_count].events = SSL_POLL_EVENT_R;
			poll_items[poll_item_count].revents = 0;
			poll_item_count++;
			list_del_init(&conn_stream->server_list);
			list_add_tail(&conn_stream->server_list, &processed_list);
		}
		pthread_mutex_unlock(&server_info->lock);

		if (poll_item_count <= 0) {
			SSL_handle_events(server_info->ssl);
			break;
		}

		ret = SSL_poll(poll_items, poll_item_count, sizeof(SSL_POLL_ITEM), &nz_timeout, 0, &poll_retcount);
		if (ret <= 0) {
			tlog(TLOG_DEBUG, "SSL_poll failed, %d", ret);
			goto errout;
		}

		for (int i = 0; i < MAX_POLL_ITEM_COUNT && poll_process_count < poll_retcount; i++) {
			if (poll_items[i].revents & SSL_POLL_EVENT_R) {
				poll_process_count++;
				conn_stream = SSL_get_ex_data(poll_items[i].desc.value.ssl, 0);
				if (conn_stream == NULL) {
					tlog(TLOG_DEBUG, "conn stream is null");
					SSL_free(poll_items[i].desc.value.ssl);
					continue;
				}

				int read_len = _dns_client_socket_ssl_recv_ext(server_info, poll_items[i].desc.value.ssl,
															   conn_stream->recv_buff.data, DNS_TCP_BUFFER);

				if (read_len < 0) {
					if (errno == EAGAIN) {
						continue;
					}

					tlog(TLOG_ERROR, "recv failed, %s", strerror(errno));
					continue;
				}

				conn_stream->recv_buff.len += read_len;

				if (conn_stream->query == NULL) {
					list_del_init(&conn_stream->server_list);
					_dns_client_conn_stream_put(conn_stream);
					continue;
				}

				if (server_info->type == DNS_SERVER_HTTP3) {
					ret = _dns_client_process_recv_http3(server_info, conn_stream);
					if (ret != 0) {
						continue;
					}

				} else if (server_info->type == DNS_SERVER_QUIC) {
					unsigned short qid = htons(conn_stream->query->sid);
					int msg_len = ntohs(*((unsigned short *)(conn_stream->recv_buff.data)));
					if (msg_len <= 0 || msg_len >= DNS_IN_PACKSIZE) {
						/* data len is invalid */
						continue;
					}

					if (msg_len > conn_stream->recv_buff.len - 2) {
						errno = EAGAIN;
						/* len is not expected, wait and recv */
						continue;
					}

					memcpy(conn_stream->recv_buff.data + 2, &qid, 2);
					if (_dns_client_recv(server_info, conn_stream->recv_buff.data + 2, conn_stream->recv_buff.len - 2,
										 &server_info->addr, server_info->ai_addrlen) != 0) {
						continue;
					}
				}
				/* process succeed, delete from processed_list*/
				list_del_init(&conn_stream->server_list);
				_dns_client_conn_stream_put(conn_stream);
			}
		}
	}
	poll_ret = 0;
	goto out;
errout:
	poll_ret = -1;
out:
	pthread_mutex_lock(&server_info->lock);
	if (list_empty(&processed_list)) {
		pthread_mutex_unlock(&server_info->lock);
		return 0;
	}

	list_splice_tail(&processed_list, &server_info->conn_stream_list);
	pthread_mutex_unlock(&server_info->lock);

	return poll_ret;
}

int _dns_client_process_quic(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	if (event->events & EPOLLIN) {
		/* connection is closed, reconnect */
		if (SSL_get_shutdown(server_info->ssl) != 0) {
			int ret = 0;
			_dns_client_close_socket_ext(server_info, 1);
			pthread_mutex_lock(&server_info->lock);
			server_info->recv_buff.len = 0;
			if (!list_empty(&server_info->conn_stream_list)) {
				/* still remain request data, reconnect and send*/
				ret = _dns_client_create_socket(server_info);
			} else {
				ret = 0;
			}
			pthread_mutex_unlock(&server_info->lock);
			tlog(TLOG_DEBUG, "quic server %s peer close", server_info->ip);
			return ret;
		}

		if (_dns_client_process_quic_poll(server_info) != 0) {
			goto errout;
		}
	}

	if (event->events & EPOLLOUT) {
		int epoll_events = EPOLLIN;
		struct dns_conn_stream *conn_stream = NULL;
		pthread_mutex_lock(&server_info->lock);
		list_for_each_entry(conn_stream, &server_info->conn_stream_list, server_list)
		{
			if (conn_stream->quic_stream != NULL) {
				continue;
			}

			if (conn_stream->send_buff.len <= 0) {
				continue;
			}

			conn_stream->quic_stream = SSL_new_stream(server_info->ssl, 0);
			if (conn_stream->quic_stream == NULL) {
				pthread_mutex_unlock(&server_info->lock);
				goto errout;
			}

			SSL_set_ex_data(conn_stream->quic_stream, 0, conn_stream);

			int send_len =
				_dns_client_socket_ssl_send_ext(server_info, conn_stream->quic_stream, conn_stream->send_buff.data,
												conn_stream->send_buff.len, SSL_WRITE_FLAG_CONCLUDE);
			if (send_len < 0) {
				if (errno == EAGAIN) {
					epoll_events = EPOLLIN | EPOLLOUT;
					SSL_handle_events(server_info->ssl);
				}
			}

			if (send_len < conn_stream->send_buff.len) {
				conn_stream->send_buff.len -= send_len;
				memmove(conn_stream->send_buff.data, conn_stream->send_buff.data + send_len,
						conn_stream->send_buff.len);
				epoll_events = EPOLLIN | EPOLLOUT;
			} else {
				conn_stream->send_buff.len = 0;
			}
		}
		pthread_mutex_unlock(&server_info->lock);

		if (server_info->fd > 0) {
			/* clear epollout event */
			struct epoll_event mod_event;
			memset(&mod_event, 0, sizeof(mod_event));
			mod_event.events = epoll_events;
			mod_event.data.ptr = server_info;
			if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &mod_event) != 0) {
				tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
				goto errout;
			}
		}
	}
	return 0;
errout:
	return -1;
}
#endif

#ifdef OSSL_QUIC1_VERSION
static int _dns_client_quic_pending_data(struct dns_conn_stream *stream, struct dns_server_info *server_info,
										 struct dns_query_struct *query, void *packet, int len)
{
	struct epoll_event event;
	if (DNS_TCP_BUFFER - stream->send_buff.len < len) {
		errno = ENOMEM;
		return -1;
	}

	if (server_info->fd <= 0) {
		errno = ECONNRESET;
		goto errout;
	}

	memcpy(stream->send_buff.data + stream->send_buff.len, packet, len);
	stream->send_buff.len += len;

	pthread_mutex_lock(&server_info->lock);
	if (list_empty(&stream->server_list)) {
		list_add_tail(&stream->server_list, &server_info->conn_stream_list);
		_dns_client_conn_stream_get(stream);
	}
	stream->server_info = server_info;

	if (list_empty(&stream->query_list)) {
		list_add_tail(&stream->query_list, &query->conn_stream_list);
		_dns_client_conn_stream_get(stream);
	}
	stream->query = query;
	pthread_mutex_unlock(&server_info->lock);

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		goto errout;
	}
	return 0;
errout:

	return -1;
}

int _dns_client_send_quic_data(struct dns_query_struct *query, struct dns_server_info *server_info, void *packet,
							   unsigned short len)
{
	int send_len = 0;
	int ret = 0;

	_dns_client_conn_server_streams_free(server_info, query);

	if (server_info->ssl == NULL) {
		tlog(TLOG_DEBUG, "ssl is invalid, server %s", server_info->ip);
		return -1;
	}

	struct dns_conn_stream *stream = _dns_client_conn_stream_new();
	if (stream == NULL) {
		tlog(TLOG_ERROR, "malloc memory failed.");
		return -1;
	}

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		ret = _dns_client_quic_pending_data(stream, server_info, query, packet, len);
		goto out;
	}

	/* run hand shake */
	SSL_handle_events(server_info->ssl);

	SSL *quic_stream = SSL_new_stream(server_info->ssl, 0);
	if (quic_stream == NULL) {
		struct epoll_event event;
		_dns_client_shutdown_socket(server_info);
		ret = _dns_client_quic_pending_data(stream, server_info, query, packet, len);
		memset(&event, 0, sizeof(event));
		event.events = EPOLLIN;
		event.data.ptr = server_info;
		if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			ret = -1;
		}
		goto out;
	}

	pthread_mutex_lock(&server_info->lock);
	list_add_tail(&stream->server_list, &server_info->conn_stream_list);
	_dns_client_conn_stream_get(stream);
	stream->server_info = server_info;

	list_add_tail(&stream->query_list, &query->conn_stream_list);
	_dns_client_conn_stream_get(stream);
	stream->query = query;
	pthread_mutex_unlock(&server_info->lock);

	/* bind stream */
	SSL_set_ex_data(quic_stream, 0, stream);
	stream->quic_stream = quic_stream;

	send_len = _dns_client_socket_ssl_send_ext(server_info, quic_stream, packet, len, SSL_WRITE_FLAG_CONCLUDE);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			ret = _dns_client_quic_pending_data(stream, server_info, query, packet, len);
			goto out;
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		ret = -1;
		goto out;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		ret = _dns_client_quic_pending_data(stream, server_info, query, packet + send_len, len - send_len);
		goto out;
	}
out:
	if (stream) {
		_dns_client_conn_stream_put(stream);
	}

	return ret;
}
#endif

int _dns_client_send_quic(struct dns_query_struct *query, struct dns_server_info *server_info, void *packet,
						  unsigned short len)
{
#ifdef OSSL_QUIC1_VERSION
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

	/* set query id to zero */
	memset(inpacket + 2, 0, 2);

	return _dns_client_send_quic_data(query, server_info, inpacket, len);
#else
	tlog(TLOG_ERROR, "quic is not supported.");
#endif
	return 0;
}
