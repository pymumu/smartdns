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

#include "smartdns/proxy.h"
#include "smartdns/util.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "client_socket.h"
#include "proxy.h"

#include <sys/epoll.h>
#include <sys/socket.h>

int _dns_proxy_handshake(struct dns_server_info *server_info, int epoll_fd, struct epoll_event *event,
						 unsigned long now)
{
	struct epoll_event fd_event;
	proxy_handshake_state ret;
	int retval = -1;
	int epoll_op = EPOLL_CTL_MOD;

	pthread_mutex_lock(&server_info->lock);
	if (server_info->proxy == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return -1;
	}

	struct proxy_channel *channel = proxy_channel_get_from_event(event->data.ptr);
	if (channel == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return -1;
	}

	ret = proxy_channel_handshake(channel, epoll_fd);
	if (ret == PROXY_HANDSHAKE_OK) {
		pthread_mutex_unlock(&server_info->lock);
		return 0;
	}

	if (ret == PROXY_HANDSHAKE_ERR) {
		goto errout;
	}

	memset(&fd_event, 0, sizeof(fd_event));
	if (ret == PROXY_HANDSHAKE_CONNECTED) {
		fd_event.events = EPOLLIN;
		/* proxy connection established */

		if (server_info->so_mark >= 0) {
			proxy_conn_set_so_mark(server_info->proxy, server_info->so_mark);
		}

		if (server_info->type == DNS_SERVER_UDP) {
			server_info->status = DNS_SERVER_STATUS_CONNECTED;
		} else if (server_info->type == DNS_SERVER_HTTP3 || server_info->type == DNS_SERVER_QUIC) {
			/* do handshake for quic */
			server_info->status = DNS_SERVER_STATUS_CONNECTING;
			fd_event.events |= EPOLLOUT;
		} else {
			if (server_info->send_buff.len > 0) {
				/* Has pending data, need EPOLLOUT to send it */
				fd_event.events |= EPOLLOUT;
			}
			/* If no pending data, only EPOLLIN to avoid infinite EPOLLOUT triggers */
		}
		retval = 0;
	}

	if (ret == PROXY_HANDSHAKE_WANT_READ) {
		fd_event.events = EPOLLIN;
	} else if (ret == PROXY_HANDSHAKE_WANT_WRITE) {
		fd_event.events = EPOLLOUT | EPOLLIN;
	}

	fd_event.data.ptr = server_info;
	if (proxy_conn_ctl(server_info->proxy, epoll_fd, epoll_op, &fd_event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		goto errout;
	}

	pthread_mutex_unlock(&server_info->lock);
	return retval;

errout:
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	if (server_info->proxy) {
		_dns_client_close_socket(server_info);
	}
	pthread_mutex_unlock(&server_info->lock);
	return -1;
}

static int _proxy_bio_write(BIO *b, const char *buf, int len)
{
	struct dns_server_info *server_info = BIO_get_data(b);
	int ret;

	if (server_info == NULL || server_info->proxy == NULL) {
		return -1;
	}

	BIO_clear_retry_flags(b);
	ret = proxy_conn_send(server_info->proxy, buf, len, 0);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			BIO_set_retry_write(b);
		}
	}
	return ret;
}

static int _proxy_bio_read(BIO *b, char *buf, int len)
{
	struct dns_server_info *server_info = BIO_get_data(b);
	int ret;

	if (server_info == NULL || server_info->proxy == NULL) {
		return -1;
	}

	BIO_clear_retry_flags(b);
	ret = proxy_conn_recv(server_info->proxy, buf, len, 0);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			BIO_set_retry_read(b);
		}
	}
	return ret;
}

static long _proxy_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	switch (cmd) {
	case BIO_CTRL_FLUSH:
		return 1;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
		return 0;
	default:
		return 0;
	}
}

static int _proxy_bio_create(BIO *b)
{
	BIO_set_init(b, 1);
	return 1;
}

static int _proxy_bio_destroy(BIO *b)
{
	if (b == NULL) {
		return 0;
	}
	BIO_set_data(b, NULL);
	BIO_set_init(b, 0);
	return 1;
}

static int _dns_client_setup_tcp_ssl_bio(struct dns_server_info *server_info, SSL *ssl)
{
	BIO_METHOD *bio_method_alloc = NULL;
	BIO_METHOD *bio_method = server_info->bio_method;
	BIO *bio = NULL;

	if (ssl == NULL) {
		tlog(TLOG_ERROR, "ssl is null, %s", server_info->ip);
		return -1;
	}

	if (bio_method == NULL) {
		bio_method_alloc = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR, "proxy_tls");
		if (bio_method_alloc == NULL) {
			tlog(TLOG_ERROR, "create bio method failed.");
			return -1;
		}

		bio_method = bio_method_alloc;
		BIO_meth_set_write(bio_method, _proxy_bio_write);
		BIO_meth_set_read(bio_method, _proxy_bio_read);
		BIO_meth_set_ctrl(bio_method, _proxy_bio_ctrl);
		BIO_meth_set_create(bio_method, _proxy_bio_create);
		BIO_meth_set_destroy(bio_method, _proxy_bio_destroy);
	}

	bio = BIO_new(bio_method);
	if (bio == NULL) {
		tlog(TLOG_ERROR, "create bio failed.");
		if (bio_method_alloc) {
			BIO_meth_free(bio_method_alloc);
		}
		return -1;
	}
	BIO_set_data(bio, (void *)server_info);
	BIO_set_init(bio, 1);

	SSL_set_bio(ssl, bio, bio);
	server_info->bio_method = bio_method;
	return 0;
}

/* QUIC BIO implementation for proxy - copied from bak */
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)

static int _dns_client_quic_bio_recvmmsg(BIO *bio, BIO_MSG *msg, size_t stride, size_t num_msg, uint64_t flags,
										 size_t *msgs_processed)
{
	struct dns_server_info *server_info = NULL;
	int total_len = 0;
	int len = 0;
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);

	*msgs_processed = 0;
	server_info = (struct dns_server_info *)BIO_get_data(bio);
	if (server_info == NULL) {
		tlog(TLOG_ERROR, "server info is null.");
		return 0;
	}

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

			if (errno == EPIPE || errno == ECONNRESET) {
				/* Ignore broken pipe and connection reset errors */
				tlog(TLOG_DEBUG, "recvmsg broken pipe or connection reset, %s", server_info->ip);
				return total_len;
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

			if (errno == EPIPE || errno == ECONNRESET) {
				/* Ignore broken pipe and connection reset errors */
				tlog(TLOG_DEBUG, "sendmsg broken pipe or connection reset, %s", server_info->ip);
				return total_len;
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

static int _dns_client_setup_quic_ssl_bio(struct dns_server_info *server_info, SSL *ssl)
{
	BIO_METHOD *bio_method_alloc = NULL;
	BIO_METHOD *bio_method = server_info->bio_method;
	BIO *udp_socket_bio = NULL;

	if (ssl == NULL) {
		tlog(TLOG_ERROR, "ssl is null, %s", server_info->ip);
		return -1;
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

int _dns_client_setup_proxy_bio(struct dns_server_info *server_info, SSL *ssl, int fd)
{

	if (ssl != NULL && fd >= 0) {
		if (SSL_set_fd(ssl, fd) == 0) {
			tlog(TLOG_ERROR, "ssl set fd failed.");
			return -1;
		}

		return 0;
	}

	if (server_info == NULL || ssl == NULL) {
		return -1;
	}

	if (server_info->type == DNS_SERVER_HTTP3 || server_info->type == DNS_SERVER_QUIC) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
		return _dns_client_setup_quic_ssl_bio(server_info, ssl);
#else
		return -1;
#endif
	} else {
		return _dns_client_setup_tcp_ssl_bio(server_info, ssl);
	}
}
