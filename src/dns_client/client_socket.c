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

#include "client_socket.h"
#include "client_http3.h"
#include "client_https.h"
#include "client_mdns.h"
#include "client_quic.h"
#include "client_tcp.h"
#include "client_tls.h"
#include "client_udp.h"
#include "conn_stream.h"

#include <openssl/ssl.h>
#include <sys/epoll.h>

int _dns_client_create_socket(struct dns_server_info *server_info)
{
	time(&server_info->last_send);
	time(&server_info->last_recv);

	if (server_info->fd > 0) {
		return -1;
	}

	if (server_info->type == DNS_SERVER_UDP) {
		return _dns_client_create_socket_udp(server_info);
	} else if (server_info->type == DNS_SERVER_MDNS) {
		return _dns_client_create_socket_udp_mdns(server_info);
	} else if (server_info->type == DNS_SERVER_TCP) {
		return _dns_client_create_socket_tcp(server_info);
	} else if (server_info->type == DNS_SERVER_TLS) {
		struct client_dns_server_flag_tls *flag_tls = NULL;
		flag_tls = &server_info->flags.tls;
		return _dns_client_create_socket_tls(server_info, flag_tls->hostname, flag_tls->alpn);
	} else if (server_info->type == DNS_SERVER_QUIC) {
		struct client_dns_server_flag_tls *flag_tls = NULL;
		const char *alpn = "doq";
		flag_tls = &server_info->flags.tls;
		if (flag_tls->alpn[0] != 0) {
			alpn = flag_tls->alpn;
		}
		return _dns_client_create_socket_quic(server_info, flag_tls->hostname, alpn);
	} else if (server_info->type == DNS_SERVER_HTTPS) {
		struct client_dns_server_flag_https *flag_https = NULL;
		flag_https = &server_info->flags.https;
		return _dns_client_create_socket_tls(server_info, flag_https->hostname, flag_https->alpn);
	} else if (server_info->type == DNS_SERVER_HTTP3) {
		struct client_dns_server_flag_https *flag_https = NULL;
		const char *alpn = "h3";
		flag_https = &server_info->flags.https;
		if (flag_https->alpn[0] != 0) {
			alpn = flag_https->alpn;
		}
		return _dns_client_create_socket_quic(server_info, flag_https->hostname, alpn);
	} else {
		return -1;
	}

	return 0;
}

void _dns_client_close_socket_ext(struct dns_server_info *server_info, int no_del_conn_list)
{
	if (server_info->ssl) {
		/* Shutdown ssl */
		if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
			_ssl_shutdown(server_info);
		}

		if (server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
			struct dns_conn_stream *conn_stream = NULL;
			struct dns_conn_stream *tmp = NULL;

			pthread_mutex_lock(&server_info->lock);
			list_for_each_entry_safe(conn_stream, tmp, &server_info->conn_stream_list, server_list)
			{
				if (conn_stream->quic_stream) {
#ifdef OSSL_QUIC1_VERSION
					SSL_stream_reset(conn_stream->quic_stream, NULL, 0);
#endif
					SSL_free(conn_stream->quic_stream);
					conn_stream->quic_stream = NULL;
				}

				if (no_del_conn_list == 1) {
					continue;
				}

				conn_stream->server_info = NULL;
				list_del_init(&conn_stream->server_list);
				_dns_client_conn_stream_put(conn_stream);
			}

			pthread_mutex_unlock(&server_info->lock);
		}

		SSL_free(server_info->ssl);
		server_info->ssl = NULL;
		server_info->ssl_write_len = -1;
	}

	if (server_info->bio_method) {
		BIO_meth_free(server_info->bio_method);
		server_info->bio_method = NULL;
	}

	if (server_info->fd <= 0) {
		return;
	}

	/* remove fd from epoll */
	if (server_info->fd > 0) {
		epoll_ctl(client.epoll_fd, EPOLL_CTL_DEL, server_info->fd, NULL);
	}

	if (server_info->proxy) {
		proxy_conn_free(server_info->proxy);
		server_info->proxy = NULL;
	} else {
		close(server_info->fd);
	}

	server_info->fd = -1;
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
	/* update send recv time */
	time(&server_info->last_send);
	time(&server_info->last_recv);
	tlog(TLOG_DEBUG, "server %s:%d closed.", server_info->ip, server_info->port);
}

void _dns_client_close_socket(struct dns_server_info *server_info)
{
	_dns_client_close_socket_ext(server_info, 0);
}

void _dns_client_shutdown_socket(struct dns_server_info *server_info)
{
	if (server_info->fd <= 0) {
		return;
	}

	switch (server_info->type) {
	case DNS_SERVER_UDP:
		server_info->status = DNS_SERVER_STATUS_CONNECTING;
		atomic_set(&server_info->is_alive, 0);
		return;
		break;
	case DNS_SERVER_TCP:
		if (server_info->fd > 0) {
			shutdown(server_info->fd, SHUT_RDWR);
		}
		break;
	case DNS_SERVER_QUIC:
	case DNS_SERVER_TLS:
	case DNS_SERVER_HTTP3:
	case DNS_SERVER_HTTPS:
		if (server_info->ssl) {
			/* Shutdown ssl */
			if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
				_ssl_shutdown(server_info);
			}
			shutdown(server_info->fd, SHUT_RDWR);
		}
		atomic_set(&server_info->is_alive, 0);
		break;
	case DNS_SERVER_MDNS:
		break;
	default:
		break;
	}
}

int _dns_client_socket_send(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_UDP) {
		return -1;
	} else if (server_info->type == DNS_SERVER_TCP) {
		return send(server_info->fd, server_info->send_buff.data, server_info->send_buff.len, MSG_NOSIGNAL);
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS ||
			   server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
		int write_len = server_info->send_buff.len;
		if (server_info->ssl_write_len > 0) {
			write_len = server_info->ssl_write_len;
			server_info->ssl_write_len = -1;
		}
		server_info->ssl_want_write = 0;

		int ret = _dns_client_socket_ssl_send(server_info, server_info->send_buff.data, write_len);
		if (ret < 0 && errno == EAGAIN) {
			server_info->ssl_write_len = write_len;
			if (_dns_client_ssl_poll_event(server_info, SSL_ERROR_WANT_WRITE) == 0) {
				errno = EAGAIN;
			}
		}
		return ret;
	} else if (server_info->type == DNS_SERVER_MDNS) {
		return -1;
	} else {
		return -1;
	}
}

int _dns_client_socket_recv(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_UDP) {
		return -1;
	} else if (server_info->type == DNS_SERVER_TCP) {
		return recv(server_info->fd, server_info->recv_buff.data + server_info->recv_buff.len,
					DNS_TCP_BUFFER - server_info->recv_buff.len, 0);
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS ||
			   server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
		int ret = _dns_client_socket_ssl_recv(server_info, server_info->recv_buff.data + server_info->recv_buff.len,
											  DNS_TCP_BUFFER - server_info->recv_buff.len);
		if (ret == -SSL_ERROR_WANT_WRITE && errno == EAGAIN) {
			if (_dns_client_ssl_poll_event(server_info, SSL_ERROR_WANT_WRITE) == 0) {
				errno = EAGAIN;
				server_info->ssl_want_write = 1;
			}
		}

		return ret;
	} else if (server_info->type == DNS_SERVER_MDNS) {
		return -1;
	} else {
		return -1;
	}
}

int _dns_client_copy_data_to_buffer(struct dns_server_info *server_info, void *packet, int len)
{
	if (DNS_TCP_BUFFER - server_info->send_buff.len < len) {
		errno = ENOMEM;
		return -1;
	}

	memcpy(server_info->send_buff.data + server_info->send_buff.len, packet, len);
	server_info->send_buff.len += len;

	return 0;
}

int _dns_client_send_data_to_buffer(struct dns_server_info *server_info, void *packet, int len)
{
	struct epoll_event event;

	if (DNS_TCP_BUFFER - server_info->send_buff.len < len) {
		errno = ENOMEM;
		return -1;
	}

	memcpy(server_info->send_buff.data + server_info->send_buff.len, packet, len);
	server_info->send_buff.len += len;

	if (server_info->fd <= 0) {
		errno = ECONNRESET;
		return -1;
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
		if (errno == ENOENT) {
			/* fd not found, ignore */
			return 0;
		}
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}
