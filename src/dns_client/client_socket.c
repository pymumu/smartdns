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
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}
