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

#include "client_gsocket.h"

#include "client_gsocket_proto.h"
#include "client_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <time.h>

int _dns_client_process_tcp_recv(struct dns_server_info *server_info)
{
	/* Drain all complete 2-byte-framed DNS messages from recv_buff */
	while (1) {
		if (server_info->recv_buff.len < 2) {
			break;
		}

		unsigned short msg_len = ntohs(*((unsigned short *)server_info->recv_buff.data));
		if (server_info->recv_buff.len < (int)(2 + msg_len)) {
			break;
		}

		/* Process one complete DNS message */
		unsigned char *data = server_info->recv_buff.data + 2;
		struct sockaddr *addr = &server_info->addr;
		socklen_t addr_len = server_info->ai_addrlen;

		if (_dns_client_recv(server_info, data, msg_len, addr, addr_len) != 0) {
			tlog(TLOG_DEBUG, "process tcp recv failed for %s", server_info->ip);
		}

		/* Consume the processed message */
		int total = 2 + msg_len;
		server_info->recv_buff.len -= total;
		if (server_info->recv_buff.len > 0) {
			memmove(server_info->recv_buff.data, server_info->recv_buff.data + total, server_info->recv_buff.len);
		}
	}
	return 0;
}

int _dns_client_process_tcp(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now)
{
	int len;
	struct dns_client_close_error close_error = {"tcp process error", 0};

	pthread_mutex_lock(&server_info->lock);

	if (server_info->gs == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return -1;
	}

	/* Drive proxy/SSL handshake (SOCKS5, HTTP-proxy, etc.) before data transfer */
	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		struct dns_gsocket_conn conn;
		int ev_flags = 0;
		int hs = 0;

		dns_gsocket_conn_init(&conn, DNS_GSOCKET_CLIENT, dns_client_gsocket_proto_get(server_info->type),
							  server_info);
		conn.gs = server_info->gs;
		conn.status = server_info->status;

		hs = dns_gsocket_driver_handshake(&conn, &ev_flags);
		if (hs < 0) {
			_dns_client_set_close_error(&close_error, "tcp handshake error", errno);
			goto errout;
		}
		if (hs == 0) {
			gepoll_mod(client.gepoll, server_info->gs, ev_flags, server_info);
			pthread_mutex_unlock(&server_info->lock);
			return 0;
		}
		server_info->status = DNS_SERVER_STATUS_CONNECTED;
		server_info->proxy_attempt = 0;
		tlog(TLOG_DEBUG, "tcp server %s connected", server_info->ip);
		/* Handshake just completed: flush any queued send data immediately */
		if (server_info->send_buff.len > 0) {
			len = _dns_client_socket_tcp_send(server_info);
			if (len < 0 && errno != EAGAIN) {
				_dns_client_set_close_error(&close_error, "tcp flush after handshake error", errno);
				goto errout;
			}
			if (server_info->send_buff.len > 0) {
				gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
			}
		}
	}

	if (event->events & EPOLLOUT) {
		/* Flush buffered send data */
		if (server_info->send_buff.len > 0) {
			len = _dns_client_socket_tcp_send(server_info);
			if (len < 0 && errno != EAGAIN) {
				_dns_client_set_close_error(&close_error, "tcp epollout send error", errno);
				goto errout;
			}
		}

		/* Switch to EPOLLIN only when send buffer is drained */
		if (server_info->send_buff.len == 0) {
			gepoll_mod(client.gepoll, server_info->gs, EPOLLIN, server_info);
		}
	}

	if (event->events & EPOLLIN) {
		len = _dns_client_socket_tcp_recv(server_info);
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				pthread_mutex_unlock(&server_info->lock);
				return 0;
			}
			_dns_client_set_close_error(&close_error, "tcp recv error", errno);
			goto errout;
		}

		if (len == 0) {
			/* Peer closed - must release server_info->lock before taking server_list_lock */
			pthread_mutex_unlock(&server_info->lock);
			pthread_mutex_lock(&client.server_list_lock);
			DNS_CLIENT_CLOSE_SOCKET_REASON(server_info, "tcp recv peer closed", ECONNRESET);
			server_info->recv_buff.len = 0;
			int ret = 0;
			if (server_info->send_buff.len > 0) {
				ret = _dns_client_create_socket(server_info);
			}
			pthread_mutex_unlock(&client.server_list_lock);
			return ret;
		}

		server_info->recv_buff.len += len;
		time(&server_info->last_recv);
		pthread_mutex_unlock(&server_info->lock);
		_dns_client_process_tcp_recv(server_info);
		return 0;
	}

	pthread_mutex_unlock(&server_info->lock);
	return 0;

errout:
	pthread_mutex_unlock(&server_info->lock);
	pthread_mutex_lock(&client.server_list_lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	DNS_CLIENT_CLOSE_SOCKET_REASON(server_info, close_error.reason, close_error.err);
	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

int _dns_client_send_tcp(struct dns_server_info *server_info, void *packet, int len)
{
	if (server_info->gs == NULL) {
		errno = EBADF;
		return -1;
	}

	/* Prepend 2-byte length for DNS-over-TCP */
	unsigned short pkt_len = htons((unsigned short)len);

	/* Build framed message into send_buff */
	if (DNS_TCP_BUFFER - server_info->send_buff.len < (int)(2 + len)) {
		errno = ENOMEM;
		return -1;
	}

	unsigned char *dst = server_info->send_buff.data + server_info->send_buff.len;
	memcpy(dst, &pkt_len, 2);
	memcpy(dst + 2, packet, len);
	server_info->send_buff.len += 2 + len;

	/* Don't send immediately if we're still doing the proxy/SSL handshake */
	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
		return 0;
	}

	/* Try to send immediately - take server_info->lock to serialise with the
	 * client work-thread which also calls _dns_client_socket_tcp_send() */
	pthread_mutex_lock(&server_info->lock);
	int ret = _dns_client_socket_tcp_send(server_info);
	pthread_mutex_unlock(&server_info->lock);
	if (ret < 0 && errno == EAGAIN) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
		return 0;
	}
	if (ret < 0) {
		return -1;
	}

	if (server_info->send_buff.len > 0) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
	}

	return 0;
}

void _dns_client_check_tcp(void)
{
	struct dns_server_info *server_info = NULL;
	time_t now = 0;

	time(&now);

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(server_info, &client.dns_server_list, list)
	{
		if (server_info->type == DNS_SERVER_UDP || server_info->type == DNS_SERVER_MDNS) {
			continue;
		}

		if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
			if (server_info->last_recv + DNS_TCP_CONNECT_TIMEOUT < now) {
				DNS_CLIENT_CLOSE_SOCKET_REASON(server_info, "tcp connect timeout", ETIMEDOUT);
			}
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}
