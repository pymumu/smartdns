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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "server_gsocket.h"

#include "connection.h"
#include "dns_server.h"
#include "server_gsocket_proto.h"
#include "server_gsocket_stream.h"

#include <errno.h>
#include <string.h>

static int _dns_server_gsocket_tcp_recv(struct dns_server_conn_gsocket *conn)
{
	while (conn->recvbuff.size < (int)sizeof(conn->recvbuff.buf)) {
		ssize_t len = gsocket_recv(conn->head.gs, conn->recvbuff.buf + conn->recvbuff.size,
								   sizeof(conn->recvbuff.buf) - conn->recvbuff.size, MSG_NOSIGNAL);
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}
			return RECV_ERROR_FAIL;
		}
		if (len == 0) {
			return RECV_ERROR_CLOSE;
		}
		conn->recvbuff.size += (int)len;
	}
	return 0;
}

static int _dns_server_gsocket_tcp_process(struct dns_server_conn_gsocket *conn)
{
	while (conn->recvbuff.size >= 2) {
		unsigned char *buf = conn->recvbuff.buf;
		unsigned short pktlen = (unsigned short)ntohs(*(unsigned short *)buf);
		if (pktlen <= 0 || pktlen >= DNS_IN_PACKSIZE) {
			return RECV_ERROR_INVALID_PACKET;
		}
		if (conn->recvbuff.size < 2 + pktlen) {
			break;
		}

		int ret = _dns_server_recv(&conn->head, buf + 2, pktlen, &conn->localaddr, conn->localaddr_len, &conn->addr,
								   conn->addr_len);
		if (ret != 0 && ret != RECV_ERROR_INVALID_PACKET) {
			return RECV_ERROR_FAIL;
		}

		int consumed = 2 + pktlen;
		if (conn->recvbuff.size > consumed) {
			memmove(conn->recvbuff.buf, conn->recvbuff.buf + consumed, conn->recvbuff.size - consumed);
		}
		conn->recvbuff.size -= consumed;
		_dns_server_client_touch(&conn->head);
	}
	return 0;
}

static int _dns_server_gsocket_tcp_send_buffered(struct dns_server_conn_gsocket *conn)
{
	if (conn->sndbuff.size <= 0) {
		return 0;
	}
	ssize_t sent = gsocket_send(conn->head.gs, conn->sndbuff.buf, conn->sndbuff.size, MSG_NOSIGNAL);
	if (sent < 0) {
		if (errno == EAGAIN) {
			return 0;
		}
		return -1;
	}
	if (sent < conn->sndbuff.size) {
		memmove(conn->sndbuff.buf, conn->sndbuff.buf + sent, conn->sndbuff.size - sent);
	}
	conn->sndbuff.size -= (int)sent;
	if (conn->sndbuff.size == 0) {
		gepoll_mod(server.gepoll, conn->head.gs, EPOLLIN, conn);
	}
	return 0;
}

static int _dns_server_gsocket_drive_client_handshake(struct dns_server_conn_gsocket *conn)
{
	struct dns_gsocket_conn gconn;
	int ev_flags = 0;
	int hs = 0;

	dns_gsocket_conn_init(&gconn, DNS_GSOCKET_SERVER_CLIENT, dns_server_gsocket_proto_get(conn->head.type), conn);
	gconn.gs = conn->head.gs;

	hs = dns_gsocket_driver_handshake(&gconn, &ev_flags);
	if (hs < 0) {
		return -1;
	}

	if (hs == 0) {
		gepoll_mod(server.gepoll, conn->head.gs, ev_flags, conn);
		return 0;
	}

	return 1;
}

static int _dns_server_gsocket_process_tcp_client_events(struct dns_server_conn_gsocket *conn, int events)
{
	if (events & EPOLLOUT) {
		if (_dns_server_gsocket_tcp_send_buffered(conn) != 0) {
			return -1;
		}
	}

	if (events & EPOLLIN) {
		int ret = _dns_server_gsocket_tcp_recv(conn);
		if (ret == RECV_ERROR_CLOSE || ret == RECV_ERROR_FAIL) {
			return -1;
		}

		ret = _dns_server_gsocket_tcp_process(conn);
		if (ret != 0 && ret != RECV_ERROR_INVALID_PACKET) {
			return -1;
		}
	}

	return 0;
}

int _dns_server_gsocket_process_client(struct dns_server_conn_gsocket *conn, struct gepoll_event *event,
									   unsigned long now)
{
	int events = event ? event->events : 0;

	int hs_state = _dns_server_gsocket_drive_client_handshake(conn);
	if (hs_state < 0) {
		_dns_server_client_close(&conn->head);
		return 0;
	}
	if (hs_state == 0) {
		return 0;
	}

	if (dns_server_gsocket_proto_client_needs_stream_poll(conn->head.type)) {
		if (dns_server_gstream_process_client_events(conn) != 0) {
			_dns_server_client_close(&conn->head);
			return 0;
		}
	} else {
		if (_dns_server_gsocket_process_tcp_client_events(conn, events) != 0) {
			_dns_server_client_close(&conn->head);
			return 0;
		}
	}

	(void)now;
	return 0;
}

void _dns_server_gsocket_tcp_idle_check(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;
	time_t now = 0;
	time(&now);

	pthread_mutex_lock(&server.conn_list_lock);
	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		if (!dns_server_gsocket_proto_is_idle_client(conn->type)) {
			continue;
		}
		struct dns_server_conn_gsocket *gclient = (struct dns_server_conn_gsocket *)conn;
		if (gclient->conn_idle_timeout <= 0) {
			continue;
		}
		if (conn->last_request_time > now - gclient->conn_idle_timeout) {
			continue;
		}
		_dns_server_client_close(conn);
	}
	pthread_mutex_unlock(&server.conn_list_lock);
}
