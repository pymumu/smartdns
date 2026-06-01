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

#include "smartdns/dns_conf.h"
#include "smartdns/util.h"

#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string.h>
#include <time.h>

static void _dns_server_gsocket_free_gsocket(struct gsocket **gs)
{
	if (gs == NULL || *gs == NULL) {
		return;
	}

	gsocket_close(*gs);
	gsocket_free(*gs);
	*gs = NULL;
}

static void _dns_server_gsocket_process_udp_multiplex_clients(void)
{
	struct dns_server_conn_head *clients[DNS_MAX_EVENTS];
	struct dns_server_conn_head *conn = NULL;
	int count = 0;
	int i = 0;
	unsigned long now = get_tick_count();

	pthread_mutex_lock(&server.conn_list_lock);
	list_for_each_entry(conn, &server.conn_list, list)
	{
		if (!dns_server_gsocket_proto_is_udp_multiplex_client(conn->type)) {
			continue;
		}

		_dns_server_conn_get(conn);
		clients[count++] = conn;
		if (count >= DNS_MAX_EVENTS) {
			break;
		}
	}
	pthread_mutex_unlock(&server.conn_list_lock);

	for (i = 0; i < count; i++) {
		struct dns_server_conn_gsocket *gclient = (struct dns_server_conn_gsocket *)clients[i];

		_dns_server_gsocket_process_client(gclient, NULL, now);
		_dns_server_conn_release(clients[i]);
	}
}

static void _dns_server_gsocket_free_unlisted_conn(struct dns_server_conn_gsocket *conn)
{
	if (conn == NULL) {
		return;
	}

	dns_server_gstream_poll_destroy(conn);
	_dns_server_gsocket_free_gsocket(&conn->head.gs);
	free(conn);
}

static struct dns_server_conn_gsocket *_dns_server_gsocket_new_client(struct dns_server_listener *listener,
																	  struct gsocket *client_gs,
																	  DNS_CONN_TYPE client_type)
{
	struct dns_server_conn_gsocket *conn = zalloc(1, sizeof(*conn));
	if (!conn) {
		return NULL;
	}

	conn->head.type = client_type;
	conn->head.gs = client_gs;
	conn->head.server_flags = listener->head.server_flags;
	conn->head.dns_group = listener->head.dns_group;
	conn->head.ipset_nftset_rule = listener->head.ipset_nftset_rule;
	conn->conn_idle_timeout = dns_conf.tcp_idle_time;
	conn->localaddr_len = sizeof(conn->localaddr);
	atomic_set(&conn->head.refcnt, 0);
	INIT_LIST_HEAD(&conn->head.list);
	INIT_LIST_HEAD(&conn->pending_stream_list);
	time(&conn->head.last_request_time);

	return conn;
}

static int _dns_server_gsocket_init_stream_poll(struct dns_server_conn_gsocket *conn, struct gsocket *gs)
{
	conn->sp = gstream_poll_create(gs);
	if (conn->sp == NULL) {
		return -1;
	}

	if (gstream_poll_add(conn->sp, gs, POLLIN, conn) != 0) {
		gstream_poll_destroy(conn->sp);
		conn->sp = NULL;
		return -1;
	}

	return 0;
}

static void _dns_server_gsocket_activate_client(struct dns_server_conn_gsocket *conn)
{
	pthread_mutex_lock(&server.conn_list_lock);
	list_add(&conn->head.list, &server.conn_list);
	pthread_mutex_unlock(&server.conn_list_lock);
	_dns_server_conn_get(&conn->head);
}

static int _dns_server_gsocket_process_quic_listener(struct dns_server_listener *listener, unsigned long now)
{
	gsocket_handshake(listener->head.gs);

	while (1) {
		struct sockaddr_storage addr = {0};
		socklen_t addr_len = sizeof(addr);
		struct gsocket *conn_gs = gsocket_accept(listener->head.gs, (struct sockaddr *)&addr, &addr_len);
		if (!conn_gs) {
			break;
		}
		gsocket_set_nonblock(conn_gs, 1);
		gsocket_handshake(conn_gs);

		DNS_CONN_TYPE client_type;
		if (dns_server_gsocket_proto_get_client_type(listener->head.type, &client_type) != 0) {
			_dns_server_gsocket_free_gsocket(&conn_gs);
			continue;
		}
		struct dns_server_conn_gsocket *conn = _dns_server_gsocket_new_client(listener, conn_gs, client_type);
		if (!conn) {
			_dns_server_gsocket_free_gsocket(&conn_gs);
			continue;
		}

		if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
			memcpy(&conn->addr, &addr, addr_len);
			conn->addr_len = addr_len;
		}
		conn->localaddr_len = sizeof(conn->localaddr);
		if (gsocket_getsockname(listener->head.gs, (struct sockaddr *)&conn->localaddr, &conn->localaddr_len) != 0) {
			memset(&conn->localaddr, 0, sizeof(conn->localaddr));
			conn->localaddr_len = 0;
		}

		if (_dns_server_gsocket_init_stream_poll(conn, conn_gs) != 0) {
			_dns_server_gsocket_free_unlisted_conn(conn);
			continue;
		}

		_dns_server_gsocket_activate_client(conn);
		_dns_server_gsocket_process_client(conn, NULL, now);
	}

	_dns_server_gsocket_process_udp_multiplex_clients();
	return 0;
}

int _dns_server_gsocket_process_listener(struct dns_server_conn_head *head, struct gepoll_event *event,
										 unsigned long now)
{
	struct dns_server_listener *listener = (struct dns_server_listener *)head;

	if (dns_server_gsocket_proto_is_quic_listener(head->type)) {
		return _dns_server_gsocket_process_quic_listener(listener, now);
	}

	(void)event;
	while (1) {
		struct sockaddr_storage addr = {0};
		socklen_t addr_len = sizeof(addr);
		struct gsocket *client_gs = gsocket_accept(listener->head.gs, (struct sockaddr *)&addr, &addr_len);
		if (!client_gs) {
			break;
		}

		gsocket_set_nonblock(client_gs, 1);
		int no_delay = 1;
		setsockopt(gsocket_get_fd(client_gs), IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay));
		set_sock_keepalive(gsocket_get_fd(client_gs), 30, 3, 5);

		DNS_CONN_TYPE client_type;
		if (dns_server_gsocket_proto_get_client_type(head->type, &client_type) != 0) {
			_dns_server_gsocket_free_gsocket(&client_gs);
			continue;
		}

		struct dns_server_conn_gsocket *conn = _dns_server_gsocket_new_client(listener, client_gs, client_type);
		if (!conn) {
			_dns_server_gsocket_free_gsocket(&client_gs);
			continue;
		}

		memcpy(&conn->addr, &addr, addr_len);
		conn->addr_len = addr_len;
		getsocket_inet(gsocket_get_fd(client_gs), (struct sockaddr *)&conn->localaddr, &conn->localaddr_len);

		if (dns_server_gsocket_proto_client_needs_stream_poll(client_type)) {
			if (_dns_server_gsocket_init_stream_poll(conn, client_gs) != 0) {
				_dns_server_gsocket_free_unlisted_conn(conn);
				continue;
			}
		}

		struct dns_gsocket_conn gconn;
		int ev_flags = EPOLLIN;
		int hs = 0;

		dns_gsocket_conn_init(&gconn, DNS_GSOCKET_SERVER_CLIENT, dns_server_gsocket_proto_get(client_type), conn);
		gconn.gs = client_gs;
		hs = dns_gsocket_driver_handshake(&gconn, &ev_flags);
		if (hs < 0) {
			_dns_server_gsocket_free_unlisted_conn(conn);
			continue;
		}

		if (gepoll_add(server.gepoll, client_gs, ev_flags, conn) != 0) {
			_dns_server_gsocket_free_unlisted_conn(conn);
			continue;
		}

		_dns_server_gsocket_activate_client(conn);
	}

	return 0;
}

void _dns_server_gsocket_close_listeners(void)
{
	struct dns_server_listener *l = NULL;
	struct dns_server_listener *tmp = NULL;

	list_for_each_entry_safe(l, tmp, &server.listener_list, list)
	{
		list_del_init(&l->list);
		if (l->head.gs) {
			if (server.gepoll) {
				gepoll_del(server.gepoll, l->head.gs);
			}
			_dns_server_gsocket_free_gsocket(&l->head.gs);
		}
		if (l->ssl_ctx) {
			SSL_CTX_free((SSL_CTX *)l->ssl_ctx);
			l->ssl_ctx = NULL;
		}
		free(l);
	}
}
