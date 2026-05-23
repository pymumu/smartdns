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

#include "connection.h"
#include "dns_server.h"
#include "server_gsocket.h"
#include "server_gsocket_stream.h"

#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"

#include <sys/eventfd.h>

/* Gepoll-based epoll_ctl shim – kept for dns_server.c call-sites that still
 * use EPOLL_CTL_ADD/MOD/DEL semantics.  op == EPOLL_CTL_DEL ignores events. */
int _dns_server_epoll_ctl(struct dns_server_conn_head *head, int op, uint32_t events)
{
	if (head == NULL || head->gs == NULL || server.gepoll == NULL) {
		return -1;
	}

	switch (op) {
	case EPOLL_CTL_ADD:
		return gepoll_add(server.gepoll, head->gs, events, head);
	case EPOLL_CTL_MOD:
		return gepoll_mod(server.gepoll, head->gs, events, head);
	case EPOLL_CTL_DEL:
		return gepoll_del(server.gepoll, head->gs);
	default:
		return -1;
	}
}

void _dns_server_conn_release(struct dns_server_conn_head *conn)
{
	if (conn == NULL) {
		return;
	}

	int refcnt = atomic_dec_return(&conn->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			BUG("BUG: refcnt is %d, type = %d", refcnt, conn->type);
		}
		return;
	}

	struct dns_server_conn_head *parent = NULL;
	if (conn->type == DNS_CONN_TYPE_HTTP2_STREAM || conn->type == DNS_CONN_TYPE_QUIC_STREAM) {
		parent = &((struct dns_server_conn_stream *)conn)->parent->head;
	}

	/* Close and free the gsocket */
	if (conn->gs != NULL) {
		if (conn->type == DNS_CONN_TYPE_TCP_CLIENT || conn->type == DNS_CONN_TYPE_TLS_CLIENT ||
			conn->type == DNS_CONN_TYPE_HTTPS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS3_CLIENT ||
			conn->type == DNS_CONN_TYPE_QUIC_CLIENT) {
			struct dns_server_conn_gsocket *gclient = (struct dns_server_conn_gsocket *)conn;
			if (gclient->sp != NULL) {
				dns_server_gstream_poll_destroy(gclient);
			}
		}
		gsocket_close(conn->gs);
		gsocket_free(conn->gs);
		conn->gs = NULL;
	}

	pthread_mutex_lock(&server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&server.conn_list_lock);
	if (parent != NULL) {
		_dns_server_conn_release(parent);
	}
	free(conn);
}

void _dns_server_conn_get(struct dns_server_conn_head *conn)
{
	if (conn == NULL) {
		return;
	}

	if (atomic_inc_return(&conn->refcnt) <= 0) {
		BUG("BUG: client ref is invalid.");
	}
}

void _dns_server_close_socket(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;

	pthread_mutex_lock(&server.conn_list_lock);
	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		_dns_server_client_close(conn);
	}
	pthread_mutex_unlock(&server.conn_list_lock);
}

void _dns_server_close_socket_server(void)
{
	/* Close all listener sockets via server_gsocket helper */
	_dns_server_gsocket_close_listeners();

	/* Also close UDP server conns in conn_list */
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;
	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		if (conn->type == DNS_CONN_TYPE_UDP_SERVER) {
			_dns_server_client_close(conn);
		}
	}
}

void _dns_server_client_touch(struct dns_server_conn_head *conn)
{
	time(&conn->last_request_time);
}

int _dns_server_client_close(struct dns_server_conn_head *conn)
{
	if (conn->gs != NULL && server.gepoll != NULL) {
		gepoll_del(server.gepoll, conn->gs);
	}

	pthread_mutex_lock(&server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&server.conn_list_lock);

	_dns_server_conn_release(conn);

	return 0;
}

int _dns_server_update_request_connection_timeout(struct dns_server_conn_head *conn, int timeout)
{
	if (conn == NULL) {
		return -1;
	}

	if (timeout == 0) {
		return 0;
	}

	switch (conn->type) {
	case DNS_CONN_TYPE_TCP_CLIENT:
	case DNS_CONN_TYPE_TLS_CLIENT:
	case DNS_CONN_TYPE_HTTPS_CLIENT:
	case DNS_CONN_TYPE_HTTPS3_CLIENT:
	case DNS_CONN_TYPE_QUIC_CLIENT: {
		struct dns_server_conn_gsocket *gclient = (struct dns_server_conn_gsocket *)conn;
		gclient->conn_idle_timeout = timeout;
	} break;
	default:
		break;
	}

	return 0;
}

void _dns_server_conn_head_init(struct dns_server_conn_head *conn, struct gsocket *gs, int type)
{
	memset(conn, 0, sizeof(*conn));
	conn->gs = gs;
	conn->type = type;
	atomic_set(&conn->refcnt, 0);
	INIT_LIST_HEAD(&conn->list);
}

int _dns_server_set_flags(struct dns_server_conn_head *head, struct dns_bind_ip *bind_ip)
{
	time(&head->last_request_time);
	head->server_flags = bind_ip->flags;
	head->dns_group = bind_ip->group;
	head->ipset_nftset_rule = &bind_ip->nftset_ipset_rule;
	atomic_set(&head->refcnt, 0);
	list_add(&head->list, &server.conn_list);

	return 0;
}
