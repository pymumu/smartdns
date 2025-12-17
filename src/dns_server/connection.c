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
#include "server_http2.h"

#include "smartdns/http2.h"

#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

int _dns_server_epoll_ctl(struct dns_server_conn_head *head, int op, uint32_t events)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = events;
	event.data.ptr = head;

	if (epoll_ctl(server.epoll_fd, op, head->fd, &event) != 0) {
		return -1;
	}

	return 0;
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

	if (conn->type == DNS_CONN_TYPE_TLS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)conn;
		if (tls_client->ssl != NULL) {
			SSL_free(tls_client->ssl);
			tls_client->ssl = NULL;
		}

		if (tls_client->http2_ctx != NULL) {
			http2_ctx_put(tls_client->http2_ctx);
			tls_client->http2_ctx = NULL;
		}
		pthread_mutex_destroy(&tls_client->ssl_lock);
	} else if (conn->type == DNS_CONN_TYPE_TLS_SERVER || conn->type == DNS_CONN_TYPE_HTTPS_SERVER) {
		struct dns_server_conn_tls_server *tls_server = (struct dns_server_conn_tls_server *)conn;
		if (tls_server->ssl_ctx != NULL) {
			SSL_CTX_free(tls_server->ssl_ctx);
			tls_server->ssl_ctx = NULL;
		}
	} else if (conn->type == DNS_CONN_TYPE_HTTP2_STREAM) {
		struct dns_server_conn_http2_stream *http2_stream = (struct dns_server_conn_http2_stream *)conn;
		if (http2_stream->stream != NULL) {
			http2_stream_close(http2_stream->stream);
			http2_stream->stream = NULL;
		}
	}

	if (conn->fd > 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	pthread_mutex_lock(&server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&server.conn_list_lock);
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
		/* Force cleanup of TLS/HTTPS client connections to prevent memory leaks */
		if (conn->type == DNS_CONN_TYPE_TLS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
			struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)conn;

			/* Free SSL connection */
			if (tls_client->ssl != NULL) {
				SSL_free(tls_client->ssl);
				tls_client->ssl = NULL;
			}
		}

		_dns_server_client_close(conn);
	}
	pthread_mutex_unlock(&server.conn_list_lock);
}

void _dns_server_close_socket_server(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;

	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		switch (conn->type) {
		case DNS_CONN_TYPE_HTTPS_SERVER:
		case DNS_CONN_TYPE_TLS_SERVER: {
			struct dns_server_conn_tls_server *tls_server = (struct dns_server_conn_tls_server *)conn;
			if (tls_server->ssl_ctx) {
				SSL_CTX_free(tls_server->ssl_ctx);
				tls_server->ssl_ctx = NULL;
			}
			_dns_server_client_close(conn);
			break;
		}
		case DNS_CONN_TYPE_UDP_SERVER:
		case DNS_CONN_TYPE_TCP_SERVER:
			_dns_server_client_close(conn);
			break;
		default:
			break;
		}
	}
}

void _dns_server_client_touch(struct dns_server_conn_head *conn)
{
	time(&conn->last_request_time);
}

int _dns_server_client_close(struct dns_server_conn_head *conn)
{
	if (conn->fd > 0) {
		_dns_server_epoll_ctl(conn, EPOLL_CTL_DEL, 0);
	}

	pthread_mutex_lock(&server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&server.conn_list_lock);

	if (conn->type == DNS_CONN_TYPE_TLS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)conn;
		if (tls_client->http2_ctx != NULL) {
			http2_ctx_close(tls_client->http2_ctx);
			tls_client->http2_ctx = NULL;
		}
	}

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
	case DNS_CONN_TYPE_TCP_CLIENT: {
		struct dns_server_conn_tcp_client *tcpclient = (struct dns_server_conn_tcp_client *)conn;
		tcpclient->conn_idle_timeout = timeout;
	} break;
	case DNS_CONN_TYPE_TLS_CLIENT:
	case DNS_CONN_TYPE_HTTPS_CLIENT: {
		struct dns_server_conn_tls_client *tlsclient = (struct dns_server_conn_tls_client *)conn;
		tlsclient->tcp.conn_idle_timeout = timeout;
	} break;
	default:
		break;
	}

	return 0;
}

void _dns_server_conn_head_init(struct dns_server_conn_head *conn, int fd, int type)
{
	memset(conn, 0, sizeof(*conn));
	conn->fd = fd;
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
