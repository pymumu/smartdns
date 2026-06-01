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
#include "client_gsocket_stream.h"
#include "client_socket.h"

#include "smartdns/util.h"

#include <errno.h>
#include <string.h>
#include <time.h>

static void _dns_client_flush_stream_pending(struct dns_server_info *server_info)
{
	dns_client_gstream_pending_flush(server_info);
}

static void _dns_client_tls_close_server(struct dns_server_info *server_info,
										 const struct dns_client_close_error *close_error)
{
	pthread_mutex_lock(&client.server_list_lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	DNS_CLIENT_CLOSE_SOCKET_REASON(server_info, close_error->reason, close_error->err);
	pthread_mutex_unlock(&client.server_list_lock);
}

static int _dns_client_tls_flush_stream_pending_locked(struct dns_server_info *server_info)
{
	int need_close = 0;

	if (list_empty(&server_info->http2_pending_list)) {
		return 0;
	}

	/*
	 * Stream sends open/attach sub-streams and may take server_info->lock.
	 * Mark the connection busy before dropping the lock so close paths defer
	 * freeing the underlying HTTP2/HTTP3/QUIC connection.
	 */
	server_info->gstream_processing++;
	pthread_mutex_unlock(&server_info->lock);
	_dns_client_flush_stream_pending(server_info);
	pthread_mutex_lock(&server_info->lock);

	if (server_info->gstream_processing > 0) {
		server_info->gstream_processing--;
	}
	if (server_info->gstream_processing == 0 && server_info->gstream_close_pending) {
		server_info->gstream_close_pending = 0;
		need_close = 1;
	}
	if (need_close) {
		pthread_mutex_unlock(&server_info->lock);
		_dns_client_close_socket(server_info);
		pthread_mutex_lock(&server_info->lock);
		errno = ECONNRESET;
		return -1;
	}

	if (server_info->gs == NULL) {
		errno = ECONNRESET;
		return -1;
	}

	return 0;
}

static void _dns_client_tls_touch_pending_locked(struct dns_server_info *server_info)
{
	if (list_empty(&server_info->http2_pending_list)) {
		return;
	}

	unsigned long now = get_tick_count();
	struct dns_http2_pending *pend = NULL;
	list_for_each_entry(pend, &server_info->http2_pending_list, list)
	{
		pend->active_tick = now;
	}
}

static void _dns_client_tls_flush_send_buffer_locked(struct dns_server_info *server_info, int rearm_when_pending)
{
	if (server_info->send_buff.len <= 0) {
		return;
	}

	int ret = (int)gsocket_send(server_info->gs, server_info->send_buff.data, server_info->send_buff.len, 0);
	if (ret <= 0) {
		return;
	}

	server_info->send_buff.len -= ret;
	if (server_info->send_buff.len <= 0) {
		return;
	}

	memmove(server_info->send_buff.data, server_info->send_buff.data + ret, server_info->send_buff.len);
	if (rearm_when_pending) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
	}
}

static int _dns_client_tls_get_events_locked(struct dns_server_info *server_info)
{
	int events = EPOLLIN;

	if (server_info->gs == NULL) {
		return events;
	}

	if (server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
		events |= gsocket_get_poll_events(server_info->gs);
		if (server_info->sp != NULL) {
			events |= gstream_poll_get_net_events(server_info->sp);
		}
	}

	if (server_info->send_buff.len > 0 || !list_empty(&server_info->http2_pending_list)) {
		events |= EPOLLOUT;
	}

	return events;
}

static void _dns_client_tls_rearm_locked(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL) {
		return;
	}

	gepoll_mod(client.gepoll, server_info->gs, _dns_client_tls_get_events_locked(server_info), server_info);
}

static int _dns_client_tls_on_handshake_done_locked(struct dns_server_info *server_info)
{
	server_info->status = DNS_SERVER_STATUS_CONNECTED;
	server_info->proxy_attempt = 0;
	tlog(TLOG_DEBUG, "tls/quic server %s connected", server_info->ip);

	if ((server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3 ||
		 server_info->type == DNS_SERVER_HTTPS) &&
		server_info->sp == NULL) {
		server_info->sp = gstream_poll_create(server_info->gs);
	}

	if (_dns_client_tls_flush_stream_pending_locked(server_info) != 0) {
		return -1;
	}

	_dns_client_tls_flush_send_buffer_locked(server_info, 1);
	_dns_client_tls_rearm_locked(server_info);
	return 0;
}

static int _dns_client_tls_drive_handshake_locked(struct dns_server_info *server_info)
{
	struct dns_gsocket_conn conn;
	int ev_flags = 0;
	int hs = 0;

	if (server_info->status != DNS_SERVER_STATUS_CONNECTING) {
		return 1;
	}

	dns_gsocket_conn_init(&conn, DNS_GSOCKET_CLIENT, dns_client_gsocket_proto_get(server_info->type), server_info);
	conn.gs = server_info->gs;
	conn.sp = server_info->sp;
	conn.status = server_info->status;

	hs = dns_gsocket_driver_handshake(&conn, &ev_flags);
	if (hs < 0) {
		return -1;
	}

	if (hs == 0) {
		_dns_client_tls_touch_pending_locked(server_info);
		gepoll_mod(client.gepoll, server_info->gs, ev_flags, server_info);
		return 0;
	}

	if (_dns_client_tls_on_handshake_done_locked(server_info) != 0) {
		return -1;
	}

	return 1;
}

static int _dns_client_tls_recv_locked(struct dns_server_info *server_info)
{
	int len = _dns_client_socket_tcp_recv(server_info);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	if (len == 0) {
		errno = ECONNRESET;
		return -1;
	}

	server_info->recv_buff.len += len;
	time(&server_info->last_recv);
	return 1;
}

int _dns_client_send_tls(struct dns_server_info *server_info, void *packet, int len)
{
	/* DoT uses same framing as TCP */
	return _dns_client_send_tcp(server_info, packet, len);
}

int _dns_client_process_tls(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now)
{
	struct dns_client_close_error close_error = {"tls process error", 0};

	pthread_mutex_lock(&server_info->lock);

	if (server_info->gs == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return -1;
	}

	/* Drive proxy/SSL handshake before data transfer */
	int hs_state = _dns_client_tls_drive_handshake_locked(server_info);
	if (hs_state < 0) {
		_dns_client_set_close_error(&close_error, "tls handshake error", errno);
		goto errout;
	}
	if (hs_state == 0) {
		pthread_mutex_unlock(&server_info->lock);
		return 0;
	}

	if (event->events & EPOLLOUT) {
		/* For QUIC/HTTP3, create gstream_poll now if not yet created */
		if ((server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) &&
			server_info->sp == NULL) {
			server_info->sp = gstream_poll_create(server_info->gs);
		}

		if (_dns_client_tls_flush_stream_pending_locked(server_info) != 0) {
			_dns_client_set_close_error(&close_error, "tls flush pending error", errno);
			goto errout;
		}

		/* Flush send buffer if any */
		_dns_client_tls_flush_send_buffer_locked(server_info, 0);
		_dns_client_tls_rearm_locked(server_info);
	}

	if (event->events & (EPOLLIN | EPOLLOUT)) {
		int ret = 0;

		switch (server_info->type) {
		case DNS_SERVER_QUIC:
		case DNS_SERVER_HTTP3:
		case DNS_SERVER_HTTPS:
			/* Create stream poll lazily after the transport handshake completes. */
			if (server_info->sp == NULL && server_info->status == DNS_SERVER_STATUS_CONNECTED) {
				server_info->sp = gstream_poll_create(server_info->gs);
			}
			if (_dns_client_tls_flush_stream_pending_locked(server_info) != 0) {
				_dns_client_set_close_error(&close_error, "tls flush pending error", errno);
				goto errout;
			}
			pthread_mutex_unlock(&server_info->lock);
			ret = dns_client_process_gstream_events(server_info);
			if (ret != 0) {
				_dns_client_set_close_error(&close_error, "gstream process error", errno);
				_dns_client_tls_close_server(server_info, &close_error);
				return ret;
			}
			return 0;
		case DNS_SERVER_TLS:
		default: {
			/* TLS: recv 2-byte-framed DNS */
			int recv_state = _dns_client_tls_recv_locked(server_info);
			if (recv_state < 0) {
				_dns_client_set_close_error(&close_error, "tls recv error", errno);
				goto errout;
			}
			if (recv_state == 0) {
				pthread_mutex_unlock(&server_info->lock);
				return 0;
			}
			pthread_mutex_unlock(&server_info->lock);
			_dns_client_process_tcp_recv(server_info);
			break;
		}
		}
	}

	pthread_mutex_unlock(&server_info->lock);
	return 0;

errout:
	pthread_mutex_unlock(&server_info->lock);
	_dns_client_tls_close_server(server_info, &close_error);
	return -1;
}
