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

#include "client_gsocket_stream.h"

#include "client_doh_gsocket.h"
#include "client_doq_gsocket.h"
#include "client_gsocket.h"
#include "client_socket.h"
#include "conn_stream.h"
#include "query.h"

#include "smartdns/util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int (*dns_client_gstream_process_fn)(struct dns_server_info *server_info, struct gsocket *stream_gs,
											 struct dns_conn_stream *conn_stream);
typedef int (*dns_client_gstream_send_pending_fn)(struct dns_server_info *server_info, struct dns_query_struct *query,
												  void *packet, int packet_data_len);

struct dns_client_gstream_proto_ops {
	dns_server_type_t type;
	dns_client_gstream_send_pending_fn send_pending;
	dns_client_gstream_process_fn process_stream;
	int queue_while_connecting;
	int required_events;
	int keep_events;
};

struct dns_conn_stream *dns_client_gstream_attach(struct dns_server_info *server_info, struct dns_query_struct *query,
												  struct gsocket *stream_gs, dns_server_type_t type)
{
	struct dns_conn_stream *conn_stream = _dns_client_conn_stream_new();
	if (conn_stream == NULL) {
		return NULL;
	}

	conn_stream->stream_gs = stream_gs;
	conn_stream->query = query;
	conn_stream->server_info = server_info;
	conn_stream->type = type;

	pthread_mutex_lock(&query->lock);
	list_add_tail(&conn_stream->query_list, &query->conn_stream_list);
	pthread_mutex_unlock(&query->lock);

	pthread_mutex_lock(&server_info->lock);
	list_add_tail(&conn_stream->server_list, &server_info->conn_stream_list);
	pthread_mutex_unlock(&server_info->lock);

	if (gstream_poll_add(server_info->sp, stream_gs, EPOLLIN, conn_stream) != 0) {
		pthread_mutex_lock(&query->lock);
		list_del_init(&conn_stream->query_list);
		pthread_mutex_unlock(&query->lock);

		pthread_mutex_lock(&server_info->lock);
		list_del_init(&conn_stream->server_list);
		pthread_mutex_unlock(&server_info->lock);

		conn_stream->query = NULL;
		conn_stream->server_info = NULL;
		conn_stream->stream_gs = NULL;
		_dns_client_conn_stream_put(conn_stream);
		return NULL;
	}

	_dns_client_conn_stream_get(conn_stream);

	return conn_stream;
}

void dns_client_gstream_detach(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream)
{
	if (server_info && server_info->sp && conn_stream->stream_gs) {
		gstream_poll_del(server_info->sp, conn_stream->stream_gs);
	}
	_dns_client_conn_stream_put(conn_stream);
}

void dns_client_gstream_close(struct gsocket **stream_gs)
{
	if (stream_gs == NULL || *stream_gs == NULL) {
		return;
	}

	gsocket_close(*stream_gs);
	gsocket_free(*stream_gs);
	*stream_gs = NULL;
}

int dns_client_gstream_append_recv(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream,
								   const void *data, int len)
{
	if (conn_stream == NULL || data == NULL || len < 0) {
		errno = EINVAL;
		return -1;
	}

	if (DNS_TCP_BUFFER - conn_stream->recv_buff.len < len) {
		errno = ENOBUFS;
		return -1;
	}

	memcpy(conn_stream->recv_buff.data + conn_stream->recv_buff.len, data, len);
	conn_stream->recv_buff.len += len;
	if (server_info) {
		time(&server_info->last_recv);
	}
	return 0;
}

void dns_client_gstream_recv_response(struct dns_server_info *server_info, struct dns_query_struct *query,
									  unsigned char *packet, int packet_len)
{
	struct sockaddr *addr = &server_info->addr;
	socklen_t addr_len = server_info->ai_addrlen;
	if (packet_len >= 2) {
		uint16_t packet_id = ntohs(*(uint16_t *)packet);
		if (packet_id == 0 && query) {
			*(uint16_t *)packet = htons(query->sid);
		}
	}
	_dns_client_recv(server_info, packet, packet_len, addr, addr_len);
	time(&server_info->last_recv);
}

static int _dns_client_gstream_send_pending_https(struct dns_server_info *server_info, struct dns_query_struct *query,
												  void *packet, int packet_data_len)
{
	return _dns_client_send_http2(server_info, query, packet, packet_data_len);
}

static int _dns_client_gstream_send_pending_quic(struct dns_server_info *server_info, struct dns_query_struct *query,
												 void *packet, int packet_data_len)
{
	return _dns_client_send_quic(server_info, query, packet, packet_data_len);
}

static int _dns_client_gstream_send_pending_http3(struct dns_server_info *server_info, struct dns_query_struct *query,
												  void *packet, int packet_data_len)
{
	return _dns_client_send_http3(server_info, query, packet, packet_data_len);
}

static const struct dns_client_gstream_proto_ops *_dns_client_gstream_get_proto(dns_server_type_t type)
{
	static const struct dns_client_gstream_proto_ops protos[] = {
		{DNS_SERVER_HTTPS, _dns_client_gstream_send_pending_https, dns_client_doh_process_stream, 1, 0, 1},
		{DNS_SERVER_HTTP3, _dns_client_gstream_send_pending_http3, dns_client_doh_process_stream, 1, 0, 0},
		{DNS_SERVER_QUIC, _dns_client_gstream_send_pending_quic, dns_client_doq_process_stream, 1, EPOLLIN, 0},
	};

	for (size_t i = 0; i < sizeof(protos) / sizeof(protos[0]); i++) {
		if (protos[i].type == type) {
			return &protos[i];
		}
	}

	return NULL;
}

int dns_client_gstream_pending_add(struct dns_server_info *server_info, struct dns_query_struct *query,
								   const void *packet, int packet_data_len)
{
	if (query == NULL || packet == NULL || packet_data_len < 0) {
		errno = EINVAL;
		return -1;
	}

	struct dns_http2_pending *pend = malloc(sizeof(*pend) + packet_data_len);
	if (pend == NULL) {
		errno = ENOMEM;
		return -1;
	}

	pend->query = query;
	pend->active_tick = get_tick_count();
	pend->data_len = packet_data_len;
	memcpy(pend->data, packet, packet_data_len);
	_dns_client_query_get(query);
	atomic_inc(&query->dns_request_sent);

	pthread_mutex_lock(&server_info->lock);
	struct dns_http2_pending *pend_check = NULL;
	list_for_each_entry(pend_check, &server_info->http2_pending_list, list)
	{
		if (pend_check->query == query) {
			pthread_mutex_unlock(&server_info->lock);
			_dns_client_query_release(query);
			atomic_dec(&query->dns_request_sent);
			free(pend);
			return 0;
		}
	}

	list_add_tail(&pend->list, &server_info->http2_pending_list);
	atomic_inc(&query->stream_pending_count);
	struct gsocket *gs = server_info->gs;
	pthread_mutex_unlock(&server_info->lock);

	if (gs) {
		gepoll_mod(client.gepoll, gs, EPOLLIN | EPOLLOUT, server_info);
	}

	return 0;
}

static void _dns_client_gstream_pending_remove(struct dns_http2_pending *pend)
{
	struct dns_query_struct *q = pend->query;

	list_del(&pend->list);
	atomic_dec(&q->dns_request_sent);
	atomic_dec(&q->stream_pending_count);
	_dns_client_query_release(q);
	free(pend);
}

void dns_client_gstream_pending_flush(struct dns_server_info *server_info)
{
	const struct dns_client_gstream_proto_ops *proto = _dns_client_gstream_get_proto(server_info->type);
	if (proto == NULL || proto->send_pending == NULL) {
		errno = EINVAL;
		return;
	}

	struct dns_http2_pending *pend = NULL;
	struct dns_http2_pending *ptmp = NULL;
	list_for_each_entry_safe(pend, ptmp, &server_info->http2_pending_list, list)
	{
		struct dns_query_struct *q = pend->query;
		if (proto->send_pending(server_info, q, pend->data, pend->data_len) != 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
				break;
			}

			_dns_client_gstream_pending_remove(pend);
			DNS_CLIENT_CLOSE_SOCKET_REASON(server_info, "gstream pending flush failed", errno);
			break;
		}

		q->send_tick = get_tick_count();
		_dns_client_gstream_pending_remove(pend);
	}
}

int dns_client_gstream_send_query(struct dns_server_info *server_info, struct dns_query_struct *query,
								  dns_server_type_t type, const void *payload, int payload_len, int send_flags,
								  const void *pending_packet, int pending_packet_len,
								  dns_client_gstream_prepare_send_fn prepare_send, void *user_data)
{
	struct gsocket *stream_gs = NULL;
	int pending = 0;
	const struct dns_client_gstream_proto_ops *proto = _dns_client_gstream_get_proto(type);
	if (proto == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (server_info->gs == NULL) {
		errno = EBADF;
		return -1;
	}

	if (proto->queue_while_connecting && server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return dns_client_gstream_pending_add(server_info, query, pending_packet, pending_packet_len);
	}

	if (proto->queue_while_connecting && server_info->sp == NULL) {
		server_info->sp = gstream_poll_create(server_info->gs);
		if (server_info->sp == NULL) {
			errno = ENOMEM;
			return -1;
		}
	}

	stream_gs = gsocket_open_stream(server_info->gs);
	if (stream_gs == NULL) {
		if (proto->queue_while_connecting && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
			return dns_client_gstream_pending_add(server_info, query, pending_packet, pending_packet_len);
		}
		if (errno == 0) {
			errno = ECONNRESET;
		}
		return -1;
	}

	if (prepare_send && prepare_send(server_info, stream_gs, user_data) != 0) {
		goto errout;
	}

	int s_ret = gsocket_send_all(stream_gs, payload, payload_len, send_flags);
	if (s_ret != 0) {
		tlog(TLOG_DEBUG,
			 "dns_client_gstream_send_query: gsocket_send_all failed, server=%s:%d type=%d ret=%d errno=%d(%s) "
			 "query=%s qtype=%d id=%d",
			 server_info->ip, server_info->port, type, s_ret, errno, strerror(errno), query->domain, query->qtype,
			 query->sid);
		if (proto->queue_while_connecting && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
			dns_client_gstream_close(&stream_gs);
			return dns_client_gstream_pending_add(server_info, query, pending_packet, pending_packet_len);
		}
		if (errno == 0) {
			errno = ECONNRESET;
		}
		goto errout;
	}

	if (dns_client_gstream_attach(server_info, query, stream_gs, type) == NULL) {
		errno = ENOMEM;
		goto errout;
	}
	stream_gs = NULL;

	int net_events = gstream_poll_get_net_events(server_info->sp);
	if (type == DNS_SERVER_HTTPS) {
		net_events |= EPOLLIN;
	}
	if (net_events != 0) {
		gepoll_mod(client.gepoll, server_info->gs, net_events, server_info);
	}

	return 0;

errout:
	dns_client_gstream_close(&stream_gs);
	if (pending) {
		int r = dns_client_gstream_pending_add(server_info, query, pending_packet, pending_packet_len);
		if (r != 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
			return DNS_SEND_RET_NON_FATAL;
		}
		return r;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
		return DNS_SEND_RET_NON_FATAL;
	}
	return -1;
}

static int _dns_client_gstream_process_events(struct dns_server_info *server_info,
											  dns_client_gstream_process_fn process_stream, int required_events,
											  int keep_events)
{
	int loop_count = 32;
	if (server_info->gs == NULL || server_info->sp == NULL) {
		return -1;
	}

	struct gstream_event events[64];
	while (loop_count-- > 0) {
		int nev = gstream_poll_wait(server_info->sp, events, 64, 0);
		if (nev < 0) {
			return -1;
		}
		if (nev == 0) {
			break;
		}

		for (int i = 0; i < nev; i++) {
			struct dns_conn_stream *conn_stream = (struct dns_conn_stream *)events[i].user_data;
			if (conn_stream == NULL) {
				continue;
			}
			if (required_events != 0 && !(events[i].revents & required_events)) {
				continue;
			}

			int done = process_stream(server_info, events[i].stream, conn_stream);
			if (done != 0) {
				dns_client_gstream_detach(server_info, conn_stream);
			}
		}
	}

	int net_events = gstream_poll_get_net_events(server_info->sp);
	if (keep_events && !list_empty(&server_info->conn_stream_list)) {
		net_events |= EPOLLIN;
	}
	if (net_events != 0) {
		gepoll_mod(client.gepoll, server_info->gs, net_events, server_info);
	}

	return 0;
}

int dns_client_process_gstream_events(struct dns_server_info *server_info)
{
	const struct dns_client_gstream_proto_ops *proto = _dns_client_gstream_get_proto(server_info->type);
	if (proto == NULL) {
		errno = EINVAL;
		return -1;
	}

	return _dns_client_gstream_process_events(server_info, proto->process_stream, proto->required_events,
											  proto->keep_events);
}
