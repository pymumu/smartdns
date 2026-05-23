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

#include "server_gsocket_stream.h"

#include "server_doh_gsocket.h"
#include "server_doq_gsocket.h"

#include "connection.h"
#include "dns_server.h"

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>

typedef int (*dns_server_gstream_request_fn)(struct dns_server_conn_gsocket *conn, struct gsocket *stream);

struct dns_server_gstream_proto_ops {
	DNS_CONN_TYPE conn_type;
	dns_server_gstream_request_fn process_request;
	int stream_owned_ret;
	int update_parent_events;
};

struct dns_server_pending_stream {
	struct list_head list;
	struct gsocket *stream;
	atomic_t refcnt;
};

struct dns_server_conn_stream *dns_server_gstream_adopt(struct dns_server_conn_gsocket *parent,
														struct gsocket *stream_gs, DNS_CONN_TYPE stream_type)
{
	struct dns_server_conn_stream *sc = zalloc(1, sizeof(*sc));
	if (!sc) {
		return NULL;
	}

	sc->head.type = stream_type;
	sc->head.gs = stream_gs;
	sc->head.server_flags = parent->head.server_flags;
	sc->head.dns_group = parent->head.dns_group;
	sc->head.ipset_nftset_rule = parent->head.ipset_nftset_rule;
	sc->parent = parent;
	_dns_server_conn_get(&parent->head);
	atomic_set(&sc->head.refcnt, 0);
	INIT_LIST_HEAD(&sc->head.list);

	pthread_mutex_lock(&server.conn_list_lock);
	list_add(&sc->head.list, &server.conn_list);
	pthread_mutex_unlock(&server.conn_list_lock);
	_dns_server_conn_get(&sc->head);

	return sc;
}

int dns_server_gstream_dispatch_query(struct dns_server_conn_gsocket *parent, struct gsocket *stream_gs,
									  DNS_CONN_TYPE stream_type, unsigned char *packet, int packet_len)
{
	struct dns_server_conn_stream *sc = dns_server_gstream_adopt(parent, stream_gs, stream_type);
	if (!sc) {
		return -1;
	}

	_dns_server_recv(&sc->head, packet, packet_len, &parent->localaddr, parent->localaddr_len, &parent->addr,
					 parent->addr_len);

	_dns_server_conn_release(&sc->head);
	return 0;
}

static void _dns_server_gstream_close_stream(struct gsocket **stream)
{
	if (stream == NULL || *stream == NULL) {
		return;
	}

	gsocket_close(*stream);
	gsocket_free(*stream);
	*stream = NULL;
}

static void _dns_server_gstream_pending_get(struct dns_server_pending_stream *pending)
{
	if (pending == NULL) {
		return;
	}

	if (atomic_inc_return(&pending->refcnt) <= 0) {
		BUG("BUG: server pending stream ref is invalid.");
	}
}

static void _dns_server_gstream_pending_put(struct dns_server_pending_stream *pending)
{
	if (pending == NULL) {
		return;
	}

	int refcnt = atomic_dec_return(&pending->refcnt);
	if (refcnt) {
		if (refcnt < 0) {
			BUG("BUG: server pending stream refcnt is %d", refcnt);
		}
		return;
	}

	list_del_init(&pending->list);
	_dns_server_gstream_close_stream(&pending->stream);
	free(pending);
}

void dns_server_gstream_poll_destroy(struct dns_server_conn_gsocket *conn)
{
	if (conn == NULL) {
		return;
	}

	if (conn->sp != NULL) {
		gstream_poll_destroy(conn->sp);
		conn->sp = NULL;
	}

	struct dns_server_pending_stream *pending = NULL;
	struct dns_server_pending_stream *tmp = NULL;
	list_for_each_entry_safe(pending, tmp, &conn->pending_stream_list, list)
	{
		_dns_server_gstream_pending_put(pending);
	}
}

static void _dns_server_gstream_accept_pending(struct dns_server_conn_gsocket *conn)
{
	while (1) {
		struct gsocket *stream = gsocket_accept(conn->head.gs, NULL, NULL);
		if (!stream) {
			break;
		}
		struct dns_server_pending_stream *pending = zalloc(1, sizeof(*pending));
		if (pending == NULL) {
			_dns_server_gstream_close_stream(&stream);
			break;
		}
		INIT_LIST_HEAD(&pending->list);
		pending->stream = stream;
		atomic_set(&pending->refcnt, 1);
		list_add_tail(&pending->list, &conn->pending_stream_list);
		if (gstream_poll_add(conn->sp, stream, POLLIN, pending) != 0) {
			_dns_server_gstream_pending_put(pending);
		}
	}
}

static int _dns_server_gstream_process_stream_event(struct dns_server_conn_gsocket *conn,
													struct dns_server_pending_stream *pending,
													dns_server_gstream_request_fn process_request, int stream_owned_ret)
{
	struct gsocket *stream = pending->stream;
	gstream_poll_del(conn->sp, stream);
	list_del_init(&pending->list);

	int ret = process_request(conn, stream);
	if (ret == -EAGAIN) {
		list_add_tail(&pending->list, &conn->pending_stream_list);
		if (gstream_poll_add(conn->sp, stream, POLLIN, pending) != 0) {
			_dns_server_gstream_pending_put(pending);
			_dns_server_gstream_pending_put(pending);
			return -1;
		}
		_dns_server_gstream_pending_put(pending);
		return 0;
	}

	if (ret != stream_owned_ret) {
		_dns_server_gstream_close_stream(&pending->stream);
	} else {
		pending->stream = NULL;
	}

	_dns_server_gstream_pending_put(pending);
	_dns_server_gstream_pending_put(pending);
	return 0;
}

static int _dns_server_gstream_process_events(struct dns_server_conn_gsocket *conn,
											  dns_server_gstream_request_fn process_request, int stream_owned_ret,
											  int update_parent_events)
{
	if (conn->sp == NULL) {
		return -1;
	}

	struct gstream_event events[64];
	while (1) {
		int n = gstream_poll_wait(conn->sp, events, 64, 0);
		if (n < 0) {
			return -1;
		}
		if (n == 0) {
			break;
		}

		for (int i = 0; i < n; i++) {
			struct gsocket *s = events[i].stream;
			if (s == conn->head.gs) {
				_dns_server_gstream_accept_pending(conn);
			} else if (events[i].revents & POLLIN) {
				struct dns_server_pending_stream *pending = events[i].user_data;
				if (pending == NULL || pending->stream != s) {
					continue;
				}
				_dns_server_gstream_pending_get(pending);
				if (_dns_server_gstream_process_stream_event(conn, pending, process_request, stream_owned_ret) != 0) {
					return -1;
				}
			}
		}
	}

	if (update_parent_events) {
		int net_evs = gstream_poll_get_net_events(conn->sp);
		if (net_evs > 0) {
			gepoll_mod(server.gepoll, conn->head.gs, net_evs, conn);
		}
	}

	return 0;
}

static const struct dns_server_gstream_proto_ops *_dns_server_gstream_get_proto(DNS_CONN_TYPE type)
{
	static const struct dns_server_gstream_proto_ops protos[] = {
		{DNS_CONN_TYPE_HTTPS_CLIENT, dns_server_doh_process_request, 1, 1},
		{DNS_CONN_TYPE_HTTPS3_CLIENT, dns_server_doh_process_request, 1, 0},
		{DNS_CONN_TYPE_QUIC_CLIENT, dns_server_doq_process_request, 0, 0},
	};

	for (size_t i = 0; i < sizeof(protos) / sizeof(protos[0]); i++) {
		if (protos[i].conn_type == type) {
			return &protos[i];
		}
	}

	return NULL;
}

int dns_server_gstream_process_client_events(struct dns_server_conn_gsocket *conn)
{
	const struct dns_server_gstream_proto_ops *proto = _dns_server_gstream_get_proto(conn->head.type);
	if (proto == NULL) {
		errno = EINVAL;
		return -1;
	}

	return _dns_server_gstream_process_events(conn, proto->process_request, proto->stream_owned_ret,
											  proto->update_parent_events);
}
