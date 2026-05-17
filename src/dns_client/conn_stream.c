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

#include "conn_stream.h"

#include "smartdns/lib/gsocket.h"
#include "smartdns/util.h"

struct dns_conn_stream *_dns_client_conn_stream_new(void)
{
	struct dns_conn_stream *stream = NULL;

	stream = zalloc(1, sizeof(*stream));
	if (stream == NULL) {
		tlog(TLOG_ERROR, "malloc conn stream failed");
		return NULL;
	}
	INIT_LIST_HEAD(&stream->server_list);
	INIT_LIST_HEAD(&stream->query_list);
	stream->stream_gs = NULL;
	stream->server_info = NULL;
	stream->query = NULL;
	atomic_set(&stream->refcnt, 1);

	return stream;
}

void _dns_client_conn_stream_get(struct dns_conn_stream *stream)
{
	if (atomic_inc_return(&stream->refcnt) <= 1) {
		BUG("stream ref is invalid");
	}
}

void _dns_client_conn_stream_put(struct dns_conn_stream *stream)
{
	int refcnt = atomic_dec_return(&stream->refcnt);
	if (refcnt) {
		if (refcnt < 0) {
			BUG("BUG: stream  %p, refcnt is %d", stream, refcnt);
		}
		return;
	}

	if (stream->stream_gs) {
		gsocket_close(stream->stream_gs);
		gsocket_free(stream->stream_gs);
		stream->stream_gs = NULL;
	}

	if (stream->query) {
		pthread_mutex_lock(&stream->query->lock);
		list_del_init(&stream->query_list);
		pthread_mutex_unlock(&stream->query->lock);
		stream->query = NULL;
	}

	if (stream->server_info) {
		pthread_mutex_lock(&stream->server_info->lock);
		list_del_init(&stream->server_list);
		pthread_mutex_unlock(&stream->server_info->lock);
	}

	free(stream);
}

void _dns_client_conn_server_streams_free(struct dns_server_info *server_info, struct dns_query_struct *query)
{
	struct dns_conn_stream *stream = NULL;
	struct dns_conn_stream *tmp = NULL;

	pthread_mutex_lock(&server_info->lock);
	list_for_each_entry_safe(stream, tmp, &server_info->conn_stream_list, server_list)
	{

		if (stream->query != query) {
			continue;
		}

		list_del_init(&stream->server_list);
		stream->server_info = NULL;
		if (stream->stream_gs) {
			if (server_info->sp) {
				gstream_poll_del(server_info->sp, stream->stream_gs);
			}
			gsocket_close(stream->stream_gs);
			gsocket_free(stream->stream_gs);
			stream->stream_gs = NULL;
		}

		_dns_client_conn_stream_put(stream);
	}
	pthread_mutex_unlock(&server_info->lock);
}
