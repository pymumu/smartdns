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
#include "client_gsocket.h"
#include "client_gsocket_proto.h"
#include "client_mdns.h"
#include "conn_stream.h"
#include "query.h"
#include "wake_event.h"

#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/util.h"

#include <errno.h>
#include <string.h>

static void _dns_client_log_close_state(struct dns_server_info *server_info, const char *phase)
{
	int stream_count = 0;
	int unfinished_stream_count = 0;
	int pending_count = 0;
	struct dns_conn_stream *conn_stream = NULL;
	struct dns_http2_pending *pend = NULL;
	struct dns_query_struct *sample_query = NULL;

	list_for_each_entry(conn_stream, &server_info->conn_stream_list, server_list)
	{
		stream_count++;
		if (conn_stream->response_done == 0) {
			unfinished_stream_count++;
		}
		if (sample_query == NULL && conn_stream->query != NULL) {
			sample_query = conn_stream->query;
		}
	}

	list_for_each_entry(pend, &server_info->http2_pending_list, list)
	{
		pending_count++;
		if (sample_query == NULL && pend->query != NULL) {
			sample_query = pend->query;
		}
	}

	if (sample_query) {
		tlog(TLOG_DEBUG,
			 "close-state[%s]: server=%s:%d type=%d status=%d prohibit=%d already_prohibit=%d send_len=%d recv_len=%d "
			 "streams=%d unfinished=%d pending=%d sample=%s qtype=%d qid=%d sent=%ld pending_sent=%ld retry=%ld "
			 "has_result=%d",
			 phase, server_info->ip, server_info->port, server_info->type, server_info->status, server_info->prohibit,
			 server_info->is_already_prohibit, server_info->send_buff.len, server_info->recv_buff.len, stream_count,
			 unfinished_stream_count, pending_count, sample_query->domain, sample_query->qtype, sample_query->sid,
			 atomic_read(&sample_query->dns_request_sent), atomic_read(&sample_query->stream_pending_count),
			 atomic_read(&sample_query->retry_count), sample_query->has_result);
	} else {
		tlog(TLOG_DEBUG,
			 "close-state[%s]: server=%s:%d type=%d status=%d prohibit=%d already_prohibit=%d send_len=%d recv_len=%d "
			 "streams=%d unfinished=%d pending=%d",
			 phase, server_info->ip, server_info->port, server_info->type, server_info->status, server_info->prohibit,
			 server_info->is_already_prohibit, server_info->send_buff.len, server_info->recv_buff.len, stream_count,
			 unfinished_stream_count, pending_count);
	}
}

void _dns_client_close_socket_with_reason(struct dns_server_info *server_info, const char *reason, int err,
										  const char *file, int line)
{
	if (server_info == NULL) {
		return;
	}

	if (reason == NULL) {
		reason = "unknown";
	}

	tlog(TLOG_DEBUG, "close-request: server=%s:%d type=%d status=%d reason=%s err=%d(%s) at %s:%d",
		 server_info->ip, server_info->port, server_info->type, server_info->status, reason, err,
		 err ? strerror(err) : "none", file ? file : "?", line);
	_dns_client_close_socket(server_info);
}

/* Helper function to check if the connection is valid */
int _dns_client_is_conn_valid(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL) {
		return 0;
	}

	if (dns_client_gsocket_proto_is_connectionless(server_info)) {
		return 1;
	}

	return (server_info->status == DNS_SERVER_STATUS_CONNECTING || server_info->status == DNS_SERVER_STATUS_CONNECTED);
}

int _dns_client_create_socket(struct dns_server_info *server_info)
{
	int ret = -1;
	pthread_mutex_lock(&server_info->lock);

	if (server_info->gs != NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return -1;
	}

	time(&server_info->last_send);
	time(&server_info->last_recv);

	ret = dns_client_gsocket_proto_create_socket(server_info);

	pthread_mutex_unlock(&server_info->lock);
	return ret;
}

void _dns_client_close_socket_ext(struct dns_server_info *server_info, int no_del_conn_list)
{
	pthread_mutex_lock(&server_info->lock);
	_dns_client_log_close_state(server_info, "before");
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
	if (server_info->gstream_processing > 0) {
		server_info->gstream_close_pending = 1;
		pthread_mutex_unlock(&server_info->lock);
		return;
	}
	server_info->gstream_close_pending = 0;

	/* Free all conn_streams */
	if (!no_del_conn_list) {
		struct dns_conn_stream *conn_stream = NULL;
		struct dns_conn_stream *tmp = NULL;
		list_for_each_entry_safe(conn_stream, tmp, &server_info->conn_stream_list, server_list)
		{
			struct dns_query_struct *query = conn_stream->query;

			if (conn_stream->stream_gs) {
				if (server_info->sp) {
					gstream_poll_del(server_info->sp, conn_stream->stream_gs);
				}
				gsocket_close(conn_stream->stream_gs);
			}
			_dns_client_conn_stream_put(conn_stream);

			if (query && conn_stream->response_done == 0) {
				_dns_client_query_schedule_retry_on_send_failure(query, "stream disconnect");
			}

			if (query) {
				pthread_mutex_lock(&query->lock);
				list_del_init(&conn_stream->query_list);
				pthread_mutex_unlock(&query->lock);
				conn_stream->query = NULL;
			}

			conn_stream->server_info = NULL;
			list_del_init(&conn_stream->server_list);
			_dns_client_conn_stream_put(conn_stream);

			if (query) {
				_dns_client_query_release(query);
			}
		}
	}

	/* Free pending HTTP/2 queries */
	{
		struct dns_http2_pending *pend, *ptmp;
		list_for_each_entry_safe(pend, ptmp, &server_info->http2_pending_list, list)
		{
			list_del(&pend->list);
			atomic_dec(&pend->query->stream_pending_count);
			atomic_dec(&pend->query->dns_request_sent);
			_dns_client_query_schedule_retry_on_send_failure(pend->query, "pending disconnect");
			_dns_client_query_release(pend->query);
			free(pend);
		}
	}

	/* Destroy stream poll */
	if (server_info->sp) {
		gstream_poll_destroy(server_info->sp);
		server_info->sp = NULL;
	}

	/* Close gsocket */
	if (server_info->gs) {
		if (client.gepoll) {
			gepoll_del(client.gepoll, server_info->gs);
		}
		gsocket_close(server_info->gs);
		gsocket_free(server_info->gs);
		server_info->gs = NULL;
	}

	tlog(TLOG_DEBUG, "server %s:%d closed.", server_info->ip, server_info->port);
	_dns_client_log_close_state(server_info, "after");
	time(&server_info->last_send);
	time(&server_info->last_recv);

	/* Advance to next proxy entry in group for the next connection attempt */
	if (server_info->proxy_name[0] != '\0') {
		server_info->proxy_attempt++;
	}

	pthread_mutex_unlock(&server_info->lock);
}

void _dns_client_close_socket(struct dns_server_info *server_info)
{
	_dns_client_close_socket_ext(server_info, 0);
}

void _dns_client_shutdown_socket(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL) {
		return;
	}

	dns_client_gsocket_proto_shutdown(server_info);
}

int _dns_client_socket_send(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL) {
		return -1;
	}

	return dns_client_gsocket_proto_socket_send(server_info);
}

int _dns_client_socket_recv(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL) {
		return -1;
	}

	return dns_client_gsocket_proto_socket_recv(server_info);
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
	if (DNS_TCP_BUFFER - server_info->send_buff.len < len) {
		errno = ENOMEM;
		return -1;
	}

	memcpy(server_info->send_buff.data + server_info->send_buff.len, packet, len);
	server_info->send_buff.len += len;

	if (server_info->gs == NULL) {
		errno = ECONNRESET;
		return -1;
	}

	if (gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info) != 0) {
		if (errno == ENOENT) {
			return 0;
		}
		tlog(TLOG_ERROR, "gepoll mod failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}
