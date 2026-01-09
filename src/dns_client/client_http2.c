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

#define _GNU_SOURCE

#include "client_http2.h"
#include "client_socket.h"
#include "client_tls.h"
#include "conn_stream.h"
#include "server_info.h"

#include "smartdns/http2.h"

#include <string.h>

/* BIO read callback for HTTP/2 */
static int _http2_bio_read(void *private_data, uint8_t *buf, int len)
{
	struct dns_server_info *server_info = (struct dns_server_info *)private_data;
	return _dns_client_socket_ssl_recv(server_info, buf, len);
}

/* BIO write callback for HTTP/2 */
static int _http2_bio_write(void *private_data, const uint8_t *buf, int len)
{
	struct dns_server_info *server_info = (struct dns_server_info *)private_data;
	return _dns_client_socket_ssl_send(server_info, buf, len);
}

/* Helper function to send buffered data from a conn_stream via HTTP/2 */
static int _dns_client_send_http2_stream(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream,
										 void *data, unsigned short len)
{
	struct http2_ctx *http2_ctx = NULL;
	struct http2_stream *http2_stream = NULL;
	struct client_dns_server_flag_https *https_flag = &server_info->flags.https;
	char content_length[32];

	pthread_mutex_lock(&server_info->lock);
	http2_ctx = server_info->http2_ctx;
	if (http2_ctx == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return -1;
	}
	/* Get reference to prevent it from being freed while we use it */
	http2_ctx_get(http2_ctx);
	pthread_mutex_unlock(&server_info->lock);

	/* Create HTTP/2 stream */
	http2_stream = http2_stream_new(http2_ctx);
	if (http2_stream == NULL) {
		if (errno != ENOSPC) {
			tlog(TLOG_WARN, "create http2 stream failed");
		}
		http2_ctx_put(http2_ctx);
		return -1;
	}

	/* Set request headers */
	snprintf(content_length, sizeof(content_length), "%d", len);
	struct http2_header_pair headers[] = {{"content-type", "application/dns-message"},
										  {"accept", "application/dns-message"},
										  {"content-length", content_length},
										  {NULL, NULL}};

	if (http2_stream_set_request(http2_stream, "POST", https_flag->path, NULL, headers) < 0) {
		goto errout;
	}

	/* Write request body */
	if (http2_stream_write_body(http2_stream, (const uint8_t *)data, len, 1) < 0) {
		goto errout;
	}

	pthread_mutex_lock(&server_info->lock);
	conn_stream->http2_stream = http2_stream;
	pthread_mutex_unlock(&server_info->lock);
	http2_stream_set_ex_data(http2_stream, conn_stream);
	http2_ctx_put(http2_ctx);
	return 0;

errout:
	http2_stream_close(http2_stream);
	http2_ctx_put(http2_ctx);
	return -1;
}

/* Helper function to release a conn_stream and its references on error */
static void _dns_client_release_stream_on_error(struct dns_server_info *server_info, struct dns_conn_stream *stream)
{
	if (!stream) {
		return;
	}

	pthread_mutex_lock(&server_info->lock);

	/* Remove from server list and release reference */
	if (!list_empty(&stream->server_list)) {
		list_del_init(&stream->server_list);
		stream->server_info = NULL;
		_dns_client_conn_stream_put(stream);
	}

	/* Remove from query list and release reference */
	if (!list_empty(&stream->query_list)) {
		if (stream->query) {
			pthread_mutex_lock(&stream->query->lock);
			list_del_init(&stream->query_list);
			pthread_mutex_unlock(&stream->query->lock);
			stream->query = NULL;
		}
		_dns_client_conn_stream_put(stream);
	}

	pthread_mutex_unlock(&server_info->lock);

	/* Release the initial reference from creation */
	_dns_client_conn_stream_put(stream);
}

/* Helper function to flush pending HTTP/2 writes */
static void _dns_client_flush_http2_writes(struct http2_ctx *http2_ctx)
{
	struct http2_poll_item poll_items[1];
	int poll_count = 0;
	int loop = 0;

	while (http2_ctx_want_write(http2_ctx) && loop++ < 10) {
		http2_ctx_poll(http2_ctx, poll_items, 1, &poll_count);
	}
}

/* Helper function to send all buffered HTTP/2 requests */
static void _dns_client_send_buffered_http2_requests(struct dns_server_info *server_info)
{
	struct dns_conn_stream *conn_stream = NULL;
	struct dns_conn_stream *tmp = NULL;

	while (1) {
		struct dns_conn_stream *target_stream = NULL;

		pthread_mutex_lock(&server_info->lock);
		list_for_each_entry_safe(conn_stream, tmp, &server_info->conn_stream_list, server_list)
		{
			if (conn_stream->http2_stream != NULL || conn_stream->send_buff.len <= 0) {
				continue;
			}
			target_stream = conn_stream;
			_dns_client_conn_stream_get(target_stream);
			break;
		}
		pthread_mutex_unlock(&server_info->lock);

		if (target_stream == NULL) {
			break;
		}

		/* Send buffered request using helper function */
		if (_dns_client_send_http2_stream(server_info, target_stream, target_stream->send_buff.data,
										  target_stream->send_buff.len) == 0) {
			/* Clear buffer as it's now in HTTP/2 stream buffer */
			target_stream->send_buff.len = 0;
			_dns_client_conn_stream_put(target_stream);
		} else {
			/* Send failed, remove from buffer and clean up */
			_dns_client_release_stream_on_error(server_info, target_stream);
		}
	}
}

/* Helper function to buffer data for HTTP/2 when connection is not ready */
static int _dns_client_http2_pending_data(struct dns_conn_stream *stream, struct dns_server_info *server_info,
										  struct dns_query_struct *query, void *packet, int len)
{
	struct epoll_event event;
	
	/* Validate input parameters */
	if (len <= 0 || len > DNS_IN_PACKSIZE - 128) {
		errno = EINVAL;
		return -1;
	}
	
	if (DNS_TCP_BUFFER - stream->send_buff.len < len) {
		errno = ENOMEM;
		return -1;
	}

	if (client.epoll_fd <= 0) {
		errno = ECONNRESET;
		goto errout;
	}

	memcpy(stream->send_buff.data + stream->send_buff.len, packet, len);
	stream->send_buff.len += len;

	pthread_mutex_lock(&server_info->lock);
	if (server_info->fd <= 0) {
		pthread_mutex_unlock(&server_info->lock);
		errno = ECONNRESET;
		goto errout;
	}

	if (list_empty(&stream->server_list)) {
		_dns_client_conn_stream_get(stream);
		list_add_tail(&stream->server_list, &server_info->conn_stream_list);
	}
	stream->server_info = server_info;

	if (list_empty(&stream->query_list)) {
		_dns_client_conn_stream_get(stream);
		pthread_mutex_lock(&query->lock);
		list_add_tail(&stream->query_list, &query->conn_stream_list);
		stream->query = query;
		pthread_mutex_unlock(&query->lock);
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		pthread_mutex_unlock(&server_info->lock);
		goto errout_put;
	}
	pthread_mutex_unlock(&server_info->lock);

	return 0;
errout_put:
	/* Clean up stream on error */
	pthread_mutex_lock(&server_info->lock);
	if (!list_empty(&stream->server_list)) {
		list_del_init(&stream->server_list);
		stream->server_info = NULL;
		_dns_client_conn_stream_put(stream);
	}
	if (!list_empty(&stream->query_list)) {
		if (stream->query) {
			pthread_mutex_lock(&stream->query->lock);
			list_del_init(&stream->query_list);
			pthread_mutex_unlock(&stream->query->lock);
			stream->query = NULL;
		}
		_dns_client_conn_stream_put(stream);
	}
	pthread_mutex_unlock(&server_info->lock);
errout:
	return -1;
}

int _dns_client_send_http2(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						   unsigned short len)
{
	struct dns_conn_stream *stream = NULL;
	struct http2_ctx *http2_ctx = NULL;
	int ret = -1;

	if (len > DNS_IN_PACKSIZE - 128) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		ret = -1;
		goto out;
	}

	/* Create connection stream for this request */
	stream = _dns_client_conn_stream_new();
	if (stream == NULL) {
		tlog(TLOG_ERROR, "malloc memory failed for http2 stream.");
		return -1;
	}
	stream->type = DNS_SERVER_HTTPS;

	/* If not connected, buffer the data and return */
	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		ret = _dns_client_http2_pending_data(stream, server_info, query, packet, len);
		goto out;
	}

	/* If connected but context not ready, buffer it too (will be flushed in process_http2) */
	if (server_info->http2_ctx == NULL) {
		ret = _dns_client_http2_pending_data(stream, server_info, query, packet, len);
		goto out;
	}

	/* Send the request via HTTP/2 */
	ret = _dns_client_send_http2_stream(server_info, stream, packet, len);
	if (ret < 0) {
		tlog(TLOG_DEBUG, "send http2 stream failed.");
		/* Fall back to buffering the data */
		ret = _dns_client_http2_pending_data(stream, server_info, query, packet, len);
		goto out;
	}

	/* Now add stream to lists since HTTP/2 stream was successfully created */
	pthread_mutex_lock(&server_info->lock);
	_dns_client_conn_stream_get(stream);
	list_add_tail(&stream->server_list, &server_info->conn_stream_list);
	stream->server_info = server_info;

	_dns_client_conn_stream_get(stream);
	pthread_mutex_lock(&query->lock);
	list_add_tail(&stream->query_list, &query->conn_stream_list);
	stream->query = query;
	pthread_mutex_unlock(&query->lock);
	pthread_mutex_unlock(&server_info->lock);

	/* Flush data immediately */
	struct http2_poll_item poll_items[1];
	int poll_count = 0;
	int loop = 0;
	while (http2_ctx_want_write(http2_ctx) && loop++ < 10) {
		http2_ctx_poll(http2_ctx, poll_items, 1, &poll_count);
	}

	/* Check if there's pending write data, if so add EPOLLOUT event */
	if (http2_ctx_want_write(http2_ctx)) {
		struct epoll_event event;
		memset(&event, 0, sizeof(event));
		event.events = EPOLLIN | EPOLLOUT;
		event.data.ptr = server_info;
		if (server_info->fd > 0) {
			if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
				tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
				/* Continue anyway, data will be sent on next EPOLLIN */
			}
		}
	}

	ret = 0;
out:
	if (stream) {
		_dns_client_conn_stream_put(stream);
	}

	return ret;
}

static int _dns_client_http2_init_ctx(struct dns_server_info *server_info)
{
	struct http2_ctx *http2_ctx = server_info->http2_ctx;
	struct client_dns_server_flag_https *https_flag = &server_info->flags.https;
	int ret = 0;

	if (http2_ctx != NULL) {
		return 0;
	}

	pthread_mutex_lock(&server_info->lock);
	if (server_info->http2_ctx == NULL) {
		http2_ctx = http2_ctx_client_new(https_flag->httphost, _http2_bio_read, _http2_bio_write, server_info, NULL);
		if (http2_ctx == NULL) {
			pthread_mutex_unlock(&server_info->lock);
			tlog(TLOG_ERROR, "init http2 context failed.");
			return -1;
		}
		server_info->http2_ctx = http2_ctx;
		/* server_info now owns the context (refcount=1 from _new) */
		pthread_mutex_unlock(&server_info->lock);

		/* Perform HTTP/2 handshake */
		ret = http2_ctx_handshake(http2_ctx);
		if (ret < 0) {
			tlog(TLOG_ERROR, "http2 handshake failed.");
			return -1;
		}
	} else {
		pthread_mutex_unlock(&server_info->lock);
	}

	return 0;
}

static int _dns_client_http2_process_write(struct dns_server_info *server_info)
{
	struct http2_ctx *http2_ctx = NULL;
	int epoll_events = EPOLLIN;

	/* Send buffered requests */
	_dns_client_send_buffered_http2_requests(server_info);

	pthread_mutex_lock(&server_info->lock);
	http2_ctx = server_info->http2_ctx;
	if (http2_ctx == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return 0;
	}
	http2_ctx_get(http2_ctx);
	pthread_mutex_unlock(&server_info->lock);

	/* Flush pending writes */
	_dns_client_flush_http2_writes(http2_ctx);

	/* Update epoll events based on write status */
	if (http2_ctx_want_write(http2_ctx)) {
		epoll_events |= EPOLLOUT;
	}

	if (server_info->fd > 0) {
		struct epoll_event mod_event;
		memset(&mod_event, 0, sizeof(mod_event));
		mod_event.events = epoll_events;
		mod_event.data.ptr = server_info;
		if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &mod_event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			http2_ctx_put(http2_ctx);
			return -1;
		}
	}
	http2_ctx_put(http2_ctx);
	return 0;
}

static int _dns_client_http2_process_stream_one(struct dns_server_info *server_info,
												struct dns_conn_stream *conn_stream)
{
	struct http2_stream *http2_stream = conn_stream->http2_stream;
	uint8_t response_body[DNS_IN_PACKSIZE];
	int response_len = 0;
	int ret = 0;

	if (http2_stream == NULL || conn_stream->query == NULL) {
		return 1;
	}

	/* Check HTTP status code first */
	int status = http2_stream_get_status(http2_stream);
	if (status > 0 && status != 200) {
		tlog(TLOG_WARN, "http2 server query from %s:%d failed, server return http code: %d", server_info->ip,
			 server_info->port, status);
		server_info->prohibit = 1;
		return 1;
	}

	/* Read response body */
	response_len = http2_stream_read_body(http2_stream, response_body, sizeof(response_body));
	if (response_len <= 0) {
		/* Error or no data - check if stream has ended */
		goto out;
	}

	/* Process DNS response */
	ret = _dns_client_recv(server_info, response_body, response_len, &server_info->addr, server_info->ai_addrlen);
	if (ret != 0) {
		tlog(TLOG_ERROR, "process dns response failed");
	}

out:
	if (http2_stream_is_end(http2_stream)) {
		return 1;
	}

	return 0;
}

static int _dns_client_http2_process_read(struct dns_server_info *server_info)
{
	struct http2_ctx *http2_ctx = NULL;
	struct http2_poll_item poll_items[128];
	int poll_count = 0;
	int loop_count = 0;
	const int MAX_LOOP_COUNT = 512;
	struct dns_conn_stream *conn_stream = NULL;
	int ret = 0;
	int i = 0;

	pthread_mutex_lock(&server_info->lock);
	http2_ctx = server_info->http2_ctx;
	if (http2_ctx == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		return 0;
	}
	http2_ctx_get(http2_ctx);
	pthread_mutex_unlock(&server_info->lock);

	/* Ensure handshake is complete before polling */
	ret = http2_ctx_handshake(http2_ctx);
	if (ret == 0) {
		/* Handshake in progress, need more data */
		http2_ctx_put(http2_ctx);
		return 0;
	} else if (ret < 0) {
		tlog(TLOG_DEBUG, "http2 handshake failed.");
		http2_ctx_put(http2_ctx);
		return -1;
	}

	/* Poll and process streams until no more ready */
	while (loop_count++ < MAX_LOOP_COUNT) {
		/* Poll for stream readiness */
		ret = http2_ctx_poll_readable(http2_ctx, poll_items, 128, &poll_count);
		if (ret < 0) {
			if (ret != HTTP2_ERR_EOF) {
				tlog(TLOG_DEBUG, "http2 poll failed, ret=%d", ret);
			}
			http2_ctx_put(http2_ctx);
			return -1;
		}

		if (poll_count == 0) {
			break;
		}

		/* Process each ready stream */
		for (i = 0; i < poll_count; i++) {
			struct http2_stream *stream = poll_items[i].stream;
			if (stream == NULL) {
				continue;
			}

			conn_stream = (struct dns_conn_stream *)http2_stream_get_ex_data(stream);
			if (conn_stream == NULL) {
				http2_stream_put(stream);
				continue;
			}

			if (poll_items[i].readable) {
				int stream_ended = _dns_client_http2_process_stream_one(server_info, conn_stream);
				if (stream_ended) {
					int need_put = 0;
					pthread_mutex_lock(&server_info->lock);
					if (!list_empty(&conn_stream->server_list)) {
						list_del_init(&conn_stream->server_list);
						conn_stream->server_info = NULL;
						need_put = 1;
					}
					pthread_mutex_unlock(&server_info->lock);

					if (need_put) {
						_dns_client_conn_stream_put(conn_stream);
					}
				}
			}
			http2_stream_put(stream);
		}

		if (poll_count < 128) {
			break;
		}
	}
	http2_ctx_put(http2_ctx);
	return 0;
}

int _dns_client_process_http2(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	if (server_info->http2_ctx == NULL) {
		if (_dns_client_http2_init_ctx(server_info) < 0) {
			return -1;
		}
	}

	if (event->events & EPOLLOUT) {
		if (_dns_client_http2_process_write(server_info) < 0) {
			return -1;
		}
	}

	/* Always process read, as write might have read data (e.g. WINDOW_UPDATE),
	   or there might be pending data in SSL/HTTP2 buffers */
	if (_dns_client_http2_process_read(server_info) < 0) {
		return -1;
	}

	return 0;
}
