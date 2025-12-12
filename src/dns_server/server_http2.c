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
 *
 *************************************************************************/

#include "server_http2.h"
#include "connection.h"
#include "dns_server.h"
#include "server_tls.h"
#include "smartdns/http2.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNS_SERVER_HTTP2_MAX_CONCURRENT_STREAMS 4096

static int _http2_server_bio_read(void *private_data, uint8_t *buf, int len)
{
	struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)private_data;
	return _dns_server_socket_ssl_recv(tls_client, buf, len);
}

static int _http2_server_bio_write(void *private_data, const uint8_t *buf, int len)
{
	struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)private_data;
	return _dns_server_socket_ssl_send(tls_client, buf, len);
}

static int _dns_server_http2_send_response(struct http2_stream *stream, int status, const char *content_type,
										   const void *body, int body_len)
{
	char content_length[32];
	snprintf(content_length, sizeof(content_length), "%d", body_len);

	struct http2_header_pair headers[] = {
		{"content-type", content_type}, {"content-length", content_length}, {NULL, NULL}};

	if (http2_stream_set_response(stream, status, headers, 2) < 0) {
		return -1;
	}

	if (http2_stream_write_body(stream, (const uint8_t *)body, body_len, 1) < 0) {
		return -1;
	}

	return 0;
}

int _dns_server_reply_http2(struct dns_request *request, struct dns_server_conn_http2_stream *stream_conn,
							unsigned char *inpacket, int inpacket_len)
{
	struct http2_stream *stream = stream_conn->stream;

	if (stream == NULL) {
		return -1;
	}

	/* Send DNS response */
	/* Content-Type for DoH is application/dns-message */
	return _dns_server_http2_send_response(stream, 200, "application/dns-message", inpacket, inpacket_len);
}

static void _dns_server_http2_process_stream(struct dns_server_conn_tls_client *tls_client, struct http2_stream *stream)
{
	uint8_t buf[DNS_IN_PACKSIZE];
	int len = 0;

	const char *method = http2_stream_get_method(stream);
	if (method == NULL) {
		return;
	}

	if (strcasecmp(method, "POST") == 0) {
		/* Read request body */
		len = http2_stream_read_body(stream, buf, sizeof(buf));
		if (len < 0) {
			/* Error or no data yet */
			if (http2_stream_is_end(stream)) {
				goto close_out;
			}
			return;
		}

		if (len == 0 && !http2_stream_is_end(stream)) {
			/* No data available but stream not ended */
			return;
		}
	} else if (strcasecmp(method, "GET") == 0) {
		const char *path = http2_stream_get_path(stream);
		char *base64_query = NULL;

		if (http2_stream_get_ex_data(stream)) {
			goto close_out;
		}
		http2_stream_set_ex_data(stream, (void *)1);

		/* Consume any body (should be empty for GET) to mark stream as read-handled */
		http2_stream_read_body(stream, NULL, 0);

		if (path == NULL) {
			_dns_server_http2_send_response(stream, 404, "text/plain", "Not Found", 9);
			goto close_out;
		}

		/* Check path prefix */
		if (strncmp(path, "/dns-query", 10) != 0) {
			_dns_server_http2_send_response(stream, 404, "text/plain", "Not Found", 9);
			goto close_out;
		}

		/* Parse query string */
		char *query_val = http2_stream_get_query_param(stream, "dns");
		if (query_val == NULL) {
			_dns_server_http2_send_response(stream, 400, "text/plain", "Bad Request", 11);
			goto close_out;
		}

		base64_query = malloc(DNS_IN_PACKSIZE);
		if (base64_query == NULL) {
			free(query_val);
			_dns_server_http2_send_response(stream, 500, "text/plain", "Bad Request", 11);
			goto close_out;
		}

		if (urldecode(base64_query, DNS_IN_PACKSIZE, query_val) < 0) {
			free(query_val);
			free(base64_query);
			_dns_server_http2_send_response(stream, 400, "text/plain", "Bad Request", 11);
			goto close_out;
		}
		free(query_val);

		len = SSL_base64_decode_ext(base64_query, buf, sizeof(buf), 1, 1);
		free(base64_query);

		if (len <= 0) {
			_dns_server_http2_send_response(stream, 400, "text/plain", "Bad Request", 11);
			goto close_out;
		}
	} else {
		_dns_server_http2_send_response(stream, 405, "text/plain", "Method Not Allowed", 18);
		goto close_out;
	}

	if (len > 0) {
		/* Create a fake connection object for this stream */
		struct dns_server_conn_http2_stream *stream_conn = zalloc(1, sizeof(struct dns_server_conn_http2_stream));
		if (stream_conn == NULL) {
			_dns_server_http2_send_response(stream, 500, "text/plain", "Bad Request", 11);
			goto close_out;
		}

		/* Initialize the fake connection */
		_dns_server_conn_head_init(&stream_conn->head, -1, DNS_CONN_TYPE_HTTP2_STREAM);
		stream_conn->stream = stream;
		stream_conn->tls_client = tls_client;

		/* Copy properties from parent connection */
		stream_conn->head.server_flags = tls_client->tcp.head.server_flags;
		stream_conn->head.dns_group = tls_client->tcp.head.dns_group;
		stream_conn->head.ipset_nftset_rule = tls_client->tcp.head.ipset_nftset_rule;

		/* We need to increment refcnt because _dns_server_recv (via request) will eventually release it */
		_dns_server_conn_get(&stream_conn->head);

		/* Process the packet */
		/* Note: _dns_server_recv takes conn, inpacket, inpacket_len, local, local_len, from, from_len */
		_dns_server_recv(&stream_conn->head, buf, len, &tls_client->tcp.localaddr, tls_client->tcp.localaddr_len,
						 &tls_client->tcp.addr, tls_client->tcp.addr_len);

		/* Release our reference (request holds one now) */
		_dns_server_conn_release(&stream_conn->head);
	}

	return;

close_out:
	if (stream != NULL) {
		/* Close stream on error */
		http2_stream_close(stream);
	}
}

int _dns_server_process_http2(struct dns_server_conn_tls_client *tls_client, struct epoll_event *event,
							  unsigned long now)
{
	struct http2_ctx *ctx = (struct http2_ctx *)tls_client->http2_ctx;
	int ret = 0;

	/* Initialize HTTP/2 context if not already done */
	if (ctx == NULL) {
		struct http2_settings settings;
		memset(&settings, 0, sizeof(settings));
		settings.max_concurrent_streams = DNS_SERVER_HTTP2_MAX_CONCURRENT_STREAMS;
		ctx = http2_ctx_server_new("smartdns-server", _http2_server_bio_read, _http2_server_bio_write, tls_client,
								   &settings);
		if (ctx == NULL) {
			tlog(TLOG_ERROR, "init http2 context failed.");
			return -1;
		}
		if (tls_client->http2_ctx != NULL) {
			http2_ctx_close(tls_client->http2_ctx);
		}
		tls_client->http2_ctx = ctx;

		/* Perform initial handshake */
		ret = http2_ctx_handshake(ctx);
		if (ret < 0) {
			const char *err_msg = http2_error_to_string(ret);
			int log_level = TLOG_ERROR;
			if (ret == HTTP2_ERR_EOF || ret == HTTP2_ERR_HTTP1) {
				log_level = TLOG_DEBUG; /* Less noisy for clients that disconnect early or misbehave */
			}
			tlog(log_level, "http2 handshake failed, ret=%d (%s), alpn=%s.", ret, err_msg, tls_client->alpn_selected);
			return -1;
		}
	}

	/* Handle EPOLLOUT - flush pending writes */
	if (event->events & EPOLLOUT) {
		struct http2_poll_item poll_items[1];
		int poll_count = 0;
		int loop = 0;
		while (http2_ctx_want_write(ctx) && loop++ < 10) {
			ret = http2_ctx_poll(ctx, poll_items, 1, &poll_count);
			if (ret < 0) {
				break;
			}
		}
	}

	/* Handle EPOLLIN - read and process data */
	if (event->events & EPOLLIN) {
		struct http2_poll_item poll_items[10];
		int poll_count = 0;
		int loop_count = 0;
		const int MAX_LOOP_COUNT = 128;

		/* Ensure handshake is complete */
		ret = http2_ctx_handshake(ctx);
		if (ret < 0) {
			const char *err_msg = http2_error_to_string(ret);
			int log_level = TLOG_ERROR;
			if (ret == HTTP2_ERR_EOF || ret == HTTP2_ERR_HTTP1) {
				log_level = TLOG_DEBUG; /* Less noisy for clients that disconnect early or misbehave */
			}
			tlog(log_level, "http2 handshake failed, ret=%d (%s), alpn=%s.", ret, err_msg, tls_client->alpn_selected);
			return -1;
		} else if (ret == 0) {
			/* Handshake in progress */
			goto update_epoll;
		}

		/* Poll and process */
		while (loop_count++ < MAX_LOOP_COUNT) {
			poll_count = 0;
			ret = http2_ctx_poll_readable(ctx, poll_items, 10, &poll_count);
			if (ret < 0) {
				if (ret == HTTP2_ERR_EAGAIN) {
					break;
				}
				if (ret == HTTP2_ERR_EOF) {
					/* Connection closed by peer */
					_dns_server_client_close(&tls_client->tcp.head);
					return 0;
				}
				tlog(TLOG_DEBUG, "http2 poll failed, %s", http2_error_to_string(ret));
				return -1;
			}

			if (poll_count == 0) {
				continue;
			}

			for (int i = 0; i < poll_count; i++) {
				if (poll_items[i].stream == NULL) {
					if (poll_items[i].readable) {
						struct http2_stream *stream = http2_ctx_accept_stream(ctx);
						if (stream) {
							/* Accept and immediately process new HTTP/2 stream */
							_dns_server_http2_process_stream(tls_client, stream);
						}
					}
					continue;
				}

				if (poll_items[i].stream && poll_items[i].readable) {
					_dns_server_http2_process_stream(tls_client, poll_items[i].stream);
				}
			}
		}
	}

update_epoll:
	/* Update epoll events */
	{
		int epoll_events = EPOLLIN;
		if (http2_ctx_want_write(ctx)) {
			epoll_events |= EPOLLOUT;
		}

		struct epoll_event mod_event;
		memset(&mod_event, 0, sizeof(mod_event));
		mod_event.events = epoll_events;
		mod_event.data.ptr = tls_client;

		if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, tls_client->tcp.head.fd, &mod_event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}
