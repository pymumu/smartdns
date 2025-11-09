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
#include "server_info.h"

#include "smartdns/http_parse.h"

#include <stdlib.h>
#include <string.h>

/* HTTP/2 connection preface (RFC 7540 Section 3.5) */
static const unsigned char HTTP2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define HTTP2_PREFACE_LEN 24

/* HTTP/2 Frame Header Size */
#define HTTP2_FRAME_HEADER_SIZE 9

/* HTTP/2 Frame Types */
#define HTTP2_FRAME_SETTINGS 0x4

/* Initialize HTTP/2 context */
struct http2_context *http2_context_init(int is_server)
{
	struct http2_context *ctx = NULL;
	
	ctx = malloc(sizeof(struct http2_context));
	if (ctx == NULL) {
		return NULL;
	}
	
	memset(ctx, 0, sizeof(struct http2_context));
	
	/* Initialize stream ID: odd for client, even for server */
	ctx->next_stream_id = is_server ? 2 : 1;
	
	/* Default SETTINGS */
	ctx->max_concurrent_streams = 100;
	ctx->initial_window_size = 65535;
	ctx->max_frame_size = 16384;
	
	/* Initialize stream list */
	INIT_LIST_HEAD(&ctx->stream_list);
	ctx->stream_count = 0;
	
	/* Allocate connection buffer for incomplete frames */
	ctx->conn_buffer_size = 32768;
	ctx->conn_buffer = malloc(ctx->conn_buffer_size);
	if (ctx->conn_buffer == NULL) {
		free(ctx);
		return NULL;
	}
	ctx->conn_buffer_len = 0;
	
	ctx->initialized = 1;
	
	return ctx;
}

/* Destroy HTTP/2 context */
void http2_context_destroy(struct http2_context *ctx)
{
	struct http2_stream *stream = NULL;
	struct http2_stream *tmp = NULL;
	
	if (ctx == NULL) {
		return;
	}
	
	/* Free all streams */
	list_for_each_entry_safe(stream, tmp, &ctx->stream_list, list)
	{
		list_del(&stream->list);
		if (stream->recv_buffer) {
			free(stream->recv_buffer);
		}
		free(stream);
	}
	
	/* Free connection buffer */
	if (ctx->conn_buffer) {
		free(ctx->conn_buffer);
	}
	
	free(ctx);
}

/* Create a new stream */
struct http2_stream *http2_stream_create(struct http2_context *ctx)
{
	struct http2_stream *stream = NULL;
	
	if (ctx == NULL || !ctx->initialized) {
		return NULL;
	}
	
	stream = malloc(sizeof(struct http2_stream));
	if (stream == NULL) {
		return NULL;
	}
	
	memset(stream, 0, sizeof(struct http2_stream));
	
	/* Assign stream ID */
	stream->stream_id = ctx->next_stream_id;
	ctx->next_stream_id += 2;  /* Skip to next odd/even number */
	
	stream->state = HTTP2_STREAM_IDLE;
	
	/* Allocate receive buffer */
	stream->recv_buffer_size = 65536;
	stream->recv_buffer = malloc(stream->recv_buffer_size);
	if (stream->recv_buffer == NULL) {
		free(stream);
		return NULL;
	}
	stream->recv_buffer_len = 0;
	
	stream->create_time = time(NULL);
	
	/* Add to stream list */
	list_add_tail(&stream->list, &ctx->stream_list);
	ctx->stream_count++;
	
	return stream;
}

/* Find stream by ID */
struct http2_stream *http2_stream_find(struct http2_context *ctx, uint32_t stream_id)
{
	struct http2_stream *stream = NULL;
	
	if (ctx == NULL) {
		return NULL;
	}
	
	list_for_each_entry(stream, &ctx->stream_list, list)
	{
		if (stream->stream_id == stream_id) {
			return stream;
		}
	}
	
	return NULL;
}

/* Close and destroy a stream */
void http2_stream_close(struct http2_context *ctx, struct http2_stream *stream)
{
	if (ctx == NULL || stream == NULL) {
		return;
	}
	
	/* Remove from list */
	list_del(&stream->list);
	ctx->stream_count--;
	
	/* Free buffers */
	if (stream->recv_buffer) {
		free(stream->recv_buffer);
	}
	
	free(stream);
}

int _dns_client_send_http2_preface(struct dns_server_info *server_info)
{
	unsigned char buffer[256];
	int offset = 0;
	int send_len = 0;
	
	/* Initialize HTTP/2 context if needed */
	if (server_info->http2_ctx == NULL) {
		server_info->http2_ctx = http2_context_init(0);  /* 0 = client */
		if (server_info->http2_ctx == NULL) {
			tlog(TLOG_ERROR, "failed to initialize HTTP/2 context.");
			return -1;
		}
	}
	
	/* Set ALPN for HTTP/2 if not already set */
	if (server_info->flags.https.alpn[0] == '\0') {
		/* Set ALPN to "h2" for HTTP/2 */
		strncpy(server_info->flags.https.alpn, "h2", DNS_MAX_ALPN_LEN - 1);
		server_info->flags.https.alpn[DNS_MAX_ALPN_LEN - 1] = '\0';
		tlog(TLOG_DEBUG, "Setting ALPN to h2 for HTTP/2");
	}

	/* Send HTTP/2 connection preface */
	memcpy(buffer, HTTP2_PREFACE, HTTP2_PREFACE_LEN);
	offset = HTTP2_PREFACE_LEN;

	/* Send empty SETTINGS frame */
	/* Frame length: 0 */
	buffer[offset++] = 0x00;
	buffer[offset++] = 0x00;
	buffer[offset++] = 0x00;
	/* Frame type: SETTINGS */
	buffer[offset++] = HTTP2_FRAME_SETTINGS;
	/* Flags: 0 */
	buffer[offset++] = 0x00;
	/* Stream ID: 0 */
	buffer[offset++] = 0x00;
	buffer[offset++] = 0x00;
	buffer[offset++] = 0x00;
	buffer[offset++] = 0x00;

	/* Send the preface and SETTINGS */
	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, buffer, offset);
	}

	if (server_info->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	send_len = _dns_client_socket_ssl_send(server_info, buffer, offset);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			return _dns_client_send_data_to_buffer(server_info, buffer, offset);
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < offset) {
		return _dns_client_send_data_to_buffer(server_info, buffer + send_len, offset - send_len);
	}

	return 0;
}

int _dns_client_send_http2(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;
	struct client_dns_server_flag_https *https_flag = NULL;
	struct http_head *http_head = NULL;
	struct http2_context *ctx = NULL;
	struct http2_stream *stream = NULL;

	if (len > sizeof(inpacket_data) - 512) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}
	
	/* Initialize HTTP/2 context if needed */
	if (server_info->http2_ctx == NULL) {
		server_info->http2_ctx = http2_context_init(0);  /* 0 = client */
		if (server_info->http2_ctx == NULL) {
			tlog(TLOG_ERROR, "failed to initialize HTTP/2 context.");
			return -1;
		}
	}
	
	ctx = (struct http2_context *)server_info->http2_ctx;
	
	/* Create a new stream for this request */
	stream = http2_stream_create(ctx);
	if (stream == NULL) {
		tlog(TLOG_ERROR, "failed to create HTTP/2 stream.");
		return -1;
	}
	
	stream->state = HTTP2_STREAM_OPEN;

	https_flag = &server_info->flags.https;

	/* Build HTTP/2 request using http_head */
	http_head = http_head_init(4096, HTTP_VERSION_2_0);
	if (http_head == NULL) {
		tlog(TLOG_ERROR, "init http head failed.");
		http2_stream_close(ctx, stream);
		return -1;
	}

	http_head_set_method(http_head, HTTP_METHOD_POST);
	http_head_set_url(http_head, https_flag->path);
	http_head_set_head_type(http_head, HTTP_HEAD_REQUEST);
	http_head_add_fields(http_head, ":authority", https_flag->httphost);
	http_head_add_fields(http_head, "content-type", "application/dns-message");
	http_head_add_fields(http_head, "accept", "application/dns-message");
	http_head_add_fields(http_head, "user-agent", "smartdns");
	http_head_set_data(http_head, packet, len);

	http_len = http_head_serialize(http_head, inpacket, DNS_IN_PACKSIZE);
	http_head_destroy(http_head);

	if (http_len <= 0) {
		tlog(TLOG_ERROR, "serialize http head failed.");
		http2_stream_close(ctx, stream);
		return -1;
	}
	
	/* Store request data in stream for tracking */
	stream->request_data = packet;
	stream->request_data_len = len;

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, http_len);
	}

	if (server_info->ssl == NULL) {
		errno = EINVAL;
		http2_stream_close(ctx, stream);
		return -1;
	}

	send_len = _dns_client_socket_ssl_send(server_info, inpacket, http_len);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, http_len);
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		http2_stream_close(ctx, stream);
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, http_len - send_len);
	}
	
	/* Stream will be closed after receiving response */

	return 0;
}

int _dns_client_process_http2_response(struct dns_server_info *server_info)
{
	int len = 0;
	struct http_head *http_head = NULL;
	unsigned char *inpacket_data = NULL;
	int dns_packet_len = 0;
	int ret = -1;
	struct http2_context *ctx = NULL;
	struct http2_stream *stream = NULL;
	
	/* Get HTTP/2 context */
	ctx = (struct http2_context *)server_info->http2_ctx;
	if (ctx == NULL || !ctx->initialized) {
		tlog(TLOG_ERROR, "HTTP/2 context not initialized.");
		return -1;
	}

	http_head = http_head_init(8192, HTTP_VERSION_2_0);
	if (http_head == NULL) {
		goto out;
	}

	len = http_head_parse(http_head, server_info->recv_buff.data, server_info->recv_buff.len);
	if (len < 0) {
		if (len == -1) {
			/* Incomplete response, wait for more data */
			ret = 0;
			goto out;
		} else if (len == -3) {
			/* Response is too large */
			tlog(TLOG_DEBUG, "http2 response is too large.");
			server_info->recv_buff.len = 0;
			goto out;
		}

		tlog(TLOG_DEBUG, "remote server not supported or parse error.");
		goto out;
	}

	if (http_head_get_httpcode(http_head) == 0) {
		/* Invalid HTTP/2 response */
		server_info->prohibit = 1;
		goto out;
	}

	if (http_head_get_httpcode(http_head) != 200) {
		tlog(TLOG_WARN, "http2 server query from %s:%d failed, server return http code : %d, %s", server_info->ip,
			 server_info->port, http_head_get_httpcode(http_head), http_head_get_httpcode_msg(http_head));
		server_info->prohibit = 1;
		goto out;
	}

	inpacket_data = (unsigned char *)http_head_get_data(http_head);
	dns_packet_len = http_head_get_data_len(http_head);

	if (inpacket_data == NULL || dns_packet_len <= 0) {
		tlog(TLOG_WARN, "recv http2 packet from %s, len = %d", server_info->ip, len);
		goto out;
	}

	tlog(TLOG_DEBUG, "recv http2 packet from %s, len = %d", server_info->ip, len);
	time(&server_info->last_recv);

	/* Process DNS result */
	if (_dns_client_recv(server_info, inpacket_data, dns_packet_len, &server_info->addr, server_info->ai_addrlen) !=
		0) {
		goto out;
	}
	
	/* Close the stream for this request (we use stream ID 1 for simplicity in DoH) */
	/* In a more complete implementation, we would track which stream ID corresponds to which request */
	if (!list_empty(&ctx->stream_list)) {
		stream = list_first_entry(&ctx->stream_list, struct http2_stream, list);
		http2_stream_close(ctx, stream);
	}

	/* Remove processed data from buffer */
	server_info->recv_buff.len -= len;
	if (server_info->recv_buff.len < 0) {
		server_info->recv_buff.len = 0;
	}

	if (server_info->recv_buff.len > 0) {
		memmove(server_info->recv_buff.data, server_info->recv_buff.data + len, server_info->recv_buff.len);
	}

	ret = 0;
out:
	if (http_head) {
		http_head_destroy(http_head);
	}
	return ret;
}
