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

/* Include http2_parse header from http_parse directory */
#include "../http_parse/http2_parse.h"

#include <stdlib.h>
#include <string.h>

int _dns_client_send_http2_preface(struct dns_server_info *server_info)
{
	unsigned char buffer[256];
	int offset = 0;
	int send_len = 0;
	struct http2_context *ctx = NULL;
	
	/* Initialize HTTP/2 context if needed */
	if (server_info->http2_ctx == NULL) {
		server_info->http2_ctx = http2_context_init(0);  /* 0 = client */
		if (server_info->http2_ctx == NULL) {
			tlog(TLOG_ERROR, "failed to initialize HTTP/2 context.");
			return -1;
		}
	}
	
	ctx = (struct http2_context *)server_info->http2_ctx;

	/* Generate preface using http2_parse function */
	offset = http2_handshake(ctx, buffer, sizeof(buffer));
	if (offset < 0) {
		tlog(TLOG_ERROR, "failed to generate HTTP/2 preface.");
		return -1;
	}

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
	
	/* Get an available stream using http2_poll */
	if (http2_poll(ctx, &stream) != 0 || stream == NULL) {
		tlog(TLOG_ERROR, "failed to get available HTTP/2 stream.");
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
