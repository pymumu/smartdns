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

#ifndef _DNS_CLIENT_HTTP2_H_
#define _DNS_CLIENT_HTTP2_H_

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

/* HTTP/2 Stream State */
typedef enum {
	HTTP2_STREAM_IDLE = 0,
	HTTP2_STREAM_OPEN,
	HTTP2_STREAM_HALF_CLOSED_LOCAL,
	HTTP2_STREAM_HALF_CLOSED_REMOTE,
	HTTP2_STREAM_CLOSED
} http2_stream_state_t;

/* HTTP/2 Stream */
struct http2_stream {
	struct list_head list;
	uint32_t stream_id;
	http2_stream_state_t state;
	
	/* Stream buffers */
	unsigned char *recv_buffer;
	int recv_buffer_size;
	int recv_buffer_len;
	
	/* Request tracking */
	void *request_data;
	int request_data_len;
	time_t create_time;
};

/* HTTP/2 Connection Context */
struct http2_context {
	/* Connection state */
	int initialized;
	uint32_t next_stream_id;  /* Next stream ID to use (odd for client, even for server) */
	
	/* SETTINGS */
	uint32_t max_concurrent_streams;
	uint32_t initial_window_size;
	uint32_t max_frame_size;
	
	/* Streams */
	struct list_head stream_list;
	int stream_count;
	
	/* Connection buffer for incomplete frames */
	unsigned char *conn_buffer;
	int conn_buffer_size;
	int conn_buffer_len;
};

/* Initialize HTTP/2 context for a server connection */
struct http2_context *http2_context_init(int is_server);

/* Destroy HTTP/2 context */
void http2_context_destroy(struct http2_context *ctx);

/* Create a new stream */
struct http2_stream *http2_stream_create(struct http2_context *ctx);

/* Find stream by ID */
struct http2_stream *http2_stream_find(struct http2_context *ctx, uint32_t stream_id);

/* Close and destroy a stream */
void http2_stream_close(struct http2_context *ctx, struct http2_stream *stream);

/* Send HTTP/2 connection preface and SETTINGS frame */
int _dns_client_send_http2_preface(struct dns_server_info *server_info);

/* Send HTTP/2 DoH request */
int _dns_client_send_http2(struct dns_server_info *server_info, void *packet, unsigned short len);

/* Process HTTP/2 response */
int _dns_client_process_http2_response(struct dns_server_info *server_info);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
