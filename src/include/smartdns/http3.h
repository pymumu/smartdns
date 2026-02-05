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

#ifndef _HTTP3_H_
#define _HTTP3_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque structures */
struct http3_ctx;
struct http3_stream;

/* HTTP/3 Settings structure */
struct http3_settings {
	int max_concurrent_streams;
	int qpack_max_table_capacity;
	int qpack_blocked_streams;
};

/* Error codes */
enum {
	HTTP3_ERR_NONE = 0,
	HTTP3_ERR_EAGAIN = -1,
	HTTP3_ERR_EOF = -2,
	HTTP3_ERR_IO = -3,
	HTTP3_ERR_PROTOCOL = -4,
};

/* BIO callback types - Abstraction for reading/writing underlying QUIC streams */
typedef int (*http3_bio_read_fn)(void *private_data, uint8_t *buf, int len);
typedef int (*http3_bio_write_fn)(void *private_data, const uint8_t *buf, int len, int eos);

/* Poll item */
struct http3_poll_item {
	struct http3_stream *stream;
	int readable;
	int writable;
};

/* Connection Operations - Abstract Interface to Transport */
struct http3_conn_ops {
	/* Create a new stream on the underlying connection */
	/* type: 0 = Bidirectional, 1 = Unidirectional */
	void *(*create_stream)(void *conn_data, int type);

	/* Close a stream handle associated with the transport */
	void (*close_stream)(void *stream_handle);

	/* BIO callbacks for the stream handles */
	int (*read)(void *stream_handle, uint8_t *buf, int len);
	int (*write)(void *stream_handle, const uint8_t *buf, int len, int eos);
};

/* Connection Lifecycle APIs */

struct http3_ctx *http3_ctx_client_new(void *conn_data, const struct http3_conn_ops *ops, const struct http3_settings *settings);
struct http3_ctx *http3_ctx_server_new(void *conn_data, const struct http3_conn_ops *ops, const struct http3_settings *settings);

void http3_ctx_close(struct http3_ctx *ctx);
struct http3_ctx *http3_ctx_get(struct http3_ctx *ctx);
void http3_ctx_put(struct http3_ctx *ctx);

/*
 * Handshake for H3 layer (e.g. SETTINGS frame exchange).
 * Assumes underlying QUIC handshake is complete.
 */
int http3_ctx_handshake(struct http3_ctx *ctx);

struct http3_stream *http3_ctx_accept_stream(struct http3_ctx *ctx);

/*
 * Drive the context.
 * For H3, we usually have a 1:1 map between H3 Stream and QUIC Stream.
 * But we also have Control Streams (Uni-directional).
 * This API might need to handle those.
 */
int http3_ctx_poll(struct http3_ctx *ctx, struct http3_poll_item *items, int max_items, int *ret_count);

/* Stream Management APIs */

struct http3_stream *http3_stream_new(struct http3_ctx *ctx);
void http3_stream_close(struct http3_stream *stream);
struct http3_stream *http3_stream_get(struct http3_stream *stream);
void http3_stream_put(struct http3_stream *stream);
int http3_stream_get_id(struct http3_stream *stream);

/* Header & Data APIs */

struct http3_header_pair {
	const char *name;
	const char *value;
};

int http3_stream_set_request(struct http3_stream *stream, const char *method, const char *path, const char *scheme,
							 const struct http3_header_pair *headers);
int http3_stream_set_response(struct http3_stream *stream, int status, const struct http3_header_pair *headers,
							  int header_count);

const char *http3_stream_get_method(struct http3_stream *stream);
const char *http3_stream_get_path(struct http3_stream *stream);
int http3_stream_get_status(struct http3_stream *stream);
const char *http3_stream_get_header(struct http3_stream *stream, const char *name);

/* Body APIs */
int http3_stream_write_body(struct http3_stream *stream, const uint8_t *data, int len, int end_stream);
int http3_stream_read_body(struct http3_stream *stream, uint8_t *data, int len);

/* BIO Setup for Stream */
/*
 * Unlike H2 where 1 connection = 1 socket, H3 has multiple QUIC streams.
 * Each H3 stream corresponds to a QUIC stream IO.
 * We need to attach BIO/IO capability to the H3 stream instance so it can read/write frames.
 */
void http3_stream_set_bio(struct http3_stream *stream, http3_bio_read_fn read, http3_bio_write_fn write,
						  void *private_data);

#ifdef __cplusplus
}
#endif

#endif /* _HTTP3_H_ */
