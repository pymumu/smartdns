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

#include "smartdns/http2.h"
#include "smartdns/util.h"

#include "hpack.h"
#include "http_parse.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_ZLIB
#include <zlib.h>
#endif

const char *http2_error_to_string(int ret)
{
	switch (ret) {
	case HTTP2_ERR_NONE:
		return "no error";
	case HTTP2_ERR_EAGAIN:
		return "operation would block";
	case HTTP2_ERR_EOF:
		return "connection closed by client";
	case HTTP2_ERR_IO:
		return "I/O error";
	case HTTP2_ERR_PROTOCOL:
		return "protocol error";
	case HTTP2_ERR_HTTP1:
		return "client sent HTTP/1.1 after ALPN h2";
	default:
		return "unknown error";
	}
}

/* HTTP/2 Frame Types */
#define HTTP2_FRAME_DATA 0x00
#define HTTP2_FRAME_HEADERS 0x01
#define HTTP2_FRAME_PRIORITY 0x02
#define HTTP2_FRAME_RST_STREAM 0x03
#define HTTP2_FRAME_SETTINGS 0x04
#define HTTP2_FRAME_PUSH_PROMISE 0x05
#define HTTP2_FRAME_PING 0x06
#define HTTP2_FRAME_GOAWAY 0x07
#define HTTP2_FRAME_WINDOW_UPDATE 0x08
#define HTTP2_FRAME_CONTINUATION 0x09

/* HTTP/2 Error Codes for RST_STREAM and GOAWAY */
#define HTTP2_RST_NO_ERROR 0
#define HTTP2_RST_PROTOCOL_ERROR 1
#define HTTP2_RST_INTERNAL_ERROR 2
#define HTTP2_RST_FLOW_CONTROL_ERROR 3
#define HTTP2_RST_COMPRESSION_ERROR 9

/* HTTP/2 Frame Flags */
#define HTTP2_FLAG_END_STREAM 0x01
#define HTTP2_FLAG_END_HEADERS 0x04
#define HTTP2_FLAG_PADDED 0x08
#define HTTP2_FLAG_PRIORITY 0x20
#define HTTP2_FLAG_ACK 0x01

/* HTTP/2 Settings */
#define HTTP2_SETTINGS_HEADER_TABLE_SIZE 0x01
#define HTTP2_SETTINGS_ENABLE_PUSH 0x02
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 0x03
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 0x04
#define HTTP2_SETTINGS_MAX_FRAME_SIZE 0x05
#define HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 0x06

/* Default values */
#define HTTP2_DEFAULT_WINDOW_SIZE 65535
#define HTTP2_DEFAULT_MAX_FRAME_SIZE 16384
#define HTTP2_FRAME_HEADER_SIZE 9
#define HTTP2_MAX_HEADER_TABLE_SIZE 65536
#define HTTP2_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_CONNECTION_PREFACE_LEN 24

/* Stream states */
typedef enum {
	HTTP2_STREAM_IDLE,
	HTTP2_STREAM_OPEN,
	HTTP2_STREAM_HALF_CLOSED_LOCAL,
	HTTP2_STREAM_HALF_CLOSED_REMOTE,
	HTTP2_STREAM_CLOSED
} http2_stream_state_t;

/* Stream structure */
struct http2_stream {
	struct http2_ctx *ctx;
	int refcount; /* Atomic reference count */
	uint32_t stream_id;
	http2_stream_state_t state;

	/* Headers using hashmap like http_head */
	struct http_head_fields header_list;
	DECLARE_HASHTABLE(header_map, 4);

	uint8_t *body_buffer;
	int body_buffer_size;
	int body_buffer_len;
	int body_read_offset;
	int end_stream_received;
	int end_stream_sent;
	int end_stream_read_handled; /* Flag to track if EOF has been reported to app */
	int accepted;                /* Flag to track if stream has been accepted by app */
	int window_size;
	int body_decompressed; /* Flag to track if body has been decompressed */
	void *ex_data;
	struct hlist_node hash_node;
	struct list_head node;
};

/* HTTP/2 context */
struct http2_ctx {
	pthread_mutex_t mutex;
	int refcount; /* Atomic reference count */
	int is_client;
	char *server;
	http2_bio_read_fn bio_read;
	http2_bio_write_fn bio_write;
	void *private_data;

	/* Connection state */
	int status; /* 0: connected, <0: error code */
	int handshake_complete;
	int settings_received;
	int preface_received; /* Server: has received client preface */
	uint32_t next_stream_id;
	int connection_window_size;
	uint32_t peer_max_frame_size;
	int peer_initial_window_size;
	int active_streams;
	struct http2_settings settings; /* HTTP/2 settings */

	/* I/O state */
	int want_read;
	int want_write;
	uint8_t *pending_write_buffer;
	int pending_write_len;
	int pending_write_capacity;

	/* HPACK */
	struct hpack_context encoder;
	struct hpack_context decoder;

	/* Streams */
	DECLARE_HASHTABLE(stream_map, 8);
	struct list_head streams;

	/* Frame buffers */
	uint8_t read_buffer[HTTP2_DEFAULT_MAX_FRAME_SIZE + HTTP2_FRAME_HEADER_SIZE];
	int read_buffer_len;
	uint8_t write_buffer[HTTP2_DEFAULT_MAX_FRAME_SIZE + HTTP2_FRAME_HEADER_SIZE];
	int write_buffer_len;
};

/* Public API implementation */
struct http2_ctx_init_params {
	const char *server;
	http2_bio_read_fn bio_read;
	http2_bio_write_fn bio_write;
	void *private_data;
	const struct http2_settings *settings;
	int is_client;
	uint32_t next_stream_id;
};

/* Forward declarations */
static int _http2_send_settings(struct http2_ctx *ctx, int ack);
static int _http2_send_window_update(struct http2_ctx *ctx, uint32_t stream_id, int increment);
static int _http2_process_frames(struct http2_ctx *ctx);
static int http2_send_rst_stream(struct http2_ctx *ctx, uint32_t stream_id, uint32_t error_code);

static void _http2_free_headers(struct http2_stream *stream);
static struct http2_stream *_http2_find_stream(struct http2_ctx *ctx, uint32_t stream_id);
static int _http2_stream_add_header(struct http2_stream *stream, const char *name, const char *value);

/* Utility functions */

static uint32_t read_uint32(const uint8_t *data)
{
	return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static void write_uint32(uint8_t *data, uint32_t value)
{
	data[0] = (value >> 24) & 0xFF;
	data[1] = (value >> 16) & 0xFF;
	data[2] = (value >> 8) & 0xFF;
	data[3] = value & 0xFF;
}

static uint32_t read_uint24(const uint8_t *data)
{
	return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8) | (uint32_t)data[2];
}

static void write_uint24(uint8_t *data, uint32_t value)
{
	data[0] = (value >> 16) & 0xFF;
	data[1] = (value >> 8) & 0xFF;
	data[2] = value & 0xFF;
}

/* Safe buffer size calculation to prevent integer overflow */
static int safe_buffer_size(int current, int factor)
{
	if (current <= 0 || factor <= 0) return current;
	if ((size_t)current > (size_t)INT_MAX / (size_t)factor) return -1; /* Overflow */
	return current * factor;
}

/* HPACK callback */
static int _http2_on_header(void *ctx, const char *name, const char *value)
{
	struct http2_stream *stream = (struct http2_stream *)ctx;
	return _http2_stream_add_header(stream, name, value);
}

static void _http2_free_headers(struct http2_stream *stream)
{
	struct http_head_fields *fields = NULL, *tmp;

	list_for_each_entry_safe(fields, tmp, &stream->header_list.list, list)
	{
		list_del(&fields->list);
		free((void *)fields->name);
		free((void *)fields->value);
		free(fields);
	}

	hash_init(stream->header_map);
}

static int _http2_stream_add_header(struct http2_stream *stream, const char *name, const char *value)
{
	uint32_t key = 0;
	struct http_head_fields *fields = NULL;

	if (name == NULL || value == NULL) {
		return -1;
	}

	fields = zalloc(1, sizeof(*fields));
	if (fields == NULL) {
		return -1;
	}

	fields->name = strdup(name);
	fields->value = strdup(value);
	if (!fields->name || !fields->value) {
		free((void *)fields->name);
		free((void *)fields->value);
		free(fields);
		return -1;
	}

	list_add_tail(&fields->list, &stream->header_list.list);
	key = hash_string_case(name);
	hash_add(stream->header_map, &fields->node, key);

	return 0;
}

static const char *_http2_stream_get_header_value(struct http2_stream *stream, const char *name)
{
	uint32_t key;
	struct http_head_fields *field = NULL;

	key = hash_string_case(name);
	hash_for_each_possible(stream->header_map, field, node, key)
	{
		if (strncasecmp(field->name, name, 128) == 0) {
			return field->value;
		}
	}

	return NULL;
}

void http2_stream_headers_walk(struct http2_stream *stream, header_walk_fn fn, void *arg)
{
	struct list_head *pos;
	if (!stream || !fn) {
		return;
	}

	list_for_each(pos, &stream->header_list.list)
	{
		struct http_head_fields *pair = list_entry(pos, struct http_head_fields, list);
		fn(arg, pair->name, pair->value);
	}
}

/* Frame handling */

static int _http2_write_frame_header(uint8_t *buf, int length, uint8_t type, uint8_t flags, uint32_t stream_id)
{
	write_uint24(buf, length);
	buf[3] = type;
	buf[4] = flags;
	write_uint32(buf + 5, stream_id & 0x7FFFFFFF);
	return HTTP2_FRAME_HEADER_SIZE;
}

static int _http2_send_frame(struct http2_ctx *ctx, const uint8_t *data, int len)
{
	/* Check if connection is already closed */
	if (ctx->status < 0) {
		return -1;
	}

	int total_sent = 0;
	int unsent = 0;

	/* First, try to flush any pending writes */
	if (ctx->pending_write_len > 0) {
		int ret = ctx->bio_write(ctx->private_data, ctx->pending_write_buffer, ctx->pending_write_len);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ctx->want_write = 1;
				/* Still have pending data, buffer new data too */
				goto buffer_new_data;
			}
			/* Real error */
			return -1;
		}

		if (ret > 0) {
			/* Partial or complete write */
			if (ret < ctx->pending_write_len) {
				/* Partial write, move remaining data */
				memmove(ctx->pending_write_buffer, ctx->pending_write_buffer + ret, ctx->pending_write_len - ret);
				ctx->pending_write_len -= ret;
				ctx->want_write = 1;
				goto buffer_new_data;
			} else {
				/* Complete write of pending data */
				ctx->pending_write_len = 0;
				ctx->want_write = 0;
			}
		} else if (ret == 0) {
			/* Connection closed */
			ctx->status = HTTP2_ERR_EOF;
			return -1;
		}
	}

	/* Now try to send the new data */
	while (total_sent < len) {
		int ret = ctx->bio_write(ctx->private_data, data + total_sent, len - total_sent);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ctx->want_write = 1;
				/* Buffer remaining data */
				goto buffer_new_data;
			}
			/* Real error */
			return -1;
		}

		if (ret == 0) {
			/* Connection closed */
			ctx->status = HTTP2_ERR_EOF;
			return -1;
		}

		total_sent += ret;
	}

	ctx->want_write = 0;
	return len;

buffer_new_data:
	/* Buffer the unsent data */
	unsent = len - total_sent;
	if (unsent > 0) {
		/* Ensure buffer capacity */
		int needed = ctx->pending_write_len + unsent;
		if (needed > ctx->pending_write_capacity) {
			int new_capacity = ctx->pending_write_capacity ? safe_buffer_size(ctx->pending_write_capacity, 2) : 8192;
			if (new_capacity < 0) {
				return -1;
			}
			while (new_capacity < needed) {
				int temp = safe_buffer_size(new_capacity, 2);
				if (temp < 0) {
					return -1;
				}
				new_capacity = temp;
			}
			uint8_t *new_buffer = realloc(ctx->pending_write_buffer, new_capacity);
			if (!new_buffer) {
				return -1;
			}
			ctx->pending_write_buffer = new_buffer;
			ctx->pending_write_capacity = new_capacity;
		}

		/* Append unsent data to buffer */
		memcpy(ctx->pending_write_buffer + ctx->pending_write_len, data + total_sent, unsent);
		ctx->pending_write_len += unsent;
	}

	ctx->want_write = 1;
	return len; /* Return success - data is buffered */
}

static int _http2_send_settings(struct http2_ctx *ctx, int ack)
{
	uint8_t frame[HTTP2_FRAME_HEADER_SIZE + 256]; /* Increased size for ENABLE_PUSH */
	int offset = HTTP2_FRAME_HEADER_SIZE;
	uint8_t flags = ack ? HTTP2_FLAG_ACK : 0;

	if (!ack) {
		/* Client: Disable Server Push */
		if (ctx->is_client) {
			write_uint32(frame + offset, (HTTP2_SETTINGS_ENABLE_PUSH << 16) | 0);
			write_uint32(frame + offset + 2, 0); /* 0 = disabled */
			offset += 6;
		}

		/* SETTINGS_HEADER_TABLE_SIZE */
		write_uint32(frame + offset, (HTTP2_SETTINGS_HEADER_TABLE_SIZE << 16) | 0);
		write_uint32(frame + offset + 2, HTTP2_MAX_HEADER_TABLE_SIZE);
		offset += 6;

		/* SETTINGS_INITIAL_WINDOW_SIZE */
		write_uint32(frame + offset, (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE << 16) | 0);
		write_uint32(frame + offset + 2, HTTP2_DEFAULT_WINDOW_SIZE);
		offset += 6;

		/* SETTINGS_MAX_FRAME_SIZE */
		write_uint32(frame + offset, (HTTP2_SETTINGS_MAX_FRAME_SIZE << 16) | 0);
		write_uint32(frame + offset + 2, HTTP2_DEFAULT_MAX_FRAME_SIZE);
		offset += 6;

		if (ctx->settings.max_concurrent_streams > 0) {
			/* SETTINGS_MAX_CONCURRENT_STREAMS */
			write_uint32(frame + offset, (HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS << 16) | 0);
			write_uint32(frame + offset + 2, ctx->settings.max_concurrent_streams);
			offset += 6;
		}
	}

	_http2_write_frame_header(frame, offset - HTTP2_FRAME_HEADER_SIZE, HTTP2_FRAME_SETTINGS, flags, 0);
	return _http2_send_frame(ctx, frame, offset);
}

static int _http2_send_window_update(struct http2_ctx *ctx, uint32_t stream_id, int increment)
{
	uint8_t frame[HTTP2_FRAME_HEADER_SIZE + 4];

	_http2_write_frame_header(frame, 4, HTTP2_FRAME_WINDOW_UPDATE, 0, stream_id);
	write_uint32(frame + HTTP2_FRAME_HEADER_SIZE, increment & 0x7FFFFFFF);

	return _http2_send_frame(ctx, frame, sizeof(frame));
}

static int _http2_send_goaway(struct http2_ctx *ctx, uint32_t last_stream_id, uint32_t error_code, const uint8_t *debug_data, int debug_len)
{
	uint8_t frame[HTTP2_FRAME_HEADER_SIZE + 8 + 256];
	int offset = HTTP2_FRAME_HEADER_SIZE;

	write_uint32(frame + offset, last_stream_id & 0x7FFFFFFF);
	write_uint32(frame + offset + 4, error_code);
	if (debug_len > 0 && debug_len <= 256) {
		memcpy(frame + offset + 8, debug_data, debug_len);
	} else {
		debug_len = 0;
	}

	_http2_write_frame_header(frame, 8 + debug_len, HTTP2_FRAME_GOAWAY, 0, 0);
	return _http2_send_frame(ctx, frame, HTTP2_FRAME_HEADER_SIZE + 8 + debug_len);
}

static int _http2_send_data_frame(struct http2_ctx *ctx, uint32_t stream_id, const uint8_t *data, int len, int end_stream)
{
	uint8_t *frame = zalloc(1, HTTP2_FRAME_HEADER_SIZE + len);
	if (!frame) {
		return -1;
	}

	uint8_t flags = end_stream ? HTTP2_FLAG_END_STREAM : 0;
	_http2_write_frame_header(frame, len, HTTP2_FRAME_DATA, flags, stream_id);
	if (len > 0) {
		memcpy(frame + HTTP2_FRAME_HEADER_SIZE, data, len);
	}

	int ret = _http2_send_frame(ctx, frame, HTTP2_FRAME_HEADER_SIZE + len);
	free(frame);
	return ret;
}

static int _http2_send_headers_frame(struct http2_ctx *ctx, uint32_t stream_id, struct http2_stream *stream, int end_stream,
									int end_headers)
{
	uint8_t *header_block = zalloc(1, 4096);
	int header_block_size = 4096;
	int header_block_len = 0;
	struct http_head_fields *field;
	uint8_t flags = 0;
	int ret = -1;
	
	if (!header_block) {
		return -1;
	}

	if (end_stream) {
		flags |= HTTP2_FLAG_END_STREAM;
	}
	if (end_headers) {
		flags |= HTTP2_FLAG_END_HEADERS;
	}
	
	/* Encode headers */
	list_for_each_entry(field, &stream->header_list.list, list)
	{
		if (header_block_len + 4096 > header_block_size) {
			int new_size = safe_buffer_size(header_block_size, 2);
			if (new_size < 0) {
				goto cleanup;
			}
			uint8_t *new_block = realloc(header_block, new_size);
			if (!new_block) {
				goto cleanup;
			}
			header_block = new_block;
			header_block_size = new_size;
		}
		int encode_ret = hpack_encode_header(&ctx->encoder, field->name, field->value, header_block + header_block_len,
									  header_block_size - header_block_len);
		if (encode_ret < 0) {
			goto cleanup;
		}
		header_block_len += encode_ret;
	}

	/* Send HEADERS frame */
	uint8_t frame[HTTP2_FRAME_HEADER_SIZE];
	_http2_write_frame_header(frame, header_block_len, HTTP2_FRAME_HEADERS, flags, stream_id);

	if (_http2_send_frame(ctx, frame, HTTP2_FRAME_HEADER_SIZE) < 0) {
		goto cleanup;
	}

	if (header_block_len > 0 && _http2_send_frame(ctx, header_block, header_block_len) < 0) {
		goto cleanup;
	}

	ret = 0;

cleanup:
	free(header_block);
	return ret;
}

static struct http2_stream *_http2_find_stream(struct http2_ctx *ctx, uint32_t stream_id)
{
	struct http2_stream *stream;

	pthread_mutex_lock(&ctx->mutex);
	hash_for_each_possible(ctx->stream_map, stream, hash_node, stream_id) {
		if (stream->stream_id == stream_id) {
			pthread_mutex_unlock(&ctx->mutex);
			return stream;
		}
	}
	pthread_mutex_unlock(&ctx->mutex);
	return NULL;
}

static struct http2_stream *_http2_create_stream(struct http2_ctx *ctx, uint32_t stream_id)
{
	/* Check concurrent streams limit */
	if (ctx->active_streams >= ctx->settings.max_concurrent_streams && ctx->settings.max_concurrent_streams > 0) {
		return NULL;
	}

	struct http2_stream *stream = malloc(sizeof(*stream));
	if (!stream) {
		return NULL;
	}

	memset(stream, 0, sizeof(*stream));
	stream->ctx = ctx;
	stream->refcount = 1; /* Initial reference count */
	stream->stream_id = stream_id;
	stream->state = HTTP2_STREAM_IDLE;

	/* Determine if stream is accepted (locally initiated) or needs accept (peer initiated) */
	if (ctx->is_client) {
		/* Client: Odd IDs are local (accepted), Even IDs are remote (need accept) */
		stream->accepted = (stream_id % 2) != 0;
	} else {
		/* Server: Even IDs are local (accepted), Odd IDs are remote (need accept) */
		stream->accepted = (stream_id % 2) == 0;
	}

	stream->window_size = ctx->peer_initial_window_size;
	stream->body_buffer_size = 8192;
	stream->body_buffer = malloc(stream->body_buffer_size);
	if (!stream->body_buffer) {
		free(stream);
		return NULL;
	}

	/* Initialize header structures */
	INIT_LIST_HEAD(&stream->header_list.list);
	hash_init(stream->header_map);

	hash_add(ctx->stream_map, &stream->hash_node, stream->stream_id);
	list_add(&stream->node, &ctx->streams);
	ctx->active_streams++;
	http2_ctx_get(ctx);

	return stream;
}

static int _http2_remove_stream(struct http2_ctx *ctx, struct http2_stream *stream)
{
	int ret = -1;
	pthread_mutex_lock(&ctx->mutex);
	hash_del(&stream->hash_node);
	list_del(&stream->node);
	ctx->active_streams--;
	ret = 0;
	pthread_mutex_unlock(&ctx->mutex);
	return ret;
}

static int _http2_process_data_frame(struct http2_ctx *ctx, int stream_id, const uint8_t *data, int len, uint8_t flags)
{
	struct http2_stream *stream = _http2_find_stream(ctx, stream_id);
	if (!stream) {
		return -1;
	}

	/* Stream ID 0 is invalid for DATA frames */
	if (stream_id == 0) {
		_http2_send_goaway(ctx, 0, HTTP2_RST_PROTOCOL_ERROR, NULL, 0);
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}

	/* Check for invalid length */
	if (len < 0) {
		http2_send_rst_stream(ctx, stream_id, HTTP2_RST_PROTOCOL_ERROR);
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}

	/* Check for integer overflow in buffer size */
	if (stream->body_buffer_len > INT_MAX - len) {
		http2_send_rst_stream(ctx, stream_id, HTTP2_RST_INTERNAL_ERROR);
		return -1;
	}

	/* Check flow control */
	if (len < 0 || stream->window_size <= 0 || ctx->connection_window_size <= 0) {
		http2_send_rst_stream(ctx, stream_id, HTTP2_RST_FLOW_CONTROL_ERROR);
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}
	if (len > stream->window_size || len > ctx->connection_window_size) {
		http2_send_rst_stream(ctx, stream_id, HTTP2_RST_FLOW_CONTROL_ERROR);
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}

	/* Append to body buffer */
	if (stream->body_buffer_len + len > stream->body_buffer_size) {
		int new_size = safe_buffer_size(stream->body_buffer_size, 2);
		if (new_size < 0) {
			http2_send_rst_stream(ctx, stream_id, HTTP2_RST_INTERNAL_ERROR);
			return -1;
		}
		while (new_size < stream->body_buffer_len + len) {
			int temp = safe_buffer_size(new_size, 2);
			if (temp < 0) {
				http2_send_rst_stream(ctx, stream_id, HTTP2_RST_INTERNAL_ERROR);
				return -1;
			}
			new_size = temp;
		}
		uint8_t *new_buffer = realloc(stream->body_buffer, new_size);
		if (!new_buffer) {
			http2_send_rst_stream(ctx, stream_id, HTTP2_RST_INTERNAL_ERROR);
			return -1;
		}
		stream->body_buffer = new_buffer;
		stream->body_buffer_size = new_size;
	}

	memcpy(stream->body_buffer + stream->body_buffer_len, data, len);
	stream->body_buffer_len += len;

	if (flags & HTTP2_FLAG_END_STREAM) {
		stream->end_stream_received = 1;
		if (stream->state == HTTP2_STREAM_OPEN) {
			stream->state = HTTP2_STREAM_HALF_CLOSED_REMOTE;
		} else if (stream->state == HTTP2_STREAM_HALF_CLOSED_LOCAL) {
			stream->state = HTTP2_STREAM_CLOSED;
		}
	}

	/* Update flow control */
	/* Send WINDOW_UPDATE immediately to prevent flow control deadlock */
	/* Connection-level WINDOW_UPDATE */
	if (_http2_send_window_update(ctx, 0, len) < 0) {
		return -1;
	}
	ctx->connection_window_size += len;

	/* Stream-level WINDOW_UPDATE */
	if (_http2_send_window_update(ctx, stream_id, len) < 0) {
		ctx->connection_window_size -= len;
		return -1;
	}
	stream->window_size += len;

	return 0;
}

static int _http2_process_headers_frame(struct http2_ctx *ctx, int stream_id, const uint8_t *data, int len,
									   uint8_t flags, uint8_t frame_type)
{
	/* Handle Padding and Priority fields (only for HEADERS frame) */
	int pad_len = 0;
	if (frame_type == HTTP2_FRAME_HEADERS) {
		if (flags & HTTP2_FLAG_PADDED) {
			if (len < 1) {
				return -1;
			}
			pad_len = data[0];
			data++;
			len--;
		}

		if (flags & HTTP2_FLAG_PRIORITY) {
			if (len < 5) {
				return -1;
			}
			data += 5;
			len -= 5;
		}
	} else if (frame_type == HTTP2_FRAME_CONTINUATION) {
		/* CONTINUATION frames must not have PADDED or PRIORITY flags */
		if (flags & (HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY)) {
			_http2_send_goaway(ctx, 0, HTTP2_RST_PROTOCOL_ERROR, NULL, 0);
			ctx->status = HTTP2_ERR_PROTOCOL;
			return -1;
		}
	}

	if (len < pad_len) {
		return -1;
	}
	len -= pad_len;

	struct http2_stream *stream = _http2_find_stream(ctx, stream_id);
	if (!stream) {
		stream = _http2_create_stream(ctx, stream_id);
		if (!stream) {
			return -1;
		}
	}

	/* Clear old headers only if this is a new HEADERS frame */
	if (frame_type == HTTP2_FRAME_HEADERS) {
		_http2_free_headers(stream);
	}

	if (len > 0) { /* Only decode if there's data */
		if (hpack_decode_headers(&ctx->decoder, data, len, _http2_on_header, stream) < 0) {
			http2_send_rst_stream(ctx, stream_id, HTTP2_RST_COMPRESSION_ERROR);
			return -1;
		}
	}

	if (stream->state == HTTP2_STREAM_IDLE) {
		stream->state = HTTP2_STREAM_OPEN;
	}

	if (flags & HTTP2_FLAG_END_STREAM) {
		stream->end_stream_received = 1;
		if (stream->state == HTTP2_STREAM_OPEN) {
			stream->state = HTTP2_STREAM_HALF_CLOSED_REMOTE;
		}
	}

	return 0;
}

static int http2_process_settings_frame(struct http2_ctx *ctx, const uint8_t *data, int len, uint8_t flags)
{
	if (flags & HTTP2_FLAG_ACK) {
		return 0;
	}

	if (len < 0 || len % 6 != 0) {
		_http2_send_goaway(ctx, 0, HTTP2_RST_PROTOCOL_ERROR, NULL, 0);
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}

	/* Process settings */
	int offset = 0;
	while (offset + 6 <= len) {
		uint16_t id = (data[offset] << 8) | data[offset + 1];
		uint32_t value = read_uint32(data + offset + 2);
		offset += 6;

		switch (id) {
		case HTTP2_SETTINGS_HEADER_TABLE_SIZE:
			ctx->encoder.max_dynamic_table_size = value;
			break;
		case HTTP2_SETTINGS_ENABLE_PUSH:
			/* Server: must ignore this setting */
			break;
		case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
			ctx->settings.max_concurrent_streams = value;
			break;
		case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
			ctx->peer_initial_window_size = value > INT_MAX ? INT_MAX : value;
			break;
		case HTTP2_SETTINGS_MAX_FRAME_SIZE:
			ctx->peer_max_frame_size = value > HTTP2_DEFAULT_MAX_FRAME_SIZE ? HTTP2_DEFAULT_MAX_FRAME_SIZE : value;
			break;
		default:
			break;
		}
	}

	/* Send SETTINGS ACK */
	ctx->settings_received = 1;
	return _http2_send_settings(ctx, 1);
}

static int http2_process_window_update_frame(struct http2_ctx *ctx, int stream_id, const uint8_t *data, int len)
{
	if (len != 4) {
		_http2_send_goaway(ctx, 0, HTTP2_RST_PROTOCOL_ERROR, NULL, 0);
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}

	uint32_t increment = read_uint32(data) & 0x7FFFFFFF;

	if (increment == 0) {
		/* RFC 9113: A receiver MUST treat the receipt of a WINDOW_UPDATE frame with an
		   increment of 0 as a stream error of type PROTOCOL_ERROR */
		if (stream_id == 0) {
			_http2_send_goaway(ctx, 0, HTTP2_RST_PROTOCOL_ERROR, NULL, 0);
		} else {
			http2_send_rst_stream(ctx, stream_id, HTTP2_RST_PROTOCOL_ERROR);
		}
		ctx->status = HTTP2_ERR_PROTOCOL;
		return -1;
	}

	if (stream_id == 0) {
		if (ctx->connection_window_size > INT_MAX - (int)increment) {
			_http2_send_goaway(ctx, 0, HTTP2_RST_FLOW_CONTROL_ERROR, NULL, 0);
			ctx->status = HTTP2_ERR_PROTOCOL;
			return -1;
		}
		ctx->connection_window_size += (int)increment;
	} else {
		struct http2_stream *stream = _http2_find_stream(ctx, stream_id);
		if (stream) {
			if (stream->window_size > INT_MAX - (int)increment) {
				http2_send_rst_stream(ctx, stream_id, HTTP2_RST_FLOW_CONTROL_ERROR);
				return -1;
			}
			stream->window_size += (int)increment;
		}
	}

	return 0;
}

/* Verify HTTP/2 connection preface (server side) */
static int http2_verify_connection_preface(struct http2_ctx *ctx)
{
	/* Server: first read and verify connection preface */
	if (ctx->is_client || ctx->preface_received) {
		return 0; /* Not applicable or already verified */
	}

	/* Need to read 24-byte connection preface */
	if (ctx->read_buffer_len < HTTP2_CONNECTION_PREFACE_LEN) {
		int to_read = HTTP2_CONNECTION_PREFACE_LEN - ctx->read_buffer_len;
		int ret = ctx->bio_read(ctx->private_data, ctx->read_buffer + ctx->read_buffer_len, to_read);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ctx->want_read = 1;
				return HTTP2_ERR_EAGAIN;
			}
			ctx->status = HTTP2_ERR_IO;
			return HTTP2_ERR_IO;
		}
		if (ret == 0) {
			ctx->status = HTTP2_ERR_EOF;
			return HTTP2_ERR_EOF;
		}

		ctx->read_buffer_len += ret;
		if (ctx->read_buffer_len < HTTP2_CONNECTION_PREFACE_LEN) {
			ctx->want_read = 1;
			return HTTP2_ERR_EAGAIN;
		}
	}

	/* Verify preface */
	if (memcmp(ctx->read_buffer, HTTP2_CONNECTION_PREFACE, HTTP2_CONNECTION_PREFACE_LEN) != 0) {
		/* Check if it looks like HTTP/1.1 */
		if (ctx->read_buffer_len >= 4 &&
			(memcmp(ctx->read_buffer, "GET ", 4) == 0 || memcmp(ctx->read_buffer, "POST ", 5) == 0 ||
			 memcmp(ctx->read_buffer, "HEAD ", 5) == 0 || memcmp(ctx->read_buffer, "PUT ", 4) == 0 ||
			 memcmp(ctx->read_buffer, "DELETE ", 7) == 0 || memcmp(ctx->read_buffer, "OPTIONS ", 8) == 0 ||
			 memcmp(ctx->read_buffer, "PATCH ", 6) == 0 || memcmp(ctx->read_buffer, "CONNECT ", 8) == 0 ||
			 memcmp(ctx->read_buffer, "TRACE ", 6) == 0)) {
			ctx->status = HTTP2_ERR_HTTP1;
			return HTTP2_ERR_HTTP1;
		}
		ctx->status = HTTP2_ERR_PROTOCOL;
		return HTTP2_ERR_PROTOCOL;
	}

	/* Preface verified, remove it from buffer */
	ctx->read_buffer_len -= HTTP2_CONNECTION_PREFACE_LEN;
	if (ctx->read_buffer_len > 0) {
		memmove(ctx->read_buffer, ctx->read_buffer + HTTP2_CONNECTION_PREFACE_LEN, ctx->read_buffer_len);
	}
	ctx->preface_received = 1;

	return 0;
}

static int _http2_process_frames(struct http2_ctx *ctx)
{
	ctx->want_read = 0;

	/* Server: verify connection preface */
	int ret = http2_verify_connection_preface(ctx);
	if (ret != 0) {
		return ret;
	}

	while (1) {
		/* Try to read frame header */
		if (ctx->read_buffer_len < HTTP2_FRAME_HEADER_SIZE) {
			ret = ctx->bio_read(ctx->private_data, ctx->read_buffer + ctx->read_buffer_len,
								HTTP2_FRAME_HEADER_SIZE - ctx->read_buffer_len);
			if (ret < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					/* Normal for async I/O - just wait for more data */
					ctx->want_read = 1;
					return HTTP2_ERR_EAGAIN;
				}
				/* Real error */
				ctx->status = HTTP2_ERR_IO;
				return HTTP2_ERR_IO;
			}
			if (ret == 0) {
				/* Connection closed */
				ctx->status = HTTP2_ERR_EOF;
				return HTTP2_ERR_EOF;
			}

			ctx->read_buffer_len += ret;
			if (ctx->read_buffer_len < HTTP2_FRAME_HEADER_SIZE) {
				/* Need more data */
				ctx->want_read = 1;
				return 0;
			}
		}

		/* Parse frame header */
		uint32_t length = read_uint24(ctx->read_buffer);
		uint8_t type = ctx->read_buffer[3];
		uint8_t flags = ctx->read_buffer[4];
		uint32_t stream_id = read_uint32(ctx->read_buffer + 5) & 0x7FFFFFFF;

		/* Validate frame length */
		if (length > ctx->peer_max_frame_size || length > INT_MAX) {
			ctx->status = HTTP2_ERR_PROTOCOL;
			return HTTP2_ERR_PROTOCOL;
		}

		/* Read frame payload */
		if (ctx->read_buffer_len < (int)(HTTP2_FRAME_HEADER_SIZE + length)) {
			int to_read = HTTP2_FRAME_HEADER_SIZE + length - ctx->read_buffer_len;
			ret = ctx->bio_read(ctx->private_data, ctx->read_buffer + ctx->read_buffer_len, to_read);
			if (ret < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					/* Normal for async I/O - just wait for more data */
					ctx->want_read = 1;
					return HTTP2_ERR_EAGAIN;
				}
				/* Real error */
				ctx->status = HTTP2_ERR_IO;
				return HTTP2_ERR_IO;
			}
			if (ret == 0) {
				/* Connection closed */
				ctx->status = HTTP2_ERR_EOF;
				return HTTP2_ERR_EOF;
			}

			ctx->read_buffer_len += ret;
			if (ctx->read_buffer_len < (int)(HTTP2_FRAME_HEADER_SIZE + length)) {
				/* Need more data */
				ctx->want_read = 1;
				return 0;
			}
		}

		/* Process frame */
		const uint8_t *payload = ctx->read_buffer + HTTP2_FRAME_HEADER_SIZE;

		switch (type) {
		case HTTP2_FRAME_DATA:
			_http2_process_data_frame(ctx, stream_id, payload, length, flags);
			break;
		case HTTP2_FRAME_HEADERS:
			_http2_process_headers_frame(ctx, stream_id, payload, length, flags, HTTP2_FRAME_HEADERS);
			break;
		case HTTP2_FRAME_CONTINUATION:
			/* CONTINUATION frames continue a HEADERS frame */
			_http2_process_headers_frame(ctx, stream_id, payload, length, flags, HTTP2_FRAME_CONTINUATION);
			break;
		case HTTP2_FRAME_SETTINGS:
			http2_process_settings_frame(ctx, payload, length, flags);
			break;
		case HTTP2_FRAME_WINDOW_UPDATE:
			http2_process_window_update_frame(ctx, stream_id, payload, length);
			break;
		case HTTP2_FRAME_PING:
			/* Echo PING */
			if (!(flags & HTTP2_FLAG_ACK)) {
				uint8_t pong[HTTP2_FRAME_HEADER_SIZE + 8];
				_http2_write_frame_header(pong, 8, HTTP2_FRAME_PING, HTTP2_FLAG_ACK, 0);
				memcpy(pong + HTTP2_FRAME_HEADER_SIZE, payload, 8);
				_http2_send_frame(ctx, pong, sizeof(pong));
			}
			break;
		case HTTP2_FRAME_RST_STREAM:
			if (length != 4) {
				_http2_send_goaway(ctx, 0, HTTP2_RST_PROTOCOL_ERROR, NULL, 0);
				ctx->status = HTTP2_ERR_PROTOCOL;
				return -1;
			}
			/* Close the stream */
			{
				struct http2_stream *rst_stream = _http2_find_stream(ctx, stream_id);
				if (rst_stream) {
					rst_stream->state = HTTP2_STREAM_CLOSED;
				}
			}
			break;
		case HTTP2_FRAME_GOAWAY:
			if (length < 8) {
				ctx->status = HTTP2_ERR_PROTOCOL;
				return -1;
			}
			ctx->status = HTTP2_ERR_EOF;
			break;
		default:
			/* Ignore unknown frames */
			break;
		}

		/* Move remaining data to beginning of buffer */
		int frame_size = HTTP2_FRAME_HEADER_SIZE + length;
		if (ctx->read_buffer_len > frame_size) {
			memmove(ctx->read_buffer, ctx->read_buffer + frame_size, ctx->read_buffer_len - frame_size);
			ctx->read_buffer_len -= frame_size;
		} else {
			ctx->read_buffer_len = 0;
		}
	}

	return 0;
}

/* Reference counting functions */

struct http2_ctx *http2_ctx_get(struct http2_ctx *ctx)
{
	if (!ctx) {
		return NULL;
	}
	__sync_add_and_fetch(&ctx->refcount, 1);
	return ctx;
}

void http2_ctx_put(struct http2_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	int refcnt = __sync_sub_and_fetch(&ctx->refcount, 1);
	if (refcnt > 0) {
		return; /* Still has references */
	}

	if (refcnt < 0) {
		BUG("http2_ctx_put: negative reference count %d", refcnt);
		return;
	}

	/* Reference count reached zero, free the context */
	pthread_mutex_lock(&ctx->mutex);

	/* Free all streams - each stream will call http2_stream_put */
	struct http2_stream *stream, *tmp;
	list_for_each_entry_safe(stream, tmp, &ctx->streams, node) {
		list_del(&stream->node);
		stream->ctx = NULL;  /* Break circular reference */
		stream->state = HTTP2_STREAM_CLOSED;
		http2_stream_put(stream);
	}

	hpack_free_context(&ctx->encoder);
	hpack_free_context(&ctx->decoder);

	/* Free pending write buffer */
	if (ctx->pending_write_buffer) {
		free(ctx->pending_write_buffer);
	}

	if (ctx->server) {
		free(ctx->server);
	}

	pthread_mutex_unlock(&ctx->mutex);
	pthread_mutex_destroy(&ctx->mutex);

	free(ctx);
}

void http2_ctx_close(struct http2_ctx *ctx)
{
	struct list_head streams_to_free;

	if (!ctx) {
		return;
	}

	pthread_mutex_lock(&ctx->mutex);

	/* Detach all streams from context */
	INIT_LIST_HEAD(&streams_to_free);
	list_splice_init(&ctx->streams, &streams_to_free);

	pthread_mutex_unlock(&ctx->mutex);

	/* Now free streams outside the lock - just break circular references */
	struct http2_stream *stream, *tmp;
	list_for_each_entry_safe(stream, tmp, &streams_to_free, node) {
		list_del(&stream->node);

		/* Detach stream from context - break the circular reference */
		stream->ctx = NULL;

		http2_stream_put(stream);

		/* Release the stream reference here */
		/* Release the reference to ctx that was taken when the stream was created */
		http2_ctx_put(ctx);
	}

	/* release context reference held by caller */
	http2_ctx_put(ctx);
}

struct http2_stream *http2_stream_get(struct http2_stream *stream)
{
	if (!stream) {
		return NULL;
	}
	__sync_add_and_fetch(&stream->refcount, 1);
	return stream;
}

void http2_stream_put(struct http2_stream *stream)
{
	if (!stream) {
		return;
	}

	int refcnt = __sync_sub_and_fetch(&stream->refcount, 1);
	if (refcnt > 0) {
		return; /* Still has references */
	}

	if (refcnt < 0) {
		BUG("http2_stream_put: negative reference count %d", refcnt);
		return;
	}

	/* Reference count reached zero, free the stream */
	struct http2_ctx *ctx = stream->ctx;

	if (ctx) {
		if (_http2_remove_stream(ctx, stream) == 0) {
			/* release ownership held by ctx */
			http2_stream_put(stream);
		}
		http2_ctx_put(ctx);
	}

	_http2_free_headers(stream);
	stream->ctx = NULL;
	free(stream->body_buffer);
	free(stream);
}

static void http2_ctx_init_common(struct http2_ctx *ctx, const struct http2_ctx_init_params *params)
{
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&ctx->mutex, &attr);
	pthread_mutexattr_destroy(&attr);
	ctx->refcount = 1; /* Initial reference count */
	ctx->is_client = params->is_client;
	ctx->server = strdup(params->server ? params->server : "");
	ctx->bio_read = params->bio_read;
	ctx->bio_write = params->bio_write;
	ctx->private_data = params->private_data;
	ctx->next_stream_id = params->next_stream_id;
	ctx->connection_window_size = HTTP2_DEFAULT_WINDOW_SIZE;
	ctx->peer_max_frame_size = HTTP2_DEFAULT_MAX_FRAME_SIZE;
	ctx->peer_initial_window_size = HTTP2_DEFAULT_WINDOW_SIZE;
	ctx->active_streams = 0;

	/* Initialize settings with defaults or provided values */
	if (params->settings) {
		ctx->settings = *params->settings;
	}

	/* Initialize I/O state */
	ctx->want_read = 0;
	ctx->want_write = 0;
	ctx->pending_write_buffer = NULL;
	ctx->pending_write_len = 0;
	ctx->pending_write_capacity = 0;

	hpack_init_context(&ctx->encoder);
	hpack_init_context(&ctx->decoder);

	hash_init(ctx->stream_map);
	INIT_LIST_HEAD(&ctx->streams);
}

static struct http2_ctx *http2_ctx_new(int is_client, const char *server, http2_bio_read_fn bio_read,
									   http2_bio_write_fn bio_write, void *private_data,
									   const struct http2_settings *settings)
{
	struct http2_ctx *ctx = zalloc(1, sizeof(*ctx));
	if (!ctx) {
		return NULL;
	}

	struct http2_ctx_init_params params = {.server = server,
										   .bio_read = bio_read,
										   .bio_write = bio_write,
										   .private_data = private_data,
										   .settings = settings,
										   .is_client = is_client,
										   .next_stream_id = is_client ? 1 : 2};
	http2_ctx_init_common(ctx, &params);

	if (is_client) {
		/* Send connection preface - may return EAGAIN, will be buffered */
		_http2_send_frame(ctx, (const uint8_t *)HTTP2_CONNECTION_PREFACE, HTTP2_CONNECTION_PREFACE_LEN);
	}

	/* Send initial SETTINGS - may return EAGAIN, will be buffered */
	_http2_send_settings(ctx, 0);

	return ctx;
}

struct http2_ctx *http2_ctx_client_new(const char *server, http2_bio_read_fn bio_read, http2_bio_write_fn bio_write,
									   void *private_data, const struct http2_settings *settings)
{
	if (!server || !bio_read || !bio_write) {
		return NULL;
	}
	return http2_ctx_new(1, server, bio_read, bio_write, private_data, settings);
}

struct http2_ctx *http2_ctx_server_new(const char *server, http2_bio_read_fn bio_read, http2_bio_write_fn bio_write,
									   void *private_data, const struct http2_settings *settings)
{
	if (!server || !bio_read || !bio_write) {
		return NULL;
	}
	return http2_ctx_new(0, server, bio_read, bio_write, private_data, settings);
}

int http2_ctx_handshake(struct http2_ctx *ctx)
{
	if (!ctx) {
		return -1;
	}

	pthread_mutex_lock(&ctx->mutex);

	if (ctx->handshake_complete) {
		pthread_mutex_unlock(&ctx->mutex);
		return 1;
	}

	/* Try to flush any pending writes (e.g., connection preface, SETTINGS) */
	if (ctx->pending_write_len > 0) {
		/* Trigger flush by calling send_frame with empty data */
		uint8_t dummy = 0;
		_http2_send_frame(ctx, &dummy, 0);
	}

	/* Process incoming frames */
	int ret = _http2_process_frames(ctx);

	/* Handshake is complete after receiving SETTINGS */
	if (ctx->settings_received) {
		ctx->handshake_complete = 1;
		pthread_mutex_unlock(&ctx->mutex);
		return 1;
	}

	if (ret == HTTP2_ERR_EAGAIN) {
		pthread_mutex_unlock(&ctx->mutex);
		return 0; /* In progress */
	}

	pthread_mutex_unlock(&ctx->mutex);
	return ret;
}

struct http2_stream *http2_ctx_accept_stream(struct http2_ctx *ctx)
{
	if (!ctx) {
		return NULL;
	}

	pthread_mutex_lock(&ctx->mutex);

	/* Try to flush any pending writes first */
	if (ctx->pending_write_len > 0) {
		uint8_t dummy = 0;
		_http2_send_frame(ctx, &dummy, 0);
	}

	/* Process frames to get new streams */
	_http2_process_frames(ctx);

	/* Find a stream that was initiated by peer */
	struct http2_stream *stream;
	list_for_each_entry(stream, &ctx->streams, node) {
		if ((ctx->is_client && (stream->stream_id % 2) == 0) || (!ctx->is_client && (stream->stream_id % 2) == 1)) {
			if (!stream->accepted && !list_empty(&stream->header_list.list) && !stream->end_stream_sent) {
				stream->accepted = 1;
				pthread_mutex_unlock(&ctx->mutex);
				if (stream) {
					/* take ownership */
					http2_stream_get(stream);
				}
				return stream;
			}
		}
	}

	pthread_mutex_unlock(&ctx->mutex);
	return NULL;
}

static int _http2_ctx_io_process(struct http2_ctx *ctx)
{
	/* Try to flush any pending writes first */
	if (ctx->pending_write_len > 0) {
		uint8_t dummy = 0;
		_http2_send_frame(ctx, &dummy, 0);
	}

	/* Process frames */
	return _http2_process_frames(ctx);
}

static int _http2_ctx_check_new_streams(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items, int *count)
{
	if (ctx->is_client || *count >= max_items) {
		return 0;
	}

	struct http2_stream *stream;
	int has_new_stream = 0;

	list_for_each_entry(stream, &ctx->streams, node) {
		/* Server accepts odd stream IDs (client-initiated) */
		/* Stream is ready to accept when it has received headers */
		if ((stream->stream_id % 2) == 1 && !stream->accepted && !list_empty(&stream->header_list.list) &&
			!stream->end_stream_sent) {
			has_new_stream = 1;
			break;
		}
	}

	if (has_new_stream) {
		/* Return server context item (stream = NULL) to indicate new connection */
		items[*count].stream = NULL;
		items[*count].readable = 1;
		items[*count].writable = 0;
		(*count)++;
		return 1;
	}
	return 0;
}

static void _http2_ctx_collect_ready_streams(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items,
											 int *count, int check_writable)
{
	struct http2_stream *stream, *tmp;
	struct list_head ready_list;
	INIT_LIST_HEAD(&ready_list);

	list_for_each_entry_safe(stream, tmp, &ctx->streams, node) {
		/* Only return streams that have been accepted */
		if (!stream->accepted) {
			continue;
		}

		/* Stream is readable if:
		 * 1. Has unread body data in buffer, OR
		 * 2. Stream has ended (all data including headers received)
		 */
		int has_body_data = stream->body_buffer_len > stream->body_read_offset;
		int stream_ended = stream->end_stream_received && !stream->end_stream_read_handled;

		int readable = has_body_data || stream_ended;
		int writable = stream->state == HTTP2_STREAM_OPEN || stream->state == HTTP2_STREAM_HALF_CLOSED_REMOTE;

		if (readable || (check_writable && writable)) {
			if (*count < max_items) {
				items[*count].stream = stream;
				items[*count].readable = readable;
				items[*count].writable = writable;
				(*count)++;
				/* Move to ready list */
				list_move_tail(&stream->node, &ready_list);
			}
		}
	}

	/* Append ready list to the end of ctx->streams */
	list_splice_tail(&ready_list, &ctx->streams);
}

static int _http2_ctx_poll(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items, int *ret_count,
						   int check_writable)
{
	pthread_mutex_lock(&ctx->mutex);

	int ret = _http2_ctx_io_process(ctx);

	/* Note: We continue even if http2_process_frames returns error (like EOF),
	   because we might have received data that made streams readable.
	   We will return the error at the end if no streams are ready. */

	int count = 0;

	_http2_ctx_check_new_streams(ctx, items, max_items, &count);
	_http2_ctx_collect_ready_streams(ctx, items, max_items, &count, check_writable);

	*ret_count = count;
	pthread_mutex_unlock(&ctx->mutex);

	/* If we have an error, return it even if there are ready items */
	if (ret < 0 && ret != HTTP2_ERR_EAGAIN) {
		return ret;
	}

	if (count > 0) {
		return 0;
	}

	if (ctx->status < 0) {
		return ctx->status;
	}

	return 0;
}

int http2_ctx_poll(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items, int *ret_count)
{
	if (!ctx || !items || !ret_count || max_items <= 0) {
		return -1;
	}
	return _http2_ctx_poll(ctx, items, max_items, ret_count, 1);
}

int http2_ctx_poll_readable(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items, int *ret_count)
{
	if (!ctx || !items || !ret_count || max_items <= 0) {
		return -1;
	}
	return _http2_ctx_poll(ctx, items, max_items, ret_count, 0);
}

struct http2_stream *http2_stream_new(struct http2_ctx *ctx)
{
	if (!ctx) {
		return NULL;
	}

	pthread_mutex_lock(&ctx->mutex);

	int stream_id = ctx->next_stream_id;
	ctx->next_stream_id += 2;

	struct http2_stream *stream = _http2_create_stream(ctx, stream_id);
	if (stream) {
		/* take ownership */
		http2_stream_get(stream);
	}

	pthread_mutex_unlock(&ctx->mutex);
	return stream;
}

static int http2_send_rst_stream(struct http2_ctx *ctx, uint32_t stream_id, uint32_t error_code)
{
	uint8_t frame[HTTP2_FRAME_HEADER_SIZE + 4];

	_http2_write_frame_header(frame, 4, HTTP2_FRAME_RST_STREAM, 0, stream_id);
	write_uint32(frame + HTTP2_FRAME_HEADER_SIZE, error_code);

	return _http2_send_frame(ctx, frame, sizeof(frame));
}

void http2_stream_close(struct http2_stream *stream)
{
	if (stream == NULL) {
		return;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);

		/* Send RST_STREAM to close the stream */
		http2_send_rst_stream(ctx, stream->stream_id, 0); /* NO_ERROR */
		if (_http2_remove_stream(ctx, stream) == 0) {
			/* release ownership held by ctx */
			http2_stream_put(stream);
		}
		pthread_mutex_unlock(&ctx->mutex);
		stream->ctx = NULL;
		http2_ctx_put(ctx);
	}
	/* Mark stream as closed */
	stream->state = HTTP2_STREAM_CLOSED;

	http2_stream_put(stream);
}

int http2_stream_get_id(struct http2_stream *stream)
{
	if (!stream) {
		return -1;
	}
	return stream->stream_id;
}

int http2_stream_set_request(struct http2_stream *stream, const char *method, const char *path,
							 const char *scheme, const struct http2_header_pair *headers)
{
	if (!stream || !method || !path) {
		return -1;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return -1;
	}
	pthread_mutex_lock(&ctx->mutex);

	/* Clear old headers */
	_http2_free_headers(stream);

	/* Add pseudo-headers */
	_http2_stream_add_header(stream, ":method", method);
	_http2_stream_add_header(stream, ":path", path);
	_http2_stream_add_header(stream, ":scheme", scheme ? scheme : "https");
	_http2_stream_add_header(stream, ":authority", ctx->server ? ctx->server : "localhost");

	/* Add additional headers from array */
	if (headers) {
		for (int i = 0; headers[i].name != NULL; i++) {
			if (headers[i].value == NULL) {
				continue;
			}
			
			if (headers[i].name == NULL) {
				continue;
			}

			_http2_stream_add_header(stream, headers[i].name, headers[i].value);
		}
	}

	/* Send HEADERS frame with END_STREAM for GET/HEAD requests (no body) */
	int end_stream = (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) ? 1 : 0;
	int ret = _http2_send_headers_frame(ctx, stream->stream_id, stream, end_stream, 1);

	if (end_stream) {
		stream->end_stream_sent = 1;
	}

	if (stream->state == HTTP2_STREAM_IDLE) {
		stream->state = HTTP2_STREAM_OPEN;
	}

	pthread_mutex_unlock(&ctx->mutex);
	return ret;
}

int http2_stream_set_response(struct http2_stream *stream, int status, const struct http2_header_pair *headers,
							  int header_count)
{
	if (!stream || status < 100 || status > 599 || header_count < 0 || (header_count > 0 && !headers)) {
		return -1;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return -1;
	}
	pthread_mutex_lock(&ctx->mutex);

	/* Clear old headers */
	_http2_free_headers(stream);

	/* Add :status pseudo-header */
	char status_str[16];
	snprintf(status_str, sizeof(status_str), "%d", status);
	_http2_stream_add_header(stream, ":status", status_str);

	/* Add additional headers from array */
	if (headers && header_count > 0) {
		for (int i = 0; i < header_count; i++) {
			if (headers[i].name == NULL || headers[i].value == NULL) {
				continue;
			}
			_http2_stream_add_header(stream, headers[i].name, headers[i].value);
		}
	}

	/* Send HEADERS frame */
	int ret = _http2_send_headers_frame(ctx, stream->stream_id, stream, 0, 1);

	pthread_mutex_unlock(&ctx->mutex);
	return ret;
}

const char *http2_stream_get_method(struct http2_stream *stream)
{
	if (!stream) {
		return NULL;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return NULL;
	}
	pthread_mutex_lock(&ctx->mutex);

	const char *method = _http2_stream_get_header_value(stream, ":method");

	pthread_mutex_unlock(&ctx->mutex);
	return method;
}

const char *http2_stream_get_path(struct http2_stream *stream)
{
	if (!stream) {
		return NULL;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return NULL;
	}
	pthread_mutex_lock(&ctx->mutex);

	const char *path = _http2_stream_get_header_value(stream, ":path");

	pthread_mutex_unlock(&ctx->mutex);
	return path;
}

int http2_stream_get_status(struct http2_stream *stream)
{
	if (!stream) {
		return -1;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return -1;
	}
	pthread_mutex_lock(&ctx->mutex);

	const char *status_str = _http2_stream_get_header_value(stream, ":status");
	int status = status_str ? atoi(status_str) : -1;

	pthread_mutex_unlock(&ctx->mutex);
	return status;
}

const char *http2_stream_get_header(struct http2_stream *stream, const char *name)
{
	if (!stream || !name) {
		return NULL;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return NULL;
	}
	pthread_mutex_lock(&ctx->mutex);

	const char *value = _http2_stream_get_header_value(stream, name);

	pthread_mutex_unlock(&ctx->mutex);
	return value;
}

int http2_stream_write_body(struct http2_stream *stream, const uint8_t *data, int len, int end_stream)
{
	if (!stream || len <= 0 || !data) {
		return -1;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (!ctx) {
		return -1;
	}
	pthread_mutex_lock(&ctx->mutex);

	int total_sent = 0;
	while (len > 0) {
		/* Check flow control */
		if (stream->window_size <= 0 || ctx->connection_window_size <= 0) {
			if (total_sent > 0) {
				break; /* Partial send */
			}
			pthread_mutex_unlock(&ctx->mutex);
			errno = EAGAIN;
			return -1;
		}
		int to_send = len;
		if (to_send > stream->window_size) {
			to_send = stream->window_size;
		}
		if (to_send > ctx->connection_window_size) {
			to_send = ctx->connection_window_size;
		}
		if ((uint32_t)to_send > (uint32_t)ctx->peer_max_frame_size) {
			to_send = ctx->peer_max_frame_size;
		}

		if (to_send <= 0) {
			if (total_sent > 0) {
				break;
			}
			pthread_mutex_unlock(&ctx->mutex);
			errno = EAGAIN;
			return -1;
		}

		int ret = _http2_send_data_frame(ctx, stream->stream_id, data + total_sent, to_send, end_stream && to_send == len);
		if (ret < 0) {
			if (total_sent > 0) {
				break; /* Partial send */
			}
			pthread_mutex_unlock(&ctx->mutex);
			return ret;
		}
		total_sent += ret;
		len -= ret;
		stream->window_size -= ret;
		ctx->connection_window_size -= ret;

		if (end_stream && len == 0) {
			stream->end_stream_sent = 1;
			if (stream->state == HTTP2_STREAM_OPEN) {
				stream->state = HTTP2_STREAM_HALF_CLOSED_LOCAL;
			} else if (stream->state == HTTP2_STREAM_HALF_CLOSED_REMOTE) {
				stream->state = HTTP2_STREAM_CLOSED;
			}
		}
	}

	pthread_mutex_unlock(&ctx->mutex);
	return total_sent;
}

/* Helper function to decompress gzip/deflate data */
static int http2_decompress_data(const uint8_t *compressed, int compressed_len, uint8_t **decompressed,
								 int *decompressed_len, int is_gzip)
{
#ifdef WITH_ZLIB
	z_stream strm;
	int ret;
	int window_bits = is_gzip ? (15 + 16) : 15; /* 15+16 for gzip, 15 for deflate */
	const int MAX_DECOMPRESSED_SIZE = 1 * 1024 * 1024; /* 10MB limit to prevent DOS */

	/* Allocate initial output buffer */
	int out_size = safe_buffer_size(compressed_len, 4);
	if (out_size < 0 || out_size < 8192) {
		out_size = 8192;
	}
	if (out_size > MAX_DECOMPRESSED_SIZE) {
		out_size = MAX_DECOMPRESSED_SIZE;
	}
	uint8_t *out_buf = malloc(out_size);
	if (!out_buf) {
		return -1;
	}

	/* Initialize zlib */
	memset(&strm, 0, sizeof(strm));
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = compressed_len;
	strm.next_in = (Bytef *)compressed;

	ret = inflateInit2(&strm, window_bits);
	if (ret != Z_OK) {
		free(out_buf);
		return -1;
	}

	/* Decompress */
	int total_out = 0;
	do {
		/* Ensure we have space in output buffer */
		if (total_out + 4096 > out_size) {
			int new_size = safe_buffer_size(out_size, 2);
			if (new_size < 0 || new_size > MAX_DECOMPRESSED_SIZE) {
				inflateEnd(&strm);
				free(out_buf);
				return -1;
			}
			uint8_t *new_buf = realloc(out_buf, new_size);
			if (!new_buf) {
				inflateEnd(&strm);
				free(out_buf);
				return -1;
			}
			out_buf = new_buf;
			out_size = new_size;
		}

		strm.avail_out = out_size - total_out;
		strm.next_out = out_buf + total_out;

		ret = inflate(&strm, Z_NO_FLUSH);
		if (ret != Z_OK && ret != Z_STREAM_END) {
			inflateEnd(&strm);
			free(out_buf);
			return -1;
		}

		total_out = strm.total_out;
	} while (ret != Z_STREAM_END && strm.avail_in > 0);

	inflateEnd(&strm);

	*decompressed = out_buf;
	*decompressed_len = total_out;
	return 0;
#else
	return -1;
#endif
}

static int http2_try_decompress_body(struct http2_stream *stream)
{
	if (!stream || stream->body_decompressed || stream->body_buffer_len == 0) {
		return 0;
	}

	/* Only decompress when the stream is fully received or connection is closed */
	if (!stream->end_stream_received && stream->ctx && stream->ctx->status >= 0) {
		return 0;
	}

	const char *content_encoding = _http2_stream_get_header_value(stream, "content-encoding");
	int is_gzip = 0;
	int should_decompress = 0;

	if (content_encoding) {
		is_gzip = (strcasecmp(content_encoding, "gzip") == 0);
		int is_deflate = (strcasecmp(content_encoding, "deflate") == 0);
		should_decompress = (is_gzip || is_deflate);
	} else if (stream->body_buffer_len > 2) {
		/* Fallback: check for gzip magic number (0x1f 0x8b) */
		if (stream->body_buffer[0] == 0x1f && stream->body_buffer[1] == 0x8b) {
			is_gzip = 1;
			should_decompress = 1;
		}
	}

	if (should_decompress) {
		uint8_t *decompressed = NULL;
		int decompressed_len = 0;

		if (http2_decompress_data(stream->body_buffer, stream->body_buffer_len, &decompressed, &decompressed_len,
								  is_gzip) == 0) {
			/* Replace compressed buffer with decompressed data */
			free(stream->body_buffer);
			stream->body_buffer = decompressed;
			stream->body_buffer_len = decompressed_len;
			stream->body_buffer_size = decompressed_len;
			stream->body_decompressed = 1;
			return 1; /* Decompression successful */
		} else {
			/* Decompression failed, set an error flag or log */
			/* For now, leave body_decompressed = 0, and let read_body handle error */
			return -1; /* Indicate failure */
		}
	}

	return 0;
}

int http2_stream_read_body(struct http2_stream *stream, uint8_t *data, int len)
{
	if (!stream || len <= 0 || !data) {
		return -1;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);
	}

	/* NOTE: We do NOT call http2_process_frames here!
	 * The caller should use http2_ctx_poll to process frames for all streams.
	 * This function only reads from the stream's buffer. */

	/* Try to decompress if needed */
	int decompress_ret = http2_try_decompress_body(stream);
	if (decompress_ret < 0) {
		/* Decompression failed, return error */
		if (ctx) {
			pthread_mutex_unlock(&ctx->mutex);
		}
		errno = EINVAL; /* Invalid data */
		return -1;
	}

	/* If content is compressed but not yet decompressed (because stream not ended),
	   we must not return raw data. */
	const char *content_encoding = _http2_stream_get_header_value(stream, "content-encoding");
	if (content_encoding && !stream->body_decompressed) {
		/* Check if it's a compression format we handle */
		if (strcasecmp(content_encoding, "gzip") == 0 || strcasecmp(content_encoding, "deflate") == 0) {
			/* If stream not ended and connection is healthy, return EAGAIN */
			if (!stream->end_stream_received && (!ctx || ctx->status >= 0)) {
				if (ctx) {
					pthread_mutex_unlock(&ctx->mutex);
				}
				errno = EAGAIN;
				return -1;
			}
			/* If stream ended but decompression failed earlier, error already returned */
		}
	}

	int available = stream->body_buffer_len - stream->body_read_offset;
	if (available <= 0) {
		if (ctx) {
			pthread_mutex_unlock(&ctx->mutex);
		}

		/* If stream ended or connection has error, return 0 (EOF) */
		if (stream->end_stream_received || (!ctx || ctx->status < 0)) {
			stream->end_stream_read_handled = 1;
			return 0;
		}

		/* No data available yet, return EAGAIN */
		errno = EAGAIN;
		return -1;
	}

	int to_read = available < len ? available : len;
	memcpy(data, stream->body_buffer + stream->body_read_offset, to_read);
	stream->body_read_offset += to_read;

	if (ctx) {
		pthread_mutex_unlock(&ctx->mutex);
	}
	return to_read;
}

int http2_stream_body_available(struct http2_stream *stream)
{
	if (!stream) {
		return 0;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);
	}

	/* Try to decompress if needed */
	http2_try_decompress_body(stream);

	/* If content is compressed but not yet decompressed, pretend no data available */
	const char *content_encoding = _http2_stream_get_header_value(stream, "content-encoding");
	if (content_encoding && !stream->body_decompressed) {
		if (strcasecmp(content_encoding, "gzip") == 0 || strcasecmp(content_encoding, "deflate") == 0) {
			if (!stream->end_stream_received && (!ctx || ctx->status >= 0)) {
				if (ctx) {
					pthread_mutex_unlock(&ctx->mutex);
				}
				return 0;
			}
		}
	}

	int available = stream->body_buffer_len - stream->body_read_offset;

	if (ctx) {
		pthread_mutex_unlock(&ctx->mutex);
	}
	return available > 0 ? 1 : 0;
}

int http2_stream_is_end(struct http2_stream *stream)
{
	if (!stream) {
		return 1;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);
	}

	/* Try to decompress if needed - this might change body_buffer_len */
	http2_try_decompress_body(stream);

	int is_end = stream->end_stream_received && (stream->body_read_offset >= stream->body_buffer_len);

	/* If connection is closed/error, and we have read all buffered data, consider stream ended */
	if (!is_end && (!ctx || ctx->status < 0) && stream->body_read_offset >= stream->body_buffer_len) {
		is_end = 1;
	}

	if (ctx) {
		pthread_mutex_unlock(&ctx->mutex);
	}
	return is_end;
}

void http2_stream_set_ex_data(struct http2_stream *stream, void *data)
{
	if (!stream) {
		return;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);
	}

	stream->ex_data = data;

	if (ctx) {
		pthread_mutex_unlock(&ctx->mutex);
	}
}

void *http2_stream_get_ex_data(struct http2_stream *stream)
{
	if (!stream) {
		return NULL;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);
	}

	void *data = stream->ex_data;

	if (ctx) {
		pthread_mutex_unlock(&ctx->mutex);
	}
	return data;
}

int http2_ctx_want_read(struct http2_ctx *ctx)
{
	if (!ctx) {
		return 0;
	}

	pthread_mutex_lock(&ctx->mutex);
	int want_read = ctx->want_read;
	pthread_mutex_unlock(&ctx->mutex);

	return want_read;
}

int http2_ctx_want_write(struct http2_ctx *ctx)
{
	if (!ctx) {
		return 0;
	}

	pthread_mutex_lock(&ctx->mutex);
	int want_write = ctx->want_write;
	pthread_mutex_unlock(&ctx->mutex);

	return want_write;
}

int http2_ctx_is_closed(struct http2_ctx *ctx)
{
	if (!ctx) {
		return 1;
	}

	pthread_mutex_lock(&ctx->mutex);
	int is_closed = (ctx->status < 0);
	pthread_mutex_unlock(&ctx->mutex);

	return is_closed;
}

char *http2_stream_get_query_param(struct http2_stream *stream, const char *name)
{
	const char *path = NULL;
	const char *q = NULL;
	const char *val_start = NULL;
	int name_len = 0;
	char *ret = NULL;
	const int MAX_VAL_LEN = 4096; /* Limit to prevent excessive memory use */

	if (stream == NULL || name == NULL) {
		return NULL;
	}

	struct http2_ctx *ctx = stream->ctx;
	if (ctx) {
		pthread_mutex_lock(&ctx->mutex);
	}

	path = _http2_stream_get_header_value(stream, ":path");
	if (path == NULL) {
		if (ctx) {
			pthread_mutex_unlock(&ctx->mutex);
		}
		return NULL;
	}

	q = strstr(path, "?");
	if (q == NULL) {
		if (ctx) {
			pthread_mutex_unlock(&ctx->mutex);
		}
		return NULL;
	}
	q++;

	name_len = strlen(name);

	while (*q) {
		if (strncmp(q, name, name_len) == 0 && q[name_len] == '=') {
			val_start = q + name_len + 1;
			break;
		}
		q = strchr(q, '&');
		if (q == NULL) {
			break;
		}
		q++;
	}

	if (val_start) {
		const char *end = strchr(val_start, '&');
		size_t val_len = end ? (size_t)(end - val_start) : strlen(val_start);
		if (val_len > (size_t)MAX_VAL_LEN) {
			if (ctx) {
				pthread_mutex_unlock(&ctx->mutex);
			}
			return NULL; /* Too long, reject */
		}
		char *encoded_val = strndup(val_start, val_len);
		if (encoded_val) {
			size_t decoded_len = val_len * 2 + 1; // Estimate
			char *decoded_val = malloc(decoded_len);
			if (decoded_val) {
				int ret_len = urldecode(decoded_val, decoded_len, encoded_val);
				if (ret_len >= 0 && (size_t)ret_len < decoded_len) {
					ret = decoded_val;
				} else {
					free(decoded_val);
				}
			}
			free(encoded_val);
		}
	}

	if (ctx) {
		pthread_mutex_unlock(&ctx->mutex);
	}

	return ret;
}
