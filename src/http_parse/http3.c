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

#include "smartdns/http3.h"
#include "http3_parse.h"
#include "qpack.h"
#include "smartdns/http_parse.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smartdns/lib/atomic.h"

#define HTTP3_HEADER_FRAME 1
#define HTTP3_DATA_FRAME 0

static int _http3_get_expected_data_len(struct http_head *http_head, int *expect_data_len)
{
	const char *content_len = NULL;
	char *endptr = NULL;
	long expect_len = 0;

	if (expect_data_len == NULL) {
		return -1;
	}

	*expect_data_len = -1;
	if (http_head == NULL) {
		return -1;
	}

	content_len = http_head_get_fields_value(http_head, "content-length");
	if (content_len == NULL || content_len[0] == '\0') {
		return 0;
	}

	expect_len = strtol(content_len, &endptr, 10);
	if (endptr == NULL || *endptr != '\0' || expect_len < 0 || expect_len > INT_MAX) {
		return -1;
	}

	*expect_data_len = (int)expect_len;
	return 0;
}

/* Structs */

struct http3_ctx {
	atomic_t refcount;
	int is_server;
	struct http3_settings settings;
	void *conn_data;
	struct http3_conn_ops ops;

	/* Handshake State */
	struct http3_stream *control_stream; /* Local Control Stream (Uni) */
};

struct http3_owned_header {
	struct list_head list;
	char *name;
	char *value;
};

struct http3_stream {
	struct http3_ctx *ctx;
	atomic_t refcount;
	int id;

	http3_bio_read_fn bio_read;
	http3_bio_write_fn bio_write;
	void *bio_data;

	struct http_head *head;
	struct http_head *rx_head;
	struct list_head owned_headers;

	uint8_t *tx_pending;
	int tx_pending_len;
	int tx_pending_offset;
	int tx_pending_user_len;
	int tx_pending_fin;

	char *pending_body;
	int pending_body_len;
	int pending_body_offset;
	uint64_t rx_body_delivered_len;

	char *rx_raw_buffer;
	int rx_raw_buffer_len;

	int open;
};

/* Internal Helpers (Static) */
static int _http_head_setup_http3_0_httpcode(struct http_head *http_head);
static int http3_parse_headers_payload(struct http_head *http_head, const uint8_t *data, int data_len);

static int http3_varint_encode(uint64_t value, uint8_t *buffer, int buffer_size)
{
	if (value <= 63) {
		if (buffer_size < 1) {
			return -1;
		}
		buffer[0] = (uint8_t)value;
		return 1;
	} else if (value <= 16383) {
		if (buffer_size < 2) {
			return -1;
		}
		buffer[0] = (uint8_t)((value >> 8) | 0x40);
		buffer[1] = (uint8_t)value;
		return 2;
	} else if (value <= 1073741823) {
		if (buffer_size < 4) {
			return -1;
		}
		buffer[0] = (uint8_t)((value >> 24) | 0x80);
		buffer[1] = (uint8_t)(value >> 16);
		buffer[2] = (uint8_t)(value >> 8);
		buffer[3] = (uint8_t)value;
		return 4;
	} else {
		if (buffer_size < 8) {
			return -1;
		}
		buffer[0] = (uint8_t)((value >> 56) | 0xC0);
		buffer[1] = (uint8_t)(value >> 48);
		buffer[2] = (uint8_t)(value >> 40);
		buffer[3] = (uint8_t)(value >> 32);
		buffer[4] = (uint8_t)(value >> 24);
		buffer[5] = (uint8_t)(value >> 16);
		buffer[6] = (uint8_t)(value >> 8);
		buffer[7] = (uint8_t)value;
		return 8;
	}
}

static int http3_varint_decode(const uint8_t *buffer, int buffer_len, uint64_t *value)
{
	if (buffer == NULL || value == NULL || buffer_len < 1) {
		return -1;
	}

	if ((buffer[0] & 0xC0) == 0x00) {
		*value = buffer[0];
		return 1;
	} else if ((buffer[0] & 0xC0) == 0x40) {
		if (buffer_len < 2) {
			return -1;
		}
		*value = ((uint64_t)(buffer[0] & 0x3F) << 8) | buffer[1];
		return 2;
	} else if ((buffer[0] & 0xC0) == 0x80) {
		if (buffer_len < 4) {
			return -1;
		}
		*value =
			((uint64_t)(buffer[0] & 0x3F) << 24) | ((uint64_t)buffer[1] << 16) | ((uint64_t)buffer[2] << 8) | buffer[3];
		return 4;
	} else {
		if (buffer_len < 8) {
			return -1;
		}
		*value = ((uint64_t)(buffer[0] & 0x3F) << 56) | ((uint64_t)buffer[1] << 48) | ((uint64_t)buffer[2] << 40) |
				 ((uint64_t)buffer[3] << 32) | ((uint64_t)buffer[4] << 24) | ((uint64_t)buffer[5] << 16) |
				 ((uint64_t)buffer[6] << 8) | buffer[7];
		return 8;
	}
}

static int _qpack_build_header(const char *name, const char *value, uint8_t *buffer, int buffer_size)
{
	int offset = 0;
	int offset_ret = 0;
	int name_len = strlen(name);
	int value_len = strlen(value);

	if (buffer_size - offset < 2) {
		return -1;
	}

	if (name_len < 7) {
		buffer[offset++] = 0x20 | name_len;
	} else {
		buffer[offset++] = 0x20 | 7;
		buffer[offset++] = name_len - 7;
	}

	if (buffer_size - offset < name_len) {
		return -1;
	}

	memcpy(buffer + offset, name, name_len);
	offset += name_len;

	if (buffer_size - offset < 2) {
		return -1;
	}

	offset_ret = http3_varint_encode(value_len, buffer + offset, buffer_size - offset);
	if (offset_ret < 0) {
		return -1;
	}
	offset += offset_ret;

	if (buffer_size - offset < value_len) {
		return -1;
	}

	memcpy(buffer + offset, value, value_len);
	offset += value_len;

	return offset;
}

static int http3_build_headers_payload(struct http_head *http_head, uint8_t *buffer, int buffer_len)
{
	int offset = 0;
	int offset_ret = 0;
	struct http_head_fields *fields = NULL;
	struct http_params *params = NULL;

	/* Insert count and delta base */
	if (buffer_len - offset < 2) {
		return -1;
	}

	buffer[offset++] = 0;
	buffer[offset++] = 0;

	if (http_head->head_type == HTTP_HEAD_REQUEST) {
		char request_path[1024];
		char *request_path_buffer = request_path;
		int request_path_buffer_len = sizeof(request_path);

		int request_path_len = snprintf(request_path, sizeof(request_path), "%s", http_head->url);
		if (request_path_len < 0) {
			return -1;
		}

		request_path_buffer += request_path_len;
		request_path_buffer_len -= request_path_len;

		int count = 0;
		list_for_each_entry(params, &http_head->params.list, list)
		{
			if (count == 0) {
				request_path_len =
					snprintf(request_path_buffer, request_path_buffer_len, "?%s=%s", params->name, params->value);
			} else {
				request_path_len =
					snprintf(request_path_buffer, request_path_buffer_len, "&%s=%s", params->name, params->value);
			}

			count++;
			request_path_buffer += request_path_len;
			request_path_buffer_len -= request_path_len;

			if (request_path_buffer_len < 2) {
				return -3;
			}
		}

		offset_ret =
			_qpack_build_header(":method", http_method_str(http_head->method), buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;

		const char *host = http_head_get_fields_value(http_head, "host");
		if (host) {
			offset_ret = _qpack_build_header(":authority", host, buffer + offset, buffer_len - offset);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;
		}

		offset_ret = _qpack_build_header(":path", request_path, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
		offset_ret = _qpack_build_header(":scheme", "https", buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	} else if (http_head->head_type == HTTP_HEAD_RESPONSE) {
		char status_str[12];
		snprintf(status_str, sizeof(status_str), "%d", http_head->code);
		offset_ret = _qpack_build_header(":status", status_str, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	}

	list_for_each_entry(fields, &http_head->field_head.list, list)
	{
		offset_ret = _qpack_build_header(fields->name, fields->value, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	}

	if (http_head->data_len > 0 && http_head->data) {
		char len_str[12];
		snprintf(len_str, sizeof(len_str), "%d", http_head->data_len);
		offset_ret = _qpack_build_header("content-length", len_str, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	}
	return offset;
}

static int http3_build_body_payload(const uint8_t *body, int body_len, uint8_t *buffer, int buffer_len)
{
	int offset = 0;
	int offset_ret = 0;

	offset_ret = http3_varint_encode(body_len, buffer + offset, buffer_len - offset);
	if (offset_ret < 0) {
		return -1;
	}
	offset += offset_ret;

	if (buffer_len - offset < body_len) {
		return -1;
	}

	memcpy(buffer + offset, body, body_len);
	offset += body_len;

	return offset;
}

/* Decoding Helpers (Static) */

static int _quic_read_varint(const uint8_t *buffer, int buffer_len, uint64_t *value, int n)
{
	uint64_t i;
	if (n < 1 || n > 8) {
		return -2;
	}

	if (buffer_len == 0) {
		return -1;
	}

	const uint8_t *p = buffer;
	i = *p;
	if (n < 8) {
		i &= (1 << (uint64_t)n) - 1;
	}

	if (i < (uint64_t)(1 << (uint64_t)n) - 1) {
		*value = i;
		return 1;
	}

	p++;
	uint64_t m = 0;

	while (p < buffer + buffer_len) {
		uint8_t b = *p;
		i += (uint64_t)(b & 127) << m;
		if ((b & 128) == 0) {
			*value = i;
			return p - buffer + 1;
		}
		m += 7;
		if (m >= 63) {
			return -1;
		}
		p++;
	}

	return -1;
}

static int _quic_read_string(const uint8_t *buffer, int buffer_len, char *str, int max_str_len, size_t *str_len, int n,
							 int huffman)
{
	uint64_t len = 0;
	int offset = 0;
	int offset_ret = 0;

	if (buffer == NULL || str == NULL || str_len == NULL || max_str_len < 0) {
		return -3;
	}

	offset_ret = _quic_read_varint(buffer, buffer_len, &len, n);
	if (offset_ret < 0) {
		return -1;
	}
	offset += offset_ret;

	if ((uint64_t)(buffer_len - offset) < len) {
		return -1;
	}
	if ((uint64_t)max_str_len < len) {
		return -3;
	}

	if (huffman) {
		size_t char_len = 0;
		if (qpack_huffman_decode(buffer + offset, buffer + offset + len, (uint8_t *)str, max_str_len, &char_len) < 0) {
			return -1;
		}

		str[char_len] = '\0';
		*str_len = char_len;
	} else {
		memcpy(str, buffer + offset, len);
		str[len] = '\0';
		*str_len = len;
	}

	return offset + len;
}

static int http3_parse_headers_payload(struct http_head *http_head, const uint8_t *data, int data_len)
{
	int offset = 0;
	int offset_ret = 0;
	int insert_count = 0;
	int delta_base = 0;
	struct qpack_header_field *header = NULL;
	const char *name = NULL;
	const char *value = NULL;
	uint64_t index = -1;
	int use_huffman = 0;
	uint8_t b = 0;
	size_t str_len = 0;
	int buffer_left_len = 0;

	if (data_len < 2) {
		return -1;
	}

	insert_count = data[0];
	delta_base = data[1];

	if (insert_count != 0 || delta_base != 0) {
		return -2;
	}

	offset += 2;

	while (offset < data_len) {
		index = -1;
		use_huffman = 0;
		name = NULL;
		value = NULL;

		char *buffer_name = NULL;
		char *buffer_value = NULL;

		str_len = 0;
		b = data[offset];

		if (b & 0x80) {
			/* indexed header*/
			if ((b & 0x40) == 0) {
				return -2;
			}

			offset_ret = _quic_read_varint(data + offset, data_len - offset, &index, 6);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;

			header = qpack_get_static_header_field(index);
			if (header == NULL) {
				return -2;
			}

			name = header->name;
			value = header->value;
		} else if (b & 0x40) {
			/* literal header with indexing */
			if ((b & 0x10) == 0) {
				return -2;
			}
			offset_ret = _quic_read_varint(data + offset, data_len - offset, &index, 4);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;

			header = qpack_get_static_header_field(index);
			if (header == NULL) {
				return -2;
			}

			name = header->name;

			b = data[offset];
			if ((b & 0x80) > 0) {
				use_huffman = 1;
			}

			buffer_value = (char *)_http_head_buffer_get_end(http_head);
			buffer_left_len = _http_head_buffer_left_len(http_head);

			offset_ret = _quic_read_string(data + offset, data_len - offset, buffer_value, buffer_left_len - 1,
										   &str_len, 7, use_huffman);
			if (offset_ret < 0) {
				return offset_ret;
			}

			offset += offset_ret;
			buffer_value[str_len] = '\0';
			if (http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -3;
			}
			value = buffer_value;
		} else if (b & 0x20) {
			/* literal header without indexing */
			b = data[offset];
			if ((b & 0x8) > 0) {
				use_huffman = 1;
			}

			buffer_name = (char *)_http_head_buffer_get_end(http_head);
			buffer_left_len = _http_head_buffer_left_len(http_head);

			offset_ret = _quic_read_string(data + offset, data_len - offset, buffer_name, buffer_left_len - 1, &str_len,
										   3, use_huffman);
			if (offset_ret < 0) {
				return offset_ret;
			}
			offset += offset_ret;
			buffer_name[str_len] = '\0';
			if (http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -3;
			}
			name = buffer_name;

			b = data[offset];
			if ((b & 0x80) > 0) {
				use_huffman = 1;
			}

			buffer_value = (char *)_http_head_buffer_get_end(http_head);
			buffer_left_len = _http_head_buffer_left_len(http_head);
			offset_ret = _quic_read_string(data + offset, data_len - offset, buffer_value, buffer_left_len - 1,
										   &str_len, 7, use_huffman);
			if (offset_ret < 0) {
				return offset_ret;
			}
			offset += offset_ret;
			buffer_value[str_len] = '\0';
			if (http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -3;
			}
			value = buffer_value;
		} else {
			return -2;
		}

		if (http_head_add_fields(http_head, name, value) != 0) {
			break;
		}
	}

	return 0;
}

struct http3_ctx *http3_ctx_client_new(void *conn_data, const struct http3_conn_ops *ops,
									   const struct http3_settings *settings)
{
	struct http3_ctx *ctx = (struct http3_ctx *)calloc(1, sizeof(struct http3_ctx));
	if (!ctx) {
		return NULL;
	}

	atomic_set(&ctx->refcount, 1);
	ctx->is_server = 0;
	ctx->conn_data = conn_data;
	if (ops) {
		ctx->ops = *ops;
	}

	if (settings) {
		ctx->settings = *settings;
	}
	return ctx;
}

struct http3_ctx *http3_ctx_server_new(void *conn_data, const struct http3_conn_ops *ops,
									   const struct http3_settings *settings)
{
	struct http3_ctx *ctx = (struct http3_ctx *)calloc(1, sizeof(struct http3_ctx));
	if (!ctx) {
		return NULL;
	}

	atomic_set(&ctx->refcount, 1);
	ctx->is_server = 1;
	ctx->conn_data = conn_data;
	if (ops) {
		ctx->ops = *ops;
	}

	if (settings) {
		ctx->settings = *settings;
	}
	return ctx;
}

void http3_ctx_close(struct http3_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->control_stream) {
		http3_stream_put(ctx->control_stream);
		ctx->control_stream = NULL;
	}
}

struct http3_ctx *http3_ctx_get(struct http3_ctx *ctx)
{
	if (ctx) {
		atomic_inc(&ctx->refcount);
	}
	return ctx;
}

void http3_ctx_put(struct http3_ctx *ctx)
{
	if (ctx) {
		if (atomic_dec_and_test(&ctx->refcount)) {
			http3_ctx_close(ctx);
			free(ctx);
		}
	}
}

int http3_ctx_handshake(struct http3_ctx *ctx)
{
	void *stream_handle = NULL;
	struct http3_stream *s = NULL;
	uint8_t type_buf[8];
	uint8_t frame_head[16];
	int payload_len = 0;
	int h_off = 0;
	int ret = 0;
	int r = 0;

	if (!ctx) {
		return -1;
	}
	if (!ctx->ops.create_stream) {
		return HTTP3_ERR_NONE; /* No ops, assume manual management? or error */
	}
	if (ctx->control_stream) {
		return HTTP3_ERR_NONE; /* Already done */
	}

	/* 1. Create Control Stream (Unidirectional) */
	/* Stream Type 0x02 = HTTP/3 Control Stream? No, Stream Type is payload inside the stream.
	   QUIC Stream Type is just Uni/Bi. We ask for Uni. */
	stream_handle = ctx->ops.create_stream(ctx->conn_data, 1 /* UNI */);
	if (!stream_handle) {
		return HTTP3_ERR_NONE; /* Skip control stream, pretend done */
	}

	/* 2. Wrap in http3_stream */
	/* We use a private helper or expose logic to link handle */
	s = http3_stream_new(ctx);
	if (!s) {
		goto err;
	}
	/* Link BIOs */
	http3_stream_set_bio(s, (http3_bio_read_fn)ctx->ops.read, (http3_bio_write_fn)ctx->ops.write, stream_handle);
	ctx->control_stream = s;

	/* 3. Send SETTINGS Frame */
	/* Frame Type 0x04 = SETTINGS */
	/* Payload: Identifier (Varint) + Value (Varint) ... */

	/* First, Write Stream Type (0x00 = Control Stream) */
	ret = http3_varint_encode(0x00, type_buf, sizeof(type_buf));
	if (ret <= 0) {
		goto protocol_err;
	}

	if (s->bio_write(s->bio_data, type_buf, ret, 0) != ret) {
		goto err;
	}

	/* For verification, we just send empty settings to say "Hello" */
	/* Frame Payload is empty if no settings */

	/* Frame Header */
	r = http3_varint_encode(0x04, frame_head, sizeof(frame_head)); /* Type = SETTINGS */
	if (r <= 0) {
		goto protocol_err;
	}
	h_off += r;
	r = http3_varint_encode(payload_len, frame_head + h_off, sizeof(frame_head) - h_off);
	if (r <= 0) {
		goto protocol_err;
	}
	h_off += r;

	if (s->bio_write(s->bio_data, frame_head, h_off, 0) != h_off) {
		goto err;
	}

	/* Send Payload (0 bytes) */

	return HTTP3_ERR_NONE;

protocol_err:
	ret = HTTP3_ERR_PROTOCOL;
	goto cleanup;

err:
	ret = HTTP3_ERR_IO;

cleanup:
	if (ctx->control_stream) {
		http3_stream_put(ctx->control_stream);
		ctx->control_stream = NULL;
	} else if (stream_handle && ctx->ops.close_stream) {
		ctx->ops.close_stream(stream_handle);
	}

	return ret;
}

struct http3_stream *http3_ctx_accept_stream(struct http3_ctx *ctx)
{
	return http3_stream_new(ctx);
}

int http3_ctx_poll(struct http3_ctx *ctx, struct http3_poll_item *items, int max_items, int *ret_count)
{
	return 0;
}

struct http3_stream *http3_stream_new(struct http3_ctx *ctx)
{
	struct http3_stream *s = (struct http3_stream *)calloc(1, sizeof(struct http3_stream));
	if (!s) {
		return NULL;
	}
	s->ctx = ctx;
	atomic_set(&s->refcount, 1);
	s->open = 1;
	INIT_LIST_HEAD(&s->owned_headers);
	/* If ctx has default ops, maybe we should not set them here?
	   The caller usually calls http3_stream_set_bio next.
	   For now, leave empty.
	*/
	return s;
}

static void _http3_stream_clear_owned_headers(struct http3_stream *stream)
{
	struct http3_owned_header *header = NULL;
	struct http3_owned_header *tmp = NULL;

	list_for_each_entry_safe(header, tmp, &stream->owned_headers, list)
	{
		list_del(&header->list);
		free(header->name);
		free(header->value);
		free(header);
	}
}

void http3_stream_close(struct http3_stream *stream)
{
	if (stream) {
		stream->open = 0;
		if (stream->ctx && stream->ctx->ops.close_stream && stream->bio_data) {
			stream->ctx->ops.close_stream(stream->bio_data);
			stream->bio_data = NULL;
		}
		if (stream->head) {
			http_head_destroy(stream->head);
			stream->head = NULL;
		}
		_http3_stream_clear_owned_headers(stream);
		if (stream->rx_head) {
			http_head_destroy(stream->rx_head);
			stream->rx_head = NULL;
		}
		if (stream->tx_pending) {
			free(stream->tx_pending);
			stream->tx_pending = NULL;
		}
		stream->tx_pending_len = 0;
		stream->tx_pending_offset = 0;
		stream->tx_pending_user_len = 0;
		stream->tx_pending_fin = 0;
		if (stream->pending_body) {
			free(stream->pending_body);
			stream->pending_body = NULL;
		}
		if (stream->rx_raw_buffer) {
			free(stream->rx_raw_buffer);
			stream->rx_raw_buffer = NULL;
		}
	}
}

struct http3_stream *http3_stream_get(struct http3_stream *stream)
{
	if (stream) {
		atomic_inc(&stream->refcount);
	}
	return stream;
}

void http3_stream_put(struct http3_stream *stream)
{
	if (stream) {
		if (atomic_dec_and_test(&stream->refcount)) {
			http3_stream_close(stream);
			free(stream);
		}
	}
}

int http3_stream_get_id(struct http3_stream *stream)
{
	return stream->id;
}

void http3_stream_set_bio(struct http3_stream *stream, http3_bio_read_fn read, http3_bio_write_fn write,
						  void *private_data)
{
	stream->bio_read = read;
	stream->bio_write = write;
	stream->bio_data = private_data;
}

static int _http3_stream_add_owned_header(struct http3_stream *stream, const char *name, const char *value)
{
	struct http3_owned_header *header = NULL;
	int ret = -1;

	if (!stream || !stream->head || !name || !value) {
		errno = EINVAL;
		return -1;
	}

	header = calloc(1, sizeof(*header));
	if (!header) {
		goto out;
	}

	header->name = strdup(name);
	header->value = strdup(value);
	if (!header->name || !header->value) {
		goto out;
	}

	if (http_head_add_fields(stream->head, header->name, header->value) != 0) {
		goto out;
	}

	list_add_tail(&header->list, &stream->owned_headers);
	ret = 0;
	header = NULL;

out:
	if (header) {
		free(header->name);
		free(header->value);
		free(header);
	}
	return ret;
}

int http3_stream_set_request(struct http3_stream *stream, const char *method, const char *path, const char *scheme,
							 const struct http3_header_pair *headers)
{
	if (!stream->head) {
		stream->head = http_head_init(1024, HTTP_VERSION_3_0);
		if (!stream->head) {
			return -1;
		}
	}

	int m = HTTP_METHOD_GET;
	if (method && strcmp(method, "POST") == 0) {
		m = HTTP_METHOD_POST;
	}

	http_head_set_head_type(stream->head, HTTP_HEAD_REQUEST);
	http_head_set_method(stream->head, m);
	if (!path) {
		path = "/";
	}
	http_head_set_url(stream->head, path);

	while (headers && headers->name) {
		if (_http3_stream_add_owned_header(stream, headers->name, headers->value) != 0) {
			return -1;
		}
		headers++;
	}
	return 0;
}

int http3_stream_set_response(struct http3_stream *stream, int status, const struct http3_header_pair *headers,
							  int header_count)
{
	if (!stream->head) {
		stream->head = http_head_init(1024, HTTP_VERSION_3_0);
		if (!stream->head) {
			return -1;
		}
	}
	http_head_set_httpcode(stream->head, status, "OK");

	for (int i = 0; i < header_count; i++) {
		if (_http3_stream_add_owned_header(stream, headers[i].name, headers[i].value) != 0) {
			return -1;
		}
	}
	return 0;
}

static int _http3_stream_flush_tx_pending(struct http3_stream *stream, int *user_len)
{
	int completed_user_len = stream->tx_pending_user_len;
	int pending_fin = stream->tx_pending_fin;

	if (user_len) {
		*user_len = -1;
	}

	while (stream->tx_pending_offset < stream->tx_pending_len) {
		int eos = pending_fin;
		int ret = stream->bio_write(stream->bio_data, stream->tx_pending + stream->tx_pending_offset,
									stream->tx_pending_len - stream->tx_pending_offset, eos);
		if (ret < 0) {
			return -1;
		}
		if (ret == 0) {
			errno = EAGAIN;
			return -1;
		}
		stream->tx_pending_offset += ret;
	}

	if (stream->tx_pending_len > 0) {
		free(stream->tx_pending);
		stream->tx_pending = NULL;
		stream->tx_pending_len = 0;
		stream->tx_pending_offset = 0;
	}

	if (user_len) {
		*user_len = completed_user_len;
	}
	stream->tx_pending_user_len = 0;
	stream->tx_pending_fin = 0;
	return 0;
}

static void _http3_stream_destroy_head(struct http3_stream *stream)
{
	if (stream->head) {
		http_head_destroy(stream->head);
		stream->head = NULL;
	}
	_http3_stream_clear_owned_headers(stream);
}

static int _http3_stream_save_tx_pending(struct http3_stream *stream, uint8_t *frame, int frame_len, int written,
										 int user_len, int end_stream)
{
	int remaining = frame_len - written;

	if (remaining <= 0) {
		free(frame);
		errno = EAGAIN;
		return -1;
	}

	if (written > 0) {
		memmove(frame, frame + written, (size_t)remaining);
	}

	stream->tx_pending = frame;
	stream->tx_pending_len = remaining;
	stream->tx_pending_offset = 0;
	stream->tx_pending_user_len = user_len;
	stream->tx_pending_fin = end_stream;
	_http3_stream_destroy_head(stream);
	errno = EAGAIN;
	return -1;
}

/* Helpers to serialize/parse using static helpers */

int http3_stream_write_body(struct http3_stream *stream, const uint8_t *data, int len, int end_stream)
{
	char head_buf[4096];
	int hlen = 0;
	uint8_t prefix[16];
	int prefix_len = 0;
	uint8_t *frame = NULL;
	int frame_len = 0;
	int ret = 0;
	int result = -1;
	int completed_user_len = -1;

	if (!stream || !stream->bio_write || len < 0 || (len > 0 && !data)) {
		errno = EINVAL;
		goto out;
	}

	if (stream->tx_pending || stream->tx_pending_fin) {
		if (_http3_stream_flush_tx_pending(stream, &completed_user_len) != 0) {
			goto out;
		}
		if (completed_user_len >= 0) {
			result = completed_user_len;
			goto out;
		}
	}

	if (stream->head) {
		hlen = http_head_serialize_http3_0(stream->head, (unsigned char *)head_buf, sizeof(head_buf));
		if (hlen < 0) {
			errno = EIO;
			goto out;
		}
	}

	if (len > 0) {
		ret = http3_varint_encode(HTTP3_DATA_FRAME, prefix, sizeof(prefix));
		if (ret <= 0) {
			errno = EIO;
			goto out;
		}
		prefix_len += ret;

		ret = http3_varint_encode(len, prefix + prefix_len, sizeof(prefix) - prefix_len);
		if (ret <= 0) {
			errno = EIO;
			goto out;
		}
		prefix_len += ret;
	}

	frame_len = hlen + prefix_len + len;
	if (frame_len > 0) {
		frame = malloc((size_t)frame_len);
		if (!frame) {
			goto out;
		}

		if (hlen > 0) {
			memcpy(frame, head_buf, (size_t)hlen);
		}
		if (prefix_len > 0) {
			memcpy(frame + hlen, prefix, (size_t)prefix_len);
			memcpy(frame + hlen + prefix_len, data, (size_t)len);
		}

		ret = stream->bio_write(stream->bio_data, frame, frame_len, end_stream);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				_http3_stream_save_tx_pending(stream, frame, frame_len, 0, len, end_stream);
				frame = NULL;
			}
			goto out;
		}
		if (ret == 0) {
			_http3_stream_save_tx_pending(stream, frame, frame_len, 0, len, end_stream);
			frame = NULL;
			goto out;
		}
		if (ret != frame_len) {
			if (ret > 0) {
				_http3_stream_save_tx_pending(stream, frame, frame_len, ret, len, end_stream);
				frame = NULL;
				goto out;
			}

			errno = EAGAIN;
			goto out;
		}
		free(frame);
		frame = NULL;

		_http3_stream_destroy_head(stream);
		result = len;
	} else if (end_stream) {
		ret = stream->bio_write(stream->bio_data, NULL, 0, 1);
		if (ret < 0) {
			goto out;
		}
		result = 0;
	} else {
		result = 0;
	}

out:
	free(frame);
	return result;
}

static int _http3_stream_body_complete(struct http3_stream *stream)
{
	const char *content_length = NULL;
	char *end = NULL;
	unsigned long long value = 0;

	if (!stream || !stream->rx_head) {
		return 0;
	}

	content_length = http_head_get_fields_value(stream->rx_head, "content-length");
	if (!content_length || content_length[0] == '\0') {
		return 0;
	}

	value = strtoull(content_length, &end, 10);
	if (end == content_length || *end != '\0') {
		return 0;
	}

	return stream->rx_body_delivered_len >= value;
}

int http3_stream_read_body(struct http3_stream *stream, uint8_t *data, int len)
{
	/* 1. Pull from bio */
	uint8_t tmp[4096];
	int r = 0;

	if (!stream || !stream->bio_read || len < 0 || (len > 0 && !data)) {
		errno = EINVAL;
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	if (_http3_stream_body_complete(stream)) {
		errno = 0;
		return 0;
	}

	r = stream->bio_read(stream->bio_data, tmp, sizeof(tmp));
	if (r > 0) {
		if (stream->rx_raw_buffer_len > INT_MAX - r) {
			errno = ENOMEM;
			return -1;
		}

		void *new_buf = realloc(stream->rx_raw_buffer, (size_t)stream->rx_raw_buffer_len + (size_t)r);
		if (!new_buf) {
			return -1;
		}

		stream->rx_raw_buffer = new_buf;
		memcpy(stream->rx_raw_buffer + stream->rx_raw_buffer_len, tmp, (size_t)r);
		stream->rx_raw_buffer_len += r;
	} else if (r < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			return -1;
		}
	}

	/* 2. Parse frames individually from raw buffer */
	while (stream->rx_raw_buffer_len > 0) {
		uint64_t type = 0, flen = 0;
		int r1 = http3_varint_decode((uint8_t *)stream->rx_raw_buffer, stream->rx_raw_buffer_len, &type);
		if (r1 < 0) {
			break;
		}
		int r2 = http3_varint_decode((uint8_t *)stream->rx_raw_buffer + r1, stream->rx_raw_buffer_len - r1, &flen);
		if (r2 < 0) {
			break;
		}
		if ((uint64_t)stream->rx_raw_buffer_len < (uint64_t)r1 + r2 + flen) {
			break;
		}

		uint8_t *payload = (uint8_t *)stream->rx_raw_buffer + r1 + r2;
		if (type == 0x01) { /* HEADERS */
			if (!stream->rx_head) {
				stream->rx_head = http_head_init(4096, HTTP_VERSION_3_0);
				if (!stream->rx_head) {
					return -1;
				}
			}
			if (http3_parse_headers_payload(stream->rx_head, payload, flen) < 0) {
				return -1;
			}
			if (_http_head_setup_http3_0_httpcode(stream->rx_head) != 0) {
				return -1;
			}
		} else if (type == 0x00) { /* DATA */
			if (flen > INT_MAX || stream->pending_body_len > INT_MAX - (int)flen) {
				errno = ENOMEM;
				return -1;
			}

			void *new_body = realloc(stream->pending_body, (size_t)stream->pending_body_len + (size_t)flen);
			if (!new_body) {
				return -1;
			}

			stream->pending_body = new_body;
			memcpy(stream->pending_body + stream->pending_body_len, payload, (size_t)flen);
			stream->pending_body_len += (int)flen;
		}

		int consumed = r1 + r2 + (int)flen;
		int left = stream->rx_raw_buffer_len - consumed;
		if (left > 0) {
			memmove(stream->rx_raw_buffer, stream->rx_raw_buffer + consumed, left);
			stream->rx_raw_buffer_len = left;
		} else {
			free(stream->rx_raw_buffer);
			stream->rx_raw_buffer = NULL;
			stream->rx_raw_buffer_len = 0;
		}
	}

	/* 3. Return from pending body buffer */
	if (stream->pending_body_len > 0) {
		int avail = stream->pending_body_len - stream->pending_body_offset;
		int to_copy = (len < avail) ? len : avail;
		memcpy(data, (uint8_t *)stream->pending_body + stream->pending_body_offset, to_copy);
		stream->pending_body_offset += to_copy;
		stream->rx_body_delivered_len += (uint64_t)to_copy;

		if (stream->pending_body_offset >= stream->pending_body_len) {
			free(stream->pending_body);
			stream->pending_body = NULL;
			stream->pending_body_len = 0;
			stream->pending_body_offset = 0;
		}
		return to_copy;
	}

	if (r == 0 && stream->rx_raw_buffer_len == 0) {
		return 0;
	}

	errno = EAGAIN;
	return -1;
}

const char *http3_stream_get_path(struct http3_stream *stream)
{
	if (stream->rx_head) {
		return http_head_get_url(stream->rx_head);
	}
	return NULL;
}
const char *http3_stream_get_method(struct http3_stream *stream)
{
	if (stream->rx_head) {
		return http_method_str(http_head_get_method(stream->rx_head));
	}
	return NULL;
}

int http3_stream_get_status(struct http3_stream *stream)
{
	if (stream->rx_head) {
		return http_head_get_httpcode(stream->rx_head);
	}
	return 0;
}

const char *http3_stream_get_header(struct http3_stream *stream, const char *name)
{
	if (stream->rx_head) {
		return http_head_get_fields_value(stream->rx_head, name);
	}
	return NULL;
}

static int _http_head_setup_http3_0_httpcode(struct http_head *http_head)
{
	const char *status = NULL;
	int status_code = 0;
	const char *method = NULL;
	const char *url = NULL;

	method = http_head_get_fields_value(http_head, ":method");
	if (method) {
		http_head->method = _http_method_parse(method);
		if (http_head->method == HTTP_METHOD_INVALID) {
			return -1;
		}

		url = http_head_get_fields_value(http_head, ":path");
		if (url == NULL) {
			return -1;
		}

		http_head->url = url;
		http_head->head_type = HTTP_HEAD_REQUEST;

		if (_http_head_parse_params(http_head, (char *)url, strlen(url) + 1) != 0) {
			return -1;
		}

		return 0;
	}

	status = http_head_get_fields_value(http_head, ":status");
	if (status == NULL) {
		return 0;
	}

	http_head->head_type = HTTP_HEAD_RESPONSE;

	status_code = atoi(status);
	if (status_code < 100 || status_code > 999) {
		return -1;
	}

	http_head->code = status_code;
	if (status_code == 200) {
		return 0;
	}

	return 0;
}

int http_head_parse_http3_0(struct http_head *http_head, const uint8_t *data, int data_len)
{
	uint64_t frame_type = 0;
	uint64_t frame_len = 0;
	int offset = 0;
	int offset_ret = 0;
	int expect_data_len = -1;

	http_head->data_len = 0;
	while (offset < data_len) {
		offset_ret = http3_varint_decode((uint8_t *)data + offset, data_len - offset, &frame_type);
		if (offset_ret < 0) {
			return offset_ret;
		}
		offset += offset_ret;

		offset_ret = http3_varint_decode((uint8_t *)data + offset, data_len - offset, &frame_len);
		if (offset_ret < 0) {
			return offset_ret;
		}
		offset += offset_ret;

		if (offset >= http_head->buff_size) {
			return -3;
		}

		if ((uint64_t)(data_len - offset) < frame_len) {
			return -1;
		}

		if (frame_type == HTTP3_HEADER_FRAME) {
			int header_len = 0;
			/* Direct call to static helper */
			header_len = http3_parse_headers_payload(http_head, data + offset, frame_len);
			if (header_len < 0) {
				return header_len;
			}

			if (_http_head_setup_http3_0_httpcode(http_head) != 0) {
				return -1;
			}

			if (_http3_get_expected_data_len(http_head, &expect_data_len) != 0) {
				return -2;
			}

		} else if (frame_type == HTTP3_DATA_FRAME) {
			if (http_head->code != 200 && http_head->head_type == HTTP_HEAD_RESPONSE) {
				if (frame_len > (uint64_t)(http_head->buff_size - http_head->buff_len)) {
					http_head->code_msg = "Unknow Error";
					return 0;
				}

				memcpy(http_head->buff + http_head->buff_len, data + offset, frame_len);
				http_head->code_msg = (const char *)(http_head->buff + http_head->buff_len);
				http_head->buff_len += frame_len;
			} else if (frame_len > 0) {
				if (http_head->data == NULL) {
					http_head->data = _http_head_buffer_get_end(http_head);
				}

				if (http_head_buffer_append(http_head, data + offset, frame_len) == NULL) {
					http_head->code_msg = "Receive Buffer Insufficient";
					http_head->code = 500;
					http_head->data_len = 0;
					http_head->buff_len = 0;
					return -3;
				}
				http_head->data_len += frame_len;
			}
		} else {
			/* skip unknown frame. e.g. GREASE  */
			offset += frame_len;
			continue;
		}
		offset += frame_len;
	}

	if (expect_data_len >= 0) {
		if (http_head->data_len < expect_data_len) {
			return -1;
		}

		if (http_head->data_len > expect_data_len) {
			return -2;
		}
	}

	if (offset >= http_head->buff_size) {
		return -3;
	}

	http_head->version = "HTTP/3.0";

	return offset;
}

int http_head_serialize_http3_0(struct http_head *http_head, uint8_t *buffer, int buffer_len)
{
	int offset = 0;
	int offset_ret = 0;
	uint8_t *header_data = NULL;
	int header_data_size = 1024;
	int header_data_len = 0;
	int result = -1;

	header_data = malloc(header_data_size);
	if (!header_data) {
		goto cleanup;
	}

	/* serialize header frame using static helper */
	header_data_len = http3_build_headers_payload(http_head, header_data, header_data_size);
	if (header_data_len < 0) {
		goto cleanup;
	}

	/* If header_data_len > header_data_size, realloc */
	if (header_data_len > header_data_size) {
		uint8_t *new_header_data = realloc(header_data, header_data_len);
		if (!new_header_data) {
			goto cleanup;
		}
		header_data = new_header_data;
		header_data_size = header_data_len;
		header_data_len = http3_build_headers_payload(http_head, header_data, header_data_size);
		if (header_data_len < 0) {
			goto cleanup;
		}
	}

	/* Frame Type: Header*/
	offset_ret = http3_varint_encode(HTTP3_HEADER_FRAME, buffer + offset, buffer_len - offset);
	if (offset_ret < 0) {
		goto cleanup;
	}
	offset += offset_ret;

	/* Header Frame Length */
	offset_ret = http3_varint_encode(header_data_len, buffer + offset, buffer_len - offset);
	if (offset_ret < 0) {
		goto cleanup;
	}
	offset += offset_ret;

	if (buffer_len - offset < header_data_len) {
		goto cleanup;
	}
	memcpy(buffer + offset, header_data, header_data_len);
	offset += header_data_len;

	/* Frame Type: Data */
	if (http_head->data_len > 0 && http_head->data) {
		/* Data Frame Length */
		offset_ret = http3_varint_encode(HTTP3_DATA_FRAME, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			goto cleanup;
		}
		offset += offset_ret;

		offset_ret =
			http3_build_body_payload(http_head->data, http_head->data_len, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			goto cleanup;
		}
		offset += offset_ret;
	}

	result = offset;

cleanup:
	if (header_data) {
		free(header_data);
	}
	return result;
}
