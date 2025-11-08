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

#include "http2_parse.h"
#include "hpack.h"
#include "http_parse.h"
#include <stdio.h>
#include <string.h>

/* HTTP/2 Frame Types (RFC 7540) */
#define HTTP2_FRAME_DATA 0x0
#define HTTP2_FRAME_HEADERS 0x1
#define HTTP2_FRAME_PRIORITY 0x2
#define HTTP2_FRAME_RST_STREAM 0x3
#define HTTP2_FRAME_SETTINGS 0x4
#define HTTP2_FRAME_PUSH_PROMISE 0x5
#define HTTP2_FRAME_PING 0x6
#define HTTP2_FRAME_GOAWAY 0x7
#define HTTP2_FRAME_WINDOW_UPDATE 0x8
#define HTTP2_FRAME_CONTINUATION 0x9

/* HTTP/2 Frame Flags */
#define HTTP2_FLAG_END_STREAM 0x1
#define HTTP2_FLAG_END_HEADERS 0x4
#define HTTP2_FLAG_PADDED 0x8
#define HTTP2_FLAG_PRIORITY 0x20

/* HTTP/2 Frame Header Size */
#define HTTP2_FRAME_HEADER_SIZE 9

/* Encode integer with prefix bits (RFC 7541 Section 5.1) */
static int _hpack_encode_integer(uint32_t value, int prefix_bits, uint8_t *buffer, int buffer_size)
{
	int max_prefix = (1 << prefix_bits) - 1;
	int offset = 0;

	if (value < (uint32_t)max_prefix) {
		if (buffer_size < 1) {
			return -1;
		}
		buffer[0] |= value;
		return 1;
	}

	if (buffer_size < 1) {
		return -1;
	}
	buffer[0] |= max_prefix;
	offset = 1;
	value -= max_prefix;

	while (value >= 128) {
		if (buffer_size - offset < 1) {
			return -1;
		}
		buffer[offset++] = (value & 0x7F) | 0x80;
		value >>= 7;
	}

	if (buffer_size - offset < 1) {
		return -1;
	}
	buffer[offset++] = value;

	return offset;
}

/* Decode integer with prefix bits (RFC 7541 Section 5.1) */
static int _hpack_decode_integer(const uint8_t *buffer, int buffer_len, int prefix_bits, uint32_t *value)
{
	int max_prefix = (1 << prefix_bits) - 1;
	int offset = 0;
	int m = 0;

	if (buffer_len < 1) {
		return -1;
	}

	*value = buffer[0] & max_prefix;
	if (*value < (uint32_t)max_prefix) {
		return 1;
	}

	offset = 1;
	while (offset < buffer_len) {
		uint32_t b = buffer[offset];
		*value += (b & 0x7F) << m;
		offset++;
		if ((b & 0x80) == 0) {
			return offset;
		}
		m += 7;
		if (m >= 28) {
			return -1;
		}
	}

	return -1;
}

/* Decode string (RFC 7541 Section 5.2) */
static int _hpack_decode_string(const uint8_t *buffer, int buffer_len, char *str, int max_str_len, size_t *str_len)
{
	int huffman = (buffer[0] & 0x80) != 0;
	uint32_t len = 0;
	int offset = 0;
	int offset_ret = 0;

	offset_ret = _hpack_decode_integer(buffer, buffer_len, 7, &len);
	if (offset_ret < 0) {
		return -1;
	}
	offset = offset_ret;

	if ((uint32_t)(buffer_len - offset) < len) {
		return -1;
	}

	if ((uint32_t)max_str_len < len) {
		return -3;
	}

	if (huffman) {
		size_t decoded_len = 0;
		if (hpack_huffman_decode(buffer + offset, buffer + offset + len, (uint8_t *)str, max_str_len, &decoded_len) <
			0) {
			return -1;
		}
		str[decoded_len] = '\0';
		*str_len = decoded_len;
	} else {
		memcpy(str, buffer + offset, len);
		str[len] = '\0';
		*str_len = len;
	}

	return offset + len;
}

/* Encode string (RFC 7541 Section 5.2) */
static int _hpack_encode_string(const char *str, int str_len, uint8_t *buffer, int buffer_size)
{
	int offset = 0;
	int offset_ret = 0;

	/* We don't use Huffman encoding for simplicity */
	if (buffer_size < 1) {
		return -1;
	}

	buffer[0] = 0; /* No Huffman encoding */
	offset_ret = _hpack_encode_integer(str_len, 7, buffer, buffer_size);
	if (offset_ret < 0) {
		return -1;
	}
	offset = offset_ret;

	if (buffer_size - offset < str_len) {
		return -1;
	}

	memcpy(buffer + offset, str, str_len);
	offset += str_len;

	return offset;
}

/* Build HPACK header block */
static int _http2_build_header_block(struct http_head *http_head, uint8_t *buffer, int buffer_len)
{
	int offset = 0;
	int offset_ret = 0;
	struct http_head_fields *fields = NULL;
	struct http_params *params = NULL;

	if (http_head->head_type == HTTP_HEAD_REQUEST) {
		char request_path[1024];
		int request_path_len = 0;

		/* Build path with query parameters */
		request_path_len = snprintf(request_path, sizeof(request_path), "%s", http_head->url);
		if (request_path_len < 0 || request_path_len >= (int)sizeof(request_path)) {
			return -1;
		}

		int count = 0;
		list_for_each_entry(params, &http_head->params.list, list)
		{
			int remain = sizeof(request_path) - request_path_len;
			int n;
			if (count == 0) {
				n = snprintf(request_path + request_path_len, remain, "?%s=%s", params->name, params->value);
			} else {
				n = snprintf(request_path + request_path_len, remain, "&%s=%s", params->name, params->value);
			}
			if (n < 0 || n >= remain) {
				return -3;
			}
			request_path_len += n;
			count++;
		}

		/* :method */
		const char *method = http_method_str(http_head->method);
		if (http_head->method == HTTP_METHOD_GET) {
			/* Indexed header field: :method GET (index 2) */
			if (buffer_len - offset < 1) {
				return -1;
			}
			buffer[offset++] = 0x82; /* 10000010 */
		} else if (http_head->method == HTTP_METHOD_POST) {
			/* Indexed header field: :method POST (index 3) */
			if (buffer_len - offset < 1) {
				return -1;
			}
			buffer[offset++] = 0x83; /* 10000011 */
		} else {
			/* Literal header field with incremental indexing: :method */
			if (buffer_len - offset < 2) {
				return -1;
			}
			buffer[offset++] = 0x42; /* 01000010 - indexed name :method (index 2) */
			offset_ret = _hpack_encode_string(method, strlen(method), buffer + offset, buffer_len - offset);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;
		}

		/* :path */
		if (strcmp(request_path, "/") == 0) {
			/* Indexed header field: :path / (index 4) */
			if (buffer_len - offset < 1) {
				return -1;
			}
			buffer[offset++] = 0x84; /* 10000100 */
		} else {
			/* Literal header field with incremental indexing: :path */
			if (buffer_len - offset < 2) {
				return -1;
			}
			buffer[offset++] = 0x44; /* 01000100 - indexed name :path (index 4) */
			offset_ret = _hpack_encode_string(request_path, strlen(request_path), buffer + offset, buffer_len - offset);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;
		}

		/* :scheme https (index 7) */
		if (buffer_len - offset < 1) {
			return -1;
		}
		buffer[offset++] = 0x87; /* 10000111 */

	} else if (http_head->head_type == HTTP_HEAD_RESPONSE) {
		/* :status */
		char status_str[12];
		snprintf(status_str, sizeof(status_str), "%d", http_head->code);

		if (http_head->code == 200) {
			/* Indexed header field: :status 200 (index 8) */
			if (buffer_len - offset < 1) {
				return -1;
			}
			buffer[offset++] = 0x88; /* 10001000 */
		} else {
			/* Literal header field: :status */
			if (buffer_len - offset < 2) {
				return -1;
			}
			buffer[offset++] = 0x48; /* 01001000 - indexed name :status (index 8) */
			offset_ret = _hpack_encode_string(status_str, strlen(status_str), buffer + offset, buffer_len - offset);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;
		}
	}

	/* Add other header fields */
	list_for_each_entry(fields, &http_head->field_head.list, list)
	{
		/* Literal header field without indexing - new name */
		if (buffer_len - offset < 2) {
			return -1;
		}
		buffer[offset++] = 0x00; /* 00000000 - literal without indexing */

		offset_ret = _hpack_encode_string(fields->name, strlen(fields->name), buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;

		offset_ret = _hpack_encode_string(fields->value, strlen(fields->value), buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	}

	/* Add content-length if data is present */
	if (http_head->data_len > 0 && http_head->data) {
		char len_str[32];
		snprintf(len_str, sizeof(len_str), "%d", http_head->data_len);

		if (buffer_len - offset < 2) {
			return -1;
		}
		buffer[offset++] = 0x5C; /* 01011100 - indexed name content-length (index 28) */
		offset_ret = _hpack_encode_string(len_str, strlen(len_str), buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	}

	return offset;
}

/* Parse HPACK header block */
static int _http2_parse_header_block(struct http_head *http_head, const uint8_t *data, int data_len)
{
	int offset = 0;
	int offset_ret = 0;

	while (offset < data_len) {
		uint8_t b = data[offset];
		const char *name = NULL;
		const char *value = NULL;
		char *buffer_name = NULL;
		char *buffer_value = NULL;
		size_t str_len = 0;
		int buffer_left_len = 0;
		struct hpack_header_field *header = NULL;

		if (b & 0x80) {
			/* Indexed Header Field */
			uint32_t index = 0;
			offset_ret = _hpack_decode_integer(data + offset, data_len - offset, 7, &index);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;

			header = hpack_get_static_header_field(index);
			if (header == NULL) {
				return -2;
			}

			name = header->name;
			value = header->value;

		} else if (b & 0x40) {
			/* Literal Header Field with Incremental Indexing */
			uint32_t index = 0;
			offset_ret = _hpack_decode_integer(data + offset, data_len - offset, 6, &index);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;

			if (index == 0) {
				/* New name */
				buffer_name = (char *)_http_head_buffer_get_end(http_head);
				buffer_left_len = _http_head_buffer_left_len(http_head);

				offset_ret =
					_hpack_decode_string(data + offset, data_len - offset, buffer_name, buffer_left_len - 1, &str_len);
				if (offset_ret < 0) {
					return offset_ret;
				}
				offset += offset_ret;

				if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
					return -3;
				}
				name = buffer_name;
			} else {
				/* Indexed name */
				header = hpack_get_static_header_field(index);
				if (header == NULL) {
					return -2;
				}
				name = header->name;
			}

			/* Value string */
			buffer_value = (char *)_http_head_buffer_get_end(http_head);
			buffer_left_len = _http_head_buffer_left_len(http_head);

			offset_ret =
				_hpack_decode_string(data + offset, data_len - offset, buffer_value, buffer_left_len - 1, &str_len);
			if (offset_ret < 0) {
				return offset_ret;
			}
			offset += offset_ret;

			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -3;
			}
			value = buffer_value;

		} else if ((b & 0xF0) == 0x00) {
			/* Literal Header Field without Indexing */
			uint32_t index = 0;
			offset_ret = _hpack_decode_integer(data + offset, data_len - offset, 4, &index);
			if (offset_ret < 0) {
				return -1;
			}
			offset += offset_ret;

			if (index == 0) {
				/* New name */
				buffer_name = (char *)_http_head_buffer_get_end(http_head);
				buffer_left_len = _http_head_buffer_left_len(http_head);

				offset_ret =
					_hpack_decode_string(data + offset, data_len - offset, buffer_name, buffer_left_len - 1, &str_len);
				if (offset_ret < 0) {
					return offset_ret;
				}
				offset += offset_ret;

				if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
					return -3;
				}
				name = buffer_name;
			} else {
				/* Indexed name */
				header = hpack_get_static_header_field(index);
				if (header == NULL) {
					return -2;
				}
				name = header->name;
			}

			/* Value string */
			buffer_value = (char *)_http_head_buffer_get_end(http_head);
			buffer_left_len = _http_head_buffer_left_len(http_head);

			offset_ret =
				_hpack_decode_string(data + offset, data_len - offset, buffer_value, buffer_left_len - 1, &str_len);
			if (offset_ret < 0) {
				return offset_ret;
			}
			offset += offset_ret;

			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -3;
			}
			value = buffer_value;

		} else {
			/* Other types not supported */
			return -2;
		}

		if (http_head_add_fields(http_head, name, value) != 0) {
			return -2;
		}
	}

	return 0;
}

/* Setup HTTP code and method from pseudo-headers */
static int _http_head_setup_http2_0(struct http_head *http_head)
{
	const char *status = NULL;
	const char *method = NULL;
	const char *path = NULL;

	method = http_head_get_fields_value(http_head, ":method");
	if (method) {
		http_head->head_type = HTTP_HEAD_REQUEST;
		if (strcmp(method, "GET") == 0) {
			http_head->method = HTTP_METHOD_GET;
		} else if (strcmp(method, "POST") == 0) {
			http_head->method = HTTP_METHOD_POST;
		} else if (strcmp(method, "PUT") == 0) {
			http_head->method = HTTP_METHOD_PUT;
		} else if (strcmp(method, "DELETE") == 0) {
			http_head->method = HTTP_METHOD_DELETE;
		}

		path = http_head_get_fields_value(http_head, ":path");
		if (path) {
			char *path_copy = (char *)_http_head_buffer_get_end(http_head);
			int path_len = strlen(path);
			if (_http_head_buffer_left_len(http_head) < path_len + 1) {
				return -3;
			}
			memcpy(path_copy, path, path_len + 1);
			_http_head_buffer_append(http_head, NULL, path_len + 1);
			http_head->url = path_copy;

			/* Parse query parameters */
			_http_head_parse_params(http_head, path_copy, path_len);
		}
	}

	status = http_head_get_fields_value(http_head, ":status");
	if (status) {
		http_head->head_type = HTTP_HEAD_RESPONSE;
		http_head->code = atoi(status);
	}

	return 0;
}

int http_head_parse_http2_0(struct http_head *http_head, const uint8_t *data, int data_len)
{
	int offset = 0;
	const uint8_t *frame_data = NULL;
	int frame_data_len = 0;
	int headers_complete = 0;
	int data_complete = 0;
	const uint8_t *body_data = NULL;
	int body_data_len = 0;

	/* Parse HTTP/2 frames */
	while (offset < data_len && (!headers_complete || !data_complete)) {
		if (data_len - offset < HTTP2_FRAME_HEADER_SIZE) {
			return -1; /* Incomplete frame header */
		}

		/* Parse frame header (9 bytes) */
		uint32_t frame_length = ((uint32_t)data[offset] << 16) | ((uint32_t)data[offset + 1] << 8) | data[offset + 2];
		uint8_t frame_type = data[offset + 3];
		uint8_t frame_flags = data[offset + 4];
		uint32_t stream_id = ((uint32_t)data[offset + 5] << 24) | ((uint32_t)data[offset + 6] << 16) |
							 ((uint32_t)data[offset + 7] << 8) | data[offset + 8];
		stream_id &= 0x7FFFFFFF; /* Clear reserved bit */

		offset += HTTP2_FRAME_HEADER_SIZE;

		if (data_len - offset < (int)frame_length) {
			return -1; /* Incomplete frame payload */
		}

		frame_data = data + offset;
		frame_data_len = frame_length;
		offset += frame_length;

		/* Process frame based on type */
		if (frame_type == HTTP2_FRAME_HEADERS) {
			int header_offset = 0;

			/* Skip padding if present */
			if (frame_flags & HTTP2_FLAG_PADDED) {
				if (frame_data_len < 1) {
					return -1;
				}
				uint8_t pad_length = frame_data[0];
				header_offset = 1;
				frame_data_len -= (1 + pad_length);
				if (frame_data_len < 0) {
					return -1;
				}
			}

			/* Skip priority if present */
			if (frame_flags & HTTP2_FLAG_PRIORITY) {
				if (frame_data_len < 5) {
					return -1;
				}
				header_offset += 5;
				frame_data_len -= 5;
			}

			/* Parse header block */
			if (_http2_parse_header_block(http_head, frame_data + header_offset, frame_data_len) < 0) {
				return -2;
			}

			if (frame_flags & HTTP2_FLAG_END_HEADERS) {
				headers_complete = 1;
			}

			if (frame_flags & HTTP2_FLAG_END_STREAM) {
				data_complete = 1;
			}

		} else if (frame_type == HTTP2_FRAME_DATA) {
			int data_offset = 0;

			/* Skip padding if present */
			if (frame_flags & HTTP2_FLAG_PADDED) {
				if (frame_data_len < 1) {
					return -1;
				}
				uint8_t pad_length = frame_data[0];
				data_offset = 1;
				frame_data_len -= (1 + pad_length);
				if (frame_data_len < 0) {
					return -1;
				}
			}

			/* Store data */
			body_data = frame_data + data_offset;
			body_data_len = frame_data_len;

			if (frame_flags & HTTP2_FLAG_END_STREAM) {
				data_complete = 1;
			}

		} else if (frame_type == HTTP2_FRAME_CONTINUATION) {
			/* Continue parsing header block */
			if (_http2_parse_header_block(http_head, frame_data, frame_data_len) < 0) {
				return -2;
			}

			if (frame_flags & HTTP2_FLAG_END_HEADERS) {
				headers_complete = 1;
			}
		}
		/* Ignore other frame types */
	}

	if (!headers_complete) {
		return -1;
	}

	/* Setup HTTP code and method from pseudo-headers */
	if (_http_head_setup_http2_0(http_head) != 0) {
		return -2;
	}

	/* Set body data if present */
	if (body_data && body_data_len > 0) {
		http_head->data = body_data;
		http_head->data_len = body_data_len;
	}

	http_head->head_ok = 1;

	return offset;
}

int http_head_serialize_http2_0(struct http_head *http_head, uint8_t *buffer, int buffer_len)
{
	int offset = 0;
	int header_block_len = 0;
	uint8_t header_block[4096];

	/* Build HPACK header block */
	header_block_len = _http2_build_header_block(http_head, header_block, sizeof(header_block));
	if (header_block_len < 0) {
		return -1;
	}

	/* Write HEADERS frame */
	uint32_t frame_length = header_block_len;
	uint8_t frame_flags = HTTP2_FLAG_END_HEADERS;
	uint32_t stream_id = 1; /* Use stream ID 1 for DoH requests */

	if (http_head->data_len == 0 || http_head->data == NULL) {
		frame_flags |= HTTP2_FLAG_END_STREAM;
	}

	if (buffer_len - offset < HTTP2_FRAME_HEADER_SIZE + (int)frame_length) {
		return -1;
	}

	/* Frame header */
	buffer[offset++] = (frame_length >> 16) & 0xFF;
	buffer[offset++] = (frame_length >> 8) & 0xFF;
	buffer[offset++] = frame_length & 0xFF;
	buffer[offset++] = HTTP2_FRAME_HEADERS;
	buffer[offset++] = frame_flags;
	buffer[offset++] = (stream_id >> 24) & 0xFF;
	buffer[offset++] = (stream_id >> 16) & 0xFF;
	buffer[offset++] = (stream_id >> 8) & 0xFF;
	buffer[offset++] = stream_id & 0xFF;

	/* Frame payload */
	memcpy(buffer + offset, header_block, header_block_len);
	offset += header_block_len;

	/* Write DATA frame if present */
	if (http_head->data_len > 0 && http_head->data) {
		frame_length = http_head->data_len;
		frame_flags = HTTP2_FLAG_END_STREAM;

		if (buffer_len - offset < HTTP2_FRAME_HEADER_SIZE + (int)frame_length) {
			return -1;
		}

		/* Frame header */
		buffer[offset++] = (frame_length >> 16) & 0xFF;
		buffer[offset++] = (frame_length >> 8) & 0xFF;
		buffer[offset++] = frame_length & 0xFF;
		buffer[offset++] = HTTP2_FRAME_DATA;
		buffer[offset++] = frame_flags;
		buffer[offset++] = (stream_id >> 24) & 0xFF;
		buffer[offset++] = (stream_id >> 16) & 0xFF;
		buffer[offset++] = (stream_id >> 8) & 0xFF;
		buffer[offset++] = stream_id & 0xFF;

		/* Frame payload */
		memcpy(buffer + offset, http_head->data, http_head->data_len);
		offset += http_head->data_len;
	}

	return offset;
}