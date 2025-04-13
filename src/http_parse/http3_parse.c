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

#include "http3_parse.h"
#include "http_parse.h"
#include "qpack.h"

#include <stdio.h>

#define HTTP3_HEADER_FRAME 1
#define HTTP3_DATA_FRAME 0

static int _quicvarint_encode(uint64_t value, uint8_t *buffer, int buffer_size)
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

	offset_ret = _quicvarint_encode(value_len, buffer + offset, buffer_size - offset);
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

static int _http3_build_headers_payload(struct http_head *http_head, uint8_t *buffer, int buffer_len)
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
		sprintf(status_str, "%d", http_head->code);
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
		sprintf(len_str, "%d", http_head->data_len);
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

	offset_ret = _quicvarint_encode(body_len, buffer + offset, buffer_len - offset);
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

static int _quicvarint_decode(const uint8_t *buffer, int buffer_len, uint64_t *value)
{
	if ((buffer[0] & 0xC0) == 0x00) {
		if (buffer_len < 1) {
			return -1;
		}

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

static int _http3_parse_headers_payload(struct http_head *http_head, const uint8_t *data, int data_len)
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
			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
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
			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
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
			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
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

	http_head->data_len = 0;
	while (offset < data_len) {
		offset_ret = _quicvarint_decode((uint8_t *)data + offset, data_len - offset, &frame_type);
		if (offset_ret < 0) {
			return offset_ret;
		}
		offset += offset_ret;

		offset_ret = _quicvarint_decode((uint8_t *)data + offset, data_len - offset, &frame_len);
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
			header_len = _http3_parse_headers_payload(http_head, data + offset, frame_len);
			if (header_len < 0) {
				return header_len;
			}

			if (_http_head_setup_http3_0_httpcode(http_head) != 0) {
				return -1;
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

				if (_http_head_buffer_append(http_head, data + offset, frame_len) == NULL) {
					http_head->code_msg = "Receive Buffer Insufficient";
					http_head->code = 500;
					http_head->data_len = 0;
					http_head->buff_len = 0;
					return -3;
				}
				memcpy(http_head->buff + http_head->buff_len, data + offset, frame_len);
				http_head->data_len += frame_len;
			}
		} else {
			/* skip unknown frame. e.g. GREASE  */
			offset += frame_len;
			continue;
		}
		offset += frame_len;
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
	uint8_t header_data[1024];
	int header_data_len = 0;

	/* serialize header frame. */
	header_data_len = _http3_build_headers_payload(http_head, header_data, sizeof(header_data));
	if (header_data_len < 0) {
		return -1;
	}

	/* Frame Type: Header*/
	offset_ret = _quicvarint_encode(HTTP3_HEADER_FRAME, buffer + offset, buffer_len - offset);
	if (offset_ret < 0) {
		return -1;
	}
	offset += offset_ret;

	/* Header Frmae Length */
	offset_ret = _quicvarint_encode(header_data_len, buffer + offset, buffer_len - offset);
	if (offset_ret < 0) {
		return -1;
	}
	offset += offset_ret;

	if (buffer_len - offset < header_data_len) {
		return -1;
	}
	memcpy(buffer + offset, header_data, header_data_len);
	offset += header_data_len;

	/* Frame Type: Data */
	if (http_head->data_len > 0 && http_head->data) {
		/* Data Frame Length */
		offset_ret = _quicvarint_encode(HTTP3_DATA_FRAME, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;

		offset_ret =
			http3_build_body_payload(http_head->data, http_head->data_len, buffer + offset, buffer_len - offset);
		if (offset_ret < 0) {
			return -1;
		}
		offset += offset_ret;
	}

	return offset;
}