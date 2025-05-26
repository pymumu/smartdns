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

#include "http1_parse.h"
#include "http_parse.h"
#include "smartdns/util.h"

#include <stdio.h>
#include <unistd.h>

static int _http_head_parse_response(struct http_head *http_head, char *key, char *value)
{
	char *field_start = NULL;
	char *tmp_ptr = NULL;
	char *ret_msg = NULL;
	char *ret_code = NULL;

	if (strstr(key, "HTTP/") == NULL) {
		return -1;
	}

	for (tmp_ptr = value; *tmp_ptr != 0; tmp_ptr++) {
		if (field_start == NULL) {
			field_start = tmp_ptr;
		}

		if (*tmp_ptr != ' ') {
			continue;
		}

		*tmp_ptr = '\0';
		ret_code = field_start;
		ret_msg = tmp_ptr + 1;
		field_start = NULL;
		break;
	}

	if (ret_code == NULL || ret_msg == NULL) {
		return -1;
	}

	if (is_numeric(ret_code) != 0) {
		return -1;
	}

	http_head->code = atol(ret_code);
	http_head->code_msg = ret_msg;
	http_head->version = key;
	http_head->head_type = HTTP_HEAD_RESPONSE;

	return 0;
}

static int _http_head_parse_request(struct http_head *http_head, char *key, char *value)
{
	int method = HTTP_METHOD_INVALID;
	char *url = NULL;
	char *version = NULL;
	char *tmp_ptr = value;
	char *field_start = NULL;

	method = _http_method_parse(key);
	if (method == HTTP_METHOD_INVALID) {
		return _http_head_parse_response(http_head, key, value);
	}

	for (tmp_ptr = value; *tmp_ptr != 0; tmp_ptr++) {
		if (field_start == NULL) {
			field_start = tmp_ptr;
		}
		if (*tmp_ptr == ' ') {
			*tmp_ptr = '\0';
			if (url == NULL) {
				url = field_start;
			}

			field_start = NULL;
		}
	}

	if (field_start && version == NULL) {
		version = field_start;
		tmp_ptr = field_start;
	}

	if (_http_head_parse_params(http_head, url, tmp_ptr - url) != 0) {
		return -2;
	}

	http_head->method = method;
	http_head->url = url;
	http_head->version = version;
	http_head->head_type = HTTP_HEAD_REQUEST;

	return 0;
}

static int _http_head_parse(struct http_head *http_head)
{
	int i = 0;
	char *key = NULL;
	char *value = NULL;
	char *data;
	int has_first_line = 0;

	int inkey = 1;
	int invalue = 0;

	data = (char *)http_head->buff;
	for (i = 0; i < http_head->head_len; i++, data++) {
		if (inkey) {
			if (key == NULL && *data != ' ' && *data != '\r' && *data != '\n') {
				key = data;
				continue;
			}

			if (*data == ':' || *data == ' ') {
				*data = '\0';
				inkey = 0;
				invalue = 1;
				continue;
			}
		}

		if (invalue) {
			if (value == NULL && *data != ' ') {
				value = data;
				continue;
			}

			if (*data == '\r' || *data == '\n') {
				*data = '\0';
				inkey = 1;
				invalue = 0;
			}
		}

		if (key && value && invalue == 0) {
			if (has_first_line == 0) {
				if (_http_head_parse_request(http_head, key, value) != 0) {
					return -2;
				}

				has_first_line = 1;
			} else {
				if (http_head_add_fields(http_head, key, value) != 0) {
					return -2;
				}
			}

			key = NULL;
			value = NULL;
			inkey = 1;
			invalue = 0;
		}
	}

	return 0;
}

static int _http1_get_chunk_len(const uint8_t *data, int data_len, int32_t *chunk_len)
{
	int offset = 0;
	int32_t chunk_value = 0;
	int is_num_start = 0;

	for (offset = 0; offset < data_len; offset++) {
		if (data[offset] == ' ') {
			continue;
		}

		if (data[offset] == '\r') {
			if (offset + 1 < data_len && data[offset + 1] == '\n') {
				offset += 2;
				break;
			}
			if (is_num_start == 0) {
				return -2;
			}

			return -2;
		}
		int value = decode_hex(data[offset]);
		if (value < 0) {
			return -2;
		}

		if (is_num_start == 0) {
			is_num_start = 1;
		}

		chunk_value = (chunk_value << 4) + value;
	}

	if (offset >= data_len) {
		return -1;
	}

	*chunk_len = chunk_value;
	return offset;
}

int http_head_parse_http1_1(struct http_head *http_head, const uint8_t *data, int in_data_len)
{
	int i = 0;
	uint8_t *buff_end = NULL;
	int left_size = 0;
	int process_data_len = 0;
	int data_len = in_data_len;
	int is_chunked = 0;

	left_size = http_head->buff_size - http_head->buff_len;

	if (left_size < data_len) {
		return -3;
	}

	buff_end = http_head->buff + http_head->buff_len;
	if (http_head->head_ok == 0) {
		for (i = 0; i < in_data_len; i++, data++) {
			*(buff_end + i) = *data;
			if (isprint(*data) == 0 && isspace(*data) == 0) {
				return -2;
			}

			if (*data == '\n') {
				if (http_head->buff_len + i < 2) {
					continue;
				}

				if (*(buff_end + i - 2) == '\n') {
					http_head->head_ok = 1;
					http_head->head_len = http_head->buff_len + i - 2;
					i++;
					buff_end += i;
					data_len -= i;
					data++;
					if (_http_head_parse(http_head) != 0) {
						return -2;
					}

					const char *content_len = NULL;
					content_len = http_head_get_fields_value(http_head, "Content-Length");
					if (content_len) {
						http_head->expect_data_len = atol(content_len);
					} else {
						http_head->expect_data_len = 0;
					}

					if (http_head->expect_data_len < 0) {
						return -2;
					}

					break;
				}
			}
		}

		process_data_len += i;
		if (process_data_len >= http_head->buff_size) {
			return -3;
		}

		if (http_head->head_ok == 0) {
			// Read data again */
			http_head->buff_len += process_data_len;
			return -1;
		}
	}

	const char *transfer_encoding = http_head_get_fields_value(http_head, "Transfer-Encoding");
	if (transfer_encoding != NULL && strncasecmp(transfer_encoding, "chunked", sizeof("chunked")) == 0) {
		is_chunked = 1;
	}

	if (http_head->head_ok == 1) {
		if (is_chunked == 0) {
			int get_data_len = (http_head->expect_data_len > data_len) ? data_len : http_head->expect_data_len;
			if (get_data_len == 0 && data_len > 0) {
				get_data_len = data_len;
			}

			if (http_head->data == NULL) {
				http_head->data = buff_end;
			}

			memcpy(buff_end, data, get_data_len);
			process_data_len += get_data_len;
			http_head->data_len += get_data_len;
			buff_end += get_data_len;
		} else {
			const uint8_t *body_data = buff_end;
			uint32_t body_data_len = 0;

			while (true) {
				int32_t chunk_len = 0;
				int offset = 0;
				offset = _http1_get_chunk_len(data, data_len, &chunk_len);
				if (offset < 0) {
					return offset;
				}

				data += offset;
				data_len -= offset;
				process_data_len += offset;

				if (chunk_len == 0) {
					http_head->data = body_data;
					http_head->data_len = body_data_len;
					break;
				}

				if (data_len < chunk_len) {
					return -1;
				}

				if (data_len < chunk_len + 2) {
					return -1;
				}

				if (data[chunk_len] != '\r' || data[chunk_len + 1] != '\n') {
					return -2;
				}

				memcpy(buff_end, data, chunk_len);
				body_data_len += chunk_len;
				buff_end += chunk_len;
				data_len -= chunk_len;
				data += chunk_len + 2;
				data_len -= 2;
				process_data_len += chunk_len + 2;
			}
		}

		/* try append null byte */
		if (process_data_len < http_head->buff_size - 1) {
			buff_end[0] = '\0';
		}
	}

	if (process_data_len >= http_head->buff_size) {
		return -3;
	}

	http_head->buff_len += process_data_len;
	if (http_head->data_len < http_head->expect_data_len) {
		return -1;
	}

	return process_data_len;
}

int http_head_serialize_http1_1(struct http_head *http_head, char *buffer, int buffer_len)
{
	int len = 0;
	char *buff_start = buffer;
	struct http_head_fields *fields = NULL;
	struct http_params *params = NULL;

	if (http_head->head_type == HTTP_HEAD_INVALID) {
		return -1;
	}

	if (http_head->head_type == HTTP_HEAD_REQUEST) {
		if (http_head->method == HTTP_METHOD_INVALID || http_head->url == NULL || http_head->version == NULL) {
			return -1;
		}

		len = snprintf(buffer, buffer_len, "%s %s", http_method_str(http_head->method), http_head->url);
		if (len < 0) {
			return -2;
		}

		buffer += len;
		buffer_len -= len;

		if (buffer_len < 2) {
			return -3;
		}

		int count = 0;
		list_for_each_entry(params, &http_head->params.list, list)
		{
			if (count == 0) {
				len = snprintf(buffer, buffer_len, "?%s=%s", params->name, params->value);
			} else {
				len = snprintf(buffer, buffer_len, "&%s=%s", params->name, params->value);
			}

			count++;
			buffer += len;
			buffer_len -= len;

			if (buffer_len < 2) {
				return -3;
			}
		}

		if (buffer_len < 2) {
			return -3;
		}

		len = snprintf(buffer, buffer_len, " %s\r\n", http_head->version);
		if (len < 0) {
			return -2;
		}
		buffer += len;
		buffer_len -= len;
	}

	if (http_head->head_type == HTTP_HEAD_RESPONSE) {
		if (http_head->code < 0 || http_head->code_msg == NULL || http_head->version == NULL) {
			return -1;
		}

		len = snprintf(buffer, buffer_len, "%s %d %s\r\n", http_head->version, http_head->code, http_head->code_msg);
		if (len < 0) {
			return -2;
		}

		buffer += len;
		buffer_len -= len;
		if (buffer_len < 2) {
			return -3;
		}
	}

	list_for_each_entry(fields, &http_head->field_head.list, list)
	{
		len = snprintf(buffer, buffer_len, "%s: %s\r\n", fields->name, fields->value);
		if (len < 0) {
			return -2;
		}

		buffer += len;
		buffer_len -= len;
		if (buffer_len < 2) {
			return -3;
		}
	}

	if (buffer_len < 2) {
		return -3;
	}

	*(buffer) = '\r';
	*(buffer + 1) = '\n';
	buffer += 2;
	buffer_len -= 2;

	if (http_head->data_len > buffer_len) {
		return -3;
	}

	if (http_head->data && http_head->data_len > 0) {
		memcpy(buffer, http_head->data, http_head->data_len);
		buffer += http_head->data_len;
		buffer_len -= http_head->data_len;
	}

	return buffer - buff_start;
}
