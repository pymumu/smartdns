/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "http_parse.h"
#include "hash.h"
#include "hashtable.h"
#include "jhash.h"
#include "list.h"
#include "qpack.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HTTP3_HEADER_FRAME 1
#define HTTP3_DATA_FRAME 0

struct http_head_fields {
	struct hlist_node node;
	struct list_head list;

	const char *name;
	const char *value;
};

struct http_params {
	struct hlist_node node;
	struct list_head list;

	const char *name;
	const char *value;
};

struct http_head {
	HTTP_VERSION http_version;
	HTTP_HEAD_TYPE head_type;
	HTTP_METHOD method;
	const char *url;
	const char *version;
	int code;
	const char *code_msg;
	int buff_size;
	int buff_len;
	uint8_t *buff;
	int head_ok;
	int head_len;
	const uint8_t *data;
	int data_len;
	int expect_data_len;
	struct http_head_fields field_head;
	struct http_params params;
	DECLARE_HASHTABLE(field_map, 4);
	DECLARE_HASHTABLE(params_map, 4);
};

/*
 * Returns:
 *  >=0  - success http data len
 *  -1   - Incomplete request
 *  -2   - parse failed
 */
struct http_head *http_head_init(int buffsize, HTTP_VERSION version)
{
	struct http_head *http_head = NULL;
	unsigned char *buffer = NULL;

	http_head = malloc(sizeof(*http_head));
	if (http_head == NULL) {
		goto errout;
	}
	memset(http_head, 0, sizeof(*http_head));
	INIT_LIST_HEAD(&http_head->field_head.list);
	hash_init(http_head->field_map);
	INIT_LIST_HEAD(&http_head->params.list);
	hash_init(http_head->params_map);

	buffer = malloc(buffsize);
	if (buffer == NULL) {
		goto errout;
	}

	http_head->buff = buffer;
	http_head->buff_size = buffsize;
	http_head->http_version = version;

	return http_head;

errout:
	if (buffer) {
		free(buffer);
	}

	if (http_head) {
		free(http_head);
	}

	return NULL;
}

struct http_head_fields *http_head_first_fields(struct http_head *http_head)
{
	struct http_head_fields *first = NULL;
	first = list_first_entry(&http_head->field_head.list, struct http_head_fields, list);

	if (first->name == NULL && first->value == NULL) {
		return NULL;
	}

	return first;
}

const char *http_head_get_fields_value(struct http_head *http_head, const char *name)
{
	uint32_t key;
	struct http_head_fields *filed;

	key = hash_string_case(name);
	hash_for_each_possible(http_head->field_map, filed, node, key)
	{
		if (strncasecmp(filed->name, name, 128) == 0) {
			return filed->value;
		}
	}

	return NULL;
}

struct http_head_fields *http_head_next_fields(struct http_head_fields *fields)
{
	struct http_head_fields *next = NULL;
	next = list_next_entry(fields, list);

	if (next->name == NULL && next->value == NULL) {
		return NULL;
	}

	return next;
}

const char *http_head_fields_get_name(struct http_head_fields *fields)
{
	if (fields == NULL) {
		return NULL;
	}

	return fields->name;
}

const char *http_head_fields_get_value(struct http_head_fields *fields)
{
	if (fields == NULL) {
		return NULL;
	}

	return fields->value;
}

int http_head_lookup_fields(struct http_head_fields *fields, const char **name, const char **value)
{
	if (fields == NULL) {
		return -1;
	}

	if (name) {
		*name = fields->name;
	}

	if (value) {
		*value = fields->value;
	}

	return 0;
}

const char *http_head_get_params_value(struct http_head *http_head, const char *name)
{
	uint32_t key;
	struct http_params *params;

	key = hash_string_case(name);
	hash_for_each_possible(http_head->params_map, params, node, key)
	{
		if (strncasecmp(params->name, name, 128) == 0) {
			return params->value;
		}
	}

	return NULL;
}

HTTP_METHOD http_head_get_method(struct http_head *http_head)
{
	return http_head->method;
}

const char *http_head_get_url(struct http_head *http_head)
{
	return http_head->url;
}

const char *http_head_get_httpversion(struct http_head *http_head)
{
	return http_head->version;
}

int http_head_get_httpcode(struct http_head *http_head)
{
	return http_head->code;
}

const char *http_head_get_httpcode_msg(struct http_head *http_head)
{
	return http_head->code_msg;
}

HTTP_HEAD_TYPE http_head_get_head_type(struct http_head *http_head)
{
	return http_head->head_type;
}

const unsigned char *http_head_get_data(struct http_head *http_head)
{
	return http_head->data;
}

int http_head_get_data_len(struct http_head *http_head)
{
	return http_head->data_len;
}

static int _http_head_buffer_left_len(struct http_head *http_head)
{
	return http_head->buff_size - http_head->buff_len;
}

static uint8_t *_http_head_buffer_get_end(struct http_head *http_head)
{
	return http_head->buff + http_head->buff_len;
}

static uint8_t *_http_head_buffer_append(struct http_head *http_head, const uint8_t *data, int data_len)
{
	if (http_head == NULL || data_len < 0) {
		return NULL;
	}

	if (http_head->buff_len + data_len > http_head->buff_size) {
		return NULL;
	}

	if (data != NULL) {
		memcpy(http_head->buff + http_head->buff_len, data, data_len);
	}
	http_head->buff_len += data_len;

	return (http_head->buff + http_head->buff_len);
}

static int _http_head_add_param(struct http_head *http_head, const char *name, const char *value)
{
	uint32_t key = 0;
	struct http_params *params = NULL;
	params = malloc(sizeof(*params));
	if (params == NULL) {
		return -1;
	}
	memset(params, 0, sizeof(*params));

	params->name = name;
	params->value = value;

	list_add_tail(&params->list, &http_head->params.list);
	key = hash_string_case(name);
	hash_add(http_head->params_map, &params->node, key);

	return 0;
}

int http_head_add_param(struct http_head *http_head, const char *name, const char *value)
{
	if (http_head == NULL || name == NULL || value == NULL) {
		return -1;
	}

	return _http_head_add_param(http_head, name, value);
}

int http_head_set_url(struct http_head *http_head, const char *url)
{
	if (http_head == NULL || url == NULL) {
		return -1;
	}

	http_head->url = url;

	return 0;
}

int http_head_set_httpversion(struct http_head *http_head, const char *version)
{
	if (http_head == NULL || version == NULL) {
		return -1;
	}

	http_head->version = version;

	return 0;
}

int http_head_set_httpcode(struct http_head *http_head, int code, const char *msg)
{
	if (http_head == NULL || code < 0 || msg == NULL) {
		return -1;
	}

	http_head->code = code;
	http_head->code_msg = msg;

	return 0;
}

int http_head_set_head_type(struct http_head *http_head, HTTP_HEAD_TYPE head_type)
{
	if (http_head == NULL || head_type == HTTP_HEAD_INVALID) {
		return -1;
	}

	http_head->head_type = head_type;

	return 0;
}

int http_head_set_method(struct http_head *http_head, HTTP_METHOD method)
{
	if (http_head == NULL || method == HTTP_METHOD_INVALID) {
		return -1;
	}

	http_head->method = method;

	return 0;
}

int http_head_set_data(struct http_head *http_head, const void *data, int len)
{
	if (http_head == NULL || data == NULL || len < 0) {
		return -1;
	}

	http_head->data = (unsigned char *)data;
	http_head->data_len = len;

	return 0;
}

static int _http_head_add_fields(struct http_head *http_head, const char *name, const char *value)
{
	uint32_t key = 0;
	struct http_head_fields *fields = NULL;
	fields = malloc(sizeof(*fields));
	if (fields == NULL) {
		return -1;
	}
	memset(fields, 0, sizeof(*fields));

	fields->name = name;
	fields->value = value;

	list_add_tail(&fields->list, &http_head->field_head.list);
	key = hash_string_case(name);
	hash_add(http_head->field_map, &fields->node, key);

	return 0;
}

int http_head_add_fields(struct http_head *http_head, const char *name, const char *value)
{
	if (http_head == NULL || name == NULL || value == NULL) {
		return -1;
	}

	return _http_head_add_fields(http_head, name, value);
}

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

static int _http_head_parse_params(struct http_head *http_head, char *url, int url_len)
{
	char *tmp_ptr = NULL;
	char *field_start = NULL;
	char *param_start = NULL;
	char *field = NULL;
	char *value = NULL;

	if (url == NULL) {
		return -1;
	}

	param_start = strstr(url, "?");
	if (param_start == NULL) {
		return 0;
	}

	*param_start = '\0';
	param_start++;

	for (tmp_ptr = param_start; tmp_ptr < url + url_len; tmp_ptr++) {
		if (field_start == NULL) {
			field_start = tmp_ptr;
		}

		if (field == NULL) {
			if (*tmp_ptr == '=') {
				*tmp_ptr = '\0';
				field = field_start;
				field_start = NULL;
			}
			continue;
		}

		if (value == NULL) {
			if (*tmp_ptr == '&' || tmp_ptr == url + url_len - 1) {
				*tmp_ptr = '\0';
				value = field_start;
				field_start = NULL;

				if (_http_head_add_param(http_head, field, value) != 0) {
					return -2;
				}
				field = NULL;
				value = NULL;
			}
			continue;
		}
	}
	return 0;
}

const char *http_method_str(HTTP_METHOD method)
{
	switch (method) {
	case HTTP_METHOD_GET:
		return "GET";
	case HTTP_METHOD_POST:
		return "POST";
	case HTTP_METHOD_PUT:
		return "PUT";
	case HTTP_METHOD_DELETE:
		return "DELETE";
	case HTTP_METHOD_TRACE:
		return "TRACE";
	case HTTP_METHOD_CONNECT:
		return "CONNECT";
	default:
		return "INVALID";
	}
}

static HTTP_METHOD _http_method_parse(const char *method)
{
	if (method == NULL) {
		return HTTP_METHOD_INVALID;
	}

	if (strncmp(method, "GET", sizeof("GET")) == 0) {
		return HTTP_METHOD_GET;
	} else if (strncmp(method, "POST", sizeof("POST")) == 0) {
		return HTTP_METHOD_POST;
	} else if (strncmp(method, "PUT", sizeof("PUT")) == 0) {
		return HTTP_METHOD_PUT;
	} else if (strncmp(method, "DELETE", sizeof("DELETE")) == 0) {
		return HTTP_METHOD_DELETE;
	} else if (strncmp(method, "TRACE", sizeof("TRACE")) == 0) {
		return HTTP_METHOD_TRACE;
	} else if (strncmp(method, "CONNECT", sizeof("CONNECT")) == 0) {
		return HTTP_METHOD_CONNECT;
	}

	return HTTP_METHOD_INVALID;
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
				if (_http_head_add_fields(http_head, key, value) != 0) {
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

static int _http_head_parse_http1_1(struct http_head *http_head, const uint8_t *data, int data_len)
{
	int i = 0;
	uint8_t *buff_end = NULL;
	int left_size = 0;
	int process_data_len = 0;
	int is_chunked = 0;

	left_size = http_head->buff_size - http_head->buff_len;

	if (left_size < data_len) {
		return -3;
	}

	buff_end = http_head->buff + http_head->buff_len;
	if (http_head->head_ok == 0) {
		for (i = 0; i < data_len; i++, data++) {
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

	http_head->buff_len += process_data_len;
	if (http_head->data_len < http_head->expect_data_len) {
		return -1;
	}

	return process_data_len;
}

static int _http_head_serialize_http1_1(struct http_head *http_head, char *buffer, int buffer_len)
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

static int _http_head_parse_http2_0(struct http_head *http_head, const uint8_t *data, int data_len)
{
	return -2;
}

static int _http_head_serialize_http2_0(struct http_head *http_head, uint8_t *buffer, int buffer_len)
{
	return -2;
}

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
		return -1;
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
				return -1;
			}
			offset += offset_ret;
			buffer_value[str_len] = '\0';
			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -1;
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
				return -1;
			}
			offset += offset_ret;
			buffer_name[str_len] = '\0';
			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -1;
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
				return -1;
			}
			offset += offset_ret;
			buffer_value[str_len] = '\0';
			if (_http_head_buffer_append(http_head, NULL, str_len + 1) == NULL) {
				return -1;
			}
			value = buffer_value;
		} else {
			return -2;
		}

		if (_http_head_add_fields(http_head, name, value) != 0) {
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

static int _http_head_parse_http3_0(struct http_head *http_head, const uint8_t *data, int data_len)
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

		if ((uint64_t)(data_len - offset) < frame_len) {
			return -1;
		}

		if (frame_type == HTTP3_HEADER_FRAME) {
			int header_len = 0;
			header_len = _http3_parse_headers_payload(http_head, data + offset, frame_len);
			if (header_len < 0) {
				return -1;
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
					return -2;
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

	http_head->version = "HTTP/3.0";

	return offset;
}

static int _http_head_serialize_http3_0(struct http_head *http_head, uint8_t *buffer, int buffer_len)
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

int http_head_parse(struct http_head *http_head, const unsigned char *data, int data_len)
{
	if (http_head->http_version == HTTP_VERSION_1_1) {
		return _http_head_parse_http1_1(http_head, data, data_len);
	} else if (http_head->http_version == HTTP_VERSION_2_0) {
		return _http_head_parse_http2_0(http_head, data, data_len);
	} else if (http_head->http_version == HTTP_VERSION_3_0) {
		return _http_head_parse_http3_0(http_head, data, data_len);
	}

	return -2;
}

int http_head_serialize(struct http_head *http_head, void *buffer, int buffer_len)
{
	if (http_head == NULL || buffer == NULL || buffer_len <= 0) {
		return -1;
	}

	if (http_head->http_version == HTTP_VERSION_1_1) {
		return _http_head_serialize_http1_1(http_head, buffer, buffer_len);
	} else if (http_head->http_version == HTTP_VERSION_2_0) {
		return _http_head_serialize_http2_0(http_head, buffer, buffer_len);
	} else if (http_head->http_version == HTTP_VERSION_3_0) {
		return _http_head_serialize_http3_0(http_head, buffer, buffer_len);
	}

	return -2;
}

void http_head_destroy(struct http_head *http_head)
{
	struct http_head_fields *fields, *tmp;
	struct http_params *params, *tmp_params;

	list_for_each_entry_safe(fields, tmp, &http_head->field_head.list, list)
	{
		list_del(&fields->list);
		free(fields);
	}

	list_for_each_entry_safe(params, tmp_params, &http_head->params.list, list)
	{
		list_del(&params->list);
		free(params);
	}

	if (http_head->buff) {
		free(http_head->buff);
	}

	free(http_head);
}
