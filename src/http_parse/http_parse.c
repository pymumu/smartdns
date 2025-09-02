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

#include "smartdns/http_parse.h"
#include "http1_parse.h"
#include "http2_parse.h"
#include "http3_parse.h"
#include "http_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	struct http_head_fields *filed = NULL;

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
	struct http_params *params = NULL;

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

int _http_head_buffer_left_len(struct http_head *http_head)
{
	return http_head->buff_size - http_head->buff_len;
}

uint8_t *_http_head_buffer_get_end(struct http_head *http_head)
{
	return http_head->buff + http_head->buff_len;
}

uint8_t *_http_head_buffer_append(struct http_head *http_head, const uint8_t *data, int data_len)
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

int _http_head_add_param(struct http_head *http_head, const char *name, const char *value)
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

int _http_head_parse_params(struct http_head *http_head, char *url, int url_len)
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

HTTP_METHOD _http_method_parse(const char *method)
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

int http_head_parse(struct http_head *http_head, const unsigned char *data, int data_len)
{
	if (http_head->http_version == HTTP_VERSION_1_1) {
		return http_head_parse_http1_1(http_head, data, data_len);
	} else if (http_head->http_version == HTTP_VERSION_2_0) {
		return http_head_parse_http2_0(http_head, data, data_len);
	} else if (http_head->http_version == HTTP_VERSION_3_0) {
		return http_head_parse_http3_0(http_head, data, data_len);
	}

	return -2;
}

int http_head_serialize(struct http_head *http_head, void *buffer, int buffer_len)
{
	if (http_head == NULL || buffer == NULL || buffer_len <= 0) {
		return -1;
	}

	if (http_head->http_version == HTTP_VERSION_1_1) {
		return http_head_serialize_http1_1(http_head, buffer, buffer_len);
	} else if (http_head->http_version == HTTP_VERSION_2_0) {
		return http_head_serialize_http2_0(http_head, buffer, buffer_len);
	} else if (http_head->http_version == HTTP_VERSION_3_0) {
		return http_head_serialize_http3_0(http_head, buffer, buffer_len);
	}

	return -2;
}

void http_head_destroy(struct http_head *http_head)
{
	struct http_head_fields *fields = NULL, *tmp;
	struct http_params *params = NULL, *tmp_params;

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
