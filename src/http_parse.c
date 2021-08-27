/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "util.h"
#include "jhash.h"
#include "list.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct http_head_fields {
	struct hlist_node node;
	struct list_head list;

	char *name;
	char *value;
};

struct http_head {
	HTTP_HEAD_TYPE head_type;
	HTTP_METHOD method;
	char *url;
	char *version;
	int code;
	char *code_msg;
	int buff_size;
	int buff_len;
	char *buff;
	int head_ok;
	int head_len;
	char *data;
	int data_len;
	int expect_data_len;
	struct http_head_fields field_head;
	DECLARE_HASHTABLE(field_map, 4);
};

/*
 * Returns:
 *  >=0  - success http data len
 *  -1   - Incomplete request
 *  -2   - parse failed
 */
struct http_head *http_head_init(int buffsize)
{
	struct http_head *http_head = NULL;
	char *buffer = NULL;

	http_head = malloc(sizeof(*http_head));
	if (http_head == NULL) {
		goto errout;
	}
	memset(http_head, 0, sizeof(*http_head));
	INIT_LIST_HEAD(&http_head->field_head.list);
	hash_init(http_head->field_map);

	buffer = malloc(buffsize);
	if (buffer == NULL) {
		goto errout;
	}

	http_head->buff = buffer;
	http_head->buff_size = buffsize;

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
	unsigned long key;
	struct http_head_fields *filed;

	key = hash_string(name);
	hash_for_each_possible(http_head->field_map, filed, node, key)
	{
		if (strncmp(filed->name, name, 128) == 0) {
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

char *http_head_get_httpcode_msg(struct http_head *http_head)
{
	return http_head->code_msg;
}

HTTP_HEAD_TYPE http_head_get_head_type(struct http_head *http_head)
{
	return http_head->head_type;
}

char *http_head_get_data(struct http_head *http_head)
{
	return http_head->data;
}

int http_head_get_data_len(struct http_head *http_head)
{
	return http_head->data_len;
}

static int _http_head_add_fields(struct http_head *http_head, char *name, char *value)
{
	unsigned long key = 0;
	struct http_head_fields *fields = NULL;
	fields = malloc(sizeof(*fields));
	if (fields == NULL) {
		return -1;
	}
	memset(fields, 0, sizeof(*fields));

	fields->name = name;
	fields->value = value;

	list_add_tail(&fields->list, &http_head->field_head.list);
	key = hash_string(name);
	hash_add(http_head->field_map, &fields->node, key);

	return 0;
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

static int _http_head_parse_request(struct http_head *http_head, char *key, char *value)
{
	int method = HTTP_METHOD_INVALID;
	char *url = NULL;
	char *version = NULL;
	char *tmp_ptr = value;
	char *field_start = NULL;

	if (strncmp(key, "GET", sizeof("GET")) == 0) {
		method = HTTP_METHOD_GET;
	} else if (strncmp(key, "POST", sizeof("POST")) == 0) {
		method = HTTP_METHOD_POST;
	} else if (strncmp(key, "PUT", sizeof("PUT")) == 0) {
		method = HTTP_METHOD_PUT;
	} else if (strncmp(key, "DELETE", sizeof("DELETE")) == 0) {
		method = HTTP_METHOD_DELETE;
	} else if (strncmp(key, "TRACE", sizeof("TRACE")) == 0) {
		method = HTTP_METHOD_TRACE;
	} else if (strncmp(key, "CONNECT", sizeof("CONNECT")) == 0) {
		method = HTTP_METHOD_CONNECT;
	} else {
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

	data = http_head->buff;
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

int http_head_parse(struct http_head *http_head, const char *data, int data_len)
{
	int i = 0;
	char *buff_end = NULL;
	int left_size = 0;
	int process_data_len = 0;

	left_size = http_head->buff_size - http_head->buff_len;

	if (left_size < data_len) {
		return -3;
	}

	buff_end = http_head->buff + http_head->buff_len;
	if (http_head->head_ok == 0) {
		for (i = 0; i < data_len; i++, data++) {
			*(buff_end + i) = *data;
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

	if (http_head->head_ok == 1) {
		int get_data_len = (http_head->expect_data_len > data_len) ? data_len : http_head->expect_data_len;
		if (http_head->data == NULL) {
			http_head->data = buff_end;
		}

		memcpy(buff_end, data, get_data_len);
		process_data_len += get_data_len;
		http_head->data_len += get_data_len;
	}

	http_head->buff_len += process_data_len;
	if (http_head->data_len < http_head->expect_data_len) {
		return -1;
	}

	return process_data_len;
}

void http_head_destroy(struct http_head *http_head)
{
	struct http_head_fields *fields, *tmp;

	list_for_each_entry_safe(fields, tmp, &http_head->field_head.list, list)
	{
		list_del(&fields->list);
		free(fields);
	}

	if (http_head->buff) {
		free(http_head->buff);
	}

	free(http_head);
}
