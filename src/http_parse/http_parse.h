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

#ifndef _HTTP_PARSE_HTTP_H_
#define _HTTP_PARSE_HTTP_H_

#include "smartdns/lib/hash.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/jhash.h"
#include "smartdns/lib/list.h"

#include "smartdns/http_parse.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

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

int _http_head_buffer_left_len(struct http_head *http_head);
uint8_t *_http_head_buffer_get_end(struct http_head *http_head);
uint8_t *_http_head_buffer_append(struct http_head *http_head, const uint8_t *data, int data_len);

int _http_head_add_param(struct http_head *http_head, const char *name, const char *value);
int _http_head_parse_params(struct http_head *http_head, char *url, int url_len);

HTTP_METHOD _http_method_parse(const char *method);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
