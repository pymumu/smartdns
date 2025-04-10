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

#ifndef _HTTP_PARSE_HTTP2_H_
#define _HTTP_PARSE_HTTP2_H_

#include "http_parse.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int http_head_parse_http2_0(struct http_head *http_head, const uint8_t *data, int data_len);

int http_head_serialize_http2_0(struct http_head *http_head, uint8_t *buffer, int buffer_len);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
