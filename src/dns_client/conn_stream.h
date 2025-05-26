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

#ifndef _DNS_CLIENT_CONN_STREAM_
#define _DNS_CLIENT_CONN_STREAM_

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _dns_client_conn_stream_put(struct dns_conn_stream *stream);

void _dns_client_conn_stream_get(struct dns_conn_stream *stream);

struct dns_conn_stream *_dns_client_conn_stream_new(void);

void _dns_client_conn_server_streams_free(struct dns_server_info *server_info, struct dns_query_struct *query);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
