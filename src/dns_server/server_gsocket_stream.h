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

#ifndef _DNS_SERVER_GSOCKET_STREAM_H_
#define _DNS_SERVER_GSOCKET_STREAM_H_

#include "server_gsocket.h"

struct dns_server_conn_stream *dns_server_gstream_adopt(struct dns_server_conn_gsocket *parent,
														struct gsocket *stream_gs, DNS_CONN_TYPE stream_type);

int dns_server_gstream_dispatch_query(struct dns_server_conn_gsocket *parent, struct gsocket *stream_gs,
									  DNS_CONN_TYPE stream_type, unsigned char *packet, int packet_len);
int dns_server_gstream_process_client_events(struct dns_server_conn_gsocket *conn);

#endif
