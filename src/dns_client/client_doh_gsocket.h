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

#ifndef _DNS_CLIENT_DOH_GSOCKET_H_
#define _DNS_CLIENT_DOH_GSOCKET_H_

#include "dns_client.h"

int dns_client_doh_send_query(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
							  int packet_data_len, dns_server_type_t type);

int dns_client_doh_send_http1(struct dns_server_info *server_info, void *packet, int packet_data_len);

int dns_client_doh_process_stream(struct dns_server_info *server_info, struct gsocket *stream_gs,
								  struct dns_conn_stream *conn_stream);

#endif
