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

#ifndef _DNS_CLIENT_GSOCKET_STREAM_H_
#define _DNS_CLIENT_GSOCKET_STREAM_H_

#include "dns_client.h"

typedef int (*dns_client_gstream_prepare_send_fn)(struct dns_server_info *server_info, struct gsocket *stream_gs,
												  void *user_data);

struct dns_conn_stream *dns_client_gstream_attach(struct dns_server_info *server_info, struct dns_query_struct *query,
												  struct gsocket *stream_gs, dns_server_type_t type);

void dns_client_gstream_detach(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream);
void dns_client_gstream_close(struct gsocket **stream_gs);
int dns_client_gstream_append_recv(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream,
								   const void *data, int len);
void dns_client_gstream_recv_response(struct dns_server_info *server_info, struct dns_query_struct *query,
									  unsigned char *packet, int packet_len);

int dns_client_gstream_pending_add(struct dns_server_info *server_info, struct dns_query_struct *query,
								   const void *packet, int packet_data_len);
void dns_client_gstream_pending_flush(struct dns_server_info *server_info);

int dns_client_gstream_send_query(struct dns_server_info *server_info, struct dns_query_struct *query,
								  dns_server_type_t type, const void *payload, int payload_len, int send_flags,
								  const void *pending_packet, int pending_packet_len,
								  dns_client_gstream_prepare_send_fn prepare_send, void *user_data);

int dns_client_process_gstream_events(struct dns_server_info *server_info);

#endif
