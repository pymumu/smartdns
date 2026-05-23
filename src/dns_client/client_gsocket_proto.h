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

#ifndef _DNS_CLIENT_GSOCKET_PROTO_H_
#define _DNS_CLIENT_GSOCKET_PROTO_H_

#include "../dns_gsocket/dns_gsocket_driver.h"

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif

const struct dns_gsocket_proto *dns_client_gsocket_proto_get(dns_server_type_t type);
int dns_client_gsocket_proto_create_socket(struct dns_server_info *server_info);
int dns_client_gsocket_proto_process(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now);
int dns_client_gsocket_proto_send_query(struct dns_server_info *server_info, struct dns_query_struct *query,
										void *packet, int len);
void dns_client_gsocket_proto_shutdown(struct dns_server_info *server_info);
int dns_client_gsocket_proto_socket_send(struct dns_server_info *server_info);
int dns_client_gsocket_proto_socket_recv(struct dns_server_info *server_info);
int dns_client_gsocket_proto_is_connectionless(struct dns_server_info *server_info);
int dns_client_gsocket_proto_can_keep_socket_on_prohibit(struct dns_server_info *server_info);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_CLIENT_GSOCKET_PROTO_H_ */
