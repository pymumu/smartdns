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

#ifndef _DNS_SERVER_GSOCKET_PROTO_H_
#define _DNS_SERVER_GSOCKET_PROTO_H_

#include "../dns_gsocket/dns_gsocket_driver.h"

#include "dns_server.h"

#include "smartdns/dns_conf.h"
#include "smartdns/lib/gepoll.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dns_server_gsocket_bind_proto {
	DNS_BIND_TYPE bind_type;
	DNS_CONN_TYPE listener_type;
	int socket_type;
	const struct dns_gsocket_layer_spec *layers;
	const char *name;
};

const struct dns_server_gsocket_bind_proto *dns_server_gsocket_bind_proto_get(DNS_BIND_TYPE bind_type);
const struct dns_gsocket_proto *dns_server_gsocket_proto_get(DNS_CONN_TYPE type);
int dns_server_gsocket_proto_process(struct dns_server_conn_head *conn, struct gepoll_event *event,
									 unsigned long now);
int dns_server_gsocket_proto_reply(struct dns_request *request, unsigned char *inpacket, int inpacket_len);
int dns_server_gsocket_proto_get_client_type(DNS_CONN_TYPE listener_type, DNS_CONN_TYPE *client_type_out);
int dns_server_gsocket_proto_is_quic_listener(DNS_CONN_TYPE type);
int dns_server_gsocket_proto_client_needs_stream_poll(DNS_CONN_TYPE type);
int dns_server_gsocket_proto_is_udp_multiplex_client(DNS_CONN_TYPE type);
int dns_server_gsocket_proto_is_idle_client(DNS_CONN_TYPE type);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_SERVER_GSOCKET_PROTO_H_ */
