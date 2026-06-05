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

#ifndef _DNS_GSOCKET_DRIVER_H_
#define _DNS_GSOCKET_DRIVER_H_

#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_GSOCKET_PROTO_CONNECTIONLESS (1 << 0)
#define DNS_GSOCKET_PROTO_STREAM         (1 << 1)
#define DNS_GSOCKET_PROTO_TLS            (1 << 2)
#define DNS_GSOCKET_PROTO_QUIC           (1 << 3)
#define DNS_GSOCKET_PROTO_HTTP           (1 << 4)
#define DNS_GSOCKET_PROTO_LISTENER       (1 << 5)
#define DNS_GSOCKET_PROTO_CLIENT         (1 << 6)
#define DNS_GSOCKET_PROTO_IDLE_CLIENT    (1 << 7)
#define DNS_GSOCKET_PROTO_UDP_MULTIPLEX  (1 << 8)

enum dns_gsocket_role {
	DNS_GSOCKET_CLIENT,
	DNS_GSOCKET_SERVER_LISTENER,
	DNS_GSOCKET_SERVER_CLIENT,
	DNS_GSOCKET_SERVER_STREAM,
};

enum dns_gsocket_layer_type {
	DNS_GSOCKET_LAYER_NONE = 0,
	DNS_GSOCKET_LAYER_BASE_UDP,
	DNS_GSOCKET_LAYER_BASE_TCP,
	DNS_GSOCKET_LAYER_PROXY,
	DNS_GSOCKET_LAYER_TLS,
	DNS_GSOCKET_LAYER_QUIC,
	DNS_GSOCKET_LAYER_HTTP1,
	DNS_GSOCKET_LAYER_HTTP2,
	DNS_GSOCKET_LAYER_HTTP3,
};

struct dns_gsocket_layer_spec {
	enum dns_gsocket_layer_type type;
	const char *alpn;
};

struct dns_gsocket_conn;

struct dns_gsocket_proto {
	int type;
	const char *name;
	unsigned int flags;
	const struct dns_gsocket_layer_spec *layers;
	int peer_type;

	int (*create)(struct dns_gsocket_conn *conn);
	int (*process)(struct dns_gsocket_conn *conn, struct gepoll_event *event, unsigned long now);
	int (*send_query)(struct dns_gsocket_conn *conn, void *request, void *packet, int packet_len);
	void (*shutdown)(struct dns_gsocket_conn *conn);
	int (*socket_send)(struct dns_gsocket_conn *conn);
	int (*socket_recv)(struct dns_gsocket_conn *conn);
	int (*reply)(struct dns_gsocket_conn *conn, void *request, unsigned char *packet, int packet_len);
};

struct dns_gsocket_conn {
	enum dns_gsocket_role role;
	const struct dns_gsocket_proto *proto;

	struct gsocket *gs;
	struct gstream_poll *sp;

	void *owner;
	void *user_data;

	int status;
	int events;
};

void dns_gsocket_conn_init(struct dns_gsocket_conn *conn, enum dns_gsocket_role role,
						   const struct dns_gsocket_proto *proto, void *owner);
int dns_gsocket_driver_create(struct dns_gsocket_conn *conn);
int dns_gsocket_driver_process(struct dns_gsocket_conn *conn, struct gepoll_event *event, unsigned long now);
int dns_gsocket_driver_send_query(struct dns_gsocket_conn *conn, void *request, void *packet, int packet_len);
void dns_gsocket_driver_shutdown(struct dns_gsocket_conn *conn);
int dns_gsocket_driver_socket_send(struct dns_gsocket_conn *conn);
int dns_gsocket_driver_socket_recv(struct dns_gsocket_conn *conn);
int dns_gsocket_driver_reply(struct dns_gsocket_conn *conn, void *request, unsigned char *packet, int packet_len);
int dns_gsocket_driver_handshake(struct dns_gsocket_conn *conn, int *poll_events);
int dns_gsocket_proto_has_flag(const struct dns_gsocket_proto *proto, unsigned int flag);
int dns_gsocket_layer_spec_has(const struct dns_gsocket_layer_spec *layers, enum dns_gsocket_layer_type type);
const char *dns_gsocket_layer_spec_alpn(const struct dns_gsocket_layer_spec *layers, enum dns_gsocket_layer_type type);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_GSOCKET_DRIVER_H_ */
