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

#include "server_gsocket_proto.h"

#include "server_gsocket.h"

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

static struct dns_server_conn_head *_dns_server_driver_conn(struct dns_gsocket_conn *conn)
{
	return (struct dns_server_conn_head *)conn->owner;
}

static int _dns_server_proto_process_udp(struct dns_gsocket_conn *conn, struct gepoll_event *event,
										 unsigned long now)
{
	return _dns_server_gsocket_process_udp((struct dns_server_conn_udp *)_dns_server_driver_conn(conn), event, now);
}

static int _dns_server_proto_process_listener(struct dns_gsocket_conn *conn, struct gepoll_event *event,
											  unsigned long now)
{
	return _dns_server_gsocket_process_listener(_dns_server_driver_conn(conn), event, now);
}

static int _dns_server_proto_process_client(struct dns_gsocket_conn *conn, struct gepoll_event *event,
											unsigned long now)
{
	return _dns_server_gsocket_process_client((struct dns_server_conn_gsocket *)_dns_server_driver_conn(conn), event,
											  now);
}

static int _dns_server_proto_reply_udp(struct dns_gsocket_conn *conn, void *request, unsigned char *inpacket,
									   int inpacket_len)
{
	return _dns_server_reply_udp(request, (struct dns_server_conn_udp *)_dns_server_driver_conn(conn), inpacket,
								 inpacket_len);
}

static int _dns_server_proto_reply_tcp(struct dns_gsocket_conn *conn, void *request, unsigned char *inpacket,
									   int inpacket_len)
{
	return _dns_server_reply_tcp(request, (struct dns_server_conn_gsocket *)_dns_server_driver_conn(conn), inpacket,
								 inpacket_len);
}

static int _dns_server_proto_reply_stream(struct dns_gsocket_conn *conn, void *request, unsigned char *inpacket,
										  int inpacket_len)
{
	return _dns_server_reply_stream(request, (struct dns_server_conn_stream *)_dns_server_driver_conn(conn), inpacket,
									inpacket_len);
}

static const struct dns_gsocket_layer_spec _dns_server_layers_udp[] = {
	{DNS_GSOCKET_LAYER_BASE_UDP, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_server_layers_tcp[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_server_layers_tls[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_TLS, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_server_layers_https[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_TLS, "h2,http/1.1"},
	{DNS_GSOCKET_LAYER_HTTP2, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_server_layers_http[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_HTTP1, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_server_layers_quic[] = {
	{DNS_GSOCKET_LAYER_BASE_UDP, NULL},
	{DNS_GSOCKET_LAYER_QUIC, "doq"},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_server_layers_https3[] = {
	{DNS_GSOCKET_LAYER_BASE_UDP, NULL},
	{DNS_GSOCKET_LAYER_QUIC, "h3"},
	{DNS_GSOCKET_LAYER_HTTP3, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_server_gsocket_bind_proto _dns_server_bind_protos[] = {
	{DNS_BIND_TYPE_UDP, DNS_CONN_TYPE_UDP_SERVER, SOCK_DGRAM, _dns_server_layers_udp, "UDP"},
	{DNS_BIND_TYPE_TCP, DNS_CONN_TYPE_TCP_SERVER, SOCK_STREAM, _dns_server_layers_tcp, "TCP"},
	{DNS_BIND_TYPE_TLS, DNS_CONN_TYPE_TLS_SERVER, SOCK_STREAM, _dns_server_layers_tls, "TLS"},
	{DNS_BIND_TYPE_HTTPS, DNS_CONN_TYPE_HTTPS_SERVER, SOCK_STREAM, _dns_server_layers_https, "HTTPS"},
	{DNS_BIND_TYPE_HTTPS3, DNS_CONN_TYPE_HTTPS3_SERVER, SOCK_DGRAM, _dns_server_layers_https3, "HTTPS3"},
	{DNS_BIND_TYPE_QUIC, DNS_CONN_TYPE_QUIC_SERVER, SOCK_DGRAM, _dns_server_layers_quic, "QUIC"},
	{DNS_BIND_TYPE_HTTP, DNS_CONN_TYPE_HTTP_SERVER, SOCK_STREAM, _dns_server_layers_http, "HTTP"},
};

static const struct dns_gsocket_proto _dns_server_conn_protos[] = {
	{
		.type = DNS_CONN_TYPE_UDP_SERVER,
		.name = "udp-server",
		.layers = _dns_server_layers_udp,
		.process = _dns_server_proto_process_udp,
		.reply = _dns_server_proto_reply_udp,
	},
	{
		.type = DNS_CONN_TYPE_TCP_SERVER,
		.name = "tcp-listener",
		.flags = DNS_GSOCKET_PROTO_LISTENER,
		.layers = _dns_server_layers_tcp,
		.peer_type = DNS_CONN_TYPE_TCP_CLIENT,
		.process = _dns_server_proto_process_listener,
	},
	{
		.type = DNS_CONN_TYPE_TLS_SERVER,
		.name = "tls-listener",
		.flags = DNS_GSOCKET_PROTO_LISTENER | DNS_GSOCKET_PROTO_TLS,
		.layers = _dns_server_layers_tls,
		.peer_type = DNS_CONN_TYPE_TLS_CLIENT,
		.process = _dns_server_proto_process_listener,
	},
	{
		.type = DNS_CONN_TYPE_HTTPS_SERVER,
		.name = "https-listener",
		.flags = DNS_GSOCKET_PROTO_LISTENER | DNS_GSOCKET_PROTO_TLS | DNS_GSOCKET_PROTO_HTTP,
		.layers = _dns_server_layers_https,
		.peer_type = DNS_CONN_TYPE_HTTPS_CLIENT,
		.process = _dns_server_proto_process_listener,
	},
	{
		.type = DNS_CONN_TYPE_HTTP_SERVER,
		.name = "http-listener",
		.flags = DNS_GSOCKET_PROTO_LISTENER | DNS_GSOCKET_PROTO_HTTP,
		.layers = _dns_server_layers_http,
		.peer_type = DNS_CONN_TYPE_HTTP_CLIENT,
		.process = _dns_server_proto_process_listener,
	},
	{
		.type = DNS_CONN_TYPE_HTTPS3_SERVER,
		.name = "https3-listener",
		.flags = DNS_GSOCKET_PROTO_LISTENER | DNS_GSOCKET_PROTO_QUIC | DNS_GSOCKET_PROTO_HTTP,
		.layers = _dns_server_layers_https3,
		.peer_type = DNS_CONN_TYPE_HTTPS3_CLIENT,
		.process = _dns_server_proto_process_listener,
	},
	{
		.type = DNS_CONN_TYPE_QUIC_SERVER,
		.name = "quic-listener",
		.flags = DNS_GSOCKET_PROTO_LISTENER | DNS_GSOCKET_PROTO_QUIC,
		.layers = _dns_server_layers_quic,
		.peer_type = DNS_CONN_TYPE_QUIC_CLIENT,
		.process = _dns_server_proto_process_listener,
	},
	{
		.type = DNS_CONN_TYPE_TCP_CLIENT,
		.name = "tcp-client",
		.flags = DNS_GSOCKET_PROTO_CLIENT | DNS_GSOCKET_PROTO_IDLE_CLIENT,
		.layers = _dns_server_layers_tcp,
		.process = _dns_server_proto_process_client,
		.reply = _dns_server_proto_reply_tcp,
	},
	{
		.type = DNS_CONN_TYPE_TLS_CLIENT,
		.name = "tls-client",
		.flags = DNS_GSOCKET_PROTO_CLIENT | DNS_GSOCKET_PROTO_TLS | DNS_GSOCKET_PROTO_IDLE_CLIENT,
		.layers = _dns_server_layers_tls,
		.process = _dns_server_proto_process_client,
		.reply = _dns_server_proto_reply_tcp,
	},
	{
		.type = DNS_CONN_TYPE_HTTPS_CLIENT,
		.name = "https-client",
		.flags = DNS_GSOCKET_PROTO_CLIENT | DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_TLS |
				 DNS_GSOCKET_PROTO_HTTP | DNS_GSOCKET_PROTO_IDLE_CLIENT,
		.layers = _dns_server_layers_https,
		.process = _dns_server_proto_process_client,
	},
	{
		.type = DNS_CONN_TYPE_HTTP_CLIENT,
		.name = "http-client",
		.flags = DNS_GSOCKET_PROTO_CLIENT | DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_HTTP |
				 DNS_GSOCKET_PROTO_IDLE_CLIENT,
		.layers = _dns_server_layers_http,
		.process = _dns_server_proto_process_client,
	},
	{
		.type = DNS_CONN_TYPE_HTTPS3_CLIENT,
		.name = "https3-client",
		.flags = DNS_GSOCKET_PROTO_CLIENT | DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_QUIC |
				 DNS_GSOCKET_PROTO_HTTP | DNS_GSOCKET_PROTO_UDP_MULTIPLEX | DNS_GSOCKET_PROTO_IDLE_CLIENT,
		.layers = _dns_server_layers_https3,
		.process = _dns_server_proto_process_client,
	},
	{
		.type = DNS_CONN_TYPE_QUIC_CLIENT,
		.name = "quic-client",
		.flags = DNS_GSOCKET_PROTO_CLIENT | DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_QUIC |
				 DNS_GSOCKET_PROTO_UDP_MULTIPLEX | DNS_GSOCKET_PROTO_IDLE_CLIENT,
		.layers = _dns_server_layers_quic,
		.process = _dns_server_proto_process_client,
	},
	{
		.type = DNS_CONN_TYPE_HTTP2_STREAM,
		.name = "http2-stream",
		.flags = DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_HTTP,
		.layers = _dns_server_layers_https,
		.reply = _dns_server_proto_reply_stream,
	},
	{
		.type = DNS_CONN_TYPE_QUIC_STREAM,
		.name = "quic-stream",
		.flags = DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_QUIC,
		.layers = _dns_server_layers_quic,
		.reply = _dns_server_proto_reply_stream,
	},
};

static const struct dns_gsocket_proto *_dns_server_gsocket_conn_proto_get(DNS_CONN_TYPE type)
{
	for (size_t i = 0; i < sizeof(_dns_server_conn_protos) / sizeof(_dns_server_conn_protos[0]); i++) {
		if (_dns_server_conn_protos[i].type == (int)type) {
			return &_dns_server_conn_protos[i];
		}
	}

	errno = EPROTONOSUPPORT;
	return NULL;
}

const struct dns_gsocket_proto *dns_server_gsocket_proto_get(DNS_CONN_TYPE type)
{
	return _dns_server_gsocket_conn_proto_get(type);
}

static enum dns_gsocket_role _dns_server_gsocket_role_from_proto(const struct dns_gsocket_proto *proto)
{
	if (dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_LISTENER)) {
		return DNS_GSOCKET_SERVER_LISTENER;
	}

	if (dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_CLIENT)) {
		return DNS_GSOCKET_SERVER_CLIENT;
	}

	if (dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_STREAM)) {
		return DNS_GSOCKET_SERVER_STREAM;
	}

	return DNS_GSOCKET_SERVER_CLIENT;
}

static void _dns_server_gsocket_conn_init(struct dns_gsocket_conn *gconn, struct dns_server_conn_head *conn,
										  const struct dns_gsocket_proto *proto)
{
	dns_gsocket_conn_init(gconn, _dns_server_gsocket_role_from_proto(proto), proto, conn);
	gconn->gs = conn->gs;
}

const struct dns_server_gsocket_bind_proto *dns_server_gsocket_bind_proto_get(DNS_BIND_TYPE bind_type)
{
	for (size_t i = 0; i < sizeof(_dns_server_bind_protos) / sizeof(_dns_server_bind_protos[0]); i++) {
		if (_dns_server_bind_protos[i].bind_type == bind_type) {
			return &_dns_server_bind_protos[i];
		}
	}

	errno = EPROTONOSUPPORT;
	return NULL;
}

int dns_server_gsocket_proto_process(struct dns_server_conn_head *conn, struct gepoll_event *event,
									 unsigned long now)
{
	struct dns_gsocket_conn gconn;
	const struct dns_gsocket_proto *proto = _dns_server_gsocket_conn_proto_get(conn->type);
	if (proto == NULL) {
		return -1;
	}

	_dns_server_gsocket_conn_init(&gconn, conn, proto);
	return dns_gsocket_driver_process(&gconn, event, now);
}

int dns_server_gsocket_proto_reply(struct dns_request *request, unsigned char *inpacket, int inpacket_len)
{
	struct dns_gsocket_conn gconn;
	const struct dns_gsocket_proto *proto = NULL;

	if (request == NULL || request->conn == NULL) {
		errno = EINVAL;
		return -1;
	}

	proto = _dns_server_gsocket_conn_proto_get(request->conn->type);
	if (proto == NULL) {
		return -1;
	}

	_dns_server_gsocket_conn_init(&gconn, request->conn, proto);
	return dns_gsocket_driver_reply(&gconn, request, inpacket, inpacket_len);
}

int dns_server_gsocket_proto_get_client_type(DNS_CONN_TYPE listener_type, DNS_CONN_TYPE *client_type_out)
{
	const struct dns_gsocket_proto *proto = _dns_server_gsocket_conn_proto_get(listener_type);
	if (!dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_LISTENER)) {
		return -1;
	}

	*client_type_out = proto->peer_type;
	return 0;
}

int dns_server_gsocket_proto_is_quic_listener(DNS_CONN_TYPE type)
{
	const struct dns_gsocket_proto *proto = _dns_server_gsocket_conn_proto_get(type);
	return dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_LISTENER) &&
		   dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_QUIC);
}

int dns_server_gsocket_proto_client_needs_stream_poll(DNS_CONN_TYPE type)
{
	const struct dns_gsocket_proto *proto = _dns_server_gsocket_conn_proto_get(type);
	return dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_CLIENT) &&
		   dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_STREAM);
}

int dns_server_gsocket_proto_is_udp_multiplex_client(DNS_CONN_TYPE type)
{
	const struct dns_gsocket_proto *proto = _dns_server_gsocket_conn_proto_get(type);
	return dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_UDP_MULTIPLEX);
}

int dns_server_gsocket_proto_is_idle_client(DNS_CONN_TYPE type)
{
	const struct dns_gsocket_proto *proto = _dns_server_gsocket_conn_proto_get(type);
	return dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_IDLE_CLIENT);
}
