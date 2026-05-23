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

#include "client_gsocket_proto.h"

#include "client_gsocket.h"
#include "client_mdns.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

static struct dns_server_info *_dns_client_driver_server(struct dns_gsocket_conn *conn)
{
	return (struct dns_server_info *)conn->owner;
}

static int _dns_client_proto_create_udp(struct dns_gsocket_conn *conn)
{
	return _dns_client_create_socket_udp(_dns_client_driver_server(conn));
}

static int _dns_client_proto_create_mdns(struct dns_gsocket_conn *conn)
{
	return _dns_client_create_socket_udp_mdns(_dns_client_driver_server(conn));
}

static int _dns_client_proto_create_tcp(struct dns_gsocket_conn *conn)
{
	return _dns_client_create_socket_tcp(_dns_client_driver_server(conn));
}

static int _dns_client_proto_create_tls(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	struct client_dns_server_flag_tls *flag_tls = &server_info->flags.tls;
	return _dns_client_create_socket_tls(server_info, flag_tls->hostname, flag_tls->alpn);
}

static int _dns_client_proto_create_https(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	struct client_dns_server_flag_https *flag_https = &server_info->flags.https;
	const char *alpn = (flag_https->alpn[0] != 0) ? flag_https->alpn : "h2,http/1.1";
	return _dns_client_create_socket_tls(server_info, flag_https->hostname, alpn);
}

static int _dns_client_proto_create_quic(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	struct client_dns_server_flag_tls *flag_tls = &server_info->flags.tls;
	const char *alpn = (flag_tls->alpn[0] != 0) ? flag_tls->alpn : "doq";
	return _dns_client_create_socket_quic(server_info, flag_tls->hostname, alpn);
}

static int _dns_client_proto_create_http3(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	struct client_dns_server_flag_https *flag_https = &server_info->flags.https;
	const char *alpn = (flag_https->alpn[0] != 0) ? flag_https->alpn : "h3";
	return _dns_client_create_socket_quic(server_info, flag_https->hostname, alpn);
}

static int _dns_client_proto_process_udp(struct dns_gsocket_conn *conn, struct gepoll_event *event, unsigned long now)
{
	return _dns_client_process_udp(_dns_client_driver_server(conn), event, now);
}

static int _dns_client_proto_process_tcp(struct dns_gsocket_conn *conn, struct gepoll_event *event, unsigned long now)
{
	return _dns_client_process_tcp(_dns_client_driver_server(conn), event, now);
}

static int _dns_client_proto_process_tls(struct dns_gsocket_conn *conn, struct gepoll_event *event, unsigned long now)
{
	return _dns_client_process_tls(_dns_client_driver_server(conn), event, now);
}

static int _dns_client_proto_send_udp(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	(void)request;
	return _dns_client_send_udp(_dns_client_driver_server(conn), packet, len);
}

static int _dns_client_proto_send_mdns(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	(void)request;
	return _dns_client_send_udp_mdns(_dns_client_driver_server(conn), packet, len);
}

static int _dns_client_proto_send_tcp(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	(void)request;
	return _dns_client_send_tcp(_dns_client_driver_server(conn), packet, len);
}

static int _dns_client_proto_send_tls(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	(void)request;
	return _dns_client_send_tls(_dns_client_driver_server(conn), packet, len);
}

static int _dns_client_proto_send_https(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	return _dns_client_send_http2(_dns_client_driver_server(conn), request, packet, len);
}

static int _dns_client_proto_send_quic(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	return _dns_client_send_quic(_dns_client_driver_server(conn), request, packet, len);
}

static int _dns_client_proto_send_http3(struct dns_gsocket_conn *conn, void *request, void *packet, int len)
{
	return _dns_client_send_http3(_dns_client_driver_server(conn), request, packet, len);
}

static void _dns_client_proto_shutdown_udp(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	atomic_set(&server_info->is_alive, 0);
}

static void _dns_client_proto_shutdown_stream(struct dns_gsocket_conn *conn)
{
	gsocket_shutdown(_dns_client_driver_server(conn)->gs, SHUT_RDWR);
}

static void _dns_client_proto_shutdown_tls(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
		_ssl_shutdown(server_info);
	}
	gsocket_shutdown(server_info->gs, SHUT_RDWR);
	atomic_set(&server_info->is_alive, 0);
}

static int _dns_client_proto_socket_send_unavailable(struct dns_gsocket_conn *conn)
{
	(void)conn;
	return -1;
}

static int _dns_client_proto_socket_recv_unavailable(struct dns_gsocket_conn *conn)
{
	(void)conn;
	return -1;
}

static int _dns_client_proto_socket_send_tcp(struct dns_gsocket_conn *conn)
{
	return _dns_client_socket_tcp_send(_dns_client_driver_server(conn));
}

static int _dns_client_proto_socket_recv_tcp(struct dns_gsocket_conn *conn)
{
	return _dns_client_socket_tcp_recv(_dns_client_driver_server(conn));
}

static int _dns_client_proto_socket_send_tls(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	int ret = _dns_client_socket_ssl_send(server_info, server_info->send_buff.data, server_info->send_buff.len);
	if (ret > 0) {
		server_info->send_buff.len -= ret;
		if (server_info->send_buff.len > 0) {
			memmove(server_info->send_buff.data, server_info->send_buff.data + ret, server_info->send_buff.len);
		}
	}
	return ret;
}

static int _dns_client_proto_socket_recv_tls(struct dns_gsocket_conn *conn)
{
	struct dns_server_info *server_info = _dns_client_driver_server(conn);
	return _dns_client_socket_ssl_recv(server_info, server_info->recv_buff.data + server_info->recv_buff.len,
									   DNS_TCP_BUFFER - server_info->recv_buff.len);
}

static const struct dns_gsocket_layer_spec _dns_client_layers_udp[] = {
	{DNS_GSOCKET_LAYER_BASE_UDP, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_client_layers_tcp[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_PROXY, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_client_layers_tls[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_PROXY, NULL},
	{DNS_GSOCKET_LAYER_TLS, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_client_layers_https[] = {
	{DNS_GSOCKET_LAYER_BASE_TCP, NULL},
	{DNS_GSOCKET_LAYER_PROXY, NULL},
	{DNS_GSOCKET_LAYER_TLS, "h2,http/1.1"},
	{DNS_GSOCKET_LAYER_HTTP2, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_client_layers_quic[] = {
	{DNS_GSOCKET_LAYER_BASE_UDP, NULL},
	{DNS_GSOCKET_LAYER_QUIC, "doq"},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_layer_spec _dns_client_layers_http3[] = {
	{DNS_GSOCKET_LAYER_BASE_UDP, NULL},
	{DNS_GSOCKET_LAYER_QUIC, "h3"},
	{DNS_GSOCKET_LAYER_HTTP3, NULL},
	{DNS_GSOCKET_LAYER_NONE, NULL},
};

static const struct dns_gsocket_proto _dns_client_protos[] = {
	{
		.type = DNS_SERVER_UDP,
		.name = "udp",
		.flags = DNS_GSOCKET_PROTO_CONNECTIONLESS,
		.layers = _dns_client_layers_udp,
		.create = _dns_client_proto_create_udp,
		.process = _dns_client_proto_process_udp,
		.send_query = _dns_client_proto_send_udp,
		.shutdown = _dns_client_proto_shutdown_udp,
		.socket_send = _dns_client_proto_socket_send_unavailable,
		.socket_recv = _dns_client_proto_socket_recv_unavailable,
	},
	{
		.type = DNS_SERVER_TCP,
		.name = "tcp",
		.layers = _dns_client_layers_tcp,
		.create = _dns_client_proto_create_tcp,
		.process = _dns_client_proto_process_tcp,
		.send_query = _dns_client_proto_send_tcp,
		.shutdown = _dns_client_proto_shutdown_stream,
		.socket_send = _dns_client_proto_socket_send_tcp,
		.socket_recv = _dns_client_proto_socket_recv_tcp,
	},
	{
		.type = DNS_SERVER_TLS,
		.name = "tls",
		.flags = DNS_GSOCKET_PROTO_TLS,
		.layers = _dns_client_layers_tls,
		.create = _dns_client_proto_create_tls,
		.process = _dns_client_proto_process_tls,
		.send_query = _dns_client_proto_send_tls,
		.shutdown = _dns_client_proto_shutdown_tls,
		.socket_send = _dns_client_proto_socket_send_tls,
		.socket_recv = _dns_client_proto_socket_recv_tls,
	},
	{
		.type = DNS_SERVER_HTTPS,
		.name = "https",
		.flags = DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_TLS | DNS_GSOCKET_PROTO_HTTP,
		.layers = _dns_client_layers_https,
		.create = _dns_client_proto_create_https,
		.process = _dns_client_proto_process_tls,
		.send_query = _dns_client_proto_send_https,
		.shutdown = _dns_client_proto_shutdown_tls,
		.socket_send = _dns_client_proto_socket_send_tls,
		.socket_recv = _dns_client_proto_socket_recv_tls,
	},
	{
		.type = DNS_SERVER_MDNS,
		.name = "mdns",
		.flags = DNS_GSOCKET_PROTO_CONNECTIONLESS,
		.layers = _dns_client_layers_udp,
		.create = _dns_client_proto_create_mdns,
		.process = _dns_client_proto_process_udp,
		.send_query = _dns_client_proto_send_mdns,
		.socket_send = _dns_client_proto_socket_send_unavailable,
		.socket_recv = _dns_client_proto_socket_recv_unavailable,
	},
	{
		.type = DNS_SERVER_QUIC,
		.name = "quic",
		.flags = DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_QUIC,
		.layers = _dns_client_layers_quic,
		.create = _dns_client_proto_create_quic,
		.process = _dns_client_proto_process_tls,
		.send_query = _dns_client_proto_send_quic,
		.shutdown = _dns_client_proto_shutdown_tls,
		.socket_send = _dns_client_proto_socket_send_tls,
		.socket_recv = _dns_client_proto_socket_recv_tls,
	},
	{
		.type = DNS_SERVER_HTTP3,
		.name = "http3",
		.flags = DNS_GSOCKET_PROTO_STREAM | DNS_GSOCKET_PROTO_QUIC | DNS_GSOCKET_PROTO_HTTP,
		.layers = _dns_client_layers_http3,
		.create = _dns_client_proto_create_http3,
		.process = _dns_client_proto_process_tls,
		.send_query = _dns_client_proto_send_http3,
		.shutdown = _dns_client_proto_shutdown_tls,
		.socket_send = _dns_client_proto_socket_send_tls,
		.socket_recv = _dns_client_proto_socket_recv_tls,
	},
};

const struct dns_gsocket_proto *dns_client_gsocket_proto_get(dns_server_type_t type)
{
	for (size_t i = 0; i < sizeof(_dns_client_protos) / sizeof(_dns_client_protos[0]); i++) {
		if (_dns_client_protos[i].type == (int)type) {
			return &_dns_client_protos[i];
		}
	}

	errno = EPROTONOSUPPORT;
	return NULL;
}

static void _dns_client_gsocket_conn_init(struct dns_gsocket_conn *conn, struct dns_server_info *server_info)
{
	dns_gsocket_conn_init(conn, DNS_GSOCKET_CLIENT, dns_client_gsocket_proto_get(server_info->type), server_info);
	conn->gs = server_info->gs;
	conn->sp = server_info->sp;
	conn->status = server_info->status;
}

int dns_client_gsocket_proto_create_socket(struct dns_server_info *server_info)
{
	struct dns_gsocket_conn conn;
	_dns_client_gsocket_conn_init(&conn, server_info);
	return dns_gsocket_driver_create(&conn);
}

int dns_client_gsocket_proto_process(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now)
{
	struct dns_gsocket_conn conn;
	_dns_client_gsocket_conn_init(&conn, server_info);
	return dns_gsocket_driver_process(&conn, event, now);
}

int dns_client_gsocket_proto_send_query(struct dns_server_info *server_info, struct dns_query_struct *query,
										void *packet, int len)
{
	struct dns_gsocket_conn conn;
	_dns_client_gsocket_conn_init(&conn, server_info);
	return dns_gsocket_driver_send_query(&conn, query, packet, len);
}

void dns_client_gsocket_proto_shutdown(struct dns_server_info *server_info)
{
	struct dns_gsocket_conn conn;
	_dns_client_gsocket_conn_init(&conn, server_info);
	dns_gsocket_driver_shutdown(&conn);
}

int dns_client_gsocket_proto_socket_send(struct dns_server_info *server_info)
{
	struct dns_gsocket_conn conn;
	_dns_client_gsocket_conn_init(&conn, server_info);
	return dns_gsocket_driver_socket_send(&conn);
}

int dns_client_gsocket_proto_socket_recv(struct dns_server_info *server_info)
{
	struct dns_gsocket_conn conn;
	_dns_client_gsocket_conn_init(&conn, server_info);
	return dns_gsocket_driver_socket_recv(&conn);
}

int dns_client_gsocket_proto_is_connectionless(struct dns_server_info *server_info)
{
	const struct dns_gsocket_proto *proto = dns_client_gsocket_proto_get(server_info->type);
	return dns_gsocket_proto_has_flag(proto, DNS_GSOCKET_PROTO_CONNECTIONLESS);
}

int dns_client_gsocket_proto_can_keep_socket_on_prohibit(struct dns_server_info *server_info)
{
	return dns_client_gsocket_proto_is_connectionless(server_info);
}
