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

#define _GNU_SOURCE

#include "client_gsocket.h"
#include "client_doh_gsocket.h"
#include "client_doq_gsocket.h"
#include "client_gsocket_stream.h"
#include "client_socket.h"
#include "conn_stream.h"
#include "dns_client.h"
#include "query.h"
#include "server_info.h"

#include "smartdns/dns_conf.h"
#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DNS_MAX_SERVERS 64
#ifndef DNS_IN_PACKSIZE
#define DNS_IN_PACKSIZE (4096)
#endif

/* Socket factory, proxy-layer and SSL-context logic moved to client_gsocket_factory.c */

/* ------------------------------------------------------------------ */
/*  Low-level I/O stubs (called from client_socket.c)                  */
/* ------------------------------------------------------------------ */

int _dns_client_socket_ssl_send(struct dns_server_info *server_info, void *data, int len)
{
	if (server_info->gs == NULL) {
		errno = EBADF;
		return -1;
	}
	return (int)gsocket_send(server_info->gs, data, len, 0);
}

int _dns_client_socket_ssl_recv(struct dns_server_info *server_info, void *buf, int len)
{
	if (server_info->gs == NULL) {
		errno = EBADF;
		return -1;
	}
	return (int)gsocket_recv(server_info->gs, buf, len, 0);
}

int _dns_client_socket_tcp_send(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL || server_info->send_buff.len <= 0) {
		return 0;
	}

	int ret = (int)gsocket_send(server_info->gs, server_info->send_buff.data, server_info->send_buff.len, 0);
	if (ret > 0) {
		server_info->send_buff.len -= ret;
		if (server_info->send_buff.len > 0) {
			memmove(server_info->send_buff.data, server_info->send_buff.data + ret, server_info->send_buff.len);
		}
	}
	return ret;
}

int _dns_client_socket_tcp_recv(struct dns_server_info *server_info)
{
	if (server_info->gs == NULL) {
		errno = EBADF;
		return -1;
	}

	unsigned char *buf = server_info->recv_buff.data + server_info->recv_buff.len;
	int avail = DNS_TCP_BUFFER - server_info->recv_buff.len;
	if (avail <= 0) {
		errno = ENOMEM;
		return -1;
	}

	return (int)gsocket_recv(server_info->gs, buf, avail, 0);
}

int _dns_client_ssl_poll_event(struct dns_server_info *server_info, int ssl_error)
{
	if (server_info->gs == NULL) {
		return -1;
	}
	/* Request EPOLLOUT so gepoll retries the write */
	gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
	return 0;
}

/* UDP/TCP processing moved to client_gsocket_udp.c/client_gsocket_tcp.c */

/* TLS transport/event processing moved to client_gsocket_transport.c */

/* ------------------------------------------------------------------ */
/*  HTTPS (HTTP/2 & HTTP/1) send                                       */
/* ------------------------------------------------------------------ */

int _dns_client_send_http2(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						   int packet_data_len)
{
	if (server_info == NULL || query == NULL || packet == NULL || packet_data_len < 2) {
		return -1;
	}

	uint16_t id = *(uint16_t *)packet;
	int is_h1 = (server_info->flags.https.alpn[0] != '\0' && strcmp(server_info->flags.https.alpn, "http/1.1") == 0);

	if (!is_h1) {
		*(uint16_t *)packet = 0;
	}

	int ret = dns_client_doh_send_query(server_info, query, packet, packet_data_len, DNS_SERVER_HTTPS);

	if (!is_h1) {
		*(uint16_t *)packet = id;
	}
	return ret;
}

int _dns_client_send_http1(struct dns_server_info *server_info, void *packet, int packet_data_len)
{
	if (server_info == NULL || packet == NULL || packet_data_len < 2) {
		return -1;
	}

	return dns_client_doh_send_http1(server_info, packet, packet_data_len);
}

/* ------------------------------------------------------------------ */
/*  QUIC / DoQ / HTTP3 sending                                          */
/* ------------------------------------------------------------------ */

int _dns_client_send_quic(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						  int packet_data_len)
{
	return dns_client_doq_send_query(query, server_info, packet, packet_data_len);
}

int _dns_client_send_http3(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						   int packet_data_len)
{
	if (server_info == NULL || query == NULL || packet == NULL || packet_data_len < 2) {
		return -1;
	}

	uint16_t id = *(uint16_t *)packet;
	*(uint16_t *)packet = 0;
	int ret = dns_client_doh_send_query(server_info, query, packet, packet_data_len, DNS_SERVER_HTTP3);
	*(uint16_t *)packet = id;
	return ret;
}
