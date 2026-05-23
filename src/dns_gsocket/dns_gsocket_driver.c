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

#include "dns_gsocket_driver.h"

#include <errno.h>
#include <string.h>

void dns_gsocket_conn_init(struct dns_gsocket_conn *conn, enum dns_gsocket_role role,
						   const struct dns_gsocket_proto *proto, void *owner)
{
	memset(conn, 0, sizeof(*conn));
	conn->role = role;
	conn->proto = proto;
	conn->owner = owner;
}

int dns_gsocket_driver_create(struct dns_gsocket_conn *conn)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->create == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return conn->proto->create(conn);
}

int dns_gsocket_driver_process(struct dns_gsocket_conn *conn, struct gepoll_event *event, unsigned long now)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->process == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return conn->proto->process(conn, event, now);
}

int dns_gsocket_driver_send_query(struct dns_gsocket_conn *conn, void *request, void *packet, int packet_len)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->send_query == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return conn->proto->send_query(conn, request, packet, packet_len);
}

void dns_gsocket_driver_shutdown(struct dns_gsocket_conn *conn)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->shutdown == NULL) {
		return;
	}

	conn->proto->shutdown(conn);
}

int dns_gsocket_driver_socket_send(struct dns_gsocket_conn *conn)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->socket_send == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return conn->proto->socket_send(conn);
}

int dns_gsocket_driver_socket_recv(struct dns_gsocket_conn *conn)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->socket_recv == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return conn->proto->socket_recv(conn);
}

int dns_gsocket_driver_reply(struct dns_gsocket_conn *conn, void *request, unsigned char *packet, int packet_len)
{
	if (conn == NULL || conn->proto == NULL || conn->proto->reply == NULL) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return conn->proto->reply(conn, request, packet, packet_len);
}

int dns_gsocket_driver_handshake(struct dns_gsocket_conn *conn, int *poll_events)
{
	int hs = 0;
	int events = EPOLLIN;

	if (conn == NULL || conn->gs == NULL) {
		errno = EINVAL;
		return -1;
	}

	hs = gsocket_handshake(conn->gs);
	if (hs < 0) {
		if (errno == 0) {
			errno = ECONNRESET;
		}
		return -1;
	}

	if (hs == GSOCKET_HANDSHAKE_DONE) {
		if (poll_events != NULL) {
			*poll_events = EPOLLIN;
		}
		return 1;
	}

	if (hs == GSOCKET_HANDSHAKE_WANT_WRITE || dns_gsocket_proto_has_flag(conn->proto, DNS_GSOCKET_PROTO_QUIC)) {
		events |= EPOLLOUT;
	}

	if (poll_events != NULL) {
		*poll_events = events;
	}

	return 0;
}

int dns_gsocket_proto_has_flag(const struct dns_gsocket_proto *proto, unsigned int flag)
{
	return proto != NULL && (proto->flags & flag);
}

int dns_gsocket_layer_spec_has(const struct dns_gsocket_layer_spec *layers, enum dns_gsocket_layer_type type)
{
	return dns_gsocket_layer_spec_alpn(layers, type) != NULL;
}

const char *dns_gsocket_layer_spec_alpn(const struct dns_gsocket_layer_spec *layers, enum dns_gsocket_layer_type type)
{
	if (type == DNS_GSOCKET_LAYER_NONE) {
		return NULL;
	}

	for (size_t i = 0; layers != NULL && layers[i].type != DNS_GSOCKET_LAYER_NONE; i++) {
		if (layers[i].type == type) {
			return layers[i].alpn != NULL ? layers[i].alpn : "";
		}
	}

	return NULL;
}
