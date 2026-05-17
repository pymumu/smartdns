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

#ifndef _DNS_SERVER_GSOCKET_H_
#define _DNS_SERVER_GSOCKET_H_

#include "dns_server.h"
#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

/* Bind one listen socket described by bind_ip. Adds to server.listener_list. */
int _dns_server_gsocket_bind(struct dns_bind_ip *bind_ip);

/* Process an event on a listener (accept new clients). */
int _dns_server_gsocket_process_listener(struct dns_server_conn_head *conn, struct gepoll_event *event,
										 unsigned long now);

/* Process an event on a TCP/TLS/HTTPS/QUIC client connection. */
int _dns_server_gsocket_process_client(struct dns_server_conn_gsocket *conn, struct gepoll_event *event,
									   unsigned long now);

/* Process an event on a UDP server socket (recv packets). */
int _dns_server_gsocket_process_udp(struct dns_server_conn_udp *conn, struct gepoll_event *event, unsigned long now);

/* Reply functions - called from _dns_reply_inpacket(). */
int _dns_server_reply_udp(struct dns_request *request, struct dns_server_conn_udp *udpconn, unsigned char *inpacket,
						  int inpacket_len);

int _dns_server_reply_tcp(struct dns_request *request, struct dns_server_conn_gsocket *conn, unsigned char *inpacket,
						  int inpacket_len);

int _dns_server_reply_stream(struct dns_request *request, struct dns_server_conn_stream *stream_conn,
							 unsigned char *inpacket, int inpacket_len);

/* Idle timeout check for TCP/TLS/HTTPS clients. */
void _dns_server_gsocket_tcp_idle_check(void);

/* Close and free all listeners in server.listener_list. */
void _dns_server_gsocket_close_listeners(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
