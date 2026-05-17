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

#ifndef _DNS_CLIENT_GSOCKET_H_
#define _DNS_CLIENT_GSOCKET_H_

#include "dns_client.h"
#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SSL context management */
SSL_CTX *_ssl_ctx_get(int is_quic);
void _ssl_shutdown(struct dns_server_info *server_info);

/* Socket creation */
int _dns_client_create_socket_udp(struct dns_server_info *server_info);
int _dns_client_create_socket_tcp(struct dns_server_info *server_info);
int _dns_client_create_socket_tls(struct dns_server_info *server_info, const char *hostname, const char *alpn);
int _dns_client_create_socket_quic(struct dns_server_info *server_info, const char *hostname, const char *alpn);

/* Low-level I/O */
int _dns_client_socket_ssl_send(struct dns_server_info *server_info, void *data, int len);
int _dns_client_socket_ssl_recv(struct dns_server_info *server_info, void *buf, int len);
int _dns_client_socket_tcp_send(struct dns_server_info *server_info);
int _dns_client_socket_tcp_recv(struct dns_server_info *server_info);
int _dns_client_ssl_poll_event(struct dns_server_info *server_info, int ssl_error);

/* UDP */
int _dns_client_send_udp(struct dns_server_info *server_info, void *packet, int len);
int _dns_client_process_udp(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now);
void _dns_client_check_udp_nat(struct dns_query_struct *query);

/* TCP */
int _dns_client_send_tcp(struct dns_server_info *server_info, void *packet, int len);
int _dns_client_process_tcp(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now);
int _dns_client_process_tcp_recv(struct dns_server_info *server_info);
void _dns_client_check_tcp(void);

/* TLS/HTTPS/QUIC */
int _dns_client_send_tls(struct dns_server_info *server_info, void *packet, int len);
int _dns_client_send_http1(struct dns_server_info *server_info, void *packet, int packet_data_len);
int _dns_client_send_http2(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						   int packet_data_len);
int _dns_client_send_quic(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						  int packet_data_len);
int _dns_client_send_http3(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						   int packet_data_len);
int _dns_client_process_tls(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_CLIENT_GSOCKET_H_ */
