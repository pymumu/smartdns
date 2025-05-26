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

#ifndef _DNS_CLIENT_TLS_H_
#define _DNS_CLIENT_TLS_H_

#include "dns_client.h"

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_client_socket_ssl_send(struct dns_server_info *server, const void *buf, int num);

int _dns_client_socket_ssl_recv(struct dns_server_info *server, void *buf, int num);

int _dns_client_socket_ssl_send_ext(struct dns_server_info *server, SSL *ssl, const void *buf, int num, uint64_t flags);

int _dns_client_socket_ssl_recv_ext(struct dns_server_info *server, SSL *ssl, void *buf, int num);

int _dns_client_create_socket_tls(struct dns_server_info *server_info, const char *hostname, const char *alpn);

int _dns_client_ssl_poll_event(struct dns_server_info *server_info, int ssl_ret);

int _dns_client_send_tls(struct dns_server_info *server_info, void *packet, unsigned short len);

int _dns_client_process_tls(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now);

SSL_CTX *_ssl_ctx_get(int is_quic);

int _ssl_shutdown(struct dns_server_info *server);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
