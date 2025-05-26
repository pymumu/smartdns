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

#ifndef _DNS_SERVER_TLS_
#define _DNS_SERVER_TLS_

#include "dns_server.h"

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_server_ssl_poll_event(struct dns_server_conn_tls_client *tls_client, int ssl_ret);

int _dns_server_tls_accept(struct dns_server_conn_tls_server *tls_server, struct epoll_event *event, unsigned long now);

int _dns_server_socket_ssl_recv(struct dns_server_conn_tls_client *tls_client, void *buf, int num);

int _dns_server_socket_ssl_send(struct dns_server_conn_tls_client *tls_client, const void *buf, int num);

int _dns_server_process_tls(struct dns_server_conn_tls_client *tls_client, struct epoll_event *event,
							unsigned long now);

int _dns_server_socket_tls(struct dns_bind_ip *bind_ip, DNS_CONN_TYPE conn_type);
#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
