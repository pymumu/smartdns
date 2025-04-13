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

#ifndef _DNS_SERVER_TCP_
#define _DNS_SERVER_TCP_

#include "dns_server.h"

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_server_reply_tcp_to_buffer(struct dns_server_conn_tcp_client *tcpclient, void *packet, int len);

int _dns_server_tcp_socket_send(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len);

int _dns_server_tcp_accept(struct dns_server_conn_tcp_server *tcpserver, struct epoll_event *event, unsigned long now);

int _dns_server_tcp_socket_recv(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len);

int _dns_server_tcp_process_requests(struct dns_server_conn_tcp_client *tcpclient);

int _dns_server_process_tcp(struct dns_server_conn_tcp_client *dnsserver, struct epoll_event *event, unsigned long now);

int _dns_server_reply_tcp(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient, void *packet,
						  unsigned short len);

void _dns_server_tcp_idle_check(void);

int _dns_server_socket_tcp(struct dns_bind_ip *bind_ip);
#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
