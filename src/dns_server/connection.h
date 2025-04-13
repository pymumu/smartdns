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

#ifndef _DNS_SERVER_CONNECTION_
#define _DNS_SERVER_CONNECTION_

#include "dns_server.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _dns_server_close_socket_server(void);

int _dns_server_client_close(struct dns_server_conn_head *conn);

void _dns_server_client_touch(struct dns_server_conn_head *conn);

int _dns_server_set_flags(struct dns_server_conn_head *head, struct dns_bind_ip *bind_ip);

void _dns_server_conn_head_init(struct dns_server_conn_head *conn, int fd, int type);

void _dns_server_conn_get(struct dns_server_conn_head *conn);

void _dns_server_conn_release(struct dns_server_conn_head *conn);

int _dns_server_epoll_ctl(struct dns_server_conn_head *head, int op, uint32_t events);

void _dns_server_close_socket(void);

int _dns_server_update_request_connection_timeout(struct dns_server_conn_head *conn, int timeout);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
