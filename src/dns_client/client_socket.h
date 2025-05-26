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

#ifndef _DNS_CLIENT_CLIENT_SOCKET_
#define _DNS_CLIENT_CLIENT_SOCKET_

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_client_send_data_to_buffer(struct dns_server_info *server_info, void *packet, int len);

int _dns_client_copy_data_to_buffer(struct dns_server_info *server_info, void *packet, int len);

int _dns_client_socket_send(struct dns_server_info *server_info);

int _dns_client_socket_recv(struct dns_server_info *server_info);

int _dns_client_create_socket(struct dns_server_info *server_info);

void _dns_client_close_socket(struct dns_server_info *server_info);

void _dns_client_close_socket_ext(struct dns_server_info *server_info, int no_del_conn_list);

void _dns_client_shutdown_socket(struct dns_server_info *server_info);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
