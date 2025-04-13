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

#ifndef _DNS_CLIENT_PENDING_SERVER_
#define _DNS_CLIENT_PENDING_SERVER_

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

struct addrinfo *_dns_client_getaddr(const char *host, char *port, int type, int protocol);

int _dns_client_add_server_pending(const char *server_ip, const char *server_host, int port,
								   dns_server_type_t server_type, struct client_dns_server_flags *flags,
								   int is_pending);

int _dns_client_add_to_pending_group(const char *group_name, const char *server_ip, int port,
									 dns_server_type_t server_type, const struct client_dns_server_flags *flags);

int _dns_client_add_to_group_pending(const char *group_name, const char *server_ip, int port,
									 dns_server_type_t server_type, const struct client_dns_server_flags *flags,
									 int is_pending);

void _dns_client_remove_all_pending_servers(void);

void _dns_client_add_pending_servers(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
