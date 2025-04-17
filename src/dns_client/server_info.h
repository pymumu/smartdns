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

#ifndef _DNS_CLIENT_SERVER_INFO_
#define _DNS_CLIENT_SERVER_INFO_

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _dns_server_inc_prohibit_server_num(struct dns_server_info *server_info);

void _dns_server_dec_prohibit_server_num(struct dns_server_info *server_info);

void _dns_client_server_close(struct dns_server_info *server_info);

const char *_dns_server_get_type_string(dns_server_type_t type);

void _dns_client_server_remove_all(void);

struct dns_server_info *_dns_client_get_server(const char *server_ip, int port, dns_server_type_t server_type,
											   const struct client_dns_server_flags *flags);

int _dns_client_server_add(const char *server_ip, const char *server_host, int port, dns_server_type_t server_type,
						   struct client_dns_server_flags *flags);

void _dns_client_check_servers(void);
#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
