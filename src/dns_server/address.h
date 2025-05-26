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

#ifndef _DNS_SERVER_ADDRESS_
#define _DNS_SERVER_ADDRESS_

#include "dns_server.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _dns_server_select_possible_ipaddress(struct dns_request *request);

int _dns_ip_address_check_add(struct dns_request *request, char *cname, unsigned char *addr, dns_type_t addr_type,
							  int ping_time, struct dns_ip_address **out_addr_map);

struct dns_ip_address *_dns_ip_address_get(struct dns_request *request, unsigned char *addr, dns_type_t addr_type);

int _dns_server_process_address(struct dns_request *request);

int _dns_server_is_adblock_ipv6(const unsigned char addr[16]);

int _dns_server_address_generate_order(int orders[], int order_num, int max_order_count);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
