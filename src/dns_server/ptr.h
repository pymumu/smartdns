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

#ifndef _DNS_SERVER_PTR_
#define _DNS_SERVER_PTR_

#include "dns_server.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_server_get_local_ttl(struct dns_request *request);

int _dns_server_process_local_ptr(struct dns_request *request);

int _dns_server_process_ptrs(struct dns_request *request);

int _dns_server_process_ptr(struct dns_request *request);

int _dns_server_get_inet_by_addr(struct sockaddr_storage *localaddr, struct sockaddr_storage *addr, int family);

int _dns_server_process_ptr_query(struct dns_request *request);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
