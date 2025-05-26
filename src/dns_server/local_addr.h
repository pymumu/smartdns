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

#ifndef _DNS_SERVER_LOCAL_ADDR_
#define _DNS_SERVER_LOCAL_ADDR_

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_server_local_addr_cache_destroy(void);

int _dns_server_local_addr_cache_init(void);

void _dns_server_process_local_addr_cache(int fd_netlink, struct epoll_event *event, unsigned long now);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
