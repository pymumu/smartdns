/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef _SMART_DNS_SERVER_H
#define _SMART_DNS_SERVER_H

#include "dns.h"
#include <stdint.h>

#ifdef __cpluscplus
extern "C" {
#endif

int dns_server_init(void);

int dns_server_run(void);

int dns_server_start(void);

void dns_server_stop(void);

void dns_server_exit(void);

/* query result notify function */
typedef int (*dns_result_callback)(char *domain, dns_rtcode_t rtcode, dns_type_t addr_type, char *ip,
								   unsigned int ping_time, void *user_ptr);

/* query domain */
int dns_server_query(char *domain, int qtype, uint32_t server_flags, dns_result_callback callback, void *user_ptr);

#ifdef __cpluscplus
}
#endif
#endif
