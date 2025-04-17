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

#ifndef _FAST_PING_FAKE_H_
#define _FAST_PING_FAKE_H_

#include "fast_ping.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _fast_ping_fake_put(struct fast_ping_fake_ip *fake);

void _fast_ping_fake_remove(struct fast_ping_fake_ip *fake);

void _fast_ping_fake_get(struct fast_ping_fake_ip *fake);

struct fast_ping_fake_ip *_fast_ping_fake_find(FAST_PING_TYPE ping_type, struct sockaddr *addr, int addr_len);

void _fast_ping_remove_all_fake_ip(void);

int _fast_ping_process_fake(struct ping_host_struct *ping_host, struct timeval *now);

int _fast_ping_send_fake(struct ping_host_struct *ping_host, struct fast_ping_fake_ip *fake);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_FAST_PING_H_
