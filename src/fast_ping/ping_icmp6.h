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

#ifndef _FAST_PING_ICMP6_H_
#define _FAST_PING_ICMP6_H_

#include "fast_ping.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

struct fast_ping_packet *_fast_ping_icmp6_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
												 u_char *packet_data, int data_len);

void _fast_ping_install_filter_v6(int sock);

int _fast_ping_sendping_v6(struct ping_host_struct *ping_host);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_FAST_PING_ICMP6_H_
