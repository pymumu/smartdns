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

#ifndef _FAST_PING_ICMP_H_
#define _FAST_PING_ICMP_H_

#include "fast_ping.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _fast_ping_sendping_v4(struct ping_host_struct *ping_host);

struct fast_ping_packet *_fast_ping_icmp_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
												u_char *packet_data, int data_len);

int _fast_ping_sockaddr_ip_cmp(struct sockaddr *first_addr, socklen_t first_addr_len, struct sockaddr *second_addr,
							   socklen_t second_addr_len);

uint16_t _fast_ping_checksum(uint16_t *header, size_t len);

int _fast_ping_icmp_create_socket(struct ping_host_struct *ping_host);

int _fast_ping_process_icmp(struct ping_host_struct *ping_host, struct timeval *now);

int _fast_ping_get_addr_by_icmp(const char *ip_str, int port, struct addrinfo **out_gai, FAST_PING_TYPE *out_ping_type);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_FAST_PING_ICMP_H_
