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

#ifndef _DNS_CLIENT_HTTP2_H
#define _DNS_CLIENT_HTTP2_H

#include "dns_client.h"
#include "server_info.h"

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Send DNS query over HTTP/2
 * @param server_info Server information
 * @param query DNS query structure
 * @param packet DNS query packet
 * @param len Packet length
 * @return 0 on success, -1 on error
 */
int _dns_client_send_http2(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
						   unsigned short len);

/**
 * Process HTTP/2 for a server (handles handshake and all streams)
 * @param server_info Server information
 * @param event Epoll event
 * @param now Current time
 * @return 0 on success, -1 on error
 */
int _dns_client_process_http2(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now);

#ifdef __cplusplus
}
#endif

#endif /* _DNS_CLIENT_HTTP2_H */
