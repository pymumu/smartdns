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
 *
 *************************************************************************/

#ifndef _SERVER_HTTP2_H_
#define _SERVER_HTTP2_H_

#include "dns_server.h"
#include "smartdns/http2.h"
#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dns_server_conn_http2_stream {
	struct dns_server_conn_head head;
	struct http2_stream *stream;
	struct dns_server_conn_tls_client *tls_client;
};

int _dns_server_process_http2(struct dns_server_conn_tls_client *tls_client, struct epoll_event *event,
							  unsigned long now);

int _dns_server_reply_http2(struct dns_request *request, struct dns_server_conn_http2_stream *stream_conn,
							unsigned char *inpacket, int inpacket_len);

#ifdef __cplusplus
}
#endif

#endif
