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

#ifndef _DNS_SERVER_HTTP2_H_
#define _DNS_SERVER_HTTP2_H_

#include "dns_server.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

/* Initialize HTTP/2 context for server connection */
int _dns_server_http2_init_context(struct dns_server_conn_tls_client *tls_client);

/* Destroy HTTP/2 context */
void _dns_server_http2_destroy_context(struct dns_server_conn_tls_client *tls_client);

/* Process HTTP/2 request and extract DNS query data */
int _dns_server_process_http2_request(struct dns_server_conn_tls_client *tls_client, unsigned char *data, int data_len,
									   unsigned char **request_data, int *request_len);

/* Send HTTP/2 DNS response */
int _dns_server_reply_http2(struct dns_request *request, struct dns_server_conn_tls_client *tls_client, void *packet,
							unsigned short len);

/* Check if data is HTTP/2 frame */
int _dns_server_is_http2_request(unsigned char *data, int data_len);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
