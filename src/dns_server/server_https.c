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

#include "server_https.h"
#include "connection.h"
#include "dns_server.h"
#include "server_socket.h"
#include "server_tcp.h"
#include "server_tls.h"

#include "smartdns/http2.h"

#include <errno.h>
#include <string.h>

int _dns_server_reply_http_error(struct dns_server_conn_tcp_client *tcpclient, int code, const char *code_msg,
								 const char *message)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char data[DNS_IN_PACKSIZE];
	int msg_len = strlen(message);

	http_len = snprintf((char *)data, DNS_IN_PACKSIZE,
						"HTTP/1.1 %d %s\r\n"
						"Content-Length: %d\r\n"
						"\r\n"
						"%s\r\n",
						code, code_msg, msg_len + 2, message);

	send_len = _dns_server_tcp_socket_send(tcpclient, data, http_len);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(tcpclient, data, http_len);
		}
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(tcpclient, data + send_len, http_len - send_len);
	}

	return 0;
}

int _dns_server_reply_https(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient, void *packet,
							unsigned short len)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	if (len > sizeof(inpacket_data)) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	http_len = snprintf((char *)inpacket, DNS_IN_PACKSIZE,
						"HTTP/1.1 200 OK\r\n"
						"Content-Type: application/dns-message\r\n"
						"Content-Length: %d\r\n"
						"\r\n",
						len);
	if (http_len < 0 || http_len >= DNS_IN_PACKSIZE) {
		tlog(TLOG_ERROR, "http header size is invalid.");
		return -1;
	}

	memcpy(inpacket + http_len, packet, len);
	http_len += len;

	send_len = _dns_server_tcp_socket_send(tcpclient, inpacket, http_len);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket, http_len);
		}
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket + send_len, http_len - send_len);
	}

	return 0;
}
