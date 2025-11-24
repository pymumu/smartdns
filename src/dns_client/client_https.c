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
#define _GNU_SOURCE

#include "client_https.h"
#include "client_socket.h"
#include "client_tls.h"
#include "server_info.h"

#include "smartdns/http_parse.h"

int _dns_client_format_https_packet(struct dns_server_info *server_info, void *packet, unsigned short len,
									unsigned char *outpacket, int outpacket_max)
{
	int http_len = 0;
	struct client_dns_server_flag_https *https_flag = NULL;

	if (len > outpacket_max - 2) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	https_flag = &server_info->flags.https;

	http_len = snprintf((char *)outpacket, outpacket_max,
						"POST %s HTTP/1.1\r\n"
						"Host: %s\r\n"
						"User-Agent: smartdns\r\n"
						"Content-Type: application/dns-message\r\n"
						"Accept: application/dns-message\r\n"
						"Content-Length: %d\r\n"
						"\r\n",
						https_flag->path, https_flag->httphost, len);
	if (http_len < 0 || http_len >= outpacket_max) {
		tlog(TLOG_ERROR, "http header size is invalid.");
		return -1;
	}

	memcpy(outpacket + http_len, packet, len);
	http_len += len;

	return http_len;
}

int _dns_client_send_http1(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	http_len = _dns_client_format_https_packet(server_info, packet, len, inpacket, sizeof(inpacket_data));
	if (http_len < 0) {
		return -1;
	}

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, http_len);
	}

	if (server_info->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	send_len = _dns_client_socket_ssl_send(server_info, inpacket, http_len);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, http_len);
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, http_len - send_len);
	}

	return 0;
}
