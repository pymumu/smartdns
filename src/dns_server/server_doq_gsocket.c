/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "server_doq_gsocket.h"

#include "connection.h"
#include "dns_server.h"
#include "server_gsocket_stream.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

int dns_server_doq_process_request(struct dns_server_conn_gsocket *parent, struct gsocket *stream_gs,
								   struct dns_server_gstream_buffer *recv_buff)
{
	if (recv_buff == NULL) {
		return -1;
	}

	while (recv_buff->len < (int)sizeof(recv_buff->data)) {
		ssize_t n =
			gsocket_recv(stream_gs, recv_buff->data + recv_buff->len, sizeof(recv_buff->data) - recv_buff->len, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}
			return -1;
		}

		if (n == 0) {
			break;
		}

		recv_buff->len += n;
		if (recv_buff->len >= 2) {
			break;
		}
	}

	if (recv_buff->len < 2) {
		return -EAGAIN;
	}

	int doq_len = ((int)recv_buff->data[0] << 8) | recv_buff->data[1];
	if (doq_len <= 0 || doq_len > DNS_IN_PACKSIZE - 2) {
		return -1;
	}

	while (recv_buff->len < doq_len + 2) {
		ssize_t n = gsocket_recv(stream_gs, recv_buff->data + recv_buff->len, doq_len + 2 - recv_buff->len, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return -EAGAIN;
			}
			return -1;
		}

		if (n == 0) {
			return -1;
		}

		recv_buff->len += n;
	}

	if (dns_server_gstream_dispatch_query(parent, stream_gs, DNS_CONN_TYPE_QUIC_STREAM, recv_buff->data + 2,
										  doq_len) != 0) {
		return -1;
	}

	return 0;
}

int dns_server_doq_reply(struct gsocket *stream, unsigned char *inpacket, int inpacket_len)
{
	if (stream == NULL) {
		return -1;
	}

	if (inpacket_len > DNS_IN_PACKSIZE - 2) {
		return -1;
	}

	unsigned char outpacket[DNS_IN_PACKSIZE];
	*((unsigned short *)outpacket) = htons(inpacket_len);
	memcpy(outpacket + 2, inpacket, inpacket_len);

	return gsocket_send_all(stream, outpacket, inpacket_len + 2, MSG_NOSIGNAL | GS_MSG_FIN);
}
