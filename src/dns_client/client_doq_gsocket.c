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

#include "client_doq_gsocket.h"

#include "client_gsocket.h"
#include "client_gsocket_stream.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

int dns_client_doq_send_query(struct dns_query_struct *query, struct dns_server_info *server_info, void *packet,
							  int packet_data_len)
{
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;
	int inpacket_len = packet_data_len + 2;

	if (packet_data_len > (int)sizeof(inpacket_data) - 2) {
		errno = EMSGSIZE;
		return -1;
	}

	*((unsigned short *)inpacket) = htons(packet_data_len);
	memcpy(inpacket + 2, packet, packet_data_len);
	memset(inpacket + 2, 0, 2);

	return dns_client_gstream_send_query(server_info, query, DNS_SERVER_QUIC, inpacket, inpacket_len, GS_MSG_FIN,
										 packet, packet_data_len, NULL, NULL);
}

static int _dns_client_doq_process_response(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream)
{
	if (conn_stream->response_done) {
		return 1;
	}

	if (conn_stream->recv_buff.len < 2) {
		return 0;
	}

	int msg_len = ntohs(*((unsigned short *)(conn_stream->recv_buff.data)));
	if (msg_len <= 0) {
		errno = EPROTO;
		return -1;
	}

	if (msg_len > conn_stream->recv_buff.len - 2) {
		return 0;
	}

	if (conn_stream->query == NULL) {
		errno = EINVAL;
		return -1;
	}

	conn_stream->response_done = 1;
	dns_client_gstream_recv_response(server_info, conn_stream->query, conn_stream->recv_buff.data + 2, msg_len);
	return 1;
}

int dns_client_doq_process_stream(struct dns_server_info *server_info, struct gsocket *stream_gs,
								  struct dns_conn_stream *conn_stream)
{
	unsigned char buf[DNS_IN_PACKSIZE];
	int len = (int)gsocket_recv(stream_gs, buf, sizeof(buf), 0);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	if (len == 0) {
		if (conn_stream->type != DNS_SERVER_HTTP3) {
			int done = _dns_client_doq_process_response(server_info, conn_stream);
			return done >= 0 ? 1 : done;
		}
		return 1;
	}

	if (dns_client_gstream_append_recv(server_info, conn_stream, buf, len) != 0) {
		return -1;
	}

	if (conn_stream->type == DNS_SERVER_HTTP3) {
		return 0;
	}

	int done = _dns_client_doq_process_response(server_info, conn_stream);
	return done > 0 ? 0 : done;
}
