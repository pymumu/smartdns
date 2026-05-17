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

#include "client_doh_gsocket.h"

#include "client_gsocket.h"
#include "client_gsocket_stream.h"
#include "query.h"

#include <errno.h>
#include <string.h>

static int _dns_client_build_doh_headers(struct dns_server_info *server_info, char *headers, int headers_len)
{
	const char *httphost = server_info->flags.https.httphost[0] ? server_info->flags.https.httphost : server_info->ip;
	int hdr_len =
		snprintf(headers, headers_len,
				 "content-type: application/dns-message\r\naccept: application/dns-message\r\nhost: %s\r\n", httphost);
	if (hdr_len <= 0 || hdr_len >= headers_len) {
		errno = ENOMEM;
		return -1;
	}

	return hdr_len;
}

static int _dns_client_doh_prepare_stream(struct dns_server_info *server_info, struct gsocket *stream_gs,
										  void *user_data)
{
	(void)user_data;
	const char *path = server_info->flags.https.path[0] ? server_info->flags.https.path : "/dns-query";
	char headers[512];
	int hdr_len = _dns_client_build_doh_headers(server_info, headers, sizeof(headers));
	if (hdr_len < 0) {
		return -1;
	}

	gsocket_setsockopt(stream_gs, SOL_HTTP, SO_HTTP_METHOD, "POST", 5);
	gsocket_setsockopt(stream_gs, SOL_HTTP, SO_HTTP_URL, path, strlen(path) + 1);
	gsocket_setsockopt(stream_gs, SOL_HTTP, SO_HTTP_HEADER, headers, hdr_len + 1);
	return 0;
}

int dns_client_doh_send_query(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet,
							  int packet_data_len, dns_server_type_t type)
{
	return dns_client_gstream_send_query(server_info, query, type, packet, packet_data_len, GS_MSG_FIN, packet,
										 packet_data_len, _dns_client_doh_prepare_stream, NULL);
}

int dns_client_doh_send_http1(struct dns_server_info *server_info, void *packet, int packet_data_len)
{
	int ret = 0;

	pthread_mutex_lock(&server_info->lock);

	if (server_info->gs == NULL) {
		errno = EBADF;
		ret = -1;
		goto out;
	}

	const char *path = server_info->flags.https.path[0] ? server_info->flags.https.path : "/dns-query";
	char headers[512];
	int hdr_len = _dns_client_build_doh_headers(server_info, headers, sizeof(headers));
	if (hdr_len < 0) {
		ret = -1;
		goto out;
	}

	gsocket_setsockopt(server_info->gs, SOL_HTTP, SO_HTTP_METHOD, "POST", 5);
	gsocket_setsockopt(server_info->gs, SOL_HTTP, SO_HTTP_URL, path, strlen(path) + 1);
	gsocket_setsockopt(server_info->gs, SOL_HTTP, SO_HTTP_HEADER, headers, hdr_len + 1);

	if (DNS_TCP_BUFFER - server_info->send_buff.len < packet_data_len) {
		errno = ENOMEM;
		ret = -1;
		goto out;
	}

	unsigned char *dst = server_info->send_buff.data + server_info->send_buff.len;
	memcpy(dst, packet, packet_data_len);
	server_info->send_buff.len += packet_data_len;

	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
		goto out;
	}

	int send_ret = _dns_client_socket_tcp_send(server_info);
	if (send_ret < 0 && errno == EAGAIN) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
		goto out;
	}
	if (send_ret < 0) {
		ret = -1;
		goto out;
	}

	if (server_info->send_buff.len > 0) {
		gepoll_mod(client.gepoll, server_info->gs, EPOLLIN | EPOLLOUT, server_info);
	}

out:
	pthread_mutex_unlock(&server_info->lock);
	return ret;
}

int dns_client_doh_process_stream(struct dns_server_info *server_info, struct gsocket *stream_gs,
								  struct dns_conn_stream *conn_stream)
{
	unsigned char buf[DNS_IN_PACKSIZE];
	int status = 0;
	socklen_t status_len = sizeof(status);

	for (;;) {
		int len = (int)gsocket_recv(stream_gs, buf, sizeof(buf), MSG_DONTWAIT);

		if (gsocket_getsockopt(stream_gs, SOL_HTTP, SO_HTTP_STATUS, &status, &status_len) == 0) {
			if (status != 0 && status != 200) {
				tlog(TLOG_INFO, "%s server %s return error: %d",
					 (server_info->type == DNS_SERVER_HTTP3) ? "HTTP3" : "HTTPS", server_info->ip, status);
				return -1;
			}
		}

		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				break;
			}
			return -1;
		}
		if (len == 0) {
			if (conn_stream->recv_buff.len > 0) {
				conn_stream->response_done = 1;
				dns_client_gstream_recv_response(server_info, conn_stream->query, conn_stream->recv_buff.data,
												 conn_stream->recv_buff.len);
				conn_stream->recv_buff.len = 0;
			}
			return 1;
		}

		if (dns_client_gstream_append_recv(server_info, conn_stream, buf, len) != 0) {
			return -1;
		}
	}

	return 0;
}
