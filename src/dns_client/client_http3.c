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

#include "client_http3.h"
#include "client_quic.h"
#include "conn_stream.h"

#include "smartdns/http_parse.h"

int _dns_client_send_http3(struct dns_query_struct *query, struct dns_server_info *server_info, void *packet,
						   unsigned short len)
{
#ifdef OSSL_QUIC1_VERSION
	int http_len = 0;
	int ret = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	struct client_dns_server_flag_https *https_flag = NULL;
	struct http_head *http_head = NULL;

	if (len > sizeof(inpacket_data) - 128) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		goto errout;
	}

	https_flag = &server_info->flags.https;
	http_head = http_head_init(4096, HTTP_VERSION_3_0);
	if (http_head == NULL) {
		tlog(TLOG_ERROR, "init http head failed.");
		goto errout;
	}

	http_head_set_method(http_head, HTTP_METHOD_POST);
	http_head_set_url(http_head, https_flag->path);
	http_head_set_head_type(http_head, HTTP_HEAD_REQUEST);
	http_head_add_fields(http_head, ":authority", https_flag->httphost);
	http_head_add_fields(http_head, "user-agent", "smartdns");
	http_head_add_fields(http_head, "content-type", "application/dns-message");
	http_head_add_fields(http_head, "accept-encoding", "identity");
	http_head_set_data(http_head, packet, len);

	http_len = http_head_serialize(http_head, inpacket_data, DNS_IN_PACKSIZE);
	if (http_len <= 0) {
		tlog(TLOG_ERROR, "serialize http head failed.");
		goto errout;
	}

	ret = _dns_client_send_quic_data(query, server_info, inpacket_data, http_len);
	http_head_destroy(http_head);
	return ret;
errout:
	if (http_head) {
		http_head_destroy(http_head);
	}

	return -1;
#else
	tlog(TLOG_ERROR, "http3 is not supported.");
#endif
	return 0;
}

#ifdef OSSL_QUIC1_VERSION
int _dns_client_process_recv_http3(struct dns_server_info *server_info, struct dns_conn_stream *conn_stream)
{
	int ret = 0;
	struct http_head *http_head = NULL;
	uint8_t *pkg_data = NULL;
	int pkg_len = 0;

	http_head = http_head_init(4096, HTTP_VERSION_3_0);
	if (http_head == NULL) {
		goto errout;
	}

	ret = http_head_parse(http_head, conn_stream->recv_buff.data, conn_stream->recv_buff.len);
	if (ret < 0) {
		if (ret == -1) {
			goto out;
		} else if (ret == -3) {
			/* repsone is too large */
			tlog(TLOG_DEBUG, "http3 response is too large.");
			conn_stream->recv_buff.len = 0;
			_dns_client_conn_stream_put(conn_stream);
			goto errout;
		}

		tlog(TLOG_DEBUG, "remote server not supported.");
		goto errout;
	}

	if (http_head_get_httpcode(http_head) == 0) {
		/* invalid http3 response */
		server_info->prohibit = 1;
		goto errout;
	}

	if (http_head_get_httpcode(http_head) != 200) {
		tlog(TLOG_WARN, "http3 server query from %s:%d failed, server return http code : %d, %s", server_info->ip,
			 server_info->port, http_head_get_httpcode(http_head), http_head_get_httpcode_msg(http_head));
		server_info->prohibit = 1;
		goto errout;
	}

	pkg_data = (uint8_t *)http_head_get_data(http_head);
	pkg_len = http_head_get_data_len(http_head);
	if (pkg_data == NULL || pkg_len <= 0) {
		goto errout;
	}

	if (_dns_client_recv(server_info, pkg_data, pkg_len, &server_info->addr, server_info->ai_addrlen) != 0) {
		goto errout;
	}
out:
	http_head_destroy(http_head);
	return 0;
errout:

	if (http_head) {
		http_head_destroy(http_head);
	}

	return -1;
}
#endif