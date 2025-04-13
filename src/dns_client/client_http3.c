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
