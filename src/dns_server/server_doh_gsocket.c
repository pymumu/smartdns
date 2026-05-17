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

#include "server_doh_gsocket.h"

#include "connection.h"
#include "dns_server.h"
#include "server_gsocket_stream.h"

#include "smartdns/util.h"

#include <errno.h>
#include <openssl/ssl.h>
#include <string.h>

static int _dns_server_doh_send_error(struct gsocket *stream_gs, int status, const char *body)
{
	gsocket_setsockopt(stream_gs, SOL_HTTP, SO_HTTP_STATUS, &status, sizeof(status));
	return gsocket_send_all(stream_gs, body, strlen(body), MSG_NOSIGNAL | GS_MSG_FIN);
}

int dns_server_doh_process_request(struct dns_server_conn_gsocket *parent, struct gsocket *stream_gs)
{
	uint8_t buf[DNS_IN_PACKSIZE];
	int len = 0;
	ssize_t n = 0;
	int err_status = 0;
	const char *err_body = NULL;

	char method[16] = {0};
	socklen_t mlen = sizeof(method) - 1;
	gsocket_getsockopt(stream_gs, SOL_HTTP, SO_HTTP_METHOD, method, &mlen);
	method[mlen] = '\0';

	if (method[0] == '\0') {
		n = gsocket_recv(stream_gs, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return -EAGAIN;
			}
			return -1;
		}
		mlen = sizeof(method) - 1;
		gsocket_getsockopt(stream_gs, SOL_HTTP, SO_HTTP_METHOD, method, &mlen);
		method[mlen] = '\0';
		if (method[0] == '\0') {
			return -EAGAIN;
		}
	}

	if (strcasecmp(method, "POST") == 0) {
		if (n == 0) {
			n = gsocket_recv(stream_gs, buf, sizeof(buf), 0);
		}
		if (n <= 0) {
			if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return -EAGAIN;
			}
			return -1;
		}
		len = (int)n;
	} else if (strcasecmp(method, "GET") == 0) {
		char url[512] = {0};
		socklen_t ulen = sizeof(url) - 1;
		if (gsocket_getsockopt(stream_gs, SOL_HTTP, SO_HTTP_URL, url, &ulen) != 0) {
			err_status = 404;
			err_body = "Not Found";
			goto send_error;
		}
		url[ulen] = '\0';

		if (strncmp(url, "/dns-query", 10) != 0) {
			err_status = 404;
			err_body = "Not Found";
			goto send_error;
		}

		char *qmark = strchr(url, '?');
		char *dns_param = NULL;
		if (qmark) {
			char *p = qmark + 1;
			while (p && *p) {
				if (strncmp(p, "dns=", 4) == 0) {
					dns_param = p + 4;
					break;
				}
				p = strchr(p, '&');
				if (p) {
					p++;
				}
			}
		}

		if (dns_param == NULL) {
			err_status = 404;
			err_body = "Not Found";
			goto send_error;
		}

		char decoded[DNS_IN_PACKSIZE];
		if (urldecode(decoded, sizeof(decoded), dns_param) < 0) {
			err_status = 400;
			err_body = "Bad Request";
			goto send_error;
		}

		len = SSL_base64_decode_ext(decoded, buf, sizeof(buf), 1, 1);
		if (len <= 0) {
			err_status = 400;
			err_body = "Bad Request";
			goto send_error;
		}

		gsocket_recv(stream_gs, NULL, 0, 0);
	} else {
		err_status = 405;
		err_body = "Method Not Allowed";
		goto send_error;
	}

	if (len > 0) {
		if (dns_server_gstream_dispatch_query(parent, stream_gs, DNS_CONN_TYPE_HTTP2_STREAM, buf, len) != 0) {
			err_status = 500;
			err_body = "Internal Server Error";
			goto send_error;
		}
		return 1;
	}

	return 0;
send_error:
	_dns_server_doh_send_error(stream_gs, err_status, err_body);
	return 0;
}

int dns_server_doh_reply(struct gsocket *stream, unsigned char *inpacket, int inpacket_len)
{
	if (stream == NULL) {
		return -1;
	}

	const char *ct = "content-type: application/dns-message";
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_HEADER, ct, (socklen_t)strlen(ct));

	size_t clen = (size_t)inpacket_len;
	gsocket_setsockopt(stream, SOL_HTTP, SO_HTTP_BODY_LEN, &clen, sizeof(clen));

	return gsocket_send_all(stream, inpacket, inpacket_len, MSG_NOSIGNAL | GS_MSG_FIN);
}
