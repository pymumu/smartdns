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

#include "server_http2.h"
#include "dns_server.h"
#include "server_https.h"
#include "server_tcp.h"

#include "../http_parse/http2_parse.h"

#include <errno.h>
#include <string.h>

int _dns_server_http2_init_context(struct dns_server_conn_tls_client *tls_client)
{
	if (tls_client->http2_ctx != NULL) {
		return 0;
	}

	/* Initialize HTTP/2 context for server (uses even stream IDs) */
	tls_client->http2_ctx = http2_context_init(1);
	if (tls_client->http2_ctx == NULL) {
		tlog(TLOG_ERROR, "Failed to initialize HTTP/2 context");
		return -1;
	}

	return 0;
}

void _dns_server_http2_destroy_context(struct dns_server_conn_tls_client *tls_client)
{
	if (tls_client->http2_ctx != NULL) {
		http2_context_destroy(tls_client->http2_ctx);
		tls_client->http2_ctx = NULL;
	}
}

int _dns_server_process_http2_request(struct dns_server_conn_tls_client *tls_client, unsigned char *data, int data_len,
									   unsigned char **request_data, int *request_len)
{
	struct http_head *http_head = NULL;
	int len = 0;

	/* Initialize HTTP/2 context if needed */
	if (tls_client->http2_ctx == NULL) {
		if (_dns_server_http2_init_context(tls_client) != 0) {
			return -1;
		}
	}

	/* Parse HTTP/2 frames */
	http_head = http_head_init(4096, HTTP_VERSION_2_0);
	if (http_head == NULL) {
		return -1;
	}

	len = http_head_parse(http_head, data, data_len);
	if (len < 0) {
		http_head_destroy(http_head);
		if (len == -1) {
			/* Need more data */
			return 0;
		}
		tlog(TLOG_DEBUG, "Failed to parse HTTP/2 frame");
		return -1;
	}

	/* Check if this is a POST request with DNS data */
	if (http_head_get_method(http_head) == HTTP_METHOD_POST) {
		const char *content_type = http_head_get_fields_value(http_head, "Content-Type");
		if (content_type == NULL ||
			strncasecmp(content_type, "application/dns-message", sizeof("application/dns-message")) != 0) {
			tlog(TLOG_DEBUG, "Invalid content type for DoH: %s", content_type);
			http_head_destroy(http_head);
			return -1;
		}

		*request_len = http_head_get_data_len(http_head);
		if (*request_len <= 0 || *request_len >= DNS_IN_PACKSIZE) {
			tlog(TLOG_DEBUG, "Invalid DNS request length: %d", *request_len);
			http_head_destroy(http_head);
			return -1;
		}

		*request_data = (unsigned char *)http_head_get_data(http_head);
	} else if (http_head_get_method(http_head) == HTTP_METHOD_GET) {
		/* GET requests not typically used in server-to-server DoH */
		tlog(TLOG_DEBUG, "GET method not supported in server HTTP/2");
		http_head_destroy(http_head);
		return -1;
	} else {
		tlog(TLOG_DEBUG, "Unsupported HTTP method");
		http_head_destroy(http_head);
		return -1;
	}

	/* Don't destroy http_head yet - request_data points to it */
	/* Caller must handle this */
	
	return len;
}

int _dns_server_reply_http2(struct dns_request *request, struct dns_server_conn_tls_client *tls_client, void *packet,
							unsigned short len)
{
	struct http_head *http_head = NULL;
	unsigned char response_buffer[DNS_IN_PACKSIZE];
	int response_len = 0;
	int ret = 0;

	/* Initialize HTTP/2 context if needed */
	if (tls_client->http2_ctx == NULL) {
		if (_dns_server_http2_init_context(tls_client) != 0) {
			return -1;
		}
	}

	/* Build HTTP/2 response */
	http_head = http_head_init(4096, HTTP_VERSION_2_0);
	if (http_head == NULL) {
		return -1;
	}

	http_head->head_type = HTTP_HEAD_RESPONSE;
	http_head->code = 200;
	http_head->data = packet;
	http_head->data_len = len;

	/* Set response headers */
	http_head_add_fields(http_head, "Content-Type", "application/dns-message");

	/* Serialize HTTP/2 response */
	response_len = http_head_serialize_http2_0(http_head, response_buffer, sizeof(response_buffer));
	if (response_len < 0) {
		tlog(TLOG_ERROR, "Failed to serialize HTTP/2 response");
		http_head_destroy(http_head);
		return -1;
	}

	http_head_destroy(http_head);

	/* Send response */
	ret = _dns_server_tcp_socket_send(&tls_client->tcp, response_buffer, response_len);
	if (ret < 0) {
		if (errno == EAGAIN) {
			return _dns_server_reply_tcp_to_buffer(&tls_client->tcp, response_buffer, response_len);
		}
		return -1;
	} else if (ret < response_len) {
		return _dns_server_reply_tcp_to_buffer(&tls_client->tcp, response_buffer + ret, response_len - ret);
	}

	return 0;
}

int _dns_server_is_http2_request(unsigned char *data, int data_len)
{
	/* HTTP/2 frame starts with 24-bit length + 8-bit type + 8-bit flags + 32-bit stream ID
	 * HTTP/1.x starts with method name ("GET", "POST", etc) or "HTTP/"
	 * 
	 * Check if this looks like an HTTP/2 frame:
	 * - First byte is NOT 'H', 'G', 'P', 'D', etc. (HTTP/1.x methods or response)
	 * - Minimum frame is 9 bytes (frame header)
	 */
	if (data_len < 9) {
		return 0;
	}

	/* HTTP/1.x always starts with ASCII characters */
	if (data[0] == 'H' || data[0] == 'G' || data[0] == 'P' || data[0] == 'D' || 
		data[0] == 'O' || data[0] == 'T' || data[0] == 'C') {
		return 0;
	}

	/* HTTP/2 frames typically have small lengths in first 3 bytes */
	/* And frame type in byte 3 should be <= 9 (CONTINUATION) */
	if (data[3] <= 9) {
		return 1;
	}

	return 0;
}
