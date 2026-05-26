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

#include "gtest/gtest.h"

#include <cerrno>
#include <cstring>
#include <openssl/ssl.h>

#include "dns_client/client_http3.h"
#include "smartdns/http_parse.h"

class ClientHTTP3 : public ::testing::Test
{
};

TEST_F(ClientHTTP3, incomplete_response_keeps_stream_pending)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	unsigned char response[1024];
	const unsigned char dns_payload[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01};

	struct http_head *http_head = http_head_init(sizeof(response), HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);
	http_head_set_httpversion(http_head, "HTTP/3");
	http_head_set_httpcode(http_head, 200, "OK");
	http_head_add_fields(http_head, "content-type", "application/dns-message");
	http_head_set_data(http_head, dns_payload, sizeof(dns_payload));
	http_head_set_head_type(http_head, HTTP_HEAD_RESPONSE);

	int response_len = http_head_serialize(http_head, response, sizeof(response));
	http_head_destroy(http_head);
	ASSERT_GT(response_len, 1);

	int partial_len = response_len - 1;
	http_head = http_head_init(sizeof(response), HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);
	EXPECT_EQ(http_head_parse(http_head, response, partial_len), -1);
	http_head_destroy(http_head);

	struct dns_server_info server_info;
	memset(&server_info, 0, sizeof(server_info));
	server_info.type = DNS_SERVER_HTTP3;

	struct dns_conn_stream conn_stream;
	memset(&conn_stream, 0, sizeof(conn_stream));
	memcpy(conn_stream.recv_buff.data, response, partial_len);
	conn_stream.recv_buff.len = partial_len;

	errno = 0;
	EXPECT_EQ(_dns_client_process_recv_http3(&server_info, &conn_stream), 1);
	EXPECT_EQ(errno, EAGAIN);
	EXPECT_EQ(conn_stream.recv_buff.len, partial_len);
#else
	GTEST_SKIP() << "OpenSSL QUIC support is not enabled";
#endif
}
