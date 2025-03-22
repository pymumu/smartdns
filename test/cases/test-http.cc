/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "client.h"
#include "dns.h"
#include "http_parse.h"
#include "include/utils.h"
#include "server.h"
#include "util.h"
#include "gtest/gtest.h"
#include <fstream>

class HTTP : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(HTTP, http1_1_request_parse)
{
	const char *data = "GET /?q=question&lang=cn HTTP/1.1\r\n"
					   "Host: www.example.com\r\n"
					   "User-Agent: smartdns/46\r\n"
					   "Accept: */*\r\n"
					   "\r\n"
					   "hello world";
	struct http_head *http_head = http_head_init(1024, HTTP_VERSION_1_1);
	ASSERT_NE(http_head, nullptr);
	int ret = http_head_parse(http_head, (const unsigned char *)data, strlen(data));
	ASSERT_GT(ret, 0);
	EXPECT_STREQ(http_head_get_httpversion(http_head), "HTTP/1.1");
	EXPECT_EQ(http_head_get_method(http_head), HTTP_METHOD_GET);
	EXPECT_STREQ(http_head_get_url(http_head), "/");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Host"), "www.example.com");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "User-Agent"), "smartdns/46");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Accept"), "*/*");
	EXPECT_STREQ((const char *)http_head_get_data(http_head), "hello world");
	EXPECT_STREQ(http_head_get_params_value(http_head, "q"), "question");
	EXPECT_STREQ(http_head_get_params_value(http_head, "lang"), "cn");

	http_head_destroy(http_head);
}

TEST_F(HTTP, http1_1_request_serialize)
{
	const char *data = "GET /?q=question&lang=cn HTTP/1.1\r\n"
					   "Host: www.example.com\r\n"
					   "User-Agent: smartdns/46\r\n"
					   "Accept: */*\r\n"
					   "\r\n"
					   "hello world";
	struct http_head *http_head = http_head_init(1024, HTTP_VERSION_1_1);
	ASSERT_NE(http_head, nullptr);
	http_head_set_httpversion(http_head, "HTTP/1.1");
	http_head_set_method(http_head, HTTP_METHOD_GET);
	http_head_set_url(http_head, "/");
	http_head_add_fields(http_head, "Host", "www.example.com");
	http_head_add_fields(http_head, "User-Agent", "smartdns/46");
	http_head_add_fields(http_head, "Accept", "*/*");
	http_head_set_data(http_head, "hello world", strlen("hello world") + 1);
	http_head_set_head_type(http_head, HTTP_HEAD_REQUEST);
	http_head_add_param(http_head, "q", "question");
	http_head_add_param(http_head, "lang", "cn");
	char buffer[1024];
	int ret = http_head_serialize(http_head, buffer, 1024);
	ASSERT_GT(ret, 0);
	EXPECT_STREQ(buffer, data);
	http_head_destroy(http_head);
}

TEST_F(HTTP, http1_1_response_parse)
{
	const char *data = "HTTP/1.1 200 OK\r\n"
					   "Server: smartdns\r\n"
					   "Content-Type: text/html\r\n"
					   "Content-Length: 11\r\n"
					   "\r\n"
					   "hello world";
	struct http_head *http_head = http_head_init(1024, HTTP_VERSION_1_1);
	ASSERT_NE(http_head, nullptr);
	int ret = http_head_parse(http_head, (const unsigned char *)data, strlen(data));
	ASSERT_GT(ret, 0);
	EXPECT_STREQ(http_head_get_httpversion(http_head), "HTTP/1.1");
	EXPECT_EQ(http_head_get_httpcode(http_head), 200);
	EXPECT_STREQ(http_head_get_httpcode_msg(http_head), "OK");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Server"), "smartdns");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Content-Type"), "text/html");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Content-Length"), "11");
	EXPECT_STREQ((const char *)http_head_get_data(http_head), "hello world");

	http_head_destroy(http_head);
}

TEST_F(HTTP, http1_1_response_serialize)
{
	const char *data = "HTTP/1.1 200 OK\r\n"
					   "Server: smartdns\r\n"
					   "Content-Type: text/html\r\n"
					   "Content-Length: 11\r\n"
					   "\r\n"
					   "hello world";
	struct http_head *http_head = http_head_init(1024, HTTP_VERSION_1_1);
	ASSERT_NE(http_head, nullptr);

	http_head_set_httpversion(http_head, "HTTP/1.1");
	http_head_set_httpcode(http_head, 200, "OK");
	http_head_add_fields(http_head, "Server", "smartdns");
	http_head_add_fields(http_head, "Content-Type", "text/html");
	http_head_add_fields(http_head, "Content-Length", "11");
	http_head_set_data(http_head, "hello world", strlen("hello world") + 1);
	http_head_set_head_type(http_head, HTTP_HEAD_RESPONSE);
	char buffer[1024];

	int ret = http_head_serialize(http_head, buffer, 1024);
	ASSERT_GT(ret, 0);
	EXPECT_STREQ(buffer, data);
	http_head_destroy(http_head);
}


TEST_F(HTTP, http3_0_parse)
{
	struct http_head *http_head = http_head_init(1024, HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);
	http_head_set_httpversion(http_head, "HTTP/3");
	http_head_set_method(http_head, HTTP_METHOD_GET);
	http_head_set_url(http_head, "/");
	http_head_add_fields(http_head, "Host", "www.example.com");
	http_head_add_fields(http_head, "User-Agent", "smartdns/46");
	http_head_add_fields(http_head, "Accept", "*/*");
	http_head_set_data(http_head, "hello world", strlen("hello world") + 1);
	http_head_set_head_type(http_head, HTTP_HEAD_REQUEST);
	http_head_add_param(http_head, "q", "question");
	http_head_add_param(http_head, "lang", "cn");
	unsigned char buffer[1024];
	int ret = http_head_serialize(http_head, buffer, 1024);
	ASSERT_EQ(ret, 149);
	http_head_destroy(http_head);

	http_head = http_head_init(1024, HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);

	ret = http_head_parse(http_head, buffer, ret);
	ASSERT_EQ(ret, 149);
	EXPECT_STREQ(http_head_get_httpversion(http_head), "HTTP/3.0");
	EXPECT_EQ(http_head_get_method(http_head), HTTP_METHOD_GET);
	EXPECT_STREQ(http_head_get_url(http_head), "/");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Host"), "www.example.com");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "User-Agent"), "smartdns/46");
	EXPECT_STREQ(http_head_get_fields_value(http_head, "Accept"), "*/*");
	EXPECT_STREQ((const char *)http_head_get_data(http_head), "hello world");
	EXPECT_STREQ(http_head_get_params_value(http_head, "q"), "question");
	EXPECT_STREQ(http_head_get_params_value(http_head, "lang"), "cn");

	http_head_destroy(http_head);
}