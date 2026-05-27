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
#include <vector>

#include "dns_client/client_http3.h"
#include "smartdns/http_parse.h"

class ClientHTTP3 : public ::testing::Test
{
};

static int quic_varint_decode_for_test(const unsigned char *buffer, int buffer_len, uint64_t *value)
{
	if ((buffer[0] & 0xC0) == 0x00) {
		if (buffer_len < 1) {
			return -1;
		}

		*value = buffer[0];
		return 1;
	} else if ((buffer[0] & 0xC0) == 0x40) {
		if (buffer_len < 2) {
			return -1;
		}

		*value = ((uint64_t)(buffer[0] & 0x3F) << 8) | buffer[1];
		return 2;
	} else if ((buffer[0] & 0xC0) == 0x80) {
		if (buffer_len < 4) {
			return -1;
		}

		*value = ((uint64_t)(buffer[0] & 0x3F) << 24) | ((uint64_t)buffer[1] << 16) |
				 ((uint64_t)buffer[2] << 8) | buffer[3];
		return 4;
	}

	if (buffer_len < 8) {
		return -1;
	}

	*value = ((uint64_t)(buffer[0] & 0x3F) << 56) | ((uint64_t)buffer[1] << 48) |
			 ((uint64_t)buffer[2] << 40) | ((uint64_t)buffer[3] << 32) | ((uint64_t)buffer[4] << 24) |
			 ((uint64_t)buffer[5] << 16) | ((uint64_t)buffer[6] << 8) | buffer[7];
	return 8;
}

static int quic_varint_encode_for_test(uint64_t value, unsigned char *buffer, int buffer_len)
{
	if (value <= 63) {
		if (buffer_len < 1) {
			return -1;
		}

		buffer[0] = (unsigned char)value;
		return 1;
	}

	return -1;
}

static std::vector<unsigned char> first_http3_data_frame_fragment(const unsigned char *response, int response_len,
																  int partial_body_len)
{
	int offset = 0;
	uint64_t frame_type = 0;
	uint64_t frame_len = 0;

	while (offset < response_len) {
		int offset_ret = quic_varint_decode_for_test(response + offset, response_len - offset, &frame_type);
		if (offset_ret < 0) {
			return {};
		}
		offset += offset_ret;

		int frame_len_offset = offset;
		offset_ret = quic_varint_decode_for_test(response + offset, response_len - offset, &frame_len);
		if (offset_ret < 0) {
			return {};
		}
		offset += offset_ret;

		if (frame_len > (uint64_t)(response_len - offset)) {
			return {};
		}

		if (frame_type == 0) {
			unsigned char encoded_len[8];
			int encoded_len_size = quic_varint_encode_for_test(partial_body_len, encoded_len, sizeof(encoded_len));
			if (encoded_len_size < 0 || partial_body_len <= 0 || (uint64_t)partial_body_len >= frame_len) {
				return {};
			}

			std::vector<unsigned char> fragment(response, response + frame_len_offset);
			fragment.insert(fragment.end(), encoded_len, encoded_len + encoded_len_size);
			fragment.insert(fragment.end(), response + offset, response + offset + partial_body_len);
			return fragment;
		}

		offset = offset + frame_len;
	}

	return {};
}

static std::vector<unsigned char> http3_response_before_first_data_frame(const unsigned char *response, int response_len)
{
	int offset = 0;
	uint64_t frame_type = 0;
	uint64_t frame_len = 0;

	while (offset < response_len) {
		int frame_start = offset;
		int offset_ret = quic_varint_decode_for_test(response + offset, response_len - offset, &frame_type);
		if (offset_ret < 0) {
			return {};
		}
		offset += offset_ret;

		offset_ret = quic_varint_decode_for_test(response + offset, response_len - offset, &frame_len);
		if (offset_ret < 0) {
			return {};
		}
		offset += offset_ret;

		if (frame_len > (uint64_t)(response_len - offset)) {
			return {};
		}

		if (frame_type == 0) {
			return std::vector<unsigned char>(response, response + frame_start);
		}

		offset = offset + frame_len;
	}

	return {};
}

static std::vector<unsigned char> http3_response_without_content_length(const unsigned char *body, int body_len)
{
	unsigned char header[1024];
	struct http_head *http_head = http_head_init(sizeof(header), HTTP_VERSION_3_0);
	if (http_head == nullptr) {
		return {};
	}

	http_head_set_httpversion(http_head, "HTTP/3");
	http_head_set_httpcode(http_head, 200, "OK");
	http_head_add_fields(http_head, "content-type", "application/dns-message");
	http_head_set_head_type(http_head, HTTP_HEAD_RESPONSE);

	int header_len = http_head_serialize(http_head, header, sizeof(header));
	http_head_destroy(http_head);
	if (header_len <= 0) {
		return {};
	}

	unsigned char encoded_len[8];
	int encoded_len_size = quic_varint_encode_for_test(body_len, encoded_len, sizeof(encoded_len));
	if (encoded_len_size < 0) {
		return {};
	}

	std::vector<unsigned char> response(header, header + header_len);
	response.push_back(0);
	response.insert(response.end(), encoded_len, encoded_len + encoded_len_size);
	response.insert(response.end(), body, body + body_len);
	return response;
}

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

TEST_F(ClientHTTP3, split_data_frame_with_content_length_keeps_stream_pending)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	unsigned char response[1024];
	const unsigned char dns_payload[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
										 0x00, 0x00, 0x00, 0x00, 0x01, 'a',  0x03, 'c',
										 'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01};

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

	std::vector<unsigned char> first_fragment = first_http3_data_frame_fragment(response, response_len, 12);
	ASSERT_FALSE(first_fragment.empty());

	http_head = http_head_init(sizeof(response), HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);
	EXPECT_EQ(http_head_parse(http_head, first_fragment.data(), first_fragment.size()), -1);
	http_head_destroy(http_head);

	struct dns_server_info server_info;
	memset(&server_info, 0, sizeof(server_info));
	server_info.type = DNS_SERVER_HTTP3;

	struct dns_conn_stream conn_stream;
	memset(&conn_stream, 0, sizeof(conn_stream));
	memcpy(conn_stream.recv_buff.data, first_fragment.data(), first_fragment.size());
	conn_stream.recv_buff.len = first_fragment.size();

	errno = 0;
	EXPECT_EQ(_dns_client_process_recv_http3(&server_info, &conn_stream), 1);
	EXPECT_EQ(errno, EAGAIN);
	EXPECT_EQ(conn_stream.recv_buff.len, (int)first_fragment.size());
#else
	GTEST_SKIP() << "OpenSSL QUIC support is not enabled";
#endif
}

TEST_F(ClientHTTP3, header_only_with_content_length_keeps_stream_pending)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	unsigned char response[1024];
	const unsigned char dns_payload[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
										 0x00, 0x00, 0x00, 0x00, 0x01, 'a',  0x03, 'c',
										 'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01};

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

	std::vector<unsigned char> header_fragment = http3_response_before_first_data_frame(response, response_len);
	ASSERT_FALSE(header_fragment.empty());

	http_head = http_head_init(sizeof(response), HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);
	EXPECT_EQ(http_head_parse(http_head, header_fragment.data(), header_fragment.size()), -1);
	http_head_destroy(http_head);

	struct dns_server_info server_info;
	memset(&server_info, 0, sizeof(server_info));
	server_info.type = DNS_SERVER_HTTP3;

	struct dns_conn_stream conn_stream;
	memset(&conn_stream, 0, sizeof(conn_stream));
	memcpy(conn_stream.recv_buff.data, header_fragment.data(), header_fragment.size());
	conn_stream.recv_buff.len = header_fragment.size();

	errno = 0;
	EXPECT_EQ(_dns_client_process_recv_http3(&server_info, &conn_stream), 1);
	EXPECT_EQ(errno, EAGAIN);
	EXPECT_EQ(conn_stream.recv_buff.len, (int)header_fragment.size());
#else
	GTEST_SKIP() << "OpenSSL QUIC support is not enabled";
#endif
}

TEST_F(ClientHTTP3, response_without_content_length_waits_for_stream_finish)
{
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
	const unsigned char dns_payload_prefix[] = {0x12, 0x34, 0x81, 0x80, 0x00, 0x01,
											   0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	std::vector<unsigned char> response =
		http3_response_without_content_length(dns_payload_prefix, sizeof(dns_payload_prefix));
	ASSERT_FALSE(response.empty());

	struct http_head *http_head = http_head_init(1024, HTTP_VERSION_3_0);
	ASSERT_NE(http_head, nullptr);
	EXPECT_GT(http_head_parse(http_head, response.data(), response.size()), 0);
	http_head_destroy(http_head);

	struct dns_server_info server_info;
	memset(&server_info, 0, sizeof(server_info));
	server_info.type = DNS_SERVER_HTTP3;

	struct dns_conn_stream conn_stream;
	memset(&conn_stream, 0, sizeof(conn_stream));
	memcpy(conn_stream.recv_buff.data, response.data(), response.size());
	conn_stream.recv_buff.len = response.size();
	conn_stream.recv_done = 0;

	errno = 0;
	EXPECT_EQ(_dns_client_process_recv_http3(&server_info, &conn_stream), 1);
	EXPECT_EQ(errno, EAGAIN);
	EXPECT_EQ(conn_stream.recv_buff.len, (int)response.size());
#else
	GTEST_SKIP() << "OpenSSL QUIC support is not enabled";
#endif
}
