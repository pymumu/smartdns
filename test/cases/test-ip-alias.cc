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
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <fstream>

class IPAlias : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST(IPAlias, map_multiip_nospeed_check)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[][4] = {{1, 2, 3, 1}, {1, 2, 3, 2}, {1, 2, 3, 3}};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[][16] = {{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
										{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
										{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "9.10.11.12", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "10.10.10.10", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "11.11.11.11", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "0102:0304:0500::", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "0506:0708:0900::", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "0a0b:0c0d:0e00::", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "ffff::1", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "ffff::2", 60, 150);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
ip-alias 1.2.3.0/24 10.10.10.10,12.12.12.12,13.13.13.13,15.15.15.15
ip-alias 0102::/16 FFFF::0001,FFFF::0002,FFFF::0003,FFFF::0004
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 4);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.10.10.10");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "12.12.12.12");
	EXPECT_EQ(client.GetAnswer()[2].GetData(), "15.15.15.15");
	EXPECT_EQ(client.GetAnswer()[3].GetData(), "13.13.13.13");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 4);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "ffff::1");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "ffff::3");
	EXPECT_EQ(client.GetAnswer()[2].GetData(), "ffff::2");
	EXPECT_EQ(client.GetAnswer()[3].GetData(), "ffff::4");
}

TEST(IPAlias, map_single_ip_nospeed_check)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[][16] = {{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
										{5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
										{10, 11, 12, 13, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "9.10.11.12", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "10.10.10.10", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "11.11.11.11", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "0102:0304:0500::", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "0506:0708:0900::", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "0a0b:0c0d:0e00::", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "ffff::1", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "ffff::2", 60, 150);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
speed-check-mode none
ip-alias 1.2.3.4 10.10.10.10
ip-alias 5.6.7.8/32 11.11.11.11
ip-alias 0102:0304:0500:: ffff::1
ip-alias 0506:0708:0900:: ffff::2
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 3);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.10.10.10");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "11.11.11.11");
	EXPECT_EQ(client.GetAnswer()[2].GetData(), "9.10.11.12");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 3);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "ffff::1");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "a0b:c0d:e00::");
	EXPECT_EQ(client.GetAnswer()[2].GetData(), "ffff::2");
}

TEST(IPAlias, mapip_withspeed_check)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[][16] = {{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
										{5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
										{10, 11, 12, 13, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "9.10.11.12", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "10.10.10.10", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "11.11.11.11", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "0102:0304:0500::", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "0506:0708:0900::", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "0a0b:0c0d:0e00::", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "ffff::1", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "ffff::2", 60, 150);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
ip-alias 1.2.3.4 10.10.10.10
ip-alias 5.6.7.8/32 11.11.11.11
ip-alias 0102::/16 ffff::1
ip-alias 0506::/16 ffff::2
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.10.10.10");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "ffff::1");
}

TEST(IPAlias, no_ip_alias)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[][16] = {{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
										{5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
										{10, 11, 12, 13, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[1]);
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[2]);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "9.10.11.12", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "10.10.10.10", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "11.11.11.11", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "0102:0304:0500::", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "0506:0708:0900::", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "0a0b:0c0d:0e00::", 60, 140);
	server.MockPing(PING_TYPE_ICMP, "ffff::1", 60, 120);
	server.MockPing(PING_TYPE_ICMP, "ffff::2", 60, 150);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
ip-alias 1.2.3.4 10.10.10.10
ip-alias 5.6.7.8/32 11.11.11.11
ip-alias 0102::/16 ffff::1
ip-alias 0506::/16 ffff::2
domain-rules /a.com/ -no-ip-alias
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "102:304:500::");
}