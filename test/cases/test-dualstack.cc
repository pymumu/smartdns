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
#include "util.h"
#include "gtest/gtest.h"
#include <fstream>

class DualStack : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DualStack, ipv4_prefer)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 150);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	usleep(220 * 1000);
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 20);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_GT(client.GetAnswer()[0].GetTTL(), 597);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "5.6.7.8");
}

TEST_F(DualStack, ipv6_prefer_allow_force_AAAA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 70);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 75);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
dualstack-ip-allow-force-AAAA yes
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	usleep(220 * 1000);
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 20);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_GT(client.GetAnswer()[0].GetTTL(), 597);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "2001:db8::2");
}

TEST_F(DualStack, ipv6_prefer_without_ipv4)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 70);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 100);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
dualstack-ip-allow-force-AAAA yes
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	usleep(220 * 1000);
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 20);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_GT(client.GetAnswer()[0].GetTTL(), 597);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");
}

TEST_F(DualStack, ipv6_no_speed)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 10000);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 10000);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	usleep(220 * 1000);
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_GT(client.GetAuthority()[0].GetTTL(), 597);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
}

TEST_F(DualStack, ipv4_no_response)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_NO_RESPONSE;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10000);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 10000);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 110);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection yes
speed-check-mode ping
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");

	usleep(220 * 1000);
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 20);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_GT(client.GetAnswer()[0].GetTTL(), 590);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");
	EXPECT_EQ(client.GetAnswer()[1].GetName(), "a.com");
	EXPECT_GT(client.GetAnswer()[1].GetTTL(), 590);
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "2001:db8::2");
}
