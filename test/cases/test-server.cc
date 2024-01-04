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

class Server : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Server, all_unreach)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		EXPECT_EQ(request->domain, "e.com");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server tls://255.255.255.255
server https://255.255.255.255
server tcp://255.255.255.255
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_EQ(client.GetAnswerNum(), 0);

	/* server should not crash */
	ASSERT_TRUE(client.Query("a.com +tcp", 60053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_EQ(client.GetAnswerNum(), 0);
}

TEST_F(Server, one_nxdomain)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		usleep(50000);

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream1.Start("udp://0.0.0.0:62053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, retry_no_result_with_NOERROR)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;
	int count = 0;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		if (count++ < 2) {
			dns_add_domain(request->response_packet, request->domain.c_str(), request->qtype, request->qclass);
			return smartdns::SERVER_REQUEST_OK;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Server, retry_no_response)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;
	int count = 0;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		count++;
		return smartdns::SERVER_REQUEST_NO_RESPONSE;
	});

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_GE(client.GetQueryTime(), 1500);
	EXPECT_GE(count, 4);
}

TEST_F(Server, max_queries)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::Server server;
	int count = 0;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		sleep(1);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 128, 10);

	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
max-query-limit 2
)""");

	std::vector<std::thread> threads;
	int success_num = 0;
	int refused_num = 0;
	for (int i = 0; i < 5; i++) {
		auto t = std::thread([&]() {
			smartdns::Client client;
			ASSERT_TRUE(client.Query("a.com", 60053));
			if (client.GetStatus() == "NOERROR") {
				success_num++;
				EXPECT_EQ(client.GetStatus(), "NOERROR");
				ASSERT_EQ(client.GetAnswerNum(), 1);
				EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
				EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
			} else if (client.GetStatus() == "REFUSED") {
				refused_num++;
			} else {
				FAIL();
			}
		});
		threads.push_back(std::move(t));
	}

	for (auto &t : threads) {
		t.join();
	}

	EXPECT_EQ(success_num, 2);
	EXPECT_EQ(refused_num, 3);

	for (int i = 0; i < 5; i++) {
		smartdns::Client client;
		ASSERT_TRUE(client.Query("a.com", 60053));
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	}
}

TEST_F(Server, interface)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001::", 128, 10000);
	server.Start(R"""(bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053 -interface lo
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}