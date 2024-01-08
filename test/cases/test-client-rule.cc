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

class ClientRule : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(ClientRule, rule)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -g client -e 
server udp://127.0.0.1:62053
client-rules 127.0.0.1 -g client
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("b.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(ClientRule, group_begin_group_end)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:62053
group-begin client
server udp://127.0.0.1:61053 -e 
client-rules 127.0.0.1 
group-end
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("b.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(ClientRule, acl)
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

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() < 0) {
		return;
	}

	std::string confstr = R"""(bind [::]:60053
server 127.0.0.1:61053
acl-enable yes
)""";

	confstr += "client-rules " + ipaddr[0] + "\n";

	server.Start(confstr);
	smartdns::Client client;
	ASSERT_TRUE(client.Query("b.com", 60053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "REFUSED");
	ASSERT_EQ(client.GetAnswerNum(), 0);

	ASSERT_TRUE(client.Query("b.com", 60053, ipaddr[0]));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}
