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


#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "gtest/gtest.h"

static void RunInProcessServer(void)
{
	smartdns::Server server(smartdns::Server::CREATE_MODE_THREAD);
	ASSERT_TRUE(server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
)"""));
	server.Stop();
}

/*
 * Servers forked after an in-process (thread mode) server must not inherit its runtime
 * state: it once made them exit after one second (cached parent pid) and kept IPv6
 * speed check disabled (cached speed-check settings).
 */
TEST(InProcessServer, ForkedServerKeepsRunning)
{
	RunInProcessServer();

	smartdns::MockServer server_upstream;
	smartdns::Server server;
	server_upstream.Start("udp://0.0.0.0:61053",
						  [&](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_NO_RESPONSE; });
	ASSERT_TRUE(server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_GE(client.GetQueryTime(), 1500);
	EXPECT_TRUE(server.IsRunning());
}

TEST(InProcessServer, ForkedServerKeepsIPv6SpeedCheck)
{
	RunInProcessServer();

	smartdns::MockServer server_upstream;
	smartdns::Server server;
	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 10);
	ASSERT_TRUE(server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
dualstack-ip-selection no
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::2");
}
