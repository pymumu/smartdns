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

class Group : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Group, conf_file)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_conf_file" + smartdns::GenerateRandomString(5) + ".conf";
	std::ofstream ofs(file);
	ASSERT_TRUE(ofs.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
	};

	ofs << R"""(
server udp://127.0.0.1:61053 -e
client-rules 127.0.0.1
address /a.com/1.1.1.1
domain-rules /b.com/ -address 4.5.6.7
# should pop all groups
group-begin dummy
address /a.com/9.9.9.9
)""";
	ofs.flush();

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
conf-file /tmp/smartdns_conf_file*.conf -g client
server udp://127.0.0.1:61053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");

	ASSERT_TRUE(client.Query("b.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "4.5.6.7");

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() > 0) {
		ASSERT_TRUE(client.Query("a.com", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	}
}

TEST_F(Group, conf_file_ip_rule)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_conf_file" + smartdns::GenerateRandomString(5) + ".conf";
	std::ofstream ofs(file);
	ASSERT_TRUE(ofs.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
	};

	ofs << R"""(
server udp://127.0.0.1:61053 -e
client-rules 127.0.0.1
ignore-ip 7.8.9.10
group-begin dummy
ignore-ip 1.2.3.4
ignore-ip 7.8.9.10
)""";
	ofs.flush();

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "7.8.9.10", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 20);
	server.MockPing(PING_TYPE_ICMP, "7.8.9.10", 60, 10);

	server.Start(R"""(bind [::]:60053
conf-file /tmp/smartdns_conf_file*.conf -g client
server udp://127.0.0.1:61053
ignore-ip 1.2.3.4
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() > 0) {
		ASSERT_TRUE(client.Query("a.com", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.8.9.10");
	}
}

TEST_F(Group, speed_check)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_conf_file" + smartdns::GenerateRandomString(5) + ".conf";
	std::ofstream ofs(file);
	ASSERT_TRUE(ofs.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
	};

	ofs << R"""(
server udp://127.0.0.1:61053 -e
client-rules 127.0.0.1
speed-check-mode none
)""";
	ofs.flush();

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "7.8.9.10", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 20);
	server.MockPing(PING_TYPE_ICMP, "7.8.9.10", 60, 10);

	server.Start(R"""(bind [::]:60053
conf-file /tmp/smartdns_conf_file*.conf -g client
server udp://127.0.0.1:61053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "7.8.9.10");

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() > 0) {
		ASSERT_TRUE(client.Query("a.com", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.8.9.10");
	}
}

TEST_F(Group, conf_inherit)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_conf_file" + smartdns::GenerateRandomString(5) + ".conf";
	std::ofstream ofs(file);
	ASSERT_TRUE(ofs.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
	};

	ofs << R"""(
server udp://127.0.0.1:61053 -e
client-rules 127.0.0.1
)""";
	ofs.flush();

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "7.8.9.10", 611);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_TXT) {
			dns_add_TXT(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 6, "hello world");
			return smartdns::SERVER_REQUEST_OK;
		} else {
			return smartdns::SERVER_REQUEST_SOA;
		}
	});

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 50);
	server.MockPing(PING_TYPE_ICMP, "7.8.9.10", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "64:ff9b::102:304", 60, 10);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053
group-begin dummy
speed-check-mode none
force-AAAA-SOA yes
force-qtype-SOA 16
conf-file /tmp/smartdns_conf_file*.conf -g client
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "7.8.9.10");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("c.com TXT", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() > 0) {
		ASSERT_TRUE(client.Query("a.com", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.8.9.10");

		ASSERT_TRUE(client.Query("b.com AAAA", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");

		ASSERT_TRUE(client.Query("c.com TXT", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "c.com");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "\"hello world\"");
	}
}

TEST_F(Group, dualstack_inherit_ipv4_prefer)
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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 200);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
group-begin dummy
group-begin client
dualstack-ip-selection no
client-rules 127.0.0.1
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() > 0) {
		ASSERT_TRUE(client.Query("a.com AAAA", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAuthorityNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 3);
		EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

		ASSERT_TRUE(client.Query("a.com", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_LT(client.GetQueryTime(), 20);
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_GT(client.GetAnswer()[0].GetTTL(), 597);
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	}
}

TEST_F(Group, group_match_client_ip)
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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 200);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode ping
group-begin client
dualstack-ip-selection no
group-match -client-ip 127.0.0.1
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	auto ipaddr = smartdns::GetAvailableIPAddresses();
	if (ipaddr.size() > 0) {
		ASSERT_TRUE(client.Query("a.com AAAA", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAuthorityNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
		EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 3);
		EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

		ASSERT_TRUE(client.Query("a.com", 60053, ipaddr[0]));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_LT(client.GetQueryTime(), 20);
		EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
		EXPECT_GT(client.GetAnswer()[0].GetTTL(), 597);
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	}
}

TEST_F(Group, group_match_domain)
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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 80);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 150);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 200);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
group-begin client
address #6
group-match -domain a.com
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "2001:db8::2");

	ASSERT_TRUE(client.Query("b.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 20);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_GT(client.GetAnswer()[0].GetTTL(), 597);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "5.6.7.8");
}
