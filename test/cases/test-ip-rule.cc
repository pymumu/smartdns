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

class IPRule : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(IPRule, white_list)
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

	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "4.5.6.7", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -whitelist-ip
server udp://127.0.0.1:62053 -whitelist-ip
whitelist-ip 4.5.6.7/24
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "4.5.6.7");
}

TEST_F(IPRule, white_list_not_in)
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

	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "9.10.11.12", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -whitelist-ip
server udp://127.0.0.1:62053 -whitelist-ip
whitelist-ip 4.5.6.7/24
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}

TEST_F(IPRule, black_list)
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

	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "4.5.6.7", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "4.5.6.7", 60, 10);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -blacklist-ip
server udp://127.0.0.1:62053 -blacklist-ip
blacklist-ip 4.5.6.7/24
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(IPRule, ignore_ip)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "4.5.6.7", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "7.8.9.10", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "4.5.6.7", 60, 90);
	server.MockPing(PING_TYPE_ICMP, "7.8.9.10", 60, 40);

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -blacklist-ip
ignore-ip 1.2.3.0/24
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.8.9.10");
}

TEST_F(IPRule, ignore_ip_set)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_test_ip_set.list" + smartdns::GenerateRandomString(5);
	std::ofstream ofs(file);
	ASSERT_TRUE(ofs.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
	};

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "4.5.6.7", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "7.8.9.10", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	/* this ip will be discard, but is reachable */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "4.5.6.7", 60, 90);
	server.MockPing(PING_TYPE_ICMP, "7.8.9.10", 60, 40);

	std::string ipset_list = R"""(
1.2.3.0/24
4.5.6.0/24
)""";
	ofs.write(ipset_list.c_str(), ipset_list.length());
	ofs.flush();

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -blacklist-ip
ip-set -name ip-list -file )""" +
				 file + R"""(
ignore-ip ip-set:ip-list
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.8.9.10");
}

TEST_F(IPRule, ip_alias_ip_set)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_test_ip_set.list" + smartdns::GenerateRandomString(5);
	std::string file_ip = "/tmp/smartdns_test_ip_set_ip.list" + smartdns::GenerateRandomString(5);
	std::ofstream ofs(file);
	std::ofstream ofs_ip(file_ip);
	ASSERT_TRUE(ofs.is_open());
	ASSERT_TRUE(ofs_ip.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
		ofs_ip.close();
		unlink(file_ip.c_str());
	};

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "4.5.6.7", 611);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "7.8.9.10", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "4.5.6.7", 60, 90);
	server.MockPing(PING_TYPE_ICMP, "7.8.9.10", 60, 40);

	std::string ipset_list = R"""(
1.2.3.0/24
4.5.6.0/24
7.8.9.0/24
)""";
	ofs.write(ipset_list.c_str(), ipset_list.length());
	ofs.flush();

	std::string ipset_list_ip = R"""(
1.1.1.1
)""";
	ofs_ip.write(ipset_list_ip.c_str(), ipset_list_ip.length());
	ofs_ip.flush();

	server.Start(R"""(bind [::]:60053
server udp://127.0.0.1:61053 -blacklist-ip
ip-set -name ip-list -file )""" +
				 file + R"""(
ip-set -name ip-list-ip -file )""" +
				 file_ip + R"""(
ip-alias ip-set:ip-list ip-set:ip-list-ip
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");
}
