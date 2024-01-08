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
