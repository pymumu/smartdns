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

#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "gtest/gtest.h"
#include <atomic>
#include <iostream>

class TXT : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(TXT, txt_record)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	std::atomic<int> upstream_count{0};

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		upstream_count++;
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
txt-record /_aaplcache._tcp/prs=10.1.1.1
txt-record /_aaplcache._tcp/prs=10.1.1.2
speed-check-mode none
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("_aaplcache._tcp TXT", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "_aaplcache._tcp");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "TXT");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "\"prs=10.1.1.1\"");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "\"prs=10.1.1.2\"");
	EXPECT_EQ(upstream_count.load(), 0);
}

TEST_F(TXT, domain_rules_txt_record)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	std::atomic<int> upstream_count{0};

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		upstream_count++;
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
domain-rules /example.com/ -txt-record v=spf1
speed-check-mode none
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com TXT", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "example.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "TXT");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "\"v=spf1\"");
	EXPECT_EQ(upstream_count.load(), 0);
}
