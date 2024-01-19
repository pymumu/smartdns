/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

class DomainSet : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DomainSet, set_add)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	smartdns::TempFile file_set;
	std::vector<std::string> domain_list;
	int count = 16;
	std::string config = "domain-set -name test-set -file " + file_set.GetPath() + "\n";
	config += R"""(bind [::]:60053
server 127.0.0.1:61053
domain-rules /domain-set:test-set/ -c none --dualstack-ip-selection no -a 9.9.9.9
)""";

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	for (int i = 0; i < count; i++) {
		auto domain = smartdns::GenerateRandomString(10) + "." + smartdns::GenerateRandomString(3);
		file_set.Write(domain);
		file_set.Write("\n");
		domain_list.emplace_back(domain);
	}

	std::cout << config << std::endl;
	server.Start(config);
	smartdns::Client client;

	for (auto &domain : domain_list) {
		ASSERT_TRUE(client.Query(domain, 60053));
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetName(), domain);
		EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
		EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.9.9.9");
	}

	ASSERT_TRUE(client.Query("a.com", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}
