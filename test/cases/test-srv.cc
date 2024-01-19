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

class SRV : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(SRV, query)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_SRV) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		dns_add_SRV(packet, DNS_RRS_AN, request->domain.c_str(), 603, 1, 1, 443, "www.example.com");
		dns_add_SRV(packet, DNS_RRS_AN, request->domain.c_str(), 603, 1, 1, 443, "www1.example.com");

		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("_ldap._tcp.local.com SRV", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "_ldap._tcp.local.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 603);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "SRV");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 1 443 www.example.com.");
}

TEST_F(SRV, match)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_SRV) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		dns_add_SRV(packet, DNS_RRS_AN, request->domain.c_str(), 603, 1, 1, 443, "www.example.com");
		dns_add_SRV(packet, DNS_RRS_AN, request->domain.c_str(), 603, 1, 1, 443, "www1.example.com");

		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
srv-record /_ldap._tcp.local.com/www.a.com,443,1,1
srv-record /_ldap._tcp.local.com/www1.a.com,443,1,1
srv-record /_ldap._tcp.local.com/www2.a.com,443,1,1
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("_ldap._tcp.local.com SRV", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 3);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "_ldap._tcp.local.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "SRV");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 1 443 www.a.com.");
}
