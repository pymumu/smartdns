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
#include "gtest/gtest.h"

TEST(DiscardBlockIP, first_ping)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		unsigned char addr[4] = {0, 0, 0, 0};
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		unsigned char addr[4] = {1, 2, 3, 4};
		usleep(20000);
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 100);
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(DiscardBlockIP, first_response)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		unsigned char addr[4] = {0, 0, 0, 0};
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		unsigned char addr[4] = {1, 2, 3, 4};
		usleep(20000);
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
response-mode fastest-response
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}