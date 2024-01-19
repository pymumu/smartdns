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

class SamePending : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(SamePending, pending)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	std::map<int, int> qid_map;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (qid_map.find(request->packet->head.id) != qid_map.end()) {
			qid_map[request->packet->head.id]++;
			usleep(5000);
		} else {
			qid_map[request->packet->head.id] = 1;
			usleep(20000);
		}

		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {1, 2, 3, 4};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 0
speed-check-mode none
log-level error
)""");

	std::vector<std::thread> threads;
	for (int i = 0; i < 5; i++) {
		auto t = std::thread([&]() {
			for (int j = 0; j < 10; j++) {
				smartdns::Client client;
				ASSERT_TRUE(client.Query("a.com", 60053));
				ASSERT_EQ(client.GetAnswerNum(), 1);
				EXPECT_EQ(client.GetStatus(), "NOERROR");
				EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
				EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
			}
		});
		threads.push_back(std::move(t));
	}

	for (auto &t : threads) {
		t.join();
	}

	EXPECT_LT(qid_map.size(), 80);
}
