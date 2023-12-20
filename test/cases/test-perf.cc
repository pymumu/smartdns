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
#include <fstream>

class Perf : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Perf, no_speed_check)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	if (smartdns::IsCommandExists("dnsperf") == false) {
		printf("dnsperf not found, skip test, please install dnsperf first.\n");
		GTEST_SKIP();
	}

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
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
speed-check-mode none
log-level error
)""");
	std::string file = "/tmp/smartdns-perftest-domain.list" + smartdns::GenerateRandomString(5);
	std::string cmd = "dnsperf -p 60053";
	cmd += " -d ";
	cmd += file;
	std::ofstream ofs(file);
	ASSERT_TRUE(ofs.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());
	};

	for (int i = 0; i < 100000; i++) {
		std::string domain = smartdns::GenerateRandomString(10);
		domain += ".";
		domain += smartdns::GenerateRandomString(3);

		if (random() % 2 == 0) {
			domain += " A";
		} else {
			domain += " AAAA";
		}

		domain += "\n";

		ofs.write(domain.c_str(), domain.length());
		ofs.flush();
	}

	system(cmd.c_str());
}
