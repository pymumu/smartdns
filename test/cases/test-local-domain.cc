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
#include "smartdns/dns.h"
#include "smartdns/dns_client.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <fstream>

class LocalDomain : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST(LocalDomain, query)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	smartdns::TempFile hosts_file;

	std::string listen_url = "udp://";
	listen_url += DNS_MDNS_IP;
	listen_url += ":" + std::to_string(DNS_MDNS_PORT);

	server_upstream1.Start(listen_url.c_str(), [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[][4] = {{1, 2, 3, 4}};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[][16] = {{1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr[0]);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:61053",
						   [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "102:304:500::1", 60, 100);
	hosts_file.Write("1.2.3.1 pc\n");
	hosts_file.Write("1.2.3.2 phone\n");
	hosts_file.Write("1.2.3.3 router\n");

	
	std::string conf = R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
local-domain lan
# mdns-lookup yes
)""";
	conf += "hosts-file " + hosts_file.GetPath() + "\n";
	conf += "\n";
	server.Start(conf);
	smartdns::Client client;

	ASSERT_TRUE(client.Query("b.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");

	ASSERT_TRUE(client.Query("pc A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "pc");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.1");

	ASSERT_TRUE(client.Query("phone.lan A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "phone.lan");
	EXPECT_GT(client.GetAnswer()[0].GetTTL(), 59);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.2");

	ASSERT_TRUE(client.Query("router.lan AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}

TEST(LocalDomain, ptr)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;
	smartdns::TempFile hosts_file;

	std::string listen_url = "udp://";
	listen_url += DNS_MDNS_IP;
	listen_url += ":" + std::to_string(DNS_MDNS_PORT);

	server_upstream1.Start(listen_url.c_str(), [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype != DNS_T_PTR) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		dns_add_PTR(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, "host.local");

		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		return smartdns::SERVER_REQUEST_ERROR;
	});
	hosts_file.Write("1.2.3.1 pc\n");
	hosts_file.Write("1.2.3.2 phone\n");
	hosts_file.Write("1.2.3.3 router\n");

	std::string conf = R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
local-domain lan
)""";
	conf += "hosts-file " + hosts_file.GetPath() + "\n";
	conf += "\n";
	server.Start(conf);
	smartdns::Client client;
	ASSERT_TRUE(client.Query("-x 1.2.3.1", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "1.3.2.1.in-addr.arpa");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "pc.");
}
