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

class Address : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Address, soa)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/#4
address /b.com/#6
address /c.com/#
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
	EXPECT_EQ(client.GetAuthority()[0].GetData(),
			  "a.gtld-servers.net. nstld.verisign-grs.com. 1800 1800 900 604800 86400");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");

	ASSERT_TRUE(client.Query("b.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
	EXPECT_EQ(client.GetAuthority()[0].GetData(),
			  "a.gtld-servers.net. nstld.verisign-grs.com. 1800 1800 900 604800 86400");

	ASSERT_TRUE(client.Query("c.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "c.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
	EXPECT_EQ(client.GetAuthority()[0].GetData(),
			  "a.gtld-servers.net. nstld.verisign-grs.com. 1800 1800 900 604800 86400");

	ASSERT_TRUE(client.Query("c.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "c.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
	EXPECT_EQ(client.GetAuthority()[0].GetData(),
			  "a.gtld-servers.net. nstld.verisign-grs.com. 1800 1800 900 604800 86400");
}

TEST_F(Address, ip)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/10.10.10.10
address /a.com/64:ff9b::1010:1010
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.10.10.10");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::1010:1010");
}

TEST_F(Address, multiaddress)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/10.10.10.10,11.11.11.11,22.22.22.22
address /a.com/64:ff9b::1010:1010,64:ff9b::1111:1111,64:ff9b::2222:2222
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	std::map<std::string, smartdns::DNSRecord *> result;

	ASSERT_EQ(client.GetAnswerNum(), 3);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	auto answers = client.GetAnswer();
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		result[client.GetAnswer()[i].GetData()] = &answers[i];
	}

	ASSERT_NE(result.find("10.10.10.10"), result.end());
	auto check_result = result["10.10.10.10"];
	EXPECT_EQ(check_result->GetName(), "a.com");
	EXPECT_EQ(check_result->GetTTL(), 600);
	EXPECT_EQ(check_result->GetType(), "A");
	EXPECT_EQ(check_result->GetData(), "10.10.10.10");

	ASSERT_NE(result.find("11.11.11.11"), result.end());
	check_result = result["11.11.11.11"];
	EXPECT_EQ(check_result->GetName(), "a.com");
	EXPECT_EQ(check_result->GetTTL(), 600);
	EXPECT_EQ(check_result->GetType(), "A");
	EXPECT_EQ(check_result->GetData(), "11.11.11.11");

	ASSERT_NE(result.find("22.22.22.22"), result.end());
	check_result = result["22.22.22.22"];
	EXPECT_EQ(check_result->GetName(), "a.com");
	EXPECT_EQ(check_result->GetTTL(), 600);
	EXPECT_EQ(check_result->GetType(), "A");
	EXPECT_EQ(check_result->GetData(), "22.22.22.22");

	result.clear();

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 3);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	answers = client.GetAnswer();
	for (int i = 0; i < client.GetAnswerNum(); i++) {
		result[client.GetAnswer()[i].GetData()] = &answers[i];
	}

	ASSERT_NE(result.find("64:ff9b::1010:1010"), result.end());
	check_result = result["64:ff9b::1010:1010"];
	EXPECT_EQ(check_result->GetName(), "a.com");
	EXPECT_EQ(check_result->GetTTL(), 600);
	EXPECT_EQ(check_result->GetType(), "AAAA");
	EXPECT_EQ(check_result->GetData(), "64:ff9b::1010:1010");

	ASSERT_NE(result.find("64:ff9b::1111:1111"), result.end());
	check_result = result["64:ff9b::1111:1111"];
	EXPECT_EQ(check_result->GetName(), "a.com");
	EXPECT_EQ(check_result->GetTTL(), 600);
	EXPECT_EQ(check_result->GetType(), "AAAA");
	EXPECT_EQ(check_result->GetData(), "64:ff9b::1111:1111");

	ASSERT_NE(result.find("64:ff9b::2222:2222"), result.end());
	check_result = result["64:ff9b::2222:2222"];
	EXPECT_EQ(check_result->GetName(), "a.com");
	EXPECT_EQ(check_result->GetTTL(), 600);
	EXPECT_EQ(check_result->GetType(), "AAAA");
	EXPECT_EQ(check_result->GetData(), "64:ff9b::2222:2222");
}

TEST_F(Address, soa_sub_ip)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/192.168.1.1
address /com/#
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.168.1.1");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("b.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
}

TEST_F(Address, set_ipv4_query_ipv6)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/192.168.1.1
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.168.1.1");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}

TEST_F(Address, set_ipv6_query_ipv4)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/64:ff9b::1010:1010
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::1010:1010");
}

TEST_F(Address, set_ipv4_allow_ipv6)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/192.168.1.1
address /b.a.com/-6
address /com/#
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.168.1.1");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("c.a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("b.a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
}

TEST_F(Address, set_both_ipv4_ipv6)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 700);
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "64:ff9b::102:304", 700);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
address /a.com/192.168.1.1
address /b.a.com/64:ff9b::1010:1010
address /com/#
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.168.1.1");

	ASSERT_TRUE(client.Query("c.a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("b.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "192.168.1.1");

	ASSERT_TRUE(client.Query("b.a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::1010:1010");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
}
