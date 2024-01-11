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
#include "util.h"
#include "gtest/gtest.h"
#include <fstream>

class Rule : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Rule, Match)
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
address /a.com/5.6.7.8
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("a.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("aa.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "aa.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Rule, PrefixWildcardMatch)
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
address /*a.com/5.6.7.8
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("a.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("aa.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "aa.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("ab.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "ab.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Rule, SubDomainMatchOnly)
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
address /*.a.com/5.6.7.8
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("aa.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "aa.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Rule, RootDomainMatchOnly)
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
address /-.a.com/5.6.7.8
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("a.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("b.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("ba.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "ba.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Rule, AAAA_SOA)
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
address /-.a.com/#6
address /*.b.com/#6
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("a.a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");

	ASSERT_TRUE(client.Query("a.b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");
}

TEST_F(Rule, root)
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
address #6
address /-.a.com/-6
address 
)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");

	ASSERT_TRUE(client.Query("a.a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}
