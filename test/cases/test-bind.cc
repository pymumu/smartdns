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
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <sys/socket.h>

TEST(Bind, tls)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server-tls 127.0.0.1:60053 -no-check-certificate
)""");
	server_wrap.Start(R"""(bind-tls [::]:60053
address /example.com/1.2.3.4
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(Bind, https)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053 -no-check-certificate
)""");
	server_wrap.Start(R"""(bind-https [::]:60053
address /example.com/1.2.3.4
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(Bind, udp_tcp)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		unsigned char addr[4] = {1, 2, 3, 4};
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(
bind [::]:60053
bind-tcp [::]:60053
server 127.0.0.1:61053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com +tcp", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_GE(client.GetAnswer()[0].GetTTL(), 609);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(Bind, self)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(
bind [::]:60053 -group self
server 127.0.0.1:61053 -group self
bind [::]:61053 -group upstream  
server 127.0.0.1:62053 -group upstream
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

TEST(Bind, nocache)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		unsigned char addr[4] = {1, 2, 3, 4};
		usleep(15 * 1000);
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(
bind [::]:60053 --no-cache
bind-tcp [::]:60053
server 127.0.0.1:61053
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com", 60053));
	EXPECT_GT(client.GetQueryTime(), 10);
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(Bind, device)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(
bind [::]:60053@lo
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

TEST(Bind, malformed_packet)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(
bind [::]:60053@lo
server 127.0.0.1:62053
log-level info
)""");

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ASSERT_NE(sockfd, -1);
	Defer
	{
		close(sockfd);
	};

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(60053);
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	for (int i = 0; i < 100000; i++) {
		char buf[4096];
		int len = random() % 4096;
		if (len <= 0) {
			len = 1;
		}

		RAND_bytes((unsigned char *)buf, len);
		sendto(sockfd, buf, len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
	}

	smartdns::Client client;

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 100);
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(Bind, group)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "9.10.11.12", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream1.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:63053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
bind [::]:60153 -group g1
bind [::]:60253 -group g2
server 127.0.0.1:61053
server 127.0.0.1:62053 -group g1 -exclude-default-group
server 127.0.0.1:63053 -group g2 -exclude-default-group
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.10.11.12");

	ASSERT_TRUE(client.Query("a.com", 60153));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com", 60253));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");
}
