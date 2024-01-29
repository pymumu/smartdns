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

class QtypeSOA : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(QtypeSOA, AAAA_HTTPS)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
force-qtype-SOA 28,65
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com -t HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com A", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
}

TEST_F(QtypeSOA, AAAA_Except)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
force-qtype-SOA 28
address /a.com/-
)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");
}

TEST_F(QtypeSOA, force_AAAA_SOA_Except)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		} else if (request->qtype == DNS_T_AAAA) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
force-AAAA-SOA yes
address /a.com/-
)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::1");
}

TEST_F(QtypeSOA, force_AAAA_SOA)
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
force-AAAA-SOA yes
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
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
}

TEST_F(QtypeSOA, bind_force_AAAA_SOA)
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

	server.Start(R"""(
bind [::]:60053
bind [::]:60153 -force-aaaa-soa
server 127.0.0.1:61053
speed-check-mode none
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

	ASSERT_TRUE(client.Query("a.com A", 60153));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com AAAA", 60153));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
}

TEST_F(QtypeSOA, HTTPS_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	std::map<int, int> qid_map;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		struct dns_rr_nested svcparam_buffer;

		dns_add_HTTPS_start(&svcparam_buffer, packet, DNS_RRS_AN, request->domain.c_str(), 3, 1, "a.com");
		const char alph[] = "\x02h2\x05h3-19";
		int alph_len = sizeof(alph) - 1;
		dns_HTTPS_add_alpn(&svcparam_buffer, alph, alph_len);
		dns_HTTPS_add_port(&svcparam_buffer, 443);
		unsigned char add_v4[] = {1, 2, 3, 4};
		unsigned char *addr[1] = {add_v4};
		dns_HTTPS_add_ipv4hint(&svcparam_buffer, addr, 1);
		unsigned char ech[] = {0x00, 0x45, 0xfe, 0x0d, 0x00};
		dns_HTTPS_add_ech(&svcparam_buffer, (void *)ech, sizeof(ech));
		unsigned char add_v6[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
		addr[0] = add_v6;
		dns_HTTPS_add_ipv6hint(&svcparam_buffer, addr, 1);
		dns_add_HTTPS_end(&svcparam_buffer);

		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
speed-check-mode none
address /a.com/#
log-level debug
cache-persist no)""");
	smartdns::Client client;
    ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
}
