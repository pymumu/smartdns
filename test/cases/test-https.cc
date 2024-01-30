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

class HTTPS : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(HTTPS, ipv4_speed_prefer)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		struct dns_rr_nested svcparam_buffer;

		dns_add_HTTPS_start(&svcparam_buffer, packet, DNS_RRS_AN, request->domain.c_str(), 3, 1, "b.com");
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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 b.com. alpn=\"h2,h3-19\" port=443 ipv4hint=1.2.3.4 ech=AEX+DQA=");
}

TEST_F(HTTPS, ipv6_speed_prefer)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		struct dns_rr_nested svcparam_buffer;

		dns_add_HTTPS_start(&svcparam_buffer, packet, DNS_RRS_AN, request->domain.c_str(), 3, 1, "b.com");
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

	server.MockPing(PING_TYPE_ICMP, "102:304:506:708:90a:b0c:d0e:f10", 60, 10);
	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(),
			  "1 b.com. alpn=\"h2,h3-19\" port=443 ech=AEX+DQA= ipv6hint=102:304:506:708:90a:b0c:d0e:f10");
}

TEST_F(HTTPS, ipv4_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

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
address /a.com/#4
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	auto result_check = client.GetAnswer()[0].GetData();

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(),
			  "1 a.com. alpn=\"h2,h3-19\" port=443 ech=AEX+DQA= ipv6hint=102:304:506:708:90a:b0c:d0e:f10");
}

TEST_F(HTTPS, ipv6_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

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
address /a.com/#6
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	auto result_check = client.GetAnswer()[0].GetData();

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 a.com. alpn=\"h2,h3-19\" port=443 ipv4hint=1.2.3.4 ech=AEX+DQA=");
}

TEST_F(HTTPS, UPSTREAM_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053",
						  [&](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
address /a.com/#6
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 60);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
}

TEST_F(HTTPS, HTTPS_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
			return smartdns::SERVER_REQUEST_OK;
		}

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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
https-record /a.com/#
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(HTTPS, HTTPS_IGN)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

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
force-qtype-SOA 65
https-record /a.com/-
log-level debug
cache-persist no)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("b.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com HTTPS", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	auto result_check = client.GetAnswer()[0].GetData();

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 a.com. alpn=\"h2,h3-19\" port=443 ipv4hint=1.2.3.4 ech=AEX+DQA=");
}

TEST_F(HTTPS, HTTPS_IGN_WITH_RULE)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

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
force-qtype-SOA 65
https-record /a.com/noipv4hint,noipv6hint
log-level debug
cache-persist no)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("b.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com HTTPS", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	auto result_check = client.GetAnswer()[0].GetData();

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 a.com. alpn=\"h2,h3-19\" port=443 ech=AEX+DQA=");
}

TEST_F(HTTPS, HTTPS_DOMAIN_RULE_IGN)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

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
address #
domain-rules /a.com/ -https-record -
log-level debug
cache-persist no)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("b.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com HTTPS", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	auto result_check = client.GetAnswer()[0].GetData();

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 a.com. alpn=\"h2,h3-19\" port=443 ipv4hint=1.2.3.4 ech=AEX+DQA=");
}

TEST_F(HTTPS, https_record)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053",
						  [&](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
force-qtype-SOA 65
https-record /a.com/target=b.com,port=1443,alpn=\"h2,h3-19\",ech=\"AEX+DQA=\",ipv4hint=1.2.3.4
log-level debug
cache-persist no)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("b.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 b.com. alpn=\"h2,h3-19\" port=1443 ipv4hint=1.2.3.4 ech=AEX+DQA=");
}

TEST_F(HTTPS, filter_ip)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		struct dns_rr_nested svcparam_buffer;

		dns_add_HTTPS_start(&svcparam_buffer, packet, DNS_RRS_AN, request->domain.c_str(), 3, 1, "b.com");
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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
https-record noipv4hint,noipv6hint
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 b.com. alpn=\"h2,h3-19\" port=443 ech=AEX+DQA=");
}

TEST_F(HTTPS, multi_not_support)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		struct dns_packet *packet = request->response_packet;
		struct dns_rr_nested svcparam_buffer;

		{
			dns_add_HTTPS_start(&svcparam_buffer, packet, DNS_RRS_AN, request->domain.c_str(), 3, 1, "b.com");
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
		}

		{

			dns_add_HTTPS_start(&svcparam_buffer, packet, DNS_RRS_AN, request->domain.c_str(), 3, 1, "c.com");
			const char alph[] = "\x02h2\x05h3-19";
			int alph_len = sizeof(alph) - 1;
			dns_HTTPS_add_alpn(&svcparam_buffer, alph, alph_len);
			dns_HTTPS_add_port(&svcparam_buffer, 443);
			unsigned char add_v4[] = {5, 6, 7, 8};
			unsigned char *addr[1] = {add_v4};
			dns_HTTPS_add_ipv4hint(&svcparam_buffer, addr, 1);
			unsigned char ech[] = {0x00, 0x45, 0xfe, 0x0d, 0x00};
			dns_HTTPS_add_ech(&svcparam_buffer, (void *)ech, sizeof(ech));
			unsigned char add_v6[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17};
			addr[0] = add_v6;
			dns_HTTPS_add_ipv6hint(&svcparam_buffer, addr, 1);
			dns_add_HTTPS_end(&svcparam_buffer);
		}

		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 10);
	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
https-record noipv4hint,noipv6hint
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(
		client.GetAnswer()[0].GetData(),
		"1 b.com. alpn=\"h2,h3-19\" port=443 ipv4hint=1.2.3.4 ech=AEX+DQA= ipv6hint=102:304:506:708:90a:b0c:d0e:f10");

	EXPECT_EQ(client.GetAnswer()[1].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[1].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[1].GetType(), "HTTPS");
	EXPECT_EQ(
		client.GetAnswer()[1].GetData(),
		"1 c.com. alpn=\"h2,h3-19\" port=443 ipv4hint=5.6.7.8 ech=AEX+DQA= ipv6hint=102:304:506:708:90a:b0c:d0e:f11");
}

TEST_F(HTTPS, BIND_FORCE_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_HTTPS) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
			return smartdns::SERVER_REQUEST_OK;
		}

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

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);

	server.Start(R"""(bind [::]:60053
bind [::]:62053 -force-https-soa
server 127.0.0.1:61053
log-console yes
dualstack-ip-selection no
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com HTTPS", 62053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 30);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("a.com HTTPS", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "HTTPS");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1 a.com. alpn=\"h2,h3-19\" port=443 ipv4hint=1.2.3.4 ech=AEX+DQA=");
}