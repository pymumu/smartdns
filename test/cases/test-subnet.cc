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

class SubNet : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(SubNet, pass_subnet)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		struct dns_opt_ecs ecs;
		struct dns_rrs *rrs = NULL;
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		int has_ecs = 0;

		rr_count = 0;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count <= 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			has_ecs = 1;
			break;
		}

		if (has_ecs == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.family != 1) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (memcmp(ecs.addr, "\x08\x08\x08\x00", 4) != 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.source_prefix != 24) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A +subnet=8.8.8.8/24", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(SubNet, conf)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		struct dns_opt_ecs ecs;
		struct dns_rrs *rrs = NULL;
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		int has_ecs = 0;

		rr_count = 0;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count <= 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			has_ecs = 1;
			break;
		}

		if (has_ecs == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.family != DNS_OPT_ECS_FAMILY_IPV4) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (memcmp(ecs.addr, "\x08\x08\x08\x00", 4) != 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.source_prefix != 24) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
edns-client-subnet 8.8.8.8/24
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(SubNet, conf_v6)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_AAAA) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		struct dns_opt_ecs ecs;
		struct dns_rrs *rrs = NULL;
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		int has_ecs = 0;

		rr_count = 0;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count <= 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			has_ecs = 1;
			break;
		}

		if (has_ecs == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.family != DNS_OPT_ECS_FAMILY_IPV6) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (memcmp(ecs.addr, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00", 16) != 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.source_prefix != 64) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 70);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
edns-client-subnet ffff:ffff:ffff:ffff:ffff::/64
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

TEST_F(SubNet, v4_server_subnet_txt)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_TXT) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		struct dns_opt_ecs ecs;
		struct dns_rrs *rrs = NULL;
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		int has_ecs = 0;

		rr_count = 0;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count <= 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			has_ecs = 1;
			break;
		}

		if (has_ecs == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.family != DNS_OPT_ECS_FAMILY_IPV4) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (memcmp(ecs.addr, "\x08\x08\x08\x00", 4) != 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.source_prefix != 24) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		dns_add_TXT(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 6, "hello world");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053 -subnet 8.8.8.8/24 -subnet-all-query-types
dualstack-ip-selection no
rr-ttl-min 0
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com TXT", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 6);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "TXT");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "\"hello world\"");
}

TEST_F(SubNet, v6_default_subnet_txt)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_TXT) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		struct dns_opt_ecs ecs;
		struct dns_rrs *rrs = NULL;
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		int has_ecs = 0;

		rr_count = 0;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count <= 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			has_ecs = 1;
			break;
		}
		if (has_ecs == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.family != DNS_OPT_ECS_FAMILY_IPV6) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (memcmp(ecs.addr, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00", 16) != 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (ecs.source_prefix != 64) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		dns_add_TXT(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 6, "hello world");
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
dualstack-ip-selection no
rr-ttl-min 0
edns-client-subnet ffff:ffff:ffff:ffff:ffff::/64
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com TXT", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 6);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "TXT");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "\"hello world\"");
}

TEST_F(SubNet, per_server)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			struct dns_opt_ecs ecs;
			struct dns_rrs *rrs = NULL;
			int rr_count = 0;
			int i = 0;
			int ret = 0;
			int has_ecs = 0;

			rr_count = 0;
			rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
			if (rr_count <= 0) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				memset(&ecs, 0, sizeof(ecs));
				ret = dns_get_OPT_ECS(rrs, &ecs);
				if (ret != 0) {
					continue;
				}
				has_ecs = 1;
				break;
			}

			if (has_ecs == 1) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}

		if (request->qtype == DNS_T_AAAA) {
			struct dns_opt_ecs ecs;
			struct dns_rrs *rrs = NULL;
			int rr_count = 0;
			int i = 0;
			int ret = 0;
			int has_ecs = 0;

			rr_count = 0;
			rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
			if (rr_count <= 0) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				memset(&ecs, 0, sizeof(ecs));
				ret = dns_get_OPT_ECS(rrs, &ecs);
				if (ret != 0) {
					continue;
				}
				has_ecs = 1;
				break;
			}

			if (has_ecs == 1) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
			return smartdns::SERVER_REQUEST_OK;
		}

		return smartdns::SERVER_REQUEST_SOA;
	});

	server_upstream2.Start("udp://0.0.0.0:62053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {

			struct dns_opt_ecs ecs;
			struct dns_rrs *rrs = NULL;
			int rr_count = 0;
			int i = 0;
			int ret = 0;
			int has_ecs = 0;

			rr_count = 0;
			rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
			if (rr_count <= 0) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				memset(&ecs, 0, sizeof(ecs));
				ret = dns_get_OPT_ECS(rrs, &ecs);
				if (ret != 0) {
					continue;
				}
				has_ecs = 1;
				break;
			}

			if (has_ecs == 0) {
				smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
				return smartdns::SERVER_REQUEST_OK;
			}

			if (ecs.family != DNS_OPT_ECS_FAMILY_IPV4) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			if (memcmp(ecs.addr, "\x08\x08\x08\x00", 4) != 0) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			if (ecs.source_prefix != 24) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		}

		if (request->qtype == DNS_T_AAAA) {
			struct dns_opt_ecs ecs;
			struct dns_rrs *rrs = NULL;
			int rr_count = 0;
			int i = 0;
			int ret = 0;
			int has_ecs = 0;

			rr_count = 0;
			rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
			if (rr_count <= 0) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				memset(&ecs, 0, sizeof(ecs));
				ret = dns_get_OPT_ECS(rrs, &ecs);
				if (ret != 0) {
					continue;
				}
				has_ecs = 1;
				break;
			}

			if (has_ecs == 0) {
				smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::1");
				return smartdns::SERVER_REQUEST_ERROR;
			}

			if (ecs.family != DNS_OPT_ECS_FAMILY_IPV6) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			if (memcmp(ecs.addr, "\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00", 16) != 0) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			if (ecs.source_prefix != 64) {
				return smartdns::SERVER_REQUEST_ERROR;
			}

			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2001:db8::2");
			return smartdns::SERVER_REQUEST_OK;
		}

		return smartdns::SERVER_REQUEST_SOA;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::1", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "2001:db8::2", 60, 10);
	server.Start(R"""(bind [::]:60053
server 127.0.0.1:62053 -subnet=8.8.8.8/24 -subnet=ffff:ffff:ffff:ffff:ffff::/64
server 127.0.0.1:61053
dualstack-ip-selection no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");

	ASSERT_TRUE(client.Query("a.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "AAAA");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2001:db8::2");
}
