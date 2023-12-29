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

class EDNS : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(EDNS, client)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	struct dns_opt_ecs ecs;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		struct dns_rrs *rrs = NULL;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count > 0) {
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				switch (rrs->type) {
				case DNS_OPT_T_ECS: {
					memset(&ecs, 0, sizeof(ecs));
					ret = dns_get_OPT_ECS(rrs, &ecs);
					if (ret != 0) {
						continue;
					}

					dns_add_OPT_ECS(request->response_packet, &ecs);

				} break;
				default:
					break;
				}
			}
		}
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
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A +subnet=2.2.2.2/24", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetOpt().size(), 2);
	EXPECT_EQ(client.GetOpt()[1], "CLIENT-SUBNET: 2.2.2.0/24/0");
	EXPECT_EQ(ecs.family, 1);
	EXPECT_EQ(ecs.source_prefix, 24);
	EXPECT_EQ(ecs.scope_prefix, 0);
	unsigned char edns_addr[4] = {2, 2, 2, 0};
	EXPECT_EQ(memcmp(ecs.addr, &edns_addr, 4), 0);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(EDNS, server)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	struct dns_opt_ecs ecs;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		struct dns_rrs *rrs = NULL;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count > 0) {
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				switch (rrs->type) {
				case DNS_OPT_T_ECS: {
					memset(&ecs, 0, sizeof(ecs));
					ret = dns_get_OPT_ECS(rrs, &ecs);
					if (ret != 0) {
						continue;
					}

					dns_add_OPT_ECS(request->response_packet, &ecs);

				} break;
				default:
					break;
				}
			}
		}
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
server 127.0.0.1:61053 -subnet=2.2.2.0/24
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(ecs.family, 1);
	EXPECT_EQ(ecs.source_prefix, 24);
	EXPECT_EQ(ecs.scope_prefix, 0);
	unsigned char edns_addr[4] = {2, 2, 2, 0};
	EXPECT_EQ(memcmp(ecs.addr, &edns_addr, 4), 0);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(EDNS, server_v6)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	struct dns_opt_ecs ecs;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		struct dns_rrs *rrs = NULL;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count > 0) {
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				switch (rrs->type) {
				case DNS_OPT_T_ECS: {
					memset(&ecs, 0, sizeof(ecs));
					ret = dns_get_OPT_ECS(rrs, &ecs);
					if (ret != 0) {
						continue;
					}

					dns_add_OPT_ECS(request->response_packet, &ecs);

				} break;
				default:
					break;
				}
			}
		}
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
server 127.0.0.1:61053 -subnet=64:ff9b::/96
speed-check-mode none
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(ecs.family, 2);
	EXPECT_EQ(ecs.source_prefix, 96);
	EXPECT_EQ(ecs.scope_prefix, 0);
	unsigned char edns_addr[16] = {00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	EXPECT_EQ(memcmp(ecs.addr, &edns_addr, 16), 0);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(EDNS, edns_client_subnet)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	struct dns_opt_ecs ecs;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		struct dns_rrs *rrs = NULL;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count > 0) {
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				switch (rrs->type) {
				case DNS_OPT_T_ECS: {
					memset(&ecs, 0, sizeof(ecs));
					ret = dns_get_OPT_ECS(rrs, &ecs);
					if (ret != 0) {
						continue;
					}

					dns_add_OPT_ECS(request->response_packet, &ecs);

				} break;
				default:
					break;
				}
			}
		}
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
edns-client-subnet 2.2.2.2/24
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(ecs.family, 1);
	EXPECT_EQ(ecs.source_prefix, 24);
	EXPECT_EQ(ecs.scope_prefix, 0);
	unsigned char edns_addr[4] = {2, 2, 2, 0};
	EXPECT_EQ(memcmp(ecs.addr, &edns_addr, 4), 0);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(EDNS, edns_client_subnet_v6)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	struct dns_opt_ecs ecs;

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		int rr_count = 0;
		int i = 0;
		int ret = 0;
		struct dns_rrs *rrs = NULL;
		rrs = dns_get_rrs_start(request->packet, DNS_RRS_OPT, &rr_count);
		if (rr_count > 0) {
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(request->packet, rrs)) {
				switch (rrs->type) {
				case DNS_OPT_T_ECS: {
					memset(&ecs, 0, sizeof(ecs));
					ret = dns_get_OPT_ECS(rrs, &ecs);
					if (ret != 0) {
						continue;
					}

					dns_add_OPT_ECS(request->response_packet, &ecs);

				} break;
				default:
					break;
				}
			}
		}
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
edns-client-subnet 64:ff9b::/96
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(ecs.family, 2);
	EXPECT_EQ(ecs.source_prefix, 96);
	EXPECT_EQ(ecs.scope_prefix, 0);
	unsigned char edns_addr[16] = {00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	EXPECT_EQ(memcmp(ecs.addr, &edns_addr, 16), 0);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 700);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}
