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
 *
 */

#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <fstream>

class ProxyTest : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(ProxyTest, SNIProxy_Passthrough)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server_doh;
	smartdns::Server server_proxy;

	// 1. Upstream server returning 1.2.3.4 for example.com
	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
        if (request->qtype == DNS_T_A) {
		    smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 60);
		    return smartdns::SERVER_REQUEST_OK;
        }

        return smartdns::SERVER_REQUEST_SOA;
	});

	server_doh.Start(R"""(bind-https 127.0.0.1:62053
server 127.0.0.1:61053
log-console yes
log-level debug
cache-persist no)""");

	server_proxy.Start(R"""(bind [::]:60053
proxy-server passthrough://0.0.0.0:62053 -name direct-passthrough
sni-proxy-server 127.0.0.2:16443 -name sni-proxy -proxy direct-passthrough -group doh
group-begin doh
address /doh.server/127.0.0.1
group-end
sni-proxy /doh.server/sni-proxy
server https://doh.server:16443 -k -host-ip 127.0.0.2
log-console yes
log-level debug
cache-persist no)""");

	smartdns::Client client;
	// Query smartdns 1 (proxied)
	std::cout << "Starting query for example.com A..." << std::endl;
	ASSERT_TRUE(client.Query("example.com A", 60053));
	std::cout << "Query result: " << client.GetResult() << std::endl;
	
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "example.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	std::cout << "Test completed successfully." << std::endl;
}
