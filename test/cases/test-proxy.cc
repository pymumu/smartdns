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

TEST_F(ProxyTest, ProxySocks5Self)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	// 1. Upstream server returning 5.6.7.8 for example.com
	// Use TCP for upstream to allow testing SOCKS5 TCP CONNECT
    server_upstream.Start(R"""(bind-tcp [::]:62054
address /example.com/5.6.7.8
log-console yes
log-level debug)""");

	// 2. SmartDNS Configured as SOCKS5 Server AND using it for upstream
	server_proxy.Start(R"""(bind [::]:60054
socks5-proxy-server 0.0.0.0:11080 -name socks5-svr
proxy-server socks5://127.0.0.1:11080 -name socks5-local
server-tcp 127.0.0.1:62054 -proxy socks5-local
log-console yes
log-level debug
cache-persist no)""");

	smartdns::Client client;
	std::cout << "Starting query for example.com A via SOCKS5..." << std::endl;
	ASSERT_TRUE(client.Query("example.com A", 60054));
	std::cout << "Query result: " << client.GetResult() << std::endl;
	
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "example.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");
	std::cout << "SOCKS5 Proxy Test completed successfully." << std::endl;
}

TEST_F(ProxyTest, ProxySocks5Auth)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	// Upstream
	server_upstream.Start(R"""(bind-tcp [::]:62055
address /example.com/1.1.1.1)""");

	// 1. Correct credentials
	server_proxy.Start(R"""(bind [::]:60055
socks5-proxy-server 0.0.0.0:11081 -name socks5-auth -user "user1" -pass "pass1"
proxy-server socks5://user1:pass1@127.0.0.1:11081 -name socks5-local-auth
server-tcp 127.0.0.1:62055 -proxy socks5-local-auth
log-console yes
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60055));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	if (client.GetAnswerNum() > 0) {
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");
	} else {
		ADD_FAILURE() << "No answer records returned";
	}

	server_proxy.Stop();

	// 2. Incorrect credentials
	server_proxy.Start(R"""(bind [::]:60055
socks5-proxy-server 0.0.0.0:11081 -name socks5-auth -user "user1" -pass "pass1"
proxy-server socks5://user1:WRONG@127.0.0.1:11081 -name socks5-local-wrong
server-tcp 127.0.0.1:62055 -proxy socks5-local-wrong
log-console yes
log-level debug)""");

	ASSERT_TRUE(client.Query("example.com A", 60055));
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");

	std::cout << "SOCKS5 Auth Test completed successfully." << std::endl;
}

TEST_F(ProxyTest, ProxyUplinkTCP)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(bind-tcp [::]:62056
address /example.com/2.2.2.2)""");

	server_proxy.Start(R"""(bind [::]:60056
socks5-proxy-server 0.0.0.0:11082 -name socks5-svr
proxy-server socks5://127.0.0.1:11082 -name socks5-local
server-tcp 127.0.0.1:62056 -proxy socks5-local
log-console yes
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60056));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2.2.2.2");
}

TEST_F(ProxyTest, ProxyUplinkTLS)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(bind-tls [::]:62057
address /example.com/3.3.3.3)""");

	server_proxy.Start(R"""(bind [::]:60057
socks5-proxy-server 0.0.0.0:11083 -name socks5-svr
proxy-server socks5://127.0.0.1:11083 -name socks5-local
server-tls 127.0.0.1:62057 -proxy socks5-local -k
log-console yes
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60057));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "3.3.3.3");
}

TEST_F(ProxyTest, ProxyUplinkHTTPS)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(bind-https [::]:62058
address /example.com/4.4.4.4)""");

	server_proxy.Start(R"""(bind [::]:60058
socks5-proxy-server 0.0.0.0:11084 -name socks5-svr
proxy-server socks5://127.0.0.1:11084 -name socks5-local
server-https https://127.0.0.1:62058 -proxy socks5-local -k
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60058));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "4.4.4.4");
}

TEST_F(ProxyTest, ProxyUplinkPassthrough)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	// Upstream
	server_upstream.Start(R"""(bind-tcp [::]:62059
address /example.com/5.5.5.5)""");

	// Proxy server with passthrough (direct upstream)
	server_proxy.Start(R"""(bind [::]:60059
proxy-server passthrough://127.0.0.1:62059 -name pass-local
server-tcp 1.2.3.4:53 -proxy pass-local
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60059));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.5.5.5");
}

TEST_F(ProxyTest, ProxyConcurrency)
{
    smartdns::Server server_upstream;
    smartdns::Server server_proxy;

    server_upstream.Start(R"""(bind-tcp [::]:62060
address /example.com/6.6.6.6)""");

    server_proxy.Start(R"""(bind [::]:60060
socks5-proxy-server 0.0.0.0:11085 -name socks5-svr
proxy-server socks5://127.0.0.1:11085 -name socks5-local
server-tcp 127.0.0.1:62060 -proxy socks5-local
log-level info)""");

    const int concurrency = 50;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};

    for (int i = 0; i < concurrency; ++i) {
        threads.emplace_back([&]() {
            smartdns::Client client;
            if (client.Query("example.com A", 60060)) {
                if (client.GetStatus() == "NOERROR") {
                    success_count++;
                }
            }
        });
    }

    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(success_count, concurrency);
}

TEST_F(ProxyTest, ProxyGroupTwoSuccess)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(bind-tcp [::]:62061
address /example.com/7.7.7.7)""");

	// Two working SOCKS5 servers in one group
	server_proxy.Start(R"""(bind [::]:60061
socks5-proxy-server 0.0.0.0:11086 -name socks5-svr1
socks5-proxy-server 0.0.0.0:11087 -name socks5-svr2
proxy-server socks5://127.0.0.1:11086 -name group-dual
proxy-server socks5://127.0.0.1:11087 -name group-dual
server-tcp 127.0.0.1:62061 -proxy group-dual
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60061));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.7.7.7");
}

TEST_F(ProxyTest, ProxyGroupTwoFail)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(bind-tcp [::]:62062
address /example.com/8.8.8.8)""");

	// Two non-existent SOCKS5 servers in one group
	server_proxy.Start(R"""(bind [::]:60062
proxy-server socks5://127.0.0.1:11098 -name group-fail
proxy-server socks5://127.0.0.1:11099 -name group-fail
server-tcp 127.0.0.1:62062 -proxy group-fail
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60062));
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}

TEST_F(ProxyTest, ProxyFallback)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(bind-tcp [::]:62063
address /example.com/9.9.9.9)""");

	// Group with one failing primary and one working fallback
	// The working fallback (11088) is hosted by the same server instance
	server_proxy.Start(R"""(bind [::]:60063
socks5-proxy-server 0.0.0.0:11088 -name socks5-bk
proxy-server socks5://127.0.0.1:11097 -name group-fallback
proxy-server socks5://127.0.0.1:11088 -name group-fallback -fallback
server-tcp 127.0.0.1:62063 -proxy group-fallback
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60063));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.9.9.9");
}

TEST_F(ProxyTest, ForwardServer_TCP)
{
	smartdns::Server server_upstream;
	smartdns::Server server_forwarder;

	// 1. Upstream server that forwarder will point to
	server_upstream.Start(R"""(bind-tcp [::]:62055
address /example.com/7.8.9.0
log-console yes
log-level debug)""");

	// 2. Forward server that forwards TCP 60055 to 62055
	server_forwarder.Start(R"""(bind [::]:63055
forward-server 127.0.0.1:60055 -target 127.0.0.1:62055
log-console yes
log-level debug)""");

	smartdns::Client client;
	// Query the forwarder port via TCP. 
	// Since forwarder just pipes data, we send a DNS query via TCP to 60055.
	// It should reach 62055 and get response.
	std::cout << "Starting TCP query for example.com A via forward-server..." << std::endl;
	ASSERT_TRUE(client.Query("+tcp example.com A", 60055));
	std::cout << "Query result: " << client.GetResult() << std::endl;
	
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.8.9.0");
	std::cout << "ForwardServer TCP test completed successfully." << std::endl;
}

TEST_F(ProxyTest, ForwardServer_UDP)
{
	smartdns::Server server_upstream;
	smartdns::Server server_forwarder;

	// 1. Upstream server
	server_upstream.Start(R"""(bind 127.0.0.1:62056
address /example.com/8.9.0.1
log-console yes
log-level debug)""");

	// 2. Forward server with UDP support
	server_forwarder.Start(R"""(bind [::]:63056
forward-server 127.0.0.1:60056 -target 127.0.0.1:62056 -udp
log-console yes
log-level debug)""");

	smartdns::Client client;
	// Query the forwarder port via UDP.
	std::cout << "Starting UDP query for example.com A via forward-server..." << std::endl;
	ASSERT_TRUE(client.Query("example.com A", 60056));
	std::cout << "Query result: " << client.GetResult() << std::endl;
	
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "8.9.0.1");
	std::cout << "ForwardServer UDP test completed successfully." << std::endl;
}

TEST_F(ProxyTest, ForwardServer_ViaProxy)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy_socks5;
	smartdns::Server server_forwarder;

	// 1. Upstream
	server_upstream.Start(R"""(bind-tcp [::]:62057
address /example.com/9.0.1.2
log-console yes
log-level debug)""");

	// 2. SOCKS5 Proxy
	server_proxy_socks5.Start(R"""(bind [::]:61081
socks5-proxy-server 127.0.0.1:11081 -name proxy1
log-console yes
log-level debug)""");

	// 3. Forward server using the SOCKS5 proxy
	server_forwarder.Start(R"""(bind [::]:63057
proxy-server socks5://127.0.0.1:11081 -name myproxy
forward-server 127.0.0.1:60057 -target 127.0.0.1:62057 -proxy myproxy
log-console yes
log-level debug)""");

	smartdns::Client client;
	std::cout << "Starting TCP query via forward-server and SOCKS5 proxy..." << std::endl;
	ASSERT_TRUE(client.Query("+tcp example.com A", 60057));
	std::cout << "Query result: " << client.GetResult() << std::endl;
	
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.0.1.2");
}
