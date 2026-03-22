#include "client.h"
#include "server.h"
#include "include/utils.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>


class ProxyForwardTest : public ::testing::Test {
protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(ProxyForwardTest, Direct_UDP) {
	smartdns::Server server;

	server.Start(R"""(
bind 127.0.0.1:62100
address /example.com/1.2.3.4
log-level debug

proxy-bind forward://127.0.0.1:63102 -target 127.0.0.1:62100 -udp
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 63102));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(ProxyForwardTest, Direct_TCP) {
	smartdns::Server server;

	server.Start(R"""(
bind 127.0.0.1:62100
bind-tcp 127.0.0.1:62100
address /example.com/1.2.3.4
log-level debug

proxy-bind forward://127.0.0.1:63101 -target 127.0.0.1:62100
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 63101));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}


TEST_F(ProxyForwardTest, TCP_to_TLS) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start(R"""(
bind-tls 127.0.0.1:62101
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind forward://127.0.0.1:63103 -targets 127.0.0.1:62101 -skip-cert-verify
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 63103));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, TLS_to_TCP) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client_wrap;

	server_upstream.Start(R"""(
bind 127.0.0.1:62100
bind-tcp 127.0.0.1:62100
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind forwards://127.0.0.1:63104 -target 127.0.0.1:62100
)""");

	server_client_wrap.Start(R"""(
bind 127.0.0.1:64100
server-tls 127.0.0.1:63104 -no-check-certificate
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Socks5_Forward_TCP) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind 127.0.0.1:62000
bind-tcp 127.0.0.1:62000
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind socks5://127.0.0.1:60200 -name to-socks5
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
bind-tcp 127.0.0.1:64100
proxy-server socks5://127.0.0.1:60200 -name out-socks5
server-tcp 127.0.0.1:62000 -proxy out-socks5
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Socks5_Forward_TLS) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind-tls 127.0.0.1:62001
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind socks5://127.0.0.1:60200 -name to-socks5
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
proxy-server socks5://127.0.0.1:60200 -name out-socks5
server-tls 127.0.0.1:62001 -proxy out-socks5 -no-check-certificate
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Socks5_Forward_DoH) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind-https 127.0.0.1:62002
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind socks5://127.0.0.1:60200 -name to-socks5
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
proxy-server socks5://127.0.0.1:60200 -name out-socks5
server-https https://127.0.0.1:62002/dns-query -proxy out-socks5 -no-check-certificate
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Http_Forward_TCP) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind 127.0.0.1:62000
bind-tcp 127.0.0.1:62000
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind http://127.0.0.1:60300 -name to-http
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
bind-tcp 127.0.0.1:64100
proxy-server http://127.0.0.1:60300 -name out-http
server-tcp 127.0.0.1:62000 -proxy out-http
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Http_Forward_TLS) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind-tls 127.0.0.1:62001
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind http://127.0.0.1:60300 -name to-http
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
proxy-server http://127.0.0.1:60300 -name out-http
server-tls 127.0.0.1:62001 -proxy out-http -no-check-certificate
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Socks5_to_Socks5_Chain) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy2;
	smartdns::Server server_proxy1;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind 127.0.0.1:62000
bind-tcp 127.0.0.1:62000
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy2.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind socks5://127.0.0.1:65100 -name to-socks5-2
)""");

	server_proxy1.Start(R"""(
bind 127.0.0.1:61200
log-level debug
proxy-server socks5://127.0.0.1:65100 -name out-layer2
proxy-bind socks5://127.0.0.1:60200 -name to-socks5-1 -proxy out-layer2
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
bind-tcp 127.0.0.1:64100
proxy-server socks5://127.0.0.1:60200 -name out-layer1
server-tcp 127.0.0.1:62000 -proxy out-layer1
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Http_to_Socks5_Chain) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy2;
	smartdns::Server server_proxy1;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind 127.0.0.1:62000
bind-tcp 127.0.0.1:62000
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy2.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind socks5://127.0.0.1:65100 -name to-socks5-2
)""");

	server_proxy1.Start(R"""(
bind 127.0.0.1:61200
log-level debug
proxy-server socks5://127.0.0.1:65100 -name out-layer2
proxy-bind http://127.0.0.1:60300 -name to-http-1 -proxy out-layer2
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
bind-tcp 127.0.0.1:64100
proxy-server http://127.0.0.1:60300 -name out-layer1
server-tcp 127.0.0.1:62000 -proxy out-layer1
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Socks5s_Forward_TCP) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind 127.0.0.1:62000
bind-tcp 127.0.0.1:62000
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind socks5s://127.0.0.1:60201 -name to-socks5s -ssl
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
proxy-server socks5s://127.0.0.1:60201 -name out-socks5s -skip-cert-verify
proxy-bind forward://127.0.0.1:63106 -target 127.0.0.1:62000 -proxy out-socks5s -skip-cert-verify
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com +tcp", 63106));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, Https_Forward_TCP) {
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;
	smartdns::Server server_client;

	server_upstream.Start(R"""(
bind 127.0.0.1:62000
bind-tcp 127.0.0.1:62000
address /example.com/1.2.3.4
log-level debug
)""");

	server_proxy.Start(R"""(
bind 127.0.0.1:61100
log-level debug
proxy-bind https://127.0.0.1:60301 -name to-https -ssl
)""");

	server_client.Start(R"""(
bind 127.0.0.1:64100
proxy-server https://127.0.0.1:60301 -name out-https -skip-cert-verify
proxy-bind forward://127.0.0.1:63107 -target 127.0.0.1:62000 -proxy out-https -udp -skip-cert-verify
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 63107));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProxyForwardTest, SNI_Proxy_DoH_Bootstrap) {
	smartdns::Server server_upstream;
	server_upstream.Start(R"""(
bind-https 127.0.0.2:62000
address /example.com/1.2.3.4
address /test.dns/127.0.0.2
log-level debug
address #6
)""");

	smartdns::Server server_socks5;
	server_socks5.Start(R"""(
bind 127.0.0.1:61200
proxy-bind socks5://127.0.0.1:65100 -name 65100
address /test.dns/127.0.0.2
log-level debug
address #6
)""");

	smartdns::Server server_proxy_sni;
	server_proxy_sni.Start(R"""(
bind 127.0.0.1:61100
proxy-server socks5://127.0.0.1:65100 -name 65100
server-https https://127.0.0.2:62000/dns-query -k
sni-proxy-server 127.0.0.1:62000 -name sniproxy -target-port 62000 -proxy 65100
sni-proxy /test.dns/sniproxy
log-level debug
address #6
)""");

	smartdns::Server server_client;
	server_client.Start(R"""(
bind 127.0.0.1:64100
server 127.0.0.1:61100 -bootstrap
server-https https://test.dns:62000/dns-query -k 
# -host-ip 127.0.0.2
address #6
log-level debug
)""");
 
	sleep(3);
	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 64100));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}
