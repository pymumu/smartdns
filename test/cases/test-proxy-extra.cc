#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <fstream>
#include <sys/socket.h>
#include <unistd.h>

class ProxyExtraTest : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(ProxyExtraTest, ProxyHttpBasic)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	// Upstream
	server_upstream.Start(R"""(bind-tcp [::]:62070
address /example.com/10.10.10.10)""");

	// HTTP Proxy Server (acting as the proxy)
	// We configure smartdns to LISTEN as an HTTP proxy on 11090
	server_proxy.Start(R"""(bind [::]:60070
http-proxy-server 0.0.0.0:11090 -name http-svr
proxy-server http://127.0.0.1:11090 -name http-local
server-tcp 127.0.0.1:62070 -proxy http-local
log-console yes
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60070));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.10.10.10");
}

TEST_F(ProxyExtraTest, ProxySocks5UpstreamDown)
{
	smartdns::Server server_proxy;

	// Upstream is NOT started, so 127.0.0.1:62071 will refuse connection.

	server_proxy.Start(R"""(bind [::]:60071
socks5-proxy-server 0.0.0.0:11091 -name socks5-svr
proxy-server socks5://127.0.0.1:11091 -name socks5-local
server-tcp 127.0.0.1:62071 -proxy socks5-local
log-console yes
log-level debug)""");

	smartdns::Client client;
	// Should fail gracefully
	ASSERT_TRUE(client.Query("example.com A", 60071));
	EXPECT_NE(client.GetStatus(), "NOERROR"); // Expect SERVFAIL or non-success
}

TEST_F(ProxyExtraTest, ProxyRecursionLimit)
{
    // Test that we don't crash on loops (though we might timeout)
    smartdns::Server server_proxy;

    // A proxy chain that points to itself: dns -> proxy A -> proxy A ...
    // Note: In smartdns, `proxy-server` defines an uplink.
    // If we set `server-tcp ... -proxy group1` and `proxy-server ... -name group1` points to ITSELF (the listener),
    // it creates a loop.
    
    // Listener on 11092. Proxy Uplink points to 127.0.0.1:11092.
    server_proxy.Start(R"""(bind [::]:60072
socks5-proxy-server 0.0.0.0:11092 -name socks5-loop
proxy-server socks5://127.0.0.1:11092 -name loop-group
server-tcp 1.2.3.4:53 -proxy loop-group
log-console yes
log-level debug)""");

    smartdns::Client client;
    // This query triggers the loop. The proxy server code has a loop detector `loop_detect` in `_proxy_server_conn_process` 
    // but that detects state machine loops, not network loops.
    // Network loops will just consume resources until timeout or max connection limit.
    // We just want to ensure it doesn't crash.
    
    // We rely on test timeout if it hangs? Or client timeout.
    // smartdns::Client has default timeout.
    ASSERT_TRUE(client.Query("example.com A", 60072));
    EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}

TEST_F(ProxyExtraTest, Socks5ClientCloseDuringResolveFailure)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start("udp://127.0.0.1:62073", [](struct smartdns::ServerRequestContext *request) {
		return smartdns::SERVER_REQUEST_SOA;
	});

	server_proxy.Start(R"""(bind [::]:60073
socks5-proxy-server 127.0.0.1:11093 -name socks5-resolve
server 127.0.0.1:62073
log-console yes
log-level debug
cache-persist no)""");

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GE(fd, 0);

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(11093);
	ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
	ASSERT_EQ(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

	const unsigned char hello[] = {0x05, 0x01, 0x00};
	ASSERT_EQ(send(fd, hello, sizeof(hello), MSG_NOSIGNAL), (ssize_t)sizeof(hello));

	unsigned char reply[2] = {};
	ASSERT_EQ(recv(fd, reply, sizeof(reply), MSG_WAITALL), (ssize_t)sizeof(reply));
	ASSERT_EQ(reply[0], 0x05);
	ASSERT_EQ(reply[1], 0x00);

	const char domain[] = "resolve-fail.smartdns.test";
	unsigned char req[4 + 1 + sizeof(domain) - 1 + 2] = {};
	size_t pos = 0;
	req[pos++] = 0x05;
	req[pos++] = 0x01;
	req[pos++] = 0x00;
	req[pos++] = 0x03;
	req[pos++] = sizeof(domain) - 1;
	memcpy(req + pos, domain, sizeof(domain) - 1);
	pos += sizeof(domain) - 1;
	req[pos++] = 0x00;
	req[pos++] = 0x50;
	ASSERT_EQ(send(fd, req, pos, MSG_NOSIGNAL), (ssize_t)pos);

	close(fd);
	sleep(2);
}

TEST_F(ProxyExtraTest, Socks5SmartDNSDomainUsesLocalAddress)
{
	std::atomic<int> upstream_queries{0};
	smartdns::MockServer server_upstream;
	smartdns::Server server_proxy;

	server_upstream.Start("udp://127.0.0.1:62075", [&](struct smartdns::ServerRequestContext *request) {
		upstream_queries++;
		return smartdns::SERVER_REQUEST_SOA;
	});

	server_proxy.Start(R"""(bind-tcp [::]:62074
socks5-proxy-server 127.0.0.1:11094 -name socks5-smart -remote-dns -group isolated
group-begin isolated -inherit none
server 127.0.0.1:62075
group-end
log-console yes
log-level debug
cache-persist no)""");

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GE(fd, 0);

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(11094);
	ASSERT_EQ(inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr), 1);
	ASSERT_EQ(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);

	const unsigned char hello[] = {0x05, 0x01, 0x00};
	ASSERT_EQ(send(fd, hello, sizeof(hello), MSG_NOSIGNAL), (ssize_t)sizeof(hello));

	unsigned char reply[2] = {};
	ASSERT_EQ(recv(fd, reply, sizeof(reply), MSG_WAITALL), (ssize_t)sizeof(reply));
	ASSERT_EQ(reply[0], 0x05);
	ASSERT_EQ(reply[1], 0x00);

	const char domain[] = "smartdns.";
	unsigned char req[4 + 1 + sizeof(domain) - 1 + 2] = {};
	size_t pos = 0;
	req[pos++] = 0x05;
	req[pos++] = 0x01;
	req[pos++] = 0x00;
	req[pos++] = 0x03;
	req[pos++] = sizeof(domain) - 1;
	memcpy(req + pos, domain, sizeof(domain) - 1);
	pos += sizeof(domain) - 1;
	req[pos++] = (62074 >> 8) & 0xff;
	req[pos++] = 62074 & 0xff;
	ASSERT_EQ(send(fd, req, pos, MSG_NOSIGNAL), (ssize_t)pos);

	unsigned char connect_reply[10] = {};
	ASSERT_EQ(recv(fd, connect_reply, sizeof(connect_reply), MSG_WAITALL), (ssize_t)sizeof(connect_reply));
	EXPECT_EQ(connect_reply[0], 0x05);
	EXPECT_EQ(connect_reply[1], 0x00);
	EXPECT_EQ(upstream_queries.load(), 0);

	close(fd);
}
