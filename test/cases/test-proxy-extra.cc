#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <fstream>

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
