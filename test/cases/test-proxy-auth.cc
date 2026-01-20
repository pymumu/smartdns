#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <fstream>

class ProxyAuthTest : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(ProxyAuthTest, ProxyHttpAuth)
{
	smartdns::Server server_upstream;
	smartdns::Server server_proxy;

	// Upstream
	server_upstream.Start(R"""(bind-tcp [::]:62070
address /example.com/10.10.10.10)""");

	// 1. Correct credentials
	// http-proxy-server listens on 11090, requires user/pass
	// proxy-server connects to 11090 using user/pass
	server_proxy.Start(R"""(bind [::]:60070
http-proxy-server 0.0.0.0:11090 -name http-auth -user "user1" -pass "pass1"
proxy-server http://user1:pass1@127.0.0.1:11090 -name http-local-auth
server-tcp 127.0.0.1:62070 -proxy http-local-auth
log-console yes
log-level debug)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com A", 60070));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	if (client.GetAnswerNum() > 0) {
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.10.10.10");
	} else {
		ADD_FAILURE() << "No answer records returned";
	}

	server_proxy.Stop();

	// 2. Incorrect credentials
	server_proxy.Start(R"""(bind [::]:60070
http-proxy-server 0.0.0.0:11090 -name http-auth -user "user1" -pass "pass1"
proxy-server http://user1:WRONG@127.0.0.1:11090 -name http-local-wrong
server-tcp 127.0.0.1:62070 -proxy http-local-wrong
log-console yes
log-level debug)""");

	ASSERT_TRUE(client.Query("example.com A", 60070));
	// Client should fail to connect to proxy, thus upstream query fails.
	// Typically returns SERVFAIL if all upstreams fail.
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");

	std::cout << "HTTP Proxy Auth Test completed successfully." << std::endl;
}
