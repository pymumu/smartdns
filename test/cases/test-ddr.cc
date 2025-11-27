#include "client.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <fstream>

class DDR : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DDR, DDR_RESPONSE)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053",
						  [&](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.Start(R"""(bind [::]:60053 -ddr
bind-tls [::]:60153 -ddr
bind-https [::]:60253 -ddr -alpn h2
bind-tcp [::]:60353
server 127.0.0.1:61053
log-console yes
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("_dns.resolver.arpa SVCB", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");

	bool has_doq = false;
	bool has_dot = false;

	for (auto &ans : client.GetAnswer()) {
		EXPECT_EQ(ans.GetName(), "_dns.resolver.arpa");
		EXPECT_EQ(ans.GetType(), "SVCB");
		if (ans.GetData().find("alpn=\"h2\"") != std::string::npos) {
			has_doq = true;
		}
		if (ans.GetData().find("alpn=\"dot\"") != std::string::npos) {
			has_dot = true;
		}
	}
	EXPECT_TRUE(has_doq);
	EXPECT_TRUE(has_dot);
}

TEST_F(DDR, DDR_SOA)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053",
						  [&](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.Start(R"""(bind [::]:60053
bind-tls [::]:60053
server 127.0.0.1:61053
log-console yes
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("_dns.resolver.arpa SVCB", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAuthorityNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "_dns.resolver.arpa");
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");
}
