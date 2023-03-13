#include "client.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"

TEST(server, TLSServer)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server-tls 127.0.0.1:60053 -no-check-certificate
log-num 0
log-console yes
log-level debug
cache-persist no)""");
	server_wrap.Start(R"""(bind-tls [::]:60053
address /example.com/1.2.3.4
log-num 0
log-console yes
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}
