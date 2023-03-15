#include "client.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"

TEST(MockServer, query_fail)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:7053", [](struct smartdns::ServerRequestContext *request) {
		request->response_data_len = 0;
		return false;
	});

	ASSERT_TRUE(client.Query("example.com", 7053));
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}
