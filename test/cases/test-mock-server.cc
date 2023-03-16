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
		return smartdns::SERVER_REQUEST_ERROR;
	});

	ASSERT_TRUE(client.Query("example.com", 7053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}

TEST(MockServer, soa)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:7053", [](struct smartdns::ServerRequestContext *request) {
		return smartdns::SERVER_REQUEST_SOA;
	});

	ASSERT_TRUE(client.Query("example.com", 7053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
}

TEST(MockServer, noerror)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:7053", [](struct smartdns::ServerRequestContext *request) {
		return smartdns::SERVER_REQUEST_OK;
	});

	ASSERT_TRUE(client.Query("example.com", 7053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}
