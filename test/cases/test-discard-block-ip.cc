#include "client.h"
#include "dns.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"

TEST(DiscardBlockIP, first_ping)
{
    smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
        unsigned char addr[4] = {0, 0, 0, 0};
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

    server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
        unsigned char addr[4] = {1, 2, 3, 4};
        usleep(20000);
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
log-num 0
log-console yes
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
    EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST(DiscardBlockIP, first_response)
{
    smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
        unsigned char addr[4] = {0, 0, 0, 0};
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

    server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
        unsigned char addr[4] = {1, 2, 3, 4};
        usleep(20000);
		dns_add_A(request->response_packet, DNS_RRS_AN, request->domain.c_str(), 611, addr);
		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
log-num 0
log-console yes
log-level debug
response-mode fastest-response
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
    EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}