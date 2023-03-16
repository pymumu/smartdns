#include "client.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include "dns.h"

TEST(server, cname)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

    server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
        std::string domain = request->domain;
        if (request->domain.length() == 0) {
            return smartdns::SERVER_REQUEST_ERROR;
        }

        if (request->qtype == DNS_T_A) {
            unsigned char addr[4] = {1, 2, 3, 4};
            dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
        } else if (request->qtype == DNS_T_AAAA) {
            unsigned char addr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 61, addr);
        } else {
            return smartdns::SERVER_REQUEST_ERROR;
        }

        EXPECT_EQ(domain, "e.com");

        request->response_packet->head.rcode = DNS_RC_NOERROR;
        return smartdns::SERVER_REQUEST_OK;
    });

	server.Start(R"""(bind [::]:60053
cname /a.com/b.com
cname /b.com/c.com
cname /c.com/d.com
cname /d.com/e.com
server 127.0.0.1:61053
log-num 0
log-console yes
log-level debug
cache-persist no)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
    std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
    EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "b.com.");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "1.2.3.4");
}
