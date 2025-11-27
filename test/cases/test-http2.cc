#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/http2.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>

// Test HTTP/2 with bind-https server (simulating upstream HTTPS server)
TEST(HTTP2, BindServerHTTP2)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server_wrap;
	smartdns::Server server;

	// Start main SmartDNS instance that queries upstream HTTPS server
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	// Start upstream HTTPS server (bind-https)
	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
address /test.com/5.6.7.8
log-level debug
)""");

	smartdns::Client client;

	// Test first query
	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	// Test second query to verify connection reuse
	ASSERT_TRUE(client.Query("test.com", 61053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");
}

TEST(HTTP2, ServerMultiStream)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	// Start main SmartDNS instance
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	// Start upstream HTTPS server (bind-https)
	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
address /test.com/5.6.7.8
log-level debug
)""");

	smartdns::Client client;
	
	// Send multiple concurrent queries
	// Note: The smartdns::Client might be synchronous, so we might need threads or a way to send async.
	// But we can verify that multiple queries on the same connection work (multiplexing).
	// The previous test already verified connection reuse.
	// To verify concurrency, we'd need to delay the response on the server, which is hard with bind-https.
	// However, we can at least verify that sending many queries quickly works.
	
	for (int i = 0; i < 10; i++) {
		ASSERT_TRUE(client.Query("example.com", 61053));
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	}
}

TEST(HTTP2, ServerALPNConfig)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	// Case 1: Server supports h2, client requests h2 -> h2
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}

TEST(HTTP2, ServerALPNFallback)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	// Case 2: Server supports http/1.1 only, client requests h2 -> fallback or fail?
	// If client requests h2 only, it should fail.
	// If client requests h2,http/1.1, it should fallback.
	
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2,http/1.1
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn http/1.1
address /example.com/1.2.3.4
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}

// Test client only supports HTTP/1.1, server supports both
TEST(HTTP2, ClientHTTP1Only)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	// Client only supports http/1.1, server supports both h2 and http/1.1
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn http/1.1
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2,http/1.1
address /example.com/1.2.3.4
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

// Test both client and server only support HTTP/1.1
TEST(HTTP2, BothHTTP1Only)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	// Both client and server only support http/1.1
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn http/1.1
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn http/1.1
address /example.com/1.2.3.4
address /test2.com/9.10.11.12
log-level debug
)""");

	smartdns::Client client;
	
	// First query
	ASSERT_TRUE(client.Query("example.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	
	// Second query to verify connection reuse with HTTP/1.1
	ASSERT_TRUE(client.Query("test2.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.10.11.12");
}

// Test concurrent queries from multiple clients
TEST(HTTP2, ConcurrentClients)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
address /test.com/5.6.7.8
log-level debug
)""");

	// Create multiple threads to query simultaneously
	std::vector<std::thread> threads;
	std::atomic<int> success_count{0};
	
	for (int i = 0; i < 5; i++) {
		threads.emplace_back([&success_count, i]() {
			smartdns::Client client;
			const char* domain = (i % 2 == 0) ? "example.com" : "test.com";
			const char* expected_ip = (i % 2 == 0) ? "1.2.3.4" : "5.6.7.8";
			
			if (client.Query(domain, 61053)) {
				if (client.GetStatus() == "NOERROR" && 
					client.GetAnswerNum() > 0 &&
					client.GetAnswer()[0].GetData() == expected_ip) {
					success_count++;
				}
			}
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	EXPECT_EQ(success_count.load(), 5);
}

// Test mixed HTTP/2 and HTTP/1.1 queries
TEST(HTTP2, MixedProtocolQueries)
{
	smartdns::Server server_wrap_h2;
	smartdns::Server server_wrap_http1;
	smartdns::Server server;

	// Main server supports both protocols
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2,http/1.1
server https://127.0.0.1:60054/dns-query -no-check-certificate -alpn http/1.1
log-level debug
)""");

	// First upstream supports HTTP/2
	server_wrap_h2.Start(R"""(bind-https [::]:60053 -alpn h2
address /h2-domain.com/1.1.1.1
log-level debug
)""");

	// Second upstream supports HTTP/1.1 only
	server_wrap_http1.Start(R"""(bind-https [::]:60054 -alpn http/1.1
address /http1-domain.com/2.2.2.2
log-level debug
)""");

	smartdns::Client client;
	
	// Query from HTTP/2 server
	ASSERT_TRUE(client.Query("h2-domain.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");
	
	// Query from HTTP/1.1 server
	ASSERT_TRUE(client.Query("http1-domain.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "2.2.2.2");
}

// Test connection reuse for HTTP/2
TEST(HTTP2, ConnectionReuse)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /domain1.com/1.1.1.1
address /domain2.com/2.2.2.2
address /domain3.com/3.3.3.3
log-level debug
)""");

	smartdns::Client client;
	
	// Multiple queries that should reuse the same HTTP/2 connection
	for (int i = 1; i <= 3; i++) {
		std::string domain = "domain" + std::to_string(i) + ".com";
		std::string expected_ip = std::to_string(i) + "." + std::to_string(i) + "." + std::to_string(i) + "." + std::to_string(i);
		
		ASSERT_TRUE(client.Query(domain.c_str(), 61053));
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_EQ(client.GetAnswer()[0].GetData(), expected_ip);
	}
}

// Test default ALPN behavior (no explicit -alpn parameter)
TEST(HTTP2, DefaultALPN)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	// Client doesn't specify ALPN (should default to supporting both)
	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate
log-level debug
)""");

	// Server supports both (no explicit -alpn, should default to h2,http/1.1)
	server_wrap.Start(R"""(bind-https [::]:60053
address /example.com/1.2.3.4
log-level debug
)""");

	smartdns::Client client;
	ASSERT_TRUE(client.Query("example.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}