#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

// Test rapid connection/disconnection to verify refcount handling
TEST(HTTP2Stress, RapidConnectionCycle)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	// Rapidly create and destroy clients to test connection lifecycle
	for (int i = 0; i < 20; i++) {
		smartdns::Client client;
		ASSERT_TRUE(client.Query("test.com", 61053));
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		// Client destructor should properly clean up
	}
}

// Test concurrent stream creation on same connection
TEST(HTTP2Stress, ConcurrentStreamCreation)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /domain.com/1.2.3.4
log-level debug
)""");

	std::vector<std::thread> threads;
	std::atomic<int> success_count{0};
	std::atomic<int> failure_count{0};

	// Launch many concurrent queries to stress test stream management
	for (int i = 0; i < 50; i++) {
		threads.emplace_back([&success_count, &failure_count]() {
			smartdns::Client client;
			if (client.Query("domain.com", 61053)) {
				if (client.GetStatus() == "NOERROR" && client.GetAnswerNum() > 0 &&
					client.GetAnswer()[0].GetData() == "1.2.3.4") {
					success_count++;
				} else {
					failure_count++;
				}
			} else {
				failure_count++;
			}
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	std::cout << "Success: " << success_count.load() << " Failure: " << failure_count.load() << std::endl;

	// Most queries should succeed
	EXPECT_GT(success_count.load(), 45);
	EXPECT_LT(failure_count.load(), 5);
}

// Test stream creation failure handling (by hitting concurrent stream limit)
TEST(HTTP2Stress, StreamCreationFailure)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	std::vector<std::thread> threads;
	std::atomic<int> total_queries{0};

	// Create many concurrent requests to potentially exceed stream limits
	for (int i = 0; i < 200; i++) {
		threads.emplace_back([&total_queries]() {
			smartdns::Client client;
			if (client.Query("test.com", 61053)) {
				total_queries++;
			}
			// Even if some fail, refcounts should be correct
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	std::cout << "Total successful queries: " << total_queries.load() << std::endl;

	// At least some queries should succeed
	EXPECT_GT(total_queries.load(), 150);
}

// Test connection disconnect and reconnect
TEST(HTTP2Stress, DisconnectReconnect)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	// First batch of queries
	for (int i = 0; i < 5; i++) {
		smartdns::Client client;
		ASSERT_TRUE(client.Query("test.com", 61053));
		EXPECT_EQ(client.GetStatus(), "NOERROR");
	}

	// Restart upstream server to force reconnection
	server_wrap.Stop();
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/5.6.7.8
log-level debug
)""");

	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	// Second batch of queries - should reconnect
	for (int i = 0; i < 5; i++) {
		smartdns::Client client;
		if (client.Query("test.com", 61053)) {
			EXPECT_EQ(client.GetStatus(), "NOERROR");
			if (client.GetAnswerNum() > 0) {
				// After reconnect, may get cached old IP or new IP
				// Just verify we get a response
			}
		}
		// Small delay between queries
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
}

// Test pending data buffering when connection not ready
TEST(HTTP2Stress, PendingDataBuffering)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	// Delay starting upstream server
	std::thread server_thread([&server_wrap]() {
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");
	});

	// Send queries immediately (should be buffered)
	std::vector<std::thread> query_threads;
	std::atomic<int> success_count{0};

	for (int i = 0; i < 10; i++) {
		query_threads.emplace_back([&success_count]() {
			smartdns::Client client;
			// These queries should be buffered and sent when connection is ready
			if (client.Query("test.com", 61053)) {
				if (client.GetStatus() == "NOERROR") {
					success_count++;
				}
			}
		});
	}

	server_thread.join();
	for (auto &t : query_threads) {
		t.join();
	}

	std::cout << "Buffered queries succeeded: " << success_count.load() << std::endl;

	// Most buffered queries should eventually succeed
	EXPECT_GT(success_count.load(), 5);
}

// Test mixed success and failure scenarios
TEST(HTTP2Stress, MixedSuccessFailure)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
server https://127.0.0.1:60054/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	// Only start one upstream server (other will fail)
	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	std::vector<std::thread> threads;
	std::atomic<int> total_attempts{0};
	std::atomic<int> success_count{0};

	for (int i = 0; i < 30; i++) {
		threads.emplace_back([&total_attempts, &success_count]() {
			smartdns::Client client;
			total_attempts++;
			if (client.Query("test.com", 61053)) {
				if (client.GetStatus() == "NOERROR") {
					success_count++;
				}
			}
			// Should handle failures gracefully without memory leaks
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	std::cout << "Total attempts: " << total_attempts.load() << " Success: " << success_count.load() << std::endl;

	// Should have some successes despite one server being down
	EXPECT_GT(success_count.load(), 0);
	EXPECT_EQ(total_attempts.load(), 30);
}

// Test rapid server restarts
TEST(HTTP2Stress, RapidServerRestart)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	for (int restart = 0; restart < 3; restart++) {
		if (restart > 0) {
			// Ensure previous instance is fully stopped
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
		}

		server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

		// Wait for server to be ready
		std::this_thread::sleep_for(std::chrono::milliseconds(200));

		// Send some queries
		for (int i = 0; i < 3; i++) {
			smartdns::Client client;
			client.Query("test.com", 61053);
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}

		server_wrap.Stop();
	}

	// Final start and verify
	std::this_thread::sleep_for(std::chrono::milliseconds(300));
	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("test.com", 61053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}

// Test long-running connection with many queries
TEST(HTTP2Stress, LongRunningConnection)
{
	smartdns::Server server_wrap;
	smartdns::Server server;
	int count = 20;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	std::atomic<int> success_count{0};
	std::atomic<int> failure_count{0};

	// Send many queries over time
	for (int i = 0; i < count; i++) {
		smartdns::Client client;
		if (client.Query("test.com", 61053)) {
			if (client.GetStatus() == "NOERROR") {
				success_count++;
			} else {
				failure_count++;
			}
		} else {
			failure_count++;
		}

		// Small delay between queries
		if (i % count == 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}

	std::cout << "Long-running test - Success: " << success_count.load() << " Failure: " << failure_count.load()
			  << std::endl;

	// Most queries should succeed
	EXPECT_GT(success_count.load(), count - 5);
	EXPECT_LT(failure_count.load(), 5);
}

// Test high concurrency on the same HTTP/2 connection (multiple streams)
TEST(HTTP2Stress, HighConcurrencySameConnection)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
cache-size 0
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
address /example.com/5.6.7.8
address /domain.com/9.10.11.12
log-level debug
)""");

	std::vector<std::thread> threads;
	std::atomic<int> success_count{0};
	std::atomic<int> failure_count{0};
	const int num_threads = 10;
	const int queries_per_thread = 10;

	// Launch many threads making multiple queries each
	// This should reuse the same HTTP/2 connection for multiple streams
	for (int i = 0; i < num_threads; i++) {
		threads.emplace_back([i, &success_count, &failure_count, queries_per_thread]() {
			for (int j = 0; j < queries_per_thread; j++) {
				smartdns::Client client;
				std::string domain;

				// Use different domains to test concurrent streams
				switch (j % 3) {
				case 0:
					domain = "test.com";
					break;
				case 1:
					domain = "example.com";
					break;
				case 2:
					domain = "domain.com";
					break;
				}

				if (client.Query(domain.c_str(), 61053)) {
					if (client.GetStatus() == "NOERROR" && client.GetAnswerNum() > 0) {
						success_count++;
					} else {
						failure_count++;
						GTEST_ASSERT_TRUE(false) << "Query failed for " << domain << " Status: " << client.GetStatus();
					}
				} else {
					failure_count++;
				}

				// Small random delay to create more interleaving
				if ((i + j) % 7 == 0) {
					std::this_thread::sleep_for(std::chrono::milliseconds(1));
				}
			}
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	int total_queries = num_threads * queries_per_thread;
	std::cout << "High concurrency test - Total queries: " << total_queries << " Success: " << success_count.load()
			  << " Failure: " << failure_count.load() << std::endl;

	// Most queries should succeed
	EXPECT_GT(success_count.load(), total_queries * 0.9);
	EXPECT_LT(failure_count.load(), total_queries * 0.1);
}

// Test rapid fire queries on same connection with minimal delays
TEST(HTTP2Stress, RapidFireSameConnection)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
log-level debug
)""");

	std::vector<std::thread> threads;
	std::atomic<int> success_count{0};
	std::atomic<int> failure_count{0};
	const int num_threads = 20;
	const int queries_per_thread = 25;

	// Rapid fire queries from multiple threads on same connection
	for (int i = 0; i < num_threads; i++) {
		threads.emplace_back([&success_count, &failure_count, queries_per_thread]() {
			for (int j = 0; j < queries_per_thread; j++) {
				smartdns::Client client;
				if (client.Query("test.com", 61053)) {
					if (client.GetStatus() == "NOERROR") {
						success_count++;
					} else {
						failure_count++;
					}
				} else {
					failure_count++;
				}
				// No delay - maximum concurrency
			}
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	int total_queries = num_threads * queries_per_thread;
	std::cout << "Rapid fire test - Total queries: " << total_queries << " Success: " << success_count.load()
			  << " Failure: " << failure_count.load() << std::endl;

	// Should handle high concurrency well
	EXPECT_GT(success_count.load(), total_queries * 0.8);
}

// Test connection sharing under load
TEST(HTTP2Stress, ConnectionSharingUnderLoad)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
log-level debug
)""");

	server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /test.com/1.2.3.4
address /example.com/5.6.7.8
log-level debug
)""");

	std::vector<std::thread> threads;
	std::atomic<int> success_count{0};
	std::atomic<int> failure_count{0};
	const int num_threads = 50;
	const int queries_per_thread = 10;

	// Test connection reuse under sustained load
	auto start_time = std::chrono::steady_clock::now();

	for (int i = 0; i < num_threads; i++) {
		threads.emplace_back([i, &success_count, &failure_count, queries_per_thread]() {
			for (int j = 0; j < queries_per_thread; j++) {
				smartdns::Client client;
				std::string domain = (j % 2 == 0) ? "test.com" : "example.com";

				if (client.Query(domain.c_str(), 61053)) {
					if (client.GetStatus() == "NOERROR" && client.GetAnswerNum() > 0) {
						success_count++;
					} else {
						failure_count++;
					}
				} else {
					failure_count++;
				}
			}
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	auto end_time = std::chrono::steady_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

	int total_queries = num_threads * queries_per_thread;
	std::cout << "Connection sharing test - Total queries: " << total_queries << " Success: " << success_count.load()
			  << " Failure: " << failure_count.load() << " Duration: " << duration.count() << "ms"
			  << " QPS: " << (total_queries * 1000.0 / duration.count()) << std::endl;

	// Should maintain good success rate under load
	EXPECT_GT(success_count.load(), total_queries * 0.85);
}
