#include "server.h"
#include "smartdns/dns.h"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

// Helper function to get environment variable with default value
int get_env_int(const char* name, int default_value) {
    const char* value = std::getenv(name);
    if (value) {
        return std::atoi(value);
    }
    return default_value;
}

// Simple UDP DNS query function
bool udp_dns_query(const std::string& domain, int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    // Build simple DNS query for A record
    unsigned char query[256];
    memset(query, 0, sizeof(query));

    // Random ID
    query[0] = rand() % 256;
    query[1] = rand() % 256;

    // Flags: recursion desired
    query[2] = 0x01;
    query[3] = 0x00;

    // QDCOUNT = 1
    query[4] = 0x00;
    query[5] = 0x01;

    // Encode domain name
    int pos = 12;
    size_t start = 0;
    size_t dot_pos = domain.find('.');
    while (dot_pos != std::string::npos) {
        std::string label = domain.substr(start, dot_pos - start);
        query[pos++] = label.size();
        memcpy(&query[pos], label.c_str(), label.size());
        pos += label.size();
        start = dot_pos + 1;
        dot_pos = domain.find('.', start);
    }
    std::string label = domain.substr(start);
    query[pos++] = label.size();
    memcpy(&query[pos], label.c_str(), label.size());
    pos += label.size();
    query[pos++] = 0; // null terminator

    // QTYPE: A (1)
    query[pos++] = 0x00;
    query[pos++] = 0x01;

    // QCLASS: IN (1)
    query[pos++] = 0x00;
    query[pos++] = 0x01;

    // Send query
    if (sendto(sock, query, pos, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    // Receive response
    unsigned char response[512];
    socklen_t addr_len = sizeof(addr);
    int recv_len = recvfrom(sock, response, sizeof(response), 0, (struct sockaddr*)&addr, &addr_len);
    close(sock);

    if (recv_len < 12) return false;

    // Check RCODE (last 4 bits of flags)
    if ((response[3] & 0x0F) == 0) return true; // NOERROR

    return false;
}

// Protocol stress test configuration
struct ProtocolConfig {
    std::string name;
    std::string bind_config;
    std::string server_config;
    std::string upstream_bind_config;
};

class Stress : public ::testing::TestWithParam<ProtocolConfig> {
protected:
    void SetUp() override {
        // Common setup if needed
    }

    void TearDown() override {
        // Common cleanup if needed
    }
};

// Define protocol configurations
const ProtocolConfig protocols[] = {
    {
        "UDP",
        "bind [::]:61053",
        "server udp://127.0.0.1:60053",
        "bind [::]:60053"
    },
    {
        "TCP",
        "bind [::]:61053",
        "server tcp://127.0.0.1:60053",
        "bind-tcp [::]:60053"
    },
    {
        "TLS",
        "bind [::]:61053",
        "server tls://127.0.0.1:60053 -no-check-certificate",
        "bind-tls [::]:60053"
    },
    {
        "HTTP2",
        "bind [::]:61053",
        "server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2",
        "bind-https [::]:60053 -alpn h2"
    },
    {
        "HTTP1_1",
        "bind [::]:61053",
        "server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn http/1.1",
        "bind-https [::]:60053 -alpn http/1.1"
    }
};

// Test stress for each protocol: 100 clients, each making 100 queries
TEST_P(Stress, Query) {
    const auto& config = GetParam();

    smartdns::Server upstream_server;
    smartdns::Server main_server;

    // Start upstream server (second layer) that returns fixed IP and mocks ping
    upstream_server.Start(config.upstream_bind_config + R"""(
address /test.com/192.168.1.100
address /example.com/192.168.1.101
address /domain.com/192.168.1.102
)""");

    // Mock ping responses for the IPs
    main_server.MockPing(PING_TYPE_ICMP, "192.168.1.100", 60, 10);
    main_server.MockPing(PING_TYPE_ICMP, "192.168.1.101", 60, 5);
    main_server.MockPing(PING_TYPE_ICMP, "192.168.1.102", 60, 20);

    // Start main server that forwards to upstream via specified protocol
    main_server.Start(config.bind_config + "\n" + config.server_config + R"""(
cache-size 0
speed-check-mode ping
)""");

    // Wait for servers to be ready
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::vector<std::thread> client_threads;
    std::atomic<int> total_queries{0};
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};
    std::atomic<bool> stop_all_tasks{false};  // Flag to control all tasks exit

    const int num_clients = get_env_int("SMARTDNS_STRESS_CLIENTS", 1);
    const int queries_per_client = get_env_int("SMARTDNS_STRESS_QUERIES", 200);

    auto start_time = std::chrono::steady_clock::now();

    // Launch 100 client threads, each making 100 queries
    for (int client_id = 0; client_id < num_clients; client_id++) {
        client_threads.emplace_back([client_id, &total_queries, &success_count, &failure_count, &stop_all_tasks, queries_per_client]() {
            for (int query_id = 0; query_id < queries_per_client; query_id++) {
                // Check if stop flag is set, terminate all tasks
                if (stop_all_tasks.load()) {
                    return;
                }

                std::string domain;

                // Rotate through different domains to test various responses
                switch (query_id % 3) {
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

                total_queries++;
                if (udp_dns_query(domain, 61053)) {
                    success_count++;
                } else {
                    failure_count++;
                    stop_all_tasks.store(true);  // Set flag to stop all tasks
                    return;
                }
            }
        });
    }

    // Wait for all client threads to complete
    for (auto& t : client_threads) {
        t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    int expected_total = num_clients * queries_per_client;
    double qps = (expected_total * 1000.0) / duration.count();

    std::cout << config.name << " Stress Test Results:" << std::endl;
    std::cout << "  Total Queries: " << total_queries.load() << " (expected: " << expected_total << ")" << std::endl;
    std::cout << "  Success: " << success_count.load() << std::endl;
    std::cout << "  Failure: " << failure_count.load() << std::endl;
    std::cout << "  Duration: " << duration.count() << "ms" << std::endl;
    std::cout << "  QPS: " << qps << std::endl;
    double success_rate = total_queries.load() > 0 ? (success_count.load() * 100.0 / total_queries.load()) : 0.0;
    std::cout << "  Success Rate: " << success_rate << "%" << std::endl;

    // Assertions
    EXPECT_FALSE(stop_all_tasks.load());  // No failures should occur, all tasks should complete
    EXPECT_EQ(total_queries.load(), expected_total);
    EXPECT_EQ(success_count.load(), expected_total);
    EXPECT_EQ(failure_count.load(), 0);
}

// Instantiate the test for each protocol
INSTANTIATE_TEST_SUITE_P(, Stress, 
                         ::testing::ValuesIn(protocols),
                         [](const ::testing::TestParamInfo<ProtocolConfig>& info) {
                             return info.param.name;
                         });
// filter to run specific tests
// ./test.bin --gtest_filter="Stress.Query/UDP"
// ./test.bin --gtest_filter="Stress.Query/TCP"
