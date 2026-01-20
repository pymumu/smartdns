#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <random>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <cstring>
#include "server.h"

// Comprehensive Stress Test with Chaos Upstream
class ProxyStressTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        signal(SIGPIPE, SIG_IGN);
    }
    virtual void TearDown() { }
};

enum Protocol {
    PROTO_HTTP,
    PROTO_SOCKS5,
    PROTO_FORWARD,
    PROTO_RAW_TCP
};

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Chaos Echo Server
// Accepts connections, waits randomly, echoes randomly, closes randomly.
class ChaosEchoServer {
    std::atomic<bool> running_{true};
    int server_fd_ = -1;
    std::thread accept_thread_;
    std::vector<std::thread> worker_threads_;
    int port_;

public:
    ChaosEchoServer(int port) : port_(port) {}

    void Start() {
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port_);
        
        bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr));
        listen(server_fd_, 100);

        accept_thread_ = std::thread([this]() {
            while (running_) {
                struct sockaddr_in client_addr;
                socklen_t len = sizeof(client_addr);
                int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &len);
                if (client_fd >= 0) {
                    worker_threads_.emplace_back(&ChaosEchoServer::HandleClient, this, client_fd);
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
        });
    }

    void HandleClient(int fd) {
        // Detach or manage? Let's detach for simple test
        // Ideally verify thread join but for stress test detach is easier 
        // IF we ensure they stop. We'll just let them run until close/error.
        // Actually, std::thread needs join/detach.
        
        std::mt19937 rng(fd + std::chrono::steady_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<int> dist_delay(0, 50);
        std::uniform_int_distribution<int> dist_action(0, 10);
        
        char buffer[4096];
        
        while (running_) {
            // Random Delay
            std::this_thread::sleep_for(std::chrono::milliseconds(dist_delay(rng)));
            
            // Randomly close
            if (dist_action(rng) < 1) { // 10% chance to kill from server side
                break;
            }

            // Read
            ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;

            // Randomly echo or send garbage
            if (dist_action(rng) < 5) {
                send(fd, buffer, n, 0); // Echo
            } else {
                send(fd, "CHAOS_DATA", 10, 0); // Garbage
            }
        }
        close(fd);
    }

    void Stop() {
        running_ = false;
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
        if (accept_thread_.joinable()) accept_thread_.join();
        for (auto& t : worker_threads_) {
            if (t.joinable()) t.detach(); // Allow workers to die naturally
        }
    }
    
    ~ChaosEchoServer() { Stop(); }
};

// Simple SOCKS5 handshake helper targeting 127.0.0.1:54000
static bool perform_socks5_handshake(int fd) {
    unsigned char greet[] = {0x05, 0x01, 0x00};
    if (send(fd, greet, sizeof(greet), 0) != sizeof(greet)) return false;
    
    unsigned char resp[2];
    if (recv(fd, resp, sizeof(resp), 0) != 2) return false;
    if (resp[0] != 0x05 || resp[1] != 0x00) return false;

    // Connect to 127.0.0.1 (0x7F000001) : 54000 (0xD2F0)
    unsigned char req[] = {
        0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xD2, 0xF0
    };
    if (send(fd, req, sizeof(req), 0) != sizeof(req)) return false;
    
    unsigned char resp2[1024];
    if (recv(fd, resp2, sizeof(resp2), 0) < 4) return false;
    return true;
}

// HTTP helper targeting 127.0.0.1:54000
static bool perform_http_connect(int fd) {
    const char* req = "CONNECT 127.0.0.1:54000 HTTP/1.1\r\nHost: 127.0.0.1:54000\r\n\r\n";
    send(fd, req, strlen(req), 0);
    char buf[1024];
    if (recv(fd, buf, sizeof(buf), 0) <= 0) return false;
    return true; // Assume success for test (200 OK typically)
}


static void chaos_client_thread(int port, Protocol proto, int id, std::atomic<bool>* running) {
    std::mt19937 rng(id + std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> dist_action(0, 10);
    std::uniform_int_distribution<int> dist_delay(0, 50); // 0-50ms
    std::uniform_int_distribution<int> dist_size(1, 4096);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    std::vector<char> buffer(8192);

    while (*running) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            bool ready = true;
            if (proto == PROTO_SOCKS5) {
                ready = perform_socks5_handshake(fd);
            } else if (proto == PROTO_HTTP) {
                if (dist_action(rng) < 5) {
                    ready = perform_http_connect(fd);
                }
                // Else raw GET which fails at proxy/upstream but stresses parsing
            }

            if (ready) {
                // Interact for a while
                int iterations = dist_action(rng) + 5;
                for (int i = 0; i < iterations; i++) {
                    if (dist_action(rng) < 2) { // 20% chance disconnect
                        break;
                    }
                    
                    int io_type = dist_action(rng);
                    if (io_type < 4) { // Write
                        int len = dist_size(rng);
                        send(fd, buffer.data(), len, 0);
                    } else if (io_type < 8) { // Read
                        set_nonblocking(fd);
                        recv(fd, buffer.data(), buffer.size(), 0);
                    } else { // Wait
                        std::this_thread::sleep_for(std::chrono::milliseconds(dist_delay(rng)));
                    }
                }
            }
        }
        close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist_delay(rng)));
    }
}

TEST_F(ProxyStressTest, ComplexScenario) {
    smartdns::Server server;
    // Start Chaos Upstream
    ChaosEchoServer upstream(54000);
    upstream.Start();

    server.Start(R"(
bind [::]:60000
log-level error
# Group 1: HTTP
proxy-bind http://127.0.0.1:64201 -name stress-http
# Group 2: SOCKS5
proxy-bind socks5://127.0.0.1:64202 -name stress-socks5
# Group 3: Forward (Passthrough)
proxy-bind forward://127.0.0.1:64203 -target 127.0.0.1:54000 -name stress-fwd
    )");

    std::atomic<bool> running(true);
    std::vector<std::thread> threads;
    int threads_per_proto = 15;

    // HTTP Threads
    for (int i = 0; i < threads_per_proto; i++) {
        threads.emplace_back(chaos_client_thread, 64201, PROTO_HTTP, i, &running);
    }
    // SOCKS5 Threads
    for (int i = 0; i < threads_per_proto; i++) {
        threads.emplace_back(chaos_client_thread, 64202, PROTO_SOCKS5, i + 100, &running);
    }
    // Forward Threads
    for (int i = 0; i < threads_per_proto; i++) {
        threads.emplace_back(chaos_client_thread, 64203, PROTO_RAW_TCP, i + 200, &running);
    }

    // Run for 15 seconds of chaos
    std::this_thread::sleep_for(std::chrono::seconds(15));

    running = false;
    for (auto& t : threads) {
        t.join();
    }
    upstream.Stop();
    SUCCEED();
}
