#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <thread>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class MockSocks5UDPServer {
public:
    MockSocks5UDPServer(int port) : port_(port), running_(false) {}

    ~MockSocks5UDPServer() {
        Stop();
    }

    void Start() {
        running_ = true;
        thread_ = std::thread(&MockSocks5UDPServer::Run, this);
    }

    void Stop() {
        running_ = false;
        if (thread_.joinable()) {
            // Close socket to wake up thread? Or just wait.
            // For simplicity in test, we just detach or join at end.
            // A real stop would involve closing the server socket.
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd >= 0) {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port_);
                addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                connect(fd, (struct sockaddr*)&addr, sizeof(addr));
                close(fd);
            }
            thread_.join();
        }
    }

private:
    int port_;
    std::atomic<bool> running_;
    std::thread thread_;

    void Run() {
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port_);

        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            std::cerr << "MockSocks5: Bind failed" << std::endl;
            return;
        }
        listen(listen_fd, 5);

        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t len = sizeof(client_addr);
            int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
            if (client_fd < 0) continue;
            if (!running_) {
                close(client_fd);
                break;
            }

            std::thread t(&MockSocks5UDPServer::HandleClient, this, client_fd);
            t.detach();
        }
        close(listen_fd);
    }

    void HandleClient(int client_fd) {
        char buf[1024];
        // 1. Handshake: VER NMETHODS METHODS
        int n = recv(client_fd, buf, sizeof(buf), 0);
        if (n < 3 || buf[0] != 0x05) { close(client_fd); return; }
        
        // Reply: VER METHOD(00)
        char reply_auth[] = {0x05, 0x00};
        send(client_fd, reply_auth, 2, 0);

        // 2. Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        n = recv(client_fd, buf, sizeof(buf), 0);
        if (n < 4 || buf[0] != 0x05) { close(client_fd); return; }

        if (buf[1] == 0x01) { // CONNECT (Not supported for this test)
             close(client_fd); return;
        } else if (buf[1] == 0x03) { // UDP ASSOCIATE
            // Setup UDP Relay
            int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in udp_addr;
            memset(&udp_addr, 0, sizeof(udp_addr));
            udp_addr.sin_family = AF_INET;
            udp_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Bind ANY
            udp_addr.sin_port = 0; // Ephemeral
            if (bind(udp_fd, (struct sockaddr*)&udp_addr, sizeof(udp_addr)) != 0) {
                 std::cerr << "MockSocks5: UDP Bind failed" << std::endl;
                 close(udp_fd); return;
            }
            
            struct sockaddr_in bound_addr;
            socklen_t blen = sizeof(bound_addr);
            getsockname(udp_fd, (struct sockaddr*)&bound_addr, &blen);
            std::cerr << "MockSocks5: UDP Listening on port " << ntohs(bound_addr.sin_port) << std::endl;

            // Reply: VER REP(00) RSV ATYP(1) BND.ADDR BND.PORT
            char reply_succ[10];
            reply_succ[0] = 0x05; reply_succ[1] = 0x00; reply_succ[2] = 0x00; reply_succ[3] = 0x01;
            // If we bound ANY, we return 127.0.0.1 so client sends to localhost (or use client's view of proxy IP)
            // Ideally we return the IP the client connected to (127.0.0.1)
            struct sockaddr_in my_ip;
            my_ip.sin_addr.s_addr = inet_addr("127.0.0.1");
            memcpy(&reply_succ[4], &my_ip.sin_addr, 4);
            memcpy(&reply_succ[8], &bound_addr.sin_port, 2);
            send(client_fd, reply_succ, 10, 0);

            // UDP Relay Loop
            // We need to relay packets.
            // Client -> SOCKS_UDP_FD -> Extract Header -> Send to Upstream -> Recv Reply -> Add Header -> Send to Client
            // Since this is a simple mock, we only handle ONE packet or loop.
            // Client address is unknown until we receive 1st packet.
            
            struct sockaddr_in last_client_addr;
            bool client_known = false;

            while (running_) {
                struct sockaddr_in src_addr;
                socklen_t slen = sizeof(src_addr);
                n = recvfrom(udp_fd, buf, sizeof(buf), 0, (struct sockaddr*)&src_addr, &slen);
                if (n <= 0) break;

                // Parse Header
                // RSV(2) FRAG(1) ATYP(1) ..
                if (n > 10 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0) {
                    // Must be from Client
                    if (!client_known) {
                        last_client_addr = src_addr;
                        client_known = true;
                    }
                    
                    // Decode Target
                    int header_len = 0;
                    struct sockaddr_in target;
                    memset(&target, 0, sizeof(target));
                    target.sin_family = AF_INET;

                    if (buf[3] == 0x01) { // IPv4
                        memcpy(&target.sin_addr, buf + 4, 4);
                        memcpy(&target.sin_port, buf + 8, 2);
                        header_len = 10;
                    } else if (buf[3] == 0x04) { // IPv6 (Skip for now or implement)
                         // Mock usually IPv4 test
                         continue;
                    } else if (buf[3] == 0x03) { // DOMAIN
                         int len = buf[4];
                         // Resolve? For now skip
                         continue;
                    }

                    // Send raw to Target
                    int raw_s = socket(AF_INET, SOCK_DGRAM, 0);
                    sendto(raw_s, buf + header_len, n - header_len, 0, (struct sockaddr*)&target, sizeof(target));

                    // Wait reply
                    char recv_buf[1024];
                    struct sockaddr_in from;
                    socklen_t flen = sizeof(from);
                    int rn = recvfrom(raw_s, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from, &flen);
                    close(raw_s);

                    if (rn > 0) {
                        // Encapsulate and send back to Client
                        // Reuse 'buf' logic for header construction?
                        // Header: RSV(2) FRAG(1) ATYP(1) IP(4) PORT(2)
                        char resp_buf[1024];
                        resp_buf[0] = 0; resp_buf[1] = 0; resp_buf[2] = 0; resp_buf[3] = 0x01;
                        memcpy(resp_buf + 4, &from.sin_addr, 4);
                        memcpy(resp_buf + 8, &from.sin_port, 2);
                        memcpy(resp_buf + 10, recv_buf, rn);
                        sendto(udp_fd, resp_buf, 10 + rn, 0, (struct sockaddr*)&last_client_addr, sizeof(last_client_addr));
                    }
                }
            }
            close(udp_fd);
        }
        
        // Wait until closed (in real world)
        // For test, just sleep or read until close
        recv(client_fd, buf, 1, 0); 
        close(client_fd);
    }
};

class ProxyUDPTest : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(ProxyUDPTest, SOCKS5_UDP_Relay)
{
    smartdns::Server server_upstream;
    MockSocks5UDPServer socks5_svr(11100);
    smartdns::Server smartdns_client;

    socks5_svr.Start();

    // Upstream: 127.0.0.1:62100 -> Responds 1.2.3.4
    server_upstream.Start(R"""(bind [::]:62100
address /example.com/1.2.3.4
)""");

    // Client: Listens 60100, Uses Proxy 127.0.0.1:11100
    smartdns_client.Start(R"""(bind [::]:60100
server 127.0.0.1:62100 -proxy myproxy
proxy-server socks5://127.0.0.1:11100 -name myproxy
log-level debug
)""");

    smartdns::Client client;
    ASSERT_TRUE(client.Query("example.com", 60100));
    EXPECT_EQ(client.GetStatus(), "NOERROR");
    ASSERT_EQ(client.GetAnswerNum(), 1);
    EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

    socks5_svr.Stop();
}
