/*
 * Comprehensive tests for DNS over TLS (DoT), DNS over QUIC (DoQ), and DNS over HTTPS (DoH)
 * with proxies and upstreams
 *
 * Tests client-side protocol handling for:
 * - DoT (DNS over TLS) as upstream server
 * - DoQ (DNS over QUIC) as upstream server
 * - DoH (DNS over HTTPS) as upstream server
 * - DoT/DoQ/DoH through SOCKS5 proxy
 * - DoT/DoQ/DoH through HTTP proxy
 */

#include "client.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

class ProtocolUpstreamTest : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

class SilentTcpServer
{
  public:
	~SilentTcpServer()
	{
		Stop();
	}

	bool Start(int port)
	{
		listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
		if (listen_fd_ < 0) {
			return false;
		}

		int on = 1;
		setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		struct sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
			Stop();
			return false;
		}

		if (listen(listen_fd_, 16) != 0) {
			Stop();
			return false;
		}

		running_ = true;
		thread_ = std::thread([this]() { AcceptLoop(); });
		return true;
	}

	void Stop()
	{
		running_ = false;
		if (listen_fd_ >= 0) {
			close(listen_fd_);
		}

		if (thread_.joinable()) {
			thread_.join();
		}
		listen_fd_ = -1;

		std::lock_guard<std::mutex> lock(client_lock_);
		for (int fd : client_fds_) {
			close(fd);
		}
		client_fds_.clear();
	}

  private:
	void AcceptLoop()
	{
		while (running_) {
			int listen_fd = listen_fd_;
			if (listen_fd < 0) {
				break;
			}

			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(listen_fd, &readfds);
			struct timeval tv = {};
			tv.tv_usec = 100000;

			int ret = select(listen_fd + 1, &readfds, NULL, NULL, &tv);
			if (ret <= 0 || !running_) {
				continue;
			}

			int client_fd = accept(listen_fd, NULL, NULL);
			if (client_fd < 0) {
				continue;
			}

			std::lock_guard<std::mutex> lock(client_lock_);
			client_fds_.push_back(client_fd);
		}
	}

	std::atomic<bool> running_{false};
	int listen_fd_ = -1;
	std::thread thread_;
	std::mutex client_lock_;
	std::vector<int> client_fds_;
};

/* ========================================================================= */
/* DoT (DNS over TLS) Upstream Tests */
/* ========================================================================= */

TEST_F(ProtocolUpstreamTest, DoT_Upstream_MultiDomain)
{
	smartdns::Server server_upstream;
	smartdns::Server server;

	ASSERT_TRUE(server_upstream.Start(R"""(
bind-tls [::]:62053
address /domain1.test/10.1.0.1
address /domain2.test/10.1.0.2
address /domain3.test/10.1.0.3
log-level error
)"""));

	ASSERT_TRUE(server.Start(R"""(
bind [::]:60053
server-tls 127.0.0.1:62053 -k
log-level error
)"""));

	smartdns::Client client;
	for (int i = 1; i <= 3; i++) {
		std::string domain = "domain" + std::to_string(i) + ".test";
		ASSERT_TRUE(client.Query(domain.c_str(), 60053));
		ASSERT_EQ(client.GetAnswerNum(), 1);
	}
}

TEST_F(ProtocolUpstreamTest, DoT_Upstream_WithCache)
{
	smartdns::Server server_upstream;
	smartdns::Server server;

	ASSERT_TRUE(server_upstream.Start(R"""(
bind-tls [::]:62053
address /cached.test/10.2.0.1
log-level error
)"""));

	ASSERT_TRUE(server.Start(R"""(
bind [::]:60053
server-tls 127.0.0.1:62053 -k
cache-size 10000
log-level error
)"""));

	smartdns::Client client;
	// First query
	ASSERT_TRUE(client.Query("cached.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);

	// Second query should hit cache
	ASSERT_TRUE(client.Query("cached.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.2.0.1");
}

/* ========================================================================= */
/* DoQ (DNS over QUIC) Upstream Tests */
/* ========================================================================= */

/* ========================================================================= */
/* Protocol Mixing Tests */
/* ========================================================================= */

TEST_F(ProtocolUpstreamTest, MultiUpstream_Mixed_Protocols)
{
	smartdns::Server server_upstream_dot;
	smartdns::Server server_upstream_tcp;
	smartdns::Server server;

	// TLS upstream
	ASSERT_TRUE(server_upstream_dot.Start(R"""(
bind-tls [::]:62053
address /via-dot.test/10.7.0.1
log-level error
)"""));

	// TCP upstream
	ASSERT_TRUE(server_upstream_tcp.Start(R"""(
bind [::]:62056
address /via-tcp.test/10.7.0.2
log-level error
)"""));

	// Proxy server with both upstreams
	ASSERT_TRUE(server.Start(R"""(
bind [::]:60053
server-tls 127.0.0.1:62053 -k
server 127.0.0.1:62056
log-level error
)"""));

	smartdns::Client client;
	// Query both domain types
	ASSERT_TRUE(client.Query("via-dot.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);

	ASSERT_TRUE(client.Query("via-tcp.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

/* ========================================================================= */
/* Domain Rule Tests with Protocol Upstreams */
/* ========================================================================= */

TEST_F(ProtocolUpstreamTest, DoT_With_SimpleAddressRule)
{
	smartdns::Server server_upstream;
	smartdns::Server server;

	ASSERT_TRUE(server_upstream.Start(R"""(
bind-tls [::]:62053
address /rule-domain.test/10.8.0.1
log-level error
)"""));

	// Simple config without domain-rule, just direct upstream
	ASSERT_TRUE(server.Start(R"""(
bind [::]:60053
server-tls 127.0.0.1:62053 -k
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("rule-domain.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.8.0.1");
}

/* ========================================================================= */
/* Stress/Load Tests with Protocol Upstreams */
/* ========================================================================= */

TEST_F(ProtocolUpstreamTest, DoT_StressConcurrentQueries)
{
	smartdns::Server server_upstream;
	smartdns::Server server;

	ASSERT_TRUE(server_upstream.Start(R"""(
bind-tls [::]:62053
address /stress-dot.test/10.10.0.1
address /stress-dot.test/10.10.0.2
address /stress-dot.test/10.10.0.3
log-level error
)"""));

	ASSERT_TRUE(server.Start(R"""(
bind [::]:60053
server-tls 127.0.0.1:62053 -k
cache-size 50000
log-level error
)"""));

	// Simulate concurrent queries via multiple client instances
	std::vector<std::thread> threads;
	std::vector<bool> results(10, false);

	for (int i = 0; i < 10; i++) {
		threads.emplace_back([i, &results]() {
			smartdns::Client client;
			results[i] = client.Query("stress-dot.test", 60053);
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	// At least 80% success rate
	int success_count = 0;
	for (bool r : results) {
		if (r)
			success_count++;
	}
	ASSERT_GE(success_count, 8);
}

TEST_F(ProtocolUpstreamTest, DoQ_StressConcurrentQueries)
{
	smartdns::Server server_upstream;
	smartdns::Server server;

	if (dns_is_quic_supported() == 0) {
		GTEST_SKIP() << "QUIC is not supported by OpenSSL in current build/runtime";
	}

	ASSERT_TRUE(server_upstream.Start(R"""(
bind-quic [::]:62057
address /stress-doq.test/10.11.0.1
address /stress-doq.test/10.11.0.2
address /stress-doq.test/10.11.0.3
log-level error
)"""));

	ASSERT_TRUE(server.Start(R"""(
bind [::]:60057
server quic://[::1]:62057 -host-name smartdns -no-check-certificate
cache-size 50000
log-level error
)"""));

	std::vector<std::thread> threads;
	std::vector<bool> results(10, false);

	for (int i = 0; i < 10; i++) {
		threads.emplace_back([i, &results]() {
			smartdns::Client client;
			results[i] = client.Query("stress-doq.test", 60057);
		});
	}

	for (auto &t : threads) {
		t.join();
	}

	int success_count = 0;
	for (bool r : results) {
		if (r)
			success_count++;
	}
	ASSERT_GE(success_count, 8);
}

TEST_F(ProtocolUpstreamTest, DoQ_Upstream_Via_Socks5_Proxy)
{
	smartdns::Server upstream_quic;
	smartdns::Server proxy_relay;

	if (dns_is_quic_supported() == 0) {
		GTEST_SKIP() << "QUIC is not supported by OpenSSL in current build/runtime";
	}

	ASSERT_TRUE(upstream_quic.Start(R"""(
bind-quic [::]:62058
address /proxy-via-doq.test/10.12.0.1
log-level error
)"""));

	ASSERT_TRUE(proxy_relay.Start(R"""(
bind [::]:60058
socks5-proxy-server 0.0.0.0:64308 -name socks5-relay
proxy-server socks5://127.0.0.1:64308 -name relay-proxy
server quic://[::1]:62058 -host-name smartdns -no-check-certificate -proxy relay-proxy
cache-size 0
speed-check-mode none
log-level error
	)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("proxy-via-doq.test", 60058));
	ASSERT_GE(client.GetAnswerNum(), 1);
	EXPECT_LT(client.GetQueryTime(), 30);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.1");
}

TEST_F(ProtocolUpstreamTest, DoT_Upstream_Via_Socks5_Proxy)
{
	smartdns::Server upstream_tls;
	smartdns::Server proxy_relay;
	smartdns::Server front_server;

	// Backend TLS upstream
	ASSERT_TRUE(upstream_tls.Start(R"""(
bind-tls [::]:62053
address /proxy-via-dot.test/10.0.0.1
log-level error
)"""));

	// Proxy relay (creates socks5 server and proxies queries via DoT upstream)
	ASSERT_TRUE(proxy_relay.Start(R"""(
bind [::]:60053
socks5-proxy-server 0.0.0.0:64300 -name socks5-relay
proxy-server socks5://127.0.0.1:64300 -name relay-proxy
server-tls 127.0.0.1:62053 -proxy relay-proxy -k
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("proxy-via-dot.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_LT(client.GetQueryTime(), 30);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.0.0.1");
}

TEST_F(ProtocolUpstreamTest, DoH_Upstream_IPv6_Via_IPv4_Socks5_Proxy)
{
	smartdns::Server upstream_https;
	smartdns::Server proxy_relay;

	ASSERT_TRUE(upstream_https.Start(R"""(
bind-https [::]:62158
address /proxy-family-doh.test/10.12.0.2
log-level error
)"""));

	ASSERT_TRUE(proxy_relay.Start(R"""(
bind [::]:60158
socks5-proxy-server 127.0.0.1:64358 -name socks5-relay
proxy-server socks5://127.0.0.1:64358 -name relay-proxy
server https://[::1]:62158 -no-check-certificate -proxy relay-proxy
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("proxy-family-doh.test", 60158));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_LT(client.GetQueryTime(), 30);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.2");
}

TEST_F(ProtocolUpstreamTest, DoT_Upstream_Via_HTTP_Proxy)
{
	smartdns::Server upstream_tls;
	smartdns::Server proxy_relay;

	ASSERT_TRUE(upstream_tls.Start(R"""(
bind-tls [::]:62063
address /proxy-http-dot.test/10.12.0.5
log-level error
)"""));

	ASSERT_TRUE(proxy_relay.Start(R"""(
bind [::]:60163
http-proxy-server 127.0.0.1:64363 -name http-relay
proxy-server http://127.0.0.1:64363 -name relay-proxy
server-tls 127.0.0.1:62063 -proxy relay-proxy -k
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("proxy-http-dot.test", 60163));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_LT(client.GetQueryTime(), 30);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.5");
}

TEST_F(ProtocolUpstreamTest, DoH_Upstream_Via_HTTP_Proxy)
{
	smartdns::Server upstream_https;
	smartdns::Server proxy_relay;

	ASSERT_TRUE(upstream_https.Start(R"""(
bind-https [::]:62164
address /proxy-http-doh.test/10.12.0.6
log-level error
)"""));

	ASSERT_TRUE(proxy_relay.Start(R"""(
bind [::]:60164
http-proxy-server 127.0.0.1:64364 -name http-relay
proxy-server http://127.0.0.1:64364 -name relay-proxy
server-https https://127.0.0.1:62164/dns-query -no-check-certificate -proxy relay-proxy
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("proxy-http-doh.test", 60164));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_LT(client.GetQueryTime(), 30);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.6");
}

TEST_F(ProtocolUpstreamTest, PendingDoHHost_UsesNameserverRuleWithoutDefaultServer)
{
	smartdns::Server doh_upstream;
	smartdns::Server bootstrap_resolver;
	smartdns::Server front_server;

	ASSERT_TRUE(doh_upstream.Start(R"""(
bind-https [::]:62159
address /pending-doh-rule.test/10.12.0.3
log-level error
)"""));

	ASSERT_TRUE(bootstrap_resolver.Start(R"""(
bind [::]:62160
address /bootstrap-doh.test/127.0.0.1
log-level error
)"""));

	ASSERT_TRUE(front_server.Start(R"""(
bind [::]:60159
server 127.0.0.1:62160 -e -g aaa
nameserver /bootstrap-doh.test/aaa
address /bootstrap-doh.test/#6
server-https https://bootstrap-doh.test:62159/dns-query -no-check-certificate
	log-level error
)"""));

	smartdns::Client client;
	for (int i = 0; i < 20; i++) {
		if (client.Query("pending-doh-rule.test", 60159) && client.GetAnswerNum() == 1) {
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.3");
}

TEST_F(ProtocolUpstreamTest, DoH_PendingConnectTimeoutReturnsServfailOnRetryFailure)
{
	SilentTcpServer silent_upstream;
	smartdns::Server front_server;

	ASSERT_TRUE(silent_upstream.Start(62161));
	ASSERT_TRUE(front_server.Start(R"""(
bind [::]:60161
server-https https://127.0.0.1:62161/dns-query -no-check-certificate
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	auto start = std::chrono::steady_clock::now();
	ASSERT_TRUE(client.Query("pending-timeout.test A +time=6", 60161));
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
	EXPECT_LT(elapsed.count(), 4500);
}

TEST_F(ProtocolUpstreamTest, DoH_ReconnectsAfterRemoteIdleClose)
{
	smartdns::Server doh_upstream;
	smartdns::Server front_server;

	ASSERT_TRUE(doh_upstream.Start(R"""(
bind-https [::]:62162
tcp-idle-time 1
address /remote-close-doh.test/10.12.0.4
log-level error
)"""));

	ASSERT_TRUE(front_server.Start(R"""(
bind [::]:60162
server-https https://127.0.0.1:62162/dns-query -no-check-certificate
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("remote-close-doh.test A +time=3", 60162));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.4");

	std::this_thread::sleep_for(std::chrono::milliseconds(1500));

	ASSERT_TRUE(client.Query("remote-close-doh.test A +time=3", 60162));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.12.0.4");
}

TEST_F(ProtocolUpstreamTest, Chained_Proxy_DoT_To_DoT)
{
	smartdns::Server backend_tls;
	smartdns::Server middle_proxy;
	smartdns::Server front_proxy;

	// Backend server (TLS)
	ASSERT_TRUE(backend_tls.Start(R"""(
bind-tls [::]:62053
address /chained-dot.test/10.0.0.4
log-level error
)"""));

	// Middle proxy (connects to backend via DoT)
	ASSERT_TRUE(middle_proxy.Start(R"""(
bind [::]:60053
socks5-proxy-server 0.0.0.0:64302 -name middle-socks5
proxy-server socks5://127.0.0.1:64302 -name middle-proxy
server-tls 127.0.0.1:62053 -proxy middle-proxy -k
log-level error
)"""));

	// Front proxy (queries middle proxy)
	ASSERT_TRUE(front_proxy.Start(R"""(
bind [::]:60054
server 127.0.0.1:60053
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("chained-dot.test", 60054));
	ASSERT_EQ(client.GetAnswerNum(), 1);
}

TEST_F(ProtocolUpstreamTest, MultiUpstream_Mixed_Protocols_Via_HTTP_Proxy)
{
	smartdns::Server upstream_dot;
	smartdns::Server upstream_https;
	smartdns::Server proxy_relay;

	// Upstream 1: DoT
	ASSERT_TRUE(upstream_dot.Start(R"""(
bind-tls [::]:62073
address /mixed-http-dot.test/10.13.0.1
log-level error
)"""));

	// Upstream 2: DoH
	ASSERT_TRUE(upstream_https.Start(R"""(
bind-https [::]:62074
address /mixed-http-doh.test/10.13.0.2
log-level error
)"""));

	// HTTP Proxy Relay
	ASSERT_TRUE(proxy_relay.Start(R"""(
bind [::]:60173
http-proxy-server 127.0.0.1:64373 -name http-relay
proxy-server http://127.0.0.1:64373 -name relay-proxy
server-tls 127.0.0.1:62073 -proxy relay-proxy -k -group dot -exclude-default-group
server-https https://127.0.0.1:62074/dns-query -no-check-certificate -proxy relay-proxy -group doh -exclude-default-group
nameserver /mixed-http-dot.test/dot
nameserver /mixed-http-doh.test/doh
cache-size 0
speed-check-mode none
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("mixed-http-dot.test", 60173));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.13.0.1");

	ASSERT_TRUE(client.Query("mixed-http-doh.test", 60173));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "10.13.0.2");
}

TEST_F(ProtocolUpstreamTest, MultiUpstream_Protocols_DoT_UDP_Mixed)
{
	smartdns::Server upstream_tls;
	smartdns::Server upstream_udp;
	smartdns::Server server;

	// Upstream 1: DoT
	ASSERT_TRUE(upstream_tls.Start(R"""(
bind-tls [::]:62053
address /dot-multi.test/10.1.0.1
log-level error
)"""));

	// Upstream 2: UDP
	ASSERT_TRUE(upstream_udp.Start(R"""(
bind [::]:62054
address /udp-multi.test/10.1.0.2
log-level error
)"""));

	// Server with mixed protocols
	ASSERT_TRUE(server.Start(R"""(
bind [::]:60053
server-tls 127.0.0.1:62053 -k
server 127.0.0.1:62054
log-level error
)"""));

	smartdns::Client client;
	ASSERT_TRUE(client.Query("dot-multi.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	ASSERT_TRUE(client.Query("udp-multi.test", 60053));
	ASSERT_EQ(client.GetAnswerNum(), 1);
}
