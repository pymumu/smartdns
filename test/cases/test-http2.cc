#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/http2.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

class HTTP2DoHClient
{
  public:
	~HTTP2DoHClient()
	{
		if (ctx_ != nullptr) {
			http2_ctx_close(ctx_);
			ctx_ = nullptr;
		}

		if (ssl_ != nullptr) {
			SSL_free(ssl_);
			ssl_ = nullptr;
		}

		if (ssl_ctx_ != nullptr) {
			SSL_CTX_free(ssl_ctx_);
			ssl_ctx_ = nullptr;
		}

		if (fd_ >= 0) {
			close(fd_);
			fd_ = -1;
		}
	}

	bool Connect(const char *host, int port)
	{
		fd_ = socket(AF_INET, SOCK_STREAM, 0);
		if (fd_ < 0) {
			last_error_ = "socket failed";
			return false;
		}

		struct sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
			last_error_ = "inet_pton failed";
			return false;
		}

		if (connect(fd_, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
			last_error_ = "connect failed";
			return false;
		}

		ssl_ctx_ = SSL_CTX_new(TLS_client_method());
		if (ssl_ctx_ == nullptr) {
			last_error_ = "SSL_CTX_new failed";
			return false;
		}

		SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, NULL);
		ssl_ = SSL_new(ssl_ctx_);
		if (ssl_ == nullptr) {
			last_error_ = "SSL_new failed";
			return false;
		}

		const unsigned char alpn[] = {2, 'h', '2'};
		if (SSL_set_alpn_protos(ssl_, alpn, sizeof(alpn)) != 0) {
			last_error_ = "SSL_set_alpn_protos failed";
			return false;
		}

		SSL_set_fd(ssl_, fd_);
		if (SSL_connect(ssl_) != 1) {
			last_error_ = "SSL_connect failed";
			return false;
		}

		const unsigned char *selected_alpn = nullptr;
		unsigned int selected_alpn_len = 0;
		SSL_get0_alpn_selected(ssl_, &selected_alpn, &selected_alpn_len);
		if (selected_alpn_len != 2 || memcmp(selected_alpn, "h2", 2) != 0) {
			last_error_ = "ALPN h2 was not selected";
			return false;
		}

		int flags = fcntl(fd_, F_GETFL, 0);
		if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) != 0) {
			last_error_ = "fcntl O_NONBLOCK failed";
			return false;
		}

		ctx_ = http2_ctx_client_new(host, BioRead, BioWrite, this, NULL);
		if (ctx_ == nullptr) {
			last_error_ = "http2_ctx_client_new failed";
			return false;
		}

		for (int i = 0; i < 200; i++) {
			int ret = http2_ctx_handshake(ctx_);
			if (ret == 1) {
				return true;
			}
			if (ret < 0) {
				last_error_ = std::string("http2 handshake failed: ") + http2_error_to_string(ret);
				return false;
			}

			struct pollfd pfd = {fd_, POLLIN, 0};
			poll(&pfd, 1, 10);
		}

		last_error_ = "http2 handshake timed out";
		return false;
	}

	bool Query(const std::vector<uint8_t> &request, std::vector<uint8_t> *response)
	{
		return QueryInternal(request, true, request.size(), response);
	}

	bool QueryWithContentLength(const std::vector<uint8_t> &request, size_t advertised_content_length,
								std::vector<uint8_t> *response)
	{
		return QueryInternal(request, true, advertised_content_length, response);
	}

	bool QueryWithoutContentLength(const std::vector<uint8_t> &request, std::vector<uint8_t> *response)
	{
		return QueryInternal(request, false, 0, response);
	}

	const std::string &LastError() const { return last_error_; }

  private:
	bool QueryInternal(const std::vector<uint8_t> &request, bool has_content_length, size_t advertised_content_length,
					   std::vector<uint8_t> *response)
	{
		if (ctx_ == nullptr || response == nullptr) {
			last_error_ = "query without connected ctx";
			return false;
		}

		struct http2_stream *stream = http2_stream_new(ctx_);
		if (stream == nullptr) {
			last_error_ = "http2_stream_new failed";
			return false;
		}

		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", advertised_content_length);
		struct http2_header_pair headers[4] = {{"content-type", "application/dns-message"},
											   {"accept", "application/dns-message"},
											   {NULL, NULL},
											   {NULL, NULL}};
		if (has_content_length) {
			headers[2].name = "content-length";
			headers[2].value = content_length;
		}

		if (http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers) != 0 ||
			http2_stream_write_body(stream, request.data(), request.size(), 1) < 0) {
			last_error_ = "write request failed";
			http2_stream_close(stream);
			return false;
		}

		bool ok = WaitResponse(stream, response);
		http2_stream_close(stream);
		return ok;
	}

	static int BioRead(void *private_data, uint8_t *buf, int len)
	{
		HTTP2DoHClient *client = (HTTP2DoHClient *)private_data;
		int ret = SSL_read(client->ssl_, buf, len);
		if (ret > 0) {
			return ret;
		}

		int ssl_err = SSL_get_error(client->ssl_, ret);
		if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		}

		return ret;
	}

	static int BioWrite(void *private_data, const uint8_t *buf, int len)
	{
		HTTP2DoHClient *client = (HTTP2DoHClient *)private_data;
		int ret = SSL_write(client->ssl_, buf, len);
		if (ret > 0) {
			return ret;
		}

		int ssl_err = SSL_get_error(client->ssl_, ret);
		if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		}

		return ret;
	}

	bool WaitResponse(struct http2_stream *stream, std::vector<uint8_t> *response)
	{
		response->clear();

		for (int i = 0; i < 300; i++) {
			struct pollfd pfd = {fd_, POLLIN, 0};
			poll(&pfd, 1, 10);

			int ret = http2_ctx_poll(ctx_, NULL, 0, NULL);
			if (ret < 0 && ret != HTTP2_ERR_EAGAIN) {
				last_error_ = std::string("http2 poll failed: ") + http2_error_to_string(ret);
				return false;
			}

			uint8_t buf[1024];
			while (true) {
				int len = http2_stream_read_body(stream, buf, sizeof(buf));
				if (len > 0) {
					response->insert(response->end(), buf, buf + len);
					continue;
				}

				if (len < 0 && errno != EAGAIN) {
					last_error_ = std::string("read response failed: ") + strerror(errno);
					return false;
				}
				break;
			}

			if (http2_stream_get_status(stream) == 200 && http2_stream_is_end(stream)) {
				return !response->empty();
			}

			if (http2_stream_is_end(stream) && http2_stream_get_status(stream) != 200) {
				last_error_ = std::string("stream ended without response, status=") +
							  std::to_string(http2_stream_get_status(stream));
				return false;
			}
		}

		last_error_ = std::string("response timed out, status=") + std::to_string(http2_stream_get_status(stream)) +
					  ", bytes=" + std::to_string(response->size());
		return false;
	}

	int fd_ = -1;
	SSL_CTX *ssl_ctx_ = nullptr;
	SSL *ssl_ = nullptr;
	struct http2_ctx *ctx_ = nullptr;
	std::string last_error_;
};

std::vector<uint8_t> BuildDnsQuery(const char *domain, uint16_t id)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char out[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_head head = {};

	head.id = id;
	head.qr = DNS_QR_QUERY;
	head.opcode = DNS_OP_QUERY;
	head.rd = 1;

	if (dns_packet_init(packet, sizeof(packet_buff), &head) != 0) {
		return {};
	}

	if (dns_add_domain(packet, domain, DNS_T_A, DNS_C_IN) != 0) {
		return {};
	}

	int len = dns_encode(out, sizeof(out), packet);
	if (len <= 0) {
		return {};
	}

	return std::vector<uint8_t>(out, out + len);
}

bool DnsResponseHasAnswer(const std::vector<uint8_t> &response)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;

	if (dns_decode(packet, sizeof(packet_buff), (unsigned char *)response.data(), response.size()) != 0) {
		return false;
	}

	int answer_count = 0;
	dns_get_rrs_start(packet, DNS_RRS_AN, &answer_count);
	return packet->head.qr == DNS_QR_ANSWER && packet->head.rcode == DNS_RC_NOERROR && answer_count > 0;
}

} // namespace

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

TEST(HTTP2, DownstreamDohServerConnectionReuse)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	server.Start(R"""(bind-https [::]:60053 -alpn h2
address /reuse-one.test/1.2.3.4
address /reuse-two.test/5.6.7.8
log-level debug
)""");

	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> first_query = BuildDnsQuery("reuse-one.test", 0x1001);
	std::vector<uint8_t> second_query = BuildDnsQuery("reuse-two.test", 0x1002);
	ASSERT_FALSE(first_query.empty());
	ASSERT_FALSE(second_query.empty());

	std::vector<uint8_t> first_response;
	ASSERT_TRUE(client.Query(first_query, &first_response)) << client.LastError();
	EXPECT_TRUE(DnsResponseHasAnswer(first_response));

	std::vector<uint8_t> second_response;
	ASSERT_TRUE(client.Query(second_query, &second_response)) << client.LastError();
	EXPECT_TRUE(DnsResponseHasAnswer(second_response));
}

TEST(HTTP2, DownstreamDohServerWithoutContentLengthReadsToEndStream)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	server.Start(R"""(bind-https [::]:60053 -alpn h2
address /no-content-length.test/6.6.6.6
log-level debug
)""");

	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> query = BuildDnsQuery("no-content-length.test", 0x3001);
	ASSERT_FALSE(query.empty());

	std::vector<uint8_t> response;
	ASSERT_TRUE(client.QueryWithoutContentLength(query, &response)) << client.LastError();
	EXPECT_TRUE(DnsResponseHasAnswer(response));
}

TEST(HTTP2, DownstreamDohServerReuseAfterInvalidContentLength)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	server.Start(R"""(bind-https [::]:60053 -alpn h2
address /reuse-after-bad.test/9.9.9.9
log-level debug
)""");

	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> bad_query = BuildDnsQuery("bad-content-length.test", 0x2001);
	std::vector<uint8_t> good_query = BuildDnsQuery("reuse-after-bad.test", 0x2002);
	ASSERT_FALSE(bad_query.empty());
	ASSERT_FALSE(good_query.empty());

	std::vector<uint8_t> bad_response;
	EXPECT_FALSE(client.QueryWithContentLength(bad_query, bad_query.size() + 1, &bad_response));

	std::vector<uint8_t> good_response;
	ASSERT_TRUE(client.Query(good_query, &good_response)) << client.LastError();
	EXPECT_TRUE(DnsResponseHasAnswer(good_response));
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
