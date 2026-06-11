#include "client.h"
#include "server.h"
#include "smartdns/dns.h"
#include "smartdns/http2.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

const char *HTTP2_TEST_CERT_FILE = "/tmp/smartdns-http2-test-cert.pem";
const char *HTTP2_TEST_KEY_FILE = "/tmp/smartdns-http2-test-key.pem";

bool EnsureHTTP2TestCert()
{
	if (access(HTTP2_TEST_CERT_FILE, F_OK) == 0 && access(HTTP2_TEST_KEY_FILE, F_OK) == 0) {
		return true;
	}

	return generate_cert_key(HTTP2_TEST_KEY_FILE, HTTP2_TEST_CERT_FILE, NULL, "DNS:smartdns,IP:127.0.0.1", 1) == 0;
}

class HTTP2DoHClient
{
  public:
	struct PendingResponse {
		struct http2_stream *stream = nullptr;
		std::vector<uint8_t> response;
		int status = 0;
		bool done = false;
		bool ok = false;
		std::string error;
	};

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
			last_error_ = std::string("socket failed: ") + strerror(errno);
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
			last_error_ = std::string("connect failed: ") + strerror(errno);
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
		int ssl_connect_ret = SSL_connect(ssl_);
		if (ssl_connect_ret != 1) {
			int ssl_get_error = SSL_get_error(ssl_, ssl_connect_ret);
			int saved_errno = errno;
			unsigned long ssl_error = ERR_get_error();
			char ssl_error_string[256] = {0};
			if (ssl_error != 0) {
				ERR_error_string_n(ssl_error, ssl_error_string, sizeof(ssl_error_string));
			}
			last_error_ = std::string("SSL_connect failed: ") + (ssl_error_string[0] ? ssl_error_string : "no ssl error");
			last_error_ += ", ssl_get_error=" + std::to_string(ssl_get_error);
			last_error_ += ", errno=" + std::to_string(saved_errno);
			last_error_ += "(" + std::string(strerror(saved_errno)) + ")";
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

	bool QueryStatus(const std::vector<uint8_t> &request, int *status, std::vector<uint8_t> *response)
	{
		if (ctx_ == nullptr || response == nullptr || status == nullptr) {
			last_error_ = "query status without connected ctx";
			return false;
		}

		struct http2_stream *stream = http2_stream_new(ctx_);
		if (stream == nullptr) {
			last_error_ = "http2_stream_new failed";
			return false;
		}

		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", request.size());
		struct http2_header_pair headers[4] = {{"content-type", "application/dns-message"},
											   {"accept", "application/dns-message"},
											   {"content-length", content_length},
											   {NULL, NULL}};

		if (http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers) != 0 ||
			http2_stream_write_body(stream, request.data(), request.size(), 1) < 0) {
			last_error_ = "write request failed";
			http2_stream_close(stream);
			return false;
		}

		bool ok = WaitAnyResponse(stream, status, response);
		http2_stream_close(stream);
		return ok;
	}

	bool StartQuery(const std::vector<uint8_t> &request, PendingResponse *pending)
	{
		if (ctx_ == nullptr || pending == nullptr) {
			last_error_ = "start query without connected ctx";
			return false;
		}

		pending->response.clear();
		pending->status = 0;
		pending->done = false;
		pending->ok = false;
		pending->error.clear();

		struct http2_stream *stream = http2_stream_new(ctx_);
		if (stream == nullptr) {
			last_error_ = "http2_stream_new failed";
			return false;
		}

		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", request.size());
		struct http2_header_pair headers[4] = {{"content-type", "application/dns-message"},
											   {"accept", "application/dns-message"},
											   {"content-length", content_length},
											   {NULL, NULL}};

		if (http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers) != 0 ||
			http2_stream_write_body(stream, request.data(), request.size(), 1) < 0) {
			last_error_ = "write request failed";
			http2_stream_close(stream);
			return false;
		}

		pending->stream = stream;
		return true;
	}

	bool PumpPending(std::vector<PendingResponse> *pending_responses, int poll_timeout_ms)
	{
		if (ctx_ == nullptr || pending_responses == nullptr) {
			last_error_ = "pump without connected ctx";
			return false;
		}

		struct pollfd pfd = {fd_, POLLIN | POLLOUT, 0};
		poll(&pfd, 1, poll_timeout_ms);

		int ret = http2_ctx_poll(ctx_, NULL, 0, NULL);
		if (ret < 0 && ret != HTTP2_ERR_EAGAIN) {
			last_error_ = std::string("http2 poll failed: ") + http2_error_to_string(ret);
			return false;
		}

		for (auto &pending : *pending_responses) {
			if (pending.done || pending.stream == nullptr) {
				continue;
			}

			uint8_t buf[1024];
			while (true) {
				int len = http2_stream_read_body(pending.stream, buf, sizeof(buf));
				if (len > 0) {
					pending.response.insert(pending.response.end(), buf, buf + len);
					continue;
				}

				if (len < 0 && errno != EAGAIN) {
					pending.error = std::string("read response failed: ") + strerror(errno);
					pending.done = true;
					pending.ok = false;
					http2_stream_close(pending.stream);
					pending.stream = nullptr;
					break;
				}
				break;
			}

			if (pending.stream != nullptr && http2_stream_get_status(pending.stream) == 200 &&
				http2_stream_is_end(pending.stream)) {
				pending.status = http2_stream_get_status(pending.stream);
				pending.done = true;
				pending.ok = !pending.response.empty();
				if (!pending.ok) {
					pending.error = "empty response";
				}
				http2_stream_close(pending.stream);
				pending.stream = nullptr;
				continue;
			}

			if (pending.stream != nullptr && http2_stream_is_end(pending.stream) &&
				http2_stream_get_status(pending.stream) != 200) {
				pending.status = http2_stream_get_status(pending.stream);
				pending.done = true;
				pending.ok = false;
				pending.error = std::string("stream ended without response, status=") +
								std::to_string(http2_stream_get_status(pending.stream));
				http2_stream_close(pending.stream);
				pending.stream = nullptr;
			}
		}

		return true;
	}

	void ClosePending(std::vector<PendingResponse> *pending_responses)
	{
		if (pending_responses == nullptr) {
			return;
		}

		for (auto &pending : *pending_responses) {
			if (pending.stream != nullptr) {
				http2_stream_close(pending.stream);
				pending.stream = nullptr;
			}
		}
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

	bool WaitAnyResponse(struct http2_stream *stream, int *status, std::vector<uint8_t> *response)
	{
		response->clear();
		*status = 0;

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

			if (http2_stream_is_end(stream)) {
				*status = http2_stream_get_status(stream);
				return *status > 0;
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

bool DnsResponseIsReply(const std::vector<uint8_t> &response)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;

	if (dns_decode(packet, sizeof(packet_buff), (unsigned char *)response.data(), response.size()) != 0) {
		return false;
	}

	return packet->head.qr == DNS_QR_ANSWER;
}

std::string NormalizeDnsName(const std::string &name)
{
	std::string result(name);
	while (!result.empty() && result.back() == '.') {
		result.pop_back();
	}
	for (auto &c : result) {
		c = std::tolower(static_cast<unsigned char>(c));
	}
	return result;
}

std::string DnsResponseSummary(const std::vector<uint8_t> &response)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	char domain[DNS_MAX_CNAME_LEN] = {0};
	int qtype = 0;
	int qclass = 0;
	int rr_count = 0;
	struct dns_rrs *rrs = NULL;

	if (dns_decode(packet, sizeof(packet_buff), (unsigned char *)response.data(), response.size()) != 0) {
		return "decode failed";
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	if (rrs != NULL) {
		dns_get_domain(rrs, domain, sizeof(domain), &qtype, &qclass);
	}

	return "id=" + std::to_string(packet->head.id) + ", qname=" + domain +
		   ", rcode=" + std::to_string(packet->head.rcode) +
		   ", ancount=" + std::to_string(packet->head.ancount);
}

bool DnsResponseHasA(const std::vector<uint8_t> &response, const char *expected_ip, std::string *error)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	unsigned char expected_addr[DNS_RR_A_LEN];

	if (inet_pton(AF_INET, expected_ip, expected_addr) != 1) {
		*error = std::string("invalid expected IP: ") + expected_ip;
		return false;
	}

	if (dns_decode(packet, sizeof(packet_buff), (unsigned char *)response.data(), response.size()) != 0) {
		*error = "decode failed";
		return false;
	}

	if (packet->head.qr != DNS_QR_ANSWER || packet->head.rcode != DNS_RC_NOERROR) {
		*error = "unexpected response: " + DnsResponseSummary(response);
		return false;
	}

	int answer_count = 0;
	struct dns_rrs *rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &answer_count);
	for (int i = 0; i < answer_count && rrs != nullptr; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		char domain[DNS_MAX_CNAME_LEN] = {0};
		unsigned char addr[DNS_RR_A_LEN];
		int ttl = 0;

		if (dns_get_A(rrs, domain, sizeof(domain), &ttl, addr) != 0) {
			continue;
		}

		if (memcmp(addr, expected_addr, sizeof(addr)) == 0) {
			return true;
		}
	}

	*error = "expected A record not found: " + DnsResponseSummary(response);
	return false;
}

bool DnsResponseIsValidForQuery(const std::vector<uint8_t> &response, uint16_t expected_id,
							   const std::string &expected_domain, const char *expected_ip, std::string *error)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char encoded_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	unsigned char expected_addr[DNS_RR_A_LEN];
	char domain[DNS_MAX_CNAME_LEN] = {0};
	int qtype = 0;
	int qclass = 0;
	int qd_count = 0;

	if (inet_pton(AF_INET, expected_ip, expected_addr) != 1) {
		*error = std::string("invalid expected IP: ") + expected_ip;
		return false;
	}

	if (dns_decode(packet, sizeof(packet_buff), (unsigned char *)response.data(), response.size()) != 0) {
		*error = "decode failed";
		return false;
	}

	if (packet->head.id != expected_id) {
		*error = "query id mismatch: expect=" + std::to_string(expected_id) +
				 ", actual=" + std::to_string(packet->head.id) + ", " + DnsResponseSummary(response);
		return false;
	}

	struct dns_rrs *query_rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &qd_count);
	if (qd_count != 1 || query_rrs == nullptr) {
		*error = "invalid question section: " + DnsResponseSummary(response);
		return false;
	}

	if (dns_get_domain(query_rrs, domain, sizeof(domain), &qtype, &qclass) != 0 ||
		qtype != DNS_T_A || qclass != DNS_C_IN) {
		*error = "query parse failed: " + DnsResponseSummary(response);
		return false;
	}

	std::string response_domain = NormalizeDnsName(domain);
	std::string expected_domain_normalized = NormalizeDnsName(expected_domain);
	if (expected_domain_normalized != response_domain) {
		*error = "unexpected qname: expect=" + expected_domain_normalized + ", actual=" + response_domain +
				 ", " + DnsResponseSummary(response);
		return false;
	}

	if (packet->head.qr != DNS_QR_ANSWER || packet->head.rcode != DNS_RC_NOERROR) {
		*error = "unexpected response: " + DnsResponseSummary(response);
		return false;
	}

	int encoded_len = dns_encode(encoded_buff, sizeof(encoded_buff), packet);
	if (encoded_len <= 0) {
		*error = "dns_encode failed: " + DnsResponseSummary(response);
		return false;
	}
	if ((size_t)encoded_len != response.size()) {
		*error = "dns body length mismatch: body=" + std::to_string(response.size()) +
				 ", encoded=" + std::to_string(encoded_len) + ", " + DnsResponseSummary(response);
		return false;
	}

	int answer_count = 0;
	struct dns_rrs *rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &answer_count);
	for (int i = 0; i < answer_count && rrs != nullptr; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		char rr_domain[DNS_MAX_CNAME_LEN] = {0};
		unsigned char addr[DNS_RR_A_LEN];
		int ttl = 0;

		if (dns_get_A(rrs, rr_domain, sizeof(rr_domain), &ttl, addr) != 0) {
			continue;
		}

		if (memcmp(addr, expected_addr, sizeof(addr)) == 0) {
			return true;
		}
	}

	*error = "expected A record not found: " + DnsResponseSummary(response);
	return false;
}

bool AllPendingDone(const std::vector<std::vector<HTTP2DoHClient::PendingResponse>> &pending_by_client)
{
	for (const auto &pending_list : pending_by_client) {
		for (const auto &pending : pending_list) {
			if (!pending.done) {
				return false;
			}
		}
	}

	return true;
}

std::string BuildConcurrentDomain(int client_index, int stream_index)
{
	return "h2-" + std::to_string(client_index) + "-" + std::to_string(stream_index) + ".example.com";
}

std::string BuildConcurrentDomain(const char *scenario, int client_index, int stream_index)
{
	return "h2-" + std::string(scenario) + "-" + std::to_string(client_index) + "-" +
		   std::to_string(stream_index) + ".example.com";
}

std::string BuildRandomComDomain(int index)
{
	uint32_t value = 0x9e3779b9u * (uint32_t)(index + 1) + 0x7f4a7c15u;
	return "h2-chain-" + std::to_string(value) + "-" + std::to_string(index) + ".com";
}

struct HTTP2DoHStressStats {
	int total = 0;
	int completed = 0;
	int success = 0;
	long duration_ms = 0;
	std::string first_failure;
};

HTTP2DoHStressStats RunDownstreamDohManyConnectionsManyStreams(int client_count, int streams_per_client, int port,
															   const char *scenario, int timeout_seconds)
{
	const int total_queries = client_count * streams_per_client;
	std::vector<std::unique_ptr<HTTP2DoHClient>> clients;
	std::vector<std::vector<HTTP2DoHClient::PendingResponse>> pending_by_client(client_count);
	clients.reserve(client_count);

	for (int client_index = 0; client_index < client_count; client_index++) {
		std::unique_ptr<HTTP2DoHClient> client(new HTTP2DoHClient());
		if (!client->Connect("127.0.0.1", port)) {
			HTTP2DoHStressStats stats;
			stats.total = total_queries;
			stats.first_failure = std::string("connect failed: ") + client->LastError();
			return stats;
		}
		pending_by_client[client_index].resize(streams_per_client);

		for (int stream_index = 0; stream_index < streams_per_client; stream_index++) {
			uint16_t id = (uint16_t)(0x4000 + client_index * streams_per_client + stream_index);
			std::string domain = BuildConcurrentDomain(scenario, client_index, stream_index);
			std::vector<uint8_t> query = BuildDnsQuery(domain.c_str(), id);
			if (query.empty()) {
				HTTP2DoHStressStats stats;
				stats.total = total_queries;
				stats.first_failure = domain + ": build DNS query failed";
				return stats;
			}
			if (!client->StartQuery(query, &pending_by_client[client_index][stream_index])) {
				HTTP2DoHStressStats stats;
				stats.total = total_queries;
				stats.first_failure = domain + ": start query failed: " + client->LastError();
				return stats;
			}
		}

		clients.push_back(std::move(client));
	}

	auto start = std::chrono::steady_clock::now();
	auto deadline = start + std::chrono::seconds(timeout_seconds);
	while (std::chrono::steady_clock::now() < deadline && !AllPendingDone(pending_by_client)) {
		for (int client_index = 0; client_index < client_count; client_index++) {
			if (!clients[client_index]->PumpPending(&pending_by_client[client_index], 1)) {
				HTTP2DoHStressStats stats;
				stats.total = total_queries;
				stats.first_failure = std::string(scenario) + ": pump failed: " + clients[client_index]->LastError();
				return stats;
			}
		}
	}
	auto end = std::chrono::steady_clock::now();

	HTTP2DoHStressStats stats;
	stats.total = total_queries;
	stats.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

	for (int client_index = 0; client_index < client_count; client_index++) {
		for (int stream_index = 0; stream_index < streams_per_client; stream_index++) {
			auto &pending = pending_by_client[client_index][stream_index];
			std::string domain = BuildConcurrentDomain(scenario, client_index, stream_index);
			if (pending.done) {
				stats.completed++;
				std::string dns_error;
				if (pending.ok && DnsResponseHasA(pending.response, "1.2.3.4", &dns_error)) {
					stats.success++;
				} else if (stats.first_failure.empty()) {
					stats.first_failure = domain + ": status=" + std::to_string(pending.status) +
										  ", error=" + pending.error + ", bytes=" +
										  std::to_string(pending.response.size()) + ", " + dns_error;
				}
			} else if (stats.first_failure.empty()) {
				stats.first_failure = domain + ": not completed, status=" + std::to_string(pending.status) +
									  ", bytes=" + std::to_string(pending.response.size());
			}
		}
		clients[client_index]->ClosePending(&pending_by_client[client_index]);
	}

	return stats;
}

bool UdpQueryHasA(const std::string &domain, int port, uint16_t id, const char *expected_ip, std::string *error)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		*error = std::string("socket failed: ") + strerror(errno);
		return false;
	}

	struct timeval timeout = {};
	timeout.tv_sec = 5;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
		*error = "inet_pton failed";
		close(fd);
		return false;
	}

	std::vector<uint8_t> query = BuildDnsQuery(domain.c_str(), id);
	if (query.empty()) {
		*error = "build DNS query failed";
		close(fd);
		return false;
	}

	ssize_t send_len = sendto(fd, query.data(), query.size(), 0, (struct sockaddr *)&addr, sizeof(addr));
	if (send_len != (ssize_t)query.size()) {
		*error = std::string("sendto failed: ") + strerror(errno);
		close(fd);
		return false;
	}

	unsigned char response[DNS_PACKSIZE];
	ssize_t recv_len = recvfrom(fd, response, sizeof(response), 0, nullptr, nullptr);
	if (recv_len <= 0) {
		*error = std::string("recvfrom failed: ") + strerror(errno);
		close(fd);
		return false;
	}

	close(fd);

	std::vector<uint8_t> response_data(response, response + recv_len);
	return DnsResponseHasA(response_data, expected_ip, error);
}

struct ConcurrentUdpQueryStats {
	int total = 0;
	int success = 0;
	int failure = 0;
	long duration_ms = 0;
	double qps = 0;
	std::string first_failure;
};

ConcurrentUdpQueryStats RunConcurrentUdpAQueries(int query_count, int port, const char *expected_ip)
{
	std::atomic<int> total_queries{0};
	std::atomic<int> success_count{0};
	std::atomic<int> failure_count{0};
	std::vector<std::string> failures(query_count);
	std::vector<std::thread> client_threads;
	client_threads.reserve(query_count);

	auto start_time = std::chrono::steady_clock::now();
	for (int i = 0; i < query_count; i++) {
		client_threads.emplace_back([i, port, expected_ip, &total_queries, &success_count, &failure_count, &failures]() {
			std::string domain = BuildRandomComDomain(i);
			std::string error;
			total_queries++;
			if (UdpQueryHasA(domain, port, 0x8000 + i, expected_ip, &error)) {
				success_count++;
				return;
			}

			failures[i] = domain + ": " + error;
			failure_count++;
		});
	}

	for (auto &thread : client_threads) {
		thread.join();
	}

	auto end_time = std::chrono::steady_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

	ConcurrentUdpQueryStats stats;
	stats.total = total_queries.load();
	stats.success = success_count.load();
	stats.failure = failure_count.load();
	stats.duration_ms = duration.count();
	stats.qps = duration.count() > 0 ? (query_count * 1000.0) / duration.count() : 0;
	for (const auto &failure : failures) {
		if (!failure.empty()) {
			stats.first_failure = failure;
			break;
		}
	}

	return stats;
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
address /reuse-one.example.com/1.2.3.4
address /reuse-two.example.com/5.6.7.8
log-level debug
)""");

	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> first_query = BuildDnsQuery("reuse-one.example.com", 0x1001);
	std::vector<uint8_t> second_query = BuildDnsQuery("reuse-two.example.com", 0x1002);
	ASSERT_FALSE(first_query.empty());
	ASSERT_FALSE(second_query.empty());

	std::vector<uint8_t> first_response;
	ASSERT_TRUE(client.Query(first_query, &first_response)) << client.LastError();
	EXPECT_TRUE(DnsResponseIsReply(first_response));

	std::vector<uint8_t> second_response;
	ASSERT_TRUE(client.Query(second_query, &second_response)) << client.LastError();
	EXPECT_TRUE(DnsResponseIsReply(second_response));
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
address /no-content-length.example.com/6.6.6.6
log-level debug
)""");

	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> query = BuildDnsQuery("no-content-length.example.com", 0x3001);
	ASSERT_FALSE(query.empty());

	std::vector<uint8_t> response;
	ASSERT_TRUE(client.QueryWithoutContentLength(query, &response)) << client.LastError();
	EXPECT_TRUE(DnsResponseIsReply(response));
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
address /reuse-after-bad.example.com/9.9.9.9
log-level debug
)""");

	HTTP2DoHClient client;
	usleep(200000);
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> bad_query = BuildDnsQuery("bad-content-length.example.com", 0x2001);
	std::vector<uint8_t> good_query = BuildDnsQuery("reuse-after-bad.example.com", 0x2002);
	ASSERT_FALSE(bad_query.empty());
	ASSERT_FALSE(good_query.empty());

	std::vector<uint8_t> bad_response;
	EXPECT_FALSE(client.QueryWithContentLength(bad_query, bad_query.size() + 1, &bad_response));

	std::vector<uint8_t> good_response;
	ASSERT_TRUE(client.Query(good_query, &good_response)) << client.LastError();
	EXPECT_TRUE(DnsResponseIsReply(good_response));
}

TEST(HTTP2, DownstreamDohServerInvalidDnsBodyGetsFailureResponse)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	ASSERT_TRUE(server.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
log-level error
)"""));

	usleep(200000);

	HTTP2DoHClient client;
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	std::vector<uint8_t> invalid_dns_body = {0x12};
	std::vector<uint8_t> response;
	int status = 0;
	ASSERT_TRUE(client.QueryStatus(invalid_dns_body, &status, &response)) << client.LastError();
	EXPECT_EQ(status, 400);
	EXPECT_FALSE(response.empty());
}

TEST(HTTP2, DownstreamDohServerManyConnectionsManyConcurrentStreams)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	server.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
log-level error
)""");

	usleep(200000);

	const int client_count = 8;
	const int streams_per_client = 200;
	const int total_queries = client_count * streams_per_client;
	std::vector<std::unique_ptr<HTTP2DoHClient>> clients;
	std::vector<std::vector<HTTP2DoHClient::PendingResponse>> pending_by_client(client_count);

	for (int client_index = 0; client_index < client_count; client_index++) {
		std::unique_ptr<HTTP2DoHClient> client(new HTTP2DoHClient());
		ASSERT_TRUE(client->Connect("127.0.0.1", 60053)) << client->LastError();
		pending_by_client[client_index].resize(streams_per_client);

		for (int stream_index = 0; stream_index < streams_per_client; stream_index++) {
			uint16_t id = 0x4000 + client_index * streams_per_client + stream_index;
			std::string domain = BuildConcurrentDomain(client_index, stream_index);
			std::vector<uint8_t> query = BuildDnsQuery(domain.c_str(), id);
			ASSERT_FALSE(query.empty());
			ASSERT_TRUE(client->StartQuery(query, &pending_by_client[client_index][stream_index]))
				<< client->LastError();
		}

		clients.push_back(std::move(client));
	}

	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline && !AllPendingDone(pending_by_client)) {
		for (int client_index = 0; client_index < client_count; client_index++) {
			ASSERT_TRUE(clients[client_index]->PumpPending(&pending_by_client[client_index], 1))
				<< clients[client_index]->LastError();
		}
	}

	int completed = 0;
	int success = 0;
	std::string first_failure;
	for (int client_index = 0; client_index < client_count; client_index++) {
		for (int stream_index = 0; stream_index < streams_per_client; stream_index++) {
			auto &pending = pending_by_client[client_index][stream_index];
			if (pending.done) {
				completed++;
				if (pending.ok && DnsResponseIsReply(pending.response)) {
					success++;
				} else if (first_failure.empty()) {
					first_failure = BuildConcurrentDomain(client_index, stream_index) + ": " + pending.error +
									", bytes=" + std::to_string(pending.response.size());
				}
			} else if (first_failure.empty()) {
				first_failure = BuildConcurrentDomain(client_index, stream_index) + ": not completed, bytes=" +
								std::to_string(pending.response.size());
			}
		}
		clients[client_index]->ClosePending(&pending_by_client[client_index]);
	}

	EXPECT_EQ(completed, total_queries) << first_failure;
	EXPECT_EQ(success, total_queries) << first_failure;
}

TEST(HTTP2, DownstreamDohServerToHttp2UpstreamManyConnectionsManyStreams)
{
	Defer
	{
		unlink(HTTP2_TEST_CERT_FILE);
		unlink(HTTP2_TEST_KEY_FILE);
		unlink("/tmp/root-ca.key");
	};

	smartdns::Server server_wrap;
	smartdns::Server server;

	ASSERT_TRUE(EnsureHTTP2TestCert());
	ASSERT_TRUE(server_wrap.Start(R"""(bind-https [::]:62054 -alpn h2
bind-cert-file /tmp/smartdns-http2-test-cert.pem
bind-cert-key-file /tmp/smartdns-http2-test-key.pem
address /example.com/1.2.3.4
speed-check-mode none
log-level error
)"""));

	ASSERT_TRUE(server.Start(R"""(bind-https [::]:62053 -alpn h2
bind-cert-file /tmp/smartdns-http2-test-cert.pem
bind-cert-key-file /tmp/smartdns-http2-test-key.pem
server https://127.0.0.1:62054/dns-query -no-check-certificate -alpn h2
speed-check-mode none
log-level error
)"""));

	usleep(2000000);

	struct Scenario {
		const char *name;
		int client_count;
		int streams_per_client;
	};
	const Scenario scenarios[] = {
		{"upstream-20x500", 20, 500},
		{"upstream-50x100", 50, 100},
		{"upstream-100x50", 100, 50},
	};
	const int max_attempts = 3;

	for (const auto &scenario : scenarios) {
		HTTP2DoHStressStats stats;
		for (int attempt = 1; attempt <= max_attempts; attempt++) {
			std::string attempt_name = std::string(scenario.name) + "-attempt-" + std::to_string(attempt);
			stats = RunDownstreamDohManyConnectionsManyStreams(
				scenario.client_count, scenario.streams_per_client, 62053, attempt_name.c_str(), 30);
			std::cout << "HTTP2 DoH upstream client stress " << scenario.name << " attempt=" << attempt << "/"
					  << max_attempts << ": total=" << stats.total << ", completed=" << stats.completed
					  << ", success=" << stats.success << ", duration=" << stats.duration_ms << "ms" << std::endl;
			if (stats.completed == stats.total && stats.success == stats.total) {
				break;
			}
		}

		ASSERT_EQ(stats.completed, stats.total) << stats.first_failure;
		ASSERT_EQ(stats.success, stats.total) << stats.first_failure;
	}
}

TEST(HTTP2, DownstreamDohServerRouterOSLikeConcurrency)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	ASSERT_TRUE(server.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
speed-check-mode none
log-level error
)"""));

	usleep(200000);

	struct Scenario {
		const char *name;
		int client_count;
		int streams_per_client;
	};
	const Scenario scenarios[] = {
		{"20x500", 20, 500},
		{"20x1000", 20, 1000},
		{"50x100", 50, 100},
		{"50x500", 50, 500},
		{"100x50", 100, 50},
		{"100x200", 100, 200},
		{"100x500", 100, 500},
		{"200x100", 200, 100},
		{"200x250", 200, 250},
	};

	for (const auto &scenario : scenarios) {
		HTTP2DoHStressStats stats = RunDownstreamDohManyConnectionsManyStreams(
			scenario.client_count, scenario.streams_per_client, 60053, scenario.name, 15);
		std::cout << "HTTP2 DoH downstream RouterOS-like stress " << scenario.name << ": total=" << stats.total
				  << ", completed=" << stats.completed << ", success=" << stats.success
				  << ", duration=" << stats.duration_ms << "ms" << std::endl;

		ASSERT_EQ(stats.completed, stats.total) << stats.first_failure;
		ASSERT_EQ(stats.success, stats.total) << stats.first_failure;
	}
}

TEST(HTTP2, DownstreamDohServerToHttp2UpstreamSingleConnectionManyConcurrentStreams)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server_wrap;
	smartdns::Server server;

	ASSERT_TRUE(server.Start(R"""(bind-https [::]:61053 -alpn h2
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
speed-check-mode none
log-level error
)"""));

	ASSERT_TRUE(server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /com/1.2.3.4
speed-check-mode none
log-level error
)"""));

	usleep(500000);

	const int stream_count = 1024;
	HTTP2DoHClient client;
	std::vector<HTTP2DoHClient::PendingResponse> pending(stream_count);

	ASSERT_TRUE(client.Connect("127.0.0.1", 61053)) << client.LastError();
	for (int stream_index = 0; stream_index < stream_count; stream_index++) {
		uint16_t id = 0x9000 + stream_index;
		std::string domain = BuildRandomComDomain(stream_index);
		std::vector<uint8_t> query = BuildDnsQuery(domain.c_str(), id);
		ASSERT_FALSE(query.empty());
		ASSERT_TRUE(client.StartQuery(query, &pending[stream_index])) << client.LastError();
	}

	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline) {
		ASSERT_TRUE(client.PumpPending(&pending, 1)) << client.LastError();
		bool all_done = true;
		for (const auto &item : pending) {
			if (!item.done) {
				all_done = false;
				break;
			}
		}
		if (all_done) {
			break;
		}
	}

	int completed = 0;
	int success = 0;
	std::string first_failure;
	for (int stream_index = 0; stream_index < stream_count; stream_index++) {
		auto &item = pending[stream_index];
		if (item.done) {
			completed++;
			std::string error;
			if (item.ok && DnsResponseHasA(item.response, "1.2.3.4", &error)) {
				success++;
			} else if (first_failure.empty()) {
				first_failure = "stream " + std::to_string(stream_index) + ": " + item.error +
								", bytes=" + std::to_string(item.response.size()) + ", " + error;
			}
		} else if (first_failure.empty()) {
			first_failure = "stream " + std::to_string(stream_index) + ": not completed, bytes=" +
							std::to_string(item.response.size());
		}
	}
	client.ClosePending(&pending);

	EXPECT_EQ(completed, stream_count) << first_failure;
	EXPECT_EQ(success, stream_count) << first_failure;
}

TEST(HTTP2, DownstreamDohServerSingleConnectionPostBacklogExactDnsBody)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	ASSERT_TRUE(server.Start(R"""(bind-https [::]:60053 -alpn h2
address /com/1.2.3.4
speed-check-mode none
log-level error
)"""));

	usleep(200000);

	const int stream_count = 2048;
	const int rounds = 3;
	HTTP2DoHClient client;
	ASSERT_TRUE(client.Connect("127.0.0.1", 60053)) << client.LastError();

	for (int round = 0; round < rounds; round++) {
		std::vector<HTTP2DoHClient::PendingResponse> pending(stream_count);
		std::vector<uint16_t> query_ids(stream_count);
		std::vector<std::string> domains(stream_count);

		for (int stream_index = 0; stream_index < stream_count; stream_index++) {
			query_ids[stream_index] = (uint16_t)(0xA000 + round * stream_count + stream_index);
			domains[stream_index] = "h2-post-backlog-" + std::to_string(round) + "-" +
									std::to_string(stream_index) + "-padding-" +
									std::string((stream_index % 17) + 1, 'x') + ".com";
			std::vector<uint8_t> query = BuildDnsQuery(domains[stream_index].c_str(), query_ids[stream_index]);
			ASSERT_FALSE(query.empty());
			ASSERT_TRUE(client.StartQuery(query, &pending[stream_index])) << client.LastError();
			if ((stream_index + 1) % 32 == 0) {
				ASSERT_TRUE(client.PumpPending(&pending, 0)) << client.LastError();
			}
		}

		usleep(50000);

		auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
		while (std::chrono::steady_clock::now() < deadline) {
			ASSERT_TRUE(client.PumpPending(&pending, 1)) << client.LastError();
			bool all_done = true;
			for (const auto &item : pending) {
				if (!item.done) {
					all_done = false;
					break;
				}
			}
			if (all_done) {
				break;
			}
		}

		std::string first_failure;
		int success = 0;
		for (int stream_index = 0; stream_index < stream_count; stream_index++) {
			auto &item = pending[stream_index];
			std::string dns_error;
			if (item.done && item.status == 200 &&
				DnsResponseIsValidForQuery(item.response, query_ids[stream_index], domains[stream_index], "1.2.3.4",
										  &dns_error)) {
				success++;
				continue;
			}

			if (first_failure.empty()) {
				first_failure = "round=" + std::to_string(round) + ", stream=" + std::to_string(stream_index) +
								", done=" + std::to_string(item.done) + ", status=" + std::to_string(item.status) +
								", bytes=" + std::to_string(item.response.size()) + ", item_error=" + item.error +
								", dns_error=" + dns_error;
			}
		}

		client.ClosePending(&pending);
		ASSERT_EQ(success, stream_count) << first_failure;
	}
}

TEST(HTTP2, UdpDownstreamToHttp2UpstreamManyConcurrentQueries)
{
	smartdns::Server server_wrap;
	smartdns::Server server;

	ASSERT_TRUE(server.Start(R"""(bind [::]:61053
server https://127.0.0.1:60053/dns-query -no-check-certificate -alpn h2
socket-buff-size 4M
speed-check-mode none
log-level error
)"""));

	ASSERT_TRUE(server_wrap.Start(R"""(bind-https [::]:60053 -alpn h2
address /com/1.2.3.4
speed-check-mode none
log-level error
)"""));

	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	const int query_count = 1024;
	ConcurrentUdpQueryStats stats = RunConcurrentUdpAQueries(query_count, 61053, "1.2.3.4");
	std::cout << "HTTP2 upstream chained stress: total=" << stats.total << ", success=" << stats.success
			  << ", failure=" << stats.failure << ", duration=" << stats.duration_ms << "ms, qps=" << stats.qps
			  << std::endl;

	EXPECT_EQ(stats.total, query_count);
	EXPECT_EQ(stats.success, query_count) << stats.first_failure;
	EXPECT_EQ(stats.failure, 0) << stats.first_failure;
}

TEST(HTTP2, DownstreamDohServerHighConcurrencyWithRetry)
{
	Defer
	{
		unlink("/tmp/smartdns-cert.pem");
		unlink("/tmp/smartdns-key.pem");
	};

	smartdns::Server server;
	ASSERT_TRUE(server.Start(R"""(bind-https [::]:60053 -alpn h2
address /example.com/1.2.3.4
log-level error
)"""));

	usleep(200000);

	const int client_count = 32;
	const int streams_per_client = 1024;
	const int total_queries = client_count * streams_per_client;
	const int max_attempts = 3;
	const int first_attempt_timeout_ms = 1;
	const int retry_timeout_ms = 15000;
	std::vector<std::unique_ptr<HTTP2DoHClient>> clients;
	std::vector<std::vector<int>> outstanding_by_client(client_count);

	for (int client_index = 0; client_index < client_count; client_index++) {
		std::unique_ptr<HTTP2DoHClient> client(new HTTP2DoHClient());
		ASSERT_TRUE(client->Connect("127.0.0.1", 60053)) << client->LastError();
		clients.push_back(std::move(client));

		outstanding_by_client[client_index].reserve(streams_per_client);
		for (int stream_index = 0; stream_index < streams_per_client; stream_index++) {
			outstanding_by_client[client_index].push_back(stream_index);
		}
	}

	int success = 0;
	int retry_count = 0;
	std::string first_failure;

	for (int attempt = 0; attempt < max_attempts; attempt++) {
		std::vector<std::vector<HTTP2DoHClient::PendingResponse>> pending_by_client(client_count);

		for (int client_index = 0; client_index < client_count; client_index++) {
			pending_by_client[client_index].resize(outstanding_by_client[client_index].size());
			for (size_t i = 0; i < outstanding_by_client[client_index].size(); i++) {
				int stream_index = outstanding_by_client[client_index][i];
				uint16_t id = 0x5000 + client_index * streams_per_client + stream_index;
				std::string domain = BuildConcurrentDomain(client_index, stream_index);
				std::vector<uint8_t> query = BuildDnsQuery(domain.c_str(), id);
				ASSERT_FALSE(query.empty());
				ASSERT_TRUE(clients[client_index]->StartQuery(query, &pending_by_client[client_index][i]))
					<< clients[client_index]->LastError();
				if ((i + 1) % 16 == 0) {
					ASSERT_TRUE(clients[client_index]->PumpPending(&pending_by_client[client_index], 0))
						<< clients[client_index]->LastError();
				}
			}
		}

		int timeout_ms = attempt == 0 ? first_attempt_timeout_ms : retry_timeout_ms;
		auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
		while (std::chrono::steady_clock::now() < deadline && !AllPendingDone(pending_by_client)) {
			for (int client_index = 0; client_index < client_count; client_index++) {
				ASSERT_TRUE(clients[client_index]->PumpPending(&pending_by_client[client_index], 1))
					<< clients[client_index]->LastError();
			}
		}

		std::vector<std::vector<int>> retry_by_client(client_count);
		for (int client_index = 0; client_index < client_count; client_index++) {
			for (size_t i = 0; i < pending_by_client[client_index].size(); i++) {
				int stream_index = outstanding_by_client[client_index][i];
				auto &pending = pending_by_client[client_index][i];
				std::string domain = BuildConcurrentDomain(client_index, stream_index);
				std::string dns_error;
				uint16_t id = 0x5000 + client_index * streams_per_client + stream_index;
				if (pending.done && pending.ok &&
					DnsResponseIsValidForQuery(pending.response, id, domain, "1.2.3.4", &dns_error)) {
					success++;
					continue;
				}

				retry_by_client[client_index].push_back(stream_index);
				if (first_failure.empty()) {
					first_failure = domain + ": " + (pending.done ? pending.error : "not completed") +
									", dns-error=" + dns_error +
									", bytes=" + std::to_string(pending.response.size()) +
									", attempt=" + std::to_string(attempt + 1);
				}
			}
			clients[client_index]->ClosePending(&pending_by_client[client_index]);
		}

		if (attempt + 1 < max_attempts) {
			for (const auto &retry_list : retry_by_client) {
				retry_count += retry_list.size();
			}
		}

		outstanding_by_client = std::move(retry_by_client);
		bool has_outstanding = false;
		for (const auto &outstanding : outstanding_by_client) {
			if (!outstanding.empty()) {
				has_outstanding = true;
				break;
			}
		}
		if (!has_outstanding) {
			break;
		}
	}

	EXPECT_EQ(success, total_queries) << first_failure;
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
