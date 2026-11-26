#include "gtest/gtest.h"
#include "smartdns/http2.h"
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

/* Armed only around the API under test; other threads and test infrastructure
 * always use the real allocators. Count node/name/value allocations together. */
static thread_local int header_alloc_countdown;
static thread_local bool header_alloc_failed;
static bool FailHeaderAllocation()
{
	if (header_alloc_countdown > 0 && --header_alloc_countdown == 0) {
		header_alloc_failed = true;
		errno = ENOMEM;
		return true;
	}
	return false;
}
extern "C" void *__real_calloc(size_t, size_t);
extern "C" char *__real_strdup(const char *);
extern "C" void *__wrap_calloc(size_t n, size_t size)
{
	return FailHeaderAllocation() ? nullptr : __real_calloc(n, size);
}
extern "C" char *__wrap_strdup(const char *value)
{
	return FailHeaderAllocation() ? nullptr : __real_strdup(value);
}

namespace {
using Headers = std::vector<std::pair<std::string, std::string>>;
static void CollectHeader(void *arg, const char *name, const char *value)
{
	static_cast<Headers *>(arg)->emplace_back(name, value);
}
static Headers ReadHeaders(http2_stream *stream)
{
	Headers result;
	http2_stream_headers_walk(stream, CollectHeader, &result);
	return result;
}
static const http2_header_pair custom[] = {{"x-one", "first"}, {"x-two", "second"}, {nullptr, nullptr}};
static Headers RequestHeaders(const char *method)
{
	return {{":method", method}, {":path", "/assembly"}, {":scheme", "https"},
			{":authority", "assembly.test"}, {"x-one", "first"}, {"x-two", "second"}};
}
static Headers ResponseHeaders()
{
	return {{":status", "201"}, {"x-one", "first"}, {"x-two", "second"}};
}

struct Endpoint {
	std::vector<uint8_t> input;
	std::vector<uint8_t> wire;
	Endpoint *peer = nullptr;
	bool blocked = false;
	static int Read(void *arg, uint8_t *buf, int len)
	{
		auto *self = static_cast<Endpoint *>(arg);
		if (self->input.empty()) { errno = EAGAIN; return -1; }
		len = std::min(len, static_cast<int>(self->input.size()));
		memcpy(buf, self->input.data(), len);
		self->input.erase(self->input.begin(), self->input.begin() + len);
		return len;
	}
	static int Write(void *arg, const uint8_t *buf, int len)
	{
		auto *self = static_cast<Endpoint *>(arg);
		if (self->blocked) { errno = EAGAIN; return -1; }
		self->wire.insert(self->wire.end(), buf, buf + len);
		self->peer->input.insert(self->peer->input.end(), buf, buf + len);
		return len;
	}
};
struct Connection {
	Endpoint client_io, server_io;
	http2_ctx *client = nullptr, *server = nullptr;
	std::vector<http2_stream *> streams;
	~Connection()
	{
		header_alloc_countdown = 0;
		for (auto *stream : streams) http2_stream_close(stream);
		if (client) http2_ctx_close(client);
		if (server) http2_ctx_close(server);
	}
	void Init()
	{
		client_io.peer = &server_io;
		server_io.peer = &client_io;
		client = http2_ctx_client_new("assembly.test", Endpoint::Read, Endpoint::Write, &client_io, nullptr);
		server = http2_ctx_server_new("assembly.test", Endpoint::Read, Endpoint::Write, &server_io, nullptr);
		ASSERT_NE(client, nullptr);
		ASSERT_NE(server, nullptr);
		int cr = 0, sr = 0;
		for (int i = 0; i < 10; ++i) {
			cr = http2_ctx_handshake(client);
			sr = http2_ctx_handshake(server);
			if (cr == 1 && sr == 1) break;
		}
		ASSERT_EQ(cr, 1);
		ASSERT_EQ(sr, 1);
		Pump(client); Pump(server); Pump(client);
		client_io.wire.clear(); server_io.wire.clear();
	}
	static void Pump(http2_ctx *ctx)
	{
		int ret = http2_ctx_poll(ctx, nullptr, 0, nullptr);
		EXPECT_TRUE(ret >= 0 || ret == HTTP2_ERR_EAGAIN) << ret;
	}
	http2_stream *New()
	{
		auto *stream = http2_stream_new(client);
		if (stream) streams.push_back(stream);
		return stream;
	}
	http2_stream *Accept()
	{
		Pump(server);
		auto *stream = http2_ctx_accept_stream(server);
		if (stream) streams.push_back(stream);
		return stream;
	}
	void Close(http2_stream *stream)
	{
		streams.erase(std::find(streams.begin(), streams.end(), stream));
		http2_stream_close(stream);
	}
};

/* The nineteenth / tenth failpoint is the header block allocation, before
 * HPACK mutates its compression state. Earlier failpoints cover every field. */
TEST(HTTP2HeaderAssembly, RequestAllocationFailuresAreAtomicAndRetryable)
{
	for (const char *failed_method : {"GET", "HEAD", "POST"}) {
		for (const char *retry_method : {"GET", "HEAD", "POST"}) {
			for (int fail = 1; fail <= 19; ++fail) {
				SCOPED_TRACE(std::string(failed_method) + " -> " + retry_method + " allocation " + std::to_string(fail));
				Connection c; c.Init();
				auto *stream = c.New(); ASSERT_NE(stream, nullptr);
				const auto before = ReadHeaders(stream);
				header_alloc_failed = false; header_alloc_countdown = fail;
				int ret = http2_stream_set_request(stream, failed_method, "/assembly", nullptr, custom);
				int saved_errno = errno; header_alloc_countdown = 0;
				ASSERT_TRUE(header_alloc_failed);
				ASSERT_EQ(ret, -1); EXPECT_EQ(saved_errno, ENOMEM);
				EXPECT_EQ(ReadHeaders(stream), before);
				EXPECT_EQ(http2_stream_get_method(stream), nullptr);
				EXPECT_EQ(http2_stream_get_path(stream), nullptr);
				EXPECT_TRUE(c.client_io.wire.empty());
				EXPECT_EQ(http2_ctx_want_write(c.client), 0);
				ASSERT_EQ(http2_stream_set_request(stream, retry_method, "/assembly", nullptr, custom), 0);
				EXPECT_EQ(ReadHeaders(stream), RequestHeaders(retry_method));
				if (strcmp(retry_method, "POST") == 0) {
					const uint8_t body[] = {'o', 'k'};
					ASSERT_EQ(http2_stream_write_body(stream, body, sizeof(body), 1), 2);
				}
				auto *peer = c.Accept(); ASSERT_NE(peer, nullptr);
				EXPECT_EQ(ReadHeaders(peer), RequestHeaders(retry_method));
				if (strcmp(retry_method, "POST") == 0) {
					uint8_t body[2] = {};
					ASSERT_EQ(http2_stream_read_body(peer, body, sizeof(body)), 2);
					EXPECT_EQ(std::string(reinterpret_cast<char *>(body), 2), "ok");
				}
				EXPECT_EQ(http2_stream_is_remote_end(peer), 1);
			}
		}
	}
}

TEST(HTTP2HeaderAssembly, FailedIdleRequestClosesWithoutResetAndSiblingSucceeds)
{
	for (int fail = 1; fail <= 19; ++fail) {
		SCOPED_TRACE(fail);
		Connection c; c.Init();
		auto *stream = c.New(); ASSERT_NE(stream, nullptr);
		header_alloc_countdown = fail;
		int ret = http2_stream_set_request(stream, "GET", "/assembly", nullptr, custom);
		header_alloc_countdown = 0;
		ASSERT_EQ(ret, -1);
		c.Close(stream);
		Connection::Pump(c.client);
		EXPECT_TRUE(c.client_io.wire.empty()) << "Idle close must not emit RST_STREAM";
		auto *sibling = c.New(); ASSERT_NE(sibling, nullptr);
		ASSERT_EQ(http2_stream_set_request(sibling, "GET", "/assembly", nullptr, custom), 0);
		auto *peer = c.Accept(); ASSERT_NE(peer, nullptr);
		EXPECT_EQ(http2_stream_get_id(peer), http2_stream_get_id(sibling));
		EXPECT_EQ(ReadHeaders(peer), RequestHeaders("GET"));
		EXPECT_EQ(http2_ctx_is_closed(c.server), 0);
	}
}

TEST(HTTP2HeaderAssembly, ResponseAllocationFailuresPreserveIncomingRequestAndRetry)
{
	for (int fail = 1; fail <= 10; ++fail) {
		SCOPED_TRACE(fail);
		Connection c; c.Init();
		auto *request = c.New(); ASSERT_NE(request, nullptr);
		ASSERT_EQ(http2_stream_set_request(request, "GET", "/assembly", nullptr, custom), 0);
		auto *response = c.Accept(); ASSERT_NE(response, nullptr);
		const auto before = ReadHeaders(response);
		ASSERT_EQ(before, RequestHeaders("GET"));
		c.server_io.wire.clear();
		header_alloc_failed = false; header_alloc_countdown = fail;
		int ret = http2_stream_set_response(response, 201, custom, 2);
		int saved_errno = errno; header_alloc_countdown = 0;
		ASSERT_TRUE(header_alloc_failed);
		ASSERT_EQ(ret, -1); EXPECT_EQ(saved_errno, ENOMEM);
		EXPECT_EQ(ReadHeaders(response), before);
		EXPECT_STREQ(http2_stream_get_method(response), "GET");
		EXPECT_STREQ(http2_stream_get_path(response), "/assembly");
		EXPECT_STREQ(http2_stream_get_header(response, "x-one"), "first");
		EXPECT_TRUE(c.server_io.wire.empty());
		EXPECT_EQ(http2_ctx_want_write(c.server), 0);
		ASSERT_EQ(http2_stream_set_response(response, 201, custom, 2), 0);
		EXPECT_EQ(ReadHeaders(response), ResponseHeaders());
		Connection::Pump(c.client);
		EXPECT_EQ(http2_stream_get_status(request), 201);
		EXPECT_EQ(ReadHeaders(request), ResponseHeaders());
	}
}

TEST(HTTP2HeaderAssembly, FailedReplacementPreservesExistingPostHeadersAndBodyState)
{
	for (int fail = 1; fail <= 19; ++fail) {
		SCOPED_TRACE(fail);
		Connection c; c.Init();
		auto *request = c.New(); ASSERT_NE(request, nullptr);
		ASSERT_EQ(http2_stream_set_request(request, "POST", "/assembly", nullptr, custom), 0);
		auto *peer = c.Accept(); ASSERT_NE(peer, nullptr);
		c.client_io.wire.clear();
		const http2_header_pair replacement[] = {{"x-new", "new"}, {"x-other", "other"}, {nullptr, nullptr}};
		header_alloc_failed = false; header_alloc_countdown = fail;
		int ret = http2_stream_set_request(request, "GET", "/replacement", "http", replacement);
		int saved_errno = errno; header_alloc_countdown = 0;
		ASSERT_TRUE(header_alloc_failed); ASSERT_EQ(ret, -1); EXPECT_EQ(saved_errno, ENOMEM);
		EXPECT_EQ(ReadHeaders(request), RequestHeaders("POST"));
		EXPECT_STREQ(http2_stream_get_method(request), "POST");
		EXPECT_STREQ(http2_stream_get_path(request), "/assembly");
		EXPECT_STREQ(http2_stream_get_header(request, "x-one"), "first");
		EXPECT_EQ(http2_stream_get_header(request, "x-new"), nullptr);
		EXPECT_TRUE(c.client_io.wire.empty());
		const uint8_t body[] = {'o', 'k'};
		ASSERT_EQ(http2_stream_write_body(request, body, sizeof(body), 1), 2);
		Connection::Pump(c.server);
		uint8_t received[2] = {};
		ASSERT_EQ(http2_stream_read_body(peer, received, sizeof(received)), 2);
		EXPECT_EQ(std::string(reinterpret_cast<char *>(received), 2), "ok");
		EXPECT_EQ(ReadHeaders(peer), RequestHeaders("POST"));
		EXPECT_EQ(http2_stream_is_remote_end(peer), 1);
	}
}

TEST(HTTP2HeaderAssembly, ResponseCanBorrowIncomingHeaderValue)
{
	Connection c; c.Init();
	auto *request = c.New(); ASSERT_NE(request, nullptr);
	ASSERT_EQ(http2_stream_set_request(request, "GET", "/assembly", nullptr, custom), 0);
	auto *response = c.Accept(); ASSERT_NE(response, nullptr);
	const char *borrowed = http2_stream_get_header(response, "x-one");
	ASSERT_NE(borrowed, nullptr);
	const http2_header_pair output[] = {{"x-borrowed", borrowed}};
	ASSERT_EQ(http2_stream_set_response(response, 200, output, 1), 0);
	Headers expected = {{":status", "200"}, {"x-borrowed", "first"}};
	EXPECT_EQ(ReadHeaders(response), expected);
	Connection::Pump(c.client);
	EXPECT_EQ(ReadHeaders(request), expected);
}

TEST(HTTP2HeaderAssembly, AuthorityPrecedenceAndNullFieldsArePreserved)
{
	const http2_header_pair input[] = {{"host", "host.test"}, {":authority", nullptr},
		{"x-null", nullptr}, {":authority", "explicit.test"}, {"Host", "later.test"},
		{"x-one", "first"}, {nullptr, nullptr}};
	for (bool explicit_authority : {false, true}) {
		Connection c; c.Init();
		auto *stream = c.New(); ASSERT_NE(stream, nullptr);
		const http2_header_pair host_only[] = {{"Host", "host.test"}, {"x-null", nullptr}, {nullptr, nullptr}};
		ASSERT_EQ(http2_stream_set_request(stream, "GET", "/assembly", "http", explicit_authority ? input : host_only), 0);
		auto *peer = c.Accept(); ASSERT_NE(peer, nullptr);
		Headers expected = {{":method", "GET"}, {":path", "/assembly"}, {":scheme", "http"},
			{":authority", explicit_authority ? "explicit.test" : "host.test"}};
		if (explicit_authority) expected.emplace_back("x-one", "first");
		EXPECT_EQ(ReadHeaders(stream), expected); EXPECT_EQ(ReadHeaders(peer), expected);
		const http2_header_pair response[] = {{nullptr, "ignored"}, {"x-null", nullptr}, {"x-one", "first"}};
		ASSERT_EQ(http2_stream_set_response(peer, 204, response, 3), 0);
		Headers expected_response = {{":status", "204"}, {"x-one", "first"}};
		EXPECT_EQ(ReadHeaders(peer), expected_response);
	}
}

TEST(HTTP2HeaderAssembly, EagainCommitsAndFlushesRequestAndResponseExactlyOnce)
{
	Connection c; c.Init();
	auto *request = c.New(); ASSERT_NE(request, nullptr);
	c.client_io.blocked = true;
	ASSERT_EQ(http2_stream_set_request(request, "GET", "/assembly", nullptr, custom), 0);
	EXPECT_EQ(ReadHeaders(request), RequestHeaders("GET"));
	EXPECT_TRUE(c.client_io.wire.empty()); EXPECT_EQ(http2_ctx_want_write(c.client), 1);
	c.client_io.blocked = false; Connection::Pump(c.client);
	EXPECT_EQ(http2_ctx_want_write(c.client), 0);
	const auto request_wire = c.client_io.wire;
	ASSERT_FALSE(request_wire.empty()); Connection::Pump(c.client);
	EXPECT_EQ(c.client_io.wire, request_wire);
	auto *response = c.Accept(); ASSERT_NE(response, nullptr);
	EXPECT_EQ(ReadHeaders(response), RequestHeaders("GET"));
	c.server_io.wire.clear(); c.server_io.blocked = true;
	ASSERT_EQ(http2_stream_set_response(response, 201, custom, 2), 0);
	EXPECT_EQ(ReadHeaders(response), ResponseHeaders());
	EXPECT_TRUE(c.server_io.wire.empty()); EXPECT_EQ(http2_ctx_want_write(c.server), 1);
	c.server_io.blocked = false; Connection::Pump(c.server);
	EXPECT_EQ(http2_ctx_want_write(c.server), 0);
	const auto response_wire = c.server_io.wire;
	ASSERT_FALSE(response_wire.empty()); Connection::Pump(c.server);
	EXPECT_EQ(c.server_io.wire, response_wire);
	Connection::Pump(c.client);
	EXPECT_EQ(http2_stream_get_status(request), 201);
	EXPECT_EQ(ReadHeaders(request), ResponseHeaders());
}
} // namespace
