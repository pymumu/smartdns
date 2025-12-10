#include "gtest/gtest.h"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <set>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "smartdns/http2.h"

class LIBHTTP2 : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		// Create socketpair for communication
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) < 0) {
			perror("socketpair");
			FAIL() << "Failed to create socketpair";
		}

		client_sock = socks[0];
		server_sock = socks[1];

		// Set non-blocking
		fcntl(client_sock, F_SETFL, O_NONBLOCK);
		fcntl(server_sock, F_SETFL, O_NONBLOCK);
	}

	void TearDown() override
	{
		if (client_sock != -1)
			close(client_sock);
		if (server_sock != -1)
			close(server_sock);
	}

	int socks[2];
	int client_sock = -1;
	int server_sock = -1;

	// BIO callbacks
	static int bio_read(void *private_data, uint8_t *buf, int len)
	{
		int fd = *(int *)private_data;
		int ret = read(fd, buf, len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			errno = EAGAIN;
			return -1;
		}
		return ret;
	}

	static int bio_write(void *private_data, const uint8_t *buf, int len)
	{
		int fd = *(int *)private_data;
		int ret = write(fd, buf, len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			errno = EAGAIN;
			return -1;
		}
		return ret;
	}
};

TEST_F(LIBHTTP2, Integrated)
{
	std::thread server_thread([this]() {
		// Server logic
		struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			int poll_ret = poll(&pfd, 1, 10);
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}

		ASSERT_EQ(ret, 1) << "Server handshake failed";

		// Accept stream
		struct http2_stream *stream = nullptr;
		int max_attempts = 200;
		while (max_attempts-- > 0 && !stream) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 100);
			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					stream = http2_ctx_accept_stream(ctx);
					if (stream)
						break;
				}
			}
			usleep(20000);
		}
		if (!stream) {
			std::cout << "Server failed to accept stream after timeout" << std::endl;
		}
		ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

		// Read request body
		uint8_t request_body[4096];
		int request_body_len = 0;
		while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
			int read_len = http2_stream_read_body(stream, request_body + request_body_len,
												  sizeof(request_body) - request_body_len);
			if (read_len > 0) {
				request_body_len += read_len;
			} else {
				usleep(10000);
			}
		}

		// Send response
		char response[8192];
		int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%d", response_len);
		struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {"content-length", content_length}};
		http2_stream_set_response(stream, 200, headers, 2);
		http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);

		usleep(100000);
		http2_ctx_put(ctx);
	});

	std::thread client_thread([this]() {
		usleep(500000); // Wait for server start
		struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		// Create stream
		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		// Send request
		struct http2_header_pair headers[] = {
			{"content-type", "application/json"}, {"content-length", "27"}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/echo", headers);
		const char *request_body = "{\"message\":\"Hello Echo!\"}";
		http2_stream_write_body(stream, (const uint8_t *)request_body, strlen(request_body), 1);

		// Wait for response
		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			if (http2_stream_get_status(stream) > 0)
				break;

			usleep(20000);
		}

		EXPECT_EQ(http2_stream_get_status(stream), 200);

		// Read response
		uint8_t response_body[4096];
		int response_body_len = 0;
		while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
			int read_len = http2_stream_read_body(stream, response_body + response_body_len,
												  sizeof(response_body) - response_body_len);
			if (read_len > 0) {
				response_body_len += read_len;
			} else {
				usleep(10000);
			}
		}

		std::string resp((char *)response_body, response_body_len);
		EXPECT_NE(resp.find("Echo Response"), std::string::npos);

		http2_stream_put(stream);
		http2_ctx_put(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, MultiStream)
{
	const int NUM_STREAMS = 3;

	std::thread server_thread([this, NUM_STREAMS]() {
		struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Server handshake failed";

		int streams_completed = 0;
		int max_iterations = 500;
		while (streams_completed < NUM_STREAMS && max_iterations-- > 0) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);

			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					http2_ctx_accept_stream(ctx);
				} else if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					http2_stream_read_body(stream, buf, sizeof(buf));

					if (http2_stream_is_end(stream)) {
						char response[256];
						int response_len =
							snprintf(response, sizeof(response), "Echo from stream %d", http2_stream_get_id(stream));
						char content_length[32];
						snprintf(content_length, sizeof(content_length), "%d", response_len);
						struct http2_header_pair headers[] = {{"content-type", "text/plain"},
															  {"content-length", content_length}};
						http2_stream_set_response(stream, 200, headers, 2);
						http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
						streams_completed++;
					}
				}
			}
			usleep(2000);
		}

		usleep(100000);
		http2_ctx_put(ctx);
	});

	std::thread client_thread([this, NUM_STREAMS]() {
		usleep(50000);
		struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		struct http2_stream *streams[NUM_STREAMS];
		for (int i = 0; i < NUM_STREAMS; i++) {
			streams[i] = http2_stream_new(ctx);
			ASSERT_NE(streams[i], nullptr);

			char path[64];
			snprintf(path, sizeof(path), "/stream%d", i);
			char body[128];
			int body_len = snprintf(body, sizeof(body), "Request from stream %d", i);
			char content_length[32];
			snprintf(content_length, sizeof(content_length), "%d", body_len);

			struct http2_header_pair headers[] = {
				{"content-type", "text/plain"}, {"content-length", content_length}, {NULL, NULL}};
			http2_stream_set_request(streams[i], "POST", path, headers);
			http2_stream_write_body(streams[i], (const uint8_t *)body, body_len, 1);
		}

		int streams_completed = 0;
		int max_iterations = 500;
		std::set<int> completed_stream_ids;
		while (streams_completed < NUM_STREAMS && max_iterations-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);

			for (int i = 0; i < count; i++) {
				if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					http2_stream_read_body(stream, buf, sizeof(buf));
					if (http2_stream_is_end(stream)) {
						int stream_id = http2_stream_get_id(stream);
						if (completed_stream_ids.find(stream_id) == completed_stream_ids.end()) {
							completed_stream_ids.insert(stream_id);
							streams_completed++;
						}
					}
				}
			}
			usleep(2000);
		}

		EXPECT_EQ(streams_completed, NUM_STREAMS);

		for (int i = 0; i < NUM_STREAMS; i++) {
			http2_stream_put(streams[i]);
		}
		http2_ctx_put(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, EarlyStreamCreation)
{
	std::thread server_thread([this]() {
		// Server logic
		struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			int poll_ret = poll(&pfd, 1, 10);
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}

		ASSERT_EQ(ret, 1) << "Server handshake failed";

		// Accept stream
		struct http2_stream *stream = nullptr;
		int max_attempts = 200;
		while (max_attempts-- > 0 && !stream) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 100);
			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					stream = http2_ctx_accept_stream(ctx);
					if (stream)
						break;
				}
			}
			usleep(20000);
		}
		ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

		// Verify we received the request
		const char *method = http2_stream_get_method(stream);
		const char *path = http2_stream_get_path(stream);
		EXPECT_STREQ(method, "POST");
		EXPECT_STREQ(path, "/early-test");

		// Read request body (should be empty for GET)
		uint8_t request_body[4096];
		int request_body_len = 0;
		while (!http2_stream_is_end(stream) && request_body_len < (int)sizeof(request_body)) {
			int read_len = http2_stream_read_body(stream, request_body + request_body_len,
												  sizeof(request_body) - request_body_len);
			if (read_len > 0) {
				request_body_len += read_len;
			} else {
				usleep(10000);
			}
		}

		// Send response
		char response[8192];
		int response_len = snprintf(response, sizeof(response), "Echo Response: %.*s", request_body_len, request_body);
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%d", response_len);
		struct http2_header_pair headers[] = {
			{"content-type", "text/plain"}, {"content-length", content_length}, {NULL, NULL}};
		http2_stream_set_response(stream, 200, headers, 2);
		http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);

		usleep(100000);
		http2_ctx_put(ctx);
	});

	std::thread client_thread([this]() {
		usleep(50000); // Wait for server start

		// Create client context
		struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// IMPORTANT: Create stream and send request BEFORE handshake completes
		// This tests that the HEADERS frame is buffered and sent after handshake
		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		// Send request immediately (before handshake)
		struct http2_header_pair headers[] = {{"user-agent", "test-client"}, {NULL, NULL}};
		int ret = http2_stream_set_request(stream, "POST", "/early-test", headers);
		EXPECT_EQ(ret, 0) << "Failed to set request";
		const char *request_body = "test echo";
		http2_stream_write_body(stream, (const uint8_t *)request_body, strlen(request_body), 1);

		// Now complete handshake
		int handshake_attempts = 200;
		ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		// Wait for response
		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			if (http2_stream_get_status(stream) > 0)
				break;

			usleep(20000);
		}

		EXPECT_EQ(http2_stream_get_status(stream), 200);

		// Read response
		uint8_t response_body[4096];
		int response_body_len = 0;
		while (!http2_stream_is_end(stream) && response_body_len < (int)sizeof(response_body)) {
			int read_len = http2_stream_read_body(stream, response_body + response_body_len,
												  sizeof(response_body) - response_body_len);
			if (read_len > 0) {
				response_body_len += read_len;
			} else {
				usleep(10000);
			}
		}

		std::string resp((char *)response_body, response_body_len);
		EXPECT_NE(resp.find("Echo Response"), std::string::npos);
		EXPECT_NE(resp.find("test echo"), std::string::npos);

		http2_stream_put(stream);
		http2_ctx_put(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, ServerLoopTerminationOnDisconnect)
{
	std::thread server_thread([this]() {
		struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			int poll_ret = poll(&pfd, 1, 10);
			if (poll_ret == 0) {
				continue;
			}
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Server handshake failed";

		// Accept stream
		struct http2_stream *stream = nullptr;
		int max_attempts = 200;
		while (max_attempts-- > 0 && !stream) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 100);
			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					stream = http2_ctx_accept_stream(ctx);
					if (stream)
						break;
				}
			}
			usleep(20000);
		}
		ASSERT_NE(stream, nullptr) << "Server failed to accept stream";

		// Read request body until EOF
		uint8_t buf[1024];
		int loop_count = 0;
		while (loop_count++ < 100) {
			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
			
			int data_read = 0;
			for (int i = 0; i < count; i++) {
				if (items[i].stream == stream && items[i].readable) {
					int ret = http2_stream_read_body(stream, buf, sizeof(buf));
					if (ret > 0) {
						data_read = 1;
					} else if (ret == 0) {
						// EOF received
						data_read = 1;
					}
				}
			}
			
			if (!data_read && http2_stream_is_end(stream)) {
				// If we are here, it means poll returned 0 items (or stream not readable),
				// which is correct behavior after EOF is consumed.
				// If the bug exists, poll would keep returning readable stream, and we would keep reading 0 bytes.
				break;
			}
			
			usleep(10000);
		}
		
		EXPECT_LT(loop_count, 100) << "Server loop did not terminate (infinite loop detected)";

		http2_ctx_put(ctx);
	});

	std::thread client_thread([this]() {
		usleep(50000);
		struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		int handshake_attempts = 200;
		int ret = 0;
		while (handshake_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1) break;
			if (ret < 0) break;
		}
		ASSERT_EQ(ret, 1);

		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/test", headers);
		http2_stream_write_body(stream, (const uint8_t *)"test", 4, 1);

		usleep(200000); // Wait for server to process
		
		http2_stream_put(stream);
		http2_ctx_put(ctx);
	});

	server_thread.join();
	client_thread.join();
}
