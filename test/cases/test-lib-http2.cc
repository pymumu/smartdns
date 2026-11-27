#include "gtest/gtest.h"
#include "include/utils.h"
#include <algorithm>
#include <atomic>
#include <chrono>
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

#include "http_parse/hpack.h"
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

	void WriteServerFrame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len)
	{
		uint8_t frame[256] = {0};
		ASSERT_GE(len, 0);
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
	}

	void WriteClientFrame(uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len)
	{
		uint8_t frame[256] = {0};
		ASSERT_GE(len, 0);
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(client_sock, frame, 9 + len), 9 + len);
	}

	void StartClientWithServerSettings(struct http2_ctx *ctx)
	{
		ASSERT_NE(ctx, nullptr);
		WriteServerFrame(0x04, 0, 0, NULL, 0);
		for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
			usleep(1000);
		}
	}
};

static int HpackCountHeader(void *ctx, const char *name, const char *value)
{
	int *count = (int *)ctx;
	(*count)++;
	return 0;
}

static int HpackExpectHuffmanHeader(void *ctx, const char *name, const char *value)
{
	int *count = (int *)ctx;
	EXPECT_STREQ(name, "x");
	EXPECT_STREQ(value, "www.example.com");
	(*count)++;
	return 0;
}

static int HpackExpectUafHeader(void *ctx, const char *name, const char *value)
{
	int *count = (int *)ctx;
	EXPECT_STREQ(name, "x-hpack-uaf");
	EXPECT_STREQ(value, "two");
	(*count)++;
	return 0;
}

TEST_F(LIBHTTP2, HpackDecodesHuffmanString)
{
	struct hpack_context hpack;
	/* RFC 7541 C.4.1 Huffman encoding of "www.example.com" */
	const uint8_t block[] = {0x00, 0x01, 'x',  0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
							 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
	int count = 0;

	hpack_init_context(&hpack);
	EXPECT_EQ(hpack_decode_headers(&hpack, block, sizeof(block), HpackExpectHuffmanHeader, &count), 0);
	EXPECT_EQ(count, 1);
	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackRejectsInvalidHuffmanPadding)
{
	/* 'a' is 00011; padding must be at most 7 bits of 1s */
	const uint8_t valid_block[] = {0x00, 0x01, 'x', 0x81, 0x1f};
	const uint8_t zero_padding_block[] = {0x00, 0x01, 'x', 0x81, 0x18};
	const uint8_t long_padding_block[] = {0x00, 0x01, 'x', 0x82, 0x1f, 0xff};
	struct hpack_context hpack;
	int count = 0;

	hpack_init_context(&hpack);
	EXPECT_EQ(hpack_decode_headers(&hpack, valid_block, sizeof(valid_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 1);
	EXPECT_LT(hpack_decode_headers(&hpack, zero_padding_block, sizeof(zero_padding_block), HpackCountHeader, &count),
			  0);
	EXPECT_LT(hpack_decode_headers(&hpack, long_padding_block, sizeof(long_padding_block), HpackCountHeader, &count),
			  0);
	EXPECT_EQ(count, 1);
	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackRejectsOverflowingLiteralStringLength)
{
	struct hpack_context hpack;
	const uint8_t invalid_block[] = {
		0x00, 0x7f, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
	};
	int count = 0;

	hpack_init_context(&hpack);
	EXPECT_LT(hpack_decode_headers(&hpack, invalid_block, sizeof(invalid_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 0);
	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackRejectsOverflowingHuffmanStringLength)
{
	struct hpack_context hpack;
	const uint8_t invalid_block[] = {
		0x00, 0xff, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01
	};
	int count = 0;

	hpack_init_context(&hpack);
	EXPECT_LT(hpack_decode_headers(&hpack, invalid_block, sizeof(invalid_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 0);
	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackRejectsDynamicTableSizeAboveLimit)
{
	struct hpack_context hpack;
	const uint8_t at_limit[] = {0x3f, 0xe1, 0xff, 0x03};    /* size update to 65536 */
	const uint8_t above_limit[] = {0x3f, 0xe2, 0xff, 0x03}; /* size update to 65537 */
	int count = 0;

	hpack_init_context(&hpack);
	EXPECT_EQ(hpack_decode_headers(&hpack, at_limit, sizeof(at_limit), HpackCountHeader, &count), 0);
	EXPECT_LT(hpack_decode_headers(&hpack, above_limit, sizeof(above_limit), HpackCountHeader, &count), 0);
	EXPECT_EQ(hpack.max_dynamic_table_size, (size_t)HPACK_MAX_DYNAMIC_TABLE_SIZE);
	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackDynamicTableSizeUpdateMustPrecedeHeaders)
{
	struct hpack_context hpack;
	hpack_init_context(&hpack);

	const uint8_t invalid_block[] = {
		0x40, 0x03, 'x', '-', 'a', 0x01, 'b', /* literal with incremental indexing */
		0x20                                      /* dynamic table size update to zero */
	};
	int count = 0;
	EXPECT_LT(hpack_decode_headers(&hpack, invalid_block, sizeof(invalid_block), HpackCountHeader, &count), 0);

	const uint8_t valid_block[] = {
		0x20,                                    /* dynamic table size update to zero */
		0x40, 0x03, 'x', '-', 'a', 0x01, 'b' /* literal with incremental indexing */
	};
	count = 0;
	EXPECT_EQ(hpack_decode_headers(&hpack, valid_block, sizeof(valid_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 1);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackResizeEvictsDynamicEntriesBeforeReuse)
{
	struct hpack_context hpack;
	uint8_t buf[128] = {0};
	hpack_init_context(&hpack);

	ASSERT_GT(hpack_encode_header(&hpack, "x-hpack-sync", "dynamic-value", buf, sizeof(buf)), 0);
	ASSERT_GT(hpack.entry_count, 0);
	ASSERT_GT(hpack.dynamic_table_size, 0U);

	hpack_resize_dynamic_table(&hpack, 0);
	EXPECT_EQ(hpack.entry_count, 0);
	EXPECT_EQ(hpack.dynamic_table_size, 0U);
	EXPECT_EQ(hpack.dynamic_table, nullptr);

	ASSERT_GT(hpack_encode_header(&hpack, "x-hpack-sync", "dynamic-value", buf, sizeof(buf)), 0);
	EXPECT_NE(buf[0], 0xbe);
	EXPECT_EQ(hpack.entry_count, 0);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackDecodeIndexedDynamicNameSurvivesEviction)
{
	struct hpack_context hpack;
	uint8_t buf[128] = {0};
	int count = 0;
	hpack_init_context(&hpack);

	ASSERT_GT(hpack_encode_header(&hpack, "x-hpack-uaf", "one", buf, sizeof(buf)), 0);
	ASSERT_EQ(hpack.entry_count, 1);
	hpack.max_dynamic_table_size = hpack.dynamic_table_size;

	const uint8_t reuse_dynamic_name[] = {
		0x7e,              /* literal indexed, name index 62: first dynamic entry */
		0x03, 't', 'w', 'o'
	};
	EXPECT_EQ(hpack_decode_headers(&hpack, reuse_dynamic_name, sizeof(reuse_dynamic_name), HpackExpectUafHeader, &count),
			  0);
	EXPECT_EQ(count, 1);
	EXPECT_EQ(hpack.entry_count, 1);
	EXPECT_STREQ(hpack.dynamic_table->name, "x-hpack-uaf");
	EXPECT_STREQ(hpack.dynamic_table->value, "two");

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackMultipleInitialSizeUpdatesRefreshTable)
{
	struct hpack_context hpack;
	hpack_init_context(&hpack);

	const uint8_t add_entry[] = {
		0x40, 0x03, 'x', '-', 'a', 0x01, 'b' /* x-a: b */
	};
	int count = 0;
	ASSERT_EQ(hpack_decode_headers(&hpack, add_entry, sizeof(add_entry), HpackCountHeader, &count), 0);
	ASSERT_GT(hpack.entry_count, 0);

	const uint8_t resize_block[] = {
		0x3f, 0xe1, 0x03, /* dynamic table size update to 512 */
		0x20,             /* dynamic table size update to zero */
		0x82              /* :method: GET */
	};
	count = 0;
	EXPECT_EQ(hpack_decode_headers(&hpack, resize_block, sizeof(resize_block), HpackCountHeader, &count), 0);
	EXPECT_EQ(count, 1);
	EXPECT_EQ(hpack.entry_count, 0);
	EXPECT_EQ(hpack.dynamic_table_size, 0U);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackShrunkTableRejectsEvictedDynamicIndex)
{
	struct hpack_context hpack;
	hpack_init_context(&hpack);

	const uint8_t add_entry[] = {
		0x40, 0x0c, 'x', '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
		0x0d, 'd', 'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
	};
	int count = 0;
	ASSERT_EQ(hpack_decode_headers(&hpack, add_entry, sizeof(add_entry), HpackCountHeader, &count), 0);
	ASSERT_GT(hpack.entry_count, 0);

	hpack_resize_dynamic_table(&hpack, 0);

	const uint8_t indexed_old_dynamic_entry[] = {
		0xbe /* dynamic table index 62 */
	};
	count = 0;
	EXPECT_LT(hpack_decode_headers(&hpack, indexed_old_dynamic_entry, sizeof(indexed_old_dynamic_entry),
								   HpackCountHeader, &count),
			  0);

	hpack_free_context(&hpack);
}

TEST_F(LIBHTTP2, HpackDynamicTableSharedAcrossInterleavedStreams)
{
	struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	WriteClientFrame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t stream1_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86, /* :scheme: http */
		0x40, /* literal header with incremental indexing, new name */
		0x0c, 'x', '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
		0x0d, 'd', 'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
	};
	WriteClientFrame(0x01, 0x04, 1, stream1_headers, sizeof(stream1_headers));

	const uint8_t stream3_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86, /* :scheme: http */
		0xbe  /* dynamic table index 62 from stream 1 */
	};
	WriteClientFrame(0x01, 0x05, 3, stream3_headers, sizeof(stream3_headers));

	struct http2_stream *stream1 = nullptr;
	struct http2_stream *stream3 = nullptr;
	for (int i = 0; i < 50 && (stream1 == nullptr || stream3 == nullptr); i++) {
		struct http2_poll_item items[8] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(ctx, items, 8, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				struct http2_stream *accepted = http2_ctx_accept_stream(ctx);
				if (accepted == nullptr) {
					continue;
				}
				if (http2_stream_get_id(accepted) == 1) {
					stream1 = accepted;
				} else if (http2_stream_get_id(accepted) == 3) {
					stream3 = accepted;
				} else {
					http2_stream_close(accepted);
				}
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}

	ASSERT_NE(stream1, nullptr);
	ASSERT_NE(stream3, nullptr);
	EXPECT_STREQ(http2_stream_get_header(stream1, "x-hpack-sync"), "dynamic-value");
	EXPECT_STREQ(http2_stream_get_header(stream3, "x-hpack-sync"), "dynamic-value");
	EXPECT_FALSE(http2_ctx_is_closed(ctx));

	http2_stream_close(stream3);
	http2_stream_close(stream1);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsHeaderTableSizeEvictsResponseEncoderEntries)
{
	struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	WriteClientFrame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t request_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86  /* :scheme: http */
	};
	WriteClientFrame(0x01, 0x05, 1, request_headers, sizeof(request_headers));

	struct http2_stream *stream = nullptr;
	for (int i = 0; i < 50 && stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		ASSERT_GE(http2_ctx_poll_readable(ctx, items, 4, &count), 0);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				stream = http2_ctx_accept_stream(ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(stream, nullptr);

	struct http2_header_pair headers[] = {{"x-hpack-response", "dynamic-value"}};
	ASSERT_EQ(http2_stream_set_response(stream, 200, headers, 1), 0);
	uint8_t response_buf[512] = {0};
	ssize_t response_len = read(client_sock, response_buf, sizeof(response_buf));
	ASSERT_GT(response_len, 0);
	ASSERT_NE(memchr(response_buf, 0x40, response_len), nullptr);

	const uint8_t settings_zero[] = {
		0x00, 0x01,             /* SETTINGS_HEADER_TABLE_SIZE */
		0x00, 0x00, 0x00, 0x00  /* zero */
	};
	WriteClientFrame(0x04, 0, 0, settings_zero, sizeof(settings_zero));
	{
		int poll_ret = http2_ctx_poll(ctx, NULL, 0, NULL);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
	}

	http2_stream_close(stream);

	const uint8_t request_headers2[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86  /* :scheme: http */
	};
	WriteClientFrame(0x01, 0x05, 3, request_headers2, sizeof(request_headers2));

	stream = nullptr;
	for (int i = 0; i < 50 && stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(ctx, items, 4, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				stream = http2_ctx_accept_stream(ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(stream, nullptr);

	ASSERT_EQ(http2_stream_set_response(stream, 200, headers, 1), 0);
	memset(response_buf, 0, sizeof(response_buf));
	response_len = read(client_sock, response_buf, sizeof(response_buf));
	ASSERT_GT(response_len, 0);
	EXPECT_EQ(memchr(response_buf, 0xbe, response_len), nullptr);
	EXPECT_NE(memchr(response_buf, 0x40, response_len), nullptr);
	bool found_headers = false;
	for (ssize_t pos = 0; pos + 9 <= response_len;) {
		unsigned length = (response_buf[pos] << 16) | (response_buf[pos+1] << 8) | response_buf[pos+2];
		ASSERT_LE(pos + 9 + length, response_len);
		if (response_buf[pos+3] == 1) {
			ASSERT_GT(length, 0U);
			EXPECT_EQ(response_buf[pos+9], 0x20); // real wire must synchronize the decoder
			found_headers = true;
		}
		pos += 9 + length;
	}
	EXPECT_TRUE(found_headers);

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, OversizedDecoderTableClosesTheConnectionWithCompressionError)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);
	uint8_t drain[2048];
	while (read(server_sock, drain, sizeof(drain)) > 0) {}
	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "GET", "/", "https", NULL), 0);
	while (read(server_sock, drain, sizeof(drain)) > 0) {}
	const uint8_t block[] = {0x3f,0xe2,0xff,0x03,0x88}; // capacity 65537 then :status 200
	WriteServerFrame(0x01,0x04,http2_stream_get_id(stream),block,sizeof(block));
	EXPECT_EQ(http2_ctx_poll(ctx,NULL,0,NULL),HTTP2_ERR_PROTOCOL);
	ssize_t length = read(server_sock,drain,sizeof(drain));
	ASSERT_GE(length,17);
	EXPECT_EQ(drain[3],7); // GOAWAY, not a stream-local RST_STREAM
	// A client has not processed any peer-initiated stream.
	EXPECT_EQ(drain[9],0); EXPECT_EQ(drain[10],0); EXPECT_EQ(drain[11],0); EXPECT_EQ(drain[12],0);
	EXPECT_EQ(drain[13],0); EXPECT_EQ(drain[14],0); EXPECT_EQ(drain[15],0); EXPECT_EQ(drain[16],9);
	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, PeerTableGrowthStaysWithinLocalEncoderLimit)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);
	uint8_t wire[2048];
	while (read(server_sock, wire, sizeof(wire)) > 0) {}
	/* SETTINGS limits our encoder, not the peer's HPACK encoder. */
	const uint8_t shrink_then_grow[] = {
		0, 1, 0, 0, 0, 0,
		0, 1, 0xff, 0xff, 0xff, 0xff,
	};
	WriteServerFrame(4, 0, 0, shrink_then_grow, sizeof(shrink_then_grow));
	int result = http2_ctx_poll(ctx, NULL, 0, NULL);
	ASSERT_TRUE(result == 0 || result == HTTP2_ERR_EAGAIN);
	while (read(server_sock, wire, sizeof(wire)) > 0) {}
	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "GET", "/", "https", NULL), 0);
	ssize_t length = read(server_sock, wire, sizeof(wire));
	ASSERT_GE(length, 14);
	ASSERT_EQ(wire[3], 1); // HEADERS
	/* Minimum 0, then local maximum 65536; never the peer's UINT32_MAX. */
	const uint8_t updates[] = {0x20, 0x3f, 0xe1, 0xff, 0x03};
	EXPECT_EQ(memcmp(wire + 9, updates, sizeof(updates)), 0);
	hpack_context decoder;
	hpack_init_context(&decoder);
	int fields = 0;
	unsigned payload = (wire[0] << 16) | (wire[1] << 8) | wire[2];
	ASSERT_LE(payload + 9, (unsigned)length);
	EXPECT_EQ(hpack_decode_headers(&decoder, wire + 9, payload, HpackCountHeader, &fields), 0);
	EXPECT_GT(fields, 0);
	EXPECT_EQ(decoder.max_dynamic_table_size, (size_t)HPACK_MAX_DYNAMIC_TABLE_SIZE);
	hpack_free_context(&decoder);
	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsOnNonZeroStreamFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	WriteServerFrame(0x04, 0, 1, NULL, 0);
	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);

	http2_ctx_close(ctx);
}

struct HTTP2CountingBio {
	int fd;
	int calls;
};

static int HTTP2CountingBioRead(void *private_data, uint8_t *buf, int len)
{
	auto *bio = (struct HTTP2CountingBio *)private_data;
	bio->calls++;
	int ret = read(bio->fd, buf, len);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		errno = EAGAIN;
		return -1;
	}
	return ret;
}

static int HTTP2CountingBioWrite(void *private_data, const uint8_t *buf, int len)
{
	auto *bio = (struct HTTP2CountingBio *)private_data;
	bio->calls++;
	int ret = write(bio->fd, buf, len);
	if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		errno = EAGAIN;
		return -1;
	}
	return ret;
}

/* The DNS client closes a connection by disconnecting the context first; after that the
 * HTTP/2 layer must never call the bio callbacks (they take server_info->lock). */
TEST_F(LIBHTTP2, DisconnectStopsAllBioCalls)
{
	struct HTTP2CountingBio bio = {client_sock, 0};
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", HTTP2CountingBioRead, HTTP2CountingBioWrite, &bio, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	struct http2_header_pair headers[] = {{"content-type", "application/dns-message"}, {NULL, NULL}};
	EXPECT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers), 0);
	EXPECT_GT(bio.calls, 0);

	http2_ctx_disconnect(ctx);
	EXPECT_EQ(http2_ctx_is_closed(ctx), 1);
	int calls = bio.calls;

	/* incoming data, polling, writing and closing the stream (RST) must all stay off the bio */
	WriteServerFrame(0x06, 0, 0, (const uint8_t *)"12345678", 8);
	EXPECT_LT(http2_ctx_poll(ctx, NULL, 0, NULL), 0);
	EXPECT_LT(http2_stream_write_body(stream, (const uint8_t *)"x", 1, 1), 0);
	http2_stream_close(stream);
	EXPECT_EQ(bio.calls, calls);

	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ServerRejectsEnablePushSetting)
{
	struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	const uint8_t settings_enable_push[] = {
		0x00, 0x02,             /* SETTINGS_ENABLE_PUSH */
		0x00, 0x00, 0x00, 0x01  /* enabled */
	};
	WriteClientFrame(0x04, 0, 0, settings_enable_push, sizeof(settings_enable_push));

	EXPECT_EQ(http2_ctx_handshake(ctx), HTTP2_ERR_PROTOCOL);

	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsMaxHeaderListSizeLimitsResponseHeaders)
{
	struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	const uint8_t settings_header_list_size[] = {
		0x00, 0x06,             /* SETTINGS_MAX_HEADER_LIST_SIZE */
		0x00, 0x00, 0x00, 0x08  /* very small */
	};
	WriteClientFrame(0x04, 0, 0, settings_header_list_size, sizeof(settings_header_list_size));

	for (int i = 0; i < 50 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t request_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86  /* :scheme: http */
	};
	WriteClientFrame(0x01, 0x05, 1, request_headers, sizeof(request_headers));

	struct http2_stream *stream = nullptr;
	for (int i = 0; i < 50 && stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(ctx, items, 4, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				stream = http2_ctx_accept_stream(ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(stream, nullptr);

	struct http2_header_pair headers[] = {{"x-large-response-header", "too-large-for-peer"}};
	EXPECT_LT(http2_stream_set_response(stream, 200, headers, 1), 0);
	/* Encoding already mutated the shared table; no new stream may reuse it. */
	errno = 0;
	struct http2_stream *reused = http2_stream_new(ctx);
	EXPECT_EQ(reused, nullptr);
	EXPECT_EQ(errno, ECONNRESET);
	if (reused) http2_stream_close(reused);

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

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
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
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

		http2_stream_close(stream);
		http2_ctx_close(ctx);
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
		const char *request_body = "{\"message\":\"Hello Echo!\"}";
		char content_length[32];
		snprintf(content_length, sizeof(content_length), "%zu", strlen(request_body));
		struct http2_header_pair headers[] = {
			{"content-type", "application/json"}, {"content-length", content_length}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/echo", NULL, headers);
		http2_stream_write_body(stream, (const uint8_t *)request_body, strlen(request_body), 1);

		// Wait for response
		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
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

		http2_stream_close(stream);
		http2_ctx_close(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, ResponseHeadersContinuation)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	auto write_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[64] = {0};
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
	};

	write_frame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t headers_fragment[] = {0x08};
	const uint8_t continuation_fragment[] = {0x03, '2', '0', '0'};
	write_frame(0x01, 0x01, 1, headers_fragment, sizeof(headers_fragment));
	write_frame(0x09, 0x04, 1, continuation_fragment, sizeof(continuation_fragment));

	for (int i = 0; i < 20 && http2_stream_get_status(stream) != 200; i++) {
		http2_ctx_poll(ctx, NULL, 0, NULL);
		usleep(1000);
	}

	EXPECT_EQ(http2_stream_get_status(stream), 200);
	EXPECT_TRUE(http2_stream_is_end(stream));

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ResponseDataFragmentsKeepStreamOpenUntilEndStream)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	StartClientWithServerSettings(ctx);

	const uint8_t headers[] = {
		0x08, 0x03, '2', '0', '0', /* :status: 200 */
		0x0f, 0x0d, 0x01, '4'     /* content-length: 4 */
	};
	WriteServerFrame(0x01, 0x04, 1, headers, sizeof(headers));

	const uint8_t first_fragment[] = {0xde, 0xad};
	WriteServerFrame(0x00, 0, 1, first_fragment, sizeof(first_fragment));

	struct http2_poll_item items[10] = {};
	int count = 0;
	ASSERT_EQ(http2_ctx_poll_readable(ctx, items, 10, &count), 0);
	ASSERT_GT(count, 0);

	bool found = false;
	for (int i = 0; i < count; i++) {
		if (items[i].stream == nullptr) {
			continue;
		}

		if (http2_stream_get_id(items[i].stream) == http2_stream_get_id(stream)) {
			found = true;
			uint8_t body[4] = {};
			EXPECT_EQ(http2_stream_get_status(items[i].stream), 200);
			ASSERT_EQ(http2_stream_read_body(items[i].stream, body, sizeof(body)), (int)sizeof(first_fragment));
			EXPECT_EQ(memcmp(body, first_fragment, sizeof(first_fragment)), 0);
			EXPECT_FALSE(http2_stream_is_end(items[i].stream));
		}
		http2_stream_put(items[i].stream);
	}
	ASSERT_TRUE(found);

	memset(items, 0, sizeof(items));
	count = 0;
	ASSERT_EQ(http2_ctx_poll_readable(ctx, items, 10, &count), 0);
	EXPECT_EQ(count, 0);

	const uint8_t second_fragment[] = {0xbe, 0xef};
	WriteServerFrame(0x00, 0x01, 1, second_fragment, sizeof(second_fragment));

	memset(items, 0, sizeof(items));
	count = 0;
	ASSERT_EQ(http2_ctx_poll_readable(ctx, items, 10, &count), 0);
	ASSERT_GT(count, 0);

	found = false;
	for (int i = 0; i < count; i++) {
		if (items[i].stream == nullptr) {
			continue;
		}

		if (http2_stream_get_id(items[i].stream) == http2_stream_get_id(stream)) {
			found = true;
			uint8_t body[4] = {};
			ASSERT_EQ(http2_stream_read_body(items[i].stream, body, sizeof(body)), (int)sizeof(second_fragment));
			EXPECT_EQ(memcmp(body, second_fragment, sizeof(second_fragment)), 0);
			EXPECT_TRUE(http2_stream_is_end(items[i].stream));
		}
		http2_stream_put(items[i].stream);
	}
	ASSERT_TRUE(found);

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ResponseEndStreamBeforeContentLengthResetsStreamOnly)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	StartClientWithServerSettings(ctx);

	const uint8_t headers[] = {
		0x08, 0x03, '2', '0', '0', /* :status: 200 */
		0x0f, 0x0d, 0x01, '4'     /* content-length: 4 */
	};
	WriteServerFrame(0x01, 0x04, 1, headers, sizeof(headers));

	const uint8_t short_body[] = {0xde, 0xad};
	WriteServerFrame(0x00, 0x01, 1, short_body, sizeof(short_body));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_EAGAIN);

	struct http2_stream *next_stream = http2_stream_new(ctx);
	ASSERT_NE(next_stream, nullptr);

	http2_stream_close(next_stream);
	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, FullyReadEndedRequestIsNotReportedReadableAgain)
{
	struct http2_ctx *client_ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(client_ctx, nullptr);
	ASSERT_NE(server_ctx, nullptr);

	int client_ret = 0;
	int server_ret = 0;
	for (int i = 0; i < 20; i++) {
		client_ret = http2_ctx_handshake(client_ctx);
		server_ret = http2_ctx_handshake(server_ctx);
		if (client_ret == 1 && server_ret == 1) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(client_ret, 1);
	ASSERT_EQ(server_ret, 1);

	const char body[] = "dns-query";
	char content_length[16];
	snprintf(content_length, sizeof(content_length), "%zu", sizeof(body) - 1);
	struct http2_header_pair headers[] = {
		{"content-type", "application/dns-message"}, {"content-length", content_length}, {NULL, NULL}};

	struct http2_stream *client_stream = http2_stream_new(client_ctx);
	ASSERT_NE(client_stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(client_stream, "POST", "/dns-query", NULL, headers), 0);
	ASSERT_EQ(http2_stream_write_body(client_stream, (const uint8_t *)body, sizeof(body) - 1, 1), (int)sizeof(body) - 1);
	int poll_ret = http2_ctx_poll(client_ctx, NULL, 0, NULL);
	ASSERT_TRUE(poll_ret >= 0 || poll_ret == HTTP2_ERR_EAGAIN);

	struct http2_stream *server_stream = nullptr;
	for (int i = 0; i < 20 && server_stream == nullptr; i++) {
		struct http2_poll_item items[4];
		int count = 0;
		ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				server_stream = http2_ctx_accept_stream(server_ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(server_stream, nullptr);

	uint8_t buf[32];
	ASSERT_EQ(http2_stream_read_body(server_stream, buf, sizeof(buf)), (int)sizeof(body) - 1);
	EXPECT_TRUE(http2_stream_is_end(server_stream));

	struct http2_poll_item items[4];
	int count = 0;
	ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
	EXPECT_EQ(count, 0);
	for (int i = 0; i < count; i++) {
		if (items[i].stream != nullptr) {
			http2_stream_put(items[i].stream);
		}
	}

	http2_stream_close(server_stream);
	http2_stream_close(client_stream);
	http2_ctx_close(server_ctx);
	http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, InvalidCompressedEndedRequestIsNotReportedReadableAgain)
{
	struct http2_ctx *client_ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(client_ctx, nullptr);
	ASSERT_NE(server_ctx, nullptr);

	int client_ret = 0;
	int server_ret = 0;
	for (int i = 0; i < 20; i++) {
		client_ret = http2_ctx_handshake(client_ctx);
		server_ret = http2_ctx_handshake(server_ctx);
		if (client_ret == 1 && server_ret == 1) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(client_ret, 1);
	ASSERT_EQ(server_ret, 1);

	const char body[] = "not-a-gzip-body";
	char content_length[16];
	snprintf(content_length, sizeof(content_length), "%zu", sizeof(body) - 1);
	struct http2_header_pair headers[] = {{"content-type", "application/dns-message"},
										  {"content-length", content_length},
										  {"content-encoding", "gzip"},
										  {NULL, NULL}};

	struct http2_stream *client_stream = http2_stream_new(client_ctx);
	ASSERT_NE(client_stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(client_stream, "POST", "/dns-query", NULL, headers), 0);
	ASSERT_EQ(http2_stream_write_body(client_stream, (const uint8_t *)body, sizeof(body) - 1, 1),
			  (int)sizeof(body) - 1);
	int poll_ret = http2_ctx_poll(client_ctx, NULL, 0, NULL);
	ASSERT_TRUE(poll_ret >= 0 || poll_ret == HTTP2_ERR_EAGAIN);

	struct http2_stream *server_stream = nullptr;
	for (int i = 0; i < 20 && server_stream == nullptr; i++) {
		struct http2_poll_item items[4];
		int count = 0;
		ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				server_stream = http2_ctx_accept_stream(server_ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(server_stream, nullptr);
	EXPECT_TRUE(http2_stream_is_remote_end(server_stream));

	uint8_t buf[32];
	errno = 0;
	ASSERT_LT(http2_stream_read_body(server_stream, buf, sizeof(buf)), 0);
	EXPECT_EQ(errno, EINVAL);

	struct http2_poll_item items[4];
	int count = 0;
	ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
	EXPECT_EQ(count, 0);
	for (int i = 0; i < count; i++) {
		if (items[i].stream != nullptr) {
			http2_stream_put(items[i].stream);
		}
	}

	http2_stream_close(server_stream);
	http2_stream_close(client_stream);
	http2_ctx_close(server_ctx);
	http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, UnsupportedContentEncodingReadsRawBody)
{
	struct http2_ctx *client_ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(client_ctx, nullptr);
	ASSERT_NE(server_ctx, nullptr);

	int client_ret = 0;
	int server_ret = 0;
	for (int i = 0; i < 20; i++) {
		client_ret = http2_ctx_handshake(client_ctx);
		server_ret = http2_ctx_handshake(server_ctx);
		if (client_ret == 1 && server_ret == 1) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(client_ret, 1);
	ASSERT_EQ(server_ret, 1);

	const char body[] = "raw-body";
	char content_length[16];
	snprintf(content_length, sizeof(content_length), "%zu", sizeof(body) - 1);
	struct http2_header_pair headers[] = {{"content-type", "application/dns-message"},
										  {"content-length", content_length},
										  {"content-encoding", "br"},
										  {NULL, NULL}};

	struct http2_stream *client_stream = http2_stream_new(client_ctx);
	ASSERT_NE(client_stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(client_stream, "POST", "/dns-query", NULL, headers), 0);
	ASSERT_EQ(http2_stream_write_body(client_stream, (const uint8_t *)body, sizeof(body) - 1, 1),
			  (int)sizeof(body) - 1);
	int poll_ret = http2_ctx_poll(client_ctx, NULL, 0, NULL);
	ASSERT_TRUE(poll_ret >= 0 || poll_ret == HTTP2_ERR_EAGAIN);

	struct http2_stream *server_stream = nullptr;
	for (int i = 0; i < 20 && server_stream == nullptr; i++) {
		struct http2_poll_item items[4];
		int count = 0;
		ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				server_stream = http2_ctx_accept_stream(server_ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(server_stream, nullptr);

	uint8_t buf[32] = {0};
	ASSERT_EQ(http2_stream_read_body(server_stream, buf, sizeof(buf)), (int)sizeof(body) - 1);
	EXPECT_EQ(memcmp(buf, body, sizeof(body) - 1), 0);
	EXPECT_TRUE(http2_stream_is_end(server_stream));

	http2_stream_close(server_stream);
	http2_stream_close(client_stream);
	http2_ctx_close(server_ctx);
	http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, PollReturnsResponseBeforeGoawayEof)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	auto write_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[64] = {0};
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
	};

	write_frame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t headers_fragment[] = {0x08};
	const uint8_t continuation_fragment[] = {0x03, '2', '0', '0'};
	write_frame(0x01, 0x01, 1, headers_fragment, sizeof(headers_fragment));
	write_frame(0x09, 0x04, 1, continuation_fragment, sizeof(continuation_fragment));
	const uint8_t goaway_payload[] = {0, 0, 0, 1, 0, 0, 0, 0};
	write_frame(0x07, 0, 0, goaway_payload, sizeof(goaway_payload));
	ASSERT_EQ(shutdown(server_sock, SHUT_WR), 0);

	struct http2_poll_item items[10] = {};
	int count = 0;
	int ret = http2_ctx_poll_readable(ctx, items, 10, &count);
	EXPECT_EQ(ret, 0);
	ASSERT_GT(count, 0);

	bool found = false;
	for (int i = 0; i < count; i++) {
		if (items[i].stream == nullptr) {
			continue;
		}

		if (http2_stream_get_id(items[i].stream) == http2_stream_get_id(stream)) {
			found = true;
			EXPECT_TRUE(items[i].readable);
			EXPECT_EQ(http2_stream_get_status(items[i].stream), 200);
			EXPECT_TRUE(http2_stream_is_end(items[i].stream));
		}
		http2_stream_put(items[i].stream);
	}
	EXPECT_TRUE(found);

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, RequestHostHeaderOverridesAuthority)
{
	struct http2_ctx *client_ctx = http2_ctx_client_new("1.1.1.1", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(client_ctx, nullptr);
	struct http2_ctx *server_ctx = http2_ctx_server_new("local-server", bio_read, bio_write, &server_sock, NULL);
	ASSERT_NE(server_ctx, nullptr);

	int client_ret = 0;
	int server_ret = 0;
	for (int i = 0; i < 50; i++) {
		server_ret = http2_ctx_handshake(server_ctx);
		client_ret = http2_ctx_handshake(client_ctx);
		if (client_ret == 1 && server_ret == 1) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(client_ret, 1);
	ASSERT_EQ(server_ret, 1);

	struct http2_stream *client_stream = http2_stream_new(client_ctx);
	ASSERT_NE(client_stream, nullptr);
	struct http2_header_pair headers[] = {{"host", "cloudflare-dns.com"}, {NULL, NULL}};
	ASSERT_EQ(http2_stream_set_request(client_stream, "GET", "/dns-query", NULL, headers), 0);

	struct http2_stream *server_stream = nullptr;
	for (int i = 0; i < 50 && server_stream == nullptr; i++) {
		struct http2_poll_item items[10] = {};
		int count = 0;
		http2_ctx_poll(server_ctx, items, 10, &count);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				server_stream = http2_ctx_accept_stream(server_ctx);
			}
			if (items[j].stream) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}

	ASSERT_NE(server_stream, nullptr);
	EXPECT_STREQ(http2_stream_get_header(server_stream, ":authority"), "cloudflare-dns.com");
	EXPECT_EQ(http2_stream_get_header(server_stream, "host"), nullptr);

	http2_stream_close(server_stream);
	http2_stream_close(client_stream);
	http2_ctx_close(server_ctx);
	http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, InvalidPingLengthFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	auto write_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[64] = {0};
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
	};

	write_frame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	const uint8_t ping_payload[] = {0};
	write_frame(0x06, 0, 0, ping_payload, sizeof(ping_payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, WriteBodyReturnsPayloadLengthForMultiFrameBody)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	auto write_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[64] = {0};
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(server_sock, frame, 9 + len), 9 + len);
	};

	write_frame(0x04, 0, 0, NULL, 0);
	for (int i = 0; i < 20 && http2_ctx_handshake(ctx) != 1; i++) {
		usleep(1000);
	}

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	struct http2_header_pair headers[] = {{"content-type", "application/dns-message"}, {NULL, NULL}};
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", NULL, headers), 0);

	std::vector<uint8_t> body(20000);
	for (size_t i = 0; i < body.size(); i++) {
		body[i] = (uint8_t)(i & 0xff);
	}

	EXPECT_EQ(http2_stream_write_body(stream, body.data(), body.size(), 1), (int)body.size());

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, ContinuationWithoutHeadersFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t payload[] = {0x00};
	WriteServerFrame(0x09, 0x04, 1, payload, sizeof(payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, HeadersInterruptedByDataFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);
	auto *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	const uint8_t headers_fragment[] = {0x08};
	const uint8_t data_payload[] = {0x01};
	WriteServerFrame(0x01, 0, 1, headers_fragment, sizeof(headers_fragment));
	WriteServerFrame(0x00, 0, 1, data_payload, sizeof(data_payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsAckWithPayloadFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t settings_payload[] = {0x00, 0x03, 0x00, 0x00, 0x00, 0x64};
	WriteServerFrame(0x04, 0x01, 0, settings_payload, sizeof(settings_payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, SettingsEnablePushInvalidValueFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t settings_payload[] = {0x00, 0x02, 0x00, 0x00, 0x00, 0x02};
	WriteServerFrame(0x04, 0, 0, settings_payload, sizeof(settings_payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, WindowUpdateZeroIncrementFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t window_update_payload[] = {0x00, 0x00, 0x00, 0x00};
	WriteServerFrame(0x08, 0, 0, window_update_payload, sizeof(window_update_payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, RstStreamOnConnectionStreamFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t rst_payload[] = {0x00, 0x00, 0x00, 0x00};
	WriteServerFrame(0x03, 0, 0, rst_payload, sizeof(rst_payload));

	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, DataAfterEndStreamFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	const uint8_t headers_fragment[] = {0x08, 0x03, '2', '0', '0'};
	WriteServerFrame(0x01, 0x05, 1, headers_fragment, sizeof(headers_fragment));
	for (int i = 0; i < 20 && http2_stream_get_status(stream) != 200; i++) {
		http2_ctx_poll(ctx, NULL, 0, NULL);
		usleep(1000);
	}
	ASSERT_EQ(http2_stream_get_status(stream), 200);

	const uint8_t data_payload[] = {0x01};
	WriteServerFrame(0x00, 0, 1, data_payload, sizeof(data_payload));
	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);

	http2_stream_close(stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, DataAfterLocallyClosedStreamDoesNotFailConnection)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);

	const uint8_t headers_fragment[] = {0x08, 0x03, '2', '0', '0'};
	const uint8_t data_payload[] = {0x2a};
	WriteServerFrame(0x01, 0x04, 1, headers_fragment, sizeof(headers_fragment));
	WriteServerFrame(0x00, 0x01, 1, data_payload, sizeof(data_payload));

	uint8_t body[8] = {0};
	int body_len = -1;
	for (int i = 0; i < 20 && body_len <= 0; i++) {
		http2_ctx_poll(ctx, NULL, 0, NULL);
		body_len = http2_stream_read_body(stream, body, sizeof(body));
		if (body_len <= 0) {
			usleep(1000);
		}
	}
	ASSERT_EQ(body_len, 1);
	EXPECT_EQ(body[0], 0x2a);
	EXPECT_EQ(http2_stream_read_body(stream, body, sizeof(body)), 0);

	http2_stream_close(stream);

	const uint8_t late_data[] = {0x11};
	WriteServerFrame(0x00, 0, 1, late_data, sizeof(late_data));
	int late_poll_ret = http2_ctx_poll(ctx, NULL, 0, NULL);
	EXPECT_TRUE(late_poll_ret == 0 || late_poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(late_poll_ret);

	struct http2_stream *next_stream = http2_stream_new(ctx);
	ASSERT_NE(next_stream, nullptr);
	ASSERT_EQ(http2_stream_set_request(next_stream, "POST", "/dns-query", "https", nullptr), 0);
	const uint8_t next_headers_fragment[] = {0x08, 0x03, '2', '0', '0'};
	WriteServerFrame(0x01, 0x05, 3, next_headers_fragment, sizeof(next_headers_fragment));
	for (int i = 0; i < 20 && http2_stream_get_status(next_stream) != 200; i++) {
		http2_ctx_poll(ctx, NULL, 0, NULL);
		usleep(1000);
	}
	EXPECT_EQ(http2_stream_get_status(next_stream), 200);

	http2_stream_close(next_stream);
	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, DataOnIdleStreamFailsProtocol)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t data_payload[] = {0x01};
	WriteServerFrame(0x00, 0, 1, data_payload, sizeof(data_payload));
	EXPECT_EQ(http2_ctx_poll(ctx, NULL, 0, NULL), HTTP2_ERR_PROTOCOL);

	http2_ctx_close(ctx);
}

TEST_F(LIBHTTP2, RefusedHeadersAndLateHeadersAfterSlotReleasePreserveHpackAndWatermark)
{
	struct http2_settings server_settings = {};
	server_settings.max_concurrent_streams = 1;
	struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, &server_settings);
	ASSERT_NE(server_ctx, nullptr);

	auto write_client_frame = [this](uint8_t type, uint8_t flags, uint32_t stream_id, const uint8_t *payload, int len) {
		uint8_t frame[256] = {0};
		ASSERT_GE(len, 0);
		ASSERT_LE(len, (int)sizeof(frame) - 9);
		frame[0] = (len >> 16) & 0xff;
		frame[1] = (len >> 8) & 0xff;
		frame[2] = len & 0xff;
		frame[3] = type;
		frame[4] = flags;
		frame[5] = (stream_id >> 24) & 0x7f;
		frame[6] = (stream_id >> 16) & 0xff;
		frame[7] = (stream_id >> 8) & 0xff;
		frame[8] = stream_id & 0xff;
		if (len > 0) {
			memcpy(frame + 9, payload, len);
		}
		ASSERT_EQ(write(client_sock, frame, 9 + len), 9 + len);
	};

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	write_client_frame(0x04, 0, 0, NULL, 0);

	int server_ret = 0;
	for (int i = 0; i < 50; i++) {
		server_ret = http2_ctx_handshake(server_ctx);
		if (server_ret == 1) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(server_ret, 1);

	const uint8_t hold_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86  /* :scheme: http */
	};
	write_client_frame(0x01, 0x05, 1, hold_headers, sizeof(hold_headers));

	struct http2_stream *hold_server_stream = nullptr;
	for (int i = 0; i < 50 && hold_server_stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		ASSERT_GE(http2_ctx_poll_readable(server_ctx, items, 4, &count), 0);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				hold_server_stream = http2_ctx_accept_stream(server_ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}
	ASSERT_NE(hold_server_stream, nullptr);

	uint8_t wire[4096];
	while (read(client_sock, wire, sizeof(wire)) > 0) {}

	const uint8_t refused_headers[] = {
		0x82,                         /* :method: GET */
		0x84,                         /* :path: / */
		0x86,                         /* :scheme: http */
		0x40,                         /* literal header with incremental indexing, new name */
		0x0c, 'x',  '-', 'h', 'p', 'a', 'c', 'k', '-', 's', 'y', 'n', 'c',
		0x0d, 'd',  'y', 'n', 'a', 'm', 'i', 'c', '-', 'v', 'a', 'l', 'u', 'e'
	};
	write_client_frame(0x01, 0x05, 3, refused_headers, sizeof(refused_headers));

	for (int i = 0; i < 50; i++) {
		int poll_ret = http2_ctx_poll_readable(server_ctx, NULL, 0, NULL);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
		usleep(1000);
	}
	EXPECT_FALSE(http2_ctx_is_closed(server_ctx));

	// Refusal must be stream-local, with the actual REFUSED_STREAM code.
	ssize_t wire_len = read(client_sock, wire, sizeof(wire));
	ASSERT_GE(wire_len, 13);
	int refused_count = 0;
	for (ssize_t pos = 0; pos < wire_len;) {
		ASSERT_LE(pos + 9, wire_len);
		unsigned len = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2];
		ASSERT_LE(pos + 9 + len, (size_t)wire_len);
		EXPECT_NE(wire[pos + 3], 7); // no GOAWAY
		if (wire[pos + 3] == 3) {
			ASSERT_EQ(len, 4U);
			EXPECT_EQ(wire[pos + 8], 3);
			EXPECT_EQ(wire[pos + 9], 0);
			EXPECT_EQ(wire[pos + 10], 0);
			EXPECT_EQ(wire[pos + 11], 0);
			EXPECT_EQ(wire[pos + 12], 7);
			refused_count++;
		}
		pos += 9 + len;
	}
	EXPECT_EQ(refused_count, 1);
	http2_stream_close(hold_server_stream);

	// The free slot must not allow stream 3 to be resurrected. Its second
	// header block nevertheless inserts another connection-wide HPACK entry.
	const uint8_t late_headers[] = {0x40, 6, 'x', '-', 'l', 'a', 't', 'e', 3, 'y', 'e', 's'};
	write_client_frame(0x01, 0, 3, late_headers, 5);
	int late_ret = http2_ctx_poll(server_ctx, nullptr, 0, nullptr);
	ASSERT_TRUE(late_ret == 0 || late_ret == HTTP2_ERR_EAGAIN);
	write_client_frame(0x09, 4, 3, late_headers + 5, sizeof(late_headers) - 5);
	late_ret = http2_ctx_poll(server_ctx, nullptr, 0, nullptr);
	ASSERT_TRUE(late_ret == 0 || late_ret == HTTP2_ERR_EAGAIN);
	EXPECT_EQ(http2_ctx_accept_stream(server_ctx), nullptr);


	const uint8_t accepted_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86, /* :scheme: http */
		0xbf, /* dynamic table index 63: x-hpack-sync: dynamic-value */
		0xbe  /* dynamic table index 62: x-late: yes */
	};
	write_client_frame(0x01, 0x05, 5, accepted_headers, sizeof(accepted_headers));

	struct http2_stream *accepted_server_stream = nullptr;
	for (int i = 0; i < 50 && accepted_server_stream == nullptr; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(server_ctx, items, 4, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				accepted_server_stream = http2_ctx_accept_stream(server_ctx);
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}

	ASSERT_NE(accepted_server_stream, nullptr);
	EXPECT_EQ(http2_stream_get_id(accepted_server_stream), 5);
	EXPECT_STREQ(http2_stream_get_header(accepted_server_stream, "x-hpack-sync"), "dynamic-value");
	EXPECT_STREQ(http2_stream_get_header(accepted_server_stream, "x-late"), "yes");
	int late_fields = 0;
	http2_stream_headers_walk(accepted_server_stream,
		[](void *arg, const char *name, const char *value) {
			if (strcmp(name, "x-late") == 0) {
				EXPECT_STREQ(value, "yes");
				++*static_cast<int *>(arg);
			}
		}, &late_fields);
	EXPECT_EQ(late_fields, 1);
	EXPECT_FALSE(http2_ctx_is_closed(server_ctx));

	http2_stream_close(accepted_server_stream);
	http2_ctx_close(server_ctx);
}

TEST_F(LIBHTTP2, PeerMaxConcurrentStreamsDoesNotOverrideServerInboundLimit)
{
	struct http2_settings server_settings = {};
	server_settings.max_concurrent_streams = 1;
	struct http2_ctx *server_ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, &server_settings);
	ASSERT_NE(server_ctx, nullptr);

	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	const uint8_t peer_settings[] = {
		0x00, 0x03,             /* SETTINGS_MAX_CONCURRENT_STREAMS */
		0x00, 0x00, 0x00, 0x00, /* zero only limits server-initiated streams */
	};
	WriteClientFrame(0x04, 0, 0, peer_settings, sizeof(peer_settings));

	int server_ret = 0;
	for (int i = 0; i < 50; i++) {
		server_ret = http2_ctx_handshake(server_ctx);
		if (server_ret == 1) {
			break;
		}
		usleep(1000);
	}
	ASSERT_EQ(server_ret, 1);

	const uint8_t request_headers[] = {
		0x82, /* :method: GET */
		0x84, /* :path: / */
		0x86  /* :scheme: http */
	};
	/* Deliberately omit END_STREAM so the first request remains active. */
	WriteClientFrame(0x01, 0x04, 1, request_headers, sizeof(request_headers));
	WriteClientFrame(0x01, 0x04, 3, request_headers, sizeof(request_headers));

	std::vector<struct http2_stream *> accepted_streams;
	for (int i = 0; i < 50; i++) {
		struct http2_poll_item items[4] = {};
		int count = 0;
		int poll_ret = http2_ctx_poll_readable(server_ctx, items, 4, &count);
		ASSERT_TRUE(poll_ret == 0 || poll_ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(poll_ret);
		for (int j = 0; j < count; j++) {
			if (items[j].stream == nullptr && items[j].readable) {
				struct http2_stream *stream = http2_ctx_accept_stream(server_ctx);
				if (stream != nullptr) {
					accepted_streams.push_back(stream);
				}
			}
			if (items[j].stream != nullptr) {
				http2_stream_put(items[j].stream);
			}
		}
		usleep(1000);
	}

	ASSERT_EQ(accepted_streams.size(), 1U);
	EXPECT_EQ(http2_stream_get_id(accepted_streams[0]), 1);
	for (auto *stream : accepted_streams) {
		http2_stream_close(stream);
	}
	http2_ctx_close(server_ctx);
}

TEST_F(LIBHTTP2, PeerMaxConcurrentStreamsLimitsLocallyInitiatedStreams)
{
	struct http2_ctx *client_ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(client_ctx, nullptr);

	const uint8_t peer_settings[] = {
		0x00, 0x03,             /* SETTINGS_MAX_CONCURRENT_STREAMS */
		0x00, 0x00, 0x00, 0x00, /* peer accepts no new client streams */
	};
	WriteServerFrame(0x04, 0, 0, peer_settings, sizeof(peer_settings));
	for (int i = 0; i < 50 && http2_ctx_handshake(client_ctx) != 1; i++) {
		usleep(1000);
	}

	EXPECT_EQ(http2_stream_new(client_ctx), nullptr);
	http2_ctx_close(client_ctx);
}

TEST_F(LIBHTTP2, StreamNewAfterGoawayFails)
{
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);
	StartClientWithServerSettings(ctx);

	const uint8_t goaway_payload[] = {0, 0, 0, 0, 0, 0, 0, 0};
	WriteServerFrame(0x07, 0, 0, goaway_payload, sizeof(goaway_payload));
	http2_ctx_poll(ctx, NULL, 0, NULL);

	struct http2_stream *stream = http2_stream_new(ctx);
	EXPECT_EQ(stream, nullptr);

	http2_ctx_close(ctx);
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
		std::set<struct http2_stream *> processed_streams;
		while (streams_completed < NUM_STREAMS && max_iterations-- > 0) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 100);

			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };

			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					struct http2_stream *s = http2_ctx_accept_stream(ctx);
				} else if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					http2_stream_read_body(stream, buf, sizeof(buf));

					if (http2_stream_is_end(stream)) {
						if (processed_streams.find(stream) == processed_streams.end()) {
							char response[256];
							int response_len = snprintf(response, sizeof(response), "Echo from stream %d",
														http2_stream_get_id(stream));
							char content_length[32];
							snprintf(content_length, sizeof(content_length), "%d", response_len);
							struct http2_header_pair headers[] = {{"content-type", "text/plain"},
																  {"content-length", content_length}};
							http2_stream_set_response(stream, 200, headers, 2);
							http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
							streams_completed++;
							processed_streams.insert(stream);
						}
					}
				}
			}
			usleep(2000);
		}

		for (auto stream : processed_streams) {
			http2_stream_close(stream);
		}

		http2_ctx_close(ctx);
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
			http2_stream_set_request(streams[i], "POST", path, NULL, headers);
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
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };

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
			http2_stream_close(streams[i]);
		}
		http2_ctx_close(ctx);
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
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
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
		http2_stream_close(stream);
		http2_ctx_close(ctx);
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
		int ret = http2_stream_set_request(stream, "POST", "/early-test", NULL, headers);
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
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
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

		http2_stream_close(stream);
		http2_ctx_close(ctx);
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
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
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
				if (items[i].stream) {
					http2_stream_put(items[i].stream);
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

		http2_stream_close(stream);
		http2_ctx_close(ctx);
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
			if (ret != 0) {
				break;
			}
		}
		ASSERT_EQ(ret, 1);

		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {NULL, NULL}};
		http2_stream_set_request(stream, "POST", "/test", NULL, headers);
		http2_stream_write_body(stream, (const uint8_t *)"test", 4, 1);
		http2_stream_close(stream);
		http2_ctx_close(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, StreamClose)
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
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
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

		// Read request and send response
		uint8_t buf[1024];
		http2_stream_read_body(stream, buf, sizeof(buf));
		http2_stream_set_response(stream, 200, NULL, 0);
		http2_stream_write_body(stream, (const uint8_t *)"OK", 2, 1);

		http2_stream_close(stream);
		http2_ctx_close(ctx);
	});

	std::thread client_thread([this]() {
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

		// Create stream
		struct http2_stream *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);

		// Send request
		http2_stream_set_request(stream, "GET", "/test", NULL, NULL);
		http2_stream_write_body(stream, NULL, 0, 1);

		// Wait for response
		int max_attempts = 200;
		while (max_attempts-- > 0) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 100);
			struct http2_poll_item items[10];
			int count = 0;
			http2_ctx_poll(ctx, items, 10, &count);
            Defer {
                for (int item = 0; item < count; item++)
                    if (items[item].stream) http2_stream_put(items[item].stream);
            };
			if (http2_stream_get_status(stream) > 0)
				break;
			usleep(20000);
		}

		// Close the stream explicitly
		http2_stream_get(stream); // Keep reference for reading after close
		http2_stream_close(stream);

		// Verify stream is marked as closed (should still be able to read)
		// After close, the stream should still be readable until all data is consumed
		EXPECT_FALSE(http2_stream_is_end(stream)); // Should not be end yet since we haven't read response

		// Read response (should still work after close)
		uint8_t buf[1024];
		int read_len = http2_stream_read_body(stream, buf, sizeof(buf));
		EXPECT_GE(read_len, 0); // Should be able to read

		// After reading all data, stream should be end
		while (!http2_stream_is_end(stream)) {
			read_len = http2_stream_read_body(stream, buf, sizeof(buf));
			if (read_len <= 0) {
				break;
			}
		}
		EXPECT_TRUE(http2_stream_is_end(stream)); // Should be end after reading all data

		http2_stream_put(stream);
		http2_ctx_put(ctx);
	});

	server_thread.join();
	client_thread.join();
}

TEST_F(LIBHTTP2, ReferenceCountingNormal)
{
	// Test normal reference counting: ctx normal, stream released by business
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	// Create a stream (already has refcount = 1)
	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	// Close context (should not free stream because business still holds reference)
	http2_ctx_close(ctx);

	// Business releases reference
	http2_stream_close(stream);

	// Now stream should be freed
	// We can't directly check, but no crash should occur
}

TEST_F(LIBHTTP2, ReferenceCountingContextError)
{
	// Test reference counting when ctx has error but stream is still referenced by business
	struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
	ASSERT_NE(ctx, nullptr);

	// Create a stream
	struct http2_stream *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);

	// Simulate context error by closing the socket (connection broken)
	close(client_sock);
	client_sock = -1;

	// Close context (should handle error gracefully)
	http2_ctx_close(ctx);

	// Business still holds reference, should be able to release it
	http2_stream_close(stream);

	// No crash should occur
}

TEST_F(LIBHTTP2, StressTest)
{
	const int NUM_STREAMS = 1024;
	std::atomic<int> server_processed(0);
	std::atomic<int> client_completed(0);
	std::atomic<bool> test_completed(false);

	std::thread server_thread([this, NUM_STREAMS, &server_processed, &test_completed]() {
		struct http2_ctx *ctx = http2_ctx_server_new("test-server", bio_read, bio_write, &server_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		auto start_time = std::chrono::steady_clock::now();
		int ret = 0;
		while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
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

		std::vector<struct http2_stream *> streams;
		start_time = std::chrono::steady_clock::now();
		while (!test_completed && std::chrono::steady_clock::now() - start_time < std::chrono::seconds(30)) {
			struct pollfd pfd = {server_sock, POLLIN, 0};
			poll(&pfd, 1, 10);

			struct http2_poll_item items[64];
			int count = 0;
			http2_ctx_poll(ctx, items, 64, &count);

			for (int i = 0; i < count; i++) {
				if (items[i].stream == nullptr && items[i].readable) {
					struct http2_stream *stream = http2_ctx_accept_stream(ctx);
					if (stream) {
						streams.push_back(stream);
					}
				} else if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					while (http2_stream_read_body(stream, buf, sizeof(buf)) > 0)
						;

					if (http2_stream_is_end(stream)) {
						char response[256];
						int response_len = snprintf(response, sizeof(response), "Echo %d", http2_stream_get_id(stream));
						char content_length[32];
						snprintf(content_length, sizeof(content_length), "%d", response_len);
						struct http2_header_pair headers[] = {{"content-type", "text/plain"},
															  {"content-length", content_length}};
						http2_stream_set_response(stream, 200, headers, 2);
						http2_stream_write_body(stream, (const uint8_t *)response, response_len, 1);
						server_processed++;
					}
				}
				if (items[i].stream) {
					http2_stream_put(items[i].stream);
				}
			}
		}

		for (auto stream : streams) {
			http2_stream_close(stream);
		}
		http2_ctx_close(ctx);
	});

	std::thread client_thread([this, NUM_STREAMS, &client_completed, &test_completed]() {
		usleep(50000);
		struct http2_ctx *ctx = http2_ctx_client_new("test-client", bio_read, bio_write, &client_sock, NULL);
		ASSERT_NE(ctx, nullptr);

		// Handshake
		auto start_time = std::chrono::steady_clock::now();
		int ret = 0;
		while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, 10);
			ret = http2_ctx_handshake(ctx);
			if (ret == 1)
				break;
			if (ret < 0)
				break;
		}
		ASSERT_EQ(ret, 1) << "Client handshake failed";

		std::vector<struct http2_stream *> streams;
		streams.reserve(NUM_STREAMS);
		std::set<int> completed_ids;

		auto process_events = [&](int timeout_ms) {
			struct pollfd pfd = {client_sock, POLLIN, 0};
			poll(&pfd, 1, timeout_ms);

			struct http2_poll_item items[64];
			int count = 0;
			http2_ctx_poll(ctx, items, 64, &count);

			for (int i = 0; i < count; i++) {
				if (items[i].stream && items[i].readable) {
					struct http2_stream *stream = items[i].stream;
					uint8_t buf[1024];
					while (http2_stream_read_body(stream, buf, sizeof(buf)) > 0)
						;

					if (http2_stream_is_end(stream)) {
						int id = http2_stream_get_id(stream);
						if (completed_ids.find(id) == completed_ids.end()) {
							completed_ids.insert(id);
							client_completed++;
						}
					}
				}
				if (items[i].stream) {
					http2_stream_put(items[i].stream);
				}
			}
		};

		for (int i = 0; i < NUM_STREAMS; i++) {
			struct http2_stream *stream = http2_stream_new(ctx);
			if (stream) {
				streams.push_back(stream);
				char path[64];
				snprintf(path, sizeof(path), "/stream%d", i);
				char body[64];
				int body_len = snprintf(body, sizeof(body), "Req %d", i);

				struct http2_header_pair headers[] = {{"content-type", "text/plain"}, {NULL, NULL}};
				http2_stream_set_request(stream, "POST", path, NULL, headers);
				http2_stream_write_body(stream, (const uint8_t *)body, body_len, 1);
			}

			// Process events periodically to prevent deadlock/buffer overflow
			if (i % 10 == 0) {
				process_events(0);
			}
		}
		ASSERT_EQ(streams.size(), NUM_STREAMS);

		start_time = std::chrono::steady_clock::now();
		while (client_completed < NUM_STREAMS &&
			   std::chrono::steady_clock::now() - start_time < std::chrono::seconds(30)) {
			process_events(10);
		}

		EXPECT_EQ(client_completed, NUM_STREAMS);

		for (auto stream : streams) {
			http2_stream_close(stream);
		}
		http2_ctx_close(ctx);
		test_completed = true;
	});

	server_thread.join();
	client_thread.join();
}

/* Raw upstream frames make cancellation/arrival ordering deterministic, without
 * a network server or access to the HTTP/2 implementation's private structs. */
class LIBHTTP2Cancelled : public LIBHTTP2
{
  protected:
	struct http2_ctx *ctx = nullptr;
	std::vector<struct http2_stream *> owned;
	int reads = 0;
	int writes = 0;
	// 0: normal, 1: EAGAIN, 2: one short write then EAGAIN, 3: EIO, 4: EOF.
	int write_mode = 0;

	static int CountingRead(void *arg, uint8_t *buf, int len)
	{
		auto *self = static_cast<LIBHTTP2Cancelled *>(arg);
		self->reads++;
		return bio_read(&self->client_sock, buf, len);
	}

	static int CountingWrite(void *arg, const uint8_t *buf, int len)
	{
		auto *self = static_cast<LIBHTTP2Cancelled *>(arg);
		self->writes++;
		if (self->write_mode == 1) { errno = EAGAIN; return -1; }
		if (self->write_mode == 3) { errno = EIO; return -1; }
		if (self->write_mode == 4) { return 0; }
		if (self->write_mode == 2) {
			self->write_mode = 1;
			return bio_write(&self->client_sock, buf, std::min(len, 3));
		}
		return bio_write(&self->client_sock, buf, len);
	}

	void SetUp() override
	{
		LIBHTTP2::SetUp();
		ctx = http2_ctx_client_new("local-doh-upstream", CountingRead, CountingWrite, this, nullptr);
		ASSERT_NE(ctx, nullptr);
		StartClientWithServerSettings(ctx);
		DrainWire();
	}

	void TearDown() override
	{
		for (auto *stream : owned) {
			http2_stream_close(stream);
		}
		http2_ctx_close(ctx);
		LIBHTTP2::TearDown();
	}

	struct http2_stream *OpenRequest()
	{
		auto *stream = http2_stream_new(ctx);
		if (stream) {
			owned.push_back(stream);
			EXPECT_EQ(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);
			const uint8_t dns_query[] = {0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
			EXPECT_EQ(http2_stream_write_body(stream, dns_query, sizeof(dns_query), 1), (int)sizeof(dns_query));
		}
		DrainWire();
		return stream;
	}

	void Cancel(struct http2_stream *stream, bool drain = true)
	{
		http2_stream_close(stream);
		owned.erase(std::remove(owned.begin(), owned.end(), stream), owned.end());
		if (drain) { DrainWire(); }
	}

	std::vector<uint8_t> DrainWire()
	{
		std::vector<uint8_t> wire;
		uint8_t buf[4096];
		ssize_t n;
		while ((n = read(server_sock, buf, sizeof(buf))) > 0) {
			wire.insert(wire.end(), buf, buf + n);
		}
		return wire;
	}

	void PollHealthy()
	{
		int ret = http2_ctx_poll(ctx, nullptr, 0, nullptr);
		ASSERT_TRUE(ret == 0 || ret == HTTP2_ERR_EAGAIN) << http2_error_to_string(ret);
		EXPECT_FALSE(http2_ctx_is_closed(ctx));
	}

	static uint32_t Read32(const uint8_t *p)
	{
		return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
	}

	void ExpectGoaway(uint32_t error)
	{
		auto wire = DrainWire();
		int found = 0;
		for (size_t pos = 0; pos < wire.size();) {
			ASSERT_LE(pos + 9, wire.size());
			size_t len = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2];
			ASSERT_LE(pos + 9 + len, wire.size());
			if (wire[pos + 3] == 7) {
				ASSERT_GE(len, 8U);
				EXPECT_EQ(Read32(&wire[pos + 5]), 0U);
				EXPECT_EQ(Read32(&wire[pos + 9]), 0U); // client has no peer-initiated streams
				EXPECT_EQ(Read32(&wire[pos + 13]), error);
				found++;
			}
			pos += 9 + len;
		}
		EXPECT_EQ(found, 1);
		EXPECT_TRUE(http2_ctx_is_closed(ctx));
	}

	static void CountSyncHeader(void *arg, const char *name, const char *value)
	{
		if (strcmp(name, "x-sync") == 0) {
			EXPECT_STREQ(value, "late");
			++*static_cast<int *>(arg);
		}
	}

	void ExpectSiblingResponse(struct http2_stream *sibling)
	{
		const uint8_t indexed[] = {0x88, 0xbe}; // :status 200, dynamic index 62: x-sync: late
		WriteServerFrame(1, 4, http2_stream_get_id(sibling), indexed, sizeof(indexed));
		const uint8_t answer[] = {0x12, 0x34, 0x81, 0x80};
		WriteServerFrame(0, 1, http2_stream_get_id(sibling), answer, sizeof(answer));
		PollHealthy();
		EXPECT_EQ(http2_stream_get_status(sibling), 200);
		EXPECT_STREQ(http2_stream_get_header(sibling, "x-sync"), "late");
		int fields = 0;
		http2_stream_headers_walk(sibling, CountSyncHeader, &fields);
		EXPECT_EQ(fields, 1);
		uint8_t body[16] = {};
		ASSERT_EQ(http2_stream_read_body(sibling, body, sizeof(body)), (int)sizeof(answer));
		EXPECT_EQ(memcmp(body, answer, sizeof(answer)), 0);
		EXPECT_EQ(http2_stream_read_body(sibling, body, sizeof(body)), 0);
		EXPECT_TRUE(http2_stream_is_end(sibling));
		EXPECT_EQ(http2_ctx_accept_stream(ctx), nullptr); // never recreate the canceled request
	}

	void CheckReadyResponsesAfterFatal(int response_count)
	{
		auto *canceled = OpenRequest();
		ASSERT_NE(canceled, nullptr);
		uint32_t canceled_id = http2_stream_get_id(canceled);
		Cancel(canceled);
		std::set<int> expected_ids;
		for (int i = 0; i < response_count; i++) {
			auto *stream = OpenRequest();
			ASSERT_NE(stream, nullptr);
			expected_ids.insert(http2_stream_get_id(stream));
		}
		const uint8_t status[] = {0x88};
		const uint8_t answer[] = {0x12, 0x34, 0x81, 0x80};
		std::vector<uint8_t> input;
		auto append = [&](uint8_t type, uint8_t flags, uint32_t id, const uint8_t *data, int len) {
			const uint8_t header[] = {0, 0, uint8_t(len), type, flags, uint8_t(id >> 24),
				uint8_t(id >> 16), uint8_t(id >> 8), uint8_t(id)};
			input.insert(input.end(), header, header + sizeof(header));
			input.insert(input.end(), data, data + len);
		};
		for (int id : expected_ids) {
			append(1, 4, id, status, sizeof(status));
			append(0, 1, id, answer, sizeof(answer));
		}
		const uint8_t invalid[] = {0x80};
		append(1, 4, canceled_id, invalid, sizeof(invalid));
		// One bounded write avoids UNIX socket per-write overhead exhausting the
		// nonblocking send queue before the intended 256-response batch arrives.
		ASSERT_EQ(write(server_sock, input.data(), input.size()), (ssize_t)input.size());

		std::set<int> delivered_ids;
		int stopped_reads = 0, stopped_writes = 0;
		for (int batch = 0; batch < (response_count + 127) / 128; batch++) {
			struct http2_poll_item items[128] = {};
			int count = 0;
			int ret = http2_ctx_poll_readable(ctx, items, 128, &count);
			Defer {
				for (int i = 0; i < count; i++) {
					if (items[i].stream) { http2_stream_put(items[i].stream); }
				}
			};
			EXPECT_EQ(ret, 0); // buffered responses take precedence over the latched fatal error
			EXPECT_EQ(count, std::min(128, response_count - batch * 128));
			EXPECT_TRUE(http2_ctx_is_closed(ctx));
			if (batch == 0) {
				stopped_reads = reads;
				stopped_writes = writes;
				ExpectGoaway(9);
			} else {
				EXPECT_EQ(reads, stopped_reads);
				EXPECT_EQ(writes, stopped_writes);
			}
			for (int i = 0; i < count; i++) {
				auto *stream = items[i].stream;
				ASSERT_NE(stream, nullptr);
				EXPECT_TRUE(items[i].readable);
				int id = http2_stream_get_id(stream);
				EXPECT_EQ(expected_ids.count(id), 1U);
				EXPECT_TRUE(delivered_ids.insert(id).second) << "Response delivered more than once: " << id;
				EXPECT_EQ(http2_stream_get_status(stream), 200);
				uint8_t body[16] = {};
				ASSERT_EQ(http2_stream_read_body(stream, body, sizeof(body)), (int)sizeof(answer));
				EXPECT_EQ(memcmp(body, answer, sizeof(answer)), 0);
				EXPECT_TRUE(http2_stream_is_end(stream));
			}
		}
		EXPECT_EQ(delivered_ids, expected_ids);
		struct http2_poll_item items[128] = {};
		int count = 0;
		EXPECT_EQ(http2_ctx_poll_readable(ctx, items, 128, &count), HTTP2_ERR_PROTOCOL);
		for (int i = 0; i < count; i++) {
			if (items[i].stream) { http2_stream_put(items[i].stream); }
		}
		EXPECT_EQ(count, 0);
		EXPECT_EQ(reads, stopped_reads);
		EXPECT_EQ(writes, stopped_writes);
	}

	void CheckRemovedIdleFrame(uint8_t type, bool allocate_higher = false, bool failed_request = false)
	{
		auto *stream = http2_stream_new(ctx);
		ASSERT_NE(stream, nullptr);
		owned.push_back(stream);
		uint32_t id = http2_stream_get_id(stream);
		if (failed_request) {
			EXPECT_LT(http2_stream_set_request(stream, "POST", nullptr, "https", nullptr), 0);
			EXPECT_FALSE(http2_ctx_is_closed(ctx));
		}
		Cancel(stream, false);
		EXPECT_TRUE(DrainWire().empty()) << "An unopened stream must not send RST_STREAM";
		if (allocate_higher) {
			auto *higher = http2_stream_new(ctx);
			ASSERT_NE(higher, nullptr);
			owned.push_back(higher);
			ASSERT_GT(http2_stream_get_id(higher), id);
		}
		const uint8_t headers[] = {0x88};
		const uint8_t data[] = {0x12};
		const uint8_t refused[] = {0, 0, 0, 7};
		WriteServerFrame(type, type == 1 ? 5 : (type == 0 ? 1 : 0), id,
						 type == 1 ? headers : (type == 0 ? data : refused), type == 3 ? 4 : 1);
		EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
		ExpectGoaway(1);
	}

	void CheckImplicitlyClosedLocalId(bool remove_before_open, bool queued)
	{
		auto *unused = http2_stream_new(ctx);
		ASSERT_NE(unused, nullptr);
		owned.push_back(unused);
		uint32_t id = http2_stream_get_id(unused);
		if (remove_before_open) { Cancel(unused); }
		if (queued) { write_mode = 1; }
		auto *higher = OpenRequest();
		ASSERT_NE(higher, nullptr);
		ASSERT_GT(http2_stream_get_id(higher), id);
		if (!remove_before_open) {
			EXPECT_TRUE(http2_stream_is_end(unused));
			EXPECT_TRUE(http2_stream_is_remote_end(unused));
			EXPECT_LT(http2_stream_set_request(unused, "POST", "/dns-query", "https", nullptr), 0);
			const uint8_t body[] = {0x12};
			EXPECT_LT(http2_stream_write_body(unused, body, sizeof(body), 1), 0);
			uint8_t out[8];
			EXPECT_EQ(http2_stream_read_body(unused, out, sizeof(out)), 0);
		}
		EXPECT_FALSE(http2_ctx_is_closed(ctx));
		if (queued) {
			EXPECT_TRUE(http2_ctx_want_write(ctx));
			write_mode = 0;
			PollHealthy();
			DrainWire();
		}
		const uint8_t block[] = {0x88, 0x40, 6, 'x', '-', 's', 'y', 'n', 'c', 4, 'l', 'a', 't', 'e'};
		WriteServerFrame(1, 5, id, block, sizeof(block));
		PollHealthy();
		if (!remove_before_open) {
			EXPECT_EQ(http2_stream_get_status(unused), -1);
			EXPECT_EQ(http2_stream_get_header(unused, "x-sync"), nullptr);
			EXPECT_FALSE(http2_stream_body_available(unused));
			Cancel(unused, false);
			EXPECT_TRUE(DrainWire().empty());
		}
		ExpectSiblingResponse(higher);
	}

	void CheckInterruptedDiscardWriteError(int mode, int expected_error)
	{
		auto *stream = OpenRequest();
		ASSERT_NE(stream, nullptr);
		uint32_t id = http2_stream_get_id(stream);
		Cancel(stream);
		const uint8_t headers[] = {0x88};
		WriteServerFrame(1, 0, id, headers, sizeof(headers));
		PollHealthy();
		write_mode = mode;
		const uint8_t ping[8] = {};
		WriteServerFrame(6, 0, 0, ping, sizeof(ping));
		EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), expected_error);
		EXPECT_TRUE(http2_ctx_is_closed(ctx));
		int old_reads = reads, old_writes = writes;
		EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), expected_error);
		EXPECT_EQ(reads, old_reads);
		EXPECT_EQ(writes, old_writes);
	}

	void LimitPeerStreamsToTwo()
	{
		const uint8_t max_streams[] = {0, 3, 0, 0, 0, 2};
		WriteServerFrame(4, 0, 0, max_streams, sizeof(max_streams));
		PollHealthy();
		DrainWire();
	}

	void CheckLateHeaders(bool retain_reset_stream, bool close_mid_block)
	{
		LimitPeerStreamsToTwo();
		auto *canceled = OpenRequest();
		ASSERT_NE(canceled, nullptr);
		auto *sibling = OpenRequest();
		ASSERT_NE(sibling, nullptr);
		uint32_t id = http2_stream_get_id(canceled);
		http2_stream_get(canceled); // inspect discarded delivery even after explicit close
		Defer { http2_stream_put(canceled); };
		const uint8_t block[] = {0x88, 0x40, 6, 'x', '-', 's', 'y', 'n', 'c', 4, 'l', 'a', 't', 'e'};
		if (close_mid_block) {
			WriteServerFrame(1, 1, id, block, 7); // END_STREAM belongs to HEADERS, not CONTINUATION
			PollHealthy();
			EXPECT_EQ(http2_stream_get_header(canceled, "x-sync"), nullptr);
		}
		if (retain_reset_stream) {
			const uint8_t refused[] = {0, 0, 0, 7};
			WriteServerFrame(3, 0, id, refused, sizeof(refused));
			PollHealthy(); // CLOSED, but still present with the caller's reference
		} else {
			Cancel(canceled);
		}
		int old_status = http2_stream_get_status(canceled);
		if (close_mid_block) {
			WriteServerFrame(9, 4, id, block + 7, sizeof(block) - 7);
		} else {
			WriteServerFrame(1, 5, id, block, sizeof(block));
		}
		PollHealthy();
		EXPECT_EQ(http2_stream_get_status(canceled), old_status);
		EXPECT_EQ(http2_stream_get_header(canceled, "x-sync"), nullptr);
		EXPECT_FALSE(http2_stream_body_available(canceled));
		if (!retain_reset_stream) {
			// Inspecting the detached object alone cannot detect a new object
			// resurrected under the same ID. That object would consume the
			// second peer-advertised slot and prevent this new request.
			auto *replacement = OpenRequest();
			ASSERT_NE(replacement, nullptr) << "Late HEADERS must not reclaim the canceled stream slot";
			EXPECT_EQ(http2_stream_get_id(replacement), 5);
		}
		ExpectSiblingResponse(sibling);
	}
};

TEST_F(LIBHTTP2Cancelled, RemovedRequestLateHeadersPreserveHpackWithoutDelivery)
{
	CheckLateHeaders(false, false);
}

TEST_F(LIBHTTP2Cancelled, RetainedResetRequestLateHeadersPreserveHpackWithoutDelivery)
{
	CheckLateHeaders(true, false);
}

TEST_F(LIBHTTP2Cancelled, CancelBetweenHeadersAndContinuationPreservesHpack)
{
	CheckLateHeaders(false, true);
}

TEST_F(LIBHTTP2Cancelled, ContinuationIgnoresUndefinedFlags)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	const uint8_t block[] = {0x88, 0x40, 6, 'x', '-', 's', 'y', 'n', 'c', 4, 'l', 'a', 't', 'e'};
	WriteServerFrame(1, 0, http2_stream_get_id(stream), block, 7);
	PollHealthy();
	// PADDED, PRIORITY, END_STREAM and all other unknown bits have no meaning here.
	WriteServerFrame(9, 0xff, http2_stream_get_id(stream), block + 7, sizeof(block) - 7);
	PollHealthy();
	EXPECT_EQ(http2_stream_get_status(stream), 200);
	EXPECT_STREQ(http2_stream_get_header(stream, "x-sync"), "late");
	EXPECT_FALSE(http2_stream_is_remote_end(stream));
}

TEST_F(LIBHTTP2Cancelled, DiscardedPaddedDataReturnsFullConnectionCreditOnly)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream);
	// 1 pad-length byte + 2 payload bytes + 3 padding bytes are all flow-controlled.
	const uint8_t padded[] = {3, 0x12, 0x34, 0, 0, 0};
	unsigned credited = 0;
	for (int i = 0; i < 32; i++) {
		WriteServerFrame(0, 8, id, padded, sizeof(padded));
		PollHealthy();
		auto wire = DrainWire();
		for (size_t pos = 0; pos < wire.size();) {
			ASSERT_LE(pos + 9, wire.size());
			size_t len = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2];
			ASSERT_LE(pos + 9 + len, wire.size());
			if (wire[pos + 3] == 8) {
				ASSERT_EQ(len, 4U);
				EXPECT_EQ(Read32(&wire[pos + 5]), 0U); // never replenish a closed stream
				credited += Read32(&wire[pos + 9]) & 0x7fffffff;
			}
			pos += 9 + len;
		}
	}
	EXPECT_EQ(credited, 32U * sizeof(padded));
}

TEST_F(LIBHTTP2Cancelled, DiscardedDataStillValidatesPadding)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream);
	const uint8_t invalid[] = {2, 0};
	WriteServerFrame(0, 8, id, invalid, sizeof(invalid));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
}

TEST_F(LIBHTTP2Cancelled, UnknownResponseStreamIsConnectionError)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	const uint8_t status[] = {0x88};
	WriteServerFrame(1, 5, http2_stream_get_id(stream) + 2, status, sizeof(status));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
}

TEST_F(LIBHTTP2Cancelled, UnsolicitedEvenResponseBelowLocalWatermarkIsConnectionError)
{
	ASSERT_NE(OpenRequest(), nullptr);
	ASSERT_NE(OpenRequest(), nullptr); // local watermark 3 does not authorize peer stream 2
	const uint8_t status[] = {0x88};
	WriteServerFrame(1, 5, 2, status, sizeof(status));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
}

TEST_F(LIBHTTP2Cancelled, WrongContinuationOnDiscardedBlockIsConnectionError)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream);
	const uint8_t status[] = {0x88};
	WriteServerFrame(1, 0, id, status, sizeof(status));
	PollHealthy();
	WriteServerFrame(9, 4, id + 2, nullptr, 0);
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
}

TEST_F(LIBHTTP2Cancelled, BadHpackOnDiscardedBlockIsCompressionError)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream);
	const uint8_t invalid[] = {0x80}; // indexed representation with forbidden index zero
	WriteServerFrame(1, 4, id, invalid, sizeof(invalid));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(9);
}

TEST_F(LIBHTTP2Cancelled, OversizedDiscardedHeaderBlockClosesConnection)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream);
	// Each fragment fits the peer frame limit, but the accumulated block exceeds 64 KiB.
	const std::vector<uint8_t> fragment(240, 0x88);
	WriteServerFrame(1, 0, id, fragment.data(), fragment.size());
	PollHealthy();
	for (int i = 1; i < 273; i++) {
		WriteServerFrame(9, 0, id, fragment.data(), fragment.size());
		PollHealthy();
	}
	WriteServerFrame(9, 4, id, fragment.data(), fragment.size());
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_INTERNAL);
	ExpectGoaway(2);
}

TEST_F(LIBHTTP2Cancelled, ReadyResponseThenFatalHpackStopsSubsequentBio)
{
	auto *canceled = OpenRequest();
	ASSERT_NE(canceled, nullptr);
	auto *sibling = OpenRequest();
	ASSERT_NE(sibling, nullptr);
	uint32_t id = http2_stream_get_id(canceled);
	Cancel(canceled);
	const uint8_t status[] = {0x88};
	const uint8_t invalid[] = {0x80};
	WriteServerFrame(1, 5, http2_stream_get_id(sibling), status, sizeof(status));
	WriteServerFrame(1, 4, id, invalid, sizeof(invalid));
	struct http2_poll_item items[4] = {};
	int count = 0;
	int ret = http2_ctx_poll_readable(ctx, items, 4, &count);
	int delivered = 0;
	for (int i = 0; i < count; i++) {
		if (items[i].stream == sibling && items[i].readable) {
			delivered++;
		}
		if (items[i].stream) {
			http2_stream_put(items[i].stream);
		}
	}
	EXPECT_TRUE(ret == 0 || ret == HTTP2_ERR_PROTOCOL);
	EXPECT_EQ(delivered, 1);
	EXPECT_EQ(http2_stream_get_status(sibling), 200);
	ExpectGoaway(9);
	int old_reads = reads;
	int old_writes = writes;
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

extern void FailHpackStrdupAfter(int calls);

TEST_F(LIBHTTP2Cancelled, DiscardedHpackAllocationFailureIsInternalError)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream);
	const uint8_t block[] = {0x40, 6, 'x', '-', 's', 'y', 'n', 'c', 4, 'l', 'a', 't', 'e'};
	WriteServerFrame(1, 4, id, block, sizeof(block));
	// Incrementally indexed literal requires dynamic-table ownership even when discarded.
	FailHpackStrdupAfter(1);
	int ret = http2_ctx_poll(ctx, nullptr, 0, nullptr);
	FailHpackStrdupAfter(0);
	EXPECT_EQ(ret, HTTP2_ERR_INTERNAL);
	ExpectGoaway(2); // INTERNAL_ERROR, never COMPRESSION_ERROR
}

TEST_F(LIBHTTP2Cancelled, QueuedResetStillDiscardsLateHeadersAndKeepsSiblingUsable)
{
	LimitPeerStreamsToTwo();
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	auto *sibling = OpenRequest();
	ASSERT_NE(sibling, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	write_mode = 1;
	Cancel(stream, false);
	EXPECT_TRUE(http2_ctx_want_write(ctx));
	EXPECT_TRUE(DrainWire().empty());
	const uint8_t block[] = {0x40, 6, 'x', '-', 's', 'y', 'n', 'c', 4, 'l', 'a', 't', 'e'};
	WriteServerFrame(1, 4, id, block, sizeof(block));
	PollHealthy();
	write_mode = 0;
	PollHealthy();
	auto wire = DrainWire();
	ASSERT_EQ(wire.size(), 13U);
	EXPECT_EQ(wire[3], 3);
	EXPECT_EQ(Read32(&wire[5]), id);
	EXPECT_EQ(Read32(&wire[9]), 0U);
	// A queued RST must retire the slot immediately, not resurrect a local
	// stream when its late response HEADERS arrive before the RST is flushed.
	auto *replacement = OpenRequest();
	ASSERT_NE(replacement, nullptr) << "Late HEADERS must not reclaim the canceled stream slot";
	EXPECT_EQ(http2_stream_get_id(replacement), 5);
	ExpectSiblingResponse(sibling);
}

TEST_F(LIBHTTP2Cancelled, PartiallyWrittenResetFlushesExactlyOnce)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	write_mode = 2;
	Cancel(stream, false);
	auto wire = DrainWire();
	ASSERT_EQ(wire.size(), 3U);
	EXPECT_TRUE(http2_ctx_want_write(ctx));
	write_mode = 0;
	PollHealthy();
	auto tail = DrainWire();
	wire.insert(wire.end(), tail.begin(), tail.end());
	ASSERT_EQ(wire.size(), 13U);
	EXPECT_EQ(wire[3], 3);
	EXPECT_EQ(Read32(&wire[5]), id);
	EXPECT_EQ(Read32(&wire[9]), 0U);
	PollHealthy();
	EXPECT_TRUE(DrainWire().empty());
}

TEST_F(LIBHTTP2Cancelled, ResetWriteFailurePreservesIoErrorAndStopsBio)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	write_mode = 3;
	Cancel(stream);
	EXPECT_TRUE(http2_ctx_is_closed(ctx));
	int old_reads = reads, old_writes = writes;
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_IO);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

TEST_F(LIBHTTP2Cancelled, ResetWriteEofPreservesEofAndStopsBio)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	write_mode = 4;
	Cancel(stream);
	EXPECT_TRUE(http2_ctx_is_closed(ctx));
	int old_reads = reads, old_writes = writes;
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_EOF);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

TEST_F(LIBHTTP2Cancelled, ClosingFlowBlockedRequestCancelsWithoutWindowUpdate)
{
	const uint8_t zero_window[] = {0, 4, 0, 0, 0, 0};
	WriteServerFrame(4, 0, 0, zero_window, sizeof(zero_window));
	PollHealthy();
	auto *stream = OpenRequest(); // body is accepted but cannot be sent
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	Cancel(stream, false);
	auto wire = DrainWire();
	ASSERT_EQ(wire.size(), 13U);
	EXPECT_EQ(wire[3], 3); // cancellation must not wait for the blocked body
	EXPECT_EQ(Read32(&wire[5]), id);
	const uint8_t increment[] = {0, 0, 0, 64};
	WriteServerFrame(8, 0, id, increment, sizeof(increment));
	PollHealthy();
	EXPECT_TRUE(DrainWire().empty()); // no canceled payload or END_STREAM sent later
}

TEST_F(LIBHTTP2, ClosingFlowBlockedServerResponseStillDrainsAfterWindowUpdate)
{
	auto *ctx = http2_ctx_server_new("local-server", bio_read, bio_write, &server_sock, nullptr);
	ASSERT_NE(ctx, nullptr);
	Defer { http2_ctx_close(ctx); };
	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	const uint8_t zero_window[] = {0, 4, 0, 0, 0, 0};
	WriteClientFrame(4, 0, 0, zero_window, sizeof(zero_window));
	ASSERT_EQ(http2_ctx_handshake(ctx), 1);
	const uint8_t request[] = {0x82, 0x84, 0x86};
	WriteClientFrame(1, 5, 1, request, sizeof(request));
	auto *stream = http2_ctx_accept_stream(ctx);
	ASSERT_NE(stream, nullptr);
	ASSERT_EQ(http2_stream_set_response(stream, 200, nullptr, 0), 0);
	const uint8_t body[] = {0x12, 0x34, 0x81, 0x80};
	ASSERT_EQ(http2_stream_write_body(stream, body, sizeof(body), 1), (int)sizeof(body));
	uint8_t wire[4096];
	while (read(client_sock, wire, sizeof(wire)) > 0) {}
	http2_stream_close(stream);
	EXPECT_EQ(read(client_sock, wire, sizeof(wire)), -1); // no premature RST
	const uint8_t increment[] = {0, 0, 0, sizeof(body)};
	WriteClientFrame(8, 0, 1, increment, sizeof(increment));
	int ret = http2_ctx_poll(ctx, nullptr, 0, nullptr);
	EXPECT_TRUE(ret == 0 || ret == HTTP2_ERR_EAGAIN);
	ssize_t len = read(client_sock, wire, sizeof(wire));
	ASSERT_EQ(len, 9 + (ssize_t)sizeof(body));
	EXPECT_EQ(wire[3], 0); // DATA
	EXPECT_EQ(wire[4], 1); // END_STREAM
	EXPECT_EQ(wire[8], 1);
	EXPECT_EQ(memcmp(wire + 9, body, sizeof(body)), 0);
	EXPECT_FALSE(http2_ctx_is_closed(ctx));
}

TEST_F(LIBHTTP2Cancelled, RequestHeadersWriteFailurePreservesIoErrorAndStopsBio)
{
	auto *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	owned.push_back(stream);
	write_mode = 3;
	EXPECT_LT(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);
	EXPECT_TRUE(http2_ctx_is_closed(ctx));
	int old_reads = reads, old_writes = writes;
	// Header-encoding cleanup must not overwrite the BIO's I/O failure with PROTOCOL.
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_IO);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

TEST_F(LIBHTTP2Cancelled, RequestHeadersWriteEofPreservesEofAndStopsBio)
{
	auto *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	owned.push_back(stream);
	write_mode = 4;
	EXPECT_LT(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);
	EXPECT_TRUE(http2_ctx_is_closed(ctx));
	int old_reads = reads, old_writes = writes;
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_EOF);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

TEST_F(LIBHTTP2Cancelled, ActivePaddedDataCountsOnlyBodyButCreditsFullPayload)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	// :status 200; content-length: 4 (literal without indexing, static name 28).
	const uint8_t headers[] = {0x88, 0x0f, 0x0d, 1, '4'};
	WriteServerFrame(1, 4, id, headers, sizeof(headers));
	PollHealthy();
	EXPECT_EQ(http2_stream_get_status(stream), 200);
	EXPECT_STREQ(http2_stream_get_header(stream, "content-length"), "4");
	DrainWire();

	auto expect_credit = [&](unsigned connection, unsigned stream_credit) {
		auto wire = DrainWire();
		unsigned connection_total = 0, stream_total = 0;
		int connection_frames = 0, stream_frames = 0;
		for (size_t pos = 0; pos < wire.size();) {
			ASSERT_LE(pos + 9, wire.size());
			size_t len = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2];
			ASSERT_LE(pos + 9 + len, wire.size());
			ASSERT_EQ(wire[pos + 3], 8); // neither RST_STREAM nor GOAWAY
			ASSERT_EQ(len, 4U);
			uint32_t stream_id = Read32(&wire[pos + 5]);
			unsigned credit = Read32(&wire[pos + 9]) & 0x7fffffff;
			if (stream_id == 0) {
				connection_total += credit;
				connection_frames++;
			} else {
				EXPECT_EQ(stream_id, id);
				stream_total += credit;
				stream_frames++;
			}
			pos += 9 + len;
		}
		EXPECT_EQ(connection_total, connection);
		EXPECT_EQ(stream_total, stream_credit);
		EXPECT_EQ(connection_frames, 1);
		EXPECT_EQ(stream_frames, stream_credit ? 1 : 0);
	};

	const uint8_t first[] = {3, 0x12, 0x34, 0, 0, 0};
	WriteServerFrame(0, 8, id, first, sizeof(first));
	PollHealthy();
	expect_credit(sizeof(first), sizeof(first));
	uint8_t body[16] = {};
	ASSERT_EQ(http2_stream_read_body(stream, body, sizeof(body)), 2);
	EXPECT_EQ(body[0], 0x12);
	EXPECT_EQ(body[1], 0x34);
	EXPECT_FALSE(http2_stream_is_remote_end(stream));

	const uint8_t last[] = {2, 0x81, 0x80, 0, 0};
	WriteServerFrame(0, 9, id, last, sizeof(last)); // PADDED | END_STREAM
	PollHealthy();
	expect_credit(sizeof(last), 0); // END_STREAM never replenishes stream credit
	ASSERT_EQ(http2_stream_read_body(stream, body, sizeof(body)), 2);
	EXPECT_EQ(body[0], 0x81);
	EXPECT_EQ(body[1], 0x80);
	EXPECT_EQ(http2_stream_read_body(stream, body, sizeof(body)), 0);
	EXPECT_TRUE(http2_stream_is_end(stream));
	EXPECT_FALSE(http2_ctx_is_closed(ctx));
}

TEST_F(LIBHTTP2, SaturatedServerRejectsEvenHeadersBeforeApplyingStreamLimit)
{
	struct http2_settings settings = {};
	settings.max_concurrent_streams = 1;
	auto *ctx = http2_ctx_server_new("local-server", bio_read, bio_write, &server_sock, &settings);
	ASSERT_NE(ctx, nullptr);
	Defer { http2_ctx_close(ctx); };
	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	WriteClientFrame(4, 0, 0, nullptr, 0);
	ASSERT_EQ(http2_ctx_handshake(ctx), 1);
	const uint8_t request[] = {0x82, 0x84, 0x86};
	WriteClientFrame(1, 5, 1, request, sizeof(request));
	auto *held = http2_ctx_accept_stream(ctx);
	ASSERT_NE(held, nullptr);
	Defer { http2_stream_close(held); };
	uint8_t wire[4096];
	while (read(client_sock, wire, sizeof(wire)) > 0) {}

	// Stream 2 belongs to the server, so a client cannot open it with HEADERS.
	// The exhausted inbound slot must not turn this into REFUSED_STREAM.
	WriteClientFrame(1, 5, 2, request, sizeof(request));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	EXPECT_TRUE(http2_ctx_is_closed(ctx));
	ssize_t size = read(client_sock, wire, sizeof(wire));
	ASSERT_GE(size, 17);
	int goaways = 0;
	for (ssize_t pos = 0; pos < size;) {
		ASSERT_LE(pos + 9, size);
		unsigned len = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2];
		ASSERT_LE(pos + 9 + len, (size_t)size);
		EXPECT_NE(wire[pos + 3], 3); // not a stream-local refusal
		if (wire[pos + 3] == 7) {
			ASSERT_GE(len, 8U);
			EXPECT_EQ(wire[pos + 9], 0);
			EXPECT_EQ(wire[pos + 10], 0);
			EXPECT_EQ(wire[pos + 11], 0);
			EXPECT_EQ(wire[pos + 12], 1); // last valid peer stream, not invalid ID 2
			EXPECT_EQ(wire[pos + 13], 0);
			EXPECT_EQ(wire[pos + 14], 0);
			EXPECT_EQ(wire[pos + 15], 0);
			EXPECT_EQ(wire[pos + 16], 1); // PROTOCOL_ERROR
			goaways++;
		}
		pos += 9 + len;
	}
	EXPECT_EQ(goaways, 1);
}

TEST_F(LIBHTTP2Cancelled, RemoteRefusedResetCancelsFlowBlockedBodyBeforeWindowUpdate)
{
	const uint8_t zero_window[] = {0, 4, 0, 0, 0, 0};
	WriteServerFrame(4, 0, 0, zero_window, sizeof(zero_window));
	PollHealthy();
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	const uint8_t refused[] = {0, 0, 0, 7};
	const uint8_t increment[] = {0, 0, 0, 64};
	// Process both frames in one poll: reset must discard the pending body
	// before WINDOW_UPDATE can make it writable again.
	WriteServerFrame(3, 0, id, refused, sizeof(refused));
	WriteServerFrame(8, 0, id, increment, sizeof(increment));
	PollHealthy();
	EXPECT_TRUE(DrainWire().empty()) << "A reset request must never flush queued DATA or END_STREAM";
	EXPECT_TRUE(http2_stream_is_remote_end(stream));
	PollHealthy();
	EXPECT_TRUE(DrainWire().empty());
}

TEST_F(LIBHTTP2Cancelled, ResetOnUnknownIdleStreamIsProtocolError)
{
	const uint8_t refused[] = {0, 0, 0, 7};
	WriteServerFrame(3, 0, 99, refused, sizeof(refused));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
	int old_reads = reads, old_writes = writes;
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

TEST_F(LIBHTTP2Cancelled, DataOnAllocatedButUnsentIdleStreamIsProtocolError)
{
	auto *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	owned.push_back(stream);
	// Allocation reserves an ID; only sending request HEADERS opens the stream.
	const uint8_t data[] = {0x12};
	WriteServerFrame(0, 1, http2_stream_get_id(stream), data, sizeof(data));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
	EXPECT_FALSE(http2_stream_body_available(stream));
}

TEST_F(LIBHTTP2Cancelled, FatalHpackPreserves129ReadyResponsesAcrossTwoPollBatchesWithoutBio)
{
	CheckReadyResponsesAfterFatal(129);
}

TEST_F(LIBHTTP2Cancelled, FatalHpackPreserves256ReadyResponsesAcrossTwoFullPollBatchesWithoutBio)
{
	CheckReadyResponsesAfterFatal(256);
}

TEST_F(LIBHTTP2Cancelled, ContentLengthResetDiscardsFlowBlockedRequestBody)
{
	const uint8_t zero_window[] = {0, 4, 0, 0, 0, 0};
	WriteServerFrame(4, 0, 0, zero_window, sizeof(zero_window));
	PollHealthy();
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	// END_STREAM with content-length 1 but no response body causes a local reset.
	const uint8_t headers[] = {0x88, 0x0f, 0x0d, 1, '1'};
	WriteServerFrame(1, 5, id, headers, sizeof(headers));
	PollHealthy();
	auto wire = DrainWire();
	ASSERT_EQ(wire.size(), 13U);
	EXPECT_EQ(wire[3], 3);
	EXPECT_EQ(Read32(&wire[5]), id);
	EXPECT_EQ(Read32(&wire[9]), 1U); // stream-local PROTOCOL_ERROR
	const uint8_t increment[] = {0, 0, 0, 64};
	WriteServerFrame(8, 0, id, increment, sizeof(increment));
	PollHealthy();
	EXPECT_TRUE(DrainWire().empty()) << "Local reset must discard the pending request body";
}

TEST_F(LIBHTTP2Cancelled, ApplicationCloseAfterRemoteResetDoesNotEchoReset)
{
	auto *stream = OpenRequest();
	ASSERT_NE(stream, nullptr);
	uint32_t id = http2_stream_get_id(stream);
	const uint8_t refused[] = {0, 0, 0, 7};
	WriteServerFrame(3, 0, id, refused, sizeof(refused));
	PollHealthy();
	EXPECT_TRUE(DrainWire().empty());
	const uint8_t body[] = {0x12};
	EXPECT_LT(http2_stream_write_body(stream, body, sizeof(body), 1), 0);
	EXPECT_LT(http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr), 0);
	EXPECT_TRUE(DrainWire().empty()) << "Application writes must not reopen a remotely reset stream";
	Cancel(stream, false);
	EXPECT_TRUE(DrainWire().empty()) << "Application close must not answer RST_STREAM with another RST_STREAM";
}

TEST_F(LIBHTTP2Cancelled, HeadersOnAllocatedButUnsentIdleStreamIsProtocolError)
{
	auto *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	owned.push_back(stream);
	const uint8_t headers[] = {0x88};
	WriteServerFrame(1, 5, http2_stream_get_id(stream), headers, sizeof(headers));
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_PROTOCOL);
	ExpectGoaway(1);
	EXPECT_EQ(http2_stream_get_status(stream), -1);
}

TEST_F(LIBHTTP2, RemoteResetReleasesFlowBlockedClosingServerResponseSlot)
{
	struct http2_settings settings = {};
	settings.max_concurrent_streams = 1;
	auto *ctx = http2_ctx_server_new("local-server", bio_read, bio_write, &server_sock, &settings);
	ASSERT_NE(ctx, nullptr);
	Defer { http2_ctx_close(ctx); };
	const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
	ASSERT_EQ(write(client_sock, preface, sizeof(preface) - 1), (ssize_t)sizeof(preface) - 1);
	const uint8_t zero_window[] = {0, 4, 0, 0, 0, 0};
	WriteClientFrame(4, 0, 0, zero_window, sizeof(zero_window));
	ASSERT_EQ(http2_ctx_handshake(ctx), 1);
	const uint8_t request[] = {0x82, 0x84, 0x86};
	WriteClientFrame(1, 5, 1, request, sizeof(request));
	auto *held = http2_ctx_accept_stream(ctx);
	ASSERT_NE(held, nullptr);
	ASSERT_EQ(http2_stream_set_response(held, 200, nullptr, 0), 0);
	const uint8_t body[] = {0x12, 0x34, 0x81, 0x80};
	ASSERT_EQ(http2_stream_write_body(held, body, sizeof(body), 1), (int)sizeof(body));
	http2_stream_close(held); // ownership released, but the response is waiting for flow credit
	uint8_t wire[4096];
	while (read(client_sock, wire, sizeof(wire)) > 0) {}
	const uint8_t cancel[] = {0, 0, 0, 8};
	WriteClientFrame(3, 0, 1, cancel, sizeof(cancel));
	int ret = http2_ctx_poll(ctx, nullptr, 0, nullptr);
	ASSERT_TRUE(ret == 0 || ret == HTTP2_ERR_EAGAIN);
	EXPECT_EQ(read(client_sock, wire, sizeof(wire)), -1); // no reset echo or response DATA

	// No window update is needed to release the canceled response's single slot.
	WriteClientFrame(1, 5, 3, request, sizeof(request));
	auto *next = http2_ctx_accept_stream(ctx);
	ASSERT_NE(next, nullptr) << "Remote reset must retire the close-after-send stream and free its slot";
	Defer { http2_stream_close(next); };
	EXPECT_EQ(http2_stream_get_id(next), 3);
	EXPECT_FALSE(http2_ctx_is_closed(ctx));
}

TEST_F(LIBHTTP2Cancelled, HeadersOnRemovedUnopenedIdIsProtocolError)
{
	CheckRemovedIdleFrame(1);
}

TEST_F(LIBHTTP2Cancelled, DataOnRemovedUnopenedIdIsProtocolError)
{
	CheckRemovedIdleFrame(0);
}

TEST_F(LIBHTTP2Cancelled, ResetOnRemovedUnopenedIdIsProtocolError)
{
	CheckRemovedIdleFrame(3);
}

TEST_F(LIBHTTP2Cancelled, AllocatingHigherIdDoesNotCloseRemovedUnopenedLowerId)
{
	CheckRemovedIdleFrame(1, true);
}

TEST_F(LIBHTTP2Cancelled, RequestValidationFailureThenCloseDoesNotOpenId)
{
	CheckRemovedIdleFrame(1, false, true);
}

TEST_F(LIBHTTP2Cancelled, OpeningHigherIdImplicitlyClosesRetainedUnusedId)
{
	CheckImplicitlyClosedLocalId(false, false);
}

TEST_F(LIBHTTP2Cancelled, OpeningHigherIdImplicitlyClosesRemovedUnusedId)
{
	CheckImplicitlyClosedLocalId(true, false);
}

TEST_F(LIBHTTP2Cancelled, QueuingHigherHeadersImplicitlyClosesRetainedUnusedId)
{
	CheckImplicitlyClosedLocalId(false, true);
}

TEST_F(LIBHTTP2Cancelled, OpeningHigherIdDoesNotCloseAlreadyOpenLowerId)
{
	auto *lower = OpenRequest();
	ASSERT_NE(lower, nullptr);
	ASSERT_NE(OpenRequest(), nullptr);
	EXPECT_FALSE(http2_stream_is_end(lower));
	const uint8_t headers[] = {0x88};
	const uint8_t body[] = {0x12, 0x34, 0x81, 0x80};
	WriteServerFrame(1, 4, http2_stream_get_id(lower), headers, sizeof(headers));
	WriteServerFrame(0, 1, http2_stream_get_id(lower), body, sizeof(body));
	PollHealthy();
	EXPECT_EQ(http2_stream_get_status(lower), 200);
	uint8_t out[8];
	ASSERT_EQ(http2_stream_read_body(lower, out, sizeof(out)), (int)sizeof(body));
	EXPECT_EQ(memcmp(out, body, sizeof(body)), 0);
	EXPECT_TRUE(http2_stream_is_end(lower));
}

TEST_F(LIBHTTP2Cancelled, HpackRequestFailureCleanupPreservesInternalErrorWithoutReset)
{
	auto *stream = http2_stream_new(ctx);
	ASSERT_NE(stream, nullptr);
	owned.push_back(stream);
	// Four request fields make eight copies before the first HPACK table insertion.
	FailHpackStrdupAfter(9);
	int ret = http2_stream_set_request(stream, "POST", "/dns-query", "https", nullptr);
	FailHpackStrdupAfter(0);
	EXPECT_LT(ret, 0);
	EXPECT_TRUE(http2_ctx_is_closed(ctx));
	int old_reads = reads, old_writes = writes;
	Cancel(stream, false);
	EXPECT_TRUE(DrainWire().empty());
	EXPECT_EQ(http2_ctx_poll(ctx, nullptr, 0, nullptr), HTTP2_ERR_INTERNAL);
	EXPECT_EQ(reads, old_reads);
	EXPECT_EQ(writes, old_writes);
}

TEST_F(LIBHTTP2Cancelled, InterruptedDiscardContinuationPreservesGoawayIoError)
{
	CheckInterruptedDiscardWriteError(3, HTTP2_ERR_IO);
}

TEST_F(LIBHTTP2Cancelled, InterruptedDiscardContinuationPreservesGoawayEof)
{
	CheckInterruptedDiscardWriteError(4, HTTP2_ERR_EOF);
}
