#include "gtest/gtest.h"
#include "smartdns/http_parse.h"
#include <string.h>

TEST(HttpParserTest, ParseMethods)
{
	struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
	const char *req = "OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int ret = http_head_parse(head, (const uint8_t *)req, strlen(req));
	EXPECT_GT(ret, 0);
	EXPECT_EQ(http_head_get_method(head), HTTP_METHOD_OPTIONS);
	http_head_destroy(head);

	head = http_head_init(4096, HTTP_VERSION_1_1);
	req = "PATCH /data HTTP/1.1\r\nHost: localhost\r\n\r\n";
	ret = http_head_parse(head, (const uint8_t *)req, strlen(req));
	EXPECT_GT(ret, 0);
	EXPECT_EQ(http_head_get_method(head), HTTP_METHOD_PATCH);
	http_head_destroy(head);
}

TEST(HttpParserTest, ValuelessParams)
{
	struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
	const char *req = "GET /image?webp&q=80 HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int ret = http_head_parse(head, (const uint8_t *)req, strlen(req));
	EXPECT_GT(ret, 0);
	
	const char *val = http_head_get_params_value(head, "webp");
	EXPECT_STREQ(val, "");

	val = http_head_get_params_value(head, "q");
	EXPECT_STREQ(val, "80");

	char buf[1024];
	int clen = http_head_serialize(head, buf, sizeof(buf));
	EXPECT_GT(clen, 0);
	EXPECT_NE(strstr(buf, "?webp&q=80"), nullptr);
	EXPECT_EQ(strstr(buf, "webp="), nullptr);

	http_head_destroy(head);
}

TEST(HttpParserTest, UrlBoundary)
{
	struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
	// Test regression case where version might be misinterpreted if spaces are present
	const char *req = "GET /path%20with%20space HTTP/1.1\r\nHost: localhost\r\n\r\n";
	int ret = http_head_parse(head, (const uint8_t *)req, strlen(req));
	EXPECT_GT(ret, 0);
	EXPECT_STREQ(http_head_get_url(head), "/path%20with%20space");
	http_head_destroy(head);
}

TEST(HttpParserTest, SnprintfCheck)
{
	struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
	http_head_set_head_type(head, HTTP_HEAD_REQUEST);
	http_head_set_method(head, HTTP_METHOD_GET);
	http_head_set_url(head, "/very/long/url/that/will/not/fit/in/a/small/buffer/hopefully");
	http_head_set_httpversion(head, "HTTP/1.1");

	char small_buf[20];
	int ret = http_head_serialize(head, small_buf, sizeof(small_buf));
	// Should return -3 for buffer too small
	EXPECT_EQ(ret, -3);

	http_head_destroy(head);
}
