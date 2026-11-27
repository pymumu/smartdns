/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <climits>
#include <limits>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <vector>
#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>

/* clang-format off */
#include "smartdns/dns_cache.h"
#include "dns_server/cache.h"
/* clang-format on */

class Cache : public ::testing::Test
{
  protected:
	void SetUp() override {}

	void TearDown() override {}
};

TEST_F(Cache, min)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {1, 2, 3, 4};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 1
rr-ttl-min 1
speed-check-mode none
response-mode fastest-response
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, update_timer_after_destroy)
{
	struct dns_cache_key cache_key;

	ASSERT_EQ(dns_cache_init(16, 0, NULL), 0);
	dns_cache_destroy();

	cache_key.domain = "shutdown.example";
	cache_key.qtype = DNS_T_A;
	cache_key.dns_group_name = "";
	cache_key.query_flag = 0;

	EXPECT_EQ(dns_cache_update_timer(&cache_key, 300), -1);
}

TEST_F(Cache, max_reply_ttl)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {1, 2, 3, 4};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 1
rr-ttl-min 600
rr-ttl-reply-max 5
speed-check-mode none
response-mode fastest-response
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 5);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	sleep(1);

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 5);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, max_reply_ttl_expired)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {1, 2, 3, 4};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 1
rr-ttl-min 600
rr-ttl-reply-max 6
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_GE(client.GetAnswer()[0].GetTTL(), 5);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, prefetch)
{
	smartdns::MockServer server_upstream;
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "9.10.11.12", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream1.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:63053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 100);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 110);
	server.MockPing(PING_TYPE_ICMP, "9.10.11.12", 60, 110);

	server.Start(R"""(bind [::]:60053
bind [::]:60153 -group g1
server 127.0.0.1:61053
server 127.0.0.1:62053 -group g1 -exclude-default-group
server 127.0.0.1:63053 -group g2
prefetch-domain yes
rr-ttl-max 2
serve-expired no
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");

	ASSERT_TRUE(client.Query("a.com", 60153));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	sleep(1);

	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");

	sleep(1);

	ASSERT_TRUE(client.Query("a.com", 60153));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, nocache)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->domain.length() == 0) {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		usleep(15000);

		if (request->qtype == DNS_T_A) {
			unsigned char addr[4] = {1, 2, 3, 4};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else if (request->qtype == DNS_T_AAAA) {
			unsigned char addr[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), 0, addr);
		} else {
			return smartdns::SERVER_REQUEST_ERROR;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 100
rr-ttl-min 600
rr-ttl-reply-max 5
domain-rules /a.com/ --no-cache
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 5);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("a.com", 60053));
	EXPECT_GT(client.GetQueryTime(), 10);
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 5);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, save_file)
{
	smartdns::MockServer server_upstream;
	auto cache_file = "/tmp/smartdns_cache." + smartdns::GenerateRandomString(10);
	std::string conf = R"""(
bind [::]:60053@lo
server 127.0.0.1:62053
cache-persist yes
dualstack-ip-selection no
)""";

	conf += "cache-file " + cache_file;
	Defer
	{
		unlink(cache_file.c_str());
	};

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});
	{
		smartdns::Server server;
		server.Start(conf);
		smartdns::Client client;

		ASSERT_TRUE(client.Query("a.com", 60053));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_LT(client.GetQueryTime(), 100);
		EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
		server.Stop();
		usleep(200 * 1000);
	}

	ASSERT_EQ(access(cache_file.c_str(), F_OK), 0);

	std::fstream fs(cache_file, std::ios::in);
	struct dns_cache_file head;
	memset(&head, 0, sizeof(head));
	fs.read((char *)&head, sizeof(head));
	EXPECT_EQ(head.magic, MAGIC_NUMBER);
	EXPECT_EQ(head.cache_number, 1);
}

TEST_F(Cache, corrupt_file)
{
	smartdns::MockServer server_upstream;
	auto cache_file = "/tmp/smartdns_cache." + smartdns::GenerateRandomString(10);
	std::string conf = R"""(
bind [::]:60053@lo
server 127.0.0.1:62053
dualstack-ip-selection no
cache-persist yes
)""";

	conf += "cache-file " + cache_file;
	Defer
	{
		unlink(cache_file.c_str());
	};

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});
	{
		smartdns::Server server;
		server.Start(conf);
		smartdns::Client client;

		ASSERT_TRUE(client.Query("a.com", 60053));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_LT(client.GetQueryTime(), 100);
		EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
		server.Stop();
		usleep(200 * 1000);
	}

	ASSERT_EQ(access(cache_file.c_str(), F_OK), 0);

	int fd = open(cache_file.c_str(), O_RDWR);
	ASSERT_NE(fd, -1);
	srandom(time(NULL));
	off_t file_size = lseek(fd, 0, SEEK_END);
	off_t offset = random() % (file_size - 300);
	std::cout << "try make corrupt at " << offset << ", file size: " << file_size << std::endl;
	lseek(fd, offset, SEEK_SET);
	for (int i = 0; i < 300; i++) {
		unsigned char c = random() % 256;
		write(fd, &c, 1);
	}
	close(fd);
	{
		smartdns::Server server;
		server.Start(conf);
		smartdns::Client client;

		ASSERT_TRUE(client.Query("a.com", 60053));
		std::cout << client.GetResult() << std::endl;
		ASSERT_EQ(client.GetAnswerNum(), 1);
		EXPECT_EQ(client.GetStatus(), "NOERROR");
		EXPECT_LT(client.GetQueryTime(), 100);
		EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 3);
		EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
		server.Stop();
		usleep(200 * 1000);
	}
}

TEST_F(Cache, invalid_data_size_file)
{
	smartdns::MockServer server_upstream;
	auto cache_file = "/tmp/smartdns_cache." + smartdns::GenerateRandomString(10);
	std::string conf = R"""(
bind [::]:60053@lo
server 127.0.0.1:62053
dualstack-ip-selection no
cache-persist yes
)""";

	conf += "cache-file " + cache_file;
	Defer
	{
		unlink(cache_file.c_str());
	};

	struct dns_cache_file file_head;
	memset(&file_head, 0, sizeof(file_head));
	file_head.magic = MAGIC_NUMBER;
	snprintf(file_head.version, sizeof(file_head.version), "%s", dns_cache_file_version());
	file_head.cache_number = 1;

	struct dns_cache_record record;
	memset(&record, 0, sizeof(record));
	record.magic = MAGIC_RECORD;

	struct dns_cache_data_head data_head;
	memset(&data_head, 0, sizeof(data_head));
	data_head.magic = MAGIC_CACHE_DATA;
	data_head.size = -1;

	int fd = open(cache_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0640);
	ASSERT_NE(fd, -1);
	ASSERT_EQ(write(fd, &file_head, sizeof(file_head)), (ssize_t)sizeof(file_head));
	ASSERT_EQ(write(fd, &record, sizeof(record)), (ssize_t)sizeof(record));
	ASSERT_EQ(write(fd, &data_head, sizeof(data_head)), (ssize_t)sizeof(data_head));
	close(fd);

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	smartdns::Server server;
	server.Start(conf);
	smartdns::Client client;

	ASSERT_TRUE(client.Query("a.com", 60053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, truncated_data_file)
{
	smartdns::MockServer server_upstream;
	auto cache_file = "/tmp/smartdns_cache." + smartdns::GenerateRandomString(10);
	std::string conf = R"""(
bind [::]:60053@lo
server 127.0.0.1:62053
dualstack-ip-selection no
cache-persist yes
)""";

	conf += "cache-file " + cache_file;
	Defer
	{
		unlink(cache_file.c_str());
	};

	struct dns_cache_file file_head;
	memset(&file_head, 0, sizeof(file_head));
	file_head.magic = MAGIC_NUMBER;
	snprintf(file_head.version, sizeof(file_head.version), "%s", dns_cache_file_version());
	file_head.cache_number = 1;

	struct dns_cache_record record;
	memset(&record, 0, sizeof(record));
	record.magic = MAGIC_RECORD;

	struct dns_cache_data_head data_head;
	memset(&data_head, 0, sizeof(data_head));
	data_head.magic = MAGIC_CACHE_DATA;
	data_head.size = 4;

	int fd = open(cache_file.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0640);
	ASSERT_NE(fd, -1);
	ASSERT_EQ(write(fd, &file_head, sizeof(file_head)), (ssize_t)sizeof(file_head));
	ASSERT_EQ(write(fd, &record, sizeof(record)), (ssize_t)sizeof(record));
	ASSERT_EQ(write(fd, &data_head, sizeof(data_head)), (ssize_t)sizeof(data_head));
	close(fd);

	server_upstream.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	smartdns::Server server;
	server.Start(conf);
	smartdns::Client client;

	ASSERT_TRUE(client.Query("a.com", 60053));
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
}

TEST_F(Cache, cname)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		std::string domain = request->domain;
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		if (domain == "a.com") {
			unsigned char addr[4] = {1, 2, 3, 4};
			dns_add_domain(request->response_packet, domain.c_str(), DNS_T_A, DNS_C_IN);
			dns_add_CNAME(request->response_packet, DNS_RRS_AN, domain.c_str(), 300, "cdn.other.example");
			/* The additional section is not an independent cache response for the CNAME target. */
			dns_add_A(request->response_packet, DNS_RRS_NR, "cdn.other.example", 300, addr);
		} else if (domain == "cdn.other.example") {
			unsigned char addr[4] = {5, 6, 7, 8};
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), 300, addr);
		} else {
			return smartdns::SERVER_REQUEST_SOA;
		}

		request->response_packet->head.rcode = DNS_RC_NOERROR;
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
cache-size 100
)""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_GE(client.GetAnswer()[0].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "cdn.other.example.");
	EXPECT_EQ(client.GetAnswer()[1].GetName(), "cdn.other.example");
	EXPECT_GE(client.GetAnswer()[1].GetTTL(), 3);
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "1.2.3.4");

	/* A CNAME response must not pre-populate the independent target cache key. */
	ASSERT_TRUE(client.Query("cdn.other.example A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "cdn.other.example");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");
}

namespace {
struct PersistedRecord {
    size_t offset;
    dns_cache_record record;
    dns_cache_data_head data;
};

std::vector<char> read_cache_bytes(const std::string &file)
{
    std::ifstream in(file, std::ios::binary);
    return std::vector<char>(std::istreambuf_iterator<char>(in), {});
}

bool write_cache_bytes(const std::string &file, const std::vector<char> &bytes)
{
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), bytes.size());
    return out.good();
}

std::vector<PersistedRecord> cache_records(const std::vector<char> &bytes)
{
    if (bytes.size() < sizeof(dns_cache_file)) return {};
    dns_cache_file header;
    memcpy(&header, bytes.data(), sizeof(header));
    std::vector<PersistedRecord> records;
    size_t offset = sizeof(header);
    for (uint32_t i = 0; i < header.cache_number; i++) {
        if (offset > bytes.size() || sizeof(dns_cache_record) + sizeof(dns_cache_data_head) > bytes.size() - offset)
            return {};
        PersistedRecord entry{};
        entry.offset = offset;
        memcpy(&entry.record, bytes.data() + offset, sizeof(entry.record));
        offset += sizeof(entry.record);
        memcpy(&entry.data, bytes.data() + offset, sizeof(entry.data));
        offset += sizeof(entry.data);
        if (entry.data.size <= 0 || static_cast<size_t>(entry.data.size) > bytes.size() - offset) return {};
        offset += entry.data.size;
        records.push_back(entry);
    }
    return records;
}

std::string persisted_config(const std::string &file)
{
    return "bind 127.0.0.1:60053\nserver 127.0.0.1:62053\ncache-size 16\n"
        "speed-check-mode none\ndualstack-ip-selection no\ncache-persist yes\n"
        "prefetch-domain no\nserve-expired no\ncache-file " + file + "\n";
}

bool seed_cache_file(const std::string &conf, const std::vector<std::string> &names, int ttl = 600)
{
    smartdns::MockServer upstream;
    if (!upstream.Start("udp://127.0.0.1:62053", [ttl](smartdns::ServerRequestContext *r) {
        unsigned char ip[] = {1, 2, 3, 4};
        dns_add_A(r->response_packet, DNS_RRS_AN, r->domain.c_str(), ttl, ip);
        return smartdns::SERVER_REQUEST_OK;
    })) return false;
    smartdns::Server server;
    if (!server.Start(conf)) return false;
    for (const auto &name : names) {
        smartdns::Client client;
        if (!client.Query(name, 60053) || client.GetStatus() != "NOERROR") return false;
    }
    server.Stop();
    return true; // MockServer is stopped before the caller performs any reload.
}
}

TEST_F(Cache, InvalidPersistedRecordDoesNotDiscardValidNeighbors)
{
    auto file = "/tmp/smartdns_cache.neighbors." + smartdns::GenerateRandomString(10);
    Defer { unlink(file.c_str()); };
    auto conf = persisted_config(file);
    ASSERT_TRUE(seed_cache_file(conf, {"first.metadata.test", "middle.metadata.test", "last.metadata.test"}));
    auto saved = read_cache_bytes(file);
    auto records = cache_records(saved);
    ASSERT_EQ(records.size(), 3U);
    for (size_t bad = 0; bad < records.size(); bad++) {
        for (int variant = 0; variant < 8; variant++) {
            SCOPED_TRACE(::testing::Message() << "record=" << bad << " variant=" << variant);
            auto changed = saved;
            auto record = records[bad].record;
            switch (variant) {
            case 0: record.info.ttl = INT_MIN; break;
            case 1: record.info.timeout = INT_MIN; break;
            case 2: record.info.insert_time = -1; break;
            case 3: record.info.replace_time = -1; break;
            case 4: record.info.hitnum = INT_MAX; break;
            case 5: record.info.hitnum_update_add = INT_MAX; break;
            case 6: record.info.hitnum = -1; break;
            case 7: record.info.hitnum_update_add = -1; break;
            }
            memcpy(changed.data() + records[bad].offset, &record, sizeof(record));
            ASSERT_TRUE(write_cache_bytes(file, changed));
            smartdns::Server server;
            ASSERT_TRUE(server.Start(conf)); // no upstream is running
            for (size_t good = 0; good < records.size(); good++) {
                if (good == bad) continue;
                smartdns::Client client;
                ASSERT_TRUE(client.Query(records[good].record.info.domain, 60053));
                EXPECT_EQ(client.GetStatus(), "NOERROR");
                ASSERT_EQ(client.GetAnswerNum(), 1);
                EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
            }
            server.Stop();
            auto retained = cache_records(read_cache_bytes(file));
            ASSERT_EQ(retained.size(), 2U);
            for (const auto &entry : retained)
                EXPECT_STRNE(entry.record.info.domain, record.info.domain);
        }
    }
}

TEST_F(Cache, BrokenRecordFramingStopsBeforeUntrustedPayload)
{
    auto file = "/tmp/smartdns_cache.framing." + smartdns::GenerateRandomString(10);
    Defer { unlink(file.c_str()); };
    auto conf = persisted_config(file);
    ASSERT_TRUE(seed_cache_file(conf, {"first.framing.test", "middle.framing.test", "last.framing.test"}));
    auto saved = read_cache_bytes(file);
    auto records = cache_records(saved);
    ASSERT_EQ(records.size(), 3U);
    for (bool bad_magic : {false, true}) {
        auto changed = saved;
        auto data = records[1].data;
        if (bad_magic) data.magic = 0;
        else data.size = 8192; // within the record limit, outside the actual file
        auto metadata = records[1].record;
        metadata.info.ttl = -1; // must not skip before validating the payload boundary
        memcpy(changed.data() + records[1].offset, &metadata, sizeof(metadata));
        memcpy(changed.data() + records[1].offset + sizeof(metadata), &data, sizeof(data));
        ASSERT_TRUE(write_cache_bytes(file, changed));
        smartdns::Server server;
        ASSERT_TRUE(server.Start(conf));
        smartdns::Client client;
        ASSERT_TRUE(client.Query(records[0].record.info.domain, 60053));
        EXPECT_EQ(client.GetStatus(), "NOERROR");
        server.Stop();
        auto retained = cache_records(read_cache_bytes(file));
        ASSERT_EQ(retained.size(), 1U);
        EXPECT_STREQ(retained[0].record.info.domain, records[0].record.info.domain);
    }
}

TEST_F(Cache, ValidLargeTtlSurvivesPrefetchPersistenceAndOfflineReload)
{
    auto file = "/tmp/smartdns_cache.large-ttl." + smartdns::GenerateRandomString(10);
    Defer { unlink(file.c_str()); };
    auto conf = persisted_config(file) + "prefetch-domain yes\nserve-expired yes\nserve-expired-prefetch-time 60\n";
    ASSERT_TRUE(seed_cache_file(conf, {"large-ttl.metadata.test"}, INT_MAX));
    auto records = cache_records(read_cache_bytes(file));
    ASSERT_EQ(records.size(), 1U);
    EXPECT_EQ(records[0].record.info.ttl, INT_MAX);
    EXPECT_EQ(records[0].record.info.timeout, INT_MAX);
    smartdns::Server server;
    ASSERT_TRUE(server.Start(conf));
    smartdns::Client client;
    ASSERT_TRUE(client.Query("large-ttl.metadata.test", 60053));
    EXPECT_EQ(client.GetStatus(), "NOERROR");
    ASSERT_EQ(client.GetAnswerNum(), 1);
    EXPECT_GT(client.GetAnswer()[0].GetTTL(), INT_MAX - 10);
    server.Stop();
}

TEST_F(Cache, FuturePersistedTimesAreDiscardedWithoutRenewingTtl)
{
    auto file = "/tmp/smartdns_cache.future." + smartdns::GenerateRandomString(10);
    Defer { unlink(file.c_str()); };
    auto conf = persisted_config(file);
    ASSERT_TRUE(seed_cache_file(conf, {"before.future.test", "future.metadata.test", "after.future.test"}));
    auto saved = read_cache_bytes(file);
    auto records = cache_records(saved);
    ASSERT_EQ(records.size(), 3U);
    for (int field = 0; field < 3; field++) for (bool extreme : {false, true}) {
        SCOPED_TRACE(::testing::Message() << "field=" << field << " extreme=" << extreme);
        auto changed = saved;
        auto record = records[1].record;
        time_t future = extreme ? (std::numeric_limits<time_t>::max)() : time(nullptr) + 8 * 3600;
        if (field != 1) record.info.insert_time = future;
        if (field != 0) record.info.replace_time = future;
        memcpy(changed.data() + records[1].offset, &record, sizeof(record));
        ASSERT_TRUE(write_cache_bytes(file, changed));
        smartdns::Server server;
        ASSERT_TRUE(server.Start(conf));
        for (size_t good : {0U, 2U}) {
            smartdns::Client client;
            ASSERT_TRUE(client.Query(records[good].record.info.domain, 60053));
            EXPECT_EQ(client.GetStatus(), "NOERROR");
        }
        server.Stop();
        auto retained = cache_records(read_cache_bytes(file));
        ASSERT_EQ(retained.size(), 2U);
        for (const auto &entry : retained)
            EXPECT_STRNE(entry.record.info.domain, record.info.domain);
    }
}

TEST_F(Cache, ValidPersistedCounterBoundsDoNotResetRecordTimes)
{
    auto file = "/tmp/smartdns_cache.counters." + smartdns::GenerateRandomString(10);
    Defer { unlink(file.c_str()); };
    auto conf = persisted_config(file);
    ASSERT_TRUE(seed_cache_file(conf, {"counters.metadata.test"}));
    auto saved = read_cache_bytes(file);
    auto records = cache_records(saved);
    ASSERT_EQ(records.size(), 1U);
    for (int hits : {0, 6000}) {
        SCOPED_TRACE(hits);
        auto changed = saved;
        auto record = records[0].record;
        record.info.hitnum = hits; record.info.hitnum_update_add = hits ? 6 : 0;
        memcpy(changed.data() + records[0].offset, &record, sizeof(record));
        ASSERT_TRUE(write_cache_bytes(file, changed));
        smartdns::Server server;
        ASSERT_TRUE(server.Start(conf));
        smartdns::Client client;
        ASSERT_TRUE(client.Query("counters.metadata.test", 60053));
        EXPECT_EQ(client.GetStatus(), "NOERROR");
        server.Stop();
        auto retained = cache_records(read_cache_bytes(file));
        ASSERT_EQ(retained.size(), 1U);
        EXPECT_EQ(retained[0].record.info.insert_time, record.info.insert_time);
        EXPECT_EQ(retained[0].record.info.replace_time, record.info.replace_time);
    }
}

TEST_F(Cache, PersistedExpiryHonorsServeExpiredWindow)
{
    auto file = "/tmp/smartdns_cache.expiry." + smartdns::GenerateRandomString(10);
    Defer { unlink(file.c_str()); };
    auto conf = persisted_config(file);
    ASSERT_TRUE(seed_cache_file(conf, {"expiry.metadata.test"}));
    auto saved = read_cache_bytes(file);
    auto records = cache_records(saved);
    ASSERT_EQ(records.size(), 1U);
    struct Scenario { int age; bool serve; bool retain; };
    for (auto test : {Scenario{10, false, true}, {600, false, false}, {700, false, false},
        {610, true, true}, {690, true, true}, {720, true, false}, {730, true, false}}) {
        SCOPED_TRACE(::testing::Message() << "age=" << test.age << " serve=" << test.serve);
        auto changed = saved;
        auto record = records[0].record;
        record.info.ttl = 600;
        record.info.insert_time = record.info.replace_time = time(nullptr) - test.age;
        memcpy(changed.data() + records[0].offset, &record, sizeof(record));
        ASSERT_TRUE(write_cache_bytes(file, changed));
        time_t before_load = time(nullptr);
        smartdns::Server server(smartdns::Server::CREATE_MODE_THREAD);
        auto reload = conf + (test.serve ? "serve-expired yes\nserve-expired-ttl 120\n" : "");
        ASSERT_TRUE(server.Start(reload));
        dns_cache_key key{record.info.domain, record.info.qtype, record.info.dns_group_name, record.info.query_flag};
        auto *loaded = dns_cache_lookup(&key);
        if (test.retain) {
            ASSERT_NE(loaded, nullptr);
            // Observe the scheduled timer, not the original persisted timeout field.
            EXPECT_GT(loaded->timer.expires, static_cast<unsigned long>(time(nullptr)));
            EXPECT_LE(loaded->timer.expires, static_cast<unsigned long>(before_load +
                600 + (test.serve ? 120 : 0) - test.age));
        } else {
            EXPECT_EQ(loaded, nullptr);
        }
        dns_cache_release(loaded);
        if (test.retain) {
            smartdns::Client client;
            ASSERT_TRUE(client.Query("expiry.metadata.test", 60053));
            EXPECT_EQ(client.GetStatus(), "NOERROR");
        }
        server.Stop();
        auto retained = cache_records(read_cache_bytes(file));
        ASSERT_EQ(retained.size(), test.retain ? 1U : 0U);
        if (test.retain) {
            EXPECT_EQ(retained[0].record.info.insert_time, record.info.insert_time);
            EXPECT_EQ(retained[0].record.info.timeout, record.info.timeout);
        }
    }
}

TEST_F(Cache, TtlConsumersDoNotOverflowAtRepresentableLimits)
{
    dns_cache cache{};
    cache.info.insert_time = time(nullptr);
    cache.info.ttl = INT_MAX;
    EXPECT_GE(dns_cache_get_ttl(&cache), INT_MAX - 1);
    EXPECT_EQ(_dns_server_expired_cache_ttl(&cache, INT_MAX), INT_MAX);
    cache.info.insert_time = 0;
    cache.info.ttl = 0;
    EXPECT_EQ(dns_cache_get_ttl(&cache), 0);
    EXPECT_LE(_dns_server_expired_cache_ttl(&cache, 0), 0);
}
