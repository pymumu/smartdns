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

#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include <condition_variable>
#include <mutex>
#include <unistd.h>
#include "smartdns/dns_server.h"

class FastestResponse : public ::testing::Test
{
  protected:
	void SetUp() override {}

	void TearDown() override {}
};

/*
 * In fastest-response mode the first upstream's answer is sent back to the
 * client immediately. That immediate reply must NOT prevent the first pool
 * from being speed-checked: otherwise its RTT stays at -1 and the whole pool
 * is dropped when the cache is compiled, so a later query served from cache
 * loses the first upstream's addresses.
 *
 * Upstream 1 answers 1.2.3.4 immediately (wins the immediate reply),
 * upstream 2 answers 5.6.7.8 after a short delay. 1.2.3.4 is mocked faster
 * than 5.6.7.8, so after the background speed-check the cache must keep both
 * addresses, sorted by RTT.
 */
TEST_F(FastestResponse, first_pool_speed_checked)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server;

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
		return smartdns::SERVER_REQUEST_OK;
	});

	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		/* Delay so upstream 1 always wins the immediate reply. */
		usleep(100 * 1000);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
		return smartdns::SERVER_REQUEST_OK;
	});

	/*
	 * Mocked RTTs. The fake ping delay is the MockPing value in ms, but the
	 * speed check compares them as time = 10 * value in 0.1ms units against the
	 * ping timeout (~849) and against the best RTT. smartdns drops addresses
	 * significantly slower than the best, so keep 5.6.7.8 only modestly slower
	 * than 1.2.3.4 (10ms vs 12ms) so both survive into the cache. 1.2.3.4 must
	 * still be the faster one so the cache order is [1.2.3.4, 5.6.7.8].
	 */
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 12);

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
response-mode fastest-response
dualstack-ip-selection no
speed-check-mode ping
)""");

	smartdns::Client client;

	/* First query: immediate reply is the first pool from upstream 1. */
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	/*
	 * Wait for the background speed-check of both pools and for the cache to be
	 * re-compiled with the real RTTs.
	 */
	usleep(600 * 1000);

	/* Second query is served from cache: both pools must be present and sorted. */
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 2);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_LT(client.GetQueryTime(), 20);
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");
	EXPECT_EQ(client.GetAnswer()[1].GetData(), "5.6.7.8");
}

/* Internal queries (e.g. resolving an upstream given by hostname) get their result through the request
 * callback. In fastest-response mode the immediate reply must still report the IPs (ip_num > 0). */
struct FastestResponseResult {
	std::mutex lock;
	std::condition_variable cond;
	bool done = false;
	int ip_num = -1;
};

static int FastestResponseCallback(const struct dns_result *result, void *user_ptr)
{
	auto *r = (struct FastestResponseResult *)user_ptr;
	std::lock_guard<std::mutex> guard(r->lock);
	if (!r->done) {
		r->ip_num = result->ip_num;
		r->done = true;
		r->cond.notify_all();
	}
	return 0;
}

TEST_F(FastestResponse, internal_query_result_has_ip)
{
	smartdns::MockServer server_upstream1;
	smartdns::MockServer server_upstream2;
	smartdns::Server server(smartdns::Server::CREATE_MODE_THREAD);

	server_upstream1.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
		return smartdns::SERVER_REQUEST_OK;
	});
	server_upstream2.Start("udp://0.0.0.0:62053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}
		usleep(100 * 1000);
		smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
		return smartdns::SERVER_REQUEST_OK;
	});
	server.MockPing(PING_TYPE_ICMP, "1.2.3.4", 60, 10);
	server.MockPing(PING_TYPE_ICMP, "5.6.7.8", 60, 12);

	ASSERT_TRUE(server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
server 127.0.0.1:62053
response-mode fastest-response
dualstack-ip-selection no
speed-check-mode ping
)"""));

	FastestResponseResult result;
	ASSERT_EQ(dns_server_query("internal.example", DNS_T_A, nullptr, FastestResponseCallback, &result), 0);
	{
		std::unique_lock<std::mutex> lock(result.lock);
		ASSERT_TRUE(result.cond.wait_for(lock, std::chrono::seconds(5), [&] { return result.done; }));
	}
	EXPECT_GT(result.ip_num, 0);
}
