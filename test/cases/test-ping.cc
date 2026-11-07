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
#include "smartdns/fast_ping.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/tlog.h"
#include "gtest/gtest.h"
#include "fast_ping/ping_host.h"
#include "fast_ping/ping_fake.h"
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <mutex>

class Ping : public ::testing::Test
{
  protected:
	virtual void SetUp()
	{
		EXPECT_EQ(fast_ping_init(), 0);
		loglevel = tlog_getlevel();
		tlog_setlevel(TLOG_DEBUG);
	}
	virtual void TearDown()
	{
		fast_ping_exit();
		tlog_setlevel(loglevel);
	}

  private:
	tlog_level loglevel;
};

void ping_result_callback(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
						  struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv, int error,
						  void *userptr)
{
	auto *count = static_cast<std::atomic<int> *>(userptr);
	if (result == PING_RESULT_RESPONSE) {
		*count = 1;
		tlog(TLOG_INFO, "ping to %s succeeded, seq=%d, ttl=%d", host, seqno, ttl);
	}
}

TEST_F(Ping, icmp)
{
	struct ping_host_struct *ping_host;
	std::atomic<int> count{0};
	
	if (smartdns::IsICMPAvailable() == false) {
		tlog(TLOG_INFO, "ICMP is not available, skip this test.");
		GTEST_SKIP();
		return;
	}

	ping_host = fast_ping_start(PING_TYPE_ICMP, "127.0.0.1", 1, 1, 200, ping_result_callback, &count);
	ASSERT_NE(ping_host, nullptr);
	usleep(10000);
	fast_ping_stop(ping_host);
	fast_ping_exit();
	EXPECT_EQ(count.load(), 1);
}

TEST_F(Ping, tcp)
{
	struct ping_host_struct *ping_host;
	std::atomic<int> count{0};
	ping_host = fast_ping_start(PING_TYPE_TCP, "127.0.0.1:1", 1, 1, 200, ping_result_callback, &count);
	ASSERT_NE(ping_host, nullptr);
	usleep(10000);
	fast_ping_stop(ping_host);
	fast_ping_exit();
	EXPECT_EQ(count.load(), 1);
}

TEST_F(Ping, tcp_syn)
{
	struct ping_host_struct *ping_host;
	std::atomic<int> count{0};
	
	/* Test TCP SYN ping - may not work in all environments */
	ping_host = fast_ping_start(PING_TYPE_TCP_SYN, "127.0.0.1:53", 5, 1000, 1000, ping_result_callback, &count);
	if (ping_host == nullptr) {
		tlog(TLOG_INFO, "TCP SYN ping not available (need root/CAP_NET_RAW), skip this test.");
		GTEST_SKIP();
		return;
	}
	
	usleep(10000);
	fast_ping_stop(ping_host);
	fast_ping_exit();
	
	EXPECT_GT(count.load(), 0);
}

TEST_F(Ping, tcp_syn_v6)
{
	struct ping_host_struct *ping_host;
	std::atomic<int> count{0};

	/* Test TCP SYN ping - may not work in all environments */
	ping_host = fast_ping_start(PING_TYPE_TCP_SYN, "[::1]:443", 2, 1000, 1000, ping_result_callback, &count);
	if (ping_host == nullptr) {
		tlog(TLOG_INFO, "TCP SYN ping not available (need root/CAP_NET_RAW), skip this test.");
		GTEST_SKIP();
		return;
	}
	
	usleep(1000000);
	fast_ping_stop(ping_host);
	fast_ping_exit();
	
	EXPECT_GT(count.load(), 0);
}

TEST_F(Ping, tcp_syn_concurrent)
{
	struct ping_host_struct *ping_host1;
	struct ping_host_struct *ping_host2;
	std::atomic<int> count1{0}, count2{0};
	
	/* Test concurrent TCP SYN pings to different servers */
	ping_host1 = fast_ping_start(PING_TYPE_TCP_SYN, "127.0.0.1:22", 1, 1, 500, ping_result_callback, &count1);
	if (ping_host1 == nullptr) {
		tlog(TLOG_INFO, "TCP SYN ping not available, skip this test.");
		GTEST_SKIP();
		return;
	}
	
	tlog(TLOG_INFO, "First ping started, now starting second...");
	
	/* A second loopback address keeps this test offline. */
	ping_host2 = fast_ping_start(PING_TYPE_TCP_SYN, "127.0.0.2:53", 1, 1, 500, ping_result_callback, &count2);
	ASSERT_NE(ping_host2, nullptr);
	
	tlog(TLOG_INFO, "Both pings started, waiting 200ms...");
	usleep(200000); /* Wait 200ms for responses */
	
	tlog(TLOG_INFO, "Wait complete, stopping pings...");
	fast_ping_stop(ping_host1);
	fast_ping_stop(ping_host2);
	fast_ping_exit();
	usleep(50000); /* Brief wait for cleanup */
	
	tlog(TLOG_INFO, "TCP SYN concurrent ping test completed, count1=%d, count2=%d", count1.load(), count2.load());
	
	/* At least one should succeed (localhost SSH should be reachable) */
	EXPECT_GE(count1.load() + count2.load(), 1);
}

void fake_ping_result_callback(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
							   struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
							   int error, void *userptr)
{
	if (result == PING_RESULT_RESPONSE) {
		auto *count = static_cast<std::atomic<int> *>(userptr);
		double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
		tlog(TLOG_INFO, "from %15s: seq=%d ttl=%d time=%.3f\n", host, seqno, ttl, rtt);
		*count = (int)rtt;
	}
}

TEST_F(Ping, fake_icmp)
{
	struct ping_host_struct *ping_host;
	std::atomic<int> count{0};
	fast_ping_fake_ip_add(PING_TYPE_ICMP, "1.2.3.4", 60, 5);
	ping_host = fast_ping_start(PING_TYPE_ICMP, "1.2.3.4", 1, 1000, 200, fake_ping_result_callback, &count);
	ASSERT_NE(ping_host, nullptr);
	usleep(100000);
	fast_ping_stop(ping_host);
	fast_ping_exit();
	EXPECT_GE(count.load(), 5);
}

namespace {
struct PingStartProbe {
	std::mutex mutex;
	std::condition_variable changed;
	bool fail_send = false;
	bool stop_on_end = false;
	bool registered_before_send = false;
	bool pending_before_send = false;
	bool inactive_before_send = false;
	bool completed_before_return = false;
	bool pending_after_response = true;
	bool removed_on_error = false;
	int responses = 0;
	int ends = 0;
	int errors = 0;
	int timeouts = 0;
	int error = 0;
	int replacement_fd = -1;
	struct fast_ping_fake_ip *held_fake = nullptr;
};

/* Only the calling test thread installs a probe; unrelated ping sends are untouched. */
thread_local PingStartProbe *start_probe = nullptr;

void start_probe_callback(struct ping_host_struct *host, const char *, FAST_PING_RESULT result,
						  struct sockaddr *, socklen_t, int, int, struct timeval *, int error, void *userptr)
{
	auto *probe = static_cast<PingStartProbe *>(userptr);
	std::lock_guard<std::mutex> lock(probe->mutex);
	if (result == PING_RESULT_RESPONSE) {
		probe->responses++;
	} else if (result == PING_RESULT_END) {
		probe->ends++;
		if (probe->stop_on_end) {
			fast_ping_stop(host);
		}
	} else if (result == PING_RESULT_TIMEOUT) {
		probe->timeouts++;
	} else if (result == PING_RESULT_ERROR) {
		probe->errors++;
		probe->error = error;
		pthread_mutex_lock(&ping.map_lock);
		probe->removed_on_error = !hash_hashed(&host->addr_node) && host->send == 0;
		pthread_mutex_unlock(&ping.map_lock);
		/* Reuse the closed fake timer descriptor. A second close during rollback
		 * would accidentally close this independently owned descriptor. */
		probe->replacement_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	}
	probe->changed.notify_all();
}
} // namespace

/* Linked only by libsmartdns-test.a; the release library has no hook. */
extern "C" int fast_ping_test_send_hook(struct ping_host_struct *host, int before)
{
	PingStartProbe *probe = start_probe;
	if (probe == nullptr || host->userptr != probe) {
		return 0;
	}
	if (before) {
		pthread_mutex_lock(&ping.map_lock);
		probe->registered_before_send = hash_hashed(&host->addr_node);
		probe->pending_before_send = host->send == 1;
		probe->inactive_before_send = host->run == 0;
		pthread_mutex_unlock(&ping.map_lock);
		if (probe->fail_send) {
			probe->held_fake = host->fake;
			if (probe->held_fake != nullptr) {
				_fast_ping_fake_get(probe->held_fake);
			}
			errno = EIO;
			return -1;
		}
	} else {
		/* Hold startup open until the real receiver has consumed the first
		 * response and removed the one-shot host. No retry can rescue it. */
		std::unique_lock<std::mutex> lock(probe->mutex);
		probe->completed_before_return = probe->changed.wait_for(lock, std::chrono::milliseconds(500),
			[&] { return probe->ends == 1; });
		if (probe->completed_before_return) {
			probe->pending_after_response = host->send != 0;
		}
	}
	return 0;
}

static void check_first_reply_before_start_returns(PING_TYPE type, const char *address, bool stop_on_end = false)
{
	if (type == PING_TYPE_TCP_SYN) {
		int family = address[0] == '[' ? AF_INET6 : AF_INET;
		int fd = socket(family, SOCK_RAW, IPPROTO_TCP);
		if (fd < 0 && (errno == EPERM || errno == EACCES || errno == EAFNOSUPPORT)) {
			GTEST_SKIP() << "Raw TCP socket unavailable";
		}
		ASSERT_GE(fd, 0);
		close(fd);
	}
	PingStartProbe probe;
	probe.stop_on_end = stop_on_end;
	start_probe = &probe;
	auto *host = fast_ping_start(type, address, 1, 1000, 1000, start_probe_callback, &probe);
	start_probe = nullptr;
	EXPECT_NE(host, nullptr);
	/* END callbacks may consume caller ownership, as the DNS callback does.
	 * Never dereference or stop that returned handle a second time. */
	if (host != nullptr && !stop_on_end) {
		fast_ping_stop(host);
	}
	/* Drain notifications before the stack-owned callback context goes away. */
	fast_ping_exit();
	EXPECT_TRUE(probe.registered_before_send);
	EXPECT_TRUE(probe.pending_before_send);
	EXPECT_TRUE(probe.inactive_before_send);
	EXPECT_TRUE(probe.completed_before_return);
	EXPECT_FALSE(probe.pending_after_response);
	EXPECT_EQ(probe.responses, 1);
	EXPECT_EQ(probe.ends, 1);
	EXPECT_EQ(probe.errors, 0);
	EXPECT_EQ(probe.timeouts, 0);
	if (probe.replacement_fd >= 0) {
		close(probe.replacement_fd);
	}
}

TEST_F(Ping, tcp_syn_first_reply_before_start_returns)
{
	check_first_reply_before_start_returns(PING_TYPE_TCP_SYN, "127.0.0.1:53");
}

TEST_F(Ping, tcp_syn_v6_first_reply_before_start_returns)
{
	check_first_reply_before_start_returns(PING_TYPE_TCP_SYN, "[::1]:443");
}

TEST_F(Ping, fake_first_reply_before_start_returns)
{
	ASSERT_EQ(fast_ping_fake_ip_add(PING_TYPE_ICMP, "192.0.2.1", 60, 1), 0);
	check_first_reply_before_start_returns(PING_TYPE_ICMP, "192.0.2.1");
}

TEST_F(Ping, fake_end_callback_stops_during_start)
{
	ASSERT_EQ(fast_ping_fake_ip_add(PING_TYPE_ICMP, "192.0.2.1", 60, 1), 0);
	check_first_reply_before_start_returns(PING_TYPE_ICMP, "192.0.2.1", true);
}

TEST_F(Ping, failed_start_rolls_back_registered_fake)
{
	ASSERT_EQ(fast_ping_fake_ip_add(PING_TYPE_ICMP, "192.0.2.1", 60, 1), 0);
	PingStartProbe probe;
	probe.fail_send = true;
	start_probe = &probe;
	auto *host = fast_ping_start(PING_TYPE_ICMP, "192.0.2.1", 1, 1000, 1000, start_probe_callback, &probe);
	start_probe = nullptr;
	EXPECT_EQ(host, nullptr);
	if (host != nullptr) {
		fast_ping_stop(host);
	}
	EXPECT_TRUE(probe.registered_before_send);
	EXPECT_TRUE(probe.pending_before_send);
	EXPECT_TRUE(probe.inactive_before_send);
	EXPECT_TRUE(probe.removed_on_error);
	EXPECT_GE(probe.replacement_fd, 0);
	if (probe.replacement_fd >= 0) {
		EXPECT_NE(fcntl(probe.replacement_fd, F_GETFD), -1);
		close(probe.replacement_fd);
	}
	pthread_mutex_lock(&ping.map_lock);
	/* hash_empty uses a C-only array type check; keep the same full-table scan. */
	bool empty = __hash_empty(ping.addrmap, sizeof(ping.addrmap) / sizeof(ping.addrmap[0]));
	pthread_mutex_unlock(&ping.map_lock);
	EXPECT_TRUE(empty);
	/* Only the fixture and this test should still own the fake endpoint. */
	EXPECT_NE(probe.held_fake, nullptr);
	if (probe.held_fake != nullptr) {
		EXPECT_EQ(atomic_read(&probe.held_fake->ref), 2);
	}
	EXPECT_EQ(fast_ping_fake_ip_remove(PING_TYPE_ICMP, "192.0.2.1"), 0);
	if (probe.held_fake != nullptr) {
		EXPECT_EQ(atomic_read(&probe.held_fake->ref), 1);
		_fast_ping_fake_put(probe.held_fake);
	}
	fast_ping_exit();
	EXPECT_EQ(probe.errors, 1);
	EXPECT_EQ(probe.error, EIO);
	EXPECT_EQ(probe.responses, 0);
	EXPECT_EQ(probe.ends, 0);
	EXPECT_EQ(probe.timeouts, 0);
}
