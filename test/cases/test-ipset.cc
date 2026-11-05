/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 *************************************************************************/

#include "smartdns/util.h"
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <unistd.h>

namespace {

const char *const kIpSetInitWorkerEnv = "SMARTDNS_IPSET_INIT_WORKER";

static int count_open_fds()
{
	DIR *dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		return -1;
	}

	int count = 0;
	while (readdir(dir) != NULL) {
		count++;
	}
	closedir(dir);

	/* Exclude the synthetic . and .. directory entries. */
	return count - 2;
}

} // namespace

/* Run this test in a fresh exec'd process so ipset_fd is guaranteed uninitialized. */
TEST(IpSet, ConcurrentSocketInitWorker)
{
	if (getenv(kIpSetInitWorkerEnv) == NULL) {
		GTEST_SKIP() << "worker test is executed in an isolated subprocess";
	}

	int probe_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (probe_fd < 0) {
		GTEST_SKIP() << "NETLINK_NETFILTER is unavailable";
	}
	close(probe_fd);

	const int thread_count = 32;
	const int fds_before = count_open_fds();
	ASSERT_GE(fds_before, 0);

	std::atomic<int> ready{0};
	std::atomic<int> failures{0};
	std::atomic<bool> start{false};
	std::vector<std::thread> workers;
	workers.reserve(thread_count);
	const std::string invalid_set_name(40, 'x');
	const unsigned char addr[4] = {192, 0, 2, 1};

	for (int i = 0; i < thread_count; i++) {
		workers.emplace_back([&]() {
			ready.fetch_add(1);
			while (!start.load()) {
				std::this_thread::yield();
			}

			errno = 0;
			if (ipset_add(invalid_set_name.c_str(), addr, sizeof(addr), 0) != -1 || errno != ENAMETOOLONG) {
				failures.fetch_add(1);
			}
		});
	}

	while (ready.load() != thread_count) {
		std::this_thread::yield();
	}
	start.store(true);
	for (auto &worker : workers) {
		worker.join();
	}

	EXPECT_EQ(failures.load(), 0);
	EXPECT_EQ(count_open_fds() - fds_before, 1) << "concurrent first use should retain exactly one netlink fd";
}

TEST(IpSet, ConcurrentFirstUseCreatesOneSocket)
{
	pid_t pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		setenv(kIpSetInitWorkerEnv, "1", 1);
		execl("/proc/self/exe", "test.bin", "--gtest_filter=IpSet.ConcurrentSocketInitWorker", (char *)NULL);
		_exit(127);
	}

	int status = 0;
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WEXITSTATUS(status), 0);
}

TEST(IpSet, ConcurrentAddsPopulateSet)
{
	if (getenv("SMARTDNS_RUN_IPSET_INTEGRATION") == NULL) {
		GTEST_SKIP() << "run in a private network namespace with SMARTDNS_RUN_IPSET_INTEGRATION=1";
	}
	if (system("ipset --version >/dev/null 2>&1") != 0) {
		GTEST_SKIP() << "ipset command is unavailable";
	}

	const std::string set_name = "sdns_" + std::to_string(getpid());
	const std::string create_set = "ipset create " + set_name + " hash:ip family inet timeout 60 >/dev/null 2>&1";
	const std::string destroy_set = "ipset destroy " + set_name + " >/dev/null 2>&1";
	if (system(create_set.c_str()) != 0) {
		GTEST_SKIP() << "cannot create the test ipset (needs CAP_NET_ADMIN)";
	}

	std::vector<std::string> ips;
	for (int i = 1; i <= 16; i++) {
		ips.push_back("198.51." + std::to_string(i) + ".1");
	}

	std::atomic<int> ready{0};
	std::atomic<int> failures{0};
	std::atomic<bool> start{false};
	std::vector<std::thread> workers;
	workers.reserve(ips.size());
	for (const auto &ip : ips) {
		workers.emplace_back([&failures, &ready, &start, &set_name, ip]() {
			unsigned char addr[4];
			if (inet_pton(AF_INET, ip.c_str(), addr) != 1) {
				failures.fetch_add(1);
				return;
			}
			ready.fetch_add(1);
			while (!start.load()) {
				std::this_thread::yield();
			}
			if (ipset_add(set_name.c_str(), addr, sizeof(addr), 60) < 0) {
				failures.fetch_add(1);
			}
		});
	}
	while (ready.load() != (int)ips.size()) {
		std::this_thread::yield();
	}
	start.store(true);
	for (auto &worker : workers) {
		worker.join();
	}

	int missing = 0;
	for (const auto &ip : ips) {
		std::string test_element = "ipset test " + set_name + " " + ip + " >/dev/null 2>&1";
		if (system(test_element.c_str()) != 0) {
			missing++;
		}
	}
	int destroy_result = system(destroy_set.c_str());

	EXPECT_EQ(failures.load(), 0);
	EXPECT_EQ(missing, 0);
	EXPECT_EQ(destroy_result, 0);
}
