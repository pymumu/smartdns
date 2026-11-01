/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
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


#include "smartdns/lib/nftset.h"
#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <cstdio>
#include <string>
#include <unistd.h>

/*
 * These tests talk to the kernel's nftables. They need CAP_NET_ADMIN and are skipped otherwise;
 * run them in a private network namespace: unshare -Urn ./test.bin --gtest_filter='NftSet.*'
 */
class NftSet : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		system("nft delete table inet smartdns_test >/dev/null 2>&1");
		if (system("nft add table inet smartdns_test >/dev/null 2>&1") != 0 ||
			system("nft add set inet smartdns_test s '{ type ipv4_addr; flags interval, timeout; }' >/dev/null 2>&1") !=
				0) {
			GTEST_SKIP() << "nftables not usable (needs CAP_NET_ADMIN, e.g. unshare -Urn)";
		}
	}

	void TearDown() override { system("nft delete table inet smartdns_test >/dev/null 2>&1"); }

	static std::string Elements()
	{
		std::string out;
		FILE *fp = popen("nft list set inet smartdns_test s 2>&1", "r");
		char line[512];
		while (fp && fgets(line, sizeof(line), fp)) {
			out += line;
		}
		if (fp) {
			pclose(fp);
		}
		return out;
	}

	static int Add(const char *ip, unsigned long timeout)
	{
		unsigned char addr[4];
		inet_pton(AF_INET, ip, addr);
		return nftset_add("inet", "smartdns_test", "s", addr, 4, timeout);
	}
};

TEST_F(NftSet, ReAddRefreshesTimeout)
{
	ASSERT_EQ(Add("10.0.0.4", 3), 0);
	sleep(2);
	ASSERT_EQ(Add("10.0.0.4", 3), 0);
	sleep(2);
	/* 4s after the first add: only alive if the second add refreshed the 3s timeout */
	EXPECT_NE(Elements().find("10.0.0.4"), std::string::npos) << Elements();
}

TEST_F(NftSet, LastByteOfOctetCanBeAdded)
{
	ASSERT_EQ(Add("10.0.0.255", 30), 0);
	EXPECT_NE(Elements().find("10.0.0.255"), std::string::npos) << Elements();
}

TEST_F(NftSet, ExpiryLeavesNoStrayRange)
{
	ASSERT_EQ(Add("10.0.0.4", 2), 0);
	sleep(3);
	ASSERT_EQ(Add("10.0.0.20", 30), 0);
	std::string elements = Elements();
	EXPECT_EQ(elements.find("10.0.0.4"), std::string::npos) << elements;
	EXPECT_EQ(elements.find("-"), std::string::npos) << elements;
	EXPECT_NE(elements.find("10.0.0.20"), std::string::npos) << elements;
}

TEST_F(NftSet, StaticRangeIsKept)
{
	ASSERT_EQ(system("nft add element inet smartdns_test s '{ 10.0.1.0/24 }'"), 0);
	ASSERT_EQ(Add("10.0.2.0", 2), 0);
	ASSERT_EQ(Add("10.0.0.254", 2), 0);
	/* covered by the static range: the refresh must not split or remove it */
	Add("10.0.1.5", 30);
	sleep(3);
	std::string elements = Elements();
	EXPECT_NE(elements.find("10.0.1.0/24"), std::string::npos) << elements;
	EXPECT_EQ(elements.find("10.0.2.0"), std::string::npos) << elements;
	EXPECT_EQ(elements.find("10.0.0.254"), std::string::npos) << elements;
	EXPECT_EQ(elements.find("10.0.1.5"), std::string::npos) << elements;
}
