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

#include <arpa/inet.h>
#include <cstring>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "gtest/gtest.h"
#include "smartdns/util.h"

namespace {

int BuildIpv4Neighbor(uint8_t *buffer, size_t buffer_size, unsigned short state, const uint8_t *mac, size_t mac_len)
{
	if (buffer_size < NLMSG_SPACE(sizeof(struct ndmsg)) + RTA_SPACE(4) + RTA_SPACE(mac_len)) {
		return -1;
	}

	std::memset(buffer, 0, buffer_size);
	auto *nlh = reinterpret_cast<struct nlmsghdr *>(buffer);
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	nlh->nlmsg_type = RTM_NEWNEIGH;
	auto *ndm = reinterpret_cast<struct ndmsg *>(NLMSG_DATA(nlh));
	ndm->ndm_family = AF_INET;
	ndm->ndm_state = state;

	auto *rta = reinterpret_cast<struct rtattr *>(buffer + NLMSG_ALIGN(nlh->nlmsg_len));
	const uint8_t address[] = {192, 0, 2, 1};
	rta->rta_type = NDA_DST;
	rta->rta_len = RTA_LENGTH(sizeof(address));
	std::memcpy(RTA_DATA(rta), address, sizeof(address));
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	rta = reinterpret_cast<struct rtattr *>(buffer + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = NDA_LLADDR;
	rta->rta_len = RTA_LENGTH(mac_len);
	std::memcpy(RTA_DATA(rta), mac, mac_len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
	return nlh->nlmsg_len;
}

} // namespace

TEST(Neighbors, ParseNeighborAcceptsVerifiedNonZeroMac)
{
	uint8_t message[256];
	const uint8_t mac[] = {1, 2, 3, 4, 5, 6};
	ASSERT_GT(BuildIpv4Neighbor(message, sizeof(message), NUD_REACHABLE, mac, sizeof(mac)), 0);

	const uint8_t *address = nullptr;
	const uint8_t *parsed_mac = nullptr;
	int address_len = 0;
	ASSERT_EQ(netlink_parse_neighbor(reinterpret_cast<struct nlmsghdr *>(message), &address, &address_len, &parsed_mac), 0);
	ASSERT_EQ(address_len, 4);
	EXPECT_EQ(std::memcmp(address, "\xC0\x00\x02\x01", 4), 0);
	EXPECT_EQ(std::memcmp(parsed_mac, mac, sizeof(mac)), 0);
}

TEST(Neighbors, ParseNeighborRejectsZeroOrShortMac)
{
	uint8_t message[256];
	const uint8_t zero_mac[] = {0, 0, 0, 0, 0, 0};
	ASSERT_GT(BuildIpv4Neighbor(message, sizeof(message), NUD_STALE, zero_mac, sizeof(zero_mac)), 0);
	const uint8_t *address = nullptr;
	const uint8_t *mac = nullptr;
	int address_len = 0;
	EXPECT_NE(netlink_parse_neighbor(reinterpret_cast<struct nlmsghdr *>(message), &address, &address_len, &mac), 0);

	const uint8_t short_mac[] = {1, 2, 3, 4, 5};
	ASSERT_GT(BuildIpv4Neighbor(message, sizeof(message), NUD_STALE, short_mac, sizeof(short_mac)), 0);
	EXPECT_NE(netlink_parse_neighbor(reinterpret_cast<struct nlmsghdr *>(message), &address, &address_len, &mac), 0);
}

TEST(Neighbors, ParseNeighborRejectsUnverifiedState)
{
	uint8_t message[256];
	const uint8_t mac[] = {1, 2, 3, 4, 5, 6};
	ASSERT_GT(BuildIpv4Neighbor(message, sizeof(message), NUD_INCOMPLETE, mac, sizeof(mac)), 0);

	const uint8_t *address = nullptr;
	const uint8_t *parsed_mac = nullptr;
	int address_len = 0;
	EXPECT_NE(netlink_parse_neighbor(reinterpret_cast<struct nlmsghdr *>(message), &address, &address_len, &parsed_mac), 0);
}
