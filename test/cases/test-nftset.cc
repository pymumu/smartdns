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

#include "gtest/gtest.h"
#include "smartdns/dns_conf.h"
#include "smartdns/lib/nftset.h"

#include <arpa/inet.h>
#include <climits>
#include <cstdint>
#include <cstring>
#include <endian.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

extern "C" {
typedef int (*nftset_request_callback_t)(const void *request, int request_len, void *reply, int reply_len);

void nftset_set_request_callback_for_test(nftset_request_callback_t callback);

int dns_server_get_nftset_timeout_for_test(const struct dns_conf_group *conf, int timeout_value);
}

namespace {

constexpr int kPayloadMax = 2048;

struct NlmsgRequest {
	struct nlmsghdr header;
	struct nfgenmsg message;
};

struct rtattr *AddAttribute(struct nlmsghdr *header, int max_length, uint16_t type, const void *data, uint16_t length)
{
	uint16_t attribute_length = RTA_LENGTH(length);
	int new_length = NLMSG_ALIGN(header->nlmsg_len) + RTA_ALIGN(attribute_length);
	if (new_length > max_length) {
		return nullptr;
	}

	auto *attribute = reinterpret_cast<struct rtattr *>(
		reinterpret_cast<uint8_t *>(header) + NLMSG_ALIGN(header->nlmsg_len));
	attribute->rta_type = type;
	attribute->rta_len = attribute_length;
	if (data != nullptr && length > 0) {
		std::memcpy(RTA_DATA(attribute), data, length);
	}
	header->nlmsg_len = new_length;
	return attribute;
}

const struct rtattr *FindAttribute(const void *data, int length, uint16_t type)
{
	auto *attribute = static_cast<const struct rtattr *>(data);
	while (RTA_OK(attribute, length)) {
		if ((attribute->rta_type & NLA_TYPE_MASK) == type) {
			return attribute;
		}
		attribute = RTA_NEXT(attribute, length);
	}
	return nullptr;
}

const struct rtattr *FindElementAttribute(const struct nlmsghdr *header, uint16_t type)
{
	int list_length = NLMSG_PAYLOAD(header, sizeof(struct nfgenmsg));
	auto *list = reinterpret_cast<const struct rtattr *>(
		reinterpret_cast<const uint8_t *>(NLMSG_DATA(header)) + NLMSG_ALIGN(sizeof(struct nfgenmsg)));
	auto *elements = FindAttribute(list, list_length, NFTA_SET_ELEM_LIST_ELEMENTS);
	if (elements == nullptr) {
		return nullptr;
	}

	int elements_length = RTA_PAYLOAD(elements);
	auto *element = FindAttribute(RTA_DATA(elements), elements_length, NFTA_LIST_ELEM);
	if (element == nullptr) {
		return nullptr;
	}

	int element_length = RTA_PAYLOAD(element);
	return FindAttribute(RTA_DATA(element), element_length, type);
}

uint64_t ReadBigEndian64(const struct rtattr *attribute)
{
	uint64_t value = 0;
	std::memcpy(&value, RTA_DATA(attribute), sizeof(value));
	return be64toh(value);
}

int BuildSetReply(void *reply, int reply_length, bool timeout_set)
{
	if (reply == nullptr || reply_length < kPayloadMax) {
		return -1;
	}

	std::memset(reply, 0, reply_length);
	auto *message = static_cast<NlmsgRequest *>(reply);
	message->header.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	message->header.nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSET;
	uint32_t flags = htonl(timeout_set ? NFT_SET_TIMEOUT : 0);
	AddAttribute(&message->header, reply_length, NFTA_SET_FLAGS, &flags, sizeof(flags));
	return 0;
}

int BuildElementReply(void *reply, int reply_length)
{
	if (reply == nullptr || reply_length < static_cast<int>(sizeof(NlmsgRequest))) {
		return -1;
	}

	std::memset(reply, 0, reply_length);
	auto *message = static_cast<NlmsgRequest *>(reply);
	message->header.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	message->header.nlmsg_type = NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWSETELEM;
	return 0;
}

class FakeNftKernel {
public:
	bool timeout_set = true;
	bool exists = false;
	int get_set_count = 0;
	int get_element_count = 0;
	int delete_element_count = 0;
	int new_element_count = 0;
	uint64_t last_timeout_ms = 0;

	int Request(const void *request_data, int request_length, void *reply, int reply_length)
	{
		int remaining = request_length;
		auto *header = static_cast<const struct nlmsghdr *>(request_data);
		while (NLMSG_OK(header, remaining)) {
			switch (header->nlmsg_type & 0xff) {
			case NFT_MSG_GETSET:
				get_set_count++;
				return BuildSetReply(reply, reply_length, timeout_set);
			case NFT_MSG_GETSETELEM:
				get_element_count++;
				if (!exists) {
					errno = ENOENT;
					return -1;
				}
				return BuildElementReply(reply, reply_length);
			case NFT_MSG_DELSETELEM:
				delete_element_count++;
				exists = false;
				break;
			case NFT_MSG_NEWSETELEM: {
				new_element_count++;
				exists = true;
				auto *timeout = FindElementAttribute(header, NFTA_SET_ELEM_TIMEOUT);
				last_timeout_ms = timeout == nullptr ? 0 : ReadBigEndian64(timeout);
				break;
			}
			default:
				break;
			}
			header = NLMSG_NEXT(header, remaining);
		}
		return 0;
	}
};

FakeNftKernel *active_kernel = nullptr;

int FakeRequest(const void *request, int request_length, void *reply, int reply_length)
{
	return active_kernel->Request(request, request_length, reply, reply_length);
}

class NftsetTest : public testing::Test {
protected:
	void SetUp() override
	{
		active_kernel = &kernel;
		nftset_set_request_callback_for_test(FakeRequest);
	}

	void TearDown() override
	{
		nftset_set_request_callback_for_test(nullptr);
		active_kernel = nullptr;
	}

	FakeNftKernel kernel;
	const unsigned char ipv4[4] = {192, 0, 2, 1};
};

TEST_F(NftsetTest, MissingTimedElementUsesExistingAddPath)
{
	ASSERT_EQ(nftset_add("inet", "filter", "policy4", ipv4, sizeof(ipv4), 300), 0);
	EXPECT_TRUE(kernel.exists);
	EXPECT_EQ(kernel.get_set_count, 1);
	EXPECT_EQ(kernel.get_element_count, 1);
	EXPECT_EQ(kernel.delete_element_count, 0);
	EXPECT_EQ(kernel.new_element_count, 1);
	EXPECT_EQ(kernel.last_timeout_ms, 300000U);
}

TEST_F(NftsetTest, ExistingTimedElementIsDeletedAndAddedAgain)
{
	kernel.exists = true;
	ASSERT_EQ(nftset_add("inet", "filter", "policy4", ipv4, sizeof(ipv4), 300), 0);
	EXPECT_TRUE(kernel.exists);
	EXPECT_EQ(kernel.delete_element_count, 1);
	EXPECT_EQ(kernel.new_element_count, 1);
	EXPECT_EQ(kernel.last_timeout_ms, 300000U);
}

TEST_F(NftsetTest, ExistingPermanentElementSkipsSetMetadataQueryWhenTimeoutIsDisabled)
{
	kernel.exists = true;
	ASSERT_EQ(nftset_add("inet", "filter", "permanent", ipv4, sizeof(ipv4), 0), 0);
	EXPECT_EQ(kernel.get_element_count, 1);
	EXPECT_EQ(kernel.get_set_count, 0);
	EXPECT_EQ(kernel.delete_element_count, 0);
	EXPECT_EQ(kernel.new_element_count, 0);
}

TEST_F(NftsetTest, ExistingPermanentElementRemainsUntouched)
{
	kernel.timeout_set = false;
	kernel.exists = true;
	ASSERT_EQ(nftset_add("inet", "filter", "permanent", ipv4, sizeof(ipv4), 300), 0);
	EXPECT_TRUE(kernel.exists);
	EXPECT_EQ(kernel.delete_element_count, 0);
	EXPECT_EQ(kernel.new_element_count, 0);
}

TEST(NftsetDnsPath, ServeExpiredLifetimeIsAddedOnlyToTimedNftset)
{
	struct dns_conf_group conf = {};
	conf.ipset_nftset.nftset_timeout_enable = 1;

	EXPECT_EQ(dns_server_get_nftset_timeout_for_test(&conf, 1800), 1800);

	conf.dns_serve_expired = 1;
	conf.dns_serve_expired_ttl = 86400;
	EXPECT_EQ(dns_server_get_nftset_timeout_for_test(&conf, 1800), 88200);

	conf.dns_serve_expired_ttl = INT_MAX;
	EXPECT_EQ(dns_server_get_nftset_timeout_for_test(&conf, 1800), INT_MAX);

	conf.ipset_nftset.nftset_timeout_enable = 0;
	EXPECT_EQ(dns_server_get_nftset_timeout_for_test(&conf, 1800), 0);
}

} // namespace
