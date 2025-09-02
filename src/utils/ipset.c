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

#include "smartdns/util.h"

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define NFNL_SUBSYS_IPSET 6

#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_TIMEOUT 6
#define IPSET_ADD 9
#define IPSET_DEL 10
#define IPSET_MAXNAMELEN 32
#define IPSET_PROTOCOL 6

#ifndef NFNETLINK_V0
#define NFNETLINK_V0 0
#endif

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif

#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER (1 << 14)
#endif

#define NETLINK_ALIGN(len) (((len) + 3) & ~(3))

#define BUFF_SZ 1024

struct ipset_netlink_attr {
	unsigned short len;
	unsigned short type;
};

struct ipset_netlink_msg {
	unsigned char family;
	unsigned char version;
	__be16 res_id;
};

static int ipset_fd;

static inline void _ipset_add_attr(struct nlmsghdr *netlink_head, uint16_t type, size_t len, const void *data)
{
	struct ipset_netlink_attr *attr = (void *)netlink_head + NETLINK_ALIGN(netlink_head->nlmsg_len);
	uint16_t payload_len = NETLINK_ALIGN(sizeof(struct ipset_netlink_attr)) + len;
	attr->type = type;
	attr->len = payload_len;
	memcpy((void *)attr + NETLINK_ALIGN(sizeof(struct ipset_netlink_attr)), data, len);
	netlink_head->nlmsg_len += NETLINK_ALIGN(payload_len);
}

static int _ipset_socket_init(void)
{
	if (ipset_fd > 0) {
		return 0;
	}

	ipset_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);

	if (ipset_fd < 0) {
		return -1;
	}

	return 0;
}

static int _ipset_operate(const char *ipset_name, const unsigned char addr[], int addr_len, unsigned long timeout,
						  int operate)
{
	struct nlmsghdr *netlink_head = NULL;
	struct ipset_netlink_msg *netlink_msg = NULL;
	struct ipset_netlink_attr *nested[3];
	char buffer[BUFF_SZ];
	uint8_t proto = 0;
	ssize_t rc = 0;
	int af = 0;
	static const struct sockaddr_nl snl = {.nl_family = AF_NETLINK};
	uint32_t expire = 0;

	if (addr_len != IPV4_ADDR_LEN && addr_len != IPV6_ADDR_LEN) {
		errno = EINVAL;
		return -1;
	}

	if (addr_len == IPV4_ADDR_LEN) {
		af = AF_INET;
	} else if (addr_len == IPV6_ADDR_LEN) {
		af = AF_INET6;
	} else {
		errno = EINVAL;
		return -1;
	}

	if (_ipset_socket_init() != 0) {
		return -1;
	}

	if (strlen(ipset_name) >= IPSET_MAXNAMELEN) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memset(buffer, 0, BUFF_SZ);

	netlink_head = (struct nlmsghdr *)buffer;
	netlink_head->nlmsg_len = NETLINK_ALIGN(sizeof(struct nlmsghdr));
	netlink_head->nlmsg_type = operate | (NFNL_SUBSYS_IPSET << 8);
	netlink_head->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;

	netlink_msg = (struct ipset_netlink_msg *)(buffer + netlink_head->nlmsg_len);
	netlink_head->nlmsg_len += NETLINK_ALIGN(sizeof(struct ipset_netlink_msg));
	netlink_msg->family = af;
	netlink_msg->version = NFNETLINK_V0;
	netlink_msg->res_id = htons(NFNL_SUBSYS_IPSET);

	proto = IPSET_PROTOCOL;
	_ipset_add_attr(netlink_head, IPSET_ATTR_PROTOCOL, sizeof(proto), &proto);
	_ipset_add_attr(netlink_head, IPSET_ATTR_SETNAME, strlen(ipset_name) + 1, ipset_name);

	nested[0] = (struct ipset_netlink_attr *)(buffer + NETLINK_ALIGN(netlink_head->nlmsg_len));
	netlink_head->nlmsg_len += NETLINK_ALIGN(sizeof(struct ipset_netlink_attr));
	nested[0]->type = NLA_F_NESTED | IPSET_ATTR_DATA;
	nested[1] = (struct ipset_netlink_attr *)(buffer + NETLINK_ALIGN(netlink_head->nlmsg_len));
	netlink_head->nlmsg_len += NETLINK_ALIGN(sizeof(struct ipset_netlink_attr));
	nested[1]->type = NLA_F_NESTED | IPSET_ATTR_IP;

	_ipset_add_attr(netlink_head,
					(af == AF_INET ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER, addr_len,
					addr);
	nested[1]->len = (void *)buffer + NETLINK_ALIGN(netlink_head->nlmsg_len) - (void *)nested[1];

	if (timeout > 0) {
		expire = htonl(timeout);
		_ipset_add_attr(netlink_head, IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER, sizeof(expire), &expire);
	}

	nested[0]->len = (void *)buffer + NETLINK_ALIGN(netlink_head->nlmsg_len) - (void *)nested[0];

	for (;;) {
		rc = sendto(ipset_fd, buffer, netlink_head->nlmsg_len, 0, (const struct sockaddr *)&snl, sizeof(snl));
		if (rc >= 0) {
			break;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			struct timespec waiter;
			waiter.tv_sec = 0;
			waiter.tv_nsec = 10000;
			nanosleep(&waiter, NULL);
			continue;
		}
	}

	return rc;
}

int ipset_add(const char *ipset_name, const unsigned char addr[], int addr_len, unsigned long timeout)
{
	return _ipset_operate(ipset_name, addr, addr_len, timeout, IPSET_ADD);
}

int ipset_del(const char *ipset_name, const unsigned char addr[], int addr_len)
{
	return _ipset_operate(ipset_name, addr, addr_len, 0, IPSET_DEL);
}