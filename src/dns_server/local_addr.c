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

#include "local_addr.h"
#include "dns_server.h"

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

static void _dns_server_local_addr_cache_add(unsigned char *netaddr, int netaddr_len, int prefix_len)
{
	prefix_t prefix;
	struct local_addr_cache_item *addr_cache_item = NULL;
	radix_node_t *node = NULL;

	if (prefix_from_blob(netaddr, netaddr_len, prefix_len, &prefix) == NULL) {
		return;
	}

	node = radix_lookup(server.local_addr_cache.addr, &prefix);
	if (node == NULL) {
		goto errout;
	}

	if (node->data == NULL) {
		addr_cache_item = malloc(sizeof(struct local_addr_cache_item));
		if (addr_cache_item == NULL) {
			return;
		}
		memset(addr_cache_item, 0, sizeof(struct local_addr_cache_item));
	} else {
		addr_cache_item = node->data;
	}

	addr_cache_item->ip_addr_len = netaddr_len;
	memcpy(addr_cache_item->ip_addr, netaddr, netaddr_len);
	addr_cache_item->mask_len = prefix_len;
	node->data = addr_cache_item;

	return;
errout:
	if (addr_cache_item) {
		free(addr_cache_item);
	}

	return;
}

static void _dns_server_local_addr_cache_del(unsigned char *netaddr, int netaddr_len, int prefix_len)
{
	radix_node_t *node = NULL;
	prefix_t prefix;

	if (prefix_from_blob(netaddr, netaddr_len, prefix_len, &prefix) == NULL) {
		return;
	}

	node = radix_search_exact(server.local_addr_cache.addr, &prefix);
	if (node == NULL) {
		return;
	}

	if (node->data != NULL) {
		free(node->data);
	}

	node->data = NULL;
	radix_remove(server.local_addr_cache.addr, node);
}

void _dns_server_process_local_addr_cache(int fd_netlink, struct epoll_event *event, unsigned long now)
{
	char buffer[1024 * 8];
	struct iovec iov = {buffer, sizeof(buffer)};
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (1) {
		ssize_t len = recvmsg(fd_netlink, &msg, 0);
		if (len == -1) {
			break;
		}

		for (nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_DONE) {
				break;
			}

			if (nh->nlmsg_type == NLMSG_ERROR) {
				break;
			}

			if (nh->nlmsg_type != RTM_NEWADDR && nh->nlmsg_type != RTM_DELADDR) {
				continue;
			}

			struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
			struct rtattr *rth = IFA_RTA(ifa);
			int rtl = IFA_PAYLOAD(nh);

			while (rtl && RTA_OK(rth, rtl)) {
				if (rth->rta_type == IFA_ADDRESS) {
					unsigned char *netaddr = RTA_DATA(rth);
					int netaddr_len = 0;

					if (ifa->ifa_family == AF_INET) {
						netaddr_len = 4;
					} else if (ifa->ifa_family == AF_INET6) {
						netaddr_len = 16;
					} else {
						continue;
					}

					if (nh->nlmsg_type == RTM_NEWADDR) {
						_dns_server_local_addr_cache_add(netaddr, netaddr_len, netaddr_len * 8);
						_dns_server_local_addr_cache_add(netaddr, netaddr_len, ifa->ifa_prefixlen);
					} else {
						_dns_server_local_addr_cache_del(netaddr, netaddr_len, netaddr_len * 8);
						_dns_server_local_addr_cache_del(netaddr, netaddr_len, ifa->ifa_prefixlen);
					}
				}
				rth = RTA_NEXT(rth, rtl);
			}
		}
	}
}

static void _dns_server_local_addr_cache_item_free(radix_node_t *node, void *cbctx)
{
	struct local_addr_cache_item *cache_item = NULL;
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	cache_item = node->data;
	free(cache_item);
	node->data = NULL;
}

int _dns_server_local_addr_cache_destroy(void)
{
	if (server.local_addr_cache.addr) {
		Destroy_Radix(server.local_addr_cache.addr, _dns_server_local_addr_cache_item_free, NULL);
		server.local_addr_cache.addr = NULL;
	}

	if (server.local_addr_cache.fd_netlink > 0) {
		close(server.local_addr_cache.fd_netlink);
		server.local_addr_cache.fd_netlink = -1;
	}

	return 0;
}

int _dns_server_local_addr_cache_init(void)
{
	int fd = 0;
	struct sockaddr_nl sa;

	server.local_addr_cache.fd_netlink = -1;
	server.local_addr_cache.addr = NULL;

	if (dns_conf.local_ptr_enable == 0) {
		return 0;
	}

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		tlog(TLOG_WARN, "create netlink socket failed, %s", strerror(errno));
		goto errout;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_IFADDR;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		tlog(TLOG_WARN, "bind netlink socket failed, %s", strerror(errno));
		goto errout;
	}

	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLERR;
	event.data.fd = fd;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "set eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	server.local_addr_cache.fd_netlink = fd;
	server.local_addr_cache.addr = New_Radix();

	struct {
		struct nlmsghdr nh;
		struct rtgenmsg gen;
	} request;

	memset(&request, 0, sizeof(request));
	request.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	request.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nh.nlmsg_type = RTM_GETADDR;
	request.gen.rtgen_family = AF_UNSPEC;

	if (send(fd, &request, request.nh.nlmsg_len, 0) < 0) {
		tlog(TLOG_WARN, "send netlink request failed, %s", strerror(errno));
		goto errout;
	}

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}
