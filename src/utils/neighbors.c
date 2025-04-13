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
#include <stdlib.h>
#include <unistd.h>

static int netlink_neighbor_fd;

int netlink_get_neighbors(int family,
						  int (*callback)(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6], void *arg),
						  void *arg)
{
	if (netlink_neighbor_fd <= 0) {
		netlink_neighbor_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
		if (netlink_neighbor_fd < 0) {
			errno = EINVAL;
			return -1;
		}
	}

	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	char buf[1024 * 16];
	struct iovec iov = {buf, sizeof(buf)};
	struct sockaddr_nl sa;
	struct msghdr msg;
	int len;
	int ret = 0;
	int send_count = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	nlh->nlmsg_type = RTM_GETNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = time(NULL);
	nlh->nlmsg_pid = getpid();

	ndm = NLMSG_DATA(nlh);
	ndm->ndm_family = family;

	while (1) {
		if (send_count > 5) {
			errno = ETIMEDOUT;
			return -1;
		}

		send_count++;
		if (send(netlink_neighbor_fd, buf, NLMSG_SPACE(sizeof(struct ndmsg)), 0) < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				struct timespec waiter;
				waiter.tv_sec = 0;
				waiter.tv_nsec = 500000;
				nanosleep(&waiter, NULL);
				continue;
			}

			close(netlink_neighbor_fd);
			netlink_neighbor_fd = -1;
			return -1;
		}

		break;
	}

	int is_received = 0;
	int recv_count = 0;
	while (1) {
		recv_count++;
		len = recvmsg(netlink_neighbor_fd, &msg, 0);
		if (len < 0) {
			if (recv_count > 5 && is_received == 0) {
				errno = ETIMEDOUT;
				return -1;
			}

			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				if (is_received) {
					break;
				}
				struct timespec waiter;
				waiter.tv_sec = 0;
				waiter.tv_nsec = 500000;
				nanosleep(&waiter, NULL);
				continue;
			}

			return -1;
		}

		if (ret != 0) {
			continue;
		}

		is_received = 1;
		uint32_t nlh_len = len;
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
			ndm = NLMSG_DATA(nlh);
			struct rtattr *rta = RTM_RTA(ndm);
			const uint8_t *mac = NULL;
			const uint8_t *net_addr = NULL;
			int net_addr_len = 0;
			unsigned int rta_len = RTM_PAYLOAD(nlh);

			if (rta_len > (sizeof(buf) - ((char *)rta - buf))) {
				continue;
			}

			for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
				if (rta->rta_type == NDA_DST) {
					if (ndm->ndm_family == AF_INET) {
						struct in_addr *addr = RTA_DATA(rta);
						if (IN_MULTICAST(ntohl(addr->s_addr))) {
							continue;
						}

						if (ntohl(addr->s_addr) == 0) {
							continue;
						}

						net_addr = (uint8_t *)&addr->s_addr;
						net_addr_len = IPV4_ADDR_LEN;
					} else if (ndm->ndm_family == AF_INET6) {
						struct in6_addr *addr = RTA_DATA(rta);
						if (IN6_IS_ADDR_MC_NODELOCAL(addr)) {
							continue;
						}
						if (IN6_IS_ADDR_MC_LINKLOCAL(addr)) {
							continue;
						}
						if (IN6_IS_ADDR_MC_SITELOCAL(addr)) {
							continue;
						}

						if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
							continue;
						}

						net_addr = addr->s6_addr;
						net_addr_len = IPV6_ADDR_LEN;
					}
				} else if (rta->rta_type == NDA_LLADDR) {
					mac = RTA_DATA(rta);
					if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
						continue;
					}
				}
			}

			if (net_addr != NULL && mac != NULL) {
				ret = callback(net_addr, net_addr_len, mac, arg);
				if (ret != 0) {
					break;
				}
			}
		}
	}

	return ret;
}