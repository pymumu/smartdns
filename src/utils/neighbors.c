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
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int netlink_neighbor_fd;
static pthread_mutex_t netlink_neighbor_lock = PTHREAD_MUTEX_INITIALIZER;

int netlink_parse_neighbor(const struct nlmsghdr *nlh, const uint8_t **out_net_addr, int *out_net_addr_len,
						   const uint8_t **out_mac)
{
	struct ndmsg *ndm = NULL;
	if (nlh == NULL || out_net_addr == NULL || out_net_addr_len == NULL || out_mac == NULL ||
		nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ndm))) {
		return -1;
	}

	ndm = NLMSG_DATA(nlh);
	struct rtattr *rta = RTM_RTA(ndm);
	unsigned int rta_len = RTM_PAYLOAD(nlh);
	const uint8_t *mac = NULL;
	const uint8_t *net_addr = NULL;
	int net_addr_len = 0;

	if (nlh->nlmsg_type != RTM_NEWNEIGH) {
		return -1;
	}

	if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6) {
		return -1;
	}

	if (ndm->ndm_flags & NTF_PROXY) {
		return -1;
	}

	/* only trust lladdr from states where the kernel resolved or verified it */
	if ((ndm->ndm_state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT)) == 0) {
		return -1;
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
				if (IN6_IS_ADDR_MULTICAST(addr)) {
					continue;
				}

				if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
					continue;
				}

				net_addr = addr->s6_addr;
				net_addr_len = IPV6_ADDR_LEN;
			}
		} else if (rta->rta_type == NDA_LLADDR) {
			if (RTA_PAYLOAD(rta) < 6) {
				mac = NULL;
				continue;
			}

			mac = RTA_DATA(rta);
			if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
				mac = NULL;
				continue;
			}
		}
	}

	if (net_addr == NULL || mac == NULL) {
		return -1;
	}

	*out_net_addr = net_addr;
	*out_net_addr_len = net_addr_len;
	*out_mac = mac;

	return 0;
}

static int _netlink_neighbor_dump_once(int family,
									   int (*callback)(const uint8_t *net_addr, int net_addr_len,
													   const uint8_t mac[6], void *arg),
									   void *arg, int *dump_intr)
{
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	static uint32_t dump_seq_next = 1;
	char buf[1024 * 16];
	struct iovec iov = {buf, sizeof(buf)};
	struct sockaddr_nl sa;
	struct msghdr msg;
	uint32_t seq = 0;
	int len = 0;
	int ret = 0;
	int send_count = 0;
	int recv_count = 0;
	int dump_done = 0;

	memset(buf, 0, sizeof(buf));
	memset(&sa, 0, sizeof(sa));
	memset(&msg, 0, sizeof(msg));

	sa.nl_family = AF_NETLINK;
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	seq = dump_seq_next++;
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	nlh->nlmsg_type = RTM_GETNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;

	ndm = NLMSG_DATA(nlh);
	memset(ndm, 0, sizeof(struct ndmsg));
	ndm->ndm_family = family;

	while (1) {
		if (send_count > 5) {
			errno = ETIMEDOUT;
			return -1;
		}

		send_count++;
		if (send(netlink_neighbor_fd, buf, NLMSG_ALIGN(nlh->nlmsg_len), 0) < 0) {
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

	while (dump_done == 0) {
		recv_count++;
		len = recvmsg(netlink_neighbor_fd, &msg, 0);
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				if (*dump_intr) {
					/* a truncated batch may have swallowed NLMSG_DONE, the
					 * caller retries the whole dump anyway */
					break;
				}

				if (recv_count > 100) {
					errno = ETIMEDOUT;
					return -1;
				}

				struct timespec waiter;
				waiter.tv_sec = 0;
				waiter.tv_nsec = 500000;
				nanosleep(&waiter, NULL);
				continue;
			}

			return -1;
		}

		if (msg.msg_flags & MSG_TRUNC) {
			/* batch larger than our buffer, the rest of it was dropped */
			*dump_intr = 1;
			continue;
		}

		uint32_t nlh_len = len;
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
			if (nlh->nlmsg_seq != seq) {
				/* stale message left over from a previous dump */
				continue;
			}

			if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
				/* neighbor table changed during the dump, entries may be
				 * missing from this snapshot */
				*dump_intr = 1;
			}

			if (nlh->nlmsg_type == NLMSG_DONE) {
				dump_done = 1;
				break;
			}

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(nlh);
				errno = -err->error;
				return -1;
			}

			if (nlh->nlmsg_type != RTM_NEWNEIGH) {
				continue;
			}

			if (ret != 0) {
				/* answer found, keep draining until NLMSG_DONE */
				continue;
			}

			const uint8_t *mac = NULL;
			const uint8_t *net_addr = NULL;
			int net_addr_len = 0;

			if (netlink_parse_neighbor(nlh, &net_addr, &net_addr_len, &mac) != 0) {
				continue;
			}

			ret = callback(net_addr, net_addr_len, mac, arg);
		}
	}

	return ret;
}

int netlink_get_neighbors(int family, const uint8_t *target_ip, int target_ip_len,
						  int (*callback)(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6], void *arg),
						  void *arg)
{
	int ret = 0;

	/* the kernel ignores an NDA_DST filter on dump requests, the target is
	 * matched by the caller in its callback */
	(void)target_ip;
	(void)target_ip_len;

	pthread_mutex_lock(&netlink_neighbor_lock);
	if (netlink_neighbor_fd <= 0) {
		netlink_neighbor_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
		if (netlink_neighbor_fd < 0) {
			errno = EINVAL;
			ret = -1;
			goto out;
		}
	}

	for (int i = 0; i < 3; i++) {
		int dump_intr = 0;

		ret = _netlink_neighbor_dump_once(family, callback, arg, &dump_intr);
		if (ret != 0) {
			goto out;
		}

		if (dump_intr == 0) {
			break;
		}

		/* inconsistent snapshot, retry the dump */
	}

out:
	pthread_mutex_unlock(&netlink_neighbor_lock);
	return ret;
}
