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
#define _GNU_SOURCE

#include "smartdns/util.h"

#include "notify_event.h"
#include "ping_host.h"
#include "ping_icmp.h"
#include "ping_udp.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>

int _fast_ping_sendping_udp(struct ping_host_struct *ping_host)
{
	struct ping_dns_head dns_head;
	int len = 0;
	int flag = 0;
	int fd = -1;

	flag |= (0 << 15) & 0x8000;
	flag |= (2 << 11) & 0x7800;
	flag |= (0 << 10) & 0x0400;
	flag |= (0 << 9) & 0x0200;
	flag |= (0 << 8) & 0x0100;
	flag |= (0 << 7) & 0x0080;
	flag |= (0 << 0) & 0x000F;

	if (ping_host->type == FAST_PING_UDP) {
		fd = ping.fd_udp;
	} else if (ping_host->type == FAST_PING_UDP6) {
		fd = ping.fd_udp6;
	} else {
		return -1;
	}

	ping_host->seq++;
	memset(&dns_head, 0, sizeof(dns_head));
	dns_head.id = htons(ping_host->sid);
	dns_head.flag = flag;
	dns_head.qdcount = htons(1);
	dns_head.qd_name = 0;
	dns_head.q_qtype = htons(2); /* DNS_T_NS */
	dns_head.q_qclass = htons(1);

	gettimeofday(&ping_host->last, NULL);
	len = sendto(fd, &dns_head, sizeof(dns_head), 0, &ping_host->addr, ping_host->addr_len);
	if (len != sizeof(dns_head)) {
		int err = errno;
		if (errno == ENETUNREACH || errno == EINVAL || errno == EADDRNOTAVAIL || errno == EPERM || errno == EACCES) {
			goto errout;
		}
		char ping_host_name[PING_MAX_HOSTLEN];
		tlog(TLOG_ERROR, "sendto %s, id %d, %s",
			 get_host_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
			 ping_host->sid, strerror(err));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _fast_ping_create_udp_sock(FAST_PING_TYPE type)
{
	int fd = -1;
	struct ping_host_struct *udp_host = NULL;
	struct epoll_event event;
	const int val = 255;
	const int on = 1;
	const int ip_tos = (IPTOS_LOWDELAY | IPTOS_RELIABILITY);

	switch (type) {
	case FAST_PING_UDP:
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create udp socket failed, %s\n", strerror(errno));
			goto errout;
		}

		udp_host = &ping.udp_host;
		udp_host->type = FAST_PING_UDP;
		break;
	case FAST_PING_UDP6:
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create udp socket failed, %s\n", strerror(errno));
			goto errout;
		}

		udp_host = &ping.udp6_host;
		udp_host->type = FAST_PING_UDP6;
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
		break;
	default:
		return -1;
	}

	setsockopt(fd, SOL_IP, IP_TTL, &val, sizeof(val));
	setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = udp_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		goto errout;
	}

	udp_host->fd = fd;
	return fd;

errout:
	close(fd);
	return -1;
}

static int _fast_ping_create_udp(FAST_PING_TYPE type)
{
	int fd = -1;
	int *set_fd = NULL;

	pthread_mutex_lock(&ping.lock);
	switch (type) {
	case FAST_PING_UDP:
		set_fd = &ping.fd_udp;
		break;
	case FAST_PING_UDP6:
		set_fd = &ping.fd_udp6;
		break;
	default:
		goto errout;
		break;
	}

	if (*set_fd > 0) {
		goto out;
	}

	fd = _fast_ping_create_udp_sock(type);
	if (fd < 0) {
		goto errout;
	}

	*set_fd = fd;
out:
	pthread_mutex_unlock(&ping.lock);
	return *set_fd;
errout:
	if (fd > 0) {
		close(fd);
	}
	pthread_mutex_unlock(&ping.lock);
	return -1;
}

int _fast_ping_get_addr_by_dns(const char *ip_str, int port, struct addrinfo **out_gai, FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	FAST_PING_TYPE ping_type = 0;
	int sockproto = 0;
	char port_str[MAX_IP_LEN];
	int domain = -1;
	char *service = NULL;

	if (port <= 0) {
		port = 53;
	}

	domain = _fast_ping_getdomain(ip_str);
	if (domain < 0) {
		goto errout;
	}

	switch (domain) {
	case AF_INET:
		ping_type = FAST_PING_UDP;
		break;
	case AF_INET6:
		ping_type = FAST_PING_UDP6;
		break;
	default:
		goto errout;
		break;
	}

	sockproto = 0;
	socktype = SOCK_DGRAM;
	snprintf(port_str, MAX_IP_LEN, "%d", port);
	service = port_str;

	if (_fast_ping_create_udp(ping_type) < 0) {
		goto errout;
	}

	gai = _fast_ping_getaddr(ip_str, service, socktype, sockproto);
	if (gai == NULL) {
		goto errout;
	}

	*out_gai = gai;
	*out_ping_type = ping_type;

	return 0;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}
	return -1;
}

int _fast_ping_process_udp(struct ping_host_struct *ping_host, struct timeval *now)
{
	ssize_t len = 0;
	u_char inpacket[ICMP_INPACKET_SIZE];
	struct sockaddr_storage from;
	struct ping_host_struct *recv_ping_host = NULL;
	struct ping_dns_head *dns_head = NULL;
	socklen_t from_len = sizeof(from);
	uint32_t addrkey = 0;
	struct timeval tvresult = *now;
	struct timeval *tvsend = NULL;
	unsigned int sid = 0;
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	struct cmsghdr *cmsg = NULL;
	int ttl = 0;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)inpacket;
	iov.iov_len = sizeof(inpacket);
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ans_data;
	msg.msg_controllen = sizeof(ans_data);

	len = recvmsg(ping_host->fd, &msg, MSG_DONTWAIT);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		goto errout;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				int *ttlPtr = (int *)CMSG_DATA(cmsg);
				ttl = *ttlPtr;
			}
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				int *ttlPtr = (int *)CMSG_DATA(cmsg);
				ttl = *ttlPtr;
			}
		}
	}

	from_len = msg.msg_namelen;
	dns_head = (struct ping_dns_head *)inpacket;
	if (len < (ssize_t)sizeof(*dns_head)) {
		goto errout;
	}

	sid = ntohs(dns_head->id);
	addrkey = _fast_ping_hash_key(sid, (struct sockaddr *)&from);
	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_possible(ping.addrmap, recv_ping_host, addr_node, addrkey)
	{
		if (_fast_ping_sockaddr_ip_cmp(&recv_ping_host->addr, recv_ping_host->addr_len, (struct sockaddr *)&from,
									   from_len) == 0 &&
			recv_ping_host->sid == sid) {
			_fast_ping_host_get(recv_ping_host);
			break;
		}
	}

	pthread_mutex_unlock(&ping.map_lock);

	if (recv_ping_host == NULL) {
		return -1;
	}

	recv_ping_host->ttl = ttl;
	tvsend = &recv_ping_host->last;
	tv_sub(&tvresult, tvsend);
	if (recv_ping_host->ping_callback) {
		_fast_ping_send_notify_event(recv_ping_host, PING_RESULT_RESPONSE, recv_ping_host->seq, recv_ping_host->ttl,
									 &tvresult);
	}

	recv_ping_host->send = 0;

	if (recv_ping_host->count == 1) {
		_fast_ping_host_remove(recv_ping_host);
	}

	_fast_ping_host_put(recv_ping_host);

	return 0;
errout:
	return -1;
}

void _fast_ping_close_udp(void)
{
	if (ping.fd_udp > 0) {
		epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping.fd_udp, NULL);
		close(ping.fd_udp);
		ping.fd_udp = -1;
	}

	if (ping.fd_udp6 > 0) {
		epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping.fd_udp6, NULL);
		close(ping.fd_udp6);
		ping.fd_udp6 = -1;
	}
}
