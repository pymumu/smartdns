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

#include "ping_icmp.h"
#include "ping_icmp6.h"

#include <errno.h>
#include <linux/filter.h>
#include <string.h>
#include <sys/epoll.h>

void _fast_ping_install_filter_v6(int sock)
{
	struct icmp6_filter icmp6_filter;
	ICMP6_FILTER_SETBLOCKALL(&icmp6_filter);
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &icmp6_filter);
	setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &icmp6_filter, sizeof(struct icmp6_filter));

	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 4),                       /* Load icmp echo ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1),           /* Ours? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),                              /* Yes, it passes. */
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),                       /* Load icmp type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP6_ECHO_REPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),                              /* No. It passes. This must not happen. */
		BPF_STMT(BPF_RET | BPF_K, 0),                                /* Echo with wrong ident. Reject. */
	};
	static struct sock_fprog filter = {sizeof insns / sizeof(insns[0]), insns};

	if (once) {
		return;
	}
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(ping.ident), 0, 1);

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
		tlog(TLOG_WARN, "WARNING: failed to install socket filter\n");
	}
}

int _fast_ping_sendping_v6(struct ping_host_struct *ping_host)
{
	struct fast_ping_packet *packet = &ping_host->packet;
	struct icmp6_hdr *icmp6 = &packet->icmp6;
	int len = 0;

	if (_fast_ping_icmp_create_socket(ping_host) < 0) {
		goto errout;
	}

	if (ping.fd_icmp6 <= 0) {
		errno = EADDRNOTAVAIL;
		goto errout;
	}

	ping_host->seq++;
	memset(icmp6, 0, sizeof(*icmp6));
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_id = ping.ident;
	icmp6->icmp6_seq = htons(ping_host->seq);

	gettimeofday(&packet->msg.tv, NULL);
	gettimeofday(&ping_host->last, NULL);
	packet->msg.sid = ping_host->sid;
	packet->msg.seq = ping_host->seq;
	icmp6->icmp6_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping.fd_icmp6, &ping_host->packet, sizeof(struct fast_ping_packet), 0, &ping_host->addr,
				 ping_host->addr_len);
	if (len != sizeof(struct fast_ping_packet)) {
		int err = errno;
		switch (err) {
		case ENETUNREACH:
		case EINVAL:
		case EADDRNOTAVAIL:
		case EHOSTUNREACH:
		case ENOBUFS:
		case EACCES:
		case EPERM:
		case EAFNOSUPPORT:
			goto errout;
		default:
			break;
		}

		if (is_private_addr_sockaddr(&ping_host->addr, ping_host->addr_len)) {
			goto errout;
		}

		char ping_host_name[PING_MAX_HOSTLEN];
		tlog(TLOG_WARN, "sendto %s, id %d, %s",
			 get_host_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
			 ping_host->sid, strerror(err));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

struct fast_ping_packet *_fast_ping_icmp6_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
												 u_char *packet_data, int data_len)
{
	int icmp_len = 0;
	struct fast_ping_packet *packet = (struct fast_ping_packet *)packet_data;
	struct icmp6_hdr *icmp6 = &packet->icmp6;
	struct cmsghdr *c = NULL;
	int hops = 0;

	if (data_len < (int)sizeof(struct icmp6_hdr)) {
		tlog(TLOG_DEBUG, "ping package length is invalid, %d, %d", data_len, (int)sizeof(struct fast_ping_packet));
		return NULL;
	}

	for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level != IPPROTO_IPV6) {
			continue;
		}
		switch (c->cmsg_type) {
		case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
		case IPV6_2292HOPLIMIT:
#endif
			if (c->cmsg_len < CMSG_LEN(sizeof(int))) {
				continue;
			}
			memcpy(&hops, CMSG_DATA(c), sizeof(hops));
			break;
		default:
			break;
		}
	}

	packet->ttl = hops;
	if (icmp6->icmp6_type != ICMP6_ECHO_REPLY) {
		errno = ENETUNREACH;
		return NULL;
	}

	icmp_len = data_len;
	if (icmp_len < 16) {
		tlog(TLOG_ERROR, "length is invalid, %d", icmp_len);
		return NULL;
	}

	if (ping.no_unprivileged_ping) {
		if (icmp6->icmp6_id != ping.ident) {
			tlog(TLOG_ERROR, "ident failed, %d:%d", icmp6->icmp6_id, ping.ident);
			return NULL;
		}
	}

	return packet;
}
