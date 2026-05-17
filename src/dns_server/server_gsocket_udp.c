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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "server_gsocket.h"

#include "dns_server.h"

#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <errno.h>
#include <netinet/ip.h>
#include <string.h>

static int _dns_server_gsocket_udp_recv_one(struct dns_server_conn_udp *udpconn)
{
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from = {0};
	socklen_t from_len = sizeof(from);
	struct sockaddr_storage local = {0};
	socklen_t local_len = sizeof(local);
	struct iovec iov = {.iov_base = inpacket, .iov_len = sizeof(inpacket)};
	char ctrlbuf[256];
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ctrlbuf,
		.msg_controllen = sizeof(ctrlbuf),
	};

	ssize_t len = gsocket_recvmsg(udpconn->head.gs, &msg, MSG_DONTWAIT);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return -2; /* no more data */
		}
		tlog(TLOG_DEBUG, "UDP recvmsg failed: %s", strerror(errno));
		return -1;
	}
	from_len = msg.msg_namelen;

	/* Extract local address from PKTINFO ancillary data */
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_PKTINFO) {
			const struct in_pktinfo *pi = (const struct in_pktinfo *)CMSG_DATA(cm);
			fill_sockaddr_by_ip((unsigned char *)&pi->ipi_addr.s_addr, sizeof(in_addr_t), 0, (struct sockaddr *)&local,
								&local_len);
		} else if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
			const struct in6_pktinfo *pi = (const struct in6_pktinfo *)CMSG_DATA(cm);
			fill_sockaddr_by_ip((unsigned char *)pi->ipi6_addr.s6_addr, sizeof(struct in6_addr), 0,
								(struct sockaddr *)&local, &local_len);
		}
	}

	return _dns_server_recv(&udpconn->head, inpacket, (int)len, &local, local_len, &from, from_len);
}

int _dns_server_gsocket_process_udp(struct dns_server_conn_udp *conn, struct gepoll_event *event, unsigned long now)
{
	(void)event;
	(void)now;
	int count = 0;
	while (count++ < 64) {
		int r = _dns_server_gsocket_udp_recv_one(conn);
		if (r == -2) {
			break; /* EAGAIN - no more packets */
		}
		if (r < 0 && r != RECV_ERROR_INVALID_PACKET) {
			break;
		}
	}
	return 0;
}
