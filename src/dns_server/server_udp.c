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

#include "server_udp.h"
#include "connection.h"
#include "dns_server.h"
#include "server_socket.h"

#include <errno.h>
#include <linux/in.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

int _dns_server_reply_udp(struct dns_request *request, struct dns_server_conn_udp *udpserver, unsigned char *inpacket,
						  int inpacket_len)
{
	int send_len = 0;
	struct iovec iovec[1];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char msg_control[64];

	if (atomic_read(&server.run) == 0 || inpacket == NULL || inpacket_len <= 0) {
		return -1;
	}

	iovec[0].iov_base = inpacket;
	iovec[0].iov_len = inpacket_len;
	memset(msg_control, 0, sizeof(msg_control));
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = msg_control;
	msg.msg_controllen = sizeof(msg_control);
	msg.msg_flags = 0;
	msg.msg_name = &request->addr;
	msg.msg_namelen = request->addr_len;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (request->localaddr.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)&request->localaddr;
		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

		struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
		memset(pktinfo, 0, sizeof(*pktinfo));
		pktinfo->ipi_spec_dst = s4->sin_addr;
	} else if (request->localaddr.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&request->localaddr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

		struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		memset(pktinfo, 0, sizeof(*pktinfo));
		pktinfo->ipi6_addr = s6->sin6_addr;
	} else {
		goto use_send;
	}

	send_len = sendmsg(udpserver->head.fd, &msg, 0);
	if (send_len == inpacket_len) {
		return 0;
	}

use_send:
	send_len = sendto(udpserver->head.fd, inpacket, inpacket_len, 0, &request->addr, request->addr_len);
	if (send_len != inpacket_len) {
		tlog(TLOG_DEBUG, "send failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int _dns_server_process_udp_one(struct dns_server_conn_udp *udpconn, struct epoll_event *event,
									   unsigned long now)
{
	int len = 0;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	struct sockaddr_storage local;
	socklen_t local_len = sizeof(local);
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	struct cmsghdr *cmsg = NULL;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)inpacket;
	iov.iov_len = sizeof(inpacket);
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ans_data;
	msg.msg_controllen = sizeof(ans_data);

	len = recvmsg(udpconn->head.fd, &msg, MSG_DONTWAIT);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return -2;
		}
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}
	from_len = msg.msg_namelen;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			const struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			unsigned char *addr = (unsigned char *)&pktinfo->ipi_addr.s_addr;
			fill_sockaddr_by_ip(addr, sizeof(in_addr_t), 0, (struct sockaddr *)&local, &local_len);
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			const struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			unsigned char *addr = (unsigned char *)pktinfo->ipi6_addr.s6_addr;
			fill_sockaddr_by_ip(addr, sizeof(struct in6_addr), 0, (struct sockaddr *)&local, &local_len);
		}
	}

	return _dns_server_recv(&udpconn->head, inpacket, len, &local, local_len, &from, from_len);
}

int _dns_server_process_udp(struct dns_server_conn_udp *udpconn, struct epoll_event *event, unsigned long now)
{
	int count = 0;
	while (count < 32) {
		int ret = _dns_server_process_udp_one(udpconn, event, now);
		if (ret != 0) {
			if (ret == -2) {
				return 0;
			}

			return ret;
		}

		count++;
	}

	return 0;
}

int _dns_server_socket_udp(struct dns_bind_ip *bind_ip)
{
	const char *host_ip = NULL;
	struct dns_server_conn_udp *conn = NULL;
	int fd = -1;

	host_ip = bind_ip->ip;
	fd = _dns_create_socket(host_ip, SOCK_DGRAM);
	if (fd <= 0) {
		goto errout;
	}

	conn = zalloc(1, sizeof(struct dns_server_conn_udp));
	if (conn == NULL) {
		goto errout;
	}

	_dns_server_conn_head_init(&conn->head, fd, DNS_CONN_TYPE_UDP_SERVER);
	_dns_server_set_flags(&conn->head, bind_ip);
	_dns_server_conn_get(&conn->head);

	return 0;
errout:
	if (conn) {
		free(conn);
		conn = NULL;
	}

	if (fd > 0) {
		close(fd);
	}
	return -1;
}
