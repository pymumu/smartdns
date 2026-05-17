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

#include "server_doh_gsocket.h"
#include "server_doq_gsocket.h"

#include "dns_server.h"

#include "smartdns/tlog.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <string.h>

int _dns_server_reply_udp(struct dns_request *request, struct dns_server_conn_udp *udpconn, unsigned char *inpacket,
						  int inpacket_len)
{
	if (atomic_read(&server.run) == 0 || inpacket == NULL || inpacket_len <= 0) {
		return -1;
	}

	struct iovec iov = {.iov_base = inpacket, .iov_len = (size_t)inpacket_len};
	char ctrlbuf[64];
	memset(ctrlbuf, 0, sizeof(ctrlbuf));
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ctrlbuf,
		.msg_controllen = sizeof(ctrlbuf),
		.msg_name = &request->addr,
		.msg_namelen = request->addr_len,
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (request->localaddr.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)&request->localaddr;
		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
		struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
		memset(pi, 0, sizeof(*pi));
		pi->ipi_spec_dst = s4->sin_addr;
	} else if (request->localaddr.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&request->localaddr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
		struct in6_pktinfo *pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		memset(pi, 0, sizeof(*pi));
		pi->ipi6_addr = s6->sin6_addr;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	ssize_t sent = gsocket_sendmsg(udpconn->head.gs, &msg, 0);
	if (sent == inpacket_len) {
		return 0;
	}

	/* Fallback: sendto without PKTINFO */
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	sent = gsocket_sendmsg(udpconn->head.gs, &msg, 0);
	return (sent == inpacket_len) ? 0 : -1;
}

int _dns_server_reply_tcp(struct dns_request *request, struct dns_server_conn_gsocket *conn, unsigned char *inpacket,
						  int inpacket_len)
{
	(void)request;
	unsigned char buf[DNS_IN_PACKSIZE + 2];
	if (inpacket_len > (int)(sizeof(buf) - 2)) {
		tlog(TLOG_ERROR, "TCP reply packet too large: %d", inpacket_len);
		return -1;
	}

	/* 2-byte length prefix */
	unsigned short nlen = htons((unsigned short)inpacket_len);
	memcpy(buf, &nlen, 2);
	memcpy(buf + 2, inpacket, inpacket_len);
	int total = inpacket_len + 2;

	ssize_t sent = gsocket_send(conn->head.gs, buf, total, MSG_NOSIGNAL);
	if (sent == total) {
		return 0;
	}
	if (sent < 0 && errno == EAGAIN) {
		/* Buffer in sndbuff and wait for EPOLLOUT */
		if (conn->sndbuff.size + total > (int)sizeof(conn->sndbuff.buf)) {
			tlog(TLOG_DEBUG, "TCP send buffer full");
			return -1;
		}
		memcpy(conn->sndbuff.buf + conn->sndbuff.size, buf, total);
		conn->sndbuff.size += total;
		gepoll_mod(server.gepoll, conn->head.gs, EPOLLIN | EPOLLOUT, conn);
		return 0;
	}
	if (sent < 0) {
		return -1;
	}
	/* Partial send - buffer remainder */
	int remaining = total - (int)sent;
	if (conn->sndbuff.size + remaining > (int)sizeof(conn->sndbuff.buf)) {
		tlog(TLOG_DEBUG, "TCP send buffer full (partial)");
		return -1;
	}
	memcpy(conn->sndbuff.buf + conn->sndbuff.size, buf + sent, remaining);
	conn->sndbuff.size += remaining;
	gepoll_mod(server.gepoll, conn->head.gs, EPOLLIN | EPOLLOUT, conn);
	return 0;
}

int _dns_server_reply_stream(struct dns_request *request, struct dns_server_conn_stream *stream_conn,
							 unsigned char *inpacket, int inpacket_len)
{
	(void)request;
	struct gsocket *stream = stream_conn->head.gs;
	if (stream == NULL) {
		return -1;
	}

	DNS_CONN_TYPE ptype = stream_conn->head.type;

	if (ptype == DNS_CONN_TYPE_HTTP2_STREAM) {
		return dns_server_doh_reply(stream, inpacket, inpacket_len);
	} else if (ptype == DNS_CONN_TYPE_QUIC_STREAM) {
		return dns_server_doq_reply(stream, inpacket, inpacket_len);
	}

	return -1;
}
