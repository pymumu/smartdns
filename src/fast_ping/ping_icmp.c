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
#include "ping_icmp6.h"

#include <errno.h>
#include <linux/filter.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>

static void _fast_ping_install_filter_v4(int sock)
{
	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),                    /* Skip IP header. F..g BSD... Look into ping6. */
		BPF_STMT(BPF_LD | BPF_H | BPF_IND, 4),                     /* Load icmp echo ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1),         /* Ours? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),                            /* Yes, it passes. */
		BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),                     /* Load icmp type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFF),                      /* No. It passes. */
		BPF_STMT(BPF_RET | BPF_K, 0)                               /* Echo with wrong ident. Reject. */
	};

	static struct sock_fprog filter = {sizeof insns / sizeof(insns[0]), insns};

	if (once) {
		return;
	}
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(ping.ident), 0, 1);

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
		tlog(TLOG_WARN, "WARNING: failed to install socket filter\n");
	}
}

int _fast_ping_sendping_v4(struct ping_host_struct *ping_host)
{
	if (_fast_ping_icmp_create_socket(ping_host) < 0) {
		goto errout;
	}

	if (ping.fd_icmp <= 0) {
		errno = EADDRNOTAVAIL;
		goto errout;
	}

	struct fast_ping_packet *packet = &ping_host->packet;
	struct icmp *icmp = &packet->icmp;
	int len = 0;

	ping_host->seq++;
	memset(icmp, 0, sizeof(*icmp));
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_id = ping.ident;
	icmp->icmp_seq = htons(ping_host->seq);

	gettimeofday(&packet->msg.tv, NULL);
	gettimeofday(&ping_host->last, NULL);
	packet->msg.sid = ping_host->sid;
	packet->msg.seq = ping_host->seq;
	icmp->icmp_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping.fd_icmp, packet, sizeof(struct fast_ping_packet), 0, &ping_host->addr, ping_host->addr_len);
	if (len != sizeof(struct fast_ping_packet)) {
		int err = errno;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			goto errout;
		}
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

static int _fast_ping_create_icmp_sock(FAST_PING_TYPE type)
{
	int fd = -1;
	struct ping_host_struct *icmp_host = NULL;
	struct epoll_event event;
	/* Set receive and send buffer to 512KB, if buffer size is too small, ping may fail. */
	int buffsize = 512 * 1024;
	socklen_t optlen = sizeof(buffsize);
	const int val = 255;
	const int on = 1;
	const int ip_tos = (IPTOS_LOWDELAY | IPTOS_RELIABILITY);

	switch (type) {
	case FAST_PING_ICMP:
		if (ping.no_unprivileged_ping == 0) {
			fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
		} else {
			fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			if (fd > 0) {
				_fast_ping_install_filter_v4(fd);
			}
		}
		if (fd < 0) {
			if (errno == EACCES || errno == EAFNOSUPPORT) {
				if (bool_print_log == 0) {
					goto errout;
				}
				bool_print_log = 0;
			}
			tlog(TLOG_ERROR, "create icmp socket failed, %s\n", strerror(errno));
			goto errout;
		}
		icmp_host = &ping.icmp_host;
		break;
	case FAST_PING_ICMP6:
		if (ping.no_unprivileged_ping == 0) {
			fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
		} else {
			fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			if (fd > 0) {
				_fast_ping_install_filter_v6(fd);
			}
		}

		if (fd < 0) {
			if (errno == EACCES || errno == EAFNOSUPPORT) {
				if (bool_print_log == 0) {
					goto errout;
				}
				bool_print_log = 0;
			}
			tlog(TLOG_INFO, "create icmpv6 socket failed, %s\n", strerror(errno));
			goto errout;
		}
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
		icmp_host = &ping.icmp6_host;
		break;
	default:
		return -1;
	}

	struct icmp_filter filt;
	filt.data = ~((1 << ICMP_SOURCE_QUENCH) | (1 << ICMP_DEST_UNREACH) | (1 << ICMP_TIME_EXCEEDED) |
				  (1 << ICMP_PARAMETERPROB) | (1 << ICMP_REDIRECT) | (1 << ICMP_ECHOREPLY));
	setsockopt(fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt);
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffsize, optlen);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffsize, optlen);
	setsockopt(fd, SOL_IP, IP_TTL, &val, sizeof(val));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	set_fd_nonblock(fd, 1);

	icmp_host->fd = fd;
	icmp_host->type = type;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = icmp_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		goto errout;
	}

	return fd;

errout:
	close(fd);
	if (icmp_host) {
		icmp_host->fd = -1;
		icmp_host->type = 0;
	}
	return -1;
}

static int _fast_ping_create_icmp(FAST_PING_TYPE type)
{
	int fd = -1;
	int *set_fd = NULL;

	pthread_mutex_lock(&ping.lock);
	switch (type) {
	case FAST_PING_ICMP:
		set_fd = &ping.fd_icmp;
		break;
	case FAST_PING_ICMP6:
		set_fd = &ping.fd_icmp6;
		break;
	default:
		goto errout;
		break;
	}

	if (*set_fd > 0) {
		goto out;
	}

	fd = _fast_ping_create_icmp_sock(type);
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

int _fast_ping_icmp_create_socket(struct ping_host_struct *ping_host)
{
	if (_fast_ping_create_icmp(ping_host->type) < 0) {
		goto errout;
	}

	return 0;
errout:
	return -1;
}

struct fast_ping_packet *_fast_ping_icmp_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
												u_char *packet_data, int data_len)
{
	struct ip *ip = (struct ip *)packet_data;
	struct fast_ping_packet *packet = NULL;
	struct icmp *icmp = NULL;
	int hlen = 0;
	int icmp_len = 0;

	if (ping.no_unprivileged_ping) {
		hlen = ip->ip_hl << 2;
		if (ip->ip_p != IPPROTO_ICMP) {
			tlog(TLOG_DEBUG, "ip type failed, %d:%d", ip->ip_p, IPPROTO_ICMP);
			return NULL;
		}
	}

	if (data_len - hlen < (int)sizeof(struct icmp)) {
		tlog(TLOG_DEBUG, "response ping package length is invalid, len: %d", data_len);
		return NULL;
	}

	int align = __alignof__(struct fast_ping_packet);
	if (((uintptr_t)(packet_data + hlen) % align) == 0 && ping.no_unprivileged_ping == 0) {
		packet = (struct fast_ping_packet *)(packet_data + hlen);
	} else {
		int copy_len = sizeof(ping_host->recv_packet_buffer);
		if (copy_len > data_len - hlen) {
			copy_len = data_len - hlen;
		}
		memcpy(&ping_host->recv_packet_buffer, packet_data + hlen, copy_len);
		packet = &ping_host->recv_packet_buffer;
	}

	icmp = &packet->icmp;
	icmp_len = data_len - hlen;
	if (icmp_len < 16) {
		tlog(TLOG_ERROR, "length is invalid, %d", icmp_len);
		return NULL;
	}

	if (icmp->icmp_type != ICMP_ECHOREPLY) {
		errno = ENETUNREACH;
		return NULL;
	}

	if (icmp->icmp_id != ping.ident && ping.no_unprivileged_ping) {
		tlog(TLOG_WARN, "ident failed, %d:%d", icmp->icmp_id, ping.ident);
		return NULL;
	}

	packet->ttl = ip->ip_ttl;
	return packet;
}

static struct fast_ping_packet *_fast_ping_recv_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
													   u_char *inpacket, int len, struct timeval *tvrecv)
{
	struct fast_ping_packet *packet = NULL;

	if (ping_host->type == FAST_PING_ICMP6) {
		packet = _fast_ping_icmp6_packet(ping_host, msg, inpacket, len);
		if (packet == NULL) {
			goto errout;
		}
	} else if (ping_host->type == FAST_PING_ICMP) {
		packet = _fast_ping_icmp_packet(ping_host, msg, inpacket, len);
		if (packet == NULL) {
			goto errout;
		}
	} else {
		tlog(TLOG_ERROR, "ping host type is invalid, %d", ping_host->type);
		goto errout;
	}

	return packet;
errout:
	return NULL;
}

int _fast_ping_process_icmp(struct ping_host_struct *ping_host, struct timeval *now)
{
	int len = 0;
	u_char inpacket[ICMP_INPACKET_SIZE];
	struct sockaddr_storage from;
	struct ping_host_struct *recv_ping_host = NULL;
	struct fast_ping_packet *packet = NULL;
	socklen_t from_len = sizeof(from);
	uint32_t addrkey = 0;
	struct timeval tvresult = *now;
	struct timeval *tvsend = NULL;
	unsigned int sid = 0;
	unsigned int seq = 0;
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];

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

	from_len = msg.msg_namelen;
	packet = _fast_ping_recv_packet(ping_host, &msg, inpacket, len, now);
	if (packet == NULL) {
		char name[PING_MAX_HOSTLEN];
		if (errno == ENETUNREACH) {
			goto errout;
		}

		tlog(TLOG_DEBUG, "recv ping packet from %s failed.",
			 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&from));
		goto errout;
	}

	tvsend = &packet->msg.tv;
	sid = packet->msg.sid;
	seq = packet->msg.seq;
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

	if (recv_ping_host->seq != seq) {
		tlog(TLOG_ERROR, "seq num mismatch, expect %u, real %u", recv_ping_host->seq, seq);
		_fast_ping_host_put(recv_ping_host);
		return -1;
	}

	recv_ping_host->ttl = packet->ttl;
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

int _fast_ping_get_addr_by_icmp(const char *ip_str, int port, struct addrinfo **out_gai, FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	int domain = -1;
	FAST_PING_TYPE ping_type = 0;
	int sockproto = 0;
	char *service = NULL;

	socktype = SOCK_RAW;
	domain = _fast_ping_getdomain(ip_str);
	if (domain < 0) {
		goto errout;
	}

	switch (domain) {
	case AF_INET:
		sockproto = IPPROTO_ICMP;
		ping_type = FAST_PING_ICMP;
		break;
	case AF_INET6:
		sockproto = IPPROTO_ICMPV6;
		ping_type = FAST_PING_ICMP6;
		break;
	default:
		goto errout;
		break;
	}

	if (out_gai != NULL) {
		gai = _fast_ping_getaddr(ip_str, service, socktype, sockproto);
		if (gai == NULL) {
			goto errout;
		}

		*out_gai = gai;
	}

	if (out_ping_type != NULL) {
		*out_ping_type = ping_type;
	}

	return 0;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}
	return -1;
}

int _fast_ping_sockaddr_ip_cmp(struct sockaddr *first_addr, socklen_t first_addr_len, struct sockaddr *second_addr,
							   socklen_t second_addr_len)
{
	void *ip1, *ip2;
	int len1, len2;

	if (first_addr->sa_family == AF_INET) {
		ip1 = &((struct sockaddr_in *)first_addr)->sin_addr.s_addr;
		len1 = IPV4_ADDR_LEN;
	} else if (first_addr->sa_family == AF_INET6) {
		struct in6_addr *in6 = &((struct sockaddr_in6 *)first_addr)->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(in6)) {
			ip1 = in6->s6_addr + 12;
			len1 = IPV4_ADDR_LEN;
		} else {
			ip1 = in6->s6_addr;
			len1 = IPV6_ADDR_LEN;
		}
	} else {
		return -1;
	}

	if (second_addr->sa_family == AF_INET) {
		ip2 = &((struct sockaddr_in *)second_addr)->sin_addr.s_addr;
		len2 = IPV4_ADDR_LEN;
	} else if (second_addr->sa_family == AF_INET6) {
		struct in6_addr *in6 = &((struct sockaddr_in6 *)second_addr)->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(in6)) {
			ip2 = in6->s6_addr + 12;
			len2 = IPV4_ADDR_LEN;
		} else {
			ip2 = in6->s6_addr;
			len2 = IPV6_ADDR_LEN;
		}
	} else {
		return -1;
	}

	if (len1 != len2) {
		return -1;
	}

	return memcmp(ip1, ip2, len1);
}

uint16_t _fast_ping_checksum(uint16_t *header, size_t len)
{
	uint32_t sum = 0;
	unsigned int i = 0;

	for (i = 0; i < len / sizeof(uint16_t); i++) {
		sum += ntohs(header[i]);
	}

	return htons(~((sum >> 16) + (sum & 0xffff)));
}

void _fast_ping_close_icmp(void)
{
	if (ping.fd_icmp > 0) {
		epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping.fd_icmp, NULL);
		close(ping.fd_icmp);
		ping.fd_icmp = -1;
	}

	if (ping.fd_icmp6 > 0) {
		epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping.fd_icmp6, NULL);
		close(ping.fd_icmp6);
		ping.fd_icmp6 = -1;
	}
}
