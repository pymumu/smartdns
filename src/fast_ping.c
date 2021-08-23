/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "fast_ping.h"
#include "atomic.h"
#include "hashtable.h"
#include "tlog.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PING_MAX_EVENTS 128
#define PING_MAX_HOSTLEN 128
#define ICMP_PACKET_SIZE (1024 * 64)
#define ICMP_INPACKET_SIZE 1024
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define SOCKET_PRIORITY (6)

#ifndef ICMP_FILTER
#define ICMP_FILTER 1
struct icmp_filter {
	uint32_t data;
};
#endif

struct ping_dns_head {
	unsigned short id;
	unsigned short flag;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short aucount;
	unsigned short adcount;
} __attribute__((packed));

typedef enum FAST_PING_TYPE {
	FAST_PING_ICMP = 1,
	FAST_PING_ICMP6 = 2,
	FAST_PING_TCP,
	FAST_PING_UDP,
	FAST_PING_UDP6,
	FAST_PING_END,
} FAST_PING_TYPE;

struct fast_ping_packet_msg {
	struct timeval tv;
	unsigned int sid;
	unsigned int seq;
	unsigned int cookie;
};

struct fast_ping_packet {
	union {
		struct icmp icmp;
		struct icmp6_hdr icmp6;
	};
	unsigned int ttl;
	struct fast_ping_packet_msg msg;
};

struct ping_host_struct {
	atomic_t ref;
	atomic_t notified;
	struct hlist_node addr_node;
	struct list_head action_list;
	FAST_PING_TYPE type;

	void *userptr;
	fast_ping_result ping_callback;
	char host[PING_MAX_HOSTLEN];

	int fd;
	unsigned int seq;
	int ttl;
	struct timeval last;
	int interval;
	int timeout;
	int count;
	int send;
	int run;
	unsigned int cookie;
	unsigned int sid;
	unsigned short port;
	unsigned short ss_family;
	union {
		struct sockaddr addr;
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
	};
	socklen_t addr_len;
	struct fast_ping_packet packet;
};

struct fast_ping_struct {
	int run;
	pthread_t tid;
	pthread_mutex_t lock;
	unsigned short ident;

	int epoll_fd;
	int fd_icmp;
	struct ping_host_struct icmp_host;
	int fd_icmp6;
	struct ping_host_struct icmp6_host;
	int fd_udp;
	struct ping_host_struct udp_host;
	int fd_udp6;
	struct ping_host_struct udp6_host;

	pthread_mutex_t map_lock;
	DECLARE_HASHTABLE(addrmap, 6);
};

static struct fast_ping_struct ping;
static atomic_t ping_sid = ATOMIC_INIT(0);
static int bool_print_log = 1;

static uint16_t _fast_ping_checksum(uint16_t *header, size_t len)
{
	uint32_t sum = 0;
	int i;

	for (i = 0; i < len / sizeof(uint16_t); i++) {
		sum += ntohs(header[i]);
	}

	return htons(~((sum >> 16) + (sum & 0xffff)));
}

static void _fast_ping_install_filter_v6(int sock)
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
		perror("WARNING: failed to install socket filter\n");
	}
}

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
		perror("WARNING: failed to install socket filter\n");
	}
}

static int _fast_ping_sockaddr_ip_cmp(struct sockaddr *first_addr, socklen_t first_addr_len,
									  struct sockaddr *second_addr, socklen_t second_addr_len)
{
	if (first_addr_len != second_addr_len) {
		return -1;
	}

	if (first_addr->sa_family != second_addr->sa_family) {
		return -1;
	}

	switch (first_addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *first_addr_in = (struct sockaddr_in *)first_addr;
		struct sockaddr_in *second_addr_in = (struct sockaddr_in *)second_addr;
		if (memcmp(&first_addr_in->sin_addr.s_addr, &second_addr_in->sin_addr.s_addr, IPV4_ADDR_LEN) != 0) {
			return -1;
		}
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *first_addr_in6 = (struct sockaddr_in6 *)first_addr;
		struct sockaddr_in6 *second_addr_in6 = (struct sockaddr_in6 *)second_addr;
		if (memcmp(&first_addr_in6->sin6_addr.s6_addr, &second_addr_in6->sin6_addr.s6_addr, IPV4_ADDR_LEN) != 0) {
			return -1;
		}
	} break;
	default:
		return -1;
	}

	return 0;
}

static uint32_t _fast_ping_hash_key(unsigned int sid, struct sockaddr *addr)
{
	uint32_t key = 0;
	void *sin_addr = NULL;
	unsigned int sin_addr_len = 0;

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in;
		addr_in = (struct sockaddr_in *)addr;
		sin_addr = &addr_in->sin_addr.s_addr;
		sin_addr_len = IPV4_ADDR_LEN;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			sin_addr = addr_in6->sin6_addr.s6_addr + 12;
			sin_addr_len = IPV4_ADDR_LEN;
		} else {
			sin_addr = addr_in6->sin6_addr.s6_addr;
			sin_addr_len = IPV6_ADDR_LEN;
		}
	} break;
	default:
		goto errout;
		break;
	}
	if (sin_addr == NULL) {
		return -1;
	}

	key = jhash(sin_addr, sin_addr_len, 0);
	key = jhash(&sid, sizeof(sid), key);

	return key;
errout:
	return -1;
}

static struct addrinfo *_fast_ping_getaddr(const char *host, const char *port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int errcode = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	errcode = getaddrinfo(host, port, &hints, &result);
	if (errcode != 0) {
		tlog(TLOG_ERROR, "get addr info failed. host:%s, port: %s, error %s\n", host, port, gai_strerror(errcode));
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

static int _fast_ping_getdomain(const char *host)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int domain = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	if (getaddrinfo(host, NULL, &hints, &result) != 0) {
		tlog(TLOG_ERROR, "get addr info failed. %s\n", strerror(errno));
		goto errout;
	}

	domain = result->ai_family;

	freeaddrinfo(result);

	return domain;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return -1;
}

static void _fast_ping_host_get(struct ping_host_struct *ping_host)
{
	if (atomic_inc_return(&ping_host->ref) <= 0) {
		tlog(TLOG_ERROR, "BUG: ping host ref is invalid, host: %s", ping_host->host);
		abort();
	}
}

static void _fast_ping_close_host_sock(struct ping_host_struct *ping_host)
{
	if (ping_host->fd < 0) {
		return;
	}
	struct epoll_event *event;
	event = (struct epoll_event *)1;
	epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping_host->fd, event);
	close(ping_host->fd);
	ping_host->fd = -1;
}

static void _fast_ping_host_put(struct ping_host_struct *ping_host)
{
	int ref_cnt = atomic_dec_and_test(&ping_host->ref);
	if (!ref_cnt) {
		if (ref_cnt < 0) {
			tlog(TLOG_ERROR, "invalid refcount of ping_host %s", ping_host->host);
			abort();
		}
		return;
	}

	_fast_ping_close_host_sock(ping_host);

	pthread_mutex_lock(&ping.map_lock);
	hash_del(&ping_host->addr_node);
	pthread_mutex_unlock(&ping.map_lock);

	if (atomic_inc_return(&ping_host->notified) == 1) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_END, &ping_host->addr, ping_host->addr_len,
								 ping_host->seq, ping_host->ttl, &tv, ping_host->userptr);
	}

	tlog(TLOG_DEBUG, "ping end, id %d", ping_host->sid);
	// memset(ping_host, 0, sizeof(*ping_host));
	ping_host->type = FAST_PING_END;
	free(ping_host);
}

static void _fast_ping_host_remove(struct ping_host_struct *ping_host)
{
	_fast_ping_close_host_sock(ping_host);

	pthread_mutex_lock(&ping.map_lock);
	if (!hash_hashed(&ping_host->addr_node)) {
		pthread_mutex_unlock(&ping.map_lock);
		return;
	}
	hash_del(&ping_host->addr_node);

	pthread_mutex_unlock(&ping.map_lock);

	if (atomic_inc_return(&ping_host->notified) == 1) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_END, &ping_host->addr, ping_host->addr_len,
								 ping_host->seq, ping_host->ttl, &tv, ping_host->userptr);
	}

	_fast_ping_host_put(ping_host);
}

static int _fast_ping_sendping_v6(struct ping_host_struct *ping_host)
{
	struct fast_ping_packet *packet = &ping_host->packet;
	struct icmp6_hdr *icmp6 = &packet->icmp6;
	int len = 0;

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
	packet->msg.cookie = ping_host->cookie;
	packet->msg.seq = ping_host->seq;
	icmp6->icmp6_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping.fd_icmp6, &ping_host->packet, sizeof(struct fast_ping_packet), 0,
				 (struct sockaddr *)&ping_host->addr, ping_host->addr_len);
	if (len < 0 || len != sizeof(struct fast_ping_packet)) {
		int err = errno;
		if (errno == ENETUNREACH || errno == EINVAL) {
			goto errout;
		}

		if (errno == EACCES) {
			if (bool_print_log == 0) {
				goto errout;
			}
			bool_print_log = 0;
		}

		char ping_host_name[PING_MAX_HOSTLEN];
		tlog(TLOG_ERROR, "sendto %s, id %d, %s",
			 gethost_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
			 ping_host->sid, strerror(err));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _fast_ping_sendping_v4(struct ping_host_struct *ping_host)
{
	struct fast_ping_packet *packet = &ping_host->packet;
	struct icmp *icmp = &packet->icmp;
	int len;

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
	packet->msg.cookie = ping_host->cookie;
	icmp->icmp_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping.fd_icmp, packet, sizeof(struct fast_ping_packet), 0, (struct sockaddr *)&ping_host->addr,
				 ping_host->addr_len);
	if (len < 0 || len != sizeof(struct fast_ping_packet)) {
		int err = errno;
		if (errno == ENETUNREACH || errno == EINVAL) {
			goto errout;
		}
		char ping_host_name[PING_MAX_HOSTLEN];
		tlog(TLOG_ERROR, "sendto %s, id %d, %s",
			 gethost_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
			 ping_host->sid, strerror(err));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _fast_ping_sendping_udp(struct ping_host_struct *ping_host)
{
	struct ping_dns_head dns_head;
	int len;
	int flag = 0;
	int fd = 0;

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
	gettimeofday(&ping_host->last, NULL);
	len = sendto(fd, &dns_head, sizeof(dns_head), 0, (struct sockaddr *)&ping_host->addr, ping_host->addr_len);
	if (len < 0 || len != sizeof(dns_head)) {
		int err = errno;
		if (errno == ENETUNREACH || errno == EINVAL) {
			goto errout;
		}
		char ping_host_name[PING_MAX_HOSTLEN];
		tlog(TLOG_ERROR, "sendto %s, id %d, %s",
			 gethost_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
			 ping_host->sid, strerror(err));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _fast_ping_sendping_tcp(struct ping_host_struct *ping_host)
{
	struct epoll_event event;
	int flags;
	int fd = -1;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = IP_TOS;

	_fast_ping_close_host_sock(ping_host);

	fd = socket(ping_host->ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		goto errout;
	}

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	set_sock_keepalive(fd, 0, 0, 0);
	/* Set the socket lingering so we will RST connections instead of wasting
	 * bandwidth with the four-step close
	 */
	set_sock_lingertime(fd, 0);

	ping_host->seq++;
	if (connect(fd, (struct sockaddr *)&ping_host->addr, ping_host->addr_len) != 0) {
		if (errno != EINPROGRESS) {
			char ping_host_name[PING_MAX_HOSTLEN];
			if (errno == ENETUNREACH || errno == EINVAL) {
				goto errout;
			}

			if (errno == EACCES) {
				if (bool_print_log == 0) {
					goto errout;
				}
				bool_print_log = 0;
			}

			tlog(TLOG_ERROR, "connect %s, id %d, %s",
				 gethost_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
				 ping_host->sid, strerror(errno));
			goto errout;
		}
	}

	gettimeofday(&ping_host->last, NULL);
	ping_host->fd = fd;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT | EPOLLERR;
	event.data.ptr = ping_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		ping_host->fd = -1;
		goto errout;
	}

	return 0;

errout:
	if (fd > 0) {
		close(fd);
		ping_host->fd = -1;
	}
	return -1;
}

static int _fast_ping_sendping(struct ping_host_struct *ping_host)
{
	int ret = -1;
	gettimeofday(&ping_host->last, NULL);

	if (ping_host->type == FAST_PING_ICMP) {
		ret = _fast_ping_sendping_v4(ping_host);
	} else if (ping_host->type == FAST_PING_ICMP6) {
		ret = _fast_ping_sendping_v6(ping_host);
	} else if (ping_host->type == FAST_PING_TCP) {
		ret = _fast_ping_sendping_tcp(ping_host);
	} else if (ping_host->type == FAST_PING_UDP || ping_host->type == FAST_PING_UDP6) {
		ret = _fast_ping_sendping_udp(ping_host);
	}

	ping_host->send = 1;

	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int _fast_ping_create_icmp_sock(FAST_PING_TYPE type)
{
	int fd = -1;
	struct ping_host_struct *icmp_host = NULL;
	struct epoll_event event;
	int buffsize = 64 * 1024;
	socklen_t optlen = sizeof(buffsize);
	const int val = 255;
	const int on = 1;
	const int ip_tos = (IPTOS_LOWDELAY | IPTOS_RELIABILITY);

	switch (type) {
	case FAST_PING_ICMP:
		fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create icmp socket failed, %s\n", strerror(errno));
			goto errout;
		}
		_fast_ping_install_filter_v4(fd);
		icmp_host = &ping.icmp_host;
		break;
	case FAST_PING_ICMP6:
		fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create icmp socket failed, %s\n", strerror(errno));
			goto errout;
		}
		_fast_ping_install_filter_v6(fd);
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

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = icmp_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		goto errout;
	}

	icmp_host->fd = fd;
	icmp_host->type = type;
	return fd;

errout:
	close(fd);
	return -1;
}

static int _fast_ping_create_icmp(FAST_PING_TYPE type)
{
	int fd = 0;
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
	int fd = 0;
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

static void _fast_ping_print_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
									struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
									void *userptr)
{
	if (result == PING_RESULT_RESPONSE) {
		double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
		tlog(TLOG_INFO, "from %15s: seq=%d ttl=%d time=%.3f\n", host, seqno, ttl, rtt);
	} else if (result == PING_RESULT_TIMEOUT) {
		tlog(TLOG_INFO, "from %15s: seq=%d timeout\n", host, seqno);
	} else if (result == PING_RESULT_END) {
		fast_ping_stop(ping_host);
	}
}

static int _fast_ping_get_addr_by_icmp(const char *ip_str, int port, struct addrinfo **out_gai,
									   FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	int domain = -1;
	FAST_PING_TYPE ping_type;
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

	if (_fast_ping_create_icmp(ping_type) < 0) {
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

static int _fast_ping_get_addr_by_tcp(const char *ip_str, int port, struct addrinfo **out_gai,
									  FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	FAST_PING_TYPE ping_type;
	int sockproto = 0;
	char *service = NULL;
	char port_str[MAX_IP_LEN];

	if (port <= 0) {
		port = 80;
	}

	sockproto = 0;
	socktype = SOCK_STREAM;
	snprintf(port_str, MAX_IP_LEN, "%d", port);
	service = port_str;
	ping_type = FAST_PING_TCP;

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

static int _fast_ping_get_addr_by_dns(const char *ip_str, int port, struct addrinfo **out_gai,
									  FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	FAST_PING_TYPE ping_type;
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

static int _fast_ping_get_addr_by_type(PING_TYPE type, const char *ip_str, int port, struct addrinfo **out_gai,
									   FAST_PING_TYPE *out_ping_type)
{
	switch (type) {
	case PING_TYPE_ICMP:
		return _fast_ping_get_addr_by_icmp(ip_str, port, out_gai, out_ping_type);
		break;
	case PING_TYPE_TCP:
		return _fast_ping_get_addr_by_tcp(ip_str, port, out_gai, out_ping_type);
		break;
	case PING_TYPE_DNS:
		return _fast_ping_get_addr_by_dns(ip_str, port, out_gai, out_ping_type);
		break;
	default:
		break;
	}

	return -1;
}

struct ping_host_struct *fast_ping_start(PING_TYPE type, const char *host, int count, int interval, int timeout,
										 fast_ping_result ping_callback, void *userptr)
{
	struct ping_host_struct *ping_host = NULL;
	struct addrinfo *gai = NULL;
	uint32_t addrkey;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	unsigned int seed;
	int ret = 0;

	if (parse_ip(host, ip_str, &port) != 0) {
		goto errout;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
		tlog(TLOG_ERROR, "get addr by type failed, host: %s", host);
		goto errout;
	}

	ping_host = malloc(sizeof(*ping_host));
	if (ping_host == NULL) {
		goto errout;
	}

	memset(ping_host, 0, sizeof(*ping_host));
	safe_strncpy(ping_host->host, host, PING_MAX_HOSTLEN);
	ping_host->fd = -1;
	ping_host->timeout = timeout;
	ping_host->count = count;
	ping_host->type = ping_type;
	ping_host->userptr = userptr;
	atomic_set(&ping_host->ref, 0);
	atomic_set(&ping_host->notified, 0);
	ping_host->sid = atomic_inc_return(&ping_sid);
	seed = ping_host->sid;
	ping_host->cookie = rand_r(&seed);
	ping_host->run = 0;
	if (ping_callback) {
		ping_host->ping_callback = ping_callback;
	} else {
		ping_host->ping_callback = _fast_ping_print_result;
	}
	ping_host->interval = (timeout > interval) ? timeout : interval;
	ping_host->addr_len = gai->ai_addrlen;
	ping_host->port = port;
	ping_host->ss_family = gai->ai_family;
	if (gai->ai_addrlen > sizeof(struct sockaddr_in6)) {
		goto errout;
	}
	memcpy(&ping_host->addr, gai->ai_addr, gai->ai_addrlen);

	tlog(TLOG_DEBUG, "ping %s, id = %d", host, ping_host->sid);

	addrkey = _fast_ping_hash_key(ping_host->sid, &ping_host->addr);
	pthread_mutex_lock(&ping.map_lock);
	_fast_ping_host_get(ping_host);
	hash_add(ping.addrmap, &ping_host->addr_node, addrkey);
	pthread_mutex_unlock(&ping.map_lock);

	_fast_ping_host_get(ping_host);
	_fast_ping_host_get(ping_host);
	// for ping race condition, get reference count twice
	if (_fast_ping_sendping(ping_host) != 0) {
		goto errout_remove;
	}

	ping_host->run = 1;
	freeaddrinfo(gai);
	_fast_ping_host_put(ping_host);
	return ping_host;
errout_remove:
	fast_ping_stop(ping_host);
	_fast_ping_host_put(ping_host);
	ping_host = NULL;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}

	if (ping_host) {
		free(ping_host);
	}

	return NULL;
}

int fast_ping_stop(struct ping_host_struct *ping_host)
{
	if (ping_host == NULL) {
		return 0;
	}

	atomic_inc_return(&ping_host->notified);
	_fast_ping_host_remove(ping_host);
	_fast_ping_host_put(ping_host);
	return 0;
}

static void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static struct fast_ping_packet *_fast_ping_icmp6_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
														u_char *packet_data, int data_len)
{
	int icmp_len;
	struct fast_ping_packet *packet = (struct fast_ping_packet *)packet_data;
	struct icmp6_hdr *icmp6 = &packet->icmp6;
	struct cmsghdr *c;
	int hops = 0;

	for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level != IPPROTO_IPV6)
			continue;
		switch (c->cmsg_type) {
		case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
		case IPV6_2292HOPLIMIT:
#endif
			if (c->cmsg_len < CMSG_LEN(sizeof(int)))
				continue;
			memcpy(&hops, CMSG_DATA(c), sizeof(hops));
		}
	}

	packet->ttl = hops;
	if (icmp6->icmp6_type != ICMP6_ECHO_REPLY) {
		tlog(TLOG_DEBUG, "icmp6 type faild, %d:%d", icmp6->icmp6_type, ICMP6_ECHO_REPLY);
		return NULL;
	}

	icmp_len = data_len;
	if (icmp_len < 16) {
		tlog(TLOG_ERROR, "length is invalid, %d", icmp_len);
		return NULL;
	}

	if (icmp6->icmp6_id != ping.ident) {
		tlog(TLOG_ERROR, "ident failed, %d:%d", icmp6->icmp6_id, ping.ident);
		return NULL;
	}

	return packet;
}

static struct fast_ping_packet *_fast_ping_icmp_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
													   u_char *packet_data, int data_len)
{
	struct ip *ip = (struct ip *)packet_data;
	struct fast_ping_packet *packet;
	struct icmp *icmp;
	int hlen;
	int icmp_len;

	if (ip->ip_p != IPPROTO_ICMP) {
		tlog(TLOG_ERROR, "ip type faild, %d:%d", ip->ip_p, IPPROTO_ICMP);
		return NULL;
	}

	hlen = ip->ip_hl << 2;
	packet = (struct fast_ping_packet *)(packet_data + hlen);
	icmp = &packet->icmp;
	icmp_len = data_len - hlen;
	packet->ttl = ip->ip_ttl;

	if (icmp_len < 16) {
		tlog(TLOG_ERROR, "length is invalid, %d", icmp_len);
		return NULL;
	}

	if (icmp->icmp_type != ICMP_ECHOREPLY) {
		tlog(TLOG_DEBUG, "icmp type faild, %d:%d", icmp->icmp_type, ICMP_ECHOREPLY);
		return NULL;
	}

	if (icmp->icmp_id != ping.ident) {
		tlog(TLOG_ERROR, "ident failed, %d:%d", icmp->icmp_id, ping.ident);
		return NULL;
	}

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

static int _fast_ping_process_icmp(struct ping_host_struct *ping_host, struct timeval *now)
{
	int len;
	u_char inpacket[ICMP_INPACKET_SIZE];
	struct sockaddr_storage from;
	struct ping_host_struct *recv_ping_host;
	struct fast_ping_packet *packet = NULL;
	socklen_t from_len = sizeof(from);
	uint32_t addrkey;
	struct timeval tvresult = *now;
	struct timeval *tvsend = NULL;
	unsigned int sid;
	unsigned int seq;
	unsigned int cookie;
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
		tlog(TLOG_DEBUG, "recv ping packet from %s failed.",
			 gethost_by_addr(name, sizeof(name), (struct sockaddr *)&from));
		goto errout;
	}

	tvsend = &packet->msg.tv;
	sid = packet->msg.sid;
	seq = packet->msg.seq;
	cookie = packet->msg.cookie;
	addrkey = _fast_ping_hash_key(sid, (struct sockaddr *)&from);
	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_possible(ping.addrmap, recv_ping_host, addr_node, addrkey)
	{
		if (_fast_ping_sockaddr_ip_cmp(&recv_ping_host->addr, recv_ping_host->addr_len, (struct sockaddr *)&from,
									   from_len) == 0 &&
			recv_ping_host->sid == sid && recv_ping_host->cookie == cookie) {
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
		recv_ping_host->ping_callback(recv_ping_host, recv_ping_host->host, PING_RESULT_RESPONSE, &recv_ping_host->addr,
									  recv_ping_host->addr_len, recv_ping_host->seq, recv_ping_host->ttl, &tvresult,
									  recv_ping_host->userptr);
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

static int _fast_ping_process_tcp(struct ping_host_struct *ping_host, struct epoll_event *event, struct timeval *now)
{
	struct timeval tvresult = *now;
	struct timeval *tvsend = &ping_host->last;
	int connect_error = 0;
	socklen_t len = sizeof(connect_error);

	if (event->events & EPOLLIN || event->events & EPOLLERR) {
		if (getsockopt(ping_host->fd, SOL_SOCKET, SO_ERROR, (char *)&connect_error, &len) != 0) {
			goto errout;
		}

		if (connect_error != 0 && connect_error != ECONNREFUSED) {
			goto errout;
		}
	}
	tv_sub(&tvresult, tvsend);
	if (ping_host->ping_callback) {
		ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_RESPONSE, &ping_host->addr,
								 ping_host->addr_len, ping_host->seq, ping_host->ttl, &tvresult, ping_host->userptr);
	}

	ping_host->send = 0;

	_fast_ping_close_host_sock(ping_host);

	if (ping_host->count == 1) {
		_fast_ping_host_remove(ping_host);
	}
	return 0;
errout:
	_fast_ping_host_remove(ping_host);

	return -1;
}

static int _fast_ping_process_udp(struct ping_host_struct *ping_host, struct timeval *now)
{
	int len;
	u_char inpacket[ICMP_INPACKET_SIZE];
	struct sockaddr_storage from;
	struct ping_host_struct *recv_ping_host;
	struct ping_dns_head *dns_head = NULL;
	socklen_t from_len = sizeof(from);
	uint32_t addrkey;
	struct timeval tvresult = *now;
	struct timeval *tvsend = NULL;
	unsigned int sid;
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	struct cmsghdr *cmsg;
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
	if (len < sizeof(*dns_head)) {
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
		recv_ping_host->ping_callback(recv_ping_host, recv_ping_host->host, PING_RESULT_RESPONSE, &recv_ping_host->addr,
									  recv_ping_host->addr_len, recv_ping_host->seq, recv_ping_host->ttl, &tvresult,
									  recv_ping_host->userptr);
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

static int _fast_ping_process(struct ping_host_struct *ping_host, struct epoll_event *event, struct timeval *now)
{
	int ret = -1;

	switch (ping_host->type) {
	case FAST_PING_ICMP6:
	case FAST_PING_ICMP:
		ret = _fast_ping_process_icmp(ping_host, now);
		break;
	case FAST_PING_TCP:
		ret = _fast_ping_process_tcp(ping_host, event, now);
		break;
	case FAST_PING_UDP6:
	case FAST_PING_UDP:
		ret = _fast_ping_process_udp(ping_host, now);
		break;
	default:
		tlog(TLOG_ERROR, "BUG: type error : %p, %d, %s, %d", ping_host, ping_host->sid, ping_host->host, ping_host->fd);
		abort();
		break;
	}

	return ret;
}

static void _fast_ping_remove_all(void)
{
	struct ping_host_struct *ping_host = NULL;
	struct ping_host_struct *ping_host_tmp = NULL;
	struct hlist_node *tmp = NULL;
	int i;

	LIST_HEAD(remove_list);

	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_safe(ping.addrmap, i, tmp, ping_host, addr_node)
	{
		list_add_tail(&ping_host->action_list, &remove_list);
	}
	pthread_mutex_unlock(&ping.map_lock);

	list_for_each_entry_safe(ping_host, ping_host_tmp, &remove_list, action_list)
	{
		_fast_ping_host_remove(ping_host);
	}
}

static void _fast_ping_period_run(void)
{
	struct ping_host_struct *ping_host = NULL;
	struct ping_host_struct *ping_host_tmp = NULL;
	struct hlist_node *tmp = NULL;
	int i = 0;
	struct timeval now;
	struct timezone tz;
	struct timeval interval;
	int64_t millisecond;
	gettimeofday(&now, &tz);
	LIST_HEAD(action);

	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_safe(ping.addrmap, i, tmp, ping_host, addr_node)
	{
		if (ping_host->run == 0) {
			continue;
		}

		interval = now;
		tv_sub(&interval, &ping_host->last);
		millisecond = interval.tv_sec * 1000 + interval.tv_usec / 1000;
		if (millisecond >= ping_host->timeout && ping_host->send == 1) {
			list_add_tail(&ping_host->action_list, &action);
			_fast_ping_host_get(ping_host);
			continue;
		}

		if (millisecond < ping_host->interval) {
			continue;
		}

		list_add_tail(&ping_host->action_list, &action);
		_fast_ping_host_get(ping_host);
	}
	pthread_mutex_unlock(&ping.map_lock);

	list_for_each_entry_safe(ping_host, ping_host_tmp, &action, action_list)
	{
		interval = now;
		tv_sub(&interval, &ping_host->last);
		millisecond = interval.tv_sec * 1000 + interval.tv_usec / 1000;
		if (millisecond >= ping_host->timeout && ping_host->send == 1) {
			ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_TIMEOUT, &ping_host->addr,
									 ping_host->addr_len, ping_host->seq, ping_host->ttl, &interval,
									 ping_host->userptr);
			ping_host->send = 0;
		}

		if (millisecond < ping_host->interval) {
			list_del(&ping_host->action_list);
			_fast_ping_host_put(ping_host);
			continue;
		}

		if (ping_host->count > 0) {
			if (ping_host->count == 1) {
				_fast_ping_host_remove(ping_host);
				list_del(&ping_host->action_list);
				_fast_ping_host_put(ping_host);
				continue;
			}
			ping_host->count--;
		}

		_fast_ping_sendping(ping_host);
		list_del(&ping_host->action_list);
		_fast_ping_host_put(ping_host);
	}
}

static void *_fast_ping_work(void *arg)
{
	struct epoll_event events[PING_MAX_EVENTS + 1];
	int num;
	int i;
	unsigned long now = {0};
	struct timeval tvnow = {0};
	int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;

	sleep_time = sleep;
	now = get_tick_count() - sleep;
	expect_time = now + sleep;
	while (ping.run) {
		now = get_tick_count();
		if (now >= expect_time) {
			_fast_ping_period_run();
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}
			expect_time += sleep;
		}

		num = epoll_wait(ping.epoll_fd, events, PING_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		if (num == 0) {
			continue;
		}

		gettimeofday(&tvnow, NULL);
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct ping_host_struct *ping_host = (struct ping_host_struct *)event->data.ptr;
			_fast_ping_process(ping_host, event, &tvnow);
		}
	}

	close(ping.epoll_fd);
	ping.epoll_fd = -1;

	return NULL;
}

int fast_ping_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret;
	bool_print_log = 1;

	if (ping.epoll_fd > 0) {
		return -1;
	}

	memset(&ping, 0, sizeof(ping));
	pthread_attr_init(&attr);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	pthread_mutex_init(&ping.map_lock, NULL);
	pthread_mutex_init(&ping.lock, NULL);
	hash_init(ping.addrmap);
	ping.epoll_fd = epollfd;
	ping.ident = (getpid() & 0XFFFF);
	ping.run = 1;
	ret = pthread_create(&ping.tid, &attr, _fast_ping_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create ping work thread failed, %s\n", strerror(errno));
		goto errout;
	}

	return 0;
errout:
	if (ping.tid > 0) {
		void *retval = NULL;
		ping.run = 0;
		pthread_join(ping.tid, &retval);
	}

	if (epollfd) {
		close(epollfd);
	}

	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);

	return -1;
}

static void _fast_ping_close_fds(void)
{
	if (ping.fd_icmp > 0) {
		close(ping.fd_icmp);
		ping.fd_icmp = -1;
	}

	if (ping.fd_icmp6 > 0) {
		close(ping.fd_icmp6);
		ping.fd_icmp6 = -1;
	}

	if (ping.fd_udp > 0) {
		close(ping.fd_udp);
		ping.fd_udp = -1;
	}

	if (ping.fd_udp6 > 0) {
		close(ping.fd_udp6);
		ping.fd_udp6 = -1;
	}
}

void fast_ping_exit(void)
{
	if (ping.tid > 0) {
		void *ret = NULL;
		ping.run = 0;
		pthread_join(ping.tid, &ret);
	}

	_fast_ping_close_fds();
	_fast_ping_remove_all();

	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);
}
