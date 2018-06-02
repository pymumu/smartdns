/*************************************************************************
 *
 * Copyright (C) 2018 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include <linux/filter.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
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

struct fast_ping_packet_msg {
	struct timeval tv;
	unsigned int sid;
	unsigned int seq;
};

struct fast_ping_packet {
	union {
		struct icmp icmp;
		struct icmp6_hdr icmp6;
	};
	struct fast_ping_packet_msg msg;
};

struct ping_host_struct {
	atomic_t ref;
	struct hlist_node host_node;
	struct hlist_node addr_node;
	FAST_PING_TYPE type;

	void *userptr;
	fast_ping_result ping_callback;
	char host[PING_MAX_HOSTLEN];

	int fd;
	unsigned int seq;
	struct timeval last;
	int interval;
	int timeout;
	int count;
	int send;
	unsigned int sid;
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

	pthread_mutex_t map_lock;
	DECLARE_HASHTABLE(hostmap, 6);
	DECLARE_HASHTABLE(addrmap, 6);
};

static struct fast_ping_struct ping;
static atomic_t ping_sid = ATOMIC_INIT(0);

uint16_t _fast_ping_checksum(uint16_t *header, size_t len)
{
	uint32_t sum = 0;
	int i;

	for (i = 0; i < len / sizeof(uint16_t); i++) {
		sum += ntohs(header[i]);
	}

	return htons(~((sum >> 16) + (sum & 0xffff)));
}

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
	insns[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(getpid()), 0, 1);

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
		perror("WARNING: failed to install socket filter\n");
	}
}

void _fast_ping_install_filter_v4(int sock)
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
	insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(getpid()), 0, 1);

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
		perror("WARNING: failed to install socket filter\n");
	}
}

static struct addrinfo *_fast_ping_getaddr(const char *host, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	if (getaddrinfo(host, NULL, &hints, &result) != 0) {
		tlog(TLOG_ERROR, "get addr info failed. %s\n", strerror(errno));
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
	atomic_inc(&ping_host->ref);
}

static void _fast_ping_host_put(struct ping_host_struct *ping_host)
{
	pthread_mutex_lock(&ping.map_lock);
	if (atomic_dec_and_test(&ping_host->ref)) {
		hash_del(&ping_host->host_node);
		hash_del(&ping_host->addr_node);
	} else {
		ping_host = NULL;
	}
	pthread_mutex_unlock(&ping.map_lock);

	if (ping_host == NULL) {
		return;
	}

	free(ping_host);
}

static void _fast_ping_host_put_locked(struct ping_host_struct *ping_host)
{
	if (atomic_dec_and_test(&ping_host->ref)) {
		hash_del(&ping_host->host_node);
		hash_del(&ping_host->addr_node);
	} else {
		ping_host = NULL;
	}

	if (ping_host == NULL) {
		return;
	}

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	
	ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_END, &ping_host->addr, ping_host->addr_len, ping_host->seq, &tv, ping_host->userptr);

	free(ping_host);
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
	icmp6->icmp6_id = getpid();
	icmp6->icmp6_seq = htons(ping_host->seq);

	gettimeofday(&packet->msg.tv, 0);
	packet->msg.sid = ping_host->sid;
	packet->msg.seq = ping_host->seq;
	icmp6->icmp6_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping_host->fd, &ping_host->packet, sizeof(struct fast_ping_packet), 0, (struct sockaddr *)&ping_host->addr, ping_host->addr_len);
	if (len < 0 || len != sizeof(struct fast_ping_packet)) {
		tlog(TLOG_ERROR, "sendto %s\n", strerror(errno));
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

	gettimeofday(&packet->msg.tv, 0);
	packet->msg.sid = ping_host->sid;
	packet->msg.seq = ping_host->seq;
	icmp->icmp_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping_host->fd, packet, sizeof(struct fast_ping_packet), 0, (struct sockaddr *)&ping_host->addr, ping_host->addr_len);
	if (len < 0 || len != sizeof(struct fast_ping_packet)) {
		tlog(TLOG_ERROR, "sendto %s\n", strerror(errno));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _fast_ping_sendping(struct ping_host_struct *ping_host)
{
	int ret = -1;

	if (ping_host->type == FAST_PING_ICMP) {
		ret = _fast_ping_sendping_v4(ping_host);
	} else if (ping_host->type == FAST_PING_ICMP6) {
		ret = _fast_ping_sendping_v6(ping_host);
	}

	ping_host->send = 1;
	gettimeofday(&ping_host->last, 0);

	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int _fast_ping_create_sock(FAST_PING_TYPE type)
{
	int fd = -1;
	struct ping_host_struct *icmp_host = NULL;
	struct epoll_event event;
	int buffsize = 64 * 1024;
	socklen_t optlen = sizeof(buffsize);

	switch (type) {
	case FAST_PING_ICMP:
		fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create icmp socket failed.\n");
			goto errout;
		}
		_fast_ping_install_filter_v4(fd);
		icmp_host = &ping.icmp_host;
		break;
	case FAST_PING_ICMP6:
		fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create icmp socket failed.\n");
			goto errout;
		}
		_fast_ping_install_filter_v6(fd);
		icmp_host = &ping.icmp6_host;
		break;
	default:
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&buffsize, optlen);
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&buffsize, optlen);

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

	fd = _fast_ping_create_sock(type);
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

void fast_ping_print_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result, struct sockaddr *addr, socklen_t addr_len, int seqno,
							struct timeval *tv, void *userptr)
{
	if (result == PING_RESULT_RESPONSE) {
		double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
		tlog(TLOG_INFO, "from %15s: seq=%d time=%.3f\n", host, seqno, rtt);
	} else if (result == PING_RESULT_TIMEOUT) {
		tlog(TLOG_INFO, "from %15s: seq=%d timeout\n", host, seqno);
	}
}

struct ping_host_struct *fast_ping_start(const char *host, int count, int timeout, fast_ping_result ping_callback, void *userptr)
{
	struct ping_host_struct *ping_host = NULL;
	struct addrinfo *gai = NULL;
	int domain = -1;
	int icmp_proto = 0;
	uint32_t hostkey;
	uint32_t addrkey;
	int fd = -1;
	FAST_PING_TYPE type;

	domain = _fast_ping_getdomain(host);
	if (domain < 0) {
		return NULL;
	}

	switch (domain) {
	case AF_INET:
		icmp_proto = IPPROTO_ICMP;
		type = FAST_PING_ICMP;
		break;
	case AF_INET6:
		icmp_proto = IPPROTO_ICMPV6;
		type = FAST_PING_ICMP6;
		break;
	default:
		return NULL;
		break;
	}

	fd = _fast_ping_create_icmp(type);
	if (fd < 0) {
		goto errout;
	}

	gai = _fast_ping_getaddr(host, SOCK_RAW, icmp_proto);
	if (gai == NULL) {
		goto errout;
	}

	ping_host = malloc(sizeof(*ping_host));
	if (ping_host == NULL) {
		goto errout;
	}

	int interval = 1000;
	memset(ping_host, 0, sizeof(*ping_host));
	strncpy(ping_host->host, host, PING_MAX_HOSTLEN);
	ping_host->fd = fd;
	ping_host->timeout = timeout;
	ping_host->count = count;
	ping_host->type = type;
	ping_host->userptr = userptr;
	atomic_set(&ping_host->ref, 0);
	ping_host->sid = atomic_inc_return(&ping_sid);
	if (ping_callback) {
		ping_host->ping_callback = ping_callback;
	} else {
		ping_host->ping_callback = fast_ping_print_result;
	}
	ping_host->interval = (timeout > interval) ? timeout : interval;
	ping_host->addr_len = gai->ai_addrlen;
	if (gai->ai_addrlen > sizeof(struct sockaddr_in6)) {
		goto errout;
	}
	memcpy(&ping_host->addr, gai->ai_addr, gai->ai_addrlen);

	if (_fast_ping_sendping(ping_host) != 0) {
		goto errout1;
	}

	hostkey = hash_string(ping_host->host);
	addrkey = jhash(&ping_host->addr, ping_host->addr_len, 0);
	addrkey = jhash(&ping_host->sid, sizeof(ping_host->sid), addrkey);
	pthread_mutex_lock(&ping.map_lock);
	_fast_ping_host_get(ping_host);
	hash_add(ping.hostmap, &ping_host->host_node, hostkey);
	hash_add(ping.addrmap, &ping_host->addr_node, addrkey);
	pthread_mutex_unlock(&ping.map_lock);

	freeaddrinfo(gai);

	return ping_host;
errout:
	if (fd > 0) {
		close(fd);
	}
errout1:
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

static struct fast_ping_packet *_fast_ping_icmp6_packet(struct ping_host_struct *ping_host, u_char *packet_data, int data_len)
{
	int icmp_len;
	struct fast_ping_packet *packet = (struct fast_ping_packet *)packet_data;
	struct icmp6_hdr *icmp6 = &packet->icmp6;

	if (icmp6->icmp6_type != ICMP6_ECHO_REPLY) {
		tlog(TLOG_ERROR, "icmp6 type faild, %d:%d", icmp6->icmp6_type, ICMP6_ECHO_REPLY);
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

static struct fast_ping_packet *_fast_ping_icmp_packet(struct ping_host_struct *ping_host, u_char *packet_data, int data_len)
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

	if (icmp_len < 16) {
		tlog(TLOG_ERROR, "length is invalid, %d", icmp_len);
		return NULL;
	}

	if (icmp->icmp_type != ICMP_ECHOREPLY) {
		tlog(TLOG_ERROR, "icmp type faild, %d:%d", icmp->icmp_type, ICMP_ECHOREPLY);
		return NULL;
	}

	if (icmp->icmp_id != ping.ident) {
		tlog(TLOG_ERROR, "ident failed, %d:%d", icmp->icmp_id, ping.ident);
		return NULL;
	}

	return packet;
}

struct fast_ping_packet *_fast_ping_recv_packet(struct ping_host_struct *ping_host, u_char *inpacket, int len, struct timeval *tvrecv)
{
	struct fast_ping_packet *packet = NULL;

	if (ping_host->type == FAST_PING_ICMP6) {
		packet = _fast_ping_icmp6_packet(ping_host, inpacket, len);
		if (packet == NULL) {
			goto errout;
		}
	} else if (ping_host->type == FAST_PING_ICMP) {
		packet = _fast_ping_icmp_packet(ping_host, inpacket, len);
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

	len = recvfrom(ping_host->fd, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		goto errout;
	}

	packet = _fast_ping_recv_packet(ping_host, inpacket, len, now);
	if (packet == NULL) {
		char name[PING_MAX_HOSTLEN];
		tlog(TLOG_DEBUG, "recv ping packet from %s failed.", gethost_by_addr(name, (struct sockaddr *)&from, from_len));
		goto errout;
	}

	addrkey = jhash(&from, from_len, 0);
	tvsend = &packet->msg.tv;
	sid = packet->msg.sid;
	seq = packet->msg.seq;
	addrkey = jhash(&sid, sizeof(sid), addrkey);
	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_possible(ping.addrmap, recv_ping_host, addr_node, addrkey)
	{
		if (recv_ping_host->addr_len == from_len && memcmp(&recv_ping_host->addr, &from, from_len) == 0 && recv_ping_host->sid == sid) {
			break;
		}
	}

	pthread_mutex_unlock(&ping.map_lock);

	if (recv_ping_host == NULL) {
		return -1;
	}

	if (recv_ping_host->seq != seq) {
		tlog(TLOG_ERROR, "seq num mismatch, expect %u, real %u", recv_ping_host->seq, seq);
		return -1;
	}

	tv_sub(&tvresult, tvsend);
	if (recv_ping_host->ping_callback) {
		recv_ping_host->ping_callback(recv_ping_host, recv_ping_host->host, PING_RESULT_RESPONSE, &recv_ping_host->addr, recv_ping_host->addr_len,
									  recv_ping_host->seq, &tvresult, recv_ping_host->userptr);
	}

	recv_ping_host->send = 0;

	if (recv_ping_host->count == 1) {
		_fast_ping_host_put(recv_ping_host);
	}

	return 0;
errout:
	return -1;
}

static int _fast_ping_process(struct ping_host_struct *ping_host, struct timeval *now)
{
	int ret = -1;

	switch (ping_host->type) {
	case FAST_PING_ICMP6:
	case FAST_PING_ICMP:
		ret = _fast_ping_process_icmp(ping_host, now);
		break;
	default:
		break;
	}

	return ret;
}

static void _fast_ping_period_run()
{
	struct ping_host_struct *ping_host;
	struct hlist_node *tmp;
	int i = 0;
	struct timeval now;
	struct timeval interval;
	int64_t millisecond;
	gettimeofday(&now, 0);

	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_safe(ping.addrmap, i, tmp, ping_host, addr_node)
	{
		interval = now;
		tv_sub(&interval, &ping_host->last);
		millisecond = interval.tv_sec * 1000 + interval.tv_usec / 1000;
		if (millisecond >= ping_host->timeout && ping_host->send == 1) {
			ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_TIMEOUT, &ping_host->addr, ping_host->addr_len, ping_host->seq, &interval,
									 ping_host->userptr);
			ping_host->send = 0;
		}

		if (millisecond < ping_host->interval) {
			continue;
		}

		if (ping_host->count > 0) {
			if (ping_host->count == 1) {
				hash_del(&ping_host->host_node);
				hash_del(&ping_host->addr_node);
				_fast_ping_host_put_locked(ping_host);
				continue;
			}
			ping_host->count--;
		}

		_fast_ping_sendping(ping_host);
	}
	pthread_mutex_unlock(&ping.map_lock);
}

static void *_fast_ping_work(void *arg)
{
	struct epoll_event events[PING_MAX_EVENTS + 1];
	int num;
	int i;
	struct timeval last = {0};
	struct timeval now = {0};
	struct timeval diff = {0};
	uint millisec = 0;

	while (ping.run) {
		diff = now;
		tv_sub(&diff, &last);
		millisec = diff.tv_sec * 1000 + diff.tv_usec / 1000;
		if (millisec >= 100) {
			_fast_ping_period_run();
			last = now;
		}

		num = epoll_wait(ping.epoll_fd, events, PING_MAX_EVENTS, 100);
		if (num < 0) {
			gettimeofday(&now, 0);
			usleep(100000);
			continue;
		}

		if (num == 0) {
			gettimeofday(&now, 0);
			continue;
		}

		gettimeofday(&now, 0);
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct ping_host_struct *ping_host = (struct ping_host_struct *)event->data.ptr;
			_fast_ping_process(ping_host, &now);
		}
	}

	close(ping.epoll_fd);
	ping.epoll_fd = -1;

	return NULL;
}

int fast_ping_init()
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret;

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

	pthread_mutex_init(&ping.map_lock, 0);
	pthread_mutex_init(&ping.lock, 0);
	hash_init(ping.hostmap);
	hash_init(ping.addrmap);
	ping.epoll_fd = epollfd;
	ping.ident = getpid();
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

void fast_ping_exit()
{
	if (ping.tid > 0) {
		void *ret = NULL;
		ping.run = 0;
		pthread_join(ping.tid, &ret);
	}

	if (ping.fd_icmp > 0) {
		close(ping.fd_icmp);
		ping.fd_icmp = -1;
	}

	if (ping.fd_icmp6 > 0) {
		close(ping.fd_icmp6);
		ping.fd_icmp6 = -1;
	}

	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);
}