/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "list.h"
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
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
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
	unsigned short nscount;
	unsigned short nrcount;
	char qd_name;
	unsigned short q_qtype;
	unsigned short q_qclass;
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

struct fast_ping_fake_ip {
	struct hlist_node node;
	atomic_t ref;
	PING_TYPE type;
	FAST_PING_TYPE ping_type;
	char host[PING_MAX_HOSTLEN];
	int ttl;
	float time;
	struct sockaddr_storage addr;
	int addr_len;
};

struct ping_host_struct {
	atomic_t ref;
	atomic_t notified;
	struct hlist_node addr_node;
	struct list_head action_list;
	FAST_PING_TYPE type;

	void *userptr;
	int error;
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

	struct fast_ping_fake_ip *fake;
	int fake_time_fd;
};

struct fast_ping_notify_event {
	struct list_head list;
	struct ping_host_struct *ping_host;
	FAST_PING_RESULT ping_result;
	unsigned int seq;
	int ttl;
	struct timeval tvresult;
};

struct fast_ping_struct {
	atomic_t run;
	pthread_t tid;
	pthread_mutex_t lock;
	unsigned short ident;

	int epoll_fd;
	int no_unprivileged_ping;
	int fd_icmp;
	struct ping_host_struct icmp_host;
	int fd_icmp6;
	struct ping_host_struct icmp6_host;
	int fd_udp;
	struct ping_host_struct udp_host;
	int fd_udp6;
	struct ping_host_struct udp6_host;

	int event_fd;
	pthread_t notify_tid;
	pthread_cond_t notify_cond;
	pthread_mutex_t notify_lock;
	struct list_head notify_event_list;

	pthread_mutex_t map_lock;
	DECLARE_HASHTABLE(addrmap, 6);
	DECLARE_HASHTABLE(fake, 6);
	int fake_ip_num;
};

static int is_fast_ping_init;
static struct fast_ping_struct ping;
static atomic_t ping_sid = ATOMIC_INIT(0);
static int bool_print_log = 1;

static void _fast_ping_host_put(struct ping_host_struct *ping_host);
static int _fast_ping_get_addr_by_type(PING_TYPE type, const char *ip_str, int port, struct addrinfo **out_gai,
									   FAST_PING_TYPE *out_ping_type);

static void _fast_ping_wakeup_thread(void)
{
	uint64_t u = 1;
	int unused __attribute__((unused));
	unused = write(ping.event_fd, &u, sizeof(u));
}

static uint16_t _fast_ping_checksum(uint16_t *header, size_t len)
{
	uint32_t sum = 0;
	unsigned int i = 0;

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
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		sin_addr = &addr_in->sin_addr.s_addr;
		sin_addr_len = IPV4_ADDR_LEN;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
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
		tlog(TLOG_ERROR, "get addr info failed. host:%s, port: %s, error %s\n", host != NULL ? host : "",
			 port != NULL ? port : "", gai_strerror(errcode));
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

static void _fast_ping_fake_put(struct fast_ping_fake_ip *fake)
{
	int ref_cnt = atomic_dec_and_test(&fake->ref);
	if (!ref_cnt) {
		if (ref_cnt < 0) {
			tlog(TLOG_ERROR, "invalid refcount of fake ping %s", fake->host);
			abort();
		}
		return;
	}

	pthread_mutex_lock(&ping.map_lock);
	if (hash_hashed(&fake->node)) {
		hash_del(&fake->node);
	}
	pthread_mutex_unlock(&ping.map_lock);

	free(fake);
}

static void _fast_ping_fake_remove(struct fast_ping_fake_ip *fake)
{
	pthread_mutex_lock(&ping.map_lock);
	if (hash_hashed(&fake->node)) {
		hash_del(&fake->node);
	}
	pthread_mutex_unlock(&ping.map_lock);

	_fast_ping_fake_put(fake);
}

static void _fast_ping_fake_get(struct fast_ping_fake_ip *fake)
{
	atomic_inc(&fake->ref);
}

static struct fast_ping_fake_ip *_fast_ping_fake_find(FAST_PING_TYPE ping_type, struct sockaddr *addr, int addr_len)
{
	struct fast_ping_fake_ip *fake = NULL;
	struct fast_ping_fake_ip *ret = NULL;
	uint32_t key = 0;

	if (ping.fake_ip_num == 0) {
		return NULL;
	}

	key = jhash(addr, addr_len, 0);
	key = jhash(&ping_type, sizeof(ping_type), key);
	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_possible(ping.fake, fake, node, key)
	{
		if (fake->ping_type != ping_type) {
			continue;
		}

		if (fake->addr_len != addr_len) {
			continue;
		}

		if (memcmp(&fake->addr, addr, fake->addr_len) != 0) {
			continue;
		}

		ret = fake;
		_fast_ping_fake_get(fake);
		break;
	}
	pthread_mutex_unlock(&ping.map_lock);
	return ret;
}

int fast_ping_fake_ip_add(PING_TYPE type, const char *host, int ttl, float time)
{
	struct fast_ping_fake_ip *fake = NULL;
	struct fast_ping_fake_ip *fake_old = NULL;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	uint32_t key = 0;
	int ret = -1;
	struct addrinfo *gai = NULL;

	if (parse_ip(host, ip_str, &port) != 0) {
		goto errout;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
		goto errout;
	}

	fake_old = _fast_ping_fake_find(ping_type, gai->ai_addr, gai->ai_addrlen);
	fake = malloc(sizeof(*fake));
	if (fake == NULL) {
		goto errout;
	}
	memset(fake, 0, sizeof(*fake));

	safe_strncpy(fake->host, ip_str, PING_MAX_HOSTLEN);
	fake->ttl = ttl;
	fake->time = time;
	fake->type = type;
	fake->ping_type = ping_type;
	memcpy(&fake->addr, gai->ai_addr, gai->ai_addrlen);
	fake->addr_len = gai->ai_addrlen;
	INIT_HLIST_NODE(&fake->node);
	atomic_set(&fake->ref, 1);

	key = jhash(&fake->addr, fake->addr_len, 0);
	key = jhash(&ping_type, sizeof(ping_type), key);
	pthread_mutex_lock(&ping.map_lock);
	hash_add(ping.fake, &fake->node, key);
	pthread_mutex_unlock(&ping.map_lock);
	ping.fake_ip_num++;

	if (fake_old != NULL) {
		_fast_ping_fake_put(fake_old);
		_fast_ping_fake_remove(fake_old);
	}

	freeaddrinfo(gai);
	return 0;
errout:
	if (fake != NULL) {
		free(fake);
	}

	if (fake_old != NULL) {
		_fast_ping_fake_put(fake_old);
	}

	if (gai != NULL) {
		freeaddrinfo(gai);
	}

	return -1;
}

int fast_ping_fake_ip_remove(PING_TYPE type, const char *host)
{
	struct fast_ping_fake_ip *fake = NULL;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	int ret = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	struct addrinfo *gai = NULL;

	if (parse_ip(host, ip_str, &port) != 0) {
		return -1;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
		goto errout;
	}

	fake = _fast_ping_fake_find(ping_type, gai->ai_addr, gai->ai_addrlen);
	if (fake == NULL) {
		goto errout;
	}

	_fast_ping_fake_remove(fake);
	_fast_ping_fake_put(fake);
	ping.fake_ip_num--;
	freeaddrinfo(gai);
	return 0;
errout:
	if (gai != NULL) {
		freeaddrinfo(gai);
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
	if (ping_host->fake_time_fd > 0) {
		struct epoll_event *event = NULL;
		event = (struct epoll_event *)1;
		epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping_host->fake_time_fd, event);

		close(ping_host->fake_time_fd);
		ping_host->fake_time_fd = -1;
	}

	if (ping_host->fd < 0) {
		return;
	}
	struct epoll_event *event = NULL;
	event = (struct epoll_event *)1;
	epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping_host->fd, event);
	close(ping_host->fd);
	ping_host->fd = -1;
}

static void _fast_ping_release_notify_event(struct fast_ping_notify_event *ping_notify_event)
{
	pthread_mutex_lock(&ping.notify_lock);
	list_del_init(&ping_notify_event->list);
	pthread_mutex_unlock(&ping.notify_lock);

	if (ping_notify_event->ping_host) {
		_fast_ping_host_put(ping_notify_event->ping_host);
		ping_notify_event->ping_host = NULL;
	}
	free(ping_notify_event);
}

static int _fast_ping_send_notify_event(struct ping_host_struct *ping_host, FAST_PING_RESULT ping_result,
										unsigned int seq, int ttl, struct timeval *tvresult)
{
	struct fast_ping_notify_event *notify_event = NULL;

	notify_event = malloc(sizeof(struct fast_ping_notify_event));
	if (notify_event == NULL) {
		goto errout;
	}
	memset(notify_event, 0, sizeof(struct fast_ping_notify_event));
	INIT_LIST_HEAD(&notify_event->list);
	notify_event->seq = seq;
	notify_event->ttl = ttl;
	notify_event->ping_result = ping_result;
	notify_event->tvresult = *tvresult;

	pthread_mutex_lock(&ping.notify_lock);
	if (list_empty(&ping.notify_event_list)) {
		pthread_cond_signal(&ping.notify_cond);
	}
	list_add_tail(&notify_event->list, &ping.notify_event_list);
	notify_event->ping_host = ping_host;
	_fast_ping_host_get(ping_host);
	pthread_mutex_unlock(&ping.notify_lock);

	return 0;

errout:
	if (notify_event) {
		_fast_ping_release_notify_event(notify_event);
	}
	return -1;
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
	if (ping_host->fake != NULL) {
		_fast_ping_fake_put(ping_host->fake);
		ping_host->fake = NULL;
	}

	pthread_mutex_lock(&ping.map_lock);
	hash_del(&ping_host->addr_node);
	pthread_mutex_unlock(&ping.map_lock);

	if (atomic_inc_return(&ping_host->notified) == 1) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		_fast_ping_send_notify_event(ping_host, PING_RESULT_END, ping_host->seq, ping_host->ttl, &tv);
	}

	tlog(TLOG_DEBUG, "ping %s end, id %d", ping_host->host, ping_host->sid);
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

		_fast_ping_send_notify_event(ping_host, PING_RESULT_END, ping_host->seq, ping_host->ttl, &tv);
	}

	_fast_ping_host_put(ping_host);
}

static int _fast_ping_sendping_v6(struct ping_host_struct *ping_host)
{
	struct fast_ping_packet *packet = &ping_host->packet;
	struct icmp6_hdr *icmp6 = &packet->icmp6;
	int len = 0;

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
	packet->msg.cookie = ping_host->cookie;
	packet->msg.seq = ping_host->seq;
	icmp6->icmp6_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping.fd_icmp6, &ping_host->packet, sizeof(struct fast_ping_packet), 0, &ping_host->addr,
				 ping_host->addr_len);
	if (len != sizeof(struct fast_ping_packet)) {
		int err = errno;
		if (errno == ENETUNREACH || errno == EINVAL || errno == EADDRNOTAVAIL || errno == EHOSTUNREACH) {
			goto errout;
		}

		if (errno == EACCES || errno == EPERM) {
			if (bool_print_log == 0) {
				goto errout;
			}
			bool_print_log = 0;
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

static int _fast_ping_send_fake(struct ping_host_struct *ping_host, struct fast_ping_fake_ip *fake)
{
	struct itimerspec its;
	int sec = fake->time / 1000;
	int cent_usec = ((long)(fake->time * 10)) % 10000;
	its.it_value.tv_sec = sec;
	its.it_value.tv_nsec = cent_usec * 1000 * 100;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(ping_host->fake_time_fd, 0, &its, NULL) < 0) {
		tlog(TLOG_ERROR, "timerfd_settime failed, %s", strerror(errno));
		goto errout;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = ping_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, ping_host->fake_time_fd, &ev) == -1) {
		if (errno != EEXIST) {
			goto errout;
		}
	}

	ping_host->seq++;

	return 0;

errout:
	return -1;
}

static int _fast_ping_sendping_v4(struct ping_host_struct *ping_host)
{
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
	packet->msg.cookie = ping_host->cookie;
	icmp->icmp_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

	len = sendto(ping.fd_icmp, packet, sizeof(struct fast_ping_packet), 0, &ping_host->addr, ping_host->addr_len);
	if (len != sizeof(struct fast_ping_packet)) {
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

static int _fast_ping_sendping_udp(struct ping_host_struct *ping_host)
{
	struct ping_dns_head dns_head;
	int len = 0;
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

static int _fast_ping_sendping_tcp(struct ping_host_struct *ping_host)
{
	struct epoll_event event;
	int flags = 0;
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
	if (connect(fd, &ping_host->addr, ping_host->addr_len) != 0) {
		if (errno != EINPROGRESS) {
			char ping_host_name[PING_MAX_HOSTLEN];
			if (errno == ENETUNREACH || errno == EINVAL || errno == EADDRNOTAVAIL || errno == EHOSTUNREACH) {
				goto errout;
			}

			if (errno == EACCES || errno == EPERM) {
				if (bool_print_log == 0) {
					goto errout;
				}
				bool_print_log = 0;
			}

			tlog(TLOG_ERROR, "connect %s, id %d, %s",
				 get_host_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
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
	struct fast_ping_fake_ip *fake = NULL;
	gettimeofday(&ping_host->last, NULL);

	fake = _fast_ping_fake_find(ping_host->type, &ping_host->addr, ping_host->addr_len);
	if (fake) {
		ret = _fast_ping_send_fake(ping_host, fake);
		_fast_ping_fake_put(fake);
		return ret;
	}

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
		ping_host->error = errno;
		return ret;
	} else {
		ping_host->error = 0;
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
									int error, void *userptr)
{
	if (result == PING_RESULT_RESPONSE) {
		double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
		tlog(TLOG_INFO, "from %15s: seq=%d ttl=%d time=%.3f\n", host, seqno, ttl, rtt);
	} else if (result == PING_RESULT_TIMEOUT) {
		tlog(TLOG_INFO, "from %15s: seq=%d timeout\n", host, seqno);
	} else if (result == PING_RESULT_ERROR) {
		tlog(TLOG_DEBUG, "from %15s: error is %s\n", host, strerror(error));
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

	if (_fast_ping_create_icmp(ping_type) < 0) {
		goto errout;
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

static int _fast_ping_get_addr_by_tcp(const char *ip_str, int port, struct addrinfo **out_gai,
									  FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	FAST_PING_TYPE ping_type = 0;
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
	uint32_t addrkey = 0;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	unsigned int seed = 0;
	int ret = 0;
	struct fast_ping_fake_ip *fake = NULL;
	int fake_time_fd = -1;

	if (parse_ip(host, ip_str, &port) != 0) {
		goto errout;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
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

	fake = _fast_ping_fake_find(ping_host->type, gai->ai_addr, gai->ai_addrlen);
	if (fake) {
		fake_time_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (fake_time_fd < 0) {
			tlog(TLOG_ERROR, "timerfd_create failed, %s", strerror(errno));
			goto errout;
		}
		/* already take ownership by find. */
		ping_host->fake = fake;
		ping_host->fake_time_fd = fake_time_fd;
		fake = NULL;
	}

	addrkey = _fast_ping_hash_key(ping_host->sid, &ping_host->addr);

	_fast_ping_host_get(ping_host);
	_fast_ping_host_get(ping_host);
	// for ping race condition, get reference count twice
	if (_fast_ping_sendping(ping_host) != 0) {
		goto errout_remove;
	}

	pthread_mutex_lock(&ping.map_lock);
	_fast_ping_host_get(ping_host);
	if (hash_empty(ping.addrmap)) {
		_fast_ping_wakeup_thread();
	}
	hash_add(ping.addrmap, &ping_host->addr_node, addrkey);
	ping_host->run = 1;
	pthread_mutex_unlock(&ping.map_lock);
	freeaddrinfo(gai);
	_fast_ping_host_put(ping_host);
	return ping_host;
errout_remove:
	ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_ERROR, &ping_host->addr, ping_host->addr_len,
							 ping_host->seq, ping_host->ttl, NULL, ping_host->error, ping_host->userptr);
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

	if (fake_time_fd > 0) {
		close(fake_time_fd);
	}

	if (fake) {
		_fast_ping_fake_put(fake);
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
	int icmp_len = 0;
	struct fast_ping_packet *packet = (struct fast_ping_packet *)packet_data;
	struct icmp6_hdr *icmp6 = &packet->icmp6;
	struct cmsghdr *c = NULL;
	int hops = 0;

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

static struct fast_ping_packet *_fast_ping_icmp_packet(struct ping_host_struct *ping_host, struct msghdr *msg,
													   u_char *packet_data, int data_len)
{
	struct ip *ip = (struct ip *)packet_data;
	struct fast_ping_packet *packet = NULL;
	struct icmp *icmp = NULL;
	int hlen = 0;
	int icmp_len = 0;

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
		errno = ENETUNREACH;
		return NULL;
	}

	if (ping.no_unprivileged_ping) {
		if (ip->ip_p != IPPROTO_ICMP) {
			tlog(TLOG_ERROR, "ip type failed, %d:%d", ip->ip_p, IPPROTO_ICMP);
			return NULL;
		}

		if (icmp->icmp_id != ping.ident) {
			tlog(TLOG_ERROR, "ident failed, %d:%d", icmp->icmp_id, ping.ident);
			return NULL;
		}
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

static int _fast_ping_process_fake(struct ping_host_struct *ping_host, struct timeval *now)
{
	struct timeval tvresult = *now;
	struct timeval *tvsend = &ping_host->last;
	uint64_t exp;
	int ret;

	ret = read(ping_host->fake_time_fd, &exp, sizeof(uint64_t));
	if (ret < 0) {
		return -1;
	}

	ping_host->ttl = ping_host->fake->ttl;
	tv_sub(&tvresult, tvsend);
	if (ping_host->ping_callback) {
		_fast_ping_send_notify_event(ping_host, PING_RESULT_RESPONSE, ping_host->seq, ping_host->ttl, &tvresult);
	}

	ping_host->send = 0;

	if (ping_host->count == 1) {
		_fast_ping_host_remove(ping_host);
	}

	return 0;
}

static int _fast_ping_process_icmp(struct ping_host_struct *ping_host, struct timeval *now)
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
	unsigned int cookie = 0;
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
		_fast_ping_send_notify_event(ping_host, PING_RESULT_RESPONSE, ping_host->seq, ping_host->ttl, &tvresult);
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

static int _fast_ping_process(struct ping_host_struct *ping_host, struct epoll_event *event, struct timeval *now)
{
	int ret = -1;

	if (ping_host->fake != NULL) {
		ret = _fast_ping_process_fake(ping_host, now);
		return ret;
	}

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
	unsigned long i = 0;

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

static void _fast_ping_remove_all_fake_ip(void)
{
	struct fast_ping_fake_ip *fake = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(ping.fake, i, tmp, fake, node)
	{
		_fast_ping_fake_put(fake);
	}
}

static void _fast_ping_period_run(void)
{
	struct ping_host_struct *ping_host = NULL;
	struct ping_host_struct *ping_host_tmp = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;
	struct timeval now;
	struct timezone tz;
	struct timeval interval;
	int64_t millisecond = 0;
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
			_fast_ping_send_notify_event(ping_host, PING_RESULT_TIMEOUT, ping_host->seq, ping_host->ttl, &interval);
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

static void _fast_ping_process_notify_event(struct fast_ping_notify_event *ping_notify_event)
{
	struct ping_host_struct *ping_host = ping_notify_event->ping_host;
	if (ping_host == NULL) {
		return;
	}

	ping_host->ping_callback(ping_host, ping_host->host, ping_notify_event->ping_result, &ping_host->addr,
							 ping_host->addr_len, ping_notify_event->seq, ping_notify_event->ttl,
							 &ping_notify_event->tvresult, ping_host->error, ping_host->userptr);
}

static void *_fast_ping_notify_worker(void *arg)
{
	struct fast_ping_notify_event *ping_notify_event = NULL;

	while (atomic_read(&ping.run)) {
		pthread_mutex_lock(&ping.notify_lock);
		if (list_empty(&ping.notify_event_list)) {
			pthread_cond_wait(&ping.notify_cond, &ping.notify_lock);
		}

		ping_notify_event = list_first_entry_or_null(&ping.notify_event_list, struct fast_ping_notify_event, list);
		if (ping_notify_event) {
			list_del_init(&ping_notify_event->list);
		}
		pthread_mutex_unlock(&ping.notify_lock);

		if (ping_notify_event == NULL) {
			continue;
		}

		_fast_ping_process_notify_event(ping_notify_event);
		_fast_ping_release_notify_event(ping_notify_event);
	}

	return NULL;
}

static void _fast_ping_remove_all_notify_event(void)
{
	struct fast_ping_notify_event *notify_event = NULL;
	struct fast_ping_notify_event *tmp = NULL;
	list_for_each_entry_safe(notify_event, tmp, &ping.notify_event_list, list)
	{
		_fast_ping_process_notify_event(notify_event);
		_fast_ping_release_notify_event(notify_event);
	}
}

static void *_fast_ping_work(void *arg)
{
	struct epoll_event events[PING_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	unsigned long last = {0};
	struct timeval tvnow = {0};
	int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;

	setpriority(PRIO_PROCESS, 0, -5);

	sleep_time = sleep;
	now = get_tick_count() - sleep;
	last = now;
	expect_time = now + sleep;
	while (atomic_read(&ping.run)) {
		now = get_tick_count();
		if (sleep_time > 0) {
			sleep_time -= now - last;
			if (sleep_time <= 0) {
				sleep_time = 0;
			}
		}

		if (now >= expect_time) {
			if (last != now) {
				_fast_ping_period_run();
			}
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}
			expect_time += sleep;
		}
		last = now;

		pthread_mutex_lock(&ping.map_lock);
		if (hash_empty(ping.addrmap)) {
			sleep_time = -1;
		}
		pthread_mutex_unlock(&ping.map_lock);

		num = epoll_wait(ping.epoll_fd, events, PING_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		if (sleep_time == -1) {
			expect_time = get_tick_count();
		}

		if (num == 0) {
			continue;
		}

		gettimeofday(&tvnow, NULL);
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			/* read event */
			if (event->data.fd == ping.event_fd) {
				uint64_t value;
				int unused __attribute__((unused));
				unused = read(ping.event_fd, &value, sizeof(uint64_t));
				continue;
			}

			struct ping_host_struct *ping_host = (struct ping_host_struct *)event->data.ptr;
			_fast_ping_process(ping_host, event, &tvnow);
		}
	}

	close(ping.epoll_fd);
	ping.epoll_fd = -1;

	return NULL;
}

static int _fast_ping_init_wakeup_event(void)
{
	int fdevent = -1;
	fdevent = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fdevent < 0) {
		tlog(TLOG_ERROR, "create eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLERR;
	event.data.fd = fdevent;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fdevent, &event) != 0) {
		tlog(TLOG_ERROR, "set eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	ping.event_fd = fdevent;

	return 0;
errout:
	return -1;
}

int fast_ping_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret = 0;
	bool_print_log = 1;

	if (is_fast_ping_init == 1) {
		return -1;
	}

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
	pthread_mutex_init(&ping.notify_lock, NULL);
	pthread_cond_init(&ping.notify_cond, NULL);

	INIT_LIST_HEAD(&ping.notify_event_list);

	hash_init(ping.addrmap);
	hash_init(ping.fake);
	ping.no_unprivileged_ping = !has_unprivileged_ping();
	ping.ident = (getpid() & 0XFFFF);
	atomic_set(&ping.run, 1);

	ping.epoll_fd = epollfd;
	ret = pthread_create(&ping.tid, &attr, _fast_ping_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create ping work thread failed, %s\n", strerror(ret));
		goto errout;
	}

	ret = pthread_create(&ping.notify_tid, &attr, _fast_ping_notify_worker, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create ping notifier work thread failed, %s\n", strerror(ret));
		goto errout;
	}

	ret = _fast_ping_init_wakeup_event();
	if (ret != 0) {
		tlog(TLOG_ERROR, "init wakeup event failed, %s\n", strerror(errno));
		goto errout;
	}

	is_fast_ping_init = 1;
	return 0;
errout:
	if (ping.notify_tid) {
		void *retval = NULL;
		atomic_set(&ping.run, 0);
		pthread_cond_signal(&ping.notify_cond);
		pthread_join(ping.notify_tid, &retval);
		ping.notify_tid = 0;
	}

	if (ping.tid) {
		void *retval = NULL;
		atomic_set(&ping.run, 0);
		_fast_ping_wakeup_thread();
		pthread_join(ping.tid, &retval);
		ping.tid = 0;
	}

	if (epollfd > 0) {
		close(epollfd);
		ping.epoll_fd = -1;
	}

	if (ping.event_fd) {
		close(ping.event_fd);
		ping.event_fd = -1;
	}

	pthread_cond_destroy(&ping.notify_cond);
	pthread_mutex_destroy(&ping.notify_lock);
	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);
	memset(&ping, 0, sizeof(ping));

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
	if (is_fast_ping_init == 0) {
		return;
	}

	if (ping.notify_tid) {
		void *retval = NULL;
		atomic_set(&ping.run, 0);
		pthread_cond_signal(&ping.notify_cond);
		pthread_join(ping.notify_tid, &retval);
		ping.notify_tid = 0;
	}

	if (ping.tid) {
		void *ret = NULL;
		atomic_set(&ping.run, 0);
		_fast_ping_wakeup_thread();
		pthread_join(ping.tid, &ret);
		ping.tid = 0;
	}

	if (ping.event_fd > 0) {
		close(ping.event_fd);
		ping.event_fd = -1;
	}

	_fast_ping_close_fds();
	_fast_ping_remove_all();
	_fast_ping_remove_all_fake_ip();
	_fast_ping_remove_all_notify_event();

	pthread_cond_destroy(&ping.notify_cond);
	pthread_mutex_destroy(&ping.notify_lock);
	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);

	is_fast_ping_init = 0;
}
