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

#ifndef _FAST_PING_H_
#define _FAST_PING_H_

#define _GNU_SOURCE

#include "smartdns/fast_ping.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/tlog.h"

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

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
	FAST_PING_TCP_SYN,
	FAST_PING_UDP,
	FAST_PING_UDP6,
	FAST_PING_END,
} FAST_PING_TYPE;

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
	unsigned short seq;
	int ttl;
	struct timeval last;
	int interval;
	int timeout;
	int count;
	int send;
	int run;
	unsigned short sid;
	unsigned short port;
	unsigned short tcp_local_port;
	unsigned short ss_family;
	union {
		struct sockaddr addr;
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
	};
	socklen_t addr_len;
	struct fast_ping_packet packet;

	struct fast_ping_packet recv_packet_buffer;

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
	int fd_tcp_syn;
	struct ping_host_struct tcp_syn_host;
	int fd_tcp_syn6;
	struct ping_host_struct tcp_syn6_host;
	int fd_tcp_syn_bind;
	uint16_t tcp_syn_bind_port;
	struct sockaddr_in tcp_syn_bind_addr;
	int fd_tcp_syn6_bind;
	uint16_t tcp_syn6_bind_port;
	struct sockaddr_in6 tcp_syn6_bind_addr;

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

extern struct fast_ping_struct ping;
extern int bool_print_log;

uint32_t _fast_ping_hash_key(unsigned int sid, struct sockaddr *addr);

struct addrinfo *_fast_ping_getaddr(const char *host, const char *port, int type, int protocol);

int _fast_ping_get_addr_by_type(PING_TYPE type, const char *ip_str, int port, struct addrinfo **out_gai,
								FAST_PING_TYPE *out_ping_type);

void tv_sub(struct timeval *out, struct timeval *in);

int _fast_ping_getdomain(const char *host);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_FAST_PING_H_
