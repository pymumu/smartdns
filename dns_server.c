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

#include "dns_server.h"
#include "dns.h"
#include "util.h"
#include "atomic.h"
#include "tlog.h"
#include "hashtable.h"
#include "list.h"
#include "dns_client.h"
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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define DNS_MAX_EVENTS 256

struct dns_server {
	int run;
	int epoll_fd;

	int fd;

	pthread_mutex_t map_lock;
	DECLARE_HASHTABLE(hostmap, 6);
};

struct dns_request {
	atomic_t refcnt;
	struct hlist_node map;
	char domain[DNS_MAX_CNAME_LEN];
	char alias[DNS_MAX_CNAME_LEN];
	unsigned short qtype;
	unsigned short id;
	unsigned short ss_family;
	socklen_t addr_len;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};

	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
	};
};

static struct dns_server server;

void _dns_server_period_run()
{
	return;
	unsigned char packet_data[DNS_PACKSIZE];
	unsigned char data[DNS_IN_PACKSIZE];

	struct dns_packet *packet = (struct dns_packet *)packet_data;

	struct dns_head head;
	memset(&head, 0, sizeof(head));
	head.rcode = 0;
	head.qr = 0;
	head.rd = 1;
	head.ra = 0;
	head.id = 1;

	int len;
	struct sockaddr_in to;
	socklen_t to_len = sizeof(to);

	dns_packet_init(packet, DNS_PACKSIZE, &head);
	dns_add_domain(packet, "www.huawei.com", DNS_T_A, 1);
	len = dns_encode(data, DNS_IN_PACKSIZE, packet);

	memset(&to, 0, sizeof(to));
	to.sin_addr.s_addr = inet_addr("192.168.1.1");
	to.sin_port = htons(53);

	len = sendto(server.fd, data, len, 0, (struct sockaddr *)&to, to_len);
	if (len < 0) {
		printf("send failed.");
	}
	printf("send.\n");
}

static int _dns_server_forward_request(unsigned char *inpacket, int inpacket_len)
{
	printf("forward request.\n");
	return -1;
}

static int _dns_recv_addr(struct dns_request *request, struct sockaddr_storage *from, socklen_t from_len)
{
	switch (from->ss_family) {
	case AF_INET:
		memcpy(&request->in, from, from_len);
		request->addr_len = from_len;
		break;
	case AF_INET6:
		memcpy(&request->in6, from, from_len);
		request->addr_len = from_len;
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static int _dns_add_rrs(struct dns_packet *packet, struct dns_request *request)
{
	int qtype;
	int ret = -1;

	qtype = request->qtype;

	switch (qtype) {
	case DNS_T_PTR: {
		char hostname[DNS_MAX_CNAME_LEN];
		if (getdomainname(hostname, DNS_MAX_CNAME_LEN) != 0) {
			if (gethostname(hostname, DNS_MAX_CNAME_LEN) != 0) {
				return -1;
			}
		}

		if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN) == 0) {
			if (gethostname(hostname, DNS_MAX_CNAME_LEN) != 0) {
				return -1;
			}
		}

		ret = dns_add_PTR(packet, DNS_RRS_AN, request->domain, 30, hostname);
	} break;
	case DNS_T_A:
		ret = dns_add_A(packet, DNS_RRS_AN, request->domain, 30, request->ipv4_addr);
		break;
	case DNS_T_AAAA:
		ret = dns_add_AAAA(packet, DNS_RRS_AN, request->domain, 30, request->ipv6_addr);
		break;
	default:
		break;
	}

	return ret;
}


static int _dns_reply(struct dns_request *request)
{
	unsigned char inpacket[DNS_IN_PACKSIZE];
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_head head;
	int ret = 0;
	int encode_len = 0;
	int send_len = 0;

	memset(&head, 0, sizeof(head));
	head.id = request->id;
	head.qr = DNS_OP_IQUERY;
	head.rd = 1;
	head.ra = 0;
	ret = dns_packet_init(packet, DNS_PACKSIZE, &head);
	if (ret != 0) {
		return -1;
	}

	ret = dns_add_domain(packet, request->domain, request->qtype, DNS_C_IN);
	if (ret != 0) {
		return -1;
	}

	ret = _dns_add_rrs(packet, request);
	if (ret != 0) {
		return -1;
	}

	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		return -1;
	}

	send_len = sendto(server.fd, inpacket, encode_len, 0, &request->addr, request->addr_len);
	if (send_len != encode_len) {
		printf("send failed.");
	}

	return 0;
}


static int dns_server_resolve_callback(char *domain, struct dns_result *result, void *user_ptr)
{
	struct dns_request *request = user_ptr;

	if (user_ptr == NULL) {
		return -1;
	}

	memcpy(request->ipv4_addr, result->addr_ipv4, 4);
	strncpy(request->alias, result->alias, DNS_MAX_CNAME_LEN);
	// memcpy(request->ipv6_addr, result->addr_ipv6, 16);
	request->qtype = DNS_T_A;

	printf("----------------%s--%d.%d.%d.%d-\n", domain, 
		request->ipv4_addr[0], 
		request->ipv4_addr[1], 
		request->ipv4_addr[2], 
		request->ipv4_addr[3]);
	_dns_reply(request);

	if (!atomic_dec_and_test(&request->refcnt)) {
		return 0;

	}

	tlog(TLOG_ERROR, "free query server %p\n", request);
	memset(request, 0, sizeof(*request));
	free(request);

	return 0;
}


static int _dns_server_recv(unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *from, socklen_t from_len)
{
	int decode_len;
	int ret = -1;
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_request *request = NULL;
	struct dns_rrs *rrs;
	int rr_count = 0;
	int i = 0;
	int qclass;
	int qtype;

	decode_len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (decode_len < 0) {
		printf("decode failed.\n");
		goto errout;
	}

	if (packet->head.qr != DNS_OP_QUERY) {
		goto errout;
	}

	request = malloc(sizeof(*request));
	if (request == NULL) {
		printf("malloc failed.\n");
		goto errout;
	}

	if (_dns_recv_addr(request, from, from_len) != 0) {
		goto errout;
	}

	request->id = packet->head.id;

	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	if (rr_count > 1) {
		goto errout;
	}

	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		ret = dns_get_domain(rrs, request->domain, sizeof(request->domain), &qtype, &qclass);
		if (ret != 0) {
			goto errout;
		}

		request->qtype = qtype;
	}

	switch (qtype) {
	case DNS_T_PTR:
		ret = _dns_reply(request);
		free(request);
		return ret;
		break;
	default:
		break;
	}

	tlog(TLOG_ERROR, "query server %p\n", request);
	atomic_set(&request->refcnt, 1);
	dns_client_query(request->domain, dns_server_resolve_callback, request);

	return 0;
errout:
	if (request) {
		ret = _dns_server_forward_request(inpacket, inpacket_len);
		free(request);
	}
	return ret;
}

static int _dns_server_process(unsigned long now)
{
	int len;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);

	len = recvfrom(server.fd, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
	if (len < 0) {
		fprintf(stderr, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}

	return _dns_server_recv(inpacket, len, &from, from_len);
}

int dns_server_run(void)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num;
	int i;
	unsigned long now = {0};
	int sleep = 1000;
	int sleep_time = 0;
	unsigned long expect_time = 0;

    now = get_tick_count() - sleep;
    expect_time = now + sleep;
    while (server.run) {
        now = get_tick_count();
        if (now - expect_time >= 0) {
            _dns_server_period_run();
            sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				
			}
            expect_time += sleep;
        }

		num = epoll_wait(server.epoll_fd, events, DNS_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		if (num == 0) {
			continue;
		}
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			if (event->data.fd != server.fd) {
				fprintf(stderr, "invalid fd\n");
				continue;
			}

			_dns_server_process(now);
		}
	}

	close(server.epoll_fd);
	server.epoll_fd = -1;

	return 0;
}

static struct addrinfo *_dns_server_getaddr(const char *host, const char *port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(host, port, &hints, &result) != 0) {
		fprintf(stderr, "get addr info failed. %s\n", strerror(errno));
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

int dns_server_start(void)
{
	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.fd = server.fd;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, server.fd, &event) != 0) {
		fprintf(stderr, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int dns_server_socket(void)
{
	int fd = -1;
	struct addrinfo *gai = NULL;

	gai = _dns_server_getaddr(NULL, "53", SOCK_DGRAM, 0);
	if (gai == NULL) {
		fprintf(stderr, "get address failed.\n");
		goto errout;
	}

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		fprintf(stderr, "create socket failed.\n");
		goto errout;
	}

	if (bind(fd, gai->ai_addr, gai->ai_addrlen) != 0) {
		fprintf(stderr, "bind failed.\n");
		goto errout;
	}

	server.fd = fd;
	freeaddrinfo(gai);

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}

	if (gai) {
		freeaddrinfo(gai);
	}
	return -1;
}

int dns_server_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int fd = -1;

	if (server.epoll_fd > 0) {
		return -1;
	}

	memset(&server, 0, sizeof(server));
	pthread_attr_init(&attr);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		fprintf(stderr, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	fd = dns_server_socket();
	if (fd < 0) {
		fprintf(stderr, "create server socket failed.\n");
		goto errout;
	}

	pthread_mutex_init(&server.map_lock, 0);
	hash_init(server.hostmap);
	server.epoll_fd = epollfd;
	server.fd = fd;
	server.run = 1;

	if (dns_server_start() != 0) {
		fprintf(stderr, "start service failed.\n");
		goto errout;
	}

	return 0;
errout:
	server.run = 0;

	if (fd > 0) {
		close(fd);
	}

	if (epollfd) {
		close(epollfd);
	}

	pthread_mutex_destroy(&server.map_lock);

	return -1;
}

void dns_server_exit(void)
{
	server.run = 0;

	if (server.fd > 0) {
		close(server.fd);
		server.fd = -1;
	}

	pthread_mutex_destroy(&server.map_lock);
}
