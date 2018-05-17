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

#include "dns_client.h"
#include "atomic.h"
#include "dns.h"
#include "fast_ping.h"
#include "hashtable.h"
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

#define DNS_MAX_HOSTNAME 256

#define DNS_MAX_EVENTS 64

#define DNS_HOSTNAME_LEN 128

struct dns_query_server {
	int fd;
	int type;
	char host[DNS_HOSTNAME_LEN];
	struct list_head list;
};

struct dns_client {
	pthread_t tid;
	int run;
	int epoll_fd;

	struct list_head dns_server_list;

	pthread_mutex_t map_lock;
	DECLARE_HASHTABLE(hostmap, 6);

	int udp;
	int tcp;
};
struct dns_query_struct {
	char domain[DNS_MAX_HOSTNAME];
	struct hlist_node host_node;
	void *user_ptr;
};

static struct dns_client client;

static dns_client_callback dns_callback;

static void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void _dns_client_period_run()
{

}

static int _dns_client_recv(unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *from, socklen_t from_len)
{
	int len;
	int i;
	int j;
	int qtype;
	int qclass;
	int ttl;
	char name[DNS_MAX_CNAME_LEN];
	int rr_count;
	struct dns_rrs *rrs = NULL;
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;

	len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (len != 0) {
		printf("decode failed.\n");
		return -1;
	}

	printf("qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d\n", packet->head.qdcount, packet->head.ancount, packet->head.nscount,
		   packet->head.nrcount, inpacket_len);

	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		dns_get_domain(rrs, name, 128, &qtype, &qclass);
		printf("domain: %s qtype: %d  qclass: %d\n", name, qtype, qclass);
	}

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				dns_get_A(rrs, name, 128, &ttl, addr);
				printf("%s %d : %d.%d.%d.%d\n", name, ttl, addr[0], addr[1], addr[2], addr[3]);
				dns_callback(name, addr, DNS_T_A, 0);
			} break;
			case DNS_T_NS:
			case DNS_T_CNAME: {
				char cname[128];
				dns_get_CNAME(rrs, name, 128, &ttl, cname, 128);
				printf("%s %d : %s\n", name, ttl, cname);
			} break;
			default:
				break;
			}
		}
	}

	printf("\n");

	return 0;
}

static int _dns_client_process(struct dns_query_struct *dns_query, struct timeval *now)
{
	int len;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);

	len = recvfrom(client.udp, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
	if (len < 0) {
		fprintf(stderr, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}

	return _dns_client_recv(inpacket, len, &from, from_len);
}

static void *_dns_client_work(void *arg)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num;
	int i;
	struct timeval last = {0};
	struct timeval now = {0};
	struct timeval diff = {0};
	uint millisec = 0;

	while (client.run) {
		diff = now;
		tv_sub(&diff, &last);
		millisec = diff.tv_sec * 1000 + diff.tv_usec / 1000;
		if (millisec >= 1000) {
			_dns_client_period_run();
			last = now;
		}

		num = epoll_wait(client.epoll_fd, events, DNS_MAX_EVENTS, 1000);
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
			struct dns_query_struct *dns_query = (struct dns_query_struct *)event->data.ptr;
			_dns_client_process(dns_query, &now);
		}
	}

	close(client.epoll_fd);
	client.epoll_fd = -1;

	return NULL;
}

static int _dns_client_send_packet(void *packet, int len)
{
	struct sockaddr_in to;
	int send_len = 0;
	socklen_t to_len = sizeof(to);

	memset(&to, 0, sizeof(to));
	to.sin_addr.s_addr = inet_addr("192.168.1.1");
	to.sin_port = htons(53);

	send_len = sendto(client.udp, packet, len, 0, (struct sockaddr *)&to, to_len);
	if (send_len != len) {
		printf("send to server failed.");
		return -1;
	}

	return 0;
}

static int _dns_client_send_request(struct dns_query_struct *request, char *doamin)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int encode_len;

	struct dns_head head;
	memset(&head, 0, sizeof(head));
	head.rcode = 0;
	head.qr = DNS_OP_QUERY;
	head.rd = 1;
	head.ra = 0;
	head.id = 1;

	dns_packet_init(packet, DNS_PACKSIZE, &head);
	dns_add_domain(packet, doamin, DNS_T_A, DNS_C_IN);
	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		printf("encode request failed.\n");
		return -1;
	}

	return _dns_client_send_packet(inpacket, encode_len);
}

int dns_client_query(char *domain, void *user_ptr)
{
	struct dns_query_struct *request = NULL;
	int ret = 0;
	request = malloc(sizeof(*request));
	if (request == NULL) {
		return -1;
	}
	INIT_HLIST_NODE(&request->host_node);
	strncpy(request->domain, domain, DNS_MAX_CNAME_LEN);
	request->user_ptr = user_ptr;

	ret =_dns_client_send_request(request, domain);
    if (ret != 0) {
		goto errout;
	}
	free(request);
	return 0;
errout:
	if (request) {
		free(request);
	}
	return -1;
}

int dns_register_callback(dns_client_callback callback)
{
	dns_callback = callback;
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

int dns_client_start(void)
{
	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.fd = client.udp;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, client.udp, &event) != 0) {
		fprintf(stderr, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int dns_client_socket(void)
{
	int fd = -1;
	struct addrinfo *gai = NULL;

	gai = _dns_server_getaddr(NULL, "54", SOCK_DGRAM, 0);
	if (gai == NULL) {
		fprintf(stderr, "get address failed.\n");
		goto errout;
	}

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		fprintf(stderr, "create socket failed.\n");
		goto errout;
	}

	client.udp = fd;
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

int dns_client_init()
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret;
	int fd = 1;

	if (client.epoll_fd > 0) {
		return -1;
	}

	memset(&client, 0, sizeof(client));
	pthread_attr_init(&attr);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		fprintf(stderr, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	fd = dns_client_socket();
	if (fd < 0) {
		fprintf(stderr, "create client socket failed.\n");
		goto errout;
	}

	client.run = 1;
	client.udp = fd;
	ret = pthread_create(&client.tid, &attr, _dns_client_work, NULL);
	if (ret != 0) {
		fprintf(stderr, "create client work thread failed, %s\n", strerror(errno));
		goto errout;
	}

	pthread_mutex_init(&client.map_lock, 0);
	hash_init(client.hostmap);
	client.epoll_fd = epollfd;

    if (dns_client_start()) {
		fprintf(stderr, "start client failed.\n");
		goto errout;
	}

	return 0;
errout:
	if (client.tid > 0) {
		void *retval = NULL;
		client.run = 0;
		pthread_join(client.tid, &retval);
	}

	if (fd > 0) {
		close(fd);
	}

	if (epollfd) {
		close(epollfd);
	}

	pthread_mutex_destroy(&client.map_lock);

	return -1;
}

void dns_client_exit()
{
	if (client.tid > 0) {
		void *ret = NULL;
		client.run = 0;
		pthread_join(client.tid, &ret);
	}

	if (client.udp > 0) {
		close(client.udp);
	}

	pthread_mutex_destroy(&client.map_lock);
}