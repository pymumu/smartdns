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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

	pthread_mutex_t server_list_lock;
	struct list_head dns_server_list;

	pthread_mutex_t dns_request_lock;
	struct list_head dns_request_list;
	struct list_head dns_request_wait_list;

	pthread_mutex_t domain_map_lock;
	DECLARE_HASHTABLE(domain_map, 6);

	int udp;
};

struct dns_server_info {
	struct list_head list;
	struct ping_host_struct *ping_host;
	dns_server_type_t type;
	unsigned short ss_family;
	socklen_t addr_len;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};
};

struct dns_query_struct {
	atomic_t refcnt;
	unsigned short sid;
	struct list_head dns_request_list;
	struct hlist_node domain_node;
	char domain[DNS_MAX_CNAME_LEN];
	int qtype;
	atomic_t dns_request_sent;
	void *user_ptr;
	unsigned long send_tick;
	dns_client_callback callback;
};

static struct dns_client client;
static atomic_t dns_client_sid = ATOMIC_INIT(0);

static struct addrinfo *_dns_client_getaddr(const char *host, char *port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int ret = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret != 0) {
		tlog(TLOG_ERROR, "get addr info failed. %s\n", gai_strerror(errno));
		tlog(TLOG_ERROR, "host = %s, port = %s, type = %d, protocol = %d", host, port, type, protocol);
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

int _dns_client_server_exist(struct addrinfo *gai, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->addr_len != gai->ai_addrlen || server_info->ss_family != gai->ai_family) {
			continue;
		}

		if (server_info->type != server_type) {
			continue;
		}

		if (memcmp(&server_info->addr, gai->ai_addr, gai->ai_addrlen) != 0) {
			continue;
		}
		pthread_mutex_lock(&client.server_list_lock);
		return 0;
	}
	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

int _dns_client_server_add(char *server_ip, struct addrinfo *gai, dns_server_type_t server_type)
{
	struct dns_server_info *server_info = NULL;

	if (_dns_client_server_exist(gai, server_type) == 0) {
		goto errout;
	}

	server_info = malloc(sizeof(*server_info));
	if (server_info == NULL) {
		goto errout;
	}
	memset(server_info, 0, sizeof(*server_info));
	server_info->ss_family = gai->ai_family;
	server_info->addr_len = gai->ai_addrlen;
	server_info->type = server_type;
	if (gai->ai_addrlen > sizeof(server_info->in6)) {
		tlog(TLOG_ERROR, "addr len invalid, %d, %d, %d", gai->ai_addrlen, sizeof(server_info->addr), server_info->ss_family);
		goto errout;
	}
	memcpy(&server_info->addr, gai->ai_addr, gai->ai_addrlen);

	// if (fast_ping_start(server_ip, 0, 60000, NULL, server_info) == NULL) {
	// 	goto errout;
	// }

	pthread_mutex_lock(&client.server_list_lock);
	list_add(&server_info->list, &client.dns_server_list);
	pthread_mutex_unlock(&client.server_list_lock);
	return 0;
errout:
	if (server_info) {
		free(server_info);
	}

	return -1;
}

int _dns_client_server_remove(char *server_ip, struct addrinfo *gai, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->addr_len != gai->ai_addrlen || server_info->ss_family != gai->ai_family) {
			continue;
		}

		if (memcmp(&server_info->addr, gai->ai_addr, gai->ai_addrlen) != 0) {
			continue;
		}
		list_del(&server_info->list);
		pthread_mutex_unlock(&client.server_list_lock);
		// if (fast_ping_stop(server_info->ping_host) != 0) {
		// 	tlog(TLOG_ERROR, "stop ping failed.\n");
		// }
		free(server_info);
		return 0;
	}
	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

int _dns_client_server_operate(char *server_ip, int port, dns_server_type_t server_type, int operate)
{
	char port_s[8];
	int sock_type;
	int ret;
	struct addrinfo *gai = NULL;

	if (server_type >= DNS_SERVER_TYPE_END) {
		return -1;
	}

	if (server_type == DNS_SERVER_UDP) {
		sock_type = SOCK_DGRAM;
	} else {
		sock_type = SOCK_STREAM;
	}

	snprintf(port_s, 8, "%d", port);
	gai = _dns_client_getaddr(server_ip, port_s, sock_type, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed, %s:%d", server_ip, port);
		goto errout;
	}

	if (operate == 0) {
		ret = _dns_client_server_add(server_ip, gai, server_type);
		if (ret != 0) {
			goto errout;
		}
	} else {
		ret = _dns_client_server_remove(server_ip, gai, server_type);
		if (ret != 0) {
			goto errout;
		}
	}
	freeaddrinfo(gai);
	return 0;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}
	return -1;
}

int dns_add_server(char *server_ip, int port, dns_server_type_t server_type)
{
	return _dns_client_server_operate(server_ip, port, server_type, 0);
}

int dns_remove_server(char *server_ip, int port, dns_server_type_t server_type)
{
	return _dns_client_server_operate(server_ip, port, server_type, 1);
}

void _dns_client_query_release(struct dns_query_struct *query)
{
	int refcnt = atomic_dec_return(&query->refcnt);
	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: refcnt is %d", refcnt);
			abort();
		}
		return;
	}

	if (query->callback) {
		query->callback(query->domain, DNS_QUERY_END, NULL, NULL, 0, query->user_ptr);
	}

	memset(query, 0, sizeof(*query));
	free(query);
}

void _dns_client_query_remove(struct dns_query_struct *query, int locked)
{
	if (locked == 0) {
		pthread_mutex_lock(&client.domain_map_lock);
		list_del_init(&query->dns_request_list);
		hash_del(&query->domain_node);
		pthread_mutex_unlock(&client.domain_map_lock);
	} else {
		list_del_init(&query->dns_request_list);
		hash_del(&query->domain_node);
	}

	_dns_client_query_release(query);
}

void _dns_client_query_get(struct dns_query_struct *query)
{
	atomic_inc(&query->refcnt);
}

void _dns_client_period_run()
{
	struct dns_query_struct *query, *tmp;

	unsigned long now = get_tick_count();
	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		if (now - query->send_tick >= 1000) {
			_dns_client_query_remove(query, 1);
		}
	}
	pthread_mutex_unlock(&client.domain_map_lock);
	return;
}

static struct dns_query_struct *_dns_client_get_request(unsigned short sid, char *domain)
{
	struct dns_query_struct *query = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int key;

	key = hash_string(domain);
	key = jhash(&sid, sizeof(sid), key);
	pthread_mutex_lock(&client.domain_map_lock);
	hash_for_each_possible_safe(client.domain_map, query, tmp, domain_node, key)
	{
		if (strncmp(query->domain, domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}
		break;
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	return query;
}

static int _dns_client_recv(unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *from, socklen_t from_len)
{
	int len;
	int i;
	int qtype;
	int qclass;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_count;
	struct dns_rrs *rrs = NULL;
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int ret = 0;
	struct dns_query_struct *query;
	int request_num = 0;

	packet->head.tc = 0;
	len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (len != 0) {
		tlog(TLOG_ERROR, "decode failed, packet len = %d, tc=%d, %d\n", inpacket_len, packet->head.tc, packet->head.id);
		return -1;
	}

	if (packet->head.qr != DNS_OP_IQUERY) {
		tlog(TLOG_ERROR, "message type error.\n");
		return -1;
	}

	tlog(TLOG_DEBUG, "qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, rd = %d, ra = %d, rcode = %d\n", packet->head.qdcount,
		 packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len, packet->head.id, packet->head.rd, packet->head.ra, packet->head.rcode);

	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		dns_get_domain(rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
		tlog(TLOG_DEBUG, "domain: %s qtype: %d  qclass: %d\n", domain, qtype, qclass);
	}

	query = _dns_client_get_request(packet->head.id, domain);
	if (query == NULL) {
		return 0;
	}

	request_num = atomic_dec_return(&query->dns_request_sent);
	if (request_num < 0) {
		tlog(TLOG_ERROR, "send count is invalid, %d", request_num);
		return -1;
	}

	if (query->callback) {
		ret = query->callback(query->domain, DNS_QUERY_RESULT, packet, inpacket, inpacket_len, query->user_ptr);
	}

	if (request_num == 0 || ret) {
		_dns_client_query_remove(query, 0);
	}

	return ret;
}

static int _dns_client_process(struct dns_query_struct *dns_query, unsigned long now)
{
	int len;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	char from_host[DNS_MAX_CNAME_LEN];

	len = recvfrom(client.udp, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}

	tlog(TLOG_DEBUG, "recv from %s", gethost_by_addr(from_host, (struct sockaddr *)&from, from_len));

	if (_dns_client_recv(inpacket, len, &from, from_len) != 0) {
		int fd = open("dns.bin", O_CREAT | O_TRUNC | O_RDWR);
		write(fd, inpacket, len);
		close(fd);
		return -1;
	}

	return 0;
}

static void *_dns_client_work(void *arg)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num;
	int i;
	unsigned long now = {0};
	unsigned int sleep = 100;
	int sleep_time;
	unsigned int expect_time = 0;

	now = get_tick_count() - sleep;
	expect_time = now + sleep;
	while (client.run) {
		now = get_tick_count();
		if (now >= expect_time) {
			_dns_client_period_run();
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}
			expect_time += sleep;
		}

		num = epoll_wait(client.epoll_fd, events, DNS_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct dns_query_struct *dns_query = (struct dns_query_struct *)event->data.ptr;
			_dns_client_process(dns_query, now);
		}
	}

	close(client.epoll_fd);
	client.epoll_fd = -1;

	return NULL;
}

static int _dns_client_send_udp(struct dns_server_info *server_info, void *packet, int len)
{
	int send_len = 0;
	send_len = sendto(client.udp, packet, len, 0, (struct sockaddr *)&server_info->addr, server_info->addr_len);
	if (send_len != len) {
		tlog(TLOG_ERROR, "send to server failed.");
		return -1;
	}

	return 0;
}

static int _dns_client_send_packet(struct dns_query_struct *query, void *packet, int len)
{
	struct dns_server_info *server_info, *tmp;
	int ret = 0;

	query->send_tick = get_tick_count();
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		atomic_inc(&query->dns_request_sent);
		switch (server_info->type) {
		case DNS_SERVER_UDP:
			ret = _dns_client_send_udp(server_info, packet, len);
			break;
		default:
			ret = -1;
			break;
		}

		if (ret != 0) {
			atomic_dec(&query->dns_request_sent);
			continue;
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
	return 0;
}

static int _dns_client_send_query(struct dns_query_struct *query, char *doamin)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int encode_len;

	struct dns_head head;
	memset(&head, 0, sizeof(head));
	head.id = query->sid;
	head.qr = DNS_QR_QUERY;
	head.opcode = DNS_OP_QUERY;
	head.aa = 1;
	head.rd = 1;
	head.ra = 1;
	head.rcode = 0;

	dns_packet_init(packet, DNS_PACKSIZE, &head);
	dns_add_domain(packet, doamin, query->qtype, DNS_C_IN);
	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		tlog(TLOG_ERROR, "encode query failed.");
		return -1;
	}

	return _dns_client_send_packet(query, inpacket, encode_len);
}

int dns_client_query(char *domain, int qtype, dns_client_callback callback, void *user_ptr)
{
	struct dns_query_struct *query = NULL;
	int ret = 0;
	unsigned int key = 0;

	query = malloc(sizeof(*query));
	if (query == NULL) {
		goto errout;
	}
	memset(query, 0, sizeof(*query));
	INIT_HLIST_NODE(&query->domain_node);
	INIT_LIST_HEAD(&query->dns_request_list);
	atomic_set(&query->refcnt, 0);
	atomic_set(&query->dns_request_sent, 0);
	strncpy(query->domain, domain, DNS_MAX_CNAME_LEN);
	query->user_ptr = user_ptr;
	query->callback = callback;
	query->qtype = qtype;
	query->send_tick = 0;
	query->sid = atomic_inc_return(&dns_client_sid);

	_dns_client_query_get(query);
	key = hash_string(domain);
	key = jhash(&query->sid, sizeof(query->sid), key);
	pthread_mutex_lock(&client.domain_map_lock);
	list_add_tail(&query->dns_request_list, &client.dns_request_list);
	hash_add(client.domain_map, &query->domain_node, key);
	pthread_mutex_unlock(&client.domain_map_lock);

	ret = _dns_client_send_query(query, domain);
	if (ret != 0) {
		goto errout_del_list;
	}

	tlog(TLOG_INFO, "send request %s, id %d\n", domain, query->sid);

	return 0;
errout_del_list:
	atomic_dec(&query->refcnt);
	pthread_mutex_lock(&client.domain_map_lock);
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);
errout:
	if (query) {
		tlog(TLOG_ERROR, "release %p", query);
		free(query);
	}
	return -1;
}

int dns_client_query_raw(char *domain, int qtype, unsigned char *raw, int raw_len, void *user_ptr)
{
	return -1;
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

int dns_client_start(void)
{
	struct epoll_event event;
	event.events = EPOLLIN;
	event.data.fd = client.udp;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, client.udp, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int dns_client_socket(void)
{
	int fd = -1;
	struct addrinfo *gai = NULL;

	gai = _dns_server_getaddr(NULL, "53", SOCK_DGRAM, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed.\n");
		goto errout;
	}

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed.\n");
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

void dns_debug(void)
{
	unsigned char data[1024];
	int len;
	char buff[4096];

	int fd = open("dns.bin", O_RDWR);
	if (fd < 0) {
		return;
	}
	len = read(fd, data, 1024);
	close(fd);
	if (len < 0) {
		return;
	}

	struct dns_packet *packet = (struct dns_packet *)buff;
	if (dns_decode(packet, 4096, data, len) != 0) {
		tlog(TLOG_ERROR, "decode failed.\n");
	}

	memset(data, 0, sizeof(data));
	len = dns_encode(data, 1024, packet);
	if (len < 0) {
		tlog(TLOG_ERROR, "encode failed.\n");
	}

	fd = open("dns-cmp.bin", O_CREAT | O_TRUNC | O_RDWR);
		write(fd, data, len);
		close(fd);
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
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	fd = dns_client_socket();
	if (fd < 0) {
		tlog(TLOG_ERROR, "create client socket failed.\n");
		goto errout;
	}

	pthread_mutex_init(&client.server_list_lock, 0);
	INIT_LIST_HEAD(&client.dns_server_list);

	pthread_mutex_init(&client.domain_map_lock, 0);
	hash_init(client.domain_map);
	INIT_LIST_HEAD(&client.dns_request_wait_list);
	INIT_LIST_HEAD(&client.dns_request_list);

	client.epoll_fd = epollfd;
	client.run = 1;
	client.udp = fd;
	ret = pthread_create(&client.tid, &attr, _dns_client_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create client work thread failed, %s\n", strerror(errno));
		goto errout;
	}

	if (dns_client_start()) {
		tlog(TLOG_ERROR, "start client failed.\n");
		goto errout;
	}

	return 0;
errout:
	if (client.tid > 0) {
		void *retval = NULL;
		client.run = 0;
		pthread_join(client.tid, &retval);
	}

	if (client.udp > 0) {
		close(client.udp);
		client.udp = -1;
	}

	if (epollfd) {
		close(epollfd);
	}

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);

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

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);
}