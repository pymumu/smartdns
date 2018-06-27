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
#define DNS_TCP_BUFFER (8 * 1024)

/* dns client */
struct dns_client {
	pthread_t tid;
	int run;
	int epoll_fd;

	/* dns server list */
	pthread_mutex_t server_list_lock;
	struct list_head dns_server_list;

	/* query list */
	pthread_mutex_t dns_request_lock;
	struct list_head dns_request_list;

	/* query doman hash table, key: sid + domain */
	pthread_mutex_t domain_map_lock;
	DECLARE_HASHTABLE(domain_map, 6);
};

struct dns_server_buff {
	unsigned char data[DNS_TCP_BUFFER];
	unsigned short len;
};

/* dns server information */
struct dns_server_info {
	struct list_head list;
	/* server ping handle */
	struct ping_host_struct *ping_host;

	/* server type */
	dns_server_type_t type;

	/* client socket */
	int fd;

	struct dns_server_buff send_buff;
	struct dns_server_buff recv_buff;

	time_t last_send;
	time_t last_recv;

	/* server addr info */
	unsigned short ai_family;

	socklen_t ai_addrlen;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};
};

/* dns replied server info */
struct dns_query_replied {
	struct hlist_node node;
	socklen_t addr_len;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};
};

/* query struct */
struct dns_query_struct {
	atomic_t refcnt;
	/* query id, hash key sid + domain*/
	char domain[DNS_MAX_CNAME_LEN];
	unsigned short sid;
	struct hlist_node domain_node;

	struct list_head dns_request_list;
	struct list_head period_list;

	/* dns query type */
	int qtype;

	/* dns query number */
	atomic_t dns_request_sent;
	unsigned long send_tick;

	/* caller notification */
	dns_client_callback callback;
	void *user_ptr;

	/* replied hash table */
	DECLARE_HASHTABLE(replied_map, 4);
};

static struct dns_client client;
static atomic_t dns_client_sid = ATOMIC_INIT(0);

/* get addr info */
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

/* check whether server exists */
int _dns_client_server_exist(struct addrinfo *gai, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->ai_addrlen != gai->ai_addrlen || server_info->ai_family != gai->ai_family) {
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

/* add dns server information */
int _dns_client_server_add(char *server_ip, struct addrinfo *gai, dns_server_type_t server_type)
{
	struct dns_server_info *server_info = NULL;

	if (_dns_client_server_exist(gai, server_type) == 0) {
		tlog(TLOG_WARN, "server exists.");
		goto errout;
	}

	server_info = malloc(sizeof(*server_info));
	if (server_info == NULL) {
		goto errout;
	}
	memset(server_info, 0, sizeof(*server_info));
	server_info->ai_family = gai->ai_family;
	server_info->ai_addrlen = gai->ai_addrlen;
	server_info->type = server_type;
	server_info->fd = 0;

	if (gai->ai_addrlen > sizeof(server_info->in6)) {
		tlog(TLOG_ERROR, "addr len invalid, %d, %zd, %d", gai->ai_addrlen, sizeof(server_info->addr), server_info->ai_family);
		goto errout;
	}
	memcpy(&server_info->addr, gai->ai_addr, gai->ai_addrlen);

	/* start ping task */
#if 0
	server_info->ping_host = fast_ping_start(server_ip, 0, 60000, 1000, NULL, server_info);
	if (server_info->ping_host == NULL) {
		tlog(TLOG_ERROR, "start ping failed.");
		goto errout;
	}
#endif

	/* add to list */
	pthread_mutex_lock(&client.server_list_lock);
	list_add(&server_info->list, &client.dns_server_list);
	pthread_mutex_unlock(&client.server_list_lock);
	return 0;
errout:
	if (server_info) {
		if (server_info->ping_host) {
			fast_ping_stop(server_info->ping_host);
		}
		free(server_info);
	}

	return -1;
}

/* remove all servers information */
void _dns_client_server_remove_all(void)
{
	struct dns_server_info *server_info, *tmp;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		list_del(&server_info->list);
		/* stop ping task */
		if (server_info->ping_host) {
			if (fast_ping_stop(server_info->ping_host) != 0) {
				tlog(TLOG_ERROR, "stop ping failed.\n");
			}
		}
		if (server_info->fd > 0) {
			close(server_info->fd);
		}
		free(server_info);
	}
	pthread_mutex_unlock(&client.server_list_lock);
}

/* remove single server */
int _dns_client_server_remove(char *server_ip, struct addrinfo *gai, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;

	/* find server and remove */
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->ai_addrlen != gai->ai_addrlen || server_info->ai_family != gai->ai_family) {
			continue;
		}

		if (memcmp(&server_info->addr, gai->ai_addr, gai->ai_addrlen) != 0) {
			continue;
		}
		list_del(&server_info->list);
		pthread_mutex_unlock(&client.server_list_lock);
		if (fast_ping_stop(server_info->ping_host) != 0) {
			tlog(TLOG_ERROR, "stop ping failed.\n");
		}
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
		tlog(TLOG_ERROR, "server type is invalid.");
		return -1;
	}

	if (server_type == DNS_SERVER_UDP) {
		sock_type = SOCK_DGRAM;
	} else {
		sock_type = SOCK_STREAM;
	}

	/* get addr info */
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

void _dns_client_query_get(struct dns_query_struct *query)
{
	atomic_inc(&query->refcnt);
}

void _dns_client_query_release(struct dns_query_struct *query)
{
	int refcnt = atomic_dec_return(&query->refcnt);
	int bucket = 0;
	struct dns_query_replied *replied_map;
	struct hlist_node *tmp;

	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: refcnt is %d", refcnt);
			abort();
		}
		return;
	}

	/* notify caller query end */
	if (query->callback) {
		query->callback(query->domain, DNS_QUERY_END, NULL, NULL, 0, query->user_ptr);
	}

	/* free resource */
	pthread_mutex_lock(&client.domain_map_lock);
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);

	hash_for_each_safe(query->replied_map, bucket, tmp, replied_map, node)
	{
		hash_del(&replied_map->node);
		free(replied_map);
	}
	memset(query, 0, sizeof(*query));
	free(query);
}

void _dns_client_query_remove(struct dns_query_struct *query)
{
	/* remove query from period check list, and release reference*/
	pthread_mutex_lock(&client.domain_map_lock);
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);

	_dns_client_query_release(query);
}

void _dns_client_query_remove_all(void)
{
	struct dns_query_struct *query, *tmp;
	LIST_HEAD(check_list);

	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		list_add(&query->period_list, &check_list);
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	list_for_each_entry_safe(query, tmp, &check_list, period_list)
	{
		list_del_init(&query->period_list);
		_dns_client_query_remove(query);
	}

	return;
}

void _dns_client_period_run(void)
{
	struct dns_query_struct *query, *tmp;
	struct dns_server_info *server_info;
	LIST_HEAD(check_list);

	unsigned long now = get_tick_count();

	/* get query which timed out to check list */
	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		if (now - query->send_tick >= 1000) {
			list_add(&query->period_list, &check_list);
			_dns_client_query_get(query);
		}
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	list_for_each_entry_safe(query, tmp, &check_list, period_list)
	{
		/* free timed out query, and notify caller */
		list_del_init(&query->period_list);
		_dns_client_query_remove(query);
		_dns_client_query_release(query);

		/* For udp nat case.
		 * when router reconnect to internet, udp port may always marked as UNREPLIED.
		 * dns query will timeout, and cannot reconnect again,
		 * create a new socket to communicate.
		 */
		pthread_mutex_lock(&client.server_list_lock);
		list_for_each_entry(server_info, &client.dns_server_list, list)
		{
			if (server_info->last_send - 5 > server_info->last_recv) {
				if (server_info->fd > 0) {
					close(server_info->fd);
					server_info->fd = -1;
				}
			}
		}
		pthread_mutex_unlock(&client.server_list_lock);
	}

	return;
}

static struct dns_query_struct *_dns_client_get_request(unsigned short sid, char *domain)
{
	struct dns_query_struct *query = NULL;
	struct dns_query_struct *query_result = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int key;

	/* get query by hash key : id + domain */
	key = hash_string(domain);
	key = jhash(&sid, sizeof(sid), key);
	pthread_mutex_lock(&client.domain_map_lock);
	hash_for_each_possible_safe(client.domain_map, query, tmp, domain_node, key)
	{
		if (sid != query->sid) {
			continue;
		}

		if (strncmp(query->domain, domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		query_result = query;
		break;
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	return query_result;
}

int _dns_replied_check_add(struct dns_query_struct *dns_query, struct sockaddr *addr, socklen_t addr_len)
{
	int key = 0;
	struct dns_query_replied *replied_map = NULL;

	if (addr_len > sizeof(struct sockaddr_in6)) {
		tlog(TLOG_ERROR, "addr length is invalid.");
		return -1;
	}

	/* avoid multiple replies from one server */
	key = jhash(addr, addr_len, 0);
	hash_for_each_possible(dns_query->replied_map, replied_map, node, key)
	{
		/* already replied, ignore this reply */
		if (memcmp(&replied_map->addr, addr, addr_len) == 0) {
			return -1;
		}
	}

	replied_map = malloc(sizeof(*replied_map));
	if (replied_map == NULL) {
		tlog(TLOG_ERROR, "malloc failed");
		return -1;
	}

	/* add address info to check hashtable */
	memcpy(&replied_map->addr, addr, addr_len);
	hash_add(dns_query->replied_map, &replied_map->node, key);
	return 0;
}

static int _dns_client_recv(unsigned char *inpacket, int inpacket_len, struct sockaddr *from, socklen_t from_len)
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

	/* decode domain from udp packet */
	len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (len != 0) {
		tlog(TLOG_ERROR, "decode failed, packet len = %d, tc=%d, %d\n", inpacket_len, packet->head.tc, packet->head.id);
		return -1;
	}

	/* not answer, return error */
	if (packet->head.qr != DNS_OP_IQUERY) {
		tlog(TLOG_ERROR, "message type error.\n");
		return -1;
	}

	tlog(TLOG_DEBUG, "qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, ra = %d, rcode = %d\n", packet->head.qdcount,
		 packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len, packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra,
		 packet->head.rcode);

	/* get question */
	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		dns_get_domain(rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
		tlog(TLOG_DEBUG, "domain: %s qtype: %d  qclass: %d\n", domain, qtype, qclass);
	}

	/* get query reference */
	query = _dns_client_get_request(packet->head.id, domain);
	if (query == NULL) {
		return 0;
	}

	/* avoid multiple replies */
	if (_dns_replied_check_add(query, (struct sockaddr *)from, from_len) != 0) {
		return 0;
	}

	request_num = atomic_dec_return(&query->dns_request_sent);
	if (request_num < 0) {
		tlog(TLOG_ERROR, "send count is invalid, %d", request_num);
		return -1;
	}

	/* notify caller dns query result */
	if (query->callback) {
		ret = query->callback(query->domain, DNS_QUERY_RESULT, packet, inpacket, inpacket_len, query->user_ptr);
	}

	if (request_num == 0 || ret) {
		/* if all server replied, or done, stop query, release resource */
		_dns_client_query_remove(query);
	}

	return ret;
}

static int _dns_client_create_socket_udp(struct dns_server_info *server_info)
{
	int fd = 0;
	struct epoll_event event;

	fd = socket(server_info->ai_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed.");
		goto errout;
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	server_info->fd = fd;

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

static int _DNS_client_create_socket_tcp(struct dns_server_info *server_info)
{
	int fd = 0;
	struct epoll_event event;

	fd = socket(server_info->ai_family, SOCK_STREAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed.");
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	if (connect(fd, (struct sockaddr *)&server_info->addr, server_info->ai_addrlen) != 0) {
		if (errno != EINPROGRESS) {
			tlog(TLOG_ERROR, "connect failed.");
			goto errout;
		}
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	server_info->fd = fd;

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

static int _dns_client_create_socket(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_UDP) {
		return _dns_client_create_socket_udp(server_info);
	} else if (server_info->type == DNS_SERVER_TCP) {
		return _DNS_client_create_socket_tcp(server_info);
	} else {
		return -1;
	}

	return 0;
}

static int _dns_client_process_udp(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int len;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	char from_host[DNS_MAX_CNAME_LEN];

	/* receive from udp */
	len = recvfrom(server_info->fd, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}

	tlog(TLOG_DEBUG, "recv udp, from %s", gethost_by_addr(from_host, (struct sockaddr *)&from, from_len));

	time(&server_info->last_recv);
	if (_dns_client_recv(inpacket, len, (struct sockaddr *)&from, from_len) != 0) {
		return -1;
	}

	return 0;
}

static int _dns_client_process_tcp(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int len;
	int ret = -1;
	unsigned char *inpacket_data = server_info->recv_buff.data;
	char from_host[DNS_MAX_CNAME_LEN];

	/* when connected */
	if (event->events & EPOLLOUT) {
		struct epoll_event event;
		pthread_mutex_lock(&client.server_list_lock);
		if (server_info->send_buff.len > 0) {
			/* send data in send_buffer */
			len = send(server_info->fd, server_info->send_buff.data, server_info->send_buff.len, MSG_NOSIGNAL);
			if (len < 0) {
				pthread_mutex_unlock(&client.server_list_lock);
				return -1;
			}

			server_info->send_buff.len -= len;
			if (server_info->send_buff.len > 0) {
				memmove(server_info->send_buff.data, server_info->send_buff.data + len, server_info->send_buff.len);
			}
		}
		pthread_mutex_unlock(&client.server_list_lock);

		/* still remain data, retry */
		if (server_info->send_buff.len > 0) {
			return 0;
		}

		/* clear epllout event */
		memset(&event, 0, sizeof(event));
		event.events = EPOLLIN;
		event.data.ptr = server_info;
		if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed.");
			return -1;
		}

		return 0;
	}

	/* receive from tcp */
	len = recv(server_info->fd, server_info->recv_buff.data + server_info->recv_buff.len, DNS_TCP_BUFFER - server_info->recv_buff.len, 0);
	if (len < 0) {
		/* no data to recv, try again */
		if (errno == EAGAIN) {
			return 0;
		}
		
		/* FOR GFW */
		if (errno == ECONNRESET) {
			goto errout;
		}

		tlog(TLOG_ERROR, "recv failed, %s, %d\n", strerror(errno), errno);
		goto errout;
	}

	/* peer server close */
	if (len == 0) {
		pthread_mutex_lock(&client.server_list_lock);
		close(server_info->fd);
		server_info->fd = 0;
		server_info->recv_buff.len = 0;
		if (server_info->send_buff.len > 0) {
			/* still remain request data, reconnect and send*/
			ret = _dns_client_create_socket(server_info);
		} else {
			ret = 0;
		}
		pthread_mutex_unlock(&client.server_list_lock);
		tlog(TLOG_DEBUG, "peer close, left = %d", server_info->send_buff.len);
		return ret;
	}

	time(&server_info->last_recv);

	server_info->recv_buff.len += len;
	if (server_info->recv_buff.len < 2) {
		/* wait and recv */
		return 0;
	}

	while (1) {
		/* tcp result format 
	 	 * | len (short) | dns query result | 
	 	 */
		inpacket_data = server_info->recv_buff.data;
		len = ntohs(*((unsigned short *)(inpacket_data)));
		if (len <= 0 || len >= DNS_IN_PACKSIZE) {
			/* data len is invalid */
			goto errout;
		}

		if (len > server_info->recv_buff.len - 2) {
			/* len is not expceded, wait and recv */
			break;
		}

		inpacket_data = server_info->recv_buff.data + 2;
		tlog(TLOG_DEBUG, "recv tcp from %s, len = %d", gethost_by_addr(from_host, (struct sockaddr *)&server_info->addr, server_info->ai_addrlen), len);

		/* process result */
		if (_dns_client_recv(inpacket_data, len, &server_info->addr, server_info->ai_addrlen) != 0) {
			goto errout;
		}
		len += 2;
		server_info->recv_buff.len -= len;

		/* move to next result */
		if (server_info->recv_buff.len > 0) {
			memmove(server_info->recv_buff.data, server_info->recv_buff.data + len, server_info->recv_buff.len);
		} else {
			break;
		}
	}

	return 0;

errout:
	pthread_mutex_lock(&client.server_list_lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	if (server_info->fd > 0) {
		close(server_info->fd);
		server_info->fd = -1;
	}
	pthread_mutex_unlock(&client.server_list_lock);

	return -1;
}

static int _dns_client_process(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	if (server_info->type == DNS_SERVER_UDP) {
		/* receive from udp */
		return _dns_client_process_udp(server_info, event, now);
	} else if (server_info->type == DNS_SERVER_TCP) {
		/* receive from tcp */
		return _dns_client_process_tcp(server_info, event, now);
	} else {
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

	sleep_time = sleep;
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
			struct dns_server_info *server_info = (struct dns_server_info *)event->data.ptr;
			_dns_client_process(server_info, event, now);
		}
	}

	close(client.epoll_fd);
	client.epoll_fd = -1;

	return NULL;
}

static int _dns_client_send_udp(struct dns_server_info *server_info, void *packet, int len)
{
	int send_len = 0;
	send_len = sendto(server_info->fd, packet, len, 0, (struct sockaddr *)&server_info->addr, server_info->ai_addrlen);
	if (send_len != len) {
		return -1;
	}

	return 0;
}

static int _dns_client_send_data_to_buffer(struct dns_server_info *server_info, void *packet, int len)
{
	struct epoll_event event;

	if (DNS_TCP_BUFFER - server_info->send_buff.len < len) {
		return -1;
	}

	memcpy(server_info->send_buff.data + server_info->send_buff.len, packet, len);
	server_info->send_buff.len += len;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

static int _dns_client_send_tcp(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	int send_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	/* TCP query format
	 * | len (short) | dns query data | 
	 */
	*((unsigned short *)(inpacket)) = htons(len);
	memcpy(inpacket + 2, packet, len);
	len += 2;

	send_len = send(server_info->fd, inpacket, len, MSG_NOSIGNAL);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, len);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, len - send_len);
	}

	return 0;
}

static int _dns_client_send_packet(struct dns_query_struct *query, void *packet, int len)
{
	struct dns_server_info *server_info, *tmp;
	int ret = 0;
	int send_err = 0;

	query->send_tick = get_tick_count();

	/* send query to all dns servers */
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->fd <= 0) {
			ret = _dns_client_create_socket(server_info);
			if (ret != 0) {
				continue;
			}
		}

		atomic_inc(&query->dns_request_sent);
		switch (server_info->type) {
		case DNS_SERVER_UDP:
			/* udp query */
			ret = _dns_client_send_udp(server_info, packet, len);
			send_err = errno;
			break;
		case DNS_SERVER_TCP:
			/* tcp query */
			ret = _dns_client_send_tcp(server_info, packet, len);
			send_err = errno;
			break;
		default:
			/* unsupport query type */
			ret = -1;
			break;
		}

		if (ret != 0) {
			char server_addr[128];
			tlog(TLOG_ERROR, "send query to %s failed, %s", gethost_by_addr(server_addr, &server_info->addr, server_info->ai_addrlen), strerror(send_err));
			atomic_dec(&query->dns_request_sent);
			continue;
		}
		time(&server_info->last_send);
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

	/* init dns packet head */
	struct dns_head head;
	memset(&head, 0, sizeof(head));
	head.id = query->sid;
	head.qr = DNS_QR_QUERY;
	head.opcode = DNS_OP_QUERY;
	head.aa = 0;
	head.rd = 1;
	head.ra = 0;
	head.rcode = 0;

	dns_packet_init(packet, DNS_PACKSIZE, &head);

	/* add question */
	dns_add_domain(packet, doamin, query->qtype, DNS_C_IN);

	/* encode packet */
	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		tlog(TLOG_ERROR, "encode query failed.");
		return -1;
	}

	/* send query packet */
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
	hash_init(query->replied_map);
	strncpy(query->domain, domain, DNS_MAX_CNAME_LEN);
	query->user_ptr = user_ptr;
	query->callback = callback;
	query->qtype = qtype;
	query->send_tick = 0;
	query->sid = atomic_inc_return(&dns_client_sid);

	_dns_client_query_get(query);
	/* add query to hashtable */
	key = hash_string(domain);
	key = jhash(&query->sid, sizeof(query->sid), key);
	pthread_mutex_lock(&client.domain_map_lock);
	list_add_tail(&query->dns_request_list, &client.dns_request_list);
	hash_add(client.domain_map, &query->domain_node, key);
	pthread_mutex_unlock(&client.domain_map_lock);

	/* send query */
	_dns_client_query_get(query);
	ret = _dns_client_send_query(query, domain);
	if (ret != 0) {
		goto errout_del_list;
	}

	tlog(TLOG_INFO, "send request %s, id %d\n", domain, query->sid);
	_dns_client_query_release(query);

	return 0;
errout_del_list:
	atomic_dec(&query->refcnt);
	pthread_mutex_lock(&client.domain_map_lock);
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);
	_dns_client_query_release(query);
errout:
	if (query) {
		tlog(TLOG_ERROR, "release %p", query);
		free(query);
	}
	return -1;
}

int dns_client_init()
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret;

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

	pthread_mutex_init(&client.server_list_lock, 0);
	INIT_LIST_HEAD(&client.dns_server_list);

	pthread_mutex_init(&client.domain_map_lock, 0);
	hash_init(client.domain_map);
	INIT_LIST_HEAD(&client.dns_request_list);

	client.epoll_fd = epollfd;
	client.run = 1;

	/* start work task */
	ret = pthread_create(&client.tid, &attr, _dns_client_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create client work thread failed, %s\n", strerror(errno));
		goto errout;
	}

	return 0;
errout:
	if (client.tid > 0) {
		void *retval = NULL;
		client.run = 0;
		pthread_join(client.tid, &retval);
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

	/* free all resouces */
	_dns_client_server_remove_all();
	_dns_client_query_remove_all();

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);
}
