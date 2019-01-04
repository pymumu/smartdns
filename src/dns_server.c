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
#define _GNU_SOURCE
#include "dns_server.h"
#include "atomic.h"
#include "dns.h"
#include "dns_cache.h"
#include "dns_client.h"
#include "dns_conf.h"
#include "fast_ping.h"
#include "hashtable.h"
#include "list.h"
#include "tlog.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
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
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define DNS_MAX_EVENTS 256
#define DNS_SERVER_TMOUT_TTL (5 * 60)
#define DNS_CONN_BUFF_SIZE 4096
#define DNS_REQUEST_MAX_TIMEOUT 850
#define DNS_PING_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT)
#define DNS_TCPPING_START (300)
#define DNS_PING_TCP_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT - DNS_TCPPING_START)

struct dns_conn_buf {
	char buf[DNS_CONN_BUFF_SIZE];
	int buffsize;
	int size;
};

struct dns_server_conn {
	struct list_head list;
	atomic_t refcnt;
	dns_server_type_t type;
	int fd;
	struct dns_conn_buf recvbuff;
	struct dns_conn_buf sndbuff;

	socklen_t addr_len;
	struct sockaddr_storage addr;

	time_t last_request_time;
};

/* dns server data */
struct dns_server {
	int run;
	int epoll_fd;
	struct dns_server_conn udp_server;
	struct dns_server_conn tcp_server;

	/* dns request list */
	pthread_mutex_t request_list_lock;
	struct list_head request_list;
	struct list_head client_list;
};

/* ip address lists of domain */
struct dns_ip_address {
	struct hlist_node node;
	int hitnum;
	dns_type_t addr_type;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

struct dns_request {
	atomic_t refcnt;

	struct dns_server_conn *client;
	/* dns request list */
	struct list_head list;

	/* dns request timeout check list */
	struct list_head check_list;

	/* dns query */
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_head head;
	unsigned long send_tick;
	unsigned short qtype;
	unsigned short id;
	unsigned short rcode;
	unsigned short ss_family;
	socklen_t addr_len;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};

	int has_ping_result;
	int has_ping_tcp;
	int has_ptr;

	int has_cname;
	char cname[DNS_MAX_CNAME_LEN];
	int ttl_cname;

	int has_ipv4;
	int ping_ttl_v4;
	int ttl_v4;
	unsigned char ipv4_addr[DNS_RR_A_LEN];

	int has_ipv6;
	int ping_ttl_v6;
	int ttl_v6;
	unsigned char ipv6_addr[DNS_RR_AAAA_LEN];

	struct dns_soa soa;
	int has_soa;

	atomic_t notified;

	atomic_t adblock;

	/* send original raw packet to server/client like proxy */
	int passthrough;
	int request_wait;
	int prefetch;

	pthread_mutex_t ip_map_lock;

	int ip_map_num;
	DECLARE_HASHTABLE(ip_map, 4);

	struct dns_domain_rule *domain_rule;
};

static struct dns_server server;

static tlog_log *dns_audit;

static int _dns_server_forward_request(unsigned char *inpacket, int inpacket_len)
{
	tlog(TLOG_DEBUG, "forward request.\n");
	return -1;
}

static void _dns_server_audit_log(struct dns_request *request)
{
	char req_host[MAX_IP_LEN];
	char req_result[MAX_IP_LEN];
	char req_time[MAX_IP_LEN];
	struct tlog_time tm;

	if (dns_audit == NULL || !dns_conf_audit_enable) {
		return;
	}

	if (request->qtype == DNS_T_AAAA) {
		snprintf(req_result, sizeof(req_result), "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", request->ipv6_addr[0],
				 request->ipv6_addr[1], request->ipv6_addr[2], request->ipv6_addr[3], request->ipv6_addr[4], request->ipv6_addr[5], request->ipv6_addr[6],
				 request->ipv6_addr[7], request->ipv6_addr[8], request->ipv6_addr[9], request->ipv6_addr[10], request->ipv6_addr[11], request->ipv6_addr[12],
				 request->ipv6_addr[13], request->ipv6_addr[14], request->ipv6_addr[15]);
	} else if (request->qtype == DNS_T_A) {
		snprintf(req_result, sizeof(req_result), "%d.%d.%d.%d", request->ipv4_addr[0], request->ipv4_addr[1], request->ipv4_addr[2], request->ipv4_addr[3]);
	} else {
		return;
	}
	gethost_by_addr(req_host, &request->addr, request->addr_len);
	tlog_localtime(&tm);

	snprintf(req_time, sizeof(req_time), "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d]", tm.year, tm.mon, tm.mday, tm.hour, tm.min, tm.sec, tm.usec / 1000);

	tlog_printf(dns_audit, "%s %s query %s, type %d, result %s\n", req_time, req_host, request->domain, request->qtype, req_result);
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
	int ret = 0;
	char *domain = request->domain;
	if (request->has_ptr) {
		char hostname[DNS_MAX_CNAME_LEN];
		if (dns_conf_server_name[0] == 0) {
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

			if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN) == 0) {
				strncpy(hostname, "smartdns", DNS_MAX_CNAME_LEN);
			}
		} else {
			strncpy(hostname, dns_conf_server_name, DNS_MAX_CNAME_LEN);
		}

		ret = dns_add_PTR(packet, DNS_RRS_AN, request->domain, 30, hostname);
	}

	if (request->has_cname) {
		ret |= dns_add_CNAME(packet, DNS_RRS_AN, request->domain, request->ttl_cname, request->cname);
		domain = request->cname;
	}

	if (request->has_ipv4 && request->qtype == DNS_T_A) {
		ret |= dns_add_A(packet, DNS_RRS_AN, domain, request->ttl_v4, request->ipv4_addr);
	}

	if (request->has_ipv6 && request->qtype == DNS_T_AAAA) {
		if (request->has_ipv4) {
			ret |= dns_add_A(packet, DNS_RRS_AN, domain, request->ttl_v4, request->ipv4_addr);
		}
		ret |= dns_add_AAAA(packet, DNS_RRS_AN, domain, request->ttl_v6, request->ipv6_addr);
	}

	if (request->has_soa) {
		ret |= dns_add_SOA(packet, DNS_RRS_NS, domain, 0, &request->soa);
	}

	return ret;
}

static void _dns_server_client_release(struct dns_server_conn *client)
{
	if (client == NULL) {
		return;
	}

	int refcnt = atomic_dec_return(&client->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: refcnt is %d, type = %d", refcnt, client->type);
			abort();
		}
		return;
	}

	if (client->fd > 0) {
		close(client->fd);
		client->fd = -1;
	}

	list_del_init(&client->list);
	free(client);
}

static void _dns_server_client_get(struct dns_server_conn *client)
{
	if (client == NULL) {
		return;
	}
	
	if (atomic_inc_return(&client->refcnt) <= 0) {
		tlog(TLOG_ERROR, "BUG: client ref is invalid.");
		abort();
	}
}

static int _dns_server_reply_tcp_to_buffer(struct dns_server_conn *client, void *packet, int len)
{
	struct epoll_event event;

	if (sizeof(client->sndbuff.buf) - client->sndbuff.size < len) {
		return -1;
	}

	memcpy(client->sndbuff.buf + client->sndbuff.size, packet, len);
	client->sndbuff.size += len;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = client;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, client->fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

static int _dns_server_reply_tcp(struct dns_server_conn *client, void *packet, unsigned short len)
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

	send_len = send(client->fd, inpacket, len, MSG_NOSIGNAL);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(client, inpacket, len);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(client, inpacket + send_len, len - send_len);
	}

	return 0;
}

static int _dns_server_reply_udp(struct dns_request *request, struct dns_server_conn *client, unsigned char *inpacket, int inpacket_len)
{
	int send_len = 0;
	send_len = sendto(client->fd, inpacket, inpacket_len, 0, &request->addr, request->addr_len);
	if (send_len != inpacket_len) {
		tlog(TLOG_ERROR, "send failed.");
		return -1;
	}

	return 0;
}

static int _dns_reply_inpacket(struct dns_request *request, unsigned char *inpacket, int inpacket_len)
{
	struct dns_server_conn *client = request->client;
	int ret = 0;

	if (client->type == DNS_SERVER_UDP) {
		ret = _dns_server_reply_udp(request, client, inpacket, inpacket_len);
	} else if (client->type == DNS_SERVER_TCP) {
		ret = _dns_server_reply_tcp(client, inpacket, inpacket_len);
	} else if (client->type == DNS_SERVER_TLS) {
		ret = -1;
	} else {
		ret = -1;
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

	_dns_server_audit_log(request);

	memset(&head, 0, sizeof(head));
	head.id = request->id;
	head.qr = DNS_QR_ANSWER;
	head.opcode = DNS_OP_QUERY;
	head.rd = 1;
	head.ra = 1;
	head.aa = 0;
	head.tc = 0;
	head.rcode = request->rcode;

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

	return _dns_reply_inpacket(request, inpacket, encode_len);
}

static int _dns_server_reply_SOA(int rcode, struct dns_request *request, struct dns_packet *packet)
{
	struct dns_soa *soa;

	request->rcode = rcode;
	request->has_soa = 1;
	request->has_ipv4 = 0;
	request->has_ipv6 = 0;
	request->has_ptr = 0;

	soa = &request->soa;

	strcpy(soa->mname, "a.gtld-servers.net");
	strcpy(soa->rname, "nstld.verisign-grs.com");
	soa->serial = 1800;
	soa->refresh = 1800;
	soa->retry = 900;
	soa->expire = 604800;
	soa->minimum = 86400;
	_dns_reply(request);

	return 0;
}

static int _dns_setup_ipset(struct dns_request *request)
{
	struct dns_ipset_rule *ipset_rule = NULL;
	int ret = 0;

	if (request->domain_rule == NULL) {
		return 0;
	}

	ipset_rule = request->domain_rule->rules[DOMAIN_RULE_IPSET];
	if (ipset_rule == NULL) {
		return 0;
	}

	if (request->has_ipv4 && request->qtype == DNS_T_A) {
		ret |= ipset_add(ipset_rule->ipsetname, request->ipv4_addr, DNS_RR_A_LEN);
	}

	if (request->has_ipv6 && request->qtype == DNS_T_AAAA) {
		if (request->has_ipv4) {
			ret |= ipset_add(ipset_rule->ipsetname, request->ipv4_addr, DNS_RR_A_LEN);
		}
		ret |= ipset_add(ipset_rule->ipsetname, request->ipv6_addr, DNS_RR_AAAA_LEN);
	}

	tlog(TLOG_DEBUG, "IPSET-MATCH: domain:%s, ipset:%s, result: %d", request->domain, ipset_rule->ipsetname, ret);

	return ret;
}

int _dns_server_request_complete(struct dns_request *request)
{
	char *cname = NULL;
	int cname_ttl = 0;

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	if (request->passthrough) {
		return 0;
	}

	if (request->has_cname) {
		cname = request->cname;
		cname_ttl = request->ttl_cname;
	}

	if (request->qtype == DNS_T_A) {
		tlog(TLOG_INFO, "result: %s, rcode: %d,  %d.%d.%d.%d\n", request->domain, request->rcode, request->ipv4_addr[0], request->ipv4_addr[1],
			 request->ipv4_addr[2], request->ipv4_addr[3]);

		if (request->has_ipv4) {
			if (request->has_ping_result == 0 && request->ttl_v4 > DNS_SERVER_TMOUT_TTL) {
				request->ttl_v4 = DNS_SERVER_TMOUT_TTL;
			}

			if (request->prefetch) {
				dns_cache_replace(request->domain, cname, cname_ttl, request->ttl_v4, DNS_T_A, request->ipv4_addr, DNS_RR_A_LEN);
			} else {
				dns_cache_insert(request->domain, cname, cname_ttl, request->ttl_v4, DNS_T_A, request->ipv4_addr, DNS_RR_A_LEN);
			}
		}

	} else if (request->qtype == DNS_T_AAAA) {
		tlog(TLOG_INFO, "result: %s, rcode: %d,  %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", request->domain, request->rcode,
			 request->ipv6_addr[0], request->ipv6_addr[1], request->ipv6_addr[2], request->ipv6_addr[3], request->ipv6_addr[4], request->ipv6_addr[5],
			 request->ipv6_addr[6], request->ipv6_addr[7], request->ipv6_addr[8], request->ipv6_addr[9], request->ipv6_addr[10], request->ipv6_addr[11],
			 request->ipv6_addr[12], request->ipv6_addr[13], request->ipv6_addr[14], request->ipv6_addr[15]);

		if (request->has_ipv4) {
			dns_cache_insert(request->domain, cname, cname_ttl, request->ttl_v4, DNS_T_AAAA, request->ipv4_addr, DNS_RR_A_LEN);

			if (((request->ping_ttl_v4 + (dns_conf_dualstack_ip_selection_threshold * 10) < request->ping_ttl_v6) && (request->ping_ttl_v4 > 0)) ||
				(request->ping_ttl_v6 == -1)) {
				tlog(TLOG_DEBUG, "Force IPV4 perfered.");
				return _dns_server_reply_SOA(DNS_RC_NOERROR, request, NULL);
			}
		}

		if (request->has_ipv6) {
			if (request->has_ping_result == 0 && request->ttl_v6 > DNS_SERVER_TMOUT_TTL) {
				request->ttl_v6 = DNS_SERVER_TMOUT_TTL;
			}

			if (request->prefetch) {
				dns_cache_replace(request->domain, cname, cname_ttl, request->ttl_v6, DNS_T_AAAA, request->ipv6_addr, DNS_RR_AAAA_LEN);
			} else {
				dns_cache_insert(request->domain, cname, cname_ttl, request->ttl_v6, DNS_T_AAAA, request->ipv6_addr, DNS_RR_AAAA_LEN);
			}
		}
	}

	if (request->prefetch) {
		return 0;
	}

	_dns_setup_ipset(request);
	_dns_reply(request);

	return 0;
}

void _dns_server_request_release(struct dns_request *request);
void _dns_server_request_remove(struct dns_request *request)
{
	pthread_mutex_lock(&server.request_list_lock);
	if (list_empty(&request->list)) {
		pthread_mutex_unlock(&server.request_list_lock);
		return;
	}
	list_del_init(&request->list);
	pthread_mutex_unlock(&server.request_list_lock);
	_dns_server_request_release(request);
}

void _dns_server_select_maxhit_ipaddress(struct dns_request *request)
{
	int maxhit = 0;
	int bucket = 0;
	struct dns_ip_address *addr_map;
	struct dns_ip_address *maxhit_addr_map = NULL;
	struct hlist_node *tmp;

	if (atomic_read(&request->notified) > 0) {
		return;
	}

	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		if (addr_map->addr_type != request->qtype) {
			continue;
		}

		if (addr_map->hitnum <= maxhit) {
			continue;
		}

		maxhit = addr_map->hitnum;
		maxhit_addr_map = addr_map;
	}

	if (maxhit_addr_map == NULL || maxhit == 1) {
		return;
	}

	tlog(TLOG_DEBUG, "select best ip address, %s", request->domain);
	switch (request->qtype) {
	case DNS_T_A: {
		memcpy(request->ipv4_addr, maxhit_addr_map->ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = DNS_SERVER_TMOUT_TTL;
	} break;
	case DNS_T_AAAA: {
		memcpy(request->ipv6_addr, maxhit_addr_map->ipv6_addr, DNS_RR_AAAA_LEN);
		request->ttl_v6 = DNS_SERVER_TMOUT_TTL;
	} break;
	default:
		break;
	}
}

void _dns_server_request_release(struct dns_request *request)
{
	struct dns_ip_address *addr_map;
	struct hlist_node *tmp;
	int bucket = 0;

	int refcnt = atomic_dec_return(&request->refcnt);
	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: refcnt is %d, domain %s, qtype =%d", refcnt, request->domain, request->qtype);
			abort();
		}
		return;
	}

	pthread_mutex_lock(&server.request_list_lock);
	list_del_init(&request->list);
	pthread_mutex_unlock(&server.request_list_lock);

	/* Select max hit ip address, and return to client */
	_dns_server_select_maxhit_ipaddress(request);

	_dns_server_request_complete(request);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_destroy(&request->ip_map_lock);
	_dns_server_client_release(request->client);
	memset(request, 0, sizeof(*request));
	free(request);
}

void _dns_server_request_get(struct dns_request *request)
{
	if (atomic_inc_return(&request->refcnt) <= 0) {
		tlog(TLOG_ERROR, "BUG: request ref is invalid, %s", request->domain);
		abort();
	}
}

void _dns_server_ping_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result, struct sockaddr *addr, socklen_t addr_len,
							 int seqno, int ttl, struct timeval *tv, void *userptr)
{
	struct dns_request *request = userptr;
	int may_complete = 0;
	int threshold = 100;

	if (request == NULL) {
		return;
	}

	if (result == PING_RESULT_END) {
		_dns_server_request_release(request);
		fast_ping_stop(ping_host);
		return;
	}

	unsigned int rtt = tv->tv_sec * 10000 + tv->tv_usec / 100;

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in;
		addr_in = (struct sockaddr_in *)addr;
		if (request->ping_ttl_v4 > rtt) {
			request->ping_ttl_v4 = rtt;
			request->has_ipv4 = 1;
			memcpy(request->ipv4_addr, &addr_in->sin_addr.s_addr, 4);
		}

		if (dns_conf_dualstack_ip_selection == 1 && request->qtype == DNS_T_AAAA) {
			threshold = dns_conf_dualstack_ip_selection_threshold * 10;
		}
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			if (request->ping_ttl_v4 > rtt) {
				request->ping_ttl_v4 = rtt;
				request->has_ipv4 = 1;
				memcpy(request->ipv4_addr, addr_in6->sin6_addr.s6_addr + 12, 4);
			}
		} else {
			if (request->ping_ttl_v6 > rtt) {
				request->ping_ttl_v6 = rtt;
				request->has_ipv6 = 1;
				memcpy(request->ipv6_addr, addr_in6->sin6_addr.s6_addr, 16);
			}
		}
	} break;
	default:
		break;
	}
	if (result == PING_RESULT_RESPONSE) {
		request->has_ping_result = 1;
		tlog(TLOG_DEBUG, "from %15s: seq=%d time=%d\n", host, seqno, rtt);
	} else {
		tlog(TLOG_DEBUG, "from %15s: seq=%d timeout\n", host, seqno);
	}

	if (rtt < threshold) {
		may_complete = 1;
	} else if (rtt < (get_tick_count() - request->send_tick) * 10) {
		may_complete = 1;
	}

	if (may_complete && request->has_ping_result == 1) {
		_dns_server_request_complete(request);
		_dns_server_request_remove(request);
	}
}

int _dns_server_ping(struct dns_request *request, PING_TYPE type, char *ip, int timeout)
{
	if (fast_ping_start(type, ip, 1, 0, timeout, _dns_server_ping_result, request) == NULL) {
		return -1;
	}

	return 0;
}

int _dns_ip_address_check_add(struct dns_request *request, unsigned char *addr, dns_type_t addr_type)
{
	uint32_t key = 0;
	struct dns_ip_address *addr_map = NULL;
	int addr_len = 0;

	if (addr_type == DNS_T_A) {
		addr_len = DNS_RR_A_LEN;
	} else if (addr_type == DNS_T_AAAA) {
		addr_len = DNS_RR_AAAA_LEN;
	} else {
		return -1;
	}

	key = jhash(addr, addr_len, 0);
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_possible(request->ip_map, addr_map, node, key)
	{
		if (addr_type == DNS_T_A) {
			if (memcmp(addr_map->ipv4_addr, addr, addr_len) == 0) {
				addr_map->hitnum++;
				pthread_mutex_unlock(&request->ip_map_lock);
				return -1;
			}
		} else if (addr_type == DNS_T_AAAA) {
			if (memcmp(addr_map->ipv6_addr, addr, addr_len) == 0) {
				addr_map->hitnum++;
				pthread_mutex_unlock(&request->ip_map_lock);
				return -1;
			}
		}
	}
	request->ip_map_num++;

	addr_map = malloc(sizeof(*addr_map));
	if (addr_map == NULL) {
		pthread_mutex_unlock(&request->ip_map_lock);
		tlog(TLOG_ERROR, "malloc failed");
		return -1;
	}

	addr_map->addr_type = addr_type;
	addr_map->hitnum = 1;
	memcpy(addr_map->addr, addr, addr_len);
	hash_add(request->ip_map, &addr_map->node, key);
	pthread_mutex_unlock(&request->ip_map_lock);

	return 0;
}

static int _dns_server_get_conf_ttl(int ttl)
{
	if (dns_conf_rr_ttl > 0) {
		return dns_conf_rr_ttl;
	}

	if (dns_conf_rr_ttl_max > 0 && ttl > dns_conf_rr_ttl_max) {
		ttl = dns_conf_rr_ttl_max;
	} else if (dns_conf_rr_ttl_min > 0 && ttl < dns_conf_rr_ttl_min) {
		ttl = dns_conf_rr_ttl_min;
	}
	return ttl;
}

static int _dns_server_ip_rule_check(struct dns_request *request, unsigned char *addr, int addr_len, dns_type_t addr_type, int result_flag)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct dns_ip_address_rule *rule = NULL;

	if (prefix_from_blob(addr, addr_len, addr_len * 8, &prefix) == NULL) {
		return -1;
	}

	node = radix_search_best(dns_conf_address_rule, &prefix);
	if (node == NULL) {
		return -1;
	}

	if (node->data == NULL) {
		return -1;
	}

	rule = node->data;
	if (rule->bogus) {
		goto match;
	}

	if (rule->blacklist) {
		if (result_flag & DNSSERVER_FLAG_BLACKLIST_IP) {
			goto match;
		}
	}

	return -1;

match:
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NXDOMAIN;
	}
	return 0;
}

static int _dns_server_process_answer(struct dns_request *request, char *domain, struct dns_packet *packet, unsigned int result_flag)
{
	int ttl;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int rr_count;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ping_timeout = DNS_PING_TIMEOUT;
	unsigned long now = get_tick_count();

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
		}

		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);
		return -1;
	}


	ping_timeout = ping_timeout - (now - request->send_tick);
	if (ping_timeout > DNS_PING_TIMEOUT) {
		ping_timeout = DNS_PING_TIMEOUT;
	} else if (ping_timeout < 10) {
		ping_timeout = 10;
	}

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				if (request->qtype != DNS_T_A) {
					/* ignore non-matched query type */
					if (dns_conf_dualstack_ip_selection == 0) {
						break;
					}
				}
				_dns_server_request_get(request);
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				tlog(TLOG_DEBUG, "domain: %s TTL:%d IP: %d.%d.%d.%d", name, ttl, addr[0], addr[1], addr[2], addr[3]);

				/* ip rule check */
				if (_dns_server_ip_rule_check(request, addr, 4, DNS_T_A, result_flag) == 0) {
					_dns_server_request_release(request);
					break;
				}

				if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(request->cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					break;
				}

				if (request->has_ipv4 == 0) {
					memcpy(request->ipv4_addr, addr, DNS_RR_A_LEN);
					request->ttl_v4 = _dns_server_get_conf_ttl(ttl);
					request->has_ipv4 = 1;
				} else {
					if (ttl < request->ttl_v4) {
						request->ttl_v4 = _dns_server_get_conf_ttl(ttl);
					}
				}

				if (addr[0] == 0 || addr[0] == 127) {
					if (atomic_inc_return(&request->adblock) <= dns_server_num() / 2) {
						_dns_server_request_release(request);
						break;
					}
				}

				if (_dns_ip_address_check_add(request, addr, DNS_T_A) != 0) {
					_dns_server_request_release(request);
					break;
				}

				request->rcode = packet->head.rcode;
				sprintf(ip, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

				if (_dns_server_ping(request, PING_TYPE_ICMP, ip, ping_timeout) != 0) {
					_dns_server_request_release(request);
				}
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				_dns_server_request_get(request);
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", name, ttl, addr[0], addr[1],
					 addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);

				if (_dns_server_ip_rule_check(request, addr, 16, DNS_T_AAAA, result_flag) == 0) {
					_dns_server_request_release(request);
					break;
				}

				if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(request->cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					break;
				}

				if (request->has_ipv6 == 0) {
					memcpy(request->ipv6_addr, addr, DNS_RR_AAAA_LEN);
					request->ttl_v6 = _dns_server_get_conf_ttl(ttl);
					request->has_ipv6 = 1;
				} else {
					if (ttl < request->ttl_v6) {
						request->ttl_v6 = _dns_server_get_conf_ttl(ttl);
					}
				}

				if (_dns_ip_address_check_add(request, addr, DNS_T_AAAA) != 0) {
					_dns_server_request_release(request);
					break;
				}

				request->rcode = packet->head.rcode;

				sprintf(ip, "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
						addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);

				if (_dns_server_ping(request, PING_TYPE_ICMP, ip, ping_timeout) != 0) {
					_dns_server_request_release(request);
				}
			} break;
			case DNS_T_NS: {
				char cname[128];
				dns_get_CNAME(rrs, name, 128, &ttl, cname, 128);
				tlog(TLOG_DEBUG, "NS: %s ttl:%d cname: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[128];
				dns_get_CNAME(rrs, name, 128, &ttl, cname, 128);
				tlog(TLOG_DEBUG, "name:%s ttl: %d cname: %s\n", name, ttl, cname);
				strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = ttl;
				request->has_cname = 1;
			} break;
			case DNS_T_SOA: {
				request->has_soa = 1;
				request->rcode = packet->head.rcode;
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_INFO, "SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, expire: %d, minimum: %d", request->soa.mname,
					 request->soa.rname, request->soa.serial, request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);
			} break;
			default:
				tlog(TLOG_INFO, "%s, qtype: %d", name, rrs->type);
				break;
			}
		}
	}

	return 0;
}

static int dns_server_update_reply_packet_id(struct dns_request *request, unsigned char *inpacket, int inpacket_len)
{
	struct dns_head *dns_head = (struct dns_head *)inpacket;
	unsigned short id = request->id;

	if (inpacket_len < sizeof(*dns_head)) {
		return -1;
	}

	dns_head->id = htons(id);

	return 0;
}

static int dns_server_resolve_callback(char *domain, dns_result_type rtype, unsigned int result_flag, struct dns_packet *packet, unsigned char *inpacket,
									   int inpacket_len, void *user_ptr)
{
	struct dns_request *request = user_ptr;
	int ip_num = 0;
	int request_wait = 0;

	if (request == NULL) {
		return -1;
	}

	if (rtype == DNS_QUERY_RESULT) {
		if (request->passthrough) {
			dns_server_update_reply_packet_id(request, inpacket, inpacket_len);
			_dns_reply_inpacket(request, inpacket, inpacket_len);
			return 0;
		}

		_dns_server_process_answer(request, domain, packet, result_flag);
		return 0;
	} else if (rtype == DNS_QUERY_ERR) {
		tlog(TLOG_ERROR, "request faield, %s", domain);
		return -1;
	} else {
		pthread_mutex_lock(&request->ip_map_lock);
		ip_num = request->ip_map_num;
		request_wait = request->request_wait;
		request->request_wait--;
		pthread_mutex_unlock(&request->ip_map_lock);

		/* Not need to wait check result if only has one ip address */
		if (ip_num == 1 && request_wait == 1) {
			_dns_server_request_complete(request);
			_dns_server_request_remove(request);
		}

		if (request->has_ipv4 == 0 && request->has_ipv6 == 0) {
			_dns_server_request_remove(request);
		}
		_dns_server_request_release(request);
	}

	return 0;
}

static int _dns_server_process_ptr(struct dns_request *request, struct dns_packet *packet)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	unsigned char *addr;
	char reverse_addr[128] = {0};
	int found = 0;

	if (getifaddrs(&ifaddr) == -1) {
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in;
			addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			addr = (unsigned char *)&(addr_in->sin_addr.s_addr);
			snprintf(reverse_addr, sizeof(reverse_addr), "%d.%d.%d.%d.in-addr.arpa", addr[3], addr[2], addr[1], addr[0]);
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6;
			addr_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
				addr = addr_in6->sin6_addr.s6_addr + 12;
				snprintf(reverse_addr, sizeof(reverse_addr), "%d.%d.%d.%d.in-addr.arpa", addr[3], addr[2], addr[1], addr[0]);
			} else {
				addr = addr_in6->sin6_addr.s6_addr;
				snprintf(reverse_addr, sizeof(reverse_addr),
						 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa", addr[15] & 0xF,
						 (addr[15] >> 4) & 0xF, addr[14] & 0xF, (addr[14] >> 4) & 0xF, addr[13] & 0xF, (addr[13] >> 4) & 0xF, addr[12] & 0xF,
						 (addr[12] >> 4) & 0xF, addr[11] & 0xF, (addr[11] >> 4) & 0xF, addr[10] & 0xF, (addr[10] >> 4) & 0xF, addr[9] & 0xF,
						 (addr[9] >> 4) & 0xF, addr[8] & 0xF, (addr[8] >> 4) & 0xF, addr[7] & 0xF, (addr[7] >> 4) & 0xF, addr[6] & 0xF, (addr[6] >> 4) & 0xF,
						 addr[5] & 0xF, (addr[5] >> 4) & 0xF, addr[4] & 0xF, (addr[4] >> 4) & 0xF, addr[3] & 0xF, (addr[3] >> 4) & 0xF, addr[2] & 0xF,
						 (addr[2] >> 4) & 0xF, addr[1] & 0xF, (addr[1] >> 4) & 0xF, addr[0] & 0xF, (addr[0] >> 4) & 0xF);
			}
		} break;
		default:
			continue;
			break;
		}

		if (strstr(request->domain, reverse_addr) != NULL) {
			found = 1;
			break;
		}
	}

	if (strstr(request->domain, "0.0.0.0") != NULL) {
		found = 1;
	}

	if (found == 0) {
		goto errout;
	}

	request->rcode = DNS_RC_NOERROR;
	request->has_ptr = 1;
	_dns_reply(request);

	freeifaddrs(ifaddr);
	return 0;
errout:
	if (ifaddr) {
		freeifaddrs(ifaddr);
	}
	return -1;
}

static void _dns_server_log_rule(char *domain, unsigned char *rule_key, int rule_key_len)
{
	char rule_name[DNS_MAX_CNAME_LEN];

	if (rule_key_len <= 0) {
		return;
	}

	reverse_string(rule_name, (char *)rule_key, rule_key_len);
	rule_name[rule_key_len] = 0;
	tlog(TLOG_INFO, "RULE-MATCH, domain: %s, rule: %s", domain, rule_name);
}

static struct dns_domain_rule *_dns_server_get_domain_rule(char *domain)
{
	int domain_len;
	char domain_key[DNS_MAX_CNAME_LEN];
	int matched_key_len = DNS_MAX_CNAME_LEN;
	unsigned char matched_key[DNS_MAX_CNAME_LEN];
	struct dns_domain_rule *domain_rule = NULL;

	domain_len = strlen(domain);
	reverse_string(domain_key, domain, domain_len);
	domain_key[domain_len] = '.';
	domain_len++;
	domain_key[domain_len] = 0;

	if (likely(dns_conf_log_level > TLOG_INFO)) {
		return art_substring(&dns_conf_domain_rule, (unsigned char *)domain_key, domain_len, NULL, NULL);
	}

	domain_rule = art_substring(&dns_conf_domain_rule, (unsigned char *)domain_key, domain_len, matched_key, &matched_key_len);
	if (domain_rule == NULL) {
		return NULL;
	}

	if (matched_key_len <= 0) {
		return NULL;
	}

	matched_key_len--;
	matched_key[matched_key_len] = 0;
	_dns_server_log_rule(domain, matched_key, matched_key_len);

	return domain_rule;
}

static int _dns_server_process_address(struct dns_request *request, struct dns_packet *packet)
{
	struct dns_address_IPV4 *address_ipv4 = NULL;
	struct dns_address_IPV6 *address_ipv6 = NULL;

	if (request->domain_rule == NULL) {
		goto errout;
	}

	switch (request->qtype) {
	case DNS_T_A:
		if (request->domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] == NULL) {
			goto errout;
		}
		address_ipv4 = request->domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4];
		memcpy(request->ipv4_addr, address_ipv4->ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = 600;
		request->has_ipv4 = 1;
		break;
	case DNS_T_AAAA:
		if (request->domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] == NULL) {
			goto errout;
		}
		address_ipv6 = request->domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6];
		memcpy(request->ipv6_addr, address_ipv6->ipv6_addr, DNS_RR_AAAA_LEN);
		request->ttl_v6 = 600;
		request->has_ipv6 = 1;
		break;
	default:
		goto errout;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	_dns_reply(request);

	return 0;
errout:
	return -1;
}

static int _dns_server_process_cache(struct dns_request *request, struct dns_packet *packet)
{
	struct dns_cache *dns_cache = NULL;

	dns_cache = dns_cache_lookup(request->domain, request->qtype);
	if (dns_cache == NULL) {
		goto errout;
	}

	if (request->qtype != dns_cache->qtype) {
		goto errout;
	}

	switch (request->qtype) {
	case DNS_T_A:
		memcpy(request->ipv4_addr, dns_cache->ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = dns_cache_get_ttl(dns_cache);
		request->has_ipv4 = 1;
		break;
	case DNS_T_AAAA:
		memcpy(request->ipv6_addr, dns_cache->ipv6_addr, DNS_RR_AAAA_LEN);
		request->ttl_v6 = dns_cache_get_ttl(dns_cache);
		request->has_ipv6 = 1;
		break;
	default:
		goto errout;
		break;
	}

	if (dns_cache->cname[0] != 0) {
		strncpy(request->cname, dns_cache->cname, DNS_MAX_CNAME_LEN);
		request->has_cname = 1;
		request->ttl_cname = dns_cache->cname_ttl;
	}

	request->rcode = DNS_RC_NOERROR;
	_dns_reply(request);
	dns_cache_update(dns_cache);
	dns_cache_release(dns_cache);

	return 0;
errout:
	return -1;
}

static int _dns_server_recv(struct dns_server_conn *client, unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *from, socklen_t from_len)
{
	int decode_len;
	int ret = -1;
	unsigned char packet_buff[DNS_PACKSIZE];
	char name[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_request *request = NULL;
	struct dns_rrs *rrs;
	int rr_count = 0;
	int i = 0;
	int qclass;
	int qtype = DNS_T_ALL;

	_dns_server_client_get(client);

	decode_len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (decode_len < 0) {
		tlog(TLOG_ERROR, "decode failed.\n");
		goto errout;
	}

	tlog(TLOG_DEBUG, "request qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, ra = %d, rcode = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len, packet->head.id, packet->head.tc,
		 packet->head.rd, packet->head.ra, packet->head.rcode);

	if (packet->head.qr != DNS_QR_QUERY) {
		goto errout;
	}

	request = malloc(sizeof(*request));
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	memset(request, 0, sizeof(*request));
	pthread_mutex_init(&request->ip_map_lock, 0);
	atomic_set(&request->adblock, 0);
	atomic_set(&request->refcnt, 0);
	request->ping_ttl_v4 = -1;
	request->ping_ttl_v6 = -1;
	request->prefetch = 0;
	request->rcode = DNS_RC_SERVFAIL;
	request->client = client;
	INIT_LIST_HEAD(&request->list);

	if (_dns_recv_addr(request, from, from_len) != 0) {
		goto errout;
	}

	request->id = packet->head.id;
	memcpy(&request->head, &packet->head, sizeof(struct dns_head));
	hash_init(request->ip_map);

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

	request->domain_rule = _dns_server_get_domain_rule(request->domain);

	switch (qtype) {
	case DNS_T_PTR:
		ret = _dns_server_process_ptr(request, packet);
		if (ret == 0) {
			goto clean_exit;
		} else {
			request->passthrough = 1;
		}
		break;
	case DNS_T_A:
		break;
	case DNS_T_AAAA:
		if (dns_conf_force_AAAA_SOA == 1) {
			_dns_server_reply_SOA(DNS_RC_NOERROR, request, packet);
			goto clean_exit;
		}
		break;
	default:
		tlog(TLOG_DEBUG, "unsupport qtype: %d, domain: %s", qtype, request->domain);
		request->passthrough = 1;
		break;
	}

	if (_dns_server_process_address(request, packet) == 0) {
		goto clean_exit;
	}

	if (_dns_server_process_cache(request, packet) == 0) {
		goto clean_exit;
	}

	tlog(TLOG_INFO, "query server %s from %s, qtype = %d\n", request->domain, gethost_by_addr(name, (struct sockaddr *)from, from_len), qtype);

	_dns_server_request_get(request);
	pthread_mutex_lock(&server.request_list_lock);
	list_add_tail(&request->list, &server.request_list);
	pthread_mutex_unlock(&server.request_list_lock);

	_dns_server_request_get(request);
	request->send_tick = get_tick_count();

	if (qtype == DNS_T_AAAA && dns_conf_dualstack_ip_selection) {
		_dns_server_request_get(request);
		request->request_wait++;
		if (dns_client_query(request->domain, DNS_T_A, dns_server_resolve_callback, request) != 0) {
			_dns_server_request_release(request);
			request->request_wait--;
		}
	}

	request->request_wait++;
	if (dns_client_query(request->domain, qtype, dns_server_resolve_callback, request) != 0) {
		_dns_server_request_release(request);
		_dns_server_request_remove(request);
		request = NULL;
		goto errout;
	}

	return 0;
clean_exit:
	if (request) {
		free(request);
	}

	_dns_server_client_release(client);

	return 0;
errout:
	if (request) {
		ret = _dns_server_forward_request(inpacket, inpacket_len);
		free(request);
	}

	_dns_server_client_release(client);
	return ret;
}

static int _dns_server_prefetch_request(char *domain, dns_type_t qtype)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = malloc(sizeof(*request));
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}
	memset(request, 0, sizeof(*request));
	pthread_mutex_init(&request->ip_map_lock, 0);
	atomic_set(&request->adblock, 0);
	request->ping_ttl_v4 = -1;
	request->ping_ttl_v6 = -1;
	request->prefetch = 1;
	request->qtype = qtype;
	request->rcode = DNS_RC_SERVFAIL;

	request->id = 0;
	hash_init(request->ip_map);
	strncpy(request->domain, domain, DNS_MAX_CNAME_LEN);

	tlog(TLOG_INFO, "prefetch domain %s, qtype = %d\n", request->domain, qtype);

	_dns_server_request_get(request);
	pthread_mutex_lock(&server.request_list_lock);
	list_add_tail(&request->list, &server.request_list);
	pthread_mutex_unlock(&server.request_list_lock);

	_dns_server_request_get(request);
	request->send_tick = get_tick_count();
	request->request_wait++;
	dns_client_query(request->domain, qtype, dns_server_resolve_callback, request);

	return 0;
errout:
	return ret;
}

static int _dns_server_process_udp(struct dns_server_conn *dnsserver, struct epoll_event *event, unsigned long now)
{
	int len;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);

	len = recvfrom(dnsserver->fd, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}

	return _dns_server_recv(dnsserver, inpacket, len, &from, from_len);
}

static void _dns_server_client_touch(struct dns_server_conn *client)
{
	time(&client->last_request_time);
}

static int _dns_server_client_close(struct dns_server_conn *client)
{
	if (client->fd > 0) {
		epoll_ctl(server.epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);
		close(client->fd);
		client->fd = -1;
	}

	list_del_init(&client->list);

	_dns_server_client_release(client);

	return 0;
}

static int _dns_server_accept(struct dns_server_conn *dnsserver, struct epoll_event *event, unsigned long now)
{
	struct sockaddr_storage addr;
	struct dns_server_conn *client = NULL;
	socklen_t addr_len = sizeof(addr);
	int fd = -1;

	fd = accept4(dnsserver->fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	client = malloc(sizeof(*client));
	if (client == NULL) {
		goto errout;
	}

	memset(client, 0, sizeof(*client));
	struct epoll_event event_client;
	memset(&event_client, 0, sizeof(event_client));
	event_client.data.ptr = client;
	event_client.events = EPOLLIN;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, fd, &event_client) != 0) {
		tlog(TLOG_ERROR, "epoll add failed, %s", strerror(errno));
		goto errout;
	}

	client->fd = fd;
	client->type = DNS_SERVER_TCP;
	atomic_set(&client->refcnt, 0);
	memcpy(&client->addr, &addr, addr_len);
	client->addr_len = addr_len;

	_dns_server_client_touch(client);

	list_add(&client->list, &server.client_list);
	_dns_server_client_get(client);

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}
	if (client) {
		free(client);
	}
	return -1;
}

int _dns_server_tcp_recv(struct dns_server_conn *dnsserver)
{
	int len = 0;

	while (dnsserver->recvbuff.size < sizeof(dnsserver->recvbuff.buf)) {
		if (dnsserver->recvbuff.size == sizeof(dnsserver->recvbuff.buf)) {
			return 0;
		}

		len = recv(dnsserver->fd, dnsserver->recvbuff.buf + dnsserver->recvbuff.size, sizeof(dnsserver->recvbuff.buf) - dnsserver->recvbuff.size, 0);
		if (len < 0) {
			if (errno == EAGAIN) {
				return 1;
			}

			return -1;
		} else if (len == 0) {
			return -1;
		}

		dnsserver->recvbuff.size += len;
	}

	return 0;
}

int _dns_server_tcp_process_one_request(struct dns_server_conn *dnsserver)
{
	int request_len = 0;
	int total_len = dnsserver->recvbuff.size;
	int proceed_len = 0;
	unsigned char *request_data = NULL;
	int ret = 0;

	for (;;) {
		if ((total_len - proceed_len) <= sizeof(unsigned short)) {
			ret = 1;
			break;
		}

		request_data = (unsigned char *)(dnsserver->recvbuff.buf + proceed_len);
		request_len = ntohs(*((unsigned short *)(request_data)));

		if (request_len >= sizeof(dnsserver->recvbuff.buf)) {
			tlog(TLOG_ERROR, "request length is invalid.");
			return -1;
		}

		if (request_len > (total_len - proceed_len)) {
			ret = 1;
			break;
		}

		request_data = (unsigned char *)(dnsserver->recvbuff.buf + proceed_len + sizeof(unsigned short));

		if (_dns_server_recv(dnsserver, request_data, request_len, &dnsserver->addr, dnsserver->addr_len) != 0) {
			tlog(TLOG_ERROR, "process tcp request failed.");
			return -1;
		}

		proceed_len += sizeof(unsigned short) + request_len;
	}

	if (total_len > proceed_len && proceed_len > 0) {
		memmove(dnsserver->recvbuff.buf, dnsserver->recvbuff.buf + proceed_len, total_len - proceed_len);
	}

	dnsserver->recvbuff.size -= proceed_len;

	return ret;
}

int _dns_server_tcp_process_requests(struct dns_server_conn *client)
{
	int recv_ret = 0;
	int request_ret = 0;
	int is_eof = 0;

	for (;;) {
		recv_ret = _dns_server_tcp_recv(client);
		if (recv_ret < 0) {
			if (client->recvbuff.size > 0) {
				is_eof = 1;
			} else {
				return -1;
			}
		}

		request_ret = _dns_server_tcp_process_one_request(client);
		if (request_ret < 0) {
			return -1;
		}

		if (request_ret == 1 && is_eof == 1) {
			return -1;
		}

		if (recv_ret == 1 && request_ret == 1) {
			return 0;
		}
	}

	return 0;
}

int _dns_server_tcp_send(struct dns_server_conn *client)
{
	int len;
	while (client->sndbuff.size > 0) {
		len = send(client->fd, client->sndbuff.buf, client->sndbuff.size, MSG_NOSIGNAL);
		if (len < 0) {
			if (errno == EAGAIN) {
				return 1;
			}
			return -1;
		} else if (len == 0) {
			break;
		}

		client->sndbuff.size -= len;
	}

	struct epoll_event event_client;
	event_client.data.ptr = client;
	event_client.events = EPOLLIN;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, client->fd, &event_client) != 0) {
		tlog(TLOG_ERROR, "epoll add failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int _dns_server_process_tcp(struct dns_server_conn *dnsserver, struct epoll_event *event, unsigned long now)
{
	if (dnsserver == &server.tcp_server) {
		return _dns_server_accept(dnsserver, event, now);
	}

	if (event->events & EPOLLIN) {
		if (_dns_server_tcp_process_requests(dnsserver) != 0) {
			_dns_server_client_close(dnsserver);
		}
	}

	if (event->events & EPOLLOUT) {
		if (_dns_server_tcp_send(dnsserver) != 0) {
			_dns_server_client_close(dnsserver);
		}
	}

	return 0;
}

static int _dns_server_process(struct dns_server_conn *dnsserver, struct epoll_event *event, unsigned long now)
{
	_dns_server_client_touch(dnsserver);
	if (dnsserver->type == DNS_SERVER_UDP) {
		return _dns_server_process_udp(dnsserver, event, now);
	} else if (dnsserver->type == DNS_SERVER_TCP) {
		return _dns_server_process_tcp(dnsserver, event, now);
	} else if (dnsserver->type == DNS_SERVER_TLS) {
		return -1;
	} else {
		return -1;
	}
}

void _dns_server_tcp_ping_check(struct dns_request *request)
{
	struct dns_ip_address *addr_map;
	int bucket = 0;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char ip[DNS_MAX_CNAME_LEN] = {0};

	if (request->has_ping_result) {
		return;
	}

	if (request->has_ping_tcp) {
		return;
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each(request->ip_map, bucket, addr_map, node)
	{
		switch (addr_map->addr_type) {
		case DNS_T_A: {
			_dns_server_request_get(request);
			sprintf(ip, "%d.%d.%d.%d:80", addr_map->ipv4_addr[0], addr_map->ipv4_addr[1], addr_map->ipv4_addr[2], addr_map->ipv4_addr[3]);
			if (_dns_server_ping(request, PING_TYPE_TCP, ip, DNS_PING_TCP_TIMEOUT) != 0) {
				_dns_server_request_release(request);
			}
		} break;
		case DNS_T_AAAA: {
			_dns_server_request_get(request);
			sprintf(name, "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]:80", addr_map->ipv6_addr[0], addr_map->ipv6_addr[1],
					addr_map->ipv6_addr[2], addr_map->ipv6_addr[3], addr_map->ipv6_addr[4], addr_map->ipv6_addr[5], addr_map->ipv6_addr[6],
					addr_map->ipv6_addr[7], addr_map->ipv6_addr[8], addr_map->ipv6_addr[9], addr_map->ipv6_addr[10], addr_map->ipv6_addr[11],
					addr_map->ipv6_addr[12], addr_map->ipv6_addr[13], addr_map->ipv6_addr[14], addr_map->ipv6_addr[15]);

			if (_dns_server_ping(request, PING_TYPE_TCP, ip, DNS_PING_TCP_TIMEOUT) != 0) {
				_dns_server_request_release(request);
			}
		} break;
		default:
			break;
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	request->has_ping_tcp = 1;
}

void _dns_server_prefetch_domain(struct dns_cache *dns_cache)
{
	tlog(TLOG_DEBUG, "prefetch by cache %s, qtype %d, ttl %d", dns_cache->domain, dns_cache->qtype, dns_cache->ttl);
	if (_dns_server_prefetch_request(dns_cache->domain, dns_cache->qtype) != 0) {
		tlog(TLOG_ERROR, "prefetch domain %s, qtype %d, failed.", dns_cache->domain, dns_cache->qtype);
	}
}

void _dns_server_tcp_idle_check(void)
{
	struct dns_server_conn *client, *tmp;
	time_t now;

	if (dns_conf_tcp_idle_time <= 0) {
		return;
	}

	time(&now);
	list_for_each_entry_safe(client, tmp, &server.client_list, list)
	{
		if (client->last_request_time > now - dns_conf_tcp_idle_time) {
			continue;
		}

		_dns_server_client_close(client);
	}
}

void _dns_server_period_run_second(void)
{
	static unsigned int sec = 0;
	sec++;

	if (sec % 2 == 0) {
		if (dns_conf_prefetch) {
			dns_cache_invalidate(_dns_server_prefetch_domain, 3);
		} else {
			dns_cache_invalidate(NULL, 0);
		}
	}

	_dns_server_tcp_idle_check();
}

void _dns_server_period_run(void)
{
	struct dns_request *request, *tmp;
	static unsigned int msec = 0;
	LIST_HEAD(check_list);

	msec++;
	if (msec % 10 == 0) {
		_dns_server_period_run_second();
	}

	unsigned long now = get_tick_count();

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		if (request->send_tick < now - DNS_TCPPING_START && request->has_ping_tcp == 0) {
			_dns_server_request_get(request);
			list_add_tail(&request->check_list, &check_list);
		}
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &check_list, check_list)
	{
		_dns_server_tcp_ping_check(request);
		_dns_server_request_remove(request);
		list_del_init(&request->check_list);
		_dns_server_request_release(request);
	}
}

int dns_server_run(void)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num;
	int i;
	unsigned long now = {0};
	int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;

	sleep_time = sleep;
	now = get_tick_count() - sleep;
	expect_time = now + sleep;
	while (server.run) {
		now = get_tick_count();
		if (now >= expect_time) {
			_dns_server_period_run();
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
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
			struct dns_server_conn *dnsserver = event->data.ptr;
			if (dnsserver == NULL) {
				tlog(TLOG_ERROR, "invalid fd\n");
				continue;
			}

			if (_dns_server_process(dnsserver, event, now) != 0) {
				tlog(TLOG_ERROR, "dns server process failed.");
			}
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

int _dns_server_start_udp(void)
{
	struct epoll_event event;

	if (server.udp_server.fd <= 0) {
		return 0;
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = &server.udp_server;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, server.udp_server.fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int _dns_server_start_tcp(void)
{
	struct epoll_event event;

	if (server.tcp_server.fd <= 0) {
		return 0;
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = &server.tcp_server;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, server.tcp_server.fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int dns_server_start(void)
{
	if (_dns_server_start_udp() != 0) {
		tlog(TLOG_ERROR, "start udp server failed.");
		return -1;
	}

	if (_dns_server_start_tcp() != 0) {
		tlog(TLOG_ERROR, "start tcp server failed.");
		return -1;
	}
	return 0;
}

int _dns_create_socket(const char *host_ip, int type)
{
	int fd = -1;
	struct addrinfo *gai = NULL;
	char port_str[8];
	char ip[MAX_IP_LEN];
	int port;
	char *host = NULL;
	int optval = 1;

	if (parse_ip(host_ip, ip, &port) == 0) {
		host = ip;
	}

	if (port <= 0) {
		port = DEFAULT_DNS_PORT;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);
	gai = _dns_server_getaddr(host, port_str, type, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed.\n");
		goto errout;
	}

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, family = %d, type = %d, proto = %d, %s\n", gai->ai_family, gai->ai_socktype, gai->ai_protocol, strerror(errno));
		goto errout;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
		tlog(TLOG_ERROR, "set socket opt failed.");
		goto errout;
	}

	if (bind(fd, gai->ai_addr, gai->ai_addrlen) != 0) {
		tlog(TLOG_ERROR, "bind failed.\n");
		goto errout;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 16) != 0) {
			tlog(TLOG_ERROR, "listen failed.\n");
			goto errout;
		}
	}

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

int _dns_server_socket(void)
{
	int fd_udp = -1;
	int fd_tcp = -1;

	if (dns_conf_server_ip[0] != 0) {
		fd_udp = _dns_create_socket(dns_conf_server_ip, SOCK_DGRAM);
		if (fd_udp < 0) {
			goto errout;
		}
	}

	if (dns_conf_server_tcp_ip[0] != 0) {
		fd_tcp = _dns_create_socket(dns_conf_server_tcp_ip, SOCK_STREAM);
		if (fd_tcp < 0) {
			goto errout;
		}
	}

	server.udp_server.fd = fd_udp;
	server.udp_server.type = DNS_SERVER_UDP;
	_dns_server_client_get(&server.udp_server);
	INIT_LIST_HEAD(&server.udp_server.list);
	server.tcp_server.fd = fd_tcp;
	server.tcp_server.type = DNS_SERVER_TCP;
	INIT_LIST_HEAD(&server.tcp_server.list);
	_dns_server_client_get(&server.tcp_server);
	return 0;
errout:
	if (fd_udp > 0) {
		close(fd_udp);
	}

	if (fd_tcp > 0) {
		close(fd_tcp);
	}

	return -1;
}

void _dns_server_close_socket(void)
{
	struct dns_server_conn *client, *tmp;

	list_for_each_entry_safe(client, tmp, &server.client_list, list)
	{
		_dns_server_client_close(client);
	}

	if (server.udp_server.fd > 0) {
		close(server.udp_server.fd);
		server.udp_server.fd = 0;
	}

	if (server.tcp_server.fd > 0) {
		close(server.tcp_server.fd);
		server.tcp_server.fd = 0;
	}
}

int _dns_server_audit_init(void)
{
	char *audit_file = SMARTDNS_AUDIT_FILE;
	if (dns_conf_audit_enable == 0) {
		return 0;
	}

	if (dns_conf_audit_file[0] != 0) {
		audit_file = dns_conf_audit_file;
	}

	dns_audit = tlog_open(audit_file, dns_conf_audit_size, dns_conf_audit_num, 1, 0, 0);
	if (dns_audit == NULL) {
		return -1;
	}

	return 0;
}

int dns_server_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret = -1;

	if (server.epoll_fd > 0) {
		return -1;
	}

	if (dns_cache_init(dns_conf_cachesize) != 0) {
		tlog(TLOG_ERROR, "init cache failed.");
		return -1;
	}

	if (_dns_server_audit_init() != 0) {
		tlog(TLOG_ERROR, "init audit failed.");
		goto errout;
	}

	memset(&server, 0, sizeof(server));
	pthread_attr_init(&attr);
	INIT_LIST_HEAD(&server.client_list);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	ret = _dns_server_socket();
	if (ret != 0) {
		tlog(TLOG_ERROR, "create server socket failed.\n");
		goto errout;
	}

	pthread_mutex_init(&server.request_list_lock, 0);
	INIT_LIST_HEAD(&server.request_list);
	server.epoll_fd = epollfd;
	server.run = 1;

	if (dns_server_start() != 0) {
		tlog(TLOG_ERROR, "start service failed.\n");
		goto errout;
	}

	return 0;
errout:
	server.run = 0;

	if (epollfd) {
		close(epollfd);
	}

	_dns_server_close_socket();
	pthread_mutex_destroy(&server.request_list_lock);

	dns_cache_destroy();

	return -1;
}

void dns_server_stop(void)
{
	server.run = 0;
}

void dns_server_exit(void)
{
	struct dns_request *request, *tmp;
	LIST_HEAD(remove_list);

	server.run = 0;
	_dns_server_close_socket();
	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		list_add_tail(&request->check_list, &remove_list);
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &remove_list, check_list)
	{
		_dns_server_request_remove(request);
	}

	pthread_mutex_destroy(&server.request_list_lock);

	dns_cache_destroy();
}
