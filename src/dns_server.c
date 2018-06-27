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
#include "atomic.h"
#include "conf.h"
#include "dns.h"
#include "dns_client.h"
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

/* dns server data */
struct dns_server {
	int run;
	int epoll_fd;
	int fd;

	/* dns request list */
	pthread_mutex_t request_list_lock;
	struct list_head request_list;
};

/* ip address lists of domain */
struct dns_ip_address {
	struct hlist_node node;
	dns_type_t addr_type;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

struct dns_request {
	atomic_t refcnt;
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

	/* send original raw packet to server/client like proxy */
	int passthrough;

	pthread_mutex_t ip_map_lock;
	DECLARE_HASHTABLE(ip_map, 4);
};

static struct dns_server server;

static int _dns_server_forward_request(unsigned char *inpacket, int inpacket_len)
{
	tlog(TLOG_ERROR, "forward request.\n");
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
	int ret = 0;
	char *domain = request->domain;
	if (request->has_ptr) {
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

static int _dns_reply_inpacket(struct dns_request *request, unsigned char *inpacket, int inpacket_len)
{
	int send_len = 0;
	unsigned short *id = (unsigned short *)inpacket;

	*id = htons(request->id);

	send_len = sendto(server.fd, inpacket, inpacket_len, 0, &request->addr, request->addr_len);
	if (send_len != inpacket_len) {
		tlog(TLOG_ERROR, "send failed.");
		return -1;
	}

	return 0;
}

static int _dns_reply(struct dns_request *request)
{
	unsigned char inpacket[DNS_IN_PACKSIZE];
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_head head;
	int ret = 0;
	int encode_len = 0;

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

int _dns_server_request_complete(struct dns_request *request)
{
	int ret = -1;
	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	if (request->passthrough) {
		return 0;
	}

	if (request->qtype == DNS_T_A) {
		tlog(TLOG_INFO, "result: %s, rcode: %d,  %d.%d.%d.%d\n", request->domain, request->rcode, request->ipv4_addr[0], request->ipv4_addr[1],
			 request->ipv4_addr[2], request->ipv4_addr[3]);
	} else if (request->qtype == DNS_T_AAAA) {
		tlog(TLOG_INFO, "result :%s, rcode: %d,  %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", request->domain, request->rcode,
			 request->ipv6_addr[0], request->ipv6_addr[1], request->ipv6_addr[2], request->ipv6_addr[3], request->ipv6_addr[4], request->ipv6_addr[5],
			 request->ipv6_addr[6], request->ipv6_addr[7], request->ipv6_addr[8], request->ipv6_addr[9], request->ipv6_addr[10], request->ipv6_addr[11],
			 request->ipv6_addr[12], request->ipv6_addr[13], request->ipv6_addr[14], request->ipv6_addr[15]);
	}

	_dns_reply(request);

	return ret;
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

void _dns_server_request_release(struct dns_request *request)
{
	struct dns_ip_address *addr_map;
	struct hlist_node *tmp;
	int bucket = 0;

	int refcnt = atomic_dec_return(&request->refcnt);
	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: refcnt is %d", refcnt);
			abort();
		}
		return;
	}

	pthread_mutex_lock(&server.request_list_lock);
	list_del_init(&request->list);
	pthread_mutex_unlock(&server.request_list_lock);

	_dns_server_request_complete(request);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_destroy(&request->ip_map_lock);
	memset(request, 0, sizeof(*request));
	free(request);
}

void _dns_server_request_get(struct dns_request *request)
{
	atomic_inc(&request->refcnt);
}

void _dns_server_ping_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result, struct sockaddr *addr, socklen_t addr_len,
							 int seqno, struct timeval *tv, void *userptr)
{
	struct dns_request *request = userptr;
	int may_complete = 0;
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

	if (rtt < 100) {
		may_complete = 1;
	} else if (rtt < (get_tick_count() - request->send_tick) * 10) {
		may_complete = 1;
	}

	if (may_complete) {
		_dns_server_request_complete(request);
		_dns_server_request_remove(request);
	}
}

int _dns_server_ping(struct dns_request *request, char *ip)
{
	if (fast_ping_start(ip, 1, 0, 1000, _dns_server_ping_result, request) == NULL) {
		return -1;
	}

	return 0;
}

int _dns_ip_address_check_add(struct dns_request *request, unsigned char *addr, dns_type_t addr_type)
{
	int key = 0;
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
				pthread_mutex_unlock(&request->ip_map_lock);
				return -1;
			}
		} else if (addr_type == DNS_T_AAAA) {
			if (memcmp(addr_map->ipv6_addr, addr, addr_len) == 0) {
				pthread_mutex_unlock(&request->ip_map_lock);
				return -1;
			}
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	addr_map = malloc(sizeof(*addr_map));
	if (addr_map == NULL) {
		tlog(TLOG_ERROR, "malloc failed");
		return -1;
	}

	addr_map->addr_type = addr_type;
	memcpy(addr_map->addr, addr, addr_len);
	hash_add(request->ip_map, &addr_map->node, key);

	return 0;
}

static int _dns_server_process_answer(struct dns_request *request, char *domain, struct dns_packet *packet)
{
	int ttl;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int rr_count;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;

	if (packet->head.rcode != DNS_RC_NOERROR) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
		}
		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);
		return -1;
	}

	request->rcode = packet->head.rcode;

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				if (request->qtype != DNS_T_A) {
					/* ignore non-matched query type */
					break;
				}
				_dns_server_request_get(request);
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				tlog(TLOG_DEBUG, "domain: %s TTL:%d IP: %d.%d.%d.%d", name, ttl, addr[0], addr[1], addr[2], addr[3]);

				if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(request->cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					break;
				}

				if (addr[0] == 0) {
					_dns_server_request_release(request);
					tlog(TLOG_WARN, "Ad blocker, domain: %s", domain);
					break;
				}

				if (request->has_ipv4 == 0) {
					memcpy(request->ipv4_addr, addr, DNS_RR_A_LEN);
					request->ttl_v4 = ttl;
					request->has_ipv4 = 1;
				}
				if (_dns_ip_address_check_add(request, addr, DNS_T_A) != 0) {
					_dns_server_request_release(request);
					break;
				}
				sprintf(ip, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

				if (_dns_server_ping(request, ip) != 0) {
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
				if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(request->cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					break;
				}

				if (request->has_ipv6 == 0) {
					memcpy(request->ipv6_addr, addr, DNS_RR_AAAA_LEN);
					request->ttl_v6 = ttl;
					request->has_ipv6 = 1;
				}

				if (_dns_ip_address_check_add(request, addr, DNS_T_AAAA) != 0) {
					_dns_server_request_release(request);
					break;
				}

				sprintf(name, "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
						addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);

				if (_dns_server_ping(request, ip) != 0) {
					_dns_server_request_release(request);
				}
			} break;
			case DNS_T_NS: {
				char cname[128];
				dns_get_CNAME(rrs, name, 128, &ttl, cname, 128);
				tlog(TLOG_DEBUG, "NS: %s %d : %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[128];
				dns_get_CNAME(rrs, name, 128, &ttl, cname, 128);
				tlog(TLOG_DEBUG, "%s %d : %s\n", name, ttl, cname);
				strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = ttl;
				request->has_cname = 1;
			} break;
			case DNS_T_SOA: {
				request->has_soa = 1;
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

static int dns_server_resolve_callback(char *domain, dns_result_type rtype, struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									   void *user_ptr)
{
	struct dns_request *request = user_ptr;

	if (request == NULL) {
		return -1;
	}

	if (rtype == DNS_QUERY_RESULT) {
		if (request->passthrough) {
			_dns_reply_inpacket(request, inpacket, inpacket_len);
			return -1;
		}
		_dns_server_process_answer(request, domain, packet);
		return 0;
	} else if (rtype == DNS_QUERY_ERR) {
		tlog(TLOG_ERROR, "request faield, %s", domain);
		return -1;
	} else {
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

int _dns_server_art_iter_callback(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct dns_address **address;
	address = data;
	*address = value;
	return 0;
}

static int _dns_server_art_domain_cmp(const art_leaf *n, const unsigned char *prefix, int prefix_len)
{
	// Fail if the prefix length is too short
	if (n->key_len > (uint32_t)prefix_len) {
		return 1;
	}

	// Compare the keys
	return memcmp(n->key, prefix, n->key_len);
}

static struct dns_address *_dns_server_get_address_by_domain(char *domain, int qtype)
{
	struct dns_address *address = NULL;
	int domain_len;
	char domain_key[DNS_MAX_CNAME_LEN];
	char type = '4';

	switch (qtype) {
	case DNS_T_A:
		type = '4';
		break;
	case DNS_T_AAAA:
		type = '6';
		break;
	default:
		return NULL;
	}

	domain_len = strlen(domain);
	reverse_string(domain_key + 1, domain, domain_len);
	domain_key[0] = type;
	domain_len++;
	if (art_iter_cmp(&dns_conf_address, (unsigned char *)domain_key, domain_len, _dns_server_art_iter_callback, _dns_server_art_domain_cmp, &address) != 0) {
		return NULL;
	}

	return address;
}

static int _dns_server_process_address(struct dns_request *request, struct dns_packet *packet)
{
	struct dns_address *address = NULL;

	address = _dns_server_get_address_by_domain(request->domain, request->qtype);
	if (address == NULL) {
		goto errout;
	}

	if (request->qtype != address->addr_type) {
		goto errout;
	}

	switch (request->qtype) {
	case DNS_T_A:
		memcpy(request->ipv4_addr, address->ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = 600;
		request->has_ipv4 = 1;
		break;
	case DNS_T_AAAA:
		memcpy(request->ipv6_addr, address->ipv6_addr, DNS_RR_AAAA_LEN);
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

static int _dns_server_recv(unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *from, socklen_t from_len)
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
	int qtype;

	decode_len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (decode_len < 0) {
		tlog(TLOG_ERROR, "decode failed.\n");
		goto errout;
	}

	if (packet->head.qr != DNS_QR_QUERY) {
		goto errout;
	}

	request = malloc(sizeof(*request));
	memset(request, 0, sizeof(*request));
	pthread_mutex_init(&request->ip_map_lock, 0);
	request->ping_ttl_v4 = -1;
	request->ping_ttl_v6 = -1;
	request->rcode = DNS_RC_SERVFAIL;
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

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

	switch (qtype) {
	case DNS_T_PTR:
		ret = _dns_server_process_ptr(request, packet);
		if (ret == 0) {
			free(request);
			return ret;
		} else {
			request->passthrough = 1;
		}
		break;
	case DNS_T_A:
		break;
	case DNS_T_AAAA:
		break;
	default:
		tlog(TLOG_DEBUG, "unsupport qtype: %d, domain: %s", qtype, request->domain);
		request->passthrough = 1;
		break;
	}

	if (_dns_server_process_address(request, packet) == 0) {
		free(request);
		return 0;
	}

	tlog(TLOG_INFO, "query server %s from %s, qtype = %d\n", request->domain, gethost_by_addr(name, (struct sockaddr *)from, from_len), qtype);

	_dns_server_request_get(request);
	pthread_mutex_lock(&server.request_list_lock);
	list_add_tail(&request->list, &server.request_list);
	pthread_mutex_unlock(&server.request_list_lock);

	_dns_server_request_get(request);
	request->send_tick = get_tick_count();
	dns_client_query(request->domain, qtype, dns_server_resolve_callback, request);

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
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}

	return _dns_server_recv(inpacket, len, &from, from_len);
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
			if (_dns_server_ping(request, ip) != 0) {
				_dns_server_request_release(request);
			}
		} break;
		case DNS_T_AAAA: {
			_dns_server_request_get(request);
			sprintf(name, "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]:80", addr_map->ipv6_addr[0], addr_map->ipv6_addr[1],
					addr_map->ipv6_addr[2], addr_map->ipv6_addr[3], addr_map->ipv6_addr[4], addr_map->ipv6_addr[5], addr_map->ipv6_addr[6],
					addr_map->ipv6_addr[7], addr_map->ipv6_addr[8], addr_map->ipv6_addr[9], addr_map->ipv6_addr[10], addr_map->ipv6_addr[11],
					addr_map->ipv6_addr[12], addr_map->ipv6_addr[13], addr_map->ipv6_addr[14], addr_map->ipv6_addr[15]);

			if (_dns_server_ping(request, ip) != 0) {
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

void _dns_server_period_run(void)
{
	struct dns_request *request, *tmp;
	LIST_HEAD(check_list);

	unsigned long now = get_tick_count();

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		if (request->send_tick < now - 500 && request->has_ping_tcp == 0) {
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
				tlog(TLOG_ERROR, "invalid fd\n");
				continue;
			}

			if (_dns_server_process(now) != 0) {
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

int dns_server_start(void)
{
	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = server.fd;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, server.fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int dns_server_socket(void)
{
	int fd = -1;
	struct addrinfo *gai = NULL;
	char port_str[8];
	char ip[MAX_IP_LEN];
	int port;
	char *host = NULL;
	int optval = 1;

	if (parse_ip(dns_conf_server_ip, ip, &port) == 0) {
		host = ip;
	}

	if (port <= 0) {
		port = DEFAULT_DNS_PORT;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);
	gai = _dns_server_getaddr(host, port_str, SOCK_DGRAM, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed.\n");
		goto errout;
	}

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed.\n");
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
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	fd = dns_server_socket();
	if (fd < 0) {
		tlog(TLOG_ERROR, "create server socket failed.\n");
		goto errout;
	}

	pthread_mutex_init(&server.request_list_lock, 0);
	INIT_LIST_HEAD(&server.request_list);
	server.epoll_fd = epollfd;
	server.fd = fd;
	server.run = 1;

	if (dns_server_start() != 0) {
		tlog(TLOG_ERROR, "start service failed.\n");
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

	pthread_mutex_destroy(&server.request_list_lock);

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

	if (server.fd > 0) {
		close(server.fd);
		server.fd = -1;
	}

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		list_add_tail(&request->check_list, &remove_list);
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &remove_list, check_list)
	{
		_dns_server_request_release(request);
	}

	pthread_mutex_destroy(&server.request_list_lock);
}
