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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#define DNS_MAX_EVENTS 256
#define DNS_SERVER_TMOUT_TTL (5 * 60)
#define DNS_CONN_BUFF_SIZE 4096
#define DNS_REQUEST_MAX_TIMEOUT 850
#define DNS_PING_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT)
#define DNS_TCPPING_START (300)
#define DNS_PING_SECOND_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT - DNS_TCPPING_START)
#define SOCKET_IP_TOS (IPTOS_LOWDELAY | IPTOS_RELIABILITY)
#define SOCKET_PRIORITY (6)
#define CACHE_AUTO_ENABLE_SIZE (1024 * 1024 * 128)

#define RECV_ERROR_AGAIN 1
#define RECV_ERROR_OK 0
#define RECV_ERROR_FAIL -1
#define RECV_ERROR_CLOSE -2

typedef enum {
	DNS_CONN_TYPE_UDP_SERVER = 0,
	DNS_CONN_TYPE_TCP_SERVER,
	DNS_CONN_TYPE_TCP_CLIENT,
	DNS_CONN_TYPE_TLS_SERVER,
	DNS_CONN_TYPE_TLS_CLIENT,
} DNS_CONN_TYPE;

struct rule_walk_args {
	void *args;
	unsigned char *key[DOMAIN_RULE_MAX];
	uint32_t key_len[DOMAIN_RULE_MAX];
};

struct dns_conn_buf {
	char buf[DNS_CONN_BUFF_SIZE];
	int buffsize;
	int size;
};

struct dns_server_conn_head {
	DNS_CONN_TYPE type;
	int fd;
	struct list_head list;
	time_t last_request_time;
	atomic_t refcnt;
	const char *dns_group;
	uint32_t server_flags;
};

struct dns_server_conn_udp {
	struct dns_server_conn_head head;
	socklen_t addr_len;
	struct sockaddr_storage addr;
};

struct dns_server_conn_tcp_server {
	struct dns_server_conn_head head;
};

struct dns_server_conn_tcp_client {
	struct dns_server_conn_head head;
	struct dns_conn_buf recvbuff;
	struct dns_conn_buf sndbuff;
	socklen_t addr_len;
	struct sockaddr_storage addr;

	socklen_t localaddr_len;
	struct sockaddr_storage localaddr;
};

/* dns server data */
struct dns_server {
	int run;
	int epoll_fd;
	struct list_head conn_list;

	/* dns request list */
	pthread_mutex_t request_list_lock;
	struct list_head request_list;
};

/* ip address lists of domain */
struct dns_ip_address {
	struct hlist_node node;
	int hitnum;
	unsigned long recv_tick;
	dns_type_t addr_type;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

struct dns_request {
	atomic_t refcnt;

	struct dns_server_conn_head *conn;
	uint32_t server_flags;

	/* dns request list */
	struct list_head list;

	/* dns request timeout check list */
	struct list_head check_list;

	/* dns query */
	char domain[DNS_MAX_CNAME_LEN];
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
	struct sockaddr_storage localaddr;

	dns_result_callback result_callback;
	void *user_ptr;

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
	atomic_t do_callback;
	atomic_t adblock;
	atomic_t soa_num;

	/* send original raw packet to server/client like proxy */
	int passthrough;
	int request_wait;
	int prefetch;
	int dualstack_selection;

	pthread_mutex_t ip_map_lock;

	int ip_map_num;
	DECLARE_HASHTABLE(ip_map, 4);

	struct dns_domain_rule domain_rule;
	struct dns_domain_check_order *check_order_list;
};

static struct dns_server server;

static tlog_log *dns_audit;

static int _dns_server_prefetch_request(char *domain, dns_type_t qtype, uint32_t server_flags);

static int _dns_server_forward_request(unsigned char *inpacket, int inpacket_len)
{
	tlog(TLOG_DEBUG, "forward request.\n");
	return -1;
}

static int _dns_server_has_bind_flag(struct dns_request *request, uint32_t flag)
{
	if (request->server_flags & flag) {
		return 0;
	}

	return -1;
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

static int _dns_server_epoll_ctl(struct dns_server_conn_head *head, int op, uint32_t events)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = events;
	event.data.ptr = head;

	if (epoll_ctl(server.epoll_fd, op, head->fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, fd = %d, %s", head->fd, strerror(errno));
		return -1;
	}

	return 0;
}

static void _dns_server_set_dualstack_selection(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;

	rule_flag = request->domain_rule.rules[DOMAIN_RULE_FLAGS];
	if (rule_flag) {
		if (rule_flag->flags & DOMAIN_FLAG_DUALSTACK_SELECT) {
			request->dualstack_selection = 1;
			return;
		}

		if (rule_flag->is_flag_set & DOMAIN_FLAG_DUALSTACK_SELECT) {
			request->dualstack_selection = 0;
			return;
		}
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_DUALSTACK_SELECTION) == 0) {
		request->dualstack_selection = 0;
		return;
	}

	request->dualstack_selection = dns_conf_dualstack_ip_selection;
}

static int _dns_server_is_return_soa(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;
	unsigned int flags = 0;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_SOA) == 0) {
		return 0;
	}

	if (request->qtype == DNS_T_AAAA) {
		if (_dns_server_has_bind_flag(request, BIND_FLAG_FORCE_AAAA_SOA) == 0 || dns_conf_force_AAAA_SOA == 1) {
			return 1;
		}
	}

	rule_flag = request->domain_rule.rules[DOMAIN_RULE_FLAGS];
	if (rule_flag) {
		flags = rule_flag->flags;
		if (flags & DOMAIN_FLAG_ADDR_SOA) {
			return 1;
		}

		if ((flags & DOMAIN_FLAG_ADDR_IPV4_SOA) && (request->qtype == DNS_T_A)) {
			return 1;
		}

		if ((flags & DOMAIN_FLAG_ADDR_IPV6_SOA) && (request->qtype == DNS_T_AAAA)) {
			return 1;
		}
	}

	return 0;
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

	if (request->qtype == DNS_T_AAAA && request->has_ipv6) {
		snprintf(req_result, sizeof(req_result),
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", request->ipv6_addr[0],
				 request->ipv6_addr[1], request->ipv6_addr[2], request->ipv6_addr[3], request->ipv6_addr[4],
				 request->ipv6_addr[5], request->ipv6_addr[6], request->ipv6_addr[7], request->ipv6_addr[8],
				 request->ipv6_addr[9], request->ipv6_addr[10], request->ipv6_addr[11], request->ipv6_addr[12],
				 request->ipv6_addr[13], request->ipv6_addr[14], request->ipv6_addr[15]);
	} else if (request->qtype == DNS_T_A && request->has_ipv4) {
		snprintf(req_result, sizeof(req_result), "%d.%d.%d.%d", request->ipv4_addr[0], request->ipv4_addr[1],
				 request->ipv4_addr[2], request->ipv4_addr[3]);
	} else if (request->has_soa) {
		if (!dns_conf_audit_log_SOA) {
			return;
		}

		snprintf(req_result, sizeof(req_result), "SOA");
	} else {
		return;
	}
	gethost_by_addr(req_host, sizeof(req_host), &request->addr);
	tlog_localtime(&tm);

	snprintf(req_time, sizeof(req_time), "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d]", tm.year, tm.mon, tm.mday, tm.hour,
			 tm.min, tm.sec, tm.usec / 1000);

	tlog_printf(dns_audit, "%s %s query %s, type %d, result %s\n", req_time, req_host, request->domain, request->qtype,
				req_result);
}

static int _dns_add_rrs(struct dns_packet *packet, struct dns_request *request)
{
	int ret = 0;
	char *domain = request->domain;
	if (request->has_ptr) {
		/* add PTR record */
		char hostname[DNS_MAX_CNAME_LEN];
		if (dns_conf_server_name[0] == 0) {
			/* get local host name */
			if (getdomainname(hostname, DNS_MAX_CNAME_LEN) != 0) {
				if (gethostname(hostname, DNS_MAX_CNAME_LEN) != 0) {
					return -1;
				}
			}

			/* get host name again */
			if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN) == 0) {
				if (gethostname(hostname, DNS_MAX_CNAME_LEN) != 0) {
					return -1;
				}
			}

			/* if hostname is (none), return smartdns */
			if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN) == 0) {
				safe_strncpy(hostname, "smartdns", DNS_MAX_CNAME_LEN);
			}
		} else {
			/* return configured server name */
			safe_strncpy(hostname, dns_conf_server_name, DNS_MAX_CNAME_LEN);
		}

		ret = dns_add_PTR(packet, DNS_RRS_AN, request->domain, 30, hostname);
	}

	/* add CNAME record */
	if (request->has_cname) {
		ret |= dns_add_CNAME(packet, DNS_RRS_AN, request->domain, request->ttl_cname, request->cname);
		domain = request->cname;
	}

	/* add A record */
	if (request->has_ipv4 && request->qtype == DNS_T_A) {
		ret |= dns_add_A(packet, DNS_RRS_AN, domain, request->ttl_v4, request->ipv4_addr);
	}

	/* add AAAA record */
	if (request->has_ipv6 && request->qtype == DNS_T_AAAA) {
		if (request->has_ipv4) {
			ret |= dns_add_A(packet, DNS_RRS_AN, domain, request->ttl_v4, request->ipv4_addr);
		}
		ret |= dns_add_AAAA(packet, DNS_RRS_AN, domain, request->ttl_v6, request->ipv6_addr);
	}

	/* add SOA record */
	if (request->has_soa) {
		ret |= dns_add_SOA(packet, DNS_RRS_NS, domain, 0, &request->soa);
	}

	return ret;
}

static void _dns_server_conn_release(struct dns_server_conn_head *conn)
{
	if (conn == NULL) {
		return;
	}

	int refcnt = atomic_dec_return(&conn->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: refcnt is %d, type = %d", refcnt, conn->type);
			abort();
		}
		return;
	}

	if (conn->fd > 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	list_del_init(&conn->list);
	free(conn);
}

static void _dns_server_conn_get(struct dns_server_conn_head *conn)
{
	if (conn == NULL) {
		return;
	}

	if (atomic_inc_return(&conn->refcnt) <= 0) {
		tlog(TLOG_ERROR, "BUG: client ref is invalid.");
		abort();
	}
}

static int _dns_server_reply_tcp_to_buffer(struct dns_server_conn_tcp_client *tcpclient, void *packet, int len)
{
	if (sizeof(tcpclient->sndbuff.buf) - tcpclient->sndbuff.size < len) {
		return -1;
	}

	memcpy(tcpclient->sndbuff.buf + tcpclient->sndbuff.size, packet, len);
	tcpclient->sndbuff.size += len;

	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

static int _dns_server_reply_tcp(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient,
								 void *packet, unsigned short len)
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

	send_len = send(tcpclient->head.fd, inpacket, len, MSG_NOSIGNAL);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket, len);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket + send_len, len - send_len);
	}

	return 0;
}

static int _dns_server_reply_udp(struct dns_request *request, struct dns_server_conn_udp *udpserver,
								 unsigned char *inpacket, int inpacket_len)
{
	int send_len = 0;
	send_len =
		sendto(udpserver->head.fd, inpacket, inpacket_len, 0, (struct sockaddr *)&request->addr, request->addr_len);
	if (send_len != inpacket_len) {
		tlog(TLOG_ERROR, "send failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int _dns_reply_inpacket(struct dns_request *request, unsigned char *inpacket, int inpacket_len)
{
	struct dns_server_conn_head *conn = request->conn;
	int ret = 0;

	if (conn == NULL) {
		tlog(TLOG_ERROR, "client is invalid, domain: %s", request->domain);
		return -1;
	}

	if (conn->type == DNS_CONN_TYPE_UDP_SERVER) {
		ret = _dns_server_reply_udp(request, (struct dns_server_conn_udp *)conn, inpacket, inpacket_len);
	} else if (conn->type == DNS_CONN_TYPE_TCP_CLIENT) {
		ret = _dns_server_reply_tcp(request, (struct dns_server_conn_tcp_client *)conn, inpacket, inpacket_len);
	} else if (conn->type == DNS_CONN_TYPE_TLS_CLIENT) {
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

	if (request->conn == NULL) {
		return 0;
	}

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

	/* init a new DNS packet */
	ret = dns_packet_init(packet, DNS_PACKSIZE, &head);
	if (ret != 0) {
		return -1;
	}

	/* add request domain */
	ret = dns_add_domain(packet, request->domain, request->qtype, DNS_C_IN);
	if (ret != 0) {
		return -1;
	}

	/* add RECORDs */
	ret = _dns_add_rrs(packet, request);
	if (ret != 0) {
		return -1;
	}

	/* encode to binary data */
	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		return -1;
	}

	/* send request */
	return _dns_reply_inpacket(request, inpacket, encode_len);
}

static int _dns_result_callback_nxdomain(struct dns_request *request)
{
	char ip[DNS_MAX_CNAME_LEN];
	unsigned int ping_time = -1;

	ip[0] = 0;
	if (request->result_callback == NULL) {
		return 0;
	}

	return request->result_callback(request->domain, DNS_RC_NXDOMAIN, request->qtype, ip, ping_time, request->user_ptr);
}

static int _dns_result_callback(struct dns_request *request)
{
	char ip[DNS_MAX_CNAME_LEN];
	unsigned int ping_time = -1;

	if (request->result_callback == NULL) {
		return 0;
	}

	if (atomic_inc_return(&request->do_callback) != 1) {
		return 0;
	}

	ip[0] = 0;
	if (request->qtype == DNS_T_A) {
		if (request->has_ipv4 == 0) {
			goto out;
		}

		sprintf(ip, "%d.%d.%d.%d", request->ipv4_addr[0], request->ipv4_addr[1], request->ipv4_addr[2],
				request->ipv4_addr[3]);
		ping_time = request->ping_ttl_v4;
		return request->result_callback(request->domain, request->rcode, request->qtype, ip, ping_time,
										request->user_ptr);
	} else if (request->qtype == DNS_T_AAAA) {
		if (request->has_ipv6 == 0) {
			goto out;
		}

		sprintf(ip, "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x", request->ipv6_addr[0],
				request->ipv6_addr[1], request->ipv6_addr[2], request->ipv6_addr[3], request->ipv6_addr[4],
				request->ipv6_addr[5], request->ipv6_addr[6], request->ipv6_addr[7], request->ipv6_addr[8],
				request->ipv6_addr[9], request->ipv6_addr[10], request->ipv6_addr[11], request->ipv6_addr[12],
				request->ipv6_addr[13], request->ipv6_addr[14], request->ipv6_addr[15]);
		ping_time = request->ping_ttl_v6;
		return request->result_callback(request->domain, request->rcode, request->qtype, ip, ping_time,
										request->user_ptr);
	}

	_dns_result_callback_nxdomain(request);

	return 0;
out:

	_dns_result_callback_nxdomain(request);
	return 0;
}

static int _dns_server_reply_SOA(int rcode, struct dns_request *request)
{
	struct dns_soa *soa;

	/* return SOA record */
	request->rcode = rcode;
	request->has_soa = 1;
	request->has_ipv4 = 0;
	request->has_ipv6 = 0;
	request->has_ptr = 0;

	soa = &request->soa;

	safe_strncpy(soa->mname, "a.gtld-servers.net", DNS_MAX_CNAME_LEN);
	safe_strncpy(soa->rname, "nstld.verisign-grs.com", DNS_MAX_CNAME_LEN);
	soa->serial = 1800;
	soa->refresh = 1800;
	soa->retry = 900;
	soa->expire = 604800;
	soa->minimum = 86400;

	_dns_result_callback(request);

	_dns_reply(request);

	return 0;
}

/* add ip to specific ipset */
static int _dns_setup_ipset(struct dns_request *request)
{
	struct dns_ipset_rule *rule = NULL, *ipset_rule = NULL, *ipset_rule_v4 = NULL, *ipset_rule_v6 = NULL;
	struct dns_rule_flags *rule_flags = NULL;
	int ret = 0;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_IPSET) == 0) {
		return 0;
	}

	/* check ipset rule */
	rule_flags = request->domain_rule.rules[DOMAIN_RULE_FLAGS];
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IGN) == 0) {
		ipset_rule = request->domain_rule.rules[DOMAIN_RULE_IPSET];
	}
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV4_IGN) == 0) {
		ipset_rule_v4 = request->domain_rule.rules[DOMAIN_RULE_IPSET_IPV4];
	}
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV6_IGN) == 0) {
		ipset_rule_v6 = request->domain_rule.rules[DOMAIN_RULE_IPSET_IPV6];
	}

	if (!(ipset_rule || ipset_rule_v4 || ipset_rule_v6)) {
		return 0;
	}

	/* add IPV4 to ipset */
	if (request->has_ipv4 && request->qtype == DNS_T_A) {
		rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
		if (rule) {
			ret |= ipset_add(rule->ipsetname, request->ipv4_addr, DNS_RR_A_LEN, request->ttl_v4 * 2);
			tlog(TLOG_DEBUG, "IPSET-MATCH: domain:%s, ipset:%s, IP: %d.%d.%d.%d, result: %d", request->domain,
				 rule->ipsetname, request->ipv4_addr[0], request->ipv4_addr[1], request->ipv4_addr[2],
				 request->ipv4_addr[3], ret);
		}
	}

	/* add IPV6 to ipset */
	if (request->has_ipv6 && request->qtype == DNS_T_AAAA) {
		if (request->has_ipv4) {
			rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
			if (rule) {
				ret |= ipset_add(rule->ipsetname, request->ipv4_addr, DNS_RR_A_LEN, request->ttl_v4 * 2);
				tlog(TLOG_DEBUG, "IPSET-MATCH: domain:%s, ipset:%s, IP: %d.%d.%d.%d, result: %d", request->domain,
					 rule->ipsetname, request->ipv4_addr[0], request->ipv4_addr[1], request->ipv4_addr[2],
					 request->ipv4_addr[3], ret);
			}
		}
		rule = ipset_rule_v6 ? ipset_rule_v6 : ipset_rule;
		if (rule) {
			ret |= ipset_add(rule->ipsetname, request->ipv6_addr, DNS_RR_AAAA_LEN, request->ttl_v6 * 2);
			tlog(TLOG_DEBUG,
				 "IPSET-MATCH: domain:%s, ipset:%s, IP: "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x, result: %d",
				 request->domain, rule->ipsetname, request->ipv6_addr[0], request->ipv6_addr[1], request->ipv6_addr[2],
				 request->ipv6_addr[3], request->ipv6_addr[4], request->ipv6_addr[5], request->ipv6_addr[6],
				 request->ipv6_addr[7], request->ipv6_addr[8], request->ipv6_addr[9], request->ipv6_addr[10],
				 request->ipv6_addr[11], request->ipv6_addr[12], request->ipv6_addr[13], request->ipv6_addr[14],
				 request->ipv6_addr[15], ret);
		}
	}

	return ret;
}

static int _dns_server_request_update_cache(struct dns_request *request, dns_type_t qtype,
											struct dns_cache_data *cache_data)
{
	int ttl;
	int speed = 0;

	if (qtype == DNS_T_A) {
		ttl = _dns_server_get_conf_ttl(request->ttl_v4);
		speed = request->ping_ttl_v4;
	} else if (qtype == DNS_T_AAAA) {
		ttl = _dns_server_get_conf_ttl(request->ttl_v6);
		speed = request->ping_ttl_v6;
	} else {
		goto errout;
	}

	if (request->has_soa) {
		ttl = dns_conf_rr_ttl;
	}

	/* if doing prefetch, update cache only */
	if (request->prefetch) {
		if (dns_cache_replace(request->domain, ttl, qtype, speed, cache_data) != 0) {
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(request->domain, ttl, qtype, speed, cache_data) != 0) {
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_data) {
		dns_cache_data_free(cache_data);
	}
	return -1;
}

static int _dns_server_request_complete_A(struct dns_request *request)
{
	char *cname = NULL;
	int cname_ttl = dns_conf_rr_ttl;
	struct dns_cache_data *cache_data = NULL;

	if (request->has_cname) {
		cname = request->cname;
		cname_ttl = request->ttl_cname;
	}

	cache_data = dns_cache_new_data();
	if (cache_data == NULL) {
		goto errout;
	}

	if (request->has_ipv4 != 0) {
		tlog(TLOG_INFO, "result: %s, rcode: %d,  %d.%d.%d.%d\n", request->domain, request->rcode, request->ipv4_addr[0],
			 request->ipv4_addr[1], request->ipv4_addr[2], request->ipv4_addr[3]);

		request->has_soa = 0;
		if (request->has_ping_result == 0 && request->ttl_v4 > DNS_SERVER_TMOUT_TTL) {
			request->ttl_v4 = DNS_SERVER_TMOUT_TTL;
		}
		dns_cache_set_data_addr(cache_data, request->server_flags, cname, cname_ttl, request->ipv4_addr, DNS_RR_A_LEN);
	} else {
		dns_cache_set_data_soa(cache_data, request->server_flags, cname, cname_ttl);
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) == 0) {
		dns_cache_data_free(cache_data);
		return 0;
	}

	if (_dns_server_request_update_cache(request, DNS_T_A, cache_data) != 0) {
		goto errout;
	}

	return 0;

errout:
	if (cache_data) {
		dns_cache_data_free(cache_data);
		cache_data = NULL;
	}

	return -1;
}

static int _dns_server_request_complete_AAAA(struct dns_request *request)
{
	int ret = -1;
	char *cname = NULL;
	int cname_ttl = dns_conf_rr_ttl;
	struct dns_cache_data *cache_data = NULL;

	if (request->has_cname) {
		cname = request->cname;
		cname_ttl = request->ttl_cname;
	}

	cache_data = dns_cache_new_data();
	if (cache_data == NULL) {
		goto errout;
	}

	if (request->has_ipv6) {
		tlog(TLOG_INFO,
			 "result: %s, rcode: %d,  %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
			 request->domain, request->rcode, request->ipv6_addr[0], request->ipv6_addr[1], request->ipv6_addr[2],
			 request->ipv6_addr[3], request->ipv6_addr[4], request->ipv6_addr[5], request->ipv6_addr[6],
			 request->ipv6_addr[7], request->ipv6_addr[8], request->ipv6_addr[9], request->ipv6_addr[10],
			 request->ipv6_addr[11], request->ipv6_addr[12], request->ipv6_addr[13], request->ipv6_addr[14],
			 request->ipv6_addr[15]);

		if (request->has_ping_result == 0 && request->ttl_v6 > DNS_SERVER_TMOUT_TTL) {
			request->ttl_v6 = DNS_SERVER_TMOUT_TTL;
		}

		/* if doing prefetch, update cache only */
		dns_cache_set_data_addr(cache_data, request->server_flags, cname, cname_ttl, request->ipv6_addr, DNS_T_AAAA);

		request->has_soa = 0;
	} else {
		dns_cache_set_data_soa(cache_data, request->server_flags, cname, cname_ttl);
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) != 0) {
		if (_dns_server_request_update_cache(request, DNS_T_AAAA, cache_data) != 0) {
			goto errout;
		}
		cache_data = NULL;
	} else {
		dns_cache_data_free(cache_data);
		cache_data = NULL;
	}

	if (request->has_ipv4 && (request->ping_ttl_v4 > 0)) {
		tlog(TLOG_INFO, "result: %s, rcode: %d,  %d.%d.%d.%d\n", request->domain, request->rcode, request->ipv4_addr[0],
			 request->ipv4_addr[1], request->ipv4_addr[2], request->ipv4_addr[3]);

		/* if ipv4 is fasting than ipv6, add ipv4 to cache, and return SOA for AAAA request */
		if ((request->ping_ttl_v4 + (dns_conf_dualstack_ip_selection_threshold * 10)) < request->ping_ttl_v6 ||
			request->ping_ttl_v6 < 0) {
			tlog(TLOG_DEBUG, "Force IPV4 perfered.");
			if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) != 0) {
				cache_data = dns_cache_new_data();
				if (cache_data == NULL) {
					goto errout;
				}

				dns_cache_set_data_addr(cache_data, request->server_flags, cname, cname_ttl, request->ipv4_addr,
										DNS_T_A);
				if (_dns_server_request_update_cache(request, DNS_T_A, cache_data) != 0) {
					goto errout;
				}
				cache_data = NULL;
			}

			if (request->dualstack_selection) {
				if (_dns_server_reply_SOA(DNS_RC_NOERROR, request) != 0) {
					ret = -1;
					goto errout;
				}

				ret = 1;
				goto errout;
			}
		}
	}

	request->has_ipv4 = 0;

	return 0;

errout:
	if (cache_data != NULL) {
		dns_cache_data_free(cache_data);
		cache_data = NULL;
	}

	return ret;
}

static int _dns_server_request_complete(struct dns_request *request)
{
	int ret = 0;

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	/* if passthrouth, return */
	if (request->passthrough) {
		return 0;
	}

	if (request->qtype == DNS_T_A) {
		if (_dns_server_request_complete_A(request) != 0) {
			tlog(TLOG_ERROR, "complete DNS A failed.");
			return -1;
		}
	} else if (request->qtype == DNS_T_AAAA) {
		ret = _dns_server_request_complete_AAAA(request);
		if (ret != 0) {
			if (ret == 1) {
				return 0;
			}
			tlog(TLOG_ERROR, "complete DNS A failed.");
			return -1;
		}
	}

	if (request->has_soa) {
		tlog(TLOG_INFO, "result: %s, qtype: %d, SOA", request->domain, request->qtype);
	}

	/* update ipset */
	_dns_setup_ipset(request);

	_dns_result_callback(request);

	if (request->prefetch) {
		return 0;
	}

	/* return result to client */
	_dns_reply(request);

	return 0;
}

static void _dns_server_request_release(struct dns_request *request);
static void _dns_server_request_remove(struct dns_request *request)
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

static void _dns_server_select_possible_ipaddress(struct dns_request *request)
{
	int maxhit = 0;
	int bucket = 0;
	unsigned long max_recv_tick = 0;
	struct dns_ip_address *addr_map;
	struct dns_ip_address *maxhit_addr_map = NULL;
	struct dns_ip_address *last_recv_addr_map = NULL;
	struct dns_ip_address *selected_addr_map = NULL;
	struct hlist_node *tmp;

	if (atomic_read(&request->notified) > 0) {
		return;
	}

	/* Return the most likely correct IP address */
	/* Returns the IP with the most hits, or the last returned record is considered to be the most likely correct. */
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		if (addr_map->addr_type != request->qtype) {
			continue;
		}

		if (addr_map->recv_tick - request->send_tick > max_recv_tick) {
			max_recv_tick = addr_map->recv_tick - request->send_tick;
			last_recv_addr_map = addr_map;
		}

		if (addr_map->hitnum > maxhit) {
			maxhit = addr_map->hitnum;
			maxhit_addr_map = addr_map;
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	if (maxhit_addr_map && maxhit > 1) {
		selected_addr_map = maxhit_addr_map;
	} else if (last_recv_addr_map) {
		selected_addr_map = last_recv_addr_map;
	}

	if (selected_addr_map == NULL) {
		return;
	}

	tlog(TLOG_DEBUG, "select best ip address, %s", request->domain);
	switch (request->qtype) {
	case DNS_T_A: {
		memcpy(request->ipv4_addr, selected_addr_map->ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = DNS_SERVER_TMOUT_TTL;
		tlog(TLOG_DEBUG, "possible result: %s, rcode: %d,  %d.%d.%d.%d\n", request->domain, request->rcode,
			 request->ipv4_addr[0], request->ipv4_addr[1], request->ipv4_addr[2], request->ipv4_addr[3]);
	} break;
	case DNS_T_AAAA: {
		memcpy(request->ipv6_addr, selected_addr_map->ipv6_addr, DNS_RR_AAAA_LEN);
		request->ttl_v6 = DNS_SERVER_TMOUT_TTL;
		tlog(TLOG_DEBUG,
			 "possible result: %s, rcode: %d,  %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
			 request->domain, request->rcode, request->ipv6_addr[0], request->ipv6_addr[1], request->ipv6_addr[2],
			 request->ipv6_addr[3], request->ipv6_addr[4], request->ipv6_addr[5], request->ipv6_addr[6],
			 request->ipv6_addr[7], request->ipv6_addr[8], request->ipv6_addr[9], request->ipv6_addr[10],
			 request->ipv6_addr[11], request->ipv6_addr[12], request->ipv6_addr[13], request->ipv6_addr[14],
			 request->ipv6_addr[15]);
	} break;
	default:
		break;
	}
}

static void _dns_server_delete_request(struct dns_request *request)
{
	if (request->conn) {
		_dns_server_conn_release(request->conn);
	}
	pthread_mutex_destroy(&request->ip_map_lock);
	memset(request, 0, sizeof(*request));
	free(request);
}

static void _dns_server_request_release_complete(struct dns_request *request, int do_complete)
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

	if (do_complete) {
		/* Select max hit ip address, and return to client */
		_dns_server_select_possible_ipaddress(request);
		_dns_server_request_complete(request);
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	_dns_server_delete_request(request);
}

static void _dns_server_request_release(struct dns_request *request)
{
	_dns_server_request_release_complete(request, 1);
}

static void _dns_server_request_get(struct dns_request *request)
{
	if (atomic_inc_return(&request->refcnt) <= 0) {
		tlog(TLOG_ERROR, "BUG: request ref is invalid, %s", request->domain);
		abort();
	}
}

static struct dns_request *_dns_server_new_request(void)
{
	struct dns_request *request = NULL;

	request = malloc(sizeof(*request));
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	memset(request, 0, sizeof(*request));
	pthread_mutex_init(&request->ip_map_lock, NULL);
	atomic_set(&request->adblock, 0);
	atomic_set(&request->soa_num, 0);
	atomic_set(&request->refcnt, 0);
	atomic_set(&request->notified, 0);
	atomic_set(&request->do_callback, 0);
	request->ping_ttl_v4 = -1;
	request->ping_ttl_v6 = -1;
	request->prefetch = 0;
	request->dualstack_selection = dns_conf_dualstack_ip_selection;
	request->rcode = DNS_RC_SERVFAIL;
	request->conn = NULL;
	request->result_callback = NULL;
	request->check_order_list = &dns_conf_check_order;
	INIT_LIST_HEAD(&request->list);
	hash_init(request->ip_map);
	_dns_server_request_get(request);

	return request;
errout:
	return NULL;
}

static void _dns_server_ping_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
									struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
									void *userptr)
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
	} else if (result == PING_RESULT_TIMEOUT) {
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

		if (request->qtype == DNS_T_AAAA && request->dualstack_selection) {
			if (request->ping_ttl_v6 < 0 && request->has_soa == 0) {
				return;
			}
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
		tlog(TLOG_DEBUG, "from %s: seq=%d time=%d\n", host, seqno, rtt);
	} else {
		tlog(TLOG_DEBUG, "from %s: seq=%d timeout\n", host, seqno);
	}

	/* If the ping delay is less than the threshold, the result is returned */
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

static int _dns_server_ping(struct dns_request *request, PING_TYPE type, char *ip, int timeout)
{
	if (fast_ping_start(type, ip, 1, 0, timeout, _dns_server_ping_result, request) == NULL) {
		return -1;
	}

	return 0;
}

static int _dns_server_check_speed(struct dns_request *request, char *ip, int mode_order, int timeout)
{
	char tcp_ip[DNS_MAX_CNAME_LEN] = {0};
	int port = 80;
	int type = DOMAIN_CHECK_NONE;

	if (mode_order >= DOMAIN_CHECK_NUM || request->check_order_list == NULL) {
		return -1;
	}

	port = request->check_order_list->tcp_port;
	type = request->check_order_list->order[mode_order];
	switch (type) {
	case DOMAIN_CHECK_ICMP:
		tlog(TLOG_DEBUG, "ping %s with icmp", ip);
		return _dns_server_ping(request, PING_TYPE_ICMP, ip, timeout);
		break;
	case DOMAIN_CHECK_TCP:
		snprintf(tcp_ip, sizeof(tcp_ip), "%s:%d", ip, port);
		tlog(TLOG_DEBUG, "ping %s with tcp", tcp_ip);
		return _dns_server_ping(request, PING_TYPE_TCP, tcp_ip, timeout);
		break;
	default:
		break;
	}

	return -1;
}

static int _dns_ip_address_check_add(struct dns_request *request, unsigned char *addr, dns_type_t addr_type)
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

	/* store the ip address and the number of hits */
	key = jhash(addr, addr_len, 0);
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_possible(request->ip_map, addr_map, node, key)
	{
		if (addr_type == DNS_T_A) {
			if (memcmp(addr_map->ipv4_addr, addr, addr_len) == 0) {
				addr_map->hitnum++;
				addr_map->recv_tick = get_tick_count();
				pthread_mutex_unlock(&request->ip_map_lock);
				return -1;
			}
		} else if (addr_type == DNS_T_AAAA) {
			if (memcmp(addr_map->ipv6_addr, addr, addr_len) == 0) {
				addr_map->hitnum++;
				addr_map->recv_tick = get_tick_count();
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
	addr_map->recv_tick = get_tick_count();
	memcpy(addr_map->addr, addr, addr_len);
	hash_add(request->ip_map, &addr_map->node, key);
	pthread_mutex_unlock(&request->ip_map_lock);

	return 0;
}

static int _dns_server_ip_rule_check(struct dns_request *request, unsigned char *addr, int addr_len,
									 dns_type_t addr_type, int result_flag)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct dns_ip_address_rule *rule = NULL;

	/* Match IP address rules */
	if (prefix_from_blob(addr, addr_len, addr_len * 8, &prefix) == NULL) {
		return -1;
	}

	switch (prefix.family) {
	case AF_INET:
		node = radix_search_best(dns_conf_address_rule.ipv4, &prefix);
		break;
	case AF_INET6:
		node = radix_search_best(dns_conf_address_rule.ipv6, &prefix);
		break;
	default:
		break;
	}

	if (node == NULL) {
		goto rule_not_found;
	}

	if (node->data == NULL) {
		goto rule_not_found;
	}

	/* bogux-nxdomain */
	rule = node->data;
	if (rule->bogus) {
		goto match;
	}

	/* blacklist-ip */
	if (rule->blacklist) {
		if (result_flag & DNSSERVER_FLAG_BLACKLIST_IP) {
			goto match;
		}
	}

	/* ignore-ip */
	if (rule->ip_ignore) {
		goto skip;
	}

rule_not_found:
	if (result_flag & DNSSERVER_FLAG_WHITELIST_IP) {
		if (rule == NULL) {
			goto skip;
		}

		if (!rule->whitelist) {
			goto skip;
		}
	}
	return -1;
skip:
	return -2;
match:
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NXDOMAIN;
	}
	return 0;
}

static int _dns_server_is_adblock_ipv6(unsigned char addr[16])
{
	int i = 0;

	for (i = 0; i < 15; i++) {
		if (addr[i]) {
			return -1;
		}
	}

	if (addr[15] == 0 || addr[15] == 1) {
		return 0;
	}

	return -1;
}

static int _dns_server_process_answer_A(struct dns_rrs *rrs, struct dns_request *request, char *domain,
										unsigned int result_flag, int ping_timeout)
{
	int ttl;
	int ip_check_result = 0;
	unsigned char addr[4];
	char name[DNS_MAX_CNAME_LEN] = {0};
	char ip[DNS_MAX_CNAME_LEN] = {0};

	if (request->qtype != DNS_T_A) {
		/* ignore non-matched query type */
		if (request->dualstack_selection == 0) {
			return 0;
		}
	}
	_dns_server_request_get(request);
	/* get A result */
	dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

	tlog(TLOG_DEBUG, "domain: %s TTL:%d IP: %d.%d.%d.%d", name, ttl, addr[0], addr[1], addr[2], addr[3]);

	/* ip rule check */
	ip_check_result = _dns_server_ip_rule_check(request, addr, 4, DNS_T_A, result_flag);
	if (ip_check_result == 0) {
		/* match */
		_dns_server_request_release(request);
		return -1;
	} else if (ip_check_result == -2) {
		/* skip */
		_dns_server_request_release(request);
		return -2;
	}

	/* if domain is not match */
	if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(request->cname, name, DNS_MAX_CNAME_LEN) != 0) {
		_dns_server_request_release(request);
		return -1;
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

	/* Ad blocking result */
	if (addr[0] == 0 || addr[0] == 127) {
		/* If half of the servers return the same result, then the domain name result is the IP address. */
		if (atomic_inc_return(&request->adblock) <= dns_server_num() / 2) {
			_dns_server_request_release(request);
			return -1;
		}
	}

	/* add this ip to reqeust */
	if (_dns_ip_address_check_add(request, addr, DNS_T_A) != 0) {
		_dns_server_request_release(request);
		return -1;
	}

	sprintf(ip, "%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);

	/* start ping */
	if (_dns_server_check_speed(request, ip, 0, ping_timeout) != 0) {
		_dns_server_request_release(request);
	}

	return 0;
}

static int _dns_server_process_answer_AAAA(struct dns_rrs *rrs, struct dns_request *request, char *domain,
										   unsigned int result_flag, int ping_timeout)
{
	unsigned char addr[16];
	char name[DNS_MAX_CNAME_LEN] = {0};
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ttl;
	int ip_check_result = 0;

	if (request->qtype != DNS_T_AAAA) {
		/* ignore non-matched query type */
		return -1;
	}
	_dns_server_request_get(request);
	dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

	tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
		 name, ttl, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10],
		 addr[11], addr[12], addr[13], addr[14], addr[15]);

	ip_check_result = _dns_server_ip_rule_check(request, addr, 16, DNS_T_AAAA, result_flag);
	if (ip_check_result == 0) {
		/* match */
		_dns_server_request_release(request);
		return -1;
	} else if (ip_check_result == -2) {
		/* skip */
		_dns_server_request_release(request);
		return -2;
	}

	/* if domain is not match */
	if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(request->cname, name, DNS_MAX_CNAME_LEN) != 0) {
		_dns_server_request_release(request);
		return -1;
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

	/* Ad blocking result */
	if (_dns_server_is_adblock_ipv6(addr) == 0) {
		/* If half of the servers return the same result, then the domain name result is the IP address. */
		if (atomic_inc_return(&request->adblock) <= dns_server_num() / 2) {
			_dns_server_request_release(request);
			return -1;
		}
	}

	/* add this ip to reqeust */
	if (_dns_ip_address_check_add(request, addr, DNS_T_AAAA) != 0) {
		_dns_server_request_release(request);
		return -1;
	}

	sprintf(ip, "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]", addr[0], addr[1], addr[2],
			addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13],
			addr[14], addr[15]);

	/* start ping */
	if (_dns_server_check_speed(request, ip, 0, ping_timeout) != 0) {
		_dns_server_request_release(request);
	}

	return 0;
}

static int _dns_server_process_answer(struct dns_request *request, char *domain, struct dns_packet *packet,
									  unsigned int result_flag)
{
	int ttl;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int rr_count;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ping_timeout = DNS_PING_TIMEOUT;
	unsigned long now = get_tick_count();
	int ret = 0;

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
				ret = _dns_server_process_answer_A(rrs, request, domain, result_flag, ping_timeout);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					continue;
				}
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_AAAA: {
				ret = _dns_server_process_answer_AAAA(rrs, request, domain, result_flag, ping_timeout);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					continue;
				}
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_NS: {
				char cname[DNS_MAX_CNAME_LEN];
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "NS: %s ttl:%d cname: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[DNS_MAX_CNAME_LEN];
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "name:%s ttl: %d cname: %s\n", name, ttl, cname);
				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = ttl;
				request->has_cname = 1;
			} break;
			case DNS_T_SOA: {
				request->has_soa = 1;
				request->rcode = packet->head.rcode;
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_DEBUG,
					 "domain: %s, qtype: %d, SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, expire: "
					 "%d, minimum: %d",
					 domain, request->qtype, request->soa.mname, request->soa.rname, request->soa.serial,
					 request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);
				if (atomic_inc_return(&request->soa_num) >= (dns_server_num() / 2)) {
					_dns_server_request_complete(request);
				}
			} break;
			default:
				tlog(TLOG_DEBUG, "%s, qtype: %d", name, rrs->type);
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

static int _dns_server_passthrough_rule_check(struct dns_request *request, char *domain, struct dns_packet *packet,
											  unsigned int result_flag)
{
	int ttl;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int rr_count;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ip_check_result = 0;

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
		}

		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);
		return 0;
	}

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				if (request->qtype != DNS_T_A) {
					/* ignore non-matched query type */
					if (request->dualstack_selection == 0) {
						break;
					}
				}
				_dns_server_request_get(request);
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				tlog(TLOG_DEBUG, "domain: %s TTL:%d IP: %d.%d.%d.%d", name, ttl, addr[0], addr[1], addr[2], addr[3]);

				/* ip rule check */
				ip_check_result = _dns_server_ip_rule_check(request, addr, 4, DNS_T_A, result_flag);
				if (ip_check_result == 0) {
					/* match */
					_dns_server_request_release(request);
					return 0;
				} else if (ip_check_result == -2) {
					/* skip */
					_dns_server_request_release(request);
					return 0;
				}
				_dns_server_request_release(request);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				_dns_server_request_get(request);
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				tlog(TLOG_DEBUG,
					 "domain: %s TTL: %d IP: %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					 name, ttl, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
					 addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);

				ip_check_result = _dns_server_ip_rule_check(request, addr, 16, DNS_T_AAAA, result_flag);
				if (ip_check_result == 0) {
					/* match */
					_dns_server_request_release(request);
					return 0;
				} else if (ip_check_result == -2) {
					/* skip */
					_dns_server_request_release(request);
					return 0;
				}
				_dns_server_request_release(request);
			} break;
			default:
				break;
			}
		}
	}

	return -1;
}

static int _dns_server_get_answer(struct dns_request *request, struct dns_packet *packet)
{
	int i = 0;
	int j = 0;
	int ttl = 0;
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	char name[DNS_MAX_CNAME_LEN] = {0};

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				char name[DNS_MAX_CNAME_LEN] = {0};

				if (request->qtype != DNS_T_A) {
					continue;
				}

				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);
				memcpy(request->ipv4_addr, addr, DNS_RR_A_LEN);
				request->ttl_v4 = _dns_server_get_conf_ttl(ttl);
				request->has_ipv4 = 1;
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				char name[DNS_MAX_CNAME_LEN] = {0};

				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					continue;
				}
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);
				memcpy(request->ipv6_addr, addr, DNS_RR_AAAA_LEN);
				request->ttl_v6 = _dns_server_get_conf_ttl(ttl);
				request->has_ipv6 = 1;
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_NS: {
				char cname[DNS_MAX_CNAME_LEN];
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "NS: %s ttl:%d cname: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[DNS_MAX_CNAME_LEN];
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "name:%s ttl: %d cname: %s\n", name, ttl, cname);
				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = ttl;
				request->has_cname = 1;
			} break;
			case DNS_T_SOA: {
				request->has_soa = 1;
				request->rcode = packet->head.rcode;
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_DEBUG,
					 "domain: %s, qtype: %d, SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, expire: "
					 "%d, minimum: %d",
					 request->domain, request->qtype, request->soa.mname, request->soa.rname, request->soa.serial,
					 request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);
				if (atomic_inc_return(&request->soa_num) >= (dns_server_num() / 2)) {
					_dns_server_request_complete(request);
				}
			} break;
			default:
				tlog(TLOG_DEBUG, "%s, qtype: %d", name, rrs->type);
				break;
			}
		}
	}

	return 0;
}

static int _dns_server_setup_ipset_packet(struct dns_request *request, struct dns_packet *packet)
{
	int ttl;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int rr_count;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	struct dns_ipset_rule *rule = NULL, *ipset_rule = NULL, *ipset_rule_v4 = NULL, *ipset_rule_v6 = NULL;
	struct dns_rule_flags *rule_flags = NULL;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_IPSET) == 0) {
		return 0;
	}
	/* check ipset rule */
	rule_flags = request->domain_rule.rules[DOMAIN_RULE_FLAGS];
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IGN) == 0) {
		ipset_rule = request->domain_rule.rules[DOMAIN_RULE_IPSET];
	}
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV4_IGN) == 0) {
		ipset_rule_v4 = request->domain_rule.rules[DOMAIN_RULE_IPSET_IPV4];
	}
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV6_IGN) == 0) {
		ipset_rule_v6 = request->domain_rule.rules[DOMAIN_RULE_IPSET_IPV6];
	}

	if (!(ipset_rule || ipset_rule_v4 || ipset_rule_v6)) {
		return 0;
	}

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				if (request->qtype != DNS_T_A) {
					/* ignore non-matched query type */
					if (request->dualstack_selection == 0) {
						break;
					}
				}
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;

				if (rule) {
					/* add IPV4 to ipset */
					ipset_add(rule->ipsetname, addr, DNS_RR_A_LEN, request->ttl_v4 * 2);
					tlog(TLOG_DEBUG, "IPSET-MATCH-PASSTHROUTH: domain: %s, ipset: %s, IP: %d.%d.%d.%d", request->domain,
						 rule->ipsetname, addr[0], addr[1], addr[2], addr[3]);
				}
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				/* add IPV6 to ipset */
				if (request->has_ipv6) {
					if (request->has_ipv4) {
						rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
						if (rule) {
							/* add IPV4 to ipset */
							ipset_add(rule->ipsetname, addr, DNS_RR_A_LEN, request->ttl_v4 * 2);
							tlog(TLOG_DEBUG, "IPSET-MATCH-PASSTHROUTH: domain: %s, ipset: %s, IP: %d.%d.%d.%d",
								 request->domain, rule->ipsetname, addr[0], addr[1], addr[2], addr[3]);
						}
					}
					rule = ipset_rule_v6 ? ipset_rule_v6 : ipset_rule;
					if (rule) {
						ipset_add(rule->ipsetname, addr, DNS_RR_AAAA_LEN, request->ttl_v6 * 2);
						tlog(TLOG_DEBUG,
							 "IPSET-MATCH-PASSTHROUTH: domain: %s, ipset: %s, IP: "
							 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
							 request->domain, rule->ipsetname, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5],
							 addr[6], addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14],
							 addr[15]);
					}
				}
			} break;
			default:
				break;
			}
		}
	}

	return 0;
}

static int _dns_server_reply_passthrouth(struct dns_request *request, struct dns_packet *packet,
										 unsigned char *inpacket, int inpacket_len)
{
	int ret = 0;

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	_dns_server_get_answer(request, packet);
	if (request->result_callback) {
		_dns_result_callback(request);
	}

	if (request->conn == NULL) {
		return 0;
	}

	/* When passthrough, modify the id to be the id of the client request. */
	dns_server_update_reply_packet_id(request, inpacket, inpacket_len);
	ret = _dns_reply_inpacket(request, inpacket, inpacket_len);

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		return ret;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) != 0 &&
		(request->qtype == DNS_T_AAAA || request->qtype == DNS_T_A)) {
		struct dns_cache_data *cache_packet = dns_cache_new_data_packet(request->server_flags, inpacket, inpacket_len);
		if (cache_packet == NULL) {
			return ret;
		}

		if (_dns_server_request_update_cache(request, request->qtype, cache_packet) != 0) {
			tlog(TLOG_WARN, "update packet cache failed.");
		}
	}

	if (_dns_server_setup_ipset_packet(request, packet) != 0) {
		tlog(TLOG_DEBUG, "setup ipset failed.");
	}

	return 0;
}

static int dns_server_resolve_callback(char *domain, dns_result_type rtype, unsigned int result_flag,
									   struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									   void *user_ptr)
{
	struct dns_request *request = user_ptr;
	int ip_num = 0;
	int request_wait = 0;
	int ret = 0;

	if (request == NULL) {
		return -1;
	}

	if (rtype == DNS_QUERY_RESULT) {
		if (request->passthrough) {
			ret = _dns_server_passthrough_rule_check(request, domain, packet, result_flag);
			if (ret == 0) {
				return 0;
			}

			return _dns_server_reply_passthrouth(request, packet, inpacket, inpacket_len);
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
			request->has_ping_result = 1;
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

static int _dns_server_process_ptr(struct dns_request *request)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	unsigned char *addr;
	char reverse_addr[128] = {0};
	int found = 0;

	if (getifaddrs(&ifaddr) == -1) {
		return -1;
	}

	/* Get the NIC IP and match it. If the match is successful, return the host name. */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in;
			addr_in = (struct sockaddr_in *)ifa->ifa_addr;
			addr = (unsigned char *)&(addr_in->sin_addr.s_addr);
			snprintf(reverse_addr, sizeof(reverse_addr), "%d.%d.%d.%d.in-addr.arpa", addr[3], addr[2], addr[1],
					 addr[0]);
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6;
			addr_in6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
				addr = addr_in6->sin6_addr.s6_addr + 12;
				snprintf(reverse_addr, sizeof(reverse_addr), "%d.%d.%d.%d.in-addr.arpa", addr[3], addr[2], addr[1],
						 addr[0]);
			} else {
				addr = addr_in6->sin6_addr.s6_addr;
				snprintf(reverse_addr, sizeof(reverse_addr),
						 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
						 "%x.ip6.arpa",
						 addr[15] & 0xF, (addr[15] >> 4) & 0xF, addr[14] & 0xF, (addr[14] >> 4) & 0xF, addr[13] & 0xF,
						 (addr[13] >> 4) & 0xF, addr[12] & 0xF, (addr[12] >> 4) & 0xF, addr[11] & 0xF,
						 (addr[11] >> 4) & 0xF, addr[10] & 0xF, (addr[10] >> 4) & 0xF, addr[9] & 0xF,
						 (addr[9] >> 4) & 0xF, addr[8] & 0xF, (addr[8] >> 4) & 0xF, addr[7] & 0xF, (addr[7] >> 4) & 0xF,
						 addr[6] & 0xF, (addr[6] >> 4) & 0xF, addr[5] & 0xF, (addr[5] >> 4) & 0xF, addr[4] & 0xF,
						 (addr[4] >> 4) & 0xF, addr[3] & 0xF, (addr[3] >> 4) & 0xF, addr[2] & 0xF, (addr[2] >> 4) & 0xF,
						 addr[1] & 0xF, (addr[1] >> 4) & 0xF, addr[0] & 0xF, (addr[0] >> 4) & 0xF);
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

	/* Determine if the smartdns service is in effect. */
	if (strstr(request->domain, "0.0.0.0.in-addr.arpa") != NULL) {
		found = 1;
	}

	/* Determine if the smartdns service is in effect. */
	if (found == 0 && strncmp(request->domain, "smartdns", sizeof("smartdns")) == 0) {
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

static void _dns_server_log_rule(const char *domain, enum domain_rule rule_type, unsigned char *rule_key,
								 int rule_key_len)
{
	char rule_name[DNS_MAX_CNAME_LEN];
	if (rule_key_len <= 0) {
		return;
	}

	reverse_string(rule_name, (char *)rule_key, rule_key_len, 1);
	rule_name[rule_key_len] = 0;
	tlog(TLOG_INFO, "RULE-MATCH, type: %d, domain: %s, rule: %s", rule_type, domain, rule_name);
}

static void _dns_server_update_rule_by_flags(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = (struct dns_rule_flags *)request->domain_rule.rules[0];
	unsigned int flags = 0;

	if (rule_flag == NULL) {
		return;
	}
	flags = rule_flag->flags;

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
		request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
		request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
		request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IGN) {
		request->domain_rule.rules[DOMAIN_RULE_IPSET] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV4_IGN) {
		request->domain_rule.rules[DOMAIN_RULE_IPSET_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV6_IGN) {
		request->domain_rule.rules[DOMAIN_RULE_IPSET_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NAMESERVER_IGNORE) {
		request->domain_rule.rules[DOMAIN_RULE_NAMESERVER] = NULL;
	}
}

static int _dns_server_get_rules(unsigned char *key, uint32_t key_len, void *value, void *arg)
{
	struct rule_walk_args *walk_args = arg;
	struct dns_request *request = walk_args->args;
	struct dns_domain_rule *domain_rule = value;
	int i = 0;
	if (domain_rule == NULL) {
		return 0;
	}

	for (i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (domain_rule->rules[i] == NULL) {
			continue;
		}

		request->domain_rule.rules[i] = domain_rule->rules[i];
		walk_args->key[i] = key;
		walk_args->key_len[i] = key_len;
	}

	/* update rules by flags */
	_dns_server_update_rule_by_flags(request);

	return 0;
}

void _dns_server_get_domain_rule(struct dns_request *request)
{
	int domain_len;
	char domain_key[DNS_MAX_CNAME_LEN];
	int matched_key_len = DNS_MAX_CNAME_LEN;
	unsigned char matched_key[DNS_MAX_CNAME_LEN];
	struct rule_walk_args walk_args;
	int i = 0;

	memset(&walk_args, 0, sizeof(walk_args));
	walk_args.args = request;

	/* reverse domain string */
	domain_len = strlen(request->domain);
	reverse_string(domain_key, request->domain, domain_len, 1);
	domain_key[domain_len] = '.';
	domain_len++;
	domain_key[domain_len] = 0;

	/* find domain rule */
	art_substring_walk(&dns_conf_domain_rule, (unsigned char *)domain_key, domain_len, _dns_server_get_rules,
					   &walk_args);
	if (likely(dns_conf_log_level > TLOG_DEBUG)) {
		return;
	}

	/* output log rule */
	for (i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (walk_args.key[i] == NULL) {
			continue;
		}

		matched_key_len = walk_args.key_len[i];
		if (walk_args.key_len[i] >= sizeof(matched_key)) {
			continue;
		}

		memcpy(matched_key, walk_args.key[i], walk_args.key_len[i]);

		matched_key_len--;
		matched_key[matched_key_len] = 0;
		_dns_server_log_rule(request->domain, i, matched_key, matched_key_len);
	}

	return;
}

static int _dns_server_pre_process_rule_flags(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;
	unsigned int flags = 0;

	/* get domain rule flag */
	rule_flag = request->domain_rule.rules[DOMAIN_RULE_FLAGS];
	if (rule_flag == NULL) {
		goto out;
	}

	flags = rule_flag->flags;
	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		/* ignore this domain */
		goto out;
	}

	if (_dns_server_is_return_soa(request)) {
		goto soa;
	}

	/* return specific type of address */
	switch (request->qtype) {
	case DNS_T_A:
		if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
			/* ignore this domain for A reqeust */
			goto out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* return SOA for A request */
			goto soa;
		}
		break;
	case DNS_T_AAAA:
		if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
			/* ignore this domain for A reqeust */
			goto out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* return SOA for A request */
			goto soa;
		}

		if (flags & DOMAIN_FLAG_ADDR_IPV4_SOA && request->dualstack_selection) {
			/* if IPV4 return SOA and dualstack-selection enabled, set request dualstack disable */
			request->dualstack_selection = 0;
		}
		break;
	default:
		goto out;
		break;
	}

out:
	return -1;

soa:
	/* return SOA */
	_dns_server_reply_SOA(DNS_RC_NOERROR, request);
	_dns_server_audit_log(request);
	return 0;
}

static int _dns_server_process_address(struct dns_request *request)
{
	struct dns_address_IPV4 *address_ipv4 = NULL;
	struct dns_address_IPV6 *address_ipv6 = NULL;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
		goto errout;
	}

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A:
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] == NULL) {
			goto errout;
		}
		address_ipv4 = request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4];
		memcpy(request->ipv4_addr, address_ipv4->ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = 600;
		request->has_ipv4 = 1;
		break;
	case DNS_T_AAAA:
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] == NULL) {
			goto errout;
		}
		address_ipv6 = request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6];
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

static void _dns_server_process_speed_check_rule(struct dns_request *request)
{
	struct dns_domain_check_order *check_order = NULL;

	/* get domain rule flag */
	check_order = request->domain_rule.rules[DOMAIN_RULE_CHECKSPEED];
	if (check_order == NULL) {
		return;
	}

	request->check_order_list = check_order;
}

static int _dns_server_get_expired_ttl_reply(struct dns_cache *dns_cache)
{
	int ttl = dns_cache_get_ttl(dns_cache);
	if (ttl > 0) {
		return ttl;
	}

	return dns_conf_serve_expired_reply_ttl;
}

static int _dns_server_process_cache_addr(struct dns_request *request, struct dns_cache *dns_cache)
{
	struct dns_cache_addr *cache_addr = (struct dns_cache_addr *)dns_cache_get_data(dns_cache);

	if (cache_addr->head.cache_type != CACHE_TYPE_ADDR) {
		goto errout;
	}
	/* Cache hits, returning results in the cache */
	switch (request->qtype) {
	case DNS_T_A:
		memcpy(request->ipv4_addr, cache_addr->addr_data.ipv4_addr, DNS_RR_A_LEN);
		request->ttl_v4 = _dns_server_get_expired_ttl_reply(dns_cache);
		request->has_ipv4 = 1;
		break;
	case DNS_T_AAAA:
		memcpy(request->ipv6_addr, cache_addr->addr_data.ipv6_addr, DNS_RR_AAAA_LEN);
		request->ttl_v6 = _dns_server_get_expired_ttl_reply(dns_cache);
		request->has_ipv6 = 1;
		break;
	default:
		goto errout;
		break;
	}

	if (cache_addr->addr_data.cname[0] != 0) {
		safe_strncpy(request->cname, cache_addr->addr_data.cname, DNS_MAX_CNAME_LEN);
		request->has_cname = 1;
		request->ttl_cname = cache_addr->addr_data.cname_ttl;
	}

	request->rcode = DNS_RC_NOERROR;

	_dns_result_callback(request);

	if (request->prefetch == 0) {
		_dns_reply(request);
	}

	return 0;
errout:
	return -1;
}

static int _dns_server_process_cache_packet(struct dns_request *request, struct dns_cache *dns_cache)
{
	struct dns_cache_packet *cache_packet = (struct dns_cache_packet *)dns_cache_get_data(dns_cache);

	if (cache_packet->head.cache_type != CACHE_TYPE_PACKET) {
		goto errout;
	}

	if (dns_cache->info.qtype != request->qtype) {
		goto errout;
	}

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	if (request->result_callback) {
		unsigned char packet_buff[DNS_PACKSIZE];
		struct dns_packet *packet = (struct dns_packet *)packet_buff;

		if (dns_decode(packet, DNS_PACKSIZE, cache_packet->data, cache_packet->head.size) != 0) {
			goto errout;
		}

		_dns_server_get_answer(request, packet);
		_dns_result_callback(request);
	}

	if (request->conn == NULL) {
		return 0;
	}

	/* When passthrough, modify the id to be the id of the client request. */
	dns_server_update_reply_packet_id(request, cache_packet->data, cache_packet->head.size);
	return _dns_reply_inpacket(request, cache_packet->data, cache_packet->head.size);
errout:
	return -1;
}

static int _dns_server_process_cache_data(struct dns_request *request, struct dns_cache *dns_cache)
{
	enum CACHE_TYPE cache_type = CACHE_TYPE_NONE;
	int ret = -1;

	cache_type = dns_cache_data_type(dns_cache->cache_data);
	switch (cache_type) {
	case CACHE_TYPE_ADDR:
		ret = _dns_server_process_cache_addr(request, dns_cache);
		if (ret != 0) {
			goto out;
		}
		break;
	case CACHE_TYPE_PACKET:
		ret = _dns_server_process_cache_packet(request, dns_cache);
		if (ret != 0) {
			goto out;
		}

		break;
	default:
		goto out;
		break;
	}

	return 0;
out:
	return -1;
}

static int _dns_server_process_cache(struct dns_request *request)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *dns_cache_A = NULL;
	int ret = -1;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) == 0) {
		goto out;
	}

	dns_cache = dns_cache_lookup(request->domain, request->qtype);
	if (dns_cache == NULL) {
		if (request->dualstack_selection && request->qtype == DNS_T_AAAA) {
			dns_cache_A = dns_cache_lookup(request->domain, DNS_T_A);
			if (dns_cache_A && dns_cache_is_soa(dns_cache_A) == 0 && dns_cache_is_soa(dns_cache)) {
				tlog(TLOG_DEBUG, "No IPV6 Found, Force IPV4 perfered.");
				if (dns_cache_get_ttl(dns_cache_A) == 0) {
					uint32_t server_flags = request->server_flags;
					if (request->conn == NULL) {
						server_flags = dns_cache_get_cache_flag(dns_cache_A->cache_data);
					}
					_dns_server_prefetch_request(request->domain, request->qtype, server_flags);
				}
				ret = _dns_server_reply_SOA(DNS_RC_NOERROR, request);
				goto out;
			}
		}
		goto out;
	}

	if (request->qtype != dns_cache->info.qtype) {
		goto out;
	}

	if (dns_cache_is_soa(dns_cache)) {
		ret = _dns_server_reply_SOA(DNS_RC_NOERROR, request);
		goto out;
	}

	if (request->dualstack_selection && request->qtype == DNS_T_AAAA) {
		dns_cache_A = dns_cache_lookup(request->domain, DNS_T_A);
		if (dns_cache_A && dns_cache_is_soa(dns_cache_A) == 0 && (dns_cache_A->info.speed > 0)) {
			if ((dns_cache_A->info.speed + (dns_conf_dualstack_ip_selection_threshold * 10)) < dns_cache->info.speed ||
				dns_cache->info.speed < 0) {
				tlog(TLOG_DEBUG, "Force IPV4 perfered.");
				ret = _dns_server_reply_SOA(DNS_RC_NOERROR, request);
				goto out_update_cache;
			}
		}
	}

	ret = _dns_server_process_cache_data(request, dns_cache);
	if (ret != 0) {
		goto out;
	}

out_update_cache:
	if (dns_cache_get_ttl(dns_cache) == 0) {
		uint32_t server_flags = request->server_flags;
		if (request->conn == NULL) {
			server_flags = dns_cache_get_cache_flag(dns_cache->cache_data);
		}
		_dns_server_prefetch_request(request->domain, request->qtype, server_flags);
	} else {
		dns_cache_update(dns_cache);
	}

out:
	if (dns_cache) {
		dns_cache_release(dns_cache);
	}

	if (dns_cache_A) {
		dns_cache_release(dns_cache_A);
		dns_cache_A = NULL;
	}

	return ret;
}

static void _dns_server_request_set_client(struct dns_request *request, struct dns_server_conn_head *conn)
{
	request->conn = conn;
	request->server_flags = conn->server_flags;
	_dns_server_conn_get(conn);
}

static void _dns_server_request_set_id(struct dns_request *request, unsigned short id)
{
	request->id = id;
}

static void _dns_server_request_set_enable_prefetch(struct dns_request *request)
{
	request->prefetch = 1;
}

static int _dns_server_request_set_client_addr(struct dns_request *request, struct sockaddr_storage *from,
											   socklen_t from_len)
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

static void _dns_server_request_set_callback(struct dns_request *request, dns_result_callback callback, void *user_ptr)
{
	request->result_callback = callback;
	request->user_ptr = user_ptr;
}

static int _dns_server_process_special_query(struct dns_request *request)
{
	int ret = 0;

	switch (request->qtype) {
	case DNS_T_PTR:
		/* return PTR record */
		ret = _dns_server_process_ptr(request);
		if (ret == 0) {
			goto clean_exit;
		} else {
			/* pass to upstream server */
			request->passthrough = 1;
		}
		break;
	case DNS_T_A:
		break;
	case DNS_T_AAAA:
		/* force return SOA */
		if (_dns_server_is_return_soa(request)) {
			_dns_server_reply_SOA(DNS_RC_NOERROR, request);
			goto clean_exit;
		}

		break;
	default:
		tlog(TLOG_DEBUG, "unsupport qtype: %d, domain: %s", request->qtype, request->domain);
		request->passthrough = 1;
		/* pass request to upstream server */
		break;
	}

	return -1;
clean_exit:
	return 0;
}

static const char *_dns_server_get_request_groupname(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_NAMESERVER) == 0) {
		return NULL;
	}

	/* Get the nameserver rule */
	if (request->domain_rule.rules[DOMAIN_RULE_NAMESERVER]) {
		struct dns_nameserver_rule *nameserver_rule = request->domain_rule.rules[DOMAIN_RULE_NAMESERVER];
		return nameserver_rule->group_name;
	}

	return NULL;
}

static void _dns_server_check_set_passthrough(struct dns_request *request)
{
	if (request->check_order_list->order[0] == DOMAIN_CHECK_NONE) {
		request->passthrough = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_SPEED_CHECK) == 0) {
		request->passthrough = 1;
	}

	if (request->passthrough == 1) {
		request->dualstack_selection = 0;
	}
}

static int _dns_server_do_query(struct dns_request *request, const char *domain, int qtype)
{
	int ret = -1;
	const char *group_name = NULL;
	const char *dns_group = NULL;

	if (request->conn) {
		dns_group = request->conn->dns_group;
	}

	safe_strncpy(request->domain, domain, sizeof(request->domain));
	request->qtype = qtype;

	/* lookup domain rule */
	_dns_server_get_domain_rule(request);
	group_name = _dns_server_get_request_groupname(request);
	if (group_name == NULL) {
		group_name = dns_group;
	}

	_dns_server_set_dualstack_selection(request);

	if (_dns_server_process_special_query(request) == 0) {
		goto clean_exit;
	}

	/* process domain flag */
	if (_dns_server_pre_process_rule_flags(request) == 0) {
		goto clean_exit;
	}

	/* process domain address */
	if (_dns_server_process_address(request) == 0) {
		goto clean_exit;
	}

	/* process speed check rule */
	_dns_server_process_speed_check_rule(request);

	/* check and set passthrough */
	_dns_server_check_set_passthrough(request);

	/* process cache */
	if (request->prefetch == 0) {
		if (_dns_server_process_cache(request) == 0) {
			goto clean_exit;
		}
	}

	// Get reference for server thread
	_dns_server_request_get(request);
	pthread_mutex_lock(&server.request_list_lock);
	list_add_tail(&request->list, &server.request_list);
	pthread_mutex_unlock(&server.request_list_lock);
	request->send_tick = get_tick_count();

	/* When the dual stack ip preference is enabled, both A and AAAA records are requested. */
	if (qtype == DNS_T_AAAA && request->dualstack_selection) {
		// Get reference for AAAA query
		_dns_server_request_get(request);
		request->request_wait++;
		if (dns_client_query(request->domain, DNS_T_A, dns_server_resolve_callback, request, group_name) != 0) {
			request->request_wait--;
			_dns_server_request_release(request);
		}
	}

	// Get reference for DNS query
	request->request_wait++;
	_dns_server_request_get(request);
	if (dns_client_query(request->domain, qtype, dns_server_resolve_callback, request, group_name) != 0) {
		request->request_wait--;
		_dns_server_request_release(request);
		tlog(TLOG_ERROR, "send dns request failed.");
		goto errout;
	}

clean_exit:
	return 0;
errout:
	_dns_server_request_remove(request);
	request = NULL;
	return ret;
}

static int _dns_server_recv(struct dns_server_conn_head *conn, unsigned char *inpacket, int inpacket_len,
							struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
							socklen_t from_len)
{
	int decode_len;
	int ret = -1;
	unsigned char packet_buff[DNS_PACKSIZE];
	char name[DNS_MAX_CNAME_LEN];
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_request *request = NULL;
	struct dns_rrs *rrs;
	int rr_count = 0;
	int i = 0;
	int qclass;
	int qtype = DNS_T_ALL;

	/* decode packet */
	tlog(TLOG_DEBUG, "recv query packet from %s, len = %d",
		 gethost_by_addr(name, sizeof(name), (struct sockaddr *)from), inpacket_len);
	decode_len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (decode_len < 0) {
		tlog(TLOG_DEBUG, "decode failed.\n");
		goto errout;
	}

	tlog(TLOG_DEBUG,
		 "request qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, ra = "
		 "%d, rcode = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len,
		 packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra, packet->head.rcode);

	if (packet->head.qr != DNS_QR_QUERY) {
		goto errout;
	}

	/* get request domain and request qtype */
	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	if (rr_count > 1) {
		goto errout;
	}

	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		ret = dns_get_domain(rrs, domain, sizeof(domain), &qtype, &qclass);
		if (ret != 0) {
			goto errout;
		}

		// Only support one question.
		break;
	}
	tlog(TLOG_INFO, "query server %s from %s, qtype = %d\n", domain, name, qtype);

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	memcpy(&request->localaddr, local, local_len);
	_dns_server_request_set_client(request, conn);
	_dns_server_request_set_client_addr(request, from, from_len);
	_dns_server_request_set_id(request, packet->head.id);
	ret = _dns_server_do_query(request, domain, qtype);
	if (ret != 0) {
		tlog(TLOG_ERROR, "do query %s failed.\n", domain);
		goto errout;
	}
	_dns_server_request_release_complete(request, 0);
	return ret;
errout:
	if (request) {
		ret = _dns_server_forward_request(inpacket, inpacket_len);
		_dns_server_request_release(request);
	}

	return ret;
}

static int _dns_server_prefetch_request(char *domain, dns_type_t qtype, uint32_t server_flags)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	request->server_flags = server_flags;
	_dns_server_request_set_enable_prefetch(request);
	ret = _dns_server_do_query(request, domain, qtype);
	if (ret != 0) {
		tlog(TLOG_ERROR, "do query %s failed.\n", domain);
		goto errout;
	}

	_dns_server_request_release_complete(request, 0);
	return ret;
errout:
	if (request) {
		_dns_server_request_release(request);
	}

	return ret;
}

int dns_server_query(char *domain, int qtype, uint32_t server_flags, dns_result_callback callback, void *user_ptr)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	request->server_flags = server_flags;
	_dns_server_request_set_callback(request, callback, user_ptr);
	ret = _dns_server_do_query(request, domain, qtype);
	if (ret != 0) {
		tlog(TLOG_ERROR, "do query %s failed.\n", domain);
		goto errout;
	}

	_dns_server_request_release_complete(request, 1);
	return ret;
errout:
	if (request) {
		_dns_server_request_set_callback(request, NULL, NULL);
		_dns_server_request_release(request);
	}

	return ret;
}

static int _dns_server_process_udp(struct dns_server_conn_udp *udpconn, struct epoll_event *event, unsigned long now)
{
	int len;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	struct sockaddr_storage local;
	socklen_t local_len = sizeof(local);
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	struct cmsghdr *cmsg;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)inpacket;
	iov.iov_len = sizeof(inpacket);
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ans_data;
	msg.msg_controllen = sizeof(ans_data);

	len = recvmsg(udpconn->head.fd, &msg, MSG_DONTWAIT);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}
	from_len = msg.msg_namelen;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			const struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			unsigned char *addr = (unsigned char *)&pktinfo->ipi_addr.s_addr;
			fill_sockaddr_by_ip(addr, sizeof(in_addr_t), 0, (struct sockaddr *)&local, &local_len);
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			const struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			unsigned char *addr = (unsigned char *)pktinfo->ipi6_addr.s6_addr;
			fill_sockaddr_by_ip(addr, sizeof(struct in6_addr), 0, (struct sockaddr *)&local, &local_len);
		}
	}

	return _dns_server_recv(&udpconn->head, inpacket, len, &local, local_len, &from, from_len);
}

static void _dns_server_client_touch(struct dns_server_conn_head *conn)
{
	time(&conn->last_request_time);
}

static int _dns_server_client_close(struct dns_server_conn_head *conn)
{
	if (conn->fd > 0) {
		_dns_server_epoll_ctl(conn, EPOLL_CTL_DEL, 0);
		close(conn->fd);
		conn->fd = -1;
	}

	list_del_init(&conn->list);

	_dns_server_conn_release(conn);

	return 0;
}

static int _dns_server_tcp_accept(struct dns_server_conn_tcp_server *tcpserver, struct epoll_event *event,
								  unsigned long now)
{
	struct sockaddr_storage addr;
	struct dns_server_conn_tcp_client *tcpclient = NULL;
	socklen_t addr_len = sizeof(addr);
	int fd = -1;

	fd = accept4(tcpserver->head.fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		tlog(TLOG_ERROR, "accept failed, %s", strerror(errno));
		return -1;
	}

	tcpclient = malloc(sizeof(*tcpclient));
	if (tcpclient == NULL) {
		tlog(TLOG_ERROR, "malloc for tcpclient failed.");
		goto errout;
	}
	memset(tcpclient, 0, sizeof(*tcpclient));

	tcpclient->head.fd = fd;
	tcpclient->head.type = DNS_CONN_TYPE_TCP_CLIENT;
	tcpclient->head.server_flags = tcpserver->head.server_flags;
	tcpclient->head.dns_group = tcpserver->head.dns_group;
	atomic_set(&tcpclient->head.refcnt, 0);
	memcpy(&tcpclient->addr, &addr, addr_len);
	tcpclient->addr_len = addr_len;
	tcpclient->localaddr_len = sizeof(struct sockaddr_storage);
	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_ADD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	if (getsocknet_inet(tcpclient->head.fd, (struct sockaddr *)&tcpclient->localaddr, &tcpclient->localaddr_len) != 0) {
		tlog(TLOG_ERROR, "get local addr failed, %s", strerror(errno));
		goto errout;
	}

	_dns_server_client_touch(&tcpclient->head);

	list_add(&tcpclient->head.list, &server.conn_list);
	_dns_server_conn_get(&tcpclient->head);

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}
	if (tcpclient) {
		free(tcpclient);
	}
	return -1;
}

static int _dns_server_tcp_recv(struct dns_server_conn_tcp_client *tcpclient)
{
	int len = 0;

	/* Receive data */
	while (tcpclient->recvbuff.size < sizeof(tcpclient->recvbuff.buf)) {
		if (tcpclient->recvbuff.size == sizeof(tcpclient->recvbuff.buf)) {
			return 0;
		}

		len = recv(tcpclient->head.fd, tcpclient->recvbuff.buf + tcpclient->recvbuff.size,
				   sizeof(tcpclient->recvbuff.buf) - tcpclient->recvbuff.size, 0);
		if (len < 0) {
			if (errno == EAGAIN) {
				return RECV_ERROR_AGAIN;
			}

			tlog(TLOG_ERROR, "recv failed, %s\n", strerror(errno));
			return RECV_ERROR_FAIL;
		} else if (len == 0) {
			return RECV_ERROR_CLOSE;
		}

		tcpclient->recvbuff.size += len;
	}

	return 0;
}

static int _dns_server_tcp_process_one_request(struct dns_server_conn_tcp_client *tcpclient)
{
	int request_len = 0;
	int total_len = tcpclient->recvbuff.size;
	int proceed_len = 0;
	unsigned char *request_data = NULL;
	int ret = 0;

	/* Handling multiple requests */
	for (;;) {
		if ((total_len - proceed_len) <= sizeof(unsigned short)) {
			ret = RECV_ERROR_AGAIN;
			break;
		}

		/* Get record length */
		request_data = (unsigned char *)(tcpclient->recvbuff.buf + proceed_len);
		request_len = ntohs(*((unsigned short *)(request_data)));

		if (request_len >= sizeof(tcpclient->recvbuff.buf)) {
			tlog(TLOG_ERROR, "request length is invalid.");
			return RECV_ERROR_FAIL;
		}

		if (request_len > (total_len - proceed_len - sizeof(unsigned short))) {
			ret = RECV_ERROR_AGAIN;
			break;
		}

		request_data = (unsigned char *)(tcpclient->recvbuff.buf + proceed_len + sizeof(unsigned short));

		/* process one record */
		if (_dns_server_recv(&tcpclient->head, request_data, request_len, &tcpclient->localaddr,
							 tcpclient->localaddr_len, &tcpclient->addr, tcpclient->addr_len) != 0) {
			tlog(TLOG_ERROR, "process tcp request failed.");
			return RECV_ERROR_FAIL;
		}

		proceed_len += sizeof(unsigned short) + request_len;
	}

	if (total_len > proceed_len && proceed_len > 0) {
		memmove(tcpclient->recvbuff.buf, tcpclient->recvbuff.buf + proceed_len, total_len - proceed_len);
	}

	tcpclient->recvbuff.size -= proceed_len;

	return ret;
}

static int _dns_server_tcp_process_requests(struct dns_server_conn_tcp_client *tcpclient)
{
	int recv_ret = 0;
	int request_ret = 0;
	int is_eof = 0;

	for (;;) {
		recv_ret = _dns_server_tcp_recv(tcpclient);
		if (recv_ret < 0) {
			if (recv_ret == RECV_ERROR_CLOSE) {
				return RECV_ERROR_CLOSE;
			}

			if (tcpclient->recvbuff.size > 0) {
				is_eof = RECV_ERROR_AGAIN;
			} else {
				return RECV_ERROR_FAIL;
			}
		}

		request_ret = _dns_server_tcp_process_one_request(tcpclient);
		if (request_ret < 0) {
			/* failed */
			tlog(TLOG_ERROR, "process one request failed.");
			return RECV_ERROR_FAIL;
		}

		if (request_ret == RECV_ERROR_AGAIN && is_eof == RECV_ERROR_AGAIN) {
			/* failed or remote shutdown */
			return RECV_ERROR_FAIL;
		}

		if (recv_ret == RECV_ERROR_AGAIN && request_ret == RECV_ERROR_AGAIN) {
			/* process complete */
			return 0;
		}
	}

	return 0;
}

static int _dns_server_tcp_send(struct dns_server_conn_tcp_client *tcpclient)
{
	int len;
	while (tcpclient->sndbuff.size > 0) {
		len = send(tcpclient->head.fd, tcpclient->sndbuff.buf, tcpclient->sndbuff.size, MSG_NOSIGNAL);
		if (len < 0) {
			if (errno == EAGAIN) {
				return RECV_ERROR_AGAIN;
			}
			return RECV_ERROR_FAIL;
		} else if (len == 0) {
			break;
		}

		tcpclient->sndbuff.size -= len;
	}

	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_MOD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

static int _dns_server_process_tcp(struct dns_server_conn_tcp_client *dnsserver, struct epoll_event *event,
								   unsigned long now)
{
	int ret = 0;

	if (event->events & EPOLLIN) {
		ret = _dns_server_tcp_process_requests(dnsserver);
		if (ret != 0) {
			_dns_server_client_close(&dnsserver->head);
			if (ret == RECV_ERROR_CLOSE) {
				return 0;
			}
			tlog(TLOG_ERROR, "process tcp request failed.");
			return RECV_ERROR_FAIL;
		}
	}

	if (event->events & EPOLLOUT) {
		if (_dns_server_tcp_send(dnsserver) != 0) {
			_dns_server_client_close(&dnsserver->head);
			tlog(TLOG_ERROR, "send tcp failed.");
			return RECV_ERROR_FAIL;
		}
	}

	return 0;
}

static int _dns_server_process(struct dns_server_conn_head *conn, struct epoll_event *event, unsigned long now)
{
	int ret;
	_dns_server_client_touch(conn);
	_dns_server_conn_get(conn);
	if (conn->type == DNS_CONN_TYPE_UDP_SERVER) {
		struct dns_server_conn_udp *udpconn = (struct dns_server_conn_udp *)conn;
		ret = _dns_server_process_udp(udpconn, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TCP_SERVER) {
		struct dns_server_conn_tcp_server *tcpserver = (struct dns_server_conn_tcp_server *)conn;
		ret = _dns_server_tcp_accept(tcpserver, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TCP_CLIENT) {
		struct dns_server_conn_tcp_client *tcpclient = (struct dns_server_conn_tcp_client *)conn;
		ret = _dns_server_process_tcp(tcpclient, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TLS_SERVER) {
		tlog(TLOG_ERROR, "unsupport dns server type %d", conn->type);
		ret = -1;
	} else {
		tlog(TLOG_ERROR, "unsupport dns server type %d", conn->type);
		ret = -1;
	}
	_dns_server_conn_release(conn);

	return ret;
}

static void _dns_server_second_ping_check(struct dns_request *request)
{
	struct dns_ip_address *addr_map;
	int bucket = 0;
	char ip[DNS_MAX_CNAME_LEN] = {0};

	if (request->has_ping_result) {
		return;
	}

	if (request->has_ping_tcp) {
		return;
	}

	/* start tcping */
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each(request->ip_map, bucket, addr_map, node)
	{
		switch (addr_map->addr_type) {
		case DNS_T_A: {
			_dns_server_request_get(request);
			sprintf(ip, "%d.%d.%d.%d", addr_map->ipv4_addr[0], addr_map->ipv4_addr[1], addr_map->ipv4_addr[2],
					addr_map->ipv4_addr[3]);
			if (_dns_server_check_speed(request, ip, 1, DNS_PING_SECOND_TIMEOUT) != 0) {
				_dns_server_request_release(request);
			}
		} break;
		case DNS_T_AAAA: {
			_dns_server_request_get(request);
			sprintf(ip, "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]",
					addr_map->ipv6_addr[0], addr_map->ipv6_addr[1], addr_map->ipv6_addr[2], addr_map->ipv6_addr[3],
					addr_map->ipv6_addr[4], addr_map->ipv6_addr[5], addr_map->ipv6_addr[6], addr_map->ipv6_addr[7],
					addr_map->ipv6_addr[8], addr_map->ipv6_addr[9], addr_map->ipv6_addr[10], addr_map->ipv6_addr[11],
					addr_map->ipv6_addr[12], addr_map->ipv6_addr[13], addr_map->ipv6_addr[14], addr_map->ipv6_addr[15]);

			if (_dns_server_check_speed(request, ip, 1, DNS_PING_SECOND_TIMEOUT) != 0) {
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

static void _dns_server_prefetch_domain(struct dns_cache *dns_cache)
{
	/* If there are still hits, continue pre-fetching */
	int hitnum = dns_cache_hitnum_dec_get(dns_cache);
	if (hitnum <= 0) {
		return;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG, "prefetch by cache %s, qtype %d, ttl %d, hitnum %d", dns_cache->info.domain, dns_cache->info.qtype,
		 dns_cache->info.ttl, hitnum);
	if (_dns_server_prefetch_request(dns_cache->info.domain, dns_cache->info.qtype,
									 dns_cache_get_cache_flag(dns_cache->cache_data)) != 0) {
		tlog(TLOG_ERROR, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
	}
}

static void _dns_server_tcp_idle_check(void)
{
	struct dns_server_conn_head *conn, *tmp;
	time_t now;

	if (dns_conf_tcp_idle_time <= 0) {
		return;
	}

	time(&now);
	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		if (conn->type != DNS_CONN_TYPE_TCP_CLIENT && conn->type != DNS_CONN_TYPE_TLS_CLIENT) {
			continue;
		}

		if (conn->last_request_time > now - dns_conf_tcp_idle_time) {
			continue;
		}

		_dns_server_client_close(conn);
	}
}

static void _dns_server_period_run_second(void)
{
	static unsigned int sec = 0;
	static time_t last = 0;
	time_t now;
	sec++;

	time(&now);
	if (last == 0) {
		last = now;
	}

	if (now - 180 > last) {
		dns_cache_invalidate(NULL, 0);
		tlog(TLOG_WARN, "Service paused for 180s, force invalidate cache.");
	}

	last = now;

	if (sec % 2 == 0) {
		if (dns_conf_prefetch) {
			/* do pre-fetching */
			dns_cache_invalidate(_dns_server_prefetch_domain, 3);
		} else {
			dns_cache_invalidate(NULL, 0);
		}
	}

	_dns_server_tcp_idle_check();
}

static void _dns_server_period_run(void)
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
		/* Need to use tcping detection speed */
		if (request->send_tick < now - DNS_TCPPING_START && request->has_ping_tcp == 0) {
			_dns_server_request_get(request);
			list_add_tail(&request->check_list, &check_list);
		}
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &check_list, check_list)
	{
		_dns_server_second_ping_check(request);
		_dns_server_request_remove(request);
		list_del_init(&request->check_list);
		_dns_server_request_release(request);
	}
}

static void _dns_server_close_socket(void)
{
	struct dns_server_conn_head *conn, *tmp;

	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		_dns_server_client_close(conn);
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
			struct dns_server_conn_head *conn_head = event->data.ptr;
			if (conn_head == NULL) {
				tlog(TLOG_ERROR, "invalid fd\n");
				continue;
			}

			if (_dns_server_process(conn_head, event, now) != 0) {
				tlog(TLOG_ERROR, "dns server process failed.");
			}
		}
	}

	_dns_server_close_socket();
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
	struct dns_server_conn_head *conn = NULL;

	list_for_each_entry(conn, &server.conn_list, list)
	{
		if (conn->fd <= 0) {
			continue;
		}

		if (_dns_server_epoll_ctl(conn, EPOLL_CTL_ADD, EPOLLIN) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed.");
			return -1;
		}
	}

	return 0;
}

static int _dns_create_socket(const char *host_ip, int type)
{
	int fd = -1;
	struct addrinfo *gai = NULL;
	char port_str[8];
	char ip[MAX_IP_LEN];
	int port;
	char *host = NULL;
	int optval = 1;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

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
		tlog(TLOG_ERROR, "create socket failed, family = %d, type = %d, proto = %d, %s\n", gai->ai_family,
			 gai->ai_socktype, gai->ai_protocol, strerror(errno));
		goto errout;
	}

	if (type == SOCK_STREAM) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
			tlog(TLOG_ERROR, "set socket opt failed.");
			goto errout;
		}
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	} else {
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval));
	}
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));

	if (bind(fd, gai->ai_addr, gai->ai_addrlen) != 0) {
		tlog(TLOG_ERROR, "bind service %s failed, %s\n", host_ip, strerror(errno));
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

static int _dns_server_set_flags(struct dns_server_conn_head *head, struct dns_bind_ip *bind_ip)
{
	time(&head->last_request_time);
	head->server_flags = bind_ip->flags;
	head->dns_group = bind_ip->group;
	atomic_set(&head->refcnt, 0);
	list_add(&head->list, &server.conn_list);

	return 0;
}

static int _dns_server_socket_udp(struct dns_bind_ip *bind_ip)
{
	const char *host_ip;
	struct dns_server_conn_udp *conn = NULL;
	int fd = -1;

	host_ip = bind_ip->ip;
	conn = malloc(sizeof(struct dns_server_conn_udp));
	if (conn == NULL) {
		goto errout;
	}
	INIT_LIST_HEAD(&conn->head.list);

	fd = _dns_create_socket(host_ip, SOCK_DGRAM);
	if (fd <= 0) {
		goto errout;
	}

	conn->head.type = DNS_CONN_TYPE_UDP_SERVER;
	conn->head.fd = fd;
	_dns_server_set_flags(&conn->head, bind_ip);
	_dns_server_conn_get(&conn->head);

	return 0;
errout:
	if (conn) {
		free(conn);
		conn = NULL;
	}

	if (fd > 0) {
		close(fd);
	}
	return -1;
}

static int _dns_server_socket_tcp(struct dns_bind_ip *bind_ip)
{
	const char *host_ip;
	struct dns_server_conn_tcp_server *conn = NULL;
	int fd = -1;

	host_ip = bind_ip->ip;
	conn = malloc(sizeof(struct dns_server_conn_tcp_server));
	if (conn == NULL) {
		goto errout;
	}
	INIT_LIST_HEAD(&conn->head.list);

	fd = _dns_create_socket(host_ip, SOCK_STREAM);
	if (fd <= 0) {
		goto errout;
	}

	conn->head.type = DNS_CONN_TYPE_TCP_SERVER;
	conn->head.fd = fd;
	_dns_server_set_flags(&conn->head, bind_ip);
	_dns_server_conn_get(&conn->head);

	return 0;
errout:
	if (conn) {
		free(conn);
		conn = NULL;
	}

	if (fd > 0) {
		close(fd);
	}
	return -1;
}

static int _dns_server_socket(void)
{
	int i = 0;

	for (i = 0; i < dns_conf_bind_ip_num; i++) {
		struct dns_bind_ip *bind_ip = &dns_conf_bind_ip[i];
		switch (bind_ip->type) {
		case DNS_BIND_TYPE_UDP:
			if (_dns_server_socket_udp(bind_ip) != 0) {
				goto errout;
			}
			break;
		case DNS_BIND_TYPE_TCP:
			if (_dns_server_socket_tcp(bind_ip) != 0) {
				goto errout;
			}
			break;
		case DNS_BIND_TYPE_TLS:
			break;
		default:
			break;
		}
	}

	return 0;
errout:

	return -1;
}

static int _dns_server_audit_init(void)
{
	char *audit_file = SMARTDNS_AUDIT_FILE;
	if (dns_conf_audit_enable == 0) {
		return 0;
	}

	if (dns_conf_audit_file[0] != 0) {
		audit_file = dns_conf_audit_file;
	}

	dns_audit = tlog_open(audit_file, dns_conf_audit_size, dns_conf_audit_num, 0, 0);
	if (dns_audit == NULL) {
		return -1;
	}

	return 0;
}

static int _dns_server_cache_init(void)
{
	if (dns_cache_init(dns_conf_cachesize, dns_conf_serve_expired, dns_conf_serve_expired_ttl) != 0) {
		tlog(TLOG_ERROR, "init cache failed.");
		return -1;
	}

	char *dns_cache_file = SMARTDNS_CACHE_FILE;
	if (dns_conf_cache_file[0] != 0) {
		dns_cache_file = dns_conf_cache_file;
	}

	if (dns_conf_cache_persist == 2) {
		uint64_t freespace = get_free_space(dns_cache_file);
		if (freespace >= CACHE_AUTO_ENABLE_SIZE) {
			tlog(TLOG_INFO, "auto enable cache persist.");
			dns_conf_cache_persist = 1;
		}
	}

	if (dns_conf_cachesize <= 0 || dns_conf_cache_persist == 0) {
		return 0;
	}

	if (dns_cache_load(dns_cache_file) != 0) {
		tlog(TLOG_WARN, "Load cache failed.");
		return 0;
	}

	return 0;
}

static int _dns_server_cache_save(void)
{
	char *dns_cache_file = SMARTDNS_CACHE_FILE;
	if (dns_conf_cache_file[0] != 0) {
		dns_cache_file = dns_conf_cache_file;
	}

	if (dns_conf_cache_persist == 0 || dns_conf_cachesize <= 0) {
		if (access(dns_cache_file, F_OK) == 0) {
			unlink(dns_cache_file);
		}
		return 0;
	}

	if (dns_cache_save(dns_cache_file) != 0) {
		tlog(TLOG_WARN, "save cache failed.");
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

	if (_dns_server_cache_init() != 0) {
		tlog(TLOG_ERROR, "init dns cache filed.");
		goto errout;
	}

	if (_dns_server_audit_init() != 0) {
		tlog(TLOG_ERROR, "init audit failed.");
		goto errout;
	}

	memset(&server, 0, sizeof(server));
	pthread_attr_init(&attr);
	INIT_LIST_HEAD(&server.conn_list);

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

	pthread_mutex_init(&server.request_list_lock, NULL);
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

	_dns_server_cache_save();
	dns_cache_destroy();
}
