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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "dns_server.h"
#include "atomic.h"
#include "dns.h"
#include "dns_cache.h"
#include "dns_client.h"
#include "dns_conf.h"
#include "dns_plugin.h"
#include "fast_ping.h"
#include "hashtable.h"
#include "http_parse.h"
#include "list.h"
#include "nftset.h"
#include "tlog.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <math.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>

#define DNS_MAX_EVENTS 256
#define IPV6_READY_CHECK_TIME 180
#define DNS_SERVER_TMOUT_TTL (5 * 60)
#define DNS_SERVER_FAIL_TTL (60)
#define DNS_SERVER_SOA_TTL (30)
#define DNS_SERVER_ADDR_TTL (60)
#define DNS_CONN_BUFF_SIZE 4096
#define DNS_REQUEST_MAX_TIMEOUT 950
#define DNS_PING_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT)
#define DNS_PING_CHECK_INTERVAL (250)
#define DNS_PING_SECOND_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT - DNS_PING_CHECK_INTERVAL)
#define SOCKET_IP_TOS (IPTOS_LOWDELAY | IPTOS_RELIABILITY)
#define SOCKET_PRIORITY (6)
#define CACHE_AUTO_ENABLE_SIZE (1024 * 1024 * 128)
#define EXPIRED_DOMAIN_PREFETCH_TIME (3600 * 8)
#define DNS_MAX_DOMAIN_REFETCH_NUM 64
#define DNS_SERVER_NEIGHBOR_CACHE_MAX_NUM 8192
#define DNS_SERVER_NEIGHBOR_CACHE_TIMEOUT (3600 * 1)
#define DNS_SERVER_NEIGHBOR_CACHE_NOMAC_TIMEOUT 60

#define PREFETCH_FLAGS_NO_DUALSTACK (1 << 0)
#define PREFETCH_FLAGS_EXPIRED (1 << 1)
#define PREFETCH_FLAGS_NOPREFETCH (1 << 2)

#define RECV_ERROR_AGAIN 1
#define RECV_ERROR_OK 0
#define RECV_ERROR_FAIL (-1)
#define RECV_ERROR_CLOSE (-2)
#define RECV_ERROR_INVALID_PACKET (-3)

typedef enum {
	DNS_CONN_TYPE_UDP_SERVER = 0,
	DNS_CONN_TYPE_TCP_SERVER,
	DNS_CONN_TYPE_TCP_CLIENT,
	DNS_CONN_TYPE_TLS_SERVER,
	DNS_CONN_TYPE_TLS_CLIENT,
	DNS_CONN_TYPE_HTTPS_SERVER,
	DNS_CONN_TYPE_HTTPS_CLIENT,
} DNS_CONN_TYPE;

typedef enum DNS_CHILD_POST_RESULT {
	DNS_CHILD_POST_SUCCESS = 0,
	DNS_CHILD_POST_FAIL,
	DNS_CHILD_POST_SKIP,
	DNS_CHILD_POST_NO_RESPONSE,
} DNS_CHILD_POST_RESULT;

struct rule_walk_args {
	void *args;
	int rule_index;
	unsigned char *key[DOMAIN_RULE_MAX];
	uint32_t key_len[DOMAIN_RULE_MAX];
};

struct neighbor_enum_args {
	uint8_t *netaddr;
	int netaddr_len;
	struct client_roue_group_mac *group_mac;
};

struct neighbor_cache_item {
	struct hlist_node node;
	struct list_head list;
	unsigned char ip_addr[DNS_RR_AAAA_LEN];
	int ip_addr_len;
	unsigned char mac[6];
	int has_mac;
	time_t last_update_time;
};

struct neighbor_cache {
	DECLARE_HASHTABLE(cache, 6);
	atomic_t cache_num;
	struct list_head list;
	pthread_mutex_t lock;
};

struct local_addr_cache_item {
	unsigned char ip_addr[DNS_RR_AAAA_LEN];
	int ip_addr_len;
	int mask_len;
};

struct local_addr_cache {
	radix_tree_t *addr;
	int fd_netlink;
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
	struct nftset_ipset_rules *ipset_nftset_rule;
};

struct dns_server_post_context {
	unsigned char inpacket_buff[DNS_IN_PACKSIZE];
	unsigned char *inpacket;
	int inpacket_maxlen;
	int inpacket_len;
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned int packet_maxlen;
	struct dns_request *request;
	struct dns_packet *packet;
	int ip_num;
	const unsigned char *ip_addr[MAX_IP_NUM];
	dns_type_t qtype;
	int do_cache;
	int do_reply;
	int do_ipset;
	int do_log_result;
	int reply_ttl;
	int cache_ttl;
	int no_check_add_ip;
	int do_audit;
	int do_force_soa;
	int skip_notify_count;
	int select_all_best_ip;
	int no_release_parent;
};

typedef enum dns_server_client_status {
	DNS_SERVER_CLIENT_STATUS_INIT = 0,
	DNS_SERVER_CLIENT_STATUS_CONNECTING,
	DNS_SERVER_CLIENT_STATUS_CONNECTIONLESS,
	DNS_SERVER_CLIENT_STATUS_CONNECTED,
	DNS_SERVER_CLIENT_STATUS_DISCONNECTED,
} dns_server_client_status;

struct dns_server_conn_udp {
	struct dns_server_conn_head head;
	socklen_t addr_len;
	struct sockaddr_storage addr;
};

struct dns_server_conn_tcp_server {
	struct dns_server_conn_head head;
};

struct dns_server_conn_tls_server {
	struct dns_server_conn_head head;
	SSL_CTX *ssl_ctx;
};

struct dns_server_conn_tcp_client {
	struct dns_server_conn_head head;
	struct dns_conn_buf recvbuff;
	struct dns_conn_buf sndbuff;
	socklen_t addr_len;
	struct sockaddr_storage addr;

	socklen_t localaddr_len;
	struct sockaddr_storage localaddr;

	int conn_idle_timeout;
	dns_server_client_status status;
};

struct dns_server_conn_tls_client {
	struct dns_server_conn_tcp_client tcp;
	SSL *ssl;
	int ssl_want_write;
	pthread_mutex_t ssl_lock;
};

/* ip address lists of domain */
struct dns_ip_address {
	struct hlist_node node;
	int hitnum;
	unsigned long recv_tick;
	int ping_time;
	dns_type_t addr_type;
	char cname[DNS_MAX_CNAME_LEN];
	unsigned char ip_addr[DNS_RR_AAAA_LEN];
};

struct dns_request_pending_list {
	pthread_mutex_t request_list_lock;
	unsigned short qtype;
	char domain[DNS_MAX_CNAME_LEN];
	uint32_t server_flags;
	char dns_group_name[DNS_GROUP_NAME_LEN];
	struct list_head request_list;
	struct hlist_node node;
};

struct dns_request_domain_rule {
	struct dns_rule *rules[DOMAIN_RULE_MAX];
	int is_sub_rule[DOMAIN_RULE_MAX];
};

typedef DNS_CHILD_POST_RESULT (*child_request_callback)(struct dns_request *request, struct dns_request *child_request,
														int is_first_resp);

struct dns_request_https {
	char domain[DNS_MAX_CNAME_LEN];
	char target[DNS_MAX_CNAME_LEN];
	int ttl;
	int priority;
	char alpn[DNS_MAX_ALPN_LEN];
	int alpn_len;
	int port;
	char ech[DNS_MAX_ECH_LEN];
	int ech_len;
};

struct dns_request {
	atomic_t refcnt;

	struct dns_server_conn_head *conn;
	struct dns_conf_group *conf;
	uint32_t server_flags;
	char dns_group_name[DNS_GROUP_NAME_LEN];

	/* dns request list */
	struct list_head list;

	struct list_head pending_list;

	/* dns request timeout check list */
	struct list_head check_list;

	/* dns query */
	char domain[DNS_MAX_CNAME_LEN];
	dns_type_t qtype;
	int qclass;
	unsigned long send_tick;
	unsigned short id;
	unsigned short rcode;
	unsigned short ss_family;
	char remote_server_fail;
	char skip_qtype_soa;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};
	socklen_t addr_len;
	struct sockaddr_storage localaddr;
	int has_ecs;
	struct dns_opt_ecs ecs;
	int edns0_do;

	struct dns_request_https *https_svcb;

	dns_result_callback result_callback;
	void *user_ptr;

	int has_ping_result;
	int has_ping_tcp;
	int has_ptr;
	char ptr_hostname[DNS_MAX_CNAME_LEN];

	int has_cname;
	char cname[DNS_MAX_CNAME_LEN];
	int ttl_cname;

	int has_ip;
	int ping_time;
	int ip_ttl;
	unsigned char ip_addr[DNS_RR_AAAA_LEN];
	int ip_addr_type;

	struct dns_soa soa;
	int has_soa;
	int force_soa;

	int is_mdns_lookup;

	struct dns_srv_records *srv_records;

	atomic_t notified;
	atomic_t do_callback;
	atomic_t adblock;
	atomic_t soa_num;

	/* send original raw packet to server/client like proxy */
	int passthrough;

	int request_wait;
	int prefetch;
	int prefetch_flags;

	int dualstack_selection;
	int dualstack_selection_force_soa;
	int dualstack_selection_query;
	int dualstack_selection_ping_time;
	int dualstack_selection_has_ip;
	struct dns_request *dualstack_request;
	int no_serve_expired;

	pthread_mutex_t ip_map_lock;

	struct dns_request *child_request;
	struct dns_request *parent_request;
	child_request_callback child_callback;

	atomic_t ip_map_num;
	DECLARE_HASHTABLE(ip_map, 4);

	struct dns_request_domain_rule domain_rule;
	int skip_domain_rule;
	const struct dns_domain_check_orders *check_order_list;
	int check_order;

	enum response_mode_type response_mode;

	struct dns_request_pending_list *request_pending_list;

	int no_select_possible_ip;
	int no_cache_cname;
	int no_cache;
	int no_ipalias;

	int has_cname_loop;

	void *private_data;
};

/* dns server data */
struct dns_server {
	atomic_t run;
	int epoll_fd;
	int event_fd;
	struct list_head conn_list;

	pid_t cache_save_pid;
	time_t cache_save_time;

	/* dns request list */
	pthread_mutex_t request_list_lock;
	struct list_head request_list;
	atomic_t request_num;

	DECLARE_HASHTABLE(request_pending, 4);
	pthread_mutex_t request_pending_lock;

	struct neighbor_cache neighbor_cache;

	struct local_addr_cache local_addr_cache;
};

static int is_server_init;
static struct dns_server server;

static tlog_log *dns_audit;

static int is_ipv6_ready;

static int _dns_server_prefetch_request(char *domain, dns_type_t qtype,
										struct dns_server_query_option *server_query_option, int prefetch_flags);
static int _dns_server_get_answer(struct dns_server_post_context *context);
static void _dns_server_request_get(struct dns_request *request);
static void _dns_server_request_release(struct dns_request *request);
static void _dns_server_request_release_complete(struct dns_request *request, int do_complete);
static int _dns_server_request_complete(struct dns_request *request);
static int _dns_server_reply_passthrough(struct dns_server_post_context *context);
static int _dns_server_do_query(struct dns_request *request, int skip_notify_event);
static int _dns_request_post(struct dns_server_post_context *context);
static int _dns_server_reply_all_pending_list(struct dns_request *request, struct dns_server_post_context *context);
static void *_dns_server_get_dns_rule(struct dns_request *request, enum domain_rule rule);
static int _dns_server_get_local_ttl(struct dns_request *request);
static const char *_dns_server_get_request_server_groupname(struct dns_request *request);
static int _dns_server_tcp_socket_send(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len);
static int _dns_server_update_request_connection_timeout(struct dns_server_conn_head *conn, int timeout);
static int _dns_server_cache_save(int check_lock);

int dns_is_ipv6_ready(void)
{
	return is_ipv6_ready;
}

static void _dns_server_wakeup_thread(void)
{
	uint64_t u = 1;
	int unused __attribute__((unused));
	unused = write(server.event_fd, &u, sizeof(u));
}

static int _dns_server_forward_request(unsigned char *inpacket, int inpacket_len)
{
	return -1;
}

static int _dns_server_has_bind_flag(struct dns_request *request, uint32_t flag)
{
	if (request->server_flags & flag) {
		return 0;
	}

	return -1;
}

static void *_dns_server_get_bind_ipset_nftset_rule(struct dns_request *request, enum domain_rule type)
{
	if (request->conn == NULL) {
		return NULL;
	}

	if (request->conn->ipset_nftset_rule == NULL) {
		return NULL;
	}

	switch (type) {
	case DOMAIN_RULE_IPSET:
		return request->conn->ipset_nftset_rule->ipset;
	case DOMAIN_RULE_IPSET_IPV4:
		return request->conn->ipset_nftset_rule->ipset_ip;
	case DOMAIN_RULE_IPSET_IPV6:
		return request->conn->ipset_nftset_rule->ipset_ip6;
	case DOMAIN_RULE_NFTSET_IP:
		return request->conn->ipset_nftset_rule->nftset_ip;
	case DOMAIN_RULE_NFTSET_IP6:
		return request->conn->ipset_nftset_rule->nftset_ip6;
	default:
		break;
	}

	return NULL;
}

static int _dns_server_get_conf_ttl(struct dns_request *request, int ttl)
{
	int rr_ttl = request->conf->dns_rr_ttl;
	int rr_ttl_min = request->conf->dns_rr_ttl_min;
	int rr_ttl_max = request->conf->dns_rr_ttl_max;

	if (request->is_mdns_lookup) {
		rr_ttl_min = DNS_SERVER_ADDR_TTL;
	}

	struct dns_ttl_rule *ttl_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_TTL);
	if (ttl_rule != NULL) {
		if (ttl_rule->ttl > 0) {
			rr_ttl = ttl_rule->ttl;
		}

		/* make domain rule ttl high priority */
		if (ttl_rule->ttl_min > 0) {
			rr_ttl_min = ttl_rule->ttl_min;
			if (request->conf->dns_rr_ttl_max <= rr_ttl_min && request->conf->dns_rr_ttl_max > 0) {
				rr_ttl_max = rr_ttl_min;
			}
		}

		if (ttl_rule->ttl_max > 0) {
			rr_ttl_max = ttl_rule->ttl_max;
			if (request->conf->dns_rr_ttl_min >= rr_ttl_max && request->conf->dns_rr_ttl_min > 0 &&
				ttl_rule->ttl_min <= 0) {
				rr_ttl_min = rr_ttl_max;
			}
		}
	}

	if (rr_ttl > 0) {
		return rr_ttl;
	}

	/* make rr_ttl_min first priority */
	if (rr_ttl_max < rr_ttl_min && rr_ttl_max > 0) {
		rr_ttl_max = rr_ttl_min;
	}

	if (rr_ttl_max > 0 && ttl >= rr_ttl_max) {
		ttl = rr_ttl_max;
	} else if (rr_ttl_min > 0 && ttl <= rr_ttl_min) {
		ttl = rr_ttl_min;
	}

	return ttl;
}

static int _dns_server_get_reply_ttl(struct dns_request *request, int ttl)
{
	int reply_ttl = ttl;

	if ((request->passthrough == 0 || request->passthrough == 2) && dns_conf_cachesize > 0 &&
		request->check_order_list->orders[0].type != DOMAIN_CHECK_NONE) {
		reply_ttl = request->conf->dns_serve_expired_reply_ttl;
		if (reply_ttl < 2) {
			reply_ttl = 2;
		}
	}

	int rr_ttl = _dns_server_get_conf_ttl(request, ttl);
	if (reply_ttl > rr_ttl) {
		reply_ttl = rr_ttl;
	}

	return reply_ttl;
}

static int _dns_server_epoll_ctl(struct dns_server_conn_head *head, int op, uint32_t events)
{
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = events;
	event.data.ptr = head;

	if (epoll_ctl(server.epoll_fd, op, head->fd, &event) != 0) {
		return -1;
	}

	return 0;
}

static void *_dns_server_get_dns_rule_ext(struct dns_request_domain_rule *domain_rule, enum domain_rule rule)
{
	if (rule >= DOMAIN_RULE_MAX || domain_rule == NULL) {
		return NULL;
	}

	return domain_rule->rules[rule];
}

static int _dns_server_is_dns_rule_extract_match_ext(struct dns_request_domain_rule *domain_rule, enum domain_rule rule)
{
	if (rule >= DOMAIN_RULE_MAX || domain_rule == NULL) {
		return 0;
	}

	return domain_rule->is_sub_rule[rule] == 0;
}

static void *_dns_server_get_dns_rule(struct dns_request *request, enum domain_rule rule)
{
	if (request == NULL) {
		return NULL;
	}

	return _dns_server_get_dns_rule_ext(&request->domain_rule, rule);
}

static int _dns_server_is_dns_rule_extract_match(struct dns_request *request, enum domain_rule rule)
{
	if (request == NULL) {
		return 0;
	}

	return _dns_server_is_dns_rule_extract_match_ext(&request->domain_rule, rule);
}

static int _dns_server_is_dns64_request(struct dns_request *request)
{
	if (request->qtype != DNS_T_AAAA) {
		return 0;
	}

	if (request->dualstack_selection_query == 1) {
		return 0;
	}

	if (request->conf->dns_dns64.prefix_len <= 0) {
		return 0;
	}

	return 1;
}

static void _dns_server_set_dualstack_selection(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;

	if (request->dualstack_selection_query || is_ipv6_ready == 0) {
		request->dualstack_selection = 0;
		return;
	}

	if ((request->prefetch_flags & PREFETCH_FLAGS_NO_DUALSTACK) != 0 ||
		(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED) != 0) {
		request->dualstack_selection = 0;
		return;
	}

	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
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

	request->dualstack_selection = request->conf->dualstack_ip_selection;
}

static int _dns_server_is_return_soa_qtype(struct dns_request *request, dns_type_t qtype)
{
	struct dns_rule_flags *rule_flag = NULL;
	unsigned int flags = 0;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_SOA) == 0) {
		/* when both has no rule SOA and force AAAA soa, force AAAA soa has high priority */
		if (qtype == DNS_T_AAAA && _dns_server_has_bind_flag(request, BIND_FLAG_FORCE_AAAA_SOA) == 0) {
			return 1;
		}

		return 0;
	}

	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag) {
		flags = rule_flag->flags;
		if (flags & DOMAIN_FLAG_ADDR_SOA) {
			return 1;
		}

		if (flags & DOMAIN_FLAG_ADDR_IGN) {
			request->skip_qtype_soa = 1;
			return 0;
		}

		switch (qtype) {
		case DNS_T_A:
			if (flags & DOMAIN_FLAG_ADDR_IPV4_SOA) {
				return 1;
			}

			if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
				request->skip_qtype_soa = 1;
				return 0;
			}
			break;
		case DNS_T_AAAA:
			if (flags & DOMAIN_FLAG_ADDR_IPV6_SOA) {
				return 1;
			}

			if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
				request->skip_qtype_soa = 1;
				return 0;
			}
			break;
		case DNS_T_HTTPS:
			if (flags & DOMAIN_FLAG_ADDR_HTTPS_SOA) {
				return 1;
			}

			if (flags & DOMAIN_FLAG_ADDR_HTTPS_IGN) {
				request->skip_qtype_soa = 1;
				return 0;
			}
			break;
		default:
			break;
		}
	}

	if (qtype == DNS_T_AAAA) {
		if (_dns_server_has_bind_flag(request, BIND_FLAG_FORCE_AAAA_SOA) == 0 || request->conf->force_AAAA_SOA == 1) {
			return 1;
		}

		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL &&
			request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] == NULL) {
			return 1;
		}
	} else if (qtype == DNS_T_A) {
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL &&
			request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] == NULL) {
			return 1;
		}
	} else if (qtype == DNS_T_HTTPS) {
		if (request->domain_rule.rules[DOMAIN_RULE_HTTPS] == NULL) {
			return 1;
		}
	}

	return 0;
}

static int _dns_server_is_return_soa(struct dns_request *request)
{
	return _dns_server_is_return_soa_qtype(request, request->qtype);
}

static void _dns_server_post_context_init(struct dns_server_post_context *context, struct dns_request *request)
{
	memset(context, 0, sizeof(*context));
	context->packet = (struct dns_packet *)(context->packet_buff);
	context->packet_maxlen = sizeof(context->packet_buff);
	context->inpacket = (unsigned char *)(context->inpacket_buff);
	context->inpacket_maxlen = sizeof(context->inpacket_buff);
	context->qtype = request->qtype;
	context->request = request;
}

static void _dns_server_context_add_ip(struct dns_server_post_context *context, const unsigned char *ip_addr)
{
	if (context->ip_num < MAX_IP_NUM) {
		context->ip_addr[context->ip_num] = ip_addr;
	}

	context->ip_num++;
}

static void _dns_server_post_context_init_from(struct dns_server_post_context *context, struct dns_request *request,
											   struct dns_packet *packet, unsigned char *inpacket, int inpacket_len)
{
	memset(context, 0, sizeof(*context));
	context->packet = packet;
	context->packet_maxlen = sizeof(context->packet_buff);
	context->inpacket = inpacket;
	context->inpacket_len = inpacket_len;
	context->inpacket_maxlen = sizeof(context->inpacket);
	context->qtype = request->qtype;
	context->request = request;
}

static struct dns_ip_address *_dns_ip_address_get(struct dns_request *request, unsigned char *addr,
												  dns_type_t addr_type)
{
	uint32_t key = 0;
	struct dns_ip_address *addr_map = NULL;
	struct dns_ip_address *addr_tmp = NULL;
	int addr_len = 0;

	if (addr_type == DNS_T_A) {
		addr_len = DNS_RR_A_LEN;
	} else if (addr_type == DNS_T_AAAA) {
		addr_len = DNS_RR_AAAA_LEN;
	} else {
		return NULL;
	}

	/* store the ip address and the number of hits */
	key = jhash(addr, addr_len, 0);
	key = jhash(&addr_type, sizeof(addr_type), key);
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_possible(request->ip_map, addr_tmp, node, key)
	{
		if (addr_type != addr_tmp->addr_type) {
			continue;
		}

		if (memcmp(addr_tmp->ip_addr, addr, addr_len) != 0) {
			continue;
		}

		addr_map = addr_tmp;
		break;
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	return addr_map;
}

static void _dns_server_audit_log(struct dns_server_post_context *context)
{
	char req_host[MAX_IP_LEN];
	char req_result[1024] = {0};
	char *ip_msg = req_result;
	char req_time[MAX_IP_LEN] = {0};
	struct tlog_time tm;
	int i = 0;
	int j = 0;
	int rr_count = 0;
	struct dns_rrs *rrs = NULL;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int ttl = 0;
	int len = 0;
	int left_len = sizeof(req_result);
	int total_len = 0;
	int ip_num = 0;
	struct dns_request *request = context->request;
	int has_soa = request->has_soa;

	if (dns_audit == NULL || !dns_conf_audit_enable || context->do_audit == 0) {
		return;
	}

	if (request->conn == NULL) {
		return;
	}

	for (j = 1; j < DNS_RRS_OPT && context->packet; j++) {
		rrs = dns_get_rrs_start(context->packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs && left_len > 0; i++, rrs = dns_get_rrs_next(context->packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char ipv4_addr[4];
				if (dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv4_addr) != 0) {
					continue;
				}

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				const char *fmt = "%d.%d.%d.%d";
				if (ip_num > 0) {
					fmt = ", %d.%d.%d.%d";
				}

				len =
					snprintf(ip_msg + total_len, left_len, fmt, ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
				ip_num++;
				has_soa = 0;
			} break;
			case DNS_T_AAAA: {
				unsigned char ipv6_addr[16];
				if (dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv6_addr) != 0) {
					continue;
				}

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				const char *fmt = "%s";
				if (ip_num > 0) {
					fmt = ", %s";
				}
				req_host[0] = '\0';
				inet_ntop(AF_INET6, ipv6_addr, req_host, sizeof(req_host));
				len = snprintf(ip_msg + total_len, left_len, fmt, req_host);
				ip_num++;
				has_soa = 0;
			} break;
			case DNS_T_SOA: {
				if (ip_num == 0) {
					has_soa = 1;
				}
			} break;
			default:
				continue;
			}

			if (len < 0 || len >= left_len) {
				left_len = 0;
				break;
			}

			left_len -= len;
			total_len += len;
		}
	}

	if (has_soa && ip_num == 0) {
		if (!dns_conf_audit_log_SOA) {
			return;
		}

		if (request->dualstack_selection_force_soa) {
			snprintf(req_result, left_len, "dualstack soa");
		} else {
			snprintf(req_result, left_len, "soa");
		}
	}

	get_host_by_addr(req_host, sizeof(req_host), &request->addr);
	tlog_localtime(&tm);

	if (req_host[0] == '\0') {
		safe_strncpy(req_host, "API", MAX_IP_LEN);
	}

	if (dns_conf_audit_syslog == 0) {
		snprintf(req_time, sizeof(req_time), "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d] ", tm.year, tm.mon, tm.mday, tm.hour,
				 tm.min, tm.sec, tm.usec / 1000);
	}

	tlog_printf(dns_audit, "%s%s query %s, type %d, time %lums, speed: %.1fms, group %s, result %s\n", req_time,
				req_host, request->domain, request->qtype, get_tick_count() - request->send_tick,
				((float)request->ping_time) / 10,
				request->dns_group_name[0] != '\0' ? request->dns_group_name : DNS_SERVER_GROUP_DEFAULT, req_result);
}

static void _dns_rrs_result_log(struct dns_server_post_context *context, struct dns_ip_address *addr_map)
{
	struct dns_request *request = context->request;

	if (context->do_log_result == 0 || addr_map == NULL) {
		return;
	}

	if (addr_map->addr_type == DNS_T_A) {
		tlog(TLOG_INFO, "result: %s, id: %d, index: %d, rtt: %.1f ms, %d.%d.%d.%d", request->domain, request->id,
			 context->ip_num, ((float)addr_map->ping_time) / 10, addr_map->ip_addr[0], addr_map->ip_addr[1],
			 addr_map->ip_addr[2], addr_map->ip_addr[3]);
	} else if (addr_map->addr_type == DNS_T_AAAA) {
		tlog(TLOG_INFO,
			 "result: %s, id: %d, index: %d, rtt: %.1f ms, "
			 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
			 request->domain, request->id, context->ip_num, ((float)addr_map->ping_time) / 10, addr_map->ip_addr[0],
			 addr_map->ip_addr[1], addr_map->ip_addr[2], addr_map->ip_addr[3], addr_map->ip_addr[4],
			 addr_map->ip_addr[5], addr_map->ip_addr[6], addr_map->ip_addr[7], addr_map->ip_addr[8],
			 addr_map->ip_addr[9], addr_map->ip_addr[10], addr_map->ip_addr[11], addr_map->ip_addr[12],
			 addr_map->ip_addr[13], addr_map->ip_addr[14], addr_map->ip_addr[15]);
	}
}

static int _dns_rrs_add_all_best_ip(struct dns_server_post_context *context)
{
	struct dns_ip_address *addr_map = NULL;
	struct dns_ip_address *added_ip_addr = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_request *request = context->request;
	unsigned long bucket = 0;

	char *domain = NULL;
	int ret = 0;
	int ignore_speed = 0;
	int maxhit = 0;

	if (context->select_all_best_ip == 0 || context->ip_num >= request->conf->dns_max_reply_ip_num) {
		return 0;
	}

	domain = request->domain;
	/* add CNAME record */
	if (request->has_cname) {
		domain = request->cname;
	}

	/* add fasted ip address at first place of dns RR */
	if (request->has_ip) {
		added_ip_addr = _dns_ip_address_get(request, request->ip_addr, request->qtype);
		_dns_rrs_result_log(context, added_ip_addr);
	}

	if (request->passthrough == 2) {
		ignore_speed = 1;
	}

	while (true) {
		pthread_mutex_lock(&request->ip_map_lock);
		hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
		{
			if (context->ip_num >= request->conf->dns_max_reply_ip_num) {
				break;
			}

			if (context->qtype != addr_map->addr_type) {
				continue;
			}

			if (addr_map == added_ip_addr) {
				continue;
			}

			if (addr_map->hitnum > maxhit) {
				maxhit = addr_map->hitnum;
			}

			if (addr_map->ping_time < 0 && ignore_speed == 0) {
				continue;
			}

			if (addr_map->hitnum < maxhit && ignore_speed == 1) {
				continue;
			}

			/* if ping time is larger than 5ms, check again. */
			if (addr_map->ping_time - request->ping_time >= 50) {
				int ttl_range = request->ping_time + request->ping_time / 10 + 5;
				if ((ttl_range < addr_map->ping_time) && addr_map->ping_time >= 100 && ignore_speed == 0) {
					continue;
				}
			}

			_dns_server_context_add_ip(context, addr_map->ip_addr);
			if (addr_map->addr_type == DNS_T_A) {
				ret |= dns_add_A(context->packet, DNS_RRS_AN, domain, request->ip_ttl, addr_map->ip_addr);
			} else if (addr_map->addr_type == DNS_T_AAAA) {
				ret |= dns_add_AAAA(context->packet, DNS_RRS_AN, domain, request->ip_ttl, addr_map->ip_addr);
			}
			_dns_rrs_result_log(context, addr_map);
		}
		pthread_mutex_unlock(&request->ip_map_lock);

		if (context->ip_num <= 0 && ignore_speed == 0) {
			ignore_speed = 1;
		} else {
			break;
		}
	}

	return ret;
}

static void _dns_server_setup_soa(struct dns_request *request)
{
	struct dns_soa *soa = NULL;
	soa = &request->soa;

	safe_strncpy(soa->mname, "a.gtld-servers.net", DNS_MAX_CNAME_LEN);
	safe_strncpy(soa->rname, "nstld.verisign-grs.com", DNS_MAX_CNAME_LEN);
	soa->serial = 1800;
	soa->refresh = 1800;
	soa->retry = 900;
	soa->expire = 604800;
	soa->minimum = 86400;
}

static int _dns_server_add_srv(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_srv_records *srv_records = request->srv_records;
	struct dns_srv_record *srv_record = NULL;
	int ret = 0;

	if (srv_records == NULL) {
		return 0;
	}

	list_for_each_entry(srv_record, &srv_records->list, list)
	{
		ret = dns_add_SRV(context->packet, DNS_RRS_AN, request->domain, request->ip_ttl, srv_record->priority,
						  srv_record->weight, srv_record->port, srv_record->host);
		if (ret != 0) {
			return -1;
		}
	}

	return 0;
}

static int _dns_add_rrs_HTTPS(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_request_https *https_svcb = request->https_svcb;
	int ret = 0;
	struct dns_rr_nested param;

	if (https_svcb == NULL || request->qtype != DNS_T_HTTPS) {
		return 0;
	}

	ret = dns_add_HTTPS_start(&param, context->packet, DNS_RRS_AN, https_svcb->domain, https_svcb->ttl,
							  https_svcb->priority, https_svcb->target);
	if (ret != 0) {
		return ret;
	}

	if (https_svcb->alpn[0] != '\0' && https_svcb->alpn_len > 0) {
		ret = dns_HTTPS_add_alpn(&param, https_svcb->alpn, https_svcb->alpn_len);
		if (ret != 0) {
			return ret;
		}
	}

	if (https_svcb->port != 0) {
		ret = dns_HTTPS_add_port(&param, https_svcb->port);
		if (ret != 0) {
			return ret;
		}
	}

	if (request->has_ip) {
		unsigned char *addr[1];
		addr[0] = request->ip_addr;
		if (request->ip_addr_type == DNS_T_A) {
			ret = dns_HTTPS_add_ipv4hint(&param, addr, 1);
		}
	}

	if (https_svcb->ech_len > 0) {
		ret = dns_HTTPS_add_ech(&param, https_svcb->ech, https_svcb->ech_len);
		if (ret != 0) {
			return ret;
		}
	}

	if (request->has_ip) {
		unsigned char *addr[1];
		addr[0] = request->ip_addr;
		if (request->ip_addr_type == DNS_T_AAAA) {
			ret = dns_HTTPS_add_ipv6hint(&param, addr, 1);
		}
	}

	dns_add_HTTPS_end(&param);
	return 0;
}

static int _dns_add_rrs(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	int ret = 0;
	int has_soa = request->has_soa;
	char *domain = request->domain;
	if (request->has_ptr) {
		/* add PTR record */
		ret = dns_add_PTR(context->packet, DNS_RRS_AN, request->domain, request->ip_ttl, request->ptr_hostname);
	}

	/* add CNAME record */
	if (request->has_cname && context->do_force_soa == 0) {
		ret |= dns_add_CNAME(context->packet, DNS_RRS_AN, request->domain, request->ttl_cname, request->cname);
		domain = request->cname;
	}

	if (request->https_svcb != NULL) {
		ret = _dns_add_rrs_HTTPS(context);
	}

	/* add A record */
	if (request->has_ip && context->do_force_soa == 0) {
		_dns_server_context_add_ip(context, request->ip_addr);
		if (context->qtype == DNS_T_A) {
			ret |= dns_add_A(context->packet, DNS_RRS_AN, domain, request->ip_ttl, request->ip_addr);
			tlog(TLOG_DEBUG, "result: %s, rtt: %.1f ms, %d.%d.%d.%d", request->domain, ((float)request->ping_time) / 10,
				 request->ip_addr[0], request->ip_addr[1], request->ip_addr[2], request->ip_addr[3]);
		}

		/* add AAAA record */
		if (context->qtype == DNS_T_AAAA) {
			ret |= dns_add_AAAA(context->packet, DNS_RRS_AN, domain, request->ip_ttl, request->ip_addr);
			tlog(TLOG_DEBUG,
				 "result: %s, rtt: %.1f ms, "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, ((float)request->ping_time) / 10, request->ip_addr[0], request->ip_addr[1],
				 request->ip_addr[2], request->ip_addr[3], request->ip_addr[4], request->ip_addr[5],
				 request->ip_addr[6], request->ip_addr[7], request->ip_addr[8], request->ip_addr[9],
				 request->ip_addr[10], request->ip_addr[11], request->ip_addr[12], request->ip_addr[13],
				 request->ip_addr[14], request->ip_addr[15]);
		}
	}

	if (context->do_force_soa == 0) {
		ret |= _dns_rrs_add_all_best_ip(context);
	}

	if (context->qtype == DNS_T_A || context->qtype == DNS_T_AAAA) {
		if (context->ip_num > 0) {
			has_soa = 0;
		}
	}
	/* add SOA record */
	if (has_soa) {
		ret |= dns_add_SOA(context->packet, DNS_RRS_NS, domain, request->ip_ttl, &request->soa);
		tlog(TLOG_DEBUG, "result: %s, qtype: %d, return SOA", request->domain, context->qtype);
	} else if (context->do_force_soa == 1) {
		_dns_server_setup_soa(request);
		ret |= dns_add_SOA(context->packet, DNS_RRS_NS, domain, request->ip_ttl, &request->soa);
	}

	if (request->has_ecs) {
		ret |= dns_add_OPT_ECS(context->packet, &request->ecs);
	}

	if (request->srv_records != NULL) {
		ret |= _dns_server_add_srv(context);
	}

	if (request->rcode != DNS_RC_NOERROR) {
		tlog(TLOG_INFO, "result: %s, qtype: %d, rtcode: %d, id: %d", domain, context->qtype, request->rcode,
			 request->id);
	}

	return ret;
}

static int _dns_setup_dns_packet(struct dns_server_post_context *context)
{
	struct dns_head head;
	struct dns_request *request = context->request;
	int ret = 0;

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
	ret = dns_packet_init(context->packet, context->packet_maxlen, &head);
	if (ret != 0) {
		return -1;
	}

	if (request->domain[0] == '\0') {
		return 0;
	}

	/* add request domain */
	ret = dns_add_domain(context->packet, request->domain, context->qtype, request->qclass);
	if (ret != 0) {
		return -1;
	}

	/* add RECORDs */
	ret = _dns_add_rrs(context);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

static int _dns_setup_dns_raw_packet(struct dns_server_post_context *context)
{
	/* encode to binary data */
	int encode_len = dns_encode(context->inpacket, context->inpacket_maxlen, context->packet);
	if (encode_len <= 0) {
		tlog(TLOG_DEBUG, "encode raw packet failed for %s", context->request->domain);
		return -1;
	}

	context->inpacket_len = encode_len;

	return 0;
}

static void _dns_server_conn_release(struct dns_server_conn_head *conn)
{
	if (conn == NULL) {
		return;
	}

	int refcnt = atomic_dec_return(&conn->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			BUG("BUG: refcnt is %d, type = %d", refcnt, conn->type);
		}
		return;
	}

	if (conn->fd > 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	if (conn->type == DNS_CONN_TYPE_TLS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)conn;
		if (tls_client->ssl != NULL) {
			SSL_free(tls_client->ssl);
			tls_client->ssl = NULL;
		}
		pthread_mutex_destroy(&tls_client->ssl_lock);
	} else if (conn->type == DNS_CONN_TYPE_TLS_SERVER || conn->type == DNS_CONN_TYPE_HTTPS_SERVER) {
		struct dns_server_conn_tls_server *tls_server = (struct dns_server_conn_tls_server *)conn;
		if (tls_server->ssl_ctx != NULL) {
			SSL_CTX_free(tls_server->ssl_ctx);
			tls_server->ssl_ctx = NULL;
		}
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
		BUG("BUG: client ref is invalid.");
	}
}

static int _dns_server_reply_tcp_to_buffer(struct dns_server_conn_tcp_client *tcpclient, void *packet, int len)
{
	if ((int)sizeof(tcpclient->sndbuff.buf) - tcpclient->sndbuff.size < len) {
		return -1;
	}

	memcpy(tcpclient->sndbuff.buf + tcpclient->sndbuff.size, packet, len);
	tcpclient->sndbuff.size += len;

	if (tcpclient->head.fd <= 0) {
		return -1;
	}

	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int _dns_server_reply_http_error(struct dns_server_conn_tcp_client *tcpclient, int code, const char *code_msg,
										const char *message)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char data[DNS_IN_PACKSIZE];
	int msg_len = strlen(message);

	http_len = snprintf((char *)data, DNS_IN_PACKSIZE,
						"HTTP/1.1 %d %s\r\n"
						"Content-Length: %d\r\n"
						"\r\n"
						"%s\r\n",
						code, code_msg, msg_len + 2, message);

	send_len = _dns_server_tcp_socket_send(tcpclient, data, http_len);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(tcpclient, data, http_len);
		}
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(tcpclient, data + send_len, http_len - send_len);
	}

	return 0;
}

static int _dns_server_reply_https(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient,
								   void *packet, unsigned short len)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	if (len > sizeof(inpacket_data)) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	http_len = snprintf((char *)inpacket, DNS_IN_PACKSIZE,
						"HTTP/1.1 200 OK\r\n"
						"Content-Type: application/dns-message\r\n"
						"Content-Length: %d\r\n"
						"\r\n",
						len);
	memcpy(inpacket + http_len, packet, len);
	http_len += len;

	send_len = _dns_server_tcp_socket_send(tcpclient, inpacket, http_len);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket, http_len);
		}
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket + send_len, http_len - send_len);
	}

	return 0;
}

static int _dns_server_reply_tcp(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient,
								 void *packet, unsigned short len)
{
	int send_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	if (len > sizeof(inpacket_data) - 2) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	/* TCP query format
	 * | len (short) | dns query data |
	 */
	*((unsigned short *)(inpacket)) = htons(len);
	memcpy(inpacket + 2, packet, len);
	len += 2;

	send_len = _dns_server_tcp_socket_send(tcpclient, inpacket, len);
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
	struct iovec iovec[1];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char msg_control[64];

	if (atomic_read(&server.run) == 0 || inpacket == NULL || inpacket_len <= 0) {
		return -1;
	}

	iovec[0].iov_base = inpacket;
	iovec[0].iov_len = inpacket_len;
	memset(msg_control, 0, sizeof(msg_control));
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = msg_control;
	msg.msg_controllen = sizeof(msg_control);
	msg.msg_flags = 0;
	msg.msg_name = &request->addr;
	msg.msg_namelen = request->addr_len;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (request->localaddr.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (struct sockaddr_in *)&request->localaddr;
		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

		struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
		memset(pktinfo, 0, sizeof(*pktinfo));
		pktinfo->ipi_spec_dst = s4->sin_addr;
	} else if (request->localaddr.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&request->localaddr;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

		struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		memset(pktinfo, 0, sizeof(*pktinfo));
		pktinfo->ipi6_addr = s6->sin6_addr;
	} else {
		goto use_send;
	}

	send_len = sendmsg(udpserver->head.fd, &msg, 0);
	if (send_len == inpacket_len) {
		return 0;
	}

use_send:
	send_len = sendto(udpserver->head.fd, inpacket, inpacket_len, 0, &request->addr, request->addr_len);
	if (send_len != inpacket_len) {
		tlog(TLOG_DEBUG, "send failed, %s", strerror(errno));
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
		ret = _dns_server_reply_tcp(request, (struct dns_server_conn_tcp_client *)conn, inpacket, inpacket_len);
	} else if (conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		ret = _dns_server_reply_https(request, (struct dns_server_conn_tcp_client *)conn, inpacket, inpacket_len);
	} else {
		ret = -1;
	}

	return ret;
}

static inline int _dns_server_expired_cache_ttl(struct dns_cache *cache, int serve_expired_ttl)
{
	return cache->info.insert_time + cache->info.ttl + serve_expired_ttl - time(NULL);
}

static int _dns_cache_is_specify_packet(int qtype)
{
	switch (qtype) {
	case DNS_T_PTR:
	case DNS_T_HTTPS:
	case DNS_T_TXT:
	case DNS_T_SRV:
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static int _dns_server_get_cache_timeout(struct dns_request *request, struct dns_cache_key *cache_key, int ttl)
{
	int timeout = 0;
	int prefetch_time = 0;
	int is_serve_expired = request->conf->dns_serve_expired;

	if (request->rcode != DNS_RC_NOERROR) {
		return ttl + 1;
	}

	if (request->is_mdns_lookup == 1) {
		return ttl + 1;
	}

	if (request->conf->dns_prefetch) {
		prefetch_time = 1;
	}

	if ((request->prefetch_flags & PREFETCH_FLAGS_NOPREFETCH)) {
		prefetch_time = 0;
	}

	if (request->edns0_do == 1) {
		prefetch_time = 0;
	}

	if (request->no_serve_expired) {
		is_serve_expired = 0;
	}

	if (prefetch_time == 1) {
		if (is_serve_expired) {
			timeout = request->conf->dns_serve_expired_prefetch_time;
			if (timeout == 0) {
				timeout = request->conf->dns_serve_expired_ttl / 2;
				if (timeout == 0 || timeout > EXPIRED_DOMAIN_PREFETCH_TIME) {
					timeout = EXPIRED_DOMAIN_PREFETCH_TIME;
				}
			}

			if ((request->prefetch_flags & PREFETCH_FLAGS_EXPIRED) == 0) {
				timeout += ttl;
			} else if (cache_key != NULL) {
				struct dns_cache *old_cache = dns_cache_lookup(cache_key);
				if (old_cache) {
					time_t next_ttl = _dns_server_expired_cache_ttl(old_cache, request->conf->dns_serve_expired_ttl) -
									  old_cache->info.ttl + ttl;
					if (next_ttl < timeout) {
						timeout = next_ttl;
					}
					dns_cache_release(old_cache);
				}
			}
		} else {
			timeout = ttl - 3;
		}
	} else {
		timeout = ttl;
		if (is_serve_expired) {
			timeout += request->conf->dns_serve_expired_ttl;
		}

		timeout += 3;
	}

	if (timeout <= 0) {
		timeout = 1;
	}

	return timeout;
}

static int _dns_server_request_update_cache(struct dns_request *request, int speed, dns_type_t qtype,
											struct dns_cache_data *cache_data, int cache_ttl)
{
	int ttl = 0;
	int ret = -1;

	if (qtype != DNS_T_A && qtype != DNS_T_AAAA && qtype != DNS_T_HTTPS) {
		goto errout;
	}

	if (cache_ttl > 0) {
		ttl = cache_ttl;
	} else {
		ttl = _dns_server_get_conf_ttl(request, request->ip_ttl);
	}

	tlog(TLOG_DEBUG, "cache %s qtype: %d ttl: %d\n", request->domain, qtype, ttl);

	/* if doing prefetch, update cache only */
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = request->qtype;
	cache_key.query_flag = request->server_flags;

	if (request->prefetch) {
		/* no prefetch for mdns request */
		if (request->is_mdns_lookup) {
			ret = 0;
			goto errout;
		}

		if (dns_cache_replace(&cache_key, request->rcode, ttl, speed,
							  _dns_server_get_cache_timeout(request, &cache_key, ttl),
							  !(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED), cache_data) != 0) {
			ret = 0;
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(&cache_key, request->rcode, ttl, speed, _dns_server_get_cache_timeout(request, NULL, ttl),
							 cache_data) != 0) {
			ret = -1;
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_data) {
		dns_cache_data_put(cache_data);
	}
	return ret;
}

static int _dns_cache_cname_packet(struct dns_server_post_context *context)
{
	struct dns_packet *packet = context->packet;
	struct dns_packet *cname_packet = NULL;
	int ret = -1;
	int i = 0;
	int j = 0;
	int rr_count = 0;
	int ttl = 0;
	int speed = 0;
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char inpacket_buff[DNS_IN_PACKSIZE];
	int inpacket_len = 0;

	struct dns_cache_data *cache_packet = NULL;
	struct dns_rrs *rrs = NULL;
	char name[DNS_MAX_CNAME_LEN] = {0};
	cname_packet = (struct dns_packet *)packet_buff;
	int has_result = 0;

	struct dns_request *request = context->request;

	if (request->has_cname == 0 || request->no_cache_cname == 1 || request->no_cache == 1) {
		return 0;
	}

	/* init a new DNS packet */
	ret = dns_packet_init(cname_packet, DNS_PACKSIZE, &packet->head);
	if (ret != 0) {
		return -1;
	}

	/* add request domain */
	ret = dns_add_domain(cname_packet, request->cname, context->qtype, DNS_C_IN);
	if (ret != 0) {
		return -1;
	}

	for (j = 1; j < DNS_RRS_OPT && context->packet; j++) {
		rrs = dns_get_rrs_start(context->packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(context->packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char ipv4_addr[4];
				if (dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv4_addr) != 0) {
					continue;
				}

				if (strncasecmp(request->cname, name, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				ret = dns_add_A(cname_packet, DNS_RRS_AN, request->cname, ttl, ipv4_addr);
				if (ret != 0) {
					return -1;
				}
				has_result = 1;
			} break;
			case DNS_T_AAAA: {
				unsigned char ipv6_addr[16];
				if (dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv6_addr) != 0) {
					continue;
				}

				if (strncasecmp(request->cname, name, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				ret = dns_add_AAAA(cname_packet, DNS_RRS_AN, request->cname, ttl, ipv6_addr);
				if (ret != 0) {
					return -1;
				}
				has_result = 1;
			} break;
			case DNS_T_SOA: {
				struct dns_soa soa;
				if (dns_get_SOA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, &soa) != 0) {
					continue;
				}

				ret = dns_add_SOA(cname_packet, DNS_RRS_AN, request->cname, ttl, &soa);
				if (ret != 0) {
					return -1;
				}
				has_result = 1;
				break;
			}
			default:
				continue;
			}
		}
	}

	if (has_result == 0) {
		return 0;
	}

	inpacket_len = dns_encode(inpacket_buff, DNS_IN_PACKSIZE, cname_packet);
	if (inpacket_len <= 0) {
		return -1;
	}

	if (context->qtype != DNS_T_A && context->qtype != DNS_T_AAAA) {
		return -1;
	}

	cache_packet = dns_cache_new_data_packet(inpacket_buff, inpacket_len);
	if (cache_packet == NULL) {
		goto errout;
	}

	ttl = _dns_server_get_conf_ttl(request, request->ip_ttl);
	speed = request->ping_time;

	tlog(TLOG_DEBUG, "Cache CNAME: %s, qtype: %d, speed: %d", request->cname, request->qtype, speed);

	/* if doing prefetch, update cache only */
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->cname;
	cache_key.qtype = context->qtype;
	cache_key.query_flag = request->server_flags;

	if (request->prefetch) {
		if (dns_cache_replace(&cache_key, request->rcode, ttl, speed,
							  _dns_server_get_cache_timeout(request, &cache_key, ttl),
							  !(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED), cache_packet) != 0) {
			ret = 0;
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(&cache_key, request->rcode, ttl, speed, _dns_server_get_cache_timeout(request, NULL, ttl),
							 cache_packet) != 0) {
			ret = -1;
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_packet) {
		dns_cache_data_put((struct dns_cache_data *)cache_packet);
	}

	return ret;
}

static int _dns_cache_packet(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	int ret = -1;

	struct dns_cache_data *cache_packet = dns_cache_new_data_packet(context->inpacket, context->inpacket_len);
	if (cache_packet == NULL) {
		goto errout;
	}

	/* if doing prefetch, update cache only */
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = context->qtype;
	cache_key.query_flag = request->server_flags;

	if (request->prefetch) {
		/* no prefetch for mdns request */
		if (request->is_mdns_lookup) {
			ret = 0;
			goto errout;
		}

		if (dns_cache_replace(&cache_key, request->rcode, request->ip_ttl, -1,
							  _dns_server_get_cache_timeout(request, &cache_key, request->ip_ttl),
							  !(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED), cache_packet) != 0) {
			ret = 0;
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(&cache_key, request->rcode, request->ip_ttl, -1,
							 _dns_server_get_cache_timeout(request, NULL, request->ip_ttl), cache_packet) != 0) {
			ret = -1;
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_packet) {
		dns_cache_data_put((struct dns_cache_data *)cache_packet);
	}

	return ret;
}

static int _dns_result_callback(struct dns_server_post_context *context)
{
	struct dns_result result;
	char ip[DNS_MAX_CNAME_LEN];
	unsigned int ping_time = -1;
	struct dns_request *request = context->request;

	if (request->result_callback == NULL) {
		return 0;
	}

	if (atomic_inc_return(&request->do_callback) != 1) {
		return 0;
	}

	ip[0] = 0;
	memset(&result, 0, sizeof(result));
	ping_time = request->ping_time;
	result.domain = request->domain;
	result.rtcode = request->rcode;
	result.addr_type = request->qtype;
	result.ip = ip;
	result.has_soa = request->has_soa | context->do_force_soa;
	result.ping_time = ping_time;
	result.ip_num = 0;

	if (request->has_ip != 0 && context->do_force_soa == 0) {
		for (int i = 0; i < context->ip_num && i < MAX_IP_NUM; i++) {
			result.ip_addr[i] = context->ip_addr[i];
			result.ip_num++;
		}

		if (request->qtype == DNS_T_A) {
			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", request->ip_addr[0], request->ip_addr[1], request->ip_addr[2],
					 request->ip_addr[3]);
		} else if (request->qtype == DNS_T_AAAA) {
			snprintf(ip, sizeof(ip), "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					 request->ip_addr[0], request->ip_addr[1], request->ip_addr[2], request->ip_addr[3],
					 request->ip_addr[4], request->ip_addr[5], request->ip_addr[6], request->ip_addr[7],
					 request->ip_addr[8], request->ip_addr[9], request->ip_addr[10], request->ip_addr[11],
					 request->ip_addr[12], request->ip_addr[13], request->ip_addr[14], request->ip_addr[15]);
		}
	}

	return request->result_callback(&result, request->user_ptr);
}

static int _dns_cache_specify_packet(struct dns_server_post_context *context)
{
	if (_dns_cache_is_specify_packet(context->qtype) != 0) {
		return 0;
	}

	return _dns_cache_packet(context);
}

static int _dns_cache_try_keep_old_cache(struct dns_request *request)
{
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = request->qtype;
	cache_key.query_flag = request->server_flags;
	return dns_cache_update_timer(&cache_key, DNS_SERVER_TMOUT_TTL);
}

static int _dns_cache_reply_packet(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	int speed = -1;
	if (context->do_cache == 0 || request->no_cache == 1) {
		return 0;
	}

	if (context->packet->head.rcode == DNS_RC_SERVFAIL || context->packet->head.rcode == DNS_RC_NXDOMAIN ||
		context->packet->head.rcode == DNS_RC_NOTIMP) {
		context->reply_ttl = DNS_SERVER_FAIL_TTL;
		/* Do not cache record if cannot connect to remote */
		if (request->remote_server_fail == 0 && context->packet->head.rcode == DNS_RC_SERVFAIL) {
			/* Try keep old cache if server fail */
			_dns_cache_try_keep_old_cache(request);
			return 0;
		}

		if (context->packet->head.rcode == DNS_RC_NOTIMP) {
			return 0;
		}

		return _dns_cache_packet(context);
	}

	if (context->qtype != DNS_T_AAAA && context->qtype != DNS_T_A && context->qtype != DNS_T_HTTPS) {
		return _dns_cache_specify_packet(context);
	}

	struct dns_cache_data *cache_packet = dns_cache_new_data_packet(context->inpacket, context->inpacket_len);
	if (cache_packet == NULL) {
		return -1;
	}

	speed = request->ping_time;
	if (context->do_force_soa) {
		speed = -1;
	}

	if (_dns_server_request_update_cache(request, speed, context->qtype, cache_packet, context->cache_ttl) != 0) {
		tlog(TLOG_WARN, "update packet cache failed.");
	}

	_dns_cache_cname_packet(context);

	return 0;
}

static void _dns_server_add_ipset_nftset(struct dns_request *request, struct dns_ipset_rule *ipset_rule,
										 struct dns_nftset_rule *nftset_rule, const unsigned char addr[], int addr_len,
										 int ipset_timeout_value, int nftset_timeout_value)
{
	if (ipset_rule != NULL) {
		/* add IPV4 to ipset */
		if (addr_len == DNS_RR_A_LEN) {
			tlog(TLOG_DEBUG, "IPSET-MATCH: domain: %s, ipset: %s, IP: %d.%d.%d.%d", request->domain,
				 ipset_rule->ipsetname, addr[0], addr[1], addr[2], addr[3]);
			ipset_add(ipset_rule->ipsetname, addr, DNS_RR_A_LEN, ipset_timeout_value);
		} else if (addr_len == DNS_RR_AAAA_LEN) {
			tlog(TLOG_DEBUG,
				 "IPSET-MATCH: domain: %s, ipset: %s, IP: "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, ipset_rule->ipsetname, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6],
				 addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
			ipset_add(ipset_rule->ipsetname, addr, DNS_RR_AAAA_LEN, ipset_timeout_value);
		}
	}

	if (nftset_rule != NULL) {
		/* add IPV4 to ipset */
		if (addr_len == DNS_RR_A_LEN) {
			tlog(TLOG_DEBUG, "NFTSET-MATCH: domain: %s, nftset: %s %s %s, IP: %d.%d.%d.%d", request->domain,
				 nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr[0], addr[1], addr[2],
				 addr[3]);
			nftset_add(nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr, DNS_RR_A_LEN,
					   nftset_timeout_value);
		} else if (addr_len == DNS_RR_AAAA_LEN) {
			tlog(TLOG_DEBUG,
				 "NFTSET-MATCH: domain: %s, nftset: %s %s %s, IP: "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr[0],
				 addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11],
				 addr[12], addr[13], addr[14], addr[15]);
			nftset_add(nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr,
					   DNS_RR_AAAA_LEN, nftset_timeout_value);
		}
	}
}

static int _dns_server_setup_ipset_nftset_packet(struct dns_server_post_context *context)
{
	int ttl = 0;
	struct dns_request *request = context->request;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	int timeout_value = 0;
	int ipset_timeout_value = 0;
	int nftset_timeout_value = 0;
	int i = 0;
	int j = 0;
	struct dns_conf_group *conf;
	struct dns_rrs *rrs = NULL;
	struct dns_ipset_rule *rule = NULL;
	struct dns_ipset_rule *ipset_rule = NULL;
	struct dns_ipset_rule *ipset_rule_v4 = NULL;
	struct dns_ipset_rule *ipset_rule_v6 = NULL;
	struct dns_nftset_rule *nftset_ip = NULL;
	struct dns_nftset_rule *nftset_ip6 = NULL;
	struct dns_rule_flags *rule_flags = NULL;
	int check_no_speed_rule = 0;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_IPSET) == 0) {
		return 0;
	}

	if (context->do_ipset == 0) {
		return 0;
	}

	if (context->ip_num <= 0) {
		return 0;
	}

	if (request->ping_time < 0 && request->has_ip > 0 && request->passthrough == 0) {
		check_no_speed_rule = 1;
	}

	conf = request->conf;

	/* check ipset rule */
	rule_flags = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IGN) == 0) {
		ipset_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_IPSET);
		if (ipset_rule == NULL) {
			ipset_rule = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_IPSET);
		}

		if (ipset_rule == NULL && check_no_speed_rule && conf->ipset_nftset.ipset_no_speed.inet_enable) {
			ipset_rule_v4 = &conf->ipset_nftset.ipset_no_speed.inet;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV4_IGN) == 0) {
		ipset_rule_v4 = _dns_server_get_dns_rule(request, DOMAIN_RULE_IPSET_IPV4);
		if (ipset_rule_v4 == NULL) {
			ipset_rule_v4 = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_IPSET_IPV4);
		}

		if (ipset_rule_v4 == NULL && check_no_speed_rule && conf->ipset_nftset.ipset_no_speed.ipv4_enable) {
			ipset_rule_v4 = &conf->ipset_nftset.ipset_no_speed.ipv4;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV6_IGN) == 0) {
		ipset_rule_v6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_IPSET_IPV6);
		if (ipset_rule_v6 == NULL) {
			ipset_rule_v6 = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_IPSET_IPV6);
		}

		if (ipset_rule_v6 == NULL && check_no_speed_rule && conf->ipset_nftset.ipset_no_speed.ipv6_enable) {
			ipset_rule_v6 = &conf->ipset_nftset.ipset_no_speed.ipv6;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_NFTSET_IP_IGN) == 0) {
		nftset_ip = _dns_server_get_dns_rule(request, DOMAIN_RULE_NFTSET_IP);
		if (nftset_ip == NULL) {
			nftset_ip = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_NFTSET_IP);
		}

		if (nftset_ip == NULL && check_no_speed_rule && conf->ipset_nftset.nftset_no_speed.ip_enable) {
			nftset_ip = &conf->ipset_nftset.nftset_no_speed.ip;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_NFTSET_IP6_IGN) == 0) {
		nftset_ip6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_NFTSET_IP6);

		if (nftset_ip6 == NULL) {
			nftset_ip6 = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_NFTSET_IP6);
		}

		if (nftset_ip6 == NULL && check_no_speed_rule && conf->ipset_nftset.nftset_no_speed.ip6_enable) {
			nftset_ip6 = &conf->ipset_nftset.nftset_no_speed.ip6;
		}
	}

	if (!(ipset_rule || ipset_rule_v4 || ipset_rule_v6 || nftset_ip || nftset_ip6)) {
		return 0;
	}

	timeout_value = request->ip_ttl * 3;
	if (timeout_value == 0) {
		timeout_value = _dns_server_get_conf_ttl(request, 0) * 3;
	}

	if (conf->ipset_nftset.ipset_timeout_enable) {
		ipset_timeout_value = timeout_value;
	}

	if (conf->ipset_nftset.nftset_timeout_enable) {
		nftset_timeout_value = timeout_value;
	}

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(context->packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(context->packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				if (context->qtype != DNS_T_A) {
					break;
				}
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
				_dns_server_add_ipset_nftset(request, rule, nftset_ip, addr, DNS_RR_A_LEN, ipset_timeout_value,
											 nftset_timeout_value);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				if (context->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				rule = ipset_rule_v6 ? ipset_rule_v6 : ipset_rule;
				_dns_server_add_ipset_nftset(request, rule, nftset_ip6, addr, DNS_RR_AAAA_LEN, ipset_timeout_value,
											 nftset_timeout_value);
			} break;
			case DNS_T_HTTPS: {
				char target[DNS_MAX_CNAME_LEN] = {0};
				struct dns_https_param *p = NULL;
				int priority = 0;

				int ret = dns_get_HTTPS_svcparm_start(rrs, &p, name, DNS_MAX_CNAME_LEN, &ttl, &priority, target,
													  DNS_MAX_CNAME_LEN);
				if (ret != 0) {
					tlog(TLOG_WARN, "get HTTPS svcparm failed");
					return -1;
				}

				for (; p; p = dns_get_HTTPS_svcparm_next(rrs, p)) {
					switch (p->key) {
					case DNS_HTTPS_T_IPV4HINT: {
						unsigned char *addr;
						for (int k = 0; k < p->len / 4; k++) {
							addr = p->value + k * 4;
							rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
							_dns_server_add_ipset_nftset(request, rule, nftset_ip, addr, DNS_RR_A_LEN,
														 ipset_timeout_value, nftset_timeout_value);
						}
					} break;
					case DNS_HTTPS_T_IPV6HINT: {
						unsigned char *addr;
						for (int k = 0; k < p->len / 16; k++) {
							addr = p->value + k * 16;
							rule = ipset_rule_v6 ? ipset_rule_v6 : ipset_rule;
							_dns_server_add_ipset_nftset(request, rule, nftset_ip6, addr, DNS_RR_AAAA_LEN,
														 ipset_timeout_value, nftset_timeout_value);
						}
					} break;
					default:
						break;
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

static int _dns_result_child_post(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_request *parent_request = request->parent_request;
	DNS_CHILD_POST_RESULT child_ret = DNS_CHILD_POST_FAIL;

	/* not a child request */
	if (parent_request == NULL) {
		return 0;
	}

	if (request->child_callback) {
		int is_first_resp = context->no_release_parent;
		child_ret = request->child_callback(parent_request, request, is_first_resp);
	}

	if (context->do_reply == 1 && child_ret == DNS_CHILD_POST_SUCCESS) {
		struct dns_server_post_context parent_context;
		_dns_server_post_context_init(&parent_context, parent_request);
		parent_context.do_cache = context->do_cache;
		parent_context.do_ipset = context->do_ipset;
		parent_context.do_force_soa = context->do_force_soa;
		parent_context.do_audit = context->do_audit;
		parent_context.do_reply = context->do_reply;
		parent_context.reply_ttl = context->reply_ttl;
		parent_context.cache_ttl = context->cache_ttl;
		parent_context.skip_notify_count = context->skip_notify_count;
		parent_context.select_all_best_ip = 1;
		parent_context.no_release_parent = context->no_release_parent;

		_dns_request_post(&parent_context);
		_dns_server_reply_all_pending_list(parent_request, &parent_context);
	}

	if (context->no_release_parent == 0) {
		tlog(TLOG_DEBUG, "query %s with child %s done", parent_request->domain, request->domain);
		request->parent_request = NULL;
		parent_request->request_wait--;
		_dns_server_request_release(parent_request);
	}

	if (child_ret == DNS_CHILD_POST_FAIL) {
		return -1;
	}

	return 0;
}

static int _dns_request_update_id_ttl(struct dns_server_post_context *context)
{
	int ttl = context->reply_ttl;
	struct dns_request *request = context->request;

	if (request->conf->dns_rr_ttl_reply_max > 0) {
		if (request->ip_ttl > request->conf->dns_rr_ttl_reply_max && ttl == 0) {
			ttl = request->ip_ttl;
		}

		if (ttl > request->conf->dns_rr_ttl_reply_max) {
			ttl = request->conf->dns_rr_ttl_reply_max;
		}

		if (ttl == 0) {
			ttl = request->conf->dns_rr_ttl_reply_max;
		}
	}

	if (ttl == 0) {
		ttl = request->ip_ttl;
		if (ttl == 0) {
			ttl = _dns_server_get_conf_ttl(request, ttl);
		}
	}

	struct dns_update_param param;
	param.id = request->id;
	param.cname_ttl = ttl;
	param.ip_ttl = ttl;
	if (dns_packet_update(context->inpacket, context->inpacket_len, &param) != 0) {
		tlog(TLOG_DEBUG, "update packet info failed.");
	}

	return 0;
}

static int _dns_request_post(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	char clientip[DNS_MAX_CNAME_LEN] = {0};
	int ret = 0;

	tlog(TLOG_DEBUG, "reply %s qtype: %d, rcode: %d, reply: %d", request->domain, request->qtype,
		 context->packet->head.rcode, context->do_reply);

	/* init a new DNS packet */
	ret = _dns_setup_dns_packet(context);
	if (ret != 0) {
		tlog(TLOG_ERROR, "setup dns packet failed.");
		return -1;
	}

	ret = _dns_setup_dns_raw_packet(context);
	if (ret != 0) {
		tlog(TLOG_ERROR, "set dns raw packet failed.");
		return -1;
	}

	/* cache reply packet */
	ret = _dns_cache_reply_packet(context);
	if (ret != 0) {
		tlog(TLOG_WARN, "cache packet for %s failed.", request->domain);
	}

	/* setup ipset */
	_dns_server_setup_ipset_nftset_packet(context);

	/* reply child request */
	_dns_result_child_post(context);

	if (context->do_reply == 0) {
		return 0;
	}

	if (context->skip_notify_count == 0) {
		if (atomic_inc_return(&request->notified) != 1) {
			tlog(TLOG_DEBUG, "skip reply %s %d", request->domain, request->qtype);
			return 0;
		}
	}

	/* log audit log */
	_dns_server_audit_log(context);

	/* reply API callback */
	_dns_result_callback(context);

	if (request->conn == NULL) {
		return 0;
	}

	ret = _dns_request_update_id_ttl(context);
	if (ret != 0) {
		tlog(TLOG_ERROR, "update packet ttl failed.");
		return -1;
	}

	tlog(TLOG_INFO, "result: %s, client: %s, qtype: %d, id: %d, group: %s, time: %lums", request->domain,
		 get_host_by_addr(clientip, sizeof(clientip), (struct sockaddr *)&request->addr), request->qtype, request->id,
		 request->dns_group_name[0] != '\0' ? request->dns_group_name : DNS_SERVER_GROUP_DEFAULT,
		 get_tick_count() - request->send_tick);

	ret = _dns_reply_inpacket(request, context->inpacket, context->inpacket_len);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "reply raw packet to client failed.");
		return -1;
	}

	return 0;
}

static int _dns_server_reply_SOA(int rcode, struct dns_request *request)
{
	/* return SOA record */
	request->rcode = rcode;
	if (request->ip_ttl <= 0) {
		request->ip_ttl = DNS_SERVER_SOA_TTL;
	}

	_dns_server_setup_soa(request);

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_audit = 1;
	context.do_reply = 1;
	context.do_force_soa = 1;
	_dns_request_post(&context);

	return 0;
}

static int _dns_server_reply_all_pending_list(struct dns_request *request, struct dns_server_post_context *context)
{
	struct dns_request_pending_list *pending_list = NULL;
	struct dns_request *req = NULL;
	struct dns_request *tmp = NULL;
	int ret = 0;

	if (request->request_pending_list == NULL) {
		return 0;
	}

	pthread_mutex_lock(&server.request_pending_lock);
	pending_list = request->request_pending_list;
	request->request_pending_list = NULL;
	hlist_del_init(&pending_list->node);
	pthread_mutex_unlock(&server.request_pending_lock);

	pthread_mutex_lock(&pending_list->request_list_lock);
	list_del_init(&request->pending_list);
	list_for_each_entry_safe(req, tmp, &(pending_list->request_list), pending_list)
	{
		struct dns_server_post_context context_pending;
		_dns_server_post_context_init_from(&context_pending, req, context->packet, context->inpacket,
										   context->inpacket_len);
		req->dualstack_selection = request->dualstack_selection;
		req->dualstack_selection_query = request->dualstack_selection_query;
		req->dualstack_selection_force_soa = request->dualstack_selection_force_soa;
		req->dualstack_selection_has_ip = request->dualstack_selection_has_ip;
		req->dualstack_selection_ping_time = request->dualstack_selection_ping_time;
		req->ping_time = request->ping_time;
		_dns_server_get_answer(&context_pending);

		context_pending.do_cache = 0;
		context_pending.do_audit = context->do_audit;
		context_pending.do_reply = context->do_reply;
		context_pending.do_force_soa = context->do_force_soa;
		context_pending.do_ipset = 0;
		context_pending.reply_ttl = request->ip_ttl;
		context_pending.no_release_parent = 0;
		_dns_server_reply_passthrough(&context_pending);

		req->request_pending_list = NULL;
		list_del_init(&req->pending_list);
		_dns_server_request_release_complete(req, 0);
	}
	pthread_mutex_unlock(&pending_list->request_list_lock);

	free(pending_list);

	return ret;
}

static void _dns_server_need_append_mdns_local_cname(struct dns_request *request)
{
	if (request->is_mdns_lookup == 0) {
		return;
	}

	if (request->has_cname != 0) {
		return;
	}

	if (request->domain[0] == '\0') {
		return;
	}

	if (strstr(request->domain, ".") != NULL) {
		return;
	}

	request->has_cname = 1;
	snprintf(request->cname, sizeof(request->cname), "%.*s.%s",
			 (int)(sizeof(request->cname) - sizeof(DNS_SERVER_GROUP_LOCAL) - 1), request->domain,
			 DNS_SERVER_GROUP_LOCAL);
	return;
}

static void _dns_server_check_complete_dualstack(struct dns_request *request, struct dns_request *dualstack_request)
{
	if (dualstack_request == NULL || request == NULL) {
		return;
	}

	if (dualstack_request->qtype == DNS_T_A && request->conf->dns_dualstack_ip_allow_force_AAAA == 0) {
		return;
	}

	if (dualstack_request->ping_time > 0) {
		return;
	}

	if (dualstack_request->dualstack_selection_query == 1) {
		return;
	}

	if (request->ping_time <= (request->conf->dns_dualstack_ip_selection_threshold * 10)) {
		return;
	}

	dualstack_request->dualstack_selection_has_ip = request->has_ip;
	dualstack_request->dualstack_selection_ping_time = request->ping_time;
	dualstack_request->dualstack_selection_force_soa = 1;
	_dns_server_request_complete(dualstack_request);
}

static int _dns_server_force_dualstack(struct dns_request *request)
{
	/* for dualstack request as first pending request, check if need to choose another request*/
	if (request->dualstack_request) {
		struct dns_request *dualstack_request = request->dualstack_request;
		request->dualstack_selection_has_ip = dualstack_request->has_ip;
		request->dualstack_selection_ping_time = dualstack_request->ping_time;
		request->dualstack_selection = 1;
		/* if another request still waiting for ping, force complete another request */
		_dns_server_check_complete_dualstack(request, dualstack_request);
	}

	if (request->dualstack_selection_ping_time < 0 || request->dualstack_selection == 0) {
		return -1;
	}

	if (request->has_soa || request->rcode != DNS_RC_NOERROR) {
		return -1;
	}

	if (request->dualstack_selection_has_ip == 0) {
		return -1;
	}

	if (request->ping_time > 0) {
		if (request->dualstack_selection_ping_time + (request->conf->dns_dualstack_ip_selection_threshold * 10) >
			request->ping_time) {
			return -1;
		}
	}

	if (request->qtype == DNS_T_A && request->conf->dns_dualstack_ip_allow_force_AAAA == 0) {
		return -1;
	}

	/* if ipv4 is fasting than ipv6, add ipv4 to cache, and return SOA for AAAA request */
	tlog(TLOG_INFO, "result: %s, qtype: %d, force %s preferred, id: %d, time1: %d, time2: %d", request->domain,
		 request->qtype, request->qtype == DNS_T_AAAA ? "IPv4" : "IPv6", request->id, request->ping_time,
		 request->dualstack_selection_ping_time);
	request->dualstack_selection_force_soa = 1;

	return 0;
}

static int _dns_server_request_complete_with_all_IPs(struct dns_request *request, int with_all_ips)
{
	int ttl = 0;
	struct dns_server_post_context context;

	if (request->rcode == DNS_RC_SERVFAIL || request->rcode == DNS_RC_NXDOMAIN) {
		ttl = DNS_SERVER_FAIL_TTL;
	}

	if (request->ip_ttl == 0) {
		request->ip_ttl = ttl;
	}

	if (request->prefetch == 1) {
		return 0;
	}

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	if (request->has_ip != 0 && request->passthrough == 0) {
		request->has_soa = 0;
		if (request->has_ping_result == 0 && request->ip_ttl > DNS_SERVER_TMOUT_TTL) {
			request->ip_ttl = DNS_SERVER_TMOUT_TTL;
		}
		ttl = request->ip_ttl;
	}

	if (_dns_server_force_dualstack(request) == 0) {
		goto out;
	}

	_dns_server_need_append_mdns_local_cname(request);

	if (request->has_soa) {
		tlog(TLOG_INFO, "result: %s, qtype: %d, SOA", request->domain, request->qtype);
	} else {
		if (request->qtype == DNS_T_A) {
			tlog(TLOG_INFO, "result: %s, qtype: %d, rtt: %.1f ms, %d.%d.%d.%d", request->domain, request->qtype,
				 ((float)request->ping_time) / 10, request->ip_addr[0], request->ip_addr[1], request->ip_addr[2],
				 request->ip_addr[3]);
		} else if (request->qtype == DNS_T_AAAA) {
			tlog(TLOG_INFO,
				 "result: %s, qtype: %d, rtt: %.1f ms, "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, request->qtype, ((float)request->ping_time) / 10, request->ip_addr[0],
				 request->ip_addr[1], request->ip_addr[2], request->ip_addr[3], request->ip_addr[4],
				 request->ip_addr[5], request->ip_addr[6], request->ip_addr[7], request->ip_addr[8],
				 request->ip_addr[9], request->ip_addr[10], request->ip_addr[11], request->ip_addr[12],
				 request->ip_addr[13], request->ip_addr[14], request->ip_addr[15]);
		}

		if (request->rcode == DNS_RC_SERVFAIL && request->has_ip) {
			request->rcode = DNS_RC_NOERROR;
		}
	}

out:
	_dns_server_post_context_init(&context, request);
	context.do_cache = 1;
	context.do_ipset = 1;
	context.do_force_soa = request->dualstack_selection_force_soa | request->force_soa;
	context.do_audit = 1;
	context.do_reply = 1;
	context.reply_ttl = _dns_server_get_reply_ttl(request, ttl);
	context.skip_notify_count = 1;
	context.select_all_best_ip = with_all_ips;
	context.no_release_parent = 1;

	_dns_request_post(&context);
	return _dns_server_reply_all_pending_list(request, &context);
}

static int _dns_server_request_complete(struct dns_request *request)
{
	return _dns_server_request_complete_with_all_IPs(request, 0);
}

static int _dns_ip_address_check_add(struct dns_request *request, char *cname, unsigned char *addr,
									 dns_type_t addr_type, int ping_time, struct dns_ip_address **out_addr_map)
{
	uint32_t key = 0;
	struct dns_ip_address *addr_map = NULL;
	int addr_len = 0;

	if (ping_time == 0) {
		ping_time = -1;
	}

	if (addr_type == DNS_T_A) {
		addr_len = DNS_RR_A_LEN;
	} else if (addr_type == DNS_T_AAAA) {
		addr_len = DNS_RR_AAAA_LEN;
	} else {
		return -1;
	}

	/* store the ip address and the number of hits */
	key = jhash(addr, addr_len, 0);
	key = jhash(&addr_type, sizeof(addr_type), key);
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_possible(request->ip_map, addr_map, node, key)
	{
		if (addr_map->addr_type != addr_type) {
			continue;
		}

		if (memcmp(addr_map->ip_addr, addr, addr_len) != 0) {
			continue;
		}

		addr_map->hitnum++;
		addr_map->recv_tick = get_tick_count();
		pthread_mutex_unlock(&request->ip_map_lock);
		return -1;
	}

	atomic_inc(&request->ip_map_num);
	addr_map = malloc(sizeof(*addr_map));
	if (addr_map == NULL) {
		pthread_mutex_unlock(&request->ip_map_lock);
		tlog(TLOG_ERROR, "malloc addr map failed");
		return -1;
	}
	memset(addr_map, 0, sizeof(*addr_map));

	addr_map->addr_type = addr_type;
	addr_map->hitnum = 1;
	addr_map->recv_tick = get_tick_count();
	addr_map->ping_time = ping_time;
	memcpy(addr_map->ip_addr, addr, addr_len);
	if (request->conf->dns_force_no_cname == 0) {
		safe_strncpy(addr_map->cname, cname, DNS_MAX_CNAME_LEN);
	}

	hash_add(request->ip_map, &addr_map->node, key);
	pthread_mutex_unlock(&request->ip_map_lock);

	if (out_addr_map != NULL) {
		*out_addr_map = addr_map;
	}

	return 0;
}

static void _dns_server_request_remove_all(void)
{
	struct dns_request *request = NULL;
	struct dns_request *tmp = NULL;
	LIST_HEAD(remove_list);

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		list_add_tail(&request->check_list, &remove_list);
		_dns_server_request_get(request);
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &remove_list, check_list)
	{
		_dns_server_request_complete(request);
		_dns_server_request_release(request);
	}
}

static void _dns_server_select_possible_ipaddress(struct dns_request *request)
{
	int maxhit = 0;
	unsigned long bucket = 0;
	unsigned long max_recv_tick = 0;
	struct dns_ip_address *addr_map = NULL;
	struct dns_ip_address *maxhit_addr_map = NULL;
	struct dns_ip_address *last_recv_addr_map = NULL;
	struct dns_ip_address *selected_addr_map = NULL;
	struct hlist_node *tmp = NULL;

	if (atomic_read(&request->notified) > 0) {
		return;
	}

	if (request->no_select_possible_ip != 0) {
		return;
	}

	if (request->ping_time > 0) {
		return;
	}

	/* Return the most likely correct IP address */
	/* Returns the IP with the most hits, or the last returned record is considered to be the most likely
	 * correct. */
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
		memcpy(request->ip_addr, selected_addr_map->ip_addr, DNS_RR_A_LEN);
		request->ip_ttl = request->conf->dns_rr_ttl_min > 0 ? request->conf->dns_rr_ttl_min : DNS_SERVER_TMOUT_TTL;
		tlog(TLOG_DEBUG, "possible result: %s, rcode: %d,  hitnum: %d, %d.%d.%d.%d", request->domain, request->rcode,
			 selected_addr_map->hitnum, request->ip_addr[0], request->ip_addr[1], request->ip_addr[2],
			 request->ip_addr[3]);
	} break;
	case DNS_T_AAAA: {
		memcpy(request->ip_addr, selected_addr_map->ip_addr, DNS_RR_AAAA_LEN);
		request->ip_ttl = request->conf->dns_rr_ttl_min > 0 ? request->conf->dns_rr_ttl_min : DNS_SERVER_TMOUT_TTL;
		tlog(TLOG_DEBUG,
			 "possible result: %s, rcode: %d,  hitnum: %d, "
			 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
			 request->domain, request->rcode, selected_addr_map->hitnum, request->ip_addr[0], request->ip_addr[1],
			 request->ip_addr[2], request->ip_addr[3], request->ip_addr[4], request->ip_addr[5], request->ip_addr[6],
			 request->ip_addr[7], request->ip_addr[8], request->ip_addr[9], request->ip_addr[10], request->ip_addr[11],
			 request->ip_addr[12], request->ip_addr[13], request->ip_addr[14], request->ip_addr[15]);
	} break;
	default:
		break;
	}
}

static void _dns_server_delete_request(struct dns_request *request)
{
	if (atomic_read(&request->notified) == 0) {
		_dns_server_request_complete(request);
	}

	if (request->conn) {
		_dns_server_conn_release(request->conn);
	}
	pthread_mutex_destroy(&request->ip_map_lock);
	if (request->https_svcb) {
		free(request->https_svcb);
	}
	memset(request, 0, sizeof(*request));
	free(request);
	atomic_dec(&server.request_num);
}

static void _dns_server_complete_with_multi_ipaddress(struct dns_request *request)
{
	struct dns_server_post_context context;
	int do_reply = 0;

	if (atomic_read(&request->ip_map_num) > 0) {
		request->has_soa = 0;
	}

	if (atomic_inc_return(&request->notified) == 1) {
		do_reply = 1;
		_dns_server_force_dualstack(request);
	}

	if (request->passthrough && do_reply == 0) {
		return;
	}

	_dns_server_need_append_mdns_local_cname(request);

	_dns_server_post_context_init(&context, request);
	context.do_cache = 1;
	context.do_ipset = 1;
	context.do_reply = do_reply;
	context.do_log_result = 1;
	context.select_all_best_ip = 1;
	context.skip_notify_count = 1;
	context.do_force_soa = request->dualstack_selection_force_soa | request->force_soa;
	_dns_request_post(&context);
	_dns_server_reply_all_pending_list(request, &context);
}

static void _dns_server_request_release_complete(struct dns_request *request, int do_complete)
{
	struct dns_ip_address *addr_map = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long bucket = 0;

	pthread_mutex_lock(&server.request_list_lock);
	int refcnt = atomic_dec_return(&request->refcnt);
	if (refcnt) {
		pthread_mutex_unlock(&server.request_list_lock);
		if (refcnt < 0) {
			BUG("BUG: refcnt is %d, domain %s, qtype %d", refcnt, request->domain, request->qtype);
		}
		return;
	}

	list_del_init(&request->list);
	list_del_init(&request->check_list);
	pthread_mutex_unlock(&server.request_list_lock);

	pthread_mutex_lock(&server.request_pending_lock);
	list_del_init(&request->pending_list);
	pthread_mutex_unlock(&server.request_pending_lock);

	if (do_complete) {
		/* Select max hit ip address, and return to client */
		_dns_server_select_possible_ipaddress(request);
		_dns_server_complete_with_multi_ipaddress(request);
	}

	if (request->parent_request != NULL) {
		_dns_server_request_release(request->parent_request);
		request->parent_request = NULL;
	}

	atomic_inc(&request->refcnt);
	smartdns_plugin_func_server_complete_request(request);
	if (atomic_dec_return(&request->refcnt) > 0) {
		/* plugin may hold request. */
		return;
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
		BUG("BUG: request ref is invalid, %s", request->domain);
	}
}

struct sockaddr *dns_server_request_get_remote_addr(struct dns_request *request)
{
	return &request->addr;
}

struct sockaddr *dns_server_request_get_local_addr(struct dns_request *request)
{
	return (struct sockaddr *)&request->localaddr;
}

const char *dns_server_request_get_group_name(struct dns_request *request)
{
	return request->dns_group_name;
}

const char *dns_server_request_get_domain(struct dns_request *request)
{
	return request->domain;
}

int dns_server_request_get_qtype(struct dns_request *request)
{
	return request->qtype;
}

int dns_server_request_get_qclass(struct dns_request *request)
{
	return request->qclass;
}

int dns_server_request_get_id(struct dns_request *request)
{
	return request->id;
}

int dns_server_request_get_rcode(struct dns_request *request)
{
	return request->rcode;
}

void dns_server_request_get(struct dns_request *request)
{
	_dns_server_request_get(request);
}

void dns_server_request_put(struct dns_request *request)
{
	_dns_server_request_release(request);
}

void dns_server_request_set_private(struct dns_request *request, void *private_data)
{
	request->private_data = private_data;
}

void *dns_server_request_get_private(struct dns_request *request)
{
	return request->private_data;
}

static int _dns_server_set_to_pending_list(struct dns_request *request)
{
	struct dns_request_pending_list *pending_list = NULL;
	struct dns_request_pending_list *pending_list_tmp = NULL;
	uint32_t key = 0;
	int ret = -1;
	if (request->qtype != DNS_T_A && request->qtype != DNS_T_AAAA) {
		return ret;
	}

	key = hash_string(request->domain);
	key = hash_string_initval(request->dns_group_name, key);
	key = jhash(&(request->qtype), sizeof(request->qtype), key);
	key = jhash(&(request->server_flags), sizeof(request->server_flags), key);
	pthread_mutex_lock(&server.request_pending_lock);
	hash_for_each_possible(server.request_pending, pending_list_tmp, node, key)
	{
		if (request->qtype != pending_list_tmp->qtype) {
			continue;
		}

		if (request->server_flags != pending_list_tmp->server_flags) {
			continue;
		}

		if (strcmp(request->dns_group_name, pending_list_tmp->dns_group_name) != 0) {
			continue;
		}

		if (strncmp(request->domain, pending_list_tmp->domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		pending_list = pending_list_tmp;
		break;
	}

	if (pending_list == NULL) {
		pending_list = malloc(sizeof(*pending_list));
		if (pending_list == NULL) {
			ret = -1;
			goto out;
		}

		memset(pending_list, 0, sizeof(*pending_list));
		pthread_mutex_init(&pending_list->request_list_lock, NULL);
		INIT_LIST_HEAD(&pending_list->request_list);
		INIT_HLIST_NODE(&pending_list->node);
		pending_list->qtype = request->qtype;
		pending_list->server_flags = request->server_flags;
		safe_strncpy(pending_list->domain, request->domain, DNS_MAX_CNAME_LEN);
		safe_strncpy(pending_list->dns_group_name, request->dns_group_name, DNS_GROUP_NAME_LEN);
		hash_add(server.request_pending, &pending_list->node, key);
		request->request_pending_list = pending_list;
	} else {
		ret = 0;
	}

	if (ret == 0) {
		_dns_server_request_get(request);
	}
	list_add_tail(&request->pending_list, &pending_list->request_list);
out:
	pthread_mutex_unlock(&server.request_pending_lock);
	return ret;
}

static struct dns_request *_dns_server_new_request(void)
{
	struct dns_request *request = NULL;

	request = malloc(sizeof(*request));
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc request failed.\n");
		goto errout;
	}

	memset(request, 0, sizeof(*request));
	pthread_mutex_init(&request->ip_map_lock, NULL);
	atomic_set(&request->adblock, 0);
	atomic_set(&request->soa_num, 0);
	atomic_set(&request->ip_map_num, 0);
	atomic_set(&request->refcnt, 0);
	atomic_set(&request->notified, 0);
	atomic_set(&request->do_callback, 0);
	request->ping_time = -1;
	request->prefetch = 0;
	request->dualstack_selection = 0;
	request->dualstack_selection_ping_time = -1;
	request->rcode = DNS_RC_SERVFAIL;
	request->conn = NULL;
	request->qclass = DNS_C_IN;
	request->result_callback = NULL;
	request->conf = dns_server_get_default_rule_group();
	request->check_order_list = &dns_conf_default_check_orders;
	request->response_mode = dns_conf_default_response_mode;
	INIT_LIST_HEAD(&request->list);
	INIT_LIST_HEAD(&request->pending_list);
	INIT_LIST_HEAD(&request->check_list);
	hash_init(request->ip_map);
	_dns_server_request_get(request);
	atomic_add(1, &server.request_num);

	return request;
errout:
	return NULL;
}

static void _dns_server_ping_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
									struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
									int error, void *userptr)
{
	struct dns_request *request = userptr;
	int may_complete = 0;
	int threshold = 100;
	struct dns_ip_address *addr_map = NULL;
	int last_rtt = request->ping_time;

	if (request == NULL) {
		return;
	}

	if (result == PING_RESULT_END) {
		_dns_server_request_release(request);
		fast_ping_stop(ping_host);
		return;
	} else if (result == PING_RESULT_TIMEOUT) {
		tlog(TLOG_DEBUG, "ping %s timeout", host);
		goto out;
		return;
	} else if (result == PING_RESULT_ERROR) {
		if (addr->sa_family != AF_INET6) {
			return;
		}

		if (is_ipv6_ready) {
			if (error == EADDRNOTAVAIL || errno == EACCES) {
				is_ipv6_ready = 0;
				tlog(TLOG_ERROR, "IPV6 is not ready, disable all ipv6 feature, recheck after %ds",
					 IPV6_READY_CHECK_TIME);
			}
		}
		return;
	}

	int rtt = tv->tv_sec * 10000 + tv->tv_usec / 100;
	if (rtt == 0) {
		rtt = 1;
	}

	if (result == PING_RESULT_RESPONSE) {
		tlog(TLOG_DEBUG, "from %s: seq=%d time=%d, lasttime=%d id=%d", host, seqno, rtt, last_rtt, request->id);
	} else {
		tlog(TLOG_DEBUG, "from %s: seq=%d timeout, id=%d", host, seqno, request->id);
	}

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		addr_map = _dns_ip_address_get(request, (unsigned char *)&addr_in->sin_addr.s_addr, DNS_T_A);
		if (addr_map) {
			addr_map->ping_time = rtt;
		}

		if (request->ping_time > rtt || request->ping_time == -1) {
			memcpy(request->ip_addr, &addr_in->sin_addr.s_addr, 4);
			request->ip_addr_type = DNS_T_A;
			request->ping_time = rtt;
			request->has_cname = 0;
			request->has_ip = 1;
			if (addr_map && addr_map->cname[0] != 0) {
				request->has_cname = 1;
				safe_strncpy(request->cname, addr_map->cname, DNS_MAX_CNAME_LEN);
			} else {
				request->has_cname = 0;
			}
		}

		if (request->qtype == DNS_T_AAAA && request->dualstack_selection) {
			if (request->ping_time < 0 && request->has_soa == 0) {
				return;
			}
		}

		if (request->qtype == DNS_T_A || request->qtype == DNS_T_HTTPS) {
			request->has_ping_result = 1;
		}
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			addr_map = _dns_ip_address_get(request, addr_in6->sin6_addr.s6_addr + 12, DNS_T_A);
			if (addr_map) {
				addr_map->ping_time = rtt;
			}

			if (request->ping_time > rtt || request->ping_time == -1) {
				request->ping_time = rtt;
				request->has_cname = 0;
				request->has_ip = 1;
				memcpy(request->ip_addr, addr_in6->sin6_addr.s6_addr + 12, 4);
				request->ip_addr_type = DNS_T_A;
				if (addr_map && addr_map->cname[0] != 0) {
					request->has_cname = 1;
					safe_strncpy(request->cname, addr_map->cname, DNS_MAX_CNAME_LEN);
				} else {
					request->has_cname = 0;
				}
			}

			if (request->qtype == DNS_T_A || request->qtype == DNS_T_HTTPS) {
				request->has_ping_result = 1;
			}
		} else {
			addr_map = _dns_ip_address_get(request, addr_in6->sin6_addr.s6_addr, DNS_T_AAAA);
			if (addr_map) {
				addr_map->ping_time = rtt;
			}

			if (request->ping_time > rtt || request->ping_time == -1) {
				request->ping_time = rtt;
				request->has_cname = 0;
				request->has_ip = 1;
				memcpy(request->ip_addr, addr_in6->sin6_addr.s6_addr, 16);
				request->ip_addr_type = DNS_T_AAAA;
				if (addr_map && addr_map->cname[0] != 0) {
					request->has_cname = 1;
					safe_strncpy(request->cname, addr_map->cname, DNS_MAX_CNAME_LEN);
				} else {
					request->has_cname = 0;
				}
			}

			if (request->qtype == DNS_T_AAAA || request->qtype == DNS_T_HTTPS) {
				request->has_ping_result = 1;
			}
		}
	} break;
	default:
		break;
	}

out:
	/* If the ping delay is less than the threshold, the result is returned */
	if (request->ping_time > 0) {
		if (request->ping_time < threshold) {
			may_complete = 1;
		} else if (request->ping_time < (int)(get_tick_count() - request->send_tick)) {
			may_complete = 1;
		}
	}

	/* Get first ping result */
	if (request->response_mode == DNS_RESPONSE_MODE_FIRST_PING_IP && last_rtt == -1 && request->ping_time > 0) {
		may_complete = 1;
	}

	if (may_complete && request->has_ping_result == 1) {
		_dns_server_request_complete(request);
	}
}

static int _dns_server_ping(struct dns_request *request, PING_TYPE type, char *ip, int timeout)
{
	if (fast_ping_start(type, ip, 1, 0, timeout, _dns_server_ping_result, request) == NULL) {
		return -1;
	}

	return 0;
}

static int _dns_server_check_speed(struct dns_request *request, char *ip)
{
	char tcp_ip[DNS_MAX_CNAME_LEN] = {0};
	int port = 80;
	int type = DOMAIN_CHECK_NONE;
	int order = request->check_order;
	int ping_timeout = DNS_PING_TIMEOUT;
	unsigned long now = get_tick_count();

	if (order >= DOMAIN_CHECK_NUM || request->check_order_list == NULL) {
		return -1;
	}

	if (request->passthrough) {
		return -1;
	}

	ping_timeout = ping_timeout - (now - request->send_tick);
	if (ping_timeout > DNS_PING_TIMEOUT) {
		ping_timeout = DNS_PING_TIMEOUT;
	} else if (ping_timeout < 200) {
		ping_timeout = 200;
	}

	port = request->check_order_list->orders[order].tcp_port;
	type = request->check_order_list->orders[order].type;
	switch (type) {
	case DOMAIN_CHECK_ICMP:
		tlog(TLOG_DEBUG, "ping %s with icmp, order: %d, timeout: %d", ip, order, ping_timeout);
		return _dns_server_ping(request, PING_TYPE_ICMP, ip, ping_timeout);
		break;
	case DOMAIN_CHECK_TCP:
		snprintf(tcp_ip, sizeof(tcp_ip), "%s:%d", ip, port);
		tlog(TLOG_DEBUG, "ping %s with tcp, order: %d, timeout: %d", tcp_ip, order, ping_timeout);
		return _dns_server_ping(request, PING_TYPE_TCP, tcp_ip, ping_timeout);
		break;
	default:
		break;
	}

	return -1;
}

static void _dns_server_neighbor_cache_free_item(struct neighbor_cache_item *item)
{
	hash_del(&item->node);
	list_del_init(&item->list);
	free(item);
	atomic_dec(&server.neighbor_cache.cache_num);
}

static void _dns_server_neighbor_cache_free_last_used_item(void)
{
	struct neighbor_cache_item *item = NULL;

	if (atomic_read(&server.neighbor_cache.cache_num) < DNS_SERVER_NEIGHBOR_CACHE_MAX_NUM) {
		return;
	}

	item = list_last_entry(&server.neighbor_cache.list, struct neighbor_cache_item, list);
	if (item == NULL) {
		return;
	}

	_dns_server_neighbor_cache_free_item(item);
}

static struct neighbor_cache_item *_dns_server_neighbor_cache_get_item(const uint8_t *net_addr, int net_addr_len)
{
	struct neighbor_cache_item *item = NULL;
	uint32_t key = 0;

	key = jhash(net_addr, net_addr_len, 0);
	hash_for_each_possible(server.neighbor_cache.cache, item, node, key)
	{
		if (item->ip_addr_len != net_addr_len) {
			continue;
		}

		if (memcmp(item->ip_addr, net_addr, net_addr_len) == 0) {
			break;
		}
	}

	return item;
}

static int _dns_server_neighbor_cache_add(const uint8_t *net_addr, int net_addr_len, const uint8_t *mac)
{
	struct neighbor_cache_item *item = NULL;
	uint32_t key = 0;

	if (net_addr_len > DNS_RR_AAAA_LEN) {
		return -1;
	}

	item = _dns_server_neighbor_cache_get_item(net_addr, net_addr_len);
	if (item == NULL) {
		item = malloc(sizeof(*item));
		memset(item, 0, sizeof(*item));
		if (item == NULL) {
			return -1;
		}
		INIT_LIST_HEAD(&item->list);
		INIT_HLIST_NODE(&item->node);
	}

	memcpy(item->ip_addr, net_addr, net_addr_len);
	item->ip_addr_len = net_addr_len;
	item->last_update_time = time(NULL);
	if (mac == NULL) {
		item->has_mac = 0;
	} else {
		memcpy(item->mac, mac, 6);
		item->has_mac = 1;
	}
	key = jhash(net_addr, net_addr_len, 0);
	hash_del(&item->node);
	hash_add(server.neighbor_cache.cache, &item->node, key);
	list_del_init(&item->list);
	list_add(&item->list, &server.neighbor_cache.list);
	atomic_inc(&server.neighbor_cache.cache_num);

	_dns_server_neighbor_cache_free_last_used_item();

	return 0;
}

static int _dns_server_neighbors_callback(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6], void *arg)
{
	struct neighbor_enum_args *args = arg;

	_dns_server_neighbor_cache_add(net_addr, net_addr_len, mac);

	if (net_addr_len != args->netaddr_len) {
		return 0;
	}

	if (memcmp(net_addr, args->netaddr, net_addr_len) != 0) {
		return 0;
	}

	args->group_mac = dns_server_rule_group_mac_get(mac);

	return 1;
}

static int _dns_server_neighbor_cache_is_valid(struct neighbor_cache_item *item)
{
	if (item == NULL) {
		return -1;
	}

	time_t now = time(NULL);

	if (item->last_update_time + DNS_SERVER_NEIGHBOR_CACHE_TIMEOUT < now) {
		return -1;
	}

	if (item->has_mac) {
		return 0;
	}

	if (item->last_update_time + DNS_SERVER_NEIGHBOR_CACHE_NOMAC_TIMEOUT < now) {
		return -1;
	}

	return 0;
}

static struct dns_client_rules *_dns_server_get_client_rules_by_mac(uint8_t *netaddr, int netaddr_len)
{
	struct client_roue_group_mac *group_mac = NULL;
	struct neighbor_cache_item *item = NULL;
	int family = AF_UNSPEC;
	int ret = 0;
	struct neighbor_enum_args args;

	if (dns_conf_client_rule.mac_num == 0) {
		return NULL;
	}

	item = _dns_server_neighbor_cache_get_item(netaddr, netaddr_len);
	if (_dns_server_neighbor_cache_is_valid(item) == 0) {
		if (item->has_mac == 0) {
			return NULL;
		}
		group_mac = dns_server_rule_group_mac_get(item->mac);
		if (group_mac != NULL) {
			return group_mac->rules;
		}
	}

	if (netaddr_len == 4) {
		family = AF_INET;
	} else if (netaddr_len == 16) {
		family = AF_INET6;
	}

	args.group_mac = group_mac;
	args.netaddr = netaddr;
	args.netaddr_len = netaddr_len;

	ret = netlink_get_neighbors(family, _dns_server_neighbors_callback, &args);
	if (ret < 0) {
		goto add_cache;
	}

	if (ret != 1 || args.group_mac == NULL) {
		goto add_cache;
	}

	return args.group_mac->rules;

add_cache:
	_dns_server_neighbor_cache_add(netaddr, netaddr_len, NULL);
	return NULL;
}

static struct dns_client_rules *_dns_server_get_client_rules(struct sockaddr_storage *addr, socklen_t addr_len)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	uint8_t *netaddr = NULL;
	struct dns_client_rules *client_rules = NULL;
	int netaddr_len = 0;

	switch (addr->ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		netaddr = (unsigned char *)&(addr_in->sin_addr.s_addr);
		netaddr_len = 4;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			netaddr = addr_in6->sin6_addr.s6_addr + 12;
			netaddr_len = 4;
		} else {
			netaddr = addr_in6->sin6_addr.s6_addr;
			netaddr_len = 16;
		}
	} break;
	default:
		return NULL;
		break;
	}

	client_rules = _dns_server_get_client_rules_by_mac(netaddr, netaddr_len);
	if (client_rules != NULL) {
		return client_rules;
	}

	if (prefix_from_blob(netaddr, netaddr_len, netaddr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	node = radix_search_best(dns_conf_client_rule.rule, &prefix);
	if (node == NULL) {
		return NULL;
	}

	client_rules = node->data;

	return client_rules;
}

static struct dns_ip_rules *_dns_server_ip_rule_get(struct dns_request *request, unsigned char *addr, int addr_len,
													dns_type_t addr_type)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct dns_ip_rules *rule = NULL;

	if (request->conf == NULL) {
		return NULL;
	}

	/* Match IP address rules */
	if (prefix_from_blob(addr, addr_len, addr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	switch (prefix.family) {
	case AF_INET:
		node = radix_search_best(request->conf->address_rule.ipv4, &prefix);
		break;
	case AF_INET6:
		node = radix_search_best(request->conf->address_rule.ipv6, &prefix);
		break;
	default:
		break;
	}

	if (node == NULL) {
		return NULL;
	}

	if (node->data == NULL) {
		return NULL;
	}

	rule = node->data;

	return rule;
}

static int _dns_server_ip_rule_check(struct dns_request *request, struct dns_ip_rules *ip_rules, int result_flag)
{
	struct ip_rule_flags *rule_flags = NULL;
	if (ip_rules == NULL) {
		goto rule_not_found;
	}

	rule_flags = container_of(ip_rules->rules[IP_RULE_FLAGS], struct ip_rule_flags, head);
	if (rule_flags != NULL) {
		if (rule_flags->flags & IP_RULE_FLAG_BOGUS) {
			request->rcode = DNS_RC_NXDOMAIN;
			request->has_soa = 1;
			request->force_soa = 1;
			_dns_server_setup_soa(request);
			goto nxdomain;
		}

		/* blacklist-ip */
		if (rule_flags->flags & IP_RULE_FLAG_BLACKLIST) {
			if (result_flag & DNSSERVER_FLAG_BLACKLIST_IP) {
				goto match;
			}
		}

		/* ignore-ip */
		if (rule_flags->flags & IP_RULE_FLAG_IP_IGNORE) {
			goto skip;
		}
	}

	if (ip_rules->rules[IP_RULE_ALIAS] != NULL) {
		goto match;
	}

rule_not_found:
	if (result_flag & DNSSERVER_FLAG_WHITELIST_IP) {
		if (rule_flags == NULL) {
			goto skip;
		}

		if (!(rule_flags->flags & IP_RULE_FLAG_WHITELIST)) {
			goto skip;
		}
	}
	return -1;
skip:
	return -2;
nxdomain:
	return -3;
match:
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NXDOMAIN;
	}
	return 0;
}

static int _dns_server_process_ip_alias(struct dns_request *request, struct dns_iplist_ip_addresses *alias,
										unsigned char **paddrs, int *paddr_num, int max_paddr_num, int addr_len)
{
	int addr_num = 0;

	if (alias == NULL) {
		return 0;
	}

	if (request == NULL) {
		return -1;
	}

	if (alias->ipaddr_num <= 0) {
		return 0;
	}

	for (int i = 0; i < alias->ipaddr_num && i < max_paddr_num; i++) {
		if (alias->ipaddr[i].addr_len != addr_len) {
			continue;
		}
		paddrs[i] = alias->ipaddr[i].addr;
		addr_num++;
	}

	*paddr_num = addr_num;
	return 0;
}

static int _dns_server_process_ip_rule(struct dns_request *request, unsigned char *addr, int addr_len,
									   dns_type_t addr_type, int result_flag, struct dns_iplist_ip_addresses **alias)
{
	struct dns_ip_rules *ip_rules = NULL;
	int ret = 0;

	ip_rules = _dns_server_ip_rule_get(request, addr, addr_len, addr_type);
	ret = _dns_server_ip_rule_check(request, ip_rules, result_flag);
	if (ret != 0) {
		return ret;
	}

	if (ip_rules->rules[IP_RULE_ALIAS] && alias != NULL) {
		if (request->no_ipalias == 0) {
			struct ip_rule_alias *rule = container_of(ip_rules->rules[IP_RULE_ALIAS], struct ip_rule_alias, head);
			*alias = &rule->ip_alias;
			if (alias == NULL) {
				return 0;
			}
		}

		/* need process ip alias */
		return -1;
	}

	return 0;
}

static int _dns_server_is_adblock_ipv6(const unsigned char addr[16])
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

static int _dns_server_process_answer_A_IP(struct dns_request *request, char *cname, unsigned char addr[4], int ttl,
										   unsigned int result_flag)
{
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ip_check_result = 0;
	unsigned char *paddrs[MAX_IP_NUM];
	int paddr_num = 0;
	struct dns_iplist_ip_addresses *alias = NULL;

	paddrs[paddr_num] = addr;
	paddr_num = 1;

	/* ip rule check */
	ip_check_result = _dns_server_process_ip_rule(request, addr, 4, DNS_T_A, result_flag, &alias);
	if (ip_check_result == 0) {
		/* match */
		return -1;
	} else if (ip_check_result == -2 || ip_check_result == -3) {
		/* skip, nxdomain */
		return ip_check_result;
	}

	int ret = _dns_server_process_ip_alias(request, alias, paddrs, &paddr_num, MAX_IP_NUM, DNS_RR_A_LEN);
	if (ret != 0) {
		return ret;
	}

	for (int i = 0; i < paddr_num; i++) {
		unsigned char *paddr = paddrs[i];
		if (atomic_read(&request->ip_map_num) == 0) {
			request->has_ip = 1;
			request->ip_addr_type = DNS_T_A;
			memcpy(request->ip_addr, paddr, DNS_RR_A_LEN);
			request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			if (cname[0] != 0 && request->has_cname == 0 && request->conf->dns_force_no_cname == 0) {
				request->has_cname = 1;
				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
			}
		} else {
			if (ttl < request->ip_ttl) {
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			}
		}

		/* Ad blocking result */
		if (paddr[0] == 0 || paddr[0] == 127) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_inc_return(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				request->rcode = DNS_RC_NOERROR;
				return -1;
			}
		}

		/* add this ip to request */
		if (_dns_ip_address_check_add(request, cname, paddr, DNS_T_A, 0, NULL) != 0) {
			/* skip result */
			return -2;
		}

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", paddr[0], paddr[1], paddr[2], paddr[3]);

		/* start ping */
		_dns_server_request_get(request);
		if (_dns_server_check_speed(request, ip) != 0) {
			_dns_server_request_release(request);
		}
	}

	return 0;
}

static int _dns_server_process_answer_AAAA_IP(struct dns_request *request, char *cname, unsigned char addr[16], int ttl,
											  unsigned int result_flag)
{
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ip_check_result = 0;
	unsigned char *paddrs[MAX_IP_NUM];
	struct dns_iplist_ip_addresses *alias = NULL;
	int paddr_num = 0;

	paddrs[paddr_num] = addr;
	paddr_num = 1;

	ip_check_result = _dns_server_process_ip_rule(request, addr, 16, DNS_T_AAAA, result_flag, &alias);
	if (ip_check_result == 0) {
		/* match */
		return -1;
	} else if (ip_check_result == -2 || ip_check_result == -3) {
		/* skip, nxdomain */
		return ip_check_result;
	}

	int ret = _dns_server_process_ip_alias(request, alias, paddrs, &paddr_num, MAX_IP_NUM, DNS_RR_AAAA_LEN);
	if (ret != 0) {
		return ret;
	}

	for (int i = 0; i < paddr_num; i++) {
		unsigned char *paddr = paddrs[i];
		if (atomic_read(&request->ip_map_num) == 0) {
			request->has_ip = 1;
			request->ip_addr_type = DNS_T_AAAA;
			memcpy(request->ip_addr, paddr, DNS_RR_AAAA_LEN);
			request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			if (cname[0] != 0 && request->has_cname == 0 && request->conf->dns_force_no_cname == 0) {
				request->has_cname = 1;
				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
			}
		} else {
			if (ttl < request->ip_ttl) {
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			}
		}

		/* Ad blocking result */
		if (_dns_server_is_adblock_ipv6(paddr) == 0) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_inc_return(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				request->rcode = DNS_RC_NOERROR;
				return -1;
			}
		}

		/* add this ip to request */
		if (_dns_ip_address_check_add(request, cname, paddr, DNS_T_AAAA, 0, NULL) != 0) {
			/* skip result */
			return -2;
		}

		snprintf(ip, sizeof(ip), "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]", paddr[0],
				 paddr[1], paddr[2], paddr[3], paddr[4], paddr[5], paddr[6], paddr[7], paddr[8], paddr[9], paddr[10],
				 paddr[11], paddr[12], paddr[13], paddr[14], paddr[15]);

		/* start ping */
		_dns_server_request_get(request);
		if (_dns_server_check_speed(request, ip) != 0) {
			_dns_server_request_release(request);
		}
	}

	return 0;
}

static int _dns_server_process_answer_A(struct dns_rrs *rrs, struct dns_request *request, const char *domain,
										char *cname, unsigned int result_flag)
{
	int ttl = 0;
	unsigned char addr[4];
	char name[DNS_MAX_CNAME_LEN] = {0};

	if (request->qtype != DNS_T_A) {
		return -1;
	}

	/* get A result */
	dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

	tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %d.%d.%d.%d", name, ttl, addr[0], addr[1], addr[2], addr[3]);

	/* if domain is not match */
	if (strncasecmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncasecmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
		return -1;
	}

	_dns_server_request_get(request);
	int ret = _dns_server_process_answer_A_IP(request, cname, addr, ttl, result_flag);
	_dns_server_request_release(request);

	return ret;
}

static int _dns_server_process_answer_AAAA(struct dns_rrs *rrs, struct dns_request *request, const char *domain,
										   char *cname, unsigned int result_flag)
{
	unsigned char addr[16];

	char name[DNS_MAX_CNAME_LEN] = {0};

	int ttl = 0;

	if (request->qtype != DNS_T_AAAA) {
		/* ignore non-matched query type */
		return -1;
	}

	dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

	tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
		 name, ttl, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10],
		 addr[11], addr[12], addr[13], addr[14], addr[15]);

	/* if domain is not match */
	if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
		return -1;
	}

	_dns_server_request_get(request);
	int ret = _dns_server_process_answer_AAAA_IP(request, cname, addr, ttl, result_flag);
	_dns_server_request_release(request);

	return ret;
}

static int _dns_server_process_answer_HTTPS(struct dns_rrs *rrs, struct dns_request *request, const char *domain,
											char *cname, unsigned int result_flag)
{
	int ttl = 0;
	int ret = -1;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char target[DNS_MAX_CNAME_LEN] = {0};
	struct dns_https_param *p = NULL;
	int priority = 0;
	struct dns_request_https *https_svcb;
	int no_ipv4 = 0;
	int no_ipv6 = 0;
	struct dns_https_record_rule *https_record_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_HTTPS);
	if (https_record_rule) {
		if (https_record_rule->filter.no_ipv4hint) {
			no_ipv4 = 1;
		}

		if (https_record_rule->filter.no_ipv6hint) {
			no_ipv6 = 1;
		}
	}

	ret = dns_get_HTTPS_svcparm_start(rrs, &p, name, DNS_MAX_CNAME_LEN, &ttl, &priority, target, DNS_MAX_CNAME_LEN);
	if (ret != 0) {
		tlog(TLOG_WARN, "get HTTPS svcparm failed");
		return -1;
	}

	https_svcb = request->https_svcb;
	if (https_svcb == 0) {
		/* ignore non-matched query type */
		tlog(TLOG_WARN, "https svcb not set");
		return -1;
	}

	tlog(TLOG_DEBUG, "domain: %s HTTPS: %s TTL: %d priority: %d", name, target, ttl, priority);
	https_svcb->ttl = ttl;
	https_svcb->priority = priority;
	safe_strncpy(https_svcb->target, target, sizeof(https_svcb->target));
	safe_strncpy(https_svcb->domain, name, sizeof(https_svcb->domain));
	request->ip_ttl = ttl;

	_dns_server_request_get(request);
	for (; p; p = dns_get_HTTPS_svcparm_next(rrs, p)) {
		switch (p->key) {
		case DNS_HTTPS_T_MANDATORY: {
		} break;
		case DNS_HTTPS_T_ALPN: {
			memcpy(https_svcb->alpn, p->value, sizeof(https_svcb->alpn));
			https_svcb->alpn_len = p->len;
		} break;
		case DNS_HTTPS_T_NO_DEFAULT_ALPN: {
		} break;
		case DNS_HTTPS_T_PORT: {
			int port = *(unsigned short *)(p->value);
			https_svcb->port = ntohs(port);
		} break;
		case DNS_HTTPS_T_IPV4HINT: {
			struct dns_rule_address_IPV4 *address_ipv4 = NULL;
			if (_dns_server_is_return_soa_qtype(request, DNS_T_A) || no_ipv4 == 1) {
				break;
			}

			if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
				break;
			}

			address_ipv4 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV4);
			if (address_ipv4 != NULL) {
				memcpy(request->ip_addr, address_ipv4->ipv4_addr, DNS_RR_A_LEN);
				request->has_ip = 1;
				request->ip_addr_type = DNS_T_A;
				break;
			}

			for (int k = 0; k < p->len / 4; k++) {
				_dns_server_process_answer_A_IP(request, cname, p->value + k * 4, ttl, result_flag);
			}
		} break;
		case DNS_HTTPS_T_ECH: {
			if (p->len > sizeof(https_svcb->ech)) {
				tlog(TLOG_WARN, "ech too long");
				break;
			}
			memcpy(https_svcb->ech, p->value, p->len);
			https_svcb->ech_len = p->len;
		} break;
		case DNS_HTTPS_T_IPV6HINT: {
			struct dns_rule_address_IPV6 *address_ipv6 = NULL;

			if (_dns_server_is_return_soa_qtype(request, DNS_T_AAAA) || no_ipv6 == 1) {
				break;
			}

			if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
				break;
			}

			address_ipv6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV6);
			if (address_ipv6 != NULL) {
				memcpy(request->ip_addr, address_ipv6->ipv6_addr, DNS_RR_AAAA_LEN);
				request->has_ip = 1;
				request->ip_addr_type = DNS_T_AAAA;
				break;
			}

			for (int k = 0; k < p->len / 16; k++) {
				_dns_server_process_answer_AAAA_IP(request, cname, p->value + k * 16, ttl, result_flag);
			}
		} break;
		}
	}

	_dns_server_request_release(request);

	return 0;
}

static int _dns_server_process_answer(struct dns_request *request, const char *domain, struct dns_packet *packet,
									  unsigned int result_flag, int *need_passthrouh)
{
	int ttl = 0;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char cname[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ret = 0;
	int is_skip = 0;
	int has_result = 0;
	int is_rcode_set = 0;

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
			request->remote_server_fail = 1;
		}

		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);

		if (request->remote_server_fail == 0) {
			return DNS_CLIENT_ACTION_DROP;
		}

		return DNS_CLIENT_ACTION_UNDEFINE;
	}

	/* when QTYPE is HTTPS, check if support */
	if (request->qtype == DNS_T_HTTPS) {
		int https_svcb_record_num = 0;
		for (j = 1; j < DNS_RRS_OPT; j++) {
			rrs = dns_get_rrs_start(packet, j, &rr_count);
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
				switch (rrs->type) {
				case DNS_T_HTTPS: {
					https_svcb_record_num++;
					if (https_svcb_record_num <= 1) {
						continue;
					}

					/* CURRENT NOT SUPPORT MUTI HTTPS RECORD */
					*need_passthrouh = 1;
					return DNS_CLIENT_ACTION_OK;
				}
				}
			}
		}
	}

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			has_result = 1;
			switch (rrs->type) {
			case DNS_T_A: {
				ret = _dns_server_process_answer_A(rrs, request, domain, cname, result_flag);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					is_skip = 1;
					continue;
				} else if (ret == -3) {
					return -1;
				}
				request->rcode = packet->head.rcode;
				is_rcode_set = 1;
			} break;
			case DNS_T_AAAA: {
				ret = _dns_server_process_answer_AAAA(rrs, request, domain, cname, result_flag);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					is_skip = 1;
					continue;
				} else if (ret == -3) {
					return -1;
				}
				request->rcode = packet->head.rcode;
				is_rcode_set = 1;
			} break;
			case DNS_T_NS: {
				char nsname[DNS_MAX_CNAME_LEN];
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, nsname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "NS: %s ttl: %d nsname: %s\n", name, ttl, nsname);
			} break;
			case DNS_T_CNAME: {
				char domain_name[DNS_MAX_CNAME_LEN] = {0};
				char domain_cname[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, domain_name, DNS_MAX_CNAME_LEN, &ttl, domain_cname, DNS_MAX_CNAME_LEN);
				if (strncasecmp(domain_name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(domain_name, cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}
				safe_strncpy(cname, domain_cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = _dns_server_get_conf_ttl(request, ttl);
				tlog(TLOG_DEBUG, "name: %s ttl: %d cname: %s\n", domain_name, ttl, cname);
			} break;
			case DNS_T_HTTPS: {
				ret = _dns_server_process_answer_HTTPS(rrs, request, domain, cname, result_flag);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					is_skip = 1;
					continue;
				}
				request->rcode = packet->head.rcode;
				is_rcode_set = 1;
				if (request->has_ip == 0) {
					request->passthrough = 1;
					_dns_server_request_complete(request);
				}
			} break;
			case DNS_T_SOA: {
				/* if DNS64 enabled, skip check SOA. */
				if (_dns_server_is_dns64_request(request)) {
					if (request->has_ip) {
						_dns_server_request_complete(request);
					}
					break;
				}

				request->has_soa = 1;
				if (request->rcode != DNS_RC_NOERROR) {
					request->rcode = packet->head.rcode;
					is_rcode_set = 1;
				}
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_DEBUG,
					 "domain: %s, qtype: %d, SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, "
					 "expire: "
					 "%d, minimum: %d",
					 domain, request->qtype, request->soa.mname, request->soa.rname, request->soa.serial,
					 request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);

				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
				int soa_num = atomic_inc_return(&request->soa_num);
				if ((soa_num >= ((int)ceilf((float)dns_server_alive_num() / 3) + 1) || soa_num > 4) &&
					atomic_read(&request->ip_map_num) <= 0) {
					request->ip_ttl = ttl;
					_dns_server_request_complete(request);
				}
			} break;
			default:
				tlog(TLOG_DEBUG, "%s, qtype: %d, rrstype = %d", name, rrs->type, j);
				break;
			}
		}
	}

	request->remote_server_fail = 0;
	if (request->rcode == DNS_RC_SERVFAIL && is_skip == 0) {
		request->rcode = packet->head.rcode;
	}

	if (has_result == 0 && request->rcode == DNS_RC_NOERROR && packet->head.tc == 1 && request->has_ip == 0 &&
		request->has_soa == 0) {
		tlog(TLOG_DEBUG, "result is truncated, %s qtype: %d, rcode: %d, id: %d, retry.", domain, request->qtype,
			 packet->head.rcode, packet->head.id);
		return DNS_CLIENT_ACTION_RETRY;
	}

	if (is_rcode_set == 0 && has_result == 1 && is_skip == 0) {
		/* need retry for some server. */
		return DNS_CLIENT_ACTION_MAY_RETRY;
	}

	return DNS_CLIENT_ACTION_OK;
}

static int _dns_server_passthrough_rule_check(struct dns_request *request, const char *domain,
											  struct dns_packet *packet, unsigned int result_flag, int *pttl)
{
	int ttl = 0;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char cname[DNS_MAX_CNAME_LEN];
	int rr_count = 0;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ip_check_result = 0;

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
			request->remote_server_fail = 1;
		}

		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);
		return 0;
	}

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				int ttl_tmp = 0;
				if (request->qtype != DNS_T_A) {
					/* ignore non-matched query type */
					if (request->dualstack_selection == 0) {
						break;
					}
				}
				_dns_server_request_get(request);
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl_tmp, addr);

				/* if domain is not match */
				if (strncasecmp(name, domain, DNS_MAX_CNAME_LEN) != 0 &&
					strncasecmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					continue;
				}

				tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %d.%d.%d.%d", name, ttl_tmp, addr[0], addr[1], addr[2],
					 addr[3]);

				/* ip rule check */
				ip_check_result = _dns_server_process_ip_rule(request, addr, 4, DNS_T_A, result_flag, NULL);
				if (ip_check_result == 0 || ip_check_result == -2 || ip_check_result == -3) {
					/* match, skip, nxdomain */
					_dns_server_request_release(request);
					return 0;
				}

				/* Ad blocking result */
				if (addr[0] == 0 || addr[0] == 127) {
					/* If half of the servers return the same result, then ignore this address */
					if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
						_dns_server_request_release(request);
						return 0;
					}
				}

				ttl = _dns_server_get_conf_ttl(request, ttl_tmp);
				_dns_server_request_release(request);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				int ttl_tmp = 0;
				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				_dns_server_request_get(request);
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl_tmp, addr);

				/* if domain is not match */
				if (strncasecmp(name, domain, DNS_MAX_CNAME_LEN) != 0 &&
					strncasecmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					continue;
				}

				tlog(TLOG_DEBUG,
					 "domain: %s TTL: %d IP: "
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					 name, ttl_tmp, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
					 addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);

				ip_check_result = _dns_server_process_ip_rule(request, addr, 16, DNS_T_AAAA, result_flag, NULL);
				if (ip_check_result == 0 || ip_check_result == -2 || ip_check_result == -3) {
					/* match, skip, nxdomain */
					_dns_server_request_release(request);
					return 0;
				}

				/* Ad blocking result */
				if (_dns_server_is_adblock_ipv6(addr) == 0) {
					/* If half of the servers return the same result, then ignore this address */
					if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
						_dns_server_request_release(request);
						return 0;
					}
				}

				ttl = _dns_server_get_conf_ttl(request, ttl_tmp);
				_dns_server_request_release(request);
			} break;
			case DNS_T_CNAME: {
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
			} break;
			default:
				if (ttl == 0) {
					/* Get TTL */
					char tmpname[DNS_MAX_CNAME_LEN];
					char tmpbuf[DNS_MAX_CNAME_LEN];
					dns_get_CNAME(rrs, tmpname, DNS_MAX_CNAME_LEN, &ttl, tmpbuf, DNS_MAX_CNAME_LEN);
					if (request->ip_ttl == 0) {
						request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
					}
				}
				break;
			}
		}
	}

	request->remote_server_fail = 0;
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = packet->head.rcode;
	}

	*pttl = ttl;
	return -1;
}

static int _dns_server_get_answer(struct dns_server_post_context *context)
{
	int i = 0;
	int j = 0;
	int ttl = 0;
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	struct dns_request *request = context->request;
	struct dns_packet *packet = context->packet;

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				char name[DNS_MAX_CNAME_LEN] = {0};
				struct dns_ip_address *addr_map = NULL;

				if (request->qtype != DNS_T_A) {
					continue;
				}

				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				if (context->no_check_add_ip == 0 &&
					_dns_ip_address_check_add(request, name, addr, DNS_T_A, request->ping_time, &addr_map) != 0) {
					continue;
				}

				_dns_server_context_add_ip(context, addr_map->ip_addr);
				if (request->has_ip == 1) {
					continue;
				}

				memcpy(request->ip_addr, addr, DNS_RR_A_LEN);
				/* add this ip to request */
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
				request->has_ip = 1;
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				char name[DNS_MAX_CNAME_LEN] = {0};
				struct dns_ip_address *addr_map = NULL;

				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					continue;
				}
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				if (context->no_check_add_ip == 0 &&
					_dns_ip_address_check_add(request, name, addr, DNS_T_AAAA, request->ping_time, &addr_map) != 0) {
					continue;
				}

				_dns_server_context_add_ip(context, addr_map->ip_addr);
				if (request->has_ip == 1) {
					continue;
				}

				memcpy(request->ip_addr, addr, DNS_RR_AAAA_LEN);
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
				request->has_ip = 1;
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_NS: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "NS: %s, ttl: %d, cname: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				if (request->conf->dns_force_no_cname) {
					continue;
				}

				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "name: %s, ttl: %d, cname: %s\n", name, ttl, cname);
				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = _dns_server_get_conf_ttl(request, ttl);
				request->has_cname = 1;
			} break;
			case DNS_T_SOA: {
				char name[DNS_MAX_CNAME_LEN] = {0};
				request->has_soa = 1;
				if (request->rcode != DNS_RC_NOERROR) {
					request->rcode = packet->head.rcode;
				}
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_DEBUG,
					 "domain: %s, qtype: %d, SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, "
					 "expire: "
					 "%d, minimum: %d",
					 request->domain, request->qtype, request->soa.mname, request->soa.rname, request->soa.serial,
					 request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			} break;
			default:
				break;
			}
		}
	}

	return 0;
}

static int _dns_server_reply_passthrough(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	_dns_server_get_answer(context);

	_dns_cache_reply_packet(context);

	if (_dns_server_setup_ipset_nftset_packet(context) != 0) {
		tlog(TLOG_DEBUG, "setup ipset failed.");
	}

	_dns_result_callback(context);

	_dns_server_audit_log(context);

	/* reply child request */
	_dns_result_child_post(context);

	if (request->conn && context->do_reply == 1) {
		char clientip[DNS_MAX_CNAME_LEN] = {0};

		/* When passthrough, modify the id to be the id of the client request. */
		int ret = _dns_request_update_id_ttl(context);
		if (ret != 0) {
			tlog(TLOG_ERROR, "update packet ttl failed.");
			return -1;
		}
		_dns_reply_inpacket(request, context->inpacket, context->inpacket_len);

		tlog(TLOG_INFO, "result: %s, client: %s, qtype: %d, id: %d, group: %s, time: %lums", request->domain,
			 get_host_by_addr(clientip, sizeof(clientip), (struct sockaddr *)&request->addr), request->qtype,
			 request->id, request->dns_group_name[0] != '\0' ? request->dns_group_name : DNS_SERVER_GROUP_DEFAULT,
			 get_tick_count() - request->send_tick);
	}

	return _dns_server_reply_all_pending_list(request, context);
}

static void _dns_server_query_end(struct dns_request *request)
{
	int ip_num = 0;
	int request_wait = 0;
	struct dns_conf_group *conf = request->conf;

	/* if mdns request timeout */
	if (request->is_mdns_lookup == 1 && request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NOERROR;
		request->force_soa = 1;
		request->ip_ttl = _dns_server_get_conf_ttl(request, DNS_SERVER_ADDR_TTL);
	}

	pthread_mutex_lock(&request->ip_map_lock);
	ip_num = atomic_read(&request->ip_map_num);
	request_wait = request->request_wait;
	request->request_wait--;
	pthread_mutex_unlock(&request->ip_map_lock);

	/* Not need to wait check result if only has one ip address */
	if (ip_num <= 1 && request_wait == 1) {
		if (request->dualstack_selection_query == 1) {
			if ((conf->ipset_nftset.ipset_no_speed.ipv4_enable || conf->ipset_nftset.nftset_no_speed.ip_enable ||
				 conf->ipset_nftset.ipset_no_speed.ipv6_enable || conf->ipset_nftset.nftset_no_speed.ip6_enable) &&
				request->conf->dns_dns64.prefix_len == 0) {
				/* if speed check fail enabled, we need reply quickly, otherwise wait for ping result.*/
				_dns_server_request_complete(request);
			}
			goto out;
		}

		if (request->dualstack_selection_has_ip && request->dualstack_selection_ping_time > 0) {
			goto out;
		}

		request->has_ping_result = 1;
		_dns_server_request_complete(request);
	}

out:
	_dns_server_request_release(request);
}

static int dns_server_dualstack_callback(const struct dns_result *result, void *user_ptr)
{
	struct dns_request *request = (struct dns_request *)user_ptr;
	tlog(TLOG_DEBUG, "dualstack result: domain: %s, ip: %s, type: %d, ping: %d, rcode: %d", result->domain, result->ip,
		 result->addr_type, result->ping_time, result->rtcode);
	if (request == NULL) {
		return -1;
	}

	if (result->rtcode == DNS_RC_NOERROR && result->ip[0] != 0) {
		request->dualstack_selection_has_ip = 1;
	}

	request->dualstack_selection_ping_time = result->ping_time;

	_dns_server_query_end(request);

	return 0;
}

static void _dns_server_passthrough_may_complete(struct dns_request *request)
{
	const unsigned char *addr;
	if (request->passthrough != 2) {
		return;
	}

	if (request->has_ip == 0 && request->has_soa == 0) {
		return;
	}

	if (request->qtype == DNS_T_A && request->has_ip == 1) {
		/* Ad blocking result */
		addr = request->ip_addr;
		if (addr[0] == 0 || addr[0] == 127) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				return;
			}
		}
	}

	if (request->qtype == DNS_T_AAAA && request->has_ip == 1) {
		addr = request->ip_addr;
		if (_dns_server_is_adblock_ipv6(addr) == 0) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				return;
			}
		}
	}

	_dns_server_request_complete_with_all_IPs(request, 1);
}

static int _dns_server_resolve_callback_reply_passthrough(struct dns_request *request, const char *domain,
														  struct dns_packet *packet, unsigned char *inpacket,
														  int inpacket_len, unsigned int result_flag)
{
	struct dns_server_post_context context;
	int ttl = 0;
	int ret = 0;

	ret = _dns_server_passthrough_rule_check(request, domain, packet, result_flag, &ttl);
	if (ret == 0) {
		return 0;
	}

	ttl = _dns_server_get_conf_ttl(request, ttl);
	_dns_server_post_context_init_from(&context, request, packet, inpacket, inpacket_len);
	context.do_cache = 1;
	context.do_audit = 1;
	context.do_reply = 1;
	context.do_ipset = 1;
	context.reply_ttl = ttl;
	return _dns_server_reply_passthrough(&context);
}

static int dns_server_resolve_callback(const char *domain, dns_result_type rtype, struct dns_server_info *server_info,
									   struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									   void *user_ptr)
{
	struct dns_request *request = user_ptr;
	int ret = 0;
	int need_passthrouh = 0;
	unsigned long result_flag = dns_client_server_result_flag(server_info);

	if (request == NULL) {
		return -1;
	}

	if (rtype == DNS_QUERY_RESULT) {
		tlog(TLOG_DEBUG, "query result from server %s:%d, type: %d, domain: %s qtype: %d rcode: %d, id: %d",
			 dns_client_get_server_ip(server_info), dns_client_get_server_port(server_info),
			 dns_client_get_server_type(server_info), domain, request->qtype, packet->head.rcode, request->id);

		if (request->passthrough == 1 && atomic_read(&request->notified) == 0) {
			return _dns_server_resolve_callback_reply_passthrough(request, domain, packet, inpacket, inpacket_len,
																  result_flag);
		}

		if (request->prefetch == 0 && request->response_mode == DNS_RESPONSE_MODE_FASTEST_RESPONSE &&
			atomic_read(&request->notified) == 0) {
			struct dns_server_post_context context;
			int ttl = 0;
			ret = _dns_server_passthrough_rule_check(request, domain, packet, result_flag, &ttl);
			if (ret != 0) {
				_dns_server_post_context_init_from(&context, request, packet, inpacket, inpacket_len);
				context.do_cache = 1;
				context.do_audit = 1;
				context.do_reply = 1;
				context.do_ipset = 1;
				context.reply_ttl = _dns_server_get_reply_ttl(request, ttl);
				context.cache_ttl = _dns_server_get_conf_ttl(request, ttl);
				request->ip_ttl = context.cache_ttl;
				context.no_check_add_ip = 1;
				_dns_server_reply_passthrough(&context);
				request->cname[0] = 0;
				request->has_ip = 0;
				request->has_cname = 0;
				request->has_ping_result = 0;
				request->has_soa = 0;
				request->has_ptr = 0;
				request->ping_time = -1;
				request->ip_ttl = 0;
			}
		}

		ret = _dns_server_process_answer(request, domain, packet, result_flag, &need_passthrouh);
		if (ret == 0 && need_passthrouh == 1 && atomic_read(&request->notified) == 0) {
			/* not supported record, passthrouth */
			request->passthrough = 1;
			return _dns_server_resolve_callback_reply_passthrough(request, domain, packet, inpacket, inpacket_len,
																  result_flag);
		}
		_dns_server_passthrough_may_complete(request);
		return ret;
	} else if (rtype == DNS_QUERY_ERR) {
		tlog(TLOG_ERROR, "request failed, %s", domain);
		return -1;
	} else {
		_dns_server_query_end(request);
	}

	return 0;
}

static int _dns_server_get_inet_by_addr(struct sockaddr_storage *localaddr, struct sockaddr_storage *addr, int family)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	char ethname[16] = {0};

	if (getifaddrs(&ifaddr) == -1) {
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (localaddr->ss_family != ifa->ifa_addr->sa_family) {
			continue;
		}

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in_1 = NULL;
			struct sockaddr_in *addr_in_2 = NULL;
			addr_in_1 = (struct sockaddr_in *)ifa->ifa_addr;
			addr_in_2 = (struct sockaddr_in *)localaddr;
			if (memcmp(&(addr_in_1->sin_addr.s_addr), &(addr_in_2->sin_addr.s_addr), 4) != 0) {
				continue;
			}
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6_1 = NULL;
			struct sockaddr_in6 *addr_in6_2 = NULL;
			addr_in6_1 = (struct sockaddr_in6 *)ifa->ifa_addr;
			addr_in6_2 = (struct sockaddr_in6 *)localaddr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6_1->sin6_addr)) {
				unsigned char *addr1 = addr_in6_1->sin6_addr.s6_addr + 12;
				unsigned char *addr2 = addr_in6_2->sin6_addr.s6_addr + 12;
				if (memcmp(addr1, addr2, 4) != 0) {
					continue;
				}
			} else {
				unsigned char *addr1 = addr_in6_1->sin6_addr.s6_addr;
				unsigned char *addr2 = addr_in6_2->sin6_addr.s6_addr;
				if (memcmp(addr1, addr2, 16) != 0) {
					continue;
				}
			}
		} break;
		default:
			continue;
			break;
		}

		safe_strncpy(ethname, ifa->ifa_name, sizeof(ethname));
		break;
	}

	if (ethname[0] == '\0') {
		goto errout;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (ifa->ifa_addr->sa_family != family) {
			continue;
		}

		if (strncmp(ethname, ifa->ifa_name, sizeof(ethname)) != 0) {
			continue;
		}

		if (family == AF_INET) {
			memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in));
		} else if (family == AF_INET6) {
			memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
		}

		break;
	}

	if (ifa == NULL) {
		goto errout;
	}

	freeifaddrs(ifaddr);
	return 0;
errout:
	if (ifaddr) {
		freeifaddrs(ifaddr);
	}

	return -1;
}

static int _dns_server_reply_request_eth_ip(struct dns_request *request)
{
	struct sockaddr_in *addr_in = NULL;
	struct sockaddr_in6 *addr_in6 = NULL;
	struct sockaddr_storage *localaddr = NULL;
	struct sockaddr_storage localaddr_buff;

	localaddr = &request->localaddr;

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A:
		if (localaddr->ss_family != AF_INET) {
			if (_dns_server_get_inet_by_addr(localaddr, &localaddr_buff, AF_INET) != 0) {
				_dns_server_reply_SOA(DNS_RC_NOERROR, request);
				return 0;
			}

			localaddr = &localaddr_buff;
		}
		addr_in = (struct sockaddr_in *)localaddr;
		memcpy(request->ip_addr, &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
		break;
	case DNS_T_AAAA:
		if (localaddr->ss_family != AF_INET6) {
			if (_dns_server_get_inet_by_addr(localaddr, &localaddr_buff, AF_INET6) != 0) {
				_dns_server_reply_SOA(DNS_RC_NOERROR, request);
				return 0;
			}

			localaddr = &localaddr_buff;
		}
		addr_in6 = (struct sockaddr_in6 *)localaddr;
		memcpy(request->ip_addr, &addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
		break;
	default:
		goto out;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = dns_conf_local_ttl;
	request->has_ip = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	_dns_request_post(&context);

	return 0;
out:
	return -1;
}

static int _dns_server_process_ptrs(struct dns_request *request)
{
	uint32_t key = 0;
	struct dns_ptr *ptr = NULL;
	struct dns_ptr *ptr_tmp = NULL;
	key = hash_string(request->domain);
	hash_for_each_possible(dns_ptr_table.ptr, ptr_tmp, node, key)
	{
		if (strncmp(ptr_tmp->ptr_domain, request->domain, DNS_MAX_PTR_LEN) != 0) {
			continue;
		}

		ptr = ptr_tmp;
		break;
	}

	if (ptr == NULL) {
		goto errout;
	}

	request->has_ptr = 1;
	safe_strncpy(request->ptr_hostname, ptr->hostname, DNS_MAX_CNAME_LEN);
	return 0;
errout:
	return -1;
}

static void _dns_server_set_request_mdns(struct dns_request *request)
{
	if (dns_conf_mdns_lookup != 1) {
		return;
	}

	request->is_mdns_lookup = 1;
}

static int _dns_server_parser_addr_from_apra(const char *arpa, unsigned char *addr, int *addr_len, int max_addr_len)
{
	int high, low;
	char *endptr = NULL;

	if (arpa == NULL || addr == NULL || addr_len == NULL || max_addr_len < 4) {
		return -1;
	}

	int ret = sscanf(arpa, "%hhd.%hhd.%hhd.%hhd.in-addr.arpa", &addr[3], &addr[2], &addr[1], &addr[0]);
	if (ret == 4 && strstr(arpa, ".in-addr.arpa") != NULL) {
		*addr_len = 4;
		return 0;
	}

	if (max_addr_len != 16) {
		return -1;
	}

	for (int i = 15; i >= 0; i--) {
		low = strtol(arpa, &endptr, 16);
		if (endptr == NULL || *endptr != '.' || *endptr == '\0') {
			return -1;
		}

		arpa = endptr + 1;
		high = strtol(arpa, &endptr, 16);
		if (endptr == NULL || *endptr != '.' || *endptr == '\0') {
			return -1;
		}

		arpa = endptr + 1;
		addr[i] = (high << 4) | low;
	}

	if (strstr(arpa, "ip6.arpa") == NULL) {
		return -1;
	}

	*addr_len = 16;

	return 0;
}

static int _dns_server_is_private_address(const unsigned char *addr, int addr_len)
{
	if (addr_len == 4) {
		if (addr[0] == 10 || (addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31) || (addr[0] == 192 && addr[1] == 168)) {
			return 0;
		}
	} else if (addr_len == 16) {
		if (addr[0] == 0xfe && addr[1] == 0x80) {
			return 0;
		}
	}

	return -1;
}

static void _dns_server_local_addr_cache_add(unsigned char *netaddr, int netaddr_len, int prefix_len)
{
	prefix_t prefix;
	struct local_addr_cache_item *addr_cache_item = NULL;
	radix_node_t *node = NULL;

	if (prefix_from_blob(netaddr, netaddr_len, prefix_len, &prefix) == NULL) {
		return;
	}

	node = radix_lookup(server.local_addr_cache.addr, &prefix);
	if (node == NULL) {
		goto errout;
	}

	if (node->data == NULL) {
		addr_cache_item = malloc(sizeof(struct local_addr_cache_item));
		if (addr_cache_item == NULL) {
			return;
		}
		memset(addr_cache_item, 0, sizeof(struct local_addr_cache_item));
	} else {
		addr_cache_item = node->data;
	}

	addr_cache_item->ip_addr_len = netaddr_len;
	memcpy(addr_cache_item->ip_addr, netaddr, netaddr_len);
	addr_cache_item->mask_len = prefix_len;
	node->data = addr_cache_item;

	return;
errout:
	if (addr_cache_item) {
		free(addr_cache_item);
	}

	return;
}

static void _dns_server_local_addr_cache_del(unsigned char *netaddr, int netaddr_len, int prefix_len)
{
	radix_node_t *node = NULL;
	prefix_t prefix;

	if (prefix_from_blob(netaddr, netaddr_len, prefix_len, &prefix) == NULL) {
		return;
	}

	node = radix_search_exact(server.local_addr_cache.addr, &prefix);
	if (node == NULL) {
		return;
	}

	if (node->data != NULL) {
		free(node->data);
	}

	node->data = NULL;
	radix_remove(server.local_addr_cache.addr, node);
}

static void _dns_server_process_local_addr_cache(int fd_netlink, struct epoll_event *event, unsigned long now)
{
	char buffer[1024 * 8];
	struct iovec iov = {buffer, sizeof(buffer)};
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nh;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (1) {
		ssize_t len = recvmsg(fd_netlink, &msg, 0);
		if (len == -1) {
			break;
		}

		for (nh = (struct nlmsghdr *)buffer; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
			if (nh->nlmsg_type == NLMSG_DONE) {
				break;
			}

			if (nh->nlmsg_type == NLMSG_ERROR) {
				break;
			}

			if (nh->nlmsg_type != RTM_NEWADDR && nh->nlmsg_type != RTM_DELADDR) {
				continue;
			}

			struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
			struct rtattr *rth = IFA_RTA(ifa);
			int rtl = IFA_PAYLOAD(nh);

			while (rtl && RTA_OK(rth, rtl)) {
				if (rth->rta_type == IFA_ADDRESS) {
					unsigned char *netaddr = RTA_DATA(rth);
					int netaddr_len = 0;

					if (ifa->ifa_family == AF_INET) {
						netaddr_len = 4;
					} else if (ifa->ifa_family == AF_INET6) {
						netaddr_len = 16;
					} else {
						continue;
					}

					if (nh->nlmsg_type == RTM_NEWADDR) {
						_dns_server_local_addr_cache_add(netaddr, netaddr_len, netaddr_len * 8);
						_dns_server_local_addr_cache_add(netaddr, netaddr_len, ifa->ifa_prefixlen);
					} else {
						_dns_server_local_addr_cache_del(netaddr, netaddr_len, netaddr_len * 8);
						_dns_server_local_addr_cache_del(netaddr, netaddr_len, ifa->ifa_prefixlen);
					}
				}
				rth = RTA_NEXT(rth, rtl);
			}
		}
	}
}

static int _dns_server_process_local_ptr(struct dns_request *request)
{
	unsigned char ptr_addr[16];
	int ptr_addr_len = 0;
	int found = 0;
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct local_addr_cache_item *addr_cache_item = NULL;

	if (_dns_server_parser_addr_from_apra(request->domain, ptr_addr, &ptr_addr_len, sizeof(ptr_addr)) != 0) {
		/* Determine if the smartdns service is in effect. */
		if (strncasecmp(request->domain, "smartdns", sizeof("smartdns")) != 0) {
			return -1;
		}
		found = 1;
		goto out;
	}

	if (dns_conf_local_ptr_enable == 0) {
		goto out;
	}

	if (prefix_from_blob(ptr_addr, ptr_addr_len, ptr_addr_len * 8, &prefix) == NULL) {
		goto out;
	}

	node = radix_search_best(server.local_addr_cache.addr, &prefix);
	if (node == NULL) {
		goto out;
	}

	if (node->data == NULL) {
		goto out;
	}

	addr_cache_item = node->data;
	if (addr_cache_item->mask_len == ptr_addr_len * 8) {
		found = 1;
		goto out;
	}

	if (dns_conf_mdns_lookup) {
		_dns_server_set_request_mdns(request);
		goto errout;
	}

out:
	if (found == 0 && _dns_server_is_private_address(ptr_addr, ptr_addr_len) == 0) {
		request->has_soa = 1;
		_dns_server_setup_soa(request);
		goto clear;
	}

	if (found == 0) {
		goto errout;
	}

	char full_hostname[DNS_MAX_CNAME_LEN];
	if (dns_conf_server_name[0] == 0) {
		char hostname[DNS_MAX_CNAME_LEN];
		char domainname[DNS_MAX_CNAME_LEN];

		/* get local domain name */
		if (getdomainname(domainname, DNS_MAX_CNAME_LEN - 1) == 0) {
			/* check domain is valid */
			if (strncmp(domainname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
				domainname[0] = '\0';
			}
		}

		if (gethostname(hostname, DNS_MAX_CNAME_LEN - 1) == 0) {
			/* check hostname is valid */
			if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
				hostname[0] = '\0';
			}
		}

		if (hostname[0] != '\0' && domainname[0] != '\0') {
			snprintf(full_hostname, sizeof(full_hostname), "%.64s.%.128s", hostname, domainname);
		} else if (hostname[0] != '\0') {
			safe_strncpy(full_hostname, hostname, DNS_MAX_CNAME_LEN);
		} else {
			safe_strncpy(full_hostname, "smartdns", DNS_MAX_CNAME_LEN);
		}
	} else {
		/* return configured server name */
		safe_strncpy(full_hostname, dns_conf_server_name, DNS_MAX_CNAME_LEN);
	}

	request->has_ptr = 1;
	safe_strncpy(request->ptr_hostname, full_hostname, DNS_MAX_CNAME_LEN);
clear:
	return 0;
errout:
	return -1;
}

static int _dns_server_get_local_ttl(struct dns_request *request)
{
	struct dns_ttl_rule *ttl_rule;

	/* get domain rule flag */
	ttl_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_TTL);
	if (ttl_rule != NULL) {
		if (ttl_rule->ttl > 0) {
			return ttl_rule->ttl;
		}
	}

	if (dns_conf_local_ttl > 0) {
		return dns_conf_local_ttl;
	}

	if (request->conf->dns_rr_ttl > 0) {
		return request->conf->dns_rr_ttl;
	}

	if (request->conf->dns_rr_ttl_min > 0) {
		return request->conf->dns_rr_ttl_min;
	}

	return DNS_SERVER_ADDR_TTL;
}

static int _dns_server_process_ptr(struct dns_request *request)
{
	if (_dns_server_process_ptrs(request) == 0) {
		goto reply_exit;
	}

	if (_dns_server_process_local_ptr(request) == 0) {
		goto reply_exit;
	}

	return -1;

reply_exit:
	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 0;
	context.do_cache = 1;
	_dns_request_post(&context);
	return 0;
}

static int _dns_server_process_DDR(struct dns_request *request)
{
	return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
}

static int _dns_server_process_srv(struct dns_request *request)
{
	struct dns_srv_records *srv_records = dns_server_get_srv_record(request->domain);
	if (srv_records == NULL) {
		return -1;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	request->srv_records = srv_records;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_audit = 1;
	context.do_reply = 1;
	context.do_cache = 0;
	context.do_force_soa = 0;
	_dns_request_post(&context);

	return 0;
}

static int _dns_server_process_svcb(struct dns_request *request)
{
	if (strncasecmp("_dns.resolver.arpa", request->domain, DNS_MAX_CNAME_LEN) == 0) {
		return _dns_server_process_DDR(request);
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

static void _dns_server_update_rule_by_flags(struct dns_request_domain_rule *request_domain_rule)
{
	struct dns_rule_flags *rule_flag = (struct dns_rule_flags *)request_domain_rule->rules[0];
	unsigned int flags = 0;

	if (rule_flag == NULL) {
		return;
	}
	flags = rule_flag->flags;

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_HTTPS_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_HTTPS] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_IPSET] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV4_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_IPSET_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV6_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_IPSET_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NFTSET_IP_IGN || flags & DOMAIN_FLAG_NFTSET_INET_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_NFTSET_IP] = NULL;
	}

	if (flags & DOMAIN_FLAG_NFTSET_IP6_IGN || flags & DOMAIN_FLAG_NFTSET_INET_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_NFTSET_IP6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NAMESERVER_IGNORE) {
		request_domain_rule->rules[DOMAIN_RULE_NAMESERVER] = NULL;
	}
}

static int _dns_server_get_rules(unsigned char *key, uint32_t key_len, int is_subkey, void *value, void *arg)
{
	struct rule_walk_args *walk_args = arg;
	struct dns_request_domain_rule *request_domain_rule = walk_args->args;
	struct dns_domain_rule *domain_rule = value;
	int i = 0;
	if (domain_rule == NULL) {
		return 0;
	}

	if (domain_rule->sub_rule_only != domain_rule->root_rule_only) {
		/* only subkey rule */
		if (domain_rule->sub_rule_only == 1 && is_subkey == 0) {
			return 0;
		}

		/* only root key rule */
		if (domain_rule->root_rule_only == 1 && is_subkey == 1) {
			return 0;
		}
	}

	if (walk_args->rule_index >= 0) {
		i = walk_args->rule_index;
	} else {
		i = 0;
	}

	for (; i < DOMAIN_RULE_MAX; i++) {
		if (domain_rule->rules[i] == NULL) {
			if (walk_args->rule_index >= 0) {
				break;
			}
			continue;
		}

		request_domain_rule->rules[i] = domain_rule->rules[i];
		request_domain_rule->is_sub_rule[i] = is_subkey;
		walk_args->key[i] = key;
		walk_args->key_len[i] = key_len;
		if (walk_args->rule_index >= 0) {
			break;
		}
	}

	/* update rules by flags */
	_dns_server_update_rule_by_flags(request_domain_rule);

	return 0;
}

static void _dns_server_get_domain_rule_by_domain_ext(struct dns_conf_group *conf,
													  struct dns_request_domain_rule *request_domain_rule,
													  int rule_index, const char *domain, int out_log)
{
	int domain_len = 0;
	char domain_key[DNS_MAX_CNAME_LEN];
	struct rule_walk_args walk_args;
	int matched_key_len = DNS_MAX_CNAME_LEN;
	unsigned char matched_key[DNS_MAX_CNAME_LEN];
	int i = 0;

	memset(&walk_args, 0, sizeof(walk_args));
	walk_args.args = request_domain_rule;
	walk_args.rule_index = rule_index;

	/* reverse domain string */
	domain_len = strlen(domain);
	if (domain_len >= (int)sizeof(domain_key) - 3) {
		return;
	}

	reverse_string(domain_key + 1, domain, domain_len, 1);
	domain_key[domain_len + 1] = '.';
	domain_key[0] = '.';
	domain_len += 2;
	domain_key[domain_len] = 0;

	/* find domain rule */
	art_substring_walk(&conf->domain_rule.tree, (unsigned char *)domain_key, domain_len, _dns_server_get_rules,
					   &walk_args);
	if (likely(dns_conf_log_level > TLOG_DEBUG) || out_log == 0) {
		return;
	}

	if (walk_args.rule_index >= 0) {
		i = walk_args.rule_index;
	} else {
		i = 0;
	}

	/* output log rule */
	for (; i < DOMAIN_RULE_MAX; i++) {
		if (walk_args.key[i] == NULL) {
			if (walk_args.rule_index >= 0) {
				break;
			}
			continue;
		}

		matched_key_len = walk_args.key_len[i];
		if (walk_args.key_len[i] >= sizeof(matched_key)) {
			continue;
		}

		memcpy(matched_key, walk_args.key[i], walk_args.key_len[i]);

		matched_key_len--;
		matched_key[matched_key_len] = 0;
		_dns_server_log_rule(domain, i, matched_key, matched_key_len);

		if (walk_args.rule_index >= 0) {
			break;
		}
	}
}

static void _dns_server_get_domain_rule_by_domain(struct dns_request *request, const char *domain, int out_log)
{
	if (request->skip_domain_rule != 0) {
		return;
	}

	if (request->conf == NULL) {
		return;
	}

	_dns_server_get_domain_rule_by_domain_ext(request->conf, &request->domain_rule, -1, domain, out_log);
	request->skip_domain_rule = 1;
}

static void _dns_server_get_domain_rule(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULES) == 0) {
		return;
	}

	_dns_server_get_domain_rule_by_domain(request, request->domain, 1);
}

static int _dns_server_pre_process_server_flags(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) == 0) {
		request->no_cache = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_IP_ALIAS) == 0) {
		request->no_ipalias = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_PREFETCH) == 0) {
		request->prefetch_flags |= PREFETCH_FLAGS_NOPREFETCH;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_SERVE_EXPIRED) == 0) {
		request->no_serve_expired = 1;
	}

	if (request->qtype == DNS_T_HTTPS && _dns_server_has_bind_flag(request, BIND_FLAG_FORCE_HTTPS_SOA) == 0) {
		_dns_server_reply_SOA(DNS_RC_NOERROR, request);
		return 0;
	}

	return -1;
}

static int _dns_server_pre_process_rule_flags(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;
	unsigned int flags = 0;
	int rcode = DNS_RC_NOERROR;

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag != NULL) {
		flags = rule_flag->flags;
	}

	if (flags & DOMAIN_FLAG_NO_SERVE_EXPIRED) {
		request->no_serve_expired = 1;
	}

	if (flags & DOMAIN_FLAG_NO_CACHE) {
		request->no_cache = 1;
	}

	if (flags & DOMAIN_FLAG_ENABLE_CACHE) {
		request->no_cache = 0;
	}

	if (flags & DOMAIN_FLAG_NO_IPALIAS) {
		request->no_ipalias = 1;
	}

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		/* ignore this domain */
		goto skip_soa_out;
	}

	/* return specific type of address */
	switch (request->qtype) {
	case DNS_T_A:
		if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
			/* ignore this domain for A request */
			goto skip_soa_out;
		}

		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL) {
			goto skip_soa_out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* if AAAA exists, return SOA with NOERROR*/
			if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL) {
				goto soa;
			}

			/* if AAAA not exists, return SOA with NXDOMAIN */
			if (_dns_server_is_return_soa_qtype(request, DNS_T_AAAA)) {
				rcode = DNS_RC_NXDOMAIN;
			}
			goto soa;
		}
		goto out;
		break;
	case DNS_T_AAAA:
		if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
			/* ignore this domain for A request */
			goto skip_soa_out;
		}

		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL) {
			goto skip_soa_out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* if A exists, return SOA with NOERROR*/
			if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL) {
				goto soa;
			}
			/* if A not exists, return SOA with NXDOMAIN */
			if (_dns_server_is_return_soa_qtype(request, DNS_T_A)) {
				rcode = DNS_RC_NXDOMAIN;
			}
			goto soa;
		}

		if (flags & DOMAIN_FLAG_ADDR_IPV4_SOA && request->dualstack_selection) {
			/* if IPV4 return SOA and dualstack-selection enabled, set request dualstack disable */
			request->dualstack_selection = 0;
		}
		goto out;
		break;
	case DNS_T_HTTPS:
		if (flags & DOMAIN_FLAG_ADDR_HTTPS_IGN) {
			/* ignore this domain for A request */
			goto skip_soa_out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* if HTTPS exists, return SOA with NOERROR*/
			if (request->domain_rule.rules[DOMAIN_RULE_HTTPS] != NULL) {
				goto soa;
			}

			if (_dns_server_is_return_soa_qtype(request, DNS_T_A) &&
				_dns_server_is_return_soa_qtype(request, DNS_T_AAAA)) {
				/* return SOA for HTTPS request */
				rcode = DNS_RC_NXDOMAIN;
				goto soa;
			}
		}

		if (request->domain_rule.rules[DOMAIN_RULE_HTTPS] != NULL) {
			goto skip_soa_out;
		}

		goto out;
		break;
	default:
		goto out;
		break;
	}

	if (_dns_server_is_return_soa(request)) {
		goto soa;
	}
skip_soa_out:
	request->skip_qtype_soa = 1;
out:
	return -1;

soa:
	/* return SOA */
	_dns_server_reply_SOA(rcode, request);
	return 0;
}

static int _dns_server_address_generate_order(int orders[], int order_num, int max_order_count)
{
	int i = 0;
	int j = 0;
	int k = 0;
	unsigned int seed = time(NULL);

	for (i = 0; i < order_num && i < max_order_count; i++) {
		orders[i] = i;
	}

	for (i = 0; i < order_num && max_order_count; i++) {
		k = rand_r(&seed) % order_num;
		j = rand_r(&seed) % order_num;
		if (j == k) {
			continue;
		}

		int temp = orders[j];
		orders[j] = orders[k];
		orders[k] = temp;
	}

	return 0;
}

static int _dns_server_process_address(struct dns_request *request)
{
	struct dns_rule_address_IPV4 *address_ipv4 = NULL;
	struct dns_rule_address_IPV6 *address_ipv6 = NULL;
	int orders[DNS_MAX_REPLY_IP_NUM];

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
		goto errout;
	}

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A:
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] == NULL) {
			goto errout;
		}
		address_ipv4 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV4);
		if (address_ipv4 == NULL) {
			goto errout;
		}
		_dns_server_address_generate_order(orders, address_ipv4->addr_num, DNS_MAX_REPLY_IP_NUM);

		memcpy(request->ip_addr, address_ipv4->ipv4_addr[orders[0]], DNS_RR_A_LEN);
		for (int i = 1; i < address_ipv4->addr_num; i++) {
			int index = orders[i];
			if (index >= address_ipv4->addr_num) {
				continue;
			}
			_dns_ip_address_check_add(request, request->cname, address_ipv4->ipv4_addr[index], DNS_T_A, 1, NULL);
		}
		break;
	case DNS_T_AAAA:
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] == NULL) {
			goto errout;
		}

		address_ipv6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV6);
		if (address_ipv6 == NULL) {
			goto errout;
		}
		_dns_server_address_generate_order(orders, address_ipv6->addr_num, DNS_MAX_REPLY_IP_NUM);

		memcpy(request->ip_addr, address_ipv6->ipv6_addr[orders[0]], DNS_RR_AAAA_LEN);
		for (int i = 1; i < address_ipv6->addr_num; i++) {
			int index = orders[i];
			if (index >= address_ipv6->addr_num) {
				continue;
			}
			_dns_ip_address_check_add(request, request->cname, address_ipv6->ipv6_addr[index], DNS_T_AAAA, 1, NULL);
		}
		break;
	default:
		goto errout;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	request->has_ip = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 1;
	context.do_ipset = 1;
	context.select_all_best_ip = 1;
	_dns_request_post(&context);

	return 0;
errout:
	return -1;
}

static struct dns_request *_dns_server_new_child_request(struct dns_request *request, const char *domain,
														 dns_type_t qtype, child_request_callback child_callback)
{
	struct dns_request *child_request = NULL;

	child_request = _dns_server_new_request();
	if (child_request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	child_request->server_flags = request->server_flags;
	safe_strncpy(child_request->dns_group_name, request->dns_group_name, sizeof(request->dns_group_name));
	safe_strncpy(child_request->domain, domain, sizeof(child_request->domain));
	child_request->prefetch = request->prefetch;
	child_request->prefetch_flags = request->prefetch_flags;
	child_request->child_callback = child_callback;
	child_request->parent_request = request;
	child_request->qtype = qtype;
	child_request->qclass = request->qclass;
	child_request->conf = request->conf;

	if (request->has_ecs) {
		memcpy(&child_request->ecs, &request->ecs, sizeof(child_request->ecs));
		child_request->has_ecs = request->has_ecs;
	}
	_dns_server_request_get(request);
	/* reference count is 1 hold by parent request */
	request->child_request = child_request;
	_dns_server_get_domain_rule(child_request);
	return child_request;
errout:
	if (child_request) {
		_dns_server_request_release(child_request);
	}

	return NULL;
}

static int _dns_server_request_copy(struct dns_request *request, struct dns_request *from)
{
	unsigned long bucket = 0;
	struct dns_ip_address *addr_map = NULL;
	struct hlist_node *tmp = NULL;
	uint32_t key = 0;
	int addr_len = 0;

	request->rcode = from->rcode;

	if (from->has_ip) {
		request->has_ip = 1;
		request->ip_ttl = _dns_server_get_conf_ttl(request, from->ip_ttl);
		request->ping_time = from->ping_time;
		memcpy(request->ip_addr, from->ip_addr, sizeof(request->ip_addr));
	}

	if (from->has_cname) {
		request->has_cname = 1;
		request->ttl_cname = from->ttl_cname;
		safe_strncpy(request->cname, from->cname, sizeof(request->cname));
	}

	if (from->has_soa) {
		request->has_soa = 1;
		memcpy(&request->soa, &from->soa, sizeof(request->soa));
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	pthread_mutex_lock(&from->ip_map_lock);
	hash_for_each_safe(from->ip_map, bucket, tmp, addr_map, node)
	{
		struct dns_ip_address *new_addr_map = NULL;

		if (addr_map->addr_type == DNS_T_A) {
			addr_len = DNS_RR_A_LEN;
		} else if (addr_map->addr_type == DNS_T_AAAA) {
			addr_len = DNS_RR_AAAA_LEN;
		} else {
			continue;
		}

		new_addr_map = malloc(sizeof(struct dns_ip_address));
		if (new_addr_map == NULL) {
			tlog(TLOG_ERROR, "malloc failed.\n");
			pthread_mutex_unlock(&from->ip_map_lock);
			return -1;
		}

		memcpy(new_addr_map, addr_map, sizeof(struct dns_ip_address));
		new_addr_map->ping_time = addr_map->ping_time;
		key = jhash(new_addr_map->ip_addr, addr_len, 0);
		key = jhash(&addr_map->addr_type, sizeof(addr_map->addr_type), key);
		pthread_mutex_lock(&request->ip_map_lock);
		hash_add(request->ip_map, &new_addr_map->node, key);
		pthread_mutex_unlock(&request->ip_map_lock);
	}
	pthread_mutex_unlock(&from->ip_map_lock);

	return 0;
}

static DNS_CHILD_POST_RESULT _dns_server_process_cname_callback(struct dns_request *request,
																struct dns_request *child_request, int is_first_resp)
{
	_dns_server_request_copy(request, child_request);
	if (child_request->rcode == DNS_RC_NOERROR && request->conf->dns_force_no_cname == 0 &&
		child_request->has_soa == 0) {
		safe_strncpy(request->cname, child_request->domain, sizeof(request->cname));
		request->has_cname = 1;
		request->ttl_cname = _dns_server_get_conf_ttl(request, child_request->ip_ttl);
	}

	return DNS_CHILD_POST_SUCCESS;
}

static int _dns_server_process_cname_pre(struct dns_request *request)
{
	struct dns_cname_rule *cname = NULL;
	struct dns_rule_flags *rule_flag = NULL;
	struct dns_request_domain_rule domain_rule;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_CNAME) == 0) {
		return 0;
	}

	if (request->has_cname_loop == 1) {
		return 0;
	}

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag != NULL) {
		if (rule_flag->flags & DOMAIN_FLAG_CNAME_IGN) {
			return 0;
		}
	}

	cname = _dns_server_get_dns_rule(request, DOMAIN_RULE_CNAME);
	if (cname == NULL) {
		return 0;
	}

	request->skip_domain_rule = 0;
	/* copy child rules */
	memcpy(&domain_rule, &request->domain_rule, sizeof(domain_rule));
	memset(&request->domain_rule, 0, sizeof(request->domain_rule));
	_dns_server_get_domain_rule_by_domain(request, cname->cname, 0);
	request->domain_rule.rules[DOMAIN_RULE_CNAME] = domain_rule.rules[DOMAIN_RULE_CNAME];
	request->domain_rule.is_sub_rule[DOMAIN_RULE_CNAME] = domain_rule.is_sub_rule[DOMAIN_RULE_CNAME];

	request->no_select_possible_ip = 1;
	request->no_cache_cname = 1;
	safe_strncpy(request->cname, cname->cname, sizeof(request->cname));

	return 0;
}

static int _dns_server_process_cname(struct dns_request *request)
{
	struct dns_cname_rule *cname = NULL;
	const char *child_group_name = NULL;
	int ret = 0;
	struct dns_rule_flags *rule_flag = NULL;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_CNAME) == 0) {
		return 0;
	}

	if (request->has_cname_loop == 1) {
		return 0;
	}

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag != NULL) {
		if (rule_flag->flags & DOMAIN_FLAG_CNAME_IGN) {
			return 0;
		}
	}

	cname = _dns_server_get_dns_rule(request, DOMAIN_RULE_CNAME);
	if (cname == NULL) {
		return 0;
	}

	tlog(TLOG_INFO, "query %s with cname %s", request->domain, cname->cname);

	struct dns_request *child_request =
		_dns_server_new_child_request(request, cname->cname, request->qtype, _dns_server_process_cname_callback);
	if (child_request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		return -1;
	}

	/* check cname rule loop */
	struct dns_request *check_request = child_request->parent_request;
	struct dns_cname_rule *child_cname = _dns_server_get_dns_rule(child_request, DOMAIN_RULE_CNAME);

	/* sub domain rule*/
	if (child_cname != NULL && strncasecmp(child_request->domain, child_cname->cname, DNS_MAX_CNAME_LEN) == 0) {
		child_request->domain_rule.rules[DOMAIN_RULE_CNAME] = NULL;
		child_request->has_cname_loop = 1;
	}

	/* loop rule */
	while (check_request != NULL && child_cname != NULL) {
		struct dns_cname_rule *check_cname = _dns_server_get_dns_rule(check_request, DOMAIN_RULE_CNAME);
		if (check_cname == NULL) {
			break;
		}

		if (strstr(child_request->domain, check_request->domain) != NULL &&
			check_request != child_request->parent_request) {
			child_request->domain_rule.rules[DOMAIN_RULE_CNAME] = NULL;
			child_request->has_cname_loop = 1;
			break;
		}

		check_request = check_request->parent_request;
	}

	child_group_name = _dns_server_get_request_server_groupname(child_request);
	if (child_group_name) {
		/* reset dns group and setup child request domain group again when do query.*/
		child_request->dns_group_name[0] = '\0';
	}

	request->request_wait++;
	ret = _dns_server_do_query(child_request, 0);
	if (ret != 0) {
		request->request_wait--;
		tlog(TLOG_ERROR, "do query %s type %d failed.\n", request->domain, request->qtype);
		goto errout;
	}

	_dns_server_request_release_complete(child_request, 0);
	return 1;

errout:

	if (child_request) {
		request->child_request = NULL;
		_dns_server_request_release(child_request);
	}

	return -1;
}

static enum DNS_CHILD_POST_RESULT
_dns_server_process_dns64_callback(struct dns_request *request, struct dns_request *child_request, int is_first_resp)
{
	unsigned long bucket = 0;
	struct dns_ip_address *addr_map = NULL;
	struct hlist_node *tmp = NULL;
	uint32_t key = 0;
	int addr_len = 0;

	if (request->has_ip == 1) {
		if (memcmp(request->ip_addr, request->conf->dns_dns64.prefix, 12) != 0) {
			return DNS_CHILD_POST_SKIP;
		}
	}

	if (child_request->qtype != DNS_T_A) {
		return DNS_CHILD_POST_FAIL;
	}

	if (child_request->has_cname == 1) {
		safe_strncpy(request->cname, child_request->cname, sizeof(request->cname));
		request->has_cname = 1;
		request->ttl_cname = child_request->ttl_cname;
	}

	if (child_request->has_ip == 0 && request->has_ip == 0) {
		request->rcode = child_request->rcode;
		if (child_request->has_soa) {
			memcpy(&request->soa, &child_request->soa, sizeof(struct dns_soa));
			request->has_soa = 1;
			return DNS_CHILD_POST_SKIP;
		}

		if (request->has_soa == 0) {
			_dns_server_setup_soa(request);
			request->has_soa = 1;
		}
		return DNS_CHILD_POST_FAIL;
	}

	if (request->has_ip == 0 && child_request->has_ip == 1) {
		request->rcode = child_request->rcode;
		memcpy(request->ip_addr, request->conf->dns_dns64.prefix, 12);
		memcpy(request->ip_addr + 12, child_request->ip_addr, 4);
		request->ip_ttl = child_request->ip_ttl;
		request->has_ip = 1;
		request->has_soa = 0;
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	pthread_mutex_lock(&child_request->ip_map_lock);
	hash_for_each_safe(child_request->ip_map, bucket, tmp, addr_map, node)
	{
		struct dns_ip_address *new_addr_map = NULL;

		if (addr_map->addr_type == DNS_T_A) {
			addr_len = DNS_RR_A_LEN;
		} else {
			continue;
		}

		new_addr_map = malloc(sizeof(struct dns_ip_address));
		if (new_addr_map == NULL) {
			tlog(TLOG_ERROR, "malloc failed.\n");
			pthread_mutex_unlock(&child_request->ip_map_lock);
			return DNS_CHILD_POST_FAIL;
		}
		memset(new_addr_map, 0, sizeof(struct dns_ip_address));

		new_addr_map->addr_type = DNS_T_AAAA;
		addr_len = DNS_RR_AAAA_LEN;
		memcpy(new_addr_map->ip_addr, request->conf->dns_dns64.prefix, 16);
		memcpy(new_addr_map->ip_addr + 12, addr_map->ip_addr, 4);

		new_addr_map->ping_time = addr_map->ping_time;
		key = jhash(new_addr_map->ip_addr, addr_len, 0);
		key = jhash(&new_addr_map->addr_type, sizeof(new_addr_map->addr_type), key);
		pthread_mutex_lock(&request->ip_map_lock);
		hash_add(request->ip_map, &new_addr_map->node, key);
		pthread_mutex_unlock(&request->ip_map_lock);
	}
	pthread_mutex_unlock(&child_request->ip_map_lock);

	if (request->dualstack_selection == 1) {
		return DNS_CHILD_POST_NO_RESPONSE;
	}

	return DNS_CHILD_POST_SKIP;
}

static int _dns_server_process_dns64(struct dns_request *request)
{
	if (_dns_server_is_dns64_request(request) == 0) {
		return 0;
	}

	tlog(TLOG_DEBUG, "query %s with dns64", request->domain);

	struct dns_request *child_request =
		_dns_server_new_child_request(request, request->domain, DNS_T_A, _dns_server_process_dns64_callback);
	if (child_request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		return -1;
	}

	request->dualstack_selection = 0;
	child_request->prefetch_flags |= PREFETCH_FLAGS_NO_DUALSTACK;
	request->request_wait++;
	int ret = _dns_server_do_query(child_request, 0);
	if (ret != 0) {
		request->request_wait--;
		tlog(TLOG_ERROR, "do query %s type %d failed.\n", request->domain, request->qtype);
		goto errout;
	}

	_dns_server_request_release_complete(child_request, 0);
	return 0;

errout:

	if (child_request) {
		request->child_request = NULL;
		_dns_server_request_release(child_request);
	}

	return -1;
}

static int _dns_server_process_https_svcb(struct dns_request *request)
{
	struct dns_https_record_rule *https_record_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_HTTPS);

	if (request->qtype != DNS_T_HTTPS) {
		return 0;
	}

	if (request->https_svcb != NULL) {
		return 0;
	}

	request->https_svcb = malloc(sizeof(*request->https_svcb));
	if (request->https_svcb == NULL) {
		return -1;
	}
	memset(request->https_svcb, 0, sizeof(*request->https_svcb));

	if (https_record_rule == NULL) {
		return 0;
	}

	if (https_record_rule->record.enable == 0) {
		return 0;
	}

	safe_strncpy(request->https_svcb->domain, request->domain, sizeof(request->https_svcb->domain));
	safe_strncpy(request->https_svcb->target, https_record_rule->record.target, sizeof(request->https_svcb->target));
	request->https_svcb->priority = https_record_rule->record.priority;
	request->https_svcb->port = https_record_rule->record.port;
	memcpy(request->https_svcb->ech, https_record_rule->record.ech, https_record_rule->record.ech_len);
	request->https_svcb->ech_len = https_record_rule->record.ech_len;
	memcpy(request->https_svcb->alpn, https_record_rule->record.alpn, sizeof(request->https_svcb->alpn));
	request->https_svcb->alpn_len = https_record_rule->record.alpn_len;
	if (https_record_rule->record.has_ipv4) {
		memcpy(request->ip_addr, https_record_rule->record.ipv4_addr, DNS_RR_A_LEN);
		request->ip_addr_type = DNS_T_A;
		request->has_ip = 1;
	} else if (https_record_rule->record.has_ipv6) {
		memcpy(request->ip_addr, https_record_rule->record.ipv6_addr, DNS_RR_AAAA_LEN);
		request->ip_addr_type = DNS_T_AAAA;
		request->has_ip = 1;
	}

	request->rcode = DNS_RC_NOERROR;

	return -1;
}

static int _dns_server_qtype_soa(struct dns_request *request)
{
	if (request->skip_qtype_soa || request->conf->soa_table == NULL) {
		return -1;
	}

	if (request->qtype >= 0 && request->qtype <= MAX_QTYPE_NUM) {
		int offset = request->qtype / 8;
		int bit = request->qtype % 8;
		if ((request->conf->soa_table[offset] & (1 << bit)) == 0) {
			return -1;
		}
	}

	_dns_server_reply_SOA(DNS_RC_NOERROR, request);
	tlog(TLOG_DEBUG, "force qtype %d soa", request->qtype);
	return 0;
}

static void _dns_server_process_speed_rule(struct dns_request *request)
{
	struct dns_domain_check_orders *check_order = NULL;
	struct dns_response_mode_rule *response_mode = NULL;

	/* get speed check mode */
	check_order = _dns_server_get_dns_rule(request, DOMAIN_RULE_CHECKSPEED);
	if (check_order != NULL) {
		request->check_order_list = check_order;
	}

	/* get response mode */
	response_mode = _dns_server_get_dns_rule(request, DOMAIN_RULE_RESPONSE_MODE);
	if (response_mode != NULL) {
		request->response_mode = response_mode->mode;
	} else {
		request->response_mode = request->conf->dns_response_mode;
	}
}

static int _dns_server_get_expired_ttl_reply(struct dns_request *request, struct dns_cache *dns_cache)
{
	int ttl = dns_cache_get_ttl(dns_cache);
	if (ttl > 0) {
		return ttl;
	}

	return request->conf->dns_serve_expired_reply_ttl;
}

static int _dns_server_process_cache_packet(struct dns_request *request, struct dns_cache *dns_cache)
{
	int ret = -1;
	struct dns_cache_packet *cache_packet = NULL;
	if (dns_cache->info.qtype != request->qtype) {
		goto out;
	}

	cache_packet = (struct dns_cache_packet *)dns_cache_get_data(dns_cache);
	if (cache_packet == NULL) {
		goto out;
	}

	int do_ipset = (dns_cache_get_ttl(dns_cache) == 0);
	if (dns_cache_is_visited(dns_cache) == 0) {
		do_ipset = 1;
	}

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.inpacket = cache_packet->data;
	context.inpacket_len = cache_packet->head.size;
	request->ping_time = dns_cache->info.speed;

	if (dns_decode(context.packet, context.packet_maxlen, cache_packet->data, cache_packet->head.size) != 0) {
		tlog(TLOG_ERROR, "decode cache failed, %d, %d", context.packet_maxlen, context.inpacket_len);
		goto out;
	}

	/* Check if records in cache contain DNSSEC, if not exist, skip cache */
	if (request->passthrough == 1) {
		if ((dns_get_OPT_option(context.packet) & DNS_OPT_FLAG_DO) == 0 && request->edns0_do == 1) {
			goto out;
		}
	}

	request->rcode = context.packet->head.rcode;
	context.do_cache = 0;
	context.do_ipset = do_ipset;
	context.do_audit = 1;
	context.do_reply = 1;
	context.reply_ttl = _dns_server_get_expired_ttl_reply(request, dns_cache);
	ret = _dns_server_reply_passthrough(&context);
out:
	if (cache_packet) {
		dns_cache_data_put((struct dns_cache_data *)cache_packet);
	}

	return ret;
}

static int _dns_server_process_cache_data(struct dns_request *request, struct dns_cache *dns_cache)
{
	int ret = -1;

	request->ping_time = dns_cache->info.speed;
	ret = _dns_server_process_cache_packet(request, dns_cache);
	if (ret != 0) {
		goto out;
	}

	return 0;
out:
	return -1;
}

static int _dns_server_process_cache(struct dns_request *request)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *dualstack_dns_cache = NULL;
	int ret = -1;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) == 0) {
		goto out;
	}

	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = request->qtype;
	cache_key.query_flag = request->server_flags;

	dns_cache = dns_cache_lookup(&cache_key);
	if (dns_cache == NULL) {
		goto out;
	}

	if (request->qtype != dns_cache->info.qtype) {
		goto out;
	}

	if (request->qtype == DNS_T_A && request->conf->dns_dualstack_ip_allow_force_AAAA == 0) {
		goto reply_cache;
	}

	if (request->qtype != DNS_T_A && request->qtype != DNS_T_AAAA) {
		goto reply_cache;
	}

	if (request->dualstack_selection) {
		int dualstack_qtype = 0;
		if (request->qtype == DNS_T_A) {
			dualstack_qtype = DNS_T_AAAA;
		} else if (request->qtype == DNS_T_AAAA) {
			dualstack_qtype = DNS_T_A;
		} else {
			goto reply_cache;
		}

		if (_dns_server_is_dns64_request(request) == 1) {
			goto reply_cache;
		}

		cache_key.qtype = dualstack_qtype;
		dualstack_dns_cache = dns_cache_lookup(&cache_key);
		if (dualstack_dns_cache == NULL && request->cname[0] != '\0') {
			cache_key.domain = request->cname;
			dualstack_dns_cache = dns_cache_lookup(&cache_key);
		}

		if (dualstack_dns_cache && (dualstack_dns_cache->info.speed > 0)) {
			if ((dualstack_dns_cache->info.speed + (request->conf->dns_dualstack_ip_selection_threshold * 10)) <
					dns_cache->info.speed ||
				dns_cache->info.speed < 0) {
				tlog(TLOG_DEBUG, "cache result: %s, qtype: %d, force %s preferred, id: %d, time1: %d, time2: %d",
					 request->domain, request->qtype, request->qtype == DNS_T_AAAA ? "IPv4" : "IPv6", request->id,
					 dns_cache->info.speed, dualstack_dns_cache->info.speed);
				request->ip_ttl = _dns_server_get_expired_ttl_reply(request, dualstack_dns_cache);
				ret = _dns_server_reply_SOA(DNS_RC_NOERROR, request);
				goto out_update_cache;
			}
		}
	}

reply_cache:
	if (dns_cache_get_ttl(dns_cache) <= 0 && request->no_serve_expired == 1) {
		goto out;
	}

	ret = _dns_server_process_cache_data(request, dns_cache);
	if (ret != 0) {
		goto out;
	}

out_update_cache:
	if (dns_cache_get_ttl(dns_cache) == 0) {
		struct dns_server_query_option dns_query_options;
		int prefetch_flags = 0;
		dns_query_options.server_flags = request->server_flags;
		dns_query_options.dns_group_name = request->dns_group_name;
		if (request->conn == NULL) {
			dns_query_options.server_flags = dns_cache_get_query_flag(dns_cache);
			dns_query_options.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
		}

		dns_query_options.ecs_enable_flag = 0;
		if (request->has_ecs) {
			dns_query_options.ecs_enable_flag |= DNS_QUEY_OPTION_ECS_DNS;
			memcpy(&dns_query_options.ecs_dns, &request->ecs, sizeof(dns_query_options.ecs_dns));
		}

		if (request->edns0_do) {
			dns_query_options.ecs_enable_flag |= DNS_QUEY_OPTION_EDNS0_DO;
			prefetch_flags |= PREFETCH_FLAGS_NOPREFETCH;
		}

		_dns_server_prefetch_request(request->domain, request->qtype, &dns_query_options, prefetch_flags);
	} else {
		dns_cache_update(dns_cache);
	}

out:
	if (dns_cache) {
		dns_cache_release(dns_cache);
	}

	if (dualstack_dns_cache) {
		dns_cache_release(dualstack_dns_cache);
		dualstack_dns_cache = NULL;
	}

	return ret;
}

void dns_server_check_ipv6_ready(void)
{
	static int do_get_conf = 0;
	static int is_icmp_check_set;
	static int is_tcp_check_set;

	if (do_get_conf == 0) {
		if (dns_conf_has_icmp_check == 1) {
			is_icmp_check_set = 1;
		}

		if (dns_conf_has_tcp_check == 1) {
			is_tcp_check_set = 1;
		}

		if (is_icmp_check_set == 0) {
			tlog(TLOG_INFO, "ICMP ping is disabled, no ipv6 icmp check feature");
		}

		do_get_conf = 1;
	}

	if (is_icmp_check_set) {
		struct ping_host_struct *check_ping = fast_ping_start(PING_TYPE_ICMP, "2001::", 1, 0, 100, NULL, NULL);
		if (check_ping) {
			fast_ping_stop(check_ping);
			is_ipv6_ready = 1;
			return;
		}

		if (errno == EADDRNOTAVAIL) {
			is_ipv6_ready = 0;
			return;
		}
	}

	if (is_tcp_check_set) {
		struct ping_host_struct *check_ping = fast_ping_start(PING_TYPE_TCP, "2001::", 1, 0, 100, NULL, NULL);
		if (check_ping) {
			fast_ping_stop(check_ping);
			is_ipv6_ready = 1;
			return;
		}

		if (errno == EADDRNOTAVAIL) {
			is_ipv6_ready = 0;
			return;
		}
	}
}

static void _dns_server_request_set_client(struct dns_request *request, struct dns_server_conn_head *conn)
{
	request->conn = conn;
	request->server_flags = conn->server_flags;
	_dns_server_conn_get(conn);
}

static int _dns_server_request_set_client_rules(struct dns_request *request, struct dns_client_rules *client_rule)
{
	if (client_rule == NULL) {
		if (_dns_server_has_bind_flag(request, BIND_FLAG_ACL) == 0 || dns_conf_acl_enable) {
			request->send_tick = get_tick_count();
			request->rcode = DNS_RC_REFUSED;
			request->no_cache = 1;
			return -1;
		}
		return 0;
	}

	tlog(TLOG_DEBUG, "match client rule.");

	if (client_rule->rules[CLIENT_RULE_GROUP]) {
		struct client_rule_group *group = (struct client_rule_group *)client_rule->rules[CLIENT_RULE_GROUP];
		if (group && group->group_name[0] != '\0') {
			safe_strncpy(request->dns_group_name, group->group_name, sizeof(request->dns_group_name));
		}
	}

	if (client_rule->rules[CLIENT_RULE_FLAGS]) {
		struct client_rule_flags *flags = (struct client_rule_flags *)client_rule->rules[CLIENT_RULE_FLAGS];
		if (flags) {
			request->server_flags = flags->flags;
		}
	}

	return 0;
}

static void _dns_server_request_set_id(struct dns_request *request, unsigned short id)
{
	request->id = id;
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

static int _dns_server_process_smartdns_domain(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;
	unsigned int flags = 0;

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag == NULL) {
		return -1;
	}

	if (_dns_server_is_dns_rule_extract_match(request, DOMAIN_RULE_FLAGS) == 0) {
		return -1;
	}

	flags = rule_flag->flags;
	if (!(flags & DOMAIN_FLAG_SMARTDNS_DOMAIN)) {
		return -1;
	}

	return _dns_server_reply_request_eth_ip(request);
}

static int _dns_server_process_ptr_query(struct dns_request *request)
{
	if (request->qtype != DNS_T_PTR) {
		return -1;
	}

	if (_dns_server_process_ptr(request) == 0) {
		return 0;
	}

	request->passthrough = 1;
	return -1;
}

static int _dns_server_process_special_query(struct dns_request *request)
{
	int ret = 0;

	switch (request->qtype) {
	case DNS_T_PTR:
		break;
	case DNS_T_SRV:
		ret = _dns_server_process_srv(request);
		if (ret == 0) {
			goto clean_exit;
		} else {
			/* pass to upstream server */
			request->passthrough = 1;
		}
	case DNS_T_HTTPS:
		break;
	case DNS_T_SVCB:
		ret = _dns_server_process_svcb(request);
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
		break;
	default:
		tlog(TLOG_DEBUG, "unsupported qtype: %d, domain: %s", request->qtype, request->domain);
		request->passthrough = 1;
		/* pass request to upstream server */
		break;
	}

	return -1;
clean_exit:
	return 0;
}

static const char *_dns_server_get_request_server_groupname(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_NAMESERVER) == 0) {
		return NULL;
	}

	/* Get the nameserver rule */
	if (request->domain_rule.rules[DOMAIN_RULE_NAMESERVER]) {
		struct dns_nameserver_rule *nameserver_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_NAMESERVER);
		return nameserver_rule->group_name;
	}

	return NULL;
}

static void _dns_server_check_set_passthrough(struct dns_request *request)
{
	if (request->check_order_list->orders[0].type == DOMAIN_CHECK_NONE) {
		request->passthrough = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_SPEED_CHECK) == 0) {
		request->passthrough = 1;
	}

	if (is_ipv6_ready == 0 && request->qtype == DNS_T_AAAA) {
		request->passthrough = 1;
	}

	if (request->passthrough == 1) {
		request->dualstack_selection = 0;
	}

	if (request->passthrough == 1 &&
		(request->qtype == DNS_T_A || request->qtype == DNS_T_AAAA || request->qtype == DNS_T_HTTPS) &&
		request->edns0_do == 0) {
		request->passthrough = 2;
	}
}

static int _dns_server_process_host(struct dns_request *request)
{
	uint32_t key = 0;
	struct dns_hosts *host = NULL;
	struct dns_hosts *host_tmp = NULL;
	int dns_type = request->qtype;

	if (dns_hosts_record_num <= 0) {
		return -1;
	}

	key = hash_string_case(request->domain);
	key = jhash(&dns_type, sizeof(dns_type), key);
	hash_for_each_possible(dns_hosts_table.hosts, host_tmp, node, key)
	{
		if (host_tmp->dns_type != dns_type) {
			continue;
		}

		if (strncasecmp(host_tmp->domain, request->domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		host = host_tmp;
		break;
	}

	if (host == NULL) {
		return -1;
	}

	if (host->is_soa) {
		request->has_soa = 1;
		return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
	}

	switch (request->qtype) {
	case DNS_T_A:
		memcpy(request->ip_addr, host->ipv4_addr, DNS_RR_A_LEN);
		break;
	case DNS_T_AAAA:
		memcpy(request->ip_addr, host->ipv6_addr, DNS_RR_AAAA_LEN);
		break;
	default:
		goto errout;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = dns_conf_local_ttl;
	request->has_ip = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 1;
	_dns_request_post(&context);

	return 0;
errout:
	return -1;
}

static int _dns_server_setup_query_option(struct dns_request *request, struct dns_query_options *options)
{
	options->enable_flag = 0;

	if (request->has_ecs) {
		memcpy(&options->ecs_dns, &request->ecs, sizeof(options->ecs_dns));
		options->enable_flag |= DNS_QUEY_OPTION_ECS_DNS;
	}

	if (request->edns0_do) {
		options->enable_flag |= DNS_QUEY_OPTION_EDNS0_DO;
	}
	options->conf_group_name = request->dns_group_name;
	return 0;
}

static void _dns_server_mdns_query_setup_server_group(struct dns_request *request, const char **group_name)
{
	if (request->is_mdns_lookup == 0 || group_name == NULL) {
		return;
	}

	*group_name = DNS_SERVER_GROUP_MDNS;
	safe_strncpy(request->dns_group_name, *group_name, sizeof(request->dns_group_name));
	return;
}

static int _dns_server_mdns_query_setup(struct dns_request *request, const char *server_group_name,
										char **request_domain, char *domain_buffer, int domain_buffer_len)
{

	if (dns_conf_mdns_lookup != 1) {
		return 0;
	}

	switch (request->qtype) {
	case DNS_T_A:
	case DNS_T_AAAA:
	case DNS_T_SRV:
		if (request->domain[0] != '\0' && strstr(request->domain, ".") == NULL) {
			snprintf(domain_buffer, domain_buffer_len, "%s.%s", request->domain, DNS_SERVER_GROUP_LOCAL);
			*request_domain = domain_buffer;
			_dns_server_set_request_mdns(request);
		}

		if (server_group_name != NULL && strncmp(server_group_name, DNS_SERVER_GROUP_MDNS, DNS_GROUP_NAME_LEN) == 0) {
			_dns_server_set_request_mdns(request);
		}
		break;
	default:
		break;
	}

	return 0;
}

static int _dns_server_query_dualstack(struct dns_request *request)
{
	int ret = -1;
	struct dns_request *request_dualstack = NULL;
	dns_type_t qtype = request->qtype;

	if (request->dualstack_selection == 0) {
		return 0;
	}

	if (qtype == DNS_T_A) {
		qtype = DNS_T_AAAA;
	} else if (qtype == DNS_T_AAAA) {
		qtype = DNS_T_A;
	} else {
		return 0;
	}

	request_dualstack = _dns_server_new_request();
	if (request_dualstack == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	request_dualstack->server_flags = request->server_flags;
	safe_strncpy(request_dualstack->dns_group_name, request->dns_group_name, sizeof(request->dns_group_name));
	safe_strncpy(request_dualstack->domain, request->domain, sizeof(request->domain));
	request_dualstack->qtype = qtype;
	request_dualstack->dualstack_selection_query = 1;
	request_dualstack->has_cname_loop = request->has_cname_loop;
	request_dualstack->prefetch = request->prefetch;
	request_dualstack->prefetch_flags = request->prefetch_flags;
	request_dualstack->conf = request->conf;
	_dns_server_request_get(request);
	request_dualstack->dualstack_request = request;
	_dns_server_request_set_callback(request_dualstack, dns_server_dualstack_callback, request);
	request->request_wait++;
	ret = _dns_server_do_query(request_dualstack, 0);
	if (ret != 0) {
		request->request_wait--;
		tlog(TLOG_ERROR, "do query %s type %d failed.\n", request->domain, qtype);
		goto errout;
	}

	_dns_server_request_release(request_dualstack);
	return ret;
errout:
	if (request_dualstack) {
		_dns_server_request_set_callback(request_dualstack, NULL, NULL);
		_dns_server_request_release(request_dualstack);
	}

	_dns_server_request_release(request);

	return ret;
}

static int _dns_server_setup_request_conf_pre(struct dns_request *request)
{
	struct dns_conf_group *rule_group = NULL;
	struct dns_request_domain_rule domain_rule;

	if (request->skip_domain_rule != 0 && request->conf) {
		return 0;
	}

	rule_group = dns_server_get_rule_group(request->dns_group_name);
	if (rule_group == NULL) {
		return -1;
	}

	request->conf = rule_group;
	memset(&domain_rule, 0, sizeof(domain_rule));
	_dns_server_get_domain_rule_by_domain_ext(rule_group, &domain_rule, DOMAIN_RULE_GROUP, request->domain, 1);
	if (domain_rule.rules[DOMAIN_RULE_GROUP] == NULL) {
		return 0;
	}

	struct dns_group_rule *group_rule = _dns_server_get_dns_rule_ext(&domain_rule, DOMAIN_RULE_GROUP);
	if (group_rule == NULL) {
		return 0;
	}
	rule_group = dns_server_get_rule_group(group_rule->group_name);
	if (rule_group == NULL) {
		return 0;
	}

	request->conf = rule_group;
	safe_strncpy(request->dns_group_name, rule_group->group_name, sizeof(request->dns_group_name));
	tlog(TLOG_DEBUG, "domain %s match group %s", request->domain, rule_group->group_name);

	return 0;
}

static int _dns_server_setup_request_conf(struct dns_request *request)
{
	struct dns_conf_group *rule_group = NULL;

	rule_group = dns_server_get_rule_group(request->dns_group_name);
	if (rule_group == NULL) {
		return -1;
	}

	request->conf = rule_group;
	request->check_order_list = &rule_group->check_orders;

	return 0;
}

static void _dns_server_setup_dns_group_name(struct dns_request *request, const char **server_group_name)
{
	const char *group_name = NULL;
	const char *temp_group_name = NULL;
	if (request->conn) {
		group_name = request->conn->dns_group;
	}

	temp_group_name = _dns_server_get_request_server_groupname(request);
	if (temp_group_name != NULL) {
		group_name = temp_group_name;
	}

	if (request->dns_group_name[0] != '\0') {
		group_name = request->dns_group_name;
	} else {
		safe_strncpy(request->dns_group_name, group_name, sizeof(request->dns_group_name));
	}

	*server_group_name = group_name;
}

static int _dns_server_do_query(struct dns_request *request, int skip_notify_event)
{
	int ret = -1;
	const char *server_group_name = NULL;
	struct dns_query_options options;
	char *request_domain = request->domain;
	char domain_buffer[DNS_MAX_CNAME_LEN * 2];

	request->send_tick = get_tick_count();

	if (_dns_server_setup_request_conf_pre(request) != 0) {
		goto errout;
	}

	/* lookup domain rule */
	_dns_server_get_domain_rule(request);

	_dns_server_setup_dns_group_name(request, &server_group_name);

	if (_dns_server_setup_request_conf(request) != 0) {
		goto errout;
	}

	if (_dns_server_mdns_query_setup(request, server_group_name, &request_domain, domain_buffer,
									 sizeof(domain_buffer)) != 0) {
		goto errout;
	}

	if (_dns_server_process_cname_pre(request) != 0) {
		goto errout;
	}

	_dns_server_set_dualstack_selection(request);

	if (_dns_server_process_special_query(request) == 0) {
		goto clean_exit;
	}

	if (_dns_server_pre_process_server_flags(request) == 0) {
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

	if (_dns_server_process_https_svcb(request) != 0) {
		goto clean_exit;
	}

	if (_dns_server_process_smartdns_domain(request) == 0) {
		goto clean_exit;
	}

	if (_dns_server_process_host(request) == 0) {
		goto clean_exit;
	}

	/* process qtype soa */
	if (_dns_server_qtype_soa(request) == 0) {
		goto clean_exit;
	}

	/* process speed check rule */
	_dns_server_process_speed_rule(request);

	/* check and set passthrough */
	_dns_server_check_set_passthrough(request);

	/* process ptr */
	if (_dns_server_process_ptr_query(request) == 0) {
		goto clean_exit;
	}

	/* process cache */
	if (request->prefetch == 0 && request->dualstack_selection_query == 0) {
		_dns_server_mdns_query_setup_server_group(request, &server_group_name);
		if (_dns_server_process_cache(request) == 0) {
			goto clean_exit;
		}
	}

	ret = _dns_server_set_to_pending_list(request);
	if (ret == 0) {
		goto clean_exit;
	}

	if (_dns_server_process_cname(request) != 0) {
		goto clean_exit;
	}

	// setup options
	_dns_server_setup_query_option(request, &options);
	_dns_server_mdns_query_setup_server_group(request, &server_group_name);

	pthread_mutex_lock(&server.request_list_lock);
	if (list_empty(&server.request_list) && skip_notify_event == 1) {
		_dns_server_wakeup_thread();
	}
	list_add_tail(&request->list, &server.request_list);
	pthread_mutex_unlock(&server.request_list_lock);

	if (_dns_server_process_dns64(request) != 0) {
		goto errout;
	}

	// Get reference for DNS query
	request->request_wait++;
	_dns_server_request_get(request);
	if (dns_client_query(request_domain, request->qtype, dns_server_resolve_callback, request, server_group_name,
						 &options) != 0) {
		request->request_wait--;
		_dns_server_request_release(request);
		tlog(TLOG_DEBUG, "send dns request failed.");
		goto errout;
	}

	/* When the dual stack ip preference is enabled, both A and AAAA records are requested. */
	_dns_server_query_dualstack(request);

clean_exit:
	return 0;
errout:
	request = NULL;
	return ret;
}

static int _dns_server_check_request_supported(struct dns_request *request, struct dns_packet *packet)
{
	if (request->qclass != DNS_C_IN) {
		return -1;
	}

	if (packet->head.opcode != DNS_OP_QUERY) {
		return -1;
	}

	return 0;
}

static int _dns_server_parser_request(struct dns_request *request, struct dns_packet *packet)
{
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	int i = 0;
	int ret = 0;
	int qclass = 0;
	int qtype = DNS_T_ALL;
	char domain[DNS_MAX_CNAME_LEN];

	if (packet->head.qr != DNS_QR_QUERY) {
		goto errout;
	}

	/* get request domain and request qtype */
	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	if (rr_count > 1 || rr_count <= 0) {
		goto errout;
	}

	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		ret = dns_get_domain(rrs, domain, sizeof(domain), &qtype, &qclass);
		if (ret != 0) {
			goto errout;
		}

		// Only support one question.
		safe_strncpy(request->domain, domain, sizeof(request->domain));
		request->qtype = qtype;
		break;
	}

	request->qclass = qclass;
	if (_dns_server_check_request_supported(request, packet) != 0) {
		goto errout;
	}

	if ((dns_get_OPT_option(packet) & DNS_OPT_FLAG_DO) && packet->head.ad == 1) {
		request->edns0_do = 1;
	}

	/* get request opts */
	rr_count = 0;
	rrs = dns_get_rrs_start(packet, DNS_RRS_OPT, &rr_count);
	if (rr_count <= 0) {
		return 0;
	}

	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		switch (rrs->type) {
		case DNS_OPT_T_TCP_KEEPALIVE: {
			unsigned short idle_timeout = 0;
			ret = dns_get_OPT_TCP_KEEPALIVE(rrs, &idle_timeout);
			if (idle_timeout == 0 || ret != 0) {
				continue;
			}

			tlog(TLOG_DEBUG, "set tcp connection timeout to %u", idle_timeout);
			_dns_server_update_request_connection_timeout(request->conn, idle_timeout / 10);
		} break;
		case DNS_OPT_T_ECS:
			ret = dns_get_OPT_ECS(rrs, &request->ecs);
			if (ret != 0) {
				continue;
			}
			request->has_ecs = 1;
		default:
			break;
		}
	}

	return 0;
errout:
	request->rcode = DNS_RC_NOTIMP;
	return -1;
}

static int _dns_server_reply_format_error(struct dns_request *request, struct dns_server_conn_head *conn,
										  unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *local,
										  socklen_t local_len, struct sockaddr_storage *from, socklen_t from_len)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int decode_len = 0;
	int need_release = 0;
	int ret = -1;

	if (request == NULL) {
		decode_len = dns_decode_head_only(packet, DNS_PACKSIZE, inpacket, inpacket_len);
		if (decode_len < 0) {
			ret = -1;
			goto out;
		}

		request = _dns_server_new_request();
		if (request == NULL) {
			ret = -1;
			goto out;
		}

		need_release = 1;
		memcpy(&request->localaddr, local, local_len);
		_dns_server_request_set_client(request, conn);
		_dns_server_request_set_client_addr(request, from, from_len);
		_dns_server_request_set_id(request, packet->head.id);
	}

	request->rcode = DNS_RC_FORMERR;
	request->no_cache = 1;
	request->send_tick = get_tick_count();
	ret = 0;
out:
	if (request && need_release) {
		_dns_server_request_release(request);
	}

	return ret;
}

static int _dns_server_recv(struct dns_server_conn_head *conn, unsigned char *inpacket, int inpacket_len,
							struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
							socklen_t from_len)
{
	int decode_len = 0;
	int ret = -1;
	unsigned char packet_buff[DNS_PACKSIZE];
	char name[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_request *request = NULL;
	struct dns_client_rules *client_rules = NULL;

	/* decode packet */
	tlog(TLOG_DEBUG, "recv query packet from %s, len = %d, type = %d",
		 get_host_by_addr(name, sizeof(name), (struct sockaddr *)from), inpacket_len, conn->type);
	decode_len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (decode_len < 0) {
		tlog(TLOG_DEBUG, "decode failed.\n");
		ret = RECV_ERROR_INVALID_PACKET;
		if (dns_save_fail_packet) {
			dns_packet_save(dns_save_fail_packet_dir, "server", name, inpacket, inpacket_len);
		}
		goto errout;
	}

	if (smartdns_plugin_func_server_recv(packet, inpacket, inpacket_len, local, local_len, from, from_len) != 0) {
		return 0;
	}

	tlog(TLOG_DEBUG,
		 "request qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, "
		 "ra = "
		 "%d, rcode = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len,
		 packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra, packet->head.rcode);

	client_rules = _dns_server_get_client_rules(from, from_len);
	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	memcpy(&request->localaddr, local, local_len);
	_dns_server_request_set_client(request, conn);
	_dns_server_request_set_client_addr(request, from, from_len);
	_dns_server_request_set_id(request, packet->head.id);

	if (_dns_server_parser_request(request, packet) != 0) {
		tlog(TLOG_DEBUG, "parser request failed.");
		ret = RECV_ERROR_INVALID_PACKET;
		goto errout;
	}

	tlog(TLOG_DEBUG, "query %s from %s, qtype: %d, id: %d, query-num: %ld", request->domain, name, request->qtype,
		 request->id, atomic_read(&server.request_num));

	if (atomic_read(&server.request_num) > dns_conf_max_query_limit && dns_conf_max_query_limit > 0) {
		static time_t last_log_time = 0;
		time_t now = time(NULL);
		if (now - last_log_time > 120) {
			last_log_time = now;
			tlog(TLOG_WARN, "maximum number of dns queries reached, max: %d", dns_conf_max_query_limit);
		}
		request->rcode = DNS_RC_REFUSED;
		ret = 0;
		goto errout;
	}

	ret = _dns_server_request_set_client_rules(request, client_rules);
	if (ret != 0) {
		ret = 0;
		goto errout;
	}

	ret = _dns_server_do_query(request, 1);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "do query %s failed.\n", request->domain);
		goto errout;
	}
	_dns_server_request_release_complete(request, 0);
	return ret;
errout:
	if (ret == RECV_ERROR_INVALID_PACKET) {
		if (_dns_server_reply_format_error(request, conn, inpacket, inpacket_len, local, local_len, from, from_len) ==
			0) {
			ret = 0;
		}
	}

	if (request) {
		request->send_tick = get_tick_count();
		request->no_cache = 1;
		_dns_server_forward_request(inpacket, inpacket_len);
		_dns_server_request_release(request);
	}

	return ret;
}

static int _dns_server_setup_server_query_options(struct dns_request *request,
												  struct dns_server_query_option *server_query_option)
{
	if (server_query_option == NULL) {
		return 0;
	}

	request->server_flags = server_query_option->server_flags;
	if (server_query_option->dns_group_name) {
		safe_strncpy(request->dns_group_name, server_query_option->dns_group_name, DNS_GROUP_NAME_LEN);
	}

	if (server_query_option->ecs_enable_flag & DNS_QUEY_OPTION_ECS_DNS) {
		request->has_ecs = 1;
		memcpy(&request->ecs, &server_query_option->ecs_dns, sizeof(request->ecs));
	}

	if (server_query_option->ecs_enable_flag & DNS_QUEY_OPTION_EDNS0_DO) {
		request->edns0_do = 1;
	}

	return 0;
}

static int _dns_server_prefetch_request(char *domain, dns_type_t qtype,
										struct dns_server_query_option *server_query_option, int prefetch_flag)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	request->prefetch = 1;
	request->prefetch_flags = prefetch_flag;
	safe_strncpy(request->domain, domain, sizeof(request->domain));
	request->qtype = qtype;
	_dns_server_setup_server_query_options(request, server_query_option);
	ret = _dns_server_do_query(request, 0);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "prefetch do query %s failed.\n", request->domain);
		goto errout;
	}

	_dns_server_request_release(request);
	return ret;
errout:
	if (request) {
		_dns_server_request_release(request);
	}

	return ret;
}

int dns_server_query(const char *domain, int qtype, struct dns_server_query_option *server_query_option,
					 dns_result_callback callback, void *user_ptr)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	safe_strncpy(request->domain, domain, sizeof(request->domain));
	request->qtype = qtype;
	_dns_server_setup_server_query_options(request, server_query_option);
	_dns_server_request_set_callback(request, callback, user_ptr);
	ret = _dns_server_do_query(request, 0);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "do query %s failed.\n", domain);
		goto errout;
	}

	_dns_server_request_release_complete(request, 0);
	return ret;
errout:
	if (request) {
		_dns_server_request_set_callback(request, NULL, NULL);
		_dns_server_request_release(request);
	}

	return ret;
}

static int _dns_server_process_udp_one(struct dns_server_conn_udp *udpconn, struct epoll_event *event,
									   unsigned long now)
{
	int len = 0;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	struct sockaddr_storage local;
	socklen_t local_len = sizeof(local);
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	struct cmsghdr *cmsg = NULL;

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
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return -2;
		}
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

static int _dns_server_process_udp(struct dns_server_conn_udp *udpconn, struct epoll_event *event, unsigned long now)
{
	int count = 0;
	while (count < 32) {
		int ret = _dns_server_process_udp_one(udpconn, event, now);
		if (ret != 0) {
			if (ret == -2) {
				return 0;
			}

			return ret;
		}

		count++;
	}

	return 0;
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

static int _dns_server_update_request_connection_timeout(struct dns_server_conn_head *conn, int timeout)
{
	if (conn == NULL) {
		return -1;
	}

	if (timeout == 0) {
		return 0;
	}

	switch (conn->type) {
	case DNS_CONN_TYPE_TCP_CLIENT: {
		struct dns_server_conn_tcp_client *tcpclient = (struct dns_server_conn_tcp_client *)conn;
		tcpclient->conn_idle_timeout = timeout;
	} break;
	case DNS_CONN_TYPE_TLS_CLIENT:
	case DNS_CONN_TYPE_HTTPS_CLIENT: {
		struct dns_server_conn_tls_client *tlsclient = (struct dns_server_conn_tls_client *)conn;
		tlsclient->tcp.conn_idle_timeout = timeout;
	} break;
	default:
		break;
	}

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
	tcpclient->head.ipset_nftset_rule = tcpserver->head.ipset_nftset_rule;
	tcpclient->conn_idle_timeout = dns_conf_tcp_idle_time;

	atomic_set(&tcpclient->head.refcnt, 0);
	memcpy(&tcpclient->addr, &addr, addr_len);
	tcpclient->addr_len = addr_len;
	tcpclient->localaddr_len = sizeof(struct sockaddr_storage);
	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_ADD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	if (getsocket_inet(tcpclient->head.fd, (struct sockaddr *)&tcpclient->localaddr, &tcpclient->localaddr_len) != 0) {
		tlog(TLOG_ERROR, "get local addr failed, %s", strerror(errno));
		goto errout;
	}

	_dns_server_client_touch(&tcpclient->head);

	list_add(&tcpclient->head.list, &server.conn_list);
	_dns_server_conn_get(&tcpclient->head);

	set_sock_keepalive(fd, 30, 3, 5);

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

static ssize_t _ssl_read(struct dns_server_conn_tls_client *conn, void *buff, int num)
{
	ssize_t ret = 0;
	if (conn == NULL || buff == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	ret = SSL_read(conn->ssl, buff, num);
	pthread_mutex_unlock(&conn->ssl_lock);
	return ret;
}

static ssize_t _ssl_write(struct dns_server_conn_tls_client *conn, const void *buff, int num)
{
	ssize_t ret = 0;
	if (conn == NULL || buff == NULL || conn->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	ret = SSL_write(conn->ssl, buff, num);
	pthread_mutex_unlock(&conn->ssl_lock);
	return ret;
}

static int _ssl_get_error(struct dns_server_conn_tls_client *conn, int ret)
{
	int err = 0;
	if (conn == NULL || conn->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	err = SSL_get_error(conn->ssl, ret);
	pthread_mutex_unlock(&conn->ssl_lock);
	return err;
}

static int _ssl_do_accept(struct dns_server_conn_tls_client *conn)
{
	int err = 0;
	if (conn == NULL || conn->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	err = SSL_accept(conn->ssl);
	pthread_mutex_unlock(&conn->ssl_lock);
	return err;
}

static int _dns_server_socket_ssl_send(struct dns_server_conn_tls_client *tls_client, const void *buf, int num)
{
	int ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (tls_client->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (num < 0) {
		errno = EINVAL;
		return -1;
	}

	ret = _ssl_write(tls_client, buf, num);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error(tls_client, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_SSL:
		ssl_err = ERR_get_error();
		int ssl_reason = ERR_GET_REASON(ssl_err);
		if (ssl_reason == SSL_R_UNINITIALIZED || ssl_reason == SSL_R_PROTOCOL_IS_SHUTDOWN ||
			ssl_reason == SSL_R_BAD_LENGTH || ssl_reason == SSL_R_SHUTDOWN_WHILE_IN_INIT ||
			ssl_reason == SSL_R_BAD_WRITE_RETRY) {
			errno = EAGAIN;
			return -1;
		}

		tlog(TLOG_ERROR, "SSL write fail error no:  %s(%d)\n", ERR_reason_error_string(ssl_err), ssl_reason);
		errno = EFAULT;
		ret = -1;
		break;
	case SSL_ERROR_SYSCALL:
		tlog(TLOG_DEBUG, "SSL syscall failed, %s", strerror(errno));
		return ret;
	default:
		errno = EFAULT;
		ret = -1;
		break;
	}

	return ret;
}

static int _dns_server_socket_ssl_recv(struct dns_server_conn_tls_client *tls_client, void *buf, int num)
{
	ssize_t ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (tls_client->ssl == NULL) {
		errno = EFAULT;
		return -1;
	}

	ret = _ssl_read(tls_client, buf, num);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error(tls_client, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_SSL:
		ssl_err = ERR_get_error();
		int ssl_reason = ERR_GET_REASON(ssl_err);
		if (ssl_reason == SSL_R_UNINITIALIZED) {
			errno = EAGAIN;
			return -1;
		}

		if (ssl_reason == SSL_R_SHUTDOWN_WHILE_IN_INIT || ssl_reason == SSL_R_PROTOCOL_IS_SHUTDOWN) {
			return 0;
		}

#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
		if (ssl_reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
			return 0;
		}
#endif

		tlog(TLOG_DEBUG, "SSL read fail error no: %s(%lx), reason: %d\n", ERR_reason_error_string(ssl_err), ssl_err,
			 ssl_reason);
		errno = EFAULT;
		ret = -1;
		break;
	case SSL_ERROR_SYSCALL:
		if (errno == 0) {
			return 0;
		}

		ret = -1;
		return ret;
	default:
		errno = EFAULT;
		ret = -1;
		break;
	}

	return ret;
}

static int _dns_server_ssl_poll_event(struct dns_server_conn_tls_client *tls_client, int ssl_ret)
{
	struct epoll_event fd_event;

	memset(&fd_event, 0, sizeof(fd_event));

	if (ssl_ret == SSL_ERROR_WANT_READ) {
		fd_event.events = EPOLLIN;
	} else if (ssl_ret == SSL_ERROR_WANT_WRITE) {
		fd_event.events = EPOLLOUT | EPOLLIN;
	} else {
		goto errout;
	}

	fd_event.data.ptr = tls_client;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, tls_client->tcp.head.fd, &fd_event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _dns_server_tcp_socket_send(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len)
{
	if (tcp_client->head.type == DNS_CONN_TYPE_TCP_CLIENT) {
		return send(tcp_client->head.fd, data, data_len, MSG_NOSIGNAL);
	} else if (tcp_client->head.type == DNS_CONN_TYPE_TLS_CLIENT ||
			   tcp_client->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcp_client;
		tls_client->ssl_want_write = 0;
		int ret = _dns_server_socket_ssl_send(tls_client, data, data_len);
		if (ret < 0 && errno == EAGAIN) {
			if (_dns_server_ssl_poll_event(tls_client, SSL_ERROR_WANT_WRITE) == 0) {
				errno = EAGAIN;
			}
		}
		return ret;
	} else {
		return -1;
	}
}

static int _dns_server_tcp_socket_recv(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len)
{
	if (tcp_client->head.type == DNS_CONN_TYPE_TCP_CLIENT) {
		return recv(tcp_client->head.fd, data, data_len, MSG_NOSIGNAL);
	} else if (tcp_client->head.type == DNS_CONN_TYPE_TLS_CLIENT ||
			   tcp_client->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcp_client;
		int ret = _dns_server_socket_ssl_recv(tls_client, data, data_len);
		if (ret == -SSL_ERROR_WANT_WRITE && errno == EAGAIN) {
			if (_dns_server_ssl_poll_event(tls_client, SSL_ERROR_WANT_WRITE) == 0) {
				errno = EAGAIN;
				tls_client->ssl_want_write = 1;
			}
		}

		return ret;
	} else {
		return -1;
	}
}

static int _dns_server_tcp_recv(struct dns_server_conn_tcp_client *tcpclient)
{
	ssize_t len = 0;

	/* Receive data */
	while (tcpclient->recvbuff.size < (int)sizeof(tcpclient->recvbuff.buf)) {
		if (tcpclient->recvbuff.size == (int)sizeof(tcpclient->recvbuff.buf)) {
			return 0;
		}

		len = _dns_server_tcp_socket_recv(tcpclient, tcpclient->recvbuff.buf + tcpclient->recvbuff.size,
										  sizeof(tcpclient->recvbuff.buf) - tcpclient->recvbuff.size);
		if (len < 0) {
			if (errno == EAGAIN) {
				return RECV_ERROR_AGAIN;
			}

			if (errno == ECONNRESET) {
				return RECV_ERROR_CLOSE;
			}

			if (errno == ETIMEDOUT) {
				return RECV_ERROR_CLOSE;
			}

			tlog(TLOG_DEBUG, "recv failed, %s\n", strerror(errno));
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
	unsigned short request_len = 0;
	int total_len = tcpclient->recvbuff.size;
	int proceed_len = 0;
	unsigned char *request_data = NULL;
	int ret = RECV_ERROR_FAIL;
	int len = 0;
	struct http_head *http_head = NULL;
	uint8_t *http_decode_data = NULL;
	char *base64_query = NULL;

	/* Handling multiple requests */
	for (;;) {
		ret = RECV_ERROR_FAIL;
		if (tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
			if ((total_len - proceed_len) <= 0) {
				ret = RECV_ERROR_AGAIN;
				goto out;
			}

			http_head = http_head_init(4096);
			if (http_head == NULL) {
				goto out;
			}

			len = http_head_parse(http_head, (char *)tcpclient->recvbuff.buf, tcpclient->recvbuff.size);
			if (len < 0) {
				if (len == -1) {
					ret = 0;
					goto out;
				}

				tlog(TLOG_DEBUG, "parser http header failed.");
				goto errout;
			}

			if (http_head_get_method(http_head) == HTTP_METHOD_POST) {
				const char *content_type = http_head_get_fields_value(http_head, "Content-Type");
				if (content_type == NULL ||
					strncasecmp(content_type, "application/dns-message", sizeof("application/dns-message")) != 0) {
					tlog(TLOG_DEBUG, "content type not supported, %s", content_type);
					goto errout;
				}

				request_len = http_head_get_data_len(http_head);
				if (request_len >= len) {
					tlog(TLOG_DEBUG, "request length is invalid.");
					goto errout;
				}
				request_data = (unsigned char *)http_head_get_data(http_head);
			} else if (http_head_get_method(http_head) == HTTP_METHOD_GET) {
				const char *path = http_head_get_url(http_head);
				if (path == NULL || strncasecmp(path, "/dns-query", sizeof("/dns-query")) != 0) {
					tlog(TLOG_DEBUG, "path not supported, %s", path);
					goto errout;
				}

				const char *dns_query = http_head_get_params_value(http_head, "dns");
				if (dns_query == NULL) {
					tlog(TLOG_DEBUG, "query is null.");
					goto errout;
				}

				if (base64_query == NULL) {
					base64_query = malloc(DNS_IN_PACKSIZE);
					if (base64_query == NULL) {
						tlog(TLOG_DEBUG, "malloc failed.");
						goto errout;
					}
				}

				if (urldecode(base64_query, DNS_IN_PACKSIZE, dns_query) < 0) {
					tlog(TLOG_DEBUG, "urldecode query failed.");
					goto errout;
				}

				if (http_decode_data == NULL) {
					http_decode_data = malloc(DNS_IN_PACKSIZE);
					if (http_decode_data == NULL) {
						tlog(TLOG_DEBUG, "malloc failed.");
						goto errout;
					}
				}

				int decode_len = SSL_base64_decode_ext(base64_query, http_decode_data, DNS_IN_PACKSIZE, 1, 1);
				if (decode_len <= 0) {
					tlog(TLOG_DEBUG, "decode query failed.");
					goto errout;
				}

				request_len = decode_len;
				request_data = http_decode_data;
			} else {
				tlog(TLOG_DEBUG, "http method is invalid.");
				goto errout;
			}

			proceed_len += len;
		} else {
			if ((total_len - proceed_len) <= (int)sizeof(unsigned short)) {
				ret = RECV_ERROR_AGAIN;
				goto out;
			}

			/* Get record length */
			request_data = (unsigned char *)(tcpclient->recvbuff.buf + proceed_len);
			request_len = ntohs(*((unsigned short *)(request_data)));

			if (request_len >= sizeof(tcpclient->recvbuff.buf)) {
				tlog(TLOG_DEBUG, "request length is invalid.");
				goto errout;
			}

			if (request_len > (total_len - proceed_len - sizeof(unsigned short))) {
				ret = RECV_ERROR_AGAIN;
				goto out;
			}

			request_data = (unsigned char *)(tcpclient->recvbuff.buf + proceed_len + sizeof(unsigned short));
			proceed_len += sizeof(unsigned short) + request_len;
		}

		/* process one record */
		ret = _dns_server_recv(&tcpclient->head, request_data, request_len, &tcpclient->localaddr,
							   tcpclient->localaddr_len, &tcpclient->addr, tcpclient->addr_len);
		if (ret != 0) {
			goto errout;
		}

		if (http_head != NULL) {
			http_head_destroy(http_head);
			http_head = NULL;
		}
	}

out:
	if (total_len > proceed_len && proceed_len > 0) {
		memmove(tcpclient->recvbuff.buf, tcpclient->recvbuff.buf + proceed_len, total_len - proceed_len);
	}

	tcpclient->recvbuff.size -= proceed_len;

errout:
	if (http_head) {
		http_head_destroy(http_head);
	}

	if (http_decode_data) {
		free(http_decode_data);
	}

	if (base64_query) {
		free(base64_query);
	}

	if ((ret == RECV_ERROR_FAIL || ret == RECV_ERROR_INVALID_PACKET) &&
		tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		_dns_server_reply_http_error(tcpclient, 400, "Bad Request", "Bad Request");
	}

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
			tlog(TLOG_DEBUG, "process one request failed.");
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

static int _dns_server_tls_want_write(struct dns_server_conn_tcp_client *tcpclient)
{
	if (tcpclient->head.type == DNS_CONN_TYPE_TLS_CLIENT || tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcpclient;
		if (tls_client->ssl_want_write == 1) {
			return 1;
		}
	}

	return 0;
}

static int _dns_server_tcp_send(struct dns_server_conn_tcp_client *tcpclient)
{
	int len = 0;
	while (tcpclient->sndbuff.size > 0 || _dns_server_tls_want_write(tcpclient) == 1) {
		len = _dns_server_tcp_socket_send(tcpclient, tcpclient->sndbuff.buf, tcpclient->sndbuff.size);
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
			tlog(TLOG_DEBUG, "process tcp request failed.");
			return RECV_ERROR_FAIL;
		}
	}

	if (event->events & EPOLLOUT) {
		if (_dns_server_tcp_send(dnsserver) != 0) {
			_dns_server_client_close(&dnsserver->head);
			tlog(TLOG_DEBUG, "send tcp failed.");
			return RECV_ERROR_FAIL;
		}
	}

	return 0;
}

static int _dns_server_tls_accept(struct dns_server_conn_tls_server *tls_server, struct epoll_event *event,
								  unsigned long now)
{
	struct sockaddr_storage addr;
	struct dns_server_conn_tls_client *tls_client = NULL;
	socklen_t addr_len = sizeof(addr);
	int fd = -1;
	SSL *ssl = NULL;

	fd = accept4(tls_server->head.fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		tlog(TLOG_ERROR, "accept failed, %s", strerror(errno));
		return -1;
	}

	tls_client = malloc(sizeof(*tls_client));
	if (tls_client == NULL) {
		tlog(TLOG_ERROR, "malloc for tls_client failed.");
		goto errout;
	}
	memset(tls_client, 0, sizeof(*tls_client));

	tls_client->tcp.head.fd = fd;
	if (tls_server->head.type == DNS_CONN_TYPE_TLS_SERVER) {
		tls_client->tcp.head.type = DNS_CONN_TYPE_TLS_CLIENT;
	} else if (tls_server->head.type == DNS_CONN_TYPE_HTTPS_SERVER) {
		tls_client->tcp.head.type = DNS_CONN_TYPE_HTTPS_CLIENT;
	} else {
		tlog(TLOG_ERROR, "invalid http server type.");
		goto errout;
	}
	tls_client->tcp.head.server_flags = tls_server->head.server_flags;
	tls_client->tcp.head.dns_group = tls_server->head.dns_group;
	tls_client->tcp.head.ipset_nftset_rule = tls_server->head.ipset_nftset_rule;
	tls_client->tcp.conn_idle_timeout = dns_conf_tcp_idle_time;

	atomic_set(&tls_client->tcp.head.refcnt, 0);
	memcpy(&tls_client->tcp.addr, &addr, addr_len);
	tls_client->tcp.addr_len = addr_len;
	tls_client->tcp.localaddr_len = sizeof(struct sockaddr_storage);
	if (_dns_server_epoll_ctl(&tls_client->tcp.head, EPOLL_CTL_ADD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	if (getsocket_inet(tls_client->tcp.head.fd, (struct sockaddr *)&tls_client->tcp.localaddr,
					   &tls_client->tcp.localaddr_len) != 0) {
		tlog(TLOG_ERROR, "get local addr failed, %s", strerror(errno));
		goto errout;
	}

	ssl = SSL_new(tls_server->ssl_ctx);
	if (ssl == NULL) {
		tlog(TLOG_ERROR, "SSL_new failed.");
		goto errout;
	}

	if (SSL_set_fd(ssl, fd) != 1) {
		tlog(TLOG_ERROR, "SSL_set_fd failed.");
		goto errout;
	}

	tls_client->ssl = ssl;
	tls_client->tcp.status = DNS_SERVER_CLIENT_STATUS_CONNECTING;
	pthread_mutex_init(&tls_client->ssl_lock, NULL);
	_dns_server_client_touch(&tls_client->tcp.head);

	list_add(&tls_client->tcp.head.list, &server.conn_list);
	_dns_server_conn_get(&tls_client->tcp.head);

	set_sock_keepalive(fd, 30, 3, 5);

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	if (ssl) {
		SSL_free(ssl);
	}

	if (tls_client) {
		free(tls_client);
	}
	return -1;
}

static int _dns_server_process_tls(struct dns_server_conn_tls_client *tls_client, struct epoll_event *event,
								   unsigned long now)
{
	int ret = 0;
	int ssl_ret = 0;
	struct epoll_event fd_event;

	if (tls_client->tcp.status == DNS_SERVER_CLIENT_STATUS_CONNECTING) {
		/* do SSL hand shake */
		ret = _ssl_do_accept(tls_client);
		if (ret <= 0) {
			memset(&fd_event, 0, sizeof(fd_event));
			ssl_ret = _ssl_get_error(tls_client, ret);
			if (_dns_server_ssl_poll_event(tls_client, ssl_ret) == 0) {
				return 0;
			}

			if (ssl_ret != SSL_ERROR_SYSCALL) {
				unsigned long ssl_err = ERR_get_error();
				int ssl_reason = ERR_GET_REASON(ssl_err);
				char name[DNS_MAX_CNAME_LEN];
				tlog(TLOG_DEBUG, "Handshake with %s failed, error no: %s(%d, %d, %d)\n",
					 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&tls_client->tcp.addr),
					 ERR_reason_error_string(ssl_err), ret, ssl_ret, ssl_reason);
				ret = 0;
			}

			goto errout;
		}

		tls_client->tcp.status = DNS_SERVER_CLIENT_STATUS_CONNECTED;
		memset(&fd_event, 0, sizeof(fd_event));
		fd_event.events = EPOLLIN | EPOLLOUT;
		fd_event.data.ptr = tls_client;
		if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, tls_client->tcp.head.fd, &fd_event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			goto errout;
		}
	}

	return _dns_server_process_tcp((struct dns_server_conn_tcp_client *)tls_client, event, now);
errout:
	_dns_server_client_close(&tls_client->tcp.head);
	return ret;
}

static int _dns_server_process(struct dns_server_conn_head *conn, struct epoll_event *event, unsigned long now)
{
	int ret = 0;
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
		if (ret != 0) {
			char name[DNS_MAX_CNAME_LEN];
			tlog(TLOG_DEBUG, "process TCP packet from %s failed.",
				 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&tcpclient->addr));
		}
	} else if (conn->type == DNS_CONN_TYPE_TLS_SERVER || conn->type == DNS_CONN_TYPE_HTTPS_SERVER) {
		struct dns_server_conn_tls_server *tls_server = (struct dns_server_conn_tls_server *)conn;
		ret = _dns_server_tls_accept(tls_server, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TLS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)conn;
		ret = _dns_server_process_tls(tls_client, event, now);
		if (ret != 0) {
			char name[DNS_MAX_CNAME_LEN];
			tlog(TLOG_DEBUG, "process TLS packet from %s failed.",
				 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&tls_client->tcp.addr));
		}
	} else {
		tlog(TLOG_ERROR, "unsupported dns server type %d", conn->type);
		_dns_server_client_close(conn);
		ret = -1;
	}
	_dns_server_conn_release(conn);

	if (ret == RECV_ERROR_INVALID_PACKET) {
		ret = 0;
	}

	return ret;
}

static int _dns_server_second_ping_check(struct dns_request *request)
{
	struct dns_ip_address *addr_map = NULL;
	unsigned long bucket = 0;
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ret = -1;

	if (request->has_ping_result) {
		return ret;
	}

	/* start tcping */
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each(request->ip_map, bucket, addr_map, node)
	{
		switch (addr_map->addr_type) {
		case DNS_T_A: {
			_dns_server_request_get(request);
			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", addr_map->ip_addr[0], addr_map->ip_addr[1], addr_map->ip_addr[2],
					 addr_map->ip_addr[3]);
			ret = _dns_server_check_speed(request, ip);
			if (ret != 0) {
				_dns_server_request_release(request);
			}
		} break;
		case DNS_T_AAAA: {
			_dns_server_request_get(request);
			snprintf(ip, sizeof(ip), "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]",
					 addr_map->ip_addr[0], addr_map->ip_addr[1], addr_map->ip_addr[2], addr_map->ip_addr[3],
					 addr_map->ip_addr[4], addr_map->ip_addr[5], addr_map->ip_addr[6], addr_map->ip_addr[7],
					 addr_map->ip_addr[8], addr_map->ip_addr[9], addr_map->ip_addr[10], addr_map->ip_addr[11],
					 addr_map->ip_addr[12], addr_map->ip_addr[13], addr_map->ip_addr[14], addr_map->ip_addr[15]);
			ret = _dns_server_check_speed(request, ip);
			if (ret != 0) {
				_dns_server_request_release(request);
			}
		} break;
		default:
			break;
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	return ret;
}

static dns_cache_tmout_action_t _dns_server_prefetch_domain(struct dns_conf_group *conf_group,
															struct dns_cache *dns_cache)
{
	/* If there are still hits, continue pre-fetching */
	struct dns_server_query_option server_query_option;
	int hitnum = dns_cache_hitnum_dec_get(dns_cache);
	if (hitnum <= 0) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG, "prefetch by cache %s, qtype %d, ttl %d, hitnum %d", dns_cache->info.domain, dns_cache->info.qtype,
		 dns_cache->info.ttl, hitnum);
	server_query_option.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
	server_query_option.server_flags = dns_cache_get_query_flag(dns_cache);
	server_query_option.ecs_enable_flag = 0;
	if (_dns_server_prefetch_request(dns_cache->info.domain, dns_cache->info.qtype, &server_query_option,
									 PREFETCH_FLAGS_NO_DUALSTACK) != 0) {
		tlog(TLOG_ERROR, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
		return DNS_CACHE_TMOUT_ACTION_RETRY;
	}

	return DNS_CACHE_TMOUT_ACTION_OK;
}

static dns_cache_tmout_action_t _dns_server_prefetch_expired_domain(struct dns_conf_group *conf_group,
																	struct dns_cache *dns_cache)
{
	time_t ttl = _dns_server_expired_cache_ttl(dns_cache, conf_group->dns_serve_expired_ttl);
	if (ttl <= 1) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG,
		 "expired domain, total %d, prefetch by cache %s, qtype %d, ttl %llu, rcode %d, insert time %llu replace time "
		 "%llu",
		 dns_cache_total_num(), dns_cache->info.domain, dns_cache->info.qtype, (unsigned long long)ttl,
		 dns_cache->info.rcode, (unsigned long long)dns_cache->info.insert_time,
		 (unsigned long long)dns_cache->info.replace_time);

	struct dns_server_query_option server_query_option;
	server_query_option.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
	server_query_option.server_flags = dns_cache_get_query_flag(dns_cache);
	server_query_option.ecs_enable_flag = 0;

	if (_dns_server_prefetch_request(dns_cache->info.domain, dns_cache->info.qtype, &server_query_option,
									 PREFETCH_FLAGS_EXPIRED) != 0) {
		tlog(TLOG_DEBUG, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
		return DNS_CACHE_TMOUT_ACTION_RETRY;
	}

	return DNS_CACHE_TMOUT_ACTION_OK;
}

static dns_cache_tmout_action_t _dns_server_cache_expired(struct dns_cache *dns_cache)
{
	if (dns_cache->info.rcode != DNS_RC_NOERROR) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	struct dns_conf_group *conf_group = dns_server_get_rule_group(dns_cache->info.dns_group_name);

	if (conf_group->dns_prefetch == 1) {
		if (conf_group->dns_serve_expired == 1) {
			return _dns_server_prefetch_expired_domain(conf_group, dns_cache);
		} else {
			return _dns_server_prefetch_domain(conf_group, dns_cache);
		}
	}

	return DNS_CACHE_TMOUT_ACTION_DEL;
}

static void _dns_server_tcp_idle_check(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;
	time_t now = 0;

	time(&now);
	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		if (conn->type != DNS_CONN_TYPE_TCP_CLIENT && conn->type != DNS_CONN_TYPE_TLS_CLIENT &&
			conn->type != DNS_CONN_TYPE_HTTPS_CLIENT) {
			continue;
		}

		struct dns_server_conn_tcp_client *tcpclient = (struct dns_server_conn_tcp_client *)conn;

		if (tcpclient->conn_idle_timeout <= 0) {
			continue;
		}

		if (conn->last_request_time > now - tcpclient->conn_idle_timeout) {
			continue;
		}

		_dns_server_client_close(conn);
	}
}

#ifdef TEST
static void _dns_server_check_need_exit(void)
{
	static int parent_pid = 0;
	if (parent_pid == 0) {
		parent_pid = getppid();
	}

	if (parent_pid != getppid()) {
		tlog(TLOG_WARN, "parent process exit, exit too.");
		dns_server_stop();
	}
}
#else
#define _dns_server_check_need_exit()
#endif

static void _dns_server_save_cache_to_file(void)
{
	time_t now;
	int check_time = dns_conf_cache_checkpoint_time;

	if (dns_conf_cache_persist == 0 || dns_conf_cachesize <= 0 || dns_conf_cache_checkpoint_time <= 0) {
		return;
	}

	time(&now);
	if (server.cache_save_pid > 0) {
		int ret = waitpid(server.cache_save_pid, NULL, WNOHANG);
		if (ret == server.cache_save_pid) {
			server.cache_save_pid = 0;
		} else if (ret < 0) {
			tlog(TLOG_ERROR, "waitpid failed, errno %d, error info '%s'", errno, strerror(errno));
			server.cache_save_pid = 0;
		} else {
			if (now - 30 > server.cache_save_time) {
				kill(server.cache_save_pid, SIGKILL);
			}
			return;
		}
	}

	if (check_time < 120) {
		check_time = 120;
	}

	if (now - check_time < server.cache_save_time) {
		return;
	}

	/* server is busy, skip*/
	pthread_mutex_lock(&server.request_list_lock);
	if (list_empty(&server.request_list) != 0) {
		pthread_mutex_unlock(&server.request_list_lock);
		return;
	}
	pthread_mutex_unlock(&server.request_list_lock);

	server.cache_save_time = now;

	int pid = fork();
	if (pid == 0) {
		/* child process */
		for (int i = 3; i < 1024; i++) {
			close(i);
		}

		tlog_setlevel(TLOG_OFF);
		_dns_server_cache_save(1);
		_exit(0);
	} else if (pid < 0) {
		tlog(TLOG_DEBUG, "fork failed, errno %d, error info '%s'", errno, strerror(errno));
		return;
	}

	server.cache_save_pid = pid;
}

static void _dns_server_period_run_second(void)
{
	static unsigned int sec = 0;
	sec++;

	_dns_server_tcp_idle_check();
	_dns_server_check_need_exit();

	if (sec % IPV6_READY_CHECK_TIME == 0 && is_ipv6_ready == 0) {
		dns_server_check_ipv6_ready();
	}

	if (sec % 60 == 0) {
		if (dns_server_check_update_hosts() == 0) {
			tlog(TLOG_INFO, "Update host file data");
		}
	}

	_dns_server_save_cache_to_file();
}

static void _dns_server_period_run(unsigned int msec)
{
	struct dns_request *request = NULL;
	struct dns_request *tmp = NULL;
	LIST_HEAD(check_list);

	if ((msec % 10) == 0) {
		_dns_server_period_run_second();
	}

	unsigned long now = get_tick_count();

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		/* Need to use tcping detection speed */
		int check_order = request->check_order + 1;
		if (atomic_read(&request->ip_map_num) == 0 || request->has_soa) {
			continue;
		}

		if (request->send_tick < now - (check_order * DNS_PING_CHECK_INTERVAL) && request->has_ping_result == 0) {
			_dns_server_request_get(request);
			list_add_tail(&request->check_list, &check_list);
			request->check_order++;
		}
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &check_list, check_list)
	{
		_dns_server_second_ping_check(request);
		list_del_init(&request->check_list);
		_dns_server_request_release(request);
	}
}

static void _dns_server_close_socket(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;

	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		_dns_server_client_close(conn);
	}
}

static void _dns_server_close_socket_server(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;

	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		switch (conn->type) {
		case DNS_CONN_TYPE_HTTPS_SERVER:
		case DNS_CONN_TYPE_TLS_SERVER: {
			struct dns_server_conn_tls_server *tls_server = (struct dns_server_conn_tls_server *)conn;
			if (tls_server->ssl_ctx) {
				SSL_CTX_free(tls_server->ssl_ctx);
				tls_server->ssl_ctx = NULL;
			}
			_dns_server_client_close(conn);
			break;
		}
		case DNS_CONN_TYPE_UDP_SERVER:
		case DNS_CONN_TYPE_TCP_SERVER:
			_dns_server_client_close(conn);
			break;
		default:
			break;
		}
	}
}

int dns_server_run(void)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	unsigned long last = {0};
	unsigned int msec = 0;
	int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;

	sleep_time = sleep;
	now = get_tick_count() - sleep;
	last = now;
	expect_time = now + sleep;
	while (atomic_read(&server.run)) {
		now = get_tick_count();
		if (sleep_time > 0) {
			sleep_time -= now - last;
			if (sleep_time <= 0) {
				sleep_time = 0;
			}

			int cnt = sleep_time / sleep;
			msec -= cnt;
			expect_time -= cnt * sleep;
			sleep_time -= cnt * sleep;
		}

		if (now >= expect_time) {
			msec++;
			if (last != now) {
				_dns_server_period_run(msec);
			}
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}

			/* When server is idle, the sleep time is 1000ms, to reduce CPU usage */
			pthread_mutex_lock(&server.request_list_lock);
			if (list_empty(&server.request_list)) {
				int cnt = 10 - (msec % 10) - 1;
				sleep_time += sleep * cnt;
				msec += cnt;
				/* sleep to next second */
				expect_time += sleep * cnt;
			}
			pthread_mutex_unlock(&server.request_list_lock);
			expect_time += sleep;
		}
		last = now;

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
			/* read event */
			if (unlikely(event->data.fd == server.event_fd)) {
				uint64_t value;
				int unused __attribute__((unused));
				unused = read(server.event_fd, &value, sizeof(uint64_t));
				continue;
			}

			if (unlikely(event->data.fd == server.local_addr_cache.fd_netlink)) {
				_dns_server_process_local_addr_cache(event->data.fd, event, now);
				continue;
			}

			struct dns_server_conn_head *conn_head = event->data.ptr;
			if (conn_head == NULL) {
				tlog(TLOG_ERROR, "invalid fd\n");
				continue;
			}

			if (_dns_server_process(conn_head, event, now) != 0) {
				tlog(TLOG_DEBUG, "dns server process failed.");
			}
		}
	}

	_dns_server_close_socket_server();
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
	const int s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		const char *error_str;
		if (s == EAI_SYSTEM) {
			error_str = strerror(errno);
		} else {
			error_str = gai_strerror(s);
		}
		tlog(TLOG_ERROR, "get addr info failed. %s.\n", error_str);
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
	char port_str[16];
	char ip[MAX_IP_LEN];
	char host_ip_device[MAX_IP_LEN * 2];
	int port = 0;
	char *host = NULL;
	int optval = 1;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;
	const char *ifname = NULL;

	safe_strncpy(host_ip_device, host_ip, sizeof(host_ip_device));
	ifname = strstr(host_ip_device, "@");
	if (ifname) {
		*(char *)ifname = '\0';
		ifname++;
	}

	if (parse_ip(host_ip_device, ip, &port) == 0) {
		host = ip;
	}

	if (port <= 0) {
		port = DEFAULT_DNS_PORT;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);
	gai = _dns_server_getaddr(host, port_str, type, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed.");
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
		/* enable TCP_FASTOPEN */
		setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	} else {
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval));
	}
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_socket_buff_size, sizeof(dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_socket_buff_size, sizeof(dns_socket_buff_size));
	}

	if (ifname != NULL) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
			tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
			goto errout;
		}
	}

	if (bind(fd, gai->ai_addr, gai->ai_addrlen) != 0) {
		tlog(TLOG_ERROR, "bind service %s failed, %s\n", host_ip, strerror(errno));
		goto errout;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 256) != 0) {
			tlog(TLOG_ERROR, "listen failed.\n");
			goto errout;
		}
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	freeaddrinfo(gai);

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}

	if (gai) {
		freeaddrinfo(gai);
	}

	tlog(TLOG_ERROR, "add server failed, host-ip: %s, type: %d", host_ip, type);
	return -1;
}

static int _dns_server_set_flags(struct dns_server_conn_head *head, struct dns_bind_ip *bind_ip)
{
	time(&head->last_request_time);
	head->server_flags = bind_ip->flags;
	head->dns_group = bind_ip->group;
	head->ipset_nftset_rule = &bind_ip->nftset_ipset_rule;
	atomic_set(&head->refcnt, 0);
	list_add(&head->list, &server.conn_list);

	return 0;
}

static int _dns_server_socket_udp(struct dns_bind_ip *bind_ip)
{
	const char *host_ip = NULL;
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
	const char *host_ip = NULL;
	struct dns_server_conn_tcp_server *conn = NULL;
	int fd = -1;
	const int on = 1;

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

	setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &on, sizeof(on));

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

static int _dns_server_socket_tls_ssl_pass_callback(char *buf, int size, int rwflag, void *userdata)
{
	struct dns_bind_ip *bind_ip = userdata;
	if (bind_ip->ssl_cert_key_pass == NULL || bind_ip->ssl_cert_key_pass[0] == '\0') {
		return 0;
	}
	safe_strncpy(buf, bind_ip->ssl_cert_key_pass, size);
	return strlen(buf);
}

static int _dns_server_socket_tls(struct dns_bind_ip *bind_ip, DNS_CONN_TYPE conn_type)
{
	const char *host_ip = NULL;
	const char *ssl_cert_file = NULL;
	const char *ssl_cert_key_file = NULL;

	struct dns_server_conn_tls_server *conn = NULL;
	int fd = -1;
	const SSL_METHOD *method = NULL;
	SSL_CTX *ssl_ctx = NULL;
	const int on = 1;

	host_ip = bind_ip->ip;
	ssl_cert_file = bind_ip->ssl_cert_file;
	ssl_cert_key_file = bind_ip->ssl_cert_key_file;

	if (ssl_cert_file == NULL || ssl_cert_key_file == NULL) {
		tlog(TLOG_WARN, "no cert or cert key file");
		goto errout;
	}

	if (ssl_cert_file[0] == '\0' || ssl_cert_key_file[0] == '\0') {
		tlog(TLOG_WARN, "no cert or cert key file");
		goto errout;
	}

	conn = malloc(sizeof(struct dns_server_conn_tls_server));
	if (conn == NULL) {
		goto errout;
	}
	INIT_LIST_HEAD(&conn->head.list);

	fd = _dns_create_socket(host_ip, SOCK_STREAM);
	if (fd <= 0) {
		goto errout;
	}

	setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &on, sizeof(on));

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	method = TLS_server_method();
	if (method == NULL) {
		goto errout;
	}
#else
	method = SSLv23_server_method();
#endif

	ssl_ctx = SSL_CTX_new(method);
	if (ssl_ctx == NULL) {
		goto errout;
	}

	SSL_CTX_set_session_cache_mode(ssl_ctx,
								   SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_NO_AUTO_CLEAR);
	SSL_CTX_set_default_passwd_cb(ssl_ctx, _dns_server_socket_tls_ssl_pass_callback);
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, bind_ip);

	/* Set the key and cert */
	if (ssl_cert_file[0] != '\0' && SSL_CTX_use_certificate_chain_file(ssl_ctx, ssl_cert_file) <= 0) {
		tlog(TLOG_ERROR, "load cert %s failed, %s", ssl_cert_file, ERR_error_string(ERR_get_error(), NULL));
		goto errout;
	}

	if (ssl_cert_key_file[0] != '\0' &&
		SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_cert_key_file, SSL_FILETYPE_PEM) <= 0) {
		tlog(TLOG_ERROR, "load cert key %s failed, %s", ssl_cert_key_file, ERR_error_string(ERR_get_error(), NULL));
		goto errout;
	}

	conn->head.type = conn_type;
	conn->head.fd = fd;
	conn->ssl_ctx = ssl_ctx;
	_dns_server_set_flags(&conn->head, bind_ip);
	_dns_server_conn_get(&conn->head);

	return 0;
errout:
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}

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
		tlog(TLOG_INFO, "bind ip %s, type %d", bind_ip->ip, bind_ip->type);

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
		case DNS_BIND_TYPE_HTTPS:
			if (_dns_server_socket_tls(bind_ip, DNS_CONN_TYPE_HTTPS_SERVER) != 0) {
				goto errout;
			}
			break;
		case DNS_BIND_TYPE_TLS:
			if (_dns_server_socket_tls(bind_ip, DNS_CONN_TYPE_TLS_SERVER) != 0) {
				goto errout;
			}
			break;
		default:
			break;
		}
	}

	return 0;
errout:

	return -1;
}

static int _dns_server_audit_syslog(struct tlog_log *log, const char *buff, int bufflen)
{
	syslog(LOG_INFO, "%.*s", bufflen, buff);
	return 0;
}

static int _dns_server_audit_init(void)
{
	char *audit_file = SMARTDNS_AUDIT_FILE;
	unsigned int tlog_flag = 0;

	if (dns_conf_audit_enable == 0) {
		return 0;
	}

	if (dns_conf_audit_file[0] != 0) {
		audit_file = dns_conf_audit_file;
	}

	if (dns_conf_audit_syslog) {
		tlog_flag |= TLOG_SEGMENT;
	}

	dns_audit = tlog_open(audit_file, dns_conf_audit_size, dns_conf_audit_num, 0, tlog_flag);
	if (dns_audit == NULL) {
		return -1;
	}

	if (dns_conf_audit_syslog) {
		tlog_reg_output_func(dns_audit, _dns_server_audit_syslog);
	}

	if (dns_conf_audit_file_mode > 0) {
		tlog_set_permission(dns_audit, dns_conf_audit_file_mode, dns_conf_audit_file_mode);
	}

	if (dns_conf_audit_console != 0) {
		tlog_logscreen(dns_audit, 1);
	}

	return 0;
}

static void _dns_server_neighbor_cache_remove_all(void)
{
	struct neighbor_cache_item *item = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long bucket = 0;

	hash_for_each_safe(server.neighbor_cache.cache, bucket, tmp, item, node)
	{
		_dns_server_neighbor_cache_free_item(item);
	}

	pthread_mutex_destroy(&server.neighbor_cache.lock);
}

static int _dns_server_neighbor_cache_init(void)
{
	hash_init(server.neighbor_cache.cache);
	INIT_LIST_HEAD(&server.neighbor_cache.list);
	atomic_set(&server.neighbor_cache.cache_num, 0);
	pthread_mutex_init(&server.neighbor_cache.lock, NULL);

	return 0;
}

static void _dns_server_local_addr_cache_item_free(radix_node_t *node, void *cbctx)
{
	struct local_addr_cache_item *cache_item = NULL;
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	cache_item = node->data;
	free(cache_item);
	node->data = NULL;
}

static int _dns_server_local_addr_cache_destroy(void)
{
	if (server.local_addr_cache.addr) {
		Destroy_Radix(server.local_addr_cache.addr, _dns_server_local_addr_cache_item_free, NULL);
		server.local_addr_cache.addr = NULL;
	}

	if (server.local_addr_cache.fd_netlink > 0) {
		close(server.local_addr_cache.fd_netlink);
		server.local_addr_cache.fd_netlink = -1;
	}

	return 0;
}

static int _dns_server_local_addr_cache_init(void)
{
	int fd = 0;
	struct sockaddr_nl sa;

	server.local_addr_cache.fd_netlink = -1;
	server.local_addr_cache.addr = NULL;

	if (dns_conf_local_ptr_enable == 0) {
		return 0;
	}

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		tlog(TLOG_WARN, "create netlink socket failed, %s", strerror(errno));
		goto errout;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_IFADDR;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		tlog(TLOG_WARN, "bind netlink socket failed, %s", strerror(errno));
		goto errout;
	}

	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLERR;
	event.data.fd = fd;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "set eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	server.local_addr_cache.fd_netlink = fd;
	server.local_addr_cache.addr = New_Radix();

	struct {
		struct nlmsghdr nh;
		struct rtgenmsg gen;
	} request;

	memset(&request, 0, sizeof(request));
	request.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	request.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.nh.nlmsg_type = RTM_GETADDR;
	request.gen.rtgen_family = AF_UNSPEC;

	if (send(fd, &request, request.nh.nlmsg_len, 0) < 0) {
		tlog(TLOG_WARN, "send netlink request failed, %s", strerror(errno));
		goto errout;
	}

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

static int _dns_server_cache_init(void)
{
	if (dns_cache_init(dns_conf_cachesize, dns_conf_cache_max_memsize, _dns_server_cache_expired) != 0) {
		tlog(TLOG_ERROR, "init cache failed.");
		return -1;
	}

	const char *dns_cache_file = dns_conf_get_cache_dir();
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

static int _dns_server_cache_save(int check_lock)
{
	const char *dns_cache_file = dns_conf_get_cache_dir();

	if (dns_conf_cache_persist == 0 || dns_conf_cachesize <= 0) {
		if (access(dns_cache_file, F_OK) == 0) {
			unlink(dns_cache_file);
		}
		return 0;
	}

	if (dns_cache_save(dns_cache_file, check_lock) != 0) {
		tlog(TLOG_WARN, "save cache failed.");
		return -1;
	}

	return 0;
}

static int _dns_server_init_wakeup_event(void)
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
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, fdevent, &event) != 0) {
		tlog(TLOG_ERROR, "set eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	server.event_fd = fdevent;

	return 0;
errout:
	return -1;
}

int dns_server_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret = -1;

	_dns_server_check_need_exit();

	if (is_server_init == 1) {
		return -1;
	}

	if (server.epoll_fd > 0) {
		return -1;
	}

	if (_dns_server_audit_init() != 0) {
		tlog(TLOG_ERROR, "init audit failed.");
		goto errout;
	}

	memset(&server, 0, sizeof(server));
	pthread_attr_init(&attr);
	INIT_LIST_HEAD(&server.conn_list);
	time(&server.cache_save_time);
	atomic_set(&server.request_num, 0);
	pthread_mutex_init(&server.request_list_lock, NULL);
	INIT_LIST_HEAD(&server.request_list);

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

	server.epoll_fd = epollfd;
	atomic_set(&server.run, 1);

	if (dns_server_start() != 0) {
		tlog(TLOG_ERROR, "start service failed.\n");
		goto errout;
	}

	dns_server_check_ipv6_ready();
	tlog(TLOG_INFO, "%s",
		 (is_ipv6_ready) ? "IPV6 is ready, enable IPV6 features"
						 : "IPV6 is not ready or speed check is disabled, disable IPV6 features");

	if (_dns_server_init_wakeup_event() != 0) {
		tlog(TLOG_ERROR, "init wakeup event failed.");
		goto errout;
	}

	if (_dns_server_cache_init() != 0) {
		tlog(TLOG_ERROR, "init dns cache filed.");
		goto errout;
	}

	if (_dns_server_local_addr_cache_init() != 0) {
		tlog(TLOG_WARN, "init local addr cache failed, disable local ptr.");
		dns_conf_local_ptr_enable = 0;
	}

	if (_dns_server_neighbor_cache_init() != 0) {
		tlog(TLOG_ERROR, "init neighbor cache failed.");
		goto errout;
	}

	is_server_init = 1;
	return 0;
errout:
	atomic_set(&server.run, 0);

	if (epollfd) {
		close(epollfd);
	}

	_dns_server_close_socket();
	pthread_mutex_destroy(&server.request_list_lock);

	return -1;
}

void dns_server_stop(void)
{
	atomic_set(&server.run, 0);
	_dns_server_wakeup_thread();
}

void dns_server_exit(void)
{
	if (is_server_init == 0) {
		return;
	}

	if (server.event_fd > 0) {
		close(server.event_fd);
		server.event_fd = -1;
	}

	if (server.cache_save_pid > 0) {
		kill(server.cache_save_pid, SIGKILL);
		server.cache_save_pid = 0;
	}

	_dns_server_close_socket();
	_dns_server_local_addr_cache_destroy();
	_dns_server_neighbor_cache_remove_all();
	_dns_server_cache_save(0);
	_dns_server_request_remove_all();
	pthread_mutex_destroy(&server.request_list_lock);
	dns_cache_destroy();

	is_server_init = 0;
}
