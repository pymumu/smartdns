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

#ifndef _DNS_SERVER_H_
#define _DNS_SERVER_H_

#include "smartdns/lib/atomic.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"

#include "smartdns/dns.h"
#include "smartdns/dns_conf.h"
#include "smartdns/dns_server.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <openssl/ssl.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define DNS_MAX_EVENTS 256
#define IPV6_READY_CHECK_TIME 180
#define DNS_SERVER_TMOUT_TTL (5 * 60)
#define DNS_SERVER_FAIL_TTL (3)
#define DNS_SERVER_SOA_TTL (30)
#define DNS_SERVER_ADDR_TTL (60)
#define DNS_CONN_BUFF_SIZE 4096
#define DNS_REQUEST_MAX_TIMEOUT 950
#define DNS_PING_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT)
#define DNS_PING_CHECK_INTERVAL (100)
#define DNS_PING_RTT_CHECK_THRESHOLD (100 * 10)
#define DNS_PING_SECOND_TIMEOUT (DNS_REQUEST_MAX_TIMEOUT - DNS_PING_CHECK_INTERVAL)
#define SOCKET_IP_TOS (IPTOS_LOWDELAY | IPTOS_RELIABILITY)
#define SOCKET_PRIORITY (6)
#define CACHE_AUTO_ENABLE_SIZE (1024 * 1024 * 128)
#define EXPIRED_DOMAIN_PREFETCH_TIME (3600 * 8)
#define DNS_MAX_DOMAIN_REFETCH_NUM 64
#define DNS_SERVER_NEIGHBOR_CACHE_MAX_NUM (1024 * 8)
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
#define RECV_ERROR_BAD_PATH (-4)

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
	uint8_t buf[DNS_CONN_BUFF_SIZE];
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
	int is_cache_reply;
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
	char *original_domain;
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
	uint8_t mac[6];
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

	int is_cache_reply;

	struct dns_srv_records *srv_records;

	atomic_t notified;
	atomic_t do_callback;
	atomic_t adblock;
	atomic_t soa_num;
	atomic_t plugin_complete_called;

	/* send original raw packet to server/client like proxy */

	/*
	 0: not passthrough, reply to client
	 1: passthrough, reply to client, no modify packet
	 2: passthrough, reply to client, check and filter ip addresses.
	 */
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

	uint64_t query_timestamp;
	int query_time;
};

/* dns server data */
struct dns_server {
	atomic_t run;
	int epoll_fd;
	int event_fd;
	struct list_head conn_list;
	pthread_mutex_t conn_list_lock;

	pid_t cache_save_pid;
	time_t cache_save_time;

	/* dns request list */
	pthread_mutex_t request_list_lock;
	struct list_head request_list;
	atomic_t request_num;

	DECLARE_HASHTABLE(request_pending, 4);
	pthread_mutex_t request_pending_lock;

	int update_neighbor_cache;
	struct neighbor_cache neighbor_cache;

	struct local_addr_cache local_addr_cache;
};

extern struct dns_server server;

int _dns_server_recv(struct dns_server_conn_head *conn, unsigned char *inpacket, int inpacket_len,
					 struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
					 socklen_t from_len);

int _dns_reply_inpacket(struct dns_request *request, unsigned char *inpacket, int inpacket_len);

int _dns_server_do_query(struct dns_request *request, int skip_notify_event);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
