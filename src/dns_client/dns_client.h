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

#ifndef _DNS_CLIENT_H_
#define _DNS_CLIENT_H_

#include "smartdns/dns.h"
#include "smartdns/dns_conf.h"
#include "smartdns/dns_stats.h"
#include "smartdns/http2.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/tlog.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define DNS_MAX_HOSTNAME 256
#define DNS_MAX_EVENTS 256
#define DNS_HOSTNAME_LEN 128
#define DNS_TCP_BUFFER (32 * 1024)
#define DNS_TCP_IDLE_TIMEOUT (60 * 10)
#define DNS_TCP_CONNECT_TIMEOUT (5)
#define DNS_QUERY_TIMEOUT (500)
#define DNS_QUERY_RETRY (4)
#define DNS_PENDING_SERVER_RETRY 60
#define SOCKET_PRIORITY (6)
#define SOCKET_IP_TOS (IPTOS_LOWDELAY | IPTOS_RELIABILITY)

/* ECS info */
struct dns_client_ecs {
	int enable;
	struct dns_opt_ecs ecs;
};

/* TCP/TLS buffer */
struct dns_server_buff {
	unsigned char data[DNS_TCP_BUFFER];
	int len;
};

typedef enum dns_server_status {
	DNS_SERVER_STATUS_INIT = 0,
	DNS_SERVER_STATUS_CONNECTING,
	DNS_SERVER_STATUS_CONNECTIONLESS,
	DNS_SERVER_STATUS_CONNECTED,
	DNS_SERVER_STATUS_DISCONNECTED,
} dns_server_status;

/* dns server information */
struct dns_server_info {
	atomic_t refcnt;
	struct list_head list;
	struct list_head check_list;
	/* server ping handle */
	struct ping_host_struct *ping_host;

	char host[DNS_HOSTNAME_LEN];
	char ip[DNS_MAX_HOSTNAME];
	int port;
	char proxy_name[DNS_HOSTNAME_LEN];
	/* server type */
	dns_server_type_t type;
	long long so_mark;
	int drop_packet_latency_ms;

	/* client socket */
	int fd;
	int ttl;
	int ttl_range;
	SSL *ssl;
	int ssl_write_len;
	int ssl_want_write;
	SSL_CTX *ssl_ctx;
	SSL_SESSION *ssl_session;
	BIO_METHOD *bio_method;

	struct proxy_conn *proxy;

	pthread_mutex_t lock;
	char skip_check_cert;
	dns_server_status status;

	struct dns_server_buff send_buff;
	struct dns_server_buff recv_buff;

	time_t last_send;
	time_t last_recv;
	unsigned long send_tick;
	int prohibit;
	atomic_t is_alive;
	int is_already_prohibit;

	/* server addr info */
	unsigned short ai_family;

	socklen_t ai_addrlen;
	union {
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr addr;
	};

	struct client_dns_server_flags flags;

	/* ECS */
	struct dns_client_ecs ecs_ipv4;
	struct dns_client_ecs ecs_ipv6;

	struct dns_server_stats stats;
	struct list_head conn_stream_list;

	/* HTTP/2 context - connection level, shared across requests */
	struct http2_ctx *http2_ctx;
	char alpn_selected[32];

	dns_server_security_status security_status;
};

struct dns_server_pending_group {
	struct list_head list;
	char group_name[DNS_GROUP_NAME_LEN];
};

struct dns_server_pending {
	struct list_head list;
	struct list_head retry_list;
	atomic_t refcnt;

	char host[DNS_HOSTNAME_LEN];
	char ipv4[DNS_HOSTNAME_LEN];
	char ipv6[DNS_HOSTNAME_LEN];
	unsigned int ping_time_v6;
	unsigned int ping_time_v4;
	unsigned int has_v4;
	unsigned int has_v6;
	unsigned int query_v4;
	unsigned int query_v6;
	unsigned int has_soa_v4;
	unsigned int has_soa_v6;

	/* server type */
	dns_server_type_t type;
	int retry_cnt;

	int port;

	struct client_dns_server_flags flags;

	struct list_head group_list;
};

/* upstream server group member */
struct dns_server_group_member {
	struct list_head list;
	struct dns_server_info *server;
};

/* upstream server groups */
struct dns_server_group {
	char group_name[DNS_GROUP_NAME_LEN];
	struct hlist_node node;
	struct list_head head;
};

/* dns client */
struct dns_client {
	pthread_t tid;
	atomic_t run;
	int epoll_fd;

	/* dns server list */
	pthread_mutex_t server_list_lock;
	struct list_head dns_server_list;
	struct dns_server_group *default_group;

	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_quic_ctx;
	int ssl_verify_skip;

	/* query list */
	struct list_head dns_request_list;
	atomic_t run_period;
	atomic_t dns_server_num;
	atomic_t dns_server_prohibit_num;

	/* query domain hash table, key: sid + domain */
	pthread_mutex_t domain_map_lock;
	DECLARE_HASHTABLE(domain_map, 6);
	DECLARE_HASHTABLE(group, 4);

	int fd_wakeup;
};

/* dns replied server info */
struct dns_query_replied {
	struct hlist_node node;
	struct dns_server_info *server;
};

struct dns_conn_stream {
	atomic_t refcnt;
	struct list_head query_list;
	struct list_head server_list;
	struct dns_server_buff send_buff;
	struct dns_server_buff recv_buff;

	struct dns_query_struct *query;
	struct dns_server_info *server_info;

	union {
		SSL *quic_stream;
		struct http2_stream *http2_stream;
	};
	dns_server_type_t type;
};

/* query struct */
struct dns_query_struct {
	struct list_head dns_request_list;
	atomic_t refcnt;
	struct dns_server_group *server_group;

	struct dns_conf_group *conf;

	struct list_head conn_stream_list;

	/* query id, hash key sid + domain*/
	char domain[DNS_MAX_CNAME_LEN];
	unsigned short sid;
	struct hlist_node domain_node;

	struct list_head period_list;

	/* dns query type */
	int qtype;

	/* dns query number */
	atomic_t dns_request_sent;
	unsigned long send_tick;

	/* caller notification */
	dns_client_callback callback;
	void *user_ptr;

	/* retry count */
	atomic_t retry_count;

	/* has result */
	int has_result;

	/* ECS */
	struct dns_client_ecs ecs;

	/* EDNS0_DO */
	int edns0_do;

	/* replied hash table */
	DECLARE_HASHTABLE(replied_map, 4);
};

extern struct dns_client client;

int _dns_client_recv(struct dns_server_info *server_info, unsigned char *inpacket, int inpacket_len,
					 struct sockaddr *from, socklen_t from_len);

int _dns_client_send_packet(struct dns_query_struct *query, void *packet, int len);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
