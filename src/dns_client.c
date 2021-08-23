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

#define _GNU_SOURCE
#include "dns_client.h"
#include "atomic.h"
#include "dns.h"
#include "dns_conf.h"
#include "dns_server.h"
#include "fast_ping.h"
#include "hashtable.h"
#include "http_parse.h"
#include "list.h"
#include "tlog.h"
#include "util.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
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
#define DNS_TCP_BUFFER (32 * 1024)
#define DNS_TCP_IDLE_TIMEOUT (60 * 10)
#define DNS_TCP_CONNECT_TIMEOUT (5)
#define DNS_QUERY_TIMEOUT (500)
#define DNS_QUERY_RETRY (6)
#define DNS_PENDING_SERVER_RETRY 40
#define SOCKET_PRIORITY (6)
#define SOCKET_IP_TOS (IPTOS_LOWDELAY | IPTOS_RELIABILITY)

/* ECS info */
struct dns_client_ecs {
	int enable;
	unsigned int family;
	unsigned int bitlen;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

/* TCP/TLS buffer */
struct dns_server_buff {
	unsigned char data[DNS_TCP_BUFFER];
	unsigned short len;
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
	struct list_head list;
	/* server ping handle */
	struct ping_host_struct *ping_host;

	char ip[DNS_HOSTNAME_LEN];
	int port;
	/* server type */
	dns_server_type_t type;

	/* client socket */
	int fd;
	int ttl;
	int ttl_range;
	SSL *ssl;
	int ssl_write_len;
	SSL_CTX *ssl_ctx;
	SSL_SESSION *ssl_session;
	pthread_mutex_t lock;
	char skip_check_cert;
	dns_server_status status;

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

	struct client_dns_server_flags flags;
};

struct dns_server_pending_group {
	struct list_head list;
	char group_name[DNS_GROUP_NAME_LEN];
};

struct dns_server_pending {
	struct list_head list;
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
	int run;
	int epoll_fd;

	/* dns server list */
	pthread_mutex_t server_list_lock;
	struct list_head dns_server_list;
	struct dns_server_group *default_group;

	SSL_CTX *ssl_ctx;
	int ssl_verify_skip;

	/* query list */
	pthread_mutex_t dns_request_lock;
	struct list_head dns_request_list;
	atomic_t dns_server_num;

	/* ECS */
	struct dns_client_ecs ecs_ipv4;
	struct dns_client_ecs ecs_ipv6;

	/* query doman hash table, key: sid + domain */
	pthread_mutex_t domain_map_lock;
	DECLARE_HASHTABLE(domain_map, 6);
	DECLARE_HASHTABLE(group, 4);
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
	struct list_head dns_request_list;
	atomic_t refcnt;
	struct dns_server_group *server_group;

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

	/* replied hash table */
	DECLARE_HASHTABLE(replied_map, 4);
};

static struct dns_client client;
static atomic_t dns_client_sid = ATOMIC_INIT(0);
static LIST_HEAD(pending_servers);
static pthread_mutex_t pending_server_mutex = PTHREAD_MUTEX_INITIALIZER;
static int dns_client_has_bootstrap_dns = 0;

int _ssl_read(struct dns_server_info *server, void *buff, int num)
{
	int ret = 0;
	if (server == NULL || buff == NULL) {
		return SSL_ERROR_SYSCALL;
	}
	pthread_mutex_lock(&server->lock);
	ret = SSL_read(server->ssl, buff, num);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

int _ssl_write(struct dns_server_info *server, const void *buff, int num)
{
	int ret = 0;
	if (server == NULL || buff == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	ret = SSL_write(server->ssl, buff, num);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

int _ssl_shutdown(struct dns_server_info *server)
{
	int ret = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	ret = SSL_shutdown(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

int _ssl_get_error(struct dns_server_info *server, int ret)
{
	int err = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	err = SSL_get_error(server->ssl, ret);
	pthread_mutex_unlock(&server->lock);
	return err;
}

int _ssl_do_handshake(struct dns_server_info *server)
{
	int err = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	err = SSL_do_handshake(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return err;
}

int _ssl_session_reused(struct dns_server_info *server)
{
	int err = 0;
	if (server == NULL || server->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&server->lock);
	err = SSL_session_reused(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return err;
}

SSL_SESSION *_ssl_get1_session(struct dns_server_info *server)
{
	SSL_SESSION *ret = 0;
	if (server == NULL || server->ssl == NULL) {
		return NULL;
	}

	pthread_mutex_lock(&server->lock);
	ret = SSL_get1_session(server->ssl);
	pthread_mutex_unlock(&server->lock);
	return ret;
}

const char *_dns_server_get_type_string(dns_server_type_t type)
{
	const char *type_str = "";

	switch (type) {
	case DNS_SERVER_UDP:
		type_str = "udp";
		break;
	case DNS_SERVER_TCP:
		type_str = "tcp";
		break;
	case DNS_SERVER_TLS:
		type_str = "tls";
		break;
	case DNS_SERVER_HTTPS:
		type_str = "https";
		break;
	default:
		break;
	}

	return type_str;
}

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
		tlog(TLOG_ERROR, "get addr info failed. %s\n", gai_strerror(ret));
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
static int _dns_client_server_exist(const char *server_ip, int port, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->port != port || server_info->type != server_type) {
			continue;
		}

		if (strncmp(server_info->ip, server_ip, DNS_HOSTNAME_LEN)) {
			continue;
		}

		pthread_mutex_unlock(&client.server_list_lock);
		return 0;
	}

	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

static void _dns_client_server_update_ttl(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
										  struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl,
										  struct timeval *tv, void *userptr)
{
	struct dns_server_info *server_info = userptr;
	if (result != PING_RESULT_RESPONSE || server_info == NULL) {
		return;
	}

	double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
	tlog(TLOG_DEBUG, "from %s: seq=%d ttl=%d time=%.3f\n", host, seqno, ttl, rtt);
	server_info->ttl = ttl;
}

/* get server control block by ip and port, type */
static struct dns_server_info *_dns_client_get_server(char *server_ip, int port, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;
	struct dns_server_info *server_info_return = NULL;

	if (server_ip == NULL) {
		return NULL;
	}

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->port != port || server_info->type != server_type) {
			continue;
		}

		if (strncmp(server_info->ip, server_ip, DNS_HOSTNAME_LEN)) {
			continue;
		}

		pthread_mutex_unlock(&client.server_list_lock);
		server_info_return = server_info;
		break;
	}

	pthread_mutex_unlock(&client.server_list_lock);

	return server_info_return;
}

/* get server group by name */
static struct dns_server_group *_dns_client_get_group(const char *group_name)
{
	unsigned long key;
	struct dns_server_group *group = NULL;
	struct hlist_node *tmp = NULL;

	if (group_name == NULL) {
		return NULL;
	}

	key = hash_string(group_name);
	hash_for_each_possible_safe(client.group, group, tmp, node, key)
	{
		if (strncmp(group->group_name, group_name, DNS_GROUP_NAME_LEN) != 0) {
			continue;
		}

		return group;
	}

	return NULL;
}

/* get server group by name */
static struct dns_server_group *_dns_client_get_dnsserver_group(const char *group_name)
{
	struct dns_server_group *group = _dns_client_get_group(group_name);

	if (group == NULL) {
		group = client.default_group;
		tlog(TLOG_DEBUG, "send query to group %s", DNS_SERVER_GROUP_DEFAULT);
	} else {
		if (list_empty(&group->head)) {
			group = client.default_group;
			tlog(TLOG_DEBUG, "send query to group %s", DNS_SERVER_GROUP_DEFAULT);
		} else {
			tlog(TLOG_DEBUG, "send query to group %s", group_name);
		}
	}

	return group;
}

/* add server to group */
static int _dns_client_add_to_group(char *group_name, struct dns_server_info *server_info)
{
	struct dns_server_group *group = NULL;
	struct dns_server_group_member *group_member = NULL;

	group = _dns_client_get_group(group_name);
	if (group == NULL) {
		tlog(TLOG_ERROR, "group %s not exist.", group_name);
		return -1;
	}

	group_member = malloc(sizeof(*group_member));
	if (group_member == NULL) {
		tlog(TLOG_ERROR, "malloc memory failed.");
		goto errout;
	}

	memset(group_member, 0, sizeof(*group_member));
	group_member->server = server_info;
	list_add(&group_member->list, &group->head);

	return 0;
errout:
	if (group_member) {
		free(group_member);
	}

	return -1;
}

static int _dns_client_add_to_pending_group(char *group_name, char *server_ip, int port, dns_server_type_t server_type)
{
	struct dns_server_pending *item, *tmp;
	struct dns_server_pending *pending = NULL;
	struct dns_server_pending_group *group = NULL;

	if (group_name == NULL || server_ip == NULL) {
		goto errout;
	}

	pthread_mutex_lock(&pending_server_mutex);
	list_for_each_entry_safe(item, tmp, &pending_servers, list)
	{
		if (strncmp(item->host, server_ip, DNS_HOSTNAME_LEN) == 0 && item->port == port && item->type == server_type) {
			pending = item;
			break;
		}
	}
	pthread_mutex_unlock(&pending_server_mutex);

	if (pending == NULL) {
		tlog(TLOG_ERROR, "cannot found server for group %s: %s, %d, %d", group_name, server_ip, port, server_type);
		goto errout;
	}

	group = malloc(sizeof(*group));
	if (group == NULL) {
		goto errout;
	}
	memset(group, 0, sizeof(*group));
	safe_strncpy(group->group_name, group_name, DNS_GROUP_NAME_LEN);

	pthread_mutex_lock(&pending_server_mutex);
	list_add_tail(&group->list, &pending->group_list);
	pthread_mutex_unlock(&pending_server_mutex);

	return 0;

errout:
	if (group) {
		free(group);
	}
	return -1;
}

/* add server to group */
static int _dns_client_add_to_group_pending(char *group_name, char *server_ip, int port, dns_server_type_t server_type,
											int ispending)
{
	struct dns_server_info *server_info = NULL;

	if (group_name == NULL || server_ip == NULL) {
		return -1;
	}

	server_info = _dns_client_get_server(server_ip, port, server_type);
	if (server_info == NULL) {
		if (ispending == 0) {
			tlog(TLOG_ERROR, "add server %s:%d to group %s failed", server_ip, port, group_name);
			return -1;
		}
		return _dns_client_add_to_pending_group(group_name, server_ip, port, server_type);
	}

	return _dns_client_add_to_group(group_name, server_info);
}

int dns_client_add_to_group(char *group_name, char *server_ip, int port, dns_server_type_t server_type)
{
	return _dns_client_add_to_group_pending(group_name, server_ip, port, server_type, 1);
}

/* free group member */
static int _dns_client_remove_member(struct dns_server_group_member *group_member)
{
	list_del_init(&group_member->list);
	free(group_member);

	return 0;
}

static int _dns_client_remove_from_group(struct dns_server_group *group, struct dns_server_info *server_info)
{
	struct dns_server_group_member *group_member;
	struct dns_server_group_member *tmp;

	list_for_each_entry_safe(group_member, tmp, &group->head, list)
	{
		if (group_member->server != server_info) {
			continue;
		}

		_dns_client_remove_member(group_member);
	}

	return 0;
}

static int _dns_client_remove_server_from_groups(struct dns_server_info *server_info)
{
	struct dns_server_group *group;
	struct hlist_node *tmp = NULL;
	int i = 0;

	hash_for_each_safe(client.group, i, tmp, group, node)
	{
		_dns_client_remove_from_group(group, server_info);
	}

	return 0;
}

int dns_client_remove_from_group(char *group_name, char *server_ip, int port, dns_server_type_t server_type)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group *group = NULL;

	server_info = _dns_client_get_server(server_ip, port, server_type);
	if (server_info == NULL) {
		return -1;
	}

	group = _dns_client_get_group(group_name);
	if (group == NULL) {
		return -1;
	}

	return _dns_client_remove_from_group(group, server_info);
}

int dns_client_add_group(char *group_name)
{
	unsigned long key;
	struct dns_server_group *group = NULL;

	if (group_name == NULL) {
		return -1;
	}

	if (_dns_client_get_group(group_name) != NULL) {
		tlog(TLOG_ERROR, "add group %s failed, group already exists", group_name);
		return -1;
	}

	group = malloc(sizeof(*group));
	if (group == NULL) {
		goto errout;
	}

	memset(group, 0, sizeof(*group));
	INIT_LIST_HEAD(&group->head);
	safe_strncpy(group->group_name, group_name, DNS_GROUP_NAME_LEN);
	key = hash_string(group_name);
	hash_add(client.group, &group->node, key);

	return 0;
errout:
	if (group) {
		free(group);
		group = NULL;
	}

	return -1;
}

static int _dns_client_remove_group(struct dns_server_group *group)
{
	struct dns_server_group_member *group_member;
	struct dns_server_group_member *tmp;

	if (group == NULL) {
		return 0;
	}

	list_for_each_entry_safe(group_member, tmp, &group->head, list)
	{
		_dns_client_remove_member(group_member);
	}

	hash_del(&group->node);
	free(group);

	return 0;
}

int dns_client_remove_group(char *group_name)
{
	unsigned long key;
	struct dns_server_group *group = NULL;
	struct hlist_node *tmp = NULL;

	if (group_name == NULL) {
		return -1;
	}

	key = hash_string(group_name);
	hash_for_each_possible_safe(client.group, group, tmp, node, key)
	{
		if (strncmp(group->group_name, group_name, DNS_GROUP_NAME_LEN) != 0) {
			continue;
		}

		_dns_client_remove_group(group);

		return 0;
	}

	return 0;
}

static void _dns_client_group_remove_all(void)
{
	struct dns_server_group *group;
	struct hlist_node *tmp = NULL;
	int i = 0;

	hash_for_each_safe(client.group, i, tmp, group, node)
	{
		_dns_client_remove_group(group);
	}
}

int dns_client_spki_decode(const char *spki, unsigned char *spki_data_out)
{
	int spki_data_len = -1;

	spki_data_len = SSL_base64_decode(spki, spki_data_out);

	if (spki_data_len != SHA256_DIGEST_LENGTH) {
		return -1;
	}

	return spki_data_len;
}

static char *_dns_client_server_get_tls_host_verify(struct dns_server_info *server_info)
{
	char *tls_host_verify = NULL;

	switch (server_info->type) {
	case DNS_SERVER_UDP: {
	} break;
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_https = &server_info->flags.https;
		tls_host_verify = flag_https->tls_host_verify;
	} break;
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &server_info->flags.tls;
		tls_host_verify = flag_tls->tls_host_verify;
	} break;
	case DNS_SERVER_TCP:
		break;
	default:
		return NULL;
		break;
	}

	if (tls_host_verify) {
		if (tls_host_verify[0] == '\0') {
			return NULL;
		}
	}

	return tls_host_verify;
}

static char *_dns_client_server_get_spki(struct dns_server_info *server_info, int *spki_len)
{
	*spki_len = 0;
	char *spki = NULL;
	switch (server_info->type) {
	case DNS_SERVER_UDP: {
	} break;
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_https = &server_info->flags.https;
		spki = flag_https->spki;
		*spki_len = flag_https->spi_len;
	} break;
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &server_info->flags.tls;
		spki = flag_tls->spki;
		*spki_len = flag_tls->spi_len;
	} break;
	case DNS_SERVER_TCP:
		break;
	default:
		return NULL;
		break;
	}

	if (*spki_len <= 0) {
		return NULL;
	}

	return spki;
}

static int _dns_client_set_trusted_cert(SSL_CTX *ssl_ctx)
{
	char *cafile = NULL;
	char *capath = NULL;
	int cert_path_set = 0;

	if (ssl_ctx == NULL) {
		return -1;
	}

	if (dns_conf_ca_file[0]) {
		cafile = dns_conf_ca_file;
	}

	if (dns_conf_ca_path[0]) {
		capath = dns_conf_ca_path;
	}

	if (cafile == NULL && capath == NULL) {
		if (SSL_CTX_set_default_verify_paths(ssl_ctx)) {
			cert_path_set = 1;
		}

		const STACK_OF(X509_NAME) *cas = SSL_CTX_get_client_CA_list(ssl_ctx);
		if (cas && sk_X509_NAME_num(cas) == 0) {
			cafile = "/etc/ssl/certs/ca-certificates.crt";
			capath = "/etc/ssl/certs";
			cert_path_set = 0;
		}
	}

	if (cert_path_set == 0) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, cafile, capath) == 0) {
			tlog(TLOG_WARN, "load certificate from %s:%s failed.", cafile, capath);
			return -1;
		}
	}

	return 0;
}

SSL_CTX *_ssl_ctx_get(void)
{
	pthread_mutex_lock(&client.server_list_lock);
	SSL_CTX *ssl_ctx = client.ssl_ctx;
	if (ssl_ctx) {
		pthread_mutex_unlock(&client.server_list_lock);
		return ssl_ctx;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	ssl_ctx = SSL_CTX_new(TLS_client_method());
#else
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#endif

	if (ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT);
	SSL_CTX_sess_set_cache_size(ssl_ctx, DNS_MAX_SERVERS);
	if (_dns_client_set_trusted_cert(ssl_ctx) != 0) {
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		client.ssl_verify_skip = 1;
	}

	client.ssl_ctx = ssl_ctx;
	pthread_mutex_unlock(&client.server_list_lock);
	return client.ssl_ctx;
errout:
	
	pthread_mutex_unlock(&client.server_list_lock);
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
	}

	return NULL;
}

/* add dns server information */
static int _dns_client_server_add(char *server_ip, char *server_host, int port, dns_server_type_t server_type,
								  struct client_dns_server_flags *flags)
{
	struct dns_server_info *server_info = NULL;
	struct addrinfo *gai = NULL;
	int spki_data_len = 0;
	int ttl = 0;
	char port_s[8];
	int sock_type;
	char skip_check_cert = 0;

	switch (server_type) {
	case DNS_SERVER_UDP: {
		struct client_dns_server_flag_udp *flag_udp = &flags->udp;
		ttl = flag_udp->ttl;
		if (ttl > 255) {
			ttl = 255;
		} else if (ttl < -32) {
			ttl = -32;
		}

		sock_type = SOCK_DGRAM;
	} break;
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_https = &flags->https;
		spki_data_len = flag_https->spi_len;
		if (flag_https->httphost[0] == 0) {
			if (server_host) {
				safe_strncpy(flag_https->httphost, server_host, DNS_MAX_CNAME_LEN);
			} else {
				safe_strncpy(flag_https->httphost, server_ip, DNS_MAX_CNAME_LEN);
			}
		}
		sock_type = SOCK_STREAM;
		skip_check_cert = flag_https->skip_check_cert;
	} break;
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &flags->tls;
		spki_data_len = flag_tls->spi_len;
		sock_type = SOCK_STREAM;
		skip_check_cert = flag_tls->skip_check_cert;
	} break;
	case DNS_SERVER_TCP:
		sock_type = SOCK_STREAM;
		break;
	default:
		return -1;
		break;
	}

	if (spki_data_len > DNS_SERVER_SPKI_LEN) {
		tlog(TLOG_ERROR, "spki data length is invalid.");
		return -1;
	}

	/* if server exist, return */
	if (_dns_client_server_exist(server_ip, port, server_type) == 0) {
		return 0;
	}

	snprintf(port_s, 8, "%d", port);
	gai = _dns_client_getaddr(server_ip, port_s, sock_type, 0);
	if (gai == NULL) {
		tlog(TLOG_DEBUG, "get address failed, %s:%d", server_ip, port);
		goto errout;
	}

	server_info = malloc(sizeof(*server_info));
	if (server_info == NULL) {
		goto errout;
	}

	if (server_type != DNS_SERVER_UDP) {
		flags->result_flag &= (~DNSSERVER_FLAG_CHECK_TTL);
	}

	memset(server_info, 0, sizeof(*server_info));
	safe_strncpy(server_info->ip, server_ip, sizeof(server_info->ip));
	server_info->port = port;
	server_info->ai_family = gai->ai_family;
	server_info->ai_addrlen = gai->ai_addrlen;
	server_info->type = server_type;
	server_info->fd = 0;
	server_info->status = DNS_SERVER_STATUS_INIT;
	server_info->ttl = ttl;
	server_info->ttl_range = 0;
	server_info->skip_check_cert = skip_check_cert;
	pthread_mutex_init(&server_info->lock, NULL);
	memcpy(&server_info->flags, flags, sizeof(server_info->flags));

	/* exclude this server from default group */
	if ((server_info->flags.server_flag & SERVER_FLAG_EXCLUDE_DEFAULT) == 0) {
		if (_dns_client_add_to_group(DNS_SERVER_GROUP_DEFAULT, server_info) != 0) {
			tlog(TLOG_ERROR, "add server to default group failed.");
			goto errout;
		}
	}

	/* if server type is TLS, create ssl context */
	if (server_type == DNS_SERVER_TLS || server_type == DNS_SERVER_HTTPS) {
		server_info->ssl_ctx = _ssl_ctx_get();
		if (server_info->ssl_ctx == NULL) {
			tlog(TLOG_ERROR, "init ssl failed.");
			goto errout;
		}

		if (client.ssl_verify_skip) {
			server_info->skip_check_cert = 1;
		}
	}

	/* safe address info */
	if (gai->ai_addrlen > sizeof(server_info->in6)) {
		tlog(TLOG_ERROR, "addr len invalid, %d, %zd, %d", gai->ai_addrlen, sizeof(server_info->addr),
			 server_info->ai_family);
		goto errout;
	}
	memcpy(&server_info->addr, gai->ai_addr, gai->ai_addrlen);

	/* start ping task */
	if (server_type == DNS_SERVER_UDP) {
		if (ttl <= 0 && (server_info->flags.result_flag & DNSSERVER_FLAG_CHECK_TTL)) {
			server_info->ping_host =
				fast_ping_start(PING_TYPE_DNS, server_ip, 0, 60000, 1000, _dns_client_server_update_ttl, server_info);
			if (server_info->ping_host == NULL) {
				tlog(TLOG_ERROR, "start ping failed.");
				goto errout;
			}

			if (ttl < 0) {
				server_info->ttl_range = -ttl;
			}
		}
	}

	/* add to list */
	pthread_mutex_lock(&client.server_list_lock);
	list_add(&server_info->list, &client.dns_server_list);
	pthread_mutex_unlock(&client.server_list_lock);

	atomic_inc(&client.dns_server_num);
	freeaddrinfo(gai);

	tlog(TLOG_INFO, "add server %s:%d, type: %s", server_ip, port, _dns_server_get_type_string(server_info->type));

	return 0;
errout:
	if (server_info) {
		if (server_info->ping_host) {
			fast_ping_stop(server_info->ping_host);
		}

		pthread_mutex_destroy(&server_info->lock);
		free(server_info);
	}

	if (gai) {
		freeaddrinfo(gai);
	}

	return -1;
}

static void _dns_client_close_socket(struct dns_server_info *server_info)
{
	if (server_info->fd <= 0) {
		return;
	}

	if (server_info->ssl) {
		/* Shutdown ssl */
		if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
			_ssl_shutdown(server_info);
		}
		SSL_free(server_info->ssl);
		server_info->ssl = NULL;
		server_info->ssl_write_len = -1;
	}

	/* remove fd from epoll */
	epoll_ctl(client.epoll_fd, EPOLL_CTL_DEL, server_info->fd, NULL);
	close(server_info->fd);

	server_info->fd = -1;
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
	/* update send recv time */
	time(&server_info->last_send);
	time(&server_info->last_recv);
	tlog(TLOG_DEBUG, "server %s closed.", server_info->ip);
}

static void _dns_client_shutdown_socket(struct dns_server_info *server_info)
{
	if (server_info->fd <= 0) {
		return;
	}

	switch (server_info->type) {
	case DNS_SERVER_UDP:
		return;
		break;
	case DNS_SERVER_TCP:
		if (server_info->fd > 0) {
			shutdown(server_info->fd, SHUT_RDWR);
		}
		break;
	case DNS_SERVER_TLS:
	case DNS_SERVER_HTTPS:
		if (server_info->ssl) {
			/* Shutdown ssl */
			if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
				_ssl_shutdown(server_info);
			}
			shutdown(server_info->fd, SHUT_RDWR);
		}
		break;
	default:
		break;
	}
}

static void _dns_client_server_close(struct dns_server_info *server_info)
{
	/* stop ping task */
	if (server_info->ping_host) {
		if (fast_ping_stop(server_info->ping_host) != 0) {
			tlog(TLOG_ERROR, "stop ping failed.\n");
		}
	}

	_dns_client_close_socket(server_info);

	if (server_info->ssl_session) {
		SSL_SESSION_free(server_info->ssl_session);
		server_info->ssl_session = NULL;
	}

	server_info->ssl_ctx = NULL;
}

/* remove all servers information */
static void _dns_client_server_remove_all(void)
{
	struct dns_server_info *server_info, *tmp;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		list_del(&server_info->list);
		_dns_client_server_close(server_info);
		pthread_mutex_destroy(&server_info->lock);
		free(server_info);
	}
	pthread_mutex_unlock(&client.server_list_lock);
}

/* remove single server */
static int _dns_client_server_remove(char *server_ip, int port, dns_server_type_t server_type)
{
	struct dns_server_info *server_info, *tmp;

	/* find server and remove */
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->port != port || server_info->type != server_type) {
			continue;
		}

		if (strncmp(server_info->ip, server_ip, DNS_HOSTNAME_LEN)) {
			continue;
		}

		list_del(&server_info->list);
		_dns_client_server_close(server_info);
		pthread_mutex_unlock(&client.server_list_lock);
		_dns_client_remove_server_from_groups(server_info);
		free(server_info);
		atomic_dec(&client.dns_server_num);
		return 0;
	}
	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

void _dns_client_server_pending_get(struct dns_server_pending *pending)
{
	if (atomic_inc_return(&pending->refcnt) <= 0) {
		tlog(TLOG_ERROR, "BUG: pending ref is invalid");
		abort();
	}
}

void _dns_client_server_pending_release_lck(struct dns_server_pending *pending)
{
	int refcnt = atomic_dec_return(&pending->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: pending refcnt is %d", refcnt);
			abort();
		}
		return;
	}

	list_del_init(&pending->list);
	free(pending);
}

void _dns_client_server_pending_release(struct dns_server_pending *pending)
{
	int refcnt = atomic_dec_return(&pending->refcnt);

	if (refcnt) {
		if (refcnt < 0) {
			tlog(TLOG_ERROR, "BUG: pending refcnt is %d", refcnt);
			abort();
		}
		return;
	}

	pthread_mutex_lock(&pending_server_mutex);
	list_del_init(&pending->list);
	pthread_mutex_unlock(&pending_server_mutex);

	free(pending);
}

static int _dns_client_server_pending(char *server_ip, int port, dns_server_type_t server_type,
									  struct client_dns_server_flags *flags)
{
	struct dns_server_pending *pending = NULL;

	pending = malloc(sizeof(*pending));
	if (pending == NULL) {
		tlog(TLOG_ERROR, "malloc failed");
		goto errout;
	}
	memset(pending, 0, sizeof(*pending));

	safe_strncpy(pending->host, server_ip, DNS_HOSTNAME_LEN);
	pending->port = port;
	pending->type = server_type;
	pending->ping_time_v4 = -1;
	pending->ping_time_v6 = -1;
	pending->ipv4[0] = 0;
	pending->ipv6[0] = 0;
	pending->has_v4 = 0;
	pending->has_v6 = 0;
	_dns_client_server_pending_get(pending);
	INIT_LIST_HEAD(&pending->group_list);
	memcpy(&pending->flags, flags, sizeof(struct client_dns_server_flags));

	pthread_mutex_lock(&pending_server_mutex);
	list_add_tail(&pending->list, &pending_servers);
	pthread_mutex_unlock(&pending_server_mutex);
	return 0;
errout:
	if (pending) {
		free(pending);
	}

	return -1;
}

static int _dns_client_add_server_pending(char *server_ip, char *server_host, int port, dns_server_type_t server_type,
										  struct client_dns_server_flags *flags, int ispending)
{
	int ret;

	if (server_type >= DNS_SERVER_TYPE_END) {
		tlog(TLOG_ERROR, "server type is invalid.");
		return -1;
	}

	if (check_is_ipaddr(server_ip) && ispending) {
		ret = _dns_client_server_pending(server_ip, port, server_type, flags);
		if (ret == 0) {
			tlog(TLOG_INFO, "add pending server %s", server_ip);
			return 0;
		}
	}

	/* add server */
	ret = _dns_client_server_add(server_ip, server_host, port, server_type, flags);
	if (ret != 0) {
		goto errout;
	}

	dns_client_has_bootstrap_dns = 1;

	return 0;
errout:
	return -1;
}

int dns_client_add_server(char *server_ip, int port, dns_server_type_t server_type,
						  struct client_dns_server_flags *flags)
{
	return _dns_client_add_server_pending(server_ip, NULL, port, server_type, flags, 1);
}

int dns_client_remove_server(char *server_ip, int port, dns_server_type_t server_type)
{
	return _dns_client_server_remove(server_ip, port, server_type);
}

int dns_server_num(void)
{
	return atomic_read(&client.dns_server_num);
}

static void _dns_client_query_get(struct dns_query_struct *query)
{
	if (atomic_inc_return(&query->refcnt) <= 0) {
		tlog(TLOG_ERROR, "BUG: query ref is invalid, domain: %s", query->domain);
		abort();
	}
}

static void _dns_client_query_release(struct dns_query_struct *query)
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
		query->callback(query->domain, DNS_QUERY_END, 0, NULL, NULL, 0, query->user_ptr);
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

static void _dns_client_query_remove(struct dns_query_struct *query)
{
	/* remove query from period check list, and release reference*/
	pthread_mutex_lock(&client.domain_map_lock);
	if (list_empty(&query->dns_request_list)) {
		pthread_mutex_unlock(&client.domain_map_lock);
		return;
	}
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);

	_dns_client_query_release(query);
}

static void _dns_client_query_remove_all(void)
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

static void _dns_client_check_udp_nat(struct dns_query_struct *query)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group_member *group_member = NULL;

	/* For udp nat case.
	 * when router reconnect to internet, udp port may always marked as UNREPLIED.
	 * dns query will timeout, and cannot reconnect again,
	 * create a new socket to communicate.
	 */
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(group_member, &query->server_group->head, list)
	{
		server_info = group_member->server;
		if (server_info->type != DNS_SERVER_UDP) {
			continue;
		}

		if (server_info->last_send - 5 > server_info->last_recv) {
			server_info->recv_buff.len = 0;
			server_info->send_buff.len = 0;
			tlog(TLOG_DEBUG, "query server %s timeout.", server_info->ip);
			_dns_client_close_socket(server_info);
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}

static void _dns_client_check_tcp(void)
{
	struct dns_server_info *server_info;
	time_t now;

	time(&now);

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(server_info, &client.dns_server_list, list)
	{
		if (server_info->type == DNS_SERVER_UDP) {
			/* no need to check udp server */
			continue;
		}

		if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
			if (server_info->last_send + DNS_TCP_CONNECT_TIMEOUT < now) {
				tlog(TLOG_DEBUG, "server %s connect timeout.", server_info->ip);
				_dns_client_close_socket(server_info);
			}
		} else if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
			if (server_info->last_recv + DNS_TCP_IDLE_TIMEOUT < now) {
				/*disconnect if the server is not responding */
				server_info->recv_buff.len = 0;
				server_info->send_buff.len = 0;
				_dns_client_close_socket(server_info);
			}
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}

static struct dns_query_struct *_dns_client_get_request(unsigned short sid, char *domain)
{
	struct dns_query_struct *query = NULL;
	struct dns_query_struct *query_result = NULL;
	struct hlist_node *tmp = NULL;
	uint32_t key;

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
		_dns_client_query_get(query_result);
		break;
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	return query_result;
}

static int _dns_replied_check_add(struct dns_query_struct *dns_query, struct sockaddr *addr, socklen_t addr_len)
{
	uint32_t key = 0;
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

static int _dns_client_recv(struct dns_server_info *server_info, unsigned char *inpacket, int inpacket_len,
							struct sockaddr *from, socklen_t from_len)
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
	int has_opt = 0;

	packet->head.tc = 0;

	/* decode domain from udp packet */
	len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (len != 0) {
		char host_name[DNS_MAX_CNAME_LEN];
		tlog(TLOG_WARN, "decode failed, packet len = %d, tc = %d, id = %d, from = %s\n", inpacket_len, packet->head.tc,
			 packet->head.id, gethost_by_addr(host_name, sizeof(host_name), from));
		return -1;
	}

	/* not answer, return error */
	if (packet->head.qr != DNS_OP_IQUERY) {
		tlog(TLOG_DEBUG, "message type error.\n");
		return -1;
	}

	tlog(TLOG_DEBUG,
		 "qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, ra = %d, rcode "
		 "= %d, payloadsize = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len,
		 packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra, packet->head.rcode,
		 dns_get_OPT_payload_size(packet));

	/* get question */
	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		dns_get_domain(rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
		tlog(TLOG_DEBUG, "domain: %s qtype: %d  qclass: %d\n", domain, qtype, qclass);
	}

	if (dns_get_OPT_payload_size(packet) > 0) {
		has_opt = 1;
	}

	/* get query reference */
	query = _dns_client_get_request(packet->head.id, domain);
	if (query == NULL) {
		return 0;
	}

	if (has_opt == 0 && server_info->flags.result_flag & DNSSERVER_FLAG_CHECK_EDNS) {
		_dns_client_query_release(query);
		return 0;
	}

	/* avoid multiple replies */
	if (_dns_replied_check_add(query, (struct sockaddr *)from, from_len) != 0) {
		_dns_client_query_release(query);
		return 0;
	}

	request_num = atomic_dec_return(&query->dns_request_sent);
	if (request_num < 0) {
		_dns_client_query_release(query);
		tlog(TLOG_ERROR, "send count is invalid, %d", request_num);
		return -1;
	}

	/* notify caller dns query result */
	if (query->callback) {
		ret = query->callback(query->domain, DNS_QUERY_RESULT, server_info->flags.result_flag, packet, inpacket,
							  inpacket_len, query->user_ptr);
		if (request_num == 0 || ret) {
			/* if all server replied, or done, stop query, release resource */
			_dns_client_query_remove(query);
		}

		if (ret == 0) {
			query->has_result = 1;
		}
	}

	_dns_client_query_release(query);
	return 0;
}

static int _dns_client_create_socket_udp(struct dns_server_info *server_info)
{
	int fd = 0;
	struct epoll_event event;
	const int on = 1;
	const int val = 255;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	fd = socket(server_info->ai_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
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
	server_info->status = DNS_SERVER_STATUS_CONNECTIONLESS;
	setsockopt(server_info->fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	setsockopt(server_info->fd, SOL_IP, IP_TTL, &val, sizeof(val));
	setsockopt(server_info->fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(server_info->fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (server_info->ai_family == AF_INET6) {
		/* for recving ip ttl value */
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
	}

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
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	fd = socket(server_info->ai_family, SOCK_STREAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed.");
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	/* enable tcp fast open */
	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &yes, sizeof(yes)) != 0) {
		tlog(TLOG_DEBUG, "enable TCP fast open failed.");
	}

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, &yes, sizeof(yes));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &yes, sizeof(yes));
	set_sock_keepalive(fd, 15, 3, 4);

	if (connect(fd, (struct sockaddr *)&server_info->addr, server_info->ai_addrlen) != 0) {
		if (errno == ENETUNREACH) {
			tlog(TLOG_DEBUG, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}

		if (errno != EINPROGRESS) {
			tlog(TLOG_ERROR, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	server_info->fd = fd;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	tlog(TLOG_DEBUG, "tcp server %s connecting.\n", server_info->ip);

	return 0;
errout:
	if (server_info->fd > 0) {
		server_info->fd = -1;
	}

	server_info->status = DNS_SERVER_STATUS_INIT;

	if (fd > 0) {
		close(fd);
	}
	return -1;
}

static int _DNS_client_create_socket_tls(struct dns_server_info *server_info, char *hostname)
{
	int fd = 0;
	struct epoll_event event;
	SSL *ssl = NULL;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	if (server_info->ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "create ssl ctx failed, %s", server_info->ip);
		goto errout;
	}

	ssl = SSL_new(server_info->ssl_ctx);
	if (ssl == NULL) {
		tlog(TLOG_ERROR, "new ssl failed, %s", server_info->ip);
		goto errout;
	}

	fd = socket(server_info->ai_family, SOCK_STREAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &yes, sizeof(yes)) != 0) {
		tlog(TLOG_DEBUG, "enable TCP fast open failed.");
	}

	// ? this cause ssl crash ?
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, &yes, sizeof(yes));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &yes, sizeof(yes));
	set_sock_keepalive(fd, 15, 3, 4);
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));

	if (connect(fd, (struct sockaddr *)&server_info->addr, server_info->ai_addrlen) != 0) {
		if (errno == ENETUNREACH) {
			tlog(TLOG_DEBUG, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}

		if (errno != EINPROGRESS) {
			tlog(TLOG_ERROR, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	SSL_set_connect_state(ssl);
	if (SSL_set_fd(ssl, fd) == 0) {
		tlog(TLOG_ERROR, "ssl set fd failed.");
		goto errout;
	}

	/* reuse ssl session */
	if (server_info->ssl_session) {
		SSL_set_session(ssl, server_info->ssl_session);
	}

	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
	if (hostname[0] != 0) {
		SSL_set_tlsext_host_name(ssl, hostname);
	}

	server_info->fd = fd;
	server_info->ssl = ssl;
	server_info->ssl_write_len = -1;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		goto errout;
	}

	tlog(TLOG_DEBUG, "tls server %s connecting.\n", server_info->ip);

	return 0;
errout:
	if (server_info->fd > 0) {
		server_info->fd = -1;
	}

	if (server_info->ssl) {
		server_info->ssl = NULL;
	}

	server_info->status = DNS_SERVER_STATUS_INIT;

	if (fd > 0) {
		close(fd);
	}

	if (ssl) {
		SSL_free(ssl);
	}

	return -1;
}

static int _dns_client_create_socket(struct dns_server_info *server_info)
{
	time(&server_info->last_send);
	time(&server_info->last_recv);

	if (server_info->fd > 0) {
		return -1;
	}

	if (server_info->type == DNS_SERVER_UDP) {
		return _dns_client_create_socket_udp(server_info);
	} else if (server_info->type == DNS_SERVER_TCP) {
		return _DNS_client_create_socket_tcp(server_info);
	} else if (server_info->type == DNS_SERVER_TLS) {
		struct client_dns_server_flag_tls *flag_tls;
		flag_tls = &server_info->flags.tls;
		return _DNS_client_create_socket_tls(server_info, flag_tls->hostname);
	} else if (server_info->type == DNS_SERVER_HTTPS) {
		struct client_dns_server_flag_https *flag_https;
		flag_https = &server_info->flags.https;
		return _DNS_client_create_socket_tls(server_info, flag_https->hostname);
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
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	int ttl = 0;
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

	len = recvmsg(server_info->fd, &msg, MSG_DONTWAIT);
	if (len < 0) {
		tlog(TLOG_ERROR, "recvfrom failed, %s\n", strerror(errno));
		return -1;
	}
	from_len = msg.msg_namelen;

	/* Get the TTL of the IP header */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				int *ttlPtr = (int *)CMSG_DATA(cmsg);
				ttl = *ttlPtr;
			}
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				int *ttlPtr = (int *)CMSG_DATA(cmsg);
				ttl = *ttlPtr;
			}
		}
	}

	tlog(TLOG_DEBUG, "recv udp packet from %s, len: %d, ttl: %d",
		 gethost_by_addr(from_host, sizeof(from_host), (struct sockaddr *)&from), len, ttl);

	/* update recv time */
	time(&server_info->last_recv);

	/* processing dns packet */
	if (_dns_client_recv(server_info, inpacket, len, (struct sockaddr *)&from, from_len) != 0) {
		return -1;
	}

	return 0;
}

static int _dns_client_socket_ssl_send(struct dns_server_info *server, const void *buf, int num)
{
	int ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (server->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	ret = _ssl_write(server, buf, num);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error(server, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
		return 0;
		break;
	case SSL_ERROR_ZERO_RETURN:
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -1;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -1;
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

static int _dns_client_socket_ssl_recv(struct dns_server_info *server, void *buf, int num)
{
	int ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (server->ssl == NULL) {
		errno = EFAULT;
		return -1;
	}

	ret = _ssl_read(server, buf, num);
	if (ret >= 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error(server, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -1;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -1;
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

		tlog(TLOG_ERROR, "SSL read fail error no: %s(%lx)\n", ERR_reason_error_string(ssl_err), ssl_err);
		errno = EFAULT;
		ret = -1;
		break;
	case SSL_ERROR_SYSCALL:
		if (errno == 0) {
			return 0;
		}

		if (errno != ECONNRESET) {
			tlog(TLOG_INFO, "SSL syscall failed, %s ", strerror(errno));
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

static int _dns_client_socket_send(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_UDP) {
		return -1;
	} else if (server_info->type == DNS_SERVER_TCP) {
		return send(server_info->fd, server_info->send_buff.data, server_info->send_buff.len, MSG_NOSIGNAL);
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS) {
		int write_len = server_info->send_buff.len;
		if (server_info->ssl_write_len > 0) {
			write_len = server_info->ssl_write_len;
			server_info->ssl_write_len = -1;
		}
		int ret = _dns_client_socket_ssl_send(server_info, server_info->send_buff.data, write_len);
		if (ret != 0) {
			if (errno == EAGAIN) {
				server_info->ssl_write_len = write_len;
			}
		}
		return ret;
	} else {
		return -1;
	}
}

static int _dns_client_socket_recv(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_UDP) {
		return -1;
	} else if (server_info->type == DNS_SERVER_TCP) {
		return recv(server_info->fd, server_info->recv_buff.data + server_info->recv_buff.len,
					DNS_TCP_BUFFER - server_info->recv_buff.len, 0);
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS) {
		return _dns_client_socket_ssl_recv(server_info, server_info->recv_buff.data + server_info->recv_buff.len,
										   DNS_TCP_BUFFER - server_info->recv_buff.len);
	} else {
		return -1;
	}
}

static int _dns_client_process_tcp_buff(struct dns_server_info *server_info)
{
	int len = 0;
	int dns_packet_len = 0;
	struct http_head *http_head = NULL;
	unsigned char *inpacket_data = NULL;
	int ret = -1;

	while (1) {
		if (server_info->type == DNS_SERVER_HTTPS) {
			http_head = http_head_init(4096);
			if (http_head == NULL) {
				goto out;
			}

			len = http_head_parse(http_head, (char *)server_info->recv_buff.data, server_info->recv_buff.len);
			if (len < 0) {
				if (len == -1) {
					ret = 0;
					goto out;
				}

				tlog(TLOG_DEBUG, "remote server not supported.");
				goto out;
			}

			if (http_head_get_httpcode(http_head) != 200) {
				tlog(TLOG_WARN, "http server query from %s:%d failed, server return http code : %d, %s",
					 server_info->ip, server_info->port, http_head_get_httpcode(http_head),
					 http_head_get_httpcode_msg(http_head));
				goto out;
			}

			dns_packet_len = http_head_get_data_len(http_head);
			inpacket_data = (unsigned char *)http_head_get_data(http_head);
		} else {
			/* tcp result format
			 * | len (short) | dns query result |
			 */
			inpacket_data = server_info->recv_buff.data;
			len = ntohs(*((unsigned short *)(inpacket_data)));
			if (len <= 0 || len >= DNS_IN_PACKSIZE) {
				/* data len is invalid */
				goto out;
			}

			if (len > server_info->recv_buff.len - 2) {
				/* len is not expceded, wait and recv */
				ret = 0;
				goto out;
			}

			inpacket_data = server_info->recv_buff.data + 2;
			dns_packet_len = len;
			len += 2;
		}

		tlog(TLOG_DEBUG, "recv tcp packet from %s, len = %d", server_info->ip, len);
		/* process result */
		if (_dns_client_recv(server_info, inpacket_data, dns_packet_len, &server_info->addr, server_info->ai_addrlen) !=
			0) {
			goto out;
		}

		if (http_head) {
			http_head_destroy(http_head);
			http_head = NULL;
		}

		server_info->recv_buff.len -= len;
		if (server_info->recv_buff.len < 0) {
			tlog(TLOG_ERROR, "Internal error.");
			abort();
		}

		/* move to next result */
		if (server_info->recv_buff.len > 0) {
			memmove(server_info->recv_buff.data, server_info->recv_buff.data + len, server_info->recv_buff.len);
		} else {
			ret = 0;
			goto out;
		}
	}

	ret = 0;
out:
	if (http_head) {
		http_head_destroy(http_head);
	}
	return ret;
}

static int _dns_client_process_tcp(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int len;
	int ret = -1;

	if (event->events & EPOLLIN) {
		/* receive from tcp */
		len = _dns_client_socket_recv(server_info);
		if (len < 0) {
			/* no data to recv, try again */
			if (errno == EAGAIN) {
				return 0;
			}

			/* FOR GFW */
			if (errno == ECONNRESET) {
				goto errout;
			}

			if (errno == ETIMEDOUT) {
				tlog(TLOG_INFO, "recv failed, server %s:%d, %s\n", server_info->ip, server_info->port, strerror(errno));
				goto errout;
			}

			tlog(TLOG_ERROR, "recv failed, server %s:%d, %s\n", server_info->ip, server_info->port, strerror(errno));
			goto errout;
		}

		/* peer server close */
		if (len == 0) {
			pthread_mutex_lock(&client.server_list_lock);
			_dns_client_close_socket(server_info);
			server_info->recv_buff.len = 0;
			if (server_info->send_buff.len > 0) {
				/* still remain request data, reconnect and send*/
				ret = _dns_client_create_socket(server_info);
			} else {
				ret = 0;
			}
			pthread_mutex_unlock(&client.server_list_lock);
			tlog(TLOG_DEBUG, "peer close, %s", server_info->ip);
			return ret;
		}

		time(&server_info->last_recv);
		server_info->recv_buff.len += len;
		if (server_info->recv_buff.len <= 2) {
			/* wait and recv */
			return 0;
		}

		if (_dns_client_process_tcp_buff(server_info) != 0) {
			goto errout;
		}
	}

	/* when connected */
	if (event->events & EPOLLOUT) {
		struct epoll_event event;

		if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
			server_info->status = DNS_SERVER_STATUS_CONNECTED;
			tlog(TLOG_DEBUG, "tcp server %s connected", server_info->ip);
		}

		if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
			server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
		}

		if (server_info->send_buff.len > 0) {
			/* send existing send_buffer data  */
			len = _dns_client_socket_send(server_info);
			if (len < 0) {
				if (errno == EAGAIN) {
					return 0;
				}
				goto errout;
			}

			pthread_mutex_lock(&client.server_list_lock);
			server_info->send_buff.len -= len;
			if (server_info->send_buff.len > 0) {
				memmove(server_info->send_buff.data, server_info->send_buff.data + len, server_info->send_buff.len);
			} else if (server_info->send_buff.len < 0) {
				tlog(TLOG_ERROR, "Internal Error");
				abort();
			}
			pthread_mutex_unlock(&client.server_list_lock);
		}
		/* still remain data, retry */
		if (server_info->send_buff.len > 0) {
			return 0;
		}

		/* clear epllout event */
		memset(&event, 0, sizeof(event));
		event.events = EPOLLIN;
		event.data.ptr = server_info;
		if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			goto errout;
		}
	}

	return 0;

errout:
	pthread_mutex_lock(&client.server_list_lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&client.server_list_lock);

	return -1;
}

static inline int _dns_client_to_hex(int c)
{
	if (c > 0x9) {
		return 'A' + c - 0xA;
	} else {
		return '0' + c;
	}
}

static int _dns_client_tls_matchName(const char *host, const char *pattern, int size)
{
	int match = -1;
	int i = 0, j = 0;

	while (i < size && host[j] != '\0') {
		if (toupper(pattern[i]) == toupper(host[j])) {
			i++;
			j++;
			continue;
		}
		if (pattern[i] == '*') {
			while (host[j] != '.' && host[j] != '\0') {
				j++;
			}
			i++;
			continue;
		}
		break;
	}

	if (i == size && host[j] == '\0') {
		match = 0;
	}

	return match;
}

static int _dns_client_tls_get_cert_CN(X509 *cert, char *cn, int max_cn_len)
{
	X509_NAME *cert_name = NULL;

	cert_name = X509_get_subject_name(cert);
	if (cert_name == NULL) {
		tlog(TLOG_ERROR, "get subject name failed.");
		goto errout;
	}

	if (X509_NAME_get_text_by_NID(cert_name, NID_commonName, cn, max_cn_len) == -1) {
		tlog(TLOG_ERROR, "cannot found x509 name");
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _dns_client_tls_verify(struct dns_server_info *server_info)
{
	X509 *cert = NULL;
	X509_PUBKEY *pubkey = NULL;
	char peer_CN[256];
	char cert_fingerprint[256];
	int i = 0;
	int key_len = 0;
	unsigned char *key_data = NULL;
	unsigned char *key_data_tmp = NULL;
	unsigned char *key_sha256 = NULL;
	char *spki = NULL;
	int spki_len = 0;
	char *tls_host_verify = NULL;
	if (server_info->ssl == NULL) {
		return -1;
	}

	pthread_mutex_lock(&server_info->lock);
	cert = SSL_get_peer_certificate(server_info->ssl);
	if (cert == NULL) {
		pthread_mutex_unlock(&server_info->lock);
		tlog(TLOG_ERROR, "get peer certificate failed.");
		return -1;
	}

	if (server_info->skip_check_cert == 0) {
		long res = SSL_get_verify_result(server_info->ssl);
		if (res != X509_V_OK) {
			pthread_mutex_unlock(&server_info->lock);
			peer_CN[0] = '\0';
			_dns_client_tls_get_cert_CN(cert, peer_CN, sizeof(peer_CN));
			tlog(TLOG_WARN, "peer server %s certificate verify failed, ret = %ld", server_info->ip, res);
			tlog(TLOG_WARN, "peer CN: %s", peer_CN);
			goto errout;
		}
	}
	pthread_mutex_unlock(&server_info->lock);

	if (_dns_client_tls_get_cert_CN(cert, peer_CN, sizeof(peer_CN)) != 0) {
		tlog(TLOG_ERROR, "get cert CN failed.");
		goto errout;
	}

	tlog(TLOG_DEBUG, "peer CN: %s", peer_CN);
	/* check tls host */
	tls_host_verify = _dns_client_server_get_tls_host_verify(server_info);
	if (tls_host_verify) {
		if (_dns_client_tls_matchName(tls_host_verify, peer_CN, strnlen(peer_CN, DNS_MAX_CNAME_LEN)) != 0) {
			tlog(TLOG_INFO, "server %s CN is invalid, peer CN: %s, expect CN: %s", server_info->ip, peer_CN,
				 tls_host_verify);
			goto errout;
		}
	}

	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL) {
		tlog(TLOG_ERROR, "get pub key failed.");
		goto errout;
	}

	/* get spki pin */
	key_len = i2d_X509_PUBKEY(pubkey, NULL);
	if (key_len <= 0) {
		tlog(TLOG_ERROR, "get x509 public key failed.");
		goto errout;
	}

	key_data = OPENSSL_malloc(key_len);
	key_data_tmp = key_data;
	if (key_data == NULL) {
		tlog(TLOG_ERROR, "malloc memory failed.");
		goto errout;
	}

	i2d_X509_PUBKEY(pubkey, &key_data_tmp);

	/* Get the SHA256 value of SPKI */
	key_sha256 = SSL_SHA256(key_data, key_len, NULL);
	if (key_sha256 == NULL) {
		tlog(TLOG_ERROR, "get sha256 failed.");
		goto errout;
	}

	char *ptr = cert_fingerprint;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		*ptr = _dns_client_to_hex(key_sha256[i] >> 4 & 0xF);
		ptr++;
		*ptr = _dns_client_to_hex(key_sha256[i] & 0xF);
		ptr++;
		*ptr = ':';
		ptr++;
	}
	ptr--;
	*ptr = 0;
	tlog(TLOG_DEBUG, "cert SPKI pin(%s): %s", "sha256", cert_fingerprint);

	spki = _dns_client_server_get_spki(server_info, &spki_len);
	if (spki && spki_len > 0 && spki_len <= SHA256_DIGEST_LENGTH) {
		/* check SPKI */
		if (memcmp(spki, key_sha256, spki_len) != 0) {
			tlog(TLOG_INFO, "server %s cert spki is invalid", server_info->ip);
			goto errout;
		} else {
			tlog(TLOG_DEBUG, "server %s cert spki verify succeed", server_info->ip);
		}
	}

	OPENSSL_free(key_data);
	X509_free(cert);
	return 0;

errout:
	if (key_data) {
		OPENSSL_free(key_data);
	}

	if (cert) {
		X509_free(cert);
	}

	return -1;
}

static int _dns_client_process_tls(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int ret = -1;
	struct epoll_event fd_event;
	int ssl_ret;

	if (unlikely(server_info->ssl == NULL)) {
		tlog(TLOG_ERROR, "ssl is invalid.");
		goto errout;
	}

	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		/* do SSL hand shake */
		ret = _ssl_do_handshake(server_info);
		if (ret == 0) {
			goto errout;
		} else if (ret < 0) {
			memset(&fd_event, 0, sizeof(fd_event));
			ssl_ret = _ssl_get_error(server_info, ret);
			if (ssl_ret == SSL_ERROR_WANT_READ) {
				fd_event.events = EPOLLIN;
			} else if (ssl_ret == SSL_ERROR_WANT_WRITE) {
				fd_event.events = EPOLLOUT | EPOLLIN;
			} else if (ssl_ret == SSL_ERROR_SYSCALL) {
				if (errno != ENETUNREACH) {
					tlog(TLOG_WARN, "Handshake with %s failed, %s", server_info->ip, strerror(errno));
				}
				goto errout;
			} else {
				unsigned long ssl_err = ERR_get_error();
				int ssl_reason = ERR_GET_REASON(ssl_err);
				tlog(TLOG_WARN, "Handshake with %s failed, error no: %s(%d, %d, %d)\n", server_info->ip,
					 ERR_reason_error_string(ssl_err), ret, ssl_ret, ssl_reason);
				goto errout;
			}

			fd_event.data.ptr = server_info;
			if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &fd_event) != 0) {
				tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
				goto errout;
			}

			return 0;
		}

		tlog(TLOG_DEBUG, "tls server %s connected.\n", server_info->ip);
		/* Was the stored session reused? */
		if (_ssl_session_reused(server_info)) {
			tlog(TLOG_DEBUG, "reused session");
		} else {
			tlog(TLOG_DEBUG, "new session");
			pthread_mutex_lock(&client.server_list_lock);
			if (server_info->ssl_session) {
				/* free session */
				SSL_SESSION_free(server_info->ssl_session);
				server_info->ssl_session = NULL;
			}

			if (_dns_client_tls_verify(server_info) != 0) {
				tlog(TLOG_WARN, "peer %s verify failed.", server_info->ip);
				pthread_mutex_unlock(&client.server_list_lock);
				goto errout;
			}

			/* save ssl session for next request */
			server_info->ssl_session = _ssl_get1_session(server_info);
			pthread_mutex_unlock(&client.server_list_lock);
		}

		server_info->status = DNS_SERVER_STATUS_CONNECTED;
		memset(&fd_event, 0, sizeof(fd_event));
		fd_event.events = EPOLLIN | EPOLLOUT;
		fd_event.data.ptr = server_info;
		if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &fd_event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			goto errout;
		}
	}

	return _dns_client_process_tcp(server_info, event, now);
errout:
	pthread_mutex_lock(&client.server_list_lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	_dns_client_close_socket(server_info);
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
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS) {
		/* recive from tls */
		return _dns_client_process_tls(server_info, event, now);
	} else {
		return -1;
	}

	return 0;
}

static int _dns_client_send_udp(struct dns_server_info *server_info, void *packet, int len)
{
	int send_len = 0;
	if (server_info->fd <= 0) {
		return -1;
	}

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
		errno = ENOMEM;
		return -1;
	}

	memcpy(server_info->send_buff.data + server_info->send_buff.len, packet, len);
	server_info->send_buff.len += len;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int _dns_client_send_tcp(struct dns_server_info *server_info, void *packet, unsigned short len)
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

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, len);
	}

	if (server_info->fd <= 0) {
		return -1;
	}

	send_len = send(server_info->fd, inpacket, len, MSG_NOSIGNAL);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, len);
		} else if (errno == EPIPE) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, len - send_len);
	}

	return 0;
}

static int _dns_client_send_tls(struct dns_server_info *server_info, void *packet, unsigned short len)
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

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, len);
	}

	if (server_info->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	send_len = _dns_client_socket_ssl_send(server_info, inpacket, len);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, len);
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, len - send_len);
	}

	return 0;
}

static int _dns_client_send_https(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	int send_len = 0;
	int http_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;
	struct client_dns_server_flag_https *https_flag = NULL;

	if (len > sizeof(inpacket_data) - 2) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	https_flag = &server_info->flags.https;

	http_len = snprintf((char *)inpacket, DNS_IN_PACKSIZE,
						"POST %s HTTP/1.1\r\n"
						"Host: %s\r\n"
						"content-type: application/dns-message\r\n"
						"Content-Length: %d\r\n"
						"\r\n",
						https_flag->path, https_flag->httphost, len);
	memcpy(inpacket + http_len, packet, len);
	http_len += len;

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, http_len);
	}

	if (server_info->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	send_len = _dns_client_socket_ssl_send(server_info, inpacket, http_len);
	if (send_len <= 0) {
		if (errno == EAGAIN || errno == EPIPE || server_info->ssl == NULL) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, http_len);
		} else if (server_info->ssl && errno != ENOMEM) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < http_len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, http_len - send_len);
	}

	return 0;
}

static int _dns_client_send_packet(struct dns_query_struct *query, void *packet, int len)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group_member *group_member = NULL;
	struct dns_server_group_member *tmp = NULL;
	int ret = 0;
	int send_err = 0;
	int i = 0;
	int total_server = 0;

	query->send_tick = get_tick_count();

	/* send query to all dns servers */
	for (i = 0; i < 2; i++) {
		total_server = 0;
		pthread_mutex_lock(&client.server_list_lock);
		list_for_each_entry_safe(group_member, tmp, &query->server_group->head, list)
		{
			server_info = group_member->server;
			total_server++;
			tlog(TLOG_DEBUG, "send query to server %s", server_info->ip);
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
			case DNS_SERVER_TLS:
				/* tls query */
				ret = _dns_client_send_tls(server_info, packet, len);
				send_err = errno;
				break;
			case DNS_SERVER_HTTPS:
				/* https query */
				ret = _dns_client_send_https(server_info, packet, len);
				send_err = errno;
				break;
			default:
				/* unsupport query type */
				ret = -1;
				break;
			}

			if (ret != 0) {
				if (send_err == ENETUNREACH) {
					tlog(TLOG_DEBUG, "send query to %s failed, %s, type: %d", server_info->ip, strerror(send_err),
						 server_info->type);
					_dns_client_close_socket(server_info);
					atomic_dec(&query->dns_request_sent);
					continue;
				}

				tlog(TLOG_DEBUG, "send query to %s failed, %s, type: %d", server_info->ip, strerror(send_err),
					 server_info->type);
				time_t now;
				time(&now);
				if (now - 5 > server_info->last_recv || send_err != ENOMEM) {
					_dns_client_shutdown_socket(server_info);
				}

				atomic_dec(&query->dns_request_sent);
				continue;
			}
			time(&server_info->last_send);
		}
		pthread_mutex_unlock(&client.server_list_lock);

		if (atomic_read(&query->dns_request_sent) > 0) {
			break;
		}
	}

	if (atomic_read(&query->dns_request_sent) <= 0) {
		tlog(TLOG_ERROR, "Send query to upstream server failed, total server number %d", total_server);
		return -1;
	}

	return 0;
}

static int _dns_client_dns_add_ecs(struct dns_packet *packet, int qtype)
{
	if (qtype == DNS_T_A && client.ecs_ipv4.enable) {
		struct dns_opt_ecs ecs;
		ecs.family = DNS_ADDR_FAMILY_IP;
		ecs.source_prefix = client.ecs_ipv4.bitlen;
		ecs.scope_prefix = 0;
		memcpy(ecs.addr, client.ecs_ipv4.ipv4_addr, DNS_RR_A_LEN);
		return dns_add_OPT_ECS(packet, &ecs);
	} else if (qtype == DNS_T_AAAA && client.ecs_ipv6.enable) {
		struct dns_opt_ecs ecs;
		ecs.family = DNS_ADDR_FAMILY_IPV6;
		ecs.source_prefix = client.ecs_ipv6.bitlen;
		ecs.scope_prefix = 0;
		memcpy(ecs.addr, client.ecs_ipv6.ipv6_addr, DNS_RR_AAAA_LEN);
		return dns_add_OPT_ECS(packet, &ecs);
	}
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

	if (dns_packet_init(packet, DNS_PACKSIZE, &head) != 0) {
		tlog(TLOG_ERROR, "init packet failed.");
		return -1;
	}

	/* add question */
	if (dns_add_domain(packet, doamin, query->qtype, DNS_C_IN) != 0) {
		tlog(TLOG_ERROR, "add domain to packet failed.");
		return -1;
	}

	dns_set_OPT_payload_size(packet, DNS_IN_PACKSIZE);
	/* dns_add_OPT_TCP_KEEYALIVE(packet, 600); */
	if (_dns_client_dns_add_ecs(packet, query->qtype) != 0) {
		tlog(TLOG_ERROR, "add ecs failed.");
		return -1;
	}

	/* encode packet */
	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		tlog(TLOG_ERROR, "encode query failed.");
		return -1;
	}

	if (encode_len > DNS_IN_PACKSIZE) {
		tlog(TLOG_ERROR, "size is invalid.");
		abort();
		return -1;
	}

	/* send query packet */
	return _dns_client_send_packet(query, inpacket, encode_len);
}

int dns_client_query(char *domain, int qtype, dns_client_callback callback, void *user_ptr, const char *group_name)
{
	struct dns_query_struct *query = NULL;
	int ret = 0;
	uint32_t key = 0;

	if (domain == NULL) {
		goto errout;
	}

	query = malloc(sizeof(*query));
	if (query == NULL) {
		goto errout;
	}
	memset(query, 0, sizeof(*query));

	INIT_HLIST_NODE(&query->domain_node);
	INIT_LIST_HEAD(&query->dns_request_list);
	atomic_set(&query->refcnt, 0);
	atomic_set(&query->dns_request_sent, 0);
	atomic_set(&query->retry_count, DNS_QUERY_RETRY);
	hash_init(query->replied_map);
	safe_strncpy(query->domain, domain, DNS_MAX_CNAME_LEN);
	query->user_ptr = user_ptr;
	query->callback = callback;
	query->qtype = qtype;
	query->send_tick = 0;
	query->has_result = 0;
	query->sid = atomic_inc_return(&dns_client_sid);
	query->server_group = _dns_client_get_dnsserver_group(group_name);
	if (query->server_group == NULL) {
		tlog(TLOG_ERROR, "get dns server group %s failed.", group_name);
		goto errout;
	}

	_dns_client_query_get(query);
	/* add query to hashtable */
	key = hash_string(domain);
	key = jhash(&query->sid, sizeof(query->sid), key);
	pthread_mutex_lock(&client.domain_map_lock);
	hash_add(client.domain_map, &query->domain_node, key);
	pthread_mutex_unlock(&client.domain_map_lock);

	/* send query */
	_dns_client_query_get(query);
	ret = _dns_client_send_query(query, domain);
	if (ret != 0) {
		_dns_client_query_release(query);
		goto errout_del_list;
	}

	pthread_mutex_lock(&client.domain_map_lock);
	list_add_tail(&query->dns_request_list, &client.dns_request_list);
	pthread_mutex_unlock(&client.domain_map_lock);

	tlog(TLOG_INFO, "send request %s, qtype %d, id %d\n", domain, qtype, query->sid);
	_dns_client_query_release(query);

	return 0;
errout_del_list:
	query->callback = NULL;
	_dns_client_query_remove(query);
	query = NULL;
errout:
	if (query) {
		free(query);
	}
	return -1;
}

static void _dns_client_check_servers(void)
{
	struct dns_server_info *server_info, *tmp;
	static unsigned int second_count = 0;

	second_count++;
	if (second_count % 60 != 0) {
		return;
	}

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->type != DNS_SERVER_UDP) {
			continue;
		}

		if (server_info->last_send - 600 > server_info->last_recv) {
			server_info->recv_buff.len = 0;
			server_info->send_buff.len = 0;
			tlog(TLOG_DEBUG, "server %s may failure.", server_info->ip);
			_dns_client_close_socket(server_info);
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}

static int _dns_client_pending_server_resolve(char *domain, dns_rtcode_t rtcode, dns_type_t addr_type, char *ip,
											  unsigned int ping_time, void *user_ptr)
{
	struct dns_server_pending *pending = user_ptr;
	int ret = 0;

	if (addr_type == DNS_T_A) {
		pending->ping_time_v4 = -1;
		if (rtcode == DNS_RC_NOERROR) {
			pending->has_v4 = 1;
			pending->ping_time_v4 = ping_time;
			safe_strncpy(pending->ipv4, ip, DNS_HOSTNAME_LEN);
		}
	} else if (addr_type == DNS_T_AAAA) {
		pending->ping_time_v6 = -1;
		if (rtcode == DNS_RC_NOERROR) {
			pending->has_v6 = 1;
			pending->ping_time_v6 = ping_time;
			safe_strncpy(pending->ipv6, ip, DNS_HOSTNAME_LEN);
		}
	} else {
		ret = -1;
	}

	_dns_client_server_pending_release(pending);
	return ret;
}

static int _dns_client_add_pendings(struct dns_server_pending *pending, char *ip)
{
	struct dns_server_pending_group *group, *tmp;

	if (_dns_client_add_server_pending(ip, pending->host, pending->port, pending->type, &pending->flags, 0) != 0) {
		return -1;
	}

	list_for_each_entry_safe(group, tmp, &pending->group_list, list)
	{
		if (_dns_client_add_to_group_pending(group->group_name, ip, pending->port, pending->type, 0) != 0) {
			tlog(TLOG_WARN, "add server to group failed, skip add.");
		}

		list_del_init(&group->list);
		free(group);
	}

	return 0;
}

static void _dns_client_add_pending_servers(void)
{
	struct dns_server_pending *pending, *tmp;
	static int dely = 0;

	/* add pending server after 3 seconds */
	if (++dely < 3) {
		return;
	}
	dely = 0;

	pthread_mutex_lock(&pending_server_mutex);
	list_for_each_entry_safe(pending, tmp, &pending_servers, list)
	{
		/* send dns type A, AAAA query to bootstrap DNS server */
		int add_success = 0;
		char *dnsserver_ip = NULL;

		if (pending->query_v4 == 0) {
			pending->query_v4 = 1;
			_dns_client_server_pending_get(pending);
			if (dns_server_query(pending->host, DNS_T_A, 0, _dns_client_pending_server_resolve, pending) != 0) {
				_dns_client_server_pending_release_lck(pending);
			}
		}

		if (pending->query_v6 == 0) {
			pending->query_v6 = 1;
			_dns_client_server_pending_get(pending);
			if (dns_server_query(pending->host, DNS_T_AAAA, 0, _dns_client_pending_server_resolve, pending) != 0) {
				_dns_client_server_pending_release_lck(pending);
			}
		}

		/* if both A, AAAA has query result, select fastest IP address */
		if (pending->has_v4 && pending->has_v6) {
			if (pending->ping_time_v4 <= pending->ping_time_v6 && pending->ipv4[0]) {
				dnsserver_ip = pending->ipv4;
			} else {
				dnsserver_ip = pending->ipv6;
			}
		} else if (pending->has_v4) {
			dnsserver_ip = pending->ipv4;
		} else if (pending->has_v6) {
			dnsserver_ip = pending->ipv6;
		}

		if (dnsserver_ip && dnsserver_ip[0]) {
			if (_dns_client_add_pendings(pending, dnsserver_ip) == 0) {
				add_success = 1;
			}
		}

		pending->retry_cnt++;
		if (pending->retry_cnt >= DNS_PENDING_SERVER_RETRY || add_success) {
			if (add_success == 0) {
				tlog(TLOG_WARN, "add pending DNS server %s failed.", pending->host);
			}
			list_del_init(&pending->list);
			_dns_client_server_pending_release_lck(pending);
		} else {
			tlog(TLOG_DEBUG, "add pending DNS server %s failed, retry %d...", pending->host, pending->retry_cnt);
			pending->query_v4 = 0;
			pending->query_v6 = 0;
		}

		/* if has no bootstrap DNS, just call getaddrinfo to get address */
		if (dns_client_has_bootstrap_dns == 0) {
			if (_dns_client_add_pendings(pending, pending->host) != 0) {
				pthread_mutex_unlock(&pending_server_mutex);
				tlog(TLOG_ERROR, "add pending DNS server %s failed", pending->host);
				exit(1);
				return;
			}

			_dns_client_server_pending_release_lck(pending);
		}
	}
	pthread_mutex_unlock(&pending_server_mutex);
}

static void _dns_client_period_run_second(void)
{
	_dns_client_check_tcp();
	_dns_client_check_servers();
	_dns_client_add_pending_servers();
}

static void _dns_client_period_run(void)
{
	struct dns_query_struct *query, *tmp;
	static unsigned int msec = 0;
	msec++;

	LIST_HEAD(check_list);

	unsigned long now = get_tick_count();

	/* get query which timed out to check list */
	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		if ((now - DNS_QUERY_TIMEOUT >= query->send_tick) && query->send_tick > 0) {
			list_add(&query->period_list, &check_list);
			_dns_client_query_get(query);
		}
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	list_for_each_entry_safe(query, tmp, &check_list, period_list)
	{
		/* free timed out query, and notify caller */
		list_del_init(&query->period_list);
		_dns_client_check_udp_nat(query);
		if (atomic_dec_and_test(&query->retry_count) || (query->has_result != 0)) {
			_dns_client_query_remove(query);
		} else {
			tlog(TLOG_DEBUG, "retry query %s", query->domain);
			_dns_client_send_query(query, query->domain);
		}
		_dns_client_query_release(query);
	}

	if (msec % 10 == 0) {
		_dns_client_period_run_second();
	}

	return;
}

static void *_dns_client_work(void *arg)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num;
	int i;
	unsigned long now = {0};
	unsigned int sleep = 100;
	int sleep_time;
	unsigned long expect_time = 0;

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
			if (server_info == NULL) {
				tlog(TLOG_WARN, "server info is invalid.");
				continue;
			}

			_dns_client_process(server_info, event, now);
		}
	}

	close(client.epoll_fd);
	client.epoll_fd = -1;

	return NULL;
}

int dns_client_set_ecs(char *ip, int subnet)
{
	return 0;
}

int dns_client_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret;

	if (client.epoll_fd > 0) {
		return -1;
	}

	memset(&client, 0, sizeof(client));
	pthread_attr_init(&attr);
	atomic_set(&client.dns_server_num, 0);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	pthread_mutex_init(&client.server_list_lock, NULL);
	INIT_LIST_HEAD(&client.dns_server_list);

	pthread_mutex_init(&client.domain_map_lock, NULL);
	hash_init(client.domain_map);
	hash_init(client.group);
	INIT_LIST_HEAD(&client.dns_request_list);

	if (dns_client_add_group(DNS_SERVER_GROUP_DEFAULT) != 0) {
		tlog(TLOG_ERROR, "add default server group failed.");
		goto errout;
	}

	client.default_group = _dns_client_get_group(DNS_SERVER_GROUP_DEFAULT);
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

void dns_client_exit(void)
{
	if (client.tid > 0) {
		void *ret = NULL;
		client.run = 0;
		pthread_join(client.tid, &ret);
	}

	/* free all resouces */
	_dns_client_server_remove_all();
	_dns_client_query_remove_all();
	_dns_client_group_remove_all();

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);
	if (client.ssl_ctx) {
		SSL_CTX_free(client.ssl_ctx);
		client.ssl_ctx = NULL;
	}
}
