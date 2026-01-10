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

#define _GNU_SOURCE
#include "smartdns/proxy_server.h"
#include "../dns_conf/ipset.h"
#include "../dns_conf/nftset.h"
#include "firewall.h"
#include "smartdns/dns_conf.h"
#include "smartdns/dns_server.h"
#include "smartdns/http_parse.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/list.h"
#include "smartdns/proxy.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netfilter_ipv4.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROXY_SERVER_MAXHOST_NAME 256
#define PROXY_SERVER_MAX_EVENTS 256
#define DEFAULT_SNI_PROXY_REDIRECT 80
#define DEFAULT_SNI_PROXY_PORT 443
#define DEFAULT_TPROXY_SERVER_PORT 1088
#define CONN_BUFF_SIZE (32 * 1024)
#define PROXY_SERVER_CONN_TIMEOUT 5
#define PROXY_SERVER_IDLE_TIMEOUT 600
#define SOCKET_IP_TOS (IPTOS_RELIABILITY | IPTOS_THROUGHPUT | IPTOS_LOWCOST)

struct rule_walk_args {
	void *args;
	int rule_index;
	uint32_t full_key_len;
	unsigned char *key[DOMAIN_RULE_MAX];
	uint32_t key_len[DOMAIN_RULE_MAX];
};

struct proxy_server_domain_rule {
	struct dns_rule *rules[DOMAIN_RULE_MAX];
	int is_sub_rule[DOMAIN_RULE_MAX];
};

typedef enum PROXY_SERVER_CONN_TYPE {
	PROXY_SERVER_CONN_NONE,
	PROXY_SERVER_CONN_SERVER_REDIRECT,
	PROXY_SERVER_CONN_SERVER,
	PROXY_SERVER_CONN_TPROXY_SERVER,
	PROXY_SERVER_CONN_TPROXY_SERVER_UDP,
	PROXY_SERVER_CONN_SNIPROXY_SERVER,
	PROXY_SERVER_CONN_CLIENT,
	PROXY_SERVER_CONN_CLIENT_REDIRECT,
	PROXY_SERVER_CONN_REMOTE,
} PROXY_SERVER_CONN_TYPE;

typedef enum PROXY_SERVER_CONN_STATE {
	PROXY_SERVER_CONN_STAT_INIT = 0,
	PROXY_SERVER_CONN_STAT_CONNECTING = 1,
	PROXY_SERVER_CONN_STAT_CONNECTED = 2,
	PROXY_SERVER_CONN_STAT_CONNECTED_PIPE_DATA = 3,
} PROXY_SERVER_CONN_STATE;

struct conn_buffer {
	char data[CONN_BUFF_SIZE];
	int size;
	int len;
};

/* proxy server cache - just stores the proxy name */
struct proxy_server {
	struct hlist_node node;
	char proxy_name[PROXY_NAME_LEN];
	time_t last_alive;
};

/* removed legacy proxy_server_info_cb and PROXY_SERVER_SOCKS5_CONN_STATE */

struct proxy_server_conn_remote {
	int sni_offset;
	int sni_len;
	struct proxy_server_conn *peer;
	struct list_head peer_list;
	struct proxy_server *proxy;
	proxy_server_type_t proxy_type;
	struct proxy_conn *pconn;
	struct dns_conf_group *conf;
};

struct proxy_server_conn_client {
	int sni_offset;
	int sni_len;
	struct proxy_server_conn *peer;
	struct proxy_server *proxy;
	int retry_all_server;
	char domain[DNS_MAX_CNAME_LEN];
	pthread_mutex_t peer_list_lock;
	struct list_head peer_list_head;
	struct dns_conf_group *conf;
	char listener_name[PROXY_NAME_LEN];
	char proxy_name[PROXY_NAME_LEN];
	char group_name[PROXY_NAME_LEN];
	PROXY_SERVER_CONN_TYPE listener_type;
	struct sockaddr_storage orig_dst;
	socklen_t orig_dst_len;
	int remote_dns;
	int force_aaaa_soa;
};

struct proxy_server_conn_redirect {
	struct conn_buffer *send_buff;
};

struct proxy_server_conn {
	struct list_head list;
	struct list_head check_list;
	PROXY_SERVER_CONN_TYPE type;
	int fd;

	atomic_t refcnt;
	PROXY_SERVER_CONN_STATE conn_state;
	socklen_t addr_len;
	time_t last;
	int timeout;
	struct sockaddr_storage addr;
	struct conn_buffer *buff;

	union {
		struct proxy_server_conn_remote remote;
		struct proxy_server_conn_client client;
		struct proxy_server_conn_redirect redirect;
	};
};

struct dns_proxy_server {
	atomic_t run;
	int epoll_fd;
	int random_fd;
	pthread_t tid;
	struct list_head conn_list;
	pthread_mutex_t conn_list_lock;

	struct list_head listeners;

	struct proxy_server default_proxy_server;

	DECLARE_HASHTABLE(proxy_server, 4);
};

static int is_proxy_server_init;
static struct dns_proxy_server dns_proxy_server;

static int _proxy_server_setup_firewall_rules(void)
{
	struct dns_tproxy_server_conf *t_conf = NULL;
	unsigned long i;

	hash_for_each(dns_proxy_table.tproxy, i, t_conf, node)
	{
		if (firewall_setup_rules(t_conf) != 0) {
			return -1;
		}
	}

	return 0;
}

static void _proxy_server_cleanup_firewall_rules(void)
{
	struct dns_tproxy_server_conf *t_conf = NULL;
	unsigned long i;

	// 遍历所有 tproxy-server
	hash_for_each(dns_proxy_table.tproxy, i, t_conf, node)
	{
		firewall_cleanup_rules(t_conf);
	}
}

/* get addr info */
static struct addrinfo *_proxy_server_getaddr(const char *host, int port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int ret = 0;
	char port_s[32];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;

	snprintf(port_s, sizeof(port_s), "%d", port);

	ret = getaddrinfo(host, port_s, &hints, &result);
	if (ret != 0) {
		tlog(TLOG_ERROR, "get addr info failed. %s\n", gai_strerror(errno));
		tlog(TLOG_ERROR, "host = %s, port = %s, type = %d, protocol = %d", host, port_s, type, protocol);
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

/* Helper function to get proxy server from hash table by name */
static struct proxy_server *_proxy_server_get_proxy_by_name(const char *proxy_name)
{
	uint32_t key = 0;
	struct proxy_server *proxy_server = NULL;
	struct hlist_node *tmp = NULL;
	const char *actual_proxy_name = NULL;

	if (proxy_name == NULL) {
		return NULL;
	}

	/* First check if already in cache */
	key = hash_string(proxy_name);
	hash_for_each_possible_safe(dns_proxy_server.proxy_server, proxy_server, tmp, node, key)
	{
		if (strncmp(proxy_server->proxy_name, proxy_name, PROXY_NAME_LEN) == 0) {
			return proxy_server;
		}
	}

	/* Not in cache, check if proxy exists using dns_conf API */
	actual_proxy_name = _dns_conf_get_proxy_name(proxy_name);
	if (actual_proxy_name == NULL) {
		tlog(TLOG_DEBUG, "proxy %s not found in dns_conf", proxy_name);
		return NULL;
	}

	/* Create proxy_server structure and add to cache */
	proxy_server = malloc(sizeof(*proxy_server));
	if (proxy_server == NULL) {
		tlog(TLOG_ERROR, "malloc proxy_server failed");
		return NULL;
	}

	memset(proxy_server, 0, sizeof(*proxy_server));
	safe_strncpy(proxy_server->proxy_name, actual_proxy_name, PROXY_NAME_LEN);
	time(&proxy_server->last_alive);

	/* Add to cache */
	hash_add(dns_proxy_server.proxy_server, &proxy_server->node, key);

	return proxy_server;
}

static void _proxy_server_free_proxy_cache(void)
{
	struct proxy_server *proxy_server = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int i;

	hash_for_each_safe(dns_proxy_server.proxy_server, i, tmp, proxy_server, node)
	{
		hash_del(&proxy_server->node);
		free(proxy_server);
	}
}

static int _proxy_server_recv_data(int fd, struct conn_buffer *buff)
{
	int n = 0;

	if (fd <= 0) {
		return -1;
	}

	for (;;) {
		if (buff->size == buff->len) {
			return 0;
		}

		/* 复制模式，读取数据到缓冲区 */
		n = recv(fd, buff->data + buff->len, buff->size - buff->len, 0);
		if (n > 0) {
			buff->len += n;
		}

		if (n == 0) {
			return -1;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 1;
			}
			return -1;
		}
	}

	return 0;
}

static int _proxy_server_send_data(struct conn_buffer *buff, int fd)
{
	int n = 0;

	if (fd <= 0) {
		return -1;
	}

	while (buff->len > 0) {
		int len = buff->len;
		if (len > buff->size) {
			len = buff->size;
		}

		n = send(fd, buff->data, len, MSG_NOSIGNAL);
		if (n == 0) {
			break;
		}

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 1;
			}
			return -1;
		}

		buff->len -= n;

		if (buff->len > 0) {
			memmove(buff->data, buff->data + n, buff->len);
		}
	}

	return 0;
}

static int _proxy_server_pipe_data(struct proxy_server_conn *from, struct proxy_server_conn *to)
{
	int in = 0;
	int out = 0;

	if (from->buff->len > 0) {
		out = _proxy_server_send_data(from->buff, to->fd);
		if (out < 0) {
			return -1;
		} else if (out == 1) {
			return 0;
		}
	}

	for (;;) {
		if (in == 0) {
			in = _proxy_server_recv_data(from->fd, from->buff);
			if (in < 0) {
				break;
			}
		}

		if (out == 0) {
			out = _proxy_server_send_data(from->buff, to->fd);
			if (out < 0) {
				break;
			}
		}

		if (in == 1 || out == 1) {
			return 0;
		}
	}

	return -1;
}

static int _proxy_server_conn_recv(struct proxy_server_conn *conn)
{
	int ret = 0;

	ret = _proxy_server_recv_data(conn->fd, conn->buff);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static void _proxy_server_conn_touch(struct proxy_server_conn *conn)
{
	time(&conn->last);
}

static int _proxy_server_conn_start(struct proxy_server_conn *conn)
{
	struct epoll_event event_client;
	memset(&event_client, 0, sizeof(event_client));
	event_client.data.ptr = conn;
	event_client.events = EPOLLIN | EPOLLOUT | EPOLLET;

	if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_ADD, conn->fd, &event_client) != 0) {
		tlog(TLOG_ERROR, "epoll add failed, %s", strerror(errno));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static int _proxy_server_conn_stop(struct proxy_server_conn *conn)
{
	if (conn->fd <= 0) {
		return -1;
	}

	if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL) != 0) {
		tlog(TLOG_ERROR, "epoll del failed, %d, %s", conn->fd, strerror(errno));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

static struct conn_buffer *_proxy_server_new_conn_buffer(void)
{
	struct conn_buffer *buffer = NULL;
	buffer = malloc(sizeof(*buffer));
	if (buffer == NULL) {
		goto errout;
	}

	memset(buffer, 0, sizeof(*buffer));
	buffer->size = sizeof(buffer->data);

	return buffer;

errout:
	if (buffer) {
		free(buffer);
	}

	return NULL;
}

static void _proxy_server_conn_put(struct proxy_server_conn *conn)
{
	if (conn == NULL) {
		return;
	}

	int ret = atomic_dec_return(&conn->refcnt);
	if (ret > 0) {
		return;
	} else if (ret < 0) {
		tlog(TLOG_ERROR, "BUG refcnt is invalid. %p", conn);
		raise(SIGSEGV);
		return;
	}

	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	/* 删除epoll处理 */
	if (conn->fd > 0) {
		if (_proxy_server_conn_stop(conn) != 0) {
			tlog(TLOG_ERROR, "epoll stop failed. %s", strerror(errno));
		}
	}

	free(conn->buff);
	if (conn->fd > 0) {
		close(conn->fd);
		conn->fd = 0;
	}

	if (conn->type == PROXY_SERVER_CONN_CLIENT) {
		pthread_mutex_destroy(&conn->client.peer_list_lock);
	} else if (conn->type == PROXY_SERVER_CONN_REMOTE) {
		if (conn->remote.pconn) {
			proxy_conn_free(conn->remote.pconn);
			conn->remote.pconn = NULL;
		}
	} else if (conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) {
		if (conn->redirect.send_buff) {
			free(conn->redirect.send_buff);
			conn->redirect.send_buff = NULL;
		}
	}

	free(conn);
}

static struct proxy_server_conn *_proxy_server_conn_new(PROXY_SERVER_CONN_TYPE type)
{
	struct proxy_server_conn *conn = NULL;
	struct conn_buffer *buffer = NULL;

	conn = malloc(sizeof(*conn));
	if (conn == NULL) {
		goto errout;
	}
	memset(conn, 0, sizeof(*conn));
	atomic_set(&conn->refcnt, 1);
	conn->type = type;
	INIT_LIST_HEAD(&conn->list);
	INIT_LIST_HEAD(&conn->check_list);

	switch (type) {
	case PROXY_SERVER_CONN_SERVER_REDIRECT:
		break;
	case PROXY_SERVER_CONN_SERVER:
		break;
	case PROXY_SERVER_CONN_CLIENT_REDIRECT:
		buffer = _proxy_server_new_conn_buffer();
		if (buffer == NULL) {
			goto errout;
		}
		conn->buff = buffer;

		buffer = _proxy_server_new_conn_buffer();
		if (buffer == NULL) {
			goto errout;
		}
		conn->redirect.send_buff = buffer;
		break;
	case PROXY_SERVER_CONN_CLIENT:
		buffer = _proxy_server_new_conn_buffer();
		if (buffer == NULL) {
			goto errout;
		}
		conn->buff = buffer;
		INIT_LIST_HEAD(&conn->client.peer_list_head);
		pthread_mutex_init(&conn->client.peer_list_lock, NULL);
		break;
	case PROXY_SERVER_CONN_REMOTE:
		buffer = _proxy_server_new_conn_buffer();
		if (buffer == NULL) {
			goto errout;
		}
		conn->buff = buffer;
		INIT_LIST_HEAD(&conn->remote.peer_list);
		break;
	default:
		break;
	}

	return conn;
errout:
	if (buffer) {
		free(buffer);
	}

	if (conn) {
		_proxy_server_conn_put(conn);
	}

	return NULL;
}

static void _proxy_server_conn_get(struct proxy_server_conn *conn)
{
	if (atomic_inc_return(&conn->refcnt) <= 1) {
		tlog(TLOG_ERROR, "BUG refcnt is invalid.");
		raise(SIGSEGV);
		return;
	}
}

static struct proxy_server_conn *_proxy_server_conn_open_remote(struct proxy_server_conn *client, const char *host,
																int port, int fast_open)
{
	struct proxy_server_conn *remote = NULL;
	struct proxy_conn *pconn = NULL;
	struct proxy_server *proxy_server = client->client.proxy;

	if (proxy_server == NULL) {
		tlog(TLOG_ERROR, "proxy_server is NULL for client");
		return NULL;
	}

	tlog(TLOG_INFO, "opening remote connection to %s:%d via proxy %s", host, port, proxy_server->proxy_name);

	/* Create proxy connection using src/proxy.c interface */
	pconn = proxy_conn_new(proxy_server->proxy_name, host, port, 0, 1);
	if (pconn == NULL) {
		tlog(TLOG_ERROR, "create proxy conn failed for %s:%d via proxy %s", host, port, proxy_server->proxy_name);
		return NULL;
	}

	/* Connect to proxy server */
	if (proxy_conn_connect(pconn) != 0 && errno != EINPROGRESS) {
		tlog(TLOG_ERROR, "proxy connect to %s:%d via %s failed, %s", host, port, proxy_server->proxy_name,
			 strerror(errno));
		proxy_conn_free(pconn);
		return NULL;
	}

	/* Create remote connection object */
	remote = _proxy_server_conn_new(PROXY_SERVER_CONN_REMOTE);
	if (remote == NULL) {
		tlog(TLOG_ERROR, "create remote conn object failed");
		proxy_conn_free(pconn);
		return NULL;
	}

	/* Setup remote connection */
	remote->fd = proxy_conn_get_fd(pconn);
	remote->remote.pconn = pconn;
	remote->remote.peer = client;
	_proxy_server_conn_get(client);
	remote->conn_state = PROXY_SERVER_CONN_STAT_CONNECTING;
	remote->timeout = PROXY_SERVER_CONN_TIMEOUT;
	_proxy_server_conn_touch(remote);

	/* Get peer address for logging */
	remote->addr_len = sizeof(remote->addr);
	getpeername(remote->fd, (struct sockaddr *)&remote->addr, &remote->addr_len);

	/* Add to client's peer list */
	pthread_mutex_lock(&client->client.peer_list_lock);
	list_add_tail(&remote->remote.peer_list, &client->client.peer_list_head);
	pthread_mutex_unlock(&client->client.peer_list_lock);

	/* Start epoll monitoring */
	if (_proxy_server_conn_start(remote) != 0) {
		tlog(TLOG_ERROR, "start remote conn epoll failed");
		_proxy_server_conn_put(remote);
		return NULL;
	}

	/* Add to global connection list */
	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_add(&remote->list, &dns_proxy_server.conn_list);
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	return remote;
}

static void _proxy_server_conn_remote_shutdown(struct proxy_server_conn *conn)
{
	if (conn->type == PROXY_SERVER_CONN_CLIENT) {
		struct proxy_server_conn *remote = NULL;
		struct proxy_server_conn *tmp = NULL;

		pthread_mutex_lock(&conn->client.peer_list_lock);
		list_for_each_entry_safe(remote, tmp, &conn->client.peer_list_head, remote.peer_list)
		{
			if (remote->fd > 0) {
				shutdown(remote->fd, SHUT_RDWR);
			}
		}
		pthread_mutex_unlock(&conn->client.peer_list_lock);
		conn->client.peer = NULL;
	} else if (conn->type == PROXY_SERVER_CONN_REMOTE) {
		struct proxy_server_conn *client = conn->remote.peer;
		if (client) {
			pthread_mutex_lock(&client->client.peer_list_lock);
			list_del_init(&conn->remote.peer_list);
			if (client->client.peer == conn || list_empty(&client->client.peer_list_head)) {
				shutdown(client->fd, SHUT_RDWR);
				client->client.peer = NULL;
			}
			pthread_mutex_unlock(&client->client.peer_list_lock);

			/* Release the reference to client that was acquired in _proxy_server_conn_open_remote */
			_proxy_server_conn_put(client);
		}

		conn->remote.peer = NULL;
	}
}

static int _proxy_server_conn_close(struct proxy_server_conn *conn)
{
	if (conn == NULL) {
		tlog(TLOG_ERROR, "conn is invalid");
		return -1;
	}

	_proxy_server_conn_remote_shutdown(conn);

	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	if (conn->fd > 0) {
		if (_proxy_server_conn_stop(conn) != 0) {
			tlog(TLOG_ERROR, "epoll stop failed. %s", strerror(errno));
		}
		close(conn->fd);
		conn->fd = -1;
	}

	_proxy_server_conn_put(conn);

	return 0;
}

static int _proxy_server_connected_init(struct proxy_server_conn *conn)
{
	conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECTED;
	conn->timeout = PROXY_SERVER_IDLE_TIMEOUT;
	return 0;
}

const char *tproxy_server_get_group_name(const char *proxy_name)
{
	struct dns_tproxy_server_conf *t_conf = NULL;

	if (proxy_name == NULL) {
		return NULL;
	}

	t_conf = dns_conf_get_tproxy_server(proxy_name);
	if (t_conf == NULL) {
		return NULL;
	}

	return t_conf->group_name;
}

const char *sniproxy_server_get_group_name(const char *proxy_name)
{
	struct dns_sniproxy_server_conf *sni_conf = NULL;

	if (proxy_name == NULL) {
		return NULL;
	}

	sni_conf = dns_conf_get_sniproxy_server(proxy_name);
	if (sni_conf == NULL) {
		return NULL;
	}

	return sni_conf->group_name;
}

int tproxy_get_original_dst(int fd, struct sockaddr_storage *orig_dst, socklen_t *addr_len)
{
	socklen_t len = *addr_len;
	if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, orig_dst, &len) == 0) {
		*addr_len = len;
		return 0;
	}
	if (getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, orig_dst, &len) == 0) {
		*addr_len = len;
		return 0;
	}
	return getsockname(fd, (struct sockaddr *)orig_dst, addr_len);
}

int tproxy_server_get_firewall_sets(const char *proxy_name, struct firewall_sets *sets)
{
	struct dns_tproxy_server_conf *t_conf = NULL;

	if (proxy_name == NULL || sets == NULL) {
		return -1;
	}

	// Initialize all structures to zero
	memset(sets, 0, sizeof(*sets));

	t_conf = dns_conf_get_tproxy_server(proxy_name);
	if (t_conf == NULL) {
		return -1;
	}

	if (t_conf->firewall_type == FIREWALL_NONE) {
		return -1;
	}

	if (t_conf->firewall_type == FIREWALL_NFTABLES) {
		// nftables: set pointers to embedded structures
		if (t_conf->nftset_names.ip_enable) {
			sets->nftset_ipv4 = &t_conf->nftset_names.ip;
		}
		if (t_conf->nftset_names.ip6_enable) {
			sets->nftset_ipv6 = &t_conf->nftset_names.ip6;
		}
	} else if (t_conf->firewall_type == FIREWALL_IPTABLES || t_conf->firewall_type == FIREWALL_IPTABLES_REDIRECT ||
			   t_conf->firewall_type == FIREWALL_IPTABLES_TPROXY) {
		// iptables: set pointers to embedded structures
		if (t_conf->ipset_names.ipv4_enable) {
			sets->ipset_ipv4 = &t_conf->ipset_names.ipv4;
		}
		if (t_conf->ipset_names.ipv6_enable) {
			sets->ipset_ipv6 = &t_conf->ipset_names.ipv6;
		}
	} else {
		return -1;
	}

	return 0;
}

static int _proxy_server_redirect_connected_init(struct proxy_server_conn *conn)
{
	conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECTED;
	conn->timeout = PROXY_SERVER_IDLE_TIMEOUT;

	if (conn->type == PROXY_SERVER_CONN_REMOTE) {
		conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECTED_PIPE_DATA;
	}

	return 0;
}

static void _proxy_server_log_rule(const char *domain, enum domain_rule rule_type, unsigned char *rule_key,
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

static void _proxy_server_update_rule_by_flags(struct proxy_server_domain_rule *sni_domain_rule)
{
	struct dns_rule_flags *rule_flag = (struct dns_rule_flags *)sni_domain_rule->rules[0];
	unsigned int flags = 0;

	if (rule_flag == NULL) {
		return;
	}
	flags = rule_flag->flags;

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
		sni_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_IPSET] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV4_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_IPSET_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV6_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_IPSET_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NFTSET_IP_IGN || flags & DOMAIN_FLAG_NFTSET_INET_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_NFTSET_IP] = NULL;
	}

	if (flags & DOMAIN_FLAG_NFTSET_IP6_IGN || flags & DOMAIN_FLAG_NFTSET_INET_IGN) {
		sni_domain_rule->rules[DOMAIN_RULE_NFTSET_IP6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NAMESERVER_IGNORE) {
		sni_domain_rule->rules[DOMAIN_RULE_NAMESERVER] = NULL;
	}

	if (flags & DOMAIN_FLAG_PROXY_IGNORE) {
		sni_domain_rule->rules[DOMAIN_RULE_PROXY] = NULL;
	}
}

static int _proxy_server_get_rules(unsigned char *key, uint32_t key_len, int is_subkey, void *value, void *arg)
{
	struct rule_walk_args *walk_args = arg;
	struct proxy_server_domain_rule *sni_domain_rule = walk_args->args;
	struct dns_domain_rule *domain_rule = value;
	int i = 0;
	if (domain_rule == NULL) {
		return 0;
	}

	/* sub rule flag check */
	int is_effective_sub = 1;
	if (key_len == walk_args->full_key_len) {
		is_effective_sub = 0;
	} else if (key_len == walk_args->full_key_len - 1 && walk_args->full_key_len > 0) {
		is_effective_sub = 0;
	}

	if (walk_args->rule_index >= 0) {
		i = walk_args->rule_index;
	} else {
		i = 0;
	}

	for (; i < domain_rule->capacity && i < DOMAIN_RULE_MAX; i++) {
		if (domain_rule->rules[i] == NULL) {
			if (walk_args->rule_index >= 0) {
				break;
			}
			continue;
		}

		if (domain_rule->rules[i]->sub_only == 1 && is_effective_sub == 0) {
			continue;
		}

		if (domain_rule->rules[i]->root_only == 1 && is_effective_sub == 1) {
			continue;
		}

		sni_domain_rule->rules[i] = domain_rule->rules[i];
		sni_domain_rule->is_sub_rule[i] = is_subkey;
		walk_args->key[i] = key;
		walk_args->key_len[i] = key_len;
		if (walk_args->rule_index >= 0) {
			break;
		}
	}

	/* update rules by flags */
	_proxy_server_update_rule_by_flags(sni_domain_rule);

	return 0;
}

static void _proxy_server_get_domain_rule_ext(struct dns_conf_group *conf, const char *domain,
											  struct proxy_server_domain_rule *sni_domain_rule, int rule_index,
											  int out_log)
{
	int domain_len = 0;
	char domain_key[DNS_MAX_CNAME_LEN];
	struct rule_walk_args walk_args;
	int matched_key_len = DNS_MAX_CNAME_LEN;
	unsigned char matched_key[DNS_MAX_CNAME_LEN];
	int i = 0;

	memset(&walk_args, 0, sizeof(walk_args));
	walk_args.args = sni_domain_rule;
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
	walk_args.full_key_len = domain_len;

	/* find domain rule */
	art_substring_walk(&conf->domain_rule.tree, (unsigned char *)domain_key, domain_len, _proxy_server_get_rules,
					   &walk_args);
	if (likely(dns_conf.log_level > TLOG_DEBUG) || out_log == 0) {
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
		_proxy_server_log_rule(domain, i, matched_key, matched_key_len);

		if (walk_args.rule_index >= 0) {
			break;
		}
	}
}

static int _proxy_server_get_domain_rule(struct proxy_server_conn *conn, const char *domain,
										 struct proxy_server_domain_rule *sni_domain_rule)
{
	struct dns_conf_group *rule_group = NULL;

	switch (conn->type) {
	case PROXY_SERVER_CONN_CLIENT:
		rule_group = conn->client.conf;
		break;
	case PROXY_SERVER_CONN_REMOTE:
		rule_group = conn->remote.conf;
		break;
	default:
		break;
	}
	struct dns_conf_group *default_group = dns_server_get_default_rule_group();

	memset(sni_domain_rule, 0, sizeof(struct proxy_server_domain_rule));
	_proxy_server_get_domain_rule_ext(default_group, domain, sni_domain_rule, -1, 0);

	if (rule_group != NULL && rule_group != default_group) {
		_proxy_server_get_domain_rule_ext(rule_group, domain, sni_domain_rule, -1, 0);
	}

	return 0;
}

static int _proxy_server_check_sniproxy_rule(struct proxy_server_conn *conn,
											 struct proxy_server_domain_rule *sni_domain_rule,
											 struct proxy_server **proxy_server)
{
	struct dns_proxy_rule *proxy_rule = NULL;

	if (sni_domain_rule == NULL) {
		tlog(TLOG_DEBUG, "sni_domain_rule is NULL, no sni-proxy rule");
		return -1;
	}

	proxy_rule = (struct dns_proxy_rule *)sni_domain_rule->rules[DOMAIN_RULE_PROXY];
	if (proxy_rule == NULL) {
		return -1;
	}

	if (proxy_rule->proxy_type != PROXY_TYPE_SNI_PROXY) {
		return -1;
	}

	/* Check if proxy_name is empty */
	if (proxy_rule->proxy_name == NULL || proxy_rule->proxy_name[0] == '\0') {
		tlog(TLOG_DEBUG, "proxy rule has empty proxy_name, ignoring");
		return -1;
	}

	tlog(TLOG_INFO, "found sni-proxy rule, proxy_name: %s", proxy_rule->proxy_name);

	/* Check if this is a sni-proxy-server listener name */
	struct dns_sniproxy_server_conf *s_conf = dns_conf_get_sniproxy_server(proxy_rule->proxy_name);
	const char *actual_proxy_name = proxy_rule->proxy_name;
	if (s_conf != NULL) {
		/* This is a sni-proxy-server listener, use its configured proxy */
		actual_proxy_name = s_conf->proxy_name;
		tlog(TLOG_DEBUG, "sni-proxy listener %s uses proxy %s", proxy_rule->proxy_name, actual_proxy_name);
	}

	*proxy_server = _proxy_server_get_proxy_by_name(actual_proxy_name);
	if (*proxy_server == NULL) {
		tlog(TLOG_WARN, "proxy server %s not found", actual_proxy_name);
		return -1;
	}

	tlog(TLOG_INFO, "sni-proxy rule matched, using proxy: %s", (*proxy_server)->proxy_name);
	return 0;
}

static int _proxy_server_check_tproxy_rule(struct proxy_server_conn *conn,
										   struct proxy_server_domain_rule *sni_domain_rule,
										   struct proxy_server **proxy_server)
{
	struct dns_proxy_rule *proxy_rule = NULL;

	if (sni_domain_rule == NULL) {
		tlog(TLOG_DEBUG, "sni_domain_rule is NULL, no tproxy rule");
		return -1;
	}

	proxy_rule = (struct dns_proxy_rule *)sni_domain_rule->rules[DOMAIN_RULE_PROXY];
	if (proxy_rule == NULL) {
		return -1;
	}

	if (proxy_rule->proxy_type != PROXY_TYPE_TPROXY) {
		return -1;
	}

	/* Check if proxy_name is empty */
	if (proxy_rule->proxy_name == NULL || proxy_rule->proxy_name[0] == '\0') {
		tlog(TLOG_DEBUG, "proxy rule has empty proxy_name, ignoring");
		return -1;
	}

	tlog(TLOG_DEBUG, "found tproxy rule, proxy_name: %s", proxy_rule->proxy_name);

	/* Check if this is a tproxy-server listener name */
	struct dns_tproxy_server_conf *t_conf = dns_conf_get_tproxy_server(proxy_rule->proxy_name);
	const char *actual_proxy_name = proxy_rule->proxy_name;
	if (t_conf != NULL) {
		/* This is a tproxy-server listener, use its configured proxy */
		actual_proxy_name = t_conf->proxy_name;
		tlog(TLOG_DEBUG, "tproxy listener %s uses proxy %s", proxy_rule->proxy_name, actual_proxy_name);
	}

	*proxy_server = _proxy_server_get_proxy_by_name(actual_proxy_name);
	if (*proxy_server == NULL) {
		tlog(TLOG_WARN, "proxy server %s not found", actual_proxy_name);
		return -1;
	}

	tlog(TLOG_INFO, "tproxy rule matched, using proxy: %s", (*proxy_server)->proxy_name);
	return 0;
}

static struct dns_client_rules *_proxy_server_get_client_rules(struct sockaddr_storage *addr, socklen_t addr_len)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	uint8_t *netaddr = NULL;
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

	if (prefix_from_blob(netaddr, netaddr_len, netaddr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	node = radix_search_best(dns_conf.client_rule.rule, &prefix);
	if (node == NULL) {
		return NULL;
	}

	return node->data;
}

static int _proxy_server_conn_setup_client_conf(struct proxy_server_conn *conn)
{
	struct dns_client_rules *client_rule = _proxy_server_get_client_rules(&conn->addr, conn->addr_len);
	if (client_rule == NULL) {
		if (conn->client.group_name[0] != '\0') {
			conn->client.conf = dns_server_get_rule_group(conn->client.group_name);
		} else {
			conn->client.conf = dns_server_get_rule_group(NULL);
		}
		return 0;
	}

	struct client_rule_group *group = (struct client_rule_group *)client_rule->rules[CLIENT_RULE_GROUP];
	if (group == NULL) {
		if (conn->client.group_name[0] != '\0') {
			conn->client.conf = dns_server_get_rule_group(conn->client.group_name);
		} else {
			conn->client.conf = dns_server_get_rule_group(NULL);
		}
		return 0;
	}

	if (conn->client.group_name[0] != '\0') {
		conn->client.conf = dns_server_get_rule_group(conn->client.group_name);
	} else {
		conn->client.conf = dns_server_get_rule_group(group->group_name);
	}
	return 0;
}

/* Removed _proxy_server_update_best_server and _proxy_server_get_best_server - no longer needed */

static int _proxy_server_conn_start_all_conn(struct proxy_server_conn *conn, struct proxy_server *proxy_server,
											 const char **domain_ip, int domain_ip_num)
{
	struct proxy_server_conn *remote = NULL;
	int send_count = 0;
	const char *target_host = NULL;
	int target_port = 443;

	/* Determine target host and port */
	if (domain_ip_num > 0 && domain_ip[0] != NULL) {
		target_host = domain_ip[0];
	} else {
		/* Use domain from SNI */
		target_host = conn->client.domain;
	}

	/* Get port from original destination if available (for tproxy) */
	if (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
		if (conn->client.orig_dst.ss_family == AF_INET) {
			struct sockaddr_in *addr_in = (struct sockaddr_in *)&conn->client.orig_dst;
			target_port = ntohs(addr_in->sin_port);
		} else if (conn->client.orig_dst.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&conn->client.orig_dst;
			target_port = ntohs(addr_in6->sin6_port);
		}
	}

	if (target_port <= 0) {
		target_port = 443;
	}

	tlog(TLOG_DEBUG, "connecting to %s:%d via proxy %s", target_host, target_port, proxy_server->proxy_name);

	/* Create remote connection using proxy.h interface */
	remote = _proxy_server_conn_open_remote(conn, target_host, target_port, 0);
	if (remote == NULL) {
		tlog(TLOG_ERROR, "failed to open remote connection to %s:%d", target_host, target_port);
		return -1;
	}

	remote->remote.proxy = proxy_server;
	remote->remote.sni_offset = conn->client.sni_offset;
	remote->remote.sni_len = conn->client.sni_len;
	remote->remote.conf = conn->client.conf;
	send_count++;

	if (send_count <= 0) {
		return -1;
	}

	conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECTED_PIPE_DATA;
	return 0;
}

static int _proxy_server_get_domain_ip(const struct dns_result *result, void *user_ptr)
{
	struct proxy_server_conn *conn = user_ptr;
	int ret = 0;
	struct proxy_server_domain_rule sni_domain_rule;
	struct proxy_server *proxy_server = NULL;

	memset(&sni_domain_rule, 0, sizeof(sni_domain_rule));

	if (result->addr_type == DNS_T_AAAA) {
		if (result->rtcode != DNS_RC_NOERROR || result->ip_num == 0 || result->has_soa != 0) {
			struct dns_server_query_option server_query_option;
			memset(&server_query_option, 0, sizeof(server_query_option));
			server_query_option.dns_group_name = conn->client.group_name;
			server_query_option.server_flags = BIND_FLAG_NO_SPEED_CHECK | BIND_FLAG_NO_DUALSTACK_SELECTION;

			tlog(TLOG_DEBUG, "fallback query domain %s A, group %s", result->domain, conn->client.group_name);
			ret = dns_server_query(result->domain, DNS_T_A, &server_query_option, _proxy_server_get_domain_ip, conn);
			if (ret != 0) {
				_proxy_server_conn_put(conn);
			}

			return ret;
		}
	}

	if (result->rtcode != DNS_RC_NOERROR) {
		if (result->rtcode == DNS_RC_NXDOMAIN) {
			tlog(TLOG_DEBUG, "domain %s not exists.", result->domain);
			goto errout;
		}
		tlog(TLOG_ERROR, "query domain %s failed, %d", result->domain, result->rtcode);
		goto errout;
	}

	if (_proxy_server_conn_setup_client_conf(conn) != 0) {
		tlog(TLOG_ERROR, "setup client config failed.");
		goto errout;
	}

	_proxy_server_get_domain_rule(conn, result->domain, &sni_domain_rule);
	_proxy_server_check_sniproxy_rule(conn, &sni_domain_rule, &proxy_server);
	if (proxy_server == NULL) {
		proxy_server = &dns_proxy_server.default_proxy_server;
	}

	char ips_buffer[MAX_IP_NUM][PROXY_SERVER_MAX_IPLEN];
	char *ips[MAX_IP_NUM];
	for (int i = 0; i < result->ip_num; i++) {
		if (result->addr_type == DNS_T_A) {
			sprintf(ips_buffer[i], "%d.%d.%d.%d", result->ip_addr[i][0], result->ip_addr[i][1], result->ip_addr[i][2],
					result->ip_addr[i][3]);
		} else if (result->addr_type == DNS_T_AAAA) {
			sprintf(ips_buffer[i], "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					result->ip_addr[i][0], result->ip_addr[i][1], result->ip_addr[i][2], result->ip_addr[i][3],
					result->ip_addr[i][4], result->ip_addr[i][5], result->ip_addr[i][6], result->ip_addr[i][7],
					result->ip_addr[i][8], result->ip_addr[i][9], result->ip_addr[i][10], result->ip_addr[i][11],
					result->ip_addr[i][12], result->ip_addr[i][13], result->ip_addr[i][14], result->ip_addr[i][15]);
		}

		ips[i] = ips_buffer[i];
	}

	ret = _proxy_server_conn_start_all_conn(conn, proxy_server, (const char **)ips, result->ip_num);
	if (ret != 0) {
		if (result->addr_type == DNS_T_AAAA) {
			struct dns_server_query_option server_query_option;
			memset(&server_query_option, 0, sizeof(server_query_option));
			server_query_option.dns_group_name = conn->client.group_name;
			server_query_option.server_flags = BIND_FLAG_NO_SPEED_CHECK;
			if (conn->client.force_aaaa_soa == 1) {
				server_query_option.server_flags |= BIND_FLAG_FORCE_AAAA_SOA;
			}

			ret = dns_server_query(result->domain, DNS_T_A, &server_query_option, _proxy_server_get_domain_ip, conn);
			if (ret != 0) {
				_proxy_server_conn_put(conn);
			}

			return ret;
		}
		goto errout;
	}

	_proxy_server_conn_put(conn);
	return ret;
errout:
	if (conn->fd > 0) {
		shutdown(conn->fd, SHUT_RDWR);
	}
	_proxy_server_conn_put(conn);
	return -1;
}

static int _proxy_server_conn_start_conn_proxy_server(struct proxy_server_conn *conn, struct proxy_server *proxy_server,
													  char *query_domain)
{
	if (proxy_server == NULL) {
		return -1;
	}

	tlog(TLOG_DEBUG, "starting connection for domain %s via proxy %s", query_domain, proxy_server->proxy_name);

	/* Directly start connection - proxy.h will handle all proxy logic */
	return _proxy_server_conn_start_all_conn(conn, proxy_server, NULL, 0);
}

static int _proxy_server_conn_process_protocol(struct proxy_server_conn *conn)
{
	int len = 0;
	char hostname[DNS_MAX_CNAME_LEN];
	char *query_domain = NULL;
	int ret = 0;
	const char *hostname_ptr = NULL;
	struct proxy_server_domain_rule sni_domain_rule;
	struct proxy_server *proxy_server = NULL;

	memset(&sni_domain_rule, 0, sizeof(sni_domain_rule));

	hostname[0] = 0;
	if (_proxy_server_conn_recv(conn) != 0) {
		goto errout;
	}

	len = parse_tls_header((const char *)conn->buff->data, conn->buff->len, hostname, &hostname_ptr);
	if (len < 0) {
		if (len == -1) {
			return 0;
		}
		if (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
			get_host_by_addr(hostname, sizeof(hostname), (struct sockaddr *)&conn->client.orig_dst);
			hostname_ptr = conn->buff->data;
		} else {
			tlog(TLOG_ERROR, "get sni failed.");
			goto errout;
		}
	}

	tlog(TLOG_INFO, "connecting to %s, listener %s, proxy %s", hostname, conn->client.listener_name,
		 conn->client.proxy_name);

	query_domain = hostname;
	ret = _proxy_server_get_domain_rule(conn, query_domain, &sni_domain_rule);
	if (ret < 0) {
		tlog(TLOG_ERROR, "failed to get domain rule for %s", query_domain);
		goto errout;
	}

	/* First try to get proxy from listener configuration */
	const char *actual_proxy_name = conn->client.proxy_name;
	if (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
		/* For tproxy listener, check if it's a tproxy-server name */
		struct dns_tproxy_server_conf *t_conf = dns_conf_get_tproxy_server(conn->client.proxy_name);
		if (t_conf != NULL) {
			actual_proxy_name = t_conf->proxy_name;
			tlog(TLOG_DEBUG, "tproxy listener %s uses proxy %s", conn->client.proxy_name, actual_proxy_name);
		}
	} else {
		/* For sni-proxy listener, check if it's a sni-proxy-server name */
		struct dns_sniproxy_server_conf *s_conf = dns_conf_get_sniproxy_server(conn->client.proxy_name);
		if (s_conf != NULL) {
			actual_proxy_name = s_conf->proxy_name;
			tlog(TLOG_DEBUG, "sni-proxy listener %s uses proxy %s", conn->client.proxy_name, actual_proxy_name);
		}
	}

	proxy_server = _proxy_server_get_proxy_by_name(actual_proxy_name);
	tlog(TLOG_DEBUG, "resolved proxy server %s for proxy name %s", hostname, actual_proxy_name);

	conn->client.sni_offset = hostname_ptr - conn->buff->data;
	conn->client.sni_len = strnlen(hostname, DNS_MAX_CNAME_LEN);

	if (_proxy_server_conn_setup_client_conf(conn) != 0) {
		tlog(TLOG_ERROR, "setup client config failed.");
		goto errout;
	}

	query_domain = hostname;

	/* Check domain rules for tproxy or sni-proxy override */
	if (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
		tlog(TLOG_DEBUG, "checking tproxy rule for domain %s", query_domain);
		_proxy_server_check_tproxy_rule(conn, &sni_domain_rule, &proxy_server);
	} else {
		tlog(TLOG_DEBUG, "checking sni-proxy rule for domain %s", query_domain);
		_proxy_server_check_sniproxy_rule(conn, &sni_domain_rule, &proxy_server);
	}

	/* If domain rule didn't override, use listener's proxy (already resolved above) */
	if (proxy_server == NULL) {
		tlog(TLOG_DEBUG, "no domain rule match, using listener proxy %s", actual_proxy_name);
		proxy_server = _proxy_server_get_proxy_by_name(actual_proxy_name);
	}

	/* Fallback to default proxy if still NULL */
	if (proxy_server == NULL) {
		tlog(TLOG_DEBUG, "using default proxy server");
		proxy_server = &dns_proxy_server.default_proxy_server;
	} else {
		tlog(TLOG_INFO, "using proxy server: %s for domain %s", proxy_server->proxy_name, query_domain);
	}

	safe_strncpy(conn->client.domain, query_domain, DNS_MAX_CNAME_LEN);
	conn->client.proxy = proxy_server;

	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;

	if (inet_pton(AF_INET, query_domain, &addr.sin.sin_addr) == 1 ||
		inet_pton(AF_INET6, query_domain, &addr.sin6.sin6_addr) == 1) {
		const char *ips[1] = {query_domain};
		ret = _proxy_server_conn_start_all_conn(conn, proxy_server, ips, 1);
	} else if (conn->client.remote_dns) {
		ret = _proxy_server_conn_start_conn_proxy_server(conn, proxy_server, query_domain);
	} else {
		struct dns_server_query_option server_query_option;
		memset(&server_query_option, 0, sizeof(server_query_option));
		server_query_option.dns_group_name = conn->client.group_name;
		server_query_option.server_flags = BIND_FLAG_NO_SPEED_CHECK | BIND_FLAG_NO_DUALSTACK_SELECTION;
		if (conn->client.force_aaaa_soa) {
			server_query_option.server_flags |= BIND_FLAG_FORCE_AAAA_SOA;
		}

		tlog(TLOG_DEBUG, "starting local resolution for domain %s, group %s", query_domain, conn->client.group_name);
		_proxy_server_conn_get(conn);
		ret = dns_server_query(query_domain, DNS_T_AAAA, &server_query_option, _proxy_server_get_domain_ip, conn);
		if (ret != 0) {
			_proxy_server_conn_put(conn);
		}
	}
	if (ret != 0) {
		shutdown(conn->fd, SHUT_RDWR);
	}

	return ret;
errout:
	return -1;
}

static struct proxy_server_conn *_proxy_server_accept(struct proxy_server_conn *conn, struct epoll_event *event,
													  unsigned long now, PROXY_SERVER_CONN_TYPE client_type)
{
	struct proxy_server_conn *client = NULL;
	int fd = -1;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char hostname[PROXY_SERVER_MAXHOST_NAME];

	fd = accept4(conn->fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}

	tlog(TLOG_DEBUG, "accepted connection on listener %s, fd %d", conn->client.listener_name, fd);

	client = _proxy_server_conn_new(client_type);
	if (client == NULL) {
		goto errout;
	}

	client->fd = fd;
	memcpy(&client->addr, &addr, addr_len);
	client->addr_len = addr_len;
	client->timeout = PROXY_SERVER_CONN_TIMEOUT;

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set non block failed.");
		goto errout;
	}

	set_sock_keepalive(fd, 30, 3, 5);
	if (_proxy_server_conn_start(client) != 0) {
		tlog(TLOG_ERROR, "start conn failed.");
		goto errout;
	}

	_proxy_server_conn_touch(client);

	if (conn->type == PROXY_SERVER_CONN_TPROXY_SERVER || conn->type == PROXY_SERVER_CONN_SNIPROXY_SERVER ||
		conn->type == PROXY_SERVER_CONN_SERVER) {
		safe_strncpy(client->client.listener_name, conn->client.listener_name, PROXY_NAME_LEN);
		safe_strncpy(client->client.proxy_name, conn->client.proxy_name, PROXY_NAME_LEN);
		safe_strncpy(client->client.group_name, conn->client.group_name, PROXY_NAME_LEN);
		client->client.listener_type = conn->type;
		client->client.orig_dst_len = sizeof(client->client.orig_dst);
		client->client.remote_dns = conn->client.remote_dns;
		client->client.force_aaaa_soa = conn->client.force_aaaa_soa;
		tproxy_get_original_dst(client->fd, &client->client.orig_dst, &client->client.orig_dst_len);
	}

	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_add(&client->list, &dns_proxy_server.conn_list);
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	tlog(TLOG_INFO, "accept connection from %s",
		 get_host_by_addr(hostname, sizeof(hostname), (struct sockaddr *)&client->addr));

	return client;
errout:
	if (fd > 0) {
		close(fd);
	}
	if (client) {
		_proxy_server_conn_put(client);
	}
	return NULL;
}

static int _proxy_server_process_conn_event_err(struct proxy_server_conn *conn, struct epoll_event *event)
{
	/* epoll消息异常处理 */
	if (!(event->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		return 0;
	}

	int err = 0;
	socklen_t len = sizeof(err);
	getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err == ECONNREFUSED) {
	}

	if (err) {
		char hostname[PROXY_SERVER_MAXHOST_NAME];
		tlog(TLOG_DEBUG, "connect %s closed,  %s",
			 get_host_by_addr(hostname, sizeof(hostname), (struct sockaddr *)&conn->addr), strerror(err));
	}

	return -1;
}

static int _proxy_server_process_conn_write_data(struct proxy_server_conn *conn, struct proxy_server_conn *peer,
												 struct epoll_event *event)
{
	/* 有足够缓存可以发送数据 */
	if (!(event->events & EPOLLOUT)) {
		return 0;
	}

	if (peer == NULL) {
		return 0;
	}

	if (_proxy_server_pipe_data(peer, conn) != 0) {
		return -1;
	}

	return 0;
}

static int _proxy_server_process_conn_read_data(struct proxy_server_conn *conn, struct proxy_server_conn *peer,
												struct epoll_event *event)
{
	/* 有数据需要读取 */
	if (!(event->events & EPOLLIN)) {
		return 0;
	}

	if (peer == NULL) {
		return 0;
	}

	if (_proxy_server_pipe_data(conn, peer) != 0) {
		return -1;
	}

	return 0;
}

static int _proxy_server_process_conn_client(struct proxy_server_conn *conn, struct epoll_event *event,
											 unsigned long now)
{
	struct proxy_server_conn *peer = conn->client.peer;

	int ret = _proxy_server_process_conn_event_err(conn, event);
	if (ret != 0) {
		goto errout;
	}

	_proxy_server_conn_touch(conn);

	if ((event->events & EPOLLOUT)) {
		if ((conn->conn_state == PROXY_SERVER_CONN_STAT_INIT) ||
			(conn->conn_state == PROXY_SERVER_CONN_STAT_CONNECTING)) {
			if (_proxy_server_connected_init(conn) != 0) {
				tlog(TLOG_ERROR, "connection init failed.");
				goto errout;
			}
		}
	}

	ret = _proxy_server_process_conn_write_data(conn, peer, event);
	if (ret != 0) {
		goto errout;
	}

	/* 有数据需要读取 */
	if (event->events & EPOLLIN) {
		if (conn->conn_state == PROXY_SERVER_CONN_STAT_CONNECTED && conn->type == PROXY_SERVER_CONN_CLIENT) {
			if (_proxy_server_conn_process_protocol(conn) != 0) {
				goto errout;
			}

			return 0;
		}
	}

	ret = _proxy_server_process_conn_read_data(conn, peer, event);
	if (ret != 0) {
		goto errout;
	}

	return 0;

errout:
	if (conn) {
		_proxy_server_conn_close(conn);
	}

	return -1;
}

static int _proxy_server_retry_all_server(struct proxy_server_conn *remote)
{

	struct proxy_server_conn *client = NULL;
	int ret = 0;

	if (remote->type != PROXY_SERVER_CONN_REMOTE) {
		return 0;
	}

	client = remote->remote.peer;

	if (client == NULL) {
		return -1;
	}

	if (client->client.peer && client->client.peer != remote) {
		return -1;
	}

	if (client->client.retry_all_server != 1) {
		return -1;
	}

	client->client.peer = NULL;
	/* Removed best_server tracking */
	client->client.retry_all_server = 0;
	ret = _proxy_server_conn_start_conn_proxy_server(client, client->client.proxy, client->client.domain);
	if (ret != 0) {
		tlog(TLOG_ERROR, "retry connect all proxy server failed.");
	}

	return ret;
}

static int _proxy_server_remote_handshake(struct proxy_server_conn *conn, struct epoll_event *event)
{
	proxy_handshake_state state;
	struct proxy_server_conn *client = conn->remote.peer;

	if (conn->conn_state == PROXY_SERVER_CONN_STAT_CONNECTED_PIPE_DATA) {
		return 0;
	}

	if (conn->remote.pconn == NULL) {
		tlog(TLOG_ERROR, "remote pconn is NULL during handshake");
		return -1;
	}

	/* Perform proxy handshake using src/proxy.c interface */
	state = proxy_conn_handshake(conn->remote.pconn);

	if (state == PROXY_HANDSHAKE_OK || state == PROXY_HANDSHAKE_CONNECTED) {
		time(&conn->remote.proxy->last_alive);
		if (client->client.peer == NULL) {
			client->client.peer = conn;
		} else if (client->client.peer != conn) {
			tlog(TLOG_DEBUG, "client already has a different peer, closing this connection");
			return -1;
		}

		conn->timeout = PROXY_SERVER_IDLE_TIMEOUT;
		conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECTED_PIPE_DATA;

		struct epoll_event event_remote;
		memset(&event_remote, 0, sizeof(event_remote));
		event_remote.data.ptr = conn;
		event_remote.events = EPOLLIN | EPOLLOUT | EPOLLET;
		if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, conn->fd, &event_remote) != 0) {
			tlog(TLOG_ERROR, "epoll mod failed after handshake, %s", strerror(errno));
			return -1;
		}

		tlog(TLOG_DEBUG, "connected to proxy server, ready to pipe data");
		return 0;
	} else if (state == PROXY_HANDSHAKE_WANT_READ || state == PROXY_HANDSHAKE_WANT_WRITE) {
		struct epoll_event event_remote;
		memset(&event_remote, 0, sizeof(event_remote));
		event_remote.data.ptr = conn;
		if (state == PROXY_HANDSHAKE_WANT_READ) {
			event_remote.events = EPOLLIN;
		} else {
			event_remote.events = EPOLLOUT;
		}

		if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, conn->fd, &event_remote) != 0) {
			tlog(TLOG_ERROR, "epoll mod failed during handshake, %s", strerror(errno));
			return -1;
		}
		return 1;
	}

	tlog(TLOG_ERROR, "proxy handshake failed, state=%d", state);
	return -1;
}

static int _proxy_server_process_conn_remote(struct proxy_server_conn *conn, struct epoll_event *event,
											 unsigned long now)
{
	struct proxy_server_conn *client = conn->remote.peer;

	int ret = _proxy_server_process_conn_event_err(conn, event);
	if (ret != 0) {
		goto errout1;
	}

	_proxy_server_conn_touch(conn);

	ret = _proxy_server_remote_handshake(conn, event);
	if (ret == 1) {
		return 0;
	} else if (ret <= -1) {
		goto errout;
	}

	_proxy_server_conn_touch(conn);

	ret = _proxy_server_process_conn_write_data(conn, client, event);
	if (ret != 0) {
		goto errout;
	}

	ret = _proxy_server_process_conn_read_data(conn, client, event);
	if (ret != 0) {
		goto errout;
	}

	if ((event->events & EPOLLIN)) {
		time(&conn->remote.proxy->last_alive);
		if (client && client->client.peer == conn) {
			/* Removed best_server tracking */
			client->client.retry_all_server = 0;
		}
	}

	return 0;
errout1:
	_proxy_server_retry_all_server(conn);
errout:
	if (conn) {
		_proxy_server_conn_close(conn);
	}

	return -1;
}

static int _proxy_server_process_conn_redirect(struct proxy_server_conn *conn, struct epoll_event *event,
											   unsigned long now)
{
	int ret = _proxy_server_process_conn_event_err(conn, event);
	if (ret != 0) {
		_proxy_server_conn_close(conn);
		return ret;
	}

	_proxy_server_conn_touch(conn);

	if ((event->events & EPOLLOUT)) {
		if ((conn->conn_state == PROXY_SERVER_CONN_STAT_INIT) ||
			(conn->conn_state == PROXY_SERVER_CONN_STAT_CONNECTING)) {
			if (_proxy_server_redirect_connected_init(conn) != 0) {
				tlog(TLOG_ERROR, "connection init failed.");
				_proxy_server_conn_close(conn);
				return -1;
			}
		}

		if (_proxy_server_send_data(conn->redirect.send_buff, conn->fd) < 0) {
			_proxy_server_conn_close(conn);
			return -1;
		}
	}

	if (event->events & EPOLLIN) {
		if (_proxy_server_conn_recv(conn) != 0) {
			_proxy_server_conn_close(conn);
			return -1;
		}

		struct http_head *head = NULL;
		head = http_head_init(CONN_BUFF_SIZE, HTTP_VERSION_1_1);
		if (head == NULL) {
			_proxy_server_conn_close(conn);
			return -1;
		}

		ret = http_head_parse(head, (const unsigned char *)conn->buff->data, conn->buff->len);
		if (ret < 0) {
			http_head_destroy(head);
			if (ret == -1) {
				return 0;
			}
			_proxy_server_conn_close(conn);
			return -1;
		}

		char data[512];
		const char msg[] = "Redirect to https\n ";
		int msg_len = sizeof(msg) - 2;
		int len = snprintf(data, sizeof(data),
						   "HTTP/1.1 301 Moved Permanently\r\n"
						   "Content-Type: text/html\r\n"
						   "Content-Length: %d\r\n"
						   "Location: https://%s%s\r\n\r\n%s",
						   msg_len, http_head_get_fields_value(head, "Host"), http_head_get_url(head), msg);
		safe_strncpy(conn->redirect.send_buff->data, data, len);
		conn->redirect.send_buff->len = len;
		_proxy_server_send_data(conn->redirect.send_buff, conn->fd);
		shutdown(conn->fd, SHUT_RDWR);
		http_head_destroy(head);
	}

	return 0;
}

static int _proxy_server_accept_sni_conn(struct proxy_server_conn *conn, struct epoll_event *event, unsigned long now)
{
	struct proxy_server_conn *client = NULL;

	client = _proxy_server_accept(conn, event, now, PROXY_SERVER_CONN_CLIENT);
	if (client == NULL) {
		return -1;
	}

	return 0;
}

static int _proxy_server_accept_tproxy_conn(struct proxy_server_conn *conn, struct epoll_event *event,
											unsigned long now)
{
	struct proxy_server_conn *client = NULL;

	client = _proxy_server_accept(conn, event, now, PROXY_SERVER_CONN_CLIENT);
	if (client == NULL) {
		return -1;
	}

	return 0;
}

static int _proxy_server_accept_redirect(struct proxy_server_conn *conn, struct epoll_event *event, unsigned long now)
{
	struct conn_buffer *buffer = NULL;
	struct proxy_server_conn *client = NULL;

	client = _proxy_server_accept(conn, event, now, PROXY_SERVER_CONN_CLIENT_REDIRECT);
	if (client == NULL) {
		return -1;
	}

	buffer = malloc(sizeof(*buffer));
	if (buffer == NULL) {
		goto errout;
	}

	memset(buffer, 0, sizeof(*buffer));
	buffer->size = sizeof(buffer->data);
	client->redirect.send_buff = buffer;

	return 0;

errout:
	if (buffer) {
		free(buffer);
		conn->redirect.send_buff = NULL;
	}

	if (client) {
		_proxy_server_conn_close(client);
	}

	return -1;
}

static int _proxy_server_process_tproxy_udp(struct proxy_server_conn *conn, struct epoll_event *event,
											unsigned long now)
{
	// TODO: Implement UDP TPROXY processing
	// This requires:
	// 1. Use recvmsg to receive UDP packets with auxiliary data
	// 2. Extract original destination from IP_ORIGDSTADDR
	// 3. Create client connection and forward the packet
	// 4. Handle SOCKS5 UDP ASSOCIATE for UDP forwarding

	tlog(TLOG_DEBUG, "UDP TPROXY processing not yet implemented");
	return 0;
}

static int _proxy_server_process(struct proxy_server_conn *conn, struct epoll_event *event, unsigned long now)
{
	if (conn->type == PROXY_SERVER_CONN_SERVER) {
		return _proxy_server_accept_sni_conn(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_TPROXY_SERVER) {
		return _proxy_server_accept_tproxy_conn(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_TPROXY_SERVER_UDP) {
		return _proxy_server_process_tproxy_udp(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_SNIPROXY_SERVER) {
		return _proxy_server_accept_sni_conn(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_SERVER_REDIRECT) {
		return _proxy_server_accept_redirect(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_CLIENT) {
		return _proxy_server_process_conn_client(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_REMOTE) {
		return _proxy_server_process_conn_remote(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) {
		return _proxy_server_process_conn_redirect(conn, event, now);
	}

	return -1;
}

static void _proxy_server_period_run(void)
{
	struct proxy_server_conn *conn = NULL;
	struct proxy_server_conn *tmp = NULL;
	LIST_HEAD(check_list);
	time_t curr_time = 0;

	time(&curr_time);

	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_for_each_entry_safe(conn, tmp, &dns_proxy_server.conn_list, list)
	{
		if (curr_time - conn->timeout < conn->last) {
			continue;
		}

		list_add_tail(&conn->check_list, &check_list);
		_proxy_server_conn_get(conn);
	}
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	list_for_each_entry_safe(conn, tmp, &check_list, check_list)
	{
		list_del_init(&conn->check_list);
		_proxy_server_retry_all_server(conn);
		_proxy_server_conn_close(conn);
		_proxy_server_conn_put(conn);
	}
}

static void *_proxy_server_work(void *arg)
{
	struct epoll_event events[PROXY_SERVER_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	unsigned long last = {0};
	unsigned int sleep = 1000;
	int sleep_time = 0;
	unsigned long expect_time = 0;

	sleep_time = sleep;
	now = get_tick_count() - sleep;
	expect_time = now + sleep;
	while (atomic_read(&dns_proxy_server.run)) {
		now = get_tick_count();
		if (sleep_time > 0) {
			sleep_time -= now - last;
			if (sleep_time <= 0) {
				sleep_time = 0;
			}
		}

		if (now >= expect_time) {
			if (last != now) {
				_proxy_server_period_run();
			}

			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}
			expect_time += sleep;
		}
		last = now;

		pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
		if (list_empty(&dns_proxy_server.conn_list)) {
			sleep_time = -1;
		}

		pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

		num = epoll_wait(dns_proxy_server.epoll_fd, events, PROXY_SERVER_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		if (sleep_time == -1) {
			now = get_tick_count();
			last = now;
			expect_time = now;
		}

		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct proxy_server_conn *conn = (struct proxy_server_conn *)event->data.ptr;
			if (conn == NULL) {
				tlog(TLOG_WARN, "server info is invalid.");
				continue;
			}

			_proxy_server_process(conn, event, now);
		}
	}

	return NULL;
}

static int _proxy_server_create_socket(const char *host_ip, int default_port, int type, int tproxy)
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
	const int priority = 6;
	const int ip_tos = IPTOS_LOWDELAY | IPTOS_RELIABILITY;
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
		port = default_port;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);
	gai = _proxy_server_getaddr(host, atoi(port_str), type, 0);
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

	if (tproxy) {
		if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) != 0) {
			tlog(TLOG_ERROR, "set IP_TRANSPARENT failed (requires root privileges), %s", strerror(errno));
		}
		// Try IPv6 transparent if simple bind
		setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &yes, sizeof(yes));
	}
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
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

static int _proxy_server_start(void)
{
	struct proxy_server_conn *conn = NULL;
	struct epoll_event event;

	list_for_each_entry(conn, &dns_proxy_server.listeners, list)
	{
		memset(&event, 0, sizeof(event));
		event.events = EPOLLIN;
		event.data.ptr = conn;
		if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_ADD, conn->fd, &event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %d, %s", conn->fd, strerror(errno));
			return -1;
		}
	}

	return 0;
}

static int _proxy_server_create_tproxy_udp_socket(struct dns_tproxy_server_conf *t_conf, struct sockaddr_storage *addr)
{
	int fd_udp = -1;
	struct proxy_server_conn *t_conn_udp = NULL;
	char host_ip[DNS_MAX_IPLEN + 8];
	int yes_opt = 1;

	fd_udp = _proxy_server_create_socket(t_conf->server, 1088, SOCK_DGRAM, 1);
	if (fd_udp < 0) {
		tlog(TLOG_ERROR, "create tproxy UDP socket for %s failed", host_ip);
		return -1;
	}

	// Set SO_MARK to match the firewall rule mark
	unsigned int so_mark = t_conf->so_mark;
	if (setsockopt(fd_udp, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
		tlog(TLOG_ERROR, "set SO_MARK for UDP failed (requires root privileges), %s", strerror(errno));
		close(fd_udp);
		return -1;
	}

	// For IPv6, also set IPV6_TRANSPARENT
	if (addr->ss_family == AF_INET6) {
		if (setsockopt(fd_udp, SOL_IPV6, IPV6_TRANSPARENT, &yes_opt, sizeof(yes_opt)) != 0) {
			tlog(TLOG_ERROR, "set IPV6_TRANSPARENT for UDP failed (requires root privileges), %s", strerror(errno));
			close(fd_udp);
			return -1;
		}
	}

	t_conn_udp = _proxy_server_conn_new(PROXY_SERVER_CONN_TPROXY_SERVER_UDP);
	if (t_conn_udp == NULL) {
		close(fd_udp);
		tlog(TLOG_ERROR, "create tproxy UDP conn for %s failed", host_ip);
		return -1;
	}

	t_conn_udp->fd = fd_udp;
	safe_strncpy(t_conn_udp->client.listener_name, t_conf->name, PROXY_NAME_LEN);
	safe_strncpy(t_conn_udp->client.proxy_name, t_conf->proxy_name, PROXY_NAME_LEN);
	safe_strncpy(t_conn_udp->client.group_name, t_conf->group_name, PROXY_NAME_LEN);

	list_add_tail(&t_conn_udp->list, &dns_proxy_server.listeners);

	return 0;
}

static int _proxy_server_create_tproxy_sockets(void)
{
	struct dns_tproxy_server_conf *t_conf = NULL;
	size_t i;

	hash_for_each(dns_proxy_table.tproxy, i, t_conf, node)
	{
		// Skip if no_server is set
		if (t_conf->no_server) {
			continue;
		}

		int fd = -1;
		struct proxy_server_conn *t_conn = NULL;
		char host_ip[DNS_MAX_IPLEN + 8];

		tlog(TLOG_INFO, "create tproxy server for %s", t_conf->server);

		// Create TCP socket
		fd = _proxy_server_create_socket(t_conf->server, 1088, SOCK_STREAM, 1);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create tproxy TCP socket for %s failed", host_ip);
			goto errout;
		}

		// Set SO_MARK to match the firewall rule mark
		unsigned int so_mark = t_conf->so_mark;
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
			tlog(TLOG_ERROR, "set SO_MARK failed (requires root privileges), %s", strerror(errno));
			goto errout;
		}

		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		getsockname(fd, (struct sockaddr *)&addr, &addr_len);

		t_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_TPROXY_SERVER);
		if (t_conn == NULL) {
			close(fd);
			tlog(TLOG_ERROR, "create tproxy TCP conn for %s failed", host_ip);
			goto errout;
		}

		t_conn->fd = fd;
		safe_strncpy(t_conn->client.listener_name, t_conf->name, PROXY_NAME_LEN);
		safe_strncpy(t_conn->client.proxy_name, t_conf->proxy_name, PROXY_NAME_LEN);
		safe_strncpy(t_conn->client.group_name, t_conf->group_name, PROXY_NAME_LEN);
		t_conn->client.remote_dns = t_conf->remote_dns;
		t_conn->client.force_aaaa_soa = t_conf->force_aaaa_soa;
		list_add_tail(&t_conn->list, &dns_proxy_server.listeners);

		// Create UDP socket if UDP support is enabled
		if (t_conf->udp_support) {
			if (_proxy_server_create_tproxy_udp_socket(t_conf, &addr) != 0) {
				goto errout;
			}
		}
	}

	return 0;
errout:
	return -1;
}

static int _proxy_server_create_sniproxy_sockets(void)
{
	struct dns_sniproxy_server_conf *s_conf = NULL;
	size_t i;
	hash_for_each(dns_proxy_table.sniproxy, i, s_conf, node)
	{
		int fd = -1;
		struct proxy_server_conn *s_conn = NULL;
		char host_ip[DNS_MAX_IPLEN + 8];

		tlog(TLOG_INFO, "create sniproxy server for %s", s_conf->server);

		fd = _proxy_server_create_socket(s_conf->server, 443, SOCK_STREAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create sniproxy socket for %s failed", host_ip);
			goto errout;
		}

		// Set SO_MARK to match the firewall rule mark
		unsigned int so_mark = s_conf->so_mark;
		if (so_mark > 0) {
			if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
				tlog(TLOG_ERROR, "set SO_MARK failed (requires root privileges), %s", strerror(errno));
				goto errout;
			}
		}

		s_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_SNIPROXY_SERVER);
		if (s_conn == NULL) {
			close(fd);
			tlog(TLOG_ERROR, "create sniproxy conn for %s failed", host_ip);
			goto errout;
		}

		s_conn->fd = fd;
		safe_strncpy(s_conn->client.listener_name, s_conf->name, PROXY_NAME_LEN);
		safe_strncpy(s_conn->client.proxy_name, s_conf->proxy_name, PROXY_NAME_LEN);
		safe_strncpy(s_conn->client.group_name, s_conf->group_name, PROXY_NAME_LEN);
		s_conn->client.remote_dns = s_conf->remote_dns;
		s_conn->client.force_aaaa_soa = s_conf->force_aaaa_soa;

		list_add_tail(&s_conn->list, &dns_proxy_server.listeners);
	}

	return 0;
errout:
	return -1;
}

static int _proxy_server_socket(void)
{
	if (_proxy_server_create_tproxy_sockets() != 0) {
		goto errout;
	}

	if (_proxy_server_create_sniproxy_sockets() != 0) {
		goto errout;
	}

	return 0;
errout: {
	/* Clean up any listeners that were added */
	struct proxy_server_conn *conn = NULL;
	struct proxy_server_conn *tmp = NULL;
	list_for_each_entry_safe(conn, tmp, &dns_proxy_server.listeners, list)
	{
		list_del_init(&conn->list);
		_proxy_server_conn_put(conn);
	}
}

	return -1;
}

static int _proxy_server_close(void)
{
	struct proxy_server_conn *conn = NULL;
	struct proxy_server_conn *tmp = NULL;

	list_for_each_entry_safe(conn, tmp, &dns_proxy_server.listeners, list)
	{
		list_del_init(&conn->list);
		_proxy_server_conn_put(conn);
	}

	return 0;
}

static int _proxy_server_conn_close_all(void)
{
	struct proxy_server_conn *conn = NULL;
	struct proxy_server_conn *tmp = NULL;
	LIST_HEAD(check_list);

	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_for_each_entry_safe(conn, tmp, &dns_proxy_server.conn_list, list)
	{
		list_add_tail(&conn->check_list, &check_list);
		_proxy_server_conn_get(conn);
	}
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	list_for_each_entry_safe(conn, tmp, &check_list, check_list)
	{
		list_del_init(&conn->check_list);
		_proxy_server_conn_close(conn);
		_proxy_server_conn_put(conn);
	}

	return 0;
}

static int proxy_server_init_default_proxy_info(void)
{
	struct proxy_server *proxy_server = &dns_proxy_server.default_proxy_server;
	struct proxy_info proxy_default;

	safe_strncpy(proxy_server->proxy_name, "default", PROXY_NAME_LEN);
	time(&proxy_server->last_alive);

	/* Add default proxy to global proxy list */
	memset(&proxy_default, 0, sizeof(proxy_default));
	proxy_default.type = PROXY_PASSTHROUGH;
	proxy_add("default", &proxy_default);

	return 0;
}

int proxy_server_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret = 0;
	int random_fd = -1;
	time_t now = 0;

	if (is_proxy_server_init == 1) {
		return -1;
	}

	if (dns_proxy_server.epoll_fd > 0) {
		return -1;
	}

	/* check if any sni-proxy-server or tproxy-server is configured */
	if (dns_conf_tproxy_server_num() == 0 && dns_conf_sniproxy_server_num() == 0) {
		tlog(TLOG_INFO, "no sni-proxy-server or tproxy-server configured, skip proxy server init.");
		return 0;
	}

	if (dns_conf_tproxy_server_num() > 0) {
		if (has_network_admin_cap() == 0) {
			tlog(TLOG_ERROR, "TPROXY requires CAP_NET_ADMIN capability, proxy server start failed.");
			tlog(TLOG_ERROR, "Please run as root or use 'setcap cap_net_admin+ep <path_to_smartdns>' to grant the capability.");
			return -1;
		}
	}

	// Set firewall rules
	if (_proxy_server_setup_firewall_rules() != 0) {
		tlog(TLOG_ERROR, "setup firewall rules failed.");
		return -1;
	}

	time(&now);
	srandom(now);
	memset(&dns_proxy_server, 0, sizeof(dns_proxy_server));
	pthread_attr_init(&attr);
	pthread_mutex_init(&dns_proxy_server.conn_list_lock, NULL);
	INIT_LIST_HEAD(&dns_proxy_server.conn_list);
	hash_init(dns_proxy_server.proxy_server);
	INIT_LIST_HEAD(&dns_proxy_server.listeners);
	proxy_server_init_default_proxy_info();

	random_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY);
	if (random_fd < 0) {
		tlog(TLOG_ERROR, "open random failed, %s\n", strerror(errno));
		goto errout;
	}

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	dns_proxy_server.epoll_fd = epollfd;
	dns_proxy_server.random_fd = random_fd;
	atomic_set(&dns_proxy_server.run, 1);

	if (_proxy_server_socket() != 0) {
		tlog(TLOG_ERROR, "create proxy server failed.");
		goto errout;
	}

	if (!list_empty(&dns_proxy_server.listeners)) {
		/* start work task */
		ret = pthread_create(&dns_proxy_server.tid, &attr, _proxy_server_work, NULL);
		if (ret != 0) {
			tlog(TLOG_ERROR, "create client work thread failed, %s\n", strerror(errno));
			goto errout;
		}

		if (_proxy_server_start() != 0) {
			tlog(TLOG_ERROR, "start sni proxy server failed.");
			goto errout;
		}
	}
	is_proxy_server_init = 1;
	return 0;
errout:
	_proxy_server_close();

	if (dns_proxy_server.tid) {
		void *retval = NULL;
		atomic_set(&dns_proxy_server.run, 0);
		pthread_join(dns_proxy_server.tid, &retval);
		dns_proxy_server.tid = 0;
	}

	if (epollfd > 0) {
		close(epollfd);
	}

	if (random_fd > 0) {
		close(random_fd);
	}

	pthread_mutex_destroy(&dns_proxy_server.conn_list_lock);

	return -1;
}

void proxy_server_exit(void)
{
	if (is_proxy_server_init == 0) {
		return;
	}

	// 清理防火墙规则
	_proxy_server_cleanup_firewall_rules();

	if (!list_empty(&dns_proxy_server.listeners)) {
		tlog(TLOG_INFO, "shutting down proxy server...");
		if (dns_proxy_server.tid) {
			void *ret = NULL;
			atomic_set(&dns_proxy_server.run, 0);
			struct proxy_server_conn *conn = NULL;
			list_for_each_entry(conn, &dns_proxy_server.listeners, list)
			{
				shutdown(conn->fd, SHUT_RDWR);
			}
			pthread_join(dns_proxy_server.tid, &ret);
			dns_proxy_server.tid = 0;
		}

		_proxy_server_close();
		_proxy_server_conn_close_all();
		_proxy_server_free_proxy_cache();
	}

	if (dns_proxy_server.epoll_fd > 0) {
		close(dns_proxy_server.epoll_fd);
		dns_proxy_server.epoll_fd = -1;
	}

	if (dns_proxy_server.random_fd > 0) {
		close(dns_proxy_server.random_fd);
		dns_proxy_server.random_fd = -1;
	}

	pthread_mutex_destroy(&dns_proxy_server.conn_list_lock);
	is_proxy_server_init = 0;
}
