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
#include "smartdns/lib/jhash.h"
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
#define CONN_BUFF_SIZE (64 * 1024)
#define PROXY_SERVER_CONN_TIMEOUT 5
#define PROXY_SERVER_CONN_TIMEOUT 5
#define PROXY_SERVER_IDLE_TIMEOUT 600
#define PROXY_SERVER_UDP_SESSION_TIMEOUT                                                                               \
	60 /* 60 seconds for UDP is standard for NAT, unreplied is often 30s. We use 60s for simplicity. */
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
	PROXY_SERVER_CONN_SOCKS5_SERVER,
	PROXY_SERVER_CONN_HTTP_SERVER,
	PROXY_SERVER_CONN_CLIENT,
	PROXY_SERVER_CONN_CLIENT_REDIRECT,
	PROXY_SERVER_CONN_REMOTE,
	PROXY_SERVER_CONN_UDP_SESSION,
	PROXY_SERVER_CONN_FORWARD_SERVER,
	PROXY_SERVER_CONN_FORWARD_SERVER_UDP,
} PROXY_SERVER_CONN_TYPE;

typedef enum PROXY_SERVER_CONN_STATE {
	PROXY_SERVER_CONN_STAT_INIT = 0,
	PROXY_SERVER_CONN_STAT_HANDSHAKE,
	PROXY_SERVER_CONN_STAT_GET_TARGET,
	PROXY_SERVER_CONN_STAT_RESOLVE,
	PROXY_SERVER_CONN_STAT_RESOLVING,
	PROXY_SERVER_CONN_STAT_CONNECT_REMOTE,
	PROXY_SERVER_CONN_STAT_CONNECTING,
	PROXY_SERVER_CONN_STAT_PIPE,
	PROXY_SERVER_CONN_STAT_CLOSE,
} PROXY_SERVER_CONN_STATE;

struct conn_buffer {
	char data[CONN_BUFF_SIZE];
	int size;
	int len;
	struct conn_buffer *next;
};

/* proxy server cache - just stores the proxy name */
struct proxy_server {
	struct hlist_node node;
	char proxy_name[PROXY_NAME_LEN];
	time_t last_alive;
	int ipv6_check_ok;
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
	char user[64];
	char pass[64];
	struct dns_conf_group *conf;
	char listener_name[PROXY_NAME_LEN];
	char proxy_name[PROXY_NAME_LEN];
	char group_name[PROXY_NAME_LEN];
	PROXY_SERVER_CONN_TYPE listener_type;
	struct sockaddr_storage orig_dst;
	socklen_t orig_dst_len;
	int remote_dns;
	int force_aaaa_soa;
	struct proxy_channel *channel;

	/* Fields for domain resolution and target tracking */
	unsigned short target_port;
};

struct proxy_server_conn_redirect {
	struct conn_buffer *send_buff;
};

struct proxy_server_conn_udp_session {
	struct proxy_server_udp_session *session_hash; /* back pointer to hash table entry */
	struct proxy_conn *pconn;
	struct conn_buffer *pending_packet_head;
	struct conn_buffer *pending_packet_tail;
	int connected;
	int spoof_fd;
};

struct proxy_server_conn_forward {
	char target[DNS_MAX_IPLEN];
	char proxy_name[PROXY_NAME_LEN];
};

struct proxy_server_udp_session {
	struct hlist_node node;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	struct proxy_server_conn *conn;
	struct proxy_server_conn *listener;
	int ifindex; /* Interface index where packet received */
	time_t last_active;
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

	struct proxy_server_conn_forward forward;

	union {
		struct proxy_server_conn_remote remote;
		struct proxy_server_conn_client client;
		struct proxy_server_conn_redirect redirect;
		struct proxy_server_conn_udp_session udp_session;
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
	DECLARE_HASHTABLE(udp_sessions, 8);
};

static int is_proxy_server_init;
static struct dns_proxy_server dns_proxy_server;

static int _proxy_server_conn_process(struct proxy_server_conn *conn);
static int get_sockaddr_port(struct sockaddr *addr);
static int _proxy_server_conn_close(struct proxy_server_conn *conn);

static int get_addr_from_string(const char *host, struct sockaddr_storage *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
		ss->ss_family = AF_INET;
		return 0;
	}
	if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
		ss->ss_family = AF_INET6;
		return 0;
	}
	return -1;
}

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
	proxy_server = zalloc(1, sizeof(*proxy_server));
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

static int _proxy_server_recv_data(struct proxy_server_conn *conn, struct conn_buffer *buff)
{
	int n = 0;
	int fd = conn->fd;

	if (fd <= 0 && (conn->type != PROXY_SERVER_CONN_REMOTE || conn->remote.pconn == NULL) &&
		!((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
		  conn->client.channel)) {
		return -1;
	}

	if (buff == NULL) {
		return -1;
	}

	for (;;) {
		if (buff->size == buff->len) {
			return 0;
		}

		/* 复制模式，读取数据到缓冲区 */
		if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
			n = proxy_conn_recv(conn->remote.pconn, buff->data + buff->len, buff->size - buff->len, 0);
		} else if ((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
				   conn->client.channel) {
			n = proxy_channel_recv(conn->client.channel, buff->data + buff->len, buff->size - buff->len, 0);
		} else {
			n = recv(fd, buff->data + buff->len, buff->size - buff->len, 0);
		}

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

static int _proxy_server_send_data(struct proxy_server_conn *conn, struct conn_buffer *buff)
{
	int n = 0;
	int fd = conn->fd;

	if (fd <= 0 && (conn->type != PROXY_SERVER_CONN_REMOTE || conn->remote.pconn == NULL) &&
		!((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
		  conn->client.channel)) {
		return -1;
	}

	if (buff == NULL) {
		return -1;
	}

	while (buff->len > 0) {
		int len = buff->len;
		if (len > buff->size) {
			len = buff->size;
		}

		if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
			n = proxy_conn_send(conn->remote.pconn, buff->data, len, 0);
		} else if ((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
				   conn->client.channel) {
			n = proxy_channel_send(conn->client.channel, buff->data, len, MSG_NOSIGNAL);
		} else {
			n = send(fd, buff->data, len, MSG_NOSIGNAL);
		}

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
		out = _proxy_server_send_data(to, from->buff);
		if (out < 0) {
			return -1;
		} else if (out == 1) {
			return 0;
		}
	}

	for (;;) {
		if (in == 0) {
			in = _proxy_server_recv_data(from, from->buff);
			if (in < 0) {
				if (from->buff && from->buff->len > 0) {
					in = 1;
				} else {
					break;
				}
			}
		}

		if (out == 0) {
			if (to->conn_state == PROXY_SERVER_CONN_STAT_PIPE) {
				out = _proxy_server_send_data(to, from->buff);

				if (out < 0) {
					break;
				}
			}
		}

		if (in == 1 || out == 1) {
			return 0;
		}

		/* If peer is not connected, and buffer is full (in=0, out=0), return 0 to wait */
		if (to->conn_state != PROXY_SERVER_CONN_STAT_PIPE) {
			if (from->buff->len == from->buff->size) {
				return 0;
			}
			/* Should continue recv */
		}
	}

	return -1;
}

static int _proxy_server_conn_recv(struct proxy_server_conn *conn)
{
	int ret = 0;

	ret = _proxy_server_recv_data(conn, conn->buff);
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

	if ((conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) ||
		(conn->type == PROXY_SERVER_CONN_UDP_SESSION && conn->udp_session.pconn)) {
		struct proxy_conn *pconn =
			(conn->type == PROXY_SERVER_CONN_REMOTE) ? conn->remote.pconn : conn->udp_session.pconn;

		proxy_conn_set_event_userdata(pconn, conn);

		if (proxy_conn_ctl(pconn, dns_proxy_server.epoll_fd, EPOLL_CTL_ADD, &event_client) != 0) {
			tlog(TLOG_ERROR, "epoll add failed for pconn, %s", strerror(errno));
			goto errout;
		}
	} else if ((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
			   conn->client.channel) {
		if (proxy_channel_ctl(conn->client.channel, dns_proxy_server.epoll_fd, EPOLL_CTL_ADD, &event_client) != 0) {
			tlog(TLOG_ERROR, "epoll add failed for channel, %s", strerror(errno));
			goto errout;
		}
	} else if (conn->fd >= 0) {
		if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_ADD, conn->fd, &event_client) != 0) {
			tlog(TLOG_ERROR, "epoll add failed for fd %d, %s", conn->fd, strerror(errno));
			goto errout;
		}
	}

	return 0;

errout:
	return -1;
}

static int _proxy_server_conn_stop(struct proxy_server_conn *conn)
{
	if (conn->fd <= 0 && (conn->type != PROXY_SERVER_CONN_REMOTE || conn->remote.pconn == NULL) &&
		!((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
		  conn->client.channel)) {
		return -1;
	}

	if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
		if (proxy_conn_ctl(conn->remote.pconn, dns_proxy_server.epoll_fd, EPOLL_CTL_DEL, NULL) != 0) {
			tlog(TLOG_ERROR, "epoll del failed, %s", strerror(errno));
			goto errout;
		}
	} else if ((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
			   conn->client.channel) {
		if (proxy_channel_ctl(conn->client.channel, dns_proxy_server.epoll_fd, EPOLL_CTL_DEL, NULL) != 0) {
			tlog(TLOG_ERROR, "epoll del failed, %s", strerror(errno));
			goto errout;
		}
	} else {
		if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL) != 0) {
			if (errno != ENOENT && errno != EBADF) {
				tlog(TLOG_ERROR, "epoll del failed, %d, %s", conn->fd, strerror(errno));
				goto errout;
			}
		}
	}

	return 0;

errout:
	return -1;
}

static struct conn_buffer *_proxy_server_new_conn_buffer(void)
{
	struct conn_buffer *buffer = NULL;
	buffer = zalloc(1, sizeof(*buffer));
	if (buffer == NULL) {
		goto errout;
	}

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
	_proxy_server_conn_stop(conn);

	free(conn->buff);
	if (conn->fd >= 0) {
		close(conn->fd);
		conn->fd = -1;
	}

	if (conn->type == PROXY_SERVER_CONN_CLIENT) {
		pthread_mutex_destroy(&conn->client.peer_list_lock);
	}

	if (conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT ||
		conn->type == PROXY_SERVER_CONN_SOCKS5_SERVER || conn->type == PROXY_SERVER_CONN_HTTP_SERVER) {
		if (conn->client.channel) {
			proxy_channel_free(conn->client.channel);
			conn->client.channel = NULL;
		}
		if (conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) {
			if (conn->redirect.send_buff) {
				free(conn->redirect.send_buff);
				conn->redirect.send_buff = NULL;
			}
		}
	} else if (conn->type == PROXY_SERVER_CONN_REMOTE) {

		if (conn->remote.pconn) {
			proxy_conn_free(conn->remote.pconn);
			conn->remote.pconn = NULL;
		}
	} else if (conn->type == PROXY_SERVER_CONN_UDP_SESSION) {
		if (conn->udp_session.pconn) {
			proxy_conn_ctl(conn->udp_session.pconn, dns_proxy_server.epoll_fd, EPOLL_CTL_DEL, NULL);

			proxy_conn_free(conn->udp_session.pconn);
			conn->udp_session.pconn = NULL;
		}
		struct conn_buffer *curr = conn->udp_session.pending_packet_head;
		while (curr) {
			struct conn_buffer *next = curr->next;
			if (conn->udp_session.pconn) {
				/* Try to send or just drop? Drop is safer on close. */
			}
			free(curr);
			curr = next;
		}
		conn->udp_session.pending_packet_head = NULL;
		conn->udp_session.pending_packet_tail = NULL;
		/* Remove from hash if still linked */
		if (conn->udp_session.session_hash) {
			hash_del(&conn->udp_session.session_hash->node);
			free(conn->udp_session.session_hash);
			conn->udp_session.session_hash = NULL;
		}

		if (conn->udp_session.spoof_fd > 0) {
			close(conn->udp_session.spoof_fd);
			conn->udp_session.spoof_fd = -1;
		}
	}

	free(conn);
}

static struct proxy_server_conn *_proxy_server_conn_new(PROXY_SERVER_CONN_TYPE type)
{
	struct proxy_server_conn *conn = NULL;
	struct conn_buffer *buffer = NULL;

	conn = zalloc(1, sizeof(*conn));
	if (conn == NULL) {
		goto errout;
	}

	conn->type = type;
	atomic_set(&conn->refcnt, 1);
	INIT_LIST_HEAD(&conn->list);
	INIT_LIST_HEAD(&conn->check_list);

	conn->udp_session.spoof_fd = -1;
	switch (type) {
	case PROXY_SERVER_CONN_SERVER_REDIRECT:
		break;
	case PROXY_SERVER_CONN_SERVER:
	case PROXY_SERVER_CONN_TPROXY_SERVER:
	case PROXY_SERVER_CONN_TPROXY_SERVER_UDP:
	case PROXY_SERVER_CONN_SNIPROXY_SERVER:
	case PROXY_SERVER_CONN_SOCKS5_SERVER:
	case PROXY_SERVER_CONN_HTTP_SERVER:
	case PROXY_SERVER_CONN_FORWARD_SERVER:
	case PROXY_SERVER_CONN_FORWARD_SERVER_UDP:
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
	int r = atomic_inc_return(&conn->refcnt);
	if (r <= 1) {
		tlog(TLOG_ERROR, "BUG refcnt is invalid.");
		raise(SIGSEGV);
		return;
	}
}

static struct proxy_server_conn *_proxy_server_conn_open_remote(struct proxy_server_conn *client, const char *host,
																int port, int is_udp, int fast_open)
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
	pconn = proxy_conn_new(proxy_server->proxy_name, host, port, is_udp, 1);
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
	remote->fd = -1;
	remote->remote.pconn = pconn;
	remote->remote.peer = client;
	client->client.retry_all_server = 0;
	_proxy_server_conn_get(client);
	remote->conn_state = PROXY_SERVER_CONN_STAT_CONNECTING;
	remote->timeout = PROXY_SERVER_CONN_TIMEOUT;
	_proxy_server_conn_touch(remote);

	remote->addr_len = sizeof(remote->addr);

	/* Add to client's peer list */
	pthread_mutex_lock(&client->client.peer_list_lock);
	list_add_tail(&remote->remote.peer_list, &client->client.peer_list_head);
	pthread_mutex_unlock(&client->client.peer_list_lock);

	/* Start epoll monitoring */
	if (_proxy_server_conn_start(remote) != 0) {
		tlog(TLOG_ERROR, "start remote conn epoll failed");
		pthread_mutex_lock(&client->client.peer_list_lock);
		list_del_init(&remote->remote.peer_list);
		pthread_mutex_unlock(&client->client.peer_list_lock);

		_proxy_server_conn_put(client);
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
		LIST_HEAD(peer_list);

		pthread_mutex_lock(&conn->client.peer_list_lock);
		list_for_each_entry_safe(remote, tmp, &conn->client.peer_list_head, remote.peer_list)
		{
			if (remote->fd >= 0) {
				shutdown(remote->fd, SHUT_RDWR);
			} else if (remote->type == PROXY_SERVER_CONN_REMOTE && remote->remote.pconn) {
				/* Shutdown internal proxy connection channels */
				proxy_conn_shutdown(remote->remote.pconn, SHUT_RDWR);
			}

			if (remote->type == PROXY_SERVER_CONN_REMOTE) {
				if (remote->remote.peer == conn) {
					remote->remote.peer = NULL;
					list_del_init(&remote->remote.peer_list);
					_proxy_server_conn_put(conn);
					list_add_tail(&remote->remote.peer_list, &peer_list);
					_proxy_server_conn_get(remote);
				}
			}
		}
		pthread_mutex_unlock(&conn->client.peer_list_lock);
		conn->client.peer = NULL;

		list_for_each_entry_safe(remote, tmp, &peer_list, remote.peer_list)
		{
			list_del_init(&remote->remote.peer_list);
			_proxy_server_conn_close(remote);
			_proxy_server_conn_put(remote);
		}

	} else if (conn->type == PROXY_SERVER_CONN_REMOTE) {
		struct proxy_server_conn *client = conn->remote.peer;
		if (client) {
			pthread_mutex_lock(&client->client.peer_list_lock);
			list_del_init(&conn->remote.peer_list);
			if (client->client.peer == conn || list_empty(&client->client.peer_list_head)) {
				if (client->client.retry_all_server == 0) {
					if (client->fd >= 0) {
						shutdown(client->fd, SHUT_RDWR);
					}
				}
				client->client.peer = NULL;
			}
			pthread_mutex_unlock(&client->client.peer_list_lock);

			/* Release the reference to client that was acquired in _proxy_server_conn_open_remote */
			_proxy_server_conn_close(client);
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

	if (conn->conn_state == PROXY_SERVER_CONN_STAT_CLOSE) {
		return 0;
	}

	char host[128] = {0};
	get_host_by_addr(host, sizeof(host), (struct sockaddr *)&conn->addr);
	tlog(TLOG_DEBUG, "connection from %s closed, state=%d", host, conn->conn_state);

	conn->conn_state = PROXY_SERVER_CONN_STAT_CLOSE;
	_proxy_server_conn_get(conn);
	_proxy_server_conn_remote_shutdown(conn);

	pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
	list_del_init(&conn->list);
	pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	if (conn->fd >= 0) {
		if (_proxy_server_conn_stop(conn) != 0) {
			tlog(TLOG_ERROR, "epoll stop failed. %s", strerror(errno));
		}
		close(conn->fd);
		conn->fd = -1;
	}

	_proxy_server_conn_put(conn);
	_proxy_server_conn_put(conn);

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
	conn->conn_state = PROXY_SERVER_CONN_STAT_PIPE;
	conn->timeout = PROXY_SERVER_IDLE_TIMEOUT;

	if (conn->type == PROXY_SERVER_CONN_REMOTE) {
		conn->conn_state = PROXY_SERVER_CONN_STAT_PIPE;
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
	/* Use the first IP if available */
	if (domain_ip_num > 0 && domain_ip[0] != NULL) {
		safe_strncpy(conn->client.domain, domain_ip[0], sizeof(conn->client.domain));
	}

	conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECT_REMOTE;
	return _proxy_server_conn_process(conn);
}

static int _proxy_server_get_domain_ip(const struct dns_result *result, void *user_ptr)
{
	struct proxy_server_conn *conn = user_ptr;
	int ret = 0;
	struct proxy_server_domain_rule sni_domain_rule;
	struct proxy_server *proxy_server = NULL;

	if (conn->conn_state == PROXY_SERVER_CONN_STAT_CLOSE) {
		tlog(TLOG_DEBUG, "connection closed during resolution");
		_proxy_server_conn_put(conn);
		return 0;
	}

	memset(&sni_domain_rule, 0, sizeof(sni_domain_rule));

	if (result->addr_type == DNS_T_AAAA) {
		if (result->rtcode != DNS_RC_NOERROR || result->ip_num == 0 || result->has_soa != 0) {
			struct dns_server_query_option server_query_option;
			memset(&server_query_option, 0, sizeof(server_query_option));
			server_query_option.dns_group_name = conn->client.group_name;
			server_query_option.server_flags = BIND_FLAG_NO_SPEED_CHECK | BIND_FLAG_NO_DUALSTACK_SELECTION;
			if (conn->client.force_aaaa_soa) {
				server_query_option.server_flags |= BIND_FLAG_FORCE_AAAA_SOA;
			}

			tlog(TLOG_DEBUG, "fallback query domain %s A, group %s", result->domain, conn->client.group_name);
			ret = dns_server_query(result->domain, DNS_T_A, &server_query_option, _proxy_server_get_domain_ip, conn);
			if (ret != 0) {
				conn->client.retry_all_server = 0;
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
		tlog(TLOG_DEBUG, "query domain %s failed, %d", result->domain, result->rtcode);
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
	int valid_ip_count = 0;
	for (int i = 0; i < result->ip_num; i++) {
		if (result->addr_type == DNS_T_A) {
			sprintf(ips_buffer[i], "%d.%d.%d.%d", result->ip_addr[i][0], result->ip_addr[i][1], result->ip_addr[i][2],
					result->ip_addr[i][3]);
			if (result->ip_addr[i][0] == 0 && result->ip_addr[i][1] == 0 && result->ip_addr[i][2] == 0 &&
				result->ip_addr[i][3] == 0) {
				continue;
			}
		} else if (result->addr_type == DNS_T_AAAA) {
			sprintf(ips_buffer[i], "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					result->ip_addr[i][0], result->ip_addr[i][1], result->ip_addr[i][2], result->ip_addr[i][3],
					result->ip_addr[i][4], result->ip_addr[i][5], result->ip_addr[i][6], result->ip_addr[i][7],
					result->ip_addr[i][8], result->ip_addr[i][9], result->ip_addr[i][10], result->ip_addr[i][11],
					result->ip_addr[i][12], result->ip_addr[i][13], result->ip_addr[i][14], result->ip_addr[i][15]);
			int is_zero = 1;
			for (int j = 0; j < 16; j++) {
				if (result->ip_addr[i][j] != 0) {
					is_zero = 0;
					break;
				}
			}
			if (is_zero) {
				continue;
			}
		}

		ips[valid_ip_count] = ips_buffer[i];
		valid_ip_count++;
	}

	if (valid_ip_count == 0 && result->ip_num > 0) {
		tlog(TLOG_WARN, "domain %s resolved to invalid IP.", result->domain);
		goto errout;
	}

	ret = _proxy_server_conn_start_all_conn(conn, proxy_server, (const char **)ips, valid_ip_count);
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
				conn->client.retry_all_server = 0;
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

static int _proxy_server_conn_query_domain(struct proxy_server_conn *conn, const char *domain)
{
	struct dns_server_query_option server_query_option;

	memset(&server_query_option, 0, sizeof(server_query_option));
	server_query_option.dns_group_name = conn->client.group_name;
	server_query_option.server_flags = BIND_FLAG_NO_SPEED_CHECK | BIND_FLAG_NO_DUALSTACK_SELECTION;
	if (conn->client.force_aaaa_soa) {
		server_query_option.server_flags |= BIND_FLAG_FORCE_AAAA_SOA;
	}

	tlog(TLOG_DEBUG, "starting local resolution for domain %s, group %s", domain, conn->client.group_name);
	_proxy_server_conn_get(conn);
	int ret = dns_server_query(domain, DNS_T_AAAA, &server_query_option, _proxy_server_get_domain_ip, conn);
	if (ret != 0) {
		conn->client.retry_all_server = 0;
		_proxy_server_conn_put(conn);
	}
	return ret;
}

static int _proxy_server_conn_start_conn_proxy_server(struct proxy_server_conn *conn, struct proxy_server *proxy_server,
													  char *query_domain)
{
	int ret = 0;
	if (proxy_server == NULL) {
		return -1;
	}

	if (!conn->client.remote_dns) {
		tlog(TLOG_DEBUG, "retry connection with local resolution for domain %s via proxy %s", query_domain,
			 proxy_server->proxy_name);
		return _proxy_server_conn_query_domain(conn, query_domain);
	}

	tlog(TLOG_DEBUG, "starting connection for domain %s via proxy %s", query_domain, proxy_server->proxy_name);

	/* Directly start connection - proxy.h will handle all proxy logic */
	ret = _proxy_server_conn_start_all_conn(conn, proxy_server, NULL, 0);
	if (ret != 0) {
		conn->client.retry_all_server = 0;
	}
	return ret;
}

/* New State Machine Implementation */

static int _proxy_server_process_handshake(struct proxy_server_conn *conn)
{
	/* For Socks5 and HTTP, delegate to proxy-channel */
	if (conn->client.listener_type == PROXY_SERVER_CONN_SOCKS5_SERVER ||
		conn->client.listener_type == PROXY_SERVER_CONN_HTTP_SERVER) {

		if (!conn->client.channel) {
			return -1;
		}

		proxy_handshake_state state = proxy_channel_handshake(conn->client.channel, -1);
		if (state == PROXY_HANDSHAKE_WANT_READ) {
			return 0; /* Need more data, stay in HANDSHAKE */
		}
		if (state == PROXY_HANDSHAKE_ERR) {
			return -1;
		}
		/* Handshake OK, move to next state */
		conn->conn_state = PROXY_SERVER_CONN_STAT_GET_TARGET;
		return 0;
	}

	/* For SNI, we need to read enough data to parse the header */
	if (conn->client.listener_type == PROXY_SERVER_CONN_SNIPROXY_SERVER) {
		if (_proxy_server_conn_recv(conn) != 0) {
			return -1;
		}
		/* Check if we have enough data or need more */
		/* Actually SNI parsing happens in GET_TARGET step usually,
		   but we need data first. Let's assume HANDSHAKE for SNI means "Read Initial Data" */
		if (conn->buff->len > 0) {
			conn->conn_state = PROXY_SERVER_CONN_STAT_GET_TARGET;
		}
		return 0;
	}

	/* For TProxy/Forward, no handshake needed */
	conn->conn_state = PROXY_SERVER_CONN_STAT_GET_TARGET;
	return 0;
}

static int _proxy_server_process_get_target(struct proxy_server_conn *conn)
{
	char host[PROXY_SERVER_MAXHOST_NAME] = {0};
	unsigned short port = 0;

	if (conn->client.listener_type == PROXY_SERVER_CONN_SOCKS5_SERVER ||
		conn->client.listener_type == PROXY_SERVER_CONN_HTTP_SERVER) {
		proxy_channel_get_target(conn->client.channel, host, sizeof(host), &port);
		conn->client.domain[0] = 0;
		if (host[0]) {
			safe_strncpy(conn->client.domain, host, sizeof(conn->client.domain));
			/* Check if it's an IP */
			struct sockaddr_storage ss;
			if (get_addr_from_string(host, &ss) == 0) {
				/* Is IP */
			}
		}
	} else if (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
		/* Use original destination */
		if (conn->client.orig_dst.ss_family == AF_INET) {
			struct sockaddr_in *addr_in = (struct sockaddr_in *)&conn->client.orig_dst;
			inet_ntop(AF_INET, &addr_in->sin_addr, host, sizeof(host));
			port = ntohs(addr_in->sin_port);
		} else if (conn->client.orig_dst.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&conn->client.orig_dst;
			inet_ntop(AF_INET6, &addr_in6->sin6_addr, host, sizeof(host));
			port = ntohs(addr_in6->sin6_port);
		}
		safe_strncpy(conn->client.domain, host, sizeof(conn->client.domain));
	} else if (conn->client.listener_type == PROXY_SERVER_CONN_FORWARD_SERVER) {
		/* Use configured target */
		char target_host[PROXY_SERVER_MAXHOST_NAME];
		int target_port = 0;
		const char *target = conn->forward.target;

		if (parse_ip(target, target_host, &target_port) != 0) {
			tlog(TLOG_ERROR, "invalid forward target %s", target);
			return -1;
		}
		safe_strncpy(conn->client.domain, target_host, sizeof(conn->client.domain));
		port = (unsigned short)target_port;
	} else if (conn->client.listener_type == PROXY_SERVER_CONN_SNIPROXY_SERVER) {
		/* Parse SNI */
		char sni[DNS_MAX_CNAME_LEN];
		const char *sni_ptr = NULL;
		int len = parse_tls_header((const char *)conn->buff->data, conn->buff->len, sni, &sni_ptr);
		if (len < 0) {
			if (len == -1) {
				return 0;
			}
			/* Need more data */
			return -1; /* Error */
		}
		safe_strncpy(conn->client.domain, sni, sizeof(conn->client.domain));
		conn->client.sni_offset = sni_ptr - conn->buff->data;
		conn->client.sni_len = strnlen(sni, DNS_MAX_CNAME_LEN);
		port = 443;
	}

	if (conn->client.domain[0] == 0) {
		/* Could not get target yet */
		return -1;
	}

	/* Store the target port */
	conn->client.target_port = port;
	tlog(TLOG_DEBUG, "extracted target: %s:%d", conn->client.domain, port);

	conn->conn_state = PROXY_SERVER_CONN_STAT_RESOLVE;
	return 0;
}

static int _proxy_server_process_resolve(struct proxy_server_conn *conn)
{
	/* 1. Get Domain and Rule */
	const char *domain = conn->client.domain;
	struct proxy_server *proxy_server = NULL;
	struct proxy_server_domain_rule sni_domain_rule;

	_proxy_server_get_domain_rule(conn, domain, &sni_domain_rule);

	/* 2. Determine Proxy Server */
	/* Check if the current proxy (from listener) is a TProxy/SNI listener proxy */
	/* If so, check if the Rule overrides it */
	if (conn->client.proxy_name[0]) {
		if (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
			_proxy_server_check_tproxy_rule(conn, &sni_domain_rule, &proxy_server);
		} else {
			_proxy_server_check_sniproxy_rule(conn, &sni_domain_rule, &proxy_server);
		}

		if (!proxy_server) {
			/* Fallback to listener configured proxy */
			proxy_server = _proxy_server_get_proxy_by_name(conn->client.proxy_name);
		}
	}

	/* Use default if no proxy found */
	if (!proxy_server) {
		proxy_server = &dns_proxy_server.default_proxy_server;
	}
	conn->client.proxy = proxy_server;

	/* 3. Check for Direct Connection (IP or Remote DNS) */
	struct sockaddr_storage ss;
	if (get_addr_from_string(domain, &ss) == 0) {
		/* Domain is an IP address, skip resolution */
		conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECT_REMOTE;
		return 0;
	}

	if (conn->client.remote_dns) {
		/* Remote DNS enabled, let the proxy server handle resolution */
		conn->conn_state = PROXY_SERVER_CONN_STAT_CONNECT_REMOTE;
		return 0;
	}

	/* 4. Perform Local Resolution */
	/* SmartDNS internal resolution */
	conn->conn_state = PROXY_SERVER_CONN_STAT_RESOLVING;
	return _proxy_server_conn_query_domain(conn, domain);
}

static int _proxy_server_process_connect_remote(struct proxy_server_conn *conn)
{
	/* Use the target host and port that were extracted and stored in GET_TARGET phase */
	const char *target_host = conn->client.domain;
	int target_port = conn->client.target_port;

	if (target_port == 0) {
		tlog(TLOG_ERROR, "process_connect_remote: target port is 0, this should not happen");
		return -1;
	}

	tlog(TLOG_DEBUG, "process_connect_remote: connecting to %s:%d", target_host, target_port);

	if (conn->client.peer) {
		return 0;
	}

	struct proxy_server_conn *remote = _proxy_server_conn_open_remote(
		conn, target_host, target_port, (conn->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER_UDP), 0);
	if (!remote) {
		tlog(TLOG_ERROR, "process_connect_remote: failed to open remote connection");
		return -1;
	}

	remote->remote.proxy = conn->client.proxy;
	/* Set other fields */
	conn->client.peer = remote;

	/* Send Success Reply to Client if needed */
	if (conn->client.listener_type == PROXY_SERVER_CONN_SOCKS5_SERVER) {
		/* Send success via channel FD directly to ensure it goes out */
		/* We simplify here: Just send 0x00 for Socks5 or 200 OK for HTTP */
		if (conn->client.channel) {
			unsigned char reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
			/* socket is likely writable as we just processed input, check ret? generally short reply is ok */
			proxy_channel_send(conn->client.channel, reply, 10, MSG_NOSIGNAL);
		}
	} else if (conn->client.listener_type == PROXY_SERVER_CONN_HTTP_SERVER) {
		if (conn->client.channel) {
			const char *reply = "HTTP/1.1 200 Connection Established\r\n\r\n";
			proxy_channel_send(conn->client.channel, (void *)reply, strlen(reply), MSG_NOSIGNAL);
		}
	}

	conn->conn_state = PROXY_SERVER_CONN_STAT_PIPE;
	return 0;
}

static int _proxy_server_conn_process(struct proxy_server_conn *conn)
{
	int loop_detect = 0;
	while (conn->conn_state != PROXY_SERVER_CONN_STAT_PIPE && conn->conn_state != PROXY_SERVER_CONN_STAT_CLOSE) {

		loop_detect++;
		if (loop_detect > 10) {
			return -1; /* Prevent infinite loops */
		}

		switch (conn->conn_state) {
		case PROXY_SERVER_CONN_STAT_INIT:
			conn->conn_state = PROXY_SERVER_CONN_STAT_HANDSHAKE;
			break;
		case PROXY_SERVER_CONN_STAT_HANDSHAKE:
			if (_proxy_server_process_handshake(conn) != 0) {
				return -1;
			}
			if (conn->conn_state == PROXY_SERVER_CONN_STAT_HANDSHAKE) {
				return 0; /* Wait for more data */
			}
			break;
		case PROXY_SERVER_CONN_STAT_GET_TARGET:
			if (_proxy_server_process_get_target(conn) != 0) {
				return -1;
			}
			break;
		case PROXY_SERVER_CONN_STAT_RESOLVE:
			if (_proxy_server_process_resolve(conn) != 0) {
				return -1;
			}
			if (conn->conn_state == PROXY_SERVER_CONN_STAT_RESOLVE) {
				return 0; /* Async query started, wait */
			}
			break;
		case PROXY_SERVER_CONN_STAT_RESOLVING:
			return 0; /* Wait for DNS */
		case PROXY_SERVER_CONN_STAT_CONNECT_REMOTE:
			if (_proxy_server_process_connect_remote(conn) != 0) {
				return -1;
			}
			break;
		default:
			return -1;
		}
	}
	return 0;
}

static struct proxy_server_conn *_proxy_server_accept(struct proxy_server_conn *conn, struct epoll_event *event,
													  unsigned long now, PROXY_SERVER_CONN_TYPE client_type)
{

	struct proxy_server_conn *client = NULL;
	int fd = -1;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char hostname[PROXY_SERVER_MAXHOST_NAME];
	struct proxy_channel *channel = NULL;

	if (conn->client.channel) {
		channel = proxy_channel_accept(conn->client.channel);
		if (channel == NULL) {
			return NULL;
		}
		addr_len = sizeof(addr);
		proxy_channel_get_addr(channel, (struct sockaddr *)&addr, &addr_len);
		/* fd remains -1 */
	} else {
		fd = accept4(conn->fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			return NULL;
		}
	}

	if (channel) {
	} else {
		tlog(TLOG_DEBUG, "accepted connection on listener %s, fd %d", conn->client.listener_name, fd);
	}

	client = _proxy_server_conn_new(client_type);
	if (client == NULL) {
		goto errout;
	}

	client->fd = fd;
	client->client.channel = channel;
	safe_strncpy(client->client.user, conn->client.user, sizeof(client->client.user));
	safe_strncpy(client->client.pass, conn->client.pass, sizeof(client->client.pass));
	proxy_channel_set_server_auth(channel, client->client.user, client->client.pass);
	memcpy(&client->addr, &addr, addr_len);
	client->addr_len = addr_len;
	client->timeout = PROXY_SERVER_CONN_TIMEOUT;

	if (channel == NULL) {
		if (set_fd_nonblock(fd, 1) != 0) {
			tlog(TLOG_ERROR, "set non block failed.");
			goto errout;
		}
		set_sock_keepalive(fd, 30, 3, 5);
	}

	if (_proxy_server_conn_start(client) != 0) {
		tlog(TLOG_ERROR, "start conn failed.");
		goto errout;
	}

	_proxy_server_conn_touch(client);

	if (conn->type == PROXY_SERVER_CONN_TPROXY_SERVER || conn->type == PROXY_SERVER_CONN_SNIPROXY_SERVER ||
		conn->type == PROXY_SERVER_CONN_SERVER || conn->type == PROXY_SERVER_CONN_SOCKS5_SERVER ||
		conn->type == PROXY_SERVER_CONN_FORWARD_SERVER || conn->type == PROXY_SERVER_CONN_HTTP_SERVER) {
		safe_strncpy(client->client.listener_name, conn->client.listener_name, PROXY_NAME_LEN);
		safe_strncpy(client->client.proxy_name, conn->client.proxy_name, PROXY_NAME_LEN);
		safe_strncpy(client->client.group_name, conn->client.group_name, PROXY_NAME_LEN);
		client->client.listener_type = conn->type;
		client->client.orig_dst_len = sizeof(client->client.orig_dst);
		client->client.remote_dns = conn->client.remote_dns;
		client->client.force_aaaa_soa = conn->client.force_aaaa_soa;

		if (conn->type == PROXY_SERVER_CONN_TPROXY_SERVER || conn->type == PROXY_SERVER_CONN_SNIPROXY_SERVER ||
			conn->type == PROXY_SERVER_CONN_SERVER) {
			tproxy_get_original_dst(client->fd, &client->client.orig_dst, &client->client.orig_dst_len);
		}
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
	} else if (channel) {
		proxy_channel_free(channel);
	}
	return NULL;
}

static int _proxy_server_process_conn_event_err(struct proxy_server_conn *conn, struct epoll_event *event)
{
	/* epoll消息异常处理 */
	if (!(event->events & (EPOLLERR | EPOLLHUP))) {
		return 0;
	}

	int err = 0;
	if (conn->fd >= 0) {
		socklen_t len = sizeof(err);
		getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len);
	} else if ((conn->type == PROXY_SERVER_CONN_CLIENT || conn->type == PROXY_SERVER_CONN_CLIENT_REDIRECT) &&
			   conn->client.channel) {
		err = proxy_channel_get_opt_error(conn->client.channel);
	} else if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
		/* Remote connection uses proxy_conn, but epoll event data.ptr is the channel */
		/* The loop in _proxy_server_work correctly identified the channel and retrieved the conn */
		/* We can get the error from the channel if we had access to it,
		   but it's easier to just call it on the conn's active channel or race mode */
		err = proxy_conn_get_last_error(conn->remote.pconn);
		if (err == 0) {
			/* Fallback to checking socket error directly if we can't get it from handshake */
			/* Since we don't have the channel here, we have to trust the handshake last_error for now,
			   or provide a better API to get error from any channel in proxy_conn */
		}
	}

	if (err == 0 && (event->events & EPOLLHUP)) {
		err = ECONNRESET;
	}
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

	ret = _proxy_server_process_conn_write_data(conn, peer, event);
	if (ret != 0) {
		goto errout;
	}

	/* Process Protocol State Machine */
	if (conn->conn_state != PROXY_SERVER_CONN_STAT_PIPE && conn->conn_state != PROXY_SERVER_CONN_STAT_CLOSE) {
		if (_proxy_server_conn_process(conn) != 0) {
			goto errout;
		}
		if (conn->conn_state != PROXY_SERVER_CONN_STAT_PIPE) {
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
	ret = _proxy_server_conn_start_conn_proxy_server(client, client->client.proxy, client->client.domain);
	if (ret != 0) {
		tlog(TLOG_ERROR, "retry connect all proxy server failed.");
	}

	return ret;
}

static int _proxy_server_handshake_fallback(struct proxy_server_conn *conn, int state)
{
	if (state != PROXY_HANDSHAKE_ERR) {
		return 0;
	}

	int last_error = proxy_conn_get_last_error(conn->remote.pconn);
	int update_global = 0;
	int retry_local = 0;

	switch (last_error) {
	case 0x03: /* Network unreachable */
	case 0x08: /* Address type not supported */
		/* These errors strongly suggest the proxy server lacks IPv6 environment */
		update_global = 1;
		retry_local = 1;
		break;
	case 0x04: /* Host unreachable */
		/* Host unreachable might be a specific host issue.
		   Retry this connection with IPv4 (force-aaaa-soa), but do not disable IPv6 globally. */
		update_global = 0;
		retry_local = 1;
		break;
	case 502:
	case 503:
	case 504:
		/* Maintain existing behavior for HTTP errors */
		update_global = 1;
		retry_local = 1;
		break;
	default:
		return 0;
	}

	/* Check if target is IPv6 */
	if (!proxy_conn_is_ipv6_target(conn->remote.pconn)) {
		return 0;
	}

	if (conn->remote.proxy->ipv6_check_ok) {
		return 0;
	}

	struct proxy_server_conn *client = conn->remote.peer;
	if (client && (client->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER ||
				   client->client.listener_type == PROXY_SERVER_CONN_SNIPROXY_SERVER ||
				   client->client.listener_type == PROXY_SERVER_CONN_SOCKS5_SERVER ||
				   client->client.listener_type == PROXY_SERVER_CONN_HTTP_SERVER)) {

		if (update_global) {
			const char *listener_name = client->client.listener_name;
			int updated = 0;
			const char *type_str = "unknown";

			if (client->client.listener_type == PROXY_SERVER_CONN_TPROXY_SERVER) {
				type_str = "tproxy-server";
				struct dns_tproxy_server_conf *t_conf = dns_conf_get_tproxy_server(listener_name);
				if (t_conf && t_conf->force_aaaa_soa == 0) {
					t_conf->force_aaaa_soa = 1;
					updated = 1;
				}
			} else if (client->client.listener_type == PROXY_SERVER_CONN_SNIPROXY_SERVER) {
				type_str = "sni-proxy";
				struct dns_sniproxy_server_conf *s_conf = dns_conf_get_sniproxy_server(listener_name);
				if (s_conf && s_conf->force_aaaa_soa == 0) {
					s_conf->force_aaaa_soa = 1;
					updated = 1;
				}
			} else if (client->client.listener_type == PROXY_SERVER_CONN_SOCKS5_SERVER) {
				type_str = "socks5-proxy";
				struct dns_socks5_proxy_server_conf *s5_conf = dns_conf_get_socks5_proxy_server(listener_name);
				if (s5_conf && s5_conf->force_aaaa_soa == 0) {
					s5_conf->force_aaaa_soa = 1;
					updated = 1;
				}
			} else if (client->client.listener_type == PROXY_SERVER_CONN_HTTP_SERVER) {
				type_str = "http-proxy";
				struct dns_http_proxy_server_conf *h_conf = dns_conf_get_http_proxy_server(listener_name);
				if (h_conf && h_conf->force_aaaa_soa == 0) {
					h_conf->force_aaaa_soa = 1;
					updated = 1;
				}
			}

			if (updated) {
				tlog(TLOG_WARN,
					 "Upstream proxy returned '%s' for IPv6 target. "
					 "Forcing force-aaaa-soa=yes for %s '%s' to disable IPv6 resolution (effective for next request). "
					 "Please configure 'force-aaaa-soa yes' in your config.",
					 proxy_handshake_error_to_string(last_error), type_str, listener_name);

				/* Propagate to all matching listeners */
				struct proxy_server_conn *l_conn = NULL;
				list_for_each_entry(l_conn, &dns_proxy_server.listeners, list)
				{
					if (l_conn->type == client->client.listener_type &&
						strcmp(l_conn->client.listener_name, listener_name) == 0) {
						l_conn->client.force_aaaa_soa = 1;
					}
				}
			}
		} else {
			tlog(TLOG_WARN,
				 "Upstream proxy returned '%s' for IPv6 target. Retrying with IPv4 (force-aaaa-soa) for this request.",
				 proxy_handshake_error_to_string(last_error));
		}

		if (retry_local) {
			client->client.force_aaaa_soa = 1;
			client->client.retry_all_server = 1;
			return 1;
		}
	}
	return 0;
}

static int _proxy_server_remote_handshake(struct proxy_server_conn *conn, struct epoll_event *event)
{
	proxy_handshake_state state;
	struct proxy_server_conn *client = conn->remote.peer;

	if (client == NULL) {
		tlog(TLOG_DEBUG, "client peer is gone during handshake");
		return -1;
	}

	if (conn->conn_state == PROXY_SERVER_CONN_STAT_PIPE) {
		return 0;
	}

	if (conn->remote.pconn == NULL) {
		tlog(TLOG_ERROR, "remote pconn is NULL during handshake");
		return -1;
	}

	/* Perform proxy handshake using src/proxy.c interface */
	struct proxy_channel *channel = proxy_channel_get_from_event(event->data.ptr);
	if (channel == NULL) {
		tlog(TLOG_ERROR, "epoll event is not a proxy channel event during handshake");
		return -1;
	}
	state = proxy_channel_handshake(channel, dns_proxy_server.epoll_fd);

	if (state == PROXY_HANDSHAKE_OK || state == PROXY_HANDSHAKE_CONNECTED) {
		time(&conn->remote.proxy->last_alive);
		if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
			conn->addr_len = sizeof(conn->addr);
			proxy_conn_get_peeraddr(conn->remote.pconn, (struct sockaddr *)&conn->addr, &conn->addr_len);
		}

		if (client->client.peer == NULL) {
			client->client.peer = conn;
		} else if (client->client.peer != conn) {
			tlog(TLOG_DEBUG, "client already has a different peer, closing this connection");
			return -1;
		}

		conn->timeout = PROXY_SERVER_IDLE_TIMEOUT;
		client->timeout = PROXY_SERVER_IDLE_TIMEOUT;
		conn->conn_state = PROXY_SERVER_CONN_STAT_PIPE;

		struct epoll_event event_remote;
		memset(&event_remote, 0, sizeof(event_remote));
		event_remote.data.ptr = conn;
		event_remote.events = EPOLLIN | EPOLLOUT | EPOLLET;

		if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
			if (proxy_conn_ctl(conn->remote.pconn, dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, &event_remote) != 0) {
				tlog(TLOG_ERROR, "epoll mod failed after handshake, %s", strerror(errno));
				return -1;
			}
		} else {
			if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, conn->fd, &event_remote) != 0) {
				tlog(TLOG_ERROR, "epoll mod failed after handshake, %s", strerror(errno));
				return -1;
			}
		}

		tlog(TLOG_DEBUG, "connected to proxy server, ready to pipe data");

		if (proxy_conn_is_ipv6_target(conn->remote.pconn)) {
			conn->remote.proxy->ipv6_check_ok = 1;
		}

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

		if (conn->type == PROXY_SERVER_CONN_REMOTE && conn->remote.pconn) {
			if (proxy_conn_ctl(conn->remote.pconn, dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, &event_remote) != 0) {
				tlog(TLOG_ERROR, "epoll mod failed during handshake, %s", strerror(errno));
				return -1;
			}
		} else {
			if (epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, conn->fd, &event_remote) != 0) {
				tlog(TLOG_ERROR, "epoll mod failed during handshake, %s", strerror(errno));
				return -1;
			}
		}
		return 1;
	}

	int last_error = proxy_conn_get_last_error(conn->remote.pconn);
	char target[DNS_MAX_CNAME_LEN] = {0};
	unsigned short target_port = 0;
	proxy_conn_get_target(conn->remote.pconn, target, sizeof(target), &target_port);
	tlog(TLOG_DEBUG, "proxy handshake failed, state=%d, error=%s, target=%s:%d", state,
		 proxy_handshake_error_to_string(last_error), target, target_port);

	if (_proxy_server_handshake_fallback(conn, state) == 1) {
		return -2;
	}
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
	} else if (ret == -2) {
		goto errout1;
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

		if (_proxy_server_send_data(conn, conn->redirect.send_buff) < 0) {
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
		_proxy_server_send_data(conn, conn->redirect.send_buff);
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

static int _proxy_server_accept_forward_conn(struct proxy_server_conn *conn, struct epoll_event *event,
											 unsigned long now)
{
	struct proxy_server_conn *client = NULL;

	client = _proxy_server_accept(conn, event, now, PROXY_SERVER_CONN_CLIENT);
	if (client == NULL) {
		return -1;
	}

	safe_strncpy(client->forward.target, conn->forward.target, sizeof(client->forward.target));
	safe_strncpy(client->forward.proxy_name, conn->forward.proxy_name, sizeof(client->forward.proxy_name));

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

	buffer = zalloc(1, sizeof(*buffer));
	if (buffer == NULL) {
		goto errout;
	}

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

static int _proxy_server_accept_socks5_conn(struct proxy_server_conn *conn, struct epoll_event *event,
											unsigned long now)
{
	struct proxy_server_conn *client = NULL;
	client = _proxy_server_accept(conn, event, now, PROXY_SERVER_CONN_CLIENT);
	if (client == NULL) {
		return -1;
	}
	return 0;
}

static int _proxy_server_accept_http_conn(struct proxy_server_conn *conn, struct epoll_event *event, unsigned long now)
{
	struct proxy_server_conn *client = NULL;
	client = _proxy_server_accept(conn, event, now, PROXY_SERVER_CONN_CLIENT);
	if (client == NULL) {
		return -1;
	}
	return 0;
}

static void _proxy_server_send_spoofed_udp_reply(struct proxy_server_conn *conn, void *data, int len,
												 struct sockaddr *dest, struct sockaddr *src, int ifindex);

static socklen_t get_sockaddr_len(struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_INET6) {
		return sizeof(struct sockaddr_in6);
	}
	return sizeof(struct sockaddr);
}

static int get_sockaddr_port(struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		return ntohs(((struct sockaddr_in *)addr)->sin_port);
	} else if (addr->sa_family == AF_INET6) {
		return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	}
	return 0;
}

static int sockaddr_cmp(struct sockaddr *x, struct sockaddr *y)
{
	if (x->sa_family != y->sa_family) {
		return -1;
	}

	if (x->sa_family == AF_INET) {
		struct sockaddr_in *xin = (struct sockaddr_in *)x;
		struct sockaddr_in *yin = (struct sockaddr_in *)y;
		if (xin->sin_addr.s_addr != yin->sin_addr.s_addr) {
			return -1;
		}
		if (xin->sin_port != yin->sin_port) {
			return -1;
		}
		return 0;
	} else if (x->sa_family == AF_INET6) {
		struct sockaddr_in6 *xin6 = (struct sockaddr_in6 *)x;
		struct sockaddr_in6 *yin6 = (struct sockaddr_in6 *)y;
		if (memcmp(&xin6->sin6_addr, &yin6->sin6_addr, sizeof(xin6->sin6_addr)) != 0) {
			return -1;
		}
		if (xin6->sin6_port != yin6->sin6_port) {
			return -1;
		}
		return 0;
	}
	return -1;
}

static uint32_t _proxy_server_udp_session_key(struct sockaddr *src, struct sockaddr *dst)
{
	uint32_t key = 0;
	if (src->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)src;
		struct sockaddr_in *d = (struct sockaddr_in *)dst;
		key = jhash_2words(s->sin_addr.s_addr, s->sin_port, key);
		key = jhash_2words(d->sin_addr.s_addr, d->sin_port, key);
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)src;
		struct sockaddr_in6 *d = (struct sockaddr_in6 *)dst;
		key = jhash(&s->sin6_addr, sizeof(s->sin6_addr), key);
		key = jhash_2words(s->sin6_port, 0, key);
		key = jhash(&d->sin6_addr, sizeof(d->sin6_addr), key);
		key = jhash_2words(d->sin6_port, 0, key);
	}
	return key;
}

static struct proxy_server_conn *_proxy_server_udp_session_get_conn(struct sockaddr *src, struct sockaddr *dst,
																	int *new_session)
{
	uint32_t key = _proxy_server_udp_session_key(src, dst);
	struct proxy_server_udp_session *session = NULL;
	struct hlist_node *tmp = NULL;

	hash_for_each_possible_safe(dns_proxy_server.udp_sessions, session, tmp, node, key)
	{
		if (sockaddr_cmp((struct sockaddr *)&session->src_addr, src) == 0 &&
			sockaddr_cmp((struct sockaddr *)&session->dst_addr, dst) == 0) {
			*new_session = 0;
			if (session->conn) {
				return session->conn;
			}
			tlog(TLOG_WARN, "Found zombie UDP session, removing");
			hash_del(&session->node);
			free(session);
			break;
		}
	}

	/* Create new session */
	session = zalloc(1, sizeof(*session));
	if (session == NULL) {
		return NULL;
	}

	memcpy(&session->src_addr, src, get_sockaddr_len(src));
	memcpy(&session->dst_addr, dst, get_sockaddr_len(dst));
	time(&session->last_active);

	/* Create connection */
	struct proxy_server_conn *conn = _proxy_server_conn_new(PROXY_SERVER_CONN_UDP_SESSION);
	if (conn == NULL) {
		free(session);
		return NULL;
	}

	memcpy(&conn->addr, src, get_sockaddr_len(src));
	time(&conn->last);

	session->conn = conn;
	conn->udp_session.session_hash = session;
	conn->timeout = PROXY_SERVER_UDP_SESSION_TIMEOUT;

	hash_add(dns_proxy_server.udp_sessions, &session->node, key);
	*new_session = 1;
	return conn;
}

static int _proxy_server_process_forward_udp(struct proxy_server_conn *conn, struct epoll_event *event,
											 unsigned long now)
{
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	socklen_t addr_len = sizeof(src_addr);
	unsigned char buf[CONN_BUFF_SIZE];
	int len = 0;
	int new_session = 0;
	struct proxy_server_conn *session_conn = NULL;

	if (atomic_read(&dns_proxy_server.run) == 0) {
		return 0;
	}

	len = recvfrom(conn->fd, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &addr_len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		tlog(TLOG_ERROR, "recvfrom failed: %s", strerror(errno));
		return -1;
	}

	/* For forward server, dst_addr is just the listener address */
	socklen_t slen = sizeof(dst_addr);
	getsockname(conn->fd, (struct sockaddr *)&dst_addr, &slen);

	session_conn =
		_proxy_server_udp_session_get_conn((struct sockaddr *)&src_addr, (struct sockaddr *)&dst_addr, &new_session);
	if (!session_conn) {
		tlog(TLOG_ERROR, "Failed to create/get udp session conn");
		return -1;
	}

	/* Update listener reference */
	session_conn->udp_session.session_hash->listener = conn;
	time(&session_conn->udp_session.session_hash->last_active);

	if (new_session) {
		char target_host[PROXY_SERVER_MAXHOST_NAME];
		int target_port = 0;
		const char *target = conn->forward.target;
		const char *proxy_name = conn->forward.proxy_name;

		if (parse_ip(target, target_host, &target_port) != 0) {
			tlog(TLOG_ERROR, "invalid forward target %s", target);
			_proxy_server_conn_close(session_conn);
			_proxy_server_conn_put(session_conn);
			return -1;
		}

		char src_ip[64] = {0};
		get_host_by_addr(src_ip, sizeof(src_ip), (struct sockaddr *)&src_addr);
		tlog(TLOG_DEBUG, "Creating new UDP forward session from %s to %s via %s", src_ip, target, proxy_name);

		session_conn->udp_session.pconn = proxy_conn_new(proxy_name, target_host, target_port, 1, 1);
		if (!session_conn->udp_session.pconn) {
			tlog(TLOG_ERROR, "create proxy conn failed");
			_proxy_server_conn_close(session_conn);
			_proxy_server_conn_put(session_conn);
			return -1;
		}

		if (proxy_conn_connect(session_conn->udp_session.pconn) != 0 && errno != EINPROGRESS) {
			tlog(TLOG_ERROR, "proxy conn connect failed: %s", strerror(errno));
			_proxy_server_conn_close(session_conn);
			_proxy_server_conn_put(session_conn);
			return -1;
		}

		session_conn->fd = -1;
		session_conn->udp_session.pending_packet_head = _proxy_server_new_conn_buffer();
		if (session_conn->udp_session.pending_packet_head) {
			if ((size_t)len > sizeof(session_conn->udp_session.pending_packet_head->data)) {
				len = sizeof(session_conn->udp_session.pending_packet_head->data);
			}
			memcpy(session_conn->udp_session.pending_packet_head->data, buf, len);
			session_conn->udp_session.pending_packet_head->len = len;
			session_conn->udp_session.pending_packet_tail = session_conn->udp_session.pending_packet_head;
		}

		_proxy_server_conn_start(session_conn);

		pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
		list_add(&session_conn->list, &dns_proxy_server.conn_list);
		pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	} else {
		/* Add packet to pending or send immediately if connected */
		if (session_conn->conn_state == PROXY_SERVER_CONN_STAT_PIPE) {
			if (proxy_conn_send(session_conn->udp_session.pconn, buf, len, 0) < 0) {
				tlog(TLOG_ERROR, "proxy_conn_send failed");
				_proxy_server_conn_close(session_conn);
				return -1;
			}
		} else {
			struct conn_buffer *buffer = _proxy_server_new_conn_buffer();
			if (buffer) {
				if ((size_t)len > sizeof(buffer->data)) {
					len = sizeof(buffer->data);
				}
				memcpy(buffer->data, buf, len);
				buffer->len = len;
				if (session_conn->udp_session.pending_packet_tail) {
					session_conn->udp_session.pending_packet_tail->next = buffer;
					session_conn->udp_session.pending_packet_tail = buffer;
				} else {
					session_conn->udp_session.pending_packet_head = buffer;
					session_conn->udp_session.pending_packet_tail = buffer;
				}
			}
		}
	}

	return 0;
}

static void _proxy_server_flush_pending_packets(struct proxy_server_conn *conn)
{
	struct conn_buffer *curr = conn->udp_session.pending_packet_head;
	while (curr) {
		struct conn_buffer *next = curr->next;
		int rc = 0;
		if (conn->udp_session.session_hash->listener &&
			conn->udp_session.session_hash->listener->type == PROXY_SERVER_CONN_FORWARD_SERVER_UDP) {
			rc = proxy_conn_send(conn->udp_session.pconn, curr->data, curr->len, 0);
		} else {
			rc = proxy_conn_sendto(conn->udp_session.pconn, curr->data, curr->len, 0,
								   (struct sockaddr *)&conn->udp_session.session_hash->dst_addr,
								   sizeof(conn->udp_session.session_hash->dst_addr));
		}
		if (rc < 0) {
			tlog(TLOG_ERROR, "Failed to send pending packet to proxy: %s", strerror(errno));
		}
		free(curr);
		curr = next;
	}
	conn->udp_session.pending_packet_head = NULL;
	conn->udp_session.pending_packet_tail = NULL;
}

static int _proxy_server_handle_udp_handshake(struct proxy_server_conn *conn, struct epoll_event *event)
{
	/* Perform proxy handshake using src/proxy.c interface */
	struct proxy_channel *channel = proxy_channel_get_from_event(event->data.ptr);
	if (channel == NULL) {
		tlog(TLOG_ERROR, "epoll event is not a proxy channel event during udp handshake");
		return -1;
	}
	int ret = proxy_channel_handshake(channel, dns_proxy_server.epoll_fd);
	if (ret != PROXY_HANDSHAKE_CONNECTED) {
		if (ret == PROXY_HANDSHAKE_ERR) {
			return -1;
		}
		return 0;
	}

	struct epoll_event ev_udp;
	ev_udp.events = EPOLLIN | EPOLLET;
	ev_udp.data.ptr = conn;
	if (proxy_conn_ctl(conn->udp_session.pconn, dns_proxy_server.epoll_fd, EPOLL_CTL_ADD, &ev_udp) != 0) {
		tlog(TLOG_ERROR, "Failed to add UDP proxy conn to epoll: %s", strerror(errno));
	}

	struct epoll_event ev_tcp;
	epoll_ctl(dns_proxy_server.epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev_tcp);

	conn->udp_session.connected = 1;
	_proxy_server_flush_pending_packets(conn);

	return 0;
}

static int _proxy_server_process_udp_session(struct proxy_server_conn *conn, struct epoll_event *event,
											 unsigned long now)
{
	int ret;
	if (conn->type != PROXY_SERVER_CONN_UDP_SESSION) {
		return -1;
	}

	/* Refresh timeout */
	if (conn->udp_session.session_hash) {
		time(&conn->udp_session.session_hash->last_active);
	}
	time(&conn->last);

	/* Handle handshake if not connected */
	if (!conn->udp_session.connected) {
		ret = _proxy_server_handle_udp_handshake(conn, event);
		if (ret < 0) {
			return -1;
		}
		return 0;
	}

	/* Connected state */
	if (conn->udp_session.connected) {
		unsigned char buf[DNS_IN_PACKSIZE];
		struct sockaddr_storage src_addr;
		socklen_t addrlen = sizeof(src_addr);
		int len;

		/* Try receiving from UDP */
		while ((len = proxy_conn_recvfrom(conn->udp_session.pconn, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr,
										  &addrlen)) > 0) {
			/* Forward back to client (the spoofer) */
			struct proxy_server_conn *listener = conn->udp_session.session_hash->listener;
			if (listener) {
				struct sockaddr_storage src = conn->udp_session.session_hash->src_addr;
				struct sockaddr_storage dst = conn->udp_session.session_hash->dst_addr;

				if (listener->type == PROXY_SERVER_CONN_FORWARD_SERVER_UDP) {
					/* For forward-server, just reply using the listener socket */
					if (sendto(listener->fd, buf, len, 0, (struct sockaddr *)&src,
							   get_sockaddr_len((struct sockaddr *)&src)) < 0) {
						tlog(TLOG_DEBUG, "forward udp reply failed: %s", strerror(errno));
					}
				} else {
					_proxy_server_send_spoofed_udp_reply(conn, buf, len, (struct sockaddr *)&src,
														 (struct sockaddr *)&dst,
														 conn->udp_session.session_hash->ifindex);
				}
			} else {
				tlog(TLOG_ERROR, "Missing listener for UDP session reply");
			}
		}
		if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			tlog(TLOG_DEBUG, "proxy_conn_recvfrom failed: %s", strerror(errno));
		}

		if (event->events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
			tlog(TLOG_DEBUG, "UDP session TCP control channel closed/error, events=0x%x", event->events);
			return -1;
		}
	}

	return 0;
}

static void _proxy_server_send_spoofed_udp_reply(struct proxy_server_conn *conn, void *data, int len,
												 struct sockaddr *dest, struct sockaddr *src, int ifindex)
{
	int fd = conn->udp_session.spoof_fd;

	if (fd < 0) {
		fd = socket(dest->sa_family, SOCK_DGRAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "Failed to create spoof socket: %s", strerror(errno));
			return;
		}

		int yes = 1;

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));

		if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) < 0) {
			tlog(TLOG_ERROR, "Failed to set IP_TRANSPARENT on spoof socket: %s", strerror(errno));
			close(fd);
			return;
		}

		/* Bind to INADDR_ANY but with the correct SOURCE PORT to spoof the port */
		struct sockaddr_storage bind_addr;
		memcpy(&bind_addr, src, sizeof(bind_addr));
		if (bind_addr.ss_family == AF_INET) {
			((struct sockaddr_in *)&bind_addr)->sin_addr.s_addr = htonl(INADDR_ANY);
		} else if (bind_addr.ss_family == AF_INET6) {
			((struct sockaddr_in6 *)&bind_addr)->sin6_addr = in6addr_any;
		}

		if (bind(fd, (struct sockaddr *)&bind_addr, get_sockaddr_len((struct sockaddr *)&bind_addr)) < 0) {
			tlog(TLOG_ERROR, "Failed to bind spoof socket (local): %s", strerror(errno));
			close(fd);
			return;
		}

		/* Force the reply out of the correct interface */
		int mark = 0;
		setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));

		/* Cache the FD */
		conn->udp_session.spoof_fd = fd;
	}

	/* Send explicitly to destination */
	/* We use sendto directly since we bound the source */
	struct msghdr msg = {0};
	struct iovec iov;
	char control[256];
	struct cmsghdr *cmsg;

	iov.iov_base = data;
	iov.iov_len = len;
	msg.msg_name = dest;
	msg.msg_namelen = get_sockaddr_len(dest);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Setup IP_PKTINFO to specify outgoing interface */
	if (ifindex > 0) {
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);

		if (src->sa_family == AF_INET) {

			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
			struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			memset(pktinfo, 0, sizeof(*pktinfo));
			/* Set Source IP via PKTINFO since we bound to ANY */
			pktinfo->ipi_spec_dst = ((struct sockaddr_in *)src)->sin_addr;
			pktinfo->ipi_ifindex = ifindex;
			msg.msg_controllen = cmsg->cmsg_len;
		} else if (src->sa_family == AF_INET6) {

			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			memset(pktinfo, 0, sizeof(*pktinfo));
			pktinfo->ipi6_addr = ((struct sockaddr_in6 *)src)->sin6_addr;
			pktinfo->ipi6_ifindex = ifindex;
			msg.msg_controllen = cmsg->cmsg_len;
		}
	}

	int retry = 2;
	int sent = 0;
	while (retry-- > 0) {
		if (sendmsg(fd, &msg, MSG_NOSIGNAL) >= 0) {
			sent = 1;
			break;
		}
		if (retry == 0) {
			tlog(TLOG_ERROR, "Failed to send spoofed reply after retries: %s", strerror(errno));
		} else {
			tlog(TLOG_WARN, "Failed to send spoofed reply, retrying: %s", strerror(errno));
			usleep(1000); // 1ms delay
		}
	}
	if (!sent) {
		/* If send fails, maybe the socket is bad? Close it so we retry next time. */
		close(fd);
		conn->udp_session.spoof_fd = -1;
	}
}

static int _proxy_server_process_tproxy_udp(struct proxy_server_conn *conn, struct epoll_event *event,
											unsigned long now)
{
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	struct iovec iov;
	struct msghdr msg;
	char buf[DNS_IN_PACKSIZE];
	char control[1024];
	struct cmsghdr *cmsg;
	int len;
	struct proxy_server_conn *session_conn = NULL;
	int new_session = 0;

	if (atomic_read(&dns_proxy_server.run) == 0) {
		return 0;
	}

	if (!(event->events & EPOLLIN)) {
		return 0;
	}

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(conn->fd, &msg, 0);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		tlog(TLOG_ERROR, "recvmsg failed: %s", strerror(errno));
		return -1;
	}

	char src_ip[64];
	get_host_by_addr(src_ip, sizeof(src_ip), (struct sockaddr *)&src_addr);
	memset(&dst_addr, 0, sizeof(dst_addr));

	int ifindex = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
			struct sockaddr_in *sin = (struct sockaddr_in *)CMSG_DATA(cmsg);
			memcpy(&dst_addr, sin, sizeof(*sin));
			dst_addr.ss_family = AF_INET;
		} else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)CMSG_DATA(cmsg);
			memcpy(&dst_addr, sin6, sizeof(*sin6));
			dst_addr.ss_family = AF_INET6;
		} else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			ifindex = pktinfo->ipi_ifindex;
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			ifindex = pktinfo->ipi6_ifindex;
		}
	}

	if (dst_addr.ss_family == 0) {
		socklen_t slen = sizeof(dst_addr);
		getsockname(conn->fd, (struct sockaddr *)&dst_addr, &slen);
	}

	session_conn =
		_proxy_server_udp_session_get_conn((struct sockaddr *)&src_addr, (struct sockaddr *)&dst_addr, &new_session);
	if (!session_conn) {
		tlog(TLOG_ERROR, "Failed to create/get udp session conn");
		return -1;
	}

	/* Update listener reference and ifindex */
	session_conn->udp_session.session_hash->listener = conn;
	if (ifindex > 0) {
		session_conn->udp_session.session_hash->ifindex = ifindex;
	}
	time(&session_conn->udp_session.session_hash->last_active);

	if (new_session) {
		char proxy_name[PROXY_NAME_LEN];
		char host[MAX_IP_LEN];
		int port;

		get_host_by_addr(host, sizeof(host), (struct sockaddr *)&dst_addr);
		port = get_sockaddr_port((struct sockaddr *)&dst_addr);
		safe_strncpy(proxy_name, conn->client.proxy_name, sizeof(proxy_name));

		int src_port = get_sockaddr_port((struct sockaddr *)&src_addr);
		tlog(TLOG_DEBUG, "Creating new UDP session from %s:%d to %s:%d via %s", src_ip, src_port, host, port,
			 proxy_name);

		session_conn->udp_session.pconn = proxy_conn_new(proxy_name, host, port, 1, 1);
		if (!session_conn->udp_session.pconn) {
			tlog(TLOG_ERROR, "create proxy conn failed");
			_proxy_server_conn_put(session_conn); /* Will cleanup session via free */
			return -1;
		}

		if (proxy_conn_connect(session_conn->udp_session.pconn) != 0 && errno != EINPROGRESS) {
			tlog(TLOG_ERROR, "proxy conn connect failed: %s", strerror(errno));
			_proxy_server_conn_put(session_conn);
			return -1;
		}

		session_conn->fd = -1;
		/* Note: We assigned `fd` of the conn to TCP FD. unique management. */

		session_conn->udp_session.pending_packet_head = _proxy_server_new_conn_buffer();
		if (session_conn->udp_session.pending_packet_head) {
			if ((size_t)len > sizeof(session_conn->udp_session.pending_packet_head->data)) {
				len = sizeof(session_conn->udp_session.pending_packet_head->data);
			}
			memcpy(session_conn->udp_session.pending_packet_head->data, buf, len);
			session_conn->udp_session.pending_packet_head->len = len;
			session_conn->udp_session.pending_packet_tail = session_conn->udp_session.pending_packet_head;
		}

		/* Start connection (add to epoll, add to global list) */
		_proxy_server_conn_start(session_conn);

		pthread_mutex_lock(&dns_proxy_server.conn_list_lock);
		list_add(&session_conn->list, &dns_proxy_server.conn_list);
		pthread_mutex_unlock(&dns_proxy_server.conn_list_lock);

	} else {
		/* Forward packet if connected */
		if (session_conn->udp_session.connected) {
			int ret = proxy_conn_sendto(session_conn->udp_session.pconn, buf, len, 0, (struct sockaddr *)&dst_addr,
										sizeof(dst_addr));
			if (ret < 0) {
				tlog(TLOG_ERROR, "Failed to forward packet to proxy: %s", strerror(errno));
			}
			_proxy_server_conn_touch(session_conn);
		} else {

			/* Queue pending packet */
			struct conn_buffer *new_buf = _proxy_server_new_conn_buffer();
			if (new_buf) {
				if ((size_t)len > sizeof(new_buf->data)) {
					len = sizeof(new_buf->data);
				}
				memcpy(new_buf->data, buf, len);
				new_buf->len = len;
				new_buf->next = NULL;

				if (session_conn->udp_session.pending_packet_tail) {
					session_conn->udp_session.pending_packet_tail->next = new_buf;
					session_conn->udp_session.pending_packet_tail = new_buf;
				} else {
					session_conn->udp_session.pending_packet_head = new_buf;
					session_conn->udp_session.pending_packet_tail = new_buf;
				}
			} else {
				tlog(TLOG_ERROR, "Failed to allocate buffer for pending packet");
			}
		}
	}

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
	} else if (conn->type == PROXY_SERVER_CONN_UDP_SESSION) {
		return _proxy_server_process_udp_session(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_SOCKS5_SERVER) {
		return _proxy_server_accept_socks5_conn(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_HTTP_SERVER) {
		return _proxy_server_accept_http_conn(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_FORWARD_SERVER) {
		return _proxy_server_accept_forward_conn(conn, event, now);
	} else if (conn->type == PROXY_SERVER_CONN_FORWARD_SERVER_UDP) {
		return _proxy_server_process_forward_udp(conn, event, now);
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
	struct proxy_server_conn *conns[PROXY_SERVER_MAX_EVENTS + 1];

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

		/* 1. Get references to ensure validity during the whole batch processing */
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct proxy_server_conn *conn = NULL;

			if (proxy_conn_is_epoll_event(event->data.ptr)) {
				conn = (struct proxy_server_conn *)proxy_conn_get_event_userdata(event->data.ptr);
			} else {
				conn = (struct proxy_server_conn *)event->data.ptr;
			}

			if (conn) {
				_proxy_server_conn_get(conn);
			}
			conns[i] = conn;
		}

		/* 2. Process events and release references */
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct proxy_server_conn *conn = conns[i];

			if (conn) {
				_proxy_server_process(conn, event, now);
				_proxy_server_conn_put(conn);
			} else {
				tlog(TLOG_WARN, "server info is invalid.");
			}
		}
	}

	return NULL;
}

static int _proxy_server_bind_socket_addr(struct addrinfo *gai, int tproxy)
{
	int fd = -1;
	int optval = 1;
	int yes = 1;
	const int priority = 6;
	const int ip_tos = IPTOS_LOWDELAY | IPTOS_RELIABILITY;

	fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, family = %d, type = %d, proto = %d, %s\n", gai->ai_family,
			 gai->ai_socktype, gai->ai_protocol, strerror(errno));
		return -1;
	}

	if (gai->ai_socktype == SOCK_STREAM) {
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
			tlog(TLOG_ERROR, "set socket opt failed.");
			goto errout;
		}
		/* enable TCP_FASTOPEN */
		setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	} else {
		/* UDP socket - enable address reuse for testing */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
			tlog(TLOG_WARN, "set SO_REUSEADDR for UDP failed, %s", strerror(errno));
		}
#ifdef SO_REUSEPORT
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) != 0) {
			tlog(TLOG_WARN, "set SO_REUSEPORT for UDP failed, %s", strerror(errno));
		}
#endif
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval));
	}

	if (gai->ai_family == AF_INET6) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
	}

	if (tproxy) {
		if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(yes)) != 0) {
			tlog(TLOG_ERROR, "set IP_TRANSPARENT failed (requires root privileges), %s", strerror(errno));
		}
		setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &yes, sizeof(yes));

		// Try IPv6 transparent
		setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &yes, sizeof(yes));
		setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &yes, sizeof(yes));
	}
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
	}

	if (bind(fd, gai->ai_addr, gai->ai_addrlen) != 0) {
		tlog(TLOG_ERROR, "bind failed, %s\n", strerror(errno));
		goto errout;
	}

	if (gai->ai_socktype == SOCK_STREAM) {
		if (listen(fd, 256) != 0) {
			tlog(TLOG_ERROR, "listen failed.\n");
			goto errout;
		}
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

static int _proxy_server_create_socket(const char *host_ip, int default_port, int type, int tproxy)
{
	struct addrinfo *gai = NULL;
	char port_str[16];
	char ip[MAX_IP_LEN];
	char host_ip_device[MAX_IP_LEN * 2];
	int port = 0;
	char *host = NULL;
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
		return -1;
	}

	int fd = _proxy_server_bind_socket_addr(gai, tproxy);

	if (fd >= 0 && ifname != NULL) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
			tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
			close(fd);
			fd = -1;
		}
	}

	freeaddrinfo(gai);

	return fd;
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

static int _proxy_server_create_tproxy_udp_socket(struct dns_tproxy_server_conf *t_conf)
{
	struct addrinfo *gai = NULL;
	struct addrinfo *p = NULL;
	char port_str[16];
	char ip[MAX_IP_LEN];
	int port = 0;
	char *host = NULL;

	if (parse_ip(t_conf->server, ip, &port) == 0) {
		host = ip;
	}

	if (port <= 0) {
		port = 1088;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);
	gai = _proxy_server_getaddr(host, atoi(port_str), SOCK_DGRAM, 0);
	if (gai == NULL) {
		tlog(TLOG_ERROR, "get address failed.");
		return -1;
	}

	for (p = gai; p != NULL; p = p->ai_next) {
		int fd_udp = _proxy_server_bind_socket_addr(p, 1);
		if (fd_udp < 0) {
			continue;
		}

		struct proxy_server_conn *t_conn_udp = _proxy_server_conn_new(PROXY_SERVER_CONN_TPROXY_SERVER_UDP);
		if (t_conn_udp == NULL) {
			close(fd_udp);
			continue;
		}

		t_conn_udp->fd = fd_udp;
		safe_strncpy(t_conn_udp->client.listener_name, t_conf->name, PROXY_NAME_LEN);
		safe_strncpy(t_conn_udp->client.proxy_name, t_conf->proxy_name, PROXY_NAME_LEN);
		safe_strncpy(t_conn_udp->client.group_name, t_conf->group_name, PROXY_NAME_LEN);

		list_add_tail(&t_conn_udp->list, &dns_proxy_server.listeners);
	}

	freeaddrinfo(gai);

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

		struct proxy_server_conn *t_conn = NULL;
		int fd = -1;

		tlog(TLOG_INFO, "create tproxy server for %s", t_conf->server);

		struct addrinfo *gai = NULL;
		struct addrinfo *p = NULL;
		char port_str[16];
		char ip[MAX_IP_LEN];
		int port = 0;
		char *host = NULL;

		if (parse_ip(t_conf->server, ip, &port) == 0) {
			host = ip;
		}

		if (port <= 0) {
			port = 1088;
		}

		snprintf(port_str, sizeof(port_str), "%d", port);
		gai = _proxy_server_getaddr(host, atoi(port_str), SOCK_STREAM, 0);
		if (gai == NULL) {
			tlog(TLOG_ERROR, "get address failed.");
			continue;
		}

		for (p = gai; p != NULL; p = p->ai_next) {
			fd = _proxy_server_bind_socket_addr(p, 1);
			if (fd < 0) {
				continue;
			}

			char ip_str[64] = {0};
			get_host_by_addr(ip_str, sizeof(ip_str), p->ai_addr);
			if (ip_str[0] == 0) {
				if (host) {
					snprintf(ip_str, sizeof(ip_str), "%s", host);
				} else {
					snprintf(ip_str, sizeof(ip_str), "unknown");
				}
			}

			tlog(TLOG_INFO, "tproxy TCP listener on %s:%d", ip_str, port);

			t_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_TPROXY_SERVER);
			if (t_conn == NULL) {
				close(fd);
				continue;
			}

			t_conn->fd = fd;
			safe_strncpy(t_conn->client.listener_name, t_conf->name, PROXY_NAME_LEN);
			safe_strncpy(t_conn->client.proxy_name, t_conf->proxy_name, PROXY_NAME_LEN);
			safe_strncpy(t_conn->client.group_name, t_conf->group_name, PROXY_NAME_LEN);
			t_conn->client.remote_dns = t_conf->remote_dns;
			t_conn->client.force_aaaa_soa = t_conf->force_aaaa_soa;
			list_add_tail(&t_conn->list, &dns_proxy_server.listeners);
		}

		freeaddrinfo(gai);

		// Create UDP socket if UDP support is enabled
		if (t_conf->udp_support) {
			_proxy_server_create_tproxy_udp_socket(t_conf);
		}
	}

	return 0;
}

static int _proxy_server_create_sniproxy_sockets(void)
{
	struct dns_sniproxy_server_conf *s_conf = NULL;
	size_t i;
	hash_for_each(dns_proxy_table.sniproxy, i, s_conf, node)
	{
		int fd = -1;
		struct proxy_server_conn *s_conn = NULL;

		tlog(TLOG_INFO, "create sniproxy server for %s", s_conf->server);

		fd = _proxy_server_create_socket(s_conf->server, 443, SOCK_STREAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create sniproxy socket for %s failed", s_conf->server);
			goto errout;
		}
		tlog(TLOG_INFO, "sniproxy TCP listener on %s", s_conf->server);

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
			tlog(TLOG_ERROR, "create sniproxy conn for %s failed", s_conf->server);
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

static int _proxy_server_create_socks5_sockets(void)
{
	struct dns_socks5_proxy_server_conf *s_conf = NULL;
	size_t i;
	hash_for_each(dns_proxy_table.socks5_proxy, i, s_conf, node)
	{
		int fd = -1;
		struct proxy_server_conn *s_conn = NULL;

		tlog(TLOG_INFO, "create socks5 proxy server for %s", s_conf->server);

		fd = _proxy_server_create_socket(s_conf->server, 1080, SOCK_STREAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create socks5 socket for %s failed", s_conf->server);
			goto errout;
		}
		tlog(TLOG_INFO, "socks5 TCP listener on %s", s_conf->server);

		unsigned int so_mark = s_conf->so_mark;
		if (so_mark > 0) {
			if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
				tlog(TLOG_ERROR, "set SO_MARK failed (requires root privileges), %s", strerror(errno));
				goto errout;
			}
		}

		s_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_SOCKS5_SERVER);
		if (s_conn == NULL) {
			close(fd);
			tlog(TLOG_ERROR, "create socks5 conn for %s failed", s_conf->server);
			goto errout;
		}

		s_conn->fd = fd;

		safe_strncpy(s_conn->client.listener_name, s_conf->name, PROXY_NAME_LEN);
		safe_strncpy(s_conn->client.proxy_name, s_conf->proxy_name, PROXY_NAME_LEN);
		safe_strncpy(s_conn->client.group_name, s_conf->group_name, PROXY_NAME_LEN);
		s_conn->client.remote_dns = s_conf->remote_dns;
		s_conn->client.force_aaaa_soa = s_conf->force_aaaa_soa;
		safe_strncpy(s_conn->client.user, s_conf->username, sizeof(s_conn->client.user));
		safe_strncpy(s_conn->client.pass, s_conf->password, sizeof(s_conn->client.pass));
		s_conn->client.channel = proxy_channel_server_new(fd, PROXY_SOCKS5);
		proxy_channel_set_server_auth(s_conn->client.channel, s_conn->client.user, s_conn->client.pass);

		list_add_tail(&s_conn->list, &dns_proxy_server.listeners);
	}
	return 0;
errout:
	return -1;
}

static int _proxy_server_create_http_sockets(void)
{
	struct dns_http_proxy_server_conf *h_conf = NULL;
	size_t i;
	hash_for_each(dns_proxy_table.http_proxy, i, h_conf, node)
	{
		int fd = -1;
		struct proxy_server_conn *h_conn = NULL;

		tlog(TLOG_INFO, "create http proxy server for %s", h_conf->server);

		fd = _proxy_server_create_socket(h_conf->server, 8080, SOCK_STREAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create http socket for %s failed", h_conf->server);
			goto errout;
		}
		tlog(TLOG_INFO, "http TCP listener on %s", h_conf->server);

		unsigned int so_mark = h_conf->so_mark;
		if (so_mark > 0) {
			if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
				tlog(TLOG_ERROR, "set SO_MARK failed (requires root privileges), %s", strerror(errno));
				goto errout;
			}
		}

		h_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_HTTP_SERVER);
		if (h_conn == NULL) {
			close(fd);
			tlog(TLOG_ERROR, "create http conn for %s failed", h_conf->server);
			goto errout;
		}

		h_conn->fd = fd;

		safe_strncpy(h_conn->client.listener_name, h_conf->name, PROXY_NAME_LEN);
		safe_strncpy(h_conn->client.proxy_name, h_conf->proxy_name, PROXY_NAME_LEN);
		safe_strncpy(h_conn->client.group_name, h_conf->group_name, PROXY_NAME_LEN);
		h_conn->client.remote_dns = h_conf->remote_dns;
		h_conn->client.force_aaaa_soa = h_conf->force_aaaa_soa;
		safe_strncpy(h_conn->client.user, h_conf->username, sizeof(h_conn->client.user));
		safe_strncpy(h_conn->client.pass, h_conf->password, sizeof(h_conn->client.pass));
		h_conn->client.channel = proxy_channel_server_new(fd, PROXY_HTTP);
		proxy_channel_set_server_auth(h_conn->client.channel, h_conn->client.user, h_conn->client.pass);

		list_add_tail(&h_conn->list, &dns_proxy_server.listeners);
	}
	return 0;
errout:
	return -1;
}

static int _proxy_server_create_forward_sockets(void)
{
	struct dns_forward_server_conf *f_conf = NULL;
	unsigned long i = 0;

	hash_for_each(dns_proxy_table.forward, i, f_conf, node)
	{
		int fd = -1;
		struct proxy_server_conn *f_conn = NULL;

		tlog(TLOG_INFO, "create forward-server for %s, target %s", f_conf->server, f_conf->target);

		// TCP Listener
		fd = _proxy_server_create_socket(f_conf->server, 0, SOCK_STREAM, 0);
		if (fd < 0) {
			tlog(TLOG_ERROR, "create forward-server tcp socket for %s failed", f_conf->server);
			goto errout;
		}
		tlog(TLOG_INFO, "forward TCP listener on %s", f_conf->server);

		if (f_conf->so_mark > 0) {
			if (setsockopt(fd, SOL_SOCKET, SO_MARK, &f_conf->so_mark, sizeof(f_conf->so_mark)) != 0) {
				tlog(TLOG_ERROR, "set SO_MARK failed, %s", strerror(errno));
				goto errout;
			}
		}

		f_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_FORWARD_SERVER);
		if (f_conn == NULL) {
			close(fd);
			goto errout;
		}
		f_conn->fd = fd;
		safe_strncpy(f_conn->client.listener_name, f_conf->name, PROXY_NAME_LEN);
		safe_strncpy(f_conn->client.proxy_name, f_conf->proxy_name, PROXY_NAME_LEN);
		safe_strncpy(f_conn->forward.target, f_conf->target, sizeof(f_conn->forward.target));
		safe_strncpy(f_conn->forward.proxy_name, f_conf->proxy_name, sizeof(f_conn->forward.proxy_name));

		list_add_tail(&f_conn->list, &dns_proxy_server.listeners);

		// UDP Listener
		if (f_conf->udp_support) {
			fd = _proxy_server_create_socket(f_conf->server, 0, SOCK_DGRAM, 0);
			if (fd < 0) {
				tlog(TLOG_ERROR, "create forward-server udp socket for %s failed", f_conf->server);
				goto errout;
			}
			tlog(TLOG_INFO, "forward UDP listener on %s", f_conf->server);

			if (f_conf->so_mark > 0) {
				if (setsockopt(fd, SOL_SOCKET, SO_MARK, &f_conf->so_mark, sizeof(f_conf->so_mark)) != 0) {
					tlog(TLOG_ERROR, "set SO_MARK failed, %s", strerror(errno));
					goto errout;
				}
			}

			f_conn = _proxy_server_conn_new(PROXY_SERVER_CONN_FORWARD_SERVER_UDP);
			if (f_conn == NULL) {
				close(fd);
				goto errout;
			}
			f_conn->fd = fd;
			safe_strncpy(f_conn->client.listener_name, f_conf->name, PROXY_NAME_LEN);
			safe_strncpy(f_conn->client.proxy_name, f_conf->proxy_name, PROXY_NAME_LEN);
			safe_strncpy(f_conn->forward.target, f_conf->target, sizeof(f_conn->forward.target));
			safe_strncpy(f_conn->forward.proxy_name, f_conf->proxy_name, sizeof(f_conn->forward.proxy_name));

			list_add_tail(&f_conn->list, &dns_proxy_server.listeners);
		}
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

	if (_proxy_server_create_socks5_sockets() != 0) {
		goto errout;
	}

	if (_proxy_server_create_http_sockets() != 0) {
		goto errout;
	}

	if (_proxy_server_create_forward_sockets() != 0) {
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

	safe_strncpy(proxy_server->proxy_name, PROXY_SERVER_PASS_THROUGH, PROXY_NAME_LEN);
	time(&proxy_server->last_alive);

	/* Add default proxy to global proxy list */
	memset(&proxy_default, 0, sizeof(proxy_default));
	proxy_default.type = PROXY_PASSTHROUGH;
	proxy_add(PROXY_SERVER_PASS_THROUGH, &proxy_default);

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
	tlog(TLOG_INFO, "proxy servers: tproxy %d, sni %d, socks5 %d, http %d, forward %d", dns_conf_tproxy_server_num(),
		 dns_conf_sniproxy_server_num(), dns_conf_socks5_proxy_server_num(), dns_conf_http_proxy_server_num(),
		 dns_conf_forward_server_num());

	if (dns_conf_tproxy_server_num() == 0 && dns_conf_sniproxy_server_num() == 0 &&
		dns_conf_socks5_proxy_server_num() == 0 && dns_conf_http_proxy_server_num() == 0 &&
		dns_conf_forward_server_num() == 0) {
		tlog(TLOG_INFO, "no proxy server configured, skip proxy server init.");
		return 0;
	}

	if (dns_conf_tproxy_server_num() > 0) {
		if (has_network_admin_cap() == 0) {
			tlog(TLOG_ERROR, "TPROXY requires CAP_NET_ADMIN capability, proxy server start failed.");
			tlog(TLOG_ERROR,
				 "Please run as root or use 'setcap cap_net_admin+ep <path_to_smartdns>' to grant the capability.");
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
	hash_init(dns_proxy_server.udp_sessions);
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
