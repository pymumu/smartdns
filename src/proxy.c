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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "smartdns/proxy.h"
#include "smartdns/dns_conf.h"
#include "smartdns/http_parse.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <time.h>

#define PROXY_SOCKS5_VERSION 0x05
#define PROXY_SOCKS5_NO_AUTH 0x00
#define PROXY_SOCKS5_AUTH_USER_PASS 0x02
#define PROXY_SOCKS5_AUTH_NONE 0xFF

#define PROXY_SOCKS5_TYPE_IPV4 0x01
#define PROXY_SOCKS5_TYPE_DOMAIN 0x03
#define PROXY_SOCKS5_TYPE_IPV6 0x04

#define PROXY_SOCKS5_CONNECT_TCP 0x01
#define PROXY_SOCKS5_CONNECT_UDP 0x03

#define PROXY_MAX_EVENTS 64
#define PROXY_MAX_HOSTNAME_LEN 256

typedef enum {
	PROXY_PHASE_INIT = 0,
	PROXY_PHASE_SOCKS5_INIT_ACK = 1,
	PROXY_PHASE_SOCKS5_AUTH = 2,
	PROXY_PHASE_SOCKS5_AUTH_ACK = 3,
	PROXY_PHASE_SOCKS5_REQ = 4,
	PROXY_PHASE_SOCKS5_REQ_ACK = 5,
	PROXY_PHASE_HTTP_INIT = 6,
	PROXY_PHASE_HTTP_AUTH = 7,
	PROXY_PHASE_HTTP_AUTH_ACK = 8,
	PROXY_PHASE_SERVER_INIT = 9,
	PROXY_PHASE_SERVER_SOCKS5_METHOD = 10,
	PROXY_PHASE_SERVER_SOCKS5_AUTH = 11,
	PROXY_PHASE_SERVER_SOCKS5_REQ = 12,
} PROXY_PHASE;

#define PROXY_ERROR_LOG_THROTTLE_SEC 60

#define PROXY_CHANNEL_MAGIC 0x50524F58 /* "PROX" */

#define PROXY_THROTTLED_ERROR_LOG(last_time, ...)                                                                      \
	do {                                                                                                               \
		time_t now = time(NULL);                                                                                       \
		if (now - (last_time) >= PROXY_ERROR_LOG_THROTTLE_SEC) {                                                       \
			tlog(TLOG_ERROR, __VA_ARGS__);                                                                             \
			(last_time) = now;                                                                                         \
		}                                                                                                              \
	} while (0)

#define PROXY_BUFFER_SIZE (1024 * 4)

struct proxy_conn_buffer {
	int len;
	uint8_t buffer[PROXY_BUFFER_SIZE];
};

/* Internal channel representing a single proxy connection */
struct proxy_channel {
	uint32_t magic; /* Magic number for identification */
	proxy_type_t type;
	PROXY_CONN_STATE state;
	PROXY_PHASE phase;
	char host[256];
	unsigned short port;
	int fd;
	int udp_fd;
	int is_udp;
	int non_block;
	int is_fallback;          /* Fallback channel flag */
	uint64_t connect_time_ms; /* Time to connect (for ranking) */
	struct sockaddr_storage udp_dest_addr;
	socklen_t udp_dest_addrlen;
	struct proxy_conn_buffer buffer;
	struct proxy_server_info *server_info;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int last_error;
	void *userdata;            /* User data from proxy_conn_ctl (e.g., server_info) */
	char server_user[64];      /* Server-side auth username */
	char server_pass[64];      /* Server-side auth password */
	struct proxy_conn *parent; /* Parent proxy_conn */
	struct list_head list;     /* Link in proxy_conn's channel_list */
};

/* External connection handle managing proxy group */
struct proxy_conn {
	char ifname[IFNAMSIZ];
	int so_mark;
	int tcp_fastopen;
	int keepalive_idle;
	int keepalive_intvl;
	int keepalive_cnt;
	char proxy_name[PROXY_NAME_LEN];
	char host[DNS_MAX_CNAME_LEN];
	unsigned short port;
	int is_udp;
	int non_block;

	struct list_head channel_list;        /* List of proxy_channel */
	struct proxy_channel *active_channel; /* Currently active channel */
	struct proxy_channel *best_channel;   /* Best performing channel (cached) */

	int channel_count;
	int connected_count;
	int fallback_count;

	pthread_mutex_t lock;
	void *userdata;
};

/* upstream server groups */
struct proxy_server_info {
	struct hlist_node node;
	char proxy_name[PROXY_NAME_LEN];
	struct sockaddr_storage server_addr;
	socklen_t server_addrlen;
	struct proxy_info info;
};

struct proxy_struct {
	int run;
	int epoll_fd;
	pthread_t tid;
	pthread_mutex_t proxy_lock;
	DECLARE_HASHTABLE(proxy_server, 4);
};

static struct proxy_struct proxy;
static int is_proxy_init;

static const char *proxy_socks5_status_code[] = {
	"success",
	"general SOCKS server failure",
	"connection not allowed by ruleset",
	"Network unreachable",
	"Host unreachable",
	"Connection refused",
	"TTL expired",
	"Command not supported",
	"Address type not supported",
};

/* Forward declarations for handshake functions */
static proxy_handshake_state _proxy_handshake_socks5(struct proxy_channel *channel);
static proxy_handshake_state _proxy_handshake_http(struct proxy_channel *channel);
static proxy_handshake_state _proxy_handshake_http_server(struct proxy_channel *channel);
static proxy_handshake_state _proxy_handshake_socks5_server(struct proxy_channel *channel);

/* get server group by name */
static struct proxy_server_info *_proxy_get_server_info(const char *proxy_name)
{
	unsigned long key;
	struct proxy_server_info *server_info = NULL;
	struct hlist_node *tmp = NULL;

	if (proxy_name == NULL) {
		return NULL;
	}

	key = hash_string(proxy_name);
	hash_for_each_possible_safe(proxy.proxy_server, server_info, tmp, node, key)
	{
		if (strncmp(server_info->proxy_name, proxy_name, PROXY_NAME_LEN) != 0) {
			continue;
		}

		return server_info;
	}

	return NULL;
}

static struct addrinfo *_proxy_getaddr(const char *host, int port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int ret = 0;
	char port_str[32];

	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;

	ret = getaddrinfo(host, port_str, &hints, &result);
	if (ret != 0) {
		tlog(TLOG_ERROR, "get addr info failed. %s\n", gai_strerror(ret));
		tlog(TLOG_ERROR, "host: %s, port: %d, type: %d, protocol: %d", host, port, type, protocol);
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

int proxy_add(const char *proxy_name, struct proxy_info *info)
{
	unsigned long key;
	char ip_str[PROXY_MAX_IPLEN];
	int port = 0;
	struct addrinfo *gai = NULL;
	struct proxy_server_info *server_info = _proxy_get_server_info(proxy_name);

	if (server_info) {
		return -1;
	}

	server_info = zalloc(1, sizeof(*server_info));
	if (server_info == NULL) {
		goto errout;
	}

	memcpy(&server_info->info, info, sizeof(struct proxy_info));

	if (info->type != PROXY_PASSTHROUGH) {
		if (parse_ip(info->server, ip_str, &port) != 0) {
			goto errout;
		}
		port = info->port;
		gai = _proxy_getaddr(info->server, port, SOCK_STREAM, 0);
		if (gai == NULL) {
			tlog(TLOG_WARN, "proxy_add: _proxy_getaddr failed for %s:%d", info->server, port);
			goto errout;
		}

		server_info->server_addrlen = gai->ai_addrlen;
		memcpy(&server_info->server_addr, gai->ai_addr, gai->ai_addrlen);
	}

	safe_strncpy(server_info->proxy_name, proxy_name, PROXY_NAME_LEN);
	key = hash_string(server_info->proxy_name);
	hash_add(proxy.proxy_server, &server_info->node, key);

	if (gai) {
		freeaddrinfo(gai);
	}
	return 0;
errout:
	if (server_info) {
		free(server_info);
		server_info = NULL;
	}

	if (gai) {
		freeaddrinfo(gai);
	}
	return -1;
}

static int _proxy_remove(struct proxy_server_info *server_info)
{
	hash_del(&server_info->node);
	free(server_info);

	return 0;
}

int proxy_remove(const char *proxy_name)
{
	struct proxy_server_info *server_info = _proxy_get_server_info(proxy_name);
	if (server_info == NULL) {
		return 0;
	}

	_proxy_remove(server_info);

	return 0;
}

static void _proxy_remove_all(void)
{
	struct proxy_server_info *server_info = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int i = 0;

	hash_for_each_safe(proxy.proxy_server, i, tmp, server_info, node)
	{
		_proxy_remove(server_info);
	}
}

static struct proxy_channel *_proxy_channel_new(struct proxy_server_info *server_info, const char *host, int port,
												int is_udp, int non_block, int is_fallback)
{
	struct proxy_channel *channel = NULL;
	struct addrinfo *gai = NULL;
	int fd = -1;

	if (is_udp == 1 && server_info->info.type != PROXY_SOCKS5 && server_info->info.type != PROXY_PASSTHROUGH) {
		tlog(TLOG_WARN, "only socks5 and passthrough support udp");
		goto errout;
	}

	if (server_info->info.type != PROXY_PASSTHROUGH) {
		if (server_info->server_addr.ss_family == 0) {
			tlog(TLOG_ERROR, "proxy server addr not set");
			goto errout;
		}
		fd = socket(server_info->server_addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	} else {
		const char *connect_host = host;
		int connect_port = port;
		if (server_info->info.server[0] != '\0' && strcmp(server_info->info.server, "0.0.0.0") != 0) {
			connect_host = server_info->info.server;
		}
		if (server_info->info.port > 0) {
			connect_port = server_info->info.port;
		}
		gai = _proxy_getaddr(connect_host, connect_port, is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
		if (gai == NULL) {
			goto errout;
		}
		fd = socket(gai->ai_family, gai->ai_socktype | SOCK_CLOEXEC, 0);
	}

	if (fd < 0) {
		goto errout;
	}

	channel = zalloc(1, sizeof(*channel));
	if (channel == NULL) {
		goto errout;
	}

	channel->magic = PROXY_CHANNEL_MAGIC;
	safe_strncpy(channel->host, host, DNS_MAX_CNAME_LEN);
	channel->port = port;
	channel->type = server_info->info.type;
	channel->state = PROXY_STATE_INIT;
	channel->phase = PROXY_PHASE_INIT;
	channel->server_info = server_info;
	channel->fd = fd;
	if (server_info->info.type != PROXY_PASSTHROUGH) {
		channel->addrlen = server_info->server_addrlen;
		memcpy(&channel->addr, &server_info->server_addr, server_info->server_addrlen);
	} else {
		channel->addrlen = gai->ai_addrlen;
		memcpy(&channel->addr, gai->ai_addr, gai->ai_addrlen);
	}
	channel->udp_fd = -1;
	channel->is_udp = is_udp;
	channel->non_block = non_block;
	channel->is_fallback = is_fallback;
	channel->connect_time_ms = 0;
	INIT_LIST_HEAD(&channel->list);

	if (non_block) {
		set_fd_nonblock(fd, 1);
	}

	if (gai) {
		freeaddrinfo(gai);
	}

	return channel;
errout:
	if (channel) {
		free(channel);
		channel = NULL;
	}

	if (fd >= 0) {
		close(fd);
	}

	if (gai) {
		freeaddrinfo(gai);
	}
	return NULL;
}

static void _proxy_channel_shutdown(struct proxy_channel *channel, int epoll_fd)
{
	if (channel == NULL) {
		return;
	}

	if (epoll_fd >= 0) {
		if (channel->fd >= 0 && channel->state != PROXY_STATE_INIT &&
			channel->state != PROXY_STATE_DISCONNECTED) {
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, channel->fd, NULL);
		}
		if (channel->udp_fd >= 0 && channel->state != PROXY_STATE_INIT &&
			channel->state != PROXY_STATE_DISCONNECTED) {
			epoll_ctl(epoll_fd, EPOLL_CTL_DEL, channel->udp_fd, NULL);
		}
	}

	if (channel->fd >= 0) {
		close(channel->fd);
		channel->fd = -1;
	}
	if (channel->udp_fd >= 0) {
		close(channel->udp_fd);
		channel->udp_fd = -1;
	}

	channel->state = PROXY_STATE_DISCONNECTED;
}

static void _proxy_channel_free(struct proxy_channel *channel)
{
	if (channel == NULL) {
		return;
	}

	/* Logic moved to shutdown to ensure consistency */
	_proxy_channel_shutdown(channel, -1);

	free(channel);
}

static int _proxy_channel_connect(struct proxy_channel *channel)
{
	if (channel == NULL) {
		return -1;
	}

	channel->state = PROXY_STATE_CONNECTING;
	if (channel->type == PROXY_PASSTHROUGH && channel->is_udp) {
		return 0;
	}
	int ret = connect(channel->fd, (struct sockaddr *)&channel->addr, channel->addrlen);
	char addr_str[128];
	get_host_by_addr(addr_str, sizeof(addr_str), (struct sockaddr *)&channel->addr);
	tlog(TLOG_DEBUG, "connect fd=%d addr=%s ret=%d errno=%d", channel->fd, addr_str, ret, errno);
	return ret;
}

static proxy_handshake_state _proxy_channel_handshake(struct proxy_channel *channel)
{
	if (channel == NULL) {
		return PROXY_HANDSHAKE_ERR;
	}

	if (channel->state == PROXY_STATE_CONNECTED) {
		return PROXY_HANDSHAKE_OK;
	}

	if (channel->state == PROXY_STATE_CONNECTING) {
		int err = 0;
		socklen_t len = sizeof(err);
		if (getsockopt(channel->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
			if (err != 0) {
				errno = err;
			}
			channel->last_error = err;
			tlog(TLOG_DEBUG, "proxy connect failed for fd %d, error %d: %s", channel->fd, err,
				 strerror(err));
			channel->state = PROXY_STATE_DISCONNECTED;
			return PROXY_HANDSHAKE_ERR;
		}

		if (channel->type == PROXY_PASSTHROUGH) {
			channel->state = PROXY_STATE_CONNECTED;
			return PROXY_HANDSHAKE_CONNECTED;
		}

		channel->state = PROXY_STATE_HANDSHAKING;
		channel->phase = PROXY_PHASE_INIT;
	}

	if (channel->state == PROXY_STATE_HANDSHAKING) {
		proxy_handshake_state ret = PROXY_HANDSHAKE_ERR;
		if (channel->parent != NULL) {
			if (channel->type == PROXY_SOCKS5) {
				ret = _proxy_handshake_socks5(channel);
			} else if (channel->type == PROXY_HTTP) {
				ret = _proxy_handshake_http(channel);
			}
		} else {
			if (channel->type == PROXY_SOCKS5) {
				ret = _proxy_handshake_socks5_server(channel);
			} else if (channel->type == PROXY_HTTP) {
				ret = _proxy_handshake_http_server(channel);
			}
		}

		if (ret == PROXY_HANDSHAKE_ERR) {
			channel->state = PROXY_STATE_DISCONNECTED;
		}
		return ret;
	}

	return PROXY_HANDSHAKE_ERR;
}

struct proxy_conn *proxy_conn_new(const char *proxy_name, const char *host, int port, int is_udp, int non_block)
{
	struct proxy_conn *proxy_conn = NULL;
	struct dns_proxy_names *proxy_names = NULL;
	struct dns_proxy_servers *proxy_server = NULL;
	struct proxy_server_info *server_info = NULL;
	struct proxy_channel *channel = NULL;
	int channel_count = 0;

	/* Get proxy group by name */
	if (proxy_name == NULL || proxy_name[0] == '\0' || strcmp(proxy_name, PROXY_SERVER_PASS_THROUGH) == 0) {
		/* Create single-channel direct/passthrough proxy_conn */
		proxy_conn = zalloc(1, sizeof(*proxy_conn));
		if (proxy_conn == NULL) {
			return NULL;
		}

		safe_strncpy(proxy_conn->proxy_name, PROXY_SERVER_PASS_THROUGH, PROXY_NAME_LEN);
		safe_strncpy(proxy_conn->host, host, DNS_MAX_CNAME_LEN);
		proxy_conn->port = port;
		proxy_conn->is_udp = is_udp;
		proxy_conn->non_block = non_block;
		INIT_LIST_HEAD(&proxy_conn->channel_list);
		pthread_mutex_init(&proxy_conn->lock, NULL);

		struct proxy_info info;
		memset(&info, 0, sizeof(info));
		info.type = PROXY_PASSTHROUGH;

		server_info = _proxy_get_server_info(PROXY_SERVER_PASS_THROUGH);
		if (server_info == NULL) {
			proxy_add(PROXY_SERVER_PASS_THROUGH, &info);
			server_info = _proxy_get_server_info(PROXY_SERVER_PASS_THROUGH);
		}

		channel = _proxy_channel_new(server_info, host, port, is_udp, non_block, 0);
		if (channel == NULL) {
			pthread_mutex_destroy(&proxy_conn->lock);
			free(proxy_conn);
			return NULL;
		}

		channel->parent = proxy_conn;
		list_add_tail(&channel->list, &proxy_conn->channel_list);
		proxy_conn->channel_count = 1;

		return proxy_conn;
	}

	proxy_names = dns_server_get_proxy_names(proxy_name);
	if (proxy_names == NULL) {
		/* Fallback to old single-server lookup for backward compatibility */
		server_info = _proxy_get_server_info(proxy_name);
		if (server_info == NULL) {
			tlog(TLOG_WARN, "proxy server %s not found", proxy_name);
			return NULL;
		}

		/* Create single-channel proxy_conn */
		proxy_conn = zalloc(1, sizeof(*proxy_conn));
		if (proxy_conn == NULL) {
			return NULL;
		}

		safe_strncpy(proxy_conn->proxy_name, proxy_name, PROXY_NAME_LEN);
		safe_strncpy(proxy_conn->host, host, DNS_MAX_CNAME_LEN);
		proxy_conn->port = port;
		proxy_conn->is_udp = is_udp;
		proxy_conn->non_block = non_block;
		INIT_LIST_HEAD(&proxy_conn->channel_list);
		proxy_conn->active_channel = NULL;
		proxy_conn->best_channel = NULL;
		proxy_conn->channel_count = 0;
		proxy_conn->connected_count = 0;
		proxy_conn->fallback_count = 0;
		pthread_mutex_init(&proxy_conn->lock, NULL);

		channel = _proxy_channel_new(server_info, host, port, is_udp, non_block, 0);
		if (channel == NULL) {
			pthread_mutex_destroy(&proxy_conn->lock);
			free(proxy_conn);
			return NULL;
		}

		channel->parent = proxy_conn;
		list_add_tail(&channel->list, &proxy_conn->channel_list);
		proxy_conn->channel_count = 1;

		return proxy_conn;
	}

	/* Create multi-channel proxy_conn for proxy group */
	proxy_conn = zalloc(1, sizeof(*proxy_conn));
	if (proxy_conn == NULL) {
		return NULL;
	}

	safe_strncpy(proxy_conn->proxy_name, proxy_name, PROXY_NAME_LEN);
	safe_strncpy(proxy_conn->host, host, DNS_MAX_CNAME_LEN);
	proxy_conn->port = port;
	proxy_conn->is_udp = is_udp;
	proxy_conn->non_block = non_block;
	INIT_LIST_HEAD(&proxy_conn->channel_list);
	proxy_conn->active_channel = NULL;
	proxy_conn->best_channel = NULL;
	proxy_conn->channel_count = 0;
	proxy_conn->connected_count = 0;
	proxy_conn->fallback_count = 0;
	pthread_mutex_init(&proxy_conn->lock, NULL);

	/* Create a channel for each proxy server in the group */
	list_for_each_entry(proxy_server, &proxy_names->server_list, list)
	{
		/* Find or create server_info for this proxy server */
		char server_key[PROXY_NAME_LEN + DNS_MAX_IPLEN];
		snprintf(server_key, sizeof(server_key), "%s_%s:%d", proxy_name, proxy_server->server, proxy_server->port);

		server_info = _proxy_get_server_info(server_key);
		if (server_info == NULL) {
			/* Create new server_info */
			struct proxy_info info;
			memset(&info, 0, sizeof(info));
			info.type = proxy_server->type;
			safe_strncpy(info.server, proxy_server->server, PROXY_MAX_IPLEN);
			info.port = proxy_server->port;
			safe_strncpy(info.username, proxy_server->username, PROXY_MAX_NAMELEN);
			safe_strncpy(info.password, proxy_server->password, PROXY_MAX_NAMELEN);

			if (proxy_add(server_key, &info) != 0) {
				tlog(TLOG_WARN, "failed to add proxy server %s", server_key);
				continue;
			}

			server_info = _proxy_get_server_info(server_key);
			if (server_info == NULL) {
				continue;
			}
		}

		channel = _proxy_channel_new(server_info, host, port, is_udp, non_block, proxy_server->fallback);
		if (channel == NULL) {
			tlog(TLOG_WARN, "failed to create channel for proxy %s", server_key);
			continue;
		}

		channel->parent = proxy_conn;
		list_add_tail(&channel->list, &proxy_conn->channel_list);
		channel_count++;

		if (proxy_server->fallback) {
			proxy_conn->fallback_count++;
		}
	}

	if (channel_count == 0) {
		tlog(TLOG_ERROR, "no channels created for proxy group %s", proxy_name);
		pthread_mutex_destroy(&proxy_conn->lock);
		free(proxy_conn);
		return NULL;
	}

	proxy_conn->channel_count = channel_count;

	tlog(TLOG_DEBUG, "created proxy_conn for group %s with %d channels (%d fallback)", proxy_name, channel_count,
		 proxy_conn->fallback_count);

	return proxy_conn;
}

void proxy_conn_free(struct proxy_conn *proxy_conn)
{
	struct proxy_channel *channel = NULL;
	struct proxy_channel *tmp = NULL;

	if (proxy_conn == NULL) {
		return;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	/* Free all channels */
	list_for_each_entry_safe(channel, tmp, &proxy_conn->channel_list, list)
	{
		list_del(&channel->list);
		channel->parent = NULL; /* Avoid recursive list_del if _proxy_channel_free were to try it */
		_proxy_channel_free(channel);
	}

	pthread_mutex_unlock(&proxy_conn->lock);
	pthread_mutex_destroy(&proxy_conn->lock);

	free(proxy_conn);
}

int proxy_conn_connect(struct proxy_conn *proxy_conn)
{
	struct proxy_channel *channel = NULL;
	int ret = 0;
	int connected_count = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	/* Initiate connections to all non-fallback channels */
	list_for_each_entry(channel, &proxy_conn->channel_list, list)
	{
		/* Skip fallback channels initially if we have primary ones */
		if (channel->is_fallback && proxy_conn->channel_count > proxy_conn->fallback_count) {
			continue;
		}

		ret = _proxy_channel_connect(channel);
		if (ret == 0 || (ret < 0 && (errno == EINPROGRESS || errno == EAGAIN))) {
			/* Connection initiated successfully (or in progress for non-blocking) */
			connected_count++;
		} else {
			tlog(TLOG_DEBUG, "failed to connect channel for proxy %s: %s", proxy_conn->proxy_name, strerror(errno));
		}
	}

	pthread_mutex_unlock(&proxy_conn->lock);

	if (connected_count == 0) {
		tlog(TLOG_WARN, "no channels connected for proxy %s", proxy_conn->proxy_name);
		return -1;
	}

	return 0;
}

static int _proxy_handshake_socks5_create_udp_fd(struct proxy_channel *channel)
{
	int ret = 0;
	char *gai_host = NULL;
	int udp_fd = -1;
	struct addrinfo *gai = NULL;

	switch (channel->udp_dest_addr.ss_family) {
	case AF_INET:
		gai_host = "0.0.0.0";
		break;
	case AF_INET6:
		gai_host = "::";
		break;
	default:
		goto errout;
		break;
	}

	gai = _proxy_getaddr(gai_host, 0, SOCK_DGRAM, 0);
	udp_fd = socket(gai->ai_family, gai->ai_socktype | SOCK_CLOEXEC, 0);
	if (udp_fd < 0) {
		goto errout;
	}

	ret = bind(udp_fd, gai->ai_addr, gai->ai_addrlen);
	if (ret < 0) {
		goto errout;
	}

	if (channel->non_block) {
		set_fd_nonblock(udp_fd, 1);
	}

	if (channel->parent) {
		if (channel->parent->ifname[0] != '\0') {
			struct ifreq ifr;
			memset(&ifr, 0, sizeof(struct ifreq));
			safe_strncpy(ifr.ifr_name, channel->parent->ifname, sizeof(ifr.ifr_name));
			setsockopt(udp_fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq));
		}
		if (channel->parent->so_mark != 0) {
			setsockopt(udp_fd, SOL_SOCKET, SO_MARK, &channel->parent->so_mark, sizeof(channel->parent->so_mark));
		}
	}

	freeaddrinfo(gai);
	return udp_fd;
errout:

	if (udp_fd >= 0) {
		close(udp_fd);
	}

	if (gai) {
		freeaddrinfo(gai);
	}

	return -1;
}

static int _proxy_handshake_socks5_connect_udp(struct proxy_channel *channel)
{
	int udp_fd = -1;

	if (channel->is_udp == 0) {
		return 0;
	}

	if (channel->udp_fd < 0) {
		udp_fd = _proxy_handshake_socks5_create_udp_fd(channel);
		if (udp_fd < 0) {
			return -1;
		}

		channel->udp_fd = udp_fd;
	}

	return connect(channel->udp_fd, (struct sockaddr *)&channel->udp_dest_addr, channel->udp_dest_addrlen);
}

static proxy_handshake_state _proxy_handshake_socks5_reply_connect_addr(struct proxy_channel *channel)
{
	char buff[DNS_MAX_CNAME_LEN * 2];
	int len = 0;
	memset(buff, 0, sizeof(buff));
	struct sockaddr_storage addr;
	char *ptr = NULL;
	socklen_t addr_len = sizeof(addr);

	buff[0] = PROXY_SOCKS5_VERSION;
	if (channel->is_udp) {
		buff[1] = PROXY_SOCKS5_CONNECT_UDP;
	} else {
		buff[1] = PROXY_SOCKS5_CONNECT_TCP;
	}

	buff[2] = 0x0;
	ptr = buff + 3;
	if (!check_is_ipaddr(channel->host)) {
		*ptr = PROXY_SOCKS5_TYPE_DOMAIN;
		ptr++;

		int domainlen = strnlen(channel->host, DNS_MAX_CNAME_LEN);
		*ptr = domainlen;
		ptr++;
		memcpy(ptr, channel->host, domainlen);
		ptr += domainlen;
	} else {
		if (channel->is_udp) {
			memset(&addr, 0, channel->server_info->server_addrlen);
			addr_len = channel->server_info->server_addrlen;
			addr.ss_family = channel->server_info->server_addr.ss_family;
		} else {
			getaddr_by_host(channel->host, (struct sockaddr *)&addr, &addr_len);
		}

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)&addr;
			*ptr = PROXY_SOCKS5_TYPE_IPV4;
			ptr++;
			memcpy(ptr, &addr_in->sin_addr.s_addr, 4);
			ptr += 4;
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
				*ptr = PROXY_SOCKS5_TYPE_IPV4;
				ptr++;
				memcpy(ptr, addr_in6->sin6_addr.s6_addr + 12, 4);
				ptr += 4;
			} else {
				*ptr = PROXY_SOCKS5_TYPE_IPV6;
				ptr++;
				memcpy(ptr, addr_in6->sin6_addr.s6_addr, 16);
				ptr += 16;
			}
		} break;
		default:
			return PROXY_HANDSHAKE_ERR;
		}
	}
	*((short *)(ptr)) = htons(channel->port);
	ptr += 2;

	len = send(channel->fd, buff, ptr - buff, MSG_NOSIGNAL);
	if (len != ptr - buff) {
		tlog(TLOG_ERROR, "Send proxy request failed.");
		return PROXY_HANDSHAKE_ERR;
	}
	channel->phase = PROXY_PHASE_SOCKS5_REQ_ACK;
	return PROXY_HANDSHAKE_WANT_READ;
}

static proxy_handshake_state _proxy_handshake_socks5_send_auth(struct proxy_channel *channel)
{
	char buff[DNS_MAX_CNAME_LEN * 2];
	int len = 0;
	int offset = 0;
	memset(buff, 0, sizeof(buff));

	buff[0] = 0x1;
	buff[1] = strnlen(channel->server_info->info.username, PROXY_MAX_NAMELEN);
	safe_strncpy(buff + 2, channel->server_info->info.username, buff[1] + 1);
	offset = buff[1] + 2;
	buff[offset] = strnlen(channel->server_info->info.password, PROXY_MAX_NAMELEN);
	safe_strncpy(buff + offset + 1, channel->server_info->info.password, buff[offset] + 1);
	offset += buff[offset] + 1;
	len = send(channel->fd, buff, offset, MSG_NOSIGNAL);
	if (len != offset) {
		tlog(TLOG_ERROR, "send auth failed, len: %d, %s", len, strerror(errno));
		return PROXY_HANDSHAKE_ERR;
	}

	channel->phase = PROXY_PHASE_SOCKS5_AUTH_ACK;
	return PROXY_HANDSHAKE_WANT_READ;
}

static proxy_handshake_state _proxy_handshake_socks5(struct proxy_channel *channel)
{
	int len = 0;
	char buff[DNS_MAX_CNAME_LEN * 2];
	static time_t last_error_log_time = 0;

	memset(buff, 0, sizeof(buff));

	if (channel == NULL) {
		return PROXY_HANDSHAKE_ERR;
	}

	if (channel->fd < 0) {
		return PROXY_HANDSHAKE_ERR;
	}

	switch (channel->phase) {
	case PROXY_PHASE_INIT: {
		buff[0] = PROXY_SOCKS5_VERSION;
		buff[1] = 0x2; // 2 auth methods
		buff[2] = PROXY_SOCKS5_NO_AUTH;
		buff[3] = PROXY_SOCKS5_AUTH_USER_PASS;
		len = send(channel->fd, buff, 4, MSG_NOSIGNAL);
		if (len != 4) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN) {
				return PROXY_HANDSHAKE_WANT_WRITE;
			}
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "connect socks5 server %s failed, %s",
									  channel->server_info->proxy_name, strerror(errno));
			return PROXY_HANDSHAKE_ERR;
		}

		channel->phase = PROXY_PHASE_SOCKS5_INIT_ACK;
		return PROXY_HANDSHAKE_WANT_READ;
	} break;
	case PROXY_PHASE_SOCKS5_INIT_ACK:
		len = recv(channel->fd, channel->buffer.buffer + channel->buffer.len, sizeof(channel->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "recv socks5 init ack from %s failed, %s",
									  channel->server_info->proxy_name, strerror(errno));
			return PROXY_HANDSHAKE_ERR;
		}

		channel->buffer.len += len;
		if (channel->buffer.len < 2) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		if (channel->buffer.len > 2) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "recv socks5 init ack from %s failed",
									  channel->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		channel->buffer.len = 0;

		if (channel->buffer.buffer[0] != PROXY_SOCKS5_VERSION) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s not support socks5",
									  channel->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		if ((unsigned char)channel->buffer.buffer[1] == PROXY_SOCKS5_AUTH_NONE) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s not support auth methods",
									  channel->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		tlog(TLOG_DEBUG, "server %s select auth method is %d", channel->server_info->proxy_name,
			 channel->buffer.buffer[1]);
		if (channel->buffer.buffer[1] == PROXY_SOCKS5_AUTH_USER_PASS) {
			channel->phase = PROXY_PHASE_SOCKS5_AUTH_ACK;
			return _proxy_handshake_socks5_send_auth(channel);
		}

		if (channel->buffer.buffer[1] == PROXY_SOCKS5_NO_AUTH) {
			channel->phase = PROXY_PHASE_SOCKS5_REQ_ACK;
			return _proxy_handshake_socks5_reply_connect_addr(channel);
		}

		PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s select invalid auth method %d",
								  channel->server_info->proxy_name, channel->buffer.buffer[1]);
		return PROXY_HANDSHAKE_ERR;
		break;
	case PROXY_PHASE_SOCKS5_AUTH_ACK:
		len = recv(channel->fd, channel->buffer.buffer + channel->buffer.len, sizeof(channel->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "recv socks5 auth ack from %s failed, %s",
									  channel->server_info->proxy_name, strerror(errno));
			return PROXY_HANDSHAKE_ERR;
		}

		channel->buffer.len += len;
		if (channel->buffer.len < 2) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		if (channel->buffer.len != 2) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "recv socks5 auth ack from %s failed",
									  channel->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		channel->buffer.len = 0;

		if (channel->buffer.buffer[0] != 0x1) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s not support socks5",
									  channel->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		if (channel->buffer.buffer[1] != 0x0) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time,
									  "server %s auth failed, incorrect user or password, code: %d",
									  channel->server_info->proxy_name, channel->buffer.buffer[1]);
			return PROXY_HANDSHAKE_ERR;
		}

		tlog(TLOG_DEBUG, "server %s auth success", channel->server_info->proxy_name);
		channel->phase = PROXY_PHASE_SOCKS5_REQ_ACK;
		return _proxy_handshake_socks5_reply_connect_addr(channel);
	case PROXY_PHASE_SOCKS5_REQ_ACK: {
		unsigned char addr[16];
		unsigned short port = 0;
		int use_dest_ip = 0;
		unsigned char *recv_buff = NULL;

		int addr_len = 0;
		len = recv(channel->fd, channel->buffer.buffer + channel->buffer.len, sizeof(channel->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			if (len == 0) {
				PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s closed connection",
										  channel->server_info->proxy_name);
			} else {
				PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "recv socks5 connect ack from %s failed, %s",
										  channel->server_info->proxy_name, strerror(errno));
			}

			return PROXY_HANDSHAKE_ERR;
		}

		channel->buffer.len += len;
		if (channel->buffer.len < 10) {
			return PROXY_HANDSHAKE_WANT_READ;
		}
		recv_buff = channel->buffer.buffer;

		if (recv_buff[0] != PROXY_SOCKS5_VERSION) {
			PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s not support socks5",
									  channel->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		if (recv_buff[1] != 0) {
			channel->last_error = recv_buff[1];
			if (recv_buff[1] <= (sizeof(proxy_socks5_status_code) / sizeof(proxy_socks5_status_code[0]))) {
				PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s reply failed, error-code: %s",
										  channel->server_info->proxy_name,
										  proxy_socks5_status_code[(int)recv_buff[1]]);
			} else {
				PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "server %s reply failed, error-code: %x",
										  channel->server_info->proxy_name, recv_buff[1]);
			}
			return PROXY_HANDSHAKE_ERR;
		}

		switch (recv_buff[3]) {
		case PROXY_SOCKS5_TYPE_IPV4: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)&channel->udp_dest_addr;
			channel->udp_dest_addrlen = sizeof(struct sockaddr_in);
			if (channel->buffer.len < 10) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			addr_len = 4;
			memcpy(addr, recv_buff + 4, addr_len);
			port = ntohs(*((short *)(recv_buff + 4 + addr_len)));
			addr_in->sin_family = AF_INET;
			memcpy(&addr_in->sin_addr.s_addr, recv_buff + 4, 4);
			memcpy(&addr_in->sin_port, recv_buff + 8, 2);
			if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0) {
				use_dest_ip = 1;
			}

			tlog(TLOG_DEBUG, "server %s proxy dest: %d.%d.%d.%d:%d\n", channel->server_info->proxy_name, addr[0],
				 addr[1], addr[2], addr[3], port);
		} break;
		case PROXY_SOCKS5_TYPE_IPV6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&channel->udp_dest_addr;
			channel->udp_dest_addrlen = sizeof(struct sockaddr_in6);
			if (channel->buffer.len < 22) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			addr_len = 16;
			memcpy(addr, recv_buff + 4, addr_len);
			port = ntohs(*((short *)(recv_buff + 4 + addr_len)));
			addr_in6->sin6_family = AF_INET6;
			memcpy(addr_in6->sin6_addr.s6_addr, recv_buff + 4, 16);
			memcpy(&addr_in6->sin6_port, recv_buff + 20, 2);

			if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 &&
				addr[6] == 0 && addr[7] == 0 && addr[8] == 0 && addr[9] == 0 && addr[10] == 0 && addr[11] == 0 &&
				addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 0) {
				use_dest_ip = 1;
			}

			tlog(TLOG_DEBUG, "server %s proxy dest: [%x:%x:%x:%x:%x:%x:%x:%x]:%d\n", channel->server_info->proxy_name,
				 ntohs(*((short *)addr)), ntohs(*((short *)(addr + 2))), ntohs(*((short *)(addr + 4))),
				 ntohs(*((short *)(addr + 6))), ntohs(*((short *)(addr + 8))), ntohs(*((short *)(addr + 10))),
				 ntohs(*((short *)(addr + 12))), ntohs(*((short *)(addr + 14))), port);
		} break;
		default:
			return PROXY_HANDSHAKE_ERR;
		}

		if (use_dest_ip && channel->is_udp) {
			memcpy(&channel->udp_dest_addr, &channel->server_info->server_addr, channel->server_info->server_addrlen);
			channel->udp_dest_addrlen = channel->server_info->server_addrlen;
			switch (channel->udp_dest_addr.ss_family) {
			case AF_INET: {
				struct sockaddr_in *addr_in = NULL;
				addr_in = (struct sockaddr_in *)&channel->udp_dest_addr;
				addr_in->sin_port = *((short *)(recv_buff + 4 + addr_len));
			} break;
			case AF_INET6: {
				struct sockaddr_in6 *addr_in6 = NULL;
				addr_in6 = (struct sockaddr_in6 *)&channel->udp_dest_addr;
				addr_in6->sin6_port = *((short *)(recv_buff + 4 + addr_len));
			} break;
			default:
				return PROXY_HANDSHAKE_ERR;
				break;
			}
		}

		if (_proxy_handshake_socks5_connect_udp(channel) != 0) {
			return PROXY_HANDSHAKE_ERR;
		}

		int consumed = 4 + addr_len + 2;
		if (channel->buffer.len > consumed) {
			memmove(channel->buffer.buffer, channel->buffer.buffer + consumed, channel->buffer.len - consumed);
			channel->buffer.len -= consumed;
		} else {
			channel->buffer.len = 0;
		}

		tlog(TLOG_DEBUG, "success connect to socks5 proxy server %s, type: %s", channel->server_info->proxy_name,
			 channel->is_udp ? "udp" : "tcp");
		channel->state = PROXY_STATE_CONNECTED;
		return PROXY_HANDSHAKE_OK;
	} break;
	default:
		PROXY_THROTTLED_ERROR_LOG(last_error_log_time, "client socks5 phase %d is invalid", channel->phase);
		return PROXY_HANDSHAKE_ERR;
	}

	return PROXY_HANDSHAKE_ERR;
}

static proxy_handshake_state _proxy_handshake_http(struct proxy_channel *channel)
{
	int len = 0;
	proxy_handshake_state ret = PROXY_HANDSHAKE_ERR;
	char buff[4096];
	struct http_head *http_head = NULL;

	if (channel == NULL) {
		return PROXY_HANDSHAKE_ERR;
	}

	if (channel->fd < 0) {
		return PROXY_HANDSHAKE_ERR;
	}

	switch (channel->phase) {
	case PROXY_PHASE_INIT: {
		char connecthost[DNS_MAX_CNAME_LEN * 2];
		struct sockaddr_storage addr;

		socklen_t addr_len = sizeof(addr);
		getaddr_by_host(channel->host, (struct sockaddr *)&addr, &addr_len);

		if (!check_is_ipaddr(channel->host)) {
			snprintf(connecthost, sizeof(connecthost), "%s:%d", channel->host, channel->port);
		} else {
			struct sockaddr_in *addr_in;
			addr_in = (struct sockaddr_in *)&addr;
			unsigned char *paddr = (unsigned char *)&addr_in->sin_addr.s_addr;
			snprintf(connecthost, sizeof(connecthost), "%d.%d.%d.%d:%d", paddr[0], paddr[1], paddr[2], paddr[3],
					 channel->port);
		}

		int msglen = 0;

		if (channel->server_info->info.username[0] == '\0') {
			msglen = snprintf(buff, sizeof(buff),
							  "CONNECT %s HTTP/1.1\r\n"
							  "Host: %s\r\n"
							  "Proxy-Connection: Keep-Alive\r\n\r\n",
							  connecthost, connecthost);
		} else {
			char auth[256];
			char base64_auth[256 * 2];
			snprintf(auth, sizeof(auth), "%s:%s", channel->server_info->info.username,
					 channel->server_info->info.password);
			SSL_base64_encode(auth, strlen(auth), base64_auth);

			msglen = snprintf(buff, sizeof(buff),
							  "CONNECT %s HTTP/1.1\r\n"
							  "Host: %s\r\n"
							  "Proxy-Authorization: Basic %s\r\n"
							  "Proxy-Connection: Keep-Alive\r\n\r\n",
							  connecthost, connecthost, base64_auth);
		}

		len = send(channel->fd, buff, msglen, MSG_NOSIGNAL);
		if (len != msglen) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN) {
				return PROXY_HANDSHAKE_WANT_WRITE;
			}
			tlog(TLOG_ERROR, "connect to https proxy server %s failed, %s", channel->server_info->proxy_name,
				 strerror(errno));
			goto out;
		}

		channel->phase = PROXY_PHASE_HTTP_AUTH_ACK;
		ret = PROXY_HANDSHAKE_WANT_READ;
		goto out;
	} break;
	case PROXY_PHASE_HTTP_AUTH_ACK: {
		http_head = http_head_init(4096, HTTP_VERSION_1_1);
		if (http_head == NULL) {
			goto out;
		}

		len = recv(channel->fd, channel->buffer.buffer + channel->buffer.len, sizeof(channel->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = PROXY_HANDSHAKE_WANT_READ;
				goto out;
			}

			if (len == 0) {
				tlog(TLOG_ERROR, "remote server %s closed.", channel->server_info->proxy_name);
			} else {
				tlog(TLOG_ERROR, "recv from %s failed, %s", channel->server_info->proxy_name, strerror(errno));
			}
			goto out;
		}
		channel->buffer.len += len;

		len = http_head_parse(http_head, channel->buffer.buffer, channel->buffer.len);
		if (len < 0) {
			if (len == -1) {
				ret = PROXY_HANDSHAKE_WANT_READ;
				goto out;
			}

			tlog(TLOG_DEBUG, "remote server %s not supported.", channel->server_info->proxy_name);
			goto out;
		}

		if (http_head_get_httpcode(http_head) != 200) {
			channel->last_error = http_head_get_httpcode(http_head);
			tlog(TLOG_WARN, "http server %s query failed, server return http code : %d, %s",
				 channel->server_info->proxy_name, http_head_get_httpcode(http_head),
				 http_head_get_httpcode_msg(http_head));
			goto out;
		}

		channel->buffer.len -= len;
		if (channel->buffer.len > 0) {
			memmove(channel->buffer.buffer, channel->buffer.buffer + len, channel->buffer.len);
		}

		if (channel->buffer.len < 0) {
			channel->buffer.len = 0;
		}
		tlog(TLOG_DEBUG, "successfully connect to target: %s:%d", channel->host, channel->port);
		channel->state = PROXY_STATE_CONNECTED;
		return PROXY_HANDSHAKE_OK;
	} break;
	default:
		goto out;
		break;
	}

out:
	if (http_head) {
		http_head_destroy(http_head);
	}

	return ret;
}

static void _proxy_channel_handshake_group_success(struct proxy_channel *channel, int epoll_fd)
{
	struct proxy_conn *proxy_conn = channel->parent;
	struct proxy_channel *other, *n;

	if (proxy_conn->active_channel == NULL) {
		proxy_conn->active_channel = channel;
		/* Clean up other connecting channels */
		list_for_each_entry_safe(other, n, &proxy_conn->channel_list, list)
		{
			if (other != channel) {
				_proxy_channel_shutdown(other, epoll_fd);
			}
		}
		tlog(TLOG_DEBUG, "proxy %s: selected best channel via %s", proxy_conn->proxy_name,
			 channel->server_info->proxy_name);
	} else if (proxy_conn->active_channel != channel) {
		/* Lost the race */
		_proxy_channel_shutdown(channel, epoll_fd);
	}
}

static int _proxy_channel_handshake_group_fail(struct proxy_channel *channel, int epoll_fd)
{
	struct proxy_conn *proxy_conn = channel->parent;
	struct proxy_channel *other = NULL;
	int viable = 0;
	int has_untried_fallback = 0;

	tlog(TLOG_DEBUG, "proxy %s: channel failed via %s", proxy_conn->proxy_name,
		 channel->server_info ? channel->server_info->proxy_name : "unknown");

	_proxy_channel_shutdown(channel, epoll_fd);

	/* Check if any other primary channel is still viable or if we should trigger fallback */
	list_for_each_entry(other, &proxy_conn->channel_list, list)
	{
		if (other->state == PROXY_STATE_CONNECTED ||
			(other->fd >= 0 && other->state >= PROXY_STATE_CONNECTING)) {
			viable = 1;
		}
		if (other->is_fallback && other->fd >= 0 && other->state == PROXY_STATE_INIT) {
			has_untried_fallback = 1;
		}
	}

	if (!viable && has_untried_fallback) {
		list_for_each_entry(other, &proxy_conn->channel_list, list)
		{
			if (other->is_fallback && other->fd >= 0 && other->state == PROXY_STATE_INIT) {
				tlog(TLOG_DEBUG, "proxy %s: activating fallback channel %s", proxy_conn->proxy_name,
					 other->server_info->proxy_name);
				_proxy_channel_connect(other);
				viable = 1;
			}
		}
	}

	return viable;
}

proxy_handshake_state proxy_channel_handshake(struct proxy_channel *channel, int epoll_fd)
{
	if (channel == NULL || channel->magic != PROXY_CHANNEL_MAGIC) {
		return PROXY_HANDSHAKE_ERR;
	}

	if (channel->parent == NULL) {
		/* Independent/Server channel: just perform handshake */
		proxy_handshake_state ret = _proxy_channel_handshake(channel);
		if (ret == PROXY_HANDSHAKE_CONNECTED) {
			ret = PROXY_HANDSHAKE_OK;
		}

		/* If UDP associate, switch to UDP FD for server side too if epoll_fd is provided */
		if (ret == PROXY_HANDSHAKE_OK && channel->udp_fd >= 0 && epoll_fd >= 0) {
			struct epoll_event ev = {0};
			ev.events = EPOLLIN;
			ev.data.ptr = channel;
			if (channel->fd >= 0) {
				epoll_ctl(epoll_fd, EPOLL_CTL_DEL, channel->fd, NULL);
			}
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, channel->udp_fd, &ev) != 0) {
				tlog(TLOG_ERROR, "proxy_channel_handshake (server): failed to add UDP FD to epoll, %s", strerror(errno));
				return PROXY_HANDSHAKE_ERR;
			}
		}
		
		return ret;
	}

	/* Client side channel with group/race management */
	struct proxy_conn *proxy_conn = channel->parent;
	proxy_handshake_state ret = PROXY_HANDSHAKE_ERR;

	pthread_mutex_lock(&proxy_conn->lock);

	/* If this channel is already connected, check if it's the active one */
	if (channel->state == PROXY_STATE_CONNECTED) {
		if (proxy_conn->active_channel == channel) {
			pthread_mutex_unlock(&proxy_conn->lock);
			return PROXY_HANDSHAKE_OK;
		}
		/* Lost the race */
		pthread_mutex_unlock(&proxy_conn->lock);
		return PROXY_HANDSHAKE_ERR;
	}

	ret = _proxy_channel_handshake(channel);

	if (ret == PROXY_HANDSHAKE_CONNECTED || ret == PROXY_HANDSHAKE_OK) {
		if (ret == PROXY_HANDSHAKE_CONNECTED) {
			channel->connect_time_ms = get_tick_count();
		}

		/* If UDP associate, switch to UDP FD */
		if (channel->udp_fd >= 0 && epoll_fd >= 0) {
			struct epoll_event ev = {0};
			ev.events = EPOLLIN;
			ev.data.ptr = channel;
			/* Explicitly remove TCP FD from epoll */
			if (channel->fd >= 0) {
				epoll_ctl(epoll_fd, EPOLL_CTL_DEL, channel->fd, NULL);
			}
			/* Add UDP FD to epoll */
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, channel->udp_fd, &ev) != 0) {
				tlog(TLOG_ERROR, "proxy_channel_handshake: failed to add UDP FD to epoll, %s", strerror(errno));
				pthread_mutex_unlock(&proxy_conn->lock);
				return PROXY_HANDSHAKE_ERR;
			}
		}

		_proxy_channel_handshake_group_success(channel, epoll_fd);

		if (proxy_conn->active_channel != channel) {
			pthread_mutex_unlock(&proxy_conn->lock);
			return PROXY_HANDSHAKE_ERR;
		}

		ret = PROXY_HANDSHAKE_CONNECTED;
	} else if (ret == PROXY_HANDSHAKE_ERR) {
		if (_proxy_channel_handshake_group_fail(channel, epoll_fd)) {
			pthread_mutex_unlock(&proxy_conn->lock);
			return PROXY_HANDSHAKE_WANT_WRITE;
		}
	}

	pthread_mutex_unlock(&proxy_conn->lock);
	return ret;
}

/* Internal channel I/O helpers */

static int proxy_channel_sendto(struct proxy_channel *channel, const void *buf, size_t len, int flags,
								const struct sockaddr *dest_addr, socklen_t addrlen)
{
	char buffer[PROXY_BUFFER_SIZE];
	int buffer_len = 0;
	int ret = 0;

	if (channel == NULL || channel->udp_fd < 0) {
		errno = ENOTCONN;
		return -1;
	}

	if (channel->state != PROXY_STATE_CONNECTED) {
		errno = EAGAIN;
		return -1;
	}

	if (channel->type == PROXY_SOCKS5) {
		/* Build SOCKS5 UDP header */
		buffer[0] = 0x00;
		buffer[1] = 0x00;
		buffer[2] = 0x00;
		buffer_len += 3;

		switch (dest_addr->sa_family) {
		case AF_INET:
			buffer[3] = PROXY_SOCKS5_TYPE_IPV4;
			memcpy(buffer + 4, &((struct sockaddr_in *)dest_addr)->sin_addr.s_addr, 4);
			memcpy(buffer + 8, &((struct sockaddr_in *)dest_addr)->sin_port, 2);
			buffer_len += 7;
			break;
		case AF_INET6:
			buffer[3] = PROXY_SOCKS5_TYPE_IPV6;
			memcpy(buffer + 4, &((struct sockaddr_in6 *)dest_addr)->sin6_addr.s6_addr, 16);
			memcpy(buffer + 20, &((struct sockaddr_in6 *)dest_addr)->sin6_port, 2);
			buffer_len += 19;
			break;
		default:
			errno = EAFNOSUPPORT;
			return -1;
		}

		if (sizeof(buffer) - buffer_len <= len) {
			errno = ENOSPC;
			return -1;
		}

		memcpy(buffer + buffer_len, buf, len);
		buffer_len += len;
	} else {
		if (sizeof(buffer) <= len) {
			errno = ENOSPC;
			return -1;
		}
		memcpy(buffer, buf, len);
		buffer_len = len;
	}

	ret = sendto(channel->udp_fd, buffer, buffer_len, MSG_NOSIGNAL, (struct sockaddr *)&channel->udp_dest_addr,
				 channel->udp_dest_addrlen);
	if (ret != buffer_len) {
		return -1;
	}

	return len;
}

static int proxy_channel_recvfrom(struct proxy_channel *channel, void *buf, size_t len, int flags,
								  struct sockaddr *src_addr, socklen_t *addrlen)
{
	char buffer[PROXY_BUFFER_SIZE];
	int buffer_len = 0;
	int ret = 0;

	if (channel == NULL) {
		return -1;
	}

	int fd = channel->fd;
	if (channel->udp_fd >= 0) {
		fd = channel->udp_fd;
	}

	if (fd < 0) {
		errno = ENOTCONN;
		return -1;
	}

	if (channel->type == PROXY_PASSTHROUGH) {
		return recvfrom(fd, buf, len, flags, src_addr, addrlen);
	}

	ret = recvfrom(fd, buffer, sizeof(buffer), MSG_NOSIGNAL, NULL, NULL);
	if (ret <= 0) {
		return -1;
	}

	if (channel->type == PROXY_SOCKS5) {
		/* Parse SOCKS5 UDP header */
		if (buffer[0] != 0x00 || buffer[1] != 0x00 || buffer[2] != 0x00) {
			errno = EPROTO;
			return -1;
		}

		switch (buffer[3]) {
		case PROXY_SOCKS5_TYPE_IPV4:
			if (ret < 10) {
				errno = EPROTO;
				return -1;
			}

			if (src_addr) {
				memset(src_addr, 0, sizeof(struct sockaddr_in));
				((struct sockaddr_in *)src_addr)->sin_family = AF_INET;
				memcpy(&((struct sockaddr_in *)src_addr)->sin_addr.s_addr, buffer + 4, 4);
				memcpy(&((struct sockaddr_in *)src_addr)->sin_port, buffer + 8, 2);
			}

			if (addrlen) {
				*addrlen = sizeof(struct sockaddr_in);
			}

			buffer_len = 10;
			break;
		case PROXY_SOCKS5_TYPE_IPV6:
			if (ret < 22) {
				errno = EPROTO;
				return -1;
			}

			if (src_addr) {
				memset(src_addr, 0, sizeof(struct sockaddr_in6));
				((struct sockaddr_in6 *)src_addr)->sin6_family = AF_INET6;
				memcpy(&((struct sockaddr_in6 *)src_addr)->sin6_addr.s6_addr, buffer + 4, 16);
				memcpy(&((struct sockaddr_in6 *)src_addr)->sin6_port, buffer + 20, 2);
			}

			if (addrlen) {
				*addrlen = sizeof(struct sockaddr_in6);
			}

			buffer_len = 22;
			break;
		default:
			errno = EPROTO;
			return -1;
		}

		if (ret - buffer_len > (int)len) {
			errno = EMSGSIZE;
			return -1;
		}
		memcpy(buf, buffer + buffer_len, ret - buffer_len);
		return ret - buffer_len;
	} else {
		if (ret > (int)len) {
			errno = EMSGSIZE;
			return -1;
		}
		memcpy(buf, buffer, ret);
		return ret;
	}
}

int proxy_channel_get_last_error(struct proxy_channel *channel)
{
	if (channel == NULL) {
		return -1;
	}
	return channel->last_error;
}

static int proxy_channel_set_so_mark(struct proxy_channel *channel, int mark)
{
	if (channel == NULL) {
		return -1;
	}

	if (channel->fd >= 0) {
		if (setsockopt(channel->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
			return -1;
		}
	}

	if (channel->is_udp && channel->udp_fd >= 0) {
		if (setsockopt(channel->udp_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
			return -1;
		}
	}

	return 0;
}

static int proxy_channel_set_ifname(struct proxy_channel *channel, const char *ifname)
{
	struct ifreq ifr;

	if (channel == NULL || ifname == NULL) {
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (channel->fd >= 0) {
		if (setsockopt(channel->fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) != 0) {
			return -1;
		}
	}

	return 0;
}

static int proxy_channel_set_tcp_fastopen(struct proxy_channel *channel, int enable)
{
	if (channel == NULL || channel->fd < 0) {
		return -1;
	}

	if (enable) {
		if (setsockopt(channel->fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &enable, sizeof(enable)) != 0) {
			return -1;
		}
	}

	return 0;
}

static int proxy_channel_set_keepalive(struct proxy_channel *channel, int idle, int intvl, int cnt)
{
	if (channel == NULL || channel->fd < 0) {
		return -1;
	}

	return set_sock_keepalive(channel->fd, idle, intvl, cnt);
}

int proxy_conn_send(struct proxy_conn *proxy_conn, const void *buf, size_t len, int flags)
{
	struct proxy_channel *channel = NULL;
	int ret = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	channel = proxy_conn->active_channel;
	if (channel == NULL) {
		tlog(TLOG_DEBUG, "proxy_conn_send: active_channel is NULL, returning EAGAIN");
		pthread_mutex_unlock(&proxy_conn->lock);
		errno = EAGAIN;
		return -1;
	}

	ret = proxy_channel_send(channel, buf, len, flags);

	/* On error, try to failover to fallback channel */
	if (ret < 0 && (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN)) {
		tlog(TLOG_DEBUG, "proxy %s: active channel failed, trying fallback", proxy_conn->proxy_name);

		/* Find a fallback channel */
		struct proxy_channel *fallback = NULL;
		list_for_each_entry(fallback, &proxy_conn->channel_list, list)
		{
			if (fallback->is_fallback && fallback->state == PROXY_STATE_CONNECTED) {
				proxy_conn->active_channel = fallback;
				ret = proxy_channel_send(fallback, buf, len, flags);
				if (ret >= 0) {
					tlog(TLOG_INFO, "proxy %s: failed over to fallback channel", proxy_conn->proxy_name);
				}
				break;
			}
		}
	}

	pthread_mutex_unlock(&proxy_conn->lock);
	return ret;
}

int proxy_conn_recv(struct proxy_conn *proxy_conn, void *buf, size_t len, int flags)
{
	struct proxy_channel *channel = NULL;
	int ret = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	channel = proxy_conn->active_channel;
	if (channel == NULL) {
		pthread_mutex_unlock(&proxy_conn->lock);
		errno = EAGAIN;
		return -1;
	}

	ret = proxy_channel_recv(channel, buf, len, flags);

	/* On error, mark channel as failed */
	if (ret < 0 && (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN)) {
		tlog(TLOG_DEBUG, "proxy %s: active channel recv failed", proxy_conn->proxy_name);
		channel->state = PROXY_STATE_DISCONNECTED;
	}

	pthread_mutex_unlock(&proxy_conn->lock);
	return ret;
}

int proxy_conn_sendto(struct proxy_conn *proxy_conn, const void *buf, size_t len, int flags,
					  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct proxy_channel *channel = NULL;
	int ret = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	channel = proxy_conn->active_channel;
	if (channel == NULL) {
		pthread_mutex_unlock(&proxy_conn->lock);
		errno = ENOTCONN;
		return -1;
	}

	ret = proxy_channel_sendto(channel, buf, len, flags, dest_addr, addrlen);

	pthread_mutex_unlock(&proxy_conn->lock);
	return ret;
}

int proxy_conn_recvfrom(struct proxy_conn *proxy_conn, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						socklen_t *addrlen)
{
	struct proxy_channel *channel = NULL;
	int ret = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	channel = proxy_conn->active_channel;
	if (channel == NULL) {
		pthread_mutex_unlock(&proxy_conn->lock);
		errno = ENOTCONN;
		return -1;
	}

	ret = proxy_channel_recvfrom(channel, buf, len, flags, src_addr, addrlen);

	pthread_mutex_unlock(&proxy_conn->lock);
	return ret;
}

int proxy_conn_is_udp(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return -1;
	}

	return proxy_conn->is_udp;
}

int proxy_init(void)
{
	if (is_proxy_init == 1) {
		return -1;
	}

	memset(&proxy, 0, sizeof(proxy));
	hash_init(proxy.proxy_server);
	is_proxy_init = 1;
	return 0;
}

void proxy_exit(void)
{
	if (is_proxy_init == 0) {
		return;
	}
	_proxy_remove_all();

	is_proxy_init = 0;

	return;
}

int proxy_conn_get_last_error(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return 0;
	}

	pthread_mutex_lock(&proxy_conn->lock);
	int err = 0;
	if (proxy_conn->active_channel) {
		err = proxy_conn->active_channel->last_error;
	}
	pthread_mutex_unlock(&proxy_conn->lock);
	return err;
}

int proxy_channel_get_opt_error(struct proxy_channel *channel)
{
	int err = 0;
	socklen_t len = sizeof(err);
	if (channel == NULL || channel->fd < 0) {
		return 0;
	}
	if (getsockopt(channel->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		return errno;
	}
	return err;
}

int proxy_conn_is_ipv6_target(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return 0;
	}

	return check_is_ipv6(proxy_conn->host) == 0;
}

const char *proxy_handshake_error_to_string(int error_code)
{
	if (error_code >= 100 && error_code < 600) {
		switch (error_code) {
		case 403:
			return "HTTP Forbidden";
		case 404:
			return "HTTP Not Found";
		case 407:
			return "HTTP Proxy Authentication Required";
		case 502:
			return "HTTP Bad Gateway";
		case 503:
			return "HTTP Service Unavailable";
		case 504:
			return "HTTP Gateway Timeout";
		default:
			return "HTTP Error";
		}
	}

	switch (error_code) {
	case 0x00:
		return "succeeded";
	case 0x01:
		return "general SOCKS server failure";
	case 0x02:
		return "connection not allowed by ruleset";
	case 0x03:
		return "Network unreachable";
	case 0x04:
		return "Host unreachable";
	case 0x05:
		return "Connection refused";
	case 0x06:
		return "TTL expired";
	case 0x07:
		return "Command not supported";
	case 0x08:
		return "Address type not supported";
	case 0xFF:
		return "unassigned";
	default:
		return "unknown error";
	}
}

/* Epoll Management Functions */

int proxy_conn_ctl(struct proxy_conn *proxy_conn, int epoll_fd, int op, struct epoll_event *event)
{
	struct proxy_channel *channel = NULL;
	int ret = 0;
	int count = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	pthread_mutex_lock(&proxy_conn->lock);

	if (proxy_conn->active_channel) {
		/* If we have an active channel, only apply to it */
		ret = proxy_channel_ctl(proxy_conn->active_channel, epoll_fd, op, event);
		pthread_mutex_unlock(&proxy_conn->lock);
		return ret;
	} else {
		/* Apply epoll operation to all valid channel FDs (Race Mode) */
		/* Rate mode only concerns TCP connections */
		list_for_each_entry(channel, &proxy_conn->channel_list, list)
		{
			if (channel->fd >= 0 && (channel->state > PROXY_STATE_INIT || op == EPOLL_CTL_DEL)) {
				if (proxy_channel_ctl(channel, epoll_fd, op, event) == 0) {
					count++;
				} else {
					tlog(TLOG_ERROR, "proxy conn ctl (race) failed for %s (op=%d), state=%d",
						 channel->server_info ? channel->server_info->proxy_name : "unknown", op, channel->state);
					ret = -1;
				}
			}
		}

		/* If we successfully operated on at least one channel, return 0 (success) */
		if (count > 0) {
			ret = 0;
		}
		pthread_mutex_unlock(&proxy_conn->lock);
		return ret;
	}
}

int proxy_conn_set_so_mark(struct proxy_conn *proxy_conn, int mark)
{
	struct proxy_channel *channel;

	if (proxy_conn == NULL) {
		return -1;
	}
	pthread_mutex_lock(&proxy_conn->lock);
	proxy_conn->so_mark = mark;

	/* Apply to all existing channels */
	list_for_each_entry(channel, &proxy_conn->channel_list, list)
	{
		proxy_channel_set_so_mark(channel, mark);
	}
	pthread_mutex_unlock(&proxy_conn->lock);

	return 0;
}

int proxy_conn_set_ifname(struct proxy_conn *proxy_conn, const char *ifname)
{
	struct proxy_channel *channel;

	if (proxy_conn == NULL || ifname == NULL) {
		return -1;
	}
	pthread_mutex_lock(&proxy_conn->lock);
	safe_strncpy(proxy_conn->ifname, ifname, sizeof(proxy_conn->ifname));

	list_for_each_entry(channel, &proxy_conn->channel_list, list)
	{
		proxy_channel_set_ifname(channel, ifname);
	}
	pthread_mutex_unlock(&proxy_conn->lock);
	return 0;
}

int proxy_conn_set_tcp_fastopen(struct proxy_conn *proxy_conn, int enable)
{
	struct proxy_channel *channel;

	if (proxy_conn == NULL) {
		return -1;
	}
	pthread_mutex_lock(&proxy_conn->lock);
	proxy_conn->tcp_fastopen = enable;

	if (enable) {
		list_for_each_entry(channel, &proxy_conn->channel_list, list)
		{
			proxy_channel_set_tcp_fastopen(channel, enable);
		}
	}
	pthread_mutex_unlock(&proxy_conn->lock);

	return 0;
}

int proxy_conn_set_keepalive(struct proxy_conn *proxy_conn, int idle, int intvl, int cnt)
{
	struct proxy_channel *channel;

	if (proxy_conn == NULL) {
		return -1;
	}
	pthread_mutex_lock(&proxy_conn->lock);
	proxy_conn->keepalive_idle = idle;
	proxy_conn->keepalive_intvl = intvl;
	proxy_conn->keepalive_cnt = cnt;

	list_for_each_entry(channel, &proxy_conn->channel_list, list)
	{
		proxy_channel_set_keepalive(channel, idle, intvl, cnt);
	}
	pthread_mutex_unlock(&proxy_conn->lock);

	return 0;
}

/* Helper functions for event loop integration */
int proxy_conn_is_epoll_event(void *ptr)
{
	if (proxy_channel_get_from_event(ptr) != NULL) {
		return 1;
	}
	return 0;
}

struct proxy_channel *proxy_channel_get_from_event(void *ptr)
{
	struct proxy_channel *channel = (struct proxy_channel *)ptr;

	if (channel == NULL || channel->magic != PROXY_CHANNEL_MAGIC) {
		return NULL;
	}

	return channel;
}

void *proxy_conn_get_event_userdata(void *ptr)
{
	struct proxy_channel *channel = proxy_channel_get_from_event(ptr);
	if (channel) {
		return channel->userdata;
	}
	return NULL;
}

void proxy_conn_set_event_userdata(struct proxy_conn *proxy_conn, void *userdata)
{
	struct proxy_channel *channel = NULL;
	if (proxy_conn == NULL) {
		return;
	}

	pthread_mutex_lock(&proxy_conn->lock);
	proxy_conn->userdata = userdata;
	list_for_each_entry(channel, &proxy_conn->channel_list, list)
	{
		channel->userdata = userdata;
	}
	pthread_mutex_unlock(&proxy_conn->lock);
}

void proxy_channel_set_server_auth(struct proxy_channel *channel, const char *user, const char *pass)
{
	if (channel == NULL) {
		return;
	}

	if (user) {
		safe_strncpy(channel->server_user, user, sizeof(channel->server_user));
	} else {
		channel->server_user[0] = '\0';
	}

	if (pass) {
		safe_strncpy(channel->server_pass, pass, sizeof(channel->server_pass));
	} else {
		channel->server_pass[0] = '\0';
	}
}

int proxy_channel_is_udp(struct proxy_channel *channel)
{
	if (channel == NULL) {
		return 0;
	}
	return channel->is_udp;
}

static proxy_handshake_state _proxy_channel_server_send_auth_method(struct proxy_channel *channel, int method)
{
	unsigned char reply[2] = {PROXY_SOCKS5_VERSION, method};
	if (send(channel->fd, reply, 2, MSG_NOSIGNAL) != 2) {
		return PROXY_HANDSHAKE_ERR;
	}
	channel->buffer.len = 0;
	return PROXY_HANDSHAKE_WANT_READ;
}

static proxy_handshake_state _proxy_channel_server_send_auth_reply(struct proxy_channel *channel, int status)
{
	unsigned char auth_reply[2] = {0x01, status};
	if (send(channel->fd, auth_reply, 2, MSG_NOSIGNAL) != 2) {
		return PROXY_HANDSHAKE_ERR;
	}
	channel->buffer.len = 0;
	return PROXY_HANDSHAKE_WANT_READ;
}

static proxy_handshake_state _proxy_handshake_socks5_server(struct proxy_channel *channel)
{
	int len = 0;
	unsigned char *buff = channel->buffer.buffer;

	if (channel == NULL || channel->fd < 0) {
		return PROXY_HANDSHAKE_ERR;
	}

	switch (channel->phase) {
	case PROXY_PHASE_SERVER_INIT:
		len = recv(channel->fd, buff + channel->buffer.len, sizeof(channel->buffer.buffer) - channel->buffer.len, 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (channel->buffer.len == 0) {
					return PROXY_HANDSHAKE_WANT_READ;
				}
			} else {
				return PROXY_HANDSHAKE_ERR;
			}
		} else {
			channel->buffer.len += len;
		}

		/* Need at least version(1) + nmethods(1) */
		if (channel->buffer.len < 2) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		if (buff[0] != PROXY_SOCKS5_VERSION) {
			return PROXY_HANDSHAKE_ERR;
		}

		int nmethods = buff[1];
		if (channel->buffer.len < 2 + nmethods) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		/* Respond with AUTH method */
		unsigned char method = PROXY_SOCKS5_NO_AUTH;
		if (channel->server_user[0] != '\0') {
			/* Check if client supports USER/PASS */
			int found = 0;
			for (int i = 0; i < nmethods; i++) {
				if (buff[2 + i] == PROXY_SOCKS5_AUTH_USER_PASS) {
					found = 1;
					break;
				}
			}
			if (found) {
				method = PROXY_SOCKS5_AUTH_USER_PASS;
			} else {
				/* Client doesn't support our auth method */
				return PROXY_HANDSHAKE_ERR;
			}
		}

		tlog(TLOG_DEBUG, "client handshake success, select auth method: %d", method);
		if (method == PROXY_SOCKS5_AUTH_USER_PASS) {
			channel->phase = PROXY_PHASE_SERVER_SOCKS5_AUTH;
		} else {
			channel->phase = PROXY_PHASE_SERVER_SOCKS5_REQ;
		}
		return _proxy_channel_server_send_auth_method(channel, method);

	case PROXY_PHASE_SERVER_SOCKS5_AUTH:
		len = recv(channel->fd, buff + channel->buffer.len, sizeof(channel->buffer.buffer) - channel->buffer.len, 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (channel->buffer.len == 0) {
					return PROXY_HANDSHAKE_WANT_READ;
				}
			} else {
				return PROXY_HANDSHAKE_ERR;
			}
		} else {
			channel->buffer.len += len;
		}

		/* Need VER(1), ULEN(1), USER(n), PLEN(1), PASS(n) */
		if (channel->buffer.len < 2) {
			return PROXY_HANDSHAKE_WANT_READ;
		}
		int ulen = buff[1];
		if (channel->buffer.len < 2 + ulen + 1) {
			return PROXY_HANDSHAKE_WANT_READ;
		}
		int plen = buff[2 + ulen];
		if (channel->buffer.len < 2 + ulen + 1 + plen) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		/* Verify credentials */
		int auth_ok = 0;
		if (ulen == (int)strlen(channel->server_user) && plen == (int)strlen(channel->server_pass) &&
			memcmp(buff + 2, channel->server_user, ulen) == 0 &&
			memcmp(buff + 2 + ulen + 1, channel->server_pass, plen) == 0) {
			auth_ok = 1;
		}

		if (!auth_ok) {
			tlog(TLOG_DEBUG, "socks5 server: auth failed");
			_proxy_channel_server_send_auth_reply(channel, 0x01);
			return PROXY_HANDSHAKE_ERR;
		}

		tlog(TLOG_DEBUG, "server verify auth success");
		channel->phase = PROXY_PHASE_SERVER_SOCKS5_REQ;
		return _proxy_channel_server_send_auth_reply(channel, 0x00);

	case PROXY_PHASE_SERVER_SOCKS5_REQ:
		len = recv(channel->fd, buff + channel->buffer.len, sizeof(channel->buffer.buffer) - channel->buffer.len, 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				if (channel->buffer.len == 0) {
					return PROXY_HANDSHAKE_WANT_READ;
				}
			} else {
				return PROXY_HANDSHAKE_ERR;
			}
		} else {
			channel->buffer.len += len;
		}

		/* Minimal request: VER CMD RSV ATYP ADDR PORT */
		/* VER=1, CMD=1, RSV=1, ATYP=1, ADDR= ?, PORT=2 */
		if (channel->buffer.len < 6) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		if (buff[0] != PROXY_SOCKS5_VERSION) {
			return PROXY_HANDSHAKE_ERR;
		}

		if (buff[1] == PROXY_SOCKS5_CONNECT_TCP) {
			channel->is_udp = 0;
		} else if (buff[1] == PROXY_SOCKS5_CONNECT_UDP) {
			channel->is_udp = 1;
		} else {
			/* We only support CONNECT and UDP ASSOCIATE */
			/* TODO: Send error reply? */
			return PROXY_HANDSHAKE_ERR;
		}

		int addr_type = buff[3];
		int addr_len = 0;

		switch (addr_type) {
		case PROXY_SOCKS5_TYPE_IPV4: {
			addr_len = 4;
			if (channel->buffer.len < 4 + addr_len + 2) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			struct sockaddr_in sa = {0};
			sa.sin_family = AF_INET;
			memcpy(&sa.sin_addr.s_addr, buff + 4, 4);
			inet_ntop(AF_INET, &sa.sin_addr, channel->host, sizeof(channel->host));
			channel->port = ntohs(*(uint16_t *)(buff + 4 + 4));

		} break;
		case PROXY_SOCKS5_TYPE_DOMAIN: {
			addr_len = buff[4]; // domain length
			if (channel->buffer.len < 4 + 1 + addr_len + 2) {
				return PROXY_HANDSHAKE_WANT_READ;
			}
			if (addr_len >= (int)sizeof(channel->host)) {
				return PROXY_HANDSHAKE_ERR;
			}
			memcpy(channel->host, buff + 5, addr_len);
			channel->host[addr_len] = '\0';
			channel->port = ntohs(*(uint16_t *)(buff + 5 + addr_len));
		} break;
		case PROXY_SOCKS5_TYPE_IPV6: {
			addr_len = 16;
			if (channel->buffer.len < 4 + addr_len + 2) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			struct sockaddr_in6 sa = {0};
			sa.sin6_family = AF_INET6;
			memcpy(&sa.sin6_addr, buff + 4, 16);
			inet_ntop(AF_INET6, &sa.sin6_addr, channel->host, sizeof(channel->host));
			channel->port = ntohs(*(uint16_t *)(buff + 4 + 16));
		} break;
		default:
			return PROXY_HANDSHAKE_ERR;
		}

		channel->buffer.len = 0;                /* Consumed */
		channel->state = PROXY_STATE_CONNECTED; /* Handshake complete */
		return PROXY_HANDSHAKE_OK;              /* Signal that we have the target */

	default:
		return PROXY_HANDSHAKE_ERR;
	}
}

static proxy_handshake_state _proxy_handshake_http_server(struct proxy_channel *channel)
{
	int len = 0;
	unsigned char *buff = channel->buffer.buffer;
	struct http_head *head = NULL;

	if (channel == NULL || channel->fd < 0) {
		return PROXY_HANDSHAKE_ERR;
	}

	len = recv(channel->fd, buff + channel->buffer.len, sizeof(channel->buffer.buffer) - channel->buffer.len, 0);
	if (len <= 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (channel->buffer.len == 0) {
				return PROXY_HANDSHAKE_WANT_READ;
			}
		} else {
			return PROXY_HANDSHAKE_ERR;
		}
	} else {
		channel->buffer.len += len;
	}

	head = http_head_init(4096, HTTP_VERSION_1_1);
	if (!head) {
		return PROXY_HANDSHAKE_ERR;
	}

	int head_len = http_head_parse(head, buff, channel->buffer.len);
	if (head_len < 0) {
		tlog(TLOG_DEBUG, "http handshake head parse failed %d", head_len);
		http_head_destroy(head);
		if (head_len == -1) {
			if (channel->buffer.len >= (int)sizeof(channel->buffer.buffer)) {
				return PROXY_HANDSHAKE_ERR;
			}
			return PROXY_HANDSHAKE_WANT_READ;
		}
		return PROXY_HANDSHAKE_ERR;
	}

	/* Check method */
	HTTP_METHOD method = http_head_get_method(head);
	char *url = (char *)http_head_get_url(head);
	tlog(TLOG_DEBUG, "http handshake method %d, url %s", method, url ? url : "null");

	if (method == HTTP_METHOD_INVALID || !url) {
		tlog(TLOG_ERROR, "http handshake invalid method %d or url %s", method, url ? url : "null");
		http_head_destroy(head);
		return PROXY_HANDSHAKE_ERR;
	}

	if (method == HTTP_METHOD_CONNECT) {
		/* HTTPS Tunnel: url is host:port */
		safe_strncpy(channel->host, url, sizeof(channel->host));
		char *p = strrchr(channel->host, ':');
		if (p) {
			*p = '\0';
			channel->port = atoi(p + 1);
		} else {
			channel->port = 443;
		}
		channel->is_udp = 0;     // CONNECT is TCP
		channel->last_error = 0; /* Signals we need to send 200 Connection Established later */

		/* For CONNECT, we consume the header. */
		channel->buffer.len -= head_len;
		if (channel->buffer.len > 0) {
			memmove(channel->buffer.buffer, channel->buffer.buffer + head_len, channel->buffer.len);
		}
	} else {
		/* HTTP Proxy: url is absolute URI http://host:port/path */
		/* We need to parse host and port */
		char scheme[32], host[256], path[1024];
		int port;
		if (parse_uri(url, scheme, host, &port, path) != 0) {
			tlog(TLOG_ERROR, "http handshake parse_uri failed for %s", url);
			http_head_destroy(head);
			return PROXY_HANDSHAKE_ERR;
		}
		safe_strncpy(channel->host, host, sizeof(channel->host));
		channel->port = port > 0 ? port : 80;
		channel->last_error = 1; /* Signals we are doing standard HTTP proxy */

		/* We keep the header for standard HTTP proxying */
	}

	http_head_destroy(head);
	channel->state = PROXY_STATE_CONNECTED;
	return PROXY_HANDSHAKE_OK;
}

struct proxy_channel *proxy_channel_server_new(int fd, proxy_type_t type)
{
	struct proxy_channel *channel = (struct proxy_channel *)calloc(1, sizeof(struct proxy_channel));
	if (channel) {
		channel->magic = PROXY_CHANNEL_MAGIC;
		channel->fd = fd;
		channel->udp_fd = -1;
		channel->type = type;
		channel->state = PROXY_STATE_HANDSHAKING;
		channel->phase = PROXY_PHASE_SERVER_INIT;
		INIT_LIST_HEAD(&channel->list);
	}
	return channel;
}

struct proxy_channel *proxy_channel_accept(struct proxy_channel *listener)
{
	if (listener == NULL || listener->fd < 0) {
		return NULL;
	}

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int fd = accept4(listener->fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		return NULL;
	}

	struct proxy_channel *channel = (struct proxy_channel *)calloc(1, sizeof(struct proxy_channel));
	if (channel) {
		channel->magic = PROXY_CHANNEL_MAGIC;
		channel->fd = fd;
		channel->udp_fd = -1; // Initialize udp_fd
		channel->state = PROXY_STATE_HANDSHAKING;
		channel->phase = PROXY_PHASE_SERVER_INIT;
		channel->type = listener->type; /* Inherit type? */
		memcpy(&channel->addr, &addr, addr_len);
		channel->addrlen = addr_len;
		INIT_LIST_HEAD(&channel->list); // Initialize list head

		if (set_fd_nonblock(fd, 1) != 0) {
			tlog(TLOG_ERROR, "set non block failed.");
			close(fd);
			free(channel);
			return NULL;
		}
		set_sock_keepalive(fd, 30, 3, 5);
	} else {
		close(fd);
	}
	return channel;
}

void proxy_channel_free(struct proxy_channel *channel)
{
	if (channel == NULL || channel->magic != PROXY_CHANNEL_MAGIC) {
		return;
	}

	if (channel->parent != NULL) {
		pthread_mutex_lock(&channel->parent->lock);
		list_del(&channel->list);
		if (channel->parent->active_channel == channel) {
			channel->parent->active_channel = NULL;
		}
		if (channel->parent->best_channel == channel) {
			channel->parent->best_channel = NULL;
		}
		pthread_mutex_unlock(&channel->parent->lock);
		channel->parent = NULL;
	}

	_proxy_channel_free(channel);
}

int proxy_channel_ctl(struct proxy_channel *channel, int epoll_fd, int op, struct epoll_event *event)
{
	int fd;
	if (channel == NULL || channel->magic != PROXY_CHANNEL_MAGIC || epoll_fd < 0) {
		return -1;
	}

	fd = channel->fd;
	/* If UDP FD is active and we are connected, operations should apply to it */
	if (channel->state == PROXY_STATE_CONNECTED && channel->udp_fd >= 0) {
		fd = channel->udp_fd;
	}

	if (fd < 0) {
		return -1;
	}

	/* Store original userdata for retrieval via proxy_conn_get_event_userdata */
	if (event && event->data.ptr) {
		channel->userdata = event->data.ptr;
	}

	struct epoll_event new_event;
	if (event) {
		new_event.events = event->events;
		new_event.data.ptr = channel; /* Always point to channel for internal dispatch */
	} else {
		/* For DEL, event can be NULL */
		new_event.events = 0;
		new_event.data.ptr = NULL;
	}

	int real_op = op;
	/* If trying to modify a channel that hasn't been added yet, try ADDing it */
	if (op == EPOLL_CTL_MOD && channel->state == PROXY_STATE_INIT) {
		real_op = EPOLL_CTL_ADD;
	}

	if (epoll_ctl(epoll_fd, real_op, fd, event ? &new_event : NULL) != 0) {
		/* Recovery logic for ADD/MOD mismatches */
		if (errno == EEXIST && real_op == EPOLL_CTL_ADD) {
			if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, event ? &new_event : NULL) == 0) {
				return 0;
			}
		} else if (errno == ENOENT && real_op == EPOLL_CTL_MOD) {
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, event ? &new_event : NULL) == 0) {
				return 0;
			}
		}
		return -1;
	}

	return 0;
}

int proxy_channel_recv(struct proxy_channel *channel, void *buf, size_t len, int flags)
{
	if (!channel || channel->fd < 0) {
		return -1;
	}

	if (channel->buffer.len > 0) {
		int copy_len = channel->buffer.len;
		if (copy_len > (int)len)
			copy_len = (int)len;
		memcpy(buf, channel->buffer.buffer, copy_len);

		if (copy_len < channel->buffer.len) {
			memmove(channel->buffer.buffer, channel->buffer.buffer + copy_len, channel->buffer.len - copy_len);
			channel->buffer.len -= copy_len;
		} else {
			channel->buffer.len = 0;
		}
		return copy_len;
	}

	int fd = channel->fd;
	if (channel->state == PROXY_STATE_CONNECTED && channel->udp_fd >= 0) {
		fd = channel->udp_fd;
	}

	return recv(fd, buf, len, flags);
}

int proxy_channel_send(struct proxy_channel *channel, const void *buf, size_t len, int flags)
{
	if (!channel || channel->fd < 0) {
		return -1;
	}
	int fd = channel->fd;
	if (channel->state == PROXY_STATE_CONNECTED && channel->udp_fd >= 0) {
		fd = channel->udp_fd;
	}

	int ret = send(fd, buf, len, flags);
	if (ret < 0 && (errno == ENOTCONN || errno == EDESTADDRREQ || errno == ENOTSUP) && channel->is_udp) {
		ret = sendto(fd, buf, len, flags, (struct sockaddr *)&channel->addr, channel->addrlen);
	}

	if (ret < 0) {
		int err = errno;
		errno = err;
	}
	return ret;
}

void proxy_channel_get_target(struct proxy_channel *channel, char *host, int host_len, unsigned short *port)
{
	if (channel) {
		if (host) {
			strncpy(host, channel->host, host_len);
			host[host_len - 1] = 0;
		}
		if (port) {
			*port = channel->port;
		}
	}
}

void proxy_channel_get_addr(struct proxy_channel *channel, struct sockaddr *addr, socklen_t *addrlen)
{
	if (channel && addr && addrlen) {
		memcpy(addr, &channel->addr, *addrlen < channel->addrlen ? *addrlen : channel->addrlen);
		*addrlen = channel->addrlen;
	}
}
