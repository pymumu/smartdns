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
#include "proxy.h"
#include "dns_conf.h"
#include "hashtable.h"
#include "http_parse.h"
#include "list.h"
#include "tlog.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/epoll.h>

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
#define PROXY_BUFFER_SIZE (1024 * 4)
#define PROXY_MAX_HOSTNAME_LEN 256

typedef enum PROXY_CONN_STATE {
	PROXY_CONN_INIT = 0,
	PROXY_CONN_INIT_ACK = 1,
	PROXY_CONN_AUTH = 2,
	PROXY_CONN_AUTH_ACK = 3,
	PROXY_CONN_CONNECTING = 4,
	PROXY_CONN_CONNECTED = 5,
} PROXY_CONN_STATE;

struct proxy_conn_buffer {
	int len;
	char buffer[PROXY_BUFFER_SIZE];
};

struct proxy_conn {
	proxy_type_t type;
	PROXY_CONN_STATE state;
	char host[DNS_MAX_CNAME_LEN];
	unsigned short port;
	int fd;
	int udp_fd;
	int buffer_len;
	int is_udp;
	struct sockaddr_storage udp_dest_addr;
	socklen_t udp_dest_addrlen;
	struct proxy_conn_buffer buffer;
	struct proxy_server_info *server_info;
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
		if (strncmp(server_info->proxy_name, proxy_name, DNS_GROUP_NAME_LEN) != 0) {
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

	server_info = malloc(sizeof(*server_info));
	if (server_info == NULL) {
		goto errout;
	}

	memset(server_info, 0, sizeof(*server_info));
	memcpy(&server_info->info, info, sizeof(struct proxy_info));

	if (parse_ip(info->server, ip_str, &port) != 0) {
		goto errout;
	}

	port = info->port;
	gai = _proxy_getaddr(info->server, port, SOCK_STREAM, 0);
	if (gai == NULL) {
		goto errout;
	}

	server_info->server_addrlen = gai->ai_addrlen;
	memcpy(&server_info->server_addr, gai->ai_addr, gai->ai_addrlen);

	safe_strncpy(server_info->proxy_name, proxy_name, PROXY_NAME_LEN);
	key = hash_string(server_info->proxy_name);
	hash_add(proxy.proxy_server, &server_info->node, key);

	freeaddrinfo(gai);
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

struct proxy_conn *proxy_conn_new(const char *proxy_name, const char *host, int port, int is_udp)
{
	struct proxy_conn *proxy_conn = NULL;
	struct proxy_server_info *server_info = NULL;
	struct addrinfo *gai = NULL;
	int fd = -1;

	server_info = _proxy_get_server_info(proxy_name);
	if (server_info == NULL) {
		goto errout;
	}

	if (is_udp == 1 && server_info->info.type != PROXY_SOCKS5) {
		tlog(TLOG_WARN, "only socks5 support udp");
		goto errout;
	}

	fd = socket(server_info->server_addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		goto errout;
	}

	proxy_conn = malloc(sizeof(*proxy_conn));
	if (proxy_conn == NULL) {
		goto errout;
	}

	memset(proxy_conn, 0, sizeof(*proxy_conn));
	safe_strncpy(proxy_conn->host, host, DNS_MAX_CNAME_LEN);
	proxy_conn->port = port;
	proxy_conn->type = server_info->info.type;
	proxy_conn->state = PROXY_CONN_INIT;
	proxy_conn->server_info = server_info;
	proxy_conn->fd = fd;
	proxy_conn->udp_fd = -1;
	proxy_conn->is_udp = is_udp;

	return proxy_conn;
errout:
	if (proxy_conn) {
		free(proxy_conn);
		proxy_conn = NULL;
	}

	if (fd >= 0) {
		close(fd);
	}

	if (gai) {
		freeaddrinfo(gai);
	}
	return NULL;
}

void proxy_conn_free(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return;
	}

	if (proxy_conn->fd >= 0) {
		close(proxy_conn->fd);
	}

	if (proxy_conn->udp_fd >= 0) {
		close(proxy_conn->udp_fd);
	}

	free(proxy_conn);
}

int proxy_conn_connect(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return -1;
	}

	return connect(proxy_conn->fd, (struct sockaddr *)&proxy_conn->server_info->server_addr,
				   proxy_conn->server_info->server_addrlen);
}

static int _proxy_handshake_socks5_create_udp_fd(struct proxy_conn *proxy_conn)
{
	int ret = 0;
	char *gai_host = NULL;
	int udp_fd = -1;
	struct addrinfo *gai = NULL;

	switch (proxy_conn->udp_dest_addr.ss_family) {
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

	freeaddrinfo(gai);
	return udp_fd;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}

	return -1;
}

static int _proxy_handshake_socks5_connect_udp(struct proxy_conn *proxy_conn)
{
	int udp_fd = -1;

	if (proxy_conn->is_udp == 0) {
		return 0;
	}

	if (proxy_conn->udp_fd < 0) {
		udp_fd = _proxy_handshake_socks5_create_udp_fd(proxy_conn);
		if (udp_fd < 0) {
			return -1;
		}

		proxy_conn->udp_fd = udp_fd;
	}

	return connect(proxy_conn->udp_fd, (struct sockaddr *)&proxy_conn->udp_dest_addr, proxy_conn->udp_dest_addrlen);
}

static proxy_handshake_state _proxy_handshake_socks5_reply_connect_addr(struct proxy_conn *proxy_conn)
{
	char buff[DNS_MAX_CNAME_LEN * 2];
	int len = 0;
	memset(buff, 0, sizeof(buff));
	struct sockaddr_storage addr;
	char *ptr = NULL;
	socklen_t addr_len = sizeof(addr);

	buff[0] = PROXY_SOCKS5_VERSION;
	if (proxy_conn->is_udp) {
		buff[1] = PROXY_SOCKS5_CONNECT_UDP;
	} else {
		buff[1] = PROXY_SOCKS5_CONNECT_TCP;
	}

	buff[2] = 0x0;
	ptr = buff + 3;
	if (proxy_conn->server_info->info.use_domain) {
		*ptr = PROXY_SOCKS5_TYPE_DOMAIN;
		ptr++;

		int domainlen = strnlen(proxy_conn->host, DNS_MAX_CNAME_LEN);
		*ptr = domainlen;
		ptr++;
		memcpy(ptr, proxy_conn->host, domainlen);
		ptr += domainlen;
	} else {
		if (proxy_conn->is_udp) {
			memset(&addr, 0, proxy_conn->server_info->server_addrlen);
			addr_len = proxy_conn->server_info->server_addrlen;
			addr.ss_family = proxy_conn->server_info->server_addr.ss_family;
		} else {
			getaddr_by_host(proxy_conn->host, (struct sockaddr *)&addr, &addr_len);
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
	*((short *)(ptr)) = htons(proxy_conn->port);
	ptr += 2;

	len = send(proxy_conn->fd, buff, ptr - buff, MSG_NOSIGNAL);
	if (len != ptr - buff) {
		tlog(TLOG_ERROR, "Send proxy request failed.");
		return PROXY_HANDSHAKE_ERR;
	}
	proxy_conn->state = PROXY_CONN_CONNECTING;
	return PROXY_HANDSHAKE_WANT_READ;
}

static proxy_handshake_state _proxy_handshake_socks5_send_auth(struct proxy_conn *proxy_conn)
{
	char buff[DNS_MAX_CNAME_LEN * 2];
	int len = 0;
	int offset = 0;
	memset(buff, 0, sizeof(buff));

	buff[0] = 0x1;
	buff[1] = strnlen(proxy_conn->server_info->info.username, PROXY_MAX_NAMELEN);
	safe_strncpy(buff + 2, proxy_conn->server_info->info.username, buff[1] + 1);
	offset = buff[1] + 2;
	buff[offset] = strnlen(proxy_conn->server_info->info.password, PROXY_MAX_NAMELEN);
	safe_strncpy(buff + offset + 1, proxy_conn->server_info->info.password, buff[offset] + 1);
	offset += buff[offset] + 1;
	len = send(proxy_conn->fd, buff, offset, MSG_NOSIGNAL);
	if (len != offset) {
		tlog(TLOG_ERROR, "send auth failed, len: %d, %s", len, strerror(errno));
		return PROXY_HANDSHAKE_ERR;
	}

	proxy_conn->state = PROXY_CONN_AUTH_ACK;
	return PROXY_HANDSHAKE_WANT_READ;
}

static proxy_handshake_state _proxy_handshake_socks5(struct proxy_conn *proxy_conn)
{
	int len = 0;
	char buff[DNS_MAX_CNAME_LEN * 2];
	memset(buff, 0, sizeof(buff));

	switch (proxy_conn->state) {
	case PROXY_CONN_INIT: {
		buff[0] = PROXY_SOCKS5_VERSION;
		buff[1] = 0x2; // 2 auth methods
		buff[2] = PROXY_SOCKS5_NO_AUTH;
		buff[3] = PROXY_SOCKS5_AUTH_USER_PASS;
		len = send(proxy_conn->fd, buff, 4, MSG_NOSIGNAL);
		if (len != 4) {
			tlog(TLOG_ERROR, "connect socks5 server %s failed, %s", proxy_conn->server_info->proxy_name,
				 strerror(errno));
			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->state = PROXY_CONN_INIT_ACK;
		return PROXY_HANDSHAKE_WANT_READ;
	} break;
	case PROXY_CONN_INIT_ACK:
		len = recv(proxy_conn->fd, proxy_conn->buffer.buffer + proxy_conn->buffer.len,
				   sizeof(proxy_conn->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			tlog(TLOG_ERROR, "recv socks5 init ack from %s failed, %s", proxy_conn->server_info->proxy_name,
				 strerror(errno));
			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->buffer.len += len;
		if (proxy_conn->buffer.len < 2) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		if (proxy_conn->buffer.len > 2) {
			tlog(TLOG_ERROR, "recv socks5 init ack from %s failed", proxy_conn->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->buffer.len = 0;

		if (proxy_conn->buffer.buffer[0] != PROXY_SOCKS5_VERSION) {
			tlog(TLOG_ERROR, "server %s not support socks5", proxy_conn->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		if ((unsigned char)proxy_conn->buffer.buffer[1] == PROXY_SOCKS5_AUTH_NONE) {
			tlog(TLOG_ERROR, "server %s not support auth methods", proxy_conn->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		tlog(TLOG_DEBUG, "server %s select auth method is %d", proxy_conn->server_info->proxy_name,
			 proxy_conn->buffer.buffer[1]);
		if (proxy_conn->buffer.buffer[1] == PROXY_SOCKS5_AUTH_USER_PASS) {
			return _proxy_handshake_socks5_send_auth(proxy_conn);
		}

		if (proxy_conn->buffer.buffer[1] == PROXY_SOCKS5_NO_AUTH) {
			return _proxy_handshake_socks5_reply_connect_addr(proxy_conn);
		}

		tlog(TLOG_ERROR, "server %s select invalid auth method %d", proxy_conn->server_info->proxy_name,
			 proxy_conn->buffer.buffer[1]);
		return PROXY_HANDSHAKE_ERR;
		break;
	case PROXY_CONN_AUTH_ACK:
		len = recv(proxy_conn->fd, proxy_conn->buffer.buffer + proxy_conn->buffer.len,
				   sizeof(proxy_conn->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			tlog(TLOG_ERROR, "recv socks5 auth ack from %s failed, %s", proxy_conn->server_info->proxy_name,
				 strerror(errno));
			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->buffer.len += len;
		if (proxy_conn->buffer.len < 2) {
			return PROXY_HANDSHAKE_WANT_READ;
		}

		if (proxy_conn->buffer.len != 2) {
			tlog(TLOG_ERROR, "recv socks5 auth ack from %s failed", proxy_conn->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->buffer.len = 0;

		if (proxy_conn->buffer.buffer[0] != 0x1) {
			tlog(TLOG_ERROR, "server %s not support socks5", proxy_conn->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		if (proxy_conn->buffer.buffer[1] != 0x0) {
			tlog(TLOG_ERROR, "server %s auth failed, incorrect user or password, code: %d",
				 proxy_conn->server_info->proxy_name, proxy_conn->buffer.buffer[1]);
			return PROXY_HANDSHAKE_ERR;
		}

		tlog(TLOG_DEBUG, "server %s auth success", proxy_conn->server_info->proxy_name);
		proxy_conn->state = PROXY_CONN_CONNECTING;
		return _proxy_handshake_socks5_reply_connect_addr(proxy_conn);
	case PROXY_CONN_CONNECTING: {
		unsigned char addr[16];
		unsigned short port = 0;
		int use_dest_ip = 0;
		char *recv_buff = NULL;

		int addr_len = 0;
		len = recv(proxy_conn->fd, proxy_conn->buffer.buffer + proxy_conn->buffer.len,
				   sizeof(proxy_conn->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			if (len == 0) {
				tlog(TLOG_ERROR, "server %s closed connection", proxy_conn->server_info->proxy_name);
			} else {
				tlog(TLOG_ERROR, "recv socks5 connect ack from %s failed, %s", proxy_conn->server_info->proxy_name,
					 strerror(errno));
			}

			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->buffer.len += len;
		if (proxy_conn->buffer.len < 10) {
			return PROXY_HANDSHAKE_WANT_READ;
		}
		recv_buff = proxy_conn->buffer.buffer;

		if (recv_buff[0] != PROXY_SOCKS5_VERSION) {
			tlog(TLOG_ERROR, "server %s not support socks5", proxy_conn->server_info->proxy_name);
			return PROXY_HANDSHAKE_ERR;
		}

		if (recv_buff[1] != 0) {
			if ((unsigned char)recv_buff[1] <=
				(sizeof(proxy_socks5_status_code) / sizeof(proxy_socks5_status_code[0]))) {
				tlog(TLOG_ERROR, "server %s reply failed, error-code: %s", proxy_conn->server_info->proxy_name,
					 proxy_socks5_status_code[(int)recv_buff[1]]);
			} else {
				tlog(TLOG_ERROR, "server %s reply failed, error-code: %x", proxy_conn->server_info->proxy_name,
					 recv_buff[1]);
			}
			return PROXY_HANDSHAKE_ERR;
		}

		switch (recv_buff[3]) {
		case PROXY_SOCKS5_TYPE_IPV4: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)&proxy_conn->udp_dest_addr;
			proxy_conn->udp_dest_addrlen = sizeof(struct sockaddr_in);
			if (proxy_conn->buffer.len < 10) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			addr_len = 4;
			memcpy(addr, recv_buff + 4, addr_len);
			port = ntohs(*((short *)(recv_buff + 4 + addr_len)));
			addr_in->sin_family = AF_INET;
			addr_in->sin_addr.s_addr = *((int *)addr);
			addr_in->sin_port = *((short *)(recv_buff + 4 + addr_len));
			if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0) {
				use_dest_ip = 1;
			}

			tlog(TLOG_DEBUG, "server %s proxy dest: %d.%d.%d.%d:%d\n", proxy_conn->server_info->proxy_name, addr[0],
				 addr[1], addr[2], addr[3], port);
		} break;
		case PROXY_SOCKS5_TYPE_IPV6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&proxy_conn->udp_dest_addr;
			proxy_conn->udp_dest_addrlen = sizeof(struct sockaddr_in6);
			if (proxy_conn->buffer.len < 22) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			addr_len = 16;
			memcpy(addr, recv_buff + 4, addr_len);
			port = ntohs(*((short *)(recv_buff + 4 + addr_len)));
			addr_in6->sin6_family = AF_INET6;
			memcpy(addr_in6->sin6_addr.s6_addr, addr, addr_len);
			addr_in6->sin6_port = *((short *)(recv_buff + 4 + addr_len));

			if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 && addr[4] == 0 && addr[5] == 0 &&
				addr[6] == 0 && addr[7] == 0 && addr[8] == 0 && addr[9] == 0 && addr[10] == 0 && addr[11] == 0 &&
				addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 0) {
				use_dest_ip = 1;
			}

			tlog(TLOG_DEBUG, "server %s proxy dest: [%x:%x:%x:%x:%x:%x:%x:%x]:%d\n",
				 proxy_conn->server_info->proxy_name, ntohs(*((short *)addr)), ntohs(*((short *)(addr + 2))),
				 ntohs(*((short *)(addr + 4))), ntohs(*((short *)(addr + 6))), ntohs(*((short *)(addr + 8))),
				 ntohs(*((short *)(addr + 10))), ntohs(*((short *)(addr + 12))), ntohs(*((short *)(addr + 14))), port);
		} break;
		default:
			return PROXY_HANDSHAKE_ERR;
		}

		if (use_dest_ip && proxy_conn->is_udp) {
			memcpy(&proxy_conn->udp_dest_addr, &proxy_conn->server_info->server_addr,
				   proxy_conn->server_info->server_addrlen);
			proxy_conn->udp_dest_addrlen = proxy_conn->server_info->server_addrlen;
			switch (proxy_conn->udp_dest_addr.ss_family) {
			case AF_INET: {
				struct sockaddr_in *addr_in = NULL;
				addr_in = (struct sockaddr_in *)&proxy_conn->udp_dest_addr;
				addr_in->sin_port = *((short *)(recv_buff + 4 + addr_len));
			} break;
			case AF_INET6: {
				struct sockaddr_in6 *addr_in6 = NULL;
				addr_in6 = (struct sockaddr_in6 *)&proxy_conn->udp_dest_addr;
				addr_in6->sin6_port = *((short *)(recv_buff + 4 + addr_len));
			} break;
			default:
				return PROXY_HANDSHAKE_ERR;
				break;
			}
		}

		if (_proxy_handshake_socks5_connect_udp(proxy_conn) != 0) {
			return PROXY_HANDSHAKE_ERR;
		}

		proxy_conn->state = PROXY_CONN_CONNECTED;
		tlog(TLOG_DEBUG, "success connect to socks5 proxy server %s", proxy_conn->server_info->proxy_name);
		return PROXY_HANDSHAKE_CONNECTED;
	} break;
	default:
		tlog(TLOG_ERROR, "client socks5 status %d is invalid", proxy_conn->state);
		return PROXY_HANDSHAKE_ERR;
	}

	return PROXY_HANDSHAKE_ERR;
}

static int _proxy_handshake_http(struct proxy_conn *proxy_conn)
{
	int len = 0;
	proxy_handshake_state ret = PROXY_HANDSHAKE_ERR;
	char buff[4096];
	struct http_head *http_head = NULL;

	switch (proxy_conn->state) {
	case PROXY_CONN_INIT: {
		char connecthost[DNS_MAX_CNAME_LEN * 2];
		struct sockaddr_storage addr;

		socklen_t addr_len = sizeof(addr);
		getaddr_by_host(proxy_conn->host, (struct sockaddr *)&addr, &addr_len);

		if (proxy_conn->server_info->info.use_domain) {
			snprintf(connecthost, sizeof(connecthost), "%s:%d", proxy_conn->host, proxy_conn->port);
		} else {
			struct sockaddr_in *addr_in;
			addr_in = (struct sockaddr_in *)&addr;
			unsigned char *paddr = (unsigned char *)&addr_in->sin_addr.s_addr;
			snprintf(connecthost, sizeof(connecthost), "%d.%d.%d.%d:%d", paddr[0], paddr[1], paddr[2], paddr[3],
					 proxy_conn->port);
		}

		int msglen = 0;

		if (proxy_conn->server_info->info.username[0] == '\0') {
			msglen = snprintf(buff, sizeof(buff),
							  "CONNECT %s HTTP/1.1\r\n"
							  "Host: %s\r\n"
							  "Proxy-Connection: Keep-Alive\r\n\r\n",
							  connecthost, connecthost);
		} else {
			char auth[256];
			char base64_auth[256 * 2];
			snprintf(auth, sizeof(auth), "%s:%s", proxy_conn->server_info->info.username,
					 proxy_conn->server_info->info.password);
			SSL_base64_encode(auth, strlen(auth), base64_auth);

			msglen = snprintf(buff, sizeof(buff),
							  "CONNECT %s HTTP/1.1\r\n"
							  "Host: %s\r\n"
							  "Proxy-Authorization: Basic %s\r\n"
							  "Proxy-Connection: Keep-Alive\r\n\r\n",
							  connecthost, connecthost, base64_auth);
		}

		len = send(proxy_conn->fd, buff, msglen, MSG_NOSIGNAL);
		if (len != msglen) {
			tlog(TLOG_ERROR, "connect to https proxy server %s failed, %s", proxy_conn->server_info->proxy_name,
				 strerror(errno));
			goto out;
		}

		proxy_conn->state = PROXY_CONN_CONNECTING;
		ret = PROXY_HANDSHAKE_WANT_READ;
		goto out;
	} break;
	case PROXY_CONN_CONNECTING: {
		http_head = http_head_init(4096);
		if (http_head == NULL) {
			goto out;
		}

		len = recv(proxy_conn->fd, proxy_conn->buffer.buffer + proxy_conn->buffer.len,
				   sizeof(proxy_conn->buffer.buffer), 0);
		if (len <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return PROXY_HANDSHAKE_WANT_READ;
			}

			if (len == 0) {
				tlog(TLOG_ERROR, "remote server %s closed.", proxy_conn->server_info->proxy_name);
			} else {
				tlog(TLOG_ERROR, "recv from %s failed, %s", proxy_conn->server_info->proxy_name, strerror(errno));
			}
			goto out;
		}
		proxy_conn->buffer.len += len;

		len = http_head_parse(http_head, proxy_conn->buffer.buffer, proxy_conn->buffer.len);
		if (len < 0) {
			if (len == -1) {
				ret = PROXY_HANDSHAKE_WANT_READ;
				goto out;
			}

			tlog(TLOG_DEBUG, "remote server %s not supported.", proxy_conn->server_info->proxy_name);
			goto out;
		}

		if (http_head_get_httpcode(http_head) != 200) {
			tlog(TLOG_WARN, "http server %s query failed, server return http code : %d, %s",
				 proxy_conn->server_info->proxy_name, http_head_get_httpcode(http_head),
				 http_head_get_httpcode_msg(http_head));
			goto out;
		}

		proxy_conn->buffer.len -= len;
		if (proxy_conn->buffer.len > 0) {
			memmove(proxy_conn->buffer.buffer, proxy_conn->buffer.buffer + len, proxy_conn->buffer.len);
		}

		if (proxy_conn->buffer.len < 0) {
			proxy_conn->buffer.len = 0;
		}
		tlog(TLOG_DEBUG, "success connect to http proxy server %s", proxy_conn->server_info->proxy_name);
		proxy_conn->state = PROXY_CONN_CONNECTED;
		ret = PROXY_HANDSHAKE_CONNECTED;
		goto out;
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

proxy_handshake_state proxy_conn_handshake(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return -1;
	}

	if (proxy_conn->state == PROXY_CONN_CONNECTED) {
		return PROXY_HANDSHAKE_OK;
	}

	switch (proxy_conn->type) {
	case PROXY_SOCKS5:
		return _proxy_handshake_socks5(proxy_conn);
	case PROXY_HTTP:
		return _proxy_handshake_http(proxy_conn);
	default:
		return PROXY_HANDSHAKE_ERR;
	}

	return PROXY_HANDSHAKE_ERR;
}

static int _proxy_is_tcp_connected(struct proxy_conn *proxy_conn)
{
	char buff[1];
	int ret = 0;
	ret = recv(proxy_conn->fd, buff, 1, MSG_PEEK | MSG_DONTWAIT);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 1;
		}
	}
	return 0;
}

int proxy_conn_sendto(struct proxy_conn *proxy_conn, const void *buf, size_t len, int flags,
					  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	char buffer[PROXY_BUFFER_SIZE];
	int buffer_len = 0;
	int ret = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	if (_proxy_is_tcp_connected(proxy_conn) == 0) {
		errno = ECONNRESET;
		return -1;
	}

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
		return -1;
	}

	if (sizeof(buffer) - buffer_len <= len) {
		errno = ENOSPC;
		return -1;
	}

	memcpy(buffer + buffer_len, buf, len);
	buffer_len += len;

	ret = sendto(proxy_conn->udp_fd, buffer, buffer_len, MSG_NOSIGNAL, (struct sockaddr *)&proxy_conn->udp_dest_addr,
				 proxy_conn->udp_dest_addrlen);
	if (ret != buffer_len) {
		return -1;
	}

	return len;
}

int proxy_conn_recvfrom(struct proxy_conn *proxy_conn, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						socklen_t *addrlen)
{
	char buffer[PROXY_BUFFER_SIZE];
	int buffer_len = 0;
	int ret = 0;

	if (proxy_conn == NULL) {
		return -1;
	}

	ret = recvfrom(proxy_conn->udp_fd, buffer, sizeof(buffer), MSG_NOSIGNAL, NULL, NULL);
	if (ret <= 0) {
		return -1;
	}

	if (buffer[0] != 0x00 || buffer[1] != 0x00 || buffer[2] != 0x00) {
		return -1;
	}

	switch (buffer[3]) {
	case PROXY_SOCKS5_TYPE_IPV4:
		if (ret < 10) {
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

		return -1;
	}

	if (ret - buffer_len > (int)len) {
		return -1;
	}

	memcpy(buf, buffer + buffer_len, ret - buffer_len);
	return ret - buffer_len;
}

int proxy_conn_get_fd(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return -1;
	}

	return proxy_conn->fd;
}

int proxy_conn_get_udpfd(struct proxy_conn *proxy_conn)
{
	if (proxy_conn == NULL) {
		return -1;
	}

	return proxy_conn->udp_fd;
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
	
	return ;
}
