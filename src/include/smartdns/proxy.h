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

#ifndef SMART_DNS_PROXY_H
#define SMART_DNS_PROXY_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include "smartdns/lib/list.h"

#define PROXY_MAX_IPLEN 256
#define PROXY_MAX_NAMELEN 128

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

typedef enum {
	PROXY_PASSTHROUGH,
	PROXY_SOCKS5,
	PROXY_SOCKS5S,
	PROXY_HTTP,
	PROXY_HTTPS,
	PROXY_TYPE_END,
} proxy_type_t;

typedef enum {
	PROXY_HANDSHAKE_ERR = -1,
	PROXY_HANDSHAKE_OK = 0,
	PROXY_HANDSHAKE_CONNECTED = 1,
	PROXY_HANDSHAKE_WANT_READ = 2,
	PROXY_HANDSHAKE_WANT_WRITE = 3,
} proxy_handshake_state;

struct proxy_info {
	proxy_type_t type;
	char server[PROXY_MAX_IPLEN];
	unsigned short port;
	char username[PROXY_MAX_NAMELEN];
	char password[PROXY_MAX_NAMELEN];
	int fallback;
};
#define PROXY_SERVER_PASS_THROUGH "-"

struct proxy_conn;
struct proxy_conn;
struct proxy_server_info;


typedef enum PROXY_CONN_STATE {
	PROXY_STATE_INIT = 0,
	PROXY_STATE_CONNECTING = 1,      /* TCP connecting */
	PROXY_STATE_HANDSHAKING = 2,     /* Performing protocol handshake */
	PROXY_STATE_CONNECTED = 3,       /* Handshake successful, ready for data */
	PROXY_STATE_DISCONNECTED = 4,    /* Connection closed or failed */
} PROXY_CONN_STATE;

/* Opaque channel handle */
struct proxy_channel;

struct proxy_channel *proxy_channel_server_new(int fd, proxy_type_t type);
struct proxy_channel *proxy_channel_accept(struct proxy_channel *listener);
void proxy_channel_free(struct proxy_channel *channel);

int proxy_channel_ctl(struct proxy_channel *channel, int epoll_fd, int op, struct epoll_event *event);
int proxy_channel_recv(struct proxy_channel *channel, void *buf, size_t len, int flags);
int proxy_channel_send(struct proxy_channel *channel, const void *buf, size_t len, int flags);
int proxy_channel_shutdown(struct proxy_channel *channel, int how);

void proxy_channel_get_target(struct proxy_channel *channel, char *host, int host_len, unsigned short *port);
int proxy_channel_is_udp(struct proxy_channel *channel);
void proxy_channel_get_addr(struct proxy_channel *channel, struct sockaddr *addr, socklen_t *addrlen);
const char *proxy_channel_get_last_error_str(struct proxy_channel *channel);
int proxy_channel_get_opt_error(struct proxy_channel *channel);
int proxy_channel_get_last_error(struct proxy_channel *channel);



int proxy_init(void);

void proxy_exit(void);

int proxy_add(const char *proxy_name, struct proxy_info *info);

int proxy_remove(const char *proxy_name);

struct proxy_conn *proxy_conn_new(const char *proxy_name, const char *host, int port, int is_udp, int non_block);

int proxy_conn_is_udp(struct proxy_conn *proxy_conn);

void proxy_conn_free(struct proxy_conn *proxy_conn);

int proxy_conn_connect(struct proxy_conn *proxy_conn);

/* I/O functions that don't expose FDs */
int proxy_conn_send(struct proxy_conn *proxy_conn, const void *buf, size_t len, int flags);

int proxy_conn_recv(struct proxy_conn *proxy_conn, void *buf, size_t len, int flags);

int proxy_conn_sendto(struct proxy_conn *proxy_conn, const void *buf, size_t len, int flags,
					  const struct sockaddr *dest_addr, socklen_t addrlen);

int proxy_conn_recvfrom(struct proxy_conn *proxy_conn, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						socklen_t *addrlen);

int proxy_conn_shutdown(struct proxy_conn *proxy_conn, int how);

proxy_handshake_state proxy_channel_handshake(struct proxy_channel *channel, int epoll_fd);

int proxy_conn_get_last_error(struct proxy_conn *proxy_conn);

const char *proxy_handshake_error_to_string(int error_code);

int proxy_conn_is_ipv6_target(struct proxy_conn *proxy_conn);

/* Epoll management - matches epoll_ctl signature for easy migration */
int proxy_conn_ctl(struct proxy_conn *proxy_conn, int epoll_fd, int op, struct epoll_event *event);
int proxy_conn_set_so_mark(struct proxy_conn *proxy_conn, int mark);
int proxy_conn_set_ifname(struct proxy_conn *proxy_conn, const char *ifname);
int proxy_conn_set_tcp_fastopen(struct proxy_conn *proxy_conn, int enable);
int proxy_conn_set_keepalive(struct proxy_conn *proxy_conn, int idle, int intvl, int cnt);

/* Check if epoll event belongs to proxy channel */
int proxy_conn_is_epoll_event(void *ptr);

/* Get proxy_channel from epoll event */
struct proxy_channel *proxy_channel_get_from_event(void *ptr);

/* Get user data (e.g., server_info) from epoll event */
void *proxy_conn_get_event_userdata(void *ptr);
void proxy_conn_set_event_userdata(struct proxy_conn *proxy_conn, void *userdata);

void proxy_channel_set_server_auth(struct proxy_channel *channel, const char *user, const char *pass);

void proxy_channel_get_peeraddr(struct proxy_channel *channel, struct sockaddr *addr, socklen_t *addrlen);
void proxy_conn_get_peeraddr(struct proxy_conn *proxy_conn, struct sockaddr *addr, socklen_t *addrlen);
void proxy_conn_get_target(struct proxy_conn *proxy_conn, char *host, int host_len, unsigned short *port);
int proxy_conn_get_state(struct proxy_conn *proxy_conn);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
