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

#ifndef SMART_DNS_PROXY_H
#define SMART_DNS_PROXY_H

#include <sys/socket.h>
#include <sys/types.h>

#define PROXY_MAX_IPLEN 256
#define PROXY_MAX_NAMELEN 128

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

typedef enum {
	PROXY_SOCKS5,
	PROXY_HTTP,
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
	int use_domain;
	char username[PROXY_MAX_NAMELEN];
	char password[PROXY_MAX_NAMELEN];
};

struct proxy_conn;

int proxy_init(void);

void proxy_exit(void);

int proxy_add(const char *proxy_name, struct proxy_info *info);

int proxy_remove(const char *proxy_name);

struct proxy_conn *proxy_conn_new(const char *proxy_name, const char *host, int port, int is_udp);

int proxy_conn_get_fd(struct proxy_conn *proxy_conn);

int proxy_conn_get_udpfd(struct proxy_conn *proxy_conn);

int proxy_conn_is_udp(struct proxy_conn *proxy_conn);

void proxy_conn_free(struct proxy_conn *proxy_conn);

int proxy_conn_connect(struct proxy_conn *proxy_conn);

int proxy_conn_sendto(struct proxy_conn *proxy_conn, const void *buf, size_t len, int flags,
					  const struct sockaddr *dest_addr, socklen_t addrlen);

int proxy_conn_recvfrom(struct proxy_conn *proxy_conn, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						socklen_t *addrlen);

proxy_handshake_state proxy_conn_handshake(struct proxy_conn *proxy_conn);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
