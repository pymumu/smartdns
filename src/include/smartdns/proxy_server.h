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

#ifndef _SMART_DNS_PROXY_SERVER_H
#define _SMART_DNS_PROXY_SERVER_H

#include <sys/socket.h>
#include "dns_conf.h"

#ifdef __cpluscplus
extern "C" {
#endif

#define PROXY_SERVER_MAX_IPLEN 64
#define PROXY_SERVER_NAME_LEN 32

typedef enum {
	PROXY_SERVER_PASSTHROUGH,
	PROXY_SERVER_SOCKS5,
	PROXY_SERVER_HTTPS,
	PROXY_SERVER_TYPE_END,
} proxy_server_type_t;

struct proxy_server_info {
	proxy_server_type_t type;
	char host[PROXY_SERVER_MAX_IPLEN];
	int port;
	char user[64];
	char pass[64];
};

struct proxy_server_conn;
struct proxy_server_opt {
	int (*open)(struct proxy_server_conn *conn, char *ip, int port);
	int (*pre_connect)(struct proxy_server_conn *conn);
	int (*on_connect)(struct proxy_server_conn *conn);
	int (*send)(struct proxy_server_conn *conn);
	int (*recv)(struct proxy_server_conn *conn);
	int (*close)(struct proxy_server_conn *conn);
};

int proxy_server_init(void);

void proxy_server_exit(void);

int tproxy_get_original_dst(int fd, struct sockaddr_storage *orig_dst, socklen_t *addr_len);

struct firewall_sets {
	struct dns_ipset_rule *ipset_ipv4;
	struct dns_ipset_rule *ipset_ipv6;
	struct dns_nftset_rule *nftset_ipv4;
	struct dns_nftset_rule *nftset_ipv6;
};

int tproxy_server_get_firewall_sets(const char *proxy_name, struct firewall_sets *sets);

const char *tproxy_server_get_group_name(const char *proxy_name);

const char *sniproxy_server_get_group_name(const char *proxy_name);

#ifdef __cpluscplus
}
#endif
#endif
