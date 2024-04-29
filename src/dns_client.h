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

#ifndef _SMART_DNS_CLIENT_H
#define _SMART_DNS_CLIENT_H

#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_SERVER_IFNAME_LEN 16
#define DNS_SERVER_SPKI_LEN 64
#define DNS_SERVER_GROUP_DEFAULT "default"
#define DNS_SERVER_GROUP_MDNS "mdns"
#define DNS_SERVER_GROUP_LOCAL "local"
#ifdef TEST
#define DNS_MDNS_IP "127.0.0.1"
#define DNS_MDNS_PORT 55353
#else
#define DNS_MDNS_IP "224.0.0.251"
#define DNS_MDNS_PORT 5353
#endif

typedef enum {
	DNS_SERVER_UDP,
	DNS_SERVER_TCP,
	DNS_SERVER_TLS,
	DNS_SERVER_HTTPS,
	DNS_SERVER_MDNS,
	DNS_SERVER_TYPE_END,
} dns_server_type_t;

typedef enum dns_result_type {
	DNS_QUERY_ERR,
	DNS_QUERY_RESULT = 1,
	DNS_QUERY_END,
} dns_result_type;

#define DNSSERVER_FLAG_BLACKLIST_IP (0x1 << 0)
#define DNSSERVER_FLAG_WHITELIST_IP (0x1 << 1)
#define DNSSERVER_FLAG_CHECK_EDNS (0x1 << 2)
#define DNSSERVER_FLAG_CHECK_TTL (0x1 << 3)

#define DNS_QUEY_OPTION_ECS_DNS (1 << 0)
#define DNS_QUEY_OPTION_ECS_IP (1 << 1)
#define DNS_QUEY_OPTION_EDNS0_DO (1 << 2)

int dns_client_init(void);

int dns_client_set_ecs(char *ip, int subnet);

struct dns_server_info;
/* query result notify function */
#define DNS_CLIENT_ACTION_OK 0
#define DNS_CLIENT_ACTION_UNDEFINE (-1)
#define DNS_CLIENT_ACTION_DROP (-2)
#define DNS_CLIENT_ACTION_RETRY (-3)
#define DNS_CLIENT_ACTION_MAY_RETRY (-4)
typedef int (*dns_client_callback)(const char *domain, dns_result_type rtype, struct dns_server_info *server_info,
								   struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
								   void *user_ptr);

unsigned int dns_client_server_result_flag(struct dns_server_info *server_info);

const char *dns_client_get_server_ip(struct dns_server_info *server_info);

int dns_client_get_server_port(struct dns_server_info *server_info);

dns_server_type_t dns_client_get_server_type(struct dns_server_info *server_info);

struct dns_query_ecs_ip {
	char ip[DNS_MAX_CNAME_LEN];
	int subnet;
};

struct dns_query_options {
	unsigned long long enable_flag;
	struct dns_opt_ecs ecs_dns;
	struct dns_query_ecs_ip ecs_ip;
	const char *conf_group_name;
};

/* query domain */
int dns_client_query(const char *domain, int qtype, dns_client_callback callback, void *user_ptr,
					 const char *group_name, struct dns_query_options *options);

void dns_client_exit(void);

struct client_dns_server_flag_udp {
	int ttl;
};

struct client_dns_server_flag_mdns {
};

struct client_dns_server_flag_tls {
	char spki[DNS_SERVER_SPKI_LEN];
	int spi_len;
	char hostname[DNS_MAX_CNAME_LEN];
	char tls_host_verify[DNS_MAX_CNAME_LEN];
	char skip_check_cert;
};

struct client_dns_server_flag_https {
	char spki[DNS_SERVER_SPKI_LEN];
	int spi_len;
	char hostname[DNS_MAX_CNAME_LEN];
	char httphost[DNS_MAX_CNAME_LEN];
	char proxyname[DNS_MAX_CNAME_LEN];
	char path[DNS_MAX_CNAME_LEN];
	char tls_host_verify[DNS_MAX_CNAME_LEN];
	char skip_check_cert;
};

struct client_dns_server_flag_ecs {
	int enable;
	char ip[DNS_MAX_CNAME_LEN];
	int subnet;
};

struct client_dns_server_flags {
	dns_server_type_t type;
	unsigned int server_flag;
	unsigned int result_flag;
	long long set_mark;
	int drop_packet_latency_ms;
	char proxyname[DNS_MAX_CNAME_LEN];
	char ifname[DNS_SERVER_IFNAME_LEN];
	struct client_dns_server_flag_ecs ipv4_ecs;
	struct client_dns_server_flag_ecs ipv6_ecs;

	union {
		struct client_dns_server_flag_udp udp;
		struct client_dns_server_flag_tls tls;
		struct client_dns_server_flag_https https;
		struct client_dns_server_flag_mdns mdns;
	};
};

int dns_client_spki_decode(const char *spki, unsigned char *spki_data_out, int spki_data_out_max_len);

/* add remote dns server */
int dns_client_add_server(char *server_ip, int port, dns_server_type_t server_type,
						  struct client_dns_server_flags *flags);

/* remove remote dns server */
int dns_client_remove_server(char *server_ip, int port, dns_server_type_t server_type);

int dns_client_add_group(const char *group_name);

int dns_client_add_to_group(const char *group_name, char *server_ip, int port, dns_server_type_t server_type,
							struct client_dns_server_flags *flags);

int dns_client_remove_from_group(const char *group_name, char *server_ip, int port, dns_server_type_t server_type,
								 struct client_dns_server_flags *flags);

int dns_client_remove_group(const char *group_name);

int dns_server_alive_num(void);

int dns_server_num(void);

#ifdef __cplusplus
}
#endif
#endif
