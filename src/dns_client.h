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

#ifndef _SMART_DNS_CLIENT_H
#define _SMART_DNS_CLIENT_H

#include "dns.h"

#ifdef __cpluscplus
extern "C" {
#endif

#define DNS_SERVER_SPKI_LEN 64
#define DNS_SERVER_GROUP_DEFAULT "default"

typedef enum {
	DNS_SERVER_UDP,
	DNS_SERVER_TCP,
	DNS_SERVER_TLS,
	DNS_SERVER_HTTPS,
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

int dns_client_init(void);

int dns_client_set_ecs(char *ip, int subnet);

/* query result notify function */
typedef int (*dns_client_callback)(char *domain, dns_result_type rtype, unsigned int result_flag,
								   struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
								   void *user_ptr);

/* query domain */
int dns_client_query(char *domain, int qtype, dns_client_callback callback, void *user_ptr, const char *group_name);

void dns_client_exit(void);

struct client_dns_server_flag_udp {
	int ttl;
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
	char path[DNS_MAX_CNAME_LEN];
	char tls_host_verify[DNS_MAX_CNAME_LEN];
	char skip_check_cert;
};

struct client_dns_server_flags {
	dns_server_type_t type;
	unsigned int server_flag;
	unsigned int result_flag;

	union {
		struct client_dns_server_flag_udp udp;
		struct client_dns_server_flag_tls tls;
		struct client_dns_server_flag_https https;
	};
};

int dns_client_spki_decode(const char *spki, unsigned char *spki_data_out);

/* add remote dns server */
int dns_client_add_server(char *server_ip, int port, dns_server_type_t server_type,
						  struct client_dns_server_flags *flags);

/* remove remote dns server */
int dns_client_remove_server(char *server_ip, int port, dns_server_type_t server_type);

int dns_client_add_group(char *group_name);

int dns_client_add_to_group(char *group_name, char *server_ip, int port, dns_server_type_t server_type);

int dns_client_remove_from_group(char *group_name, char *server_ip, int port, dns_server_type_t server_type);

int dns_client_remove_group(char *group_name);

int dns_server_num(void);

#ifdef __cpluscplus
}
#endif
#endif
