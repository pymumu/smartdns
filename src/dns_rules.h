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

#ifndef _DNS_RULES
#define _DNS_RULES

#include <stdint.h>

#include "atomic.h"
#include "common.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

enum domain_rule {
	DOMAIN_RULE_FLAGS = 0,
	DOMAIN_RULE_ADDRESS_IPV4,
	DOMAIN_RULE_ADDRESS_IPV6,
	DOMAIN_RULE_IPSET,
	DOMAIN_RULE_IPSET_IPV4,
	DOMAIN_RULE_IPSET_IPV6,
	DOMAIN_RULE_NFTSET_IP,
	DOMAIN_RULE_NFTSET_IP6,
	DOMAIN_RULE_NAMESERVER,
	DOMAIN_RULE_GROUP,
	DOMAIN_RULE_CHECKSPEED,
	DOMAIN_RULE_RESPONSE_MODE,
	DOMAIN_RULE_CNAME,
	DOMAIN_RULE_HTTPS,
	DOMAIN_RULE_TTL,
	DOMAIN_RULE_MAX,
};

struct dns_rule {
	atomic_t refcnt;
	enum domain_rule rule;
};

#define DOMAIN_FLAG_ADDR_SOA (1 << 0)
#define DOMAIN_FLAG_ADDR_IPV4_SOA (1 << 1)
#define DOMAIN_FLAG_ADDR_IPV6_SOA (1 << 2)
#define DOMAIN_FLAG_ADDR_IGN (1 << 3)
#define DOMAIN_FLAG_ADDR_IPV4_IGN (1 << 4)
#define DOMAIN_FLAG_ADDR_IPV6_IGN (1 << 5)
#define DOMAIN_FLAG_IPSET_IGN (1 << 6)
#define DOMAIN_FLAG_IPSET_IPV4_IGN (1 << 7)
#define DOMAIN_FLAG_IPSET_IPV6_IGN (1 << 8)
#define DOMAIN_FLAG_NAMESERVER_IGNORE (1 << 9)
#define DOMAIN_FLAG_DUALSTACK_SELECT (1 << 10)
#define DOMAIN_FLAG_SMARTDNS_DOMAIN (1 << 11)
#define DOMAIN_FLAG_NFTSET_INET_IGN (1 << 12)
#define DOMAIN_FLAG_NFTSET_IP_IGN (1 << 13)
#define DOMAIN_FLAG_NFTSET_IP6_IGN (1 << 14)
#define DOMAIN_FLAG_NO_SERVE_EXPIRED (1 << 15)
#define DOMAIN_FLAG_CNAME_IGN (1 << 16)
#define DOMAIN_FLAG_NO_CACHE (1 << 17)
#define DOMAIN_FLAG_NO_IPALIAS (1 << 18)
#define DOMAIN_FLAG_GROUP_IGNORE (1 << 19)
#define DOMAIN_FLAG_ENABLE_CACHE (1 << 20)
#define DOMAIN_FLAG_ADDR_HTTPS_SOA (1 << 21)
#define DOMAIN_FLAG_ADDR_HTTPS_IGN (1 << 22)

struct dns_rule_flags {
	struct dns_rule head;
	unsigned int flags;
	unsigned int is_flag_set;
};

struct dns_rule_address_IPV4 {
	struct dns_rule head;
	char addr_num;
	unsigned char ipv4_addr[][DNS_RR_A_LEN];
};

struct dns_rule_address_IPV6 {
	struct dns_rule head;
	char addr_num;
	unsigned char ipv6_addr[][DNS_RR_AAAA_LEN];
};

struct dns_ipset_rule {
	struct dns_rule head;
	const char *ipsetname;
};

struct dns_nftset_rule {
	struct dns_rule head;
	const char *familyname;
	const char *nfttablename;
	const char *nftsetname;
};

struct dns_nameserver_rule {
	struct dns_rule head;
	const char *group_name;
};

struct dns_group_rule {
	struct dns_rule head;
	const char *group_name;
};

typedef enum {
	DOMAIN_CHECK_NONE = 0,
	DOMAIN_CHECK_ICMP = 1,
	DOMAIN_CHECK_TCP = 2,
	DOMAIN_CHECK_NUM = 3,
} DOMAIN_CHECK_TYPE;

struct dns_domain_check_order {
	DOMAIN_CHECK_TYPE type;
	unsigned short tcp_port;
};

struct dns_domain_check_orders {
	struct dns_rule head;
	struct dns_domain_check_order orders[DOMAIN_CHECK_NUM];
};

enum response_mode_type {
	DNS_RESPONSE_MODE_FIRST_PING_IP = 0,
	DNS_RESPONSE_MODE_FASTEST_IP,
	DNS_RESPONSE_MODE_FASTEST_RESPONSE,
};

struct dns_response_mode_rule {
	struct dns_rule head;
	enum response_mode_type mode;
};

struct dns_cname_rule {
	struct dns_rule head;
	char cname[DNS_MAX_CNAME_LEN];
};

struct dns_https_record {
	int enable;
	char target[DNS_MAX_CNAME_LEN];
	int priority;
	char alpn[DNS_MAX_ALPN_LEN];
	int alpn_len;
	int port;
	unsigned char ech[DNS_MAX_ECH_LEN];
	int ech_len;
	int has_ipv4;
	unsigned char ipv4_addr[DNS_RR_A_LEN];
	int has_ipv6;
	unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
};

struct dns_https_filter {
	int no_ipv4hint;
	int no_ipv6hint;
};

struct dns_https_record_rule {
	struct dns_rule head;
	struct dns_https_record record;
	struct dns_https_filter filter;
};

struct dns_ttl_rule {
	struct dns_rule head;
	int ttl;
	int ttl_max;
	int ttl_min;
};

void *_new_dns_rule_ext(enum domain_rule domain_rule, int ext_size);
void *_new_dns_rule(enum domain_rule domain_rule);
void _dns_rule_put(struct dns_rule *rule);

struct dns_domain_rule *domain_rule_new(uint8_t capacity);
int domain_rule_free(struct dns_domain_rule *domain_rule);
// ensures users can't directly modify `struct dns_domain_rule`
int domain_rule_get_data(struct dns_domain_rule *domain_rule, int *sub_rule_only, int *root_rule_only);
int domain_rule_set_data(struct dns_domain_rule *domain_rule, int sub_rule_only, int root_rule_only);
/**
 * Get rule without allocation.
 */
struct dns_rule *domain_rule_get(struct dns_domain_rule *domain_rule, enum domain_rule type);
/**
 * Get flags rule with essentially allocation.
 */
struct dns_rule_flags *domain_rule_get_or_insert_flags(struct dns_domain_rule *domain_rule);
int domain_rule_set(struct dns_domain_rule *domain_rule, enum domain_rule type, struct dns_rule *rule);

#ifdef __cplusplus
}
#endif
#endif // !_DNS_RULES