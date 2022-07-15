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

#ifndef _DNS_CONF
#define _DNS_CONF

#include "art.h"
#include "atomic.h"
#include "conf.h"
#include "dns.h"
#include "dns_client.h"
#include "hash.h"
#include "hashtable.h"
#include "list.h"
#include "radix.h"

#ifdef __cpluscplus
extern "C" {
#endif

#define DNS_MAX_BIND_IP 16
#define DNS_MAX_SERVERS 64
#define DNS_MAX_SERVER_NAME_LEN 128
#define DNS_MAX_PTR_LEN 128
#define DNS_MAX_IPSET_NAMELEN 32
#define DNS_MAX_NFTSET_FAMILYLEN 8
#define DNS_MAX_NFTSET_NAMELEN 256
#define DNS_GROUP_NAME_LEN 32
#define DNS_NAX_GROUP_NUMBER 16
#define DNS_MAX_IPLEN 64
#define DNS_CONF_USRNAME_LEN 32
#define DNS_MAX_SPKI_LEN 64
#define DNS_MAX_URL_LEN 256
#define DNS_MAX_PATH 1024
#define DEFAULT_DNS_PORT 53
#define DEFAULT_DNS_TLS_PORT 853
#define DEFAULT_DNS_HTTPS_PORT 443
#define DNS_MAX_CONF_CNAME_LEN 256
#define SMARTDNS_CONF_FILE "/etc/smartdns/smartdns.conf"
#define SMARTDNS_LOG_FILE "/var/log/smartdns/smartdns.log"
#define SMARTDNS_AUDIT_FILE "/var/log/smartdns/smartdns-audit.log"
#define SMARTDNS_CACHE_FILE "/tmp/smartdns.cache"
#define SMARTDNS_DEBUG_DIR "/tmp/smartdns"

enum domain_rule {
	DOMAIN_RULE_FLAGS = 0,
	DOMAIN_RULE_ADDRESS_IPV4,
	DOMAIN_RULE_ADDRESS_IPV6,
	DOMAIN_RULE_IPSET,
	DOMAIN_RULE_IPSET_IPV4,
	DOMAIN_RULE_IPSET_IPV6,
#ifdef WITH_NFTSET
	DOMAIN_RULE_NFTSET_IP,
	DOMAIN_RULE_NFTSET_IP6,
#endif
	DOMAIN_RULE_NAMESERVER,
	DOMAIN_RULE_CHECKSPEED,
	DOMAIN_RULE_MAX,
};

typedef enum {
	DNS_BIND_TYPE_UDP,
	DNS_BIND_TYPE_TCP,
	DNS_BIND_TYPE_TLS,
} DNS_BIND_TYPE;

#define DOMAIN_CHECK_NONE 0
#define DOMAIN_CHECK_ICMP 1
#define DOMAIN_CHECK_TCP 2
#define DOMAIN_CHECK_NUM 3

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
#ifdef WITH_NFTSET
#define DOMAIN_FLAG_NFTSET_INET_IGN (1 << 12)
#define DOMAIN_FLAG_NFTSET_IP_IGN (1 << 13)
#define DOMAIN_FLAG_NFTSET_IP6_IGN (1 << 14)
#endif

#define SERVER_FLAG_EXCLUDE_DEFAULT (1 << 0)

#define BIND_FLAG_NO_RULE_ADDR (1 << 0)
#define BIND_FLAG_NO_RULE_NAMESERVER (1 << 1)
#define BIND_FLAG_NO_RULE_IPSET (1 << 2)
#define BIND_FLAG_NO_RULE_SNIPROXY (1 << 3)
#define BIND_FLAG_NO_RULE_SOA (1 << 4)
#define BIND_FLAG_NO_SPEED_CHECK (1 << 5)
#define BIND_FLAG_NO_CACHE (1 << 6)
#define BIND_FLAG_NO_DUALSTACK_SELECTION (1 << 7)
#define BIND_FLAG_FORCE_AAAA_SOA (1 << 8)

struct dns_rule {
	atomic_t refcnt;
	enum domain_rule rule;
	char rule_data[];
};

struct dns_rule_flags {
	struct dns_rule head;
	unsigned int flags;
	unsigned int is_flag_set;
};

struct dns_rule_address_IPV4 {
	struct dns_rule head;
	unsigned char ipv4_addr[DNS_RR_A_LEN];
};

struct dns_rule_address_IPV6 {
	struct dns_rule head;
	unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
};

struct dns_ipset_name {
	struct hlist_node node;
	char ipsetname[DNS_MAX_IPSET_NAMELEN];
};

struct dns_ipset_rule {
	struct dns_rule head;
	const char *ipsetname;
};

#ifdef WITH_NFTSET
struct dns_nftset_name {
	struct hlist_node node;
	char nftfamilyname[DNS_MAX_NFTSET_FAMILYLEN];
	char nfttablename[DNS_MAX_NFTSET_NAMELEN];
	char nftsetname[DNS_MAX_NFTSET_NAMELEN];
};

struct dns_nftset_rule {
	struct dns_rule head;
	const char *familyname;
	const char *nfttablename;
	const char *nftsetname;
};
#endif

struct dns_domain_rule {
	struct dns_rule head;
	struct dns_rule *rules[DOMAIN_RULE_MAX];
};

struct dns_nameserver_rule {
	struct dns_rule head;
	const char *group_name;
};

struct dns_server_groups {
	struct hlist_node node;
	char group_name[DNS_GROUP_NAME_LEN];
	int server_num;
	struct dns_servers *servers[DNS_MAX_SERVERS];
};

struct dns_domain_check_order {
	char type;
	unsigned short tcp_port;
};

struct dns_domain_check_orders {
	struct dns_rule head;
	struct dns_domain_check_order orders[DOMAIN_CHECK_NUM];
};

struct dns_group_table {
	DECLARE_HASHTABLE(group, 8);
};
extern struct dns_group_table dns_group_table;

struct dns_ptr {
	struct hlist_node node;
	char ptr_domain[DNS_MAX_PTR_LEN];
	char hostname[DNS_MAX_CNAME_LEN];
};

struct dns_ptr_table {
	DECLARE_HASHTABLE(ptr, 16);
};
extern struct dns_ptr_table dns_ptr_table;

typedef enum dns_hosts_type {
	DNS_HOST_TYPE_HOST = 0,
	DNS_HOST_TYPE_DNSMASQ = 1,
} dns_hosts_type;

struct dns_hosts {
	struct hlist_node node;
	char domain[DNS_MAX_CNAME_LEN];
	dns_hosts_type host_type;
	int dns_type;
	int is_soa;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
	};
};

struct dns_hosts_table {
	DECLARE_HASHTABLE(hosts, 16);
};
extern struct dns_hosts_table dns_hosts_table;
extern int dns_hosts_record_num;

struct dns_servers {
	char server[DNS_MAX_IPLEN];
	unsigned short port;
	unsigned int result_flag;
	unsigned int server_flag;
	int ttl;
	dns_server_type_t type;
	char skip_check_cert;
	char spki[DNS_MAX_SPKI_LEN];
	char hostname[DNS_MAX_CNAME_LEN];
	char httphost[DNS_MAX_CNAME_LEN];
	char tls_host_verify[DNS_MAX_CNAME_LEN];
	char path[DNS_MAX_URL_LEN];
};

/* ip address lists of domain */
struct dns_bogus_ip_address {
	struct hlist_node node;
	dns_type_t addr_type;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

enum address_rule {
	ADDRESS_RULE_BLACKLIST = 1,
	ADDRESS_RULE_WHITELIST = 2,
	ADDRESS_RULE_BOGUS = 3,
	ADDRESS_RULE_IP_IGNORE = 4,
};

struct dns_ip_address_rule {
	unsigned int blacklist : 1;
	unsigned int whitelist : 1;
	unsigned int bogus : 1;
	unsigned int ip_ignore : 1;
};

struct dns_edns_client_subnet {
	int enable;
	char ip[DNS_MAX_IPLEN];
	int subnet;
};

struct dns_conf_address_rule {
	radix_tree_t *ipv4;
	radix_tree_t *ipv6;
};

struct dns_bind_ip {
	DNS_BIND_TYPE type;
	uint32_t flags;
	char ip[DNS_MAX_IPLEN];
	const char *group;
};

struct dns_qtype_soa_list {
	struct hlist_node node;
	uint32_t qtypeid;
};

struct dns_qtype_soa_table {
	DECLARE_HASHTABLE(qtype, 8);
};
extern struct dns_qtype_soa_table dns_qtype_soa_table;

struct dns_domain_set_rule {
	struct list_head list;
	enum domain_rule type;
	void *rule;
	unsigned int flags;
	unsigned int is_clear_flag;
};

struct dns_domain_set_rule_list {
	struct hlist_node node;
	char domain_set[DNS_MAX_CNAME_LEN];
	struct list_head domain_ruls_list;
};

struct dns_domain_set_rule_table {
	DECLARE_HASHTABLE(rule_list, 4);
};
extern struct dns_domain_set_rule_table dns_domain_set_rule_table;

enum dns_domain_set_type {
	DNS_DOMAIN_SET_LIST = 0,
	DNS_DOMAIN_SET_GEOSITE = 1,
};

struct dns_domain_set_name {
	struct list_head list;
	enum dns_domain_set_type type;
	char file[DNS_MAX_PATH];
};

struct dns_domain_set_name_list {
	struct hlist_node node;
	char name[DNS_MAX_CNAME_LEN];
	struct list_head set_name_list;
};
struct dns_domain_set_name_table {
	DECLARE_HASHTABLE(names, 4);
};
extern struct dns_domain_set_name_table dns_domain_set_name_table;

extern struct dns_bind_ip dns_conf_bind_ip[DNS_MAX_BIND_IP];
extern int dns_conf_bind_ip_num;

extern int dns_conf_tcp_idle_time;
extern int dns_conf_cachesize;
extern int dns_conf_prefetch;
extern int dns_conf_serve_expired;
extern int dns_conf_serve_expired_ttl;
extern int dns_conf_serve_expired_prefetch_time;
extern int dns_conf_serve_expired_reply_ttl;
extern struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
extern int dns_conf_server_num;

extern int dns_conf_log_level;
extern char dns_conf_log_file[DNS_MAX_PATH];
extern size_t dns_conf_log_size;
extern int dns_conf_log_num;

extern char dns_conf_ca_file[DNS_MAX_PATH];
extern char dns_conf_ca_path[DNS_MAX_PATH];

extern char dns_conf_cache_file[DNS_MAX_PATH];
extern int dns_conf_cache_persist;

extern struct dns_domain_check_orders dns_conf_check_orders;

extern struct dns_server_groups dns_conf_server_groups[DNS_NAX_GROUP_NUMBER];
extern int dns_conf_server_group_num;

extern int dns_conf_audit_enable;
extern int dns_conf_audit_log_SOA;
extern char dns_conf_audit_file[DNS_MAX_PATH];
extern size_t dns_conf_audit_size;
extern int dns_conf_audit_num;

extern char dns_conf_server_name[DNS_MAX_SERVER_NAME_LEN];
extern art_tree dns_conf_domain_rule;
extern struct dns_conf_address_rule dns_conf_address_rule;

extern int dns_conf_dualstack_ip_selection;
extern int dns_conf_dualstack_ip_allow_force_AAAA;
extern int dns_conf_dualstack_ip_selection_threshold;

extern int dns_conf_max_reply_ip_num;
enum response_mode_type {
	DNS_RESPONSE_MODE_FIRST_PING_IP = 0,
	DNS_RESPONSE_MODE_FASTEST_IP,
	DNS_RESPONSE_MODE_FASTEST_RESPONSE,
};
extern enum response_mode_type dns_conf_response_mode;

extern int dns_conf_rr_ttl;
extern int dns_conf_rr_ttl_reply_max;
extern int dns_conf_rr_ttl_min;
extern int dns_conf_rr_ttl_max;
extern int dns_conf_force_AAAA_SOA;
extern int dns_conf_ipset_timeout_enable;
extern int dns_conf_nftset_timeout_enable;
extern int dns_conf_local_ttl;

extern int dns_conf_force_no_cname;

extern char dns_conf_user[DNS_CONF_USRNAME_LEN];

extern struct dns_edns_client_subnet dns_conf_ipv4_ecs;
extern struct dns_edns_client_subnet dns_conf_ipv6_ecs;

extern char dns_conf_sni_proxy_ip[DNS_MAX_IPLEN];

extern int dns_save_fail_packet;
extern char dns_save_fail_packet_dir[DNS_MAX_PATH];
extern char dns_resolv_file[DNS_MAX_PATH];

void dns_server_load_exit(void);

int dns_server_load_conf(const char *file);

int dns_server_check_update_hosts(void);

extern int config_addtional_file(void *data, int argc, char *argv[]);
#ifdef __cpluscplus
}
#endif
#endif // !_DNS_CONF
