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

#ifndef _DNS_CONF
#define _DNS_CONF

#include "smartdns/dns.h"
#include "smartdns/dns_client.h"
#include "smartdns/lib/art.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/conf.h"
#include "smartdns/lib/hash.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/lib/radix.h"
#include "smartdns/proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_MAX_BIND_IP 32
#define DNS_MAX_SERVERS 64
#define DNS_MAX_SERVER_NAME_LEN 128
#define DNS_MAX_PTR_LEN 128
#define DNS_MAX_IPSET_NAMELEN 32
#define DNS_MAX_NFTSET_FAMILYLEN 8
#define DNS_MAX_NFTSET_NAMELEN 256
#define DNS_GROUP_NAME_LEN 32

#define PROXY_NAME_LEN 32
#define PROXY_MAX_SERVERS 128

#define DNS_NAX_GROUP_NUMBER 16
#define DNS_MAX_IPLEN 64
#define DNS_PROXY_MAX_LEN 128
#define DNS_CONF_USERNAME_LEN 32
#define DNS_MAX_SPKI_LEN 64
#define DNS_MAX_URL_LEN 256
#define DNS_MAX_PATH 1024
#define DEFAULT_DNS_PORT 53
#define DEFAULT_DNS_TLS_PORT 853
#define DEFAULT_DNS_HTTPS_PORT 443
#define DEFAULT_DNS_QUIC_PORT 853
#define DNS_MAX_CONF_CNAME_LEN 256
#define MAX_QTYPE_NUM 65535
#define DNS_MAX_REPLY_IP_NUM 8
#define DNS_MAX_QUERY_LIMIT 65535
#define DNS_DEFAULT_CHECKPOINT_TIME (3600 * 24)
#define DNS_MAX_SERVE_EXPIRED_TIME (3600 * 24 * 365)
#define MAX_INTERFACE_LEN 16

#define SMARTDNS_CONF_FILE "/etc/smartdns/smartdns.conf"
#define SMARTDNS_LOG_FILE "/var/log/smartdns/smartdns.log"
#define SMARTDNS_AUDIT_FILE "/var/log/smartdns/smartdns-audit.log"
#define SMARTDNS_CACHE_FILE "/var/cache/smartdns/smartdns.cache"
#define SMARTDNS_DATA_DIR "/var/lib/smartdns"
#define SMARTDNS_TMP_CACHE_FILE "/tmp/smartdns.cache"
#define SMARTDNS_DEBUG_DIR "/tmp/smartdns"
#define DNS_RESOLV_FILE "/etc/resolv.conf"

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

enum ip_rule {
	IP_RULE_FLAGS = 0,
	IP_RULE_ALIAS = 1,
	IP_RULE_MAX,
};

enum client_rule {
	CLIENT_RULE_FLAGS = 0,
	CLIENT_RULE_GROUP,
	CLIENT_RULE_MAX,
};

typedef enum {
	DNS_BIND_TYPE_UDP,
	DNS_BIND_TYPE_TCP,
	DNS_BIND_TYPE_TLS,
	DNS_BIND_TYPE_HTTPS,
} DNS_BIND_TYPE;

typedef enum {
	DOMAIN_CHECK_NONE = 0,
	DOMAIN_CHECK_ICMP = 1,
	DOMAIN_CHECK_TCP = 2,
	DOMAIN_CHECK_NUM = 3,
} DOMAIN_CHECK_TYPE;

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

#define IP_RULE_FLAG_BLACKLIST (1 << 0)
#define IP_RULE_FLAG_WHITELIST (1 << 1)
#define IP_RULE_FLAG_BOGUS (1 << 2)
#define IP_RULE_FLAG_IP_IGNORE (1 << 3)

#define SERVER_FLAG_EXCLUDE_DEFAULT (1 << 0)
#define SERVER_FLAG_HITCHHIKING (1 << 1)

#define BIND_FLAG_NO_RULE_ADDR (1 << 0)
#define BIND_FLAG_NO_RULE_NAMESERVER (1 << 1)
#define BIND_FLAG_NO_RULE_IPSET (1 << 2)
#define BIND_FLAG_NO_RULE_SNIPROXY (1 << 3)
#define BIND_FLAG_NO_RULE_SOA (1 << 4)
#define BIND_FLAG_NO_SPEED_CHECK (1 << 5)
#define BIND_FLAG_NO_CACHE (1 << 6)
#define BIND_FLAG_NO_DUALSTACK_SELECTION (1 << 7)
#define BIND_FLAG_FORCE_AAAA_SOA (1 << 8)
#define BIND_FLAG_NO_RULE_CNAME (1 << 9)
#define BIND_FLAG_NO_RULE_NFTSET (1 << 10)
#define BIND_FLAG_NO_IP_ALIAS (1 << 11)
#define BIND_FLAG_NO_PREFETCH (1 << 12)
#define BIND_FLAG_FORCE_HTTPS_SOA (1 << 13)
#define BIND_FLAG_NO_SERVE_EXPIRED (1 << 14)
#define BIND_FLAG_NO_RULES (1 << 15)
#define BIND_FLAG_ACL (1 << 16)

enum response_mode_type {
	DNS_RESPONSE_MODE_FIRST_PING_IP = 0,
	DNS_RESPONSE_MODE_FASTEST_IP,
	DNS_RESPONSE_MODE_FASTEST_RESPONSE,
};

struct dns_rule {
	atomic_t refcnt;
	enum domain_rule rule;
};

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

struct dns_ipset_name {
	struct hlist_node node;
	char ipsetname[DNS_MAX_IPSET_NAMELEN];
};

struct dns_ipset_rule {
	struct dns_rule head;
	const char *ipsetname;
};

struct dns_ipset_names {
	char inet_enable;
	char ipv4_enable;
	char ipv6_enable;
	struct dns_ipset_rule inet;
	struct dns_ipset_rule ipv4;
	struct dns_ipset_rule ipv6;
};
extern struct dns_ipset_names dns_conf_ipset_no_speed;
extern struct dns_ipset_names dns_conf_ipset;

struct dns_cname_rule {
	struct dns_rule head;
	char cname[DNS_MAX_CNAME_LEN];
};

struct dns_ttl_rule {
	struct dns_rule head;
	int ttl;
	int ttl_max;
	int ttl_min;
};

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

struct dns_nftset_names {
	char inet_enable;
	char ip_enable;
	char ip6_enable;
	struct dns_nftset_rule inet;
	struct dns_nftset_rule ip;
	struct dns_nftset_rule ip6;
};
extern struct dns_nftset_names dns_conf_nftset_no_speed;
extern struct dns_nftset_names dns_conf_nftset;

struct dns_domain_rule {
	unsigned char sub_rule_only : 1;
	unsigned char root_rule_only : 1;
	struct dns_rule *rules[DOMAIN_RULE_MAX];
};

struct dns_nameserver_rule {
	struct dns_rule head;
	const char *group_name;
};

struct dns_group_rule {
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
	DOMAIN_CHECK_TYPE type;
	unsigned short tcp_port;
};

struct dns_domain_check_orders {
	struct dns_rule head;
	struct dns_domain_check_order orders[DOMAIN_CHECK_NUM];
};

struct dns_response_mode_rule {
	struct dns_rule head;
	enum response_mode_type mode;
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

struct dns_group_table {
	DECLARE_HASHTABLE(group, 8);
};
extern struct dns_group_table dns_group_table;

struct dns_ptr {
	struct hlist_node node;
	char ptr_domain[DNS_MAX_PTR_LEN];
	char hostname[DNS_MAX_CNAME_LEN];
	char is_dynamic;
	char is_soa;
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
	char is_soa;
	char is_dynamic;
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

struct dns_proxy_names {
	struct hlist_node node;
	char proxy_name[PROXY_NAME_LEN];
	struct list_head server_list;
};

struct dns_proxy_table {
	DECLARE_HASHTABLE(proxy, 4);
};
extern struct dns_proxy_table dns_proxy_table;

struct dns_edns_client_subnet {
	int enable;
	char ip[DNS_MAX_IPLEN];
	int subnet;
};

struct dns_servers {
	char server[DNS_MAX_CNAME_LEN];
	unsigned short port;
	unsigned int result_flag;
	unsigned int server_flag;
	int ttl;
	dns_server_type_t type;
	long long set_mark;
	unsigned int drop_packet_latency_ms;
	int tcp_keepalive;
	int fallback;
	int subnet_all_query_types;
	char skip_check_cert;
	char spki[DNS_MAX_SPKI_LEN];
	char hostname[DNS_MAX_CNAME_LEN];
	char httphost[DNS_MAX_CNAME_LEN];
	char tls_host_verify[DNS_MAX_CNAME_LEN];
	char path[DNS_MAX_URL_LEN];
	char proxyname[PROXY_NAME_LEN];
	char ifname[MAX_INTERFACE_LEN];
	char alpn[DNS_MAX_ALPN_LEN];
	struct dns_edns_client_subnet ipv4_ecs;
	struct dns_edns_client_subnet ipv6_ecs;
};

struct dns_proxy_servers {
	struct list_head list;
	char server[DNS_MAX_IPLEN];
	proxy_type_t type;
	unsigned short port;
	char username[DNS_PROXY_MAX_LEN];
	char password[DNS_PROXY_MAX_LEN];
	int use_domain;
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

struct dns_iplist_ip_address {
	int addr_len;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

struct dns_iplist_ip_addresses {
	int ipaddr_num;
	struct dns_iplist_ip_address *ipaddr;
};

struct dns_conf_address_rule {
	radix_tree_t *ipv4;
	radix_tree_t *ipv6;
};

struct dns_conf_domain_rule {
	art_tree tree;
};

struct dns_conf_ipset_nftset {
	int ipset_timeout_enable;
	struct dns_ipset_names ipset_no_speed;
	int nftset_timeout_enable;
	struct dns_nftset_names nftset_no_speed;
};

struct dns_dns64 {
	unsigned char prefix[DNS_RR_AAAA_LEN];
	uint32_t prefix_len;
};

struct dns_conf_group {
	struct hlist_node node;
	struct dns_conf_domain_rule domain_rule;
	struct dns_conf_address_rule address_rule;
	uint8_t *soa_table;
	/* === AUTO COPY FIELD BEGIN === */
	char copy_data_section_begin[0];
	struct dns_conf_ipset_nftset ipset_nftset;
	struct dns_domain_check_orders check_orders;
	/* ECS */
	struct dns_edns_client_subnet ipv4_ecs;
	struct dns_edns_client_subnet ipv6_ecs;

	/* DNS64 */
	struct dns_dns64 dns_dns64;

	int force_AAAA_SOA;
	int dualstack_ip_selection;
	int dns_dualstack_ip_allow_force_AAAA;
	int dns_dualstack_ip_selection_threshold;
	int dns_rr_ttl;
	int dns_rr_ttl_reply_max;
	int dns_rr_ttl_min;
	int dns_rr_ttl_max;
	int dns_local_ttl;
	int dns_force_no_cname;
	int dns_prefetch;
	int dns_serve_expired;
	int dns_serve_expired_ttl;
	int dns_serve_expired_prefetch_time;
	int dns_serve_expired_reply_ttl;
	int dns_max_reply_ip_num;
	enum response_mode_type dns_response_mode;
	char copy_data_section_end[0];
	/* === AUTO COPY FIELD END === */
	const char *group_name;
};

struct dns_conf_rule {
	struct dns_conf_group *default_conf;
	DECLARE_HASHTABLE(group, 8);
	int group_num;
};

struct dns_client_rule {
	atomic_t refcnt;
	enum client_rule rule;
};

struct client_rule_flags {
	struct dns_client_rule head;
	unsigned int flags;
	unsigned int is_flag_set;
};

struct client_rule_group {
	struct dns_client_rule head;
	const char *group_name;
};

struct dns_client_rules {
	struct dns_client_rule *rules[CLIENT_RULE_MAX];
};

struct client_roue_group_mac {
	struct hlist_node node;
	uint8_t mac[6];
	struct dns_client_rules *rules;
};

struct dns_conf_client_rule {
	radix_tree_t *rule;
	DECLARE_HASHTABLE(mac, 6);
	int mac_num;
};

struct nftset_ipset_rules {
	struct dns_ipset_rule *ipset;
	struct dns_ipset_rule *ipset_ip;
	struct dns_ipset_rule *ipset_ip6;
	struct dns_nftset_rule *nftset_ip;
	struct dns_nftset_rule *nftset_ip6;
};

struct dns_bind_ip {
	DNS_BIND_TYPE type;
	uint32_t flags;
	char ip[DNS_MAX_IPLEN];
	const char *ssl_cert_file;
	const char *ssl_cert_key_file;
	const char *ssl_cert_key_pass;
	const char *group;
	struct nftset_ipset_rules nftset_ipset_rule;
};

struct dns_domain_set_rule {
	struct list_head list;
	enum domain_rule type;
	void *rule;
	unsigned int flags;
	unsigned int is_clear_flag;
};

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

struct dns_ip_rule {
	atomic_t refcnt;
	enum ip_rule rule;
};

enum dns_ip_set_type {
	DNS_IP_SET_LIST = 0,
};

struct dns_ip_rules {
	struct dns_ip_rule *rules[IP_RULE_MAX];
};

struct ip_rule_flags {
	struct dns_ip_rule head;
	unsigned int flags;
	unsigned int is_flag_set;
};

struct ip_rule_alias {
	struct dns_ip_rule head;
	struct dns_iplist_ip_addresses ip_alias;
};

struct dns_ip_set_name {
	struct list_head list;
	enum dns_ip_set_type type;
	char file[DNS_MAX_PATH];
};

struct dns_ip_set_name_list {
	struct hlist_node node;
	char name[DNS_MAX_CNAME_LEN];
	struct list_head set_name_list;
};
struct dns_ip_set_name_table {
	DECLARE_HASHTABLE(names, 4);
};
extern struct dns_ip_set_name_table dns_ip_set_name_table;

struct dns_set_rule_add_callback_args {
	int type;
	void *rule;
};

struct dns_set_rule_flags_callback_args {
	unsigned int flags;
	int is_clear_flag;
};

struct dns_srv_record {
	struct list_head list;
	char host[DNS_MAX_CNAME_LEN];
	unsigned short priority;
	unsigned short weight;
	unsigned short port;
};

struct dns_srv_records {
	char domain[DNS_MAX_CNAME_LEN];
	struct hlist_node node;
	struct list_head list;
};

struct dns_srv_record_table {
	DECLARE_HASHTABLE(srv, 4);
};
extern struct dns_srv_record_table dns_conf_srv_record_table;

struct dns_conf_plugin {
	struct hlist_node node;
	char name[DNS_MAX_CNAME_LEN];
	char file[DNS_MAX_PATH];
	char args[DNS_MAX_PATH * 4];
	int argc;
	int args_len;
};

struct dns_conf_plugin_conf {
	struct hlist_node node;
	char key[MAX_KEY_LEN];
	char value[MAX_LINE_LEN];
};

struct dns_conf_plugin_table {
	DECLARE_HASHTABLE(plugins, 4);
	DECLARE_HASHTABLE(plugins_conf, 4);
};
extern struct dns_conf_plugin_table dns_conf_plugin_table;
extern char dns_conf_exist_bootstrap_dns;
extern int dns_ping_cap_force_enable;

struct dns_config {
	struct dns_bind_ip bind_ip[DNS_MAX_BIND_IP];
	int bind_ip_num;

	char bind_ca_file[DNS_MAX_PATH];
	char bind_ca_key_file[DNS_MAX_PATH];
	char bind_root_ca_key_file[DNS_MAX_PATH];
	char bind_ca_key_pass[DNS_MAX_PATH];
	int  bind_ca_validity_days;
	char need_cert;
	int tcp_idle_time;
	ssize_t cachesize;
	ssize_t cache_max_memsize;
	struct dns_servers servers[DNS_MAX_SERVERS];
	int server_num;

	/* proxy servers */
	struct dns_proxy_servers proxy_servers[PROXY_MAX_SERVERS];
	int proxy_server_num;

	int log_level;
	char log_file[DNS_MAX_PATH];
	size_t log_size;
	int log_num;
	int log_file_mode;
	int log_console;
	int log_syslog;

	char ca_file[DNS_MAX_PATH];
	char ca_path[DNS_MAX_PATH];

	char cache_file[DNS_MAX_PATH];
	char var_libdir[DNS_MAX_PATH];
	int cache_persist;
	int cache_checkpoint_time;

	char data_dir[DNS_MAX_PATH];

	struct dns_domain_check_orders default_check_orders;
	int has_icmp_check;
	int has_tcp_check;

	struct dns_server_groups server_groups[DNS_NAX_GROUP_NUMBER];
	int server_group_num;

	int audit_enable;
	int audit_log_SOA;
	char audit_file[DNS_MAX_PATH];
	size_t audit_size;
	int audit_num;
	int audit_file_mode;
	int audit_console;
	int audit_syslog;

	char server_name[DNS_MAX_SERVER_NAME_LEN];
	struct dns_conf_domain_rule domain_rule;
	struct dns_conf_client_rule client_rule;

	int max_query_limit;
	enum response_mode_type default_response_mode;
	int nftset_debug_enable;
	int local_ttl;
	int mdns_lookup;
	int local_ptr_enable;
	int acl_enable;

	char user[DNS_CONF_USERNAME_LEN];

	char sni_proxy_ip[DNS_MAX_IPLEN];
	int resolv_hostname;

	int expand_ptr_from_address;

	int dns_save_fail_packet;
	char dns_save_fail_packet_dir[DNS_MAX_PATH];
	char dns_resolv_file[DNS_MAX_PATH];

	int dns_no_pidfile;
	int dns_no_daemon;
	int dns_restart_on_crash;
	size_t dns_socket_buff_size;
};
extern struct dns_config dns_conf;

void dns_server_load_exit(void);

int dns_server_load_conf(const char *file);

int dns_server_check_update_hosts(void);

struct dns_proxy_names *dns_server_get_proxy_names(const char *proxyname);

struct dns_srv_records *dns_server_get_srv_record(const char *domain);

struct dns_conf_group *dns_server_get_rule_group(const char *group_name);

struct dns_conf_group *dns_server_get_default_rule_group(void);

struct client_roue_group_mac *dns_server_rule_group_mac_get(const uint8_t mac[6]);

const char *dns_conf_get_plugin_conf(const char *key);

void dns_conf_clear_all_plugin_conf(void);

extern int config_additional_file(void *data, int argc, char *argv[]);

const char *dns_conf_get_cache_dir(void);

const char *dns_conf_get_data_dir(void);

#ifdef __cplusplus
}
#endif
#endif // !_DNS_CONF
