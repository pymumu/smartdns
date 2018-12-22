#ifndef _DNS_CONF
#define _DNS_CONF

#include "art.h"
#include "conf.h"
#include "dns.h"
#include "dns_client.h"
#include "hash.h"
#include "hashtable.h"
#include "list.h"
#include "radix.h"

#define DNS_MAX_SERVERS 64
#define DNS_MAX_IPSET_NAMELEN 32
#define DNS_MAX_IPLEN 64
#define DNS_MAX_PATH 1024
#define DEFAULT_DNS_PORT 53
#define DEFAULT_DNS_TLS_PORT 853
#define DNS_MAX_CONF_CNAME_LEN 128
#define SMARTDNS_CONF_FILE "/etc/smartdns/smartdns.conf"
#define SMARTDNS_LOG_FILE "/var/log/smartdns.log"
#define SMARTDNS_AUDIT_FILE "/var/log/smartdns-audit.log"

enum domain_rule {
	DOMAIN_RULE_ADDRESS_IPV4 = 1,
	DOMAIN_RULE_ADDRESS_IPV6 = 2,
	DOMAIN_RULE_IPSET = 3,
	DOMAIN_RULE_MAX,
};

struct dns_address_IPV4 {
	unsigned char ipv4_addr[DNS_RR_A_LEN];
};

struct dns_address_IPV6 {
	unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
};

struct dns_ipset_name {
	struct hlist_node node;
	char ipsetname[DNS_MAX_IPSET_NAMELEN];
};

struct dns_ipset_rule {
	const char *ipsetname;
};

struct dns_domain_rule {
	void *rules[DOMAIN_RULE_MAX];
};

struct dns_servers {
	char server[DNS_MAX_IPLEN];
	unsigned short port;
	unsigned int result_flag;
	int ttl;
	dns_server_type_t type;
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
	ADDRESS_RULE_BOGUS = 2,
};

struct dns_ip_address_rule {
	unsigned int blacklist : 1;
	unsigned int bogus : 1;
};

struct dns_edns_client_subnet {
	int enable;
	char ip[DNS_MAX_IPLEN];
	int subnet;
};

extern char dns_conf_server_ip[DNS_MAX_IPLEN];
extern char dns_conf_server_tcp_ip[DNS_MAX_IPLEN];
extern int dns_conf_tcp_idle_time;
extern int dns_conf_cachesize;
extern int dns_conf_prefetch;
extern struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
extern int dns_conf_server_num;

extern int dns_conf_log_level;
extern char dns_conf_log_file[DNS_MAX_PATH];
extern size_t dns_conf_log_size;
extern int dns_conf_log_num;

extern int dns_conf_audit_enable;
extern char dns_conf_audit_file[DNS_MAX_PATH];
extern size_t dns_conf_audit_size;
extern int dns_conf_audit_num;

extern char dns_conf_server_name[DNS_MAX_CONF_CNAME_LEN];
extern art_tree dns_conf_domain_rule;
extern radix_tree_t *dns_conf_address_rule;

extern int dns_conf_dualstack_preference;
extern int dns_conf_dualstack_threshold;

extern int dns_conf_rr_ttl;
extern int dns_conf_rr_ttl_min;
extern int dns_conf_rr_ttl_max;
extern int dns_conf_force_AAAA_SOA;

extern struct dns_edns_client_subnet dns_conf_ipv4_ecs;
extern struct dns_edns_client_subnet dns_conf_ipv6_ecs;

void dns_server_load_exit(void);

int dns_server_load_conf(const char *file);

extern int config_addtional_file(void *data, int argc, char *argv[]);

#endif // !_DNS_CONF