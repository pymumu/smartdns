#ifndef _DNS_CONF
#define _DNS_CONF

#include "list.h"
#include "art.h"
#include "dns.h"

#define DNS_MAX_SERVERS 32
#define DNS_MAX_IPLEN 64
#define DNS_MAX_PATH 1024
#define DEFAULT_DNS_PORT 53
#define DNS_MAX_CONF_CNAME_LEN 128

typedef enum dns_conf_server_type {
	DNS_CONF_TYPE_UDP,
	DNS_CONF_TYPE_TCP,
	DNS_CONF_TYPE_HTTP,
} dns_conf_server_type_t;

struct dns_servers {
	char server[DNS_MAX_IPLEN];
	unsigned short port;
	dns_conf_server_type_t type;
};

struct dns_address {
	dns_type_t addr_type;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

extern char dns_conf_server_ip[DNS_MAX_IPLEN];
extern int dns_conf_cachesize;
extern struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
extern int dns_conf_server_num;

extern int dns_conf_log_level;
extern char dns_conf_log_file[DNS_MAX_PATH];
extern int dns_conf_log_size;
extern int dns_conf_log_num;

extern char dns_conf_server_name[DNS_MAX_CONF_CNAME_LEN];
extern art_tree dns_conf_address;

extern int dns_conf_rr_ttl;
extern int dns_conf_rr_ttl_min;
extern int dns_conf_rr_ttl_max;


int load_conf(const char *file);

void load_exit(void);

#endif // !_DNS_CONF