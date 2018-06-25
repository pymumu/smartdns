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
	struct list_head list;
	char domain[DNS_MAX_CONF_CNAME_LEN];
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
extern int dns_conf_verbose;
extern int dns_conf_loglevel;
extern char dns_conf_logfile[DNS_MAX_PATH];
extern int dns_conf_lognum;
extern art_tree dns_conf_address;

int load_conf(const char *file);

void load_exit(void);

#endif // !_DNS_CONF