#ifndef _DNS_CONF

#define DNS_MAX_SERVERS 32
#define DNS_MAX_IPLEN 64
#define DNS_MAX_PATH 1024
#define DEFAULT_DNS_PORT 53

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

extern char dns_conf_server_ip[DNS_MAX_IPLEN];
extern int dns_conf_cachesize;
extern struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
extern int dns_conf_server_num;
extern int dns_conf_verbose;
extern int dns_conf_loglevel;
extern char dns_conf_logfile[DNS_MAX_PATH];
extern int dns_conf_lognum;

int load_conf(const char *file);

#endif // !_DNS_CONF