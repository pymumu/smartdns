#ifndef _DNS_CONF

#define DNS_MAX_SERVERS 32
#define DNS_MAX_IPLEN 64

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

extern int dns_conf_port;
extern int dns_conf_cachesize;
extern struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
extern int dns_conf_server_num;

int load_conf(const char *file);

#endif // !_DNS_CONF