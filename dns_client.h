#ifndef _SMART_DNS_CLIENT_H
#define _SMART_DNS_CLIENT_H

#include "dns.h"

typedef enum {
	DNS_SERVER_UDP,
	DNS_SERVER_TCP,
	DNS_SERVER_HTTP,
	DNS_SERVER_TYPE_END,
} dns_server_type_t;

struct dns_result {
	char alias[DNS_MAX_CNAME_LEN];
	unsigned long ttl_v4;
	unsigned char addr_ipv4[4];
	unsigned long ttl_v6;
	unsigned char addr_ipv6[16];
};

typedef enum dns_result_type {
	DNS_QUERY_ERR,
	DNS_QUERY_RESULT = 1,
	DNS_QUERY_END,
} dns_result_type;

int dns_client_init(void);

typedef int (*dns_client_callback)(char *domain, dns_result_type rtype, struct dns_packet *packet, unsigned char *inpacket, int inpacket_len, void *user_ptr);

int dns_client_query(char *domain, int qtype, dns_client_callback callback, void *user_ptr);

int dns_client_query_raw(char *domain, int qtype, unsigned char *raw, int raw_len, void *user_ptr);

void dns_client_exit(void);

int dns_add_server(char *server_ip, int port, dns_server_type_t server_type);

int dns_remove_server(char *server_ip, int port, dns_server_type_t server_type);

#endif
