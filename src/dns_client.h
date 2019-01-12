#ifndef _SMART_DNS_CLIENT_H
#define _SMART_DNS_CLIENT_H

#include "dns.h"

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
#define DNSSERVER_FLAG_CHECK_EDNS (0x1 << 1)
#define DNSSERVER_FLAG_CHECK_TTL (0x1 << 2)

int dns_client_init(void);

int dns_client_set_ecs(char *ip, int subnet);

/* query result notify function */
typedef int (*dns_client_callback)(char *domain, dns_result_type rtype, unsigned int result_flag, struct dns_packet *packet, unsigned char *inpacket,
								   int inpacket_len, void *user_ptr);

/* query domain */
int dns_client_query(char *domain, int qtype, dns_client_callback callback, void *user_ptr);

void dns_client_exit(void);

/* add remote dns server */
int dns_add_server(char *server_ip, int port, dns_server_type_t server_type, int result_flag, int ttl);

/* remove remote dns server */
int dns_remove_server(char *server_ip, int port, dns_server_type_t server_type);

int dns_server_num(void);

#endif
