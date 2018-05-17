#ifndef _SMART_DNS_CLIENT_H
#define _SMART_DNS_CLIENT_H

int dns_client_init(void);

typedef int (*dns_client_callback)(char *domain, unsigned char *addr, int addr_type, void *user_ptr);
int dns_register_callback(dns_client_callback callback);

int dns_client_query(char *domain, void *user_ptr);

void dns_client_exit(void);

#endif
