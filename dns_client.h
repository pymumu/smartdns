#ifndef _SMART_DNS_CLIENT_H
#define _SMART_DNS_CLIENT_H

int dns_client_init(void);

int dns_client_query(char *host);

void dns_client_exit(void);

#endif
