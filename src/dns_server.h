#ifndef _SMART_DNS_SERVER_H
#define _SMART_DNS_SERVER_H

#include "dns.h"

#ifdef __cpluscplus
extern "C" {
#endif

int dns_server_init(void);

int dns_server_run(void);

int dns_server_start(void);

void dns_server_stop(void);

void dns_server_exit(void);

/* query result notify function */
typedef int (*dns_result_callback)(char *domain, dns_rtcode_t rtcode, dns_type_t addr_type, char *ip, unsigned int ping_time, void *user_ptr);

/* query domain */
int dns_server_query(char *domain, int qtype, dns_result_callback callback, void *user_ptr);

#ifdef __cpluscplus
}
#endif
#endif
