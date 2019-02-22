#ifndef _SMART_DNS_SERVER_H
#define _SMART_DNS_SERVER_H

#ifdef __cpluscplus
extern "C" {
#endif

int dns_server_init(void);

int dns_server_run(void);

int dns_server_start(void);

void dns_server_stop(void);

void dns_server_exit(void);

#ifdef __cpluscplus
}
#endif
#endif
