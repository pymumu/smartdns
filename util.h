

#ifndef SMART_DNS_UTIL_H
#define SMART_DNS_UTIL_H

#include <netdb.h>

unsigned long get_tick_count();

char *gethost_by_addr(char *host, struct sockaddr *addr, socklen_t addr_len);

#endif