

#ifndef SMART_DNS_UTIL_H
#define SMART_DNS_UTIL_H

#include <netdb.h>

#define PORT_NOT_DEFINED -1
#define MAX_IP_LEN 64

unsigned long get_tick_count();

char *gethost_by_addr(char *host, struct sockaddr *addr, socklen_t addr_len);

int parse_ip(const char *value, char *ip, int *port);

#endif