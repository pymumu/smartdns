

#ifndef SMART_DNS_UTIL_H
#define SMART_DNS_UTIL_H

#include <netdb.h>

#define PORT_NOT_DEFINED -1
#define MAX_IP_LEN 64

unsigned long get_tick_count(void);

char *gethost_by_addr(char *host, int maxsize, struct sockaddr *addr);

int getaddr_by_host(char *host, struct sockaddr *addr, socklen_t *addr_len);

int parse_ip(const char *value, char *ip, int *port);

int set_fd_nonblock(int fd, int nonblock);

char *reverse_string(char *output, char *input, int len);

void print_stack(void);

int ipset_add(const char *ipsetname, const unsigned char addr[], int addr_len, unsigned long timeout);

int ipset_del(const char *ipsetname, const unsigned char addr[], int addr_len);

void SSL_CRYPTO_thread_setup(void);

void SSL_CRYPTO_thread_cleanup(void);

unsigned char *SSL_SHA256(const unsigned char *d, size_t n, unsigned char *md);

int SSL_base64_decode(const char *in, unsigned char *out);

#endif