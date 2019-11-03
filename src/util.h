

#ifndef SMART_DNS_UTIL_H
#define SMART_DNS_UTIL_H

#include <netdb.h>
#include <time.h>
#include "stringutil.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define PORT_NOT_DEFINED -1
#define MAX_IP_LEN 64

unsigned long get_tick_count(void);

char *gethost_by_addr(char *host, int maxsize, struct sockaddr *addr);

int getaddr_by_host(char *host, struct sockaddr *addr, socklen_t *addr_len);

int getsocknet_inet(int fd, struct sockaddr *addr, socklen_t *addr_len);

int fill_sockaddr_by_ip(unsigned char *ip, int ip_len, int port, struct sockaddr *addr, socklen_t *addr_len);

int parse_ip(const char *value, char *ip, int *port);

int check_is_ipaddr(const char *ip);

int parse_uri(char *value, char *scheme, char *host, int *port, char *path);

int set_fd_nonblock(int fd, int nonblock);

char *reverse_string(char *output, const char *input, int len, int to_lower_case);

void print_stack(void);

int ipset_add(const char *ipsetname, const unsigned char addr[], int addr_len, unsigned long timeout);

int ipset_del(const char *ipsetname, const unsigned char addr[], int addr_len);

void SSL_CRYPTO_thread_setup(void);

void SSL_CRYPTO_thread_cleanup(void);

unsigned char *SSL_SHA256(const unsigned char *d, size_t n, unsigned char *md);

int SSL_base64_decode(const char *in, unsigned char *out);

int create_pid_file(const char *pid_file);

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
int parse_tls_header(const char *data, size_t data_len, char *hostname, const char **hostname_ptr);

void get_compiled_time(struct tm *tm);

int has_network_raw_cap(void);

int set_sock_keepalive(int fd, int keepidle, int keepinterval, int keepcnt);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
