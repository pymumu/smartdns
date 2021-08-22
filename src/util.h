/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SMART_DNS_UTIL_H
#define SMART_DNS_UTIL_H

#include "stringutil.h"
#include <netdb.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif
#ifndef TCP_THIN_LINEAR_TIMEOUTS
#define TCP_THIN_LINEAR_TIMEOUTS 16
#endif

#ifndef TCP_THIN_DUPACK
#define TCP_THIN_DUPACK 17
#endif

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

int is_numeric(const char *str);

int has_network_raw_cap(void);

int set_sock_keepalive(int fd, int keepidle, int keepinterval, int keepcnt);

int set_sock_lingertime(int fd, int time);

uint64_t get_free_space(const char *path);

void print_stack(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
