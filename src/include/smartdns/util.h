/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "smartdns/lib/stringutil.h"
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

#define IPV6_ADDR_LEN 16
#define IPV4_ADDR_LEN 4

#define TMP_BUFF_LEN_32 32

#ifndef BASE_FILE_NAME
#define BASE_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif
#define BUG(format, ...) bug_ext(BASE_FILE_NAME, __LINE__, __func__, format, ##__VA_ARGS__)

void bug_ext(const char *file, int line, const char *func, const char *errfmt, ...)
	__attribute__((format(printf, 4, 5))) __attribute__((nonnull(4)));

unsigned long get_tick_count(void);

unsigned long long get_utc_time_ms(void);

char *dir_name(char *path);

int get_uid_gid(uid_t *uid, gid_t *gid);

int drop_root_privilege(void);

int create_dir_with_perm(const char *dir_path);

char *get_host_by_addr(char *host, int maxsize, const struct sockaddr *addr);

int generate_random_addr(unsigned char *addr, int addr_len, int mask);

int generate_addr_map(const unsigned char *addr_from, const unsigned char *addr_to, unsigned char *addr_out,
					  int addr_len, int mask);

int is_private_addr(const unsigned char *addr, int addr_len);

int is_private_addr_sockaddr(const struct sockaddr *addr, socklen_t addr_len);

int getaddr_by_host(const char *host, struct sockaddr *addr, socklen_t *addr_len);

int get_raw_addr_by_sockaddr(const struct sockaddr_storage *addr, int addr_len, unsigned char *raw_addr,
							 int *raw_addr_len);

int get_raw_addr_by_ip(const char *ip, unsigned char *raw_addr, int *raw_addr_len);

int getsocket_inet(int fd, struct sockaddr *addr, socklen_t *addr_len);

int fill_sockaddr_by_ip(unsigned char *ip, int ip_len, int port, struct sockaddr *addr, socklen_t *addr_len);

int parse_ip(const char *value, char *ip, int *port);

int check_is_ipaddr(const char *ip);

int check_is_ipv4(const char *ip);

int check_is_ipv6(const char *ip);

int parser_mac_address(const char *in_mac, uint8_t mac[6]);

int parse_uri(const char *value, char *scheme, char *host, int *port, char *path);

int parse_uri_ext(const char *value, char *scheme, char *user, char *password, char *host, int *port, char *path);

int urldecode(char *dst, int dst_maxlen, const char *src);

int set_fd_nonblock(int fd, int nonblock);

char *reverse_string(char *output, const char *input, int len, int to_lower_case);

char *to_lower_case(char *output, const char *input, int len);

void print_stack(void);

int ipset_add(const char *ipset_name, const unsigned char addr[], int addr_len, unsigned long timeout);

int ipset_del(const char *ipset_name, const unsigned char addr[], int addr_len);

int netlink_get_neighbors(int family,
						  int (*callback)(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6], void *arg),
						  void *arg);

void SSL_CRYPTO_thread_setup(void);

void SSL_CRYPTO_thread_cleanup(void);

unsigned char *SSL_SHA256(const unsigned char *d, size_t n, unsigned char *md);

int SSL_base64_decode(const char *in, unsigned char *out, int max_outlen);

int SSL_base64_decode_ext(const char *in, unsigned char *out, int max_outlen, int url_safe, int auto_padding);

int SSL_base64_encode(const void *in, int in_len, char *out);

int generate_cert_key(const char *key_path, const char *cert_path, const char *root_key_path, const char *san, int days);

int generate_cert_san(char *san, int max_san_len);

int is_cert_valid(const char *cert_file_path);

int create_pid_file(const char *pid_file);

int full_path(char *normalized_path, int normalized_path_len, const char *path);

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first server name found (pointer to static
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

unsigned long get_system_mem_size(void);

int is_numeric(const char *str);

int has_network_raw_cap(void);

int has_unprivileged_ping(void);

int set_sock_keepalive(int fd, int keepidle, int keepinterval, int keepcnt);

int set_sock_lingertime(int fd, int time);

uint64_t get_free_space(const char *path);

void print_stack(void);

void close_all_fd(int keepfd);

typedef enum daemon_ret {
	DAEMON_RET_OK = 0,
	DAEMON_RET_ERR = -1,
	DAEMON_RET_CHILD_OK = -2,
	DAEMON_RET_PARENT_OK = -3,
} daemon_ret;

daemon_ret daemon_run(int *wstatus);

int daemon_kickoff(int status, int no_close);

int daemon_keepalive(void);

void daemon_close_stdfds(void);

int write_file(const char *filename, void *data, int data_len);

int set_http_host(const char *uri_host, int port, int default_port, char *host);

int dns_packet_save(const char *dir, const char *type, const char *from, const void *packet, int packet_len);

int dns_packet_debug(const char *packet_file);

int dns_is_quic_supported(void);

int decode_hex(int ch);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
