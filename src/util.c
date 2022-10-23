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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#endif
#include "dns_conf.h"
#include "tlog.h"
#include "util.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>

#ifdef WITH_NFTSET
#include <nftables/libnftables.h>
#endif

#define TMP_BUFF_LEN_32 32

#define NFNL_SUBSYS_IPSET 6

#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
#define IPSET_ATTR_TIMEOUT 6
#define IPSET_ADD 9
#define IPSET_DEL 10
#define IPSET_MAXNAMELEN 32
#define IPSET_PROTOCOL 6

#define IPV6_ADDR_LEN 16
#define IPV4_ADDR_LEN 4

#ifndef NFNETLINK_V0
#define NFNETLINK_V0 0
#endif

#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif

#ifndef NLA_F_NET_BYTEORDER
#define NLA_F_NET_BYTEORDER (1 << 14)
#endif

#define NETLINK_ALIGN(len) (((len) + 3) & ~(3))

#define BUFF_SZ 1024
#define PACKET_BUF_SIZE 8192
#define PACKET_MAGIC 0X11040918

struct ipset_netlink_attr {
	unsigned short len;
	unsigned short type;
};

struct ipset_netlink_msg {
	unsigned char family;
	unsigned char version;
	__be16 res_id;
};

static int ipset_fd;
static int pidfile_fd;

unsigned long get_tick_count(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

char *gethost_by_addr(char *host, int maxsize, struct sockaddr *addr)
{
	struct sockaddr_storage *addr_store = (struct sockaddr_storage *)addr;
	host[0] = 0;
	switch (addr_store->ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &addr_in->sin_addr, host, maxsize);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			struct sockaddr_in addr_in4;
			memset(&addr_in4, 0, sizeof(addr_in4));
			memcpy(&addr_in4.sin_addr.s_addr, addr_in6->sin6_addr.s6_addr + 12, sizeof(addr_in4.sin_addr.s_addr));
			inet_ntop(AF_INET, &addr_in4.sin_addr, host, maxsize);
		} else {
			inet_ntop(AF_INET6, &addr_in6->sin6_addr, host, maxsize);
		}
	} break;
	default:
		goto errout;
		break;
	}
	return host;
errout:
	return NULL;
}

int getaddr_by_host(const char *host, struct sockaddr *addr, socklen_t *addr_len)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int ret = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, "53", &hints, &result);
	if (ret != 0) {
		goto errout;
	}

	if (result->ai_addrlen > *addr_len) {
		result->ai_addrlen = *addr_len;
	}

	addr->sa_family = result->ai_family;
	memcpy(addr, result->ai_addr, result->ai_addrlen);
	*addr_len = result->ai_addrlen;

	freeaddrinfo(result);

	return 0;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return -1;
}

int getsocknet_inet(int fd, struct sockaddr *addr, socklen_t *addr_len)
{
	struct sockaddr_storage addr_store;
	socklen_t addr_store_len = sizeof(addr_store);
	if (getsockname(fd, (struct sockaddr *)&addr_store, &addr_store_len) != 0) {
		goto errout;
	}

	switch (addr_store.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		*addr_len = sizeof(struct sockaddr_in);
		memcpy(addr, addr_in, sizeof(struct sockaddr_in));
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			struct sockaddr_in addr_in4;
			memset(&addr_in4, 0, sizeof(addr_in4));
			memcpy(&addr_in4.sin_addr.s_addr, addr_in6->sin6_addr.s6_addr + 12, sizeof(addr_in4.sin_addr.s_addr));
			addr_in4.sin_family = AF_INET;
			addr_in4.sin_port = 0;
			*addr_len = sizeof(struct sockaddr_in);
			memcpy(addr, &addr_in4, sizeof(struct sockaddr_in));
		} else {
			addr_in6->sin6_family = AF_INET6;
			*addr_len = sizeof(struct sockaddr_in6);
			memcpy(addr, addr_in6, sizeof(struct sockaddr_in6));
		}
	} break;
	default:
		goto errout;
		break;
	}
	return 0;
errout:
	return -1;
}

int fill_sockaddr_by_ip(unsigned char *ip, int ip_len, int port, struct sockaddr *addr, socklen_t *addr_len)
{
	if (ip == NULL || addr == NULL || addr_len == NULL) {
		return -1;
	}

	if (ip_len == IPV4_ADDR_LEN) {
		struct sockaddr_in *addr_in = NULL;
		addr->sa_family = AF_INET;
		addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_port = htons(port);
		addr_in->sin_family = AF_INET;
		memcpy(&addr_in->sin_addr.s_addr, ip, ip_len);
		*addr_len = 16;
	} else if (ip_len == IPV6_ADDR_LEN) {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr->sa_family = AF_INET6;
		addr_in6 = (struct sockaddr_in6 *)addr;
		addr_in6->sin6_port = htons(port);
		addr_in6->sin6_family = AF_INET6;
		memcpy(addr_in6->sin6_addr.s6_addr, ip, ip_len);
		*addr_len = 28;
	}

	return -1;
}

int parse_ip(const char *value, char *ip, int *port)
{
	int offset = 0;
	char *colon = NULL;

	colon = strstr(value, ":");

	if (strstr(value, "[")) {
		/* ipv6 with port */
		char *bracket_end = strstr(value, "]");
		if (bracket_end == NULL) {
			return -1;
		}

		offset = bracket_end - value - 1;
		memcpy(ip, value + 1, offset);
		ip[offset] = 0;

		colon = strstr(bracket_end, ":");
		if (colon) {
			colon++;
		}
	} else if (colon && strstr(colon + 1, ":")) {
		/* ipv6 without port */
		strncpy(ip, value, MAX_IP_LEN);
		colon = NULL;
	} else {
		/* ipv4 */
		colon = strstr(value, ":");
		if (colon == NULL) {
			/* without port */
			strncpy(ip, value, MAX_IP_LEN);
		} else {
			/* with port */
			offset = colon - value;
			colon++;
			memcpy(ip, value, offset);
			ip[offset] = 0;
		}
	}

	if (colon) {
		/* get port num */
		*port = atoi(colon);
	} else {
		*port = PORT_NOT_DEFINED;
	}

	if (ip[0] == 0) {
		return -1;
	}

	return 0;
}

static int _check_is_ipv4(const char *ip)
{
	const char *ptr = ip;
	char c = 0;
	int dot_num = 0;
	int dig_num = 0;

	while ((c = *ptr++) != '\0') {
		if (c == '.') {
			dot_num++;
			dig_num = 0;
			continue;
		}

		/* check number count of one field */
		if (dig_num >= 4) {
			return -1;
		}

		if (c >= '0' && c <= '9') {
			dig_num++;
			continue;
		}

		return -1;
	}

	/* check field number */
	if (dot_num != 3) {
		return -1;
	}

	return 0;
}
static int _check_is_ipv6(const char *ip)
{
	const char *ptr = ip;
	char c = 0;
	int colon_num = 0;
	int dig_num = 0;

	while ((c = *ptr++) != '\0') {
		if (c == '[' || c == ']') {
			continue;
		}

		if (c == ':') {
			colon_num++;
			dig_num = 0;
			continue;
		}

		/* check number count of one field */
		if (dig_num >= 5) {
			return -1;
		}

		dig_num++;
		if (c >= '0' && c <= '9') {
			continue;
		}

		if (c >= 'a' && c <= 'f') {
			continue;
		}

		if (c >= 'A' && c <= 'F') {
			continue;
		}

		return -1;
	}

	/* check field number */
	if (colon_num > 7) {
		return -1;
	}

	return 0;
}
int check_is_ipaddr(const char *ip)
{
	if (strstr(ip, ".")) {
		/* IPV4 */
		return _check_is_ipv4(ip);
	} else if (strstr(ip, ":")) {
		/* IPV6 */
		return _check_is_ipv6(ip);
	}
	return -1;
}

int parse_uri(char *value, char *scheme, char *host, int *port, char *path)
{
	char *scheme_end = NULL;
	int field_len = 0;
	char *process_ptr = value;
	char host_name[PATH_MAX];

	char *host_end = NULL;

	scheme_end = strstr(value, "://");
	if (scheme_end) {
		field_len = scheme_end - value;
		if (scheme) {
			memcpy(scheme, value, field_len);
			scheme[field_len] = 0;
		}
		process_ptr += field_len + 3;
	} else {
		if (scheme) {
			scheme[0] = '\0';
		}
	}

	host_end = strstr(process_ptr, "/");
	if (host_end == NULL) {
		return parse_ip(process_ptr, host, port);
	};

	field_len = host_end - process_ptr;
	if (field_len >= (int)sizeof(host_name)) {
		return -1;
	}
	memcpy(host_name, process_ptr, field_len);
	host_name[field_len] = 0;

	if (parse_ip(host_name, host, port) != 0) {
		return -1;
	}

	process_ptr += field_len;

	if (path) {
		strncpy(path, process_ptr, PATH_MAX);
	}
	return 0;
}

int set_fd_nonblock(int fd, int nonblock)
{
	int ret = 0;
	int flags = fcntl(fd, F_GETFL);

	if (flags == -1) {
		return -1;
	}

	flags = (nonblock) ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1) {
		return -1;
	}

	return 0;
}

char *reverse_string(char *output, const char *input, int len, int to_lower_case)
{
	char *begin = output;
	if (len <= 0) {
		*output = 0;
		return output;
	}

	len--;
	while (len >= 0) {
		*output = *(input + len);
		if (to_lower_case) {
			if (*output >= 'A' && *output <= 'Z') {
				/* To lower case */
				*output = *output + 32;
			}
		}
		output++;
		len--;
	}

	*output = 0;

	return begin;
}

char *to_lower_case(char *output, const char *input, int len)
{
	char *begin = output;
	int i = 0;
	if (len <= 0) {
		*output = 0;
		return output;
	}

	len--;
	while (i < len && *(input + i) != '\0') {
		*output = *(input + i);
		if (*output >= 'A' && *output <= 'Z') {
			/* To lower case */
			*output = *output + 32;
		}
		output++;
		i++;
	}

	*output = 0;

	return begin;
}

static inline void _ipset_add_attr(struct nlmsghdr *netlink_head, uint16_t type, size_t len, const void *data)
{
	struct ipset_netlink_attr *attr = (void *)netlink_head + NETLINK_ALIGN(netlink_head->nlmsg_len);
	uint16_t payload_len = NETLINK_ALIGN(sizeof(struct ipset_netlink_attr)) + len;
	attr->type = type;
	attr->len = payload_len;
	memcpy((void *)attr + NETLINK_ALIGN(sizeof(struct ipset_netlink_attr)), data, len);
	netlink_head->nlmsg_len += NETLINK_ALIGN(payload_len);
}

static int _ipset_socket_init(void)
{
	if (ipset_fd > 0) {
		return 0;
	}

	ipset_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);

	if (ipset_fd < 0) {
		return -1;
	}

	return 0;
}

static int _ipset_support_timeout(void)
{
	if (dns_conf_ipset_timeout_enable) {
		return 0;
	}

	return -1;
}

static int _ipset_operate(const char *ipsetname, const unsigned char addr[], int addr_len, unsigned long timeout,
						  int operate)
{
	struct nlmsghdr *netlink_head = NULL;
	struct ipset_netlink_msg *netlink_msg = NULL;
	struct ipset_netlink_attr *nested[3];
	char buffer[BUFF_SZ];
	uint8_t proto = 0;
	ssize_t rc = 0;
	int af = 0;
	static const struct sockaddr_nl snl = {.nl_family = AF_NETLINK};
	uint32_t expire = 0;

	if (addr_len != IPV4_ADDR_LEN && addr_len != IPV6_ADDR_LEN) {
		errno = EINVAL;
		return -1;
	}

	if (addr_len == IPV4_ADDR_LEN) {
		af = AF_INET;
	} else if (addr_len == IPV6_ADDR_LEN) {
		af = AF_INET6;
	} else {
		errno = EINVAL;
		return -1;
	}

	if (_ipset_socket_init() != 0) {
		return -1;
	}

	if (strlen(ipsetname) >= IPSET_MAXNAMELEN) {
		errno = ENAMETOOLONG;
		return -1;
	}

	memset(buffer, 0, BUFF_SZ);

	netlink_head = (struct nlmsghdr *)buffer;
	netlink_head->nlmsg_len = NETLINK_ALIGN(sizeof(struct nlmsghdr));
	netlink_head->nlmsg_type = operate | (NFNL_SUBSYS_IPSET << 8);
	netlink_head->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE;

	netlink_msg = (struct ipset_netlink_msg *)(buffer + netlink_head->nlmsg_len);
	netlink_head->nlmsg_len += NETLINK_ALIGN(sizeof(struct ipset_netlink_msg));
	netlink_msg->family = af;
	netlink_msg->version = NFNETLINK_V0;
	netlink_msg->res_id = htons(0);

	proto = IPSET_PROTOCOL;
	_ipset_add_attr(netlink_head, IPSET_ATTR_PROTOCOL, sizeof(proto), &proto);
	_ipset_add_attr(netlink_head, IPSET_ATTR_SETNAME, strlen(ipsetname) + 1, ipsetname);

	nested[0] = (struct ipset_netlink_attr *)(buffer + NETLINK_ALIGN(netlink_head->nlmsg_len));
	netlink_head->nlmsg_len += NETLINK_ALIGN(sizeof(struct ipset_netlink_attr));
	nested[0]->type = NLA_F_NESTED | IPSET_ATTR_DATA;
	nested[1] = (struct ipset_netlink_attr *)(buffer + NETLINK_ALIGN(netlink_head->nlmsg_len));
	netlink_head->nlmsg_len += NETLINK_ALIGN(sizeof(struct ipset_netlink_attr));
	nested[1]->type = NLA_F_NESTED | IPSET_ATTR_IP;

	_ipset_add_attr(netlink_head,
					(af == AF_INET ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER, addr_len,
					addr);
	nested[1]->len = (void *)buffer + NETLINK_ALIGN(netlink_head->nlmsg_len) - (void *)nested[1];

	if (timeout > 0 && _ipset_support_timeout() == 0) {
		expire = htonl(timeout);
		_ipset_add_attr(netlink_head, IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER, sizeof(expire), &expire);
	}

	nested[0]->len = (void *)buffer + NETLINK_ALIGN(netlink_head->nlmsg_len) - (void *)nested[0];

	for (;;) {
		rc = sendto(ipset_fd, buffer, netlink_head->nlmsg_len, 0, (const struct sockaddr *)&snl, sizeof(snl));
		if (rc >= 0) {
			break;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			struct timespec waiter;
			waiter.tv_sec = 0;
			waiter.tv_nsec = 10000;
			nanosleep(&waiter, NULL);
			continue;
		}
	}

	return rc;
}

int ipset_add(const char *ipsetname, const unsigned char addr[], int addr_len, unsigned long timeout)
{
	return _ipset_operate(ipsetname, addr, addr_len, timeout, IPSET_ADD);
}

int ipset_del(const char *ipsetname, const unsigned char addr[], int addr_len)
{
	return _ipset_operate(ipsetname, addr, addr_len, 0, IPSET_DEL);
}

#ifdef WITH_NFTSET
static struct nft_ctx *_nftset_init(void)
{
	static struct nft_ctx *nft_ctx = NULL;
	if (nft_ctx) {
		return nft_ctx;
	}

	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft_ctx) {
		return NULL;
	}

	nft_ctx_buffer_error(nft_ctx);
	return nft_ctx;
}

static int _nftset_operate(const char *familyname, const char *tablename, const char *setname,
						   const unsigned char addr[], int af, const char *op, const char *flags)
{
	char cmd_buf[1024] = {'\0'};

	struct nft_ctx *nft_ctx = _nftset_init();
	if (nft_ctx == NULL) {
		return -1;
	}

	char addr_str[INET6_ADDRSTRLEN];
	if (!inet_ntop(af, addr, addr_str, INET6_ADDRSTRLEN)) {
		return -1;
	}

	int ret = snprintf(cmd_buf, sizeof(cmd_buf), "%s element %s %s %s { %s %s }", op, familyname, tablename, setname,
					   addr_str, flags);

	if (ret == -1) {
		return -1;
	}

	ret = nft_run_cmd_from_buffer(nft_ctx, cmd_buf);
	nft_ctx_get_error_buffer(nft_ctx);

	return ret;
}

int nftset_add(const char *familyname, const char *tablename, const char *setname, const unsigned char addr[],
			   int addr_len, unsigned long timeout)
{
	char flag_timeout[32] = {'\0'};
	int af = addr_len == IPV6_ADDR_LEN ? AF_INET6 : AF_INET;
	if (dns_conf_nftset_timeout_enable) {
		snprintf(flag_timeout, sizeof(flag_timeout), "timeout %lus", timeout);
	}
	return _nftset_operate(familyname, tablename, setname, addr, af, "add", flag_timeout);
}

int nftset_del(const char *familyname, const char *tablename, const char *setname, const unsigned char addr[],
			   int addr_len)
{
	int af = addr_len == IPV6_ADDR_LEN ? AF_INET6 : AF_INET;
	return _nftset_operate(familyname, tablename, setname, addr, af, "delete", "");
}
#endif

unsigned char *SSL_SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char m[SHA256_DIGEST_LENGTH];

	if (md == NULL) {
		md = m;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (ctx == NULL) {
		return NULL;
	}

	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, d, n);
	EVP_DigestFinal_ex(ctx, m, NULL);
	EVP_MD_CTX_destroy(ctx);

	return (md);
}

int SSL_base64_decode(const char *in, unsigned char *out)
{
	size_t inlen = strlen(in);
	int outlen = 0;

	if (inlen == 0) {
		return 0;
	}

	outlen = EVP_DecodeBlock(out, (unsigned char *)in, inlen);
	if (outlen < 0) {
		goto errout;
	}

	/* Subtract padding bytes from |outlen| */
	while (in[--inlen] == '=') {
		--outlen;
	}

	return outlen;
errout:
	return -1;
}

int create_pid_file(const char *pid_file)
{
	int fd = 0;
	int flags = 0;
	char buff[TMP_BUFF_LEN_32];

	/*  create pid file, and lock this file */
	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "create pid file failed, %s\n", strerror(errno));
		return -1;
	}

	flags = fcntl(fd, F_GETFD);
	if (flags < 0) {
		fprintf(stderr, "Could not get flags for PID file %s\n", pid_file);
		goto errout;
	}

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1) {
		fprintf(stderr, "Could not set flags for PID file %s\n", pid_file);
		goto errout;
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		fprintf(stderr, "Server is already running.\n");
		goto errout;
	}

	snprintf(buff, TMP_BUFF_LEN_32, "%d\n", getpid());

	if (write(fd, buff, strnlen(buff, TMP_BUFF_LEN_32)) < 0) {
		fprintf(stderr, "write pid to file failed, %s.\n", strerror(errno));
		goto errout;
	}

	if (pidfile_fd > 0) {
		close(pidfile_fd);
	}

	pidfile_fd = fd;

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

#if OPENSSL_API_COMPAT < 0x10100000
#define THREAD_STACK_SIZE (16 * 1024)
static pthread_mutex_t *lock_cs;
static long *lock_count;

static __attribute__((unused)) void _pthreads_locking_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}

static __attribute__((unused)) unsigned long _pthreads_thread_id(void)
{
	unsigned long ret = 0;

	ret = (unsigned long)pthread_self();
	return (ret);
}

void SSL_CRYPTO_thread_setup(void)
{
	int i = 0;

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	if (!lock_cs || !lock_count) {
		/* Nothing we can do about this...void function! */
		if (lock_cs) {
			OPENSSL_free(lock_cs);
		}
		if (lock_count) {
			OPENSSL_free(lock_count);
		}
		return;
	}
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

#if OPENSSL_API_COMPAT < 0x10000000
	CRYPTO_set_id_callback(_pthreads_thread_id);
#else
	CRYPTO_THREADID_set_callback(_pthreads_thread_id);
#endif
	CRYPTO_set_locking_callback(_pthreads_locking_callback);
}

void SSL_CRYPTO_thread_cleanup(void)
{
	int i = 0;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
}
#endif

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static int parse_extensions(const char *, size_t, char *, const char **);
static int parse_server_name_extension(const char *, size_t, char *, const char **);

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
int parse_tls_header(const char *data, size_t data_len, char *hostname, const char **hostname_ptr)
{
	char tls_content_type = 0;
	char tls_version_major = 0;
	char tls_version_minor = 0;
	size_t pos = TLS_HEADER_LEN;
	size_t len = 0;

	if (hostname == NULL) {
		return -3;
	}

	/* Check that our TCP payload is at least large enough for a TLS header */
	if (data_len < TLS_HEADER_LEN) {
		return -1;
	}

	/* SSL 2.0 compatible Client Hello
	 *
	 * High bit of first byte (length) and content type is Client Hello
	 *
	 * See RFC5246 Appendix E.2
	 */
	if (data[0] & 0x80 && data[2] == 1) {
		return -2;
	}

	tls_content_type = data[0];
	if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
		return -5;
	}

	tls_version_major = data[1];
	tls_version_minor = data[2];
	if (tls_version_major < 3) {
		return -2;
	}

	/* TLS record length */
	len = ((unsigned char)data[3] << 8) + (unsigned char)data[4] + TLS_HEADER_LEN;
	data_len = MIN(data_len, len);

	/* Check we received entire TLS record length */
	if (data_len < len) {
		return -1;
	}

	/*
	 * Handshake
	 */
	if (pos + 1 > data_len) {
		return -5;
	}
	if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		return -5;
	}

	/* Skip past fixed length records:
	 * 1	Handshake Type
	 * 3	Length
	 * 2	Version (again)
	 * 32	Random
	 * to	Session ID Length
	 */
	pos += 38;

	/* Session ID */
	if (pos + 1 > data_len) {
		return -5;
	}
	len = (unsigned char)data[pos];
	pos += 1 + len;

	/* Cipher Suites */
	if (pos + 2 > data_len) {
		return -5;
	}
	len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
	pos += 2 + len;

	/* Compression Methods */
	if (pos + 1 > data_len) {
		return -5;
	}
	len = (unsigned char)data[pos];
	pos += 1 + len;

	if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
		return -2;
	}

	/* Extensions */
	if (pos + 2 > data_len) {
		return -5;
	}
	len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
	pos += 2;

	if (pos + len > data_len) {
		return -5;
	}
	return parse_extensions(data + pos, len, hostname, hostname_ptr);
}

static int parse_extensions(const char *data, size_t data_len, char *hostname, const char **hostname_ptr)
{
	size_t pos = 0;
	size_t len = 0;

	/* Parse each 4 bytes for the extension header */
	while (pos + 4 <= data_len) {
		/* Extension Length */
		len = ((unsigned char)data[pos + 2] << 8) + (unsigned char)data[pos + 3];

		/* Check if it's a server name extension */
		if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
			/* There can be only one extension of each type, so we break
			 * our state and move p to beinnging of the extension here */
			if (pos + 4 + len > data_len) {
				return -5;
			}
			return parse_server_name_extension(data + pos + 4, len, hostname, hostname_ptr);
		}
		pos += 4 + len; /* Advance to the next extension header */
	}
	/* Check we ended where we expected to */
	if (pos != data_len) {
		return -5;
	}

	return -2;
}

static int parse_server_name_extension(const char *data, size_t data_len, char *hostname, const char **hostname_ptr)
{
	size_t pos = 2; /* skip server name list length */
	size_t len = 0;

	while (pos + 3 < data_len) {
		len = ((unsigned char)data[pos + 1] << 8) + (unsigned char)data[pos + 2];

		if (pos + 3 + len > data_len) {
			return -5;
		}

		switch (data[pos]) { /* name type */
		case 0x00:           /* host_name */
			strncpy(hostname, data + pos + 3, len);
			if (hostname_ptr) {
				*hostname_ptr = data + pos + 3;
			}
			hostname[len] = '\0';

			return len;
		default:
			break;
		}
		pos += 3 + len;
	}
	/* Check we ended where we expected to */
	if (pos != data_len) {
		return -5;
	}

	return -2;
}

void get_compiled_time(struct tm *tm)
{
	char s_month[5];
	int month = 0;
	int day = 0;
	int year = 0;
	int hour = 0;
	int min = 0;
	int sec = 0;
	static const char *month_names = "JanFebMarAprMayJunJulAugSepOctNovDec";

	sscanf(__DATE__, "%4s %d %d", s_month, &day, &year);
	month = (strstr(month_names, s_month) - month_names) / 3;
	sscanf(__TIME__, "%d:%d:%d", &hour, &min, &sec);
	tm->tm_year = year - 1900;
	tm->tm_mon = month;
	tm->tm_mday = day;
	tm->tm_isdst = -1;
	tm->tm_hour = hour;
	tm->tm_min = min;
	tm->tm_sec = sec;
}

int is_numeric(const char *str)
{
	while (*str != '\0') {
		if (*str < '0' || *str > '9') {
			return -1;
		}
		str++;
	}
	return 0;
}

int has_network_raw_cap(void)
{
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		return 0;
	}

	close(fd);
	return 1;
}

int has_unprivileged_ping(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (fd < 0) {
		return 0;
	}

	close(fd);

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	if (fd < 0) {
		return 0;
	}

	close(fd);

	return 1;
}

int set_sock_keepalive(int fd, int keepidle, int keepinterval, int keepcnt)
{
	const int yes = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) != 0) {
		return -1;
	}

	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepinterval, sizeof(keepinterval));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepcnt, sizeof(keepcnt));

	return 0;
}

int set_sock_lingertime(int fd, int time)
{
	struct linger l;

	l.l_onoff = 1;
	l.l_linger = 0;

	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l)) != 0) {
		return -1;
	}

	return 0;
}

uint64_t get_free_space(const char *path)
{
	uint64_t size = 0;
	struct statvfs buf;
	if (statvfs(path, &buf) != 0) {
		return 0;
	}

	size = (uint64_t)buf.f_frsize * buf.f_bavail;

	return size;
}

struct backtrace_state {
	void **current;
	void **end;
};

static _Unwind_Reason_Code unwind_callback(struct _Unwind_Context *context, void *arg)
{
	struct backtrace_state *state = (struct backtrace_state *)(arg);
	uintptr_t pc = _Unwind_GetIP(context);
	if (pc) {
		if (state->current == state->end) {
			return _URC_END_OF_STACK;
		}

		*state->current++ = (void *)(pc);
	}
	return _URC_NO_REASON;
}

void print_stack(void)
{
	const size_t max_buffer = 30;
	void *buffer[max_buffer];
	int idx = 0;

	struct backtrace_state state = {buffer, buffer + max_buffer};
	_Unwind_Backtrace(unwind_callback, &state);
	int frame_num = state.current - buffer;
	if (frame_num == 0) {
		return;
	}

	tlog(TLOG_FATAL, "Stack:");
	for (idx = 0; idx < frame_num; ++idx) {
		const void *addr = buffer[idx];
		const char *symbol = "";

		Dl_info info;
		memset(&info, 0, sizeof(info));
		if (dladdr(addr, &info) && info.dli_sname) {
			symbol = info.dli_sname;
		}

		void *offset = (void *)((char *)(addr) - (char *)(info.dli_fbase));
		tlog(TLOG_FATAL, "#%.2d: %p %s() from %s+%p", idx + 1, addr, symbol, info.dli_fname, offset);
	}
}

void bug_ext(const char *file, int line, const char *func, const char *errfmt, ...)
{
	va_list ap;

	va_start(ap, errfmt);
	tlog_vext(TLOG_FATAL, file, line, func, NULL, errfmt, ap);
	va_end(ap);

	print_stack();
	/* trigger BUG */
	sleep(1);
	raise(SIGSEGV);

	while (true) {
		sleep(1);
	};
}

int write_file(const char *filename, void *data, int data_len)
{
	int fd = open(filename, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		return -1;
	}

	int len = write(fd, data, data_len);
	if (len < 0) {
		goto errout;
	}

	close(fd);
	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

int dns_packet_save(const char *dir, const char *type, const char *from, const void *packet, int packet_len)
{
	char *data = NULL;
	int data_len = 0;
	char filename[BUFF_SZ];
	char time_s[BUFF_SZ];
	int ret = -1;

	struct tm *ptm;
	struct tm tm;
	struct timeval tmval;
	struct stat sb;

	if (stat(dir, &sb) != 0) {
		mkdir(dir, 0750);
	}

	if (gettimeofday(&tmval, NULL) != 0) {
		return -1;
	}

	ptm = localtime_r(&tmval.tv_sec, &tm);
	if (ptm == NULL) {
		return -1;
	}

	ret = snprintf(time_s, sizeof(time_s) - 1, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d", ptm->tm_year + 1900,
				   ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, (int)(tmval.tv_usec / 1000));
	ret = snprintf(filename, sizeof(filename) - 1, "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d%.1d.packet", dir, type,
				   ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
				   (int)(tmval.tv_usec / 100000));

	data = malloc(PACKET_BUF_SIZE);
	if (data == NULL) {
		return -1;
	}

	data_len = snprintf(data, PACKET_BUF_SIZE,
						"type: %s\n"
						"from: %s\n"
						"time: %s\n"
						"packet-len: %d\n",
						type, from, time_s, packet_len);
	if (data_len <= 0 || data_len >= PACKET_BUF_SIZE) {
		goto out;
	}

	data[data_len] = 0;
	data_len++;
	uint32_t magic = htonl(PACKET_MAGIC);
	memcpy(data + data_len, &magic, sizeof(magic));
	data_len += sizeof(magic);
	int len_in_h = htonl(packet_len);
	memcpy(data + data_len, &len_in_h, sizeof(len_in_h));
	data_len += 4;
	memcpy(data + data_len, packet, packet_len);
	data_len += packet_len;

	ret = write_file(filename, data, data_len);
	if (ret != 0) {
		goto out;
	}

	ret = 0;
out:
	if (data) {
		free(data);
	}

	return ret;
}

#ifdef DEBUG
struct _dns_read_packet_info {
	int data_len;
	int message_len;
	char *message;
	int packet_len;
	uint8_t *packet;
	uint8_t data[0];
};

static struct _dns_read_packet_info *_dns_read_packet_file(const char *packet_file)
{
	struct _dns_read_packet_info *info = NULL;
	int fd = 0;
	int len = 0;
	int message_len = 0;
	uint8_t *ptr = NULL;

	info = malloc(sizeof(struct _dns_read_packet_info) + PACKET_BUF_SIZE);
	fd = open(packet_file, O_RDONLY);
	if (fd < 0) {
		printf("open file %s failed, %s\n", packet_file, strerror(errno));
		goto errout;
	}

	len = read(fd, info->data, PACKET_BUF_SIZE);
	if (len < 0) {
		printf("read file %s failed, %s\n", packet_file, strerror(errno));
		goto errout;
	}

	message_len = strnlen((char *)info->data, PACKET_BUF_SIZE);
	if (message_len >= 512 || message_len >= len) {
		printf("invalid packet file, bad message len\n");
		goto errout;
	}

	info->message_len = message_len;
	info->message = (char *)info->data;

	ptr = info->data + message_len + 1;
	uint32_t magic = 0;
	if (ptr - (uint8_t *)info + sizeof(magic) >= (size_t)len) {
		printf("invalid packet file, magic length is invalid.\n");
		goto errout;
	}

	memcpy(&magic, ptr, sizeof(magic));
	if (magic != htonl(PACKET_MAGIC)) {
		printf("invalid packet file, bad magic\n");
		goto errout;
	}
	ptr += sizeof(magic);

	uint32_t packet_len = 0;
	if (ptr - info->data + sizeof(packet_len) >= (size_t)len) {
		printf("invalid packet file, packet length is invalid.\n");
		goto errout;
	}

	memcpy(&packet_len, ptr, sizeof(packet_len));
	packet_len = ntohl(packet_len);
	ptr += sizeof(packet_len);
	if (packet_len != (size_t)len - (ptr - info->data)) {
		printf("invalid packet file, packet length is invalid\n");
		goto errout;
	}

	info->packet_len = packet_len;
	info->packet = ptr;

	close(fd);
	return info;
errout:

	if (fd > 0) {
		close(fd);
	}

	if (info) {
		free(info);
	}

	return NULL;
}

static int _dns_debug_display(struct dns_packet *packet)
{
	int i = 0;
	int j = 0;
	int ttl = 0;
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	char req_host[MAX_IP_LEN];

	for (j = 1; j < DNS_RRS_END; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		printf("section: %d\n", j);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				char name[DNS_MAX_CNAME_LEN] = {0};
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);
				req_host[0] = '\0';
				inet_ntop(AF_INET, addr, req_host, sizeof(req_host));
				printf("domain: %s A: %s TTL: %d\n", name, req_host, ttl);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);
				req_host[0] = '\0';
				inet_ntop(AF_INET6, addr, req_host, sizeof(req_host));
				printf("domain: %s AAAA: %s TTL:%d\n", name, req_host, ttl);
			} break;
			case DNS_T_NS: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				printf("domain: %s TTL: %d NS: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				if (dns_conf_force_no_cname) {
					continue;
				}

				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				printf("domain: %s TTL: %d CNAME: %s\n", name, ttl, cname);
			} break;
			case DNS_T_SOA: {
				char name[DNS_MAX_CNAME_LEN] = {0};
				struct dns_soa soa;
				dns_get_SOA(rrs, name, 128, &ttl, &soa);
				printf("domain: %s SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, expire: "
					   "%d, minimum: %d",
					   name, soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum);
			} break;
			default:
				break;
			}
		}
		printf("\n");
	}

	return 0;
}

int dns_packet_debug(const char *packet_file)
{
	struct _dns_read_packet_info *info = NULL;
	char buff[DNS_PACKSIZE];

	tlog_setlogscreen_only(1);
	tlog_setlevel(TLOG_DEBUG);

	info = _dns_read_packet_file(packet_file);
	if (info == NULL) {
		goto errout;
	}

	const char *send_env = getenv("SMARTDNS_DEBUG_SEND");
	if (send_env != NULL) {
		char ip[32];
		int port = 53;
		if (parse_ip(send_env, ip, &port) == 0) {
			int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
			if (sockfd > 0) {
				struct sockaddr_in server;
				server.sin_family = AF_INET;
				server.sin_port = htons(port);
				server.sin_addr.s_addr = inet_addr(ip);
				sendto(sockfd, info->packet, info->packet_len, 0, (struct sockaddr *)&server, sizeof(server));
				close(sockfd);
			}
		}
	}

	struct dns_packet *packet = (struct dns_packet *)buff;
	if (dns_decode(packet, DNS_PACKSIZE, info->packet, info->packet_len) != 0) {
		printf("decode failed.\n");
		goto errout;
	}

	_dns_debug_display(packet);

	free(info);
	return 0;

errout:
	if (info) {
		free(info);
	}

	return -1;
}

#endif