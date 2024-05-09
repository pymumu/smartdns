/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_UNWIND_BACKTRACE
#include <unwind.h>
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

enum daemon_msg_type {
	DAEMON_MSG_KICKOFF,
	DAEMON_MSG_KEEPALIVE,
	DAEMON_MSG_DAEMON_PID,
};

struct daemon_msg {
	enum daemon_msg_type type;
	int value;
};

static int ipset_fd;
static int pidfile_fd;
static int daemon_fd;
static int netlink_neighbor_fd;

unsigned long get_tick_count(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

char *dir_name(char *path)
{
	if (strstr(path, "/") == NULL) {
		safe_strncpy(path, "./", PATH_MAX);
		return path;
	}

	return dirname(path);
}

char *get_host_by_addr(char *host, int maxsize, struct sockaddr *addr)
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

int generate_random_addr(unsigned char *addr, int addr_len, int mask)
{
	if (mask / 8 > addr_len) {
		return -1;
	}

	int offset = mask / 8;
	int bit = 0;

	for (int i = offset; i < addr_len; i++) {
		bit = 0xFF;
		if (i == offset) {
			bit = ~(0xFF << (8 - mask % 8)) & 0xFF;
		}
		addr[i] = jhash(&addr[i], 1, 0) & bit;
	}

	return 0;
}

int generate_addr_map(const unsigned char *addr_from, const unsigned char *addr_to, unsigned char *addr_out,
					  int addr_len, int mask)
{
	if ((mask / 8) >= addr_len) {
		if (mask % 8 != 0) {
			return -1;
		}
	}

	int offset = mask / 8;
	int bit = mask % 8;
	for (int i = 0; i < offset; i++) {
		addr_out[i] = addr_to[i];
	}

	if (bit != 0) {
		int mask1 = 0xFF >> bit;
		int mask2 = (0xFF << (8 - bit)) & 0xFF;
		addr_out[offset] = addr_from[offset] & mask1;
		addr_out[offset] |= addr_to[offset] & mask2;
		offset = offset + 1;
	}

	for (int i = offset; i < addr_len; i++) {
		addr_out[i] = addr_from[i];
	}

	return 0;
}

int is_private_addr(const unsigned char *addr, int addr_len)
{
	if (addr_len == IPV4_ADDR_LEN) {
		if (addr[0] == 10) {
			return 1;
		}

		if (addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31) {
			return 1;
		}

		if (addr[0] == 192 && addr[1] == 168) {
			return 1;
		}
	} else if (addr_len == IPV6_ADDR_LEN) {
		if (addr[0] == 0xFD) {
			return 1;
		}

		if (addr[0] == 0xFE && addr[1] == 0x80) {
			return 1;
		}
	}

	return 0;
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

int get_raw_addr_by_ip(const char *ip, unsigned char *raw_addr, int *raw_addr_len)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		if (*raw_addr_len < DNS_RR_A_LEN) {
			goto errout;
		}
		memcpy(raw_addr, &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
		*raw_addr_len = DNS_RR_A_LEN;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			if (*raw_addr_len < DNS_RR_A_LEN) {
				goto errout;
			}
			memcpy(raw_addr, addr_in6->sin6_addr.s6_addr + 12, DNS_RR_A_LEN);
			*raw_addr_len = DNS_RR_A_LEN;
		} else {
			if (*raw_addr_len < DNS_RR_AAAA_LEN) {
				goto errout;
			}
			memcpy(raw_addr, addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
			*raw_addr_len = DNS_RR_AAAA_LEN;
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

int getsocket_inet(int fd, struct sockaddr *addr, socklen_t *addr_len)
{
	struct sockaddr_storage addr_store;
	socklen_t addr_store_len = sizeof(addr_store);
	if (getsockname(fd, (struct sockaddr *)&addr_store, &addr_store_len) != 0) {
		goto errout;
	}

	switch (addr_store.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr_store;
		addr_in->sin_family = AF_INET;
		*addr_len = sizeof(struct sockaddr_in);
		memcpy(addr, addr_in, sizeof(struct sockaddr_in));
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr_store;
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

int check_is_ipv4(const char *ip)
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

int check_is_ipv6(const char *ip)
{
	const char *ptr = ip;
	char c = 0;
	int colon_num = 0;
	int dig_num = 0;

	while ((c = *ptr++) != '\0') {
		if (c == '[' || c == ']') {
			continue;
		}

		/* scope id, end of ipv6 address*/
		if (c == '%') {
			break;
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
		return check_is_ipv4(ip);
	} else if (strstr(ip, ":")) {
		/* IPV6 */
		return check_is_ipv6(ip);
	}
	return -1;
}

int parse_uri(const char *value, char *scheme, char *host, int *port, char *path)
{
	return parse_uri_ext(value, scheme, NULL, NULL, host, port, path);
}

int urldecode(char *dst, int dst_maxlen, const char *src)
{
	char a, b;
	int len = 0;
	while (*src) {
		if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
			if (a >= 'a') {
				a -= 'a' - 'A';
			}

			if (a >= 'A') {
				a -= ('A' - 10);
			} else {
				a -= '0';
			}

			if (b >= 'a') {
				b -= 'a' - 'A';
			}

			if (b >= 'A') {
				b -= ('A' - 10);
			} else {
				b -= '0';
			}
			*dst++ = 16 * a + b;
			src += 3;
		} else if (*src == '+') {
			*dst++ = ' ';
			src++;
		} else {
			*dst++ = *src++;
		}

		len++;
		if (len >= dst_maxlen - 1) {
			return -1;
		}
	}
	*dst++ = '\0';

	return len;
}

int parse_uri_ext(const char *value, char *scheme, char *user, char *password, char *host, int *port, char *path)
{
	char *scheme_end = NULL;
	int field_len = 0;
	const char *process_ptr = value;
	char user_pass_host_part[PATH_MAX];
	char *user_password = NULL;
	char *host_part = NULL;

	const char *host_end = NULL;

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
		host_end = process_ptr + strlen(process_ptr);
	};

	field_len = host_end - process_ptr;
	if (field_len >= (int)sizeof(user_pass_host_part)) {
		return -1;
	}
	memcpy(user_pass_host_part, process_ptr, field_len);
	user_pass_host_part[field_len] = 0;

	host_part = strstr(user_pass_host_part, "@");
	if (host_part != NULL) {
		*host_part = '\0';
		host_part = host_part + 1;
		user_password = user_pass_host_part;
		char *sep = strstr(user_password, ":");
		if (sep != NULL) {
			*sep = '\0';
			sep = sep + 1;
			if (password) {
				if (urldecode(password, 128, sep) < 0) {
					return -1;
				}
			}
		}
		if (user) {
			if (urldecode(user, 128, user_password) < 0) {
				return -1;
			}
		}
	} else {
		host_part = user_pass_host_part;
	}

	if (host != NULL && parse_ip(host_part, host, port) != 0) {
		return -1;
	}

	process_ptr += field_len;

	if (path) {
		strcpy(path, process_ptr);
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

	ipset_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);

	if (ipset_fd < 0) {
		return -1;
	}

	return 0;
}

static int _ipset_operate(const char *ipset_name, const unsigned char addr[], int addr_len, unsigned long timeout,
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

	if (strlen(ipset_name) >= IPSET_MAXNAMELEN) {
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
	_ipset_add_attr(netlink_head, IPSET_ATTR_SETNAME, strlen(ipset_name) + 1, ipset_name);

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

	if (timeout > 0) {
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

int ipset_add(const char *ipset_name, const unsigned char addr[], int addr_len, unsigned long timeout)
{
	return _ipset_operate(ipset_name, addr, addr_len, timeout, IPSET_ADD);
}

int ipset_del(const char *ipset_name, const unsigned char addr[], int addr_len)
{
	return _ipset_operate(ipset_name, addr, addr_len, 0, IPSET_DEL);
}

int netlink_get_neighbors(int family,
						  int (*callback)(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6], void *arg),
						  void *arg)
{
	if (netlink_neighbor_fd <= 0) {
		netlink_neighbor_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
		if (netlink_neighbor_fd < 0) {
			return -1;
		}
	}

	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	char buf[1024 * 16];
	struct iovec iov = {buf, sizeof(buf)};
	struct sockaddr_nl sa;
	struct msghdr msg;
	int len;
	int ret = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	nlh->nlmsg_type = RTM_GETNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = time(NULL);
	nlh->nlmsg_pid = getpid();

	ndm = NLMSG_DATA(nlh);
	ndm->ndm_family = family;

	if (send(netlink_neighbor_fd, buf, NLMSG_SPACE(sizeof(struct ndmsg)), 0) < 0) {
		return -1;
	}

	while ((len = recvmsg(netlink_neighbor_fd, &msg, 0)) > 0) {
		if (ret != 0) {
			continue;
		}

		int nlh_len = len;
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, nlh_len); nlh = NLMSG_NEXT(nlh, nlh_len)) {
			ndm = NLMSG_DATA(nlh);
			struct rtattr *rta = RTM_RTA(ndm);
			const uint8_t *mac = NULL;
			const uint8_t *net_addr = NULL;
			int net_addr_len = 0;
			int rta_len = RTM_PAYLOAD(nlh);

			for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
				if (rta->rta_type == NDA_DST) {
					if (ndm->ndm_family == AF_INET) {
						struct in_addr *addr = RTA_DATA(rta);
						if (IN_MULTICAST(ntohl(addr->s_addr))) {
							continue;
						}

						if (ntohl(addr->s_addr) == 0) {
							continue;
						}

						net_addr = (uint8_t *)&addr->s_addr;
						net_addr_len = IPV4_ADDR_LEN;
					} else if (ndm->ndm_family == AF_INET6) {
						struct in6_addr *addr = RTA_DATA(rta);
						if (IN6_IS_ADDR_MC_NODELOCAL(addr)) {
							continue;
						}
						if (IN6_IS_ADDR_MC_LINKLOCAL(addr)) {
							continue;
						}
						if (IN6_IS_ADDR_MC_SITELOCAL(addr)) {
							continue;
						}

						if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
							continue;
						}

						net_addr = addr->s6_addr;
						net_addr_len = IPV6_ADDR_LEN;
					}
				} else if (rta->rta_type == NDA_LLADDR) {
					mac = RTA_DATA(rta);
				}
			}

			if (net_addr != NULL && mac != NULL) {
				ret = callback(net_addr, net_addr_len, mac, arg);
				if (ret != 0) {
					break;
				}
			}
		}
	}

	return ret;
}

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

int SSL_base64_decode_ext(const char *in, unsigned char *out, int max_outlen, int url_safe, int auto_padding)
{
	size_t inlen = strlen(in);
	char *in_padding_data = NULL;
	int padding_len = 0;
	const char *in_data = in;
	int outlen = 0;

	if (inlen == 0) {
		return 0;
	}

	if (inlen % 4 == 0) {
		auto_padding = 0;
	}

	if (auto_padding == 1 || url_safe == 1) {
		padding_len = 4 - inlen % 4;
		in_padding_data = (char *)malloc(inlen + padding_len + 1);
		if (in_padding_data == NULL) {
			goto errout;
		}

		if (url_safe) {
			for (size_t i = 0; i < inlen; i++) {
				if (in[i] == '-') {
					in_padding_data[i] = '+';
				} else if (in[i] == '_') {
					in_padding_data[i] = '/';
				} else {
					in_padding_data[i] = in[i];
				}
			}
		} else {
			memcpy(in_padding_data, in, inlen);
		}

		if (auto_padding) {
			memset(in_padding_data + inlen, '=', padding_len);
		} else {
			padding_len = 0;
		}

		in_padding_data[inlen + padding_len] = '\0';
		in_data = in_padding_data;
		inlen += padding_len;
	}

	if (max_outlen < (int)inlen / 4 * 3) {
		goto errout;
	}

	outlen = EVP_DecodeBlock(out, (unsigned char *)in_data, inlen);
	if (outlen < 0) {
		goto errout;
	}

	/* Subtract padding bytes from |outlen| */
	while (in[--inlen] == '=') {
		--outlen;
	}

	if (in_padding_data) {
		free(in_padding_data);
	}

	outlen -= padding_len;

	return outlen;
errout:

	if (in_padding_data) {
		free(in_padding_data);
	}

	return -1;
}

int SSL_base64_decode(const char *in, unsigned char *out, int max_outlen)
{
	return SSL_base64_decode_ext(in, out, max_outlen, 0, 0);
}

int SSL_base64_encode(const void *in, int in_len, char *out)
{
	int outlen = 0;

	if (in_len == 0) {
		return 0;
	}

	outlen = EVP_EncodeBlock((unsigned char *)out, in, in_len);
	if (outlen < 0) {
		goto errout;
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
		fprintf(stderr, "create pid file %s failed, %s\n", pid_file, strerror(errno));
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
		memset(buff, 0, TMP_BUFF_LEN_32);
		if (read(fd, buff, TMP_BUFF_LEN_32) <= 0) {
			buff[0] = '\0';
		}
		fprintf(stderr, "Server is already running, pid is %s", buff);
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

int full_path(char *normalized_path, int normalized_path_len, const char *path)
{
	const char *p = path;

	if (path == NULL || normalized_path == NULL) {
		return -1;
	}

	while (*p == ' ') {
		p++;
	}

	if (*p == '\0' || *p == '/') {
		return -1;
	}

	char buf[PATH_MAX];
	snprintf(normalized_path, normalized_path_len, "%s/%s", getcwd(buf, sizeof(buf)), path);
	return 0;
}

int generate_cert_key(const char *key_path, const char *cert_path, const char *san, int days)
{
	int ret = -1;
#if (OPENSSL_VERSION_NUMBER <= 0x30000000L)
	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
#endif
	X509_EXTENSION *cert_ext = NULL;
	BIO *cert_file = NULL;
	BIO *key_file = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	const int RSA_KEY_LENGTH = 2048;

	if (key_path == NULL || cert_path == NULL) {
		return ret;
	}

	key_file = BIO_new_file(key_path, "wb");
	cert_file = BIO_new_file(cert_path, "wb");
	cert = X509_new();
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	pkey = EVP_RSA_gen(RSA_KEY_LENGTH);
#else
	bn = BN_new();
	rsa = RSA_new();
	pkey = EVP_PKEY_new();
	if (rsa == NULL || pkey == NULL || bn == NULL) {
		goto out;
	}

	EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
	BN_set_word(bn, RSA_F4);
	if (RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, bn, NULL) != 1) {
		goto out;
	}
#endif

	if (key_file == NULL || cert_file == NULL || cert == NULL || pkey == NULL) {
		goto out;
	}

	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);           // serial number
	X509_gmtime_adj(X509_get_notBefore(cert), 0);               // now
	X509_gmtime_adj(X509_get_notAfter(cert), days * 24 * 3600); // accepts secs

	X509_set_pubkey(cert, pkey);

	X509_NAME *name = X509_get_subject_name(cert);

	const unsigned char *country = (unsigned char *)"smartdns";
	const unsigned char *company = (unsigned char *)"smartdns";
	const unsigned char *common_name = (unsigned char *)"smartdns";

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1, 0);

	if (san != NULL) {
		cert_ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
		if (cert_ext == NULL) {
			goto out;
		}
		X509_add_ext(cert, cert_ext, -1);
	}

	X509_set_issuer_name(cert, name);
	X509_sign(cert, pkey, EVP_sha256());

	ret = PEM_write_bio_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL);
	if (ret != 1) {
		goto out;
	}

	ret = PEM_write_bio_X509(cert_file, cert);
	if (ret != 1) {
		goto out;
	}

	chmod(key_path, S_IRUSR);
	chmod(cert_path, S_IRUSR);

	ret = 0;
out:
	if (cert_ext) {
		X509_EXTENSION_free(cert_ext);
	}

	if (pkey) {
		EVP_PKEY_free(pkey);
	}

#if (OPENSSL_VERSION_NUMBER <= 0x30000000L)
	if (rsa && pkey == NULL) {
		RSA_free(rsa);
	}

	if (bn) {
		BN_free(bn);
	}
#endif

	if (cert_file) {
		BIO_free_all(cert_file);
	}

	if (key_file) {
		BIO_free_all(key_file);
	}

	if (cert) {
		X509_free(cert);
	}

	return ret;
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

	if (lock_cs != NULL) {
		return;
	}

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

	if (lock_cs == NULL) {
		return;
	}

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);
	lock_cs = NULL;
	lock_count = NULL;
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
			 * our state and move p to beginning of the extension here */
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

unsigned long get_system_mem_size(void)
{
	struct sysinfo memInfo;
	sysinfo(&memInfo);
	long long totalMem = memInfo.totalram;
	totalMem *= memInfo.mem_unit;

	return totalMem;
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
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval));
	setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

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

#ifdef HAVE_UNWIND_BACKTRACE

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
#else
void print_stack(void) { }
#endif

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
	int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0644);
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
	struct timeval tm_val;
	struct stat sb;

	if (stat(dir, &sb) != 0) {
		mkdir(dir, 0750);
	}

	if (gettimeofday(&tm_val, NULL) != 0) {
		return -1;
	}

	ptm = localtime_r(&tm_val.tv_sec, &tm);
	if (ptm == NULL) {
		return -1;
	}

	snprintf(time_s, sizeof(time_s) - 1, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d", ptm->tm_year + 1900, ptm->tm_mon + 1,
			 ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, (int)(tm_val.tv_usec / 1000));
	snprintf(filename, sizeof(filename) - 1, "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d%.3d.packet", dir, type,
			 ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
			 (int)(tm_val.tv_usec / 1000));

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

static void _close_all_fd_by_res(void)
{
	struct rlimit lim;
	int maxfd = 0;
	int i = 0;

	getrlimit(RLIMIT_NOFILE, &lim);

	maxfd = lim.rlim_cur;
	if (maxfd > 4096) {
		maxfd = 4096;
	}

	for (i = 3; i < maxfd; i++) {
		close(i);
	}
}

void close_all_fd(int keepfd)
{
	DIR *dirp;
	int dir_fd = -1;
	struct dirent *dentp;

	dirp = opendir("/proc/self/fd");
	if (dirp == NULL) {
		goto errout;
	}

	dir_fd = dirfd(dirp);

	while ((dentp = readdir(dirp)) != NULL) {
		int fd = atol(dentp->d_name);
		if (fd < 0) {
			continue;
		}

		if (fd == dir_fd || fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO || fd == keepfd) {
			continue;
		}
		close(fd);
	}

	closedir(dirp);
	return;
errout:
	if (dirp) {
		closedir(dirp);
	}
	_close_all_fd_by_res();
	return;
}

void daemon_close_stdfds(void)
{
	int fd_null = open("/dev/null", O_RDWR);
	if (fd_null < 0) {
		fprintf(stderr, "open /dev/null failed, %s\n", strerror(errno));
		return;
	}

	dup2(fd_null, STDIN_FILENO);
	dup2(fd_null, STDOUT_FILENO);
	dup2(fd_null, STDERR_FILENO);

	if (fd_null > 2) {
		close(fd_null);
	}
}

int daemon_kickoff(int status, int no_close)
{
	struct daemon_msg msg;

	if (daemon_fd <= 0) {
		return -1;
	}

	msg.type = DAEMON_MSG_KICKOFF;
	msg.value = status;

	int ret = write(daemon_fd, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		fprintf(stderr, "notify parent process failed, %s\n", strerror(errno));
		return -1;
	}

	if (no_close == 0) {
		daemon_close_stdfds();
	}

	close(daemon_fd);
	daemon_fd = -1;

	return 0;
}

int daemon_keepalive(void)
{
	struct daemon_msg msg;
	static time_t last = 0;
	time_t now = time(NULL);

	if (daemon_fd <= 0) {
		return -1;
	}

	if (now == last) {
		return 0;
	}

	last = now;

	msg.type = DAEMON_MSG_KEEPALIVE;
	msg.value = 0;

	int ret = write(daemon_fd, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		return -1;
	}

	return 0;
}

daemon_ret daemon_run(int *wstatus)
{
	pid_t pid = 0;
	int fds[2] = {0};

	if (pipe(fds) != 0) {
		fprintf(stderr, "run daemon process failed, pipe failed, %s\n", strerror(errno));
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "run daemon process failed, fork failed, %s\n", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return -1;
	} else if (pid > 0) {
		struct pollfd pfd;
		int ret = 0;

		close(fds[1]);

		pfd.fd = fds[0];
		pfd.events = POLLIN;
		pfd.revents = 0;

		do {
			ret = poll(&pfd, 1, 3000);
			if (ret <= 0) {
				fprintf(stderr, "run daemon process failed, wait child timeout, kill child.\n");
				goto errout;
			}

			if (!(pfd.revents & POLLIN)) {
				goto errout;
			}

			struct daemon_msg msg;

			ret = read(fds[0], &msg, sizeof(msg));
			if (ret != sizeof(msg)) {
				goto errout;
			}

			if (msg.type == DAEMON_MSG_KEEPALIVE) {
				continue;
			} else if (msg.type == DAEMON_MSG_DAEMON_PID) {
				pid = msg.value;
				continue;
			} else if (msg.type == DAEMON_MSG_KICKOFF) {
				if (wstatus != NULL) {
					*wstatus = msg.value;
				}
				return DAEMON_RET_PARENT_OK;
			} else {
				goto errout;
			}
		} while (true);

		return DAEMON_RET_ERR;
	}

	setsid();

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "double fork failed, %s\n", strerror(errno));
		_exit(1);
	} else if (pid > 0) {
		struct daemon_msg msg;
		int unused __attribute__((unused));
		msg.type = DAEMON_MSG_DAEMON_PID;
		msg.value = pid;
		unused = write(fds[1], &msg, sizeof(msg));
		_exit(0);
	}

	umask(0);
	if (chdir("/") != 0) {
		goto errout;
	}
	close(fds[0]);

	daemon_fd = fds[1];
	return DAEMON_RET_CHILD_OK;
errout:
	kill(pid, SIGKILL);
	if (wstatus != NULL) {
		*wstatus = -1;
	}
	return DAEMON_RET_ERR;
}

int parser_mac_address(const char *in_mac, uint8_t mac[6])
{
	int fileld_num = 0;

	if (in_mac == NULL) {
		return -1;
	}

	fileld_num =
		sscanf(in_mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (fileld_num == 6) {
		return 0;
	}

	fileld_num =
		sscanf(in_mac, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (fileld_num == 6) {
		return 0;
	}

	return -1;
}

#if defined(DEBUG) || defined(TEST)
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
	int ret;

	for (j = 1; j < DNS_RRS_OPT; j++) {
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
			case DNS_T_SRV: {
				unsigned short priority = 0;
				unsigned short weight = 0;
				unsigned short port = 0;

				char name[DNS_MAX_CNAME_LEN] = {0};
				char target[DNS_MAX_CNAME_LEN];

				ret = dns_get_SRV(rrs, name, DNS_MAX_CNAME_LEN, &ttl, &priority, &weight, &port, target,
								  DNS_MAX_CNAME_LEN);
				if (ret < 0) {
					tlog(TLOG_DEBUG, "decode SRV failed, %s", name);
					return -1;
				}

				printf("domain: %s SRV: %s TTL: %d priority: %d weight: %d port: %d\n", name, target, ttl, priority,
					   weight, port);
			} break;
			case DNS_T_HTTPS: {
				char name[DNS_MAX_CNAME_LEN] = {0};
				char target[DNS_MAX_CNAME_LEN] = {0};
				struct dns_https_param *p = NULL;
				int priority = 0;

				ret = dns_get_HTTPS_svcparm_start(rrs, &p, name, DNS_MAX_CNAME_LEN, &ttl, &priority, target,
												  DNS_MAX_CNAME_LEN);
				if (ret != 0) {
					printf("get HTTPS svcparm failed\n");
					break;
				}

				printf("domain: %s HTTPS: %s TTL: %d priority: %d\n", name, target, ttl, priority);

				for (; p; p = dns_get_HTTPS_svcparm_next(rrs, p)) {
					switch (p->key) {
					case DNS_HTTPS_T_MANDATORY: {
						printf("  HTTPS: mandatory: %s\n", p->value);
					} break;
					case DNS_HTTPS_T_ALPN: {
						char alph[64] = {0};
						int total_alph_len = 0;
						char *ptr = (char *)p->value;
						do {
							int alphlen = *ptr;
							memcpy(alph + total_alph_len, ptr + 1, alphlen);
							total_alph_len += alphlen;
							ptr += alphlen + 1;
							alph[total_alph_len] = ',';
							total_alph_len++;
							alph[total_alph_len] = ' ';
							total_alph_len++;
						} while (ptr - (char *)p->value < p->len);
						if (total_alph_len > 2) {
							alph[total_alph_len - 2] = '\0';
						}
						printf("  HTTPS: alpn: %s\n", alph);
					} break;
					case DNS_HTTPS_T_NO_DEFAULT_ALPN: {
						printf("  HTTPS: no_default_alpn: %s\n", p->value);
					} break;
					case DNS_HTTPS_T_PORT: {
						int port = *(unsigned short *)(p->value);
						printf("  HTTPS: port: %d\n", port);
					} break;
					case DNS_HTTPS_T_IPV4HINT: {
						printf("  HTTPS: ipv4hint: %d\n", p->len / 4);
						for (int k = 0; k < p->len / 4; k++) {
							char ip[16] = {0};
							inet_ntop(AF_INET, p->value + k * 4, ip, sizeof(ip));
							printf("    ipv4: %s\n", ip);
						}
					} break;
					case DNS_HTTPS_T_ECH: {
						printf("  HTTPS: ech: ");
						for (int k = 0; k < p->len; k++) {
							printf("%02x ", p->value[k]);
						}
						printf("\n");
					} break;
					case DNS_HTTPS_T_IPV6HINT: {
						printf("  HTTPS: ipv6hint: %d\n", p->len / 16);
						for (int k = 0; k < p->len / 16; k++) {
							char ip[64] = {0};
							inet_ntop(AF_INET6, p->value + k * 16, ip, sizeof(ip));
							printf("    ipv6: %s\n", ip);
						}
					} break;
					}
				}
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

	rr_count = 0;
	rrs = dns_get_rrs_start(packet, DNS_RRS_OPT, &rr_count);
	if (rr_count <= 0) {
		return 0;
	}

	printf("section opt:\n");
	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		switch (rrs->type) {
		case DNS_OPT_T_TCP_KEEPALIVE: {
			unsigned short idle_timeout = 0;
			ret = dns_get_OPT_TCP_KEEPALIVE(rrs, &idle_timeout);
			if (idle_timeout == 0) {
				continue;
			}

			printf("tcp keepalive: %d\n", idle_timeout);
		} break;
		case DNS_OPT_T_ECS: {
			struct dns_opt_ecs ecs;
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			printf("ecs family: %d, src_prefix: %d, scope_prefix: %d, ", ecs.family, ecs.source_prefix,
				   ecs.scope_prefix);
			if (ecs.family == 1) {
				char ip[16] = {0};
				inet_ntop(AF_INET, ecs.addr, ip, sizeof(ip));
				printf("ecs address: %s\n", ip);
			} else if (ecs.family == 2) {
				char ip[64] = {0};
				inet_ntop(AF_INET6, ecs.addr, ip, sizeof(ip));
				printf("ecs address: %s\n", ip);
			}
		} break;
		default:
			break;
		}
	}

	return 0;
}

int dns_packet_debug(const char *packet_file)
{
	struct _dns_read_packet_info *info = NULL;
	char buff[DNS_PACKSIZE];

	tlog_set_maxlog_count(0);
	tlog_setlogscreen(1);
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
