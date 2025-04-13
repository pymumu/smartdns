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

#include "smartdns/dns.h"
#include "smartdns/lib/jhash.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

char *get_host_by_addr(char *host, int maxsize, const struct sockaddr *addr)
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

int is_private_addr_sockaddr(const struct sockaddr *addr, socklen_t addr_len)
{
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		return is_private_addr((const unsigned char *)&addr_in->sin_addr.s_addr, IPV4_ADDR_LEN);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			return is_private_addr(addr_in6->sin6_addr.s6_addr + 12, IPV4_ADDR_LEN);
		} else {
			return is_private_addr(addr_in6->sin6_addr.s6_addr, IPV6_ADDR_LEN);
		}
	} break;
	default:
		goto errout;
		break;
	}

errout:
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

int get_raw_addr_by_sockaddr(const struct sockaddr_storage *addr, int addr_len, unsigned char *raw_addr,
							 int *raw_addr_len)
{
	switch (addr->ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		if (*raw_addr_len < DNS_RR_A_LEN) {
			goto errout;
		}
		memcpy(raw_addr, &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
		*raw_addr_len = DNS_RR_A_LEN;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
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

int get_raw_addr_by_ip(const char *ip, unsigned char *raw_addr, int *raw_addr_len)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	return get_raw_addr_by_sockaddr(&addr, addr_len, raw_addr, raw_addr_len);
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

