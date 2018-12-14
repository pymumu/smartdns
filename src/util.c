#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

unsigned long get_tick_count(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

char *gethost_by_addr(char *host, struct sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_storage *addr_store = (struct sockaddr_storage *)addr;
	host[0] = 0;
	switch (addr_store->ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in;
		addr_in = (struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &addr_in->sin_addr, host, addr_len);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			struct sockaddr_in addr_in4;
			memset(&addr_in4, 0, sizeof(addr_in4));
			memcpy(&addr_in4.sin_addr.s_addr, addr_in6->sin6_addr.s6_addr + 12, sizeof(addr_in4.sin_addr.s_addr));
			inet_ntop(AF_INET, &addr_in4.sin_addr, host, addr_len);
		} else {
			inet_ntop(AF_INET6, &addr_in6->sin6_addr, host, addr_len);
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

int getaddr_by_host(char *host, struct sockaddr *addr, socklen_t *addr_len)
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

int set_fd_nonblock(int fd, int nonblock)
{
	int ret;
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

char *reverse_string(char *output, char *input, int len)
{
	char *begin = output;
	if (len <= 0) {
		*output = 0;
		return output;
	}
	
	len--;
	while (len >= 0) {
		*output = *(input + len);
		output++;
		len--;
	}

	*output = 0;

	return begin;
}
