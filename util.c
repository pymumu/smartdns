#include "util.h"
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

unsigned long get_tick_count()
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