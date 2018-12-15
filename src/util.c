#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NFNL_SUBSYS_IPSET 6

#define IPSET_ATTR_DATA 7
#define IPSET_ATTR_IP 1
#define IPSET_ATTR_IPADDR_IPV4 1
#define IPSET_ATTR_IPADDR_IPV6 2
#define IPSET_ATTR_PROTOCOL 1
#define IPSET_ATTR_SETNAME 2
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

#define BUFF_SZ 256

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

static int _ipset_operate(const char *ipsetname, const unsigned char addr[], int addr_len, int operate)
{
	struct nlmsghdr *netlink_head;
	struct ipset_netlink_msg *netlink_msg;
	struct ipset_netlink_attr *nested[2];
	char buffer[BUFF_SZ];
	uint8_t proto;
	ssize_t rc;
	int af = 0;
	static const struct sockaddr_nl snl = {.nl_family = AF_NETLINK};

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
	netlink_head->nlmsg_flags = NLM_F_REQUEST;

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
	_ipset_add_attr(netlink_head, (af == AF_INET ? IPSET_ATTR_IPADDR_IPV4 : IPSET_ATTR_IPADDR_IPV6) | NLA_F_NET_BYTEORDER, addr_len, addr);

	nested[1]->len = (void *)buffer + NETLINK_ALIGN(netlink_head->nlmsg_len) - (void *)nested[1];
	nested[0]->len = (void *)buffer + NETLINK_ALIGN(netlink_head->nlmsg_len) - (void *)nested[0];

	for (;;) {
		rc = sendto(ipset_fd, buffer, netlink_head->nlmsg_len, 0, (struct sockaddr *)&snl, sizeof(snl));
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

int ipset_add(const char *ipsetname, const unsigned char addr[], int addr_len)
{
	return _ipset_operate(ipsetname, addr, addr_len, IPSET_ADD);
}

int ipset_del(const char *ipsetname, const unsigned char addr[], int addr_len)
{
	return _ipset_operate(ipsetname, addr, addr_len, IPSET_DEL);
}