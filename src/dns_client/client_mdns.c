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

#define _GNU_SOURCE

#include "client_mdns.h"
#include "server_info.h"

#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

int _dns_client_create_socket_udp_mdns(struct dns_server_info *server_info)
{
	int fd = -1;
	struct epoll_event event;
	const int on = 1;
	const int val = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	fd = socket(server_info->ai_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	safe_strncpy(ifr.ifr_name, server_info->flags.ifname, sizeof(ifr.ifr_name));
	ioctl(fd, SIOCGIFINDEX, &ifr);
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
		tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
		goto errout;
	}

	server_info->fd = fd;
	server_info->status = DNS_SERVER_STATUS_CONNECTIONLESS;
	server_info->security_status = DNS_CLIENT_SERVER_SECURITY_NOT_APPLICABLE;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	setsockopt(server_info->fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	setsockopt(server_info->fd, SOL_IP, IP_TTL, &val, sizeof(val));
	setsockopt(server_info->fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(server_info->fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	setsockopt(server_info->fd, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val));
	if (server_info->ai_family == AF_INET6) {
		/* for receiving ip ttl value */
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
	}

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	server_info->fd = -1;
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;

	return -1;
}

int _dns_client_send_udp_mdns(struct dns_server_info *server_info, void *packet, int len)
{
	int send_len = 0;
	const struct sockaddr *addr = &server_info->addr;
	socklen_t addrlen = server_info->ai_addrlen;

	if (server_info->fd <= 0) {
		return -1;
	}

	send_len = sendto(server_info->fd, packet, len, 0, addr, addrlen);
	if (send_len != len) {
		goto errout;
	}

	return 0;

errout:
	return -1;
}

int _dns_client_add_mdns_server(void)
{
	struct client_dns_server_flags server_flags;
	int ret = 0;
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;

	if (dns_conf.mdns_lookup != 1) {
		return 0;
	}

	memset(&server_flags, 0, sizeof(server_flags));
	server_flags.server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT | DOMAIN_FLAG_IPSET_IGN | DOMAIN_FLAG_NFTSET_INET_IGN;

	if (dns_client_add_group(DNS_SERVER_GROUP_MDNS) != 0) {
		tlog(TLOG_ERROR, "add default server group failed.");
		goto errout;
	}

#ifdef TEST
	safe_strncpy(server_flags.ifname, "lo", sizeof(server_flags.ifname));
	ret = _dns_client_server_add(DNS_MDNS_IP, "", DNS_MDNS_PORT, DNS_SERVER_MDNS, &server_flags);
	if (ret != 0) {
		tlog(TLOG_ERROR, "add mdns server to %s failed.", "lo");
		goto errout;
	}

	if (dns_client_add_to_group(DNS_SERVER_GROUP_MDNS, DNS_MDNS_IP, DNS_MDNS_PORT, DNS_SERVER_MDNS, &server_flags) !=
		0) {
		tlog(TLOG_ERROR, "add mdns server to group %s failed.", DNS_SERVER_GROUP_MDNS);
		goto errout;
	}

	return 0;
#endif

	if (getifaddrs(&ifaddr) == -1) {
		goto errout;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		const unsigned char *addr = NULL;
		int addr_len = 0;

		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (AF_INET != ifa->ifa_addr->sa_family && AF_INET6 != ifa->ifa_addr->sa_family) {
			continue;
		}

		addr = (const unsigned char *)&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		addr_len = sizeof(struct in_addr);

		// Skip the local interface
		if (strcmp(ifa->ifa_name, "lo") == 0 || strcmp(ifa->ifa_name, "localhost") == 0) {
			continue;
		}

		if (is_private_addr(addr, addr_len) == 0) {
			continue;
		}

		safe_strncpy(server_flags.ifname, ifa->ifa_name, sizeof(server_flags.ifname));
		char *dns_ip[] = {DNS_MDNS_IP, DNS_MDNS_IP6, 0};
		for (int i = 0; dns_ip[i] != NULL; i++) {
			ret = _dns_client_server_add(dns_ip[i], "", DNS_MDNS_PORT, DNS_SERVER_MDNS, &server_flags);
			if (ret != 0) {
				tlog(TLOG_ERROR, "add mdns server failed for %s.", dns_ip[i]);
				goto errout;
			}

			if (dns_client_add_to_group(DNS_SERVER_GROUP_MDNS, dns_ip[i], DNS_MDNS_PORT, DNS_SERVER_MDNS,
										&server_flags) != 0) {
				tlog(TLOG_ERROR, "add mdns server to group failed for %s.", dns_ip[i]);
				goto errout;
			}
		}
	}

	freeifaddrs(ifaddr);

	return 0;

errout:
	if (ifaddr) {
		freeifaddrs(ifaddr);
	}

	return -1;
}
