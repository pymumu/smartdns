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

#include "neighbor.h"
#include "dns_server.h"

#include "smartdns/fast_ping.h"

#include <errno.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

void dns_server_enable_update_neighbor_cache(int enable)
{
	if (enable) {
		server.update_neighbor_cache = 1;
	} else {
		if (dns_conf.client_rule.mac_num > 0) {
			return;
		}
		server.update_neighbor_cache = 0;
	}
}

static void _dns_server_neighbor_cache_free_item(struct neighbor_cache_item *item)
{
	hash_del(&item->node);
	list_del_init(&item->list);
	free(item);
	atomic_dec(&server.neighbor_cache.cache_num);
}

void _dns_server_neighbor_cache_remove_all(void)
{
	struct neighbor_cache_item *item = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long bucket = 0;

	pthread_mutex_lock(&server.neighbor_cache.lock);
	hash_for_each_safe(server.neighbor_cache.cache, bucket, tmp, item, node)
	{
		_dns_server_neighbor_cache_free_item(item);
	}
	pthread_mutex_unlock(&server.neighbor_cache.lock);

	if (server.neigh_netlink_fd >= 0) {
		epoll_ctl(server.epoll_fd, EPOLL_CTL_DEL, server.neigh_netlink_fd, NULL);
		close(server.neigh_netlink_fd);
		server.neigh_netlink_fd = -1;
	}

	pthread_mutex_destroy(&server.neighbor_cache.lock);
}

static void _dns_server_neighbor_cache_free_last_used_item(void)
{
	struct neighbor_cache_item *item = NULL;

	if (atomic_read(&server.neighbor_cache.cache_num) < DNS_SERVER_NEIGHBOR_CACHE_MAX_NUM) {
		return;
	}

	if (list_empty(&server.neighbor_cache.list)) {
		return;
	}

	item = list_last_entry(&server.neighbor_cache.list, struct neighbor_cache_item, list);
	if (item == NULL) {
		return;
	}

	_dns_server_neighbor_cache_free_item(item);
}

static struct neighbor_cache_item *_dns_server_neighbor_cache_get_item(const uint8_t *net_addr, int net_addr_len)
{
	struct neighbor_cache_item *item = NULL, *item_result = NULL;
	uint32_t key = 0;

	key = jhash(net_addr, net_addr_len, 0);
	hash_for_each_possible(server.neighbor_cache.cache, item, node, key)
	{
		if (item->ip_addr_len != net_addr_len) {
			continue;
		}

		if (memcmp(item->ip_addr, net_addr, net_addr_len) != 0) {
			continue;
		}

		item_result = item;
		break;
	}

	return item_result;
}

int _dns_server_neighbor_cache_get_mac(const uint8_t *net_addr, int net_addr_len, uint8_t mac[6])
{
	struct neighbor_cache_item *item = NULL;
	int ret = -1;

	pthread_mutex_lock(&server.neighbor_cache.lock);
	item = _dns_server_neighbor_cache_get_item(net_addr, net_addr_len);
	if (item != NULL && item->has_mac) {
		memcpy(mac, item->mac, 6);
		ret = 0;
	}
	pthread_mutex_unlock(&server.neighbor_cache.lock);

	return ret;
}

static int _dns_server_neighbor_cache_add(const uint8_t *net_addr, int net_addr_len, const uint8_t *mac)
{
	struct neighbor_cache_item *item = NULL;
	uint32_t key = 0;
	int is_new_item = 0;

	if (net_addr_len > DNS_RR_AAAA_LEN) {
		return -1;
	}

	pthread_mutex_lock(&server.neighbor_cache.lock);
	item = _dns_server_neighbor_cache_get_item(net_addr, net_addr_len);
	if (item == NULL) {
		item = zalloc(1, sizeof(*item));
		if (item == NULL) {
			pthread_mutex_unlock(&server.neighbor_cache.lock);
			return -1;
		}
		INIT_LIST_HEAD(&item->list);
		INIT_HLIST_NODE(&item->node);
		is_new_item = 1;
	}

	memcpy(item->ip_addr, net_addr, net_addr_len);
	item->ip_addr_len = net_addr_len;
	item->last_update_time = time(NULL);
	if (mac == NULL) {
		item->has_mac = 0;
	} else {
		memcpy(item->mac, mac, 6);
		item->has_mac = 1;
	}

	if (is_new_item) {
		key = jhash(net_addr, net_addr_len, 0);
		hash_add(server.neighbor_cache.cache, &item->node, key);
		atomic_inc(&server.neighbor_cache.cache_num);
	} else {
		list_del_init(&item->list);
	}
	list_add(&item->list, &server.neighbor_cache.list);

	_dns_server_neighbor_cache_free_last_used_item();
	pthread_mutex_unlock(&server.neighbor_cache.lock);

	return 0;
}

static int _dns_server_neighbor_cache_dump_callback(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6],
													void *arg)
{
	_dns_server_neighbor_cache_add(net_addr, net_addr_len, mac);
	return 0;
}

void _dns_server_process_neighbor_cache_event(void)
{
	char buffer[1024 * 8];
	struct iovec iov = {buffer, sizeof(buffer)};
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct nlmsghdr *nlh = NULL;
	int fd = -1;
	int resynced = 0;

	if (server.neigh_netlink_fd < 0) {
		return;
	}

	fd = server.neigh_netlink_fd;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (1) {
		ssize_t len = recvmsg(fd, &msg, 0);
		if (len < 0) {
			if (errno == ENOBUFS && resynced == 0) {
				/* events were dropped, resync from a full table dump */
				resynced = 1;
				netlink_get_neighbors(AF_UNSPEC, NULL, 0, _dns_server_neighbor_cache_dump_callback, NULL);
				continue;
			}
			break;
		}

		for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
			if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
				break;
			}

			/* RTM_DELNEIGH is ignored on purpose: the last known mac is kept
			 * until the cache entry itself times out */
			const uint8_t *mac = NULL;
			const uint8_t *net_addr = NULL;
			int net_addr_len = 0;

			if (netlink_parse_neighbor(nlh, &net_addr, &net_addr_len, &mac) != 0) {
				continue;
			}

			_dns_server_neighbor_cache_add(net_addr, net_addr_len, mac);
		}
	}
}

static int _dns_server_neighbor_monitor_init(void)
{
	int fd = -1;
	struct sockaddr_nl sa;
	struct epoll_event event;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		tlog(TLOG_WARN, "create neighbor netlink socket failed, %s", strerror(errno));
		goto errout;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_NEIGH;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		tlog(TLOG_WARN, "bind neighbor netlink socket failed, %s", strerror(errno));
		goto errout;
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLERR;
	event.data.fd = fd;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_WARN, "add neighbor netlink event failed, %s", strerror(errno));
		goto errout;
	}

	server.neigh_netlink_fd = fd;

	return 0;
errout:
	if (fd >= 0) {
		close(fd);
	}

	return -1;
}

int _dns_server_neighbor_cache_init(void)
{
	hash_init(server.neighbor_cache.cache);
	INIT_LIST_HEAD(&server.neighbor_cache.list);
	atomic_set(&server.neighbor_cache.cache_num, 0);
	pthread_mutex_init(&server.neighbor_cache.lock, NULL);

	if (dns_conf.client_rule.mac_num > 0) {
		server.update_neighbor_cache = 1;
	}

	if (_dns_server_neighbor_monitor_init() != 0) {
		tlog(TLOG_WARN, "neighbor table monitor init failed, fallback to polling mode.");
	}

	/* seed the cache with the current kernel neighbor table */
	netlink_get_neighbors(AF_UNSPEC, NULL, 0, _dns_server_neighbor_cache_dump_callback, NULL);

	return 0;
}

static int _dns_server_neighbors_callback(const uint8_t *net_addr, int net_addr_len, const uint8_t mac[6], void *arg)
{
	struct neighbor_enum_args *args = arg;

	_dns_server_neighbor_cache_add(net_addr, net_addr_len, mac);

	if (net_addr_len != args->netaddr_len) {
		return 0;
	}

	if (memcmp(net_addr, args->netaddr, net_addr_len) != 0) {
		return 0;
	}

	args->group_mac = dns_server_rule_group_mac_get(mac);

	return 1;
}

static int _dns_server_neighbor_cache_is_valid(struct neighbor_cache_item *item)
{
	if (item == NULL) {
		return -1;
	}

	time_t now = time(NULL);

	if (item->last_update_time + DNS_SERVER_NEIGHBOR_CACHE_TIMEOUT < now) {
		return -1;
	}

	if (item->has_mac) {
		return 0;
	}

	if (item->last_update_time + DNS_SERVER_NEIGHBOR_CACHE_NOMAC_TIMEOUT < now) {
		return -1;
	}

	return 0;
}

static void _dns_server_neighbor_probe(int family, uint8_t *netaddr, int netaddr_len)
{
	/* force the kernel to resolve the neighbor: connect() on a UDP socket
	 * sends nothing, an actual (empty) datagram must be queued to trigger
	 * ARP/NS for the destination */
	int probe_fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (probe_fd < 0) {
		return;
	}

	struct sockaddr_storage dest;
	socklen_t dest_len = 0;
	memset(&dest, 0, sizeof(dest));
	dest.ss_family = family;
	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)&dest;
		memcpy(&in->sin_addr, netaddr, 4);
		in->sin_port = htons(9); /* discard port */
		dest_len = sizeof(struct sockaddr_in);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&dest;
		memcpy(&in6->sin6_addr, netaddr, 16);
		in6->sin6_port = htons(9); /* discard port */
		dest_len = sizeof(struct sockaddr_in6);
	}

	if (dest_len > 0) {
		sendto(probe_fd, "", 0, 0, (struct sockaddr *)&dest, dest_len);
	}

	close(probe_fd);
}

struct dns_client_rules *_dns_server_get_client_rules_by_mac(uint8_t *netaddr, int netaddr_len)
{
	struct client_roue_group_mac *group_mac = NULL;
	struct neighbor_cache_item *item = NULL;
	uint8_t mac[6] = {0};
	int cache_valid = 0;
	int has_mac = 0;
	int family = AF_UNSPEC;
	int ret = 0;
	struct neighbor_enum_args args;

	if (server.update_neighbor_cache == 0) {
		return NULL;
	}

	pthread_mutex_lock(&server.neighbor_cache.lock);
	item = _dns_server_neighbor_cache_get_item(netaddr, netaddr_len);
	if (_dns_server_neighbor_cache_is_valid(item) == 0) {
		cache_valid = 1;
		has_mac = item->has_mac;
		if (has_mac) {
			memcpy(mac, item->mac, sizeof(mac));
		}
	}
	pthread_mutex_unlock(&server.neighbor_cache.lock);

	if (cache_valid) {
		if (!has_mac) {
			return NULL;
		}
		group_mac = dns_server_rule_group_mac_get(mac);
		if (group_mac != NULL) {
			return group_mac->rules;
		}

		return NULL;
	}

	if (netaddr_len == 4) {
		family = AF_INET;
	} else if (netaddr_len == 16) {
		family = AF_INET6;
	}

	args.group_mac = group_mac;
	args.netaddr = netaddr;
	args.netaddr_len = netaddr_len;

	ret = netlink_get_neighbors(family, netaddr, netaddr_len, _dns_server_neighbors_callback, &args);
	if (ret <= 0) {
		goto add_cache;
	}

	if (args.group_mac == NULL) {
		return NULL;
	}

	return args.group_mac->rules;

add_cache:
	_dns_server_neighbor_cache_add(netaddr, netaddr_len, NULL);
	_dns_server_neighbor_probe(family, netaddr, netaddr_len);

	return NULL;
}
