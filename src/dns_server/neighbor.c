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

	hash_for_each_safe(server.neighbor_cache.cache, bucket, tmp, item, node)
	{
		_dns_server_neighbor_cache_free_item(item);
	}

	pthread_mutex_destroy(&server.neighbor_cache.lock);
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

	return 0;
}

static void _dns_server_neighbor_cache_free_last_used_item(void)
{
	struct neighbor_cache_item *item = NULL;

	if (atomic_read(&server.neighbor_cache.cache_num) < DNS_SERVER_NEIGHBOR_CACHE_MAX_NUM) {
		return;
	}

	item = list_last_entry(&server.neighbor_cache.list, struct neighbor_cache_item, list);
	if (item == NULL) {
		return;
	}

	_dns_server_neighbor_cache_free_item(item);
}

struct neighbor_cache_item *_dns_server_neighbor_cache_get_item(const uint8_t *net_addr, int net_addr_len)
{
	struct neighbor_cache_item *item, *item_result = NULL;
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

static int _dns_server_neighbor_cache_add(const uint8_t *net_addr, int net_addr_len, const uint8_t *mac)
{
	struct neighbor_cache_item *item = NULL;
	uint32_t key = 0;

	if (net_addr_len > DNS_RR_AAAA_LEN) {
		return -1;
	}

	item = _dns_server_neighbor_cache_get_item(net_addr, net_addr_len);
	if (item == NULL) {
		item = malloc(sizeof(*item));
		memset(item, 0, sizeof(*item));
		if (item == NULL) {
			return -1;
		}
		INIT_LIST_HEAD(&item->list);
		INIT_HLIST_NODE(&item->node);
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
	key = jhash(net_addr, net_addr_len, 0);
	hash_del(&item->node);
	hash_add(server.neighbor_cache.cache, &item->node, key);
	list_del_init(&item->list);
	list_add(&item->list, &server.neighbor_cache.list);
	atomic_inc(&server.neighbor_cache.cache_num);

	_dns_server_neighbor_cache_free_last_used_item();

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

struct dns_client_rules *_dns_server_get_client_rules_by_mac(uint8_t *netaddr, int netaddr_len)
{
	struct client_roue_group_mac *group_mac = NULL;
	struct neighbor_cache_item *item = NULL;
	int family = AF_UNSPEC;
	int ret = 0;
	struct neighbor_enum_args args;

	if (server.update_neighbor_cache == 0) {
		return NULL;
	}

	item = _dns_server_neighbor_cache_get_item(netaddr, netaddr_len);
	if (_dns_server_neighbor_cache_is_valid(item) == 0) {
		if (item->has_mac == 0) {
			return NULL;
		}
		group_mac = dns_server_rule_group_mac_get(item->mac);
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

	for (int i = 0; i < 1; i++) {
		ret = netlink_get_neighbors(family, _dns_server_neighbors_callback, &args);
		if (ret < 0) {
			goto add_cache;
		}
	}

	if (args.group_mac == NULL) {
		return NULL;
	}

	return args.group_mac->rules;

add_cache:
	_dns_server_neighbor_cache_add(netaddr, netaddr_len, NULL);
	return NULL;
}
