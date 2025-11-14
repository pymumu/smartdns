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

#include "address.h"
#include "context.h"
#include "dns_server.h"
#include "ptr.h"
#include "request.h"
#include "rules.h"
#include "speed_check.h"

int _dns_server_is_adblock_ipv6(const unsigned char addr[16])
{
	int i = 0;

	for (i = 0; i < 15; i++) {
		if (addr[i]) {
			return -1;
		}
	}

	if (addr[15] == 0 || addr[15] == 1) {
		return 0;
	}

	return -1;
}

int _dns_server_address_generate_order(int orders[], int order_num, int max_order_count)
{
	int i = 0;
	int j = 0;
	int k = 0;
	unsigned int seed = time(NULL);

	for (i = 0; i < order_num && i < max_order_count; i++) {
		orders[i] = i;
	}

	for (i = 0; i < order_num && max_order_count; i++) {
		k = rand_r(&seed) % order_num;
		j = rand_r(&seed) % order_num;
		if (j == k) {
			continue;
		}

		int temp = orders[j];
		orders[j] = orders[k];
		orders[k] = temp;
	}

	return 0;
}

int _dns_server_process_address(struct dns_request *request)
{
	struct dns_rule_address_IPV4 *address_ipv4 = NULL;
	struct dns_rule_address_IPV6 *address_ipv6 = NULL;
	int orders[DNS_MAX_REPLY_IP_NUM];

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
		goto errout;
	}

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A:
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] == NULL) {
			goto errout;
		}
		address_ipv4 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV4);
		if (address_ipv4 == NULL) {
			goto errout;
		}
		_dns_server_address_generate_order(orders, address_ipv4->addr_num, DNS_MAX_REPLY_IP_NUM);

		memcpy(request->ip_addr, address_ipv4->ipv4_addr[orders[0]], DNS_RR_A_LEN);
		for (int i = 1; i < address_ipv4->addr_num; i++) {
			int index = orders[i];
			if (index >= address_ipv4->addr_num) {
				continue;
			}
			_dns_ip_address_check_add(request, request->cname, address_ipv4->ipv4_addr[index], DNS_T_A, 1, NULL);
		}
		break;
	case DNS_T_AAAA:
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] == NULL) {
			goto errout;
		}

		address_ipv6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV6);
		if (address_ipv6 == NULL) {
			goto errout;
		}
		_dns_server_address_generate_order(orders, address_ipv6->addr_num, DNS_MAX_REPLY_IP_NUM);

		memcpy(request->ip_addr, address_ipv6->ipv6_addr[orders[0]], DNS_RR_AAAA_LEN);
		for (int i = 1; i < address_ipv6->addr_num; i++) {
			int index = orders[i];
			if (index >= address_ipv6->addr_num) {
				continue;
			}
			_dns_ip_address_check_add(request, request->cname, address_ipv6->ipv6_addr[index], DNS_T_AAAA, 1, NULL);
		}
		break;
	default:
		goto errout;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	request->has_ip = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 1;
	context.do_ipset = 1;
	context.select_all_best_ip = 1;
	_dns_request_post(&context);

	return 0;
errout:
	return -1;
}

int _dns_ip_address_check_add(struct dns_request *request, char *cname, unsigned char *addr, dns_type_t addr_type,
							  int ping_time, struct dns_ip_address **out_addr_map)
{
	uint32_t key = 0;
	struct dns_ip_address *addr_map = NULL;
	int addr_len = 0;

	if (ping_time == 0) {
		ping_time = -1;
	}

	if (addr_type == DNS_T_A) {
		addr_len = DNS_RR_A_LEN;
	} else if (addr_type == DNS_T_AAAA) {
		addr_len = DNS_RR_AAAA_LEN;
	} else {
		return -1;
	}

	/* store the ip address and the number of hits */
	key = jhash(addr, addr_len, 0);
	key = jhash(&addr_type, sizeof(addr_type), key);
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_possible(request->ip_map, addr_map, node, key)
	{
		if (addr_map->addr_type != addr_type) {
			continue;
		}

		if (memcmp(addr_map->ip_addr, addr, addr_len) != 0) {
			continue;
		}

		addr_map->hitnum++;
		addr_map->recv_tick = get_tick_count();
		pthread_mutex_unlock(&request->ip_map_lock);
		return -1;
	}

	atomic_inc(&request->ip_map_num);
	addr_map = zalloc(1, sizeof(*addr_map));
	if (addr_map == NULL) {
		pthread_mutex_unlock(&request->ip_map_lock);
		tlog(TLOG_ERROR, "malloc addr map failed");
		return -1;
	}

	addr_map->addr_type = addr_type;
	addr_map->hitnum = 1;
	addr_map->recv_tick = get_tick_count();
	addr_map->ping_time = ping_time;
	memcpy(addr_map->ip_addr, addr, addr_len);
	if (request->conf->dns_force_no_cname == 0) {
		safe_strncpy(addr_map->cname, cname, DNS_MAX_CNAME_LEN);
	}

	hash_add(request->ip_map, &addr_map->node, key);
	pthread_mutex_unlock(&request->ip_map_lock);

	if (out_addr_map != NULL) {
		*out_addr_map = addr_map;
	}

	return 0;
}

void _dns_server_select_possible_ipaddress(struct dns_request *request)
{
	int maxhit = 0;
	unsigned long bucket = 0;
	unsigned long max_recv_tick = 0;
	struct dns_ip_address *addr_map = NULL;
	struct dns_ip_address *maxhit_addr_map = NULL;
	struct dns_ip_address *last_recv_addr_map = NULL;
	struct dns_ip_address *selected_addr_map = NULL;
	struct hlist_node *tmp = NULL;

	if (atomic_read(&request->notified) > 0) {
		return;
	}

	if (request->no_select_possible_ip != 0) {
		return;
	}

	if (request->ping_time > 0) {
		return;
	}

	/* Return the most likely correct IP address */
	/* Returns the IP with the most hits, or the last returned record is considered to be the most likely
	 * correct. */
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		if (addr_map->addr_type != request->qtype) {
			continue;
		}

		if (addr_map->recv_tick - request->send_tick > max_recv_tick) {
			max_recv_tick = addr_map->recv_tick - request->send_tick;
			last_recv_addr_map = addr_map;
		}

		if (addr_map->hitnum > maxhit) {
			maxhit = addr_map->hitnum;
			maxhit_addr_map = addr_map;
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	if (maxhit_addr_map && maxhit > 1) {
		selected_addr_map = maxhit_addr_map;
	} else if (last_recv_addr_map) {
		selected_addr_map = last_recv_addr_map;
	}

	if (selected_addr_map == NULL) {
		return;
	}

	tlog(TLOG_DEBUG, "select best ip address, %s", request->domain);
	switch (request->qtype) {
	case DNS_T_A: {
		memcpy(request->ip_addr, selected_addr_map->ip_addr, DNS_RR_A_LEN);
		tlog(TLOG_DEBUG, "possible result: %s, rcode: %d,  hitnum: %d, %d.%d.%d.%d", request->domain, request->rcode,
			 selected_addr_map->hitnum, request->ip_addr[0], request->ip_addr[1], request->ip_addr[2],
			 request->ip_addr[3]);
	} break;
	case DNS_T_AAAA: {
		memcpy(request->ip_addr, selected_addr_map->ip_addr, DNS_RR_AAAA_LEN);
		tlog(TLOG_DEBUG,
			 "possible result: %s, rcode: %d,  hitnum: %d, "
			 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
			 request->domain, request->rcode, selected_addr_map->hitnum, request->ip_addr[0], request->ip_addr[1],
			 request->ip_addr[2], request->ip_addr[3], request->ip_addr[4], request->ip_addr[5], request->ip_addr[6],
			 request->ip_addr[7], request->ip_addr[8], request->ip_addr[9], request->ip_addr[10], request->ip_addr[11],
			 request->ip_addr[12], request->ip_addr[13], request->ip_addr[14], request->ip_addr[15]);
	} break;
	default:
		break;
	}
}

struct dns_ip_address *_dns_ip_address_get(struct dns_request *request, unsigned char *addr, dns_type_t addr_type)
{
	uint32_t key = 0;
	struct dns_ip_address *addr_map = NULL;
	struct dns_ip_address *addr_tmp = NULL;
	int addr_len = 0;

	if (addr_type == DNS_T_A) {
		addr_len = DNS_RR_A_LEN;
	} else if (addr_type == DNS_T_AAAA) {
		addr_len = DNS_RR_AAAA_LEN;
	} else {
		return NULL;
	}

	/* store the ip address and the number of hits */
	key = jhash(addr, addr_len, 0);
	key = jhash(&addr_type, sizeof(addr_type), key);
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_possible(request->ip_map, addr_tmp, node, key)
	{
		if (addr_type != addr_tmp->addr_type) {
			continue;
		}

		if (memcmp(addr_tmp->ip_addr, addr, addr_len) != 0) {
			continue;
		}

		addr_map = addr_tmp;
		break;
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	return addr_map;
}
