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

#include "ip_rule.h"
#include "dns_server.h"
#include "neighbor.h"
#include "soa.h"

struct dns_client_rules *_dns_server_get_client_rules(struct sockaddr_storage *addr, socklen_t addr_len)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	uint8_t netaddr[DNS_RR_AAAA_LEN] = {0};
	struct dns_client_rules *client_rules = NULL;
	int netaddr_len = sizeof(netaddr);

	if (get_raw_addr_by_sockaddr(addr, addr_len, netaddr, &netaddr_len) != 0) {
		return NULL;
	}

	client_rules = _dns_server_get_client_rules_by_mac(netaddr, netaddr_len);
	if (client_rules != NULL) {
		return client_rules;
	}

	if (prefix_from_blob(netaddr, netaddr_len, netaddr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	node = radix_search_best(dns_conf.client_rule.rule, &prefix);
	if (node == NULL) {
		return NULL;
	}

	client_rules = node->data;

	return client_rules;
}

static struct dns_ip_rules *_dns_server_ip_rule_get(struct dns_request *request, unsigned char *addr, int addr_len,
													dns_type_t addr_type)
{
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct dns_ip_rules *rule = NULL;

	if (request->conf == NULL) {
		return NULL;
	}

	/* Match IP address rules */
	if (prefix_from_blob(addr, addr_len, addr_len * 8, &prefix) == NULL) {
		return NULL;
	}

	switch (prefix.family) {
	case AF_INET:
		node = radix_search_best(request->conf->address_rule.ipv4, &prefix);
		break;
	case AF_INET6:
		node = radix_search_best(request->conf->address_rule.ipv6, &prefix);
		break;
	default:
		break;
	}

	if (node == NULL) {
		return NULL;
	}

	if (node->data == NULL) {
		return NULL;
	}

	rule = node->data;

	return rule;
}

static int _dns_server_ip_rule_check(struct dns_request *request, struct dns_ip_rules *ip_rules, int result_flag)
{
	struct ip_rule_flags *rule_flags = NULL;
	if (ip_rules == NULL) {
		goto rule_not_found;
	}

	struct dns_ip_rule *rule = ip_rules->rules[IP_RULE_FLAGS];
	if (rule != NULL) {
		rule_flags = container_of(rule, struct ip_rule_flags, head);
		if (rule_flags != NULL) {
			if (rule_flags->flags & IP_RULE_FLAG_BOGUS) {
				request->rcode = DNS_RC_NXDOMAIN;
				request->has_soa = 1;
				request->force_soa = 1;
				_dns_server_setup_soa(request);
				goto nxdomain;
			}

			/* blacklist-ip */
			if (rule_flags->flags & IP_RULE_FLAG_BLACKLIST) {
				if (result_flag & DNSSERVER_FLAG_BLACKLIST_IP) {
					goto match;
				}
			}

			/* ignore-ip */
			if (rule_flags->flags & IP_RULE_FLAG_IP_IGNORE) {
				goto skip;
			}
		}
	}

	if (ip_rules->rules[IP_RULE_ALIAS] != NULL) {
		goto match;
	}

rule_not_found:
	if (result_flag & DNSSERVER_FLAG_WHITELIST_IP) {
		if (rule_flags == NULL) {
			goto skip;
		}

		if (!(rule_flags->flags & IP_RULE_FLAG_WHITELIST)) {
			goto skip;
		}
	}
	return -1;
skip:
	return -2;
nxdomain:
	return -3;
match:
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NXDOMAIN;
	}
	return 0;
}

int _dns_server_process_ip_alias(struct dns_request *request, struct dns_iplist_ip_addresses *alias,
								 unsigned char **paddrs, int *paddr_num, int max_paddr_num, int addr_len)
{
	int addr_num = 0;

	if (alias == NULL) {
		return 0;
	}

	if (request == NULL) {
		return -1;
	}

	if (alias->ipaddr_num <= 0) {
		return 0;
	}

	for (int i = 0; i < alias->ipaddr_num && i < max_paddr_num; i++) {
		if (alias->ipaddr[i].addr_len != addr_len) {
			continue;
		}
		paddrs[i] = alias->ipaddr[i].addr;
		addr_num++;
	}

	*paddr_num = addr_num;
	return 0;
}

int _dns_server_process_ip_rule(struct dns_request *request, unsigned char *addr, int addr_len, dns_type_t addr_type,
								int result_flag, struct dns_iplist_ip_addresses **alias)
{
	struct dns_ip_rules *ip_rules = NULL;
	int ret = 0;

	ip_rules = _dns_server_ip_rule_get(request, addr, addr_len, addr_type);
	ret = _dns_server_ip_rule_check(request, ip_rules, result_flag);
	if (ret != 0) {
		return ret;
	}

	if (ip_rules->rules[IP_RULE_ALIAS] && alias != NULL) {
		if (request->no_ipalias == 0) {
			struct ip_rule_alias *rule = container_of(ip_rules->rules[IP_RULE_ALIAS], struct ip_rule_alias, head);
			*alias = &rule->ip_alias;
			if (alias == NULL) {
				return 0;
			}
		}

		/* need process ip alias */
		return -1;
	}

	return 0;
}
