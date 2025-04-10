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
#include "dns_conf_group.h"
#include "ip_alias.h"
#include "set_file.h"
#include "smartdns/util.h"

#include <getopt.h>

int _config_ip_rule_set_each(const char *ip_set, set_rule_add_func callback, void *priv)
{
	struct dns_ip_set_name_list *set_name_list = NULL;
	struct dns_ip_set_name *set_name_item = NULL;

	uint32_t key = 0;

	key = hash_string(ip_set);
	hash_for_each_possible(dns_ip_set_name_table.names, set_name_list, node, key)
	{
		if (strcmp(set_name_list->name, ip_set) == 0) {
			break;
		}
	}

	if (set_name_list == NULL) {
		tlog(TLOG_WARN, "ip set %s not found.", ip_set);
		return -1;
	}

	list_for_each_entry(set_name_item, &set_name_list->set_name_list, list)
	{
		switch (set_name_item->type) {
		case DNS_IP_SET_LIST:
			if (_config_set_rule_each_from_list(set_name_item->file, callback, priv) != 0) {
				return -1;
			}
			break;
		default:
			tlog(TLOG_WARN, "ip set %s type %d not support.", set_name_list->name, set_name_item->type);
			break;
		}
	}

	return 0;
}

static void _dns_iplist_ip_address_add(struct dns_iplist_ip_addresses *iplist, unsigned char addr[], int addr_len)
{
	iplist->ipaddr = realloc(iplist->ipaddr, (iplist->ipaddr_num + 1) * sizeof(struct dns_iplist_ip_address));
	if (iplist->ipaddr == NULL) {
		return;
	}
	memset(&iplist->ipaddr[iplist->ipaddr_num], 0, sizeof(struct dns_iplist_ip_address));
	iplist->ipaddr[iplist->ipaddr_num].addr_len = addr_len;
	memcpy(iplist->ipaddr[iplist->ipaddr_num].addr, addr, addr_len);
	iplist->ipaddr_num++;
}

int _config_ip_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	char *ip_cidr = argv[1];

	/* clang-format off */
	static struct option long_options[] = {
		{"blacklist-ip", no_argument, NULL, 'b'},
		{"whitelist-ip", no_argument, NULL, 'w'},
		{"bogus-nxdomain", no_argument, NULL, 'n'},
		{"ignore-ip", no_argument, NULL, 'i'},
		{"ip-alias", required_argument, NULL, 'a'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'b': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_BLACKLIST, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'w': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_WHITELIST, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'n': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_BOGUS, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'i': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_IP_IGNORE, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'a': {
			if (_conf_ip_alias(ip_cidr, optarg) != 0) {
				goto errout;
			}
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown ip-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	return 0;
errout:
	return -1;
}

static int _config_ip_rules_free(struct dns_ip_rules *ip_rules)
{
	int i = 0;

	if (ip_rules == NULL) {
		return 0;
	}

	for (i = 0; i < IP_RULE_MAX; i++) {
		if (ip_rules->rules[i] == NULL) {
			continue;
		}

		_dns_ip_rule_put(ip_rules->rules[i]);
		ip_rules->rules[i] = NULL;
	}

	free(ip_rules);
	return 0;
}

static radix_node_t *_create_addr_node(const char *addr)
{
	radix_node_t *node = NULL;
	void *p = NULL;
	prefix_t prefix;
	const char *errmsg = NULL;
	radix_tree_t *tree = NULL;

	p = prefix_pton(addr, -1, &prefix, &errmsg);
	if (p == NULL) {
		return NULL;
	}

	switch (prefix.family) {
	case AF_INET:
		tree = _config_current_rule_group()->address_rule.ipv4;
		break;
	case AF_INET6:
		tree = _config_current_rule_group()->address_rule.ipv6;
		break;
	}

	node = radix_lookup(tree, &prefix);
	return node;
}

static int _config_ip_rule_flag_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_ip_rule_flag_set(ip_cidr, args->flags, args->is_clear_flag);
}

int _config_ip_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear)
{
	struct dns_ip_rules *ip_rules = NULL;
	struct dns_ip_rules *add_ip_rules = NULL;
	struct ip_rule_flags *ip_rule_flags = NULL;
	radix_node_t *node = NULL;

	if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		struct dns_set_rule_flags_callback_args args;
		args.flags = flag;
		args.is_clear_flag = is_clear;
		return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_ip_rule_flag_callback, &args);
	}

	/* Get existing or create domain rule */
	node = _create_addr_node(ip_cidr);
	if (node == NULL) {
		tlog(TLOG_ERROR, "create addr node failed.");
		goto errout;
	}

	ip_rules = node->data;
	if (ip_rules == NULL) {
		add_ip_rules = malloc(sizeof(*add_ip_rules));
		if (add_ip_rules == NULL) {
			goto errout;
		}
		memset(add_ip_rules, 0, sizeof(*add_ip_rules));
		ip_rules = add_ip_rules;
		node->data = ip_rules;
	}

	/* add new rule to domain */
	if (ip_rules->rules[IP_RULE_FLAGS] == NULL) {
		ip_rule_flags = _new_dns_ip_rule(IP_RULE_FLAGS);
		ip_rule_flags->flags = 0;
		ip_rules->rules[IP_RULE_FLAGS] = &ip_rule_flags->head;
	}

	ip_rule_flags = container_of(ip_rules->rules[IP_RULE_FLAGS], struct ip_rule_flags, head);
	if (is_clear == false) {
		ip_rule_flags->flags |= flag;
	} else {
		ip_rule_flags->flags &= ~flag;
	}
	ip_rule_flags->is_flag_set |= flag;

	return 0;
errout:
	if (add_ip_rules) {
		free(add_ip_rules);
	}

	tlog(TLOG_ERROR, "set ip %s flags failed", ip_cidr);

	return 0;
}

static int _config_ip_rule_add_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_ip_rule_add(ip_cidr, args->type, args->rule);
}

int _config_ip_rule_add(const char *ip_cidr, enum ip_rule type, void *rule)
{
	struct dns_ip_rules *ip_rules = NULL;
	struct dns_ip_rules *add_ip_rules = NULL;
	radix_node_t *node = NULL;

	if (ip_cidr == NULL) {
		goto errout;
	}

	if (type >= IP_RULE_MAX) {
		goto errout;
	}

	if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		struct dns_set_rule_add_callback_args args;
		args.type = type;
		args.rule = rule;
		return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_ip_rule_add_callback, &args);
	}

	/* Get existing or create domain rule */
	node = _create_addr_node(ip_cidr);
	if (node == NULL) {
		tlog(TLOG_ERROR, "create addr node failed.");
		goto errout;
	}

	ip_rules = node->data;
	if (ip_rules == NULL) {
		add_ip_rules = malloc(sizeof(*add_ip_rules));
		if (add_ip_rules == NULL) {
			goto errout;
		}
		memset(add_ip_rules, 0, sizeof(*add_ip_rules));
		ip_rules = add_ip_rules;
		node->data = ip_rules;
	}

	/* add new rule to domain */
	if (ip_rules->rules[type]) {
		_dns_ip_rule_put(ip_rules->rules[type]);
		ip_rules->rules[type] = NULL;
	}

	ip_rules->rules[type] = rule;
	_dns_ip_rule_get(rule);

	return 0;
errout:
	if (add_ip_rules) {
		free(add_ip_rules);
	}

	tlog(TLOG_ERROR, "add ip %s rule failed", ip_cidr);
	return -1;
}

static void *_new_dns_ip_rule_ext(enum ip_rule ip_rule, int ext_size)
{
	struct dns_ip_rule *rule;
	int size = 0;

	if (ip_rule >= IP_RULE_MAX) {
		return NULL;
	}

	switch (ip_rule) {
	case IP_RULE_FLAGS:
		size = sizeof(struct ip_rule_flags);
		break;
	case IP_RULE_ALIAS:
		size = sizeof(struct ip_rule_alias);
		break;
	default:
		return NULL;
	}

	size += ext_size;
	rule = malloc(size);
	if (!rule) {
		return NULL;
	}
	memset(rule, 0, size);
	rule->rule = ip_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

void *_new_dns_ip_rule(enum ip_rule ip_rule)
{
	return _new_dns_ip_rule_ext(ip_rule, 0);
}

void _dns_ip_rule_get(struct dns_ip_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

void _dns_ip_rule_put(struct dns_ip_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt)) {
		if (rule->rule == IP_RULE_ALIAS) {
			struct ip_rule_alias *alias = container_of(rule, struct ip_rule_alias, head);
			if (alias->ip_alias.ipaddr) {
				free(alias->ip_alias.ipaddr);
				alias->ip_alias.ipaddr = NULL;
				alias->ip_alias.ipaddr_num = 0;
			}
		}
		free(rule);
	}
}

int _config_ip_rule_alias_add_ip(const char *ip, struct ip_rule_alias *ip_alias)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	unsigned char *paddr = NULL;
	int ret = 0;

	ret = getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len);
	if (ret != 0) {
		tlog(TLOG_ERROR, "ip is invalid: %s", ip);
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		paddr = (unsigned char *)&(addr_in->sin_addr.s_addr);
		_dns_iplist_ip_address_add(&ip_alias->ip_alias, paddr, DNS_RR_A_LEN);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			paddr = addr_in6->sin6_addr.s6_addr + 12;
			_dns_iplist_ip_address_add(&ip_alias->ip_alias, paddr, DNS_RR_A_LEN);
		} else {
			paddr = addr_in6->sin6_addr.s6_addr;
			_dns_iplist_ip_address_add(&ip_alias->ip_alias, paddr, DNS_RR_AAAA_LEN);
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

int _config_blacklist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_BLACKLIST, 0);
}

int _config_bogus_nxdomain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_BOGUS, 0);
}

int _config_ip_ignore(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_IP_IGNORE, 0);
}

int _config_whitelist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_WHITELIST, 0);
}

void _config_ip_iter_free(radix_node_t *node, void *cbctx)
{
	struct dns_ip_rules *ip_rules = NULL;
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	ip_rules = node->data;
	_config_ip_rules_free(ip_rules);
	node->data = NULL;
}
