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

#include "client_rule.h"
#include "dns_conf_group.h"
#include "ip_rule.h"
#include "server_group.h"
#include "set_file.h"
#include "smartdns/util.h"

#include <getopt.h>

static radix_node_t *_create_client_rules_node(const char *addr)
{
	radix_node_t *node = NULL;
	void *p = NULL;
	prefix_t prefix;
	const char *errmsg = NULL;

	p = prefix_pton(addr, -1, &prefix, &errmsg);
	if (p == NULL) {
		return NULL;
	}

	node = radix_lookup(dns_conf.client_rule.rule, &prefix);
	return node;
}

static void *_new_dns_client_rule_ext(enum client_rule client_rule, int ext_size)
{
	struct dns_client_rule *rule;
	int size = 0;

	if (client_rule >= CLIENT_RULE_MAX) {
		return NULL;
	}

	switch (client_rule) {
	case CLIENT_RULE_FLAGS:
		size = sizeof(struct client_rule_flags);
		break;
	case CLIENT_RULE_GROUP:
		size = sizeof(struct client_rule_group);
		break;
	default:
		return NULL;
	}

	size += ext_size;
	rule = zalloc(1, size);
	if (!rule) {
		return NULL;
	}
	rule->rule = client_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

static void *_new_dns_client_rule(enum client_rule client_rule)
{
	return _new_dns_client_rule_ext(client_rule, 0);
}

static void _dns_client_rule_get(struct dns_client_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static void _dns_client_rule_put(struct dns_client_rule *rule)
{
	int refcount = atomic_dec_return(&rule->refcnt);
	if (refcount > 0) {
		return;
	}

	free(rule);
}

static int _config_client_rules_free(struct dns_client_rules *client_rules)
{
	int i = 0;

	if (client_rules == NULL) {
		return 0;
	}

	for (i = 0; i < CLIENT_RULE_MAX; i++) {
		if (client_rules->rules[i] == NULL) {
			continue;
		}

		_dns_client_rule_put(client_rules->rules[i]);
		client_rules->rules[i] = NULL;
	}

	free(client_rules);
	return 0;
}

static struct client_roue_group_mac *_config_client_rule_group_mac_new(uint8_t mac[6])
{
	struct client_roue_group_mac *group_mac = NULL;
	uint32_t key;

	group_mac = zalloc(1, sizeof(*group_mac));
	if (group_mac == NULL) {
		return NULL;
	}
	memcpy(group_mac->mac, mac, 6);

	key = jhash(mac, 6, 0);
	hash_add(dns_conf.client_rule.mac, &group_mac->node, key);
	dns_conf.client_rule.mac_num++;

	return group_mac;
}

struct client_roue_group_mac *dns_server_rule_group_mac_get(const uint8_t mac[6])
{
	struct client_roue_group_mac *group_mac = NULL;
	uint32_t key;

	key = jhash(mac, 6, 0);
	hash_for_each_possible(dns_conf.client_rule.mac, group_mac, node, key)
	{
		if (memcmp(group_mac->mac, mac, 6) == 0) {
			return group_mac;
		}
	}

	return NULL;
}

static struct client_roue_group_mac *_config_client_rule_group_mac_get_or_add(uint8_t mac[6])
{
	struct client_roue_group_mac *group_mac = dns_server_rule_group_mac_get(mac);
	if (group_mac == NULL) {
		group_mac = _config_client_rule_group_mac_new(mac);
	}

	return group_mac;
}

static int _config_client_rule_add(const char *ip_cidr, enum client_rule type, void *rule);
static int _config_client_rule_add_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_client_rule_add(ip_cidr, args->type, args->rule);
}

static int _config_client_rule_add(const char *ip_cidr, enum client_rule type, void *rule)
{
	struct dns_client_rules *client_rules = NULL;
	struct dns_client_rules *add_client_rules = NULL;
	struct client_roue_group_mac *group_mac = NULL;
	radix_node_t *node = NULL;

	if (ip_cidr == NULL) {
		goto errout;
	}

	if (type >= CLIENT_RULE_MAX) {
		goto errout;
	}

	uint8_t mac[6];
	int is_mac_address = 0;

	is_mac_address = parser_mac_address(ip_cidr, mac);
	if (is_mac_address == 0) {
		group_mac = _config_client_rule_group_mac_get_or_add(mac);
		if (group_mac == NULL) {
			tlog(TLOG_ERROR, "get or add mac %s failed", ip_cidr);
			goto errout;
		}

		client_rules = group_mac->rules;
	} else {
		if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
			struct dns_set_rule_add_callback_args args;
			args.type = type;
			args.rule = rule;
			return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_client_rule_add_callback, &args);
		}

		/* Get existing or create domain rule */
		node = _create_client_rules_node(ip_cidr);
		if (node == NULL) {
			tlog(TLOG_ERROR, "create addr node failed.");
			goto errout;
		}

		client_rules = node->data;
	}

	if (client_rules == NULL) {
		add_client_rules = zalloc(1, sizeof(*add_client_rules));
		if (add_client_rules == NULL) {
			goto errout;
		}
		client_rules = add_client_rules;
		if (is_mac_address == 0) {
			group_mac->rules = client_rules;
		} else {
			node->data = client_rules;
		}
	}

	/* add new rule to domain */
	if (client_rules->rules[type]) {
		_dns_client_rule_put(client_rules->rules[type]);
		client_rules->rules[type] = NULL;
	}

	client_rules->rules[type] = rule;
	_dns_client_rule_get(rule);

	return 0;
errout:
	if (add_client_rules) {
		free(add_client_rules);
	}

	tlog(TLOG_ERROR, "add client %s rule failed", ip_cidr);
	return -1;
}

static int _config_client_rule_flag_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_client_rule_flag_set(ip_cidr, args->flags, args->is_clear_flag);
}

int _config_client_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear)
{
	struct dns_client_rules *client_rules = NULL;
	struct dns_client_rules *add_client_rules = NULL;
	struct client_rule_flags *client_rule_flags = NULL;
	struct client_roue_group_mac *group_mac = NULL;
	radix_node_t *node = NULL;
	uint8_t mac[6];
	int is_mac_address = 0;

	is_mac_address = parser_mac_address(ip_cidr, mac);
	if (is_mac_address == 0) {
		group_mac = _config_client_rule_group_mac_get_or_add(mac);
		if (group_mac == NULL) {
			tlog(TLOG_ERROR, "get or add mac %s failed", ip_cidr);
			goto errout;
		}

		client_rules = group_mac->rules;
	} else {
		if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
			struct dns_set_rule_flags_callback_args args;
			args.flags = flag;
			args.is_clear_flag = is_clear;
			return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_client_rule_flag_callback, &args);
		}

		/* Get existing or create domain rule */
		node = _create_client_rules_node(ip_cidr);
		if (node == NULL) {
			tlog(TLOG_ERROR, "create addr node failed.");
			goto errout;
		}

		client_rules = node->data;
	}

	if (client_rules == NULL) {
		add_client_rules = zalloc(1, sizeof(*add_client_rules));
		if (add_client_rules == NULL) {
			goto errout;
		}
		client_rules = add_client_rules;
		if (is_mac_address == 0) {
			group_mac->rules = client_rules;
		} else {
			node->data = client_rules;
		}
	}

	/* add new rule to domain */
	if (client_rules->rules[CLIENT_RULE_FLAGS] == NULL) {
		client_rule_flags = _new_dns_client_rule(CLIENT_RULE_FLAGS);
		client_rule_flags->flags = 0;
		client_rules->rules[CLIENT_RULE_FLAGS] = &client_rule_flags->head;
	}

	client_rule_flags = container_of(client_rules->rules[CLIENT_RULE_FLAGS], struct client_rule_flags, head);
	if (is_clear == false) {
		client_rule_flags->flags |= flag;
	} else {
		client_rule_flags->flags &= ~flag;
	}
	client_rule_flags->is_flag_set |= flag;

	return 0;
errout:
	if (add_client_rules) {
		free(add_client_rules);
	}

	tlog(TLOG_ERROR, "set ip %s flags failed", ip_cidr);

	return -1;
}

static void _config_client_rule_iter_free_cb(radix_node_t *node, void *cbctx)
{
	struct dns_client_rules *client_rules = NULL;
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	client_rules = node->data;
	_config_client_rules_free(client_rules);
	node->data = NULL;
}

int _config_client_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	const char *client = argv[1];
	unsigned int server_flag = 0;
	const char *group = NULL;

	/* clang-format off */
	static struct option long_options[] = {
		{"group", required_argument, NULL, 'g'},
		{"no-rule-addr", no_argument, NULL, 'A'},   
		{"no-rule-nameserver", no_argument, NULL, 'N'},   
		{"no-rule-ipset", no_argument, NULL, 'I'},   
		{"no-rule-sni-proxy", no_argument, NULL, 'P'},   
		{"no-rule-soa", no_argument, NULL, 'O'},
		{"no-speed-check", no_argument, NULL, 'S'},  
		{"no-cache", no_argument, NULL, 'C'},  
		{"no-dualstack-selection", no_argument, NULL, 'D'},
		{"no-ip-alias", no_argument, NULL, 'a'},
		{"force-aaaa-soa", no_argument, NULL, 'F'},
		{"acl", no_argument, NULL, 251},
		{"no-rules", no_argument, NULL, 252},
		{"no-serve-expired", no_argument, NULL, 253},
		{"force-https-soa", no_argument, NULL, 254},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	/* get current group */
	if (_config_current_group()) {
		group = _config_current_group()->group_name;
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "g:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'g': {
			group = optarg;
			break;
		}
		case 'A': {
			server_flag |= BIND_FLAG_NO_RULE_ADDR;
			break;
		}
		case 'a': {
			server_flag |= BIND_FLAG_NO_IP_ALIAS;
			break;
		}
		case 'N': {
			server_flag |= BIND_FLAG_NO_RULE_NAMESERVER;
			break;
		}
		case 'I': {
			server_flag |= BIND_FLAG_NO_RULE_IPSET;
			break;
		}
		case 'P': {
			server_flag |= BIND_FLAG_NO_RULE_SNIPROXY;
			break;
		}
		case 'S': {
			server_flag |= BIND_FLAG_NO_SPEED_CHECK;
			break;
		}
		case 'C': {
			server_flag |= BIND_FLAG_NO_CACHE;
			break;
		}
		case 'O': {
			server_flag |= BIND_FLAG_NO_RULE_SOA;
			break;
		}
		case 'D': {
			server_flag |= BIND_FLAG_NO_DUALSTACK_SELECTION;
			break;
		}
		case 'F': {
			server_flag |= BIND_FLAG_FORCE_AAAA_SOA;
			break;
		}
		case 251: {
			server_flag |= BIND_FLAG_ACL;
			break;
		}
		case 252: {
			server_flag |= BIND_FLAG_NO_RULES;
			break;
		}
		case 253: {
			server_flag |= BIND_FLAG_NO_SERVE_EXPIRED;
			break;
		}
		case 254: {
			server_flag |= BIND_FLAG_FORCE_HTTPS_SOA;
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown client-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	if (group != NULL) {
		if (_config_client_rule_group_add(client, group) != 0) {
			tlog(TLOG_ERROR, "add group rule failed.");
			goto errout;
		}
	}

	if (_config_client_rule_flag_set(client, server_flag, 0) != 0) {
		tlog(TLOG_ERROR, "set client rule flags failed.");
		goto errout;
	}

	return 0;
errout:
	return -1;
}

static void _config_client_rule_destroy_mac(void)
{
	struct hlist_node *tmp = NULL;
	unsigned int i;
	struct client_roue_group_mac *group_mac = NULL;

	hash_for_each_safe(dns_conf.client_rule.mac, i, tmp, group_mac, node)
	{
		hlist_del_init(&group_mac->node);
		_config_client_rules_free(group_mac->rules);
		free(group_mac);
	}
}

void _config_client_rule_destroy(void)
{
	Destroy_Radix(dns_conf.client_rule.rule, _config_client_rule_iter_free_cb, NULL);
	_config_client_rule_destroy_mac();
}

int _config_client_rule_group_add(const char *client, const char *group_name)
{
	struct client_rule_group *client_rule = NULL;
	const char *group = NULL;

	client_rule = _new_dns_client_rule(CLIENT_RULE_GROUP);
	if (client_rule == NULL) {
		goto errout;
	}

	group = _dns_conf_get_group_name(group_name);
	if (group == NULL) {
		goto errout;
	}

	client_rule->group_name = group;
	if (_config_client_rule_add(client, CLIENT_RULE_GROUP, client_rule) != 0) {
		goto errout;
	}

	_dns_client_rule_put(&client_rule->head);

	return 0;
errout:
	if (client_rule != NULL) {
		_dns_client_rule_put(&client_rule->head);
	}
	return -1;
}
