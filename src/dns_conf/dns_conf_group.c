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

#include "dns_conf_group.h"
#include "domain_rule.h"
#include "ip_rule.h"
#include "server_group.h"
#include "smartdns/lib/stringutil.h"

struct dns_conf_group_info *dns_conf_current_group_info;
struct dns_conf_group_info *dns_conf_default_group_info;
static LIST_HEAD(dns_conf_group_info_list);

struct dns_conf_rule dns_conf_rule;

int _config_rule_group_init(void)
{
	hash_init(dns_conf_rule.group);
	dns_conf_rule.default_conf = _config_rule_group_new("");
	if (dns_conf_rule.default_conf == NULL) {
		tlog(TLOG_WARN, "init default domain rule failed.");
		return -1;
	}

	return 0;
}

__attribute__((unused)) int _dns_conf_group_int(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

__attribute__((unused)) int _dns_conf_group_int_base(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

__attribute__((unused)) int _dns_conf_group_string(const char *value, char *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	char *ptr = (char *)conf_group + (size_t)data;
	safe_strncpy(ptr, value, DNS_MAX_PATH);

	return 0;
}

__attribute__((unused)) int _dns_conf_group_yesno(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

__attribute__((unused)) int _dns_conf_group_size(size_t value, size_t *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(size_t *)ptr = value;

	return 0;
}

__attribute__((unused)) int _dns_conf_group_ssize(ssize_t value, ssize_t *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(ssize_t *)ptr = value;

	return 0;
}

__attribute__((unused)) int _dns_conf_group_enum(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

struct dns_conf_group *_config_current_rule_group(void)
{
	if (dns_conf_current_group_info == NULL) {
		return NULL;
	}

	return dns_conf_current_group_info->rule;
}

struct dns_conf_group_info *_config_current_group(void)
{
	return dns_conf_current_group_info;
}

void _config_set_current_group(struct dns_conf_group_info *group_info)
{
	if (group_info == NULL) {
		return;
	}

	dns_conf_current_group_info = group_info;
}

struct dns_conf_group_info *_config_default_group(void)
{
	return dns_conf_default_group_info;
}

void _config_current_group_pop(void)
{
	struct dns_conf_group_info *group_info = NULL;

	group_info = list_last_entry(&dns_conf_group_info_list, struct dns_conf_group_info, list);
	if (group_info == NULL) {
		return;
	}

	if (group_info == dns_conf_default_group_info) {
		dns_conf_current_group_info = dns_conf_default_group_info;
		return;
	}

	list_del(&group_info->list);
	free(group_info);

	group_info = list_last_entry(&dns_conf_group_info_list, struct dns_conf_group_info, list);
	if (group_info == NULL) {
		dns_conf_current_group_info = NULL;
		return;
	}

	dns_conf_current_group_info = group_info;
}

static int _config_domain_rule_iter_copy(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	art_tree *dest_tree = data;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *new_domain_rule = NULL;

	new_domain_rule = malloc(sizeof(struct dns_domain_rule));
	if (new_domain_rule == NULL) {
		return -1;
	}
	memset(new_domain_rule, 0, sizeof(struct dns_domain_rule));
	
	old_domain_rule = (struct dns_domain_rule *)value;
	for (int i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (old_domain_rule->rules[i]) {
			_dns_rule_get(old_domain_rule->rules[i]);
			new_domain_rule->rules[i] = old_domain_rule->rules[i];
		}
	}
	new_domain_rule->sub_rule_only = old_domain_rule->sub_rule_only;
	new_domain_rule->root_rule_only = old_domain_rule->root_rule_only;

	old_domain_rule = art_insert(dest_tree, key, key_len, new_domain_rule);
	if (old_domain_rule) {
		_config_domain_rule_free(old_domain_rule);
	}

	return 0;
}

static int _config_rule_group_setup_value(struct dns_conf_group_info *group_info)
{
	struct dns_conf_group *group_rule = group_info->rule;
	int soa_talbe_size = MAX_QTYPE_NUM / 8 + 1;
	uint8_t *soa_table = NULL;
	struct dns_conf_group *parent_group = _config_current_rule_group();

	if (group_info->inherit_group != NULL) {
		if (strncmp(group_info->inherit_group, "none", sizeof("none")) == 0) {
			parent_group = NULL;
		} else if (strncmp(group_info->inherit_group, "parent", sizeof("parent")) == 0) {
			parent_group = _config_current_rule_group();
		} else if (strncmp(group_info->inherit_group, "default", sizeof("default")) == 0) {
			parent_group = dns_server_get_default_rule_group();
		} else {
			parent_group = _config_rule_group_get(group_info->inherit_group);
			if (parent_group == NULL) {
				tlog(TLOG_WARN, "inherit group %s not exist.", group_info->inherit_group);
				return -1;
			}
		}
	}

	soa_table = malloc(soa_talbe_size);
	if (soa_table == NULL) {
		tlog(TLOG_WARN, "malloc qtype soa table failed.");
		return -1;
	}
	group_rule->soa_table = soa_table;

	if (parent_group != NULL) {
		/* copy parent group data. */
		memcpy(&group_rule->copy_data_section_begin, &parent_group->copy_data_section_begin,
			   offsetof(struct dns_conf_group, copy_data_section_end) -
				   offsetof(struct dns_conf_group, copy_data_section_begin));
		memcpy(group_rule->soa_table, parent_group->soa_table, soa_talbe_size);
		art_iter(&parent_group->domain_rule.tree, _config_domain_rule_iter_copy, &group_rule->domain_rule.tree);
		return 0;
	}

	memset(soa_table, 0, soa_talbe_size);
	memcpy(&group_rule->check_orders, &dns_conf.default_check_orders, sizeof(group_rule->check_orders));
	group_rule->dualstack_ip_selection = 1;
	group_rule->dns_dualstack_ip_selection_threshold = 10;
	group_rule->dns_rr_ttl_min = 600;
	group_rule->dns_serve_expired = 1;

	if (group_rule->dns_prefetch == 1) {
		group_rule->dns_serve_expired_ttl = 24 * 3600 * 7;
	} else {
		group_rule->dns_serve_expired_ttl = 24 * 3600;
	}

	group_rule->dns_serve_expired_reply_ttl = 3;
	group_rule->dns_max_reply_ip_num = DNS_MAX_REPLY_IP_NUM;
	group_rule->dns_response_mode = dns_conf.default_response_mode;

	return 0;
}

int _config_current_group_push(const char *group_name, const char *inherit_group_name)
{
	struct dns_conf_group_info *group_info = NULL;
	struct dns_conf_group *group_rule = NULL;

	group_info = malloc(sizeof(*group_info));
	if (group_info == NULL) {
		goto errout;
	}

	if (dns_conf_default_group_info != NULL) {
		group_name = _dns_conf_get_group_name(group_name);
		if (group_name == NULL) {
			goto errout;
		}
	}

	if (inherit_group_name == NULL && _config_current_rule_group() != NULL) {
		inherit_group_name = _config_current_rule_group()->group_name;
	}

	memset(group_info, 0, sizeof(*group_info));
	group_info->inherit_group = inherit_group_name;
	INIT_LIST_HEAD(&group_info->list);
	list_add_tail(&group_info->list, &dns_conf_group_info_list);

	group_rule = _config_rule_group_get(group_name);
	if (group_rule == NULL) {
		group_rule = _config_rule_group_new(group_name);
		if (group_rule == NULL) {
			goto errout;
		}
	}

	group_info->group_name = group_name;
	group_info->rule = group_rule;
	_config_rule_group_setup_value(group_info);

	dns_conf_current_group_info = group_info;
	if (dns_conf_default_group_info == NULL) {
		dns_conf_default_group_info = group_info;
	}

	return 0;

errout:
	if (group_info) {
		free(group_info);
	}
	return -1;
}

int _config_current_group_push_default(void)
{
	return _config_current_group_push(NULL, NULL);
}

int _config_current_group_pop_to(struct dns_conf_group_info *group_info)
{
	while (dns_conf_current_group_info != NULL && dns_conf_current_group_info != group_info) {
		_config_current_group_pop();
	}

	return 0;
}

int _config_current_group_pop_to_default(void)
{
	return _config_current_group_pop_to(dns_conf_default_group_info);
}

int _config_current_group_pop_all(void)
{
	while (dns_conf_current_group_info != NULL && dns_conf_current_group_info != dns_conf_default_group_info) {
		_config_current_group_pop();
	}

	if (dns_conf_default_group_info == NULL) {
		return 0;
	}

	list_del(&dns_conf_default_group_info->list);
	free(dns_conf_default_group_info);
	dns_conf_default_group_info = NULL;
	dns_conf_current_group_info = NULL;

	return 0;
}

struct dns_conf_group *_config_rule_group_get(const char *group_name)
{
	uint32_t key = 0;
	struct dns_conf_group *rule_group = NULL;
	if (group_name == NULL) {
		group_name = "";
	}

	key = hash_string(group_name);
	hash_for_each_possible(dns_conf_rule.group, rule_group, node, key)
	{
		if (strncmp(rule_group->group_name, group_name, DNS_GROUP_NAME_LEN) == 0) {
			return rule_group;
		}
	}

	return NULL;
}

struct dns_conf_group *dns_server_get_rule_group(const char *group_name)
{
	if (dns_conf_rule.group_num <= 1) {
		return dns_conf_rule.default_conf;
	}

	struct dns_conf_group *rule_group = _config_rule_group_get(group_name);
	if (rule_group) {
		return rule_group;
	}

	return dns_conf_rule.default_conf;
}

struct dns_conf_group *dns_server_get_default_rule_group(void)
{
	return dns_conf_rule.default_conf;
}

struct dns_conf_group *_config_rule_group_new(const char *group_name)
{
	struct dns_conf_group *rule_group = NULL;
	uint32_t key = 0;

	if (group_name == NULL) {
		return NULL;
	}

	rule_group = malloc(sizeof(*rule_group));
	if (rule_group == NULL) {
		return NULL;
	}

	memset(rule_group, 0, sizeof(*rule_group));
	rule_group->group_name = group_name;

	INIT_HLIST_NODE(&rule_group->node);
	art_tree_init(&rule_group->domain_rule.tree);

	rule_group->address_rule.ipv4 = New_Radix();
	rule_group->address_rule.ipv6 = New_Radix();

	key = hash_string(group_name);
	hash_add(dns_conf_rule.group, &rule_group->node, key);
	dns_conf_rule.group_num++;

	return rule_group;
}

static void _config_rule_group_remove(struct dns_conf_group *rule_group)
{
	hlist_del_init(&rule_group->node);
	art_iter(&rule_group->domain_rule.tree, _config_domain_iter_free, NULL);
	art_tree_destroy(&rule_group->domain_rule.tree);
	Destroy_Radix(rule_group->address_rule.ipv4, _config_ip_iter_free, NULL);
	Destroy_Radix(rule_group->address_rule.ipv6, _config_ip_iter_free, NULL);
	free(rule_group->soa_table);
	dns_conf_rule.group_num--;

	free(rule_group);
}

void _config_rule_group_destroy(void)
{
	struct dns_conf_group *group;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_rule.group, i, tmp, group, node)
	{
		_config_rule_group_remove(group);
	}

	dns_conf_rule.default_conf = NULL;
}

void _dns_conf_group_post(void)
{
	struct dns_conf_group *group;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_rule.group, i, tmp, group, node)
	{
		if ((group->dns_rr_ttl_min > group->dns_rr_ttl_max) && group->dns_rr_ttl_max > 0) {
			group->dns_rr_ttl_min = group->dns_rr_ttl_max;
		}

		if ((group->dns_rr_ttl_max < group->dns_rr_ttl_min) && group->dns_rr_ttl_max > 0) {
			group->dns_rr_ttl_max = group->dns_rr_ttl_min;
		}

		if (group->dns_serve_expired == 1 && group->dns_serve_expired_ttl == 0) {
			group->dns_serve_expired_ttl = DNS_MAX_SERVE_EXPIRED_TIME;
		}
	}
}