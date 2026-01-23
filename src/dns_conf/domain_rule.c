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

#include "domain_rule.h"
#include "address.h"
#include "cname.h"
#include "dns_conf_group.h"
#include "https_record.h"
#include "ipset.h"
#include "nameserver.h"
#include "nftset.h"
#include "server_group.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"
#include "speed_check_mode.h"

#include <getopt.h>

static inline uint8_t _get_required_capacity(enum domain_rule type, uint8_t current_capacity)
{
	uint8_t required = type + 1;

	/* Ensure type is within valid range */
	if (type >= DOMAIN_RULE_MAX || type < 0) {
		return 0;
	}

	if (current_capacity == 0) {
		return required;
	}

	/* Expand by 2 slots at a time, but cap at DOMAIN_RULE_MAX */
	uint8_t new_capacity = ((required - current_capacity + 1) / 2) * 2 + current_capacity;

	if (new_capacity > DOMAIN_RULE_MAX) {
		new_capacity = DOMAIN_RULE_MAX;
	}

	return new_capacity;
}

static struct dns_domain_rule *_alloc_domain_rule(uint8_t capacity)
{
	size_t size = sizeof(struct dns_domain_rule) + capacity * sizeof(struct dns_rule *);
	struct dns_domain_rule *rule = malloc(size);

	if (rule == NULL) {
		return NULL;
	}

	memset(rule, 0, size);
	rule->capacity = capacity;

	return rule;
}

/*
 * Ensure the domain rule has enough capacity for the given rule type
 * Reallocates if necessary, preserving existing rules
 */
static struct dns_domain_rule *_ensure_domain_rule_capacity(struct dns_domain_rule *domain_rule, enum domain_rule type)
{
	if (type >= DOMAIN_RULE_MAX || type < 0) {
		tlog(TLOG_ERROR, "Invalid domain rule type %d", type);
		return NULL;
	}

	if (domain_rule == NULL) {
		uint8_t capacity = _get_required_capacity(type, 0);
		return _alloc_domain_rule(capacity);
	}

	if (type < domain_rule->capacity) {
		return domain_rule;
	}

	uint8_t new_capacity = _get_required_capacity(type, domain_rule->capacity);
	if (new_capacity == 0) {
		return NULL;
	}

	if (new_capacity <= domain_rule->capacity) {
		return domain_rule;
	}

	size_t new_size = sizeof(struct dns_domain_rule) + new_capacity * sizeof(struct dns_rule *);
	struct dns_domain_rule *new_rule = realloc(domain_rule, new_size);
	if (new_rule == NULL) {
		return NULL;
	}

	uint8_t old_capacity = new_rule->capacity;
	memset((void *)(new_rule->rules + old_capacity), 0, (new_capacity - old_capacity) * sizeof(struct dns_rule *));
	new_rule->capacity = new_capacity;

	return new_rule;
}

void *_new_dns_rule_ext(enum domain_rule domain_rule, int ext_size)
{
	struct dns_rule *rule;
	int size = 0;

	if (domain_rule >= DOMAIN_RULE_MAX) {
		return NULL;
	}

	switch (domain_rule) {
	case DOMAIN_RULE_FLAGS:
		size = sizeof(struct dns_rule_flags);
		break;
	case DOMAIN_RULE_ADDRESS_IPV4:
		size = sizeof(struct dns_rule_address_IPV4);
		break;
	case DOMAIN_RULE_ADDRESS_IPV6:
		size = sizeof(struct dns_rule_address_IPV6);
		break;
	case DOMAIN_RULE_IPSET:
	case DOMAIN_RULE_IPSET_IPV4:
	case DOMAIN_RULE_IPSET_IPV6:
		size = sizeof(struct dns_ipset_rule);
		break;
	case DOMAIN_RULE_NFTSET_IP:
	case DOMAIN_RULE_NFTSET_IP6:
		size = sizeof(struct dns_nftset_rule);
		break;
	case DOMAIN_RULE_NAMESERVER:
		size = sizeof(struct dns_nameserver_rule);
		break;
	case DOMAIN_RULE_GROUP:
		size = sizeof(struct dns_group_rule);
		break;
	case DOMAIN_RULE_CHECKSPEED:
		size = sizeof(struct dns_domain_check_orders);
		break;
	case DOMAIN_RULE_RESPONSE_MODE:
		size = sizeof(struct dns_response_mode_rule);
		break;
	case DOMAIN_RULE_CNAME:
		size = sizeof(struct dns_cname_rule);
		break;
	case DOMAIN_RULE_HTTPS:
		size = sizeof(struct dns_https_record_rule);
		break;
	case DOMAIN_RULE_SRV:
		size = sizeof(struct dns_srv_record_rule);
		break;
	case DOMAIN_RULE_TTL:
		size = sizeof(struct dns_ttl_rule);
		break;
	default:
		return NULL;
	}

	size += ext_size;
	rule = zalloc(1, size);
	if (!rule) {
		return NULL;
	}
	rule->rule = domain_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

void *_new_dns_rule(enum domain_rule domain_rule)
{
	return _new_dns_rule_ext(domain_rule, 0);
}

void _dns_rule_get(struct dns_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static void _dns_rule_free(struct dns_rule *rule)
{
	if (rule->rule == DOMAIN_RULE_HTTPS) {
		struct dns_https_record_rule *https_rule = (struct dns_https_record_rule *)rule;
		struct dns_https_record *record, *tmp;
		if (https_rule->record_list.next != NULL && https_rule->record_list.prev != NULL) {
			list_for_each_entry_safe(record, tmp, &https_rule->record_list, list)
			{
				list_del(&record->list);
				free(record);
			}
		}
	} else if (rule->rule == DOMAIN_RULE_SRV) {
		struct dns_srv_record_rule *srv_rule = (struct dns_srv_record_rule *)rule;
		struct dns_srv_record *record, *tmp;
		if (srv_rule->record_list.next != NULL && srv_rule->record_list.prev != NULL) {
			list_for_each_entry_safe(record, tmp, &srv_rule->record_list, list)
			{
				list_del(&record->list);
				free(record);
			}
		}
	}
	free(rule);
}

void _dns_rule_put(struct dns_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt)) {
		_dns_rule_free(rule);
	}
}

static struct dns_domain_set_name_list *_config_get_domain_set_name_list(const char *name)
{
	uint32_t key = 0;
	struct dns_domain_set_name_list *set_name_list = NULL;

	key = hash_string(name);
	hash_for_each_possible(dns_domain_set_name_table.names, set_name_list, node, key)
	{
		if (strcmp(set_name_list->name, name) == 0) {
			return set_name_list;
		}
	}

	return NULL;
}

static int _config_domain_rule_set_each(const char *domain_set, set_rule_add_func callback, void *priv)
{
	struct dns_domain_set_name_list *set_name_list = NULL;
	struct dns_domain_set_name *set_name_item = NULL;

	set_name_list = _config_get_domain_set_name_list(domain_set);
	if (set_name_list == NULL) {
		tlog(TLOG_WARN, "domain set %s not found.", domain_set);
		return -1;
	}

	list_for_each_entry(set_name_item, &set_name_list->set_name_list, list)
	{
		switch (set_name_item->type) {
		case DNS_DOMAIN_SET_LIST:
			if (_config_set_rule_each_from_list(set_name_item->file, callback, priv) != 0) {
				return -1;
			}
			break;
		case DNS_DOMAIN_SET_GEOSITE:
			break;
		default:
			tlog(TLOG_WARN, "domain set %s type %d not support.", set_name_list->name, set_name_item->type);
			break;
		}
	}

	return 0;
}

static int _config_domain_rule_add_callback(const char *domain, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_domain_rule_add(domain, args->type, args->rule);
}

static int _config_setup_domain_key(const char *domain, char *domain_key, int domain_key_max_len, int *domain_key_len,
									int *root_rule_only, int *sub_rule_only)
{
	int tmp_root_rule_only = 0;
	int tmp_sub_rule_only = 0;
	int domain_len = 0;

	int len = strlen(domain);
	domain_len = len;
	if (!domain_key || !domain_key_len || domain_key_max_len <= 0 || len + 3 > domain_key_max_len) {
		tlog(TLOG_ERROR, "invalid parameters or domain too long: %s (max %d)", domain, domain_key_max_len - 3);
		return -1;
	}

	while (len > 0 && domain[len - 1] == '.') {
		len--;
	}

	reverse_string(domain_key + 1, domain, len, 1);
	if (domain[0] == '*' && domain_len > 1) {
		/* prefix wildcard */
		len--;
		if (domain[1] == '.') {
			tmp_sub_rule_only = 1;
		} else if ((domain[1] == '-') && (domain[2] == '.')) {
			len--;
			tmp_sub_rule_only = 1;
			tmp_root_rule_only = 1;
		}
	} else if (domain[0] == '-' && domain_len > 1) {
		/* root match only */
		len--;
		if (domain[1] == '.') {
			tmp_root_rule_only = 1;
		}
	} else if (len > 0) {
		/* suffix match */
		if (len + 2 < domain_key_max_len) {
			domain_key[len + 1] = '.';
			len++;
		}
	}

	/* add dot to the front when sub rule only */
	domain_key[0] = '.';
	if (tmp_sub_rule_only == 1 && tmp_root_rule_only == 0) {
		domain_key[len + 1] = '\0';
	} else if (tmp_root_rule_only == 1 && tmp_sub_rule_only == 0) {
		if (domain_key[len] == '.') {
			len--;
		}
		domain_key[len + 1] = '\0';
	} else {
		domain_key[len + 1] = '\0';
	}

	*domain_key_len = len + 1;
	if (root_rule_only) {
		*root_rule_only = tmp_root_rule_only;
	}

	if (sub_rule_only) {
		*sub_rule_only = tmp_sub_rule_only;
	}

	return 0;
}

static __attribute__((unused)) struct dns_domain_rule *_config_domain_rule_get(const char *domain)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
		return NULL;
	}

	return art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
}

int _config_domain_rule_free(struct dns_domain_rule *domain_rule)
{
	int i = 0;

	if (domain_rule == NULL) {
		return 0;
	}

	/* Iterate only through allocated capacity, not DOMAIN_RULE_MAX */
	for (i = 0; i < domain_rule->capacity; i++) {
		if (domain_rule->rules[i] == NULL) {
			continue;
		}

		_dns_rule_put(domain_rule->rules[i]);
		domain_rule->rules[i] = NULL;
	}

	free(domain_rule);
	return 0;
}

int _config_domain_iter_free(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct dns_domain_rule *domain_rule = value;
	return _config_domain_rule_free(domain_rule);
}

static int _config_domain_rule_delete_callback(const char *domain, void *priv)
{
	return _config_domain_rule_delete(domain);
}

int _config_domain_rule_delete(const char *domain)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_delete_callback,
											NULL);
	}
	/* Reverse string, for suffix match */

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
		goto errout;
	}

	/* delete existing rules */
	void *rule = art_delete(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (rule) {
		_config_domain_rule_free(rule);
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "delete domain %s rule failed", domain);
	return -1;
}

static int _config_domain_rule_flag_callback(const char *domain, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_domain_rule_flag_set(domain, args->flags, args->is_clear_flag);
}

int _config_domain_rule_flag_set(const char *domain, unsigned int flag, unsigned int is_clear)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;
	struct dns_rule_flags *rule_flags = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		struct dns_set_rule_flags_callback_args args;
		args.flags = flag;
		args.is_clear_flag = is_clear;
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_flag_callback,
											&args);
	}

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		goto errout;
	}

	/* Get existing domain rule */
	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		/* Allocate new domain rule with minimum capacity for flags */
		domain_rule = _alloc_domain_rule(_get_required_capacity(DOMAIN_RULE_FLAGS, 0));
		if (domain_rule == NULL) {
			goto errout;
		}
		add_domain_rule = domain_rule;
	}

	/* add new rule to domain */
	if (domain_rule->rules[DOMAIN_RULE_FLAGS] == NULL) {
		rule_flags = _new_dns_rule(DOMAIN_RULE_FLAGS);
		rule_flags->flags = 0;
		domain_rule->rules[DOMAIN_RULE_FLAGS] = (struct dns_rule *)rule_flags;
	}

	rule_flags = (struct dns_rule_flags *)domain_rule->rules[DOMAIN_RULE_FLAGS];
	rule_flags->head.sub_only = sub_rule_only;
	rule_flags->head.root_only = root_rule_only;
	if (is_clear == false) {
		rule_flags->flags |= flag;
	} else {
		rule_flags->flags &= ~flag;
	}
	rule_flags->is_flag_set |= flag;

	/* update domain rule */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len,
									 add_domain_rule);
		if (old_domain_rule) {
			_config_domain_rule_free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add domain %s rule failed", domain);
	return 0;
}

int _config_domain_rule_remove(const char *domain, enum domain_rule type)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (type < 0 || type >= DOMAIN_RULE_MAX) {
		tlog(TLOG_ERROR, "invalid domain rule type %d", type);
		return -1;
	}

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_delete_callback,
											NULL);
	}

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		tlog(TLOG_ERROR, "setup domain key failed for %s", domain);
		return -1;
	}

	struct dns_domain_rule *domain_rule =
		art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		tlog(TLOG_ERROR, "domain %s not found", domain);
		return -1;
	}

	if (domain_rule->rules[type] == NULL) {
		return 0;
	}

	_dns_rule_put(domain_rule->rules[type]);
	domain_rule->rules[type] = NULL;

	return 0;
}

int _config_domain_rule_add(const char *domain, enum domain_rule type, void *rule)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		struct dns_set_rule_add_callback_args args;
		args.type = type;
		args.rule = rule;
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_add_callback,
											&args);
	}

	/* Reverse string, for suffix match */
	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		goto errout;
	}

	if (type >= DOMAIN_RULE_MAX) {
		goto errout;
	}

	/* Get existing domain rule */
	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);

	/* Track if this is a new allocation (before capacity expansion) */
	int was_new_allocation = (domain_rule == NULL);
	struct dns_domain_rule *old_ptr = domain_rule;

	/* Ensure capacity for the new rule type */
	domain_rule = _ensure_domain_rule_capacity(domain_rule, type);
	if (domain_rule == NULL) {
		tlog(TLOG_ERROR, "failed to allocate capacity for domain %s rule type %d", domain, type);
		goto errout;
	}

	/* Set add_domain_rule if this was a new allocation or if realloc moved the memory */
	if (was_new_allocation) {
		add_domain_rule = domain_rule;
	} else if (domain_rule != old_ptr) {
		/* Memory was moved by realloc, need to update ART tree
		 * Note: old_ptr is already freed by realloc, so we don't free it again */
		old_domain_rule =
			art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len, domain_rule);
		/* old_domain_rule == old_ptr, already freed by realloc, don't free again */
		add_domain_rule = NULL;
	}

	/* add new rule to domain */
	if (domain_rule->rules[type]) {
		_dns_rule_put(domain_rule->rules[type]);
		domain_rule->rules[type] = NULL;
	}

	domain_rule->rules[type] = rule;
	((struct dns_rule *)rule)->sub_only = sub_rule_only;
	((struct dns_rule *)rule)->root_only = root_rule_only;
	_dns_rule_get(rule);

	/* update domain rule - only for new allocations */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len,
									 add_domain_rule);
		if (old_domain_rule) {
			_config_domain_rule_free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add domain %s rule failed", domain);
	return -1;
}

static int _conf_domain_rule_rr_ttl(const char *domain, int ttl, int ttl_min, int ttl_max)
{
	struct dns_ttl_rule *rr_ttl = NULL;

	if (ttl < 0 || ttl_min < 0 || ttl_max < 0) {
		tlog(TLOG_ERROR, "invalid ttl value.");
		goto errout;
	}

	rr_ttl = _new_dns_rule(DOMAIN_RULE_TTL);
	if (rr_ttl == NULL) {
		goto errout;
	}

	rr_ttl->ttl = ttl;
	rr_ttl->ttl_min = ttl_min;
	rr_ttl->ttl_max = ttl_max;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_TTL, rr_ttl) != 0) {
		goto errout;
	}

	_dns_rule_put(&rr_ttl->head);

	return 0;
errout:
	if (rr_ttl != NULL) {
		_dns_rule_put(&rr_ttl->head);
	}

	return -1;
}

static int _conf_domain_rule_no_serve_expired(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_SERVE_EXPIRED, 0);
}

static int _conf_domain_rule_delete(const char *domain)
{
	return _config_domain_rule_delete(domain);
}

static int _conf_domain_rule_no_cache(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_CACHE, 0);
}

static int _conf_domain_rule_enable_cache(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_ENABLE_CACHE, 0);
}

static int _conf_domain_rule_no_ipalias(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_IPALIAS, 0);
}

static int _conf_domain_rule_no_ignore_ip(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_IGNORE_IP, 0);
}

int _conf_domain_rule_response_mode(char *domain, const char *mode)
{
	enum response_mode_type response_mode_type = DNS_RESPONSE_MODE_FIRST_PING_IP;
	struct dns_response_mode_rule *response_mode = NULL;

	for (int i = 0; response_mode_list()[i].name != NULL; i++) {
		if (strcmp(mode, response_mode_list()[i].name) == 0) {
			response_mode_type = response_mode_list()[i].id;
			break;
		}
	}

	response_mode = _new_dns_rule(DOMAIN_RULE_RESPONSE_MODE);
	if (response_mode == NULL) {
		goto errout;
	}
	response_mode->mode = response_mode_type;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_RESPONSE_MODE, response_mode) != 0) {
		goto errout;
	}

	_dns_rule_put(&response_mode->head);
	return 0;
errout:
	if (response_mode) {
		_dns_rule_put(&response_mode->head);
	}

	return 0;
}

int _conf_domain_rule_speed_check(char *domain, const char *mode)
{
	struct dns_domain_check_orders *check_orders = NULL;

	check_orders = _new_dns_rule(DOMAIN_RULE_CHECKSPEED);
	if (check_orders == NULL) {
		goto errout;
	}

	if (_config_speed_check_mode_parser(check_orders, mode) != 0) {
		goto errout;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_CHECKSPEED, check_orders) != 0) {
		goto errout;
	}

	_dns_rule_put(&check_orders->head);
	return 0;
errout:
	if (check_orders) {
		_dns_rule_put(&check_orders->head);
	}
	return 0;
}

int _conf_domain_rule_group(const char *domain, const char *group_name)
{
	struct dns_group_rule *group_rule = NULL;
	const char *group = NULL;

	if (strncmp(group_name, "-", sizeof("-")) != 0) {
		group = _dns_conf_get_group_name(group_name);
		if (group == NULL) {
			goto errout;
		}

		group_rule = _new_dns_rule(DOMAIN_RULE_GROUP);
		if (group_rule == NULL) {
			goto errout;
		}

		group_rule->group_name = group;
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_GROUP_IGNORE, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_GROUP, group_rule) != 0) {
		goto errout;
	}

	_dns_rule_put(&group_rule->head);

	return 0;
errout:
	if (group_rule) {
		_dns_rule_put(&group_rule->head);
	}

	tlog(TLOG_ERROR, "add group %s, %s failed", domain, group_name);
	return 0;
}

static int _conf_domain_rule_dualstack_selection(char *domain, const char *yesno)
{
	if (strncmp(yesno, "yes", sizeof("yes")) == 0 || strncmp(yesno, "Yes", sizeof("Yes")) == 0) {
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_DUALSTACK_SELECT, 0) != 0) {
			goto errout;
		}
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_DUALSTACK_SELECT, 1) != 0) {
			goto errout;
		}
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "set dualstack for %s failed. ", domain);
	return 1;
}

int _config_domain_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];
	int rr_ttl = 0;
	int rr_ttl_min = 0;
	int rr_ttl_max = 0;
	const char *group = NULL;
	char group_name[DNS_MAX_CONF_CNAME_LEN];

	/* clang-format off */
	static struct option long_options[] = {
		{"speed-check-mode", required_argument, NULL, 'c'},
		{"response-mode", required_argument, NULL, 'r'},
		{"address", required_argument, NULL, 'a'},
		{"https-record", required_argument, NULL, 'h'},
		{"ipset", required_argument, NULL, 'p'},
		{"nftset", required_argument, NULL, 't'},
		{"nameserver", required_argument, NULL, 'n'},
		{"group", required_argument, NULL, 'g'},
		{"dualstack-ip-selection", required_argument, NULL, 'd'},
		{"cname", required_argument, NULL, 'A'},
		{"rr-ttl", required_argument, NULL, 251},
		{"rr-ttl-min", required_argument, NULL, 252},
		{"rr-ttl-max", required_argument, NULL, 253},
		{"no-serve-expired", no_argument, NULL, 254},
		{"delete", no_argument, NULL, 255},
		{"no-cache", no_argument, NULL, 256},
		{"no-ip-alias", no_argument, NULL, 257},
		{"enable-cache", no_argument, NULL, 258},
		{"no-ignore-ip", no_argument, NULL, 259},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	/* check domain set exists. */
	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		const char *set_name = domain + sizeof("domain-set:") - 1;
		struct dns_domain_set_name_list *name = _config_get_domain_set_name_list(set_name);
		if (name == NULL) {
			tlog(TLOG_ERROR, "domain set '%s' not found.", set_name);
			goto errout;
		}
	}

	for (int i = 2; i < argc - 1; i++) {
		if (strncmp(argv[i], "-g", sizeof("-g")) == 0 || strncmp(argv[i], "--group", sizeof("--group")) == 0 ||
			strncmp(argv[i], "-group", sizeof("-group")) == 0) {
			safe_strncpy(group_name, argv[i + 1], DNS_MAX_CONF_CNAME_LEN);
			group = group_name;
			break;
		}
	}

	if (group != NULL) {
		_config_current_group_push(group, NULL);
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "c:a:p:t:n:d:A:r:g:h:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'c': {
			const char *check_mode = optarg;
			if (check_mode == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_speed_check(domain, check_mode) != 0) {
				tlog(TLOG_ERROR, "add check-speed-rule rule failed.");
				goto errout;
			}

			break;
		}
		case 'r': {
			const char *response_mode = optarg;
			if (response_mode == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_response_mode(domain, response_mode) != 0) {
				tlog(TLOG_ERROR, "add response-mode rule failed.");
				goto errout;
			}

			break;
		}
		case 'a': {
			const char *address = optarg;
			if (address == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_address(domain, address) != 0) {
				tlog(TLOG_ERROR, "add address rule failed.");
				goto errout;
			}

			break;
		}
		case 'h': {
			const char *https_record = optarg;
			if (https_record == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_https_record(domain, https_record) != 0) {
				tlog(TLOG_ERROR, "add https-record rule failed.");
				goto errout;
			}

			break;
		}
		case 'p': {
			const char *ipsetname = optarg;
			if (ipsetname == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_ipset(domain, ipsetname) != 0) {
				tlog(TLOG_ERROR, "add ipset rule failed.");
				goto errout;
			}

			break;
		}
		case 'n': {
			const char *nameserver_group = optarg;
			if (nameserver_group == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_nameserver(domain, nameserver_group) != 0) {
				tlog(TLOG_ERROR, "add nameserver rule failed.");
				goto errout;
			}

			break;
		}
		case 'A': {
			const char *cname = optarg;

			if (_conf_domain_rule_cname(domain, cname) != 0) {
				tlog(TLOG_ERROR, "add cname rule failed.");
				goto errout;
			}

			break;
		}
		case 'd': {
			const char *yesno = optarg;
			if (_conf_domain_rule_dualstack_selection(domain, yesno) != 0) {
				tlog(TLOG_ERROR, "set dualstack selection rule failed.");
				goto errout;
			}

			break;
		}
		case 't': {
			const char *nftsetname = optarg;
			if (nftsetname == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_nftset(domain, nftsetname) != 0) {
				tlog(TLOG_ERROR, "add nftset rule failed.");
				goto errout;
			}

			break;
		}
		case 'g': {
			break;
		}
		case 251: {
			rr_ttl = atoi(optarg);
			break;
		}
		case 252: {
			rr_ttl_min = atoi(optarg);
			break;
		}
		case 253: {
			rr_ttl_max = atoi(optarg);
			break;
		}
		case 254: {
			if (_conf_domain_rule_no_serve_expired(domain) != 0) {
				tlog(TLOG_ERROR, "set no-serve-expired rule failed.");
				goto errout;
			}

			break;
		}
		case 255: {
			if (_conf_domain_rule_delete(domain) != 0) {
				tlog(TLOG_ERROR, "delete domain rule failed.");
				goto errout;
			}

			return 0;
		}
		case 256: {
			if (_conf_domain_rule_no_cache(domain) != 0) {
				tlog(TLOG_ERROR, "set no-cache rule failed.");
				goto errout;
			}

			break;
		}
		case 257: {
			if (_conf_domain_rule_no_ipalias(domain) != 0) {
				tlog(TLOG_ERROR, "set no-ipalias rule failed.");
				goto errout;
			}

			break;
		}
		case 258: {
			if (_conf_domain_rule_enable_cache(domain) != 0) {
				tlog(TLOG_ERROR, "set enable-cache rule failed.");
				goto errout;
			}

			break;
		}
		case 259: {
			if (_conf_domain_rule_no_ignore_ip(domain) != 0) {
				tlog(TLOG_ERROR, "set no-ignore-ip rule failed.");
				goto errout;
			}

			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown domain-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	if (rr_ttl > 0 || rr_ttl_min > 0 || rr_ttl_max > 0) {
		if (_conf_domain_rule_rr_ttl(domain, rr_ttl, rr_ttl_min, rr_ttl_max) != 0) {
			tlog(TLOG_ERROR, "set rr-ttl rule failed.");
			goto errout;
		}
	}

	if (group != NULL) {
		_config_current_group_pop();
	}

	return 0;
errout:
	if (group != NULL) {
		_config_current_group_pop();
	}
	return -1;
}

void *dns_conf_get_domain_rule(const char *domain, enum domain_rule type)
{
	struct dns_domain_rule *domain_rule = NULL;
	char domain_key[DNS_MAX_CONF_CNAME_LEN] = {0};
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		return NULL;
	}

	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		return NULL;
	}

	if (type >= DOMAIN_RULE_MAX || type >= domain_rule->capacity) {
		return NULL;
	}

	return domain_rule->rules[type];
}
