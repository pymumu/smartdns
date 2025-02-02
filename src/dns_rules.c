/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "stddef.h"
#include "stdlib.h"
#include "string.h"

#include "dns_rules.h"
#include "tlog.h"

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
	case DOMAIN_RULE_TTL:
		size = sizeof(struct dns_ttl_rule);
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
	rule->rule = domain_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

void *_new_dns_rule(enum domain_rule domain_rule)
{
	return _new_dns_rule_ext(domain_rule, 0);
}

static void _dns_rule_get(struct dns_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

void _dns_rule_put(struct dns_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt)) {
		free(rule);
	}
}

enum layout_type {
	DOMAIN_RULE_LAYOUT_ARRAY = 1,
	DOMAIN_RULE_LAYOUT_POINTER = 2,
};

struct dns_domain_rule {
	unsigned char sub_rule_only : 1;
	unsigned char root_rule_only : 1;
	struct dns_rule *rules[DOMAIN_RULE_MAX];
};

struct dns_domain_rule *domain_rule_new(uint8_t capacity)
{
	struct dns_domain_rule *domain_rule;

	domain_rule = calloc(1, sizeof(struct dns_domain_rule));
	if (domain_rule == NULL) {
		return NULL;
	}

	return domain_rule;
}

static struct dns_rule **_domain_rule_access(struct dns_domain_rule *domain_rule, enum domain_rule type, int insert)
{
	if (domain_rule == NULL) {
		return NULL;
	}

	return &domain_rule->rules[type];
}

int domain_rule_free(struct dns_domain_rule *domain_rule)
{
	int i = 0;

	if (domain_rule == NULL) {
		return 0;
	}

	for (i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (domain_rule->rules[i] == NULL) {
			continue;
		}

		_dns_rule_put(domain_rule->rules[i]);
		domain_rule->rules[i] = NULL;
	}

	free(domain_rule);
	return 0;
}

int domain_rule_get_data(struct dns_domain_rule *domain_rule, int *sub_rule_only, int *root_rule_only)
{
	if (domain_rule == NULL) {
		return -1;
	}

	*sub_rule_only = domain_rule->sub_rule_only;
	*root_rule_only = domain_rule->root_rule_only;

	return 0;
}

int domain_rule_set_data(struct dns_domain_rule *domain_rule, int sub_rule_only, int root_rule_only)
{
	if (domain_rule == NULL) {
		return -1;
	}

	domain_rule->sub_rule_only = sub_rule_only;
	domain_rule->root_rule_only = root_rule_only;

	return 0;
}

struct dns_rule *domain_rule_get(struct dns_domain_rule *domain_rule, enum domain_rule type)
{
	struct dns_rule **ptr_rule;

	ptr_rule = _domain_rule_access(domain_rule, type, 0);
	if (ptr_rule == NULL) {
		return NULL;
	}

	return *ptr_rule;
}

struct dns_rule_flags *domain_rule_get_or_insert_flags(struct dns_domain_rule *domain_rule)
{
	struct dns_rule **ptr_rule;
	struct dns_rule_flags *rule_flags;

	ptr_rule = _domain_rule_access(domain_rule, DOMAIN_RULE_FLAGS, 1);
	if (ptr_rule == NULL) {
		return NULL;
	}

	rule_flags = _new_dns_rule(DOMAIN_RULE_FLAGS);
	if (rule_flags == NULL) {
		return NULL;
	}

	*ptr_rule = (struct dns_rule *)rule_flags;
	rule_flags->flags = 0;

	return rule_flags;
}

int domain_rule_set(struct dns_domain_rule *domain_rule, enum domain_rule type, struct dns_rule *rule)
{
	struct dns_rule **ptr_rule;

	if (domain_rule == NULL || type == DOMAIN_RULE_FLAGS) {
		return -1;
	}

	ptr_rule = _domain_rule_access(domain_rule, type, 1);
	if (ptr_rule == NULL) {
		return -1;
	}

	if (*ptr_rule) {
		_dns_rule_put(*ptr_rule);
		*ptr_rule = NULL;
	}

	*ptr_rule = rule;
	_dns_rule_get(rule);

	return 0;
}