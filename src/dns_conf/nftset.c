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

#include "nftset.h"
#include "dns_conf_group.h"
#include "domain_rule.h"
#include "get_domain.h"
#include "smartdns/lib/stringutil.h"

struct dns_nftset_table {
	DECLARE_HASHTABLE(nftset, 8);
};
static struct dns_nftset_table dns_nftset_table;

void _config_nftset_table_destroy(void)
{
	struct dns_nftset_name *nftset = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_nftset_table.nftset, i, tmp, nftset, node)
	{
		hlist_del_init(&nftset->node);
		free(nftset);
	}
}

const struct dns_nftset_name *_dns_conf_get_nftable(const char *familyname, const char *tablename, const char *setname)
{
	uint32_t key = 0;
	struct dns_nftset_name *nftset_name = NULL;

	if (familyname == NULL || tablename == NULL || setname == NULL) {
		return NULL;
	}

	const char *hasher[4] = {familyname, tablename, setname, NULL};

	key = hash_string_array(hasher);
	hash_for_each_possible(dns_nftset_table.nftset, nftset_name, node, key)
	{
		if (strncmp(nftset_name->nftfamilyname, familyname, DNS_MAX_NFTSET_FAMILYLEN) == 0 &&
			strncmp(nftset_name->nfttablename, tablename, DNS_MAX_NFTSET_NAMELEN) == 0 &&
			strncmp(nftset_name->nftsetname, setname, DNS_MAX_NFTSET_NAMELEN) == 0) {
			return nftset_name;
		}
	}

	nftset_name = malloc(sizeof(*nftset_name));
	if (nftset_name == NULL) {
		goto errout;
	}

	safe_strncpy(nftset_name->nftfamilyname, familyname, DNS_MAX_NFTSET_FAMILYLEN);
	safe_strncpy(nftset_name->nfttablename, tablename, DNS_MAX_NFTSET_NAMELEN);
	safe_strncpy(nftset_name->nftsetname, setname, DNS_MAX_NFTSET_NAMELEN);
	hash_add(dns_nftset_table.nftset, &nftset_name->node, key);

	return nftset_name;
errout:
	if (nftset_name) {
		free(nftset_name);
	}

	return NULL;
}

int _conf_domain_rule_nftset(char *domain, const char *nftsetname)
{
	struct dns_nftset_rule *nftset_rule = NULL;
	const struct dns_nftset_name *nftset = NULL;
	char *copied_name = NULL;
	enum domain_rule type = 0;
	int ignore_flag = 0;
	char *setname = NULL;
	char *tablename = NULL;
	char *family = NULL;
	int ret = -1;

	copied_name = strdup(nftsetname);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok; tok = strtok(NULL, ",")) {
		char *saveptr = NULL;
		char *tok_set = NULL;
		nftset_rule = NULL;

		if (strncmp(tok, "#4:", 3U) == 0) {
			type = DOMAIN_RULE_NFTSET_IP;
			ignore_flag = DOMAIN_FLAG_NFTSET_IP_IGN;
		} else if (strncmp(tok, "#6:", 3U) == 0) {
			type = DOMAIN_RULE_NFTSET_IP6;
			ignore_flag = DOMAIN_FLAG_NFTSET_IP6_IGN;
		} else if (strncmp(tok, "-", 2U) == 0) {
			_config_domain_rule_flag_set(domain, DOMAIN_FLAG_NFTSET_INET_IGN, 0);
			continue;
		} else {
			goto errout;
		}

		tok_set = tok + 3;

		if (strncmp(tok_set, "-", 2U) == 0) {
			_config_domain_rule_flag_set(domain, ignore_flag, 0);
			continue;
		}

		family = strtok_r(tok_set, "#", &saveptr);
		if (family == NULL) {
			goto errout;
		}

		tablename = strtok_r(NULL, "#", &saveptr);
		if (tablename == NULL) {
			goto errout;
		}

		setname = strtok_r(NULL, "#", &saveptr);
		if (setname == NULL) {
			goto errout;
		}

		/* new nftset domain */
		nftset = _dns_conf_get_nftable(family, tablename, setname);
		if (nftset == NULL) {
			goto errout;
		}

		nftset_rule = _new_dns_rule(type);
		if (nftset_rule == NULL) {
			goto errout;
		}

		nftset_rule->nfttablename = nftset->nfttablename;
		nftset_rule->nftsetname = nftset->nftsetname;
		nftset_rule->familyname = nftset->nftfamilyname;

		if (_config_domain_rule_add(domain, type, nftset_rule) != 0) {
			goto errout;
		}
		_dns_rule_put(&nftset_rule->head);
		nftset_rule = NULL;
	}

	ret = 0;
	goto clear;

errout:
	tlog(TLOG_ERROR, "add nftset %s %s failed.", domain, nftsetname);

	if (nftset_rule) {
		_dns_rule_put(&nftset_rule->head);
	}

clear:
	if (copied_name) {
		free(copied_name);
	}

	return ret;
}

static int _config_nftset_setvalue(struct dns_nftset_names *nftsets, const char *nftsetvalue)
{
	const struct dns_nftset_name *nftset = NULL;
	char *copied_name = NULL;
	int nftset_num = 0;
	char *setname = NULL;
	char *tablename = NULL;
	char *family = NULL;
	int ret = -1;
	struct dns_nftset_rule *nftset_rule_array[2] = {NULL, NULL};
	char *nftset_rule_enable_array[2] = {NULL, NULL};

	if (nftsetvalue == NULL) {
		goto errout;
	}

	copied_name = strdup(nftsetvalue);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok && nftset_num <= 2; tok = strtok(NULL, ",")) {
		char *saveptr = NULL;
		char *tok_set = NULL;

		if (strncmp(tok, "#4:", 3U) == 0) {
			nftsets->ip_enable = 1;
			nftset_rule_array[nftset_num] = &nftsets->ip;
			nftset_rule_enable_array[nftset_num] = &nftsets->ip_enable;
			nftset_num++;
		} else if (strncmp(tok, "#6:", 3U) == 0) {
			nftset_rule_enable_array[nftset_num] = &nftsets->ip6_enable;
			nftset_rule_array[nftset_num] = &nftsets->ip6;
			nftset_num++;
		} else if (strncmp(tok, "-", 2U) == 0) {
			continue;
			continue;
		} else {
			goto errout;
		}

		tok_set = tok + 3;

		if (nftset_num == 0) {
			nftset_rule_array[0] = &nftsets->ip;
			nftset_rule_enable_array[0] = &nftsets->ip_enable;
			nftset_rule_array[1] = &nftsets->ip6;
			nftset_rule_enable_array[1] = &nftsets->ip6_enable;
			nftset_num = 2;
		}

		if (strncmp(tok_set, "-", 2U) == 0) {
			continue;
		}

		family = strtok_r(tok_set, "#", &saveptr);
		if (family == NULL) {
			goto errout;
		}

		tablename = strtok_r(NULL, "#", &saveptr);
		if (tablename == NULL) {
			goto errout;
		}

		setname = strtok_r(NULL, "#", &saveptr);
		if (setname == NULL) {
			goto errout;
		}

		/* new nftset domain */
		nftset = _dns_conf_get_nftable(family, tablename, setname);
		if (nftset == NULL) {
			goto errout;
		}

		for (int i = 0; i < nftset_num; i++) {
			nftset_rule_array[i]->familyname = nftset->nftfamilyname;
			nftset_rule_array[i]->nfttablename = nftset->nfttablename;
			nftset_rule_array[i]->nftsetname = nftset->nftsetname;
			*nftset_rule_enable_array[i] = 1;
		}

		nftset_num = 0;
	}

	ret = 0;
	goto clear;

errout:
	ret = -1;
clear:
	if (copied_name) {
		free(copied_name);
	}

	return ret;
}

int _config_nftset(void *data, int argc, char *argv[])
{
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];
	int ret = 0;

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_nftset(domain, value);
errout:
	tlog(TLOG_ERROR, "add nftset %s failed", value);
	return ret;
}

int _config_nftset_no_speed(void *data, int argc, char *argv[])
{
	char *nftsetname = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_config_nftset_setvalue(&_config_current_rule_group()->ipset_nftset.nftset_no_speed, nftsetname) != 0) {
		goto errout;
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "add nftset %s failed", nftsetname);
	return -1;
}
