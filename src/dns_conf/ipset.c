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

#include "ipset.h"
#include "dns_conf_group.h"
#include "domain_rule.h"
#include "get_domain.h"
#include "smartdns/lib/stringutil.h"

/* ipset */
struct dns_ipset_table {
	DECLARE_HASHTABLE(ipset, 8);
};
static struct dns_ipset_table dns_ipset_table;

int _config_ipset_init(void)
{
	hash_init(dns_ipset_table.ipset);
	return 0;
}

void _config_ipset_table_destroy(void)
{
	struct dns_ipset_name *ipset_name = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ipset_table.ipset, i, tmp, ipset_name, node)
	{
		hlist_del_init(&ipset_name->node);
		free(ipset_name);
	}
}

const char *_dns_conf_get_ipset(const char *ipsetname)
{
	uint32_t key = 0;
	struct dns_ipset_name *ipset_name = NULL;

	key = hash_string(ipsetname);
	hash_for_each_possible(dns_ipset_table.ipset, ipset_name, node, key)
	{
		if (strncmp(ipset_name->ipsetname, ipsetname, DNS_MAX_IPSET_NAMELEN) == 0) {
			return ipset_name->ipsetname;
		}
	}

	ipset_name = malloc(sizeof(*ipset_name));
	if (ipset_name == NULL) {
		goto errout;
	}

	key = hash_string(ipsetname);
	safe_strncpy(ipset_name->ipsetname, ipsetname, DNS_MAX_IPSET_NAMELEN);
	hash_add(dns_ipset_table.ipset, &ipset_name->node, key);

	return ipset_name->ipsetname;
errout:
	if (ipset_name) {
		free(ipset_name);
	}

	return NULL;
}

int _conf_domain_rule_ipset(char *domain, const char *ipsetname)
{
	struct dns_ipset_rule *ipset_rule = NULL;
	const char *ipset = NULL;
	char *copied_name = NULL;
	enum domain_rule type = 0;
	int ignore_flag = 0;
	int ret = -1;

	copied_name = strdup(ipsetname);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok; tok = strtok(NULL, ",")) {
		if (tok[0] == '#') {
			if (strncmp(tok, "#6:", 3U) == 0) {
				type = DOMAIN_RULE_IPSET_IPV6;
				ignore_flag = DOMAIN_FLAG_IPSET_IPV6_IGN;
			} else if (strncmp(tok, "#4:", 3U) == 0) {
				type = DOMAIN_RULE_IPSET_IPV4;
				ignore_flag = DOMAIN_FLAG_IPSET_IPV4_IGN;
			} else {
				goto errout;
			}
			tok += 3;
		} else {
			type = DOMAIN_RULE_IPSET;
			ignore_flag = DOMAIN_FLAG_IPSET_IGN;
		}

		if (strncmp(tok, "-", 1) == 0) {
			_config_domain_rule_flag_set(domain, ignore_flag, 0);
			continue;
		}

		/* new ipset domain */
		ipset = _dns_conf_get_ipset(tok);
		if (ipset == NULL) {
			goto errout;
		}

		ipset_rule = _new_dns_rule(type);
		if (ipset_rule == NULL) {
			goto errout;
		}

		ipset_rule->ipsetname = ipset;

		if (_config_domain_rule_add(domain, type, ipset_rule) != 0) {
			goto errout;
		}
		_dns_rule_put(&ipset_rule->head);
		ipset_rule = NULL;
	}

	ret = 0;
	goto clear;

errout:
	tlog(TLOG_ERROR, "add ipset %s failed", ipsetname);

	if (ipset_rule) {
		_dns_rule_put(&ipset_rule->head);
	}

clear:
	if (copied_name) {
		free(copied_name);
	}

	return ret;
}

static int _config_ipset_setvalue(struct dns_ipset_names *ipsets, const char *ipsetvalue)
{
	char *copied_name = NULL;
	const char *ipset = NULL;
	struct dns_ipset_rule *ipset_rule_array[2] = {NULL, NULL};
	char *ipset_rule_enable_array[2] = {NULL, NULL};
	int ipset_num = 0;

	copied_name = strdup(ipsetvalue);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok && ipset_num <= 2; tok = strtok(NULL, ",")) {
		if (tok[0] == '#') {
			if (strncmp(tok, "#6:", 3U) == 0) {
				ipset_rule_array[ipset_num] = &ipsets->ipv6;
				ipset_rule_enable_array[ipset_num] = &ipsets->ipv6_enable;
				ipset_num++;
			} else if (strncmp(tok, "#4:", 3U) == 0) {
				ipset_rule_array[ipset_num] = &ipsets->ipv4;
				ipset_rule_enable_array[ipset_num] = &ipsets->ipv4_enable;
				ipset_num++;
			} else {
				goto errout;
			}
			tok += 3;
		}

		if (ipset_num == 0) {
			ipset_rule_array[0] = &ipsets->inet;
			ipset_rule_enable_array[0] = &ipsets->inet_enable;
			ipset_num = 1;
		}

		if (strncmp(tok, "-", 1) == 0) {
			continue;
		}

		/* new ipset domain */
		ipset = _dns_conf_get_ipset(tok);
		if (ipset == NULL) {
			goto errout;
		}

		for (int i = 0; i < ipset_num; i++) {
			ipset_rule_array[i]->ipsetname = ipset;
			*ipset_rule_enable_array[i] = 1;
		}

		ipset_num = 0;
	}

	free(copied_name);
	return 0;
errout:
	if (copied_name) {
		free(copied_name);
	}

	return 0;
}

int _config_ipset(void *data, int argc, char *argv[])
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

	ret = _conf_domain_rule_ipset(domain, value);
	if (ret != 0) {
		goto errout;
	}

	return 0;
errout:
	tlog(TLOG_WARN, "add ipset %s failed.", value);
	return ret;
}

int _config_ipset_no_speed(void *data, int argc, char *argv[])
{
	char *ipsetname = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_config_ipset_setvalue(&_config_current_rule_group()->ipset_nftset.ipset_no_speed, ipsetname) != 0) {
		goto errout;
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "add ipset-no-speed %s failed", ipsetname);
	return 0;
}