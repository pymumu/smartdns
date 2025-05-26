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

#include "nameserver.h"
#include "domain_rule.h"
#include "get_domain.h"
#include "server_group.h"

int _conf_domain_rule_nameserver(const char *domain, const char *group_name)
{
	struct dns_nameserver_rule *nameserver_rule = NULL;
	const char *group = NULL;

	if (strncmp(group_name, "-", sizeof("-")) != 0) {
		group = _dns_conf_get_group_name(group_name);
		if (group == NULL) {
			goto errout;
		}

		nameserver_rule = _new_dns_rule(DOMAIN_RULE_NAMESERVER);
		if (nameserver_rule == NULL) {
			goto errout;
		}

		nameserver_rule->group_name = group;
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_NAMESERVER_IGNORE, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_NAMESERVER, nameserver_rule) != 0) {
		goto errout;
	}

	_dns_rule_put(&nameserver_rule->head);

	return 0;
errout:
	if (nameserver_rule) {
		_dns_rule_put(&nameserver_rule->head);
	}

	tlog(TLOG_ERROR, "add nameserver %s, %s failed", domain, group_name);
	return 0;
}

int _config_nameserver(void *data, int argc, char *argv[])
{
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_nameserver(domain, value);
errout:
	tlog(TLOG_ERROR, "add nameserver %s failed", value);
	return 0;
}
