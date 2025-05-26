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

#include "cname.h"

#include "domain_rule.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"

int _conf_domain_rule_cname(const char *domain, const char *cname)
{
	struct dns_cname_rule *cname_rule = NULL;
	enum domain_rule type = DOMAIN_RULE_CNAME;

	cname_rule = _new_dns_rule(type);
	if (cname_rule == NULL) {
		goto errout;
	}

	/* ignore this domain */
	if (*cname == '-') {
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_CNAME_IGN, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	safe_strncpy(cname_rule->cname, cname, DNS_MAX_CONF_CNAME_LEN);

	if (_config_domain_rule_add(domain, type, cname_rule) != 0) {
		goto errout;
	}
	_dns_rule_put(&cname_rule->head);
	cname_rule = NULL;

	return 0;

errout:
	tlog(TLOG_ERROR, "add cname %s:%s failed", domain, cname);

	if (cname_rule) {
		_dns_rule_put(&cname_rule->head);
	}

	return 0;
}

int _config_cname(void *data, int argc, char *argv[])
{
	char *value = argv[1];
	char domain[DNS_MAX_CONF_CNAME_LEN];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_cname(domain, value);
errout:
	tlog(TLOG_ERROR, "add cname %s:%s failed", domain, value);
	return 0;
}