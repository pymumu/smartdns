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

#include "ip_alias.h"
#include "ip_rule.h"

static int _config_ip_alias_add_ip_callback(const char *ip_cidr, void *priv)
{
	return _config_ip_rule_alias_add_ip(ip_cidr, (struct ip_rule_alias *)priv);
}

int _conf_ip_alias(const char *ip_cidr, const char *ips)
{
	struct ip_rule_alias *ip_alias = NULL;
	char *target_ips = NULL;
	int ret = 0;

	if (ip_cidr == NULL || ips == NULL) {
		goto errout;
	}

	ip_alias = _new_dns_ip_rule(IP_RULE_ALIAS);
	if (ip_alias == NULL) {
		goto errout;
	}

	if (strncmp(ips, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		if (_config_ip_rule_set_each(ips + sizeof("ip-set:") - 1, _config_ip_alias_add_ip_callback, ip_alias) != 0) {
			goto errout;
		}
	} else {
		target_ips = strdup(ips);
		if (target_ips == NULL) {
			goto errout;
		}

		for (char *tok = strtok(target_ips, ","); tok != NULL; tok = strtok(NULL, ",")) {
			ret = _config_ip_rule_alias_add_ip(tok, ip_alias);
			if (ret != 0) {
				goto errout;
			}
		}
	}

	if (_config_ip_rule_add(ip_cidr, IP_RULE_ALIAS, ip_alias) != 0) {
		goto errout;
	}

	_dns_ip_rule_put(&ip_alias->head);
	if (target_ips) {
		free(target_ips);
	}

	return 0;
errout:

	if (ip_alias) {
		_dns_ip_rule_put(&ip_alias->head);
	}

	if (target_ips) {
		free(target_ips);
	}

	return -1;
}

int _config_ip_alias(void *data, int argc, char *argv[])
{
	if (argc <= 2) {
		return -1;
	}

	return _conf_ip_alias(argv[1], argv[2]);
}