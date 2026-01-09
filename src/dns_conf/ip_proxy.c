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

#include "ip_proxy.h"
#include "dns_conf_group.h"
#include "ip_alias.h"
#include "ip_rule.h"
#include "set_file.h"
#include "smartdns/util.h"

int _conf_ip_proxy(const char *ip_cidr, const char *proxy_name, enum proxy_type proxy_type)
{
	struct ip_rule_proxy *proxy_rule = NULL;
	const char *proxy = NULL;

	proxy = _dns_conf_get_proxy_name(proxy_name);
	if (proxy == NULL) {
		goto errout;
	}

	proxy_rule = _new_dns_ip_rule(IP_RULE_PROXY);
	if (proxy_rule == NULL) {
		goto errout;
	}

	proxy_rule->proxy_name = proxy;
	proxy_rule->proxy_type = proxy_type;

	if (_config_ip_rule_add(ip_cidr, IP_RULE_PROXY, proxy_rule) != 0) {
		goto errout;
	}

	_dns_ip_rule_put(&proxy_rule->head);

	return 0;
errout:
	if (proxy_rule) {
		_dns_ip_rule_put(&proxy_rule->head);
	}

	tlog(TLOG_ERROR, "add ip proxy %s, %s failed", ip_cidr, proxy_name);
	return -1;
}