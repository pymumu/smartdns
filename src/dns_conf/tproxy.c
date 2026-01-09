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

#include "tproxy.h"
#include "domain_rule.h"
#include "ip_proxy.h"
#include "smartdns/util.h"

int _config_tproxy(void *data, int argc, char *argv[])
{
	char *value = argv[1];
	char domain[DNS_MAX_CONF_CNAME_LEN];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	/* Check if domain is actually an IP address */
	if (check_is_ipaddr(domain) == 0) {
		/* It's an IP address, add to ip-rule */
		return _conf_ip_proxy(domain, value, PROXY_TYPE_TPROXY);
	} else {
		/* It's a domain name, add to domain-rule */
		return _conf_domain_rule_tproxy(domain, value);
	}

errout:
	tlog(TLOG_ERROR, "add tproxy %s:%s failed", domain, value);
	return 0;
}

int _config_sni_proxy(void *data, int argc, char *argv[])
{
	char *value = argv[1];
	char domain[DNS_MAX_CONF_CNAME_LEN];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	/* Check if domain is actually an IP address */
	if (check_is_ipaddr(domain) == 0) {
		/* It's an IP address, add to ip-rule */
		return _conf_ip_proxy(domain, value, PROXY_TYPE_SNI_PROXY);
	} else {
		/* It's a domain name, add to domain-rule */
		return _conf_domain_rule_sniproxy(domain, value);
	}

errout:
	tlog(TLOG_ERROR, "add sni-proxy %s:%s failed", domain, value);
	return 0;
}