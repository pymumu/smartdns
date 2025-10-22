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

#include "dns64.h"
#include "dns_conf_group.h"
#include "domain_rule.h"

int _config_dns64(void *data, int argc, char *argv[])
{
	prefix_t prefix;
	char *subnet = NULL;
	const char *errmsg = NULL;
	void *p = NULL;

	if (argc <= 1) {
		return -1;
	}

	subnet = argv[1];

	if (strncmp(subnet, "-", 2U) == 0) {
		memset(&_config_current_rule_group()->dns_dns64, 0, sizeof(struct dns_dns64));
		return 0;
	}

	p = prefix_pton(subnet, -1, &prefix, &errmsg);
	if (p == NULL) {
		goto errout;
	}

	if (prefix.family != AF_INET6) {
		tlog(TLOG_ERROR, "dns64 subnet %s is not ipv6", subnet);
		goto errout;
	}

	if (prefix.bitlen <= 0 || prefix.bitlen > 96) {
		tlog(TLOG_ERROR, "dns64 subnet %s is not valid", subnet);
		goto errout;
	}

	struct dns_dns64 *dns64 = &(_config_current_rule_group()->dns_dns64);
	memcpy(&dns64->prefix, &prefix.add.sin6.s6_addr, sizeof(dns64->prefix));
	dns64->prefix_len = prefix.bitlen;

	return 0;

errout:
	return -1;
}

static void _dns_conf_dns64_setup_ipv4only_arpa_rule(void)
{
	_config_domain_rule_flag_set(DNS64_IPV4ONLY_APRA_DOMAIN, DOMAIN_FLAG_DUALSTACK_SELECT, 0);
	_conf_domain_rule_speed_check(DNS64_IPV4ONLY_APRA_DOMAIN, "none");
	_conf_domain_rule_response_mode(DNS64_IPV4ONLY_APRA_DOMAIN, "fastest-response");
}

void _dns_conf_dns64_post(void)
{
	_dns_conf_dns64_setup_ipv4only_arpa_rule();
}