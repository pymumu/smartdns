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

#include "smartdns_domain.h"
#include "domain_rule.h"

#include <stdio.h>

void _config_setup_smartdns_domain(void)
{
	char hostname[DNS_MAX_CNAME_LEN];
	char domainname[DNS_MAX_CNAME_LEN];

	hostname[0] = '\0';
	domainname[0] = '\0';

	/* get local domain name */
	if (getdomainname(domainname, DNS_MAX_CNAME_LEN - 1) == 0) {
		/* check domain is valid */
		if (strncmp(domainname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
			domainname[0] = '\0';
		}
	}

	if (gethostname(hostname, DNS_MAX_CNAME_LEN - 1) == 0) {
		/* check hostname is valid */
		if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
			hostname[0] = '\0';
		}
	}

	if (dns_conf.resolv_hostname == 1) {
		/* add hostname to rule table */
		if (hostname[0] != '\0') {
			_config_domain_rule_flag_set(hostname, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
		}

		/* add domainname to rule table */
		if (domainname[0] != '\0') {
			char full_domain[DNS_MAX_CNAME_LEN];
			snprintf(full_domain, DNS_MAX_CNAME_LEN, "%.64s.%.128s", hostname, domainname);
			_config_domain_rule_flag_set(full_domain, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
		}
	}

	/* add server name to rule table */
	if (dns_conf.server_name[0] != '\0' &&
		strncmp(dns_conf.server_name, "smartdns", DNS_MAX_SERVER_NAME_LEN - 1) != 0) {
		_config_domain_rule_flag_set(dns_conf.server_name, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
	}

	_config_domain_rule_flag_set("smartdns", DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
}
