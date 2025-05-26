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

#include "ddns_domain.h"
#include "domain_rule.h"
#include "smartdns/lib/stringutil.h"

static char ddns_domain[DNS_MAX_CNAME_LEN] = {0};

const char *dns_conf_get_ddns_domain(void)
{
	return ddns_domain;
}

int _config_ddns_domain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	const char *domain = argv[1];
	safe_strncpy(ddns_domain, domain, sizeof(ddns_domain));
	_config_domain_rule_flag_set(domain, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
	return 0;
}
