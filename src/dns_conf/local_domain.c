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

#include "local_domain.h"
#include "domain_rule.h"
#include "nameserver.h"
#include "smartdns/lib/stringutil.h"

static char local_domain[DNS_MAX_CNAME_LEN] = {0};

const char *dns_conf_get_local_domain(void)
{
	return local_domain;
}

int _config_local_domain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	const char *domain = argv[1];

	if (local_domain[0] != '\0') {
		_config_domain_rule_remove(local_domain, DOMAIN_RULE_NAMESERVER);
        local_domain[0] = '\0';
	}

    if (domain[0] == '\0' || strncmp(domain, "-", sizeof("-")) == 0) {
        return 0;
    }

	safe_strncpy(local_domain, domain, sizeof(local_domain));
	_conf_domain_rule_nameserver(local_domain, DNS_SERVER_GROUP_MDNS);
	return 0;
}
