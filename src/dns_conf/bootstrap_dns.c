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

#include "bootstrap_dns.h"
#include "domain_rule.h"
#include "nameserver.h"
#include "smartdns/util.h"

char dns_conf_exist_bootstrap_dns;

int _config_update_bootstrap_dns_rule(void)
{
	struct dns_servers *server = NULL;

	if (dns_conf_exist_bootstrap_dns == 0) {
		return 0;
	}

	for (int i = 0; i < dns_conf.server_num; i++) {
		server = &dns_conf.servers[i];
		if (check_is_ipaddr(server->server) == 0) {
			continue;
		}

		_conf_domain_rule_nameserver(server->server, "bootstrap-dns");
	}

	return 0;
}