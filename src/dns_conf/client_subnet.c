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

#include "client_subnet.h"
#include "dns_conf_group.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

int _conf_client_subnet(char *subnet, struct dns_edns_client_subnet *ipv4_ecs, struct dns_edns_client_subnet *ipv6_ecs)
{
	char *slash = NULL;
	int subnet_len = 0;
	struct dns_edns_client_subnet *ecs = NULL;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char str_subnet[128];

	if (subnet == NULL) {
		return -1;
	}

	safe_strncpy(str_subnet, subnet, sizeof(str_subnet));
	slash = strstr(str_subnet, "/");
	if (slash) {
		*slash = 0;
		slash++;
		subnet_len = atoi(slash);
	}

	if (getaddr_by_host(str_subnet, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET:
		if (subnet_len < 0 || subnet_len > 32) {
			return -1;
		}

		if (subnet_len == 0) {
			subnet_len = 32;
		}
		ecs = ipv4_ecs;
		break;
	case AF_INET6:
		if (subnet_len < 0 || subnet_len > 128) {
			return -1;
		}

		if (subnet_len == 0) {
			subnet_len = 128;
		}
		ecs = ipv6_ecs;
		break;
	default:
		goto errout;
	}

	if (ecs == NULL) {
		return 0;
	}

	safe_strncpy(ecs->ip, str_subnet, DNS_MAX_IPLEN);
	ecs->subnet = subnet_len;
	ecs->enable = 1;

	return 0;

errout:
	return -1;
}

int _conf_edns_client_subnet(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _conf_client_subnet(argv[1], &_config_current_rule_group()->ipv4_ecs,
							   &_config_current_rule_group()->ipv6_ecs);
}
