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

#include "ecs.h"

#include "smartdns/util.h"

static int _dns_client_setup_ecs(char *ip, int subnet, struct dns_client_ecs *ecs)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		return -1;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		memcpy(&ecs->ecs.addr, &addr_in->sin_addr.s_addr, 4);
		ecs->ecs.source_prefix = subnet;
		ecs->ecs.scope_prefix = 0;
		ecs->ecs.family = DNS_OPT_ECS_FAMILY_IPV4;
		ecs->enable = 1;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			ecs->ecs.source_prefix = subnet;
			ecs->ecs.scope_prefix = 0;
			ecs->ecs.family = DNS_OPT_ECS_FAMILY_IPV4;
			ecs->enable = 1;
		} else {
			memcpy(&ecs->ecs.addr, addr_in6->sin6_addr.s6_addr, 16);
			ecs->ecs.source_prefix = subnet;
			ecs->ecs.scope_prefix = 0;
			ecs->ecs.family = DNS_ADDR_FAMILY_IPV6;
			ecs->enable = 1;
		}
	} break;
	default:
		return -1;
	}
	return 0;
}

int _dns_client_server_add_ecs(struct dns_server_info *server_info, struct client_dns_server_flags *flags)
{
	int ret = 0;

	if (flags == NULL) {
		return 0;
	}

	if (flags->ipv4_ecs.enable) {
		ret = _dns_client_setup_ecs(flags->ipv4_ecs.ip, flags->ipv4_ecs.subnet, &server_info->ecs_ipv4);
	}

	if (flags->ipv6_ecs.enable) {
		ret |= _dns_client_setup_ecs(flags->ipv6_ecs.ip, flags->ipv6_ecs.subnet, &server_info->ecs_ipv6);
	}

	return ret;
}

int _dns_client_dns_add_ecs(struct dns_query_struct *query, struct dns_packet *packet)
{
	if (query->ecs.enable == 0) {
		return 0;
	}

	return dns_add_OPT_ECS(packet, &query->ecs.ecs);
}

int _dns_client_query_setup_default_ecs(struct dns_query_struct *query)
{
	struct dns_conf_group *conf = query->conf;
	struct dns_edns_client_subnet *ecs_conf = NULL;

	if (query->qtype == DNS_T_A && conf->ipv4_ecs.enable) {
		ecs_conf = &conf->ipv4_ecs;
	} else if (query->qtype == DNS_T_AAAA && conf->ipv6_ecs.enable) {
		ecs_conf = &conf->ipv6_ecs;
	} else {
		if (conf->ipv4_ecs.enable) {
			ecs_conf = &conf->ipv4_ecs;
		} else if (conf->ipv6_ecs.enable) {
			ecs_conf = &conf->ipv6_ecs;
		}
	}

	if (ecs_conf == NULL) {
		return 0;
	}

	struct dns_client_ecs ecs;
	if (_dns_client_setup_ecs(ecs_conf->ip, ecs_conf->subnet, &ecs) != 0) {
		return -1;
	}

	memcpy(&query->ecs, &ecs, sizeof(query->ecs));
	return 0;
}
