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

#include "mdns.h"
#include "dns_server.h"
#include "request.h"

void _dns_server_need_append_mdns_local_cname(struct dns_request *request)
{
	if (request->is_mdns_lookup == 0) {
		return;
	}

	if (request->has_cname != 0) {
		return;
	}

	if (request->domain[0] == '\0') {
		return;
	}

	if (strstr(request->domain, ".") != NULL) {
		return;
	}

	request->has_cname = 1;
	snprintf(request->cname, sizeof(request->cname), "%.*s.%s",
			 (int)(sizeof(request->cname) - sizeof(DNS_SERVER_GROUP_LOCAL) - 1), request->domain,
			 DNS_SERVER_GROUP_LOCAL);
	return;
}

void _dns_server_mdns_query_setup_server_group(struct dns_request *request, const char **group_name)
{
	if (request->is_mdns_lookup == 0 || group_name == NULL) {
		return;
	}

	*group_name = DNS_SERVER_GROUP_MDNS;
	safe_strncpy(request->dns_group_name, *group_name, sizeof(request->dns_group_name));
	return;
}

int _dns_server_mdns_query_setup(struct dns_request *request, const char *server_group_name, char **request_domain,
								 char *domain_buffer, int domain_buffer_len)
{

	if (dns_conf.mdns_lookup != 1) {
		return 0;
	}

	switch (request->qtype) {
	case DNS_T_A:
	case DNS_T_AAAA:
	case DNS_T_SRV:
		if (request->domain[0] != '\0' && strstr(request->domain, ".") == NULL) {
			snprintf(domain_buffer, domain_buffer_len, "%s.%s", request->domain, DNS_SERVER_GROUP_LOCAL);
			*request_domain = domain_buffer;
			_dns_server_set_request_mdns(request);
		}

		if (server_group_name != NULL && strncmp(server_group_name, DNS_SERVER_GROUP_MDNS, DNS_GROUP_NAME_LEN) == 0) {
			_dns_server_set_request_mdns(request);
		}
		break;
	default:
		break;
	}

	return 0;
}