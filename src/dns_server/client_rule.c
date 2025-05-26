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

#include "client_rule.h"
#include "request.h"

int _dns_server_request_set_client_rules(struct dns_request *request, struct dns_client_rules *client_rule)
{
	if (client_rule == NULL) {
		if (_dns_server_has_bind_flag(request, BIND_FLAG_ACL) == 0 || dns_conf.acl_enable) {
			request->send_tick = get_tick_count();
			request->rcode = DNS_RC_REFUSED;
			request->no_cache = 1;
			return -1;
		}
		return 0;
	}

	tlog(TLOG_DEBUG, "match client rule.");

	if (client_rule->rules[CLIENT_RULE_GROUP]) {
		struct client_rule_group *group = (struct client_rule_group *)client_rule->rules[CLIENT_RULE_GROUP];
		if (group && group->group_name[0] != '\0') {
			safe_strncpy(request->dns_group_name, group->group_name, sizeof(request->dns_group_name));
		}
	}

	if (client_rule->rules[CLIENT_RULE_FLAGS]) {
		struct client_rule_flags *flags = (struct client_rule_flags *)client_rule->rules[CLIENT_RULE_FLAGS];
		if (flags) {
			request->server_flags = flags->flags;
		}
	}

	return 0;
}
