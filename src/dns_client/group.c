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

#include "group.h"
#include "pending_server.h"
#include "server_info.h"

#include "smartdns/util.h"

/* get server group by name */
struct dns_server_group *_dns_client_get_group(const char *group_name)
{
	uint32_t key = 0;
	struct dns_server_group *group = NULL;
	struct hlist_node *tmp = NULL;

	if (group_name == NULL) {
		return NULL;
	}

	key = hash_string(group_name);
	hash_for_each_possible_safe(client.group, group, tmp, node, key)
	{
		if (strncmp(group->group_name, group_name, DNS_GROUP_NAME_LEN) != 0) {
			continue;
		}

		return group;
	}

	return NULL;
}

/* get server group by name */
struct dns_server_group *_dns_client_get_dnsserver_group(const char *group_name)
{
	struct dns_server_group *group = _dns_client_get_group(group_name);

	if (group == NULL) {
		goto use_default;
	} else {
		if (list_empty(&group->head)) {
			tlog(TLOG_DEBUG, "group %s not exist, use default group.", group_name);
			goto use_default;
		}
	}

	return group;

use_default:
	return client.default_group;
}

/* add server to group */
int _dns_client_add_to_group(const char *group_name, struct dns_server_info *server_info)
{
	struct dns_server_group *group = NULL;
	struct dns_server_group_member *group_member = NULL;

	group = _dns_client_get_group(group_name);
	if (group == NULL) {
		tlog(TLOG_ERROR, "group %s not exist.", group_name);
		return -1;
	}

	group_member = malloc(sizeof(*group_member));
	if (group_member == NULL) {
		tlog(TLOG_ERROR, "malloc memory failed.");
		goto errout;
	}

	memset(group_member, 0, sizeof(*group_member));
	group_member->server = server_info;
	dns_client_server_info_get(server_info);
	list_add(&group_member->list, &group->head);

	return 0;
errout:
	if (group_member) {
		free(group_member);
	}

	return -1;
}

int dns_client_add_to_group(const char *group_name, const char *server_ip, int port, dns_server_type_t server_type,
							struct client_dns_server_flags *flags)
{
	return _dns_client_add_to_group_pending(group_name, server_ip, port, server_type, flags, 1);
}

/* free group member */
static int _dns_client_remove_member(struct dns_server_group_member *group_member)
{
	if (group_member == NULL) {
		return -1;
	}

	if (group_member->server) {
		dns_client_server_info_release(group_member->server);
	}

	list_del_init(&group_member->list);
	free(group_member);

	return 0;
}

static int _dns_client_remove_from_group(struct dns_server_group *group, struct dns_server_info *server_info)
{
	struct dns_server_group_member *group_member = NULL;
	struct dns_server_group_member *tmp = NULL;

	list_for_each_entry_safe(group_member, tmp, &group->head, list)
	{
		if (group_member->server != server_info) {
			continue;
		}

		_dns_client_remove_member(group_member);
	}

	return 0;
}

int _dns_client_remove_server_from_groups(struct dns_server_info *server_info)
{
	struct dns_server_group *group = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(client.group, i, tmp, group, node)
	{
		_dns_client_remove_from_group(group, server_info);
	}

	return 0;
}

int dns_client_remove_from_group(const char *group_name, const char *server_ip, int port, dns_server_type_t server_type,
								 struct client_dns_server_flags *flags)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group *group = NULL;

	server_info = _dns_client_get_server(server_ip, port, server_type, flags);
	if (server_info == NULL) {
		return -1;
	}

	group = _dns_client_get_group(group_name);
	if (group == NULL) {
		return -1;
	}

	return _dns_client_remove_from_group(group, server_info);
}

int dns_client_add_group(const char *group_name)
{
	uint32_t key = 0;
	struct dns_server_group *group = NULL;

	if (group_name == NULL) {
		return -1;
	}

	if (_dns_client_get_group(group_name) != NULL) {
		return 0;
	}

	group = malloc(sizeof(*group));
	if (group == NULL) {
		goto errout;
	}

	memset(group, 0, sizeof(*group));
	INIT_LIST_HEAD(&group->head);
	safe_strncpy(group->group_name, group_name, DNS_GROUP_NAME_LEN);
	key = hash_string(group_name);
	hash_add(client.group, &group->node, key);

	return 0;
errout:
	if (group) {
		free(group);
		group = NULL;
	}

	return -1;
}

static int _dns_client_remove_group(struct dns_server_group *group)
{
	struct dns_server_group_member *group_member = NULL;
	struct dns_server_group_member *tmp = NULL;

	if (group == NULL) {
		return 0;
	}

	list_for_each_entry_safe(group_member, tmp, &group->head, list)
	{
		_dns_client_remove_member(group_member);
	}

	hash_del(&group->node);
	free(group);

	return 0;
}

int dns_client_remove_group(const char *group_name)
{
	uint32_t key = 0;
	struct dns_server_group *group = NULL;
	struct hlist_node *tmp = NULL;

	if (group_name == NULL) {
		return -1;
	}

	key = hash_string(group_name);
	hash_for_each_possible_safe(client.group, group, tmp, node, key)
	{
		if (strncmp(group->group_name, group_name, DNS_GROUP_NAME_LEN) != 0) {
			continue;
		}

		_dns_client_remove_group(group);

		return 0;
	}

	return 0;
}

void _dns_client_group_remove_all(void)
{
	struct dns_server_group *group = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(client.group, i, tmp, group, node)
	{
		_dns_client_remove_group(group);
	}
}