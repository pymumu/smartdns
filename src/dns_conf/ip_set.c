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

#include "ip_set.h"
#include "smartdns/lib/stringutil.h"

#include <errno.h>
#include <getopt.h>
#include <string.h>

struct dns_ip_set_name_table dns_ip_set_name_table;

int _config_ip_set(void *data, int argc, char *argv[])
{
	int opt = 0;
	uint32_t key = 0;
	struct dns_ip_set_name *ip_set = NULL;
	struct dns_ip_set_name_list *ip_set_name_list = NULL;
	char set_name[DNS_MAX_CNAME_LEN] = {0};

	/* clang-format off */
	static struct option long_options[] = {
		{"name", required_argument, NULL, 'n'},
		{"type", required_argument, NULL, 't'},
		{"file", required_argument, NULL, 'f'},
		{NULL, 0, NULL, 0}
	};

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	ip_set = malloc(sizeof(*ip_set));
	if (ip_set == NULL) {
		tlog(TLOG_ERROR, "cannot malloc memory.");
		goto errout;
	}
	memset(ip_set, 0, sizeof(*ip_set));
	INIT_LIST_HEAD(&ip_set->list);

	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:t:f:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n':
			safe_strncpy(set_name, optarg, DNS_MAX_CNAME_LEN);
			break;
		case 't': {
			const char *type = optarg;
			if (strncmp(type, "list", 5) == 0) {
				ip_set->type = DNS_IP_SET_LIST;
			} else {
				tlog(TLOG_ERROR, "invalid domain set type.");
				goto errout;
			}
			break;
		}
		case 'f':
			conf_get_conf_fullpath(optarg, ip_set->file, DNS_MAX_PATH);
			break;
		default:
			break;
		}
	}
	/* clang-format on */

	if (access(ip_set->file, F_OK) != 0) {
		tlog(TLOG_ERROR, "ip set file %s not readable. %s", ip_set->file, strerror(errno));
		goto errout;
	}

	if (set_name[0] == 0 || ip_set->file[0] == 0) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	key = hash_string(set_name);
	hash_for_each_possible(dns_ip_set_name_table.names, ip_set_name_list, node, key)
	{
		if (strcmp(ip_set_name_list->name, set_name) == 0) {
			break;
		}
	}

	if (ip_set_name_list == NULL) {
		ip_set_name_list = malloc(sizeof(*ip_set_name_list));
		if (ip_set_name_list == NULL) {
			tlog(TLOG_ERROR, "cannot malloc memory.");
			goto errout;
		}
		memset(ip_set_name_list, 0, sizeof(*ip_set_name_list));
		INIT_LIST_HEAD(&ip_set_name_list->set_name_list);
		safe_strncpy(ip_set_name_list->name, set_name, DNS_MAX_CNAME_LEN);
		hash_add(dns_ip_set_name_table.names, &ip_set_name_list->node, key);
	}

	list_add_tail(&ip_set->list, &ip_set_name_list->set_name_list);
	return 0;

errout:
	if (ip_set) {
		free(ip_set);
	}

	if (ip_set_name_list != NULL) {
		free(ip_set_name_list);
	}
	return -1;
}

void _config_ip_set_name_table_init(void)
{
	hash_init(dns_ip_set_name_table.names);
}

void _config_ip_set_name_table_destroy(void)
{
	struct dns_ip_set_name_list *set_name_list = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_ip_set_name *set_name = NULL;
	struct dns_ip_set_name *tmp1 = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ip_set_name_table.names, i, tmp, set_name_list, node)
	{
		hlist_del_init(&set_name_list->node);
		list_for_each_entry_safe(set_name, tmp1, &set_name_list->set_name_list, list)
		{
			list_del(&set_name->list);
			free(set_name);
		}

		free(set_name_list);
	}
}