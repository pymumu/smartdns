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

#include "domain_set.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <errno.h>
#include <getopt.h>
#include <string.h>

struct dns_domain_set_name_table dns_domain_set_name_table;

int _config_domain_set(void *data, int argc, char *argv[])
{
	int opt = 0;
	uint32_t key = 0;
	struct dns_domain_set_name *domain_set = NULL;
	struct dns_domain_set_name_list *domain_set_name_list = NULL;
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

	domain_set = zalloc(1, sizeof(*domain_set));
	if (domain_set == NULL) {
		tlog(TLOG_ERROR, "cannot malloc memory.");
		goto errout;
	}
	INIT_LIST_HEAD(&domain_set->list);

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
				domain_set->type = DNS_DOMAIN_SET_LIST;
			} else if (strncmp(type, "geosite", 7) == 0) {
				domain_set->type = DNS_DOMAIN_SET_GEOSITE;
			} else {
				tlog(TLOG_ERROR, "invalid domain set type.");
				goto errout;
			}
			break;
		}
		case 'f':
			conf_get_conf_fullpath(optarg, domain_set->file, DNS_MAX_PATH);
			break;
		default:
			break;
		}
	}
	/* clang-format on */

	if (set_name[0] == 0 || domain_set->file[0] == 0) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	if (access(domain_set->file, F_OK) != 0) {
		tlog(TLOG_ERROR, "domain set file %s not readable. %s", domain_set->file, strerror(errno));
		goto errout;
	}

	key = hash_string(set_name);
	hash_for_each_possible(dns_domain_set_name_table.names, domain_set_name_list, node, key)
	{
		if (strcmp(domain_set_name_list->name, set_name) == 0) {
			break;
		}
	}

	if (domain_set_name_list == NULL) {
		domain_set_name_list = zalloc(1, sizeof(*domain_set_name_list));
		if (domain_set_name_list == NULL) {
			tlog(TLOG_ERROR, "cannot malloc memory.");
			goto errout;
		}
		INIT_LIST_HEAD(&domain_set_name_list->set_name_list);
		safe_strncpy(domain_set_name_list->name, set_name, DNS_MAX_CNAME_LEN);
		hash_add(dns_domain_set_name_table.names, &domain_set_name_list->node, key);
	}

	list_add_tail(&domain_set->list, &domain_set_name_list->set_name_list);
	return 0;

errout:
	if (domain_set) {
		free(domain_set);
	}
	return -1;
}

void _config_domain_set_name_table_init(void)
{
	hash_init(dns_domain_set_name_table.names);
}

void _config_domain_set_name_table_destroy(void)
{
	struct dns_domain_set_name_list *set_name_list = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_domain_set_name *set_name = NULL;
	struct dns_domain_set_name *tmp1 = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_domain_set_name_table.names, i, tmp, set_name_list, node)
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