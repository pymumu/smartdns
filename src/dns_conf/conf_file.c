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

#define _GNU_SOURCE

#include "conf_file.h"
#include "dns_conf_group.h"
#include "set_file.h"
#include "smartdns/lib/conf.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/util.h"
#include "smartdns/lib/stringutil.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>

struct conf_file_path {
	struct hlist_node node;
	char file[DNS_MAX_PATH];
};

struct hash_table conf_file_table;

int conf_file_table_init(void)
{
	hash_table_init(conf_file_table, 8);

	return 0;
}

static int conf_file_check_duplicate(const char *conf_file)
{
	struct conf_file_path *file = NULL;
	uint32_t key = 0;

	key = hash_string(conf_file);
	hash_table_for_each_possible(conf_file_table, file, node, key)
	{
		if (strncmp(file->file, conf_file, DNS_MAX_PATH) != 0) {
			continue;
		}

		return 0;
	}

	file = zalloc(1, sizeof(*file));
	if (file == NULL) {
		return -1;
	}

	safe_strncpy(file->file, conf_file, DNS_MAX_PATH);
	hash_table_add(conf_file_table, &file->node, key);
	return -1;
}

static int conf_additional_file(const char *conf_file)
{
	char file_path[PATH_MAX];
	char file_path_dir[PATH_MAX];

	if (conf_file == NULL) {
		return -1;
	}

	if (conf_file[0] != '/') {
		safe_strncpy(file_path_dir, conf_get_conf_file(), DNS_MAX_PATH);
		dir_name(file_path_dir);
		if (strncmp(file_path_dir, conf_get_conf_file(), sizeof(file_path_dir)) == 0) {
			if (snprintf(file_path, DNS_MAX_PATH, "%s", conf_file) < 0) {
				return -1;
			}
		} else {
			if (snprintf(file_path, DNS_MAX_PATH, "%s/%s", file_path_dir, conf_file) < 0) {
				return -1;
			}
		}
	} else {
		safe_strncpy(file_path, conf_file, DNS_MAX_PATH);
	}

	if (access(file_path, R_OK) != 0) {
		tlog(TLOG_ERROR, "config file '%s' is not readable, %s", conf_file, strerror(errno));
		return -1;
	}

	if (conf_file_check_duplicate(file_path) == 0) {
		return 0;
	}

	return load_conf(file_path, smartdns_config_item(), _conf_printf);
}

static int _config_additional_file_callback(const char *file, void *priv)
{
	return conf_additional_file(file);
}

int config_additional_file(void *data, int argc, char *argv[])
{
	const char *conf_pattern = NULL;
	int opt = 0;
	const char *group_name = NULL;
	int ret = 0;
	struct dns_conf_group_info *last_group_info;

	if (argc < 1) {
		return -1;
	}

	conf_pattern = argv[1];
	if (conf_pattern == NULL) {
		return -1;
	}

	/* clang-format off */
	static struct option long_options[] = {
		{"group", required_argument, NULL, 'g'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	/* process extra options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "g:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'g': {
			group_name = optarg;
			break;
		}
		default:
			break;
		}
	}

	last_group_info = _config_current_group();
	if (group_name != NULL) {
		ret = _config_current_group_push(group_name, NULL);
		if (ret != 0) {
			tlog(TLOG_ERROR, "begin group '%s' failed.", group_name);
			return -1;
		}
	}

	ret = _config_foreach_file(conf_pattern, _config_additional_file_callback, NULL);
	if (group_name != NULL) {
		_config_current_group_pop_to(last_group_info);
	}

	return ret;
}

void _config_file_hash_table_destroy(void)
{
	struct conf_file_path *file = NULL;
	struct hlist_node *tmp = NULL;
	int i = 0;

	hash_table_for_each_safe(conf_file_table, i, tmp, file, node)
	{
		hlist_del_init(&file->node);
		free(file);
	}

	hash_table_free(conf_file_table, free);
}
