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
#include "client_rule.h"
#include "dns_conf_group.h"
#include "domain_rule.h"
#include "smartdns/lib/stringutil.h"

#include <getopt.h>

int _config_group_begin(void *data, int argc, char *argv[])
{
	int opt = 0;

	const char *group_name = NULL;
	const char *inherit_group_name = NULL;
	if (argc < 2) {
		return -1;
	}

	/* clang-format off */
	static struct option long_options[] = {
		{"inherit", required_argument, NULL, 'h'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	group_name = argv[1];
	if (group_name[0] == '\0') {
		group_name = NULL;
	}

	while (1) {
		opt = getopt_long_only(argc, argv, "n", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'h': {
			inherit_group_name = optarg;
			break;
		}
		default:
			break;
		}
	}

	if (_config_current_group_push(group_name, inherit_group_name) != 0) {
		return -1;
	}

	return 0;
}

int _config_group_end(void *data, int argc, char *argv[])
{
	_config_current_group_pop();
	return 0;
}

int _config_group_match(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	struct dns_conf_group_info *saved_group_info = _config_current_group();
	const char *group_name = saved_group_info->group_name;
	char group_name_buf[DNS_MAX_CONF_CNAME_LEN];

	/* clang-format off */
	static struct option long_options[] = {
		{"domain", required_argument, NULL, 'd'},
		{"client-ip", required_argument, NULL, 'c'},
		{"group", required_argument, NULL, 'g'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1 || group_name == NULL) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	_config_set_current_group(_config_default_group());

	for (int i = 1; i < argc - 1; i++) {
		if (strncmp(argv[i], "-g", sizeof("-g")) == 0 || strncmp(argv[i], "--group", sizeof("--group")) == 0 ||
			strncmp(argv[i], "-group", sizeof("-group")) == 0) {
			safe_strncpy(group_name_buf, argv[i + 1], DNS_MAX_CONF_CNAME_LEN);
			group_name = group_name_buf;
			break;
		}
	}

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
		case 'd': {
			const char *domain = optarg;

			if (_conf_domain_rule_group(domain, group_name) != 0) {
				tlog(TLOG_ERROR, "set group match for domain %s failed.", optarg);
				goto errout;
			}
			break;
		}
		case 'c': {
			char *client_ip = optarg;
			if (_config_client_rule_group_add(client_ip, group_name) != 0) {
				tlog(TLOG_ERROR, "add group rule failed.");
				goto errout;
			}
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown group-match option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}
		optind_last = optind;
	}

	_config_set_current_group(saved_group_info);

	return 0;
errout:
	_config_set_current_group(saved_group_info);
	return -1;
}