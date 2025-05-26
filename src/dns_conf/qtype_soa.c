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

#include "qtype_soa.h"
#include "dns_conf_group.h"
#include "smartdns/lib/stringutil.h"

static int _conf_qtype_soa(uint8_t *soa_table, int argc, char *argv[])
{
	int i = 0;
	int j = 0;
	int is_clear = 0;

	if (argc <= 1) {
		return -1;
	}

	if (argc >= 2) {
		if (strncmp(argv[1], "-", sizeof("-")) == 0) {
			if (argc == 2) {
				memset(soa_table, 0, MAX_QTYPE_NUM / 8 + 1);
				return 0;
			}

			is_clear = 1;
		}

		if (strncmp(argv[1], "-,", sizeof(",")) == 0) {
			is_clear = 1;
		}
	}

	for (i = 1; i < argc; i++) {
		char sub_arg[1024];
		safe_strncpy(sub_arg, argv[i], sizeof(sub_arg));
		for (char *tok = strtok(sub_arg, ","); tok; tok = strtok(NULL, ",")) {
			char *dash = strstr(tok, "-");
			if (dash != NULL) {
				*dash = '\0';
			}

			if (*tok == '\0') {
				continue;
			}

			long start = atol(tok);
			long end = start;

			if (start > MAX_QTYPE_NUM || start < 0) {
				tlog(TLOG_ERROR, "invalid qtype %ld", start);
				continue;
			}

			if (dash != NULL && *(dash + 1) != '\0') {
				end = atol(dash + 1);
				if (end > MAX_QTYPE_NUM) {
					end = MAX_QTYPE_NUM;
				}
			}

			for (j = start; j <= end; j++) {
				int offset = j / 8;
				int bit = j % 8;
				if (is_clear) {
					soa_table[offset] &= ~(1 << bit);
				} else {
					soa_table[offset] |= (1 << bit);
				}
			}
		}
	}

	return 0;
}

int _config_qtype_soa(void *data, int argc, char *argv[])
{
	return _conf_qtype_soa(_config_current_rule_group()->soa_table, argc, argv);
}