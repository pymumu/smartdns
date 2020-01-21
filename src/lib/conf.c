/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "conf.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *currrent_conf_file = NULL;

const char *conf_get_conf_file(void)
{
	return currrent_conf_file;
}

int conf_custom(const char *item, void *data, int argc, char *argv[])
{
	struct config_item_custom *item_custom = data;
	return item_custom->custom_func(item_custom->custom_data, argc, argv);
}

int conf_int(const char *item, void *data, int argc, char *argv[])
{
	struct config_item_int *item_int = data;
	int value = 0;
	if (argc < 2) {
		return -1;
	}

	value = atoi(argv[1]);

	if (value < item_int->min) {
		value = item_int->min;
	} else if (value > item_int->max) {
		value = item_int->max;
	}

	*(item_int->data) = value;

	return 0;
}

int conf_string(const char *item, void *data, int argc, char *argv[])
{
	struct config_item_string *item_string = data;

	if (argc < 2) {
		return -1;
	}

	strncpy(item_string->data, argv[1], item_string->size);

	return 0;
}

int conf_yesno(const char *item, void *data, int argc, char *argv[])
{
	struct config_item_yesno *item_yesno = data;
	int yes = 0;

	if (argc < 2) {
		return -1;
	}

	char *value = argv[1];
	if (strncmp("auto", value, sizeof("auto")) == 0 || strncmp("AUTO", value, sizeof("AUTO")) == 0) {
		return 0;
	}

	if (strncmp("yes", value, sizeof("yes")) == 0 || strncmp("YES", value, sizeof("YES")) == 0) {
		yes = 1;
	} else if (strncmp("no", value, sizeof("no")) == 0 || strncmp("NO", value, sizeof("NO")) == 0) {
		yes = 0;
	}

	*(item_yesno->data) = yes;

	return 0;
}

int conf_size(const char *item, void *data, int argc, char *argv[])
{
	/* read dns cache size */
	int base = 1;
	size_t size = 0;
	int num = 0;
	struct config_item_size *item_size = data;
	char *value = argv[1];

	if (strstr(value, "k") || strstr(value, "K")) {
		base = 1024;
	} else if (strstr(value, "m") || strstr(value, "M")) {
		base = 1024 * 1024;
	} else if (strstr(value, "g") || strstr(value, "G")) {
		base = 1024 * 1024 * 1024;
	}

	num = atoi(value);
	if (num < 0) {
		return -1;
	}

	size = num * base;
	if (size > item_size->max) {
		size = item_size->max;
	} else if (size < item_size->min) {
		size = item_size->min;
	}

	*(item_size->data) = size;

	return 0;
}

void conf_getopt_reset(void)
{
	static struct option long_options[] = {{"-", 0, 0, 0}, {0, 0, 0, 0}};
	int argc = 2;
	char *argv[3] = {"reset", "", 0};

	optind = 0;
	opterr = 0;
	optopt = 0;
	getopt_long(argc, argv, "", long_options, NULL);
	optind = 0;
	opterr = 0;
	optopt = 0;
}

int conf_parse_args(char *key, char *value, int *argc, char **argv)
{
	char *start = NULL;
	char *ptr = value;
	int count = 0;
	int sep_flag = ' ';

	argv[0] = key;
	count++;

	while (*ptr != '\0') {
		if (*ptr == '\\') {
			char *tmp = ptr + 1;
			while (*tmp != '\0') {
				*(tmp - 1) = *tmp;
				tmp++;
			}
			ptr++;
			continue;
		}

		if (*ptr == '"' && start == NULL) {
			sep_flag = '"';
			start = NULL;
		}

		if (*ptr != sep_flag && start == NULL) {
			start = ptr;
			ptr++;
			continue;
		}

		if (*ptr == sep_flag && start == NULL) {
			ptr++;
			continue;
		}

		if (*ptr == sep_flag && start) {
			argv[count] = start;
			*ptr = '\0';
			ptr++;
			count++;
			sep_flag = ' ';
			start = NULL;
			continue;
		}

		ptr++;
	}

	if (start != ptr && start) {
		argv[count] = start;
		count++;
	}

	*argc = count;
	argv[count] = 0;

	return 0;
}

void load_exit(void)
{
	return;
}

int load_conf_printf(const char *file, int lineno, int ret)
{
	if (ret != CONF_RET_OK) {
		printf("process config file '%s' failed at line %d.", file, lineno);
		if (ret == CONF_RET_ERR || ret == CONF_RET_NOENT) {
			return -1;
		}

		return 0;
	}

	return 0;
}

int load_conf_file(const char *file, struct config_item *items, conf_error_handler handler)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char key[MAX_KEY_LEN];
	char value[MAX_LINE_LEN];
	int filed_num = 0;
	int i;
	int argc;
	char *argv[1024];
	int ret = 0;
	int call_ret = 0;
	int line_no = 0;

	if (handler == NULL) {
		handler = load_conf_printf;
	}

	fp = fopen(file, "r");
	if (fp == NULL) {
		return -1;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_no++;
		filed_num = sscanf(line, "%63s %1023[^\r\n]s", key, value);
		if (filed_num <= 0) {
			continue;
		}

		/* comment, skip */
		if (key[0] == '#') {
			continue;
		}

		/* if field format is not key = value, error */
		if (filed_num != 2) {
			goto errout;
		}

		for (i = 0;; i++) {
			if (items[i].item == NULL) {
				handler(file, line_no, CONF_RET_NOENT);
				break;
			}

			if (strncmp(items[i].item, key, MAX_KEY_LEN) != 0) {
				continue;
			}

			if (conf_parse_args(key, value, &argc, argv) != 0) {
				continue;
			}

			conf_getopt_reset();
			/* call item function */
			currrent_conf_file = file;
			call_ret = items[i].item_func(items[i].item, items[i].data, argc, argv);
			ret = handler(file, line_no, call_ret);
			if (ret != 0) {
				conf_getopt_reset();
				goto errout;
			}

			conf_getopt_reset();

			break;
		}
	}

	fclose(fp);

	return 0;
errout:
	if (fp) {
		fclose(fp);
	}
	return -1;
}

int load_conf(const char *file, struct config_item items[], conf_error_handler handler)
{
	return load_conf_file(file, items, handler);
}
