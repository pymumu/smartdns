/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *current_conf_file = NULL;
static int current_conf_lineno = 0;

const char *conf_get_conf_file(void)
{
	return current_conf_file;
}

int conf_get_current_lineno(void)
{
	return current_conf_lineno;
}

static char *get_dir_name(char *path)
{
	if (strstr(path, "/") == NULL) {
		strncpy(path, "./", PATH_MAX);
		return path;
	}

	return dirname(path);
}

const char *conf_get_conf_fullpath(const char *path, char *fullpath, size_t path_len)
{
	char file_path_dir[PATH_MAX];

	if (path_len < 1) {
		return NULL;
	}

	if (path[0] == '/') {
		strncpy(fullpath, path, path_len);
		return fullpath;
	}

	strncpy(file_path_dir, conf_get_conf_file(), PATH_MAX - 1);
	file_path_dir[PATH_MAX - 1] = 0;
	get_dir_name(file_path_dir);
	if (file_path_dir[0] == '\0') {
		strncpy(fullpath, path, path_len);
		return fullpath;
	}

	if (snprintf(fullpath, PATH_MAX, "%s/%s", file_path_dir, path) < 0) {
		return NULL;
	}

	return fullpath;
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

	if (item_int->func) {
		return item_int->func(value, item_int->data);
	}

	*(item_int->data) = value;

	return 0;
}

int conf_int_base(const char *item, void *data, int argc, char *argv[])
{
	struct config_item_int_base *item_int = data;
	int value = 0;
	if (argc < 2) {
		return -1;
	}

	value = strtol(argv[1], NULL, item_int->base);

	if (value < item_int->min) {
		value = item_int->min;
	} else if (value > item_int->max) {
		value = item_int->max;
	}

	if (item_int->func) {
		return item_int->func(value, item_int->data);
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

	if (item_string->func) {
		return item_string->func(argv[1], item_string->data);
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

	if (item_yesno->func) {
		return item_yesno->func(yes, item_yesno->data);
	}

	*(item_yesno->data) = yes;

	return 0;
}

int conf_size(const char *item, void *data, int argc, char *argv[])
{
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

	if (item_size->func) {
		return item_size->func(size, item_size->data);
	}

	*(item_size->data) = size;

	return 0;
}

int conf_ssize(const char *item, void *data, int argc, char *argv[])
{
	int base = 1;
	ssize_t size = 0;
	int num = 0;
	struct config_item_ssize *item_size = data;
	char *value = argv[1];

	if (strstr(value, "k") || strstr(value, "K")) {
		base = 1024;
	} else if (strstr(value, "m") || strstr(value, "M")) {
		base = 1024 * 1024;
	} else if (strstr(value, "g") || strstr(value, "G")) {
		base = 1024 * 1024 * 1024;
	}

	num = atoi(value);
	size = num * base;
	if (size > item_size->max) {
		size = item_size->max;
	} else if (size < item_size->min) {
		size = item_size->min;
	}

	if (item_size->func) {
		return item_size->func(size, item_size->data);
	}

	*(item_size->data) = size;

	return 0;
}

int conf_enum(const char *item, void *data, int argc, char *argv[])
{
	struct config_enum *item_enum = data;
	char *enum_name = argv[1];
	int i = 0;

	if (argc <= 0) {
		return -1;
	}

	for (i = 0; item_enum->list[i].name != NULL; i++) {
		if (strcmp(enum_name, item_enum->list[i].name) == 0) {
			if (item_enum->func) {
				return item_enum->func(item_enum->list[i].id, item_enum->data);
			}
			*(item_enum->data) = item_enum->list[i].id;
			return 0;
		}
	}

	printf("Not found config value '%s', valid value is:\n", enum_name);
	for (i = 0; item_enum->list[i].name != NULL; i++) {
		printf(" %s\n", item_enum->list[i].name);
	}

	return -1;
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

int conf_parse_key_values(char *line, int *key_num, char **keys, char **values)
{
	int count = 0;
	char *ptr = line;
	char *key = NULL;
	char *value = NULL;
	char *field_start = NULL;
	int filed_stage = 0;
	int inquote = 0;
	int end = 0;

	if (line == NULL || key_num == NULL || keys == NULL || values == NULL) {
		return -1;
	}

	while (1) {
		if (*ptr == '\'' || *ptr == '"') {
			if (inquote == 0) {
				inquote = *ptr;
				ptr++;
				continue;
			} else if (inquote == *ptr) {
				inquote = 0;
				*ptr = '\0';
			}
		}

		if (field_start == NULL) {
			field_start = ptr;
		}

		if (inquote != 0) {
			ptr++;
			continue;
		}

		if (*ptr == ',' || *ptr == '=' || *ptr == '\0') {
			if (filed_stage == 0) {
				key = field_start;
				if (*key == '\0' || *key == ',') {
					field_start = NULL;
					if (end == 1) {
						break;
					}
					ptr++;
					continue;
				}
				value = ptr;
				filed_stage = 1;
				keys[count] = key;
				values[count] = value;
				if (*ptr == '\0' || *ptr == ',') {
					count++;
					key = NULL;
					value = NULL;
					filed_stage = 0;
				}
				*ptr = '\0';
			} else if (filed_stage == 1) {
				value = field_start;
				if (*ptr == '=') {
					goto errout;
				}
				filed_stage = 0;
				keys[count] = key;
				values[count] = value;
				count++;
				*ptr = '\0';
				key = NULL;
				value = NULL;
			}

			field_start = NULL;
		}

		if (end == 1) {
			break;
		}

		ptr++;
		if (*ptr == '\0') {
			end = 1;
		}
	}

	*key_num = count;

	return 0;
errout:
	return -1;
}

static int conf_parse_args(char *key, char *value, int *argc, char **argv)
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
			*(tmp - 1) = '\0';
			ptr++;
			continue;
		}

		if ((*ptr == '"' || *ptr == '\'') && start == NULL) {
			sep_flag = *ptr;
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

void load_exit(void) {}

static int load_conf_printf(const char *file, int lineno, int ret)
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

static int load_conf_file(const char *file, struct config_item *items, conf_error_handler handler)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN + MAX_KEY_LEN];
	char key[MAX_KEY_LEN];
	char value[MAX_LINE_LEN];
	int filed_num = 0;
	int i = 0;
	int last_item_index = -1;
	int argc = 0;
	char *argv[1024];
	int ret = 0;
	int call_ret = 0;
	int line_no = 0;
	int line_len = 0;
	int read_len = 0;
	int is_last_line_wrap = 0;
	int current_line_wrap = 0;
	int is_func_found = 0;
	const char *last_file = NULL;

	if (handler == NULL) {
		handler = load_conf_printf;
	}

	fp = fopen(file, "r");
	if (fp == NULL) {
		fprintf(stderr, "open config file '%s' failed, %s\n", file, strerror(errno));
		return -1;
	}

	line_no = 0;
	while (fgets(line + line_len, MAX_LINE_LEN - line_len, fp)) {
		current_line_wrap = 0;
		line_no++;
		read_len = strnlen(line + line_len, sizeof(line));
		if (read_len >= 2 && *(line + line_len + read_len - 2) == '\\') {
			read_len -= 1;
			current_line_wrap = 1;
		}

		/* comment in wrap line, skip */
		if (is_last_line_wrap && read_len > 0) {
			if (*(line + line_len) == '#') {
				continue;
			}
		}

		/* trim prefix spaces in wrap line */
		if ((current_line_wrap == 1 || is_last_line_wrap == 1) && read_len > 0) {
			is_last_line_wrap = current_line_wrap;
			read_len -= 1;
			for (i = 0; i < read_len; i++) {
				char *ptr = line + line_len + i;
				if (*ptr == ' ' || *ptr == '\t') {
					continue;
				}

				memmove(line + line_len, ptr, read_len - i + 1);
				line_len += read_len - i;
				break;
			}

			line[line_len] = '\0';
			if (current_line_wrap) {
				continue;
			}
		}

		line_len = 0;
		is_last_line_wrap = 0;
		key[0] = '\0';
		value[0] = '\0';
		filed_num = sscanf(line, "%63s %8191[^\r\n]s", key, value);
		if (filed_num <= 0) {
			continue;
		}

		/* comment, skip */
		if (key[0] == '#') {
			continue;
		}

		/* if field format is not key = value, error */
		if (filed_num != 2 && filed_num != 1) {
			handler(file, line_no, CONF_RET_BADCONF);
			goto errout;
		}

		is_func_found = 0;

		for (i = last_item_index;; i++) {
			if (i < 0) {
				continue;
			}

			if (items[i].item == NULL) {
				break;
			}

			if (strncmp(items[i].item, key, MAX_KEY_LEN) != 0) {
				if (last_item_index >= 0) {
					i = -1;
					last_item_index = -1;
				}
				continue;
			}

			if (conf_parse_args(key, value, &argc, argv) != 0) {
				continue;
			}

			conf_getopt_reset();
			/* call item function */
			last_file = current_conf_file;
			current_conf_file = file;
			current_conf_lineno = line_no;
			call_ret = items[i].item_func(items[i].item, items[i].data, argc, argv);
			ret = handler(file, line_no, call_ret);
			if (ret != 0) {
				conf_getopt_reset();
				goto errout;
			}

			conf_getopt_reset();
			if (last_file) {
				current_conf_file = last_file;
			}

			last_item_index = i;
			is_func_found = 1;
			break;
		}

		if (is_func_found == 0) {
			handler(file, line_no, CONF_RET_NOENT);
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
