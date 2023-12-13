/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef _GENERIC_CONF_H
#define _GENERIC_CONF_H

#include <unistd.h>

#define MAX_LINE_LEN 8192
#define MAX_KEY_LEN 64
#define CONF_INT_MAX (~(1 << 31))
#define CONF_INT_MIN (1 << 31)

#define CONF_RET_OK 0
#define CONF_RET_ERR -1
#define CONF_RET_WARN -2
#define CONF_RET_NOENT -3
#define CONF_RET_BADCONF -4

struct config_item {
	const char *item;
	int (*item_func)(const char *item, void *data, int argc, char *argv[]);
	void *data;
};

struct config_item_custom {
	void *custom_data;
	int (*custom_func)(void *data, int argc, char *argv[]);
};

struct config_item_int {
	int *data;
	int min;
	int max;
};

struct config_item_int_base {
	int *data;
	int min;
	int max;
	int base;
};

struct config_item_string {
	char *data;
	size_t size;
};

struct config_item_yesno {
	int *data;
};

struct config_item_size {
	size_t *data;
	size_t min;
	size_t max;
};

struct config_item_ssize {
	ssize_t *data;
	ssize_t min;
	ssize_t max;
};

struct config_enum_list {
	char *name;
	int id;
};

struct config_enum {
	int *data;
	struct config_enum_list *list;
};

#define CONF_INT(key, value, min_value, max_value)                                                                     \
	{                                                                                                                  \
		key, conf_int, &(struct config_item_int)                                                                       \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value                                                          \
		}                                                                                                              \
	}
#define CONF_INT_BASE(key, value, min_value, max_value, base_value)                                                    \
	{                                                                                                                  \
		key, conf_int_base, &(struct config_item_int_base)                                                             \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value, .base = base_value                                      \
		}                                                                                                              \
	}
#define CONF_STRING(key, value, len_value)                                                                             \
	{                                                                                                                  \
		key, conf_string, &(struct config_item_string)                                                                 \
		{                                                                                                              \
			.data = value, .size = len_value                                                                           \
		}                                                                                                              \
	}
#define CONF_YESNO(key, value)                                                                                         \
	{                                                                                                                  \
		key, conf_yesno, &(struct config_item_yesno)                                                                   \
		{                                                                                                              \
			.data = value                                                                                              \
		}                                                                                                              \
	}
#define CONF_SIZE(key, value, min_value, max_value)                                                                    \
	{                                                                                                                  \
		key, conf_size, &(struct config_item_size)                                                                     \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value                                                          \
		}                                                                                                              \
	}
#define CONF_SSIZE(key, value, min_value, max_value)                                                                   \
	{                                                                                                                  \
		key, conf_ssize, &(struct config_item_ssize)                                                                   \
		{                                                                                                              \
			.data = value, .min = min_value, .max = max_value                                                          \
		}                                                                                                              \
	}

#define CONF_ENUM(key, value, enum)                                                                                    \
	{                                                                                                                  \
		key, conf_enum, &(struct config_enum)                                                                          \
		{                                                                                                              \
			.data = (int *)value, .list = (struct config_enum_list *)enum                                              \
		}                                                                                                              \
	}

/*
 * func: int (*func)(void *data, int argc, char *argv[]);
 */
#define CONF_CUSTOM(key, func, data)                                                                                   \
	{                                                                                                                  \
		key, conf_custom, &(struct config_item_custom)                                                                 \
		{                                                                                                              \
			.custom_data = data, .custom_func = func                                                                   \
		}                                                                                                              \
	}

#define CONF_END()                                                                                                     \
	{                                                                                                                  \
		NULL, NULL, NULL                                                                                               \
	}

extern int conf_custom(const char *item, void *data, int argc, char *argv[]);

extern int conf_int(const char *item, void *data, int argc, char *argv[]);

extern int conf_int_base(const char *item, void *data, int argc, char *argv[]);

extern int conf_string(const char *item, void *data, int argc, char *argv[]);

extern int conf_yesno(const char *item, void *data, int argc, char *argv[]);

extern int conf_size(const char *item, void *data, int argc, char *argv[]);

extern int conf_ssize(const char *item, void *data, int argc, char *argv[]);

extern int conf_enum(const char *item, void *data, int argc, char *argv[]);

/*
 * Example:
 *  int num = 0;
 *
 *  struct config_item items [] = {
 *       CONF_INT("CONF_NUM", &num, -1, 10),
 *       CONF_END();
 *  }
 *
 *  load_conf(file, items);
 *
 */

typedef int(conf_error_handler)(const char *file, int lineno, int ret);

int load_conf(const char *file, struct config_item items[], conf_error_handler handler);

void load_exit(void);

int conf_get_current_lineno(void);

const char *conf_get_conf_file(void);

const char *conf_get_conf_fullpath(const char *path, char *fullpath, size_t path_len);

#endif // !_GENERIC_CONF_H
