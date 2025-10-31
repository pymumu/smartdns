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

#ifndef _DNS_CONF_CONF_GROUP_H_
#define _DNS_CONF_CONF_GROUP_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

struct dns_conf_group_info {
	struct list_head list;
	const char *group_name;
	const char *inherit_group;
	struct dns_conf_group *rule;
};

extern struct dns_conf_rule dns_conf_rule;

#define group_member(m) ((void *)offsetof(struct dns_conf_group, m))
int _dns_conf_group_int(int value, int *data);
int _dns_conf_group_int_base(int value, int *data);
int _dns_conf_group_string(const char *value, char *data);
int _dns_conf_group_yesno(int value, int *data);
int _dns_conf_group_size(size_t value, size_t *data);
int _dns_conf_group_ssize(ssize_t value, ssize_t *data);
int _dns_conf_group_enum(int value, int *data);

int _config_rule_group_init(void);
void _config_rule_group_destroy(void);

struct dns_conf_group *_config_rule_group_new(const char *group_name);

struct dns_conf_group *_config_current_rule_group(void);
struct dns_conf_group_info *_config_current_group(void);
struct dns_conf_group_info *_config_default_group(void);
void _config_set_current_group(struct dns_conf_group_info *group_info);

void _config_current_group_pop(void);
int _config_current_group_push(const char *group_name, const char *inherit_group_name);
int _config_current_group_push_default(void);
int _config_current_group_pop_to_default(void);
int _config_current_group_pop_to(struct dns_conf_group_info *group_info);
int _config_current_group_pop_all(void);

void _dns_conf_group_post(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
