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

#ifndef _DNS_CONF_SERVER_GROUP_H_
#define _DNS_CONF_SERVER_GROUP_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_conf_get_group_set(const char *group_name, struct dns_servers *server);

struct dns_server_groups *_dns_conf_get_group(const char *group_name);

const char *_dns_conf_get_group_name(const char *group_name);

struct dns_conf_group *_config_rule_group_get(const char *group_name);

struct dns_conf_group *dns_server_get_rule_group(const char *group_name);

struct dns_conf_group *dns_server_get_default_rule_group(void);

struct dns_conf_group *_config_rule_group_new(const char *group_name);

void _config_group_table_init(void);

void _config_group_table_destroy(void);

void _config_rule_group_destroy(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
