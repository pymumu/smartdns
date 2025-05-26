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

#ifndef _DNS_CONF_IP_RULE_H_
#define _DNS_CONF_IP_RULE_H_

#include "dns_conf.h"
#include "set_file.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _config_ip_iter_free(radix_node_t *node, void *cbctx);

int _config_ip_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear);
int _config_ip_rule_set_each(const char *ip_set, set_rule_add_func callback, void *priv);

int _config_blacklist_ip(void *data, int argc, char *argv[]);
int _config_bogus_nxdomain(void *data, int argc, char *argv[]);
int _config_ip_ignore(void *data, int argc, char *argv[]);
int _config_whitelist_ip(void *data, int argc, char *argv[]);
int _config_ip_rules(void *data, int argc, char *argv[]);

int _config_ip_rule_alias_add_ip(const char *ip, struct ip_rule_alias *ip_alias);
int _config_ip_rule_add(const char *ip_cidr, enum ip_rule type, void *rule);

void *_new_dns_ip_rule(enum ip_rule ip_rule);
void _dns_ip_rule_get(struct dns_ip_rule *rule);
void _dns_ip_rule_put(struct dns_ip_rule *rule);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
