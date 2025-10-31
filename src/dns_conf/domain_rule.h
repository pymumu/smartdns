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

#ifndef _DNS_CONF_DOMAIN_RULE_H_
#define _DNS_CONF_DOMAIN_RULE_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _config_domain_iter_free(void *data, const unsigned char *key, uint32_t key_len, void *value);

void *_new_dns_rule_ext(enum domain_rule domain_rule, int ext_size);
void *_new_dns_rule(enum domain_rule domain_rule);
void _dns_rule_get(struct dns_rule *rule);
void _dns_rule_put(struct dns_rule *rule);

int _config_domain_rule_add(const char *domain, enum domain_rule type, void *rule);
int _config_domain_rule_remove(const char *domain, enum domain_rule type);
int _config_domain_rule_flag_set(const char *domain, unsigned int flag, unsigned int is_clear);
int _config_domain_rules(void *data, int argc, char *argv[]);
int _config_domain_rule_delete(const char *domain);
int _conf_domain_rule_group(const char *domain, const char *group_name);
int _config_domain_rule_free(struct dns_domain_rule *domain_rule);

int _conf_domain_rule_speed_check(char *domain, const char *mode);
int _conf_domain_rule_response_mode(char *domain, const char *mode);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
