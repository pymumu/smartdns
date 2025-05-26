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

#ifndef _DNS_CONF_IPSET_H_
#define _DNS_CONF_IPSET_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

const char *_dns_conf_get_ipset(const char *ipsetname);
int _config_ipset_init(void);
void _config_ipset_table_destroy(void);

int _conf_domain_rule_ipset(char *domain, const char *ipsetname);

int _config_ipset_no_speed(void *data, int argc, char *argv[]);

int _config_ipset(void *data, int argc, char *argv[]);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
