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

#ifndef _DNS_CONF_NFTSET_H_
#define _DNS_CONF_NFTSET_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

const struct dns_nftset_name *_dns_conf_get_nftable(const char *familyname, const char *tablename, const char *setname);

void _config_nftset_table_destroy(void);

int _config_nftset(void *data, int argc, char *argv[]);

int _config_nftset_no_speed(void *data, int argc, char *argv[]);

int _conf_domain_rule_nftset(char *domain, const char *nftsetname);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
