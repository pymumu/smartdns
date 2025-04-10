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

#ifndef _DNS_CONF_H_
#define _DNS_CONF_H_

#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

const struct config_item *smartdns_config_item(void);

int _conf_printf(const char *key, const char *value, const char *file, int lineno, int ret);

struct config_enum_list *response_mode_list(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
