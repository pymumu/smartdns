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

#ifndef _DNS_CONF_BIND_H_
#define _DNS_CONF_BIND_H_

#include "dns_conf.h"
#include "smartdns/dns_conf.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _config_add_default_server_if_needed(void);
int _config_bind_ip_udp(void *data, int argc, char *argv[]);
int _config_bind_ip_tcp(void *data, int argc, char *argv[]);
int _config_bind_ip_tls(void *data, int argc, char *argv[]);
int _config_bind_ip_https(void *data, int argc, char *argv[]);

void dns_server_bind_destroy(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
