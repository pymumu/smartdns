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

#ifndef SMART_DNS_H
#define SMART_DNS_H

#include "smartdns/dns_cache.h"
#include "smartdns/dns_client.h"
#include "smartdns/dns_conf.h"
#include "smartdns/dns_plugin.h"
#include "smartdns/dns_server.h"
#include "smartdns/dns_stats.h"
#include "smartdns/fast_ping.h"
#include "smartdns/util.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void smartdns_exit(int status);

void smartdns_restart(void);

int smartdns_get_cert(char *key, char *cert);

int smartdns_main(int argc, char *argv[]);

int smartdns_server_run(const char *config_file);

int smartdns_server_stop(void);

const char *smartdns_version(void);

#ifdef TEST

typedef void (*smartdns_post_func)(void *arg);

int smartdns_reg_post_func(smartdns_post_func func, void *arg);

int smartdns_test_main(int argc, char *argv[], int fd_notify, int no_close_allfds);

#endif

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
