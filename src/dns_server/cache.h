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

#ifndef _DNS_SERVER_CACHE_
#define _DNS_SERVER_CACHE_

#include "dns_server.h"
#include "smartdns/dns_cache.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int _dns_server_cache_save(int check_lock);

void _dns_server_save_cache_to_file(void);

int _dns_server_cache_init(void);

int _dns_server_process_cache(struct dns_request *request);

int _dns_cache_cname_packet(struct dns_server_post_context *context);

int _dns_server_request_update_cache(struct dns_request *request, int speed, dns_type_t qtype,
									 struct dns_cache_data *cache_data, int cache_ttl);

int _dns_cache_packet(struct dns_server_post_context *context);

int _dns_cache_try_keep_old_cache(struct dns_request *request);

int _dns_cache_specify_packet(struct dns_server_post_context *context);

int _dns_server_expired_cache_ttl(struct dns_cache *cache, int serve_expired_ttl);
#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
