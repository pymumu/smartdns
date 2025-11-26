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

#ifndef _DNS_CLIENT_QUERY_
#define _DNS_CLIENT_QUERY_

#include "dns_client.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _dns_client_retry_dns_query(struct dns_query_struct *query);

void _dns_client_query_remove(struct dns_query_struct *query);

void _dns_client_query_release(struct dns_query_struct *query);

void _dns_client_query_get(struct dns_query_struct *query);

void _dns_client_query_remove_all(void);

int _dns_client_send_query(struct dns_query_struct *query);

struct dns_query_struct *_dns_client_get_request(char *domain, int qtype, unsigned short sid);

int _dns_replied_check_add(struct dns_query_struct *dns_query, struct dns_server_info *server);
void _dns_replied_check_remove(struct dns_query_struct *dns_query, struct dns_server_info *server);

int _dns_client_query_parser_options(struct dns_query_struct *query, struct dns_query_options *options);

void _dns_client_retry_dns_query(struct dns_query_struct *query);

int _dns_client_add_hashmap(struct dns_query_struct *query);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
