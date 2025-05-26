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

#ifndef _DNS_SERVER_RULES_
#define _DNS_SERVER_RULES_

#include "dns_server.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void *_dns_server_get_dns_rule(struct dns_request *request, enum domain_rule rule);

int _dns_server_get_conf_ttl(struct dns_request *request, int ttl);

void *_dns_server_get_dns_rule_ext(struct dns_request_domain_rule *domain_rule, enum domain_rule rule);

void _dns_server_get_domain_rule(struct dns_request *request);

int _dns_server_pre_process_rule_flags(struct dns_request *request);

int _dns_server_get_reply_ttl(struct dns_request *request, int ttl);

int _dns_server_is_dns_rule_extract_match(struct dns_request *request, enum domain_rule rule);

void _dns_server_get_domain_rule_by_domain_ext(struct dns_conf_group *conf,
											   struct dns_request_domain_rule *request_domain_rule, int rule_index,
											   const char *domain, int out_log);

int _dns_server_passthrough_rule_check(struct dns_request *request, const char *domain, struct dns_packet *packet,
									   unsigned int result_flag, int *pttl);

void _dns_server_process_speed_rule(struct dns_request *request);

void _dns_server_get_domain_rule_by_domain(struct dns_request *request, const char *domain, int out_log);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
