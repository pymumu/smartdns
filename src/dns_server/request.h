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

#ifndef _DNS_SERVER_REQUEST_
#define _DNS_SERVER_REQUEST_

#include "dns_server.h"
#include "smartdns/dns.h"
#include "smartdns/dns_cache.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _dns_server_request_release_complete(struct dns_request *request, int do_complete);

void _dns_server_query_end(struct dns_request *request);

int _dns_server_process_DDR(struct dns_request *request);

void *dns_server_request_get_private(struct dns_request *request);

struct dns_request *_dns_server_new_request(void);

struct dns_request *_dns_server_new_child_request(struct dns_request *request, const char *domain, dns_type_t qtype,
												  child_request_callback child_callback);

const char *_dns_server_get_request_server_groupname(struct dns_request *request);

int _dns_server_request_complete(struct dns_request *request);

int _dns_server_request_copy(struct dns_request *request, struct dns_request *from);

void _dns_server_request_set_callback(struct dns_request *request, dns_result_callback callback, void *user_ptr);

int _dns_server_setup_request_conf_pre(struct dns_request *request);

int _dns_server_setup_request_conf(struct dns_request *request);

int _dns_server_setup_server_query_options(struct dns_request *request,
										   struct dns_server_query_option *server_query_option);

int _dns_server_request_set_client_addr(struct dns_request *request, struct sockaddr_storage *from, socklen_t from_len);

int _dns_server_check_request_supported(struct dns_request *request, struct dns_packet *packet);

int _dns_server_parser_request(struct dns_request *request, struct dns_packet *packet);

void _dns_server_set_request_mdns(struct dns_request *request);

int _dns_server_process_svcb(struct dns_request *request);

int _dns_server_process_DDR(struct dns_request *request);

int _dns_server_process_srv(struct dns_request *request);

int _dns_server_process_host(struct dns_request *request);

void _dns_server_check_set_passthrough(struct dns_request *request);

int _dns_server_process_special_query(struct dns_request *request);

int _dns_server_process_dns64(struct dns_request *request);

void _dns_server_setup_dns_group_name(struct dns_request *request, const char **server_group_name);

int _dns_server_setup_query_option(struct dns_request *request, struct dns_query_options *options);

int _dns_server_process_smartdns_domain(struct dns_request *request);

void _dns_server_passthrough_may_complete(struct dns_request *request);

int _dns_server_pre_process_server_flags(struct dns_request *request);

int _dns_server_get_expired_ttl_reply(struct dns_request *request, struct dns_cache *dns_cache);

int _dns_server_process_https_svcb(struct dns_request *request);

void _dns_server_request_set_client(struct dns_request *request, struct dns_server_conn_head *conn);

void _dns_server_request_set_id(struct dns_request *request, unsigned short id);

void _dns_server_request_set_mac(struct dns_request *request, struct sockaddr_storage *from, socklen_t from_len);

int _dns_server_has_bind_flag(struct dns_request *request, uint32_t flag);

int _dns_server_is_dns64_request(struct dns_request *request);

void _dns_server_request_release(struct dns_request *request);

void _dns_server_request_get(struct dns_request *request);

void _dns_server_request_remove_all(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
