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

#include "dns64.h"
#include "address.h"
#include "context.h"
#include "dns_server.h"
#include "ptr.h"
#include "request.h"
#include "request_pending.h"
#include "rules.h"
#include "soa.h"

#include "smartdns/dns_conf.h"

#include <errno.h>
#include <string.h>

int _dns_server_is_dns64_request(struct dns_request *request)
{
	if (request->conf->dns_dns64.prefix_len <= 0) {
		return 0;
	}

	if (request->dualstack_selection_query == 1) {
		return 0;
	}

	if (strncmp(request->domain, DNS64_IPV4ONLY_APRA_DOMAIN, sizeof(DNS64_IPV4ONLY_APRA_DOMAIN)) == 0) {
		return 1;
	}

	if (request->qtype != DNS_T_AAAA) {
		return 0;
	}

	return 1;
}

static int _dns_server_process_ipv4only_arpa(struct dns_request *request)
{
	if (strncmp(request->domain, DNS64_IPV4ONLY_APRA_DOMAIN, sizeof(DNS64_IPV4ONLY_APRA_DOMAIN)) != 0) {
		return -1;
	}

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A: {
		u_int8_t *ipv4_addr1 = (u_int8_t[]){192, 0, 0, 170};
		u_int8_t *ipv4_addr2 = (u_int8_t[]){192, 0, 0, 171};
		memcpy(request->ip_addr, ipv4_addr1, DNS_RR_A_LEN);
		_dns_ip_address_check_add(request, request->cname, ipv4_addr1, DNS_T_A, 1, NULL);
		_dns_ip_address_check_add(request, request->cname, ipv4_addr2, DNS_T_A, 1, NULL);
		request->has_ip = 1;
	} break;
	case DNS_T_AAAA:
		/* no AAAA record for ipv4only.arpa */
		request->has_ip = 0;
		break;
	default:
		goto errout;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	request->dualstack_selection = 0;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 1;
	context.do_ipset = 0;
	context.do_cache = 0;
	context.select_all_best_ip = 1;
	_dns_request_post(&context);
	_dns_server_reply_all_pending_list(request, &context);

	return 0;
errout:
	return -1;
}

static enum DNS_CHILD_POST_RESULT
_dns_server_process_dns64_callback(struct dns_request *request, struct dns_request *child_request, int is_first_resp)
{
	unsigned long bucket = 0;
	struct dns_ip_address *addr_map = NULL;
	struct hlist_node *tmp = NULL;
	uint32_t key = 0;
	int addr_len = 0;

	if (request->has_ip == 1) {
		if (memcmp(request->ip_addr, request->conf->dns_dns64.prefix, 12) != 0) {
			return DNS_CHILD_POST_SKIP;
		}
	}

	if (child_request->qtype != DNS_T_A) {
		return DNS_CHILD_POST_FAIL;
	}

	if (child_request->has_cname == 1) {
		safe_strncpy(request->cname, child_request->cname, sizeof(request->cname));
		request->has_cname = 1;
		request->ttl_cname = child_request->ttl_cname;
	}

	if (child_request->has_ip == 0 && request->has_ip == 0) {
		request->rcode = child_request->rcode;
		if (child_request->has_soa) {
			memcpy(&request->soa, &child_request->soa, sizeof(struct dns_soa));
			request->has_soa = 1;
			return DNS_CHILD_POST_SKIP;
		}

		if (request->has_soa == 0) {
			_dns_server_setup_soa(request);
			request->has_soa = 1;
		}
		return DNS_CHILD_POST_FAIL;
	}

	if (request->has_ip == 0 && child_request->has_ip == 1) {
		request->rcode = child_request->rcode;
		memcpy(request->ip_addr, request->conf->dns_dns64.prefix, 12);
		memcpy(request->ip_addr + 12, child_request->ip_addr, 4);
		request->ip_ttl = child_request->ip_ttl;
		request->has_ip = 1;
		request->has_soa = 0;
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	pthread_mutex_lock(&child_request->ip_map_lock);
	hash_for_each_safe(child_request->ip_map, bucket, tmp, addr_map, node)
	{
		struct dns_ip_address *new_addr_map = NULL;

		if (addr_map->addr_type == DNS_T_A) {
			addr_len = DNS_RR_A_LEN;
		} else {
			continue;
		}

		new_addr_map = zalloc(1, sizeof(struct dns_ip_address));
		if (new_addr_map == NULL) {
			tlog(TLOG_ERROR, "malloc failed.\n");
			pthread_mutex_unlock(&child_request->ip_map_lock);
			return DNS_CHILD_POST_FAIL;
		}

		new_addr_map->addr_type = DNS_T_AAAA;
		addr_len = DNS_RR_AAAA_LEN;
		memcpy(new_addr_map->ip_addr, request->conf->dns_dns64.prefix, 16);
		memcpy(new_addr_map->ip_addr + 12, addr_map->ip_addr, 4);

		new_addr_map->ping_time = addr_map->ping_time;
		key = jhash(new_addr_map->ip_addr, addr_len, 0);
		key = jhash(&new_addr_map->addr_type, sizeof(new_addr_map->addr_type), key);
		pthread_mutex_lock(&request->ip_map_lock);
		hash_add(request->ip_map, &new_addr_map->node, key);
		pthread_mutex_unlock(&request->ip_map_lock);
	}
	pthread_mutex_unlock(&child_request->ip_map_lock);

	if (request->dualstack_selection == 1) {
		return DNS_CHILD_POST_NO_RESPONSE;
	}

	return DNS_CHILD_POST_SKIP;
}

int _dns_server_process_dns64(struct dns_request *request)
{
	if (_dns_server_is_dns64_request(request) == 0) {
		return 0;
	}

	tlog(TLOG_DEBUG, "query %s with dns64", request->domain);

	if (_dns_server_process_ipv4only_arpa(request) == 0) {
		return 2;
	}

	struct dns_request *child_request =
		_dns_server_new_child_request(request, request->domain, DNS_T_A, _dns_server_process_dns64_callback);
	if (child_request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		return -1;
	}

	request->dualstack_selection = 0;
	child_request->prefetch_flags |= PREFETCH_FLAGS_NO_DUALSTACK;
	request->request_wait++;
	int ret = _dns_server_do_query(child_request, 0);
	if (ret != 0) {
		request->request_wait--;
		tlog(TLOG_ERROR, "do query %s type %d failed.\n", request->domain, request->qtype);
		goto errout;
	}

	_dns_server_request_release_complete(child_request, 0);
	return 0;

errout:

	if (child_request) {
		request->child_request = NULL;
		_dns_server_request_release(child_request);
	}

	return -1;
}