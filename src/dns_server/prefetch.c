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

#include "dns_server.h"
#include "prefetch.h"
#include "request.h"
#include "cache.h"

#include "smartdns/dns_cache.h"

int _dns_server_prefetch_request(char *domain, dns_type_t qtype,
										struct dns_server_query_option *server_query_option, int prefetch_flag)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	request->prefetch = 1;
	request->prefetch_flags = prefetch_flag;
	safe_strncpy(request->domain, domain, sizeof(request->domain));
	request->qtype = qtype;
	_dns_server_setup_server_query_options(request, server_query_option);
	ret = _dns_server_do_query(request, 0);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "prefetch do query %s failed.\n", request->domain);
		goto errout;
	}

	_dns_server_request_release(request);
	return ret;
errout:
	if (request) {
		_dns_server_request_release(request);
	}

	return ret;
}

dns_cache_tmout_action_t _dns_server_prefetch_domain(struct dns_conf_group *conf_group,
															struct dns_cache *dns_cache)
{
	/* If there are still hits, continue pre-fetching */
	struct dns_server_query_option server_query_option;
	int hitnum = dns_cache_hitnum_dec_get(dns_cache);
	if (hitnum <= 0) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG, "prefetch by cache %s, qtype %d, ttl %d, hitnum %d", dns_cache->info.domain, dns_cache->info.qtype,
		 dns_cache->info.ttl, hitnum);
	server_query_option.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
	server_query_option.server_flags = dns_cache_get_query_flag(dns_cache);
	server_query_option.ecs_enable_flag = 0;
	if (_dns_server_prefetch_request(dns_cache->info.domain, dns_cache->info.qtype, &server_query_option,
									 PREFETCH_FLAGS_NO_DUALSTACK) != 0) {
		tlog(TLOG_ERROR, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
		return DNS_CACHE_TMOUT_ACTION_RETRY;
	}

	return DNS_CACHE_TMOUT_ACTION_OK;
}

dns_cache_tmout_action_t _dns_server_prefetch_expired_domain(struct dns_conf_group *conf_group,
																	struct dns_cache *dns_cache)
{
	time_t ttl = _dns_server_expired_cache_ttl(dns_cache, conf_group->dns_serve_expired_ttl);
	if (ttl <= 1) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	/* start prefetch domain */
	tlog(TLOG_DEBUG,
		 "expired domain, total %d, prefetch by cache %s, qtype %d, ttl %llu, rcode %d, insert time %llu replace time "
		 "%llu",
		 dns_cache_total_num(), dns_cache->info.domain, dns_cache->info.qtype, (unsigned long long)ttl,
		 dns_cache->info.rcode, (unsigned long long)dns_cache->info.insert_time,
		 (unsigned long long)dns_cache->info.replace_time);

	struct dns_server_query_option server_query_option;
	server_query_option.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
	server_query_option.server_flags = dns_cache_get_query_flag(dns_cache);
	server_query_option.ecs_enable_flag = 0;

	if (_dns_server_prefetch_request(dns_cache->info.domain, dns_cache->info.qtype, &server_query_option,
									 PREFETCH_FLAGS_EXPIRED) != 0) {
		tlog(TLOG_DEBUG, "prefetch domain %s, qtype %d, failed.", dns_cache->info.domain, dns_cache->info.qtype);
		return DNS_CACHE_TMOUT_ACTION_RETRY;
	}

	return DNS_CACHE_TMOUT_ACTION_OK;
}
