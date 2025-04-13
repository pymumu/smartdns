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

#include "request.h"
#include "request_pending.h"
#include "address.h"
#include "connection.h"
#include "dns_server.h"
#include "dualstack.h"
#include "neighbor.h"
#include "ptr.h"
#include "rules.h"
#include "soa.h"
#include "mdns.h"
#include "context.h"

#include "smartdns/dns_plugin.h"
#include "smartdns/dns_stats.h"

int _dns_server_has_bind_flag(struct dns_request *request, uint32_t flag)
{
	if (request->server_flags & flag) {
		return 0;
	}

	return -1;
}

int _dns_server_is_dns64_request(struct dns_request *request)
{
	if (request->qtype != DNS_T_AAAA) {
		return 0;
	}

	if (request->dualstack_selection_query == 1) {
		return 0;
	}

	if (request->conf->dns_dns64.prefix_len <= 0) {
		return 0;
	}

	return 1;
}

static int _dns_server_request_complete_with_all_IPs(struct dns_request *request, int with_all_ips)
{
	int ttl = 0;
	struct dns_server_post_context context;

	if (request->rcode == DNS_RC_SERVFAIL || request->rcode == DNS_RC_NXDOMAIN) {
		ttl = DNS_SERVER_FAIL_TTL;
	}

	if (request->ip_ttl == 0) {
		request->ip_ttl = ttl;
	}

	if (request->prefetch == 1) {
		return 0;
	}

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	if (request->has_ip != 0 && request->passthrough == 0) {
		request->has_soa = 0;
		if (request->has_ping_result == 0 && request->ip_ttl > DNS_SERVER_TMOUT_TTL) {
			request->ip_ttl = DNS_SERVER_TMOUT_TTL;
		}
		ttl = request->ip_ttl;
	}

	if (_dns_server_force_dualstack(request) == 0) {
		goto out;
	}

	_dns_server_need_append_mdns_local_cname(request);

	if (request->has_soa) {
		tlog(TLOG_INFO, "result: %s, qtype: %d, SOA", request->domain, request->qtype);
	} else {
		if (request->qtype == DNS_T_A) {
			tlog(TLOG_INFO, "result: %s, qtype: %d, rtt: %.1f ms, %d.%d.%d.%d", request->domain, request->qtype,
				 ((float)request->ping_time) / 10, request->ip_addr[0], request->ip_addr[1], request->ip_addr[2],
				 request->ip_addr[3]);
		} else if (request->qtype == DNS_T_AAAA) {
			tlog(TLOG_INFO,
				 "result: %s, qtype: %d, rtt: %.1f ms, "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, request->qtype, ((float)request->ping_time) / 10, request->ip_addr[0],
				 request->ip_addr[1], request->ip_addr[2], request->ip_addr[3], request->ip_addr[4],
				 request->ip_addr[5], request->ip_addr[6], request->ip_addr[7], request->ip_addr[8],
				 request->ip_addr[9], request->ip_addr[10], request->ip_addr[11], request->ip_addr[12],
				 request->ip_addr[13], request->ip_addr[14], request->ip_addr[15]);
		}

		if (request->rcode == DNS_RC_SERVFAIL && request->has_ip) {
			request->rcode = DNS_RC_NOERROR;
		}
	}

out:
	_dns_server_post_context_init(&context, request);
	context.do_cache = 1;
	context.do_ipset = 1;
	context.do_force_soa = request->dualstack_selection_force_soa | request->force_soa;
	context.do_audit = 1;
	context.do_reply = 1;
	context.reply_ttl = _dns_server_get_reply_ttl(request, ttl);
	context.skip_notify_count = 1;
	context.select_all_best_ip = with_all_ips;
	context.no_release_parent = 1;
	_dns_request_post(&context);
	return _dns_server_reply_all_pending_list(request, &context);
}

int _dns_server_request_complete(struct dns_request *request)
{
	return _dns_server_request_complete_with_all_IPs(request, 0);
}

void _dns_server_request_remove_all(void)
{
	struct dns_request *request = NULL;
	struct dns_request *tmp = NULL;
	LIST_HEAD(remove_list);

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		list_add_tail(&request->check_list, &remove_list);
		_dns_server_request_get(request);
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &remove_list, check_list)
	{
		_dns_server_request_complete(request);
		_dns_server_request_release(request);
	}
}

static void _dns_server_delete_request(struct dns_request *request)
{
	if (atomic_read(&request->notified) == 0) {
		_dns_server_request_complete(request);
	}

	if (request->conn) {
		_dns_server_conn_release(request->conn);
	}
	pthread_mutex_destroy(&request->ip_map_lock);
	if (request->https_svcb) {
		free(request->https_svcb);
	}
	memset(request, 0, sizeof(*request));
	free(request);
	atomic_dec(&server.request_num);
}

static void _dns_server_complete_with_multi_ipaddress(struct dns_request *request)
{
	struct dns_server_post_context context;
	int do_reply = 0;

	if (atomic_read(&request->ip_map_num) > 0) {
		request->has_soa = 0;
	}

	if (atomic_inc_return(&request->notified) == 1) {
		do_reply = 1;
		_dns_server_force_dualstack(request);
	}

	if (request->passthrough && do_reply == 0) {
		return;
	}

	_dns_server_need_append_mdns_local_cname(request);

	_dns_server_post_context_init(&context, request);
	context.do_cache = 1;
	context.do_ipset = 1;
	context.do_reply = do_reply;
	context.do_log_result = 1;
	context.select_all_best_ip = 1;
	context.skip_notify_count = 1;
	context.do_force_soa = request->dualstack_selection_force_soa | request->force_soa;
	_dns_request_post(&context);
	_dns_server_reply_all_pending_list(request, &context);
}

void _dns_server_request_release_complete(struct dns_request *request, int do_complete)
{
	struct dns_ip_address *addr_map = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long bucket = 0;

	pthread_mutex_lock(&server.request_list_lock);
	int refcnt = atomic_dec_return(&request->refcnt);
	if (refcnt) {
		pthread_mutex_unlock(&server.request_list_lock);
		if (refcnt < 0) {
			BUG("BUG: refcnt is %d, domain %s, qtype %d", refcnt, request->domain, request->qtype);
		}
		return;
	}

	list_del_init(&request->list);
	list_del_init(&request->check_list);
	pthread_mutex_unlock(&server.request_list_lock);

	pthread_mutex_lock(&server.request_pending_lock);
	list_del_init(&request->pending_list);
	pthread_mutex_unlock(&server.request_pending_lock);

	if (do_complete && atomic_read(&request->plugin_complete_called) == 0) {
		/* Select max hit ip address, and return to client */
		_dns_server_select_possible_ipaddress(request);
		_dns_server_complete_with_multi_ipaddress(request);
	}

	if (request->parent_request != NULL) {
		_dns_server_request_release(request->parent_request);
		request->parent_request = NULL;
	}

	atomic_inc(&request->refcnt);
	if (atomic_inc_return(&request->plugin_complete_called) == 1) {
		smartdns_plugin_func_server_complete_request(request);
	}

	if (atomic_dec_return(&request->refcnt) > 0) {
		/* plugin may hold request. */
		return;
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	if (request->rcode == DNS_RC_NOERROR) {
		stats_inc(&dns_stats.request.success_count);
	}

	if (request->conn) {
		dns_stats_avg_time_add(request->query_time);
	}
	_dns_server_delete_request(request);
}

void _dns_server_request_release(struct dns_request *request)
{
	_dns_server_request_release_complete(request, 1);
}

void _dns_server_request_get(struct dns_request *request)
{
	if (atomic_inc_return(&request->refcnt) <= 0) {
		BUG("BUG: request ref is invalid, %s", request->domain);
	}
}

const struct sockaddr *dns_server_request_get_remote_addr(struct dns_request *request)
{
	if (request->conn == NULL) {
		return NULL;
	}

	return &request->addr;
}

const struct sockaddr *dns_server_request_get_local_addr(struct dns_request *request)
{
	if (request == NULL) {
		return NULL;
	}

	return (struct sockaddr *)&request->localaddr;
}

const uint8_t *dns_server_request_get_remote_mac(struct dns_request *request)
{
	if (request->conn == NULL) {
		return NULL;
	}

	return request->mac;
};

const char *dns_server_request_get_group_name(struct dns_request *request)
{
	if (request == NULL) {
		return NULL;
	}

	return request->dns_group_name;
}

const char *dns_server_request_get_domain(struct dns_request *request)
{
	if (request == NULL) {
		return NULL;
	}

	return request->domain;
}

int dns_server_request_get_qtype(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->qtype;
}

int dns_server_request_get_qclass(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->qclass;
}

int dns_server_request_get_query_time(struct dns_request *request)
{
	if (request == NULL) {
		return -1;
	}

	return request->query_time;
}

uint64_t dns_server_request_get_query_timestamp(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->query_timestamp;
}

float dns_server_request_get_ping_time(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return (float)request->ping_time / 10;
}

int dns_server_request_is_prefetch(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->prefetch;
}

int dns_server_request_is_dualstack(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->dualstack_selection_query;
}

int dns_server_request_is_blocked(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return _dns_server_is_return_soa(request);
}

int dns_server_request_is_cached(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->is_cache_reply;
}

int dns_server_request_get_id(struct dns_request *request)
{
	if (request == NULL) {
		return 0;
	}

	return request->id;
}

int dns_server_request_get_rcode(struct dns_request *request)
{
	if (request == NULL) {
		return DNS_RC_SERVFAIL;
	}

	return request->rcode;
}

void dns_server_request_get(struct dns_request *request)
{
	_dns_server_request_get(request);
}

void dns_server_request_put(struct dns_request *request)
{
	_dns_server_request_release(request);
}

void dns_server_request_set_private(struct dns_request *request, void *private_data)
{
	if (request == NULL) {
		return;
	}

	request->private_data = private_data;
}

void *dns_server_request_get_private(struct dns_request *request)
{
	if (request == NULL) {
		return NULL;
	}

	return request->private_data;
}

struct dns_request *_dns_server_new_request(void)
{
	struct dns_request *request = NULL;

	request = malloc(sizeof(*request));
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc request failed.\n");
		goto errout;
	}

	memset(request, 0, sizeof(*request));
	pthread_mutex_init(&request->ip_map_lock, NULL);
	atomic_set(&request->adblock, 0);
	atomic_set(&request->soa_num, 0);
	atomic_set(&request->ip_map_num, 0);
	atomic_set(&request->refcnt, 0);
	atomic_set(&request->notified, 0);
	atomic_set(&request->do_callback, 0);
	atomic_set(&request->plugin_complete_called, 0);
	request->ping_time = -1;
	request->prefetch = 0;
	request->dualstack_selection = 0;
	request->dualstack_selection_ping_time = -1;
	request->rcode = DNS_RC_SERVFAIL;
	request->conn = NULL;
	request->qclass = DNS_C_IN;
	request->result_callback = NULL;
	request->conf = dns_server_get_default_rule_group();
	request->check_order_list = &dns_conf.default_check_orders;
	request->response_mode = dns_conf.default_response_mode;
	request->query_timestamp = get_utc_time_ms();
	INIT_LIST_HEAD(&request->list);
	INIT_LIST_HEAD(&request->pending_list);
	INIT_LIST_HEAD(&request->check_list);
	hash_init(request->ip_map);
	_dns_server_request_get(request);
	atomic_add(1, &server.request_num);
	stats_inc(&dns_stats.request.total);

	return request;
errout:
	return NULL;
}

void _dns_server_query_end(struct dns_request *request)
{
	int ip_num = 0;
	int request_wait = 0;
	struct dns_conf_group *conf = request->conf;

	/* if mdns request timeout */
	if (request->is_mdns_lookup == 1 && request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = DNS_RC_NOERROR;
		request->force_soa = 1;
		request->ip_ttl = _dns_server_get_conf_ttl(request, DNS_SERVER_ADDR_TTL);
	}

	pthread_mutex_lock(&request->ip_map_lock);
	ip_num = atomic_read(&request->ip_map_num);
	request_wait = request->request_wait;
	request->request_wait--;
	pthread_mutex_unlock(&request->ip_map_lock);

	/* Not need to wait check result if only has one ip address */
	if (ip_num <= 1 && request_wait == 1) {
		if (request->dualstack_selection_query == 1) {
			if ((conf->ipset_nftset.ipset_no_speed.ipv4_enable || conf->ipset_nftset.nftset_no_speed.ip_enable ||
				 conf->ipset_nftset.ipset_no_speed.ipv6_enable || conf->ipset_nftset.nftset_no_speed.ip6_enable) &&
				request->conf->dns_dns64.prefix_len == 0) {
				/* if speed check fail enabled, we need reply quickly, otherwise wait for ping result.*/
				_dns_server_request_complete(request);
			}
			goto out;
		}

		if (request->dualstack_selection_has_ip && request->dualstack_selection_ping_time > 0) {
			goto out;
		}

		request->has_ping_result = 1;
		_dns_server_request_complete(request);
	}

out:
	_dns_server_request_release(request);
}

void _dns_server_passthrough_may_complete(struct dns_request *request)
{
	const unsigned char *addr;
	if (request->passthrough != 2) {
		return;
	}

	if (request->has_ip == 0 && request->has_soa == 0) {
		return;
	}

	if (request->qtype == DNS_T_A && request->has_ip == 1) {
		/* Ad blocking result */
		addr = request->ip_addr;
		if (addr[0] == 0 || addr[0] == 127) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				return;
			}
		}
	}

	if (request->qtype == DNS_T_AAAA && request->has_ip == 1) {
		addr = request->ip_addr;
		if (_dns_server_is_adblock_ipv6(addr) == 0) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				return;
			}
		}
	}

	_dns_server_request_complete_with_all_IPs(request, 1);
}

static int _dns_server_reply_request_eth_ip(struct dns_request *request)
{
	struct sockaddr_in *addr_in = NULL;
	struct sockaddr_in6 *addr_in6 = NULL;
	struct sockaddr_storage *localaddr = NULL;
	struct sockaddr_storage localaddr_buff;

	localaddr = &request->localaddr;

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A:
		if (localaddr->ss_family != AF_INET) {
			if (_dns_server_get_inet_by_addr(localaddr, &localaddr_buff, AF_INET) != 0) {
				_dns_server_reply_SOA(DNS_RC_NOERROR, request);
				return 0;
			}

			localaddr = &localaddr_buff;
		}
		addr_in = (struct sockaddr_in *)localaddr;
		memcpy(request->ip_addr, &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
		break;
	case DNS_T_AAAA:
		if (localaddr->ss_family != AF_INET6) {
			if (_dns_server_get_inet_by_addr(localaddr, &localaddr_buff, AF_INET6) != 0) {
				_dns_server_reply_SOA(DNS_RC_NOERROR, request);
				return 0;
			}

			localaddr = &localaddr_buff;
		}
		addr_in6 = (struct sockaddr_in6 *)localaddr;
		memcpy(request->ip_addr, &addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
		break;
	default:
		goto out;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = dns_conf.local_ttl;
	request->has_ip = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	_dns_request_post(&context);

	return 0;
out:
	return -1;
}

void _dns_server_set_request_mdns(struct dns_request *request)
{
	if (dns_conf.mdns_lookup != 1) {
		return;
	}

	request->is_mdns_lookup = 1;
}

int _dns_server_process_DDR(struct dns_request *request)
{
	return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
}

int _dns_server_process_srv(struct dns_request *request)
{
	struct dns_srv_records *srv_records = dns_server_get_srv_record(request->domain);
	if (srv_records == NULL) {
		return -1;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	request->srv_records = srv_records;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_audit = 1;
	context.do_reply = 1;
	context.do_cache = 0;
	context.do_force_soa = 0;
	_dns_request_post(&context);

	return 0;
}

int _dns_server_process_svcb(struct dns_request *request)
{
	if (strncasecmp("_dns.resolver.arpa", request->domain, DNS_MAX_CNAME_LEN) == 0) {
		return _dns_server_process_DDR(request);
	}

	return -1;
}

int _dns_server_pre_process_server_flags(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) == 0) {
		request->no_cache = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_IP_ALIAS) == 0) {
		request->no_ipalias = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_PREFETCH) == 0) {
		request->prefetch_flags |= PREFETCH_FLAGS_NOPREFETCH;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_SERVE_EXPIRED) == 0) {
		request->no_serve_expired = 1;
	}

	if (request->qtype == DNS_T_HTTPS && _dns_server_has_bind_flag(request, BIND_FLAG_FORCE_HTTPS_SOA) == 0) {
		_dns_server_reply_SOA(DNS_RC_NOERROR, request);
		return 0;
	}

	return -1;
}

struct dns_request *_dns_server_new_child_request(struct dns_request *request, const char *domain,
														 dns_type_t qtype, child_request_callback child_callback)
{
	struct dns_request *child_request = NULL;

	child_request = _dns_server_new_request();
	if (child_request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	child_request->server_flags = request->server_flags;
	safe_strncpy(child_request->dns_group_name, request->dns_group_name, sizeof(request->dns_group_name));
	safe_strncpy(child_request->domain, domain, sizeof(child_request->domain));
	child_request->prefetch = request->prefetch;
	child_request->prefetch_flags = request->prefetch_flags;
	child_request->child_callback = child_callback;
	child_request->parent_request = request;
	child_request->qtype = qtype;
	child_request->qclass = request->qclass;
	child_request->conf = request->conf;

	if (request->has_ecs) {
		memcpy(&child_request->ecs, &request->ecs, sizeof(child_request->ecs));
		child_request->has_ecs = request->has_ecs;
	}
	_dns_server_request_get(request);
	/* reference count is 1 hold by parent request */
	request->child_request = child_request;
	_dns_server_get_domain_rule(child_request);
	return child_request;
errout:
	if (child_request) {
		_dns_server_request_release(child_request);
	}

	return NULL;
}

int _dns_server_request_copy(struct dns_request *request, struct dns_request *from)
{
	unsigned long bucket = 0;
	struct dns_ip_address *addr_map = NULL;
	struct hlist_node *tmp = NULL;
	uint32_t key = 0;
	int addr_len = 0;

	request->rcode = from->rcode;

	if (from->has_ip) {
		request->has_ip = 1;
		request->ip_ttl = _dns_server_get_conf_ttl(request, from->ip_ttl);
		request->ping_time = from->ping_time;
		memcpy(request->ip_addr, from->ip_addr, sizeof(request->ip_addr));
	}

	if (from->has_cname) {
		request->has_cname = 1;
		request->ttl_cname = from->ttl_cname;
		safe_strncpy(request->cname, from->cname, sizeof(request->cname));
	}

	if (from->has_soa) {
		request->has_soa = 1;
		memcpy(&request->soa, &from->soa, sizeof(request->soa));
	}

	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		hash_del(&addr_map->node);
		free(addr_map);
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	pthread_mutex_lock(&from->ip_map_lock);
	hash_for_each_safe(from->ip_map, bucket, tmp, addr_map, node)
	{
		struct dns_ip_address *new_addr_map = NULL;

		if (addr_map->addr_type == DNS_T_A) {
			addr_len = DNS_RR_A_LEN;
		} else if (addr_map->addr_type == DNS_T_AAAA) {
			addr_len = DNS_RR_AAAA_LEN;
		} else {
			continue;
		}

		new_addr_map = malloc(sizeof(struct dns_ip_address));
		if (new_addr_map == NULL) {
			tlog(TLOG_ERROR, "malloc failed.\n");
			pthread_mutex_unlock(&from->ip_map_lock);
			return -1;
		}

		memcpy(new_addr_map, addr_map, sizeof(struct dns_ip_address));
		new_addr_map->ping_time = addr_map->ping_time;
		key = jhash(new_addr_map->ip_addr, addr_len, 0);
		key = jhash(&addr_map->addr_type, sizeof(addr_map->addr_type), key);
		pthread_mutex_lock(&request->ip_map_lock);
		hash_add(request->ip_map, &new_addr_map->node, key);
		pthread_mutex_unlock(&request->ip_map_lock);
	}
	pthread_mutex_unlock(&from->ip_map_lock);

	return 0;
}

const char *_dns_server_get_request_server_groupname(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_NAMESERVER) == 0) {
		return NULL;
	}

	/* Get the nameserver rule */
	if (request->domain_rule.rules[DOMAIN_RULE_NAMESERVER]) {
		struct dns_nameserver_rule *nameserver_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_NAMESERVER);
		return nameserver_rule->group_name;
	}

	return NULL;
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

		new_addr_map = malloc(sizeof(struct dns_ip_address));
		if (new_addr_map == NULL) {
			tlog(TLOG_ERROR, "malloc failed.\n");
			pthread_mutex_unlock(&child_request->ip_map_lock);
			return DNS_CHILD_POST_FAIL;
		}
		memset(new_addr_map, 0, sizeof(struct dns_ip_address));

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

int _dns_server_get_expired_ttl_reply(struct dns_request *request, struct dns_cache *dns_cache)
{
	int ttl = dns_cache_get_ttl(dns_cache);
	if (ttl > 0) {
		return ttl;
	}

	return request->conf->dns_serve_expired_reply_ttl;
}

int _dns_server_process_https_svcb(struct dns_request *request)
{
	struct dns_https_record_rule *https_record_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_HTTPS);

	if (request->qtype != DNS_T_HTTPS) {
		return 0;
	}

	if (request->https_svcb != NULL) {
		return 0;
	}

	request->https_svcb = malloc(sizeof(*request->https_svcb));
	if (request->https_svcb == NULL) {
		return -1;
	}
	memset(request->https_svcb, 0, sizeof(*request->https_svcb));

	if (https_record_rule == NULL) {
		return 0;
	}

	if (https_record_rule->record.enable == 0) {
		return 0;
	}

	safe_strncpy(request->https_svcb->domain, request->domain, sizeof(request->https_svcb->domain));
	safe_strncpy(request->https_svcb->target, https_record_rule->record.target, sizeof(request->https_svcb->target));
	request->https_svcb->priority = https_record_rule->record.priority;
	request->https_svcb->port = https_record_rule->record.port;
	memcpy(request->https_svcb->ech, https_record_rule->record.ech, https_record_rule->record.ech_len);
	request->https_svcb->ech_len = https_record_rule->record.ech_len;
	memcpy(request->https_svcb->alpn, https_record_rule->record.alpn, sizeof(request->https_svcb->alpn));
	request->https_svcb->alpn_len = https_record_rule->record.alpn_len;
	if (https_record_rule->record.has_ipv4) {
		memcpy(request->ip_addr, https_record_rule->record.ipv4_addr, DNS_RR_A_LEN);
		request->ip_addr_type = DNS_T_A;
		request->has_ip = 1;
	} else if (https_record_rule->record.has_ipv6) {
		memcpy(request->ip_addr, https_record_rule->record.ipv6_addr, DNS_RR_AAAA_LEN);
		request->ip_addr_type = DNS_T_AAAA;
		request->has_ip = 1;
	}

	request->rcode = DNS_RC_NOERROR;

	return -1;
}

void _dns_server_request_set_client(struct dns_request *request, struct dns_server_conn_head *conn)
{
	request->conn = conn;
	request->server_flags = conn->server_flags;
	_dns_server_conn_get(conn);
}

void _dns_server_request_set_id(struct dns_request *request, unsigned short id)
{
	request->id = id;
}

void _dns_server_request_set_mac(struct dns_request *request, struct sockaddr_storage *from, socklen_t from_len)
{
	uint8_t netaddr[DNS_RR_AAAA_LEN] = {0};
	int netaddr_len = sizeof(netaddr);

	if (get_raw_addr_by_sockaddr(from, from_len, netaddr, &netaddr_len) != 0) {
		return;
	}

	struct neighbor_cache_item *item = _dns_server_neighbor_cache_get_item(netaddr, netaddr_len);
	if (item) {
		if (item->has_mac) {
			memcpy(request->mac, item->mac, 6);
		}
	}
}

int _dns_server_request_set_client_addr(struct dns_request *request, struct sockaddr_storage *from, socklen_t from_len)
{
	switch (from->ss_family) {
	case AF_INET:
		memcpy(&request->in, from, from_len);
		request->addr_len = from_len;
		break;
	case AF_INET6:
		memcpy(&request->in6, from, from_len);
		request->addr_len = from_len;
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

void _dns_server_request_set_callback(struct dns_request *request, dns_result_callback callback, void *user_ptr)
{
	request->result_callback = callback;
	request->user_ptr = user_ptr;
}

int _dns_server_process_smartdns_domain(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;
	unsigned int flags = 0;

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag == NULL) {
		return -1;
	}

	if (_dns_server_is_dns_rule_extract_match(request, DOMAIN_RULE_FLAGS) == 0) {
		return -1;
	}

	flags = rule_flag->flags;
	if (!(flags & DOMAIN_FLAG_SMARTDNS_DOMAIN)) {
		return -1;
	}

	return _dns_server_reply_request_eth_ip(request);
}

int _dns_server_process_special_query(struct dns_request *request)
{
	int ret = 0;

	switch (request->qtype) {
	case DNS_T_PTR:
		break;
	case DNS_T_SRV:
		ret = _dns_server_process_srv(request);
		if (ret == 0) {
			goto clean_exit;
		} else {
			/* pass to upstream server */
			request->passthrough = 1;
		}
	case DNS_T_HTTPS:
		break;
	case DNS_T_SVCB:
		ret = _dns_server_process_svcb(request);
		if (ret == 0) {
			goto clean_exit;
		} else {
			/* pass to upstream server */
			request->passthrough = 1;
		}
		break;
	case DNS_T_A:
		break;
	case DNS_T_AAAA:
		break;
	default:
		tlog(TLOG_DEBUG, "unsupported qtype: %d, domain: %s", request->qtype, request->domain);
		request->passthrough = 1;
		/* pass request to upstream server */
		break;
	}

	return -1;
clean_exit:
	return 0;
}

void _dns_server_check_set_passthrough(struct dns_request *request)
{
	if (request->check_order_list->orders[0].type == DOMAIN_CHECK_NONE) {
		request->passthrough = 1;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_SPEED_CHECK) == 0) {
		request->passthrough = 1;
	}

	if (is_ipv6_ready == 0 && request->qtype == DNS_T_AAAA) {
		request->passthrough = 1;
	}

	if (request->passthrough == 1) {
		request->dualstack_selection = 0;
	}

	if (request->passthrough == 1 &&
		(request->qtype == DNS_T_A || request->qtype == DNS_T_AAAA || request->qtype == DNS_T_HTTPS) &&
		request->edns0_do == 0) {
		request->passthrough = 2;
	}
}

int _dns_server_process_host(struct dns_request *request)
{
	uint32_t key = 0;
	struct dns_hosts *host = NULL;
	struct dns_hosts *host_tmp = NULL;
	int dns_type = request->qtype;

	if (dns_hosts_record_num <= 0) {
		return -1;
	}

	key = hash_string_case(request->domain);
	key = jhash(&dns_type, sizeof(dns_type), key);
	hash_for_each_possible(dns_hosts_table.hosts, host_tmp, node, key)
	{
		if (host_tmp->dns_type != dns_type) {
			continue;
		}

		if (strncasecmp(host_tmp->domain, request->domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		host = host_tmp;
		break;
	}

	if (host == NULL) {
		return -1;
	}

	if (host->is_soa) {
		request->has_soa = 1;
		return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
	}

	switch (request->qtype) {
	case DNS_T_A:
		memcpy(request->ip_addr, host->ipv4_addr, DNS_RR_A_LEN);
		break;
	case DNS_T_AAAA:
		memcpy(request->ip_addr, host->ipv6_addr, DNS_RR_AAAA_LEN);
		break;
	default:
		goto errout;
		break;
	}

	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = dns_conf.local_ttl;
	request->has_ip = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 1;
	_dns_request_post(&context);

	return 0;
errout:
	return -1;
}

int _dns_server_setup_query_option(struct dns_request *request, struct dns_query_options *options)
{
	options->enable_flag = 0;

	if (request->has_ecs) {
		memcpy(&options->ecs_dns, &request->ecs, sizeof(options->ecs_dns));
		options->enable_flag |= DNS_QUEY_OPTION_ECS_DNS;
	}

	if (request->edns0_do) {
		options->enable_flag |= DNS_QUEY_OPTION_EDNS0_DO;
	}
	options->conf_group_name = request->dns_group_name;
	return 0;
}

int _dns_server_setup_request_conf_pre(struct dns_request *request)
{
	struct dns_conf_group *rule_group = NULL;
	struct dns_request_domain_rule domain_rule;

	if (request->skip_domain_rule != 0 && request->conf) {
		return 0;
	}

	rule_group = dns_server_get_rule_group(request->dns_group_name);
	if (rule_group == NULL) {
		return -1;
	}

	request->conf = rule_group;
	memset(&domain_rule, 0, sizeof(domain_rule));
	_dns_server_get_domain_rule_by_domain_ext(rule_group, &domain_rule, DOMAIN_RULE_GROUP, request->domain, 1);
	if (domain_rule.rules[DOMAIN_RULE_GROUP] == NULL) {
		return 0;
	}

	struct dns_group_rule *group_rule = _dns_server_get_dns_rule_ext(&domain_rule, DOMAIN_RULE_GROUP);
	if (group_rule == NULL) {
		return 0;
	}
	rule_group = dns_server_get_rule_group(group_rule->group_name);
	if (rule_group == NULL) {
		return 0;
	}

	request->conf = rule_group;
	safe_strncpy(request->dns_group_name, rule_group->group_name, sizeof(request->dns_group_name));
	tlog(TLOG_DEBUG, "domain %s match group %s", request->domain, rule_group->group_name);

	return 0;
}

int _dns_server_setup_request_conf(struct dns_request *request)
{
	struct dns_conf_group *rule_group = NULL;

	rule_group = dns_server_get_rule_group(request->dns_group_name);
	if (rule_group == NULL) {
		return -1;
	}

	request->conf = rule_group;
	request->check_order_list = &rule_group->check_orders;

	return 0;
}

void _dns_server_setup_dns_group_name(struct dns_request *request, const char **server_group_name)
{
	const char *group_name = NULL;
	const char *temp_group_name = NULL;
	if (request->conn) {
		group_name = request->conn->dns_group;
	}

	temp_group_name = _dns_server_get_request_server_groupname(request);
	if (temp_group_name != NULL) {
		group_name = temp_group_name;
	}

	if (request->dns_group_name[0] != '\0' && group_name == NULL) {
		group_name = request->dns_group_name;
	} else {
		safe_strncpy(request->dns_group_name, group_name, sizeof(request->dns_group_name));
	}

	*server_group_name = group_name;
}

int _dns_server_check_request_supported(struct dns_request *request, struct dns_packet *packet)
{
	if (request->qclass != DNS_C_IN) {
		return -1;
	}

	if (packet->head.opcode != DNS_OP_QUERY) {
		return -1;
	}

	return 0;
}

int _dns_server_parser_request(struct dns_request *request, struct dns_packet *packet)
{
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	int i = 0;
	int ret = 0;
	int qclass = 0;
	int qtype = DNS_T_ALL;
	char domain[DNS_MAX_CNAME_LEN];

	if (packet->head.qr != DNS_QR_QUERY) {
		goto errout;
	}

	/* get request domain and request qtype */
	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
	if (rr_count > 1 || rr_count <= 0) {
		goto errout;
	}

	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		ret = dns_get_domain(rrs, domain, sizeof(domain), &qtype, &qclass);
		if (ret != 0) {
			goto errout;
		}

		// Only support one question.
		safe_strncpy(request->domain, domain, sizeof(request->domain));
		request->qtype = qtype;
		break;
	}

	request->qclass = qclass;
	if (_dns_server_check_request_supported(request, packet) != 0) {
		goto errout;
	}

	if ((dns_get_OPT_option(packet) & DNS_OPT_FLAG_DO) && packet->head.ad == 1) {
		request->edns0_do = 1;
	}

	/* get request opts */
	rr_count = 0;
	rrs = dns_get_rrs_start(packet, DNS_RRS_OPT, &rr_count);
	if (rr_count <= 0) {
		return 0;
	}

	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		switch (rrs->type) {
		case DNS_OPT_T_TCP_KEEPALIVE: {
			unsigned short idle_timeout = 0;
			ret = dns_get_OPT_TCP_KEEPALIVE(rrs, &idle_timeout);
			if (idle_timeout == 0 || ret != 0) {
				continue;
			}

			tlog(TLOG_DEBUG, "set tcp connection timeout to %u", idle_timeout);
			_dns_server_update_request_connection_timeout(request->conn, idle_timeout / 10);
		} break;
		case DNS_OPT_T_ECS:
			ret = dns_get_OPT_ECS(rrs, &request->ecs);
			if (ret != 0) {
				continue;
			}
			request->has_ecs = 1;
		default:
			break;
		}
	}

	return 0;
errout:
	request->rcode = DNS_RC_NOTIMP;
	return -1;
}

int _dns_server_setup_server_query_options(struct dns_request *request,
										   struct dns_server_query_option *server_query_option)
{
	if (server_query_option == NULL) {
		return 0;
	}

	request->server_flags = server_query_option->server_flags;
	if (server_query_option->dns_group_name) {
		safe_strncpy(request->dns_group_name, server_query_option->dns_group_name, DNS_GROUP_NAME_LEN);
	}

	if (server_query_option->ecs_enable_flag & DNS_QUEY_OPTION_ECS_DNS) {
		request->has_ecs = 1;
		memcpy(&request->ecs, &server_query_option->ecs_dns, sizeof(request->ecs));
	}

	if (server_query_option->ecs_enable_flag & DNS_QUEY_OPTION_EDNS0_DO) {
		request->edns0_do = 1;
	}

	return 0;
}
