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

#include "cache.h"
#include "answer.h"
#include "context.h"
#include "dns_server.h"
#include "prefetch.h"
#include "request.h"
#include "rules.h"
#include "soa.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>

int _dns_server_expired_cache_ttl(struct dns_cache *cache, int serve_expired_ttl)
{
	return cache->info.insert_time + cache->info.ttl + serve_expired_ttl - time(NULL);
}

static int _dns_cache_is_specify_packet(int qtype)
{
	switch (qtype) {
	case DNS_T_PTR:
	case DNS_T_HTTPS:
	case DNS_T_TXT:
	case DNS_T_SRV:
	case DNS_T_CAA:
		break;
	default:
		return -1;
		break;
	}

	return 0;
}

static int _dns_server_get_cache_timeout(struct dns_request *request, struct dns_cache_key *cache_key, int ttl)
{
	int timeout = 0;
	int prefetch_time = 0;
	int is_serve_expired = request->conf->dns_serve_expired;

	if (request->rcode != DNS_RC_NOERROR) {
		return ttl + 1;
	}

	if (request->is_mdns_lookup == 1) {
		return ttl + 1;
	}

	if (request->conf->dns_prefetch) {
		prefetch_time = 1;
	}

	if ((request->prefetch_flags & PREFETCH_FLAGS_NOPREFETCH)) {
		prefetch_time = 0;
	}

	if (request->edns0_do == 1) {
		prefetch_time = 0;
	}

	if (request->no_serve_expired) {
		is_serve_expired = 0;
	}

	if (prefetch_time == 1) {
		if (is_serve_expired) {
			timeout = request->conf->dns_serve_expired_prefetch_time;
			if (timeout == 0) {
				timeout = request->conf->dns_serve_expired_ttl / 2;
				if (timeout == 0 || timeout > EXPIRED_DOMAIN_PREFETCH_TIME) {
					timeout = EXPIRED_DOMAIN_PREFETCH_TIME;
				}
			}

			if ((request->prefetch_flags & PREFETCH_FLAGS_EXPIRED) == 0) {
				timeout += ttl;
			} else if (cache_key != NULL) {
				struct dns_cache *old_cache = dns_cache_lookup(cache_key);
				if (old_cache) {
					time_t next_ttl = _dns_server_expired_cache_ttl(old_cache, request->conf->dns_serve_expired_ttl) -
									  old_cache->info.ttl + ttl;
					if (next_ttl < timeout) {
						timeout = next_ttl;
					}
					dns_cache_release(old_cache);
				}
			}
		} else {
			timeout = ttl - 3;
		}
	} else {
		timeout = ttl;
		if (is_serve_expired) {
			timeout += request->conf->dns_serve_expired_ttl;
		}

		timeout += 3;
	}

	if (timeout <= 0) {
		timeout = 1;
	}

	return timeout;
}

int _dns_server_request_update_cache(struct dns_request *request, int speed, dns_type_t qtype,
									 struct dns_cache_data *cache_data, int cache_ttl)
{
	int ttl = 0;
	int ret = -1;

	if (qtype != DNS_T_A && qtype != DNS_T_AAAA && qtype != DNS_T_HTTPS) {
		goto errout;
	}

	if (cache_ttl > 0) {
		ttl = cache_ttl;
	} else {
		ttl = _dns_server_get_conf_ttl(request, request->ip_ttl);
	}

	tlog(TLOG_DEBUG, "cache %s qtype: %d ttl: %d\n", request->domain, qtype, ttl);

	/* if doing prefetch, update cache only */
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = request->qtype;
	cache_key.query_flag = request->server_flags;

	if (request->prefetch) {
		/* no prefetch for mdns request */
		if (request->is_mdns_lookup) {
			ret = 0;
			goto errout;
		}

		if (dns_cache_replace(&cache_key, request->rcode, ttl, speed,
							  _dns_server_get_cache_timeout(request, &cache_key, ttl),
							  !(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED), cache_data) != 0) {
			ret = 0;
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(&cache_key, request->rcode, ttl, speed, _dns_server_get_cache_timeout(request, NULL, ttl),
							 cache_data) != 0) {
			ret = -1;
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_data) {
		dns_cache_data_put(cache_data);
	}
	return ret;
}

int _dns_cache_cname_packet(struct dns_server_post_context *context)
{
	struct dns_packet *packet = context->packet;
	struct dns_packet *cname_packet = NULL;
	int ret = -1;
	int i = 0;
	int j = 0;
	int rr_count = 0;
	int ttl = 0;
	int speed = 0;
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char inpacket_buff[DNS_IN_PACKSIZE];
	int inpacket_len = 0;

	struct dns_cache_data *cache_packet = NULL;
	struct dns_rrs *rrs = NULL;
	char name[DNS_MAX_CNAME_LEN] = {0};
	cname_packet = (struct dns_packet *)packet_buff;
	int has_result = 0;

	struct dns_request *request = context->request;

	if (request->has_cname == 0 || request->no_cache_cname == 1 || request->no_cache == 1) {
		return 0;
	}

	/* init a new DNS packet */
	ret = dns_packet_init(cname_packet, DNS_PACKSIZE, &packet->head);
	if (ret != 0) {
		return -1;
	}

	/* add request domain */
	ret = dns_add_domain(cname_packet, request->cname, context->qtype, DNS_C_IN);
	if (ret != 0) {
		return -1;
	}

	for (j = 1; j < DNS_RRS_OPT && context->packet; j++) {
		rrs = dns_get_rrs_start(context->packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(context->packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char ipv4_addr[4];
				if (dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv4_addr) != 0) {
					continue;
				}

				if (strncasecmp(request->cname, name, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				ret = dns_add_A(cname_packet, DNS_RRS_AN, request->cname, ttl, ipv4_addr);
				if (ret != 0) {
					return -1;
				}
				has_result = 1;
			} break;
			case DNS_T_AAAA: {
				unsigned char ipv6_addr[16];
				if (dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv6_addr) != 0) {
					continue;
				}

				if (strncasecmp(request->cname, name, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				ret = dns_add_AAAA(cname_packet, DNS_RRS_AN, request->cname, ttl, ipv6_addr);
				if (ret != 0) {
					return -1;
				}
				has_result = 1;
			} break;
			case DNS_T_SOA: {
				struct dns_soa soa;
				if (dns_get_SOA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, &soa) != 0) {
					continue;
				}

				ret = dns_add_SOA(cname_packet, DNS_RRS_AN, request->cname, ttl, &soa);
				if (ret != 0) {
					return -1;
				}
				has_result = 1;
				break;
			}
			default:
				continue;
			}
		}
	}

	if (has_result == 0) {
		return 0;
	}

	inpacket_len = dns_encode(inpacket_buff, DNS_IN_PACKSIZE, cname_packet);
	if (inpacket_len <= 0) {
		return -1;
	}

	if (context->qtype != DNS_T_A && context->qtype != DNS_T_AAAA) {
		return -1;
	}

	cache_packet = dns_cache_new_data_packet(inpacket_buff, inpacket_len);
	if (cache_packet == NULL) {
		goto errout;
	}

	ttl = _dns_server_get_conf_ttl(request, request->ip_ttl);
	speed = request->ping_time;

	tlog(TLOG_DEBUG, "Cache CNAME: %s, qtype: %d, speed: %d", request->cname, request->qtype, speed);

	/* if doing prefetch, update cache only */
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->cname;
	cache_key.qtype = context->qtype;
	cache_key.query_flag = request->server_flags;

	if (request->prefetch) {
		if (dns_cache_replace(&cache_key, request->rcode, ttl, speed,
							  _dns_server_get_cache_timeout(request, &cache_key, ttl),
							  !(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED), cache_packet) != 0) {
			ret = 0;
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(&cache_key, request->rcode, ttl, speed, _dns_server_get_cache_timeout(request, NULL, ttl),
							 cache_packet) != 0) {
			ret = -1;
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_packet) {
		dns_cache_data_put(cache_packet);
	}

	return ret;
}

int _dns_cache_packet(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	int ret = -1;

	struct dns_cache_data *cache_packet = dns_cache_new_data_packet(context->inpacket, context->inpacket_len);
	if (cache_packet == NULL) {
		goto errout;
	}

	/* if doing prefetch, update cache only */
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = context->qtype;
	cache_key.query_flag = request->server_flags;

	if (request->prefetch) {
		/* no prefetch for mdns request */
		if (request->is_mdns_lookup) {
			ret = 0;
			goto errout;
		}

		if (dns_cache_replace(&cache_key, request->rcode, request->ip_ttl, -1,
							  _dns_server_get_cache_timeout(request, &cache_key, request->ip_ttl),
							  !(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED), cache_packet) != 0) {
			ret = 0;
			goto errout;
		}
	} else {
		/* insert result to cache */
		if (dns_cache_insert(&cache_key, request->rcode, request->ip_ttl, -1,
							 _dns_server_get_cache_timeout(request, NULL, request->ip_ttl), cache_packet) != 0) {
			ret = -1;
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_packet) {
		dns_cache_data_put(cache_packet);
	}

	return ret;
}

int _dns_cache_specify_packet(struct dns_server_post_context *context)
{
	if (_dns_cache_is_specify_packet(context->qtype) != 0) {
		return 0;
	}

	return _dns_cache_packet(context);
}

int _dns_cache_try_keep_old_cache(struct dns_request *request)
{
	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = request->qtype;
	cache_key.query_flag = request->server_flags;
	return dns_cache_update_timer(&cache_key, DNS_SERVER_TMOUT_TTL);
}

static int _dns_server_process_cache_packet(struct dns_request *request, struct dns_cache *dns_cache)
{
	int ret = -1;
	struct dns_cache_packet *cache_packet = NULL;
	if (dns_cache->info.qtype != request->qtype) {
		goto out;
	}

	cache_packet = (struct dns_cache_packet *)dns_cache_get_data(dns_cache);
	if (cache_packet == NULL) {
		goto out;
	}

	int do_ipset = (dns_cache_get_ttl(dns_cache) == 0);
	if (dns_cache_is_visited(dns_cache) == 0) {
		do_ipset = 1;
	}

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);

	if (request->original_domain != NULL && cache_packet->head.size < DNS_IN_PACKSIZE) {
		context.inpacket = context.inpacket_buff;
		memcpy(context.inpacket, cache_packet->data, cache_packet->head.size);
	} else {
		context.inpacket = cache_packet->data;
	}
	context.inpacket_len = cache_packet->head.size;
	request->ping_time = dns_cache->info.speed;

	if (dns_decode(context.packet, context.packet_maxlen, cache_packet->data, cache_packet->head.size) != 0) {
		tlog(TLOG_ERROR, "decode cache failed, %d, %d", context.packet_maxlen, context.inpacket_len);
		goto out;
	}

	/* Check if records in cache contain DNSSEC, if not exist, skip cache */
	if (request->passthrough == 1) {
		if ((dns_get_OPT_option(context.packet) & DNS_OPT_FLAG_DO) == 0 && request->edns0_do == 1) {
			goto out;
		}
	}

	request->is_cache_reply = 1;
	request->rcode = context.packet->head.rcode;
	context.do_cache = 0;
	context.do_ipset = do_ipset;
	context.do_audit = 1;
	context.do_reply = 1;
	context.is_cache_reply = 1;
	context.reply_ttl = _dns_server_get_expired_ttl_reply(request, dns_cache);
	ret = _dns_server_reply_passthrough(&context);
out:
	if (cache_packet) {
		dns_cache_data_put((struct dns_cache_data *)cache_packet);
	}

	return ret;
}

static int _dns_server_process_cache_data(struct dns_request *request, struct dns_cache *dns_cache)
{
	int ret = -1;

	request->ping_time = dns_cache->info.speed;
	ret = _dns_server_process_cache_packet(request, dns_cache);
	if (ret != 0) {
		goto out;
	}

	return 0;
out:
	return -1;
}

int _dns_server_process_cache(struct dns_request *request)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *dualstack_dns_cache = NULL;
	int ret = -1;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_CACHE) == 0) {
		goto out;
	}

	struct dns_cache_key cache_key;
	cache_key.dns_group_name = request->dns_group_name;
	cache_key.domain = request->domain;
	cache_key.qtype = request->qtype;
	cache_key.query_flag = request->server_flags;

	dns_cache = dns_cache_lookup(&cache_key);
	if (dns_cache == NULL) {
		goto out;
	}

	if (request->qtype != dns_cache->info.qtype) {
		goto out;
	}

	if (request->qtype == DNS_T_A && request->conf->dns_dualstack_ip_allow_force_AAAA == 0) {
		goto reply_cache;
	}

	if (request->qtype != DNS_T_A && request->qtype != DNS_T_AAAA) {
		goto reply_cache;
	}

	if (request->dualstack_selection) {
		int dualstack_qtype = 0;
		if (request->qtype == DNS_T_A) {
			dualstack_qtype = DNS_T_AAAA;
		} else if (request->qtype == DNS_T_AAAA) {
			dualstack_qtype = DNS_T_A;
		} else {
			goto reply_cache;
		}

		if (_dns_server_is_dns64_request(request) == 1) {
			goto reply_cache;
		}

		cache_key.qtype = dualstack_qtype;
		dualstack_dns_cache = dns_cache_lookup(&cache_key);
		if (dualstack_dns_cache == NULL && request->cname[0] != '\0') {
			cache_key.domain = request->cname;
			dualstack_dns_cache = dns_cache_lookup(&cache_key);
		}

		if (dualstack_dns_cache && (dualstack_dns_cache->info.speed > 0)) {
			if ((dualstack_dns_cache->info.speed + (request->conf->dns_dualstack_ip_selection_threshold * 10)) <
					dns_cache->info.speed ||
				dns_cache->info.speed < 0) {
				tlog(TLOG_DEBUG, "cache result: %s, qtype: %d, force %s preferred, id: %d, time1: %d, time2: %d",
					 request->domain, request->qtype, request->qtype == DNS_T_AAAA ? "IPv4" : "IPv6", request->id,
					 dns_cache->info.speed, dualstack_dns_cache->info.speed);
				request->ip_ttl = _dns_server_get_expired_ttl_reply(request, dualstack_dns_cache);
				ret = _dns_server_reply_SOA(DNS_RC_NOERROR, request);
				goto out_update_cache;
			}
		}
	}

reply_cache:
	if (dns_cache_get_ttl(dns_cache) <= 0 && request->no_serve_expired == 1) {
		goto out;
	}

	ret = _dns_server_process_cache_data(request, dns_cache);
	if (ret != 0) {
		goto out;
	}

out_update_cache:
	if (dns_cache_get_ttl(dns_cache) == 0) {
		struct dns_server_query_option dns_query_options;
		int prefetch_flags = 0;
		dns_query_options.server_flags = request->server_flags;
		dns_query_options.dns_group_name = request->dns_group_name;
		if (request->conn == NULL) {
			dns_query_options.server_flags = dns_cache_get_query_flag(dns_cache);
			dns_query_options.dns_group_name = dns_cache_get_dns_group_name(dns_cache);
		}

		dns_query_options.ecs_enable_flag = 0;
		if (request->has_ecs) {
			dns_query_options.ecs_enable_flag |= DNS_QUEY_OPTION_ECS_DNS;
			memcpy(&dns_query_options.ecs_dns, &request->ecs, sizeof(dns_query_options.ecs_dns));
		}

		if (request->edns0_do) {
			dns_query_options.ecs_enable_flag |= DNS_QUEY_OPTION_EDNS0_DO;
			prefetch_flags |= PREFETCH_FLAGS_NOPREFETCH;
		}

		_dns_server_prefetch_request(request->domain, request->qtype, &dns_query_options, prefetch_flags);
	} else {
		dns_cache_update(dns_cache);
	}

out:
	if (dns_cache) {
		dns_cache_release(dns_cache);
	}

	if (dualstack_dns_cache) {
		dns_cache_release(dualstack_dns_cache);
		dualstack_dns_cache = NULL;
	}

	return ret;
}

void _dns_server_save_cache_to_file(void)
{
	time_t now;
	int check_time = dns_conf.cache_checkpoint_time;

	if (dns_conf.cache_persist == 0 || dns_conf.cachesize <= 0 || dns_conf.cache_checkpoint_time <= 0) {
		return;
	}

	time(&now);
	if (server.cache_save_pid > 0) {
		int ret = waitpid(server.cache_save_pid, NULL, WNOHANG);
		if (ret == server.cache_save_pid) {
			server.cache_save_pid = 0;
		} else if (ret < 0) {
			tlog(TLOG_ERROR, "waitpid failed, errno %d, error info '%s'", errno, strerror(errno));
			server.cache_save_pid = 0;
		} else {
			if (now - 30 > server.cache_save_time) {
				kill(server.cache_save_pid, SIGKILL);
			}
			return;
		}
	}

	if (check_time < 120) {
		check_time = 120;
	}

	if (now - check_time < server.cache_save_time) {
		return;
	}

	/* server is busy, skip*/
	pthread_mutex_lock(&server.request_list_lock);
	if (list_empty(&server.request_list) != 0) {
		pthread_mutex_unlock(&server.request_list_lock);
		return;
	}
	pthread_mutex_unlock(&server.request_list_lock);

	server.cache_save_time = now;

	int pid = fork();
	if (pid == 0) {
		/* child process */
		for (int i = 3; i < 1024; i++) {
			close(i);
		}

		tlog_setlevel(TLOG_OFF);
		_dns_server_cache_save(1);
		_exit(0);
	} else if (pid < 0) {
		tlog(TLOG_DEBUG, "fork failed, errno %d, error info '%s'", errno, strerror(errno));
		return;
	}

	server.cache_save_pid = pid;
}

static dns_cache_tmout_action_t _dns_server_cache_expired(struct dns_cache *dns_cache)
{
	if (dns_cache->info.rcode != DNS_RC_NOERROR) {
		return DNS_CACHE_TMOUT_ACTION_DEL;
	}

	struct dns_conf_group *conf_group = dns_server_get_rule_group(dns_cache->info.dns_group_name);

	if (conf_group->dns_prefetch == 1) {
		if (conf_group->dns_serve_expired == 1) {
			return _dns_server_prefetch_expired_domain(conf_group, dns_cache);
		} else {
			return _dns_server_prefetch_domain(conf_group, dns_cache);
		}
	}

	return DNS_CACHE_TMOUT_ACTION_DEL;
}

int _dns_server_cache_init(void)
{
	if (dns_cache_init(dns_conf.cachesize, dns_conf.cache_max_memsize, _dns_server_cache_expired) != 0) {
		tlog(TLOG_ERROR, "init cache failed.");
		return -1;
	}

	const char *dns_cache_file = dns_conf_get_cache_dir();
	if (dns_conf.cache_persist == 2) {
		uint64_t freespace = get_free_space(dns_cache_file);
		if (freespace >= CACHE_AUTO_ENABLE_SIZE) {
			tlog(TLOG_INFO, "auto enable cache persist.");
			dns_conf.cache_persist = 1;
		}
	}

	if (dns_conf.cachesize <= 0 || dns_conf.cache_persist == 0) {
		return 0;
	}

	if (dns_cache_load(dns_cache_file) != 0) {
		tlog(TLOG_WARN, "Load cache failed.");
		return 0;
	}

	return 0;
}

int _dns_server_cache_save(int check_lock)
{
	const char *dns_cache_file = dns_conf_get_cache_dir();

	if (dns_conf.cache_persist == 0 || dns_conf.cachesize <= 0) {
		if (access(dns_cache_file, F_OK) == 0) {
			unlink(dns_cache_file);
		}
		return 0;
	}

	if (dns_cache_save(dns_cache_file, check_lock) != 0) {
		tlog(TLOG_WARN, "save cache failed.");
		return -1;
	}

	return 0;
}
