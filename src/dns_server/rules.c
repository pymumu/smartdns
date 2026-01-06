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

#include "rules.h"
#include "address.h"
#include "dns_server.h"
#include "ip_rule.h"
#include "request.h"
#include "request_pending.h"
#include "soa.h"

void *_dns_server_get_dns_rule_ext(struct dns_request_domain_rule *domain_rule, enum domain_rule rule)
{
	if (rule >= DOMAIN_RULE_MAX || domain_rule == NULL) {
		return NULL;
	}

	return domain_rule->rules[rule];
}

static int _dns_server_is_dns_rule_extract_match_ext(struct dns_request_domain_rule *domain_rule, enum domain_rule rule)
{
	if (rule >= DOMAIN_RULE_MAX || domain_rule == NULL) {
		return 0;
	}

	return domain_rule->is_sub_rule[rule] == 0;
}

static void _dns_server_log_rule(const char *domain, enum domain_rule rule_type, unsigned char *rule_key,
								 int rule_key_len)
{
	char rule_name[DNS_MAX_CNAME_LEN] = {0};
	if (rule_key_len <= 0) {
		return;
	}

	reverse_string(rule_name, (char *)rule_key, rule_key_len, 1);
	rule_name[rule_key_len] = 0;
	tlog(TLOG_INFO, "RULE-MATCH, type: %d, domain: %s, rule: %s", rule_type, domain, rule_name);
}

static void _dns_server_update_rule_by_flags(struct dns_request_domain_rule *request_domain_rule)
{
	unsigned int flags = 0;
	flags = request_domain_rule->flags;

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_ADDRESS_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_ADDR_HTTPS_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_HTTPS] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_IPSET] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV4_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_IPSET_IPV4] = NULL;
	}

	if (flags & DOMAIN_FLAG_IPSET_IPV6_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_IPSET_IPV6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NFTSET_IP_IGN || flags & DOMAIN_FLAG_NFTSET_INET_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_NFTSET_IP] = NULL;
	}

	if (flags & DOMAIN_FLAG_NFTSET_IP6_IGN || flags & DOMAIN_FLAG_NFTSET_INET_IGN) {
		request_domain_rule->rules[DOMAIN_RULE_NFTSET_IP6] = NULL;
	}

	if (flags & DOMAIN_FLAG_NAMESERVER_IGNORE) {
		request_domain_rule->rules[DOMAIN_RULE_NAMESERVER] = NULL;
	}
}

static int _dns_server_get_rules(unsigned char *key, uint32_t key_len, int is_subkey, void *value, void *arg)
{
	struct rule_walk_args *walk_args = arg;
	struct dns_request_domain_rule *request_domain_rule = walk_args->args;
	struct dns_domain_rule *domain_rule = value;
	int i = 0;
	if (domain_rule == NULL) {
		return 0;
	}

	/* sub rule flag check */
	int is_effective_sub = 1;
	if (key_len == walk_args->full_key_len) {
		is_effective_sub = 0;
	} else if (key_len == walk_args->full_key_len - 1 && walk_args->full_key_len > 0) {
		is_effective_sub = 0;
	}

	if (walk_args->rule_index >= 0) {
		i = walk_args->rule_index;
	} else {
		i = 0;
	}

	for (; i < domain_rule->capacity; i++) {
		if (domain_rule->rules[i] == NULL) {
			if (walk_args->rule_index >= 0) {
				break;
			}
			continue;
		}

		if (i == DOMAIN_RULE_FLAGS) {
			struct dns_rule_flags *rule_flags = (struct dns_rule_flags *)domain_rule->rules[i];
			if (rule_flags->head.sub_only == 1 && is_effective_sub == 0) {
				continue;
			}

			if (rule_flags->head.root_only == 1 && is_effective_sub == 1) {
				continue;
			}

			request_domain_rule->flags |= ((struct dns_rule_flags *)domain_rule->rules[i])->flags;
		}

		if (domain_rule->rules[i]->sub_only == 1 && is_effective_sub == 0) {
			continue;
		}

		if (domain_rule->rules[i]->root_only == 1 && is_effective_sub == 1) {
			continue;
		}

		request_domain_rule->rules[i] = domain_rule->rules[i];
		request_domain_rule->is_sub_rule[i] = is_subkey;
		walk_args->key[i] = key;
		walk_args->key_len[i] = key_len;
		if (walk_args->rule_index >= 0) {
			break;
		}
	}

	/* update rules by flags */
	_dns_server_update_rule_by_flags(request_domain_rule);

	return 0;
}

void _dns_server_get_domain_rule_by_domain_ext(struct dns_conf_group *conf,
											   struct dns_request_domain_rule *request_domain_rule, int rule_index,
											   const char *domain, int out_log)
{
	int domain_len = 0;
	char domain_key[DNS_MAX_CNAME_LEN] = {0};
	struct rule_walk_args walk_args;
	int matched_key_len = DNS_MAX_CNAME_LEN;
	unsigned char matched_key[DNS_MAX_CNAME_LEN] = {0};
	int i = 0;

	memset(&walk_args, 0, sizeof(walk_args));
	walk_args.args = request_domain_rule;
	walk_args.rule_index = rule_index;

	/* reverse domain string */
	domain_len = strlen(domain);
	if (domain_len >= (int)sizeof(domain_key) - 3) {
		return;
	}

	reverse_string(domain_key + 1, domain, domain_len, 1);
	domain_key[domain_len + 1] = '.';
	domain_key[0] = '.';
	domain_len += 2;
	domain_key[domain_len] = 0;
	walk_args.full_key_len = domain_len;

	/* find domain rule */
	art_substring_walk(&conf->domain_rule.tree, (unsigned char *)domain_key, domain_len, _dns_server_get_rules,
					   &walk_args);
	if (likely(dns_conf.log_level > TLOG_DEBUG) || out_log == 0) {
		return;
	}

	if (walk_args.rule_index >= 0) {
		i = walk_args.rule_index;
	} else {
		i = 0;
	}

	/* output log rule */
	for (; i < DOMAIN_RULE_MAX; i++) {
		if (walk_args.key[i] == NULL) {
			if (walk_args.rule_index >= 0) {
				break;
			}
			continue;
		}

		matched_key_len = walk_args.key_len[i];
		if (walk_args.key_len[i] >= sizeof(matched_key)) {
			continue;
		}

		memcpy(matched_key, walk_args.key[i], walk_args.key_len[i]);

		matched_key_len--;
		matched_key[matched_key_len] = 0;
		_dns_server_log_rule(domain, i, matched_key, matched_key_len);

		if (walk_args.rule_index >= 0) {
			break;
		}
	}
}

void _dns_server_get_domain_rule(struct dns_request *request)
{
	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULES) == 0) {
		return;
	}

	_dns_server_get_domain_rule_by_domain(request, request->domain, 1);
}

int _dns_server_passthrough_rule_check(struct dns_request *request, const char *domain, struct dns_packet *packet,
									   unsigned int result_flag, int *pttl)
{
	int ttl = 0;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char cname[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ip_check_result = 0;

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
			request->remote_server_fail = 1;
		}

		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);
		return 0;
	}

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				int ttl_tmp = 0;
				if (request->qtype != DNS_T_A) {
					/* ignore non-matched query type */
					if (request->dualstack_selection == 0) {
						break;
					}
				}
				_dns_server_request_get(request);
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl_tmp, addr);

				/* if domain is not match */
				if (strncasecmp(name, domain, DNS_MAX_CNAME_LEN) != 0 &&
					strncasecmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					continue;
				}

				tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %d.%d.%d.%d", name, ttl_tmp, addr[0], addr[1], addr[2],
					 addr[3]);

				/* ip rule check */
				ip_check_result = _dns_server_process_ip_rule(request, addr, 4, DNS_T_A, result_flag, NULL);
				if (ip_check_result == 0 || ip_check_result == -2 || ip_check_result == -3) {
					/* match, skip, nxdomain */
					_dns_server_request_release(request);
					return 0;
				}

				/* Ad blocking result */
				if (addr[0] == 0 || addr[0] == 127) {
					/* If half of the servers return the same result, then ignore this address */
					if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
						_dns_server_request_release(request);
						return 0;
					}
				}

				ttl = _dns_server_get_conf_ttl(request, ttl_tmp);
				_dns_server_request_release(request);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				int ttl_tmp = 0;
				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				_dns_server_request_get(request);
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl_tmp, addr);

				/* if domain is not match */
				if (strncasecmp(name, domain, DNS_MAX_CNAME_LEN) != 0 &&
					strncasecmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
					_dns_server_request_release(request);
					continue;
				}

				tlog(TLOG_DEBUG,
					 "domain: %s TTL: %d IP: "
					 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					 name, ttl_tmp, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
					 addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);

				ip_check_result = _dns_server_process_ip_rule(request, addr, 16, DNS_T_AAAA, result_flag, NULL);
				if (ip_check_result == 0 || ip_check_result == -2 || ip_check_result == -3) {
					/* match, skip, nxdomain */
					_dns_server_request_release(request);
					return 0;
				}

				/* Ad blocking result */
				if (_dns_server_is_adblock_ipv6(addr) == 0) {
					/* If half of the servers return the same result, then ignore this address */
					if (atomic_read(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
						_dns_server_request_release(request);
						return 0;
					}
				}

				ttl = _dns_server_get_conf_ttl(request, ttl_tmp);
				_dns_server_request_release(request);
			} break;
			case DNS_T_CNAME: {
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
			} break;
			default:
				if (ttl == 0) {
					/* Get TTL */
					char tmpname[DNS_MAX_CNAME_LEN] = {0};
					char tmpbuf[DNS_MAX_CNAME_LEN] = {0};
					dns_get_CNAME(rrs, tmpname, DNS_MAX_CNAME_LEN, &ttl, tmpbuf, DNS_MAX_CNAME_LEN);
					if (request->ip_ttl == 0) {
						request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
					}
				}
				break;
			}
		}
	}

	request->remote_server_fail = 0;
	if (request->rcode == DNS_RC_SERVFAIL) {
		request->rcode = packet->head.rcode;
	}

	*pttl = ttl;
	return -1;
}

int _dns_server_get_conf_ttl(struct dns_request *request, int ttl)
{
	int rr_ttl = request->conf->dns_rr_ttl;
	int rr_ttl_min = request->conf->dns_rr_ttl_min;
	int rr_ttl_max = request->conf->dns_rr_ttl_max;

	if (request->is_mdns_lookup) {
		rr_ttl_min = DNS_SERVER_ADDR_TTL;
	}

	struct dns_ttl_rule *ttl_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_TTL);
	if (ttl_rule != NULL) {
		if (ttl_rule->ttl > 0) {
			rr_ttl = ttl_rule->ttl;
		}

		/* make domain rule ttl high priority */
		if (ttl_rule->ttl_min > 0) {
			rr_ttl_min = ttl_rule->ttl_min;
			if (request->conf->dns_rr_ttl_max <= rr_ttl_min && request->conf->dns_rr_ttl_max > 0) {
				rr_ttl_max = rr_ttl_min;
			}
		}

		if (ttl_rule->ttl_max > 0) {
			rr_ttl_max = ttl_rule->ttl_max;
			if (request->conf->dns_rr_ttl_min >= rr_ttl_max && request->conf->dns_rr_ttl_min > 0 &&
				ttl_rule->ttl_min <= 0) {
				rr_ttl_min = rr_ttl_max;
			}
		}
	}

	if (rr_ttl > 0) {
		return rr_ttl;
	}

	/* make rr_ttl_min first priority */
	if (rr_ttl_max < rr_ttl_min && rr_ttl_max > 0) {
		rr_ttl_max = rr_ttl_min;
	}

	if (rr_ttl_max > 0 && ttl >= rr_ttl_max) {
		ttl = rr_ttl_max;
	} else if (rr_ttl_min > 0 && ttl <= rr_ttl_min) {
		ttl = rr_ttl_min;
	}

	return ttl;
}

int _dns_server_get_reply_ttl(struct dns_request *request, int ttl)
{
	int reply_ttl = ttl;

	if ((request->passthrough == 0 || request->passthrough == 2) && dns_conf.cachesize > 0 &&
		request->check_order_list->orders[0].type != DOMAIN_CHECK_NONE && request->no_serve_expired == 0 &&
		request->has_soa == 0 && request->no_cache == 0) {
		reply_ttl = request->conf->dns_serve_expired_reply_ttl;
		if (reply_ttl < 2) {
			reply_ttl = 2;
		}
	}

	int rr_ttl = _dns_server_get_conf_ttl(request, ttl);
	if (reply_ttl > rr_ttl) {
		reply_ttl = rr_ttl;
	}

	return reply_ttl;
}

void *_dns_server_get_dns_rule(struct dns_request *request, enum domain_rule rule)
{
	if (request == NULL) {
		return NULL;
	}

	return _dns_server_get_dns_rule_ext(&request->domain_rule, rule);
}

uint32_t _dns_server_get_rule_flags(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;
	if (request == NULL) {
		return 0;
	}

	if (request->domain_rule.flags != 0) {
		return request->domain_rule.flags;
	}

	if (request->domain_rule.rules[DOMAIN_RULE_FLAGS] == NULL) {
		return 0;
	}

	rule_flag = (struct dns_rule_flags *)request->domain_rule.rules[DOMAIN_RULE_FLAGS];

	return rule_flag->flags;
}

int _dns_server_is_dns_rule_extract_match(struct dns_request *request, enum domain_rule rule)
{
	if (request == NULL) {
		return 0;
	}

	return _dns_server_is_dns_rule_extract_match_ext(&request->domain_rule, rule);
}

int _dns_server_pre_process_rule_flags(struct dns_request *request)
{
	/* get domain rule flag */
	unsigned int flags = _dns_server_get_rule_flags(request);
	int rcode = DNS_RC_NOERROR;

	if (flags & DOMAIN_FLAG_NO_SERVE_EXPIRED) {
		request->no_serve_expired = 1;
	}

	if (flags & DOMAIN_FLAG_NO_CACHE) {
		request->no_cache = 1;
	}

	if (flags & DOMAIN_FLAG_ENABLE_CACHE) {
		request->no_cache = 0;
	}

	if (flags & DOMAIN_FLAG_NO_IPALIAS) {
		request->no_ipalias = 1;
	}

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		/* ignore this domain */
		goto skip_soa_out;
	}

	/* return specific type of address */
	switch (request->qtype) {
	case DNS_T_A:
		if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
			/* ignore this domain for A request */
			goto skip_soa_out;
		}

		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL) {
			goto skip_soa_out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* if AAAA exists, return SOA with NOERROR*/
			if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL) {
				goto soa;
			}

			/* if AAAA not exists, return SOA with NXDOMAIN */
			if (_dns_server_is_return_soa_qtype(request, DNS_T_AAAA)) {
				rcode = DNS_RC_NXDOMAIN;
			}
			goto soa;
		}
		goto out;
		break;
	case DNS_T_AAAA:
		if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
			/* ignore this domain for A request */
			goto skip_soa_out;
		}

		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL) {
			goto skip_soa_out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* if A exists, return SOA with NOERROR*/
			if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL) {
				goto soa;
			}
			/* if A not exists, return SOA with NXDOMAIN */
			if (_dns_server_is_return_soa_qtype(request, DNS_T_A)) {
				rcode = DNS_RC_NXDOMAIN;
			}
			goto soa;
		}

		if (flags & DOMAIN_FLAG_ADDR_IPV4_SOA && request->dualstack_selection) {
			/* if IPV4 return SOA and dualstack-selection enabled, set request dualstack disable */
			request->dualstack_selection = 0;
		}
		goto out;
		break;
	case DNS_T_HTTPS:
		if (flags & DOMAIN_FLAG_ADDR_HTTPS_IGN) {
			/* ignore this domain for A request */
			goto skip_soa_out;
		}

		if (_dns_server_is_return_soa(request)) {
			/* if HTTPS exists, return SOA with NOERROR*/
			if (request->domain_rule.rules[DOMAIN_RULE_HTTPS] != NULL) {
				goto soa;
			}

			if (_dns_server_is_return_soa_qtype(request, DNS_T_A) &&
				_dns_server_is_return_soa_qtype(request, DNS_T_AAAA)) {
				/* return SOA for HTTPS request */
				rcode = DNS_RC_NXDOMAIN;
				goto soa;
			}
		}

		if (request->domain_rule.rules[DOMAIN_RULE_HTTPS] != NULL) {
			goto skip_soa_out;
		}

		goto out;
		break;
	default:
		goto out;
		break;
	}

	if (_dns_server_is_return_soa(request)) {
		goto soa;
	}
skip_soa_out:
	request->skip_qtype_soa = 1;
out:
	return -1;

soa:
	/* return SOA */
	_dns_server_reply_SOA(rcode, request);
	return 0;
}

void _dns_server_process_speed_rule(struct dns_request *request)
{
	struct dns_domain_check_orders *check_order = NULL;
	struct dns_response_mode_rule *response_mode = NULL;

	/* get speed check mode */
	check_order = _dns_server_get_dns_rule(request, DOMAIN_RULE_CHECKSPEED);
	if (check_order != NULL) {
		request->check_order_list = check_order;
	}

	/* get response mode */
	response_mode = _dns_server_get_dns_rule(request, DOMAIN_RULE_RESPONSE_MODE);
	if (response_mode != NULL) {
		request->response_mode = response_mode->mode;
	} else {
		request->response_mode = request->conf->dns_response_mode;
	}
}

void _dns_server_get_domain_rule_by_domain(struct dns_request *request, const char *domain, int out_log)
{
	if (request->skip_domain_rule != 0) {
		return;
	}

	if (request->conf == NULL) {
		return;
	}

	_dns_server_get_domain_rule_by_domain_ext(request->conf, &request->domain_rule, -1, domain, out_log);
	request->skip_domain_rule = 1;
}