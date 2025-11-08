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

#include "context.h"
#include "address.h"
#include "audit.h"
#include "cache.h"
#include "dns_server.h"
#include "ip_rule.h"
#include "ipset_nftset.h"
#include "request.h"
#include "request_pending.h"
#include "rules.h"
#include "soa.h"

void _dns_server_post_context_init(struct dns_server_post_context *context, struct dns_request *request)
{
	memset(context, 0, sizeof(*context));
	context->packet = (struct dns_packet *)(context->packet_buff);
	context->packet_maxlen = sizeof(context->packet_buff);
	context->inpacket = (unsigned char *)(context->inpacket_buff);
	context->inpacket_maxlen = sizeof(context->inpacket_buff);
	context->qtype = request->qtype;
	context->request = request;
}

static void _dns_server_context_add_ip(struct dns_server_post_context *context, const unsigned char *ip_addr)
{
	if (context->ip_num < MAX_IP_NUM) {
		context->ip_addr[context->ip_num] = ip_addr;
	}

	context->ip_num++;
}

void _dns_server_post_context_init_from(struct dns_server_post_context *context, struct dns_request *request,
										struct dns_packet *packet, unsigned char *inpacket, int inpacket_len)
{
	memset(context, 0, sizeof(*context));
	context->packet = packet;
	context->packet_maxlen = sizeof(context->packet_buff);
	context->inpacket = inpacket;
	context->inpacket_len = inpacket_len;
	context->inpacket_maxlen = sizeof(context->inpacket);
	context->qtype = request->qtype;
	context->request = request;
}

static void _dns_rrs_result_log(struct dns_server_post_context *context, struct dns_ip_address *addr_map)
{
	struct dns_request *request = context->request;

	if (context->do_log_result == 0 || addr_map == NULL) {
		return;
	}

	if (addr_map->addr_type == DNS_T_A) {
		tlog(TLOG_INFO, "result: %s, id: %d, index: %d, rtt: %.1f ms, %d.%d.%d.%d", request->domain, request->id,
			 context->ip_num, ((float)addr_map->ping_time) / 10, addr_map->ip_addr[0], addr_map->ip_addr[1],
			 addr_map->ip_addr[2], addr_map->ip_addr[3]);
	} else if (addr_map->addr_type == DNS_T_AAAA) {
		tlog(TLOG_INFO,
			 "result: %s, id: %d, index: %d, rtt: %.1f ms, "
			 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
			 request->domain, request->id, context->ip_num, ((float)addr_map->ping_time) / 10, addr_map->ip_addr[0],
			 addr_map->ip_addr[1], addr_map->ip_addr[2], addr_map->ip_addr[3], addr_map->ip_addr[4],
			 addr_map->ip_addr[5], addr_map->ip_addr[6], addr_map->ip_addr[7], addr_map->ip_addr[8],
			 addr_map->ip_addr[9], addr_map->ip_addr[10], addr_map->ip_addr[11], addr_map->ip_addr[12],
			 addr_map->ip_addr[13], addr_map->ip_addr[14], addr_map->ip_addr[15]);
	}
}

static int _dns_rrs_add_all_best_ip(struct dns_server_post_context *context)
{
	struct dns_ip_address *addr_map = NULL;
	struct dns_ip_address *added_ip_addr = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_request *request = context->request;
	unsigned long bucket = 0;

	char *domain = NULL;
	int ret = 0;
	int ignore_speed = 0;
	int maxhit = 0;

	if (context->select_all_best_ip == 0 || context->ip_num >= request->conf->dns_max_reply_ip_num) {
		return 0;
	}

	domain = request->domain;
	/* add CNAME record */
	if (request->has_cname) {
		domain = request->cname;
	}

	/* add fasted ip address at first place of dns RR */
	if (request->has_ip) {
		added_ip_addr = _dns_ip_address_get(request, request->ip_addr, request->qtype);
		_dns_rrs_result_log(context, added_ip_addr);
	}

	if (request->passthrough == 2) {
		ignore_speed = 1;
	}

	while (true) {
		pthread_mutex_lock(&request->ip_map_lock);
		hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
		{
			if (context->ip_num >= request->conf->dns_max_reply_ip_num) {
				break;
			}

			if (context->qtype != addr_map->addr_type) {
				continue;
			}

			if (addr_map == added_ip_addr) {
				continue;
			}

			if (addr_map->hitnum > maxhit) {
				maxhit = addr_map->hitnum;
			}

			if (addr_map->ping_time < 0 && ignore_speed == 0) {
				continue;
			}

			if (addr_map->hitnum < maxhit && ignore_speed == 1) {
				continue;
			}

			/* if ping time is larger than 5ms, check again. */
			if (addr_map->ping_time - request->ping_time >= 50) {
				int ttl_range = request->ping_time + request->ping_time / 10 + 5;
				if ((ttl_range < addr_map->ping_time) && addr_map->ping_time >= 100 && ignore_speed == 0) {
					continue;
				}
			}

			_dns_server_context_add_ip(context, addr_map->ip_addr);
			if (addr_map->addr_type == DNS_T_A) {
				ret |= dns_add_A(context->packet, DNS_RRS_AN, domain, request->ip_ttl, addr_map->ip_addr);
			} else if (addr_map->addr_type == DNS_T_AAAA) {
				ret |= dns_add_AAAA(context->packet, DNS_RRS_AN, domain, request->ip_ttl, addr_map->ip_addr);
			}
			_dns_rrs_result_log(context, addr_map);
		}
		pthread_mutex_unlock(&request->ip_map_lock);

		if (context->ip_num <= 0 && ignore_speed == 0) {
			ignore_speed = 1;
		} else {
			break;
		}
	}

	return ret;
}

static int _dns_server_add_srv(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_srv_records *srv_records = request->srv_records;
	struct dns_srv_record *srv_record = NULL;
	int ret = 0;

	if (srv_records == NULL) {
		return 0;
	}

	list_for_each_entry(srv_record, &srv_records->list, list)
	{
		ret = dns_add_SRV(context->packet, DNS_RRS_AN, request->domain, request->ip_ttl, srv_record->priority,
						  srv_record->weight, srv_record->port, srv_record->host);
		if (ret != 0) {
			return -1;
		}
	}

	return 0;
}

static int _dns_add_rrs_ip_hint(struct dns_server_post_context *context, struct dns_rr_nested *param, dns_type_t qtype)
{
	typedef int (*addfunc)(struct dns_rr_nested *svcparam, unsigned char *addr[], int addr_num);
	struct dns_request *request = context->request;
	struct dns_ip_address *addr_map = NULL;
	unsigned long bucket = 0;
	struct hlist_node *tmp = NULL;
	int ret = 0;
	int all_ips = 0;
	int addr_num = 0;
	addfunc add_func = NULL;

	unsigned char *addr[8];
	int addr_buffer_size = sizeof(addr) / sizeof(addr[0]);

	if (qtype == DNS_T_A) {
		add_func = dns_HTTPS_add_ipv4hint;
	} else if (qtype == DNS_T_AAAA) {
		add_func = dns_HTTPS_add_ipv6hint;
	} else {
		return 0; // Unsupported type
	}

	if (request->passthrough == 2) {
		all_ips = 1;
	}

	if (request->has_ip == 0) {
		return 0;
	}

	if (all_ips == 0) {
		if (request->ip_addr_type == (int)qtype) {
			addr[0] = request->ip_addr;
			ret = add_func(param, addr, 1);

			return ret;
		}
		return 0;
	}

	ret = 0;
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each_safe(request->ip_map, bucket, tmp, addr_map, node)
	{
		if (addr_map->addr_type == qtype) {
			addr[addr_num] = addr_map->ip_addr;
			addr_num++;
			if (addr_num >= addr_buffer_size) {
				break;
			}
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	if (addr_num > 0) {
		ret = add_func(param, addr, addr_num);
	}

	return ret;
}

static int _dns_add_rrs_HTTPS(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_request_https *https_svcb = request->https_svcb;
	int ret = 0;
	struct dns_rr_nested param;

	if (https_svcb == NULL || request->qtype != DNS_T_HTTPS) {
		return 0;
	}

	ret = dns_add_HTTPS_start(&param, context->packet, DNS_RRS_AN, https_svcb->domain, https_svcb->ttl,
							  https_svcb->priority, https_svcb->target);
	if (ret != 0) {
		return ret;
	}

	if (https_svcb->alpn[0] != '\0' && https_svcb->alpn_len > 0) {
		ret = dns_HTTPS_add_alpn(&param, https_svcb->alpn, https_svcb->alpn_len);
		if (ret != 0) {
			return ret;
		}
	}

	if (https_svcb->port != 0) {
		ret = dns_HTTPS_add_port(&param, https_svcb->port);
		if (ret != 0) {
			return ret;
		}
	}

	ret = _dns_add_rrs_ip_hint(context, &param, DNS_T_A);
	if (ret != 0) {
		return ret;
	}

	if (https_svcb->ech_len > 0) {
		ret = dns_HTTPS_add_ech(&param, https_svcb->ech, https_svcb->ech_len);
		if (ret != 0) {
			return ret;
		}
	}

	ret = _dns_add_rrs_ip_hint(context, &param, DNS_T_AAAA);
	if (ret != 0) {
		return ret;
	}

	dns_add_HTTPS_end(&param);
	return 0;
}

static int _dns_add_rrs(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	int ret = 0;
	int has_soa = request->has_soa;
	char *domain = request->domain;
	if (request->has_ptr) {
		/* add PTR record */
		ret = dns_add_PTR(context->packet, DNS_RRS_AN, request->domain, request->ip_ttl, request->ptr_hostname);
	}

	/* add CNAME record */
	if (request->has_cname && context->do_force_soa == 0) {
		ret |= dns_add_CNAME(context->packet, DNS_RRS_AN, request->domain, request->ttl_cname, request->cname);
		domain = request->cname;
	}

	if (request->https_svcb != NULL) {
		ret = _dns_add_rrs_HTTPS(context);
	}

	/* add A record */
	if (request->has_ip && context->do_force_soa == 0) {
		_dns_server_context_add_ip(context, request->ip_addr);
		if (context->qtype == DNS_T_A) {
			ret |= dns_add_A(context->packet, DNS_RRS_AN, domain, request->ip_ttl, request->ip_addr);
			tlog(TLOG_DEBUG, "result: %s, rtt: %.1f ms, %d.%d.%d.%d", request->domain, ((float)request->ping_time) / 10,
				 request->ip_addr[0], request->ip_addr[1], request->ip_addr[2], request->ip_addr[3]);
		}

		/* add AAAA record */
		if (context->qtype == DNS_T_AAAA) {
			ret |= dns_add_AAAA(context->packet, DNS_RRS_AN, domain, request->ip_ttl, request->ip_addr);
			tlog(TLOG_DEBUG,
				 "result: %s, rtt: %.1f ms, "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, ((float)request->ping_time) / 10, request->ip_addr[0], request->ip_addr[1],
				 request->ip_addr[2], request->ip_addr[3], request->ip_addr[4], request->ip_addr[5],
				 request->ip_addr[6], request->ip_addr[7], request->ip_addr[8], request->ip_addr[9],
				 request->ip_addr[10], request->ip_addr[11], request->ip_addr[12], request->ip_addr[13],
				 request->ip_addr[14], request->ip_addr[15]);
		}
	}

	if (context->do_force_soa == 0) {
		ret |= _dns_rrs_add_all_best_ip(context);
	}

	if (context->qtype == DNS_T_A || context->qtype == DNS_T_AAAA) {
		if (context->ip_num > 0) {
			has_soa = 0;
		}
	}
	/* add SOA record */
	if (has_soa) {
		ret |= dns_add_SOA(context->packet, DNS_RRS_NS, domain, request->ip_ttl, &request->soa);
		tlog(TLOG_DEBUG, "result: %s, qtype: %d, return SOA", request->domain, context->qtype);
	} else if (context->do_force_soa == 1) {
		_dns_server_setup_soa(request);
		ret |= dns_add_SOA(context->packet, DNS_RRS_NS, domain, request->ip_ttl, &request->soa);
	}

	if (request->has_ecs) {
		ret |= dns_add_OPT_ECS(context->packet, &request->ecs);
	}

	if (request->srv_records != NULL) {
		ret |= _dns_server_add_srv(context);
	}

	if (request->rcode != DNS_RC_NOERROR) {
		tlog(TLOG_INFO, "result: %s, qtype: %d, rtcode: %d, id: %d", domain, context->qtype, request->rcode,
			 request->id);
	}

	return ret;
}

static int _dns_setup_dns_packet(struct dns_server_post_context *context)
{
	struct dns_head head;
	struct dns_request *request = context->request;
	int ret = 0;

	memset(&head, 0, sizeof(head));
	head.id = request->id;
	head.qr = DNS_QR_ANSWER;
	head.opcode = DNS_OP_QUERY;
	head.rd = 1;
	head.ra = 1;
	head.aa = 0;
	head.tc = 0;
	head.rcode = request->rcode;

	/* init a new DNS packet */
	ret = dns_packet_init(context->packet, context->packet_maxlen, &head);
	if (ret != 0) {
		return -1;
	}

	if (request->domain[0] == '\0') {
		return 0;
	}

	/* add request domain */
	ret = dns_add_domain(context->packet, request->domain, context->qtype, request->qclass);
	if (ret != 0) {
		return -1;
	}

	/* add RECORDs */
	ret = _dns_add_rrs(context);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

static int _dns_setup_dns_raw_packet(struct dns_server_post_context *context)
{
	/* encode to binary data */
	int encode_len = dns_encode(context->inpacket, context->inpacket_maxlen, context->packet);
	if (encode_len <= 0) {
		tlog(TLOG_DEBUG, "encode raw packet failed for %s", context->request->domain);
		return -1;
	}

	context->inpacket_len = encode_len;

	return 0;
}

static int _dns_result_callback(struct dns_server_post_context *context)
{
	struct dns_result result;
	char ip[DNS_MAX_CNAME_LEN];
	unsigned int ping_time = -1;
	struct dns_request *request = context->request;

	if (request->result_callback == NULL) {
		return 0;
	}

	if (atomic_inc_return(&request->do_callback) != 1) {
		return 0;
	}

	ip[0] = 0;
	memset(&result, 0, sizeof(result));
	ping_time = request->ping_time;
	result.domain = request->domain;
	result.rtcode = request->rcode;
	result.addr_type = request->qtype;
	result.ip = ip;
	result.has_soa = request->has_soa | context->do_force_soa;
	result.ping_time = ping_time;
	result.ip_num = 0;

	if (request->has_ip != 0 && context->do_force_soa == 0) {
		for (int i = 0; i < context->ip_num && i < MAX_IP_NUM; i++) {
			result.ip_addr[i] = context->ip_addr[i];
			result.ip_num++;
		}

		if (request->qtype == DNS_T_A) {
			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", request->ip_addr[0], request->ip_addr[1], request->ip_addr[2],
					 request->ip_addr[3]);
		} else if (request->qtype == DNS_T_AAAA) {
			snprintf(ip, sizeof(ip), "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
					 request->ip_addr[0], request->ip_addr[1], request->ip_addr[2], request->ip_addr[3],
					 request->ip_addr[4], request->ip_addr[5], request->ip_addr[6], request->ip_addr[7],
					 request->ip_addr[8], request->ip_addr[9], request->ip_addr[10], request->ip_addr[11],
					 request->ip_addr[12], request->ip_addr[13], request->ip_addr[14], request->ip_addr[15]);
		}
	}

	return request->result_callback(&result, request->user_ptr);
}

static int _dns_server_setup_ipset_nftset_packet(struct dns_server_post_context *context)
{
	int ttl = 0;
	struct dns_request *request = context->request;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	int timeout_value = 0;
	int ipset_timeout_value = 0;
	int nftset_timeout_value = 0;
	int i = 0;
	int j = 0;
	struct dns_conf_group *conf;
	struct dns_rrs *rrs = NULL;
	struct dns_ipset_rule *rule = NULL;
	struct dns_ipset_rule *ipset_rule = NULL;
	struct dns_ipset_rule *ipset_rule_v4 = NULL;
	struct dns_ipset_rule *ipset_rule_v6 = NULL;
	struct dns_nftset_rule *nftset_ip = NULL;
	struct dns_nftset_rule *nftset_ip6 = NULL;
	struct dns_rule_flags *rule_flags = NULL;
	int check_no_speed_rule = 0;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_IPSET) == 0) {
		return 0;
	}

	if (context->do_ipset == 0) {
		return 0;
	}

	if (context->ip_num <= 0) {
		return 0;
	}

	if (request->ping_time < 0 && request->has_ip > 0 && request->passthrough == 0) {
		check_no_speed_rule = 1;
	}

	conf = request->conf;

	/* check ipset rule */
	rule_flags = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IGN) == 0) {
		ipset_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_IPSET);
		if (ipset_rule == NULL) {
			ipset_rule = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_IPSET);
		}

		if (ipset_rule == NULL && check_no_speed_rule && conf->ipset_nftset.ipset_no_speed.inet_enable) {
			ipset_rule_v4 = &conf->ipset_nftset.ipset_no_speed.inet;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV4_IGN) == 0) {
		ipset_rule_v4 = _dns_server_get_dns_rule(request, DOMAIN_RULE_IPSET_IPV4);
		if (ipset_rule_v4 == NULL) {
			ipset_rule_v4 = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_IPSET_IPV4);
		}

		if (ipset_rule_v4 == NULL && check_no_speed_rule && conf->ipset_nftset.ipset_no_speed.ipv4_enable) {
			ipset_rule_v4 = &conf->ipset_nftset.ipset_no_speed.ipv4;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_IPSET_IPV6_IGN) == 0) {
		ipset_rule_v6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_IPSET_IPV6);
		if (ipset_rule_v6 == NULL) {
			ipset_rule_v6 = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_IPSET_IPV6);
		}

		if (ipset_rule_v6 == NULL && check_no_speed_rule && conf->ipset_nftset.ipset_no_speed.ipv6_enable) {
			ipset_rule_v6 = &conf->ipset_nftset.ipset_no_speed.ipv6;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_NFTSET_IP_IGN) == 0) {
		nftset_ip = _dns_server_get_dns_rule(request, DOMAIN_RULE_NFTSET_IP);
		if (nftset_ip == NULL) {
			nftset_ip = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_NFTSET_IP);
		}

		if (nftset_ip == NULL && check_no_speed_rule && conf->ipset_nftset.nftset_no_speed.ip_enable) {
			nftset_ip = &conf->ipset_nftset.nftset_no_speed.ip;
		}
	}

	if (!rule_flags || (rule_flags->flags & DOMAIN_FLAG_NFTSET_IP6_IGN) == 0) {
		nftset_ip6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_NFTSET_IP6);

		if (nftset_ip6 == NULL) {
			nftset_ip6 = _dns_server_get_bind_ipset_nftset_rule(request, DOMAIN_RULE_NFTSET_IP6);
		}

		if (nftset_ip6 == NULL && check_no_speed_rule && conf->ipset_nftset.nftset_no_speed.ip6_enable) {
			nftset_ip6 = &conf->ipset_nftset.nftset_no_speed.ip6;
		}
	}

	if (!(ipset_rule || ipset_rule_v4 || ipset_rule_v6 || nftset_ip || nftset_ip6)) {
		return 0;
	}

	timeout_value = request->ip_ttl * 3;
	if (timeout_value == 0) {
		timeout_value = _dns_server_get_conf_ttl(request, 0) * 3;
	}

	if (conf->ipset_nftset.ipset_timeout_enable) {
		ipset_timeout_value = timeout_value;
	}

	if (conf->ipset_nftset.nftset_timeout_enable) {
		nftset_timeout_value = timeout_value;
	}

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(context->packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(context->packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				if (context->qtype != DNS_T_A) {
					break;
				}
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
				_dns_server_add_ipset_nftset(request, rule, nftset_ip, addr, DNS_RR_A_LEN, ipset_timeout_value,
											 nftset_timeout_value);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				if (context->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					break;
				}
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				rule = ipset_rule_v6 ? ipset_rule_v6 : ipset_rule;
				_dns_server_add_ipset_nftset(request, rule, nftset_ip6, addr, DNS_RR_AAAA_LEN, ipset_timeout_value,
											 nftset_timeout_value);
			} break;
			case DNS_T_HTTPS: {
				char target[DNS_MAX_CNAME_LEN] = {0};
				struct dns_https_param *p = NULL;
				int priority = 0;

				int ret = dns_get_HTTPS_svcparm_start(rrs, &p, name, DNS_MAX_CNAME_LEN, &ttl, &priority, target,
													  DNS_MAX_CNAME_LEN);
				if (ret != 0) {
					tlog(TLOG_WARN, "get HTTPS svcparm failed");
					return -1;
				}

				for (; p; p = dns_get_HTTPS_svcparm_next(rrs, p)) {
					switch (p->key) {
					case DNS_HTTPS_T_IPV4HINT: {
						unsigned char *addr;
						for (int k = 0; k < p->len / 4; k++) {
							addr = p->value + k * 4;
							rule = ipset_rule_v4 ? ipset_rule_v4 : ipset_rule;
							_dns_server_add_ipset_nftset(request, rule, nftset_ip, addr, DNS_RR_A_LEN,
														 ipset_timeout_value, nftset_timeout_value);
						}
					} break;
					case DNS_HTTPS_T_IPV6HINT: {
						unsigned char *addr;
						for (int k = 0; k < p->len / 16; k++) {
							addr = p->value + k * 16;
							rule = ipset_rule_v6 ? ipset_rule_v6 : ipset_rule;
							_dns_server_add_ipset_nftset(request, rule, nftset_ip6, addr, DNS_RR_AAAA_LEN,
														 ipset_timeout_value, nftset_timeout_value);
						}
					} break;
					default:
						break;
					}
				}
			} break;
			default:
				break;
			}
		}
	}

	return 0;
}

static int _dns_result_child_post(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	struct dns_request *parent_request = request->parent_request;
	DNS_CHILD_POST_RESULT child_ret = DNS_CHILD_POST_FAIL;

	/* not a child request */
	if (parent_request == NULL) {
		return 0;
	}

	if (request->child_callback) {
		int is_first_resp = context->no_release_parent;
		child_ret = request->child_callback(parent_request, request, is_first_resp);
	}

	if (context->do_reply == 1 && child_ret == DNS_CHILD_POST_SUCCESS) {
		struct dns_server_post_context parent_context;
		_dns_server_post_context_init(&parent_context, parent_request);
		parent_context.do_cache = context->do_cache;
		parent_context.do_ipset = context->do_ipset;
		parent_context.do_force_soa = context->do_force_soa;
		parent_context.do_audit = context->do_audit;
		parent_context.do_reply = context->do_reply;
		parent_context.reply_ttl = context->reply_ttl;
		parent_context.cache_ttl = context->cache_ttl;
		parent_context.skip_notify_count = context->skip_notify_count;
		parent_context.select_all_best_ip = 1;
		parent_context.no_release_parent = context->no_release_parent;

		_dns_request_post(&parent_context);
		_dns_server_reply_all_pending_list(parent_request, &parent_context);
	}

	if (context->no_release_parent == 0) {
		tlog(TLOG_DEBUG, "query %s with child %s done", parent_request->domain, request->domain);
		request->parent_request = NULL;
		parent_request->request_wait--;
		_dns_server_request_release(parent_request);
	}

	if (child_ret == DNS_CHILD_POST_FAIL) {
		return -1;
	}

	return 0;
}

static int _dns_request_update_id_ttl_domain(struct dns_server_post_context *context)
{
	int ttl = context->reply_ttl;
	struct dns_request *request = context->request;

	if (request->conf->dns_rr_ttl_reply_max > 0) {
		if (request->ip_ttl > request->conf->dns_rr_ttl_reply_max && ttl == 0) {
			ttl = request->ip_ttl;
		}

		if (ttl > request->conf->dns_rr_ttl_reply_max) {
			ttl = request->conf->dns_rr_ttl_reply_max;
		}

		if (ttl == 0) {
			ttl = request->conf->dns_rr_ttl_reply_max;
		}
	}

	if (ttl == 0) {
		ttl = request->ip_ttl;
		if (ttl == 0) {
			ttl = _dns_server_get_conf_ttl(request, ttl);
		}
	}

	struct dns_update_param param;
	param.id = request->id;
	param.cname_ttl = ttl;
	param.ip_ttl = ttl;
	param.query_domain = request->original_domain;
	if (dns_packet_update(context->inpacket, context->inpacket_len, &param) != 0) {
		tlog(TLOG_DEBUG, "update packet info failed.");
	}

	return 0;
}

int _dns_request_post(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	char clientip[DNS_MAX_CNAME_LEN] = {0};
	int ret = 0;

	tlog(TLOG_DEBUG, "reply %s qtype: %d, rcode: %d, reply: %d", request->domain, request->qtype,
		 context->packet->head.rcode, context->do_reply);

	/* init a new DNS packet */
	ret = _dns_setup_dns_packet(context);
	if (ret != 0) {
		tlog(TLOG_ERROR, "setup dns packet failed.");
		return -1;
	}

	ret = _dns_setup_dns_raw_packet(context);
	if (ret != 0) {
		tlog(TLOG_ERROR, "set dns raw packet failed.");
		return -1;
	}

	/* cache reply packet */
	ret = _dns_cache_reply_packet(context);
	if (ret != 0) {
		tlog(TLOG_WARN, "cache packet for %s failed.", request->domain);
	}

	/* setup ipset */
	_dns_server_setup_ipset_nftset_packet(context);

	/* reply child request */
	_dns_result_child_post(context);

	if (context->do_reply == 0) {
		return 0;
	}

	if (context->skip_notify_count == 0) {
		if (atomic_inc_return(&request->notified) != 1) {
			tlog(TLOG_DEBUG, "skip reply %s %d", request->domain, request->qtype);
			return 0;
		}
	}

	/* log audit log */
	_dns_server_audit_log(context);

	/* reply API callback */
	_dns_result_callback(context);

	if (request->conn == NULL) {
		return 0;
	}

	ret = _dns_request_update_id_ttl_domain(context);
	if (ret != 0) {
		tlog(TLOG_ERROR, "update packet ttl failed.");
		return -1;
	}

	tlog(TLOG_INFO, "result: %s, client: %s, qtype: %d, id: %d, group: %s, time: %lums", request->domain,
		 get_host_by_addr(clientip, sizeof(clientip), (struct sockaddr *)&request->addr), request->qtype, request->id,
		 request->dns_group_name[0] != '\0' ? request->dns_group_name : DNS_SERVER_GROUP_DEFAULT,
		 get_tick_count() - request->send_tick);

	ret = _dns_reply_inpacket(request, context->inpacket, context->inpacket_len);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "reply raw packet to client failed.");
		return -1;
	}

	return 0;
}

int _dns_server_get_answer(struct dns_server_post_context *context)
{
	int i = 0;
	int j = 0;
	int ttl = 0;
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	struct dns_request *request = context->request;
	struct dns_packet *packet = context->packet;

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				char name[DNS_MAX_CNAME_LEN] = {0};
				struct dns_ip_address *addr_map = NULL;

				if (request->qtype != DNS_T_A) {
					continue;
				}

				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				if (context->no_check_add_ip == 0 &&
					_dns_ip_address_check_add(request, name, addr, DNS_T_A, request->ping_time, &addr_map) != 0) {
					continue;
				}

				if (addr_map != NULL) {
					_dns_server_context_add_ip(context, addr_map->ip_addr);
				}

				if (request->has_ip == 1) {
					continue;
				}

				memcpy(request->ip_addr, addr, DNS_RR_A_LEN);
				/* add this ip to request */
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
				request->has_ip = 1;
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				char name[DNS_MAX_CNAME_LEN] = {0};
				struct dns_ip_address *addr_map = NULL;

				if (request->qtype != DNS_T_AAAA) {
					/* ignore non-matched query type */
					continue;
				}
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				if (context->no_check_add_ip == 0 &&
					_dns_ip_address_check_add(request, name, addr, DNS_T_AAAA, request->ping_time, &addr_map) != 0) {
					continue;
				}

				if (addr_map != NULL) {
					_dns_server_context_add_ip(context, addr_map->ip_addr);
				}

				if (request->has_ip == 1) {
					continue;
				}

				memcpy(request->ip_addr, addr, DNS_RR_AAAA_LEN);
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
				request->has_ip = 1;
				request->rcode = packet->head.rcode;
			} break;
			case DNS_T_NS: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "NS: %s, ttl: %d, cname: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				if (request->conf->dns_force_no_cname) {
					continue;
				}

				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "name: %s, ttl: %d, cname: %s\n", name, ttl, cname);
				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = _dns_server_get_conf_ttl(request, ttl);
				request->has_cname = 1;
			} break;
			case DNS_T_SOA: {
				char name[DNS_MAX_CNAME_LEN] = {0};
				request->has_soa = 1;
				if (request->rcode != DNS_RC_NOERROR) {
					request->rcode = packet->head.rcode;
				}
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_DEBUG,
					 "domain: %s, qtype: %d, SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, "
					 "expire: "
					 "%d, minimum: %d",
					 request->domain, request->qtype, request->soa.mname, request->soa.rname, request->soa.serial,
					 request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			} break;
			default:
				break;
			}
		}
	}

	return 0;
}

int _dns_cache_reply_packet(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;
	int speed = -1;
	if (context->do_cache == 0 || request->no_cache == 1) {
		return 0;
	}

	if (context->packet->head.rcode == DNS_RC_SERVFAIL || context->packet->head.rcode == DNS_RC_NXDOMAIN ||
		context->packet->head.rcode == DNS_RC_NOTIMP) {
		context->reply_ttl = DNS_SERVER_FAIL_TTL;
		/* Do not cache record if cannot connect to remote */
		if (request->remote_server_fail == 0 && context->packet->head.rcode == DNS_RC_SERVFAIL) {
			/* Try keep old cache if server fail */
			_dns_cache_try_keep_old_cache(request);
			return 0;
		}

		if (context->packet->head.rcode == DNS_RC_NOTIMP) {
			return 0;
		}

		if (context->packet->head.rcode == DNS_RC_NXDOMAIN) {
			context->reply_ttl = 0;
		}

		return _dns_cache_packet(context);
	}

	if (context->qtype != DNS_T_AAAA && context->qtype != DNS_T_A && context->qtype != DNS_T_HTTPS) {
		return _dns_cache_specify_packet(context);
	}

	struct dns_cache_data *cache_packet = dns_cache_new_data_packet(context->inpacket, context->inpacket_len);
	if (cache_packet == NULL) {
		return -1;
	}

	speed = request->ping_time;
	if (context->do_force_soa) {
		speed = -1;
	}

	if (_dns_server_request_update_cache(request, speed, context->qtype, cache_packet, context->cache_ttl) != 0) {
		tlog(TLOG_WARN, "update packet cache failed.");
	}

	_dns_cache_cname_packet(context);

	return 0;
}

int _dns_server_reply_passthrough(struct dns_server_post_context *context)
{
	struct dns_request *request = context->request;

	if (atomic_inc_return(&request->notified) != 1) {
		return 0;
	}

	_dns_server_get_answer(context);

	_dns_cache_reply_packet(context);

	if (_dns_server_setup_ipset_nftset_packet(context) != 0) {
		tlog(TLOG_DEBUG, "setup ipset failed.");
	}

	_dns_result_callback(context);

	_dns_server_audit_log(context);

	/* reply child request */
	_dns_result_child_post(context);

	if (request->conn && context->do_reply == 1) {
		char clientip[DNS_MAX_CNAME_LEN] = {0};

		/* When passthrough, modify the id to be the id of the client request. */
		int ret = _dns_request_update_id_ttl_domain(context);
		if (ret != 0) {
			tlog(TLOG_ERROR, "update packet ttl failed.");
			return -1;
		}

		_dns_reply_inpacket(request, context->inpacket, context->inpacket_len);

		tlog(TLOG_INFO, "result: %s, client: %s, qtype: %d, id: %d, group: %s, time: %lums", request->domain,
			 get_host_by_addr(clientip, sizeof(clientip), (struct sockaddr *)&request->addr), request->qtype,
			 request->id, request->dns_group_name[0] != '\0' ? request->dns_group_name : DNS_SERVER_GROUP_DEFAULT,
			 get_tick_count() - request->send_tick);
	}

	return _dns_server_reply_all_pending_list(request, context);
}
