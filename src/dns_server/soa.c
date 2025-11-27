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

#include "soa.h"
#include "context.h"
#include "dns_server.h"
#include "request.h"
#include "rules.h"

#include "smartdns/dns_stats.h"

int _dns_server_is_return_soa_qtype(struct dns_request *request, dns_type_t qtype)
{
	uint32_t flags = _dns_server_get_rule_flags(request);

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_SOA) == 0) {
		/* when both has no rule SOA and force AAAA soa, force AAAA soa has high priority */
		if (qtype == DNS_T_AAAA && _dns_server_has_bind_flag(request, BIND_FLAG_FORCE_AAAA_SOA) == 0) {
			return 1;
		}

		return 0;
	}

	if (flags & DOMAIN_FLAG_ADDR_IGN) {
		request->skip_qtype_soa = 1;
		return 0;
	}

	if (flags & DOMAIN_FLAG_ADDR_SOA) {
		stats_inc(&dns_stats.request.blocked_count);
		return 1;
	}

	switch (qtype) {
	case DNS_T_A:
		if (flags & DOMAIN_FLAG_ADDR_IPV4_SOA) {
			stats_inc(&dns_stats.request.blocked_count);
			return 1;
		}

		if (flags & DOMAIN_FLAG_ADDR_IPV4_IGN) {
			request->skip_qtype_soa = 1;
			return 0;
		}
		break;
	case DNS_T_AAAA:
		if (flags & DOMAIN_FLAG_ADDR_IPV6_SOA) {
			stats_inc(&dns_stats.request.blocked_count);
			return 1;
		}

		if (flags & DOMAIN_FLAG_ADDR_IPV6_IGN) {
			request->skip_qtype_soa = 1;
			return 0;
		}
		break;
	case DNS_T_HTTPS:
		if (flags & DOMAIN_FLAG_ADDR_HTTPS_SOA) {
			stats_inc(&dns_stats.request.blocked_count);
			return 1;
		}

		if (flags & DOMAIN_FLAG_ADDR_HTTPS_IGN) {
			request->skip_qtype_soa = 1;
			return 0;
		}
		break;
	default:
		break;
	}

	if (qtype == DNS_T_AAAA) {
		if (_dns_server_has_bind_flag(request, BIND_FLAG_FORCE_AAAA_SOA) == 0 || request->conf->force_AAAA_SOA == 1) {
			return 1;
		}

		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] != NULL &&
			request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] == NULL) {
			return 1;
		}
	} else if (qtype == DNS_T_A) {
		if (request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV6] != NULL &&
			request->domain_rule.rules[DOMAIN_RULE_ADDRESS_IPV4] == NULL) {
			return 1;
		}
	} else if (qtype == DNS_T_HTTPS) {
		if (request->domain_rule.rules[DOMAIN_RULE_HTTPS] == NULL) {
			return 1;
		}
	}

	return 0;
}

int _dns_server_reply_SOA_ext(int rcode, struct dns_request *request)
{
	/* return SOA record */
	request->rcode = rcode;
	if (request->ip_ttl <= 0) {
		request->ip_ttl = DNS_SERVER_SOA_TTL;
	}
	request->has_soa = 1;

	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_audit = 1;
	context.do_reply = 1;
	context.do_force_soa = 1;
	_dns_request_post(&context);

	return 0;
}

int _dns_server_reply_SOA(int rcode, struct dns_request *request)
{
	_dns_server_setup_soa(request);
	return _dns_server_reply_SOA_ext(rcode, request);
}

int _dns_server_qtype_soa(struct dns_request *request)
{
	if (request->skip_qtype_soa || request->conf->soa_table == NULL) {
		return -1;
	}

	if (request->qtype >= 0 && request->qtype <= MAX_QTYPE_NUM) {
		int offset = request->qtype / 8;
		int bit = request->qtype % 8;
		if ((request->conf->soa_table[offset] & (1 << bit)) == 0) {
			return -1;
		}
	}

	_dns_server_reply_SOA(DNS_RC_NOERROR, request);
	tlog(TLOG_DEBUG, "force qtype %d soa", request->qtype);
	return 0;
}

int _dns_server_is_return_soa(struct dns_request *request)
{
	return _dns_server_is_return_soa_qtype(request, request->qtype);
}

void _dns_server_setup_soa(struct dns_request *request)
{
	struct dns_soa *soa = NULL;
	soa = &request->soa;

	safe_strncpy(soa->mname, "a.gtld-servers.net", DNS_MAX_CNAME_LEN);
	safe_strncpy(soa->rname, "nstld.verisign-grs.com", DNS_MAX_CNAME_LEN);
	soa->serial = 1800;
	soa->refresh = 1800;
	soa->retry = 900;
	soa->expire = 604800;
	soa->minimum = 86400;
}
