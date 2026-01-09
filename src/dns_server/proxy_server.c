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

#include "proxy_server.h"
#include "context.h"
#include "dns_server.h"
#include "request.h"
#include "rules.h"
#include "soa.h"

static int _dns_server_update_proxy_request_rules(struct dns_request *request, struct dns_proxy_rule *proxy_rule)
{
	int force_aaaa_soa = 0;
	if (proxy_rule == NULL || request == NULL) {
		return -1;
	}

	const char *proxy_name = proxy_rule->proxy_name;
	if (proxy_name == NULL || proxy_name[0] == '\0') {
		return -1;
	}

	if (proxy_rule->proxy_type == PROXY_TYPE_SNI_PROXY) {
		struct dns_sniproxy_server_conf *t_conf = dns_conf_get_sniproxy_server(proxy_name);
		if (t_conf == NULL) {
			return -1;
		}
		request->passthrough = !t_conf->speed_check;
		force_aaaa_soa = t_conf->force_aaaa_soa;
	} else if (proxy_rule->proxy_type == PROXY_TYPE_TPROXY) {
		struct dns_tproxy_server_conf *s_conf = dns_conf_get_tproxy_server(proxy_name);
		if (s_conf == NULL) {
			return -1;
		}
		request->passthrough = !s_conf->speed_check;
		force_aaaa_soa = s_conf->force_aaaa_soa;
	} else {
		return -1;
	}

	if (force_aaaa_soa && request->qtype == DNS_T_AAAA) {
		request->force_soa = force_aaaa_soa;
	}

	return 0;
}

int _dns_server_process_proxyserver(struct dns_request *request)
{
	struct sockaddr_in *addr_in = NULL;
	struct sockaddr_in6 *addr_in6 = NULL;
	struct sockaddr_storage *localaddr;
	struct dns_server_conn_head *conn = NULL;
	struct dns_proxy_rule *proxy_rule = NULL;

	conn = request->conn;
	if (conn == NULL) {
		goto errout;
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_SNIPROXY) == 0) {
		goto errout;
	}

	localaddr = &request->localaddr;

	proxy_rule = (struct dns_proxy_rule *)_dns_server_get_dns_rule(request, DOMAIN_RULE_PROXY);
	if (proxy_rule == NULL) {
		goto errout;
	}

	/* update speed check by proxy rule */
	_dns_server_update_proxy_request_rules(request, proxy_rule);

	if (request->force_soa) {
		_dns_server_reply_SOA(DNS_RC_NOERROR, request);
		return 0;
	}

	if (proxy_rule->proxy_type != PROXY_TYPE_SNI_PROXY) {
		goto errout;
	}

	/* address /domain/ rule */
	switch (request->qtype) {
	case DNS_T_A:
		if (localaddr->ss_family != AF_INET) {
			_dns_server_reply_SOA(DNS_RC_NOERROR, request);
			return 0;
		}
		addr_in = (struct sockaddr_in *)localaddr;
		memcpy(request->ip_addr, &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
		break;
	case DNS_T_AAAA:
		if (localaddr->ss_family != AF_INET6) {
			_dns_server_reply_SOA(DNS_RC_NOERROR, request);
			return 0;
		}
		addr_in6 = (struct sockaddr_in6 *)localaddr;
		memcpy(request->ip_addr, &addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
		break;
	default:
		goto errout;
		break;
	}

	request->ip_ttl = 600;
	request->has_ip = 1;

	request->rcode = DNS_RC_NOERROR;
	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	_dns_request_post(&context);

	return 0;
errout:
	return -1;
}

void _dns_server_request_set_no_proxyserver(struct dns_request *request)
{
	request->noproxy = 1;
}

const char *_dns_server_get_proxy_server_groupname(struct dns_request *request)
{
	struct dns_proxy_rule *proxy_rule = NULL;
	const char *group_name = NULL;

	if (request == NULL) {
		return NULL;
	}

	if (request->noproxy) {
		return NULL;
	}

	proxy_rule = (struct dns_proxy_rule *)_dns_server_get_dns_rule(request, DOMAIN_RULE_PROXY);
	if (proxy_rule == NULL) {
		return NULL;
	}

	if (proxy_rule->proxy_type == PROXY_TYPE_SNI_PROXY) {
		struct dns_sniproxy_server_conf *s_conf = dns_conf_get_sniproxy_server(proxy_rule->proxy_name);
		if (s_conf != NULL) {
			group_name = s_conf->group_name;
		}
	} else if (proxy_rule->proxy_type == PROXY_TYPE_TPROXY) {
		struct dns_tproxy_server_conf *t_conf = dns_conf_get_tproxy_server(proxy_rule->proxy_name);
		if (t_conf != NULL) {
			group_name = t_conf->group_name;
		}
	}

	return group_name;
}