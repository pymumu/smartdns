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
#include "dualstack.h"
#include "request.h"
#include "rules.h"
#include "smartdns/fast_ping.h"

#include <errno.h>
#include <string.h>

int is_ipv6_ready;

int dns_is_ipv6_ready(void)
{
	return is_ipv6_ready;
}

void dns_server_check_ipv6_ready(void)
{
	static int do_get_conf = 0;
	static int is_icmp_check_set;
	static int is_tcp_check_set;

	if (do_get_conf == 0) {
		if (dns_conf.has_icmp_check == 1) {
			is_icmp_check_set = 1;
		}

		if (dns_conf.has_tcp_check == 1) {
			is_tcp_check_set = 1;
		}

		if (is_icmp_check_set == 0) {
			tlog(TLOG_INFO, "ICMP ping is disabled, no ipv6 icmp check feature");
		}

		do_get_conf = 1;
	}

	if (is_icmp_check_set) {
		struct ping_host_struct *check_ping = fast_ping_start(PING_TYPE_ICMP, "2001::", 1, 0, 100, NULL, NULL);
		if (check_ping) {
			fast_ping_stop(check_ping);
			is_ipv6_ready = 1;
			return;
		}

		if (errno == EADDRNOTAVAIL) {
			is_ipv6_ready = 0;
			return;
		}
	}

	if (is_tcp_check_set) {
		struct ping_host_struct *check_ping = fast_ping_start(PING_TYPE_TCP, "2001::", 1, 0, 100, NULL, NULL);
		if (check_ping) {
			fast_ping_stop(check_ping);
			is_ipv6_ready = 1;
			return;
		}

		if (errno == EADDRNOTAVAIL) {
			is_ipv6_ready = 0;
			return;
		}
	}
}

void _dns_server_set_dualstack_selection(struct dns_request *request)
{
	struct dns_rule_flags *rule_flag = NULL;

	if (request->dualstack_selection_query || is_ipv6_ready == 0) {
		request->dualstack_selection = 0;
		return;
	}

	if ((request->prefetch_flags & PREFETCH_FLAGS_NO_DUALSTACK) != 0 ||
		(request->prefetch_flags & PREFETCH_FLAGS_EXPIRED) != 0) {
		request->dualstack_selection = 0;
		return;
	}

	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag) {
		if (rule_flag->flags & DOMAIN_FLAG_DUALSTACK_SELECT) {
			request->dualstack_selection = 1;
			return;
		}

		if (rule_flag->is_flag_set & DOMAIN_FLAG_DUALSTACK_SELECT) {
			request->dualstack_selection = 0;
			return;
		}
	}

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_DUALSTACK_SELECTION) == 0) {
		request->dualstack_selection = 0;
		return;
	}

	request->dualstack_selection = request->conf->dualstack_ip_selection;
}

static void _dns_server_check_complete_dualstack(struct dns_request *request, struct dns_request *dualstack_request)
{
	if (dualstack_request == NULL || request == NULL) {
		return;
	}

	if (dualstack_request->qtype == DNS_T_A && request->conf->dns_dualstack_ip_allow_force_AAAA == 0) {
		return;
	}

	if (dualstack_request->ping_time > 0) {
		return;
	}

	if (dualstack_request->dualstack_selection_query == 1) {
		return;
	}

	if (request->ping_time <= (request->conf->dns_dualstack_ip_selection_threshold * 10)) {
		return;
	}

	dualstack_request->dualstack_selection_has_ip = request->has_ip;
	dualstack_request->dualstack_selection_ping_time = request->ping_time;
	dualstack_request->dualstack_selection_force_soa = 1;
	_dns_server_request_complete(dualstack_request);
}

int _dns_server_force_dualstack(struct dns_request *request)
{
	/* for dualstack request as first pending request, check if need to choose another request*/
	if (request->dualstack_request) {
		struct dns_request *dualstack_request = request->dualstack_request;
		request->dualstack_selection_has_ip = dualstack_request->has_ip;
		request->dualstack_selection_ping_time = dualstack_request->ping_time;
		request->dualstack_selection = 1;
		/* if another request still waiting for ping, force complete another request */
		_dns_server_check_complete_dualstack(request, dualstack_request);
	}

	if (request->dualstack_selection_ping_time < 0 || request->dualstack_selection == 0) {
		return -1;
	}

	if (request->has_soa || request->rcode != DNS_RC_NOERROR) {
		return -1;
	}

	if (request->dualstack_selection_has_ip == 0) {
		return -1;
	}

	if (request->ping_time > 0) {
		if (request->dualstack_selection_ping_time + (request->conf->dns_dualstack_ip_selection_threshold * 10) >
			request->ping_time) {
			return -1;
		}
	}

	if (request->qtype == DNS_T_A && request->conf->dns_dualstack_ip_allow_force_AAAA == 0) {
		return -1;
	}

	/* if ipv4 is fasting than ipv6, add ipv4 to cache, and return SOA for AAAA request */
	tlog(TLOG_INFO, "result: %s, qtype: %d, force %s preferred, id: %d, time1: %d, time2: %d", request->domain,
		 request->qtype, request->qtype == DNS_T_AAAA ? "IPv4" : "IPv6", request->id, request->ping_time,
		 request->dualstack_selection_ping_time);
	request->dualstack_selection_force_soa = 1;

	return 0;
}

static int dns_server_dualstack_callback(const struct dns_result *result, void *user_ptr)
{
	struct dns_request *request = (struct dns_request *)user_ptr;
	tlog(TLOG_DEBUG, "dualstack result: domain: %s, ip: %s, type: %d, ping: %d, rcode: %d", result->domain, result->ip,
		 result->addr_type, result->ping_time, result->rtcode);
	if (request == NULL) {
		return -1;
	}

	if (result->rtcode == DNS_RC_NOERROR && result->ip[0] != 0) {
		request->dualstack_selection_has_ip = 1;
	}

	request->dualstack_selection_ping_time = result->ping_time;

	_dns_server_query_end(request);

	return 0;
}

int _dns_server_query_dualstack(struct dns_request *request)
{
	int ret = -1;
	struct dns_request *request_dualstack = NULL;
	dns_type_t qtype = request->qtype;

	if (request->dualstack_selection == 0) {
		return 0;
	}

	if (qtype == DNS_T_A) {
		qtype = DNS_T_AAAA;
	} else if (qtype == DNS_T_AAAA) {
		qtype = DNS_T_A;
	} else {
		return 0;
	}

	request_dualstack = _dns_server_new_request();
	if (request_dualstack == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	request_dualstack->server_flags = request->server_flags;
	safe_strncpy(request_dualstack->dns_group_name, request->dns_group_name, sizeof(request->dns_group_name));
	safe_strncpy(request_dualstack->domain, request->domain, sizeof(request->domain));
	request_dualstack->qtype = qtype;
	request_dualstack->dualstack_selection_query = 1;
	request_dualstack->has_cname_loop = request->has_cname_loop;
	request_dualstack->prefetch = request->prefetch;
	request_dualstack->prefetch_flags = request->prefetch_flags;
	request_dualstack->conf = request->conf;
	_dns_server_request_get(request);
	request_dualstack->dualstack_request = request;
	_dns_server_request_set_callback(request_dualstack, dns_server_dualstack_callback, request);
	request->request_wait++;
	ret = _dns_server_do_query(request_dualstack, 0);
	if (ret != 0) {
		request->request_wait--;
		tlog(TLOG_DEBUG, "do query %s type %d failed.\n", request->domain, qtype);
		goto errout;
	}

	_dns_server_request_release(request_dualstack);
	return ret;
errout:
	if (request_dualstack) {
		_dns_server_request_set_callback(request_dualstack, NULL, NULL);
		_dns_server_request_release(request_dualstack);
	}

	_dns_server_request_release(request);

	return ret;
}
