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

#include "cname.h"
#include "request.h"
#include "rules.h"

static DNS_CHILD_POST_RESULT _dns_server_process_cname_callback(struct dns_request *request,
																struct dns_request *child_request, int is_first_resp)
{
	_dns_server_request_copy(request, child_request);
	if (child_request->rcode == DNS_RC_NOERROR && request->conf->dns_force_no_cname == 0 &&
		child_request->has_soa == 0) {
		safe_strncpy(request->cname, child_request->domain, sizeof(request->cname));
		request->has_cname = 1;
		request->ttl_cname = _dns_server_get_conf_ttl(request, child_request->ip_ttl);
	}

	return DNS_CHILD_POST_SUCCESS;
}

int _dns_server_process_cname_pre(struct dns_request *request)
{
	struct dns_cname_rule *cname = NULL;
	struct dns_rule_flags *rule_flag = NULL;
	struct dns_request_domain_rule domain_rule;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_CNAME) == 0) {
		return 0;
	}

	if (request->has_cname_loop == 1) {
		return 0;
	}

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag != NULL) {
		if (rule_flag->flags & DOMAIN_FLAG_CNAME_IGN) {
			return 0;
		}
	}

	cname = _dns_server_get_dns_rule(request, DOMAIN_RULE_CNAME);
	if (cname == NULL) {
		return 0;
	}

	request->skip_domain_rule = 0;
	/* copy child rules */
	memcpy(&domain_rule, &request->domain_rule, sizeof(domain_rule));
	memset(&request->domain_rule, 0, sizeof(request->domain_rule));
	_dns_server_get_domain_rule_by_domain(request, cname->cname, 0);
	request->domain_rule.rules[DOMAIN_RULE_CNAME] = domain_rule.rules[DOMAIN_RULE_CNAME];
	request->domain_rule.is_sub_rule[DOMAIN_RULE_CNAME] = domain_rule.is_sub_rule[DOMAIN_RULE_CNAME];

	request->no_select_possible_ip = 1;
	request->no_cache_cname = 1;
	safe_strncpy(request->cname, cname->cname, sizeof(request->cname));

	return 0;
}

int _dns_server_process_cname(struct dns_request *request)
{
	struct dns_cname_rule *cname = NULL;
	const char *child_group_name = NULL;
	int ret = 0;
	struct dns_rule_flags *rule_flag = NULL;

	if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_CNAME) == 0) {
		return 0;
	}

	if (request->has_cname_loop == 1) {
		return 0;
	}

	/* get domain rule flag */
	rule_flag = _dns_server_get_dns_rule(request, DOMAIN_RULE_FLAGS);
	if (rule_flag != NULL) {
		if (rule_flag->flags & DOMAIN_FLAG_CNAME_IGN) {
			return 0;
		}
	}

	cname = _dns_server_get_dns_rule(request, DOMAIN_RULE_CNAME);
	if (cname == NULL) {
		return 0;
	}

	tlog(TLOG_INFO, "query %s with cname %s", request->domain, cname->cname);

	struct dns_request *child_request =
		_dns_server_new_child_request(request, cname->cname, request->qtype, _dns_server_process_cname_callback);
	if (child_request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		return -1;
	}

	/* check cname rule loop */
	struct dns_request *check_request = child_request->parent_request;
	struct dns_cname_rule *child_cname = _dns_server_get_dns_rule(child_request, DOMAIN_RULE_CNAME);

	/* sub domain rule*/
	if (child_cname != NULL && strncasecmp(child_request->domain, child_cname->cname, DNS_MAX_CNAME_LEN) == 0) {
		child_request->domain_rule.rules[DOMAIN_RULE_CNAME] = NULL;
		child_request->has_cname_loop = 1;
	}

	/* loop rule */
	while (check_request != NULL && child_cname != NULL) {
		struct dns_cname_rule *check_cname = _dns_server_get_dns_rule(check_request, DOMAIN_RULE_CNAME);
		if (check_cname == NULL) {
			break;
		}

		if (strstr(child_request->domain, check_request->domain) != NULL &&
			check_request != child_request->parent_request) {
			child_request->domain_rule.rules[DOMAIN_RULE_CNAME] = NULL;
			child_request->has_cname_loop = 1;
			break;
		}

		check_request = check_request->parent_request;
	}

	/* query cname domain  */
	if (child_request->has_cname_loop == 1 && strncasecmp(request->domain, cname->cname, DNS_MAX_CNAME_LEN) == 0) {
		request->has_cname_loop = 0;
		request->domain_rule.rules[DOMAIN_RULE_CNAME] = NULL;
		tlog(TLOG_DEBUG, "query cname domain %s", request->domain);
		goto out;
	}

	child_group_name = _dns_server_get_request_server_groupname(child_request);
	if (child_group_name) {
		/* reset dns group and setup child request domain group again when do query.*/
		child_request->dns_group_name[0] = '\0';
	}

	request->request_wait++;
	ret = _dns_server_do_query(child_request, 0);
	if (ret != 0) {
		request->request_wait--;
		tlog(TLOG_ERROR, "do query %s type %d failed.\n", request->domain, request->qtype);
		goto errout;
	}

	_dns_server_request_release_complete(child_request, 0);
	return 1;

errout:
	if (child_request) {
		request->child_request = NULL;
		_dns_server_request_release(child_request);
	}

	return -1;

out:
	if (child_request) {
		child_request->parent_request = NULL;
		request->child_request = NULL;
		_dns_server_request_release(child_request);
		_dns_server_request_release(request);
	}
	return 0;
}
