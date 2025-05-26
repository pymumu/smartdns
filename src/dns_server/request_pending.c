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

#include "request_pending.h"
#include "answer.h"
#include "context.h"
#include "dns_server.h"
#include "request.h"

int _dns_server_set_to_pending_list(struct dns_request *request)
{
	struct dns_request_pending_list *pending_list = NULL;
	struct dns_request_pending_list *pending_list_tmp = NULL;
	uint32_t key = 0;
	int ret = -1;
	if (request->qtype != DNS_T_A && request->qtype != DNS_T_AAAA) {
		return ret;
	}

	key = hash_string(request->domain);
	key = hash_string_initval(request->dns_group_name, key);
	key = jhash(&(request->qtype), sizeof(request->qtype), key);
	key = jhash(&(request->server_flags), sizeof(request->server_flags), key);
	pthread_mutex_lock(&server.request_pending_lock);
	hash_for_each_possible(server.request_pending, pending_list_tmp, node, key)
	{
		if (request->qtype != pending_list_tmp->qtype) {
			continue;
		}

		if (request->server_flags != pending_list_tmp->server_flags) {
			continue;
		}

		if (strcmp(request->dns_group_name, pending_list_tmp->dns_group_name) != 0) {
			continue;
		}

		if (strncmp(request->domain, pending_list_tmp->domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		pending_list = pending_list_tmp;
		break;
	}

	if (pending_list == NULL) {
		pending_list = malloc(sizeof(*pending_list));
		if (pending_list == NULL) {
			ret = -1;
			goto out;
		}

		memset(pending_list, 0, sizeof(*pending_list));
		pthread_mutex_init(&pending_list->request_list_lock, NULL);
		INIT_LIST_HEAD(&pending_list->request_list);
		INIT_HLIST_NODE(&pending_list->node);
		pending_list->qtype = request->qtype;
		pending_list->server_flags = request->server_flags;
		safe_strncpy(pending_list->domain, request->domain, DNS_MAX_CNAME_LEN);
		safe_strncpy(pending_list->dns_group_name, request->dns_group_name, DNS_GROUP_NAME_LEN);
		hash_add(server.request_pending, &pending_list->node, key);
		request->request_pending_list = pending_list;
	} else {
		ret = 0;
	}

	if (ret == 0) {
		_dns_server_request_get(request);
	}
	list_add_tail(&request->pending_list, &pending_list->request_list);
out:
	pthread_mutex_unlock(&server.request_pending_lock);
	return ret;
}

int _dns_server_reply_all_pending_list(struct dns_request *request, struct dns_server_post_context *context)
{
	struct dns_request_pending_list *pending_list = NULL;
	struct dns_request *req = NULL;
	struct dns_request *tmp = NULL;
	int ret = 0;

	if (request->request_pending_list == NULL) {
		return 0;
	}

	pthread_mutex_lock(&server.request_pending_lock);
	pending_list = request->request_pending_list;
	request->request_pending_list = NULL;
	hlist_del_init(&pending_list->node);
	pthread_mutex_unlock(&server.request_pending_lock);

	pthread_mutex_lock(&pending_list->request_list_lock);
	list_del_init(&request->pending_list);
	list_for_each_entry_safe(req, tmp, &(pending_list->request_list), pending_list)
	{
		struct dns_server_post_context context_pending;
		_dns_server_post_context_init_from(&context_pending, req, context->packet, context->inpacket,
										   context->inpacket_len);
		req->dualstack_selection = request->dualstack_selection;
		req->dualstack_selection_query = request->dualstack_selection_query;
		req->dualstack_selection_force_soa = request->dualstack_selection_force_soa;
		req->dualstack_selection_has_ip = request->dualstack_selection_has_ip;
		req->dualstack_selection_ping_time = request->dualstack_selection_ping_time;
		req->ping_time = request->ping_time;
		req->is_cache_reply = request->is_cache_reply;
		_dns_server_get_answer(&context_pending);

		context_pending.is_cache_reply = context->is_cache_reply;
		context_pending.do_cache = 0;
		context_pending.do_audit = context->do_audit;
		context_pending.do_reply = context->do_reply;
		context_pending.do_force_soa = context->do_force_soa;
		context_pending.do_ipset = 0;
		context_pending.reply_ttl = request->ip_ttl;
		context_pending.no_release_parent = 0;

		_dns_server_reply_passthrough(&context_pending);

		req->request_pending_list = NULL;
		list_del_init(&req->pending_list);
		_dns_server_request_release_complete(req, 0);
	}
	pthread_mutex_unlock(&pending_list->request_list_lock);

	free(pending_list);

	return ret;
}
