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

#include "smartdns/util.h"

#include "conn_stream.h"
#include "ecs.h"
#include "query.h"
#include "wake_event.h"
#include <openssl/rand.h>

void _dns_client_query_get(struct dns_query_struct *query)
{
	if (atomic_inc_return(&query->refcnt) <= 0) {
		BUG("query ref is invalid, domain: %s", query->domain);
	}
}

void _dns_client_query_release(struct dns_query_struct *query)
{
	int refcnt = atomic_dec_return(&query->refcnt);
	unsigned long bucket = 0;
	struct dns_query_replied *replied_map = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_conn_stream *stream = NULL;
	struct dns_conn_stream *stream_tmp = NULL;

	if (refcnt) {
		if (refcnt < 0) {
			BUG("BUG: refcnt is %d", refcnt);
		}
		return;
	}

	/* notify caller query end */
	if (query->callback) {
		tlog(TLOG_DEBUG, "result: %s, qtype: %d, has-result: %d, id %d", query->domain, query->qtype, query->has_result,
			 query->sid);
		query->callback(query->domain, DNS_QUERY_END, NULL, NULL, NULL, 0, query->user_ptr);
	}

	pthread_mutex_lock(&query->lock);
	list_for_each_entry_safe(stream, stream_tmp, &query->conn_stream_list, query_list)
	{
		list_del_init(&stream->query_list);
		stream->query = NULL;
		_dns_client_conn_stream_put(stream);
	}
	pthread_mutex_unlock(&query->lock);

	pthread_mutex_destroy(&query->lock);

	/* free resource */
	pthread_mutex_lock(&client.domain_map_lock);
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);

	hash_for_each_safe(query->replied_map, bucket, tmp, replied_map, node)
	{
		hash_del(&replied_map->node);
		free(replied_map);
	}
	memset(query, 0, sizeof(*query));
	free(query);
}

void _dns_client_query_remove(struct dns_query_struct *query)
{
	/* remove query from period check list, and release reference*/
	pthread_mutex_lock(&client.domain_map_lock);
	list_del_init(&query->dns_request_list);
	hash_del(&query->domain_node);
	pthread_mutex_unlock(&client.domain_map_lock);

	_dns_client_query_release(query);
}

void _dns_client_query_remove_all(void)
{
	struct dns_query_struct *query = NULL;
	struct dns_query_struct *tmp = NULL;
	LIST_HEAD(check_list);

	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		list_add(&query->period_list, &check_list);
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	list_for_each_entry_safe(query, tmp, &check_list, period_list)
	{
		list_del_init(&query->period_list);
		_dns_client_query_remove(query);
	}
}

static void _dns_client_query_cancel_pending(struct dns_query_struct *query)
{
	struct dns_server_info *server_info = NULL;
	struct dns_http2_pending *pend = NULL;
	struct dns_http2_pending *ptmp = NULL;
	LIST_HEAD(cancel_list);

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(server_info, &client.dns_server_list, list)
	{
		pthread_mutex_lock(&server_info->lock);
		list_for_each_entry_safe(pend, ptmp, &server_info->http2_pending_list, list)
		{
			if (pend->query != query) {
				continue;
			}

			list_move_tail(&pend->list, &cancel_list);
		}
		pthread_mutex_unlock(&server_info->lock);
	}
	pthread_mutex_unlock(&client.server_list_lock);

	list_for_each_entry_safe(pend, ptmp, &cancel_list, list)
	{
		struct dns_query_struct *pending_query = pend->query;

		tlog(TLOG_DEBUG,
			 "cancel pending before retry: domain=%s qtype=%d id=%d sent=%ld pending=%ld retry=%ld data_len=%d",
			 pending_query->domain, pending_query->qtype, pending_query->sid,
			 atomic_read(&pending_query->dns_request_sent), atomic_read(&pending_query->stream_pending_count),
			 atomic_read(&pending_query->retry_count), pend->data_len);
		list_del_init(&pend->list);
		atomic_dec(&pending_query->dns_request_sent);
		atomic_dec(&pending_query->stream_pending_count);
		_dns_client_query_schedule_retry_on_send_failure(pending_query, "cancel pending before retry");
		_dns_client_query_release(pending_query);
		free(pend);
	}
}

void _dns_client_query_schedule_retry_on_send_failure(struct dns_query_struct *query, const char *reason)
{
	if (query == NULL) {
		return;
	}

	int request_num = atomic_dec_return(&query->dns_request_sent);
	if (request_num < 0) {
		tlog(TLOG_ERROR, "send count is invalid, %d", request_num);
		return;
	}

	if (request_num == 0 && query->has_result == 0) {
		tlog(TLOG_DEBUG, "%s: retry schedule: domain=%s qtype=%d id=%d sent=%d retry=%ld pending=%ld",
			 reason ? reason : "send failure", query->domain, query->qtype, query->sid, request_num,
			 atomic_read(&query->retry_count), atomic_read(&query->stream_pending_count));
		query->send_tick = get_tick_count() - DNS_QUERY_TIMEOUT;
		_dns_client_do_wakeup_event();
		return;
	}

	tlog(TLOG_DEBUG, "%s: no retry yet: domain=%s qtype=%d id=%d sent=%d retry=%ld pending=%ld has_result=%d",
		 reason ? reason : "send failure", query->domain, query->qtype, query->sid, request_num,
		 atomic_read(&query->retry_count), atomic_read(&query->stream_pending_count), query->has_result);
}

static int _dns_client_query_has_active_pending(struct dns_query_struct *query, unsigned long now)
{
	struct dns_server_info *server_info = NULL;
	struct dns_http2_pending *pend = NULL;
	int has_active_pending = 0;

	if (atomic_read(&query->stream_pending_count) <= 0) {
		return 0;
	}

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(server_info, &client.dns_server_list, list)
	{
		pthread_mutex_lock(&server_info->lock);
		list_for_each_entry(pend, &server_info->http2_pending_list, list)
		{
			if (pend->query != query) {
				continue;
			}

			if (pend->active_tick > 0 && now - DNS_QUERY_TIMEOUT < pend->active_tick) {
				has_active_pending = 1;
				break;
			}
		}
		pthread_mutex_unlock(&server_info->lock);
		if (has_active_pending) {
			break;
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);

	return has_active_pending;
}

int _dns_client_send_query(struct dns_query_struct *query)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int encode_len = 0;

	/* init dns packet head */
	struct dns_head head;
	memset(&head, 0, sizeof(head));
	head.id = query->sid;
	head.qr = DNS_QR_QUERY;
	head.opcode = DNS_OP_QUERY;
	head.aa = 0;
	head.rd = 1;
	head.ra = 0;
	head.ad = query->edns0_do;
	head.rcode = 0;

	if (dns_packet_init(packet, DNS_PACKSIZE, &head) != 0) {
		tlog(TLOG_ERROR, "init packet failed.");
		return -1;
	}

	/* add question */
	if (dns_add_domain(packet, query->domain, query->qtype, DNS_C_IN) != 0) {
		tlog(TLOG_ERROR, "add domain to packet failed.");
		return -1;
	}

	dns_set_OPT_payload_size(packet, DNS_IN_PACKSIZE);
	if (query->edns0_do) {
		dns_set_OPT_option(packet, DNS_OPT_FLAG_DO);
	}
	/* dns_add_OPT_TCP_KEEPALIVE(packet, 1200); */
	if (_dns_client_dns_add_ecs(query, packet) != 0) {
		tlog(TLOG_ERROR, "add ecs failed.");
		return -1;
	}

	/* encode packet */
	encode_len = dns_encode(inpacket, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		tlog(TLOG_ERROR, "encode query failed.");
		return -1;
	}

	if (encode_len > DNS_IN_PACKSIZE) {
		BUG("size is invalid.");
		return -1;
	}

	/* send query packet */
	return _dns_client_send_packet(query, inpacket, encode_len);
}

struct dns_query_struct *_dns_client_get_request(char *domain, int qtype, unsigned short sid)
{
	struct dns_query_struct *query = NULL;
	struct dns_query_struct *query_result = NULL;
	struct hlist_node *tmp = NULL;
	uint32_t key = 0;

	/* get query by hash key : id + domain */
	key = hash_string(domain);
	key = jhash(&sid, sizeof(sid), key);
	key = jhash(&qtype, sizeof(qtype), key);
	pthread_mutex_lock(&client.domain_map_lock);
	hash_for_each_possible_safe(client.domain_map, query, tmp, domain_node, key)
	{
		if (sid != query->sid) {
			continue;
		}

		if (qtype != query->qtype) {
			continue;
		}

		if (strncmp(query->domain, domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		query_result = query;
		_dns_client_query_get(query_result);
		break;
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	return query_result;
}

int _dns_replied_check_add(struct dns_query_struct *dns_query, struct dns_server_info *server)
{
	uint32_t key = 0;
	struct dns_query_replied *replied_map = NULL;

	/* avoid multiple replies from one server */
	key = jhash((const void *)&server, sizeof(server), 0);
	hash_for_each_possible(dns_query->replied_map, replied_map, node, key)
	{
		/* already replied, ignore this reply */
		if (replied_map->server == server) {
			return -1;
		}
	}

	replied_map = zalloc(1, sizeof(*replied_map));
	if (replied_map == NULL) {
		tlog(TLOG_ERROR, "malloc failed");
		return -1;
	}

	/* add address info to check hashtable */
	replied_map->server = server;
	hash_add(dns_query->replied_map, &replied_map->node, key);
	return 0;
}

void _dns_replied_check_remove(struct dns_query_struct *dns_query, struct dns_server_info *server)
{
	uint32_t key = 0;
	struct dns_query_replied *replied_map = NULL;

	key = jhash((const void *)&server, sizeof(server), 0);
	hash_for_each_possible(dns_query->replied_map, replied_map, node, key)
	{
		if (replied_map->server == server) {
			hash_del(&replied_map->node);
			free(replied_map);
			return;
		}
	}
}

int _dns_client_query_parser_options(struct dns_query_struct *query, struct dns_query_options *options)
{
	if (options->enable_flag & DNS_QUEY_OPTION_ECS_IP) {
		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		struct dns_opt_ecs *ecs = NULL;

		ecs = &query->ecs.ecs;
		getaddr_by_host(options->ecs_ip.ip, (struct sockaddr *)&addr, &addr_len);

		query->ecs.enable = 1;
		ecs->source_prefix = options->ecs_ip.subnet;
		ecs->scope_prefix = 0;

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)&addr;
			ecs->family = DNS_OPT_ECS_FAMILY_IPV4;
			memcpy(&ecs->addr, &addr_in->sin_addr.s_addr, 4);
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
				memcpy(&ecs->addr, addr_in6->sin6_addr.s6_addr + 12, 4);
				ecs->family = DNS_OPT_ECS_FAMILY_IPV4;
			} else {
				memcpy(&ecs->addr, addr_in6->sin6_addr.s6_addr, 16);
				ecs->family = DNS_OPT_ECS_FAMILY_IPV6;
			}
		} break;
		default:
			tlog(TLOG_WARN, "ECS set failure.");
			break;
		}
	}

	if (options->enable_flag & DNS_QUEY_OPTION_ECS_DNS) {
		struct dns_opt_ecs *ecs = &options->ecs_dns;
		if (ecs->family != DNS_OPT_ECS_FAMILY_IPV6 && ecs->family != DNS_OPT_ECS_FAMILY_IPV4) {
			return -1;
		}

		if (ecs->family == DNS_OPT_ECS_FAMILY_IPV4 && ecs->source_prefix > 32) {
			return -1;
		}

		if (ecs->family == DNS_OPT_ECS_FAMILY_IPV6 && ecs->source_prefix > 128) {
			return -1;
		}

		memcpy(&query->ecs.ecs, ecs, sizeof(query->ecs.ecs));
		query->ecs.enable = 1;
	}

	if (query->ecs.enable == 0) {
		_dns_client_query_setup_default_ecs(query);
	}

	if (options->enable_flag & DNS_QUEY_OPTION_EDNS0_DO) {
		query->edns0_do = 1;
	}

	return 0;
}

void _dns_client_retry_dns_query(struct dns_query_struct *query)
{
	if (_dns_client_query_has_active_pending(query, get_tick_count())) {
		return;
	}

	_dns_client_query_cancel_pending(query);
	if (atomic_dec_and_test(&query->retry_count) || (query->has_result != 0)) {
		if (query->has_result == 0) {
			tlog(TLOG_DEBUG, "retry query %s, type: %d, id: %d failed, sent=%ld pending=%ld retry=%ld",
				 query->domain, query->qtype, query->sid, atomic_read(&query->dns_request_sent),
				 atomic_read(&query->stream_pending_count), atomic_read(&query->retry_count));
		}
		_dns_client_query_remove(query);
	} else {
		tlog(TLOG_DEBUG, "retry query %s, type: %d, id: %d, sent=%ld pending=%ld retry=%ld", query->domain,
			 query->qtype, query->sid, atomic_read(&query->dns_request_sent),
			 atomic_read(&query->stream_pending_count), atomic_read(&query->retry_count));
		_dns_client_send_query(query);
	}
}

int _dns_client_add_hashmap(struct dns_query_struct *query)
{
	uint32_t key = 0;
	struct hlist_node *tmp = NULL;
	struct dns_query_struct *query_check = NULL;
	int is_exists = 0;
	int loop = 0;

	while (loop++ <= 32) {
		if (RAND_bytes((unsigned char *)&query->sid, sizeof(query->sid)) != 1) {
			query->sid = random();
		}

		key = hash_string(query->domain);
		key = jhash(&query->sid, sizeof(query->sid), key);
		key = jhash(&query->qtype, sizeof(query->qtype), key);
		is_exists = 0;
		pthread_mutex_lock(&client.domain_map_lock);
		hash_for_each_possible_safe(client.domain_map, query_check, tmp, domain_node, key)
		{
			if (query->sid != query_check->sid) {
				continue;
			}

			if (query->qtype != query_check->qtype) {
				continue;
			}

			if (strncmp(query_check->domain, query->domain, DNS_MAX_CNAME_LEN) != 0) {
				continue;
			}

			is_exists = 1;
			break;
		}

		if (is_exists == 1) {
			pthread_mutex_unlock(&client.domain_map_lock);
			continue;
		}

		hash_add(client.domain_map, &query->domain_node, key);
		pthread_mutex_unlock(&client.domain_map_lock);
		break;
	}

	return 0;
}
