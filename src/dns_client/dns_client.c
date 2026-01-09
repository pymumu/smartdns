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

#define _GNU_SOURCE

#include "smartdns/util.h"

#include "client_http2.h"
#include "client_http3.h"
#include "client_https.h"
#include "client_mdns.h"
#include "client_quic.h"
#include "client_socket.h"
#include "client_tcp.h"
#include "client_tls.h"
#include "client_udp.h"
#include "conn_stream.h"
#include "dns_client.h"
#include "ecs.h"
#include "group.h"
#include "packet.h"
#include "pending_server.h"
#include "proxy.h"
#include "query.h"
#include "server_info.h"
#include "wake_event.h"

static int is_client_init;
struct dns_client client;

void dns_client_flags_init(struct client_dns_server_flags *flags)
{
	memset(flags, 0, sizeof(*flags));
}

static int _dns_client_server_package_address_match(struct dns_server_info *server_info, struct sockaddr *addr,
													socklen_t addr_len)
{
	if (server_info->type == DNS_SERVER_MDNS) {
		return 0;
	}

	if (addr_len != server_info->ai_addrlen) {
		return -1;
	}

	if (memcmp(addr, &server_info->addr, addr_len) != 0) {
		return -1;
	}

	return 0;
}

int _dns_client_recv(struct dns_server_info *server_info, unsigned char *inpacket, int inpacket_len,
					 struct sockaddr *from, socklen_t from_len)
{
	int len = 0;
	int i = 0;
	int j = 0;
	int qtype = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	struct dns_rrs *rrs = NULL;
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int ret = 0;
	struct dns_query_struct *query = NULL;
	int request_num = 0;
	int has_opt = 0;

	packet->head.tc = 0;

	if (_dns_client_server_package_address_match(server_info, from, from_len) != 0) {
		tlog(TLOG_DEBUG, "packet from invalid server.");
		return -1;
	}
	stats_inc(&server_info->stats.recv_count);

	/* decode domain from udp packet */
	len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (len != 0) {
		char host_name[DNS_MAX_CNAME_LEN];
		tlog(TLOG_INFO, "decode failed, packet len = %d, tc = %d, id = %d, from = %s\n", inpacket_len, packet->head.tc,
			 packet->head.id, get_host_by_addr(host_name, sizeof(host_name), from));
		if (dns_conf.dns_save_fail_packet) {
			dns_packet_save(dns_conf.dns_save_fail_packet_dir, "client", host_name, inpacket, inpacket_len);
		}
		return -1;
	}

	/* not answer, return error */
	if (packet->head.qr != DNS_OP_IQUERY) {
		tlog(TLOG_DEBUG, "message type error.\n");
		return -1;
	}

	tlog(TLOG_DEBUG,
		 "qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, ra = %d, rcode "
		 "= %d, payloadsize = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len,
		 packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra, packet->head.rcode,
		 dns_get_OPT_payload_size(packet));

	/* get question */
	for (j = 0; j < DNS_RRS_END && domain[0] == '\0'; j++) {
		rrs = dns_get_rrs_start(packet, (dns_rr_type)j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			dns_get_domain(rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
			tlog(TLOG_DEBUG, "domain: %s qtype: %d  qclass: %d\n", domain, qtype, qclass);
			break;
		}
	}

	if (dns_get_OPT_payload_size(packet) > 0) {
		has_opt = 1;
	}

	atomic_set(&server_info->is_alive, 1);
	int latency = get_tick_count() - server_info->send_tick;
	dns_stats_server_stats_avg_time_add(&server_info->stats, latency);

	/* get query reference */
	query = _dns_client_get_request(domain, qtype, packet->head.id);
	if (query == NULL) {
		return 0;
	}

	if (has_opt == 0 && server_info->flags.result_flag & DNSSERVER_FLAG_CHECK_EDNS) {
		_dns_client_query_release(query);
		return 0;
	}

	/* avoid multiple replies */
	if (_dns_replied_check_add(query, server_info) != 0) {
		_dns_client_query_release(query);
		return 0;
	}

	request_num = atomic_dec_return(&query->dns_request_sent);
	if (request_num < 0) {
		_dns_client_query_release(query);
		tlog(TLOG_ERROR, "send count is invalid, %d", request_num);
		return -1;
	}

	/* notify caller dns query result */
	if (query->callback) {
		ret = query->callback(query->domain, DNS_QUERY_RESULT, server_info, packet, inpacket, inpacket_len,
							  query->user_ptr);

		if (ret == DNS_CLIENT_ACTION_RETRY || ret == DNS_CLIENT_ACTION_DROP) {
			/* remove this result */
			_dns_replied_check_remove(query, server_info);
			atomic_inc(&query->dns_request_sent);
			if (ret == DNS_CLIENT_ACTION_RETRY) {
				/*
				 * retry immdiately
				 * The socket needs to be re-created to avoid being limited, such as 1.1.1.1
				 */
				pthread_mutex_lock(&client.server_list_lock);
				_dns_client_close_socket(server_info);
				pthread_mutex_unlock(&client.server_list_lock);
				_dns_client_retry_dns_query(query);
			}
		} else {
			if (ret == DNS_CLIENT_ACTION_OK) {
				query->has_result = 1;
			} else {
				tlog(TLOG_DEBUG, "query %s result is invalid, %d", query->domain, ret);
			}

			if (request_num == 0) {
				/* if all server replied, or done, stop query, release resource */
				_dns_client_query_remove(query);
			}
		}
	}

	stats_inc(&server_info->stats.success_count);
	_dns_client_query_release(query);
	return 0;
}

static int _dns_client_process(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	if (server_info->proxy) {
		int ret = _dns_proxy_handshake(server_info, event, now);
		if (ret != 0) {
			return ret;
		}
	}

	if (server_info->type == DNS_SERVER_UDP || server_info->type == DNS_SERVER_MDNS) {
		/* receive from udp */
		return _dns_client_process_udp(server_info, event, now);
	} else if (server_info->type == DNS_SERVER_TCP) {
		/* receive from tcp */
		return _dns_client_process_tcp(server_info, event, now);
	} else if (server_info->type == DNS_SERVER_TLS || server_info->type == DNS_SERVER_HTTPS ||
			   server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
		/* receive from tls */
		return _dns_client_process_tls(server_info, event, now);
	} else {
		return -1;
	}

	return 0;
}

static int _dns_client_send_http(struct dns_server_info *server_info, struct dns_query_struct *query, void *packet_data,
								 int packet_data_len)
{
	/* If ALPN is negotiated and is NOT h2, use HTTP/1.1 */
	if (server_info->alpn_selected[0] != '\0' && strncmp(server_info->alpn_selected, "h2", 2) != 0) {
		return _dns_client_send_http1(server_info, packet_data, packet_data_len);
	}

	/* Default to HTTP/2 buffering (stream-based).
	   If ALPN later turns out to be H1, _dns_client_process_https_streams will handle it. */
	return _dns_client_send_http2(server_info, query, packet_data, packet_data_len);
}

static int _dns_client_check_server_prohibit(struct dns_server_info *server_info, int prohibit_time)
{
	if (server_info->prohibit) {
		if (server_info->is_already_prohibit == 0) {
			server_info->is_already_prohibit = 1;
			_dns_server_inc_prohibit_server_num(server_info);
			time(&server_info->last_send);
			time(&server_info->last_recv);
			if (server_info->type != DNS_SERVER_MDNS) {
				tlog(TLOG_INFO, "server %s not alive, prohibit", server_info->ip);
			}
			_dns_client_shutdown_socket(server_info);
		}

		time_t now = 0;
		time(&now);
		if ((now - prohibit_time < server_info->last_send)) {
			return 1;
		}
		server_info->prohibit = 0;
		server_info->is_already_prohibit = 0;
		_dns_server_dec_prohibit_server_num(server_info);
		if (now - prohibit_time >= server_info->last_send) {
			_dns_client_close_socket(server_info);
		}
	}
	return 0;
}

static int _dns_client_send_one_packet(struct dns_server_info *server_info, struct dns_query_struct *query,
									   void *packet_data, int packet_data_len)
{
	int ret = 0;
	int send_err = 0;
	int retry = 0;

	atomic_inc(&query->dns_request_sent);
	stats_inc(&server_info->stats.total);
	errno = 0;
	server_info->send_tick = get_tick_count();

	while (1) {
		switch (server_info->type) {
		case DNS_SERVER_UDP:
			/* udp query */
			ret = _dns_client_send_udp(server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_TCP:
			/* tcp query */
			ret = _dns_client_send_tcp(server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_TLS:
			/* tls query */
			ret = _dns_client_send_tls(server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_HTTPS:
			/* https query - buffer raw data in stream, protocol determined later */
			ret = _dns_client_send_http(server_info, query, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_MDNS:
			/* mdns query */
			ret = _dns_client_send_udp_mdns(server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_QUIC:
			/* quic query */
			ret = _dns_client_send_quic(query, server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		case DNS_SERVER_HTTP3:
			/* http3 query */
			ret = _dns_client_send_http3(query, server_info, packet_data, packet_data_len);
			send_err = errno;
			break;
		default:
			/* unsupported query type */
			ret = -1;
			break;
		}

		if (ret != 0) {
			switch (send_err) {
			case EBADF:
			case ECONNRESET:
			case EPIPE:
			case EDESTADDRREQ:
			case EINVAL:
			case EISCONN:
			case ENOTCONN:
			case ENOTSOCK:
			case EOPNOTSUPP: {
				tlog(TLOG_DEBUG, "send query to %s failed, %s, type: %d", server_info->ip, strerror(send_err),
					 server_info->type);
				_dns_client_close_socket(server_info);
				if (retry == 0) {
					retry = 1;
					if (_dns_client_create_socket(server_info) == 0) {
						continue;
					}
				}
				atomic_dec(&query->dns_request_sent);
				return -1;
			}
			default:
				break;
			}

			tlog(TLOG_DEBUG, "send query to %s failed, %s, type: %d", server_info->ip, strerror(send_err),
				 server_info->type);
			time_t now = 0;
			time(&now);
			if (now - 10 > server_info->last_recv || send_err != ENOMEM) {
				server_info->prohibit = 1;
			}

			atomic_dec(&query->dns_request_sent);
			return -1;
		}
		break;
	}
	time(&server_info->last_send);

	return 0;
}

int _dns_client_send_packet(struct dns_query_struct *query, void *packet, int len)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group_member *group_member = NULL;
	struct dns_server_group_member *tmp = NULL;
	int ret = 0;
	int i = 0;
	int total_server = 0;
	int send_count = 0;
	void *packet_data = NULL;
	int packet_data_len = 0;
	unsigned char packet_data_buffer[DNS_IN_PACKSIZE];
	int prohibit_time = 60;

	query->send_tick = get_tick_count();

	/* send query to all dns servers */
	atomic_inc(&query->dns_request_sent);
	for (i = 0; i < 2; i++) {
		total_server = 0;
		if (i == 1) {
			prohibit_time = 5;
		}

		/* fallback group exists, use fallback group */
		if (atomic_read(&query->retry_count) == 1) {
			struct dns_server_group *fallback_server_group = _dns_client_get_group("fallback");
			if (fallback_server_group != NULL) {
				query->server_group = fallback_server_group;
			}
		}

		pthread_mutex_lock(&client.server_list_lock);
		list_for_each_entry_safe(group_member, tmp, &query->server_group->head, list)
		{
			server_info = group_member->server;

			/* skip fallback server for first query */
			if (server_info->flags.fallback && atomic_read(&query->retry_count) == DNS_QUERY_RETRY && i == 0) {
				continue;
			}

			if (_dns_client_check_server_prohibit(server_info, prohibit_time)) {
				continue;
			}

			total_server++;
			tlog(TLOG_DEBUG, "send query to server %s:%d, type:%d", server_info->ip, server_info->port,
				 server_info->type);
			if (server_info->fd <= 0) {
				ret = _dns_client_create_socket(server_info);
				if (ret != 0) {
					server_info->prohibit = 1;
					continue;
				}
			}

			if (_dns_client_setup_server_packet(server_info, query, packet, len, packet_data_buffer, &packet_data,
												&packet_data_len) != 0) {
				continue;
			}

			if (_dns_client_send_one_packet(server_info, query, packet_data, packet_data_len) == 0) {
				send_count++;
			}
		}
		pthread_mutex_unlock(&client.server_list_lock);

		if (send_count > 0) {
			break;
		}
	}

	int num = atomic_dec_return(&query->dns_request_sent);
	if (num == 0 && send_count > 0) {
		_dns_client_query_remove(query);
	}

	if (send_count <= 0) {
		static time_t lastlog = 0;
		time_t now = 0;
		time(&now);
		if (now - lastlog > 120) {
			lastlog = now;
			tlog(TLOG_WARN, "send query %s to upstream server failed, total server number %d", query->domain,
				 total_server);
		}
		return -1;
	}

	return 0;
}

int dns_client_query(const char *domain, int qtype, dns_client_callback callback, void *user_ptr,
					 const char *group_name, struct dns_query_options *options)
{
	struct dns_query_struct *query = NULL;
	int ret = 0;
	int unused __attribute__((unused));

	if (domain == NULL) {
		goto errout;
	}

	if (atomic_read(&client.run) == 0) {
		goto errout;
	}

	query = zalloc(1, sizeof(*query));
	if (query == NULL) {
		goto errout;
	}

	INIT_HLIST_NODE(&query->domain_node);
	INIT_LIST_HEAD(&query->dns_request_list);
	INIT_LIST_HEAD(&query->conn_stream_list);
	pthread_mutex_init(&query->lock, NULL);
	atomic_set(&query->refcnt, 0);
	atomic_set(&query->dns_request_sent, 0);
	atomic_set(&query->retry_count, DNS_QUERY_RETRY);
	hash_init(query->replied_map);
	safe_strncpy(query->domain, domain, DNS_MAX_CNAME_LEN);
	query->user_ptr = user_ptr;
	query->callback = callback;
	query->qtype = qtype;
	query->send_tick = 0;
	query->has_result = 0;
	query->server_group = _dns_client_get_dnsserver_group(group_name);
	if (query->server_group == NULL) {
		tlog(TLOG_ERROR, "get dns server group %s failed.", group_name);
		goto errout;
	}

	query->conf = dns_server_get_rule_group(options->conf_group_name);
	if (query->conf == NULL) {
		tlog(TLOG_ERROR, "get dns config group %s failed.", options->conf_group_name);
		goto errout;
	}

	if (_dns_client_query_parser_options(query, options) != 0) {
		tlog(TLOG_ERROR, "parser options for %s failed.", domain);
		goto errout;
	}

	_dns_client_query_get(query);
	/* add query to hashtable */
	if (_dns_client_add_hashmap(query) != 0) {
		tlog(TLOG_ERROR, "add query to hash map failed.");
		goto errout;
	}

	/* send query */
	_dns_client_query_get(query);
	ret = _dns_client_send_query(query);
	if (ret != 0) {
		_dns_client_query_release(query);
		goto errout_del_list;
	}

	pthread_mutex_lock(&client.domain_map_lock);
	if (hash_hashed(&query->domain_node)) {
		if (list_empty(&client.dns_request_list)) {
			_dns_client_do_wakeup_event();
		}

		list_add_tail(&query->dns_request_list, &client.dns_request_list);
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	tlog(TLOG_INFO, "request: %s, qtype: %d, id: %d, group: %s", domain, qtype, query->sid,
		 query->server_group->group_name);
	_dns_client_query_release(query);

	return 0;
errout_del_list:
	query->callback = NULL;
	_dns_client_query_remove(query);
	query = NULL;
errout:
	if (query) {
		free(query);
	}
	return -1;
}

static void _dns_client_period_run_second(void)
{
	_dns_client_check_tcp();
	_dns_client_check_servers();
	_dns_client_add_pending_servers();
}

static void _dns_client_period_run(unsigned int msec)
{
	struct dns_query_struct *query = NULL;
	struct dns_query_struct *tmp = NULL;

	LIST_HEAD(check_list);
	unsigned long now = get_tick_count();

	/* get query which timed out to check list */
	pthread_mutex_lock(&client.domain_map_lock);
	list_for_each_entry_safe(query, tmp, &client.dns_request_list, dns_request_list)
	{
		if ((now - DNS_QUERY_TIMEOUT >= query->send_tick) && query->send_tick > 0) {
			list_add(&query->period_list, &check_list);
			_dns_client_query_get(query);
		}
	}
	pthread_mutex_unlock(&client.domain_map_lock);

	list_for_each_entry_safe(query, tmp, &check_list, period_list)
	{
		/* free timed out query, and notify caller */
		list_del_init(&query->period_list);

		/* check udp nat after retrying. */
		if (atomic_read(&query->retry_count) == 1) {
			_dns_client_check_udp_nat(query);
		}
		_dns_client_retry_dns_query(query);
		_dns_client_query_release(query);
	}

	if (msec % 10 == 0) {
		_dns_client_period_run_second();
	}
}

static void *_dns_client_work(void *arg)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	unsigned int msec = 0;
	unsigned int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;
	unsigned long start_time = 0;

	now = get_tick_count();
	start_time = now;
	expect_time = now + sleep;

	while (atomic_read(&client.run)) {
		now = get_tick_count();

		if (now >= expect_time) {
			unsigned long elapsed_from_start = now - start_time;
			unsigned int current_period = (elapsed_from_start + sleep / 2) / sleep;

			if (current_period > msec) {
				msec = current_period;
			}

			expect_time = start_time + (msec + 1) * sleep;
			_dns_client_period_run(msec);
			msec++;

			/* When client is idle, the sleep time is 1000ms, to reduce CPU usage */
			pthread_mutex_lock(&client.domain_map_lock);
			if (list_empty(&client.dns_request_list)) {
				if (msec % 10 != 0) {
					msec = ((msec / 10) + 1) * 10;
					expect_time = start_time + msec * sleep;
				}
			}
			pthread_mutex_unlock(&client.domain_map_lock);
		}

		sleep_time = (int)(expect_time - now);
		if (sleep_time < 0) {
			sleep_time = 0;
		}

		num = epoll_wait(client.epoll_fd, events, DNS_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			struct dns_server_info *server_info = (struct dns_server_info *)event->data.ptr;
			if (event->data.fd == client.fd_wakeup) {
				_dns_client_clear_wakeup_event();
				continue;
			}

			if (server_info == NULL) {
				tlog(TLOG_WARN, "server info is invalid.");
				continue;
			}

			_dns_client_process(server_info, event, now);
		}
	}

	close(client.epoll_fd);
	client.epoll_fd = -1;

	return NULL;
}

int dns_client_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int fd_wakeup = -1;
	int ret = 0;

	if (is_client_init == 1) {
		return -1;
	}

	if (client.epoll_fd > 0) {
		return -1;
	}

	memset(&client, 0, sizeof(client));
	pthread_attr_init(&attr);
	atomic_set(&client.dns_server_num, 0);
	atomic_set(&client.dns_server_prohibit_num, 0);
	atomic_set(&client.run_period, 0);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	pthread_mutex_init(&client.server_list_lock, NULL);
	INIT_LIST_HEAD(&client.dns_server_list);

	pthread_mutex_init(&client.domain_map_lock, NULL);
	hash_init(client.domain_map);
	hash_init(client.group);
	INIT_LIST_HEAD(&client.dns_request_list);

	if (dns_client_add_group(DNS_SERVER_GROUP_DEFAULT) != 0) {
		tlog(TLOG_ERROR, "add default server group failed.");
		goto errout;
	}

	if (_dns_client_add_mdns_server() != 0) {
		tlog(TLOG_ERROR, "add mdns server failed.");
		goto errout;
	}

	client.default_group = _dns_client_get_group(DNS_SERVER_GROUP_DEFAULT);
	client.epoll_fd = epollfd;
	atomic_set(&client.run, 1);

	/* start work task */
	ret = pthread_create(&client.tid, &attr, _dns_client_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create client work thread failed, %s\n", strerror(errno));
		goto errout;
	}

	fd_wakeup = _dns_client_create_wakeup_event();
	if (fd_wakeup < 0) {
		tlog(TLOG_ERROR, "create wakeup event failed, %s\n", strerror(errno));
		goto errout;
	}

	client.fd_wakeup = fd_wakeup;
	is_client_init = 1;

	return 0;
errout:
	if (client.tid) {
		void *retval = NULL;
		atomic_set(&client.run, 0);
		pthread_join(client.tid, &retval);
		client.tid = 0;
	}

	if (epollfd > 0) {
		close(epollfd);
	}

	if (fd_wakeup > 0) {
		close(fd_wakeup);
	}

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);

	return -1;
}

void dns_client_exit(void)
{
	if (is_client_init == 0) {
		return;
	}

	if (client.tid) {
		void *ret = NULL;
		atomic_set(&client.run, 0);
		_dns_client_do_wakeup_event();
		pthread_join(client.tid, &ret);
		client.tid = 0;
	}

	/* free all resources */
	_dns_client_close_wakeup_event();
	_dns_client_remove_all_pending_servers();
	_dns_client_server_remove_all();
	_dns_client_query_remove_all();
	_dns_client_group_remove_all();

	pthread_mutex_destroy(&client.server_list_lock);
	pthread_mutex_destroy(&client.domain_map_lock);
	if (client.ssl_ctx) {
		SSL_CTX_free(client.ssl_ctx);
		client.ssl_ctx = NULL;
	}

	if (client.ssl_quic_ctx) {
		SSL_CTX_free(client.ssl_quic_ctx);
		client.ssl_quic_ctx = NULL;
	}

	is_client_init = 0;
}
