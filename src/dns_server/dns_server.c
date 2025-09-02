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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns_server.h"
#include "address.h"
#include "answer.h"
#include "audit.h"
#include "cache.h"
#include "client_rule.h"
#include "cname.h"
#include "connection.h"
#include "context.h"
#include "dualstack.h"
#include "ip_rule.h"
#include "local_addr.h"
#include "mdns.h"
#include "neighbor.h"
#include "ptr.h"
#include "request.h"
#include "request_pending.h"
#include "rules.h"
#include "server_https.h"
#include "server_socket.h"
#include "server_tcp.h"
#include "server_tls.h"
#include "server_udp.h"
#include "soa.h"
#include "speed_check.h"

#include "smartdns/dns_cache.h"
#include "smartdns/dns_client.h"
#include "smartdns/dns_conf.h"
#include "smartdns/dns_plugin.h"
#include "smartdns/dns_stats.h"
#include "smartdns/fast_ping.h"
#include "smartdns/http_parse.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/lib/nftset.h"
#include "smartdns/util.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

static int is_server_init;
struct dns_server server;

static void _dns_server_wakeup_thread(void)
{
	uint64_t u = 1;
	int unused __attribute__((unused));
	unused = write(server.event_fd, &u, sizeof(u));
}

static int _dns_server_forward_request(unsigned char *inpacket, int inpacket_len)
{
	return -1;
}

int _dns_reply_inpacket(struct dns_request *request, unsigned char *inpacket, int inpacket_len)
{
	struct dns_server_conn_head *conn = request->conn;
	int ret = 0;

	if (conn == NULL) {
		tlog(TLOG_ERROR, "client is invalid, domain: %s", request->domain);
		return -1;
	}

	if (conn->type == DNS_CONN_TYPE_UDP_SERVER) {
		ret = _dns_server_reply_udp(request, (struct dns_server_conn_udp *)conn, inpacket, inpacket_len);
	} else if (conn->type == DNS_CONN_TYPE_TCP_CLIENT) {
		ret = _dns_server_reply_tcp(request, (struct dns_server_conn_tcp_client *)conn, inpacket, inpacket_len);
	} else if (conn->type == DNS_CONN_TYPE_TLS_CLIENT) {
		ret = _dns_server_reply_tcp(request, (struct dns_server_conn_tcp_client *)conn, inpacket, inpacket_len);
	} else if (conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		ret = _dns_server_reply_https(request, (struct dns_server_conn_tcp_client *)conn, inpacket, inpacket_len);
	} else {
		ret = -1;
	}

	return ret;
}

static int _dns_server_resolve_callback_reply_passthrough(struct dns_request *request, const char *domain,
														  struct dns_packet *packet, unsigned char *inpacket,
														  int inpacket_len, unsigned int result_flag)
{
	struct dns_server_post_context context;
	int ttl = 0;
	int ret = 0;

	ret = _dns_server_passthrough_rule_check(request, domain, packet, result_flag, &ttl);
	if (ret == 0) {
		return 0;
	}

	ttl = _dns_server_get_conf_ttl(request, ttl);
	_dns_server_post_context_init_from(&context, request, packet, inpacket, inpacket_len);
	context.do_cache = 1;
	context.do_audit = 1;
	context.do_reply = 1;
	context.do_ipset = 1;
	context.reply_ttl = ttl;
	return _dns_server_reply_passthrough(&context);
}

static int dns_server_resolve_callback(const char *domain, dns_result_type rtype, struct dns_server_info *server_info,
									   struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									   void *user_ptr)
{
	struct dns_request *request = user_ptr;
	int ret = 0;
	int need_passthrouh = 0;
	unsigned long result_flag = dns_client_server_result_flag(server_info);

	if (request == NULL) {
		return -1;
	}

	if (rtype == DNS_QUERY_RESULT) {
		tlog(TLOG_DEBUG, "query result from server %s:%d, type: %d, domain: %s qtype: %d rcode: %d, id: %d",
			 dns_client_get_server_ip(server_info), dns_client_get_server_port(server_info),
			 dns_client_get_server_type(server_info), domain, request->qtype, packet->head.rcode, request->id);

		if (request->passthrough == 1 && atomic_read(&request->notified) == 0) {
			return _dns_server_resolve_callback_reply_passthrough(request, domain, packet, inpacket, inpacket_len,
																  result_flag);
		}

		if (request->prefetch == 0 && request->response_mode == DNS_RESPONSE_MODE_FASTEST_RESPONSE &&
			atomic_read(&request->notified) == 0) {
			struct dns_server_post_context context;
			int ttl = 0;
			ret = _dns_server_passthrough_rule_check(request, domain, packet, result_flag, &ttl);
			if (ret != 0) {
				_dns_server_post_context_init_from(&context, request, packet, inpacket, inpacket_len);
				context.do_cache = 1;
				context.do_audit = 1;
				context.do_reply = 1;
				context.do_ipset = 1;
				context.reply_ttl = _dns_server_get_reply_ttl(request, ttl);
				context.cache_ttl = _dns_server_get_conf_ttl(request, ttl);
				request->ip_ttl = context.cache_ttl;
				context.no_check_add_ip = 1;
				_dns_server_reply_passthrough(&context);
				request->cname[0] = 0;
				request->has_ip = 0;
				request->has_cname = 0;
				request->has_ping_result = 0;
				request->has_soa = 0;
				request->has_ptr = 0;
				request->ping_time = -1;
				request->ip_ttl = 0;
			}
		}

		ret = _dns_server_process_answer(request, domain, packet, result_flag, &need_passthrouh);
		if (ret == 0 && need_passthrouh == 1 && atomic_read(&request->notified) == 0) {
			/* not supported record, passthrouth */
			request->passthrough = 1;
			return _dns_server_resolve_callback_reply_passthrough(request, domain, packet, inpacket, inpacket_len,
																  result_flag);
		}
		_dns_server_passthrough_may_complete(request);
		return ret;
	} else if (rtype == DNS_QUERY_ERR) {
		tlog(TLOG_ERROR, "request failed, %s", domain);
		return -1;
	} else {
		_dns_server_query_end(request);
	}

	return 0;
}

int dns_server_get_server_name(char *name, int name_len)
{
	if (name == NULL || name_len <= 0) {
		return -1;
	}

	if (dns_conf.server_name[0] == 0) {
		char hostname[DNS_MAX_CNAME_LEN];
		char domainname[DNS_MAX_CNAME_LEN];

		/* get local domain name */
		if (getdomainname(domainname, DNS_MAX_CNAME_LEN - 1) == 0) {
			/* check domain is valid */
			if (strncmp(domainname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
				domainname[0] = '\0';
			}
		}

		if (gethostname(hostname, DNS_MAX_CNAME_LEN - 1) == 0) {
			/* check hostname is valid */
			if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
				hostname[0] = '\0';
			}
		}

		if (hostname[0] != '\0' && domainname[0] != '\0') {
			snprintf(name, name_len, "%.64s.%.128s", hostname, domainname);
		} else if (hostname[0] != '\0') {
			safe_strncpy(name, hostname, name_len);
		} else {
			safe_strncpy(name, "smartdns", name_len);
		}
	} else {
		/* return configured server name */
		safe_strncpy(name, dns_conf.server_name, name_len);
	}

	return 0;
}

int _dns_server_do_query(struct dns_request *request, int skip_notify_event)
{
	int ret = -1;
	const char *server_group_name = NULL;
	struct dns_query_options options;
	char *request_domain = request->domain;
	char domain_buffer[DNS_MAX_CNAME_LEN * 2];

	request->send_tick = get_tick_count();

	if (_dns_server_setup_request_conf_pre(request) != 0) {
		goto errout;
	}

	/* lookup domain rule */
	_dns_server_get_domain_rule(request);

	_dns_server_setup_dns_group_name(request, &server_group_name);

	if (_dns_server_setup_request_conf(request) != 0) {
		goto errout;
	}

	if (_dns_server_mdns_query_setup(request, server_group_name, &request_domain, domain_buffer,
									 sizeof(domain_buffer)) != 0) {
		goto errout;
	}

	if (_dns_server_process_cname_pre(request) != 0) {
		goto errout;
	}

	_dns_server_set_dualstack_selection(request);

	if (_dns_server_process_special_query(request) == 0) {
		goto clean_exit;
	}

	if (_dns_server_pre_process_server_flags(request) == 0) {
		goto clean_exit;
	}

	/* process domain flag */
	if (_dns_server_pre_process_rule_flags(request) == 0) {
		goto clean_exit;
	}

	/* process domain address */
	if (_dns_server_process_address(request) == 0) {
		goto clean_exit;
	}

	if (_dns_server_process_https_svcb(request) != 0) {
		goto clean_exit;
	}

	if (_dns_server_process_smartdns_domain(request) == 0) {
		goto clean_exit;
	}

	if (_dns_server_process_host(request) == 0) {
		goto clean_exit;
	}

	/* process qtype soa */
	if (_dns_server_qtype_soa(request) == 0) {
		goto clean_exit;
	}

	/* process speed check rule */
	_dns_server_process_speed_rule(request);

	/* check and set passthrough */
	_dns_server_check_set_passthrough(request);

	/* process ptr */
	if (_dns_server_process_ptr_query(request) == 0) {
		goto clean_exit;
	}

	/* process cache */
	if (request->prefetch == 0 && request->dualstack_selection_query == 0) {
		_dns_server_mdns_query_setup_server_group(request, &server_group_name);
		if (_dns_server_process_cache(request) == 0) {
			goto clean_exit;
		}
	}

	ret = _dns_server_set_to_pending_list(request);
	if (ret == 0) {
		goto clean_exit;
	}

	if (_dns_server_process_cname(request) != 0) {
		goto clean_exit;
	}

	// setup options
	_dns_server_setup_query_option(request, &options);
	_dns_server_mdns_query_setup_server_group(request, &server_group_name);

	pthread_mutex_lock(&server.request_list_lock);
	if (list_empty(&server.request_list) && skip_notify_event == 1) {
		_dns_server_wakeup_thread();
	}
	list_add_tail(&request->list, &server.request_list);
	pthread_mutex_unlock(&server.request_list_lock);

	if (_dns_server_process_dns64(request) != 0) {
		goto errout;
	}

	// Get reference for DNS query
	request->request_wait++;
	_dns_server_request_get(request);
	if (dns_client_query(request_domain, request->qtype, dns_server_resolve_callback, request, server_group_name,
						 &options) != 0) {
		request->request_wait--;
		_dns_server_request_release(request);
		tlog(TLOG_DEBUG, "send dns request failed.");
		goto errout;
	}

	/* When the dual stack ip preference is enabled, both A and AAAA records are requested. */
	_dns_server_query_dualstack(request);

clean_exit:
	return 0;
errout:
	return ret;
}

static int _dns_server_reply_format_error(struct dns_request *request, struct dns_server_conn_head *conn,
										  unsigned char *inpacket, int inpacket_len, struct sockaddr_storage *local,
										  socklen_t local_len, struct sockaddr_storage *from, socklen_t from_len)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	int decode_len = 0;
	int need_release = 0;
	int ret = -1;

	if (request == NULL) {
		decode_len = dns_decode_head_only(packet, DNS_PACKSIZE, inpacket, inpacket_len);
		if (decode_len < 0) {
			ret = -1;
			goto out;
		}

		request = _dns_server_new_request();
		if (request == NULL) {
			ret = -1;
			goto out;
		}

		need_release = 1;
		memcpy(&request->localaddr, local, local_len);
		_dns_server_request_set_client(request, conn);
		_dns_server_request_set_client_addr(request, from, from_len);
		_dns_server_request_set_id(request, packet->head.id);
	}

	request->rcode = DNS_RC_FORMERR;
	request->no_cache = 1;
	request->send_tick = get_tick_count();
	ret = 0;
out:
	if (request && need_release) {
		_dns_server_request_release(request);
	}

	return ret;
}

int _dns_server_recv(struct dns_server_conn_head *conn, unsigned char *inpacket, int inpacket_len,
					 struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
					 socklen_t from_len)
{
	int decode_len = 0;
	int ret = -1;
	unsigned char packet_buff[DNS_PACKSIZE];
	char name[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_request *request = NULL;
	struct dns_client_rules *client_rules = NULL;

	/* decode packet */
	tlog(TLOG_DEBUG, "recv query packet from %s, len = %d, type = %d",
		 get_host_by_addr(name, sizeof(name), (struct sockaddr *)from), inpacket_len, conn->type);
	decode_len = dns_decode(packet, DNS_PACKSIZE, inpacket, inpacket_len);
	if (decode_len < 0) {
		tlog(TLOG_DEBUG, "decode failed.\n");
		ret = RECV_ERROR_INVALID_PACKET;
		if (dns_conf.dns_save_fail_packet) {
			dns_packet_save(dns_conf.dns_save_fail_packet_dir, "server", name, inpacket, inpacket_len);
		}
		goto errout;
	}

	if (smartdns_plugin_func_server_recv(packet, inpacket, inpacket_len, local, local_len, from, from_len) != 0) {
		return 0;
	}

	tlog(TLOG_DEBUG,
		 "request qdcount = %d, ancount = %d, nscount = %d, nrcount = %d, len = %d, id = %d, tc = %d, rd = %d, "
		 "ra = "
		 "%d, rcode = %d\n",
		 packet->head.qdcount, packet->head.ancount, packet->head.nscount, packet->head.nrcount, inpacket_len,
		 packet->head.id, packet->head.tc, packet->head.rd, packet->head.ra, packet->head.rcode);
	client_rules = _dns_server_get_client_rules(from, from_len);
	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	memcpy(&request->localaddr, local, local_len);
	_dns_server_request_set_mac(request, from, from_len);
	_dns_server_request_set_client(request, conn);
	_dns_server_request_set_client_addr(request, from, from_len);
	_dns_server_request_set_id(request, packet->head.id);
	stats_inc(&dns_stats.request.from_client_count);

	if (_dns_server_parser_request(request, packet) != 0) {
		tlog(TLOG_DEBUG, "parser request failed.");
		ret = RECV_ERROR_INVALID_PACKET;
		goto errout;
	}

	tlog(TLOG_DEBUG, "query %s from %s, qtype: %d, id: %d, query-num: %ld", request->domain, name, request->qtype,
		 request->id, atomic_read(&server.request_num));

	if (atomic_read(&server.request_num) > dns_conf.max_query_limit && dns_conf.max_query_limit > 0) {
		static time_t last_log_time = 0;
		time_t now = time(NULL);
		if (now - last_log_time > 120) {
			last_log_time = now;
			tlog(TLOG_WARN, "maximum number of dns queries reached, max: %d", dns_conf.max_query_limit);
		}
		request->rcode = DNS_RC_REFUSED;
		ret = 0;
		goto errout;
	}

	ret = _dns_server_request_set_client_rules(request, client_rules);
	if (ret != 0) {
		ret = 0;
		goto errout;
	}

	ret = _dns_server_do_query(request, 1);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "do query %s failed.\n", request->domain);
		goto errout;
	}
	_dns_server_request_release_complete(request, 0);
	return ret;
errout:
	if (ret == RECV_ERROR_INVALID_PACKET) {
		if (_dns_server_reply_format_error(request, conn, inpacket, inpacket_len, local, local_len, from, from_len) ==
			0) {
			ret = 0;
		}
	}

	if (request) {
		request->send_tick = get_tick_count();
		request->no_cache = 1;
		_dns_server_forward_request(inpacket, inpacket_len);
		_dns_server_request_release(request);
	}

	return ret;
}

int dns_server_query(const char *domain, int qtype, struct dns_server_query_option *server_query_option,
					 dns_result_callback callback, void *user_ptr)
{
	int ret = -1;
	struct dns_request *request = NULL;

	request = _dns_server_new_request();
	if (request == NULL) {
		tlog(TLOG_ERROR, "malloc failed.\n");
		goto errout;
	}

	safe_strncpy(request->domain, domain, sizeof(request->domain));
	request->qtype = qtype;
	_dns_server_setup_server_query_options(request, server_query_option);
	_dns_server_request_set_callback(request, callback, user_ptr);
	ret = _dns_server_do_query(request, 0);
	if (ret != 0) {
		tlog(TLOG_DEBUG, "do query %s failed.\n", domain);
		goto errout;
	}

	_dns_server_request_release_complete(request, 0);
	return ret;
errout:
	if (request) {
		_dns_server_request_set_callback(request, NULL, NULL);
		_dns_server_request_release(request);
	}

	return ret;
}

static int _dns_server_process(struct dns_server_conn_head *conn, struct epoll_event *event, unsigned long now)
{
	int ret = 0;
	_dns_server_client_touch(conn);
	_dns_server_conn_get(conn);
	if (conn->type == DNS_CONN_TYPE_UDP_SERVER) {
		struct dns_server_conn_udp *udpconn = (struct dns_server_conn_udp *)conn;
		ret = _dns_server_process_udp(udpconn, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TCP_SERVER) {
		struct dns_server_conn_tcp_server *tcpserver = (struct dns_server_conn_tcp_server *)conn;
		ret = _dns_server_tcp_accept(tcpserver, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TCP_CLIENT) {
		struct dns_server_conn_tcp_client *tcpclient = (struct dns_server_conn_tcp_client *)conn;
		ret = _dns_server_process_tcp(tcpclient, event, now);
		if (ret != 0) {
			char name[DNS_MAX_CNAME_LEN];
			tlog(TLOG_DEBUG, "process TCP packet from %s failed.",
				 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&tcpclient->addr));
		}
	} else if (conn->type == DNS_CONN_TYPE_TLS_SERVER || conn->type == DNS_CONN_TYPE_HTTPS_SERVER) {
		struct dns_server_conn_tls_server *tls_server = (struct dns_server_conn_tls_server *)conn;
		ret = _dns_server_tls_accept(tls_server, event, now);
	} else if (conn->type == DNS_CONN_TYPE_TLS_CLIENT || conn->type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)conn;
		ret = _dns_server_process_tls(tls_client, event, now);
		if (ret != 0) {
			char name[DNS_MAX_CNAME_LEN];
			tlog(TLOG_DEBUG, "process TLS packet from %s failed.",
				 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&tls_client->tcp.addr));
		}
	} else {
		tlog(TLOG_ERROR, "unsupported dns server type %d", conn->type);
		_dns_server_client_close(conn);
		ret = -1;
	}
	_dns_server_conn_release(conn);

	if (ret == RECV_ERROR_INVALID_PACKET) {
		ret = 0;
	}

	return ret;
}

static int _dns_server_socket(void)
{
	int i = 0;

	for (i = 0; i < dns_conf.bind_ip_num; i++) {
		struct dns_bind_ip *bind_ip = &dns_conf.bind_ip[i];
		tlog(TLOG_INFO, "bind ip %s, type %d", bind_ip->ip, bind_ip->type);

		switch (bind_ip->type) {
		case DNS_BIND_TYPE_UDP:
			if (_dns_server_socket_udp(bind_ip) != 0) {
				goto errout;
			}
			break;
		case DNS_BIND_TYPE_TCP:
			if (_dns_server_socket_tcp(bind_ip) != 0) {
				goto errout;
			}
			break;
		case DNS_BIND_TYPE_HTTPS:
			if (_dns_server_socket_tls(bind_ip, DNS_CONN_TYPE_HTTPS_SERVER) != 0) {
				goto errout;
			}
			break;
		case DNS_BIND_TYPE_TLS:
			if (_dns_server_socket_tls(bind_ip, DNS_CONN_TYPE_TLS_SERVER) != 0) {
				goto errout;
			}
			break;
		default:
			break;
		}
	}

	return 0;
errout:

	return -1;
}

#ifdef TEST
static void _dns_server_check_need_exit(void)
{
	static int parent_pid = 0;
	if (parent_pid == 0) {
		parent_pid = getppid();
	}

	if (parent_pid != getppid()) {
		tlog(TLOG_WARN, "parent process exit, exit too.");
		dns_server_stop();
	}
}
#else
#define _dns_server_check_need_exit()
#endif

static void _dns_server_period_run_second(void)
{
	static unsigned int sec = 0;
	sec++;

	_dns_server_tcp_idle_check();
	_dns_server_check_need_exit();

	if (sec % IPV6_READY_CHECK_TIME == 0 && is_ipv6_ready == 0) {
		dns_server_check_ipv6_ready();
	}

	if (sec % 60 == 0) {
		if (dns_server_check_update_hosts() == 0) {
			tlog(TLOG_INFO, "Update host file data");
		}
	}

	_dns_server_save_cache_to_file();

	dns_stats_period_run_second();
}

static void _dns_server_period_run(unsigned int msec)
{
	struct dns_request *request = NULL;
	struct dns_request *tmp = NULL;
	LIST_HEAD(check_list);

	if ((msec % 10) == 0) {
		_dns_server_period_run_second();
	}

	unsigned long now = get_tick_count();

	pthread_mutex_lock(&server.request_list_lock);
	list_for_each_entry_safe(request, tmp, &server.request_list, list)
	{
		/* Need to use tcping detection speed */
		int check_order = request->check_order + 1;
		if (atomic_read(&request->ip_map_num) == 0 || request->has_soa) {
			continue;
		}

		if (request->send_tick < now - (check_order * DNS_PING_CHECK_INTERVAL) && request->has_ping_result == 0) {
			_dns_server_request_get(request);
			list_add_tail(&request->check_list, &check_list);
			request->check_order++;
		}
	}
	pthread_mutex_unlock(&server.request_list_lock);

	list_for_each_entry_safe(request, tmp, &check_list, check_list)
	{
		_dns_server_second_ping_check(request);
		list_del_init(&request->check_list);
		_dns_server_request_release(request);
	}
}

int dns_server_run(void)
{
	struct epoll_event events[DNS_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	unsigned long last = {0};
	unsigned int msec = 0;
	int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;

	sleep_time = sleep;
	now = get_tick_count() - sleep;
	last = now;
	expect_time = now + sleep;
	while (atomic_read(&server.run)) {
		now = get_tick_count();
		if (sleep_time > 0) {
			sleep_time -= now - last;
			if (sleep_time <= 0) {
				sleep_time = 0;
			}

			int cnt = sleep_time / sleep;
			msec -= cnt;
			expect_time -= cnt * sleep;
			sleep_time -= cnt * sleep;
		}

		if (now >= expect_time) {
			msec++;
			if (last != now) {
				_dns_server_period_run(msec);
			}
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}

			/* When server is idle, the sleep time is 1000ms, to reduce CPU usage */
			pthread_mutex_lock(&server.request_list_lock);
			if (list_empty(&server.request_list)) {
				int cnt = 10 - (msec % 10) - 1;
				sleep_time += sleep * cnt;
				msec += cnt;
				/* sleep to next second */
				expect_time += sleep * cnt;
			}
			pthread_mutex_unlock(&server.request_list_lock);
			expect_time += sleep;
		}
		last = now;

		num = epoll_wait(server.epoll_fd, events, DNS_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		if (num == 0) {
			continue;
		}

		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			/* read event */
			if (unlikely(event->data.fd == server.event_fd)) {
				uint64_t value;
				int unused __attribute__((unused));
				unused = read(server.event_fd, &value, sizeof(uint64_t));
				continue;
			}

			if (unlikely(event->data.fd == server.local_addr_cache.fd_netlink)) {
				_dns_server_process_local_addr_cache(event->data.fd, event, now);
				continue;
			}

			struct dns_server_conn_head *conn_head = event->data.ptr;
			if (conn_head == NULL) {
				tlog(TLOG_ERROR, "invalid fd\n");
				continue;
			}

			if (_dns_server_process(conn_head, event, now) != 0) {
				tlog(TLOG_DEBUG, "dns server process failed.");
			}
		}
	}

	_dns_server_close_socket_server();
	close(server.epoll_fd);
	server.epoll_fd = -1;

	return 0;
}

int dns_server_start(void)
{
	struct dns_server_conn_head *conn = NULL;

	list_for_each_entry(conn, &server.conn_list, list)
	{
		if (conn->fd <= 0) {
			continue;
		}

		if (_dns_server_epoll_ctl(conn, EPOLL_CTL_ADD, EPOLLIN) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed.");
			return -1;
		}
	}

	return 0;
}

static int _dns_server_init_wakeup_event(void)
{
	int fdevent = -1;
	fdevent = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fdevent < 0) {
		tlog(TLOG_ERROR, "create eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLERR;
	event.data.fd = fdevent;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_ADD, fdevent, &event) != 0) {
		tlog(TLOG_ERROR, "set eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	server.event_fd = fdevent;

	return 0;
errout:
	return -1;
}

int dns_server_init(void)
{
	pthread_mutexattr_t attr;
	int epollfd = -1;
	int ret = -1;

	_dns_server_check_need_exit();

	if (is_server_init == 1) {
		return -1;
	}

	if (server.epoll_fd > 0) {
		return -1;
	}

	if (_dns_server_audit_init() != 0) {
		tlog(TLOG_ERROR, "init audit failed.");
		goto errout;
	}

	memset(&server, 0, sizeof(server));

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

	INIT_LIST_HEAD(&server.conn_list);
	time(&server.cache_save_time);
	atomic_set(&server.request_num, 0);
	pthread_mutex_init(&server.request_list_lock, NULL);
	pthread_mutex_init(&server.conn_list_lock, &attr);
	INIT_LIST_HEAD(&server.request_list);
	pthread_mutexattr_destroy(&attr);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	ret = _dns_server_socket();
	if (ret != 0) {
		tlog(TLOG_ERROR, "create server socket failed.\n");
		goto errout;
	}

	server.epoll_fd = epollfd;
	atomic_set(&server.run, 1);

	if (dns_server_start() != 0) {
		tlog(TLOG_ERROR, "start service failed.\n");
		goto errout;
	}

	dns_server_check_ipv6_ready();
	tlog(TLOG_INFO, "%s",
		 (is_ipv6_ready) ? "IPV6 is ready, enable IPV6 features"
						 : "IPV6 is not ready or speed check is disabled, disable IPV6 features");

	if (_dns_server_init_wakeup_event() != 0) {
		tlog(TLOG_ERROR, "init wakeup event failed.");
		goto errout;
	}

	if (_dns_server_cache_init() != 0) {
		tlog(TLOG_ERROR, "init dns cache filed.");
		goto errout;
	}

	if (_dns_server_local_addr_cache_init() != 0) {
		tlog(TLOG_WARN, "init local addr cache failed, disable local ptr.");
		dns_conf.local_ptr_enable = 0;
	}

	if (_dns_server_neighbor_cache_init() != 0) {
		tlog(TLOG_ERROR, "init neighbor cache failed.");
		goto errout;
	}

	is_server_init = 1;
	return 0;
errout:
	atomic_set(&server.run, 0);

	if (epollfd) {
		close(epollfd);
	}

	_dns_server_close_socket();
	pthread_mutex_destroy(&server.request_list_lock);

	return -1;
}

void dns_server_stop(void)
{
	atomic_set(&server.run, 0);
	_dns_server_wakeup_thread();
}

void dns_server_exit(void)
{
	if (is_server_init == 0) {
		return;
	}

	if (server.event_fd > 0) {
		close(server.event_fd);
		server.event_fd = -1;
	}

	if (server.cache_save_pid > 0) {
		kill(server.cache_save_pid, SIGKILL);
		server.cache_save_pid = 0;
	}

	_dns_server_close_socket();
	_dns_server_local_addr_cache_destroy();
	_dns_server_neighbor_cache_remove_all();
	_dns_server_cache_save(0);
	_dns_server_request_remove_all();
	pthread_mutex_destroy(&server.request_list_lock);
	dns_cache_destroy();

	is_server_init = 0;
}
