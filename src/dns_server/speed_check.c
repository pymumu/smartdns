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

#include "speed_check.h"
#include "address.h"
#include "dns_server.h"
#include "dualstack.h"
#include "request.h"

#include "smartdns/fast_ping.h"
#include <errno.h>
#include <string.h>

static void _dns_server_ping_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
									struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
									int error, void *userptr)
{
	struct dns_request *request = userptr;
	int may_complete = 0;
	int threshold = 100;
	struct dns_ip_address *addr_map = NULL;
	int last_rtt = request->ping_time;

	if (request == NULL) {
		return;
	}

	if (result == PING_RESULT_END) {
		_dns_server_request_release(request);
		fast_ping_stop(ping_host);
		return;
	} else if (result == PING_RESULT_TIMEOUT) {
		tlog(TLOG_DEBUG, "ping %s timeout", host);
		goto out;
		return;
	} else if (result == PING_RESULT_ERROR) {
		if (addr->sa_family != AF_INET6) {
			return;
		}

		if (is_ipv6_ready == 1 && (error == EADDRNOTAVAIL || errno == EACCES)) {
			if (is_private_addr_sockaddr(addr, addr_len) == 0) {
				is_ipv6_ready = 0;
				tlog(TLOG_WARN, "IPV6 is not ready, disable all ipv6 feature, recheck after %ds",
					 IPV6_READY_CHECK_TIME);
			}
		}
		return;
	}

	int rtt = tv->tv_sec * 10000 + tv->tv_usec / 100;
	if (rtt == 0) {
		rtt = 1;
	}

	if (result == PING_RESULT_RESPONSE) {
		tlog(TLOG_DEBUG, "from %s: seq=%d time=%d, lasttime=%d id=%d", host, seqno, rtt, last_rtt, request->id);
	} else {
		tlog(TLOG_DEBUG, "from %s: seq=%d timeout, id=%d", host, seqno, request->id);
	}

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		addr_map = _dns_ip_address_get(request, (unsigned char *)&addr_in->sin_addr.s_addr, DNS_T_A);
		if (addr_map) {
			addr_map->ping_time = rtt;
		}

		if (request->ping_time > rtt || request->ping_time == -1) {
			memcpy(request->ip_addr, &addr_in->sin_addr.s_addr, 4);
			request->ip_addr_type = DNS_T_A;
			request->ping_time = rtt;
			request->has_cname = 0;
			request->has_ip = 1;
			if (addr_map && addr_map->cname[0] != 0) {
				request->has_cname = 1;
				safe_strncpy(request->cname, addr_map->cname, DNS_MAX_CNAME_LEN);
			} else {
				request->has_cname = 0;
			}
		}

		if (request->qtype == DNS_T_AAAA && request->dualstack_selection) {
			if (request->ping_time < 0 && request->has_soa == 0) {
				return;
			}
		}

		if (request->qtype == DNS_T_A || request->qtype == DNS_T_HTTPS) {
			request->has_ping_result = 1;
		}
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			addr_map = _dns_ip_address_get(request, addr_in6->sin6_addr.s6_addr + 12, DNS_T_A);
			if (addr_map) {
				addr_map->ping_time = rtt;
			}

			if (request->ping_time > rtt || request->ping_time == -1) {
				request->ping_time = rtt;
				request->has_cname = 0;
				request->has_ip = 1;
				memcpy(request->ip_addr, addr_in6->sin6_addr.s6_addr + 12, 4);
				request->ip_addr_type = DNS_T_A;
				if (addr_map && addr_map->cname[0] != 0) {
					request->has_cname = 1;
					safe_strncpy(request->cname, addr_map->cname, DNS_MAX_CNAME_LEN);
				} else {
					request->has_cname = 0;
				}
			}

			if (request->qtype == DNS_T_A || request->qtype == DNS_T_HTTPS) {
				request->has_ping_result = 1;
			}
		} else {
			addr_map = _dns_ip_address_get(request, addr_in6->sin6_addr.s6_addr, DNS_T_AAAA);
			if (addr_map) {
				addr_map->ping_time = rtt;
			}

			if (request->ping_time > rtt || request->ping_time == -1) {
				request->ping_time = rtt;
				request->has_cname = 0;
				request->has_ip = 1;
				memcpy(request->ip_addr, addr_in6->sin6_addr.s6_addr, 16);
				request->ip_addr_type = DNS_T_AAAA;
				if (addr_map && addr_map->cname[0] != 0) {
					request->has_cname = 1;
					safe_strncpy(request->cname, addr_map->cname, DNS_MAX_CNAME_LEN);
				} else {
					request->has_cname = 0;
				}
			}

			if (request->qtype == DNS_T_AAAA || request->qtype == DNS_T_HTTPS) {
				request->has_ping_result = 1;
			}
		}
	} break;
	default:
		break;
	}

out:
	/* If the ping delay is less than the threshold, the result is returned */
	if (request->ping_time > 0) {
		if (request->ping_time < threshold) {
			may_complete = 1;
		} else if (request->ping_time < (int)(get_tick_count() - request->send_tick)) {
			may_complete = 1;
		}
	}

	/* Get first ping result */
	if (request->response_mode == DNS_RESPONSE_MODE_FIRST_PING_IP && last_rtt == -1 && request->ping_time > 0) {
		may_complete = 1;
	}

	if (may_complete && request->has_ping_result == 1) {
		_dns_server_request_complete(request);
	}
}

static int _dns_server_ping(struct dns_request *request, PING_TYPE type, char *ip, int timeout)
{
	if (fast_ping_start(type, ip, 1, 0, timeout, _dns_server_ping_result, request) == NULL) {
		return -1;
	}

	return 0;
}

int _dns_server_check_speed(struct dns_request *request, char *ip)
{
	char tcp_ip[DNS_MAX_CNAME_LEN] = {0};
	int port = 80;
	int type = DOMAIN_CHECK_NONE;
	int order = request->check_order;
	int ping_timeout = DNS_PING_TIMEOUT;
	unsigned long now = get_tick_count();

	if (order >= DOMAIN_CHECK_NUM || request->check_order_list == NULL) {
		return -1;
	}

	if (request->passthrough) {
		return -1;
	}

	ping_timeout = ping_timeout - (now - request->send_tick);
	if (ping_timeout > DNS_PING_TIMEOUT) {
		ping_timeout = DNS_PING_TIMEOUT;
	} else if (ping_timeout < 200) {
		ping_timeout = 200;
	}

	port = request->check_order_list->orders[order].tcp_port;
	type = request->check_order_list->orders[order].type;
	switch (type) {
	case DOMAIN_CHECK_ICMP:
		tlog(TLOG_DEBUG, "ping %s with icmp, order: %d, timeout: %d", ip, order, ping_timeout);
		return _dns_server_ping(request, PING_TYPE_ICMP, ip, ping_timeout);
		break;
	case DOMAIN_CHECK_TCP:
		snprintf(tcp_ip, sizeof(tcp_ip), "%s:%d", ip, port);
		tlog(TLOG_DEBUG, "ping %s with tcp, order: %d, timeout: %d", tcp_ip, order, ping_timeout);
		return _dns_server_ping(request, PING_TYPE_TCP, tcp_ip, ping_timeout);
		break;
	default:
		break;
	}

	return -1;
}

int _dns_server_second_ping_check(struct dns_request *request)
{
	struct dns_ip_address *addr_map = NULL;
	unsigned long bucket = 0;
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ret = -1;

	if (request->has_ping_result) {
		return ret;
	}

	/* start tcping */
	pthread_mutex_lock(&request->ip_map_lock);
	hash_for_each(request->ip_map, bucket, addr_map, node)
	{
		switch (addr_map->addr_type) {
		case DNS_T_A: {
			_dns_server_request_get(request);
			snprintf(ip, sizeof(ip), "%d.%d.%d.%d", addr_map->ip_addr[0], addr_map->ip_addr[1], addr_map->ip_addr[2],
					 addr_map->ip_addr[3]);
			ret = _dns_server_check_speed(request, ip);
			if (ret != 0) {
				_dns_server_request_release(request);
			}
		} break;
		case DNS_T_AAAA: {
			_dns_server_request_get(request);
			snprintf(ip, sizeof(ip), "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]",
					 addr_map->ip_addr[0], addr_map->ip_addr[1], addr_map->ip_addr[2], addr_map->ip_addr[3],
					 addr_map->ip_addr[4], addr_map->ip_addr[5], addr_map->ip_addr[6], addr_map->ip_addr[7],
					 addr_map->ip_addr[8], addr_map->ip_addr[9], addr_map->ip_addr[10], addr_map->ip_addr[11],
					 addr_map->ip_addr[12], addr_map->ip_addr[13], addr_map->ip_addr[14], addr_map->ip_addr[15]);
			ret = _dns_server_check_speed(request, ip);
			if (ret != 0) {
				_dns_server_request_release(request);
			}
		} break;
		default:
			break;
		}
	}
	pthread_mutex_unlock(&request->ip_map_lock);

	return ret;
}
