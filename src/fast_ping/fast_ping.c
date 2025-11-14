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

#include "smartdns/fast_ping.h"
#include "smartdns/lib/atomic.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include "fast_ping.h"
#include "notify_event.h"
#include "ping_fake.h"
#include "ping_host.h"
#include "ping_icmp.h"
#include "ping_icmp6.h"
#include "ping_tcp.h"
#include "ping_tcp_syn.h"
#include "ping_udp.h"
#include "wakeup_event.h"

#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>

static int is_fast_ping_init;
struct fast_ping_struct ping;
static atomic_t ping_sid = ATOMIC_INIT(0);
int bool_print_log = 1;

uint32_t _fast_ping_hash_key(unsigned int sid, struct sockaddr *addr)
{
	uint32_t key = 0;
	void *sin_addr = NULL;
	unsigned int sin_addr_len = 0;

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)addr;
		sin_addr = &addr_in->sin_addr.s_addr;
		sin_addr_len = IPV4_ADDR_LEN;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			sin_addr = addr_in6->sin6_addr.s6_addr + 12;
			sin_addr_len = IPV4_ADDR_LEN;
		} else {
			sin_addr = addr_in6->sin6_addr.s6_addr;
			sin_addr_len = IPV6_ADDR_LEN;
		}
	} break;
	default:
		goto errout;
		break;
	}
	if (sin_addr == NULL) {
		return -1;
	}

	key = jhash(sin_addr, sin_addr_len, 0);
	key = jhash(&sid, sizeof(sid), key);

	return key;
errout:
	return -1;
}

struct addrinfo *_fast_ping_getaddr(const char *host, const char *port, int type, int protocol)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int errcode = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	errcode = getaddrinfo(host, port, &hints, &result);
	if (errcode != 0) {
		tlog(TLOG_ERROR, "get addr info failed. host:%s, port: %s, error %s\n", host != NULL ? host : "",
			 port != NULL ? port : "", gai_strerror(errcode));
		goto errout;
	}

	return result;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

int _fast_ping_getdomain(const char *host)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int domain = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	if (getaddrinfo(host, NULL, &hints, &result) != 0) {
		tlog(TLOG_ERROR, "get addr info failed. %s\n", strerror(errno));
		goto errout;
	}

	domain = result->ai_family;

	freeaddrinfo(result);

	return domain;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return -1;
}

static int _fast_ping_sendping(struct ping_host_struct *ping_host)
{
	int ret = -1;
	struct fast_ping_fake_ip *fake = NULL;
	gettimeofday(&ping_host->last, NULL);

	fake = _fast_ping_fake_find(ping_host->type, &ping_host->addr, ping_host->addr_len);
	if (fake) {
		ret = _fast_ping_send_fake(ping_host, fake);
		_fast_ping_fake_put(fake);
		return ret;
	}

	if (ping_host->type == FAST_PING_ICMP) {
		ret = _fast_ping_sendping_v4(ping_host);
	} else if (ping_host->type == FAST_PING_ICMP6) {
		ret = _fast_ping_sendping_v6(ping_host);
	} else if (ping_host->type == FAST_PING_TCP) {
		ret = _fast_ping_sendping_tcp(ping_host);
	} else if (ping_host->type == FAST_PING_TCP_SYN) {
		ret = _fast_ping_sendping_tcp_syn(ping_host);
	} else if (ping_host->type == FAST_PING_UDP || ping_host->type == FAST_PING_UDP6) {
		ret = _fast_ping_sendping_udp(ping_host);
	}

	ping_host->send = 1;

	if (ret != 0) {
		ping_host->error = errno;
		return ret;
	} else {
		ping_host->error = 0;
	}

	return 0;
}

static void _fast_ping_print_result(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
									struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
									int error, void *userptr)
{
	if (result == PING_RESULT_RESPONSE) {
		double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
		tlog(TLOG_INFO, "from %15s: seq=%d ttl=%d time=%.3f\n", host, seqno, ttl, rtt);
	} else if (result == PING_RESULT_TIMEOUT) {
		tlog(TLOG_INFO, "from %15s: seq=%d timeout\n", host, seqno);
	} else if (result == PING_RESULT_ERROR) {
		tlog(TLOG_DEBUG, "from %15s: error is %s\n", host, strerror(error));
	} else if (result == PING_RESULT_END) {
		fast_ping_stop(ping_host);
	}
}

int _fast_ping_get_addr_by_type(PING_TYPE type, const char *ip_str, int port, struct addrinfo **out_gai,
									   FAST_PING_TYPE *out_ping_type)
{
	switch (type) {
	case PING_TYPE_ICMP:
		return _fast_ping_get_addr_by_icmp(ip_str, port, out_gai, out_ping_type);
		break;
	case PING_TYPE_TCP:
		return _fast_ping_get_addr_by_tcp(ip_str, port, out_gai, out_ping_type);
		break;
	case PING_TYPE_TCP_SYN:
		return _fast_ping_get_addr_by_tcp_syn(ip_str, port, out_gai, out_ping_type);
		break;
	case PING_TYPE_DNS:
		return _fast_ping_get_addr_by_dns(ip_str, port, out_gai, out_ping_type);
		break;
	default:
		break;
	}

	return -1;
}

struct ping_host_struct *fast_ping_start(PING_TYPE type, const char *host, int count, int interval, int timeout,
										 fast_ping_result ping_callback, void *userptr)
{
	struct ping_host_struct *ping_host = NULL;
	struct addrinfo *gai = NULL;
	uint32_t addrkey = 0;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	int ret = 0;
	struct fast_ping_fake_ip *fake = NULL;
	int fake_time_fd = -1;

	if (parse_ip(host, ip_str, &port) != 0) {
		goto errout;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
		goto errout;
	}

	ping_host = zalloc(1, sizeof(*ping_host));
	if (ping_host == NULL) {
		goto errout;
	}
	safe_strncpy(ping_host->host, host, PING_MAX_HOSTLEN);
	ping_host->fd = -1;
	ping_host->timeout = timeout;
	ping_host->count = count;
	ping_host->type = ping_type;
	ping_host->userptr = userptr;
	atomic_set(&ping_host->ref, 0);
	atomic_set(&ping_host->notified, 0);
	ping_host->sid = atomic_inc_return(&ping_sid);
	ping_host->run = 0;
	if (ping_callback) {
		ping_host->ping_callback = ping_callback;
	} else {
		ping_host->ping_callback = _fast_ping_print_result;
	}
	ping_host->interval = (timeout > interval) ? timeout : interval;
	ping_host->addr_len = gai->ai_addrlen;
	ping_host->port = port;
	ping_host->ss_family = gai->ai_family;
	if (gai->ai_addrlen > sizeof(struct sockaddr_in6)) {
		goto errout;
	}
	memcpy(&ping_host->addr, gai->ai_addr, gai->ai_addrlen);

	tlog(TLOG_DEBUG, "ping %s, id = %d", host, ping_host->sid);

	fake = _fast_ping_fake_find(ping_host->type, gai->ai_addr, gai->ai_addrlen);
	if (fake) {
		fake_time_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (fake_time_fd < 0) {
			tlog(TLOG_ERROR, "timerfd_create failed, %s", strerror(errno));
			goto errout;
		}
		/* already take ownership by find. */
		ping_host->fake = fake;
		ping_host->fake_time_fd = fake_time_fd;
		fake = NULL;
	}

	addrkey = _fast_ping_hash_key(ping_host->sid, &ping_host->addr);

	_fast_ping_host_get(ping_host);
	_fast_ping_host_get(ping_host);
	// for ping race condition, get reference count twice
	if (_fast_ping_sendping(ping_host) != 0) {
		goto errout_remove;
	}

	pthread_mutex_lock(&ping.map_lock);
	_fast_ping_host_get(ping_host);
	if (hash_empty(ping.addrmap)) {
		_fast_ping_wakeup_thread();
	}
	hash_add(ping.addrmap, &ping_host->addr_node, addrkey);
	ping_host->run = 1;
	pthread_mutex_unlock(&ping.map_lock);
	freeaddrinfo(gai);
	_fast_ping_host_put(ping_host);
	return ping_host;
errout_remove:
	ping_host->ping_callback(ping_host, ping_host->host, PING_RESULT_ERROR, &ping_host->addr, ping_host->addr_len,
							 ping_host->seq, ping_host->ttl, NULL, ping_host->error, ping_host->userptr);
	fast_ping_stop(ping_host);
	_fast_ping_host_put(ping_host);
	ping_host = NULL;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}

	if (ping_host) {
		free(ping_host);
	}

	if (fake_time_fd > 0) {
		close(fake_time_fd);
	}

	if (fake) {
		_fast_ping_fake_put(fake);
	}

	return NULL;
}

int fast_ping_stop(struct ping_host_struct *ping_host)
{
	if (ping_host == NULL) {
		return 0;
	}

	atomic_inc_return(&ping_host->notified);
	_fast_ping_host_remove(ping_host);
	_fast_ping_host_put(ping_host);
	return 0;
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static int _fast_ping_process(struct ping_host_struct *ping_host, struct epoll_event *event, struct timeval *now)
{
	int ret = -1;

	if (ping_host->fake != NULL) {
		ret = _fast_ping_process_fake(ping_host, now);
		return ret;
	}

	switch (ping_host->type) {
	case FAST_PING_ICMP6:
	case FAST_PING_ICMP:
		ret = _fast_ping_process_icmp(ping_host, now);
		break;
	case FAST_PING_TCP:
		ret = _fast_ping_process_tcp(ping_host, event, now);
		break;
	case FAST_PING_TCP_SYN:
		ret = _fast_ping_process_tcp_syn(ping_host, now);
		break;
	case FAST_PING_UDP6:
	case FAST_PING_UDP:
		ret = _fast_ping_process_udp(ping_host, now);
		break;
	default:
		tlog(TLOG_ERROR, "BUG: type error : %p, %d, %s, %d", ping_host, ping_host->sid, ping_host->host, ping_host->fd);
		abort();
		break;
	}

	return ret;
}

static void _fast_ping_period_run(void)
{
	struct ping_host_struct *ping_host = NULL;
	struct ping_host_struct *ping_host_tmp = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;
	struct timeval now;
	struct timezone tz;
	struct timeval interval;
	int64_t millisecond = 0;
	gettimeofday(&now, &tz);
	LIST_HEAD(action);

	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_safe(ping.addrmap, i, tmp, ping_host, addr_node)
	{
		if (ping_host->run == 0) {
			continue;
		}

		interval = now;
		tv_sub(&interval, &ping_host->last);
		millisecond = interval.tv_sec * 1000 + interval.tv_usec / 1000;
		if (millisecond >= ping_host->timeout && ping_host->send == 1) {
			list_add_tail(&ping_host->action_list, &action);
			_fast_ping_host_get(ping_host);
			continue;
		}

		if (millisecond < ping_host->interval) {
			continue;
		}

		list_add_tail(&ping_host->action_list, &action);
		_fast_ping_host_get(ping_host);
	}
	pthread_mutex_unlock(&ping.map_lock);

	list_for_each_entry_safe(ping_host, ping_host_tmp, &action, action_list)
	{
		interval = now;
		tv_sub(&interval, &ping_host->last);
		millisecond = interval.tv_sec * 1000 + interval.tv_usec / 1000;
		if (millisecond >= ping_host->timeout && ping_host->send == 1) {
			_fast_ping_send_notify_event(ping_host, PING_RESULT_TIMEOUT, ping_host->seq, ping_host->ttl, &interval);
			ping_host->send = 0;
		}

		if (millisecond < ping_host->interval) {
			list_del(&ping_host->action_list);
			_fast_ping_host_put(ping_host);
			continue;
		}

		if (ping_host->count > 0) {
			if (ping_host->count == 1) {
				_fast_ping_host_remove(ping_host);
				list_del(&ping_host->action_list);
				_fast_ping_host_put(ping_host);
				continue;
			}
			ping_host->count--;
		}

		_fast_ping_sendping(ping_host);
		list_del(&ping_host->action_list);
		_fast_ping_host_put(ping_host);
	}
}

static void *_fast_ping_work(void *arg)
{
	struct epoll_event events[PING_MAX_EVENTS + 1];
	int num = 0;
	int i = 0;
	unsigned long now = {0};
	struct timeval tvnow = {0};
	int sleep = 100;
	int sleep_time = 0;
	unsigned long expect_time = 0;
	unsigned long start_time = 0;

	setpriority(PRIO_PROCESS, 0, -5);

	now = get_tick_count();
	start_time = now;
	expect_time = now + sleep;
	
	while (atomic_read(&ping.run)) {
		now = get_tick_count();
		
		if (now >= expect_time) {
			_fast_ping_period_run();
			unsigned long elapsed_from_start = now - start_time;
			unsigned long next_period = (elapsed_from_start / sleep) + 1;
			expect_time = start_time + next_period * sleep;
		}
		
		sleep_time = (int)(expect_time - now);
		if (sleep_time < 0) {
			sleep_time = 0;
		}

		pthread_mutex_lock(&ping.map_lock);
		if (hash_empty(ping.addrmap)) {
			sleep_time = -1; 
		}
		pthread_mutex_unlock(&ping.map_lock);

		num = epoll_wait(ping.epoll_fd, events, PING_MAX_EVENTS, sleep_time);
		if (num < 0) {
			usleep(100000);
			continue;
		}

		if (sleep_time == -1) {
			now = get_tick_count();
			start_time = now;
			expect_time = now + sleep;
		}

		if (num == 0) {
			continue;
		}

		gettimeofday(&tvnow, NULL);
		for (i = 0; i < num; i++) {
			struct epoll_event *event = &events[i];
			/* read event */
			if (event->data.fd == ping.event_fd) {
				uint64_t value;
				int unused __attribute__((unused));
				unused = read(ping.event_fd, &value, sizeof(uint64_t));
				continue;
			}

			struct ping_host_struct *ping_host = (struct ping_host_struct *)event->data.ptr;
			_fast_ping_process(ping_host, event, &tvnow);
		}
	}

	close(ping.epoll_fd);
	ping.epoll_fd = -1;

	return NULL;
}

int fast_ping_init(void)
{
	pthread_attr_t attr;
	int epollfd = -1;
	int ret = 0;
	bool_print_log = 1;

	if (is_fast_ping_init == 1) {
		return -1;
	}

	if (ping.epoll_fd > 0) {
		return -1;
	}

	memset(&ping, 0, sizeof(ping));
	pthread_attr_init(&attr);

	epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (epollfd < 0) {
		tlog(TLOG_ERROR, "create epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	pthread_mutex_init(&ping.map_lock, NULL);
	pthread_mutex_init(&ping.lock, NULL);
	pthread_mutex_init(&ping.notify_lock, NULL);
	pthread_cond_init(&ping.notify_cond, NULL);

	INIT_LIST_HEAD(&ping.notify_event_list);

	hash_init(ping.addrmap);
	hash_init(ping.fake);
	ping.no_unprivileged_ping = !has_unprivileged_ping();
	ping.ident = (getpid() & 0XFFFF);
	atomic_set(&ping.run, 1);

	ping.epoll_fd = epollfd;
	ret = pthread_create(&ping.tid, &attr, _fast_ping_work, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create ping work thread failed, %s\n", strerror(ret));
		goto errout;
	}

	ret = pthread_create(&ping.notify_tid, &attr, _fast_ping_notify_worker, NULL);
	if (ret != 0) {
		tlog(TLOG_ERROR, "create ping notifier work thread failed, %s\n", strerror(ret));
		goto errout;
	}

	ret = _fast_ping_init_wakeup_event();
	if (ret != 0) {
		tlog(TLOG_ERROR, "init wakeup event failed, %s\n", strerror(errno));
		goto errout;
	}

	is_fast_ping_init = 1;
	return 0;
errout:
	if (ping.notify_tid) {
		void *retval = NULL;
		atomic_set(&ping.run, 0);
		pthread_cond_signal(&ping.notify_cond);
		pthread_join(ping.notify_tid, &retval);
		ping.notify_tid = 0;
	}

	if (ping.tid) {
		void *retval = NULL;
		atomic_set(&ping.run, 0);
		_fast_ping_wakeup_thread();
		pthread_join(ping.tid, &retval);
		ping.tid = 0;
	}

	if (epollfd > 0) {
		close(epollfd);
		ping.epoll_fd = -1;
	}

	if (ping.event_fd) {
		close(ping.event_fd);
		ping.event_fd = -1;
	}

	pthread_cond_destroy(&ping.notify_cond);
	pthread_mutex_destroy(&ping.notify_lock);
	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);
	memset(&ping, 0, sizeof(ping));

	return -1;
}

static void _fast_ping_close_fds(void)
{
	_fast_ping_close_icmp();
	_fast_ping_close_udp();
	_fast_ping_close_tcp_syn();
}

void fast_ping_exit(void)
{
	if (is_fast_ping_init == 0) {
		return;
	}

	if (ping.notify_tid) {
		void *retval = NULL;
		atomic_set(&ping.run, 0);
		pthread_cond_signal(&ping.notify_cond);
		pthread_join(ping.notify_tid, &retval);
		ping.notify_tid = 0;
	}

	if (ping.tid) {
		void *ret = NULL;
		atomic_set(&ping.run, 0);
		_fast_ping_wakeup_thread();
		pthread_join(ping.tid, &ret);
		ping.tid = 0;
	}

	if (ping.event_fd > 0) {
		close(ping.event_fd);
		ping.event_fd = -1;
	}

	_fast_ping_close_fds();
	_fast_ping_remove_all();
	_fast_ping_remove_all_fake_ip();
	_fast_ping_remove_all_notify_event();

	pthread_cond_destroy(&ping.notify_cond);
	pthread_mutex_destroy(&ping.notify_lock);
	pthread_mutex_destroy(&ping.lock);
	pthread_mutex_destroy(&ping.map_lock);

	is_fast_ping_init = 0;
}
