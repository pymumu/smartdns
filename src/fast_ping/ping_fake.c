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

#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include "notify_event.h"
#include "ping_fake.h"
#include "ping_host.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

void _fast_ping_fake_put(struct fast_ping_fake_ip *fake)
{
	int ref_cnt = atomic_dec_and_test(&fake->ref);
	if (!ref_cnt) {
		if (ref_cnt < 0) {
			tlog(TLOG_ERROR, "invalid refcount of fake ping %s", fake->host);
			abort();
		}
		return;
	}

	pthread_mutex_lock(&ping.map_lock);
	if (hash_hashed(&fake->node)) {
		hash_del(&fake->node);
	}
	pthread_mutex_unlock(&ping.map_lock);

	free(fake);
}

void _fast_ping_fake_remove(struct fast_ping_fake_ip *fake)
{
	pthread_mutex_lock(&ping.map_lock);
	if (hash_hashed(&fake->node)) {
		hash_del(&fake->node);
	}
	pthread_mutex_unlock(&ping.map_lock);

	_fast_ping_fake_put(fake);
}

void _fast_ping_fake_get(struct fast_ping_fake_ip *fake)
{
	atomic_inc(&fake->ref);
}

struct fast_ping_fake_ip *_fast_ping_fake_find(FAST_PING_TYPE ping_type, struct sockaddr *addr, int addr_len)
{
	struct fast_ping_fake_ip *fake = NULL;
	struct fast_ping_fake_ip *ret = NULL;
	uint32_t key = 0;

	if (ping.fake_ip_num == 0) {
		return NULL;
	}

	key = jhash(addr, addr_len, 0);
	key = jhash(&ping_type, sizeof(ping_type), key);
	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_possible(ping.fake, fake, node, key)
	{
		if (fake->ping_type != ping_type) {
			continue;
		}

		if (fake->addr_len != addr_len) {
			continue;
		}

		if (memcmp(&fake->addr, addr, fake->addr_len) != 0) {
			continue;
		}

		ret = fake;
		_fast_ping_fake_get(fake);
		break;
	}
	pthread_mutex_unlock(&ping.map_lock);
	return ret;
}

int fast_ping_fake_ip_add(PING_TYPE type, const char *host, int ttl, float time)
{
	struct fast_ping_fake_ip *fake = NULL;
	struct fast_ping_fake_ip *fake_old = NULL;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	uint32_t key = 0;
	int ret = -1;
	struct addrinfo *gai = NULL;

	if (parse_ip(host, ip_str, &port) != 0) {
		goto errout;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
		goto errout;
	}

	fake_old = _fast_ping_fake_find(ping_type, gai->ai_addr, gai->ai_addrlen);
	fake = malloc(sizeof(*fake));
	if (fake == NULL) {
		goto errout;
	}
	memset(fake, 0, sizeof(*fake));

	safe_strncpy(fake->host, ip_str, PING_MAX_HOSTLEN);
	fake->ttl = ttl;
	fake->time = time;
	fake->type = type;
	fake->ping_type = ping_type;
	memcpy(&fake->addr, gai->ai_addr, gai->ai_addrlen);
	fake->addr_len = gai->ai_addrlen;
	INIT_HLIST_NODE(&fake->node);
	atomic_set(&fake->ref, 1);

	key = jhash(&fake->addr, fake->addr_len, 0);
	key = jhash(&ping_type, sizeof(ping_type), key);
	pthread_mutex_lock(&ping.map_lock);
	hash_add(ping.fake, &fake->node, key);
	pthread_mutex_unlock(&ping.map_lock);
	ping.fake_ip_num++;

	if (fake_old != NULL) {
		_fast_ping_fake_put(fake_old);
		_fast_ping_fake_remove(fake_old);
	}

	freeaddrinfo(gai);
	return 0;
errout:
	if (fake != NULL) {
		free(fake);
	}

	if (fake_old != NULL) {
		_fast_ping_fake_put(fake_old);
	}

	if (gai != NULL) {
		freeaddrinfo(gai);
	}

	return -1;
}

int fast_ping_fake_ip_remove(PING_TYPE type, const char *host)
{
	struct fast_ping_fake_ip *fake = NULL;
	char ip_str[PING_MAX_HOSTLEN];
	int port = -1;
	int ret = -1;
	FAST_PING_TYPE ping_type = FAST_PING_END;
	struct addrinfo *gai = NULL;

	if (parse_ip(host, ip_str, &port) != 0) {
		return -1;
	}

	ret = _fast_ping_get_addr_by_type(type, ip_str, port, &gai, &ping_type);
	if (ret != 0) {
		goto errout;
	}

	fake = _fast_ping_fake_find(ping_type, gai->ai_addr, gai->ai_addrlen);
	if (fake == NULL) {
		goto errout;
	}

	_fast_ping_fake_remove(fake);
	_fast_ping_fake_put(fake);
	ping.fake_ip_num--;
	freeaddrinfo(gai);
	return 0;
errout:
	if (gai != NULL) {
		freeaddrinfo(gai);
	}
	return -1;
}

int _fast_ping_send_fake(struct ping_host_struct *ping_host, struct fast_ping_fake_ip *fake)
{
	struct itimerspec its;
	int sec = fake->time / 1000;
	int cent_usec = ((long)(fake->time * 10)) % 10000;
	its.it_value.tv_sec = sec;
	its.it_value.tv_nsec = cent_usec * 1000 * 100;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(ping_host->fake_time_fd, 0, &its, NULL) < 0) {
		tlog(TLOG_ERROR, "timerfd_settime failed, %s", strerror(errno));
		goto errout;
	}

	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.ptr = ping_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, ping_host->fake_time_fd, &ev) == -1) {
		if (errno != EEXIST) {
			goto errout;
		}
	}

	ping_host->seq++;

	return 0;

errout:
	return -1;
}

int _fast_ping_process_fake(struct ping_host_struct *ping_host, struct timeval *now)
{
	struct timeval tvresult = *now;
	struct timeval *tvsend = &ping_host->last;
	uint64_t exp;
	int ret;

	ret = read(ping_host->fake_time_fd, &exp, sizeof(uint64_t));
	if (ret < 0) {
		return -1;
	}

	ping_host->ttl = ping_host->fake->ttl;
	tv_sub(&tvresult, tvsend);
	if (ping_host->ping_callback) {
		_fast_ping_send_notify_event(ping_host, PING_RESULT_RESPONSE, ping_host->seq, ping_host->ttl, &tvresult);
	}

	ping_host->send = 0;

	if (ping_host->count == 1) {
		_fast_ping_host_remove(ping_host);
	}

	return 0;
}

void _fast_ping_remove_all_fake_ip(void)
{
	struct fast_ping_fake_ip *fake = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(ping.fake, i, tmp, fake, node)
	{
		_fast_ping_fake_put(fake);
	}
}
