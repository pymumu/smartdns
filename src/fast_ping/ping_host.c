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

#include "ping_host.h"
#include "notify_event.h"
#include "ping_fake.h"
#include "smartdns/util.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>

void _fast_ping_host_get(struct ping_host_struct *ping_host)
{
	if (atomic_inc_return(&ping_host->ref) <= 0) {

		BUG("ping host ref is invalid, host: %s", ping_host->host);
	}
}

void _fast_ping_close_host_sock(struct ping_host_struct *ping_host)
{
	if (ping_host->fake_time_fd > 0) {
		struct epoll_event *event = NULL;
		event = (struct epoll_event *)1;
		epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping_host->fake_time_fd, event);

		close(ping_host->fake_time_fd);
		ping_host->fake_time_fd = -1;
	}

	if (ping_host->fd < 0) {
		return;
	}
	struct epoll_event *event = NULL;
	event = (struct epoll_event *)1;
	epoll_ctl(ping.epoll_fd, EPOLL_CTL_DEL, ping_host->fd, event);
	close(ping_host->fd);
	ping_host->fd = -1;
}

void _fast_ping_host_put(struct ping_host_struct *ping_host)
{
	int ref_cnt = atomic_dec_and_test(&ping_host->ref);
	if (!ref_cnt) {
		if (ref_cnt < 0) {

			BUG("invalid refcount of ping_host %s", ping_host->host);
		}
		return;
	}

	_fast_ping_close_host_sock(ping_host);
	if (ping_host->fake != NULL) {
		_fast_ping_fake_put(ping_host->fake);
		ping_host->fake = NULL;
	}

	pthread_mutex_lock(&ping.map_lock);
	hash_del(&ping_host->addr_node);
	pthread_mutex_unlock(&ping.map_lock);

	if (atomic_inc_return(&ping_host->notified) == 1) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		_fast_ping_send_notify_event(ping_host, PING_RESULT_END, ping_host->seq, ping_host->ttl, &tv);
	}

	tlog(TLOG_DEBUG, "ping %s end, id %d", ping_host->host, ping_host->sid);
	ping_host->type = FAST_PING_END;
	free(ping_host);
}

void _fast_ping_host_remove(struct ping_host_struct *ping_host)
{
	_fast_ping_close_host_sock(ping_host);

	pthread_mutex_lock(&ping.map_lock);
	if (!hash_hashed(&ping_host->addr_node)) {
		pthread_mutex_unlock(&ping.map_lock);
		return;
	}
	hash_del(&ping_host->addr_node);

	pthread_mutex_unlock(&ping.map_lock);

	if (atomic_inc_return(&ping_host->notified) == 1) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		_fast_ping_send_notify_event(ping_host, PING_RESULT_END, ping_host->seq, ping_host->ttl, &tv);
	}

	_fast_ping_host_put(ping_host);
}

void _fast_ping_remove_all(void)
{
	struct ping_host_struct *ping_host = NULL;
	struct ping_host_struct *ping_host_tmp = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	LIST_HEAD(remove_list);

	pthread_mutex_lock(&ping.map_lock);
	hash_for_each_safe(ping.addrmap, i, tmp, ping_host, addr_node)
	{
		list_add_tail(&ping_host->action_list, &remove_list);
	}
	pthread_mutex_unlock(&ping.map_lock);

	list_for_each_entry_safe(ping_host, ping_host_tmp, &remove_list, action_list)
	{
		_fast_ping_host_remove(ping_host);
	}
}
