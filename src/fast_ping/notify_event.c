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

#include "notify_event.h"
#include "ping_host.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

static void _fast_ping_release_notify_event(struct fast_ping_notify_event *ping_notify_event)
{
	pthread_mutex_lock(&ping.notify_lock);
	list_del_init(&ping_notify_event->list);
	pthread_mutex_unlock(&ping.notify_lock);

	if (ping_notify_event->ping_host) {
		_fast_ping_host_put(ping_notify_event->ping_host);
		ping_notify_event->ping_host = NULL;
	}
	free(ping_notify_event);
}

int _fast_ping_send_notify_event(struct ping_host_struct *ping_host, FAST_PING_RESULT ping_result, unsigned int seq,
								 int ttl, struct timeval *tvresult)
{
	struct fast_ping_notify_event *notify_event = NULL;

	notify_event = malloc(sizeof(struct fast_ping_notify_event));
	if (notify_event == NULL) {
		goto errout;
	}
	memset(notify_event, 0, sizeof(struct fast_ping_notify_event));
	INIT_LIST_HEAD(&notify_event->list);
	notify_event->seq = seq;
	notify_event->ttl = ttl;
	notify_event->ping_result = ping_result;
	notify_event->tvresult = *tvresult;

	pthread_mutex_lock(&ping.notify_lock);
	if (list_empty(&ping.notify_event_list)) {
		pthread_cond_signal(&ping.notify_cond);
	}
	list_add_tail(&notify_event->list, &ping.notify_event_list);
	notify_event->ping_host = ping_host;
	_fast_ping_host_get(ping_host);
	pthread_mutex_unlock(&ping.notify_lock);

	return 0;

errout:
	if (notify_event) {
		_fast_ping_release_notify_event(notify_event);
	}
	return -1;
}

static void _fast_ping_process_notify_event(struct fast_ping_notify_event *ping_notify_event)
{
	struct ping_host_struct *ping_host = ping_notify_event->ping_host;
	if (ping_host == NULL) {
		return;
	}

	ping_host->ping_callback(ping_host, ping_host->host, ping_notify_event->ping_result, &ping_host->addr,
							 ping_host->addr_len, ping_notify_event->seq, ping_notify_event->ttl,
							 &ping_notify_event->tvresult, ping_host->error, ping_host->userptr);
}

void *_fast_ping_notify_worker(void *arg)
{
	struct fast_ping_notify_event *ping_notify_event = NULL;

	while (atomic_read(&ping.run)) {
		pthread_mutex_lock(&ping.notify_lock);
		if (list_empty(&ping.notify_event_list)) {
			pthread_cond_wait(&ping.notify_cond, &ping.notify_lock);
		}

		ping_notify_event = list_first_entry_or_null(&ping.notify_event_list, struct fast_ping_notify_event, list);
		if (ping_notify_event) {
			list_del_init(&ping_notify_event->list);
		}
		pthread_mutex_unlock(&ping.notify_lock);

		if (ping_notify_event == NULL) {
			continue;
		}

		_fast_ping_process_notify_event(ping_notify_event);
		_fast_ping_release_notify_event(ping_notify_event);
	}

	return NULL;
}

void _fast_ping_remove_all_notify_event(void)
{
	struct fast_ping_notify_event *notify_event = NULL;
	struct fast_ping_notify_event *tmp = NULL;
	list_for_each_entry_safe(notify_event, tmp, &ping.notify_event_list, list)
	{
		_fast_ping_process_notify_event(notify_event);
		_fast_ping_release_notify_event(notify_event);
	}
}