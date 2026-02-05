/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "smartdns/lib/gsocket.h"
#include "smartdns/lib/list.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

/* Stream item in gstream_poll */
struct gstream_item {
	struct gsocket *stream;
	int events;
	void *user_data;
	struct list_head list;
};

/* Stream poll manager - manages streams on a QUIC connection */
struct gstream_poll {
	struct gsocket *quic_connection; /* Associated QUIC connection */
	struct list_head streams;
	int count;
	int has_pollout_streams; /* Track if any stream wants to write */
};

struct gstream_poll *gstream_poll_create(struct gsocket *quic_connection)
{
	if (!quic_connection) {
		errno = EINVAL;
		return NULL;
	}

	struct gstream_poll *sp = calloc(1, sizeof(struct gstream_poll));
	if (!sp) {
		return NULL;
	}

	sp->quic_connection = quic_connection;
	INIT_LIST_HEAD(&sp->streams);
	sp->count = 0;
	sp->has_pollout_streams = 0;

	/* Automatically add the connection itself to monitor for new stream arrivals */
	/* The connection will have stream == quic_connection to indicate it's for accept */
	gstream_poll_add(sp, quic_connection, POLLIN, NULL);

	return sp;
}

int gstream_poll_add(struct gstream_poll *sp, struct gsocket *stream, int events, void *user_data)
{
	if (!sp || !stream) {
		errno = EINVAL;
		return -1;
	}

	/* Check if already exists */
	struct gstream_item *item;
	list_for_each_entry(item, &sp->streams, list)
	{
		if (item->stream == stream) {
			/* Update events and user_data */
			item->events = events;
			item->user_data = user_data;
			/* Update POLLOUT tracking */
			if (events & POLLOUT) {
				sp->has_pollout_streams = 1;
			}
			return 0;
		}
	}

	/* Add new item */
	item = calloc(1, sizeof(struct gstream_item));
	if (!item) {
		return -1;
	}

	item->stream = stream;
	item->events = events;
	item->user_data = user_data;
	list_add_tail(&item->list, &sp->streams);
	sp->count++;

	/* Update POLLOUT tracking */
	if (events & POLLOUT) {
		sp->has_pollout_streams = 1;
	}

	return 0;
}

/* Helper to recalculate has_pollout_streams flag */
static void _update_pollout_tracking(struct gstream_poll *sp)
{
	struct gstream_item *item;
	sp->has_pollout_streams = 0;
	list_for_each_entry(item, &sp->streams, list)
	{
		if (item->events & POLLOUT) {
			sp->has_pollout_streams = 1;
			break;
		}
	}
}

int gstream_poll_mod(struct gstream_poll *sp, struct gsocket *stream, int events, void *user_data)
{
	if (!sp || !stream) {
		errno = EINVAL;
		return -1;
	}

	/* Find and update existing item */
	struct gstream_item *item;
	list_for_each_entry(item, &sp->streams, list)
	{
		if (item->stream == stream) {
			item->events = events;
			item->user_data = user_data;
			/* Recalculate POLLOUT tracking */
			_update_pollout_tracking(sp);
			return 0;
		}
	}

	/* Not found */
	errno = ENOENT;
	return -1;
}

int gstream_poll_del(struct gstream_poll *sp, struct gsocket *stream)
{
	if (!sp || !stream) {
		errno = EINVAL;
		return -1;
	}

	struct gstream_item *item, *tmp;
	list_for_each_entry_safe(item, tmp, &sp->streams, list)
	{
		if (item->stream == stream) {
			int had_pollout = (item->events & POLLOUT);
			list_del(&item->list);
			free(item);
			sp->count--;
			/* Recalculate POLLOUT tracking if needed */
			if (had_pollout) {
				_update_pollout_tracking(sp);
			}
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int gstream_poll_wait(struct gstream_poll *sp, struct gstream_event *events, int maxevents, int timeout_ms)
{
	if (!sp || !events || maxevents <= 0) {
		errno = EINVAL;
		return -1;
	}

	if (sp->count == 0) {
		return 0;
	}

	int check_count = sp->count < maxevents ? sp->count : maxevents;

	/* Allocate temporary array on stack for stream_poll */
	struct gstream_poll_item *items = alloca(check_count * sizeof(struct gstream_poll_item));

	/* Collect streams into poll items */
	struct gstream_item *item;
	int idx = 0;
	list_for_each_entry(item, &sp->streams, list)
	{
		if (idx >= check_count) {
			break;
		}

		items[idx].stream = item->stream;
		items[idx].events = item->events;
		items[idx].revents = 0;

		/* Prepare event structure with user_data */
		events[idx].stream = item->stream;
		events[idx].events = item->events;
		events[idx].revents = 0;
		events[idx].user_data = item->user_data;

		idx++;
	}

	/* Call stream_poll on the QUIC connection */
	struct gsocket_io *io = gsocket_get_top_layer(sp->quic_connection);
	if (!io || !io->stream_poll) {
		errno = ENOTSUP;
		return -1;
	}

	int ret = io->stream_poll(io, items, idx, timeout_ms);
	if (ret < 0) {
		return ret;
	}

	/* Fill in revents - only copy items with revents set */
	int ready = 0;
	for (int i = 0; i < idx; i++) {
		if (items[i].revents) {
			events[ready].stream = events[i].stream;
			events[ready].events = events[i].events;
			events[ready].revents = items[i].revents;
			events[ready].user_data = events[i].user_data;
			ready++;
		}
	}

	return ready;
}

void gstream_poll_destroy(struct gstream_poll *sp)
{
	if (!sp) {
		return;
	}

	struct gstream_item *item, *tmp;
	list_for_each_entry_safe(item, tmp, &sp->streams, list)
	{
		list_del(&item->list);
		free(item);
	}

	free(sp);
}

int gstream_poll_get_net_events(struct gstream_poll *sp)
{
	if (!sp || !sp->quic_connection) {
		return EPOLLIN;
	}

	/* Get SSL layer's network requirements */
	int ssl_events = gsocket_get_poll_events(sp->quic_connection);

	/* If any stream wants to write, ensure EPOLLOUT is set
	 * This ensures the underlying socket is monitored for writability
	 * even if SSL_net_write_desired() hasn't been triggered yet */
	if (sp->has_pollout_streams) {
		ssl_events |= EPOLLOUT;
	}

	return ssl_events;
}
