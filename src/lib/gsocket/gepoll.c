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

#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/lib/list.h"
#include "smartdns/lib/rbtree.h"
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/* Internal wrapper */
struct gepoll {
	int efd;
	struct rb_root registry;
};

struct gepoll_entry {
	struct rb_node _node;
	int fd;
	struct gsocket *sock;
	void *user_data;
	int user_events;
};

/* Helper: Find */
static struct gepoll_entry *_gepoll_find(struct rb_root *root, int fd)
{
	struct rb_node *node = root->rb_node;
	while (node) {
		struct gepoll_entry *data = rb_entry(node, struct gepoll_entry, _node);
		if (fd < data->fd) {
			node = node->rb_left;
		} else if (fd > data->fd) {
			node = node->rb_right;
		} else {
			return data;
		}
	}
	return NULL;
}

/* Helper: Insert */
static int _gepoll_insert(struct rb_root *root, struct gepoll_entry *data)
{
	struct rb_node **new_node = &(root->rb_node), *parent = NULL;

	while (*new_node) {
		struct gepoll_entry *this_node = rb_entry(*new_node, struct gepoll_entry, _node);
		parent = *new_node;
		if (data->fd < this_node->fd) {
			new_node = &((*new_node)->rb_left);
		} else if (data->fd > this_node->fd) {
			new_node = &((*new_node)->rb_right);
		} else {
			return -1; /* Duplicate */
		}
	}

	rb_link_node(&data->_node, parent, new_node);
	rb_insert_color(&data->_node, root);
	return 0;
}

struct gepoll *gepoll_create(int flags)
{
	struct gepoll *ep = calloc(1, sizeof(struct gepoll));
	if (!ep)
		return NULL;
	if (flags > 0 && flags != EPOLL_CLOEXEC) {
		ep->efd = epoll_create(flags);
	} else {
		ep->efd = epoll_create1(flags);
	}
	if (ep->efd < 0) {
		free(ep);
		return NULL;
	}
	ep->registry = RB_ROOT;
	return ep;
}

void gepoll_destroy(struct gepoll *ep)
{
	if (!ep) {
		return;
	}

	struct rb_node *node;
	while ((node = rb_first(&ep->registry))) {
		struct gepoll_entry *entry = rb_entry(node, struct gepoll_entry, _node);
		rb_erase(node, &ep->registry);
		free(entry);
	}

	if (ep->efd >= 0) {
		close(ep->efd);
	}
	free(ep);
}

int gepoll_add(struct gepoll *ep, struct gsocket *sock, int events, void *user_data)
{
	int fd = gsocket_get_fd(sock);
	if (fd < 0) {
		return -1;
	}

	struct gepoll_entry *entry = calloc(1, sizeof(struct gepoll_entry));
	entry->fd = fd;
	entry->sock = sock;
	entry->user_data = user_data;
	entry->user_events = events;

	if (_gepoll_insert(&ep->registry, entry) != 0) {
		free(entry);
		return -1;
	}

	struct epoll_event ev;
	ev.events = events;
	ev.data.ptr = entry;

	if (epoll_ctl(ep->efd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		rb_erase(&entry->_node, &ep->registry);
		free(entry);
		return -1;
	}

	return 0;
}

int gepoll_mod(struct gepoll *ep, struct gsocket *sock, int events, void *user_data)
{
	int fd = gsocket_get_fd(sock);
	struct gepoll_entry *entry = _gepoll_find(&ep->registry, fd);
	if (!entry) {
		return -1;
	}

	entry->user_events = events;
	entry->user_data = user_data;

	struct epoll_event ev;
	ev.data.ptr = entry;
	ev.events = events;
	return epoll_ctl(ep->efd, EPOLL_CTL_MOD, fd, &ev);
}

int gepoll_del(struct gepoll *ep, struct gsocket *sock)
{
	int fd = gsocket_get_fd(sock);
	struct gepoll_entry *entry = _gepoll_find(&ep->registry, fd);
	if (!entry) {
		return -1;
	}

	epoll_ctl(ep->efd, EPOLL_CTL_DEL, fd, NULL);
	rb_erase(&entry->_node, &ep->registry);
	free(entry);
	return 0;
}

int gepoll_wait(struct gepoll *ep, struct gepoll_event *events, int maxevents, int timeout)
{
	struct epoll_event ep_events[maxevents];
	int nfds = epoll_wait(ep->efd, ep_events, maxevents, timeout);
	if (nfds <= 0) {
		return nfds;
	}

	for (int i = 0; i < nfds; i++) {
		struct gepoll_entry *entry = (struct gepoll_entry *)ep_events[i].data.ptr;
		events[i].events = ep_events[i].events;
		events[i].user_data = entry ? entry->user_data : NULL;
	}
	return nfds;
}
