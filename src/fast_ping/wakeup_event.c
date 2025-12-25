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

#include "wakeup_event.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

void _fast_ping_wakeup_thread(void)
{
	uint64_t u = 1;
	int unused __attribute__((unused));
	unused = write(ping.event_fd, &u, sizeof(u));
}

int _fast_ping_init_wakeup_event(void)
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
	event.data.ptr = NULL;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fdevent, &event) != 0) {
		tlog(TLOG_ERROR, "set eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	ping.event_fd = fdevent;

	return 0;
errout:
	return -1;
}
