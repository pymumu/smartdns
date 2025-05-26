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

#include "wake_event.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>

void _dns_client_close_wakeup_event(void)
{
	if (client.fd_wakeup > 0) {
		close(client.fd_wakeup);
		client.fd_wakeup = -1;
	}
}

void _dns_client_clear_wakeup_event(void)
{
	uint64_t val = 0;
	int unused __attribute__((unused));

	if (client.fd_wakeup <= 0) {
		return;
	}

	unused = read(client.fd_wakeup, &val, sizeof(val));
}

void _dns_client_do_wakeup_event(void)
{
	uint64_t val = 1;
	int unused __attribute__((unused));
	if (client.fd_wakeup <= 0) {
		return;
	}

	unused = write(client.fd_wakeup, &val, sizeof(val));
}

int _dns_client_create_wakeup_event(void)
{
	int fd_wakeup = -1;

	fd_wakeup = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd_wakeup < 0) {
		tlog(TLOG_ERROR, "create eventfd failed, %s\n", strerror(errno));
		goto errout;
	}

	struct epoll_event event;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = fd_wakeup;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd_wakeup, &event) < 0) {
		tlog(TLOG_ERROR, "add eventfd to epoll failed, %s\n", strerror(errno));
		goto errout;
	}

	return fd_wakeup;

errout:
	if (fd_wakeup > 0) {
		close(fd_wakeup);
	}

	return -1;
}
