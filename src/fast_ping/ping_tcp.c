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

#include "smartdns/util.h"

#include "notify_event.h"
#include "ping_host.h"
#include "ping_tcp.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>

int _fast_ping_sendping_tcp(struct ping_host_struct *ping_host)
{
	struct epoll_event event;
	int flags = 0;
	int fd = -1;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = IP_TOS;

	_fast_ping_close_host_sock(ping_host);

	fd = socket(ping_host->ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		goto errout;
	}

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	set_sock_keepalive(fd, 0, 0, 0);
	/* Set the socket lingering so we will RST connections instead of wasting
	 * bandwidth with the four-step close
	 */
	set_sock_lingertime(fd, 0);

	ping_host->seq++;
	if (connect(fd, &ping_host->addr, ping_host->addr_len) != 0) {
		if (errno != EINPROGRESS) {
			char ping_host_name[PING_MAX_HOSTLEN];
			if (errno == ENETUNREACH || errno == EINVAL || errno == EADDRNOTAVAIL || errno == EHOSTUNREACH) {
				goto errout;
			}

			if (errno == EACCES || errno == EPERM) {
				if (bool_print_log == 0) {
					goto errout;
				}
				bool_print_log = 0;
			}

			tlog(TLOG_INFO, "connect %s, id %d, %s",
				 get_host_by_addr(ping_host_name, sizeof(ping_host_name), (struct sockaddr *)&ping_host->addr),
				 ping_host->sid, strerror(errno));
			goto errout;
		}
	}

	gettimeofday(&ping_host->last, NULL);
	ping_host->fd = fd;
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT | EPOLLERR;
	event.data.ptr = ping_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		ping_host->fd = -1;
		goto errout;
	}

	return 0;

errout:
	if (fd > 0) {
		close(fd);
		ping_host->fd = -1;
	}
	return -1;
}

int _fast_ping_get_addr_by_tcp(const char *ip_str, int port, struct addrinfo **out_gai, FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	int socktype = 0;
	FAST_PING_TYPE ping_type = 0;
	int sockproto = 0;
	char *service = NULL;
	char port_str[MAX_IP_LEN];

	if (port <= 0) {
		port = 80;
	}

	sockproto = 0;
	socktype = SOCK_STREAM;
	snprintf(port_str, MAX_IP_LEN, "%d", port);
	service = port_str;
	ping_type = FAST_PING_TCP;

	gai = _fast_ping_getaddr(ip_str, service, socktype, sockproto);
	if (gai == NULL) {
		goto errout;
	}

	*out_gai = gai;
	*out_ping_type = ping_type;

	return 0;
errout:
	if (gai) {
		freeaddrinfo(gai);
	}
	return -1;
}

int _fast_ping_process_tcp(struct ping_host_struct *ping_host, struct epoll_event *event, struct timeval *now)
{
	struct timeval tvresult = *now;
	struct timeval *tvsend = &ping_host->last;
	int connect_error = 0;
	socklen_t len = sizeof(connect_error);

	if (event->events & EPOLLIN || event->events & EPOLLERR) {
		if (getsockopt(ping_host->fd, SOL_SOCKET, SO_ERROR, (char *)&connect_error, &len) != 0) {
			goto errout;
		}

		if (connect_error != 0 && connect_error != ECONNREFUSED) {
			goto errout;
		}
	}
	tv_sub(&tvresult, tvsend);
	if (ping_host->ping_callback) {
		_fast_ping_send_notify_event(ping_host, PING_RESULT_RESPONSE, ping_host->seq, ping_host->ttl, &tvresult);
	}

	ping_host->send = 0;

	_fast_ping_close_host_sock(ping_host);

	if (ping_host->count == 1) {
		_fast_ping_host_remove(ping_host);
	}
	return 0;
errout:
	_fast_ping_host_remove(ping_host);

	return -1;
}
