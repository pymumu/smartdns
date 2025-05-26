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

#include "smartdns/proxy.h"
#include "smartdns/util.h"

#include "proxy.h"
#include "client_socket.h"

#include <sys/epoll.h>
#include <sys/socket.h>

int _dns_proxy_handshake(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	struct epoll_event fd_event;
	proxy_handshake_state ret = proxy_conn_handshake(server_info->proxy);
	int fd = server_info->fd;
	int retval = -1;
	int epoll_op = EPOLL_CTL_MOD;

	if (ret == PROXY_HANDSHAKE_OK) {
		return 0;
	}

	if (ret == PROXY_HANDSHAKE_ERR || fd < 0) {
		goto errout;
	}

	memset(&fd_event, 0, sizeof(fd_event));
	if (ret == PROXY_HANDSHAKE_CONNECTED) {
		fd_event.events = EPOLLIN;
		if (server_info->type == DNS_SERVER_UDP || server_info->type == DNS_SERVER_HTTP3 ||
			server_info->type == DNS_SERVER_QUIC) {
			epoll_ctl(client.epoll_fd, EPOLL_CTL_DEL, fd, NULL);
			event->events = 0;
			fd = proxy_conn_get_udpfd(server_info->proxy);
			if (fd < 0) {
				tlog(TLOG_ERROR, "get udp fd failed");
				goto errout;
			}

			set_fd_nonblock(fd, 1);
			if (server_info->so_mark >= 0) {
				unsigned int so_mark = server_info->so_mark;
				if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
					tlog(TLOG_DEBUG, "set socket mark failed, %s", strerror(errno));
				}
			}
			server_info->fd = fd;
			epoll_op = EPOLL_CTL_ADD;

			if (server_info->type == DNS_SERVER_UDP) {
				server_info->status = DNS_SERVER_STATUS_CONNECTED;
			} else {
				/* do handshake for quic */
				server_info->status = DNS_SERVER_STATUS_CONNECTING;
				fd_event.events |= EPOLLOUT;
			}

		} else {
			fd_event.events |= EPOLLOUT;
		}
		retval = 0;
	}

	if (ret == PROXY_HANDSHAKE_WANT_READ) {
		fd_event.events = EPOLLIN;
	} else if (ret == PROXY_HANDSHAKE_WANT_WRITE) {
		fd_event.events = EPOLLOUT | EPOLLIN;
	}

	fd_event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, epoll_op, fd, &fd_event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		goto errout;
	}

	return retval;

errout:
	pthread_mutex_lock(&server_info->lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&server_info->lock);
	return -1;
}
