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

#include "client_gsocket.h"

#include "client_socket.h"

#include "smartdns/util.h"

#include <errno.h>
#include <string.h>
#include <time.h>

int _dns_client_process_udp(struct dns_server_info *server_info, struct gepoll_event *event, unsigned long now)
{
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	struct msghdr msg;
	struct iovec iov;
	char ans_data[1024];
	struct cmsghdr *cmsg;
	int ttl = 0;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = inpacket;
	iov.iov_len = sizeof(inpacket);
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ans_data;
	msg.msg_controllen = sizeof(ans_data);

	int fd = gsocket_get_fd(server_info->gs);
	int len = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		server_info->prohibit = 1;
		if (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EHOSTUNREACH) {
			tlog(TLOG_DEBUG, "recvfrom %s failed, %s\n", server_info->ip, strerror(errno));
			goto errout;
		}
		tlog(TLOG_ERROR, "recvfrom %s failed, %s\n", server_info->ip, strerror(errno));
		goto errout;
	}
	from_len = msg.msg_namelen;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				ttl = *(int *)CMSG_DATA(cmsg);
			}
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				ttl = *(int *)CMSG_DATA(cmsg);
			}
		}
	}

	int latency = get_tick_count() - server_info->send_tick;
	tlog(TLOG_DEBUG, "recv udp packet from %s, len: %d, ttl: %d, latency: %d", server_info->ip, len, ttl, latency);

	time(&server_info->last_recv);

	if (latency > 0 && latency < server_info->drop_packet_latency_ms) {
		return 0;
	}

	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		server_info->status = DNS_SERVER_STATUS_CONNECTED;
	}

	if (_dns_client_recv(server_info, inpacket, len, (struct sockaddr *)&from, from_len) != 0) {
		return -1;
	}

	return 0;

errout:
	pthread_mutex_lock(&client.server_list_lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

int _dns_client_send_udp(struct dns_server_info *server_info, void *packet, int len)
{
	if (server_info->gs == NULL) {
		errno = EBADF;
		return -1;
	}

	ssize_t ret = gsocket_send(server_info->gs, packet, len, 0);
	if (ret < 0) {
		return -1;
	}

	time(&server_info->last_send);
	return 0;
}

void _dns_client_check_udp_nat(struct dns_query_struct *query)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group_member *group_member = NULL;

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(group_member, &query->server_group->head, list)
	{
		server_info = group_member->server;
		if (server_info->type != DNS_SERVER_UDP) {
			continue;
		}

		if (server_info->last_send - 5 > server_info->last_recv) {
			server_info->recv_buff.len = 0;
			server_info->send_buff.len = 0;
			tlog(TLOG_DEBUG, "query server %s timeout.", server_info->ip);
			_dns_client_close_socket(server_info);
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}
