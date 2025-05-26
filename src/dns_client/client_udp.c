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

#include "client_socket.h"
#include "client_udp.h"
#include "server_info.h"

#include <net/if.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

static int _dns_client_create_socket_udp_proxy(struct dns_server_info *server_info)
{
	struct proxy_conn *proxy = NULL;
	int fd = -1;
	struct epoll_event event;
	int ret = -1;

	proxy = proxy_conn_new(server_info->proxy_name, server_info->ip, server_info->port, 1, 1);
	if (proxy == NULL) {
		tlog(TLOG_ERROR, "create proxy failed, %s, proxy: %s", server_info->ip, server_info->proxy_name);
		goto errout;
	}

	fd = proxy_conn_get_fd(proxy);
	if (fd < 0) {
		tlog(TLOG_ERROR, "get proxy fd failed, %s", server_info->ip);
		goto errout;
	}

	if (server_info->so_mark >= 0) {
		unsigned int so_mark = server_info->so_mark;
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
			tlog(TLOG_DEBUG, "set socket mark failed, %s", strerror(errno));
		}
	}

	if (server_info->flags.ifname[0] != '\0') {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		safe_strncpy(ifr.ifr_name, server_info->flags.ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
			tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
			goto errout;
		}
	}

	set_fd_nonblock(fd, 1);
	set_sock_keepalive(fd, 30, 3, 5);
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
	}

	ret = proxy_conn_connect(proxy);
	if (ret != 0) {
		if (errno != EINPROGRESS) {
			tlog(TLOG_DEBUG, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	server_info->fd = fd;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	server_info->proxy = proxy;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	return 0;
errout:
	if (proxy) {
		proxy_conn_free(proxy);
	}

	return -1;
}

int _dns_client_create_socket_udp(struct dns_server_info *server_info)
{
	int fd = 0;
	struct epoll_event event;
	const int on = 1;
	const int val = 255;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	if (server_info->proxy_name[0] != '\0') {
		return _dns_client_create_socket_udp_proxy(server_info);
	}

	fd = socket(server_info->ai_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	if (server_info->flags.ifname[0] != '\0') {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		safe_strncpy(ifr.ifr_name, server_info->flags.ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq)) < 0) {
			tlog(TLOG_ERROR, "bind socket to device %s failed, %s\n", ifr.ifr_name, strerror(errno));
			goto errout;
		}
	}

	server_info->fd = fd;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;

	if (connect(fd, &server_info->addr, server_info->ai_addrlen) != 0) {
		if (errno != EINPROGRESS) {
			tlog(TLOG_DEBUG, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	if (server_info->so_mark >= 0) {
		unsigned int so_mark = server_info->so_mark;
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
			tlog(TLOG_DEBUG, "set socket mark failed, %s", strerror(errno));
		}
	}

	setsockopt(server_info->fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	setsockopt(server_info->fd, SOL_IP, IP_TTL, &val, sizeof(val));
	setsockopt(server_info->fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(server_info->fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (server_info->ai_family == AF_INET6) {
		/* for receiving ip ttl value */
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on));
		setsockopt(server_info->fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
	}

	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(server_info->fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size,
				   sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(server_info->fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size,
				   sizeof(dns_conf.dns_socket_buff_size));
	}

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	server_info->fd = -1;
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;

	return -1;
}

static int _dns_client_process_send_udp_buffer(struct dns_server_info *server_info, struct epoll_event *event,
											   unsigned long now)
{
	int send_len = 0;
	if (server_info->send_buff.len <= 0 || server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return 0;
	}

	while (server_info->send_buff.len - send_len > 0) {
		int ret = 0;
		int packet_len = 0;
		packet_len = *(int *)(server_info->send_buff.data + send_len);
		send_len += sizeof(packet_len);
		if (packet_len > server_info->send_buff.len - 1) {
			goto errout;
		}

		ret = _dns_client_send_udp(server_info, server_info->send_buff.data + send_len, packet_len);
		if (ret < 0) {
			tlog(TLOG_ERROR, "sendto failed, %s", strerror(errno));
			goto errout;
		}
		send_len += packet_len;
	}

	server_info->send_buff.len -= send_len;
	if (server_info->send_buff.len < 0) {
		server_info->send_buff.len = 0;
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

static int _dns_client_process_udp_proxy(struct dns_server_info *server_info, struct epoll_event *event,
										 unsigned long now)
{
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	char from_host[DNS_MAX_CNAME_LEN];
	unsigned char inpacket[DNS_IN_PACKSIZE];
	int len = 0;
	int ret = 0;

	_dns_client_process_send_udp_buffer(server_info, event, now);

	if (!(event->events & EPOLLIN)) {
		return 0;
	}

	len = proxy_conn_recvfrom(server_info->proxy, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, &from_len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		if (errno == ECONNREFUSED || errno == ENETUNREACH || errno == EHOSTUNREACH) {
			tlog(TLOG_DEBUG, "recvfrom %s failed, %s\n", server_info->ip, strerror(errno));
			goto errout;
		}

		tlog(TLOG_ERROR, "recvfrom %s failed, %s\n", server_info->ip, strerror(errno));
		goto errout;
	} else if (len == 0) {
		pthread_mutex_lock(&server_info->lock);
		_dns_client_close_socket(server_info);
		server_info->recv_buff.len = 0;
		if (server_info->send_buff.len > 0) {
			/* still remain request data, reconnect and send*/
			ret = _dns_client_create_socket(server_info);
		} else {
			ret = 0;
		}
		pthread_mutex_unlock(&server_info->lock);
		tlog(TLOG_DEBUG, "peer close, %s", server_info->ip);
		return ret;
	}

	int latency = get_tick_count() - server_info->send_tick;
	tlog(TLOG_DEBUG, "recv udp packet from %s, len: %d, latency: %d",
		 get_host_by_addr(from_host, sizeof(from_host), (struct sockaddr *)&from), len, latency);

	if (latency < server_info->drop_packet_latency_ms) {
		tlog(TLOG_DEBUG, "drop packet from %s, latency: %d", from_host, latency);
		return 0;
	}

	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		server_info->status = DNS_SERVER_STATUS_CONNECTED;
	}

	/* update recv time */
	time(&server_info->last_recv);

	/* processing dns packet */
	if (_dns_client_recv(server_info, inpacket, len, (struct sockaddr *)&from, from_len) != 0) {
		return -1;
	}

	return 0;
errout:
	pthread_mutex_lock(&server_info->lock);
	server_info->recv_buff.len = 0;
	server_info->send_buff.len = 0;
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&server_info->lock);
	return -1;
}

int _dns_client_process_udp(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int len = 0;
	unsigned char inpacket[DNS_IN_PACKSIZE];
	struct sockaddr_storage from;
	socklen_t from_len = sizeof(from);
	char from_host[DNS_MAX_CNAME_LEN];
	struct msghdr msg;
	struct iovec iov;
	char ans_data[4096];
	int ttl = 0;
	struct cmsghdr *cmsg = NULL;

	if (server_info->proxy) {
		return _dns_client_process_udp_proxy(server_info, event, now);
	}

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (char *)inpacket;
	iov.iov_len = sizeof(inpacket);
	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ans_data;
	msg.msg_controllen = sizeof(ans_data);

	len = recvmsg(server_info->fd, &msg, MSG_DONTWAIT);
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

	/* Get the TTL of the IP header */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				int *ttlPtr = (int *)CMSG_DATA(cmsg);
				ttl = *ttlPtr;
			}
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT) {
			if (cmsg->cmsg_len >= sizeof(int)) {
				int *ttlPtr = (int *)CMSG_DATA(cmsg);
				ttl = *ttlPtr;
			}
		}
	}

	int from_port = from.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&from)->sin_port)
											  : ntohs(((struct sockaddr_in6 *)&from)->sin6_port);
	int latency = get_tick_count() - server_info->send_tick;
	tlog(TLOG_DEBUG, "recv udp packet from %s:%d, len: %d, ttl: %d, latency: %d",
		 get_host_by_addr(from_host, sizeof(from_host), (struct sockaddr *)&from), from_port, len, ttl, latency);

	/* update recv time */
	time(&server_info->last_recv);

	if (latency > 0 && latency < server_info->drop_packet_latency_ms) {
		tlog(TLOG_DEBUG, "drop packet from %s, latency: %d", from_host, latency);
		return 0;
	}

	if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
		server_info->status = DNS_SERVER_STATUS_CONNECTED;
	}

	/* processing dns packet */
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
	int send_len = 0;
	const struct sockaddr *addr = &server_info->addr;
	socklen_t addrlen = server_info->ai_addrlen;
	int ret = 0;

	if (server_info->fd <= 0) {
		return -1;
	}

	if (server_info->proxy) {
		if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
			/*set packet len*/
			_dns_client_copy_data_to_buffer(server_info, &len, sizeof(len));
			return _dns_client_copy_data_to_buffer(server_info, packet, len);
		}

		send_len = proxy_conn_sendto(server_info->proxy, packet, len, 0, addr, addrlen);
		if (send_len != len) {
			_dns_client_close_socket(server_info);
			server_info->recv_buff.len = 0;
			if (server_info->send_buff.len > 0) {
				/* still remain request data, reconnect and send*/
				ret = _dns_client_create_socket(server_info);
			} else {
				ret = 0;
			}

			if (ret != 0) {
				return -1;
			}

			_dns_client_copy_data_to_buffer(server_info, &len, sizeof(len));
			return _dns_client_copy_data_to_buffer(server_info, packet, len);
		}

		return 0;
	}

	send_len = sendto(server_info->fd, packet, len, 0, NULL, 0);
	if (send_len != len) {
		goto errout;
	}

	return 0;

errout:
	return -1;
}

void _dns_client_check_udp_nat(struct dns_query_struct *query)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_group_member *group_member = NULL;

	/* For udp nat case.
	 * when router reconnect to internet, udp port may always marked as UNREPLIED.
	 * dns query will timeout, and cannot reconnect again,
	 * create a new socket to communicate.
	 */
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
