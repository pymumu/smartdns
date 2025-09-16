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

#include "smartdns/http_parse.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include "client_socket.h"
#include "client_tcp.h"
#include "client_tls.h"
#include "server_info.h"

#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

int _dns_client_create_socket_tcp(struct dns_server_info *server_info)
{
	int fd = -1;
	struct epoll_event event;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;
	struct proxy_conn *proxy = NULL;
	int ret = 0;

	if (server_info->proxy_name[0] != '\0') {
		proxy = proxy_conn_new(server_info->proxy_name, server_info->ip, server_info->port, 0, 1);
		if (proxy == NULL) {
			tlog(TLOG_ERROR, "create proxy failed, %s, proxy: %s", server_info->ip, server_info->proxy_name);
			goto errout;
		}
		fd = proxy_conn_get_fd(proxy);
	} else {
		fd = socket(server_info->ai_family, SOCK_STREAM, 0);
	}

	if (fd < 0) {
		tlog(TLOG_ERROR, "create socket failed, %s", strerror(errno));
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

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set socket non block failed, %s", strerror(errno));
		goto errout;
	}

	if (server_info->so_mark >= 0) {
		unsigned int so_mark = server_info->so_mark;
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark)) != 0) {
			tlog(TLOG_DEBUG, "set socket mark failed, %s", strerror(errno));
		}
	}

	/* enable tcp fast open */
	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &yes, sizeof(yes)) != 0) {
		tlog(TLOG_DEBUG, "enable TCP fast open failed, %s", strerror(errno));
	}

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, &yes, sizeof(yes));
	setsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &yes, sizeof(yes));
	set_sock_keepalive(fd, 30, 3, 5);
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
	}

	if (proxy) {
		ret = proxy_conn_connect(proxy);
	} else {
		ret = connect(fd, &server_info->addr, server_info->ai_addrlen);
	}

	if (ret != 0) {
		if (errno != EINPROGRESS) {
			tlog(TLOG_DEBUG, "connect %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	server_info->fd = fd;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	server_info->security_status = DNS_CLIENT_SERVER_SECURITY_NOT_APPLICABLE;
	server_info->proxy = proxy;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN | EPOLLOUT;
	event.data.ptr = server_info;
	if (epoll_ctl(client.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	tlog(TLOG_DEBUG, "tcp server %s connecting.\n", server_info->ip);

	return 0;
errout:
	if (server_info->fd > 0) {
		server_info->fd = -1;
	}

	server_info->status = DNS_SERVER_STATUS_INIT;

	if (fd > 0 && proxy == NULL) {
		close(fd);
	}

	if (proxy) {
		proxy_conn_free(proxy);
	}

	return -1;
}

static int _dns_client_process_tcp_buff(struct dns_server_info *server_info)
{
	int len = 0;
	int dns_packet_len = 0;
	struct http_head *http_head = NULL;
	unsigned char *inpacket_data = NULL;
	int ret = -1;

	while (1) {
		if (server_info->type == DNS_SERVER_HTTPS) {
			http_head = http_head_init(4096, HTTP_VERSION_1_1);
			if (http_head == NULL) {
				goto out;
			}

			len = http_head_parse(http_head, server_info->recv_buff.data, server_info->recv_buff.len);
			if (len < 0) {
				if (len == -1) {
					ret = 0;
					goto out;
				} else if (len == -3) {
					/* repsone is too large */
					tlog(TLOG_DEBUG, "http response is too large.");
					server_info->recv_buff.len = 0;
					goto out;
				}

				tlog(TLOG_DEBUG, "remote server not supported.");
				goto out;
			}

			if (http_head_get_httpcode(http_head) != 200) {
				tlog(TLOG_WARN, "http server query from %s:%d failed, server return http code : %d, %s",
					 server_info->ip, server_info->port, http_head_get_httpcode(http_head),
					 http_head_get_httpcode_msg(http_head));
				server_info->prohibit = 1;
				goto out;
			}

			dns_packet_len = http_head_get_data_len(http_head);
			inpacket_data = (unsigned char *)http_head_get_data(http_head);
		} else {
			/* tcp result format
			 * | len (short) | dns query result |
			 */
			inpacket_data = server_info->recv_buff.data;
			len = ntohs(*((unsigned short *)(inpacket_data)));
			if (len <= 0 || len >= DNS_IN_PACKSIZE) {
				/* data len is invalid */
				goto out;
			}

			if (len > server_info->recv_buff.len - 2) {
				/* len is not expected, wait and recv */
				ret = 0;
				goto out;
			}

			inpacket_data = server_info->recv_buff.data + 2;
			dns_packet_len = len;
			len += 2;
		}

		if (inpacket_data == NULL || dns_packet_len <= 0) {
			tlog(TLOG_WARN, "recv tcp packet from %s, len = %d", server_info->ip, len);
			goto out;
		}

		tlog(TLOG_DEBUG, "recv tcp packet from %s, len = %d", server_info->ip, len);
		time(&server_info->last_recv);
		/* process result */
		if (_dns_client_recv(server_info, inpacket_data, dns_packet_len, &server_info->addr, server_info->ai_addrlen) !=
			0) {
			goto out;
		}

		if (http_head) {
			http_head_destroy(http_head);
			http_head = NULL;
		}

		server_info->recv_buff.len -= len;
		if (server_info->recv_buff.len < 0) {
			BUG("Internal error.");
		}

		/* move to next result */
		if (server_info->recv_buff.len > 0) {
			memmove(server_info->recv_buff.data, server_info->recv_buff.data + len, server_info->recv_buff.len);
		} else {
			ret = 0;
			goto out;
		}
	}

	ret = 0;
out:
	if (http_head) {
		http_head_destroy(http_head);
	}
	return ret;
}

int _dns_client_process_tcp(struct dns_server_info *server_info, struct epoll_event *event, unsigned long now)
{
	int len = 0;
	int ret = -1;

	if (event->events & EPOLLIN) {
		/* receive from tcp */
		len = _dns_client_socket_recv(server_info);
		if (len < 0) {
			/* no data to recv, try again */
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				return 0;
			}

			if (errno == ECONNRESET || errno == ENETUNREACH || errno == EHOSTUNREACH) {
				tlog(TLOG_DEBUG, "recv failed, server %s:%d, %s\n", server_info->ip, server_info->port,
					 strerror(errno));
				goto errout;
			}

			if (errno == ETIMEDOUT || errno == ECONNREFUSED) {
				tlog(TLOG_INFO, "recv failed, server %s:%d, %s\n", server_info->ip, server_info->port, strerror(errno));
				goto errout;
			}

			tlog(TLOG_WARN, "recv failed, server %s:%d, %s\n", server_info->ip, server_info->port, strerror(errno));
			goto errout;
		}

		/* peer server close */
		if (len == 0) {
			pthread_mutex_lock(&client.server_list_lock);
			_dns_client_close_socket(server_info);
			server_info->recv_buff.len = 0;
			if (server_info->send_buff.len > 0) {
				/* still remain request data, reconnect and send*/
				ret = _dns_client_create_socket(server_info);
			} else {
				ret = 0;
			}
			pthread_mutex_unlock(&client.server_list_lock);
			tlog(TLOG_DEBUG, "peer close, %s:%d", server_info->ip, server_info->port);
			return ret;
		}

		server_info->recv_buff.len += len;
		if (server_info->recv_buff.len <= 2) {
			/* wait and recv */
			return 0;
		}

		if (_dns_client_process_tcp_buff(server_info) != 0) {
			goto errout;
		}
	}

	/* when connected */
	if (event->events & EPOLLOUT) {
		if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
			server_info->status = DNS_SERVER_STATUS_CONNECTED;
			tlog(TLOG_DEBUG, "tcp server %s connected", server_info->ip);
		}

		if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
			server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
		}

		if (server_info->send_buff.len > 0 || server_info->ssl_want_write == 1) {
			/* send existing send_buffer data  */
			len = _dns_client_socket_send(server_info);
			if (len < 0) {
				if (errno == EAGAIN) {
					return 0;
				}
				goto errout;
			}

			pthread_mutex_lock(&client.server_list_lock);
			server_info->send_buff.len -= len;
			if (server_info->send_buff.len > 0) {
				memmove(server_info->send_buff.data, server_info->send_buff.data + len, server_info->send_buff.len);
			} else if (server_info->send_buff.len < 0) {
				BUG("Internal Error");
			}
			pthread_mutex_unlock(&client.server_list_lock);
		}
		/* still remain data, retry */
		if (server_info->send_buff.len > 0) {
			return 0;
		}

		/* clear epollout event */
		struct epoll_event mod_event;
		memset(&mod_event, 0, sizeof(mod_event));
		mod_event.events = EPOLLIN;
		mod_event.data.ptr = server_info;
		if (server_info->fd > 0) {
			if (epoll_ctl(client.epoll_fd, EPOLL_CTL_MOD, server_info->fd, &mod_event) != 0) {
				tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
				goto errout;
			}
		}
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

int _dns_client_send_tcp(struct dns_server_info *server_info, void *packet, unsigned short len)
{
	int send_len = 0;
	unsigned char inpacket_data[DNS_IN_PACKSIZE];
	unsigned char *inpacket = inpacket_data;

	if (len > sizeof(inpacket_data) - 2) {
		tlog(TLOG_ERROR, "packet size is invalid.");
		return -1;
	}

	/* TCP query format
	 * | len (short) | dns query data |
	 */
	*((unsigned short *)(inpacket)) = htons(len);
	memcpy(inpacket + 2, packet, len);
	len += 2;

	if (server_info->status != DNS_SERVER_STATUS_CONNECTED) {
		return _dns_client_send_data_to_buffer(server_info, inpacket, len);
	}

	if (server_info->fd <= 0) {
		return -1;
	}

	send_len = send(server_info->fd, inpacket, len, MSG_NOSIGNAL);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_client_send_data_to_buffer(server_info, inpacket, len);
		} else if (errno == EPIPE) {
			_dns_client_shutdown_socket(server_info);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_client_send_data_to_buffer(server_info, inpacket + send_len, len - send_len);
	}

	return 0;
}

void _dns_client_check_tcp(void)
{
	struct dns_server_info *server_info = NULL;
	time_t now = 0;

	time(&now);

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry(server_info, &client.dns_server_list, list)
	{
		if (server_info->type == DNS_SERVER_UDP || server_info->type == DNS_SERVER_MDNS) {
			/* no need to check udp server */
			continue;
		}

#if defined(OSSL_QUIC1_VERSION) && !defined (OPENSSL_NO_QUIC)
		if (server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
			if (server_info->ssl) {
				_ssl_do_handevent(server_info);
				if (SSL_get_shutdown(server_info->ssl) != 0) {
					_dns_client_close_socket_ext(server_info, 1);
					tlog(TLOG_DEBUG, "quick server %s:%d shutdown.", server_info->ip, server_info->port);
				}
			}
		}
#endif

		if (server_info->status == DNS_SERVER_STATUS_CONNECTING) {
			if (server_info->last_recv + DNS_TCP_CONNECT_TIMEOUT < now) {
				tlog(TLOG_DEBUG, "server %s:%d connect timeout.", server_info->ip, server_info->port);
				_dns_client_close_socket(server_info);
			}
		} else if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
			if (server_info->last_recv + DNS_TCP_IDLE_TIMEOUT < now) {
				/*disconnect if the server is not responding */
				server_info->recv_buff.len = 0;
				server_info->send_buff.len = 0;
				_dns_client_close_socket(server_info);
			}
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}
