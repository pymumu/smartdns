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

#include "server_tcp.h"
#include "connection.h"
#include "dns_server.h"
#include "server_https.h"
#include "server_http2.h"
#include "server_socket.h"
#include "server_tls.h"

#include "smartdns/http_parse.h"
#include "../http_parse/http2_parse.h"

#include <errno.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/epoll.h>

int _dns_server_reply_tcp_to_buffer(struct dns_server_conn_tcp_client *tcpclient, void *packet, int len)
{
	if ((int)sizeof(tcpclient->sndbuff.buf) - tcpclient->sndbuff.size < len) {
		return -1;
	}

	memcpy(tcpclient->sndbuff.buf + tcpclient->sndbuff.size, packet, len);
	tcpclient->sndbuff.size += len;

	if (tcpclient->head.fd <= 0) {
		return -1;
	}

	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_MOD, EPOLLIN | EPOLLOUT) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

int _dns_server_reply_tcp(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient, void *packet,
						  unsigned short len)
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

	send_len = _dns_server_tcp_socket_send(tcpclient, inpacket, len);
	if (send_len < 0) {
		if (errno == EAGAIN) {
			/* save data to buffer, and retry when EPOLLOUT is available */
			return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket, len);
		}
		return -1;
	} else if (send_len < len) {
		/* save remain data to buffer, and retry when EPOLLOUT is available */
		return _dns_server_reply_tcp_to_buffer(tcpclient, inpacket + send_len, len - send_len);
	}

	return 0;
}

int _dns_server_tcp_accept(struct dns_server_conn_tcp_server *tcpserver, struct epoll_event *event, unsigned long now)
{
	struct sockaddr_storage addr;
	struct dns_server_conn_tcp_client *tcpclient = NULL;
	socklen_t addr_len = sizeof(addr);
	int fd = -1;

	fd = accept4(tcpserver->head.fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		tlog(TLOG_ERROR, "accept failed, %s", strerror(errno));
		return -1;
	}

	tcpclient = malloc(sizeof(*tcpclient));
	if (tcpclient == NULL) {
		tlog(TLOG_ERROR, "malloc for tcpclient failed.");
		goto errout;
	}
	memset(tcpclient, 0, sizeof(*tcpclient));
	_dns_server_conn_head_init(&tcpclient->head, fd, DNS_CONN_TYPE_TCP_CLIENT);
	tcpclient->head.server_flags = tcpserver->head.server_flags;
	tcpclient->head.dns_group = tcpserver->head.dns_group;
	tcpclient->head.ipset_nftset_rule = tcpserver->head.ipset_nftset_rule;
	tcpclient->conn_idle_timeout = dns_conf.tcp_idle_time;

	memcpy(&tcpclient->addr, &addr, addr_len);
	tcpclient->addr_len = addr_len;
	tcpclient->localaddr_len = sizeof(struct sockaddr_storage);
	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_ADD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	if (getsocket_inet(tcpclient->head.fd, (struct sockaddr *)&tcpclient->localaddr, &tcpclient->localaddr_len) != 0) {
		tlog(TLOG_ERROR, "get local addr failed, %s", strerror(errno));
		goto errout;
	}

	_dns_server_client_touch(&tcpclient->head);

	pthread_mutex_lock(&server.conn_list_lock);
	list_add(&tcpclient->head.list, &server.conn_list);
	pthread_mutex_unlock(&server.conn_list_lock);
	_dns_server_conn_get(&tcpclient->head);

	set_sock_keepalive(fd, 30, 3, 5);

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}
	if (tcpclient) {
		free(tcpclient);
	}
	return -1;
}

int _dns_server_tcp_socket_send(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len)
{
	if (tcp_client->head.type == DNS_CONN_TYPE_TCP_CLIENT) {
		return send(tcp_client->head.fd, data, data_len, MSG_NOSIGNAL);
	} else if (tcp_client->head.type == DNS_CONN_TYPE_TLS_CLIENT ||
			   tcp_client->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcp_client;
		tls_client->ssl_want_write = 0;
		int ret = _dns_server_socket_ssl_send(tls_client, data, data_len);
		if (ret < 0 && errno == EAGAIN) {
			if (_dns_server_ssl_poll_event(tls_client, SSL_ERROR_WANT_WRITE) == 0) {
				errno = EAGAIN;
			}
		}
		return ret;
	} else {
		return -1;
	}
}

int _dns_server_tcp_socket_recv(struct dns_server_conn_tcp_client *tcp_client, void *data, int data_len)
{
	if (tcp_client->head.type == DNS_CONN_TYPE_TCP_CLIENT) {
		return recv(tcp_client->head.fd, data, data_len, MSG_NOSIGNAL);
	} else if (tcp_client->head.type == DNS_CONN_TYPE_TLS_CLIENT ||
			   tcp_client->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcp_client;
		int ret = _dns_server_socket_ssl_recv(tls_client, data, data_len);
		if (ret == -SSL_ERROR_WANT_WRITE && errno == EAGAIN) {
			if (_dns_server_ssl_poll_event(tls_client, SSL_ERROR_WANT_WRITE) == 0) {
				errno = EAGAIN;
				tls_client->ssl_want_write = 1;
			}
		}

		return ret;
	} else {
		return -1;
	}
}

static int _dns_server_tcp_recv(struct dns_server_conn_tcp_client *tcpclient)
{
	ssize_t len = 0;

	/* Receive data */
	while (tcpclient->recvbuff.size < (int)sizeof(tcpclient->recvbuff.buf)) {
		if (tcpclient->recvbuff.size == (int)sizeof(tcpclient->recvbuff.buf)) {
			return 0;
		}

		if (unlikely(tcpclient->recvbuff.size < 0)) {
			BUG("recv buffer size is invalid.");
		}

		len = _dns_server_tcp_socket_recv(tcpclient, tcpclient->recvbuff.buf + tcpclient->recvbuff.size,
										  sizeof(tcpclient->recvbuff.buf) - tcpclient->recvbuff.size);
		if (len < 0) {
			if (errno == EAGAIN) {
				return RECV_ERROR_AGAIN;
			}

			if (errno == ECONNRESET) {
				return RECV_ERROR_CLOSE;
			}

			if (errno == ETIMEDOUT) {
				return RECV_ERROR_CLOSE;
			}

			tlog(TLOG_DEBUG, "recv failed, %s\n", strerror(errno));
			return RECV_ERROR_FAIL;
		} else if (len == 0) {
			return RECV_ERROR_CLOSE;
		}

		tcpclient->recvbuff.size += len;
	}

	return 0;
}

static int _dns_server_tcp_process_one_request(struct dns_server_conn_tcp_client *tcpclient)
{
	unsigned short request_len = 0;
	int total_len = tcpclient->recvbuff.size;
	int proceed_len = 0;
	unsigned char *request_data = NULL;
	int ret = RECV_ERROR_FAIL;
	int len = 0;
	struct http_head *http_head = NULL;
	uint8_t *http_decode_data = NULL;
	char *base64_query = NULL;

	/* Handling multiple requests */
	for (;;) {
		ret = RECV_ERROR_FAIL;

		if (proceed_len > tcpclient->recvbuff.size) {
			tlog(TLOG_DEBUG, "proceed_len > recvbuff.size");
			goto out;
		}

		if (tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
			if ((total_len - proceed_len) <= 0) {
				ret = RECV_ERROR_AGAIN;
				goto out;
			}

			/* Check if this is HTTP/2 or HTTP/1.1 */
			int is_http2 = 0;
			if (tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
				/* Cast to TLS client to access http2_ctx */
				struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcpclient;
				
				/* If http2_ctx exists, we're using HTTP/2 */
				if (tls_client->http2_ctx != NULL) {
					is_http2 = 1;
				} else if (_dns_server_is_http2_request(tcpclient->recvbuff.buf + proceed_len, 
														 tcpclient->recvbuff.size - proceed_len)) {
					is_http2 = 1;
				}
			}

			if (is_http2) {
				/* Handle HTTP/2 request */
				struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcpclient;
				unsigned char *http2_request_data = NULL;
				int http2_request_len = 0;
				
				len = _dns_server_process_http2_request(tls_client, 
														 tcpclient->recvbuff.buf + proceed_len,
														 tcpclient->recvbuff.size - proceed_len,
														 &http2_request_data, &http2_request_len);
				if (len < 0) {
					tlog(TLOG_DEBUG, "Failed to process HTTP/2 request");
					goto errout;
				} else if (len == 0) {
					/* Need more data */
					ret = RECV_ERROR_AGAIN;
					goto out;
				}
				
				request_data = http2_request_data;
				request_len = http2_request_len;
				proceed_len += len;
			} else {
				/* Handle HTTP/1.1 request */
				http_head = http_head_init(4096, HTTP_VERSION_1_1);
				if (http_head == NULL) {
					goto out;
				}

				len = http_head_parse(http_head, tcpclient->recvbuff.buf + proceed_len, tcpclient->recvbuff.size  - proceed_len);
				if (len < 0) {
					if (len == -1) {
						ret = 0;
						goto out;
					} else if (len == -3) {
						tcpclient->recvbuff.size = 0;
						tlog(TLOG_DEBUG, "recv buffer is not enough.");
						goto errout;
					}

					tlog(TLOG_DEBUG, "parser http header failed.");
					goto errout;
				}

				if (http_head_get_method(http_head) == HTTP_METHOD_POST) {
					const char *content_type = http_head_get_fields_value(http_head, "Content-Type");
					if (content_type == NULL ||
						strncasecmp(content_type, "application/dns-message", sizeof("application/dns-message")) != 0) {
						tlog(TLOG_DEBUG, "content type not supported, %s", content_type);
						goto errout;
					}

					request_len = http_head_get_data_len(http_head);
					if (request_len >= len) {
						tlog(TLOG_DEBUG, "request length is invalid.");
						goto errout;
					}
					request_data = (unsigned char *)http_head_get_data(http_head);
				} else if (http_head_get_method(http_head) == HTTP_METHOD_GET) {
					const char *path = http_head_get_url(http_head);
					if (path == NULL || strncasecmp(path, "/dns-query", sizeof("/dns-query")) != 0) {
						ret = RECV_ERROR_BAD_PATH;
						tlog(TLOG_DEBUG, "path not supported, %s", path);
						goto errout;
					}

					const char *dns_query = http_head_get_params_value(http_head, "dns");
					if (dns_query == NULL) {
						tlog(TLOG_DEBUG, "query is null.");
						goto errout;
					}

					if (base64_query == NULL) {
						base64_query = malloc(DNS_IN_PACKSIZE);
						if (base64_query == NULL) {
							tlog(TLOG_DEBUG, "malloc failed.");
							goto errout;
						}
					}

					if (urldecode(base64_query, DNS_IN_PACKSIZE, dns_query) < 0) {
						tlog(TLOG_DEBUG, "urldecode query failed.");
						goto errout;
					}

					if (http_decode_data == NULL) {
						http_decode_data = malloc(DNS_IN_PACKSIZE);
						if (http_decode_data == NULL) {
							tlog(TLOG_DEBUG, "malloc failed.");
							goto errout;
						}
					}

					int decode_len = SSL_base64_decode_ext(base64_query, http_decode_data, DNS_IN_PACKSIZE, 1, 1);
					if (decode_len <= 0) {
						tlog(TLOG_DEBUG, "decode query failed.");
						goto errout;
					}

					request_len = decode_len;
					request_data = http_decode_data;
				} else {
					tlog(TLOG_DEBUG, "http method is invalid.");
					goto errout;
				}

				proceed_len += len;
			}
		} else {
			if ((total_len - proceed_len) <= (int)sizeof(unsigned short)) {
				ret = RECV_ERROR_AGAIN;
				goto out;
			}

			/* Get record length */
			request_data = (unsigned char *)(tcpclient->recvbuff.buf + proceed_len);
			request_len = ntohs(*((unsigned short *)(request_data)));

			if (request_len >= sizeof(tcpclient->recvbuff.buf)) {
				tlog(TLOG_DEBUG, "request length is invalid. len = %d", request_len);
				goto errout;
			}

			if (request_len > (total_len - proceed_len - sizeof(unsigned short))) {
				ret = RECV_ERROR_AGAIN;
				goto out;
			}

			request_data = (unsigned char *)(tcpclient->recvbuff.buf + proceed_len + sizeof(unsigned short));
			proceed_len += sizeof(unsigned short) + request_len;
		}

		/* process one record */
		ret = _dns_server_recv(&tcpclient->head, request_data, request_len, &tcpclient->localaddr,
							   tcpclient->localaddr_len, &tcpclient->addr, tcpclient->addr_len);
		if (ret != 0) {
			goto errout;
		}

		if (http_head != NULL) {
			http_head_destroy(http_head);
			http_head = NULL;
		}
	}

out:
	if (total_len > proceed_len && proceed_len > 0) {
		memmove(tcpclient->recvbuff.buf, tcpclient->recvbuff.buf + proceed_len, total_len - proceed_len);
	}

	tcpclient->recvbuff.size -= proceed_len;

errout:
	if (http_head) {
		http_head_destroy(http_head);
	}

	if (http_decode_data) {
		free(http_decode_data);
	}

	if (base64_query) {
		free(base64_query);
	}

	if (tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		if (ret == RECV_ERROR_BAD_PATH) {
			_dns_server_reply_http_error(tcpclient, 404, "Not Found", "Not Found");
		} else if (ret == RECV_ERROR_FAIL || ret == RECV_ERROR_INVALID_PACKET) {
			_dns_server_reply_http_error(tcpclient, 400, "Bad Request", "Bad Request");
		}
	}

	return ret;
}

int _dns_server_tcp_process_requests(struct dns_server_conn_tcp_client *tcpclient)
{
	int recv_ret = 0;
	int request_ret = 0;
	int is_eof = 0;
	int i = 0;

	for (i = 0; i < 32; i++) {
		recv_ret = _dns_server_tcp_recv(tcpclient);
		if (recv_ret < 0) {
			if (recv_ret == RECV_ERROR_CLOSE) {
				return RECV_ERROR_CLOSE;
			}

			if (tcpclient->recvbuff.size > 0) {
				is_eof = RECV_ERROR_AGAIN;
			} else {
				return RECV_ERROR_FAIL;
			}
		}

		request_ret = _dns_server_tcp_process_one_request(tcpclient);
		if (request_ret < 0) {
			/* failed */
			tlog(TLOG_DEBUG, "process one request failed.");
			return RECV_ERROR_FAIL;
		}

		if (request_ret == RECV_ERROR_AGAIN && is_eof == RECV_ERROR_AGAIN) {
			/* failed or remote shutdown */
			return RECV_ERROR_FAIL;
		}

		if (recv_ret == RECV_ERROR_AGAIN && request_ret == RECV_ERROR_AGAIN) {
			/* process complete */
			return 0;
		}
	}

	return 0;
}

static int _dns_server_tls_want_write(struct dns_server_conn_tcp_client *tcpclient)
{
	if (tcpclient->head.type == DNS_CONN_TYPE_TLS_CLIENT || tcpclient->head.type == DNS_CONN_TYPE_HTTPS_CLIENT) {
		struct dns_server_conn_tls_client *tls_client = (struct dns_server_conn_tls_client *)tcpclient;
		if (tls_client->ssl_want_write == 1) {
			return 1;
		}
	}

	return 0;
}

static int _dns_server_tcp_send(struct dns_server_conn_tcp_client *tcpclient)
{
	int len = 0;
	while (tcpclient->sndbuff.size > 0 || _dns_server_tls_want_write(tcpclient) == 1) {
		len = _dns_server_tcp_socket_send(tcpclient, tcpclient->sndbuff.buf, tcpclient->sndbuff.size);
		if (len < 0) {
			if (errno == EAGAIN) {
				return RECV_ERROR_AGAIN;
			}
			return RECV_ERROR_FAIL;
		} else if (len == 0) {
			break;
		}

		tcpclient->sndbuff.size -= len;
	}

	if (_dns_server_epoll_ctl(&tcpclient->head, EPOLL_CTL_MOD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	return 0;
}

int _dns_server_process_tcp(struct dns_server_conn_tcp_client *dnsserver, struct epoll_event *event, unsigned long now)
{
	int ret = 0;

	if (event->events & EPOLLIN) {
		ret = _dns_server_tcp_process_requests(dnsserver);
		if (ret != 0) {
			_dns_server_client_close(&dnsserver->head);
			if (ret == RECV_ERROR_CLOSE) {
				return 0;
			}
			tlog(TLOG_DEBUG, "process tcp request failed.");
			return RECV_ERROR_FAIL;
		}
	}

	if (event->events & EPOLLOUT) {
		if (_dns_server_tcp_send(dnsserver) != 0) {
			_dns_server_client_close(&dnsserver->head);
			tlog(TLOG_DEBUG, "send tcp failed.");
			return RECV_ERROR_FAIL;
		}
	}

	return 0;
}

void _dns_server_tcp_idle_check(void)
{
	struct dns_server_conn_head *conn = NULL;
	struct dns_server_conn_head *tmp = NULL;
	time_t now = 0;

	time(&now);
	pthread_mutex_lock(&server.conn_list_lock);
	list_for_each_entry_safe(conn, tmp, &server.conn_list, list)
	{
		if (conn->type != DNS_CONN_TYPE_TCP_CLIENT && conn->type != DNS_CONN_TYPE_TLS_CLIENT &&
			conn->type != DNS_CONN_TYPE_HTTPS_CLIENT) {
			continue;
		}

		struct dns_server_conn_tcp_client *tcpclient = (struct dns_server_conn_tcp_client *)conn;

		if (tcpclient->conn_idle_timeout <= 0) {
			continue;
		}

		if (conn->last_request_time > now - tcpclient->conn_idle_timeout) {
			continue;
		}

		_dns_server_client_close(conn);
	}
	pthread_mutex_unlock(&server.conn_list_lock);
}

int _dns_server_socket_tcp(struct dns_bind_ip *bind_ip)
{
	const char *host_ip = NULL;
	struct dns_server_conn_tcp_server *conn = NULL;
	int fd = -1;
	const int on = 1;

	host_ip = bind_ip->ip;

	fd = _dns_create_socket(host_ip, SOCK_STREAM);
	if (fd <= 0) {
		goto errout;
	}

	setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &on, sizeof(on));

	conn = malloc(sizeof(struct dns_server_conn_tcp_server));
	if (conn == NULL) {
		goto errout;
	}
	memset(conn, 0, sizeof(struct dns_server_conn_tcp_server));
	_dns_server_conn_head_init(&conn->head, fd, DNS_CONN_TYPE_TCP_SERVER);
	_dns_server_set_flags(&conn->head, bind_ip);
	_dns_server_conn_get(&conn->head);

	return 0;
errout:
	if (conn) {
		free(conn);
		conn = NULL;
	}

	if (fd > 0) {
		close(fd);
	}
	return -1;
}
