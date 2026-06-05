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

#include "server_http.h"
#include "connection.h"
#include "dns_server.h"
#include "server_https.h"
#include "server_socket.h"
#include "server_tcp.h"

#include <errno.h>
#include <netinet/tcp.h>
#include <string.h>

int _dns_server_reply_http(struct dns_request *request, struct dns_server_conn_tcp_client *tcpclient, void *packet,
						   unsigned short len)
{
	return _dns_server_reply_https(request, tcpclient, packet, len);
}

int _dns_server_socket_http(struct dns_bind_ip *bind_ip)
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

	conn = zalloc(1, sizeof(struct dns_server_conn_tcp_server));
	if (conn == NULL) {
		goto errout;
	}
	_dns_server_conn_head_init(&conn->head, fd, DNS_CONN_TYPE_HTTP_SERVER);
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
