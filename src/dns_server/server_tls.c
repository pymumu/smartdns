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

#include "server_tls.h"
#include "connection.h"
#include "dns_server.h"
#include "server_socket.h"
#include "server_tcp.h"

#include <errno.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <string.h>
#include <sys/epoll.h>

static ssize_t _ssl_read(struct dns_server_conn_tls_client *conn, void *buff, int num)
{
	ssize_t ret = 0;
	if (conn == NULL || buff == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	ret = SSL_read(conn->ssl, buff, num);
	pthread_mutex_unlock(&conn->ssl_lock);
	return ret;
}

static ssize_t _ssl_write(struct dns_server_conn_tls_client *conn, const void *buff, int num)
{
	ssize_t ret = 0;
	if (conn == NULL || buff == NULL || conn->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	ret = SSL_write(conn->ssl, buff, num);
	pthread_mutex_unlock(&conn->ssl_lock);
	return ret;
}

static int _ssl_get_error(struct dns_server_conn_tls_client *conn, int ret)
{
	int err = 0;
	if (conn == NULL || conn->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	err = SSL_get_error(conn->ssl, ret);
	pthread_mutex_unlock(&conn->ssl_lock);
	return err;
}

static int _ssl_do_accept(struct dns_server_conn_tls_client *conn)
{
	int err = 0;
	if (conn == NULL || conn->ssl == NULL) {
		return SSL_ERROR_SYSCALL;
	}

	pthread_mutex_lock(&conn->ssl_lock);
	err = SSL_accept(conn->ssl);
	pthread_mutex_unlock(&conn->ssl_lock);
	return err;
}

int _dns_server_socket_ssl_send(struct dns_server_conn_tls_client *tls_client, const void *buf, int num)
{
	int ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (tls_client->ssl == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (num < 0) {
		errno = EINVAL;
		return -1;
	}

	ret = _ssl_write(tls_client, buf, num);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error(tls_client, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_SSL:
		ssl_err = ERR_get_error();
		int ssl_reason = ERR_GET_REASON(ssl_err);
		if (ssl_reason == SSL_R_UNINITIALIZED || ssl_reason == SSL_R_PROTOCOL_IS_SHUTDOWN ||
			ssl_reason == SSL_R_BAD_LENGTH || ssl_reason == SSL_R_SHUTDOWN_WHILE_IN_INIT ||
			ssl_reason == SSL_R_BAD_WRITE_RETRY) {
			errno = EAGAIN;
			return -1;
		}

		tlog(TLOG_ERROR, "SSL write fail error no:  %s(%d)\n", ERR_reason_error_string(ssl_err), ssl_reason);
		errno = EFAULT;
		ret = -1;
		break;
	case SSL_ERROR_SYSCALL:
		tlog(TLOG_DEBUG, "SSL syscall failed, %s", strerror(errno));
		return ret;
	default:
		errno = EFAULT;
		ret = -1;
		break;
	}

	return ret;
}

int _dns_server_socket_ssl_recv(struct dns_server_conn_tls_client *tls_client, void *buf, int num)
{
	ssize_t ret = 0;
	int ssl_ret = 0;
	unsigned long ssl_err = 0;

	if (tls_client->ssl == NULL) {
		errno = EFAULT;
		return -1;
	}

	ret = _ssl_read(tls_client, buf, num);
	if (ret > 0) {
		return ret;
	}

	ssl_ret = _ssl_get_error(tls_client, ret);
	switch (ssl_ret) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return 0;
		break;
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_READ;
		break;
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		ret = -SSL_ERROR_WANT_WRITE;
		break;
	case SSL_ERROR_SSL:
		ssl_err = ERR_get_error();
		int ssl_reason = ERR_GET_REASON(ssl_err);
		if (ssl_reason == SSL_R_UNINITIALIZED) {
			errno = EAGAIN;
			return -1;
		}

		if (ssl_reason == SSL_R_SHUTDOWN_WHILE_IN_INIT || ssl_reason == SSL_R_PROTOCOL_IS_SHUTDOWN) {
			return 0;
		}

#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
		if (ssl_reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
			return 0;
		}
#endif

		tlog(TLOG_DEBUG, "SSL read fail error no: %s(%lx), reason: %d\n", ERR_reason_error_string(ssl_err), ssl_err,
			 ssl_reason);
		errno = EFAULT;
		ret = -1;
		break;
	case SSL_ERROR_SYSCALL:
		if (errno == 0) {
			return 0;
		}

		ret = -1;
		return ret;
	default:
		errno = EFAULT;
		ret = -1;
		break;
	}

	return ret;
}

int _dns_server_ssl_poll_event(struct dns_server_conn_tls_client *tls_client, int ssl_ret)
{
	struct epoll_event fd_event;

	memset(&fd_event, 0, sizeof(fd_event));

	if (ssl_ret == SSL_ERROR_WANT_READ) {
		fd_event.events = EPOLLIN;
	} else if (ssl_ret == SSL_ERROR_WANT_WRITE) {
		fd_event.events = EPOLLOUT | EPOLLIN;
	} else {
		goto errout;
	}

	fd_event.data.ptr = tls_client;
	if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, tls_client->tcp.head.fd, &fd_event) != 0) {
		if (errno == ENOENT) {
			/* fd not found, ignore */
			return 0;
		}
		tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
		goto errout;
	}

	return 0;

errout:
	return -1;
}

int _dns_server_tls_accept(struct dns_server_conn_tls_server *tls_server, struct epoll_event *event, unsigned long now)
{
	struct sockaddr_storage addr;
	struct dns_server_conn_tls_client *tls_client = NULL;
	DNS_CONN_TYPE conn_type;
	socklen_t addr_len = sizeof(addr);
	int fd = -1;
	SSL *ssl = NULL;

	fd = accept4(tls_server->head.fd, (struct sockaddr *)&addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		tlog(TLOG_ERROR, "accept failed, %s", strerror(errno));
		return -1;
	}

	if (tls_server->head.type == DNS_CONN_TYPE_TLS_SERVER) {
		conn_type = DNS_CONN_TYPE_TLS_CLIENT;
	} else if (tls_server->head.type == DNS_CONN_TYPE_HTTPS_SERVER) {
		conn_type = DNS_CONN_TYPE_HTTPS_CLIENT;
	} else {
		tlog(TLOG_ERROR, "invalid http server type.");
		goto errout;
	}

	tls_client = malloc(sizeof(*tls_client));
	if (tls_client == NULL) {
		tlog(TLOG_ERROR, "malloc for tls_client failed.");
		goto errout;
	}
	memset(tls_client, 0, sizeof(*tls_client));
	_dns_server_conn_head_init(&tls_client->tcp.head, fd, conn_type);
	tls_client->tcp.head.server_flags = tls_server->head.server_flags;
	tls_client->tcp.head.dns_group = tls_server->head.dns_group;
	tls_client->tcp.head.ipset_nftset_rule = tls_server->head.ipset_nftset_rule;
	tls_client->tcp.conn_idle_timeout = dns_conf.tcp_idle_time;

	atomic_set(&tls_client->tcp.head.refcnt, 0);
	memcpy(&tls_client->tcp.addr, &addr, addr_len);
	tls_client->tcp.addr_len = addr_len;
	tls_client->tcp.localaddr_len = sizeof(struct sockaddr_storage);
	if (_dns_server_epoll_ctl(&tls_client->tcp.head, EPOLL_CTL_ADD, EPOLLIN) != 0) {
		tlog(TLOG_ERROR, "epoll ctl failed.");
		return -1;
	}

	if (getsocket_inet(tls_client->tcp.head.fd, (struct sockaddr *)&tls_client->tcp.localaddr,
					   &tls_client->tcp.localaddr_len) != 0) {
		tlog(TLOG_ERROR, "get local addr failed, %s", strerror(errno));
		goto errout;
	}

	ssl = SSL_new(tls_server->ssl_ctx);
	if (ssl == NULL) {
		tlog(TLOG_ERROR, "SSL_new failed.");
		goto errout;
	}

	if (SSL_set_fd(ssl, fd) != 1) {
		tlog(TLOG_ERROR, "SSL_set_fd failed.");
		goto errout;
	}

	tls_client->ssl = ssl;
	tls_client->tcp.status = DNS_SERVER_CLIENT_STATUS_CONNECTING;
	pthread_mutex_init(&tls_client->ssl_lock, NULL);
	_dns_server_client_touch(&tls_client->tcp.head);

	pthread_mutex_lock(&server.conn_list_lock);
	list_add(&tls_client->tcp.head.list, &server.conn_list);
	pthread_mutex_unlock(&server.conn_list_lock);

	_dns_server_conn_get(&tls_client->tcp.head);

	set_sock_keepalive(fd, 30, 3, 5);

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	if (ssl) {
		SSL_free(ssl);
	}

	if (tls_client) {
		free(tls_client);
	}
	return -1;
}

int _dns_server_process_tls(struct dns_server_conn_tls_client *tls_client, struct epoll_event *event, unsigned long now)
{
	int ret = 0;
	int ssl_ret = 0;
	struct epoll_event fd_event;

	if (tls_client->tcp.status == DNS_SERVER_CLIENT_STATUS_CONNECTING) {
		/* do SSL hand shake */
		ret = _ssl_do_accept(tls_client);
		if (ret <= 0) {
			memset(&fd_event, 0, sizeof(fd_event));
			ssl_ret = _ssl_get_error(tls_client, ret);
			if (_dns_server_ssl_poll_event(tls_client, ssl_ret) == 0) {
				return 0;
			}

			if (ssl_ret != SSL_ERROR_SYSCALL) {
				unsigned long ssl_err = ERR_get_error();
				int ssl_reason = ERR_GET_REASON(ssl_err);
				char name[DNS_MAX_CNAME_LEN];
				tlog(TLOG_DEBUG, "Handshake with %s failed, error no: %s(%d, %d, %d)\n",
					 get_host_by_addr(name, sizeof(name), (struct sockaddr *)&tls_client->tcp.addr),
					 ERR_reason_error_string(ssl_err), ret, ssl_ret, ssl_reason);
				ret = 0;
			}

			goto errout;
		}

		tls_client->tcp.status = DNS_SERVER_CLIENT_STATUS_CONNECTED;
		memset(&fd_event, 0, sizeof(fd_event));
		fd_event.events = EPOLLIN | EPOLLOUT;
		fd_event.data.ptr = tls_client;
		if (epoll_ctl(server.epoll_fd, EPOLL_CTL_MOD, tls_client->tcp.head.fd, &fd_event) != 0) {
			tlog(TLOG_ERROR, "epoll ctl failed, %s", strerror(errno));
			goto errout;
		}
	}

	return _dns_server_process_tcp((struct dns_server_conn_tcp_client *)tls_client, event, now);
errout:
	_dns_server_client_close(&tls_client->tcp.head);
	return ret;
}

static int _dns_server_socket_tls_ssl_pass_callback(char *buf, int size, int rwflag, void *userdata)
{
	struct dns_bind_ip *bind_ip = userdata;
	if (bind_ip->ssl_cert_key_pass == NULL || bind_ip->ssl_cert_key_pass[0] == '\0') {
		return 0;
	}
	safe_strncpy(buf, bind_ip->ssl_cert_key_pass, size);
	return strlen(buf);
}

int _dns_server_socket_tls(struct dns_bind_ip *bind_ip, DNS_CONN_TYPE conn_type)
{
	const char *host_ip = NULL;
	const char *ssl_cert_file = NULL;
	const char *ssl_cert_key_file = NULL;

	struct dns_server_conn_tls_server *conn = NULL;
	int fd = -1;
	const SSL_METHOD *method = NULL;
	SSL_CTX *ssl_ctx = NULL;
	const int on = 1;

	host_ip = bind_ip->ip;
	ssl_cert_file = bind_ip->ssl_cert_file;
	ssl_cert_key_file = bind_ip->ssl_cert_key_file;

	if (ssl_cert_file == NULL || ssl_cert_key_file == NULL) {
		tlog(TLOG_WARN, "no cert or cert key file");
		goto errout;
	}

	if (ssl_cert_file[0] == '\0' || ssl_cert_key_file[0] == '\0') {
		tlog(TLOG_WARN, "no cert or cert key file");
		goto errout;
	}

	fd = _dns_create_socket(host_ip, SOCK_STREAM);
	if (fd <= 0) {
		goto errout;
	}

	setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &on, sizeof(on));

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	method = TLS_server_method();
	if (method == NULL) {
		goto errout;
	}
#else
	method = SSLv23_server_method();
#endif

	ssl_ctx = SSL_CTX_new(method);
	if (ssl_ctx == NULL) {
		goto errout;
	}

	SSL_CTX_set_session_cache_mode(ssl_ctx,
								   SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_NO_AUTO_CLEAR);
	SSL_CTX_set_default_passwd_cb(ssl_ctx, _dns_server_socket_tls_ssl_pass_callback);
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, bind_ip);

	/* Set the key and cert */
	if (ssl_cert_file[0] != '\0' && SSL_CTX_use_certificate_chain_file(ssl_ctx, ssl_cert_file) <= 0) {
		tlog(TLOG_ERROR, "load cert %s failed, %s", ssl_cert_file, ERR_error_string(ERR_get_error(), NULL));
		goto errout;
	}

	if (ssl_cert_key_file[0] != '\0' &&
		SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_cert_key_file, SSL_FILETYPE_PEM) <= 0) {
		tlog(TLOG_ERROR, "load cert key %s failed, %s", ssl_cert_key_file, ERR_error_string(ERR_get_error(), NULL));
		goto errout;
	}

	conn = malloc(sizeof(struct dns_server_conn_tls_server));
	if (conn == NULL) {
		goto errout;
	}
	memset(conn, 0, sizeof(struct dns_server_conn_tls_server));
	_dns_server_conn_head_init(&conn->head, fd, conn_type);
	conn->ssl_ctx = ssl_ctx;
	_dns_server_set_flags(&conn->head, bind_ip);
	_dns_server_conn_get(&conn->head);

	return 0;
errout:
	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
		ssl_ctx = NULL;
	}

	if (conn) {
		free(conn);
		conn = NULL;
	}

	if (fd > 0) {
		close(fd);
	}
	return -1;
}
