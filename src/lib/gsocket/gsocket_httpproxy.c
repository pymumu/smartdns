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
#include "smartdns/http_parse.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

struct httpproxy_ctx {
	char proxy_host[256];
	uint16_t proxy_port;
	char target_host[256]; /* Stores IP or Domain */
	uint16_t target_port;

	char *user;
	char *pass;
	int state;
	char buffer[4096];
	int buf_len;
	int is_server;

	/* Error Reporting */
	int last_error_code; /* HTTP status code */
	char error_msg[256]; /* Human-readable error message */
};

enum { HTTPPROXY_INIT = 0, HTTPPROXY_AUTH_ACK, HTTPPROXY_DONE, HTTPPROXY_ERR, HTTPPROXY_SRV_INIT = 10 };

/* --- Generic IO Proxies --- */
static ssize_t _io_proxy_send(struct gsocket_io *io, const void *b, size_t l, int f)
{
	return io->lower->send(io->lower, b, l, f);
}
static ssize_t _io_proxy_recvfrom(struct gsocket_io *io, void *b, size_t l, int f, struct sockaddr *s, socklen_t *sl)
{
	return io->lower->recvfrom(io->lower, b, l, f, s, sl);
}
static ssize_t _io_proxy_sendto(struct gsocket_io *io, const void *b, size_t l, int f, const struct sockaddr *d,
								socklen_t dl)
{
	return io->lower->sendto(io->lower, b, l, f, d, dl);
}
static ssize_t _io_proxy_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	if (!io->lower || !io->lower->sendmsg) {
		return -1;
	}
	return io->lower->sendmsg(io->lower, msg, flags);
}

static int _io_proxy_close(struct gsocket_io *io)
{
	return io->lower->close(io->lower);
}

static int _io_proxy_get_fd(struct gsocket_io *io)
{
	return io->lower->get_fd(io->lower);
}

static int _io_proxy_shutdown(struct gsocket_io *io, int h)
{
	return io->lower->shutdown(io->lower, h);
}

static int _io_proxy_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (!io->lower || !io->lower->getsockname) {
		return -1;
	}
	return io->lower->getsockname(io->lower, addr, len);
}

static int _io_proxy_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (!io->lower || !io->lower->getpeername) {
		return -1;
	}
	return io->lower->getpeername(io->lower, addr, len);
}

static int _io_proxy_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	if (!io->lower || !io->lower->getsockopt) {
		return -1;
	}
	return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
}

static int _io_proxy_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	if (!io->lower || !io->lower->setsockopt) {
		return -1;
	}
	return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
}

static int _httpproxy_server_handshake(struct gsocket_io *io)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	if (ctx->state == HTTPPROXY_SRV_INIT) {
		int ret = io->lower->recv(io->lower, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - 1 - ctx->buf_len, 0);
		if (ret <= 0) {
			if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return GSOCKET_HANDSHAKE_WANT_READ;
			}
			return GSOCKET_HANDSHAKE_ERR;
		}

		ctx->buf_len += ret;
		ctx->buffer[ctx->buf_len] = 0;

		struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
		int parsed = http_head_parse(head, (const unsigned char *)ctx->buffer, ctx->buf_len);
		if (parsed < 0) {
			http_head_destroy(head);
			return (parsed == -1) ? GSOCKET_HANDSHAKE_WANT_READ : GSOCKET_HANDSHAKE_ERR;
		}

		HTTP_METHOD method = http_head_get_method(head);
		const char *url = http_head_get_url(head);

		if (method == HTTP_METHOD_CONNECT) {
			if (url) {
				char host[MAX_IP_LEN];
				int port = 0;
				if (parse_ip(url, host, &port) == 0) {
					strncpy(ctx->target_host, host, sizeof(ctx->target_host) - 1);
					ctx->target_host[sizeof(ctx->target_host) - 1] = '\0';
					ctx->target_port = (uint16_t)port;
				} else {
					const char *host_val = http_head_get_fields_value(head, "Host");
					if (host_val && parse_ip(host_val, host, &port) == 0) {
						strncpy(ctx->target_host, host, sizeof(ctx->target_host) - 1);
						ctx->target_host[sizeof(ctx->target_host) - 1] = '\0';
						ctx->target_port = (uint16_t)port;
					} else {
						http_head_destroy(head);
						return GSOCKET_HANDSHAKE_ERR;
					}
				}
			}

			if (ctx->user && ctx->pass) {
				const char *auth = http_head_get_fields_value(head, "Proxy-Authorization");
				char expected_auth[1024];
				char user_pass[256];
				snprintf(user_pass, sizeof(user_pass), "%s:%s", ctx->user, ctx->pass);
				char encoded[512];
				SSL_base64_encode((unsigned char *)user_pass, strlen(user_pass), (char *)encoded);
				snprintf(expected_auth, sizeof(expected_auth), "Basic %s", encoded);

				if (!auth || strcmp(auth, expected_auth) != 0) {
					char *fail = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
					io->lower->send(io->lower, fail, strlen(fail), MSG_NOSIGNAL);
					http_head_destroy(head);
					return GSOCKET_HANDSHAKE_ERR;
				}
			}
			http_head_destroy(head);

			char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
			ret = io->lower->send(io->lower, ok, strlen(ok), MSG_NOSIGNAL);
			if (ret != (int)strlen(ok)) {
				if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
					return GSOCKET_HANDSHAKE_WANT_WRITE;
				}
				return GSOCKET_HANDSHAKE_ERR;
			}
			ctx->buf_len = 0;
		} else {
			if (url) {
				char scheme[32];
				char host[256];
				int port = 0;
				char path[1024];

				int parse_ret = parse_uri(url, scheme, host, &port, path);

				if (parse_ret == 0) {
					strncpy(ctx->target_host, host, sizeof(ctx->target_host) - 1);
					ctx->target_host[sizeof(ctx->target_host) - 1] = '\0';
					ctx->target_port = (port == PORT_NOT_DEFINED) ? 80 : (uint16_t)port;
				} else {
					const char *host_val = http_head_get_fields_value(head, "Host");
					if (host_val && parse_ip(host_val, host, &port) == 0) {
						strncpy(ctx->target_host, host, sizeof(ctx->target_host) - 1);
						ctx->target_host[sizeof(ctx->target_host) - 1] = '\0';
						ctx->target_port = (port == PORT_NOT_DEFINED) ? 80 : (uint16_t)port;
					} else {
						http_head_destroy(head);
						return GSOCKET_HANDSHAKE_ERR;
					}
				}
			}

			if (ctx->user && ctx->pass) {
				const char *auth = http_head_get_fields_value(head, "Proxy-Authorization");
				char expected_auth[1024];
				char user_pass[256];
				snprintf(user_pass, sizeof(user_pass), "%s:%s", ctx->user, ctx->pass);
				char encoded[512];
				SSL_base64_encode((unsigned char *)user_pass, strlen(user_pass), (char *)encoded);
				snprintf(expected_auth, sizeof(expected_auth), "Basic %s", encoded);

				if (!auth || strcmp(auth, expected_auth) != 0) {
					char *fail = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
					io->lower->send(io->lower, fail, strlen(fail), MSG_NOSIGNAL);
					http_head_destroy(head);
					return GSOCKET_HANDSHAKE_ERR;
				}
			}
			/* Forward the original request, data remains in buffer */
			http_head_destroy(head);
		}

		ctx->state = HTTPPROXY_DONE;
		return GSOCKET_HANDSHAKE_DONE;
	}

	switch (ctx->state) {
	case HTTPPROXY_DONE:
		return GSOCKET_HANDSHAKE_DONE;
	default:
		break;
	}
	return GSOCKET_HANDSHAKE_ERR;
}

static int _httpproxy_client_handshake(struct gsocket_io *io)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	switch (ctx->state) {
	case HTTPPROXY_INIT: {
		char req[2048];
		const char *host = ctx->target_host;
		int is_ipv6 = (strchr(host, ':') != NULL);

		if (is_ipv6) {
			snprintf(req, sizeof(req), "CONNECT [%s]:%d HTTP/1.1\r\nHost: [%s]:%d\r\n", host, ctx->target_port, host,
					 ctx->target_port);
		} else {
			snprintf(req, sizeof(req), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n", host, ctx->target_port, host,
					 ctx->target_port);
		}

		int len = (int)strlen(req);
		if (ctx->user && ctx->pass) {
			char auth[256];
			snprintf(auth, sizeof(auth), "%s:%s", ctx->user, ctx->pass);
			char encoded[512];
			SSL_base64_encode((unsigned char *)auth, strlen(auth), (char *)encoded); /* OpenSSL API */
			snprintf(req + len, sizeof(req) - len, "Proxy-Authorization: Basic %s\r\n", encoded);
			len = (int)strlen(req);
		}

		snprintf(req + len, sizeof(req) - len, "\r\n");
		len = (int)strlen(req);

		int ret = io->lower->send(io->lower, req, len, MSG_NOSIGNAL);
		if (ret != len) {
			if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return GSOCKET_HANDSHAKE_WANT_WRITE;
			}
			return GSOCKET_HANDSHAKE_ERR;
		}
		ctx->state = HTTPPROXY_AUTH_ACK;
		return GSOCKET_HANDSHAKE_WANT_READ;
	}
	case HTTPPROXY_AUTH_ACK: {
		int ret = io->lower->recv(io->lower, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - 1 - ctx->buf_len, 0);
		if (ret <= 0) {
			if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				return GSOCKET_HANDSHAKE_WANT_READ;
			}
			return GSOCKET_HANDSHAKE_ERR;
		}
		ctx->buf_len += ret;
		ctx->buffer[ctx->buf_len] = 0;
		struct http_head *head = http_head_init(4096, HTTP_VERSION_1_1);
		int parsed = http_head_parse(head, (const unsigned char *)ctx->buffer, ctx->buf_len);
		if (parsed < 0) {
			http_head_destroy(head);
			return (parsed == -1) ? GSOCKET_HANDSHAKE_WANT_READ : GSOCKET_HANDSHAKE_ERR;
		}
		int code = http_head_get_httpcode(head);
		http_head_destroy(head);
		if (code == 200) {
			ctx->state = HTTPPROXY_DONE;
			if (parsed < ctx->buf_len) {
				memmove(ctx->buffer, ctx->buffer + parsed, ctx->buf_len - parsed);
				ctx->buf_len -= parsed;
			} else {
				ctx->buf_len = 0;
			}
			return GSOCKET_HANDSHAKE_DONE;
		} else {
			/* Capture HTTP error code */
			ctx->last_error_code = code;

			/* Map HTTP error to errno and error message */
			switch (code) {
			case HTTP_PROXY_ERR_AUTH_REQUIRED:
				errno = EACCES;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Proxy authentication required");
				break;
			case HTTP_PROXY_ERR_FORBIDDEN:
				errno = EACCES;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Forbidden by proxy");
				break;
			case HTTP_PROXY_ERR_NOT_FOUND:
				errno = EHOSTUNREACH;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Target not found");
				break;
			case HTTP_PROXY_ERR_BAD_GATEWAY:
				errno = EHOSTUNREACH;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Bad gateway");
				break;
			case HTTP_PROXY_ERR_UNAVAILABLE:
				errno = EHOSTUNREACH;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Service unavailable");
				break;
			case HTTP_PROXY_ERR_TIMEOUT:
				errno = ETIMEDOUT;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Gateway timeout");
				break;
			default:
				errno = EIO;
				snprintf(ctx->error_msg, sizeof(ctx->error_msg), "HTTP proxy error (code: %d)", code);
				break;
			}

			return GSOCKET_HANDSHAKE_ERR;
		}
	}
	case HTTPPROXY_DONE:
		return GSOCKET_HANDSHAKE_DONE;
	}
	return GSOCKET_HANDSHAKE_ERR;
}

static int _httpproxy_handshake(struct gsocket_io *io)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	if (io->lower && io->lower->handshake) {
		int res = io->lower->handshake(io->lower);
		if (res != GSOCKET_HANDSHAKE_DONE) {
			return res;
		}
	}

	return ctx->is_server ? _httpproxy_server_handshake(io) : _httpproxy_client_handshake(io);
}

static ssize_t _httpproxy_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	if (ctx->state != HTTPPROXY_DONE) {
		int ret = io->handshake(io);
		if (ret != GSOCKET_HANDSHAKE_DONE) {
			if (ret == GSOCKET_HANDSHAKE_WANT_READ || ret == GSOCKET_HANDSHAKE_WANT_WRITE) {
				errno = EAGAIN;
				return -1;
			}
			return -1;
		}
	}

	if (ctx->buf_len > 0) {
		size_t copy = (len < (size_t)ctx->buf_len) ? len : (size_t)ctx->buf_len;
		memcpy(buf, ctx->buffer, copy);
		memmove(ctx->buffer, ctx->buffer + copy, ctx->buf_len - copy);
		ctx->buf_len -= (int)copy;
		return (ssize_t)copy;
	}
	return io->lower->recv(io->lower, buf, len, flags);
}

static ssize_t _httpproxy_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	if (ctx->state != HTTPPROXY_DONE) {
		int ret = io->handshake(io);
		if (ret != GSOCKET_HANDSHAKE_DONE) {
			if (ret == GSOCKET_HANDSHAKE_WANT_READ || ret == GSOCKET_HANDSHAKE_WANT_WRITE) {
				errno = EAGAIN;
				return -1;
			}
			return -1;
		}
	}

	if (ctx->buf_len > 0) {
		size_t total = 0;
		for (int i = 0; i < (int)msg->msg_iovlen && ctx->buf_len > 0; i++) {
			size_t copy =
				(msg->msg_iov[i].iov_len < (size_t)ctx->buf_len) ? msg->msg_iov[i].iov_len : (size_t)ctx->buf_len;
			memcpy(msg->msg_iov[i].iov_base, ctx->buffer, copy);
			memmove(ctx->buffer, ctx->buffer + copy, ctx->buf_len - copy);
			ctx->buf_len -= (int)copy;
			total += copy;
		}
		if (total > 0) {
			return (ssize_t)total;
		}
	}

	if (!io->lower || !io->lower->recvmsg) {
		return -1;
	}
	return io->lower->recvmsg(io->lower, msg, flags);
}

static int _httpproxy_connect(struct gsocket_io *io, const char *host, int port)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	if (ctx->is_server) {
		return -1;
	}

	if (strlen(host) >= sizeof(ctx->target_host)) {
		return -1;
	}
	strncpy(ctx->target_host, host, sizeof(ctx->target_host) - 1);
	ctx->target_host[sizeof(ctx->target_host) - 1] = '\0';
	ctx->target_port = port;

	int ret = io->lower->connect(io->lower, ctx->proxy_host, ctx->proxy_port);
	if (ret != 0 && errno != EINPROGRESS) {
		return ret;
	}

	int flags = fcntl(io->lower->get_fd(io->lower), F_GETFL, 0);
	if (!(flags & O_NONBLOCK)) {
		while (ctx->state != HTTPPROXY_DONE) {
			int res = _httpproxy_handshake(io);
			if (res == GSOCKET_HANDSHAKE_ERR) {
				errno = EPROTO;
				return -1;
			}
			if (res == GSOCKET_HANDSHAKE_DONE) {
				break;
			}
		}
	}
	return ret;
}

static void _httpproxy_free(struct gsocket_io *io)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;
	if (ctx->user) {
		free(ctx->user);
	}
	if (ctx->pass) {
		free(ctx->pass);
	}
	free(ctx);
	free(io);
}

static int _httpproxy_get_target(struct gsocket_io *io, struct gsocket_address *target)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;

	strncpy(target->host, ctx->target_host, sizeof(target->host) - 1);
	target->host[sizeof(target->host) - 1] = '\0';
	target->port = ctx->target_port;

	return 0;
}

static int _httpproxy_get_error(struct gsocket_io *io, void *err_struct)
{
	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;
	struct gsocket_error *err = (struct gsocket_error *)err_struct;

	err->layer = SOL_HTTP;
	err->error_code = ctx->last_error_code;
	err->errno_val = errno;
	strncpy(err->message, ctx->error_msg, sizeof(err->message) - 1);
	err->message[sizeof(err->message) - 1] = '\0';

	return 0;
}

struct gsocket_io *gsocket_io_httpproxy_new(const char *proxy_ip, int proxy_port, const char *user, const char *pass)
{
	struct gsocket_io *io = NULL;
	struct httpproxy_ctx *ctx = NULL;

	io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		goto err;
	}
	ctx = calloc(1, sizeof(struct httpproxy_ctx));
	if (!ctx) {
		goto err;
	}

	strncpy(ctx->proxy_host, proxy_ip, sizeof(ctx->proxy_host) - 1);
	ctx->proxy_port = proxy_port;

	if (user) {
		ctx->user = strdup(user);
		if (!ctx->user) {
			goto err;
		}
	}

	if (pass) {
		ctx->pass = strdup(pass);
		if (!ctx->pass) {
			goto err;
		}
	}

	io->ctx = ctx;
	io->handshake = _httpproxy_handshake;
	io->connect = _httpproxy_connect;
	io->recv = _httpproxy_recv;
	io->recvmsg = _httpproxy_recvmsg;
	io->send = _io_proxy_send;
	io->sendmsg = _io_proxy_sendmsg;
	io->recvfrom = _io_proxy_recvfrom;
	io->sendto = _io_proxy_sendto;
	io->close = _io_proxy_close;
	io->get_fd = _io_proxy_get_fd;
	io->shutdown = _io_proxy_shutdown;
	io->free = _httpproxy_free;
	io->get_proxy_target = _httpproxy_get_target;
	io->get_error = _httpproxy_get_error;

	return io;

err:
	if (io) {
		free(io);
	}
	if (ctx) {
		if (ctx->user) {
			free(ctx->user);
		}
		if (ctx->pass) {
			free(ctx->pass);
		}
		free(ctx);
	}
	return NULL;
}

static struct gsocket_io *_httpproxy_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	if (!io->lower || !io->lower->accept) {
		return NULL;
	}

	struct gsocket_io *clower = io->lower->accept(io->lower, addr, addrlen);
	if (!clower) {
		return NULL;
	}

	struct httpproxy_ctx *ctx = (struct httpproxy_ctx *)io->ctx;
	struct gsocket_io *server_io = gsocket_io_httpproxy_server_new(ctx->user, ctx->pass);
	if (!server_io) {
		clower->free(clower);
		return NULL;
	}

	server_io->lower = clower;
	return server_io;
}

struct gsocket_io *gsocket_io_httpproxy_server_new(const char *user, const char *pass)
{
	struct gsocket_io *io = NULL;
	struct httpproxy_ctx *ctx = NULL;

	io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		goto err;
	}
	ctx = calloc(1, sizeof(struct httpproxy_ctx));
	if (!ctx) {
		goto err;
	}

	ctx->is_server = 1;
	ctx->state = HTTPPROXY_SRV_INIT;
	if (user) {
		ctx->user = strdup(user);
		if (!ctx->user) {
			goto err;
		}
	}

	if (pass) {
		ctx->pass = strdup(pass);
		if (!ctx->pass) {
			goto err;
		}
	}

	io->ctx = ctx;
	io->handshake = _httpproxy_handshake;
	io->recv = _httpproxy_recv;
	io->recvmsg = _httpproxy_recvmsg;
	io->send = _io_proxy_send;
	io->sendmsg = _io_proxy_sendmsg;
	io->recvfrom = _io_proxy_recvfrom;
	io->sendto = _io_proxy_sendto;
	io->close = _io_proxy_close;
	io->get_fd = _io_proxy_get_fd;
	io->shutdown = _io_proxy_shutdown;
	io->free = _httpproxy_free;
	io->get_proxy_target = _httpproxy_get_target;
	io->get_error = _httpproxy_get_error;
	io->accept = _httpproxy_accept;
	io->getpeername = _io_proxy_getpeername;
	io->getsockname = _io_proxy_getsockname;
	io->getsockopt = _io_proxy_getsockopt;
	io->setsockopt = _io_proxy_setsockopt;

	return io;

err:
	if (io) {
		free(io);
	}
	if (ctx) {
		if (ctx->user) {
			free(ctx->user);
		}
		if (ctx->pass) {
			free(ctx->pass);
		}
		free(ctx);
	}
	return NULL;
}
