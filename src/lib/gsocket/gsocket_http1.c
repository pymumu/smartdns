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
 *
 */

#include "smartdns/http_parse.h"
#include "smartdns/lib/gsocket.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct http1_ctx {
	struct gsocket_io *io;
	int is_server;
	char unused_buf[32768];
	int unused_len;
	struct gsocket_io *ready_stream;
	struct gsocket_io *default_stream;
};

struct http1_stream_ctx {
	struct gsocket_io *conn_io;
	struct http1_ctx *conn_ctx;
	struct http_head *head;
	int header_received;
	int header_sent;
	char *method;
	char *url;
	char *extra_headers;
	int extra_headers_len;
	size_t content_length;
	size_t read_length;
	size_t sent_length;
	int eof_mode;
	int status_code;
};

static ssize_t _http1_stream_send(struct gsocket_io *io, const void *buf, size_t len, int flags);
static ssize_t _http1_stream_recv(struct gsocket_io *io, void *buf, size_t len, int flags);
static int _http1_stream_close(struct gsocket_io *io);
static void _http1_stream_free(struct gsocket_io *io);
static int _http1_stream_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval,
									socklen_t optlen);
static int _http1_stream_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);
static int _http1_stream_get_fd(struct gsocket_io *io);

static int _http1_conn_handshake(struct gsocket_io *io);
static struct gsocket_io *_http1_conn_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen);
static int _http1_conn_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms);
static int _http1_conn_get_fd(struct gsocket_io *io);
static int _http1_conn_close(struct gsocket_io *io);
static void _http1_conn_free(struct gsocket_io *io);
static struct gsocket_io *_http1_conn_open_stream(struct gsocket_io *io);
static int _http1_conn_connect(struct gsocket_io *io, const char *host, int port);
static ssize_t _http1_conn_send(struct gsocket_io *io, const void *buf, size_t len, int flags);
static ssize_t _http1_conn_recv(struct gsocket_io *io, void *buf, size_t len, int flags);
static int _http1_conn_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _http1_conn_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _http1_conn_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen);
static int _http1_conn_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);

struct gsocket_io *gsocket_io_http1_new(int is_server)
{
	struct gsocket_io *io = calloc(1, sizeof(struct gsocket_io));
	struct http1_ctx *ctx = calloc(1, sizeof(struct http1_ctx));

	if (!io || !ctx) {
		if (io) {
			free(io);
		}

		if (ctx) {
			free(ctx);
		}
		return NULL;
	}

	ctx->io = io;
	ctx->is_server = is_server;
	io->ctx = ctx;

	io->handshake = _http1_conn_handshake;
	io->accept = _http1_conn_accept;
	io->stream_poll = _http1_conn_stream_poll;
	io->open_stream = _http1_conn_open_stream;
	io->get_fd = _http1_conn_get_fd;
	io->close = _http1_conn_close;
	io->free = _http1_conn_free;
	io->connect = _http1_conn_connect;
	io->send = _http1_conn_send;
	io->recv = _http1_conn_recv;
	io->getsockname = _http1_conn_getsockname;
	io->getpeername = _http1_conn_getpeername;
	io->setsockopt = _http1_conn_setsockopt;
	io->getsockopt = _http1_conn_getsockopt;

	return io;
}

static void _http1_populate_metadata(struct http1_stream_ctx *s_ctx, struct http_head *head)
{
	s_ctx->read_length = 0;
	if (s_ctx->head && s_ctx->head != head) {
		http_head_destroy(s_ctx->head);
	}
	s_ctx->head = head;

	const char *cl = http_head_get_fields_value(head, "Content-Length");
	if (cl) {
		s_ctx->content_length = atoi(cl);
		s_ctx->eof_mode = 0;
	} else {
		s_ctx->content_length = 0;
		/* Request with no Content-Length means 0 body. Response means read until close. */
		s_ctx->eof_mode = s_ctx->conn_ctx->is_server ? 0 : 1;
	}
	if (http_head_get_head_type(head) == HTTP_HEAD_RESPONSE) {
		s_ctx->status_code = http_head_get_httpcode(head);
	} else {
		s_ctx->status_code = 200;
	}

	HTTP_METHOD method = http_head_get_method(head);
	const char *url = http_head_get_url(head);
	if (method != HTTP_METHOD_INVALID) {
		const char *mstr = http_method_str(method);
		if (mstr) {
			if (s_ctx->method) {
				free(s_ctx->method);
			}
			s_ctx->method = strdup(mstr);
		}
	}

	if (url) {
		if (s_ctx->url) {
			free(s_ctx->url);
		}
		s_ctx->url = strdup(url);
	}
}

static ssize_t _http1_stream_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct http1_stream_ctx *ctx = (struct http1_stream_ctx *)io->ctx;
	struct gsocket_io *lower = ctx->conn_io->lower;
	char header_buf[1024];
	int hlen = 0;
	ssize_t ret = 0;

	if (ctx->header_received && !ctx->eof_mode && ctx->sent_length >= ctx->content_length) {
		ctx->header_sent = 0;
		ctx->sent_length = 0;
	}

	if (!ctx->header_sent) {
		if (!ctx->conn_ctx->is_server) {
			size_t cl = len;
			if (ctx->content_length > 0) {
				cl = ctx->content_length;
			}
			hlen = snprintf(header_buf, sizeof(header_buf), "%s %s HTTP/1.1\r\nContent-Length: %zu\r\n\r\n",
							ctx->method ? ctx->method : "GET", ctx->url ? ctx->url : "/", cl);
		} else {
			const char *reason = "OK";
			if (ctx->status_code == 404) {
				reason = "Not Found";
			}

			size_t cl = len;
			if (ctx->content_length > 0) {
				cl = ctx->content_length;
			}

			int pos = snprintf(header_buf, sizeof(header_buf), "HTTP/1.1 %d %s\r\n", ctx->status_code, reason);
			if (ctx->extra_headers) {
				if (sizeof(header_buf) - pos > (size_t)ctx->extra_headers_len) {
					memcpy(header_buf + pos, ctx->extra_headers, ctx->extra_headers_len);
					pos += ctx->extra_headers_len;
				}
			}
			snprintf(header_buf + pos, sizeof(header_buf) - pos, "Content-Length: %zu\r\n\r\n", cl);
			hlen = strlen(header_buf);
		}

		if (hlen > 0) {
			ret = lower->send(lower, header_buf, hlen, MSG_NOSIGNAL);
			if (ret <= 0) {
				return ret;
			}
		}
		ctx->header_sent = 1;
	}

	ret = lower->send(lower, buf, len, flags);
	if (ret > 0) {
		ctx->sent_length += ret;
	}
	return ret;
}

static int _http1_recv_header(struct http1_ctx *ctx, struct http_head **head_ret, int flags)
{
	struct gsocket_io *io = ctx->io;
	struct http_head *head = NULL;
	ssize_t n = 0;
	int ret = 0;
	int header_size = 0;
	int remaining = 0;

	if (ctx->unused_len < (int)sizeof(ctx->unused_buf)) {
		n = io->lower->recv(io->lower, ctx->unused_buf + ctx->unused_len, sizeof(ctx->unused_buf) - ctx->unused_len,
							flags);
		if (n > 0) {
			ctx->unused_len += n;
		} else if (n == 0) {
			return GSOCKET_HANDSHAKE_EOF;
		} else if (errno != EAGAIN && errno != EWOULDBLOCK) {
			return GSOCKET_HANDSHAKE_ERR;
		}
	}

	if (ctx->unused_len == 0) {
		return GSOCKET_HANDSHAKE_WANT_READ;
	}

	head = http_head_init(32768, HTTP_VERSION_1_1);
	if (!head) {
		return GSOCKET_HANDSHAKE_ERR;
	}

	ret = http_head_parse(head, (unsigned char *)ctx->unused_buf, ctx->unused_len);
	if (ret > 0 || http_head_is_ok(head)) {
		if (ret > 0) {
			header_size = ret - http_head_get_data_len(head);
		} else {
			header_size = http_head_get_head_len(head);
		}

		remaining = ctx->unused_len - header_size;
		if (remaining > 0) {
			memmove(ctx->unused_buf, ctx->unused_buf + header_size, remaining);
		}
		ctx->unused_len = remaining;
		*head_ret = head;
		return GSOCKET_HANDSHAKE_DONE;
	} else if (ret == -1) {
		return GSOCKET_HANDSHAKE_WANT_READ;
	}

	http_head_destroy(head);
	return GSOCKET_HANDSHAKE_ERR;
}

static ssize_t _http1_stream_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct http1_stream_ctx *ctx = (struct http1_stream_ctx *)io->ctx;
	struct http1_ctx *cctx = ctx->conn_ctx;
	struct http_head *head = NULL;
	ssize_t ret = 0;

	/* If stream is in EOF mode, always return 0 */
	if (ctx->eof_mode) {
		return 0;
	}

	if (ctx->header_received && !ctx->eof_mode && ctx->read_length >= ctx->content_length) {
		ctx->header_received = 0;
		return 0;
	}

	if (!ctx->header_received) {
		int result = _http1_recv_header(cctx, &head, flags);
		if (result == GSOCKET_HANDSHAKE_DONE) {
			if (head) {
				ctx->header_received = 1;
				_http1_populate_metadata(ctx, head);
			} else {
				/* EOF during recv - mark as EOF mode */
				ctx->eof_mode = 1;
				return 0;
			}
		} else {
			if (result == GSOCKET_HANDSHAKE_WANT_READ) {
				errno = EAGAIN;
				return -1;
			}
			return -1;
		}
	}

	if (!ctx->eof_mode && ctx->read_length >= ctx->content_length) {
		return 0;
	}

	if (cctx->unused_len > 0) {
		size_t to_copy = len < (size_t)cctx->unused_len ? len : (size_t)cctx->unused_len;
		if (!ctx->eof_mode && to_copy > ctx->content_length - ctx->read_length) {
			to_copy = ctx->content_length - ctx->read_length;
		}

		if (to_copy > 0) {
			memcpy(buf, cctx->unused_buf, to_copy);
			memmove(cctx->unused_buf, cctx->unused_buf + to_copy, cctx->unused_len - to_copy);
			cctx->unused_len -= to_copy;
			ctx->read_length += to_copy;
			return to_copy;
		}
	}

	size_t to_read = len;
	if (!ctx->eof_mode && to_read > ctx->content_length - ctx->read_length) {
		to_read = ctx->content_length - ctx->read_length;
	}

	if (to_read == 0) {
		return 0;
	}

	ret = ctx->conn_io->lower->recv(ctx->conn_io->lower, buf, to_read, flags);
	if (ret > 0) {
		ctx->read_length += ret;
	}

	return ret;
}

static int _http1_stream_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	struct http1_stream_ctx *ctx = (struct http1_stream_ctx *)io->ctx;
	if (level == SOL_HTTP) {
		switch (optname) {
		case SO_HTTP_METHOD:
			if (ctx->method) {
				free(ctx->method);
			}
			ctx->method = strdup((const char *)optval);
			return 0;
		case SO_HTTP_URL:
			if (ctx->url) {
				free(ctx->url);
			}
			ctx->url = strdup((const char *)optval);
			return 0;
		case SO_HTTP_STATUS:
			ctx->status_code = *(int *)optval;
			return 0;
		case SO_HTTP_HEADER:
			if (ctx->extra_headers) {
				free(ctx->extra_headers);
			}
			ctx->extra_headers = (char *)malloc(optlen + 3);
			if (ctx->extra_headers) {
				memcpy(ctx->extra_headers, optval, optlen);
				ctx->extra_headers[optlen] = '\r';
				ctx->extra_headers[optlen + 1] = '\n';
				ctx->extra_headers[optlen + 2] = 0;
				ctx->extra_headers_len = optlen + 2;
			}
			return 0;
		case SO_HTTP_BODY_LEN:
			ctx->content_length = *(size_t *)optval;
			return 0;
		}
	}
	return 0;
}

static int _http1_stream_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct http1_stream_ctx *ctx = (struct http1_stream_ctx *)io->ctx;
	if (level == SOL_HTTP) {
		switch (optname) {
		case SO_HTTP_STATUS:
			*(int *)optval = ctx->status_code;
			*optlen = sizeof(int);
			return 0;
		case SO_HTTP_METHOD:
			if (ctx->method) {
				size_t l = strlen(ctx->method);
				if (l >= *optlen) {
					l = *optlen - 1;
				}
				memcpy(optval, ctx->method, l);
				((char *)optval)[l] = 0;
				*optlen = l;
				return 0;
			}
			return -1;
		case SO_HTTP_URL:
			if (ctx->url) {
				size_t l = strlen(ctx->url);
				if (l >= *optlen) {
					l = *optlen - 1;
				}
				memcpy(optval, ctx->url, l);
				((char *)optval)[l] = 0;
				*optlen = l;
				return 0;
			}
			return -1;
		case SO_HTTP_BODY_LEN:
			*(size_t *)optval = ctx->content_length;
			*optlen = sizeof(size_t);
			return 0;
		}
	}

	return 0;
}

static int _http1_stream_close(struct gsocket_io *io)
{
	return 0;
}

static void _http1_stream_free(struct gsocket_io *io)
{
	struct http1_stream_ctx *ctx = (struct http1_stream_ctx *)io->ctx;
	if (ctx) {
		if (ctx->head) {
			http_head_destroy(ctx->head);
		}

		if (ctx->method) {
			free(ctx->method);
		}

		if (ctx->url) {
			free(ctx->url);
		}

		if (ctx->extra_headers) {
			free(ctx->extra_headers);
		}

		free(ctx);
	}

	free(io);
}
static int _http1_stream_get_fd(struct gsocket_io *io)
{
	struct http1_stream_ctx *ctx = (struct http1_stream_ctx *)io->ctx;
	return ctx->conn_io->get_fd(ctx->conn_io);
}

static int _http1_conn_handshake(struct gsocket_io *io)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	struct http_head *head = NULL;
	if (io->lower && io->lower->handshake) {
		int ret = io->lower->handshake(io->lower);
		if (ret != GSOCKET_HANDSHAKE_DONE) {
			return ret;
		}
	}

	if (!ctx->is_server || ctx->default_stream) {
		return GSOCKET_HANDSHAKE_DONE;
	}

	int ret = _http1_recv_header(ctx, &head, MSG_DONTWAIT);
	if (ret == GSOCKET_HANDSHAKE_DONE) {
		struct gsocket_io *s_io = _http1_conn_open_stream(io);
		if (!s_io) {
			if (head) {
				http_head_destroy(head);
			}
			return GSOCKET_HANDSHAKE_ERR;
		}
		struct http1_stream_ctx *s_ctx = (struct http1_stream_ctx *)s_io->ctx;

		/* Populate stream with request metadata */
		s_ctx->header_received = 1;
		_http1_populate_metadata(s_ctx, head);

		ctx->default_stream = s_io;
		ctx->ready_stream = s_io;
		return GSOCKET_HANDSHAKE_DONE;
	}

	return ret;
}

static struct gsocket_io *_http1_conn_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (!ctx->is_server) {
		return NULL;
	}

	if (io->lower && io->lower->accept) {
		struct gsocket_io *l = io->lower->accept(io->lower, addr, addrlen);
		if (l) {
			struct gsocket_io *h = gsocket_io_http1_new(1);
			if (h) {
				h->lower = l;
				return h;
			}
			if (l->free) {
				l->free(l);
			}
			return NULL;
		} else if (errno != EINVAL && errno != ENOTSUP && errno != 0 && errno != EAGAIN) {
			return NULL;
		}
	}

	_http1_conn_handshake(io);

	if (ctx->ready_stream) {
		struct gsocket_io *s = ctx->ready_stream;
		ctx->ready_stream = NULL;
		if (ctx->default_stream == s) {
			ctx->default_stream = NULL;
		}
		return s;
	}
	errno = EAGAIN;
	return NULL;
}

static int _http1_conn_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (count == 0 || !io->lower) {
		return 0;
	}

	/* Try to receive more requests if we're a server and don't have a ready stream */
	if (ctx->is_server && !ctx->ready_stream) {
		_http1_conn_handshake(io);
	}

	/* Check if underlying network socket has data available */
	int network_ready = 0;
	if (io->lower && io->lower->get_fd) {
		int fd = io->lower->get_fd(io->lower);
		if (fd >= 0) {
			struct pollfd pfd;
			pfd.fd = fd;
			pfd.events = POLLIN;
			pfd.revents = 0;
			if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
				network_ready = 1;
			}
		}
	}

	int signaled = 0;
	for (int i = 0; i < count; i++) {
		struct gsocket_io *s_io = gsocket_get_top_layer(items[i].stream);

		if (s_io == io || (s_io->lower && io->lower && s_io->lower == io->lower)) {
			/* Polling the connection itself - check if new stream is ready to accept */
			if (ctx->ready_stream && (items[i].events & POLLIN)) {
				items[i].revents |= POLLIN;
				signaled++;
			}
			/* Don't signal POLLIN just because network has data - only when ready_stream exists */
		} else {
			/* Polling an existing stream */
			struct http1_stream_ctx *s_ctx = (struct http1_stream_ctx *)s_io->ctx;

			/* Check POLLIN: stream needs to read request body */
			int need_read =
				(s_ctx->header_received && !s_ctx->eof_mode && s_ctx->read_length < s_ctx->content_length) ||
				ctx->unused_len > 0 || network_ready;
			if (need_read && (items[i].events & POLLIN)) {
				items[i].revents |= POLLIN;
				signaled++;
			}

			/* Check POLLOUT: stream is ready to send response (header received, can write) */
			if (s_ctx->header_received && (items[i].events & POLLOUT)) {
				items[i].revents |= POLLOUT;
				signaled++;
			}
		}
	}

	return signaled;
}

static int _http1_conn_get_fd(struct gsocket_io *io)
{
	return io->lower ? io->lower->get_fd(io->lower) : -1;
}

static int _http1_conn_close(struct gsocket_io *io)
{
	return 0;
}

static void _http1_conn_free(struct gsocket_io *io)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (ctx) {
		if (ctx->ready_stream) {
			ctx->ready_stream->free(ctx->ready_stream);
		}

		if (ctx->default_stream && ctx->default_stream != ctx->ready_stream) {
			ctx->default_stream->free(ctx->default_stream);
		}

		free(ctx);
	}
	free(io);
}

static struct gsocket_io *_http1_conn_open_stream(struct gsocket_io *io)
{
	struct gsocket_io *s_io = calloc(1, sizeof(struct gsocket_io));
	struct http1_stream_ctx *s_ctx = calloc(1, sizeof(struct http1_stream_ctx));
	if (!s_io || !s_ctx) {
		if (s_io) {
			free(s_io);
		}

		if (s_ctx) {
			free(s_ctx);
		}

		return NULL;
	}
	s_ctx->conn_io = io;
	s_ctx->conn_ctx = (struct http1_ctx *)io->ctx;
	s_ctx->status_code = 200;
	s_io->ctx = s_ctx;
	s_io->send = _http1_stream_send;
	s_io->recv = _http1_stream_recv;
	s_io->close = _http1_stream_close;
	s_io->free = _http1_stream_free;
	s_io->setsockopt = _http1_stream_setsockopt;
	s_io->getsockopt = _http1_stream_getsockopt;
	s_io->get_fd = _http1_stream_get_fd;
	return s_io;
}

static int _http1_conn_connect(struct gsocket_io *io, const char *h, int p)
{
	return io->lower ? io->lower->connect(io->lower, h, p) : -1;
}

static ssize_t _http1_conn_send(struct gsocket_io *io, const void *b, size_t l, int f)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (!ctx->default_stream) {
		ctx->default_stream = _http1_conn_open_stream(io);
	}

	return ctx->default_stream->send(ctx->default_stream, b, l, f);
}

static ssize_t _http1_conn_recv(struct gsocket_io *io, void *b, size_t l, int f)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (!ctx->default_stream) {
		int r = _http1_conn_handshake(io);
		if (r != GSOCKET_HANDSHAKE_DONE) {
			if (r == GSOCKET_HANDSHAKE_WANT_READ) {
				errno = EAGAIN;
			} else if (r == GSOCKET_HANDSHAKE_EOF) {
				return 0;
			}

			return -1;
		}
	}
	ssize_t ret = ctx->default_stream->recv(ctx->default_stream, b, l, f);
	if (ret == 0 && l > 0) {
		ctx->default_stream->free(ctx->default_stream);
		ctx->default_stream = NULL;
	}
	return ret;
}

static int _http1_conn_getsockname(struct gsocket_io *i, struct sockaddr *a, socklen_t *l)
{
	return i->lower ? i->lower->getsockname(i->lower, a, l) : -1;
}

static int _http1_conn_getpeername(struct gsocket_io *i, struct sockaddr *a, socklen_t *l)
{
	return i->lower ? i->lower->getpeername(i->lower, a, l) : -1;
}

static int _http1_conn_setsockopt(struct gsocket_io *io, int lv, int opt, const void *val, socklen_t len)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (lv == SOL_HTTP) {
		if (!ctx->default_stream) {
			ctx->default_stream = _http1_conn_open_stream(io);
		}

		return ctx->default_stream->setsockopt(ctx->default_stream, lv, opt, val, len);
	}
	return io->lower ? io->lower->setsockopt(io->lower, lv, opt, val, len) : -1;
}
static int _http1_conn_getsockopt(struct gsocket_io *io, int lv, int opt, void *val, socklen_t *len)
{
	struct http1_ctx *ctx = (struct http1_ctx *)io->ctx;
	if (lv == SOL_HTTP) {
		if (!ctx->default_stream) {
			_http1_conn_handshake(io);
		}

		if (ctx->default_stream) {
			return ctx->default_stream->getsockopt(ctx->default_stream, lv, opt, val, len);
		}
	}
	return io->lower ? io->lower->getsockopt(io->lower, lv, opt, val, len) : -1;
}
