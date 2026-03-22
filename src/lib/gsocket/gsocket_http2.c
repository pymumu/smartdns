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
#include "smartdns/http2.h"
#include "smartdns/lib/gsocket.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct gsocket_http2_ctx {
	struct gsocket_io *io;
	struct http2_ctx *h2_ctx;
	struct gsocket_io *ready_stream; /* Accepted stream waiting to be picked up */
	int is_server;
	char alpn_protocol[32];               /* Negotiated ALPN protocol */
	struct gsocket_io *http1_fallback_io; /* HTTP/1.1 fallback layer if ALPN negotiates to http/1.1 */
};

struct gsocket_http2_stream_ctx {
	struct gsocket_io *conn_io; /* Parent connection IO */
	struct http2_stream *h2_stream;
	int received_eof;

	/* Request headers */
	char *method;
	char *path;
	char *scheme;
	int headers_sent;
	int status_code;
	size_t content_length;
	char *extra_headers;
	int extra_headers_len;
};
static int _http2_stream_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);
static int _http2_conn_process(struct gsocket_io *io);
static struct gsocket_io *_http2_create_stream_io(struct gsocket_io *conn_io, struct http2_stream *h2_stream);
static int _http2_conn_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _http2_conn_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _http2_conn_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen);
static int _http2_conn_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);

/* BIO Callbacks */
static int _http2_bio_read(void *private_data, uint8_t *buf, int len)
{
	struct gsocket_io *io = (struct gsocket_io *)private_data;
	if (!io || !io->lower) {
		errno = EAGAIN;
		return -1;
	}

	int ret = io->lower->recv(io->lower, buf, len, MSG_DONTWAIT);
	return ret;
}

static int _http2_bio_write(void *private_data, const uint8_t *buf, int len)
{
	struct gsocket_io *io = (struct gsocket_io *)private_data;
	if (!io || !io->lower) {
		errno = EAGAIN;
		return -1;
	}

	int ret = io->lower->send(io->lower, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
	return ret;
}

static ssize_t _http2_stream_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (!s_ctx || !s_ctx->h2_stream) {
		return -1;
	}

	int ret;

	while (1) {
		ret = http2_stream_read_body(s_ctx->h2_stream, (uint8_t *)buf, len);
		if (ret > 0) {
			return ret;
		}

		if (http2_stream_is_end(s_ctx->h2_stream)) {
			return 0; // EOF
		}

		if (flags & MSG_DONTWAIT) {
			errno = EAGAIN;
			return -1;
		}

		/* Blocking read: drive connection IO */
		if (s_ctx->conn_io) {
			_http2_conn_process(s_ctx->conn_io);
		}

		/* Check if data became available */
		if (http2_stream_body_available(s_ctx->h2_stream)) {
			continue;
		}
		if (http2_stream_is_end(s_ctx->h2_stream)) {
			// fflush(stdout);
			return 0;
		}

		/* Wait for data on underlying FD */
		if (s_ctx->conn_io && s_ctx->conn_io->lower && s_ctx->conn_io->lower->get_fd) {
			struct pollfd pfd;
			pfd.fd = s_ctx->conn_io->lower->get_fd(s_ctx->conn_io->lower);
			pfd.events = POLLIN;

			int pr = poll(&pfd, 1, 1000);
			if (pr < 0) {
				if (errno == EINTR) {
					continue;
				}
				return -1;
			}
			if (pr == 0) {
				/* Timeout in polling lower FD. Loop to process connection again? */
			}
		} else {
			usleep(1000);
		}
	}
}

static ssize_t _http2_stream_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (!s_ctx || !s_ctx->h2_stream) {
		return -1;
	}

	if (!s_ctx->headers_sent) {
		/* Send headers first */
		struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)s_ctx->conn_io->ctx;
		if (ctx->is_server) {
			struct http2_header_pair pairs[16];
			int count = 0;
			char cl_str[32];
			if (s_ctx->content_length > 0) {
				snprintf(cl_str, sizeof(cl_str), "%zu", s_ctx->content_length);
				pairs[count].name = "content-length";
				pairs[count].value = cl_str;
				count++;
			}

			/* Simple parsing for extra_headers (assume one for now or add more logic) */
			if (s_ctx->extra_headers) {
				char *h = strdup(s_ctx->extra_headers);
				char *p = strstr(h, ": ");
				if (p) {
					*p = 0;
					char *v = p + 2;
					char *e = strstr(v, "\r\n");
					if (e) {
						*e = 0;
					}
					pairs[count].name = strdup(h);
					pairs[count].value = strdup(v);
					count++;
				}
				free(h);
			}

			http2_stream_set_response(s_ctx->h2_stream, s_ctx->status_code, pairs, count);

			/* Free temporary strdups if we added any */
			if (s_ctx->extra_headers) {
				int extra_idx = (s_ctx->content_length > 0) ? 1 : 0;
				if (count > extra_idx) {
					free((void *)pairs[extra_idx].name);
					free((void *)pairs[extra_idx].value);
				}
			}
		} else {
			/* Client Side: Send Request Headers */
			const char *method = s_ctx->method ? s_ctx->method : "GET";
			const char *path = s_ctx->path ? s_ctx->path : "/";
			const char *scheme = "http"; // Default to http for now, or check SSL?

			struct http2_header_pair pairs[16];
			int count = 0;

			/* Simple parsing for extra_headers (assume one for now or add more logic) */
			if (s_ctx->extra_headers) {
				char *h = strdup(s_ctx->extra_headers);
				char *p = strstr(h, ": ");
				if (p) {
					*p = 0;
					char *v = p + 2;
					char *e = strstr(v, "\r\n");
					if (e) {
						*e = 0;
					}
					pairs[count].name = strdup(h);
					pairs[count].value = strdup(v);
					count++;
				}
				free(h);
			}

			// Add null terminator for pairs array (set_request iterates until name is NULL)
			pairs[count].name = NULL;
			pairs[count].value = NULL;

			http2_stream_set_request(s_ctx->h2_stream, method, path, scheme, count > 0 ? pairs : NULL);

			/* Free temporary strdups if we added any */
			if (s_ctx->extra_headers && count > 0) {
				free((void *)pairs[0].name);
				free((void *)pairs[0].value);
			}

			if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
				s_ctx->headers_sent = 1;
				return len;
			}
		}
		s_ctx->headers_sent = 1;
	}

	int end_stream = (flags & GS_MSG_FIN) ? 1 : 0;
	int ret = http2_stream_write_body(s_ctx->h2_stream, (const uint8_t *)buf, len, end_stream);

	/* Flush connection immediately if possible */
	if (s_ctx->conn_io) {
		_http2_conn_process(s_ctx->conn_io);
	}

	return ret;
}

static int _http2_stream_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (level != SOL_HTTP) {
		return -1;
	}

	if (optname == SO_HTTP_METHOD) {
		if (s_ctx->method) {
			free(s_ctx->method);
		}
		s_ctx->method = strndup((const char *)optval, optlen);
		return 0;
	}

	if (optname == SO_HTTP_URL) {
		if (s_ctx->path) {
			free(s_ctx->path);
		}
		s_ctx->path = strndup((const char *)optval, optlen);
		return 0;
	}

	if (optname == SO_HTTP_STATUS) {
		s_ctx->status_code = *(int *)optval;
		return 0;
	}

	if (optname == SO_HTTP_BODY_LEN) {
		s_ctx->content_length = *(size_t *)optval;
		return 0;
	}

	if (optname == SO_HTTP_HEADER) {
		if (s_ctx->extra_headers) {
			free(s_ctx->extra_headers);
		}
		s_ctx->extra_headers = (char *)malloc(optlen + 1);
		if (s_ctx->extra_headers) {
			memcpy(s_ctx->extra_headers, optval, optlen);
			s_ctx->extra_headers[optlen] = 0;
			s_ctx->extra_headers_len = optlen;
		}
		return 0;
	}

	return 0;
}

static int _http2_stream_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (level == SOL_HTTP) {
		switch (optname) {
		case SO_HTTP_STATUS:
			if (s_ctx->h2_stream) {
				int status = http2_stream_get_status(s_ctx->h2_stream);
				if (status > 0) {
					s_ctx->status_code = status;
				}
			}
			*(int *)optval = s_ctx->status_code;
			*optlen = sizeof(int);
			return 0;
		case SO_HTTP_BODY_LEN:
			*(size_t *)optval = s_ctx->content_length;
			*optlen = sizeof(size_t);
			return 0;
		case SO_HTTP_METHOD:
			if (s_ctx->method && *optlen > 0) {
				size_t len = strlen(s_ctx->method);
				if (len >= *optlen) {
					len = *optlen - 1;
				}
				memcpy(optval, s_ctx->method, len);
				((char *)optval)[len] = 0;
				*optlen = len;
				return 0;
			}
			return -1;
		case SO_HTTP_URL:
			if (s_ctx->path && *optlen > 0) {
				size_t len = strlen(s_ctx->path);
				if (len >= *optlen) {
					len = *optlen - 1;
				}
				memcpy(optval, s_ctx->path, len);
				((char *)optval)[len] = 0;
				*optlen = len;
				return 0;
			}
			return -1;
		}
	}
	return 0;
}

static int _http2_stream_close(struct gsocket_io *io)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (s_ctx && s_ctx->h2_stream) {
		http2_stream_close(s_ctx->h2_stream);
		s_ctx->h2_stream = NULL;
	}

	return 0;
}

static void _http2_stream_free(struct gsocket_io *io)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (s_ctx) {
		if (s_ctx->method) {
			free(s_ctx->method);
		}
		if (s_ctx->path) {
			free(s_ctx->path);
		}
		if (s_ctx->scheme) {
			free(s_ctx->scheme);
		}
		if (s_ctx->h2_stream) {
			http2_stream_close(s_ctx->h2_stream);
			s_ctx->h2_stream = NULL;
		}
		if (s_ctx->extra_headers) {
			free(s_ctx->extra_headers);
		}
		free(s_ctx);
	}
	free(io);
}

static int _http2_stream_get_fd(struct gsocket_io *io)
{
	struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)io->ctx;
	if (s_ctx && s_ctx->conn_io && s_ctx->conn_io->lower) {
		return s_ctx->conn_io->lower->get_fd(s_ctx->conn_io->lower);
	}

	return -1;
}

static int _http2_conn_process(struct gsocket_io *io)
{
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;

	/* Lower handshake */
	if (io->lower && io->lower->handshake) {
		int ret = io->lower->handshake(io->lower);
		if (ret != GSOCKET_HANDSHAKE_DONE) {
			return ret;
		}

		/* After SSL handshake completes, check ALPN protocol */
		if (ctx->alpn_protocol[0] == 0) {
			char alpn[32] = {0};
			socklen_t alpn_len = sizeof(alpn) - 1;
			if (io->lower->getsockopt && io->lower->getsockopt(io->lower, SOL_SSL, SO_SSL_ALPN, alpn, &alpn_len) == 0) {
				alpn[alpn_len] = 0;
				strncpy(ctx->alpn_protocol, alpn, sizeof(ctx->alpn_protocol) - 1);
				ctx->alpn_protocol[sizeof(ctx->alpn_protocol) - 1] = '\0';

				/* If ALPN is http/1.1, set up fallback */
				if (strcmp(alpn, "http/1.1") == 0) {
					if (!ctx->http1_fallback_io) {
						ctx->http1_fallback_io = gsocket_io_http1_new(ctx->is_server);
						if (ctx->http1_fallback_io) {
							/* Link the HTTP/1.1 layer to the same lower layer */
							ctx->http1_fallback_io->lower = io->lower;
						}
					}
					/* In fallback mode, delegate handshake to HTTP/1.1 */
					if (ctx->http1_fallback_io && ctx->http1_fallback_io->handshake) {
						return ctx->http1_fallback_io->handshake(ctx->http1_fallback_io);
					}
					return GSOCKET_HANDSHAKE_DONE;
				}
				/* If ALPN is h2 or empty, use HTTP/2 */
				else if (!ctx->is_server && !ctx->h2_ctx) {
					/* Create HTTP/2 context for client */
					struct http2_settings settings = {0};
					ctx->h2_ctx = http2_ctx_client_new("localhost", _http2_bio_read, _http2_bio_write, io, &settings);
					if (!ctx->h2_ctx) {
						return GSOCKET_HANDSHAKE_ERR;
					}
				}
			}
		}
	}

	/* If in HTTP/1.1 fallback mode, delegate to HTTP/1.1 */
	if (ctx->http1_fallback_io) {
		if (ctx->http1_fallback_io->handshake) {
			return ctx->http1_fallback_io->handshake(ctx->http1_fallback_io);
		}
		return GSOCKET_HANDSHAKE_DONE;
	}

	/* For clients without SSL (no ALPN), create HTTP/2 context if not exists */
	if (!ctx->is_server && !ctx->h2_ctx) {
		struct http2_settings settings = {0};
		ctx->h2_ctx = http2_ctx_client_new("localhost", _http2_bio_read, _http2_bio_write, io, &settings);
		if (!ctx->h2_ctx) {
			return GSOCKET_HANDSHAKE_ERR;
		}
	}

	int ret = http2_ctx_handshake(ctx->h2_ctx);
	if (ret == 0) {
		if (http2_ctx_want_write(ctx->h2_ctx)) {
			int c = 0;
			http2_ctx_poll(ctx->h2_ctx, NULL, 0, &c); /* Drive IO to flush */
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_WANT_READ;
	}

	if (ret == -1) {
		return GSOCKET_HANDSHAKE_ERR;
	}

	/* Handshake done (ret==1). Drive IO processing via poll to flush any ACKs */
	int count = 0;
	while (1) {
		int r = http2_ctx_poll(ctx->h2_ctx, NULL, 0, &count);
		if (r == HTTP2_ERR_EAGAIN) {
			break;
		}

		if (r < 0) {
			return GSOCKET_HANDSHAKE_ERR;
		}
	}

	return GSOCKET_HANDSHAKE_DONE;
}

static struct gsocket_io *_http2_create_stream_io(struct gsocket_io *conn_io, struct http2_stream *h2_stream)
{
	struct gsocket_io *s_io = (struct gsocket_io *)calloc(1, sizeof(struct gsocket_io));
	struct gsocket_http2_stream_ctx *s_ctx =
		(struct gsocket_http2_stream_ctx *)calloc(1, sizeof(struct gsocket_http2_stream_ctx));

	if (!s_io || !s_ctx) {
		goto _err;
	}

	s_ctx->conn_io = conn_io;
	s_ctx->h2_stream = h2_stream;
	s_ctx->status_code = 200;

	const char *method = http2_stream_get_method(h2_stream);
	if (method) {
		s_ctx->method = strdup(method);
	}
	const char *path = http2_stream_get_path(h2_stream);
	if (path) {
		s_ctx->path = strdup(path);
	}

	s_io->ctx = s_ctx;
	s_io->send = _http2_stream_send;
	s_io->recv = _http2_stream_recv;
	s_io->close = _http2_stream_close;
	s_io->free = _http2_stream_free;
	s_io->get_fd = _http2_stream_get_fd;
	s_io->setsockopt = _http2_stream_setsockopt;
	s_io->getsockopt = _http2_stream_getsockopt;

	return s_io;

_err:
	if (s_io) {
		free(s_io);
	}

	if (s_ctx) {
		free(s_ctx);
	}

	return NULL;
}

static struct gsocket_io *_http2_conn_open_stream(struct gsocket_io *io)
{
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;

	/* If in HTTP/1.1 fallback mode, delegate to HTTP/1.1 */
	if (ctx->http1_fallback_io && ctx->http1_fallback_io->open_stream) {
		return ctx->http1_fallback_io->open_stream(ctx->http1_fallback_io);
	}

	if (!ctx->h2_ctx) {
		return NULL;
	}

	struct http2_stream *stream = http2_stream_new(ctx->h2_ctx);
	if (!stream) {
		return NULL;
	}

	return _http2_create_stream_io(io, stream);
}

static struct gsocket_io *_http2_conn_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;

	/* If in HTTP/1.1 fallback mode, delegate to HTTP/1.1 */
	if (ctx->http1_fallback_io && ctx->http1_fallback_io->accept) {
		return ctx->http1_fallback_io->accept(ctx->http1_fallback_io, addr, addrlen);
	}

	if (!ctx->is_server) {
		return NULL;
	}

	/* Try to accept from lower layer (Listener delegation) */
	if (io->lower && io->lower->accept) {
		struct gsocket_io *lower_client = io->lower->accept(io->lower, addr, addrlen);
		if (lower_client) {
			/* Wrap the new client connection */
			struct gsocket_io *http2_client = gsocket_io_http2_new(1);
			if (http2_client) {
				http2_client->lower = lower_client;
				return http2_client;
			} else {
				if (lower_client->free) {
					lower_client->free(lower_client);
				}
				return NULL;
			}
		} else if (errno != EINVAL && errno != ENOTSUP && errno != EAGAIN && errno != EWOULDBLOCK) {
			/* Real error or EAGAIN from lower accept */
			return NULL;
		}
		/* If EINVAL/ENOTSUP, fall through to stream accept logic */
	}

	if (ctx->ready_stream) {
		struct gsocket_io *stream = ctx->ready_stream;
		ctx->ready_stream = NULL;
		return stream;
	}

	/* Drive handshake/IO if needed */
	_http2_conn_process(io);

	/* Try to accept from HTTP/2 ctx */
	struct http2_stream *stream = http2_ctx_accept_stream(ctx->h2_ctx);
	if (stream) {
		return _http2_create_stream_io(io, stream);
	}

	if (http2_ctx_want_read(ctx->h2_ctx) || http2_ctx_want_write(ctx->h2_ctx)) {
		errno = EAGAIN;
	}

	return NULL;
}

static int _http2_conn_close(struct gsocket_io *io)
{
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;
	if (ctx->h2_ctx) {
		http2_ctx_close(ctx->h2_ctx);
		ctx->h2_ctx = NULL;
	}

	return 0;
}

static void _http2_conn_free(struct gsocket_io *io)
{
	if (io->ctx) {
		struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;
		_http2_conn_close(io);
		/* Free HTTP/1.1 fallback layer if present */
		if (ctx->http1_fallback_io) {
			/* Don't free lower layer as it's shared */
			ctx->http1_fallback_io->lower = NULL;
			if (ctx->http1_fallback_io->free) {
				ctx->http1_fallback_io->free(ctx->http1_fallback_io);
			}
		}
		free(io->ctx);
	}
	free(io);
}

static int _http2_conn_get_fd(struct gsocket_io *io)
{
	if (io->lower && io->lower->get_fd) {
		return io->lower->get_fd(io->lower);
	}

	return -1;
}

static int _http2_conn_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms)
{
	/*
	   For now, we map gstream_poll_item to http2_poll_item.
	   This requires finding the underlying http2_stream for each gsocket_io stream.
	*/
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;

	/* If in HTTP/1.1 fallback mode, delegate to HTTP/1.1 */
	if (ctx->http1_fallback_io && ctx->http1_fallback_io->stream_poll) {
		return ctx->http1_fallback_io->stream_poll(ctx->http1_fallback_io, items, count, timeout_ms);
	}

	if (!ctx->h2_ctx) {
		return -1;
	}

	/* Drive IO */
	int p_ret = _http2_conn_process(io);

	if (p_ret == GSOCKET_HANDSHAKE_ERR) {
		return -1;
	}

	/* Try to accept new streams if we don't have one ready */
	if (ctx->is_server && !ctx->ready_stream) {
		struct http2_stream *stream = http2_ctx_accept_stream(ctx->h2_ctx);
		if (stream) {
			ctx->ready_stream = _http2_create_stream_io(io, stream);
		}
	}

	int events_signaled = 0;

	/* Iterate items and check status */
	for (int i = 0; i < count; i++) {
		struct gsocket_io *s_io = gsocket_get_top_layer(items[i].stream);

		if (s_io == io) {
			/* Polling connection for new streams (accept) */
			if (ctx->ready_stream) {
				if (items[i].events & POLLIN) {
					items[i].revents |= POLLIN;
					events_signaled++;
				}
			} else if (p_ret == GSOCKET_HANDSHAKE_ERR) {
				/* If connection error, signal ERR? Or just let it fail? */
				items[i].revents |= POLLERR;
				events_signaled++;
			}
			continue;
		}

		/* It is a stream */
		struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)s_io->ctx;
		if (s_ctx && s_ctx->h2_stream) {
			if (items[i].events & POLLIN) {
				if (http2_stream_body_available(s_ctx->h2_stream) || http2_stream_is_end(s_ctx->h2_stream)) {
					items[i].revents |= POLLIN;
					events_signaled++;
				}
			}
			if (items[i].events & POLLOUT) {
				/* Assume always writable if window allows? */
				/* For now, just say yes */
				items[i].revents |= POLLOUT;
				events_signaled++;
			}
		}
	}

	if (events_signaled > 0) {
		return events_signaled;
	}

	/* Fallback to poll underlying FD */
	if (io->lower && io->lower->get_fd) {
		struct pollfd pfd;
		pfd.fd = io->lower->get_fd(io->lower);
		pfd.events = POLLIN; /* Always poll IN for HTTP/2 processing */
		if (http2_ctx_want_write(ctx->h2_ctx)) {
			pfd.events |= POLLOUT;
		}

		int ret = poll(&pfd, 1, timeout_ms);
		if (ret > 0) {
			/* If FD is ready, drive handshake/IO again to make streams ready */
			_http2_conn_process(io);

			/* Re-check streams */
			for (int i = 0; i < count; i++) {
				// Duplicate check logic ...
				struct gsocket_io *s_io = gsocket_get_top_layer(items[i].stream);
				if (s_io == io) {
					/* Check again for ready stream after more IO */
					if (ctx->is_server && !ctx->ready_stream) {
						struct http2_stream *stream = http2_ctx_accept_stream(ctx->h2_ctx);
						if (stream) {
							ctx->ready_stream = _http2_create_stream_io(io, stream);
						}
					}

					if (ctx->ready_stream) {
						if (items[i].events & POLLIN) {
							items[i].revents |= POLLIN;
							events_signaled++;
						}
					}

					/* Also accept if FD has data? No, valid HTTP2 might have data but no new stream. */
				} else {
					struct gsocket_http2_stream_ctx *s_ctx = (struct gsocket_http2_stream_ctx *)s_io->ctx;
					if (s_ctx && s_ctx->h2_stream) {
						if (items[i].events & POLLIN) {
							if (http2_stream_body_available(s_ctx->h2_stream) ||
								http2_stream_is_end(s_ctx->h2_stream)) {
								items[i].revents |= POLLIN;
								events_signaled++;
							}
						}
					}
				}
			}
		}
	}

	return events_signaled;
}

static int _http2_connect(struct gsocket_io *io, const char *host, int port)
{
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)io->ctx;

	/* Connect lower layer */
	if (io->lower && io->lower->connect) {
		int ret = io->lower->connect(io->lower, host, port);
		if (ret < 0 && errno != EINPROGRESS) {
			return ret;
		}
		/* If EINPROGRESS, we continue to setup context but don't drive IO yet?
		   Actually, we can setup context. IO driving will fail with EAGAIN.
		*/
	}

	/* Don't create HTTP/2 context yet - wait for ALPN negotiation in handshake */
	/* Store host for later use */
	if (!ctx->is_server && !ctx->h2_ctx && !ctx->http1_fallback_io) {
		/* We'll create the appropriate context in handshake after ALPN is known */
	}

	return 0;
}

struct gsocket_io *gsocket_io_http2_new(int is_server)
{
	struct gsocket_io *io = (struct gsocket_io *)calloc(1, sizeof(struct gsocket_io));
	struct gsocket_http2_ctx *ctx = (struct gsocket_http2_ctx *)calloc(1, sizeof(struct gsocket_http2_ctx));

	if (!io || !ctx) {
		goto _err;
	}

	ctx->io = io;
	ctx->is_server = is_server;

	struct http2_settings settings = {0};

	if (is_server) {
		ctx->h2_ctx = http2_ctx_server_new("gsocket-server", _http2_bio_read, _http2_bio_write, io, &settings);
		if (!ctx->h2_ctx) {
			goto _err;
		}
	}

	io->ctx = ctx;
	io->connect = _http2_connect;
	io->handshake = _http2_conn_process;
	io->accept = _http2_conn_accept;
	io->open_stream = _http2_conn_open_stream;
	io->close = _http2_conn_close;
	io->free = _http2_conn_free;
	io->get_fd = _http2_conn_get_fd;
	io->stream_poll = _http2_conn_stream_poll;
	io->getsockname = _http2_conn_getsockname;
	io->getpeername = _http2_conn_getpeername;
	io->setsockopt = _http2_conn_setsockopt;
	io->getsockopt = _http2_conn_getsockopt;

	return io;

_err:
	if (io) {
		free(io);
	}

	if (ctx) {
		free(ctx);
	}

	return NULL;
}

static int _http2_conn_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (io->lower && io->lower->getsockname) {
		return io->lower->getsockname(io->lower, addr, len);
	}
	return -1;
}

static int _http2_conn_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (io->lower && io->lower->getpeername) {
		return io->lower->getpeername(io->lower, addr, len);
	}
	return -1;
}

static int _http2_conn_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	if (io->lower && io->lower->setsockopt) {
		return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}

static int _http2_conn_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	if (io->lower && io->lower->getsockopt) {
		return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}
