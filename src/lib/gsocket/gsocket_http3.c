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
#include "smartdns/http3.h"
#include "smartdns/lib/gsocket.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

/* Context for the gsocket_io */
struct gsocket_http3_ctx {
	struct http3_ctx *h3_ctx;       /* Shared H3 Context (Connection level) */
	struct http3_stream *h3_stream; /* H3 Stream (Stream level) */
	int is_server;
	int is_connection; /* 1 if this IO represents the QUIC connection, 0 if stream */
	int is_listener;   /* 1 if this IO is a listener */
	int status_code;
	int headers_sent;
	int handshake_done;
	size_t content_length;
	char *extra_headers;
	int extra_headers_len;
	char *request_method;
	char *request_path;
};

/* Forward Declarations */
static int _http3_handshake(struct gsocket_io *io);
static struct gsocket_io *_http3_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen);
static struct gsocket_io *_http3_open_stream(struct gsocket_io *io);
static int _http3_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms);
static void _http3_ctx_free(struct gsocket_io *io);
static int _http3_stream_get_fd(struct gsocket_io *io);
static int _http3_conn_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _http3_conn_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _http3_conn_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen);
static int _http3_conn_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);

static int _http3_parse_extra_headers(const char *headers, struct http3_header_pair *pairs, char **owned_names,
									  char **owned_values, int max_pairs)
{
	int count = 0;
	const char *p = headers;

	while (p && *p && count < max_pairs) {
		const char *line_end = strstr(p, "\r\n");
		const char *next = NULL;
		int end_is_terminator = 0;
		size_t line_len = 0;
		char *line = NULL;
		char *name_dup = NULL;
		char *value_dup = NULL;

		if (line_end) {
			line_len = (size_t)(line_end - p);
		} else {
			line_end = strchr(p, '\n');
			if (line_end) {
				line_len = (size_t)(line_end - p);
			} else {
				line_len = strlen(p);
				line_end = p + line_len;
				end_is_terminator = 1;
			}
		}

		if (!end_is_terminator && *line_end != '\0') {
			next = line_end + ((line_end[0] == '\r' && line_end[1] == '\n') ? 2 : 1);
		}

		if (line_len == 0) {
			if (!next) {
				break;
			}
			p = next;
			continue;
		}

		line = strndup(p, line_len);
		if (line == NULL) {
			break;
		}

		char *sep = strchr(line, ':');
		if (sep) {
			*sep = '\0';
			char *name = line;
			char *value = sep + 1;

			while (*value == ' ' || *value == '\t') {
				value++;
			}

			if (name[0] != '\0' && value[0] != '\0') {
				name_dup = strdup(name);
				value_dup = strdup(value);
				if (!name_dup || !value_dup) {
					goto next_line;
				}

				owned_names[count] = name_dup;
				owned_values[count] = value_dup;
				pairs[count].name = owned_names[count];
				pairs[count].value = owned_values[count];
				name_dup = NULL;
				value_dup = NULL;
				count++;
			}
		}

	next_line:
		free(name_dup);
		free(value_dup);
		free(line);
		if (!next) {
			break;
		}
		p = next;
	}

	return count;
}

static void _http3_free_parsed_headers(char **owned_names, char **owned_values, int count)
{
	for (int i = 0; i < count; i++) {
		free(owned_names[i]);
		free(owned_values[i]);
	}
}

static int _http3_copy_string_opt(const char *value, void *optval, socklen_t *optlen)
{
	size_t len = 0;

	if (!value || !optval || !optlen || *optlen == 0) {
		errno = EINVAL;
		return -1;
	}

	len = strlen(value);
	if (len >= (size_t)*optlen) {
		len = (size_t)*optlen - 1;
	}
	memcpy(optval, value, len);
	((char *)optval)[len] = 0;
	*optlen = (socklen_t)len;
	return 0;
}

/* Ops Forward Declarations */
static void *_h3_ops_create_stream(void *conn_data, int type);
static void _h3_ops_close_stream(void *stream_handle);
static int _h3_ops_read(void *stream_handle, uint8_t *buf, int len);
static int _h3_ops_write(void *stream_handle, const uint8_t *buf, int len, int eof);

static const struct http3_conn_ops _h3_ops = {
	.create_stream = _h3_ops_create_stream,
	.close_stream = _h3_ops_close_stream,
	.read = _h3_ops_read,
	.write = _h3_ops_write,
};

static void _http3_lower_free(struct gsocket_io *io)
{
	if (io && io->free) {
		io->free(io);
	}
}

/* BIO Callbacks to bridge http3_stream -> gsocket_io (lower) */
static int _http3_bio_read(void *private_data, uint8_t *buf, int len)
{
	struct gsocket_io *lower = (struct gsocket_io *)private_data;
	if (!lower || !lower->recv) {
		return -1;
	}

	ssize_t ret = lower->recv(lower, buf, len, 0);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		return -1;
	}

	return (int)ret;
}

static int _http3_bio_write(void *private_data, const uint8_t *buf, int len, int eos)
{
	struct gsocket_io *lower = (struct gsocket_io *)private_data;
	if (!lower || !lower->send) {
		return -1;
	}

	int flags = MSG_NOSIGNAL;
	if (eos) {
		flags |= GS_MSG_FIN;
	}

	ssize_t ret = lower->send(lower, buf, len, flags);
	if (ret < 0) {
		return -1;
	}

	return (int)ret;
}

static void _http3_ctx_free(struct gsocket_io *io)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;
	if (ctx) {
		if (ctx->h3_stream) {
			/* Clear bio_data to prevent http3_stream_put from calling _h3_ops_close_stream
			 * on the lower layer. gsocket_free() already traverses and frees it. */
			http3_stream_set_bio(ctx->h3_stream, NULL, NULL, NULL);
			http3_stream_put(ctx->h3_stream);
		}

		if (ctx->h3_ctx) {
			/* If we own the context (connection level), put it?
			   Usually context is refcounted if shared.
			   For now, assume 1:1 for connection io. */
			http3_ctx_put(ctx->h3_ctx);
		}

		if (ctx->extra_headers) {
			free(ctx->extra_headers);
		}
		if (ctx->request_method) {
			free(ctx->request_method);
		}
		if (ctx->request_path) {
			free(ctx->request_path);
		}
		free(ctx);
		io->ctx = NULL;

		/* DO NOT free io->lower here. gsocket_free() automatically traverses and frees layers. */
	}

	free(io);
}

static int _http3_handshake(struct gsocket_io *io)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;

	/* 1. Underlying Handshake (QUIC) */
	if (io->lower && io->lower->handshake) {
		int ret = io->lower->handshake(io->lower);
		if (ret != GSOCKET_HANDSHAKE_DONE) {
			return ret;
		}
	}

	/* 2. HTTP/3 Handshake (Settings exchange etc - if implemented) */
	/* Only done on connection level */
	if (ctx->is_connection && ctx->h3_ctx) {
		/* PROHIBIT handshake on Listener (Server Socket) */
		if (ctx->is_listener) {
			return GSOCKET_HANDSHAKE_DONE;
		}

		if (ctx->handshake_done) {
			return GSOCKET_HANDSHAKE_DONE;
		}

		int ret = http3_ctx_handshake(ctx->h3_ctx);
		if (ret == 0) {
			ctx->handshake_done = 1;
			return GSOCKET_HANDSHAKE_DONE;
		}

		if (ret < 0) {
			return GSOCKET_HANDSHAKE_ERR;
		}
	}

	return GSOCKET_HANDSHAKE_DONE;
}

static int _http3_connect(struct gsocket_io *io, const char *host, int port)
{
	/* Delegate to lower (QUIC connect) header */
	if (io->lower && io->lower->connect) {
		return io->lower->connect(io->lower, host, port);
	}

	return -1;
}

/* Stream IO Operations */

static ssize_t _http3_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;
	if (!ctx->h3_stream) {
		errno = EINVAL; /* Not a stream */
		return -1;
	}

	/* Use http3_stream_read_body which parses frames from BIO */
	int ret = http3_stream_read_body(ctx->h3_stream, (uint8_t *)buf, len);
	if (ret == 0) {
		if (errno == EAGAIN) {
			return -1;
		}

		return 0;
	}

	if (ret < 0) {
		return -1;
	}

	return ret;
}

static ssize_t _http3_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;
	struct http3_header_pair pairs[16] = {0};
	char *owned_names[16] = {0};
	char *owned_values[16] = {0};
	int owned_count = (int)(sizeof(owned_names) / sizeof(owned_names[0]));
	char cl_str[32];
	int ret = -1;

	if (!ctx->h3_stream) {
		errno = EINVAL;
		goto out;
	}

	if (!ctx->headers_sent) {
		if (ctx->is_server) {
			int count = 0;

			if (ctx->content_length > 0) {
				snprintf(cl_str, sizeof(cl_str), "%zu", ctx->content_length);
				pairs[count].name = "content-length";
				pairs[count].value = cl_str;
				count++;
			}

			if (ctx->extra_headers && count < (int)(sizeof(pairs) / sizeof(pairs[0]))) {
				count +=
					_http3_parse_extra_headers(ctx->extra_headers, &pairs[count], &owned_names[count],
											   &owned_values[count], (int)(sizeof(pairs) / sizeof(pairs[0])) - count);
			}
			if (http3_stream_set_response(ctx->h3_stream, ctx->status_code, pairs, count) != 0) {
				goto out;
			}
		} else {
			/* For client, we assume method/url set via setsockopt or defaults */
			const char *method = ctx->request_method;
			const char *path = ctx->request_path;
			if (!method) {
				method = "GET";
			}

			if (!path) {
				path = "/";
			}

			int count = 0;
			if (ctx->extra_headers) {
				count = _http3_parse_extra_headers(ctx->extra_headers, pairs, owned_names, owned_values,
												   (int)(sizeof(pairs) / sizeof(pairs[0])) - 1);
			}

			if (http3_stream_set_request(ctx->h3_stream, method, path, "https", count > 0 ? pairs : NULL) != 0) {
				goto out;
			}
		}
		ctx->headers_sent = 1;
	}

	/* Write body wraps data in DATA frames and sends via BIO */
	int end_stream = (flags & GS_MSG_FIN) ? 1 : 0;
	ret = http3_stream_write_body(ctx->h3_stream, (const uint8_t *)buf, len, end_stream);

out:
	_http3_free_parsed_headers(owned_names, owned_values, owned_count);
	return ret;
}

/* Setsockopt to handle Headers */
static int _http3_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;

	if (level == SOL_HTTP) {
		if (!ctx->h3_stream) {
			return -1;
		}

		switch (optname) {
		case SO_HTTP_METHOD: {
			if (!optval) {
				errno = EINVAL;
				return -1;
			}
			char *method = strndup((const char *)optval, optlen);
			if (!method) {
				return -1;
			}
			free(ctx->request_method);
			ctx->request_method = method;
			return http3_stream_set_request(ctx->h3_stream, ctx->request_method, ctx->request_path, NULL, NULL);
		}
		case SO_HTTP_URL:
			/* Assuming method set previously or defaults to GET */
			{
				if (!optval) {
					errno = EINVAL;
					return -1;
				}
				char *path = strndup((const char *)optval, optlen);
				if (!path) {
					return -1;
				}
				free(ctx->request_path);
				ctx->request_path = path;
				return http3_stream_set_request(ctx->h3_stream, ctx->request_method, ctx->request_path, "https", NULL);
			}
		case SO_HTTP_STATUS:
			if (!optval || optlen < sizeof(ctx->status_code)) {
				errno = EINVAL;
				return -1;
			}
			ctx->status_code = *(int *)optval;
			return 0;
		case SO_HTTP_BODY_LEN:
			if (!optval || optlen < sizeof(ctx->content_length)) {
				errno = EINVAL;
				return -1;
			}
			ctx->content_length = *(size_t *)optval;
			return 0;
		case SO_HTTP_HEADER: {
			if (!optval) {
				errno = EINVAL;
				return -1;
			}
			char *headers = malloc(optlen + 1);
			if (!headers) {
				return -1;
			}
			memcpy(headers, optval, optlen);
			headers[optlen] = 0;
			free(ctx->extra_headers);
			ctx->extra_headers = headers;
			ctx->extra_headers_len = optlen;
		}
			return 0;
		}
	}

	if (io->lower && io->lower->setsockopt) {
		return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
	}

	return -1;
}

static int _http3_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;
	if (level == SOL_HTTP) {
		if (!ctx->h3_stream) {
			return -1;
		}

		if (optname == SO_HTTP_STATUS) {
			if (!optval || !optlen || *optlen < sizeof(ctx->status_code)) {
				errno = EINVAL;
				return -1;
			}
			if (ctx->h3_stream) {
				int status = http3_stream_get_status(ctx->h3_stream);
				if (status > 0) {
					ctx->status_code = status;
				}
			}
			*(int *)optval = ctx->status_code;
			*optlen = sizeof(int);
			return 0;
		}

		if (optname == SO_HTTP_BODY_LEN) {
			if (!optval || !optlen || *optlen < sizeof(ctx->content_length)) {
				errno = EINVAL;
				return -1;
			}
			const char *content_length = http3_stream_get_header(ctx->h3_stream, "content-length");
			if (content_length && content_length[0]) {
				char *end = NULL;
				unsigned long long value = strtoull(content_length, &end, 10);
				if (end != content_length && *end == '\0') {
					ctx->content_length = (size_t)value;
				}
			}
			*(size_t *)optval = ctx->content_length;
			*optlen = sizeof(size_t);
			return 0;
		}

		if (optname == SO_HTTP_METHOD) {
			const char *method = http3_stream_get_method(ctx->h3_stream);
			if (method) {
				return _http3_copy_string_opt(method, optval, optlen);
			}
			return -1;
		}

		if (optname == SO_HTTP_URL) {
			const char *path = http3_stream_get_path(ctx->h3_stream);
			if (path) {
				return _http3_copy_string_opt(path, optval, optlen);
			}
			return -1;
		}
	}

	if (io->lower && io->lower->getsockopt) {
		return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
	}

	return -1;
}

static int _http3_stream_get_fd(struct gsocket_io *io)
{
	if (io->lower && io->lower->get_fd) {
		return io->lower->get_fd(io->lower);
	}

	return -1;
}

/* Helper to setup new stream IO */
static struct gsocket_io *_http3_create_stream_io(struct gsocket_io *lower_stream_io, struct http3_ctx *h3_ctx_ref,
												  int is_server)
{
	struct gsocket_io *io = NULL;
	struct gsocket_http3_ctx *ctx = NULL;

	io = calloc(1, sizeof(*io));
	ctx = calloc(1, sizeof(*ctx));

	if (!io || !ctx) {
		goto err;
	}

	ctx->is_connection = 0;
	ctx->is_server = is_server;
	ctx->h3_ctx = http3_ctx_get(h3_ctx_ref); /* Ref counting if needed */
	if (!ctx->h3_ctx) {
		goto err;
	}
	ctx->h3_stream = http3_stream_new(ctx->h3_ctx);
	if (!ctx->h3_stream) {
		goto err;
	}
	ctx->status_code = 200;

	io->ctx = ctx;
	io->lower = lower_stream_io; /* The QUIC stream IO */

	io->recv = _http3_recv;
	io->send = _http3_send;
	io->free = _http3_ctx_free;
	io->setsockopt = _http3_setsockopt;
	io->getsockopt = _http3_getsockopt;
	io->get_fd = _http3_stream_get_fd;

	/* Setup BIO on stream */
	http3_stream_set_bio(ctx->h3_stream, _http3_bio_read, _http3_bio_write, lower_stream_io);

	return io;

err:
	if (ctx && ctx->h3_ctx) {
		http3_ctx_put(ctx->h3_ctx);
	}
	free(ctx);
	free(io);

	return NULL;
}

static struct gsocket_io *_http3_create_connection_io(struct gsocket_io *lower_conn_io, int is_server)
{
	struct gsocket_io *io = NULL;
	struct gsocket_http3_ctx *ctx = NULL;

	io = calloc(1, sizeof(*io));
	ctx = calloc(1, sizeof(*ctx));

	if (!io || !ctx) {
		goto err;
	}

	io->ctx = ctx;
	io->lower = lower_conn_io;

	ctx->is_connection = 1;
	ctx->is_listener = 0;
	ctx->is_server = is_server;

	if (is_server) {
		ctx->h3_ctx = http3_ctx_server_new(io, &_h3_ops, NULL);
	} else {
		ctx->h3_ctx = http3_ctx_client_new(io, &_h3_ops, NULL);
	}
	if (!ctx->h3_ctx) {
		goto err;
	}

	/* Connection IO supports accept (streams) and handshake */
	io->handshake = _http3_handshake;
	io->accept = _http3_accept;
	io->open_stream = _http3_open_stream;
	io->stream_poll = _http3_stream_poll;
	io->free = _http3_ctx_free;
	io->get_fd = _http3_stream_get_fd;
	/* Connection level setsockopt/getsockopt? maybe */

	return io;

err:
	free(ctx);
	free(io);

	return NULL;
}

static struct gsocket_io *_http3_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;

	/* Accept QUIC object from lower */
	if (!io->lower || !io->lower->accept) {
		return NULL;
	}

	struct gsocket_io *lower_io = io->lower->accept(io->lower, addr, addrlen);
	if (!lower_io) {
		return NULL;
	}

	if (ctx->is_listener) {
		/* Accepted a new Connection from Listener */
		struct gsocket_io *h3_conn_io = _http3_create_connection_io(lower_io, ctx->is_server);
		if (!h3_conn_io) {
			_http3_lower_free(lower_io);
			return NULL;
		}

		return h3_conn_io;
	} else {
		/* Accepted a new Stream from Connection */
		struct gsocket_io *h3_stream_io = _http3_create_stream_io(lower_io, ctx->h3_ctx, ctx->is_server);
		if (!h3_stream_io) {
			_http3_lower_free(lower_io);
			return NULL;
		}

		return h3_stream_io;
	}
}

static struct gsocket_io *_http3_open_stream(struct gsocket_io *io)
{
	struct gsocket_http3_ctx *ctx = (struct gsocket_http3_ctx *)io->ctx;

	/* Open QUIC stream from lower */
	if (!io->lower || !io->lower->open_stream) {
		return NULL;
	}

	struct gsocket_io *quic_stream_io = io->lower->open_stream(io->lower);
	if (!quic_stream_io) {
		return NULL;
	}

	/* Wrap in HTTP/3 Stream IO */
	struct gsocket_io *h3_stream_io = _http3_create_stream_io(quic_stream_io, ctx->h3_ctx, ctx->is_server);
	if (!h3_stream_io) {
		_http3_lower_free(quic_stream_io);
		return NULL;
	}

	return h3_stream_io;
}

static int _http3_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms)
{
	/* Use lower layer poll (gsocket_ssl) */
	if (io->lower && io->lower->stream_poll) {
		return io->lower->stream_poll(io->lower, items, count, timeout_ms);
	}

	return -1;
}

static int _http3_get_poll_events(struct gsocket_io *io)
{
	if (io->lower && io->lower->get_poll_events) {
		return io->lower->get_poll_events(io->lower);
	}
	return EPOLLIN;
}

static int _http3_listen(struct gsocket_io *io, int backlog)
{
	/* Delegate listen to lower layer (SSL/QUIC) */
	if (io->lower && io->lower->listen) {
		return io->lower->listen(io->lower, backlog);
	}
	return -1;
}

struct gsocket_io *gsocket_io_http3_new(int is_server)
{
	struct gsocket_io *io = NULL;
	struct gsocket_http3_ctx *ctx = NULL;

	io = calloc(1, sizeof(*io));
	ctx = calloc(1, sizeof(*ctx));

	if (!io || !ctx) {
		goto err;
	}

	io->ctx = ctx;

	ctx->is_server = is_server;
	ctx->is_connection = 1;
	ctx->is_listener = is_server; /* If server, assuming it's a listener initially */

	if (is_server) {
		ctx->h3_ctx = http3_ctx_server_new(io, &_h3_ops, NULL);
	} else {
		ctx->h3_ctx = http3_ctx_client_new(io, &_h3_ops, NULL);
	}
	if (!ctx->h3_ctx) {
		goto err;
	}

	io->handshake = _http3_handshake;
	io->connect = _http3_connect;
	io->accept = _http3_accept;
	io->open_stream = _http3_open_stream;
	io->stream_poll = _http3_stream_poll;
	io->free = _http3_ctx_free;
	io->get_fd = _http3_stream_get_fd;
	io->getsockname = _http3_conn_getsockname;
	io->getpeername = _http3_conn_getpeername;
	io->setsockopt = _http3_conn_setsockopt;
	io->getsockopt = _http3_conn_getsockopt;
	io->get_poll_events = _http3_get_poll_events;
	io->listen = _http3_listen;

	return io;

err:
	free(ctx);
	free(io);

	return NULL;
}

static int _http3_conn_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (io->lower && io->lower->getsockname) {
		return io->lower->getsockname(io->lower, addr, len);
	}
	return -1;
}

static int _http3_conn_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	if (io->lower && io->lower->getpeername) {
		return io->lower->getpeername(io->lower, addr, len);
	}
	return -1;
}

static int _http3_conn_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	if (io->lower && io->lower->setsockopt) {
		return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}

static int _http3_conn_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	if (io->lower && io->lower->getsockopt) {
		return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}

/* Ops Implementations */
static void *_h3_ops_create_stream(void *conn_data, int type)
{
	struct gsocket_io *io = (struct gsocket_io *)conn_data;
	if (!io || !io->lower || !io->lower->open_stream) {
		return NULL;
	}
	if (type != 0) {
		errno = EOPNOTSUPP;
		return NULL;
	}
	struct gsocket_io *stream_io = io->lower->open_stream(io->lower);

	return stream_io;
}

static void _h3_ops_close_stream(void *stream_handle)
{
	struct gsocket_io *io = (struct gsocket_io *)stream_handle;
	if (io && io->free) {
		io->free(io);
	}
}

static int _h3_ops_read(void *stream_handle, uint8_t *buf, int len)
{
	struct gsocket_io *io = (struct gsocket_io *)stream_handle;
	if (io && io->recv) {
		ssize_t ret = io->recv(io, buf, len, 0);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return 0; /* BIO retry */
		}
		return (int)ret;
	}
	return -1;
}

static int _h3_ops_write(void *stream_handle, const uint8_t *buf, int len, int eos)
{
	struct gsocket_io *io = (struct gsocket_io *)stream_handle;
	if (io && io->send) {
		int flags = MSG_NOSIGNAL;
		if (eos) {
			flags |= GS_MSG_FIN;
		}
		ssize_t ret = io->send(io, buf, len, flags);
		return (int)ret;
	}
	return -1;
}
