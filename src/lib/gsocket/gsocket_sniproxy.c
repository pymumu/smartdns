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

#include "smartdns/dns_conf.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/util.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct sniproxy_ctx {
	struct gsocket_address target;
	int target_valid;
	char buffer[4096];
	int buf_len;
	int sni_parsed;
};

static ssize_t _sniproxy_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	return io->lower->send(io->lower, buf, len, flags);
}

static int _sniproxy_handshake(struct gsocket_io *io)
{
	if (io->lower && io->lower->handshake) {
		int ret = io->lower->handshake(io->lower);
		if (ret != GSOCKET_HANDSHAKE_DONE) {
			return ret;
		}
	}

	struct sniproxy_ctx *ctx = (struct sniproxy_ctx *)io->ctx;
	if (ctx->sni_parsed) {
		return GSOCKET_HANDSHAKE_DONE;
	}

	/* Read Client Hello */
	ssize_t ret = io->lower->recv(io->lower, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - ctx->buf_len, 0);
	if (ret > 0) {
		ctx->buf_len += ret;
	} else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return GSOCKET_HANDSHAKE_WANT_READ;
	} else if (ret == 0) {
		return GSOCKET_HANDSHAKE_EOF;
	} else {
		return GSOCKET_HANDSHAKE_ERR;
	}

	/* Try to parse SNI */
	char sni[256];
	const char *sni_ptr;
	int len = parse_tls_header(ctx->buffer, ctx->buf_len, sni, &sni_ptr);
	if (len < 0) {
		if (len == -1) {
			/* Need more data */
			if (ctx->buf_len >= (int)sizeof(ctx->buffer)) {
				return GSOCKET_HANDSHAKE_ERR; /* Buffer full but still no complete header */
			}
			return GSOCKET_HANDSHAKE_WANT_READ;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}

	/* SNI Found */
	safe_strncpy(ctx->target.host, sni, sizeof(ctx->target.host));
	ctx->target.port = ctx->target.port ? ctx->target.port : 443;
	ctx->target_valid = 1;
	ctx->sni_parsed = 1;

	return GSOCKET_HANDSHAKE_DONE;
}

static ssize_t _sniproxy_recv_wrapper(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct sniproxy_ctx *ctx = (struct sniproxy_ctx *)io->ctx;

	if (ctx->buf_len > 0) {
		int to_copy = (len < (size_t)ctx->buf_len) ? (int)len : ctx->buf_len;
		memcpy(buf, ctx->buffer, to_copy);

		if (to_copy < ctx->buf_len) {
			memmove(ctx->buffer, ctx->buffer + to_copy, ctx->buf_len - to_copy);
		}
		ctx->buf_len -= to_copy;
		return to_copy;
	}

	return io->lower->recv(io->lower, buf, len, flags);
}

static int _sniproxy_get_poll_events(struct gsocket_io *io)
{
	struct sniproxy_ctx *ctx = (struct sniproxy_ctx *)io->ctx;
	int events = 0;
	if (io->lower && io->lower->get_poll_events) {
		events = io->lower->get_poll_events(io->lower);
	}

	if (ctx->buf_len > 0) {
		events |= EPOLLIN;
	}
	return events;
}

static int _sniproxy_get_proxy_target(struct gsocket_io *io, struct gsocket_address *target)
{
	struct sniproxy_ctx *ctx = (struct sniproxy_ctx *)io->ctx;
	if (ctx->target_valid) {
		*target = ctx->target;
		return 0;
	}
	return -1;
}

static int _sniproxy_close(struct gsocket_io *io)
{
	if (io->lower) {
		return io->lower->close(io->lower);
	}
	return 0;
}

static void _sniproxy_free(struct gsocket_io *io)
{
	if (io->ctx) {
		free(io->ctx);
	}
	/* Do not free lower layer, gsocket handles it */
	free(io);
}

/* Passthrough boilerplate */
static int _sniproxy_bind(struct gsocket_io *io, const char *host, int port)
{
	return io->lower->bind(io->lower, host, port);
}
static int _sniproxy_listen(struct gsocket_io *io, int backlog)
{
	return io->lower->listen(io->lower, backlog);
}
static int _sniproxy_connect(struct gsocket_io *io, const char *host, int port)
{
	return io->lower->connect(io->lower, host, port);
}
static int _sniproxy_get_fd(struct gsocket_io *io)
{
	return io->lower->get_fd(io->lower);
}
static int _sniproxy_shutdown(struct gsocket_io *io, int how)
{
	return io->lower->shutdown(io->lower, how);
}
static int _sniproxy_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	return io->lower->getsockname(io->lower, addr, len);
}
static int _sniproxy_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	return io->lower->getpeername(io->lower, addr, len);
}
static int _sniproxy_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
}
static int _sniproxy_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
}
static ssize_t _sniproxy_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	return io->lower->recvmsg(io->lower, msg, flags);
}
static ssize_t _sniproxy_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	return io->lower->sendmsg(io->lower, msg, flags);
}

static struct gsocket_io *_sniproxy_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	struct gsocket_io *client_io = io->lower->accept(io->lower, addr, addrlen);
	if (!client_io) {
		return NULL;
	}

	struct gsocket_io *sni_io = calloc(1, sizeof(struct gsocket_io));
	if (!sni_io) {
		goto err;
	}

	struct sniproxy_ctx *ctx = calloc(1, sizeof(struct sniproxy_ctx));
	if (!ctx) {
		goto err;
	}

	sni_io->ctx = ctx;
	sni_io->lower = client_io;

	struct sniproxy_ctx *srv_ctx = (struct sniproxy_ctx *)io->ctx;
	ctx->target.port = srv_ctx->target.port;

	sni_io->handshake = _sniproxy_handshake;
	sni_io->recv = _sniproxy_recv_wrapper; /* Specific wrapper to handle buffered data */
	sni_io->send = _sniproxy_send;
	sni_io->get_proxy_target = _sniproxy_get_proxy_target;

	sni_io->close = _sniproxy_close;
	sni_io->free = _sniproxy_free;
	sni_io->get_fd = _sniproxy_get_fd;
	sni_io->shutdown = _sniproxy_shutdown;
	sni_io->getsockname = _sniproxy_getsockname;
	sni_io->getpeername = _sniproxy_getpeername;
	sni_io->getsockopt = _sniproxy_getsockopt;
	sni_io->setsockopt = _sniproxy_setsockopt;
	sni_io->recvmsg = _sniproxy_recvmsg;
	sni_io->sendmsg = _sniproxy_sendmsg;

	return sni_io;

err:
	if (client_io) {
		client_io->close(client_io);
		client_io->free(client_io);
	}
	if (sni_io) {
		free(sni_io);
	}
	return NULL;
}

struct gsocket_io *gsocket_io_sniproxy_server_new(uint16_t target_port)
{
	struct gsocket_io *io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		return NULL;
	}

	struct sniproxy_ctx *ctx = calloc(1, sizeof(struct sniproxy_ctx));
	if (!ctx) {
		goto err;
	}
	io->ctx = ctx;
	ctx->target.port = target_port;

	io->accept = _sniproxy_accept;

	io->bind = _sniproxy_bind;
	io->listen = _sniproxy_listen;
	io->connect = _sniproxy_connect;
	io->get_fd = _sniproxy_get_fd;
	io->close = _sniproxy_close;
	io->free = _sniproxy_free;
	io->shutdown = _sniproxy_shutdown;
	io->getsockname = _sniproxy_getsockname;
	io->getpeername = _sniproxy_getpeername;
	io->getsockopt = _sniproxy_getsockopt;
	io->setsockopt = _sniproxy_setsockopt;
	io->recv = _sniproxy_recv_wrapper; /* Fix: use wrapper to handle buffered data */
	io->send = _sniproxy_send;
	io->recvmsg = _sniproxy_recvmsg;
	io->sendmsg = _sniproxy_sendmsg;
	io->get_poll_events = _sniproxy_get_poll_events;

	return io;

err:
	if (io) {
		free(io);
	}
	return NULL;
}
