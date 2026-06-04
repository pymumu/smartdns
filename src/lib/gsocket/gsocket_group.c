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
#include "smartdns/lib/gsocket.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct group_member {
	struct gsocket *sock;
	int weight;
	struct group_member *next;
};

struct group_io_ctx {
	enum gsocket_group_policy policy;
	struct group_member *members;
	struct group_member *active_member;
	struct group_member *rr_next_member;
	struct gsocket_io *io_ptr;
};

static int _group_connect_err_is_async(int err)
{
	return err == EINPROGRESS || err == EALREADY || err == EWOULDBLOCK || err == EAGAIN;
}

static struct group_member *_group_member_next(struct group_io_ctx *ctx, struct group_member *member)
{
	if (!member || !member->next) {
		return ctx->members;
	}

	return member->next;
}

static int _group_connect_member(struct group_io_ctx *ctx, struct group_member *member, const char *host, int port)
{
	errno = 0;
	int ret = gsocket_connect(member->sock, host, port);
	int err = errno;

	if (ret == 0 || err == EISCONN) {
		ctx->active_member = member;
		return 0;
	}

	if (_group_connect_err_is_async(err)) {
		ctx->active_member = member;
		errno = err;
		return -1;
	}

	if (err == 0) {
		err = ECONNREFUSED;
	}
	errno = err;
	return -1;
}

static int _group_connect_failover(struct group_io_ctx *ctx, const char *host, int port)
{
	struct group_member *curr = ctx->members;
	int last_errno = ENOTCONN;

	while (curr) {
		int ret = _group_connect_member(ctx, curr, host, port);
		if (ctx->active_member == curr) {
			return ret;
		}
		last_errno = errno;
		curr = curr->next;
	}

	errno = last_errno;
	return -1;
}

static int _group_connect_rr(struct group_io_ctx *ctx, const char *host, int port)
{
	int count = 0;
	struct group_member *curr = ctx->members;
	while (curr) {
		count++;
		curr = curr->next;
	}
	if (count == 0) {
		errno = ENOTCONN;
		return -1;
	}

	struct group_member *member = ctx->rr_next_member ? ctx->rr_next_member : ctx->members;
	int last_errno = ENOTCONN;

	for (int i = 0; i < count; i++) {
		int ret = _group_connect_member(ctx, member, host, port);
		ctx->rr_next_member = _group_member_next(ctx, member);
		if (ctx->active_member == member) {
			return ret;
		}
		last_errno = errno;
		member = _group_member_next(ctx, member);
	}

	errno = last_errno;
	return -1;
}

static int _group_connect(struct gsocket_io *io, const char *host, int port)
{
	struct group_io_ctx *ctx = io->ctx;

	ctx->active_member = NULL;
	if (ctx->policy == GSOCKET_GROUP_RR) {
		return _group_connect_rr(ctx, host, port);
	}

	/* Default to Failover */
	return _group_connect_failover(ctx, host, port);
}

static struct gsocket *_group_active_sock(struct group_io_ctx *ctx)
{
	if (!ctx->active_member) {
		errno = ENOTCONN;
		return NULL;
	}

	return ctx->active_member->sock;
}

static int _group_handshake(struct gsocket_io *io)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return GSOCKET_HANDSHAKE_ERR;
	}

	return gsocket_handshake(sock);
}

static ssize_t _group_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_send(sock, buf, len, flags);
}

static ssize_t _group_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_recv(sock, buf, len, flags);
}

static ssize_t _group_recvfrom(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
							   socklen_t *addrlen)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_recvfrom(sock, buf, len, flags, src_addr, addrlen);
}

static ssize_t _group_sendto(struct gsocket_io *io, const void *buf, size_t len, int flags,
							 const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_sendto(sock, buf, len, flags, dest_addr, addrlen);
}

static ssize_t _group_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_recvmsg(sock, msg, flags);
}

static ssize_t _group_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_sendmsg(sock, msg, flags);
}

static int _group_shutdown(struct gsocket_io *io, int how)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_shutdown(sock, how);
}

static int _group_close(struct gsocket_io *io)
{
	struct group_io_ctx *ctx = io->ctx;
	/* Close ALL members? Or just the active one?
	   Usually the group owns the members, so close all. */
	struct group_member *curr = ctx->members;
	while (curr) {
		gsocket_close(curr->sock);
		curr = curr->next;
	}
	return 0;
}

static int _group_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_getsockname(sock, addr, len);
}

static int _group_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_getpeername(sock, addr, len);
}

static int _group_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_getsockopt(sock, level, optname, optval, optlen);
}

static int _group_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	struct group_io_ctx *ctx = io->ctx;
	if (ctx->active_member) {
		return gsocket_setsockopt(ctx->active_member->sock, level, optname, optval, optlen);
	}

	struct group_member *curr = ctx->members;
	int ret = 0;
	int last_errno = ENOTCONN;
	while (curr) {
		if (gsocket_setsockopt(curr->sock, level, optname, optval, optlen) != 0) {
			ret = -1;
			last_errno = errno;
		}
		curr = curr->next;
	}

	if (ret != 0) {
		errno = last_errno;
	}
	return ret;
}

static struct gsocket_io *_group_open_stream(struct gsocket_io *io)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return NULL;
	}

	struct gsocket_io *top = gsocket_get_top_layer(sock);
	if (!top || !top->open_stream) {
		errno = ENOTSUP;
		return NULL;
	}

	return top->open_stream(top);
}

static int _group_stream_poll(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	struct gsocket_io *top = gsocket_get_top_layer(sock);
	if (!top || !top->stream_poll) {
		errno = ENOTSUP;
		return -1;
	}

	return top->stream_poll(top, items, count, timeout_ms);
}

static int _group_get_proxy_target(struct gsocket_io *io, struct gsocket_address *addr)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_get_proxy_target(sock, addr);
}

static int _group_get_poll_events(struct gsocket_io *io)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return 0;
	}

	return gsocket_get_poll_events(sock);
}

static int _group_get_error(struct gsocket_io *io, void *err_struct)
{
	struct group_io_ctx *ctx = io->ctx;
	struct gsocket *sock = _group_active_sock(ctx);
	if (!sock) {
		return -1;
	}

	return gsocket_getsockopt(sock, SOL_PROTO_ERROR, SO_ERROR_DETAIL, err_struct, NULL);
}

static void _group_free(struct gsocket_io *io)
{
	struct group_io_ctx *ctx = io->ctx;
	struct group_member *curr = ctx->members;
	while (curr) {
		struct group_member *next = curr->next;
		gsocket_free(curr->sock); /* Group owns members */
		free(curr);
		curr = next;
	}
	free(ctx);
	free(io);
}

/* Helper to map other methods if needed... */

static int _group_get_fd(struct gsocket_io *io)
{
	struct group_io_ctx *ctx = io->ctx;
	if (ctx->active_member) {
		return gsocket_get_fd(ctx->active_member->sock);
	}
	return GS_INVALID_FD;
}

struct gsocket *gsocket_group_new(enum gsocket_group_policy policy)
{
	/* Use base socket constructor.
	   This creates a gsocket wrapped around -1 with a default base layer.
	   We will push the Group Layer on top.
	*/
	struct gsocket *group_sock = NULL;
	struct gsocket_io *io = NULL;
	struct group_io_ctx *ctx = NULL;

	group_sock = gsocket_new(GS_INVALID_FD);
	if (!group_sock) {
		goto err;
	}

	io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		goto err;
	}
	ctx = calloc(1, sizeof(struct group_io_ctx));
	if (!ctx) {
		goto err;
	}

	ctx->policy = policy;
	ctx->io_ptr = io;
	io->ctx = ctx;

	io->connect = _group_connect;
	io->handshake = _group_handshake;
	io->send = _group_send;
	io->recv = _group_recv;
	io->recvfrom = _group_recvfrom;
	io->sendto = _group_sendto;
	io->recvmsg = _group_recvmsg;
	io->sendmsg = _group_sendmsg;
	io->shutdown = _group_shutdown;
	io->close = _group_close;
	io->getsockname = _group_getsockname;
	io->getpeername = _group_getpeername;
	io->getsockopt = _group_getsockopt;
	io->setsockopt = _group_setsockopt;
	io->open_stream = _group_open_stream;
	io->stream_poll = _group_stream_poll;
	io->get_proxy_target = _group_get_proxy_target;
	io->get_poll_events = _group_get_poll_events;
	io->get_error = _group_get_error;
	io->free = _group_free;
	io->get_fd = _group_get_fd;

	/* gsocket_new has already set a bottom layer. We push ours. */
	if (gsocket_push_layer(group_sock, io) != 0) {
		io = NULL;
		ctx = NULL;
		goto err;
	}

	return group_sock;

err:
	if (group_sock) {
		gsocket_free(group_sock);
	}
	if (io) {
		free(io);
	}
	if (ctx) {
		free(ctx);
	}
	return NULL;
}

int gsocket_group_add(struct gsocket *group, struct gsocket *member, int weight)
{
	if (!group || !member) {
		return -1;
	}
	struct gsocket_io *top = gsocket_get_top_layer(group);
	if (!top || !top->ctx) {
		return -1;
	}

	/* TODO: We trust that 'top' is indeed a group layer.
	   Ideally check against a magic number or function pointer */
	struct group_io_ctx *ctx = top->ctx;

	struct group_member *new_mem = calloc(1, sizeof(struct group_member));
	if (!new_mem) {
		return -1;
	}
	new_mem->sock = member;
	new_mem->weight = weight;

	/* Append to list */
	if (!ctx->members) {
		ctx->members = new_mem;
		ctx->rr_next_member = new_mem;
	} else {
		struct group_member *curr = ctx->members;
		while (curr->next) {
			curr = curr->next;
		}
		curr->next = new_mem;
	}
	return 0;
}
