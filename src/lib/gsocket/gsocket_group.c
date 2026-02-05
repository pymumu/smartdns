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
#include <time.h>

struct group_member {
	struct gsocket *sock;
	int weight;
	struct group_member *next;
};

struct group_io_ctx {
	enum gsocket_group_policy policy;
	struct group_member *members;
	struct group_member *active_member;
	struct gsocket_io *io_ptr;
};

#include <stdio.h>

static int _group_connect_failover(struct group_io_ctx *ctx, const char *host, int port)
{
	struct group_member *curr = ctx->members;
	while (curr) {
		if (gsocket_connect(curr->sock, host, port) == 0) {
			ctx->active_member = curr;
			return 0;
		}
		curr = curr->next;
	}
	return -1;
}

static int _group_connect_rr(struct group_io_ctx *ctx, const char *host, int port)
{
	/* Stateless RR (Random) */
	int count = 0;
	struct group_member *curr = ctx->members;
	while (curr) {
		count++;
		curr = curr->next;
	}
	if (count == 0) {
		return -1;
	}

	static int rand_inited = 0;
	if (!rand_inited) {
		srand(time(NULL));
		rand_inited = 1;
	}

	int start_idx = rand() % count; // TODO: Use better rand?

	for (int i = 0; i < count; i++) {
		int target_idx = (start_idx + i) % count;

		/* Find member at index */
		curr = ctx->members;
		for (int k = 0; k < target_idx; k++) {
			curr = curr->next;
		}

		if (gsocket_connect(curr->sock, host, port) == 0) {
			ctx->active_member = curr;
			return 0;
		}
	}
	return -1;
}

static int _group_connect(struct gsocket_io *io, const char *host, int port)
{
	struct group_io_ctx *ctx = io->ctx;

	if (ctx->policy == GSOCKET_GROUP_RR) {
		return _group_connect_rr(ctx, host, port);
	}

	/* Default to Failover */
	return _group_connect_failover(ctx, host, port);
}

static ssize_t _group_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	if (!ctx->active_member) {
		return -1;
	}
	return gsocket_send(ctx->active_member->sock, buf, len, flags);
}

static ssize_t _group_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	if (!ctx->active_member) {
		return -1;
	}
	return gsocket_recv(ctx->active_member->sock, buf, len, flags);
}

static ssize_t _group_recvfrom(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
							   socklen_t *addrlen)
{
	struct group_io_ctx *ctx = io->ctx;
	if (!ctx->active_member) {
		return -1;
	}
	return gsocket_recvfrom(ctx->active_member->sock, buf, len, flags, src_addr, addrlen);
}

static ssize_t _group_sendto(struct gsocket_io *io, const void *buf, size_t len, int flags,
							 const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct group_io_ctx *ctx = io->ctx;
	if (!ctx->active_member) {
		return -1;
	}
	return gsocket_sendto(ctx->active_member->sock, buf, len, flags, dest_addr, addrlen);
}

static ssize_t _group_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	if (!ctx->active_member) {
		return -1;
	}
	return gsocket_recvmsg(ctx->active_member->sock, msg, flags);
}

static ssize_t _group_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	struct group_io_ctx *ctx = io->ctx;
	if (!ctx->active_member) {
		return -1;
	}
	return gsocket_sendmsg(ctx->active_member->sock, msg, flags);
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
	io->send = _group_send;
	io->recv = _group_recv;
	io->recvfrom = _group_recvfrom;
	io->sendto = _group_sendto;
	io->recvmsg = _group_recvmsg;
	io->sendmsg = _group_sendmsg;
	io->close = _group_close;
	io->free = _group_free;
	io->get_fd = _group_get_fd;

	/* gsocket_new has already set a bottom layer. We push ours. */
	gsocket_push_layer(group_sock, io);

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
	} else {
		struct group_member *curr = ctx->members;
		while (curr->next) {
			curr = curr->next;
		}
		curr->next = new_mem;
	}
	return 0;
}
