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
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

struct tproxy_ctx {
	struct gsocket_address client_addr;
	struct gsocket_address original_dst;
	int original_dst_valid;
};

static void _tproxy_free(struct gsocket_io *io)
{
	if (io->ctx) {
		free(io->ctx);
		io->ctx = NULL;
	}
	/* Do not free lower layer, gsocket handles it */
	free(io);
}

static ssize_t _tproxy_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	return io->lower->recv(io->lower, buf, len, flags);
}

static ssize_t _tproxy_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	return io->lower->send(io->lower, buf, len, flags);
}

static int _tproxy_handshake(struct gsocket_io *io)
{
	if (io->lower && io->lower->handshake) {
		return io->lower->handshake(io->lower);
	}
	return GSOCKET_HANDSHAKE_DONE;
}

static ssize_t _tproxy_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct tproxy_ctx *ctx = (struct tproxy_ctx *)io->ctx;
	struct cmsghdr *cmsg;

	/* Save original control buffer to avoid dangling pointer */
	void *saved_control = msg->msg_control;
	socklen_t saved_controllen = msg->msg_controllen;
	char control_tmp[256];

	if (!ctx->original_dst_valid) {
		if (msg->msg_control == NULL || msg->msg_controllen < sizeof(control_tmp)) {
			msg->msg_control = control_tmp;
			msg->msg_controllen = sizeof(control_tmp);
		}
	}

	ssize_t ret = io->lower->recvmsg(io->lower, msg, flags);
	if (ret < 0) {
		msg->msg_control = saved_control;
		msg->msg_controllen = saved_controllen;
		return ret;
	}

	/* Extract original destination from CMSG if available */
	if (!ctx->original_dst_valid && msg->msg_controllen > 0) {
		for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
				struct sockaddr_in *sin = (struct sockaddr_in *)CMSG_DATA(cmsg);
				inet_ntop(AF_INET, &sin->sin_addr, ctx->original_dst.host, sizeof(ctx->original_dst.host));
				ctx->original_dst.port = ntohs(sin->sin_port);
				ctx->original_dst_valid = 1;
				break;
			} else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)CMSG_DATA(cmsg);
				inet_ntop(AF_INET6, &sin6->sin6_addr, ctx->original_dst.host, sizeof(ctx->original_dst.host));
				ctx->original_dst.port = ntohs(sin6->sin6_port);
				ctx->original_dst_valid = 1;
				break;
			}
		}
	}

	/* Restore original pointers, though any control data received is now inaccessible to the caller
	   if we overrode it. This is a compromise to ensure safety. */
	msg->msg_control = saved_control;
	msg->msg_controllen = saved_controllen;

	return ret;
}

static ssize_t _tproxy_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	return io->lower->sendmsg(io->lower, msg, flags);
}

static int _tproxy_bind(struct gsocket_io *io, const char *host, int port)
{
	int fd = io->lower->get_fd(io->lower);
	if (fd >= 0) {
		int opt = 1;
		setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt));
		setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &opt, sizeof(opt));
		setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
	}
	return io->lower->bind(io->lower, host, port);
}

static int _tproxy_listen(struct gsocket_io *io, int backlog)
{
	return io->lower->listen(io->lower, backlog);
}

static int _tproxy_connect(struct gsocket_io *io, const char *host, int port)
{
	return io->lower->connect(io->lower, host, port);
}

static int _tproxy_shutdown(struct gsocket_io *io, int how)
{
	return io->lower->shutdown(io->lower, how);
}

static int _tproxy_get_fd(struct gsocket_io *io)
{
	return io->lower->get_fd(io->lower);
}

static int _tproxy_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	return io->lower->getsockname(io->lower, addr, len);
}

static int _tproxy_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	return io->lower->getpeername(io->lower, addr, len);
}

static int _tproxy_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
}

static int _tproxy_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	return io->lower->setsockopt(io->lower, level, optname, optval, optlen);
}

static int _tproxy_get_proxy_target(struct gsocket_io *io, struct gsocket_address *target)
{
	struct tproxy_ctx *ctx = (struct tproxy_ctx *)io->ctx;
	if (ctx->original_dst_valid) {
		*target = ctx->original_dst;
		return 0;
	}
	errno = ENODATA;
	return -1;
}

static int _tproxy_close(struct gsocket_io *io)
{
	int ret = 0;
	if (io->lower) {
		ret = io->lower->close(io->lower);
	}
	return ret;
}

static struct gsocket_io *_tproxy_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	struct gsocket_io *client_io = io->lower->accept(io->lower, addr, addrlen);
	if (!client_io) {
		return NULL;
	}

	struct gsocket_io *tproxy_io = calloc(1, sizeof(struct gsocket_io));
	if (!tproxy_io) {
		goto err;
	}

	struct tproxy_ctx *ctx = calloc(1, sizeof(struct tproxy_ctx));
	if (!ctx) {
		goto err;
	}

	tproxy_io->ctx = ctx;
	tproxy_io->lower = client_io;

	tproxy_io->recv = _tproxy_recv;
	tproxy_io->send = _tproxy_send;
	tproxy_io->handshake = _tproxy_handshake;
	tproxy_io->recvmsg = _tproxy_recvmsg;
	tproxy_io->sendmsg = _tproxy_sendmsg;
	tproxy_io->get_fd = _tproxy_get_fd;
	tproxy_io->close = _tproxy_close;
	tproxy_io->free = _tproxy_free;

	tproxy_io->shutdown = _tproxy_shutdown;
	tproxy_io->getsockname = _tproxy_getsockname;
	tproxy_io->getpeername = _tproxy_getpeername;
	tproxy_io->getsockopt = _tproxy_getsockopt;
	tproxy_io->setsockopt = _tproxy_setsockopt;

	tproxy_io->get_proxy_target = _tproxy_get_proxy_target;

	/* TCP: Try to get SO_ORIGINAL_DST immediately */
	struct sockaddr_storage dst_addr = {0};
	socklen_t dst_len = sizeof(dst_addr);
	int client_fd = client_io->get_fd(client_io);

	if (client_fd >= 0) {
		if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &dst_addr, &dst_len) == 0) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&dst_addr;
			inet_ntop(AF_INET, &sin->sin_addr, ctx->original_dst.host, sizeof(ctx->original_dst.host));
			ctx->original_dst.port = ntohs(sin->sin_port);
			ctx->original_dst_valid = 1;
		} else if (getsockopt(client_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &dst_addr, &dst_len) == 0) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&dst_addr;
			inet_ntop(AF_INET6, &sin6->sin6_addr, ctx->original_dst.host, sizeof(ctx->original_dst.host));
			ctx->original_dst.port = ntohs(sin6->sin6_port);
			ctx->original_dst_valid = 1;
		}
	}

	return tproxy_io;

err:
	if (client_io) {
		client_io->close(client_io);
		client_io->free(client_io);
	}
	if (ctx) {
		free(ctx);
	}
	if (tproxy_io) {
		free(tproxy_io);
	}
	return NULL;
}

struct gsocket_io *gsocket_io_tproxy_server_new(void)
{
	struct gsocket_io *io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		return NULL;
	}

	struct tproxy_ctx *ctx = calloc(1, sizeof(struct tproxy_ctx));
	if (!ctx) {
		goto err;
	}
	io->ctx = ctx;

	io->accept = _tproxy_accept;
	/* For UDP listener */
	io->recvmsg = _tproxy_recvmsg;

	/* Passthrough methods */
	io->bind = _tproxy_bind;
	io->listen = _tproxy_listen;
	io->connect = _tproxy_connect;
	io->get_fd = _tproxy_get_fd;
	io->close = _tproxy_close;
	io->free = _tproxy_free;
	io->shutdown = _tproxy_shutdown;
	io->getsockname = _tproxy_getsockname;
	io->getpeername = _tproxy_getpeername;
	io->getsockopt = _tproxy_getsockopt;
	io->setsockopt = _tproxy_setsockopt;

	io->get_proxy_target = _tproxy_get_proxy_target;

	io->recv = _tproxy_recv;
	io->send = _tproxy_send;
	io->handshake = _tproxy_handshake;
	io->sendmsg = _tproxy_sendmsg;

	return io;

err:
	if (io) {
		free(io);
	}
	return NULL;
}
