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
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct gsocket {
	int fd; /* Underlying FD, though layers might abstract this */
	struct gsocket_io *top_layer;
};

/* Forward Declarations */
static ssize_t _sock_recv(struct gsocket_io *io, void *buf, size_t len, int flags);
static ssize_t _sock_send(struct gsocket_io *io, const void *buf, size_t len, int flags);
static ssize_t _sock_recvfrom(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
							  socklen_t *addrlen);
static ssize_t _sock_sendto(struct gsocket_io *io, const void *buf, size_t len, int flags,
							const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t _sock_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags);
static ssize_t _sock_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags);
static int _sock_handshake(struct gsocket_io *io);
static int _sock_connect(struct gsocket_io *io, const char *host, int port);
static int _sock_bind(struct gsocket_io *io, const char *host, int port);
static int _sock_listen(struct gsocket_io *io, int backlog);
static struct gsocket_io *_sock_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen);
static int _sock_close(struct gsocket_io *io);
static void _sock_free(struct gsocket_io *io);
static int _sock_get_fd(struct gsocket_io *io);
static int _sock_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _sock_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
static int _sock_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);
static int _sock_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen);
static int _sock_shutdown(struct gsocket_io *io, int how);

/* Default Socket Layer (Bottom Layer) */
struct socket_io_ctx {
	int fd;
};

static ssize_t _sock_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct socket_io_ctx *ctx = io->ctx;
	return recv(ctx->fd, buf, len, flags);
}

static ssize_t _sock_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct socket_io_ctx *ctx = io->ctx;
	return send(ctx->fd, buf, len, flags & ~GS_MSG_FIN);
}

static ssize_t _sock_recvfrom(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
							  socklen_t *addrlen)
{
	struct socket_io_ctx *ctx = io->ctx;
	return recvfrom(ctx->fd, buf, len, flags, src_addr, addrlen);
}

static ssize_t _sock_sendto(struct gsocket_io *io, const void *buf, size_t len, int flags,
							const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct socket_io_ctx *ctx = io->ctx;
	return sendto(ctx->fd, buf, len, flags & ~GS_MSG_FIN, dest_addr, addrlen);
}

static ssize_t _sock_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct socket_io_ctx *ctx = io->ctx;
	return recvmsg(ctx->fd, msg, flags);
}

static ssize_t _sock_sendmsg(struct gsocket_io *io, const struct msghdr *msg, int flags)
{
	struct socket_io_ctx *ctx = io->ctx;
	return sendmsg(ctx->fd, msg, flags & ~GS_MSG_FIN);
}

static int _sock_get_fd(struct gsocket_io *io)
{
	if (!io || !io->ctx) {
		return -1;
	}

	struct socket_io_ctx *ctx = io->ctx;
	return ctx->fd;
}

static int _sock_handshake(struct gsocket_io *io)
{
	/* Plain sockets don't have a handshake */
	return GSOCKET_HANDSHAKE_DONE;
}

static int _sock_connect(struct gsocket_io *io, const char *host, int port)
{
	struct socket_io_ctx *ctx = io->ctx;
	int fd = ctx->fd;
	struct sockaddr_storage addr;
	memset(&addr, 0, sizeof(addr));
	struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

	// Check if host is IP
	if (inet_pton(AF_INET, host, &addr4->sin_addr) == 1) {
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(port);
		return connect(fd, (struct sockaddr *)addr4, sizeof(struct sockaddr_in));
	}

	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
	if (inet_pton(AF_INET6, host, &addr6->sin6_addr) == 1) {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(port);
		return connect(fd, (struct sockaddr *)addr6, sizeof(struct sockaddr_in6));
	}

	// Resolve host
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (host && host[0] == '\0') host = NULL;
	if (getaddrinfo(host, port_str, &hints, &res) != 0) {
		return -1;
	}

	int ret = -1;
	if (res) {
		ret = connect(fd, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);
	}
	return ret;
}

static int _sock_bind(struct gsocket_io *io, const char *host, int port)
{
	struct socket_io_ctx *ctx = io->ctx;
	int fd = ctx->fd;
	struct addrinfo hints, *res;
	char port_str[16];
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = 0;
	hints.ai_flags = AI_PASSIVE;

	snprintf(port_str, sizeof(port_str), "%d", port);

	if (host && host[0] == '\0') host = NULL;
	if (getaddrinfo(host, port_str, &hints, &res) != 0) {
		return -1;
	}

	ret = bind(fd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return ret;
}

static int _sock_listen(struct gsocket_io *io, int backlog)
{
	struct socket_io_ctx *ctx = io->ctx;
	return listen(ctx->fd, backlog);
}

static int _sock_close(struct gsocket_io *io)
{
	struct socket_io_ctx *ctx = io->ctx;
	/* Only close the FD. The io struct itself is freed by the wrapper or caller */
	if (ctx->fd >= 0) {
		close(ctx->fd);
		ctx->fd = GS_INVALID_FD;
	}
	return 0;
}

static void _sock_free(struct gsocket_io *io)
{
	struct socket_io_ctx *ctx = io->ctx;
	free(ctx);
	free(io);
}

static int _sock_getsockname(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	struct socket_io_ctx *ctx = io->ctx;
	return getsockname(ctx->fd, addr, len);
}

static int _sock_getpeername(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len)
{
	struct socket_io_ctx *ctx = io->ctx;
	return getpeername(ctx->fd, addr, len);
}

static int _sock_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct socket_io_ctx *ctx = io->ctx;
	return getsockopt(ctx->fd, level, optname, optval, optlen);
}

static int _sock_setsockopt(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen)
{
	struct socket_io_ctx *ctx = io->ctx;
	return setsockopt(ctx->fd, level, optname, optval, optlen);
}

static int _sock_shutdown(struct gsocket_io *io, int how)
{
	struct socket_io_ctx *ctx = io->ctx;
	return shutdown(ctx->fd, how);
}

/* Helper to create default layer */
static struct gsocket_io *gsocket_io_socket_new(int fd)
{
	struct gsocket_io *io = zalloc(1, sizeof(struct gsocket_io));
	if (!io) {
		return NULL;
	}
	struct socket_io_ctx *ctx = zalloc(1, sizeof(struct socket_io_ctx));
	if (!ctx) {
		goto err;
	}
	ctx->fd = fd;
	io->ctx = ctx;

	io->recv = _sock_recv;
	io->send = _sock_send;
	io->recvfrom = _sock_recvfrom;
	io->sendto = _sock_sendto;
	io->recvmsg = _sock_recvmsg;
	io->sendmsg = _sock_sendmsg;
	io->handshake = _sock_handshake;
	io->connect = _sock_connect;
	io->bind = _sock_bind;
	io->listen = _sock_listen;
	io->accept = _sock_accept;
	io->shutdown = _sock_shutdown;
	io->close = _sock_close;
	io->getsockname = _sock_getsockname;
	io->getpeername = _sock_getpeername;
	io->getsockopt = _sock_getsockopt;
	io->setsockopt = _sock_setsockopt;
	io->open_stream = NULL;
	io->get_fd = _sock_get_fd;
	io->free = _sock_free;

	return io;

err:
	if (ctx) {
		free(ctx);
	}
	if (io) {
		free(io);
	}
	return NULL;
}

/* Core Implementation */

struct gsocket *gsocket_new(int fd)
{
	struct gsocket *sock = zalloc(1, sizeof(struct gsocket));
	if (!sock) {
		return NULL;
	}
	sock->fd = fd;

	sock->top_layer = gsocket_io_socket_new(fd);
	if (!sock->top_layer) {
		goto err;
	}

	return sock;

err:
	if (sock) {
		free(sock);
	}
	return NULL;
}

void gsocket_free(struct gsocket *sock)
{
	if (!sock) {
		return;
	}
	/* Free all layers from top down */
	struct gsocket_io *curr = sock->top_layer;
	while (curr) {
		struct gsocket_io *next = curr->lower;
		if (curr->free) {
			curr->free(curr);
		}
		curr = next;
	}
	free(sock);
}

int gsocket_close(struct gsocket *sock)
{
	if (!sock || !sock->top_layer || !sock->top_layer->close) {
		return -1;
	}
	return sock->top_layer->close(sock->top_layer);
}

void gsocket_push_layer(struct gsocket *sock, struct gsocket_io *layer)
{
	if (!sock || !layer) {
		return;
	}
	layer->lower = sock->top_layer;
	sock->top_layer = layer;
}

struct gsocket_io *gsocket_get_top_layer(struct gsocket *sock)
{
	return sock ? sock->top_layer : NULL;
}

int gsocket_get_fd(struct gsocket *sock)
{
	if (!sock) {
		return -1;
	}
	
	if (sock->top_layer && sock->top_layer->get_fd) {
		return sock->top_layer->get_fd(sock->top_layer);
	}
	return sock->fd;
}

/* Wrappers definitions... */
/* Implementing the Delegate logic */

ssize_t gsocket_recv(struct gsocket *sock, void *buf, size_t len, int flags)
{
	if (!sock) {
		errno = EINVAL;
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->recv) {
		return -1;
	}
	return sock->top_layer->recv(sock->top_layer, buf, len, flags);
}

ssize_t gsocket_send(struct gsocket *sock, const void *buf, size_t len, int flags)
{
	if (!sock) {
		errno = EINVAL;
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->send) {
		return -1;
	}
	return sock->top_layer->send(sock->top_layer, buf, len, flags);
}

ssize_t gsocket_recvfrom(struct gsocket *sock, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						 socklen_t *addrlen)
{
	if (!sock) {
		errno = EINVAL;
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->recvfrom) {
		return -1;
	}
	return sock->top_layer->recvfrom(sock->top_layer, buf, len, flags, src_addr, addrlen);
}

ssize_t gsocket_sendto(struct gsocket *sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
					   socklen_t addrlen)
{
	if (!sock) {
		errno = EINVAL;
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->sendto) {
		return -1;
	}
	return sock->top_layer->sendto(sock->top_layer, buf, len, flags, dest_addr, addrlen);
}

ssize_t gsocket_recvmsg(struct gsocket *sock, struct msghdr *msg, int flags)
{
	if (!sock) {
		errno = EINVAL;
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->recvmsg) {
		return -1;
	}
	return sock->top_layer->recvmsg(sock->top_layer, msg, flags);
}

ssize_t gsocket_sendmsg(struct gsocket *sock, const struct msghdr *msg, int flags)
{
	if (!sock) {
		errno = EINVAL;
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->sendmsg) {
		return -1;
	}
	return sock->top_layer->sendmsg(sock->top_layer, msg, flags);
}

int gsocket_bind_device(struct gsocket *sock, const char *dev)
{
	if (!sock || !dev) {
		return -1;
	}
#ifdef SO_BINDTODEVICE
	struct ifreq ifr;
	if (strlen(dev) >= IFNAMSIZ) {
		errno = EINVAL;
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	return gsocket_setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
#else
	errno = ENOTSUP;
	return -1;
#endif
}

int gsocket_handshake(struct gsocket *sock)
{
	if (!sock) {
		return GSOCKET_HANDSHAKE_ERR;
	}
	
	if (!sock->top_layer || !sock->top_layer->handshake) {
		return GSOCKET_HANDSHAKE_DONE;
	}
	return sock->top_layer->handshake(sock->top_layer);
}

/* Standard Socket Wrappers */
int gsocket_connect(struct gsocket *sock, const char *host, int port)
{
	if (!sock) {
		return -1;
	}
	struct gsocket_io *io = gsocket_get_top_layer(sock);
	while (io) {
		if (io->connect) {
			return io->connect(io, host, port);
		}
		io = io->lower;
	}
	return -1;
}

int gsocket_bind(struct gsocket *sock, const char *host, int port)
{
	if (!sock) {
		return -1;
	}
	struct gsocket_io *io = gsocket_get_top_layer(sock);
	while (io) {
		if (io->bind) {
			return io->bind(io, host, port);
		}
		io = io->lower;
	}
	return -1;
}

int gsocket_listen(struct gsocket *sock, int backlog)
{
	if (!sock) {
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->listen) {
		return -1;
	}
	return sock->top_layer->listen(sock->top_layer, backlog);
}

static struct gsocket_io *_sock_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socket_io_ctx *ctx = io->ctx;
	int new_fd = accept(ctx->fd, addr, addrlen);
	if (new_fd < 0) {
		return NULL;
	}

	/* Create a new IO layer for the accepted FD */
	struct gsocket_io *new_io = zalloc(1, sizeof(struct gsocket_io));
	if (!new_io) {
		goto err;
	}
	struct socket_io_ctx *new_ctx = zalloc(1, sizeof(struct socket_io_ctx));
	if (!new_ctx) {
		goto err;
	}
	new_ctx->fd = new_fd;

	new_io->ctx = new_ctx;
	new_io->recv = _sock_recv;
	new_io->send = _sock_send;
	new_io->recvfrom = _sock_recvfrom;
	new_io->sendto = _sock_sendto;
	new_io->recvmsg = _sock_recvmsg;
	new_io->sendmsg = _sock_sendmsg;
	new_io->handshake = _sock_handshake;
	new_io->connect = _sock_connect;
	new_io->bind = _sock_bind;
	new_io->listen = NULL;
	new_io->accept = NULL;
	new_io->get_fd = _sock_get_fd;
	new_io->getsockname = _sock_getsockname;
	new_io->getpeername = _sock_getpeername;
	new_io->getsockopt = _sock_getsockopt;
	new_io->setsockopt = _sock_setsockopt;
	new_io->shutdown = _sock_shutdown;
	new_io->close = _sock_close;
	new_io->open_stream = NULL;
	new_io->free = _sock_free;

	return new_io;

err:
	if (new_fd >= 0) {
		close(new_fd);
	}
	
	if (new_ctx) {
		free(new_ctx);
	}
	
	if (new_io) {
		free(new_io);
	}
	return NULL;
}

struct gsocket *gsocket_accept(struct gsocket *sock, struct sockaddr *addr, socklen_t *addrlen)
{
	if (!sock) {
		return NULL;
	}
	
	if (!sock->top_layer || !sock->top_layer->accept) {
		return NULL;
	}

	struct gsocket_io *new_layer = sock->top_layer->accept(sock->top_layer, addr, addrlen);
	if (!new_layer) {
		return NULL;
	}

	/* Wrap the returned layer in a new gsocket container */
	struct gsocket *client_sock = zalloc(1, sizeof(struct gsocket));
	if (!client_sock) {
		/* Free all layers that were just created */
		struct gsocket_io *curr = new_layer;
		while (curr) {
			struct gsocket_io *next = curr->lower;
			if (curr->free) {
				curr->free(curr);
			}
			curr = next;
		}
		return NULL;
	}
	client_sock->fd = GS_INVALID_FD; /* FD is managed by the layer */
	client_sock->top_layer = new_layer;
	if (new_layer->get_fd) {
		client_sock->fd = new_layer->get_fd(new_layer);
	}
	return client_sock;
}

struct gsocket *gsocket_open_stream(struct gsocket *sock)
{
	if (!sock) {
		return NULL;
	}
	
	if (!sock->top_layer || !sock->top_layer->open_stream) {
		return NULL;
	}

	struct gsocket_io *new_layer = sock->top_layer->open_stream(sock->top_layer);
	if (!new_layer) {
		return NULL;
	}

	struct gsocket *stream_sock = zalloc(1, sizeof(struct gsocket));
	if (!stream_sock) {
		new_layer->free(new_layer);
		return NULL;
	}
	stream_sock->top_layer = new_layer;
	/* Streams don't have a direct FD usually */
	stream_sock->fd = GS_INVALID_FD;

	return stream_sock;
}

int gsocket_shutdown(struct gsocket *sock, int how)
{
	if (!sock) {
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->shutdown) {
		return -1;
	}
	return sock->top_layer->shutdown(sock->top_layer, how);
}

/* Option Wrappers */
int gsocket_getsockname(struct gsocket *sock, struct sockaddr *addr, socklen_t *len)
{
	if (!sock) {
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->getsockname) {
		return -1;
	}
	return sock->top_layer->getsockname(sock->top_layer, addr, len);
}
int gsocket_getpeername(struct gsocket *sock, struct sockaddr *addr, socklen_t *len)
{
	if (!sock) {
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->getpeername) {
		return -1;
	}
	return sock->top_layer->getpeername(sock->top_layer, addr, len);
}
int gsocket_getsockopt(struct gsocket *sock, int level, int optname, void *optval, socklen_t *optlen)
{
	if (!sock) {
		return -1;
	}

	/* Handle protocol error reporting */
	if (level == SOL_PROTO_ERROR) {
		if (optname == SO_ERROR_DETAIL) {
			/* Query top layer for error information */
			struct gsocket_io *top = sock->top_layer;
			if (top && top->get_error) {
				return top->get_error(top, optval);
			}
			/* No error information available */
			return -1;
		}
		return -1;
	}

	if (!sock->top_layer || !sock->top_layer->getsockopt) {
		return -1;
	}
	return sock->top_layer->getsockopt(sock->top_layer, level, optname, optval, optlen);
}
int gsocket_setsockopt(struct gsocket *sock, int level, int optname, const void *optval, socklen_t optlen)
{
	if (!sock) {
		return -1;
	}
	
	if (!sock->top_layer || !sock->top_layer->setsockopt) {
		return -1;
	}
	return sock->top_layer->setsockopt(sock->top_layer, level, optname, optval, optlen);
}

int gsocket_set_nonblock(struct gsocket *sock, int enable)
{
	int fd = gsocket_get_fd(sock);
	if (fd < 0) {
		return -1;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return -1;
	}

	if (enable) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}

	return fcntl(fd, F_SETFL, flags);
}

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif

int gsocket_set_fastopen(struct gsocket *sock, int enable)
{
	int fd = gsocket_get_fd(sock);
	if (fd < 0) {
		return -1;
	}

	int val = 1;
	if (!enable) {
		val = 0;
	}

	/* TCP_FASTOPEN_CONNECT for client (Linux 4.11+) */
	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &val, sizeof(val)) == 0) {
		return 0;
	}

	/* TCP_FASTOPEN for server (accepting fastopen connections) */
	/* val is the queue length for TFO. Use 5 as a default */
	val = enable ? 5 : 0;
	return setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val));
}

int gsocket_get_proxy_target(struct gsocket *gs, struct gsocket_address *target)
{
	if (!gs) {
		return -1;
	}
	struct gsocket_io *io = gsocket_get_top_layer(gs);
	while (io) {
		if (io->get_proxy_target) {
			return io->get_proxy_target(io, target);
		}
		io = io->lower;
	}

	errno = ENOTSUP;
	return -1;
}

/* Get required network poll events for this socket (for QUIC, etc) */
int gsocket_get_poll_events(struct gsocket *sock)
{
	if (!sock || !sock->top_layer) {
		return EPOLLIN; /* Default: always monitor for read */
	}

	/* If top layer has a get_poll_events function, use it */
	if (sock->top_layer->get_poll_events) {
		return sock->top_layer->get_poll_events(sock->top_layer);
	}

	return EPOLLIN; /* Default */
}

int gsocket_set_reuseaddr(struct gsocket *sock, int enable)
{
	return gsocket_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
}

int gsocket_set_mark(struct gsocket *sock, int mark)
{
	return gsocket_setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
}

int gsocket_set_defer_accept(struct gsocket *sock, int enable)
{
#ifdef TCP_DEFER_ACCEPT
	return gsocket_setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &enable, sizeof(enable));
#else
	return 0;
#endif
}

int gsocket_set_quickack(struct gsocket *sock, int enable)
{
#ifdef TCP_QUICKACK
	return gsocket_setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &enable, sizeof(enable));
#else
	return 0;
#endif
}

int gsocket_set_keepalive(struct gsocket *sock, int idle, int intvl, int cnt)
{
	int fd = gsocket_get_fd(sock);
	if (fd < 0) {
		return -1;
	}
	return set_sock_keepalive(fd, idle, intvl, cnt);
}

int gsocket_set_reuseport(struct gsocket *sock, int enable)
{
	int fd = gsocket_get_fd(sock);
	if (fd < 0) {
		return -1;
	}

#ifdef SO_REUSEPORT
	int val = enable ? 1 : 0;
	return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#else
	return -1;
#endif
}
