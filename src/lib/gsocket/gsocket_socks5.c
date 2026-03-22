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
#include "smartdns/tlog.h"
#include "smartdns/util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

/* SOCKS5 Protocol Constants */
#define SOCKS5_VERSION 0x05
#define SOCKS5_AUTH_NONE 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_INVALID 0xFF

#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

#define SOCKS5_REPLY_SUCCESS 0x00

#define SOCKS5_USERPASS_VER 0x01
#define SOCKS5_USERPASS_SUCCESS 0x00
#define SOCKS5_USERPASS_FAILURE 0x01

struct socks5_ctx {
	char proxy_host[256];
	uint16_t proxy_port;
	struct sockaddr_storage target_addr;
	char *user;
	char *pass;
	int state;
	char buffer[4096];
	int buf_len;
	int buf_sent; /* Track partial sends in handshake */
	int is_server;

	/* Target domain support */
	int target_type; /* 0=IPv4, 1=Domain, 2=IPv6 */
	char target_domain[256];
	uint16_t target_port;

	/* UDP Support */
	int udp_fd;                    /* Internal UDP socket for data */
	struct sockaddr_in relay_addr; /* Server: Client's Address; Client: Server's Relay Address */
	int is_udp;
	int control_fd; /* Client Mode: TCP Control Socket if lower is UDP */

	/* Error Reporting */
	int last_error_code; /* SOCKS5 error code from server */
	char error_msg[256]; /* Human-readable error message */
};

enum {
	S5_INIT = 0,
	S5_INIT_ACK,
	S5_AUTH,
	S5_AUTH_ACK,
	S5_REQ,
	S5_REQ_ACK,
	S5_DONE,
	S5_ERR,

	/* Server States */
	S5_SRV_INIT = 10,
	S5_SRV_INIT_ACK,
	S5_SRV_AUTH,
	S5_SRV_AUTH_ACK,
	S5_SRV_REQ,
	S5_SRV_REQ_ACK,
	S5_SRV_REPLY
};

/* --- Generic IO Proxies --- */
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

/* SOCKS5 Header Parsing Helpers */
static int _socks5_parse_address(const char *buf, size_t len, struct sockaddr_storage *addr, int *header_len)
{
	if (len < 1) {
		return -1;
	}

	int atyp = (unsigned char)buf[0];

	if (atyp == SOCKS5_ATYP_IPV4) {
		if (len < 7) {
			return -1;
		}
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, buf + 1, 4);
		memcpy(&sin->sin_port, buf + 5, 2);
		*header_len = 7;
		return 0;
	} else if (atyp == SOCKS5_ATYP_IPV6) {
		if (len < 19) {
			return -1;
		}
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, buf + 1, 16);
		memcpy(&sin6->sin6_port, buf + 17, 2);
		*header_len = 19;
		return 0;
	} else if (atyp == SOCKS5_ATYP_DOMAIN) {
		if (len < 2) {
			return -1;
		}
		int dlen = (unsigned char)buf[1];
		if (len < (size_t)(2 + dlen + 2)) {
			return -1;
		}
		*header_len = 2 + dlen + 2;
		return 1; /* Mark as Domain */
	}

	return -1;
}

static int _socks5_format_address(char *buf, size_t len, const struct sockaddr *addr, int *header_len)
{
	if (!addr) {
		return -1;
	}

	if (addr->sa_family == AF_INET) {
		if (len < 7) {
			return -1;
		}
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		buf[0] = SOCKS5_ATYP_IPV4;
		memcpy(buf + 1, &sin->sin_addr, 4);
		memcpy(buf + 5, &sin->sin_port, 2);
		*header_len = 7;
		return 0;
	} else if (addr->sa_family == AF_INET6) {
		if (len < 19) {
			return -1;
		}
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		buf[0] = SOCKS5_ATYP_IPV6;
		memcpy(buf + 1, &sin6->sin6_addr, 16);
		memcpy(buf + 17, &sin6->sin6_port, 2);
		*header_len = 19;
		return 0;
	}

	return -1;
}

static ssize_t _s5_hs_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->is_udp && ctx->control_fd >= 0) {
		return recv(ctx->control_fd, buf, len, flags);
	}
	return io->lower->recv(io->lower, buf, len, flags);
}

static ssize_t _s5_hs_send(struct gsocket_io *io, const void *buf, size_t len, int flags)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->is_udp && ctx->control_fd >= 0) {
		return send(ctx->control_fd, buf, len, flags);
	}
	return io->lower->send(io->lower, buf, len, flags);
}

static int _s5_srv_recv_buffer(struct gsocket_io *io, struct socks5_ctx *ctx, int needed)
{
	if (ctx->buf_len >= needed) {
		return 0;
	}

	int ret = io->lower->recv(io->lower, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - ctx->buf_len, 0);
	if (ret > 0) {
		ctx->buf_len += ret;
		if (ctx->buf_len >= needed) {
			return 0;
		}
		return GSOCKET_HANDSHAKE_WANT_READ;
	} else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return GSOCKET_HANDSHAKE_WANT_READ;
	} else {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Connection closed by client");
		return GSOCKET_HANDSHAKE_ERR;
	}
}

static int _s5_srv_handle_init(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = _s5_srv_recv_buffer(io, ctx, 2);
	if (ret != 0) {
		return ret;
	}

	if (ctx->buffer[0] != SOCKS5_VERSION) {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unsupported SOCKS version: 0x%02x", ctx->buffer[0]);
		return GSOCKET_HANDSHAKE_ERR;
	}

	int nmethods = (unsigned char)ctx->buffer[1];
	int needed = 2 + nmethods;

	ret = _s5_srv_recv_buffer(io, ctx, needed);
	if (ret != 0) {
		return ret;
	}

	int method = SOCKS5_AUTH_INVALID;
	if (ctx->user && ctx->pass) {
		for (int i = 0; i < nmethods; i++) {
			if (ctx->buffer[2 + i] == SOCKS5_AUTH_USERPASS) {
				method = SOCKS5_AUTH_USERPASS;
			}
		}
	} else {
		for (int i = 0; i < nmethods; i++) {
			if (ctx->buffer[2 + i] == SOCKS5_AUTH_NONE) {
				method = SOCKS5_AUTH_NONE;
			}
		}
	}

	if (method == SOCKS5_AUTH_INVALID) {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "No supported auth method found in %d methods", nmethods);
		return GSOCKET_HANDSHAKE_ERR;
	}

	/* Prepare response in buffer start */
	ctx->buffer[0] = SOCKS5_VERSION;
	ctx->buffer[1] = method;

	/* Keep remaining data at buffer+2 */
	if (ctx->buf_len > needed) {
		if (2 + ctx->buf_len - needed > (int)sizeof(ctx->buffer)) {
			return GSOCKET_HANDSHAKE_ERR;
		}
		memmove(ctx->buffer + 2, ctx->buffer + needed, ctx->buf_len - needed);
		ctx->buf_len = ctx->buf_len - needed + 2;
	} else {
		ctx->buf_len = 2;
	}

	ctx->state = S5_SRV_INIT_ACK;
	ctx->buf_sent = 0;
	return 0; /* Continue */
}

static int _s5_srv_handle_init_ack(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = io->lower->send(io->lower, ctx->buffer + ctx->buf_sent, 2 - ctx->buf_sent, MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}
	ctx->buf_sent += ret;
	if (ctx->buf_sent < 2) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	char method = ctx->buffer[1];
	/* Shift remaining data to start of buffer */
	if (ctx->buf_len > 2) {
		memmove(ctx->buffer, ctx->buffer + 2, ctx->buf_len - 2);
		ctx->buf_len -= 2;
	} else {
		ctx->buf_len = 0;
	}

	if (method == SOCKS5_AUTH_USERPASS) {
		ctx->state = S5_SRV_AUTH;
	} else {
		ctx->state = S5_SRV_REQ;
	}
	return 0; /* Continue */
}

static int _s5_srv_handle_auth(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = _s5_srv_recv_buffer(io, ctx, 2);
	if (ret != 0) {
		return ret;
	}

	if (ctx->buffer[0] != SOCKS5_USERPASS_VER) {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid auth version: 0x%02x", ctx->buffer[0]);
		return GSOCKET_HANDSHAKE_ERR;
	}

	int ulen = (unsigned char)ctx->buffer[1];
	int needed = 2 + ulen + 1;

	ret = _s5_srv_recv_buffer(io, ctx, needed);
	if (ret != 0) {
		return ret;
	}

	int plen = (unsigned char)ctx->buffer[2 + ulen];
	int total = needed + plen;

	ret = _s5_srv_recv_buffer(io, ctx, total);
	if (ret != 0) {
		return ret;
	}

	int match = 0;
	if (ctx->user && ctx->pass) {
		if (ulen == (int)strlen(ctx->user) && plen == (int)strlen(ctx->pass)) {
			if (memcmp(ctx->buffer + 2, ctx->user, ulen) == 0 &&
				memcmp(ctx->buffer + 2 + ulen + 1, ctx->pass, plen) == 0) {
				match = 1;
			}
		}
	}

	/* Prepare response in buffer start */
	ctx->buffer[0] = SOCKS5_USERPASS_VER;
	ctx->buffer[1] = match ? SOCKS5_USERPASS_SUCCESS : SOCKS5_USERPASS_FAILURE;

	if (ctx->buf_len > total) {
		if (2 + ctx->buf_len - total > (int)sizeof(ctx->buffer)) {
			return GSOCKET_HANDSHAKE_ERR;
		}
		memmove(ctx->buffer + 2, ctx->buffer + total, ctx->buf_len - total);
		ctx->buf_len = ctx->buf_len - total + 2;
	} else {
		ctx->buf_len = 2;
	}

	ctx->state = S5_SRV_AUTH_ACK;
	ctx->buf_sent = 0;
	return 0; /* Continue */
}

static int _s5_srv_handle_auth_ack(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = io->lower->send(io->lower, ctx->buffer + ctx->buf_sent, 2 - ctx->buf_sent, MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}
	ctx->buf_sent += ret;
	if (ctx->buf_sent < 2) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	if (ctx->buffer[1] != SOCKS5_USERPASS_SUCCESS) {
		return GSOCKET_HANDSHAKE_ERR;
	}

	if (ctx->buf_len > 2) {
		memmove(ctx->buffer, ctx->buffer + 2, ctx->buf_len - 2);
		ctx->buf_len -= 2;
	} else {
		ctx->buf_len = 0;
	}

	ctx->state = S5_SRV_REQ;
	return 0; /* Continue */
}

static int _s5_srv_create_udp_socket(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	if (ctx->udp_fd != -1) {
		return 0; /* Already created */
	}

	int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_fd < 0) {
		return -1;
	}

	struct sockaddr_in udp_addr = {};
	udp_addr.sin_family = AF_INET;
	udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	udp_addr.sin_port = 0;

	if (bind(udp_fd, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) != 0) {
		close(udp_fd);
		return -1;
	}

	socklen_t alen = sizeof(udp_addr);
	getsockname(udp_fd, (struct sockaddr *)&udp_addr, &alen);

	struct sockaddr_in control_addr;
	socklen_t clen = sizeof(control_addr);
	if (getsockname(io->lower->get_fd(io->lower), (struct sockaddr *)&control_addr, &clen) == 0) {
		udp_addr.sin_addr = control_addr.sin_addr;
	} else {
		udp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}

	ctx->udp_fd = udp_fd;
	ctx->is_udp = 1;

	int sflags = fcntl(ctx->udp_fd, F_GETFL, 0);
	fcntl(ctx->udp_fd, F_SETFL, sflags | O_NONBLOCK);

	return 0;
}

static void _s5_srv_build_reply(struct gsocket_io *io, struct socks5_ctx *ctx, char *reply)
{
	reply[0] = SOCKS5_VERSION;
	reply[1] = SOCKS5_REPLY_SUCCESS;
	reply[2] = 0x00;
	reply[3] = SOCKS5_ATYP_IPV4;
	memset(reply + 4, 0, 6);

	if (ctx->buffer[1] == SOCKS5_CMD_UDP_ASSOCIATE) {
		if (_s5_srv_create_udp_socket(io, ctx) == 0) {
			struct sockaddr_in udp_addr;
			socklen_t alen = sizeof(udp_addr);
			getsockname(ctx->udp_fd, (struct sockaddr *)&udp_addr, &alen);

			struct sockaddr_in control_addr;
			socklen_t clen = sizeof(control_addr);
			if (getsockname(io->lower->get_fd(io->lower), (struct sockaddr *)&control_addr, &clen) == 0) {
				udp_addr.sin_addr = control_addr.sin_addr;
			}

			memcpy(reply + 4, &udp_addr.sin_addr, 4);
			memcpy(reply + 8, &udp_addr.sin_port, 2);
		} else {
			reply[1] = 0x01; /* General failure */
		}
	}
}

static int _s5_srv_handle_req(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = _s5_srv_recv_buffer(io, ctx, 4);
	if (ret != 0) {
		return ret;
	}

	if (ctx->buffer[1] != SOCKS5_CMD_CONNECT && ctx->buffer[1] != SOCKS5_CMD_UDP_ASSOCIATE) {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unsupported SOCKS command: 0x%02x", ctx->buffer[1]);
		return GSOCKET_HANDSHAKE_ERR;
	}

	struct sockaddr_storage target_addr_storage = {};
	int header_len = 0;
	int res = _socks5_parse_address(ctx->buffer + 3, ctx->buf_len - 3, &target_addr_storage, &header_len);
	if (res < 0) {
		/* Need more data */
		if (ctx->buf_len > 512) {
			return GSOCKET_HANDSHAKE_ERR; /* Sanity limit */
		}

		int r = io->lower->recv(io->lower, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - ctx->buf_len, 0);
		if (r > 0) {
			ctx->buf_len += r;
			/* Re-parse after getting more data */
			res = _socks5_parse_address(ctx->buffer + 3, ctx->buf_len - 3, &target_addr_storage, &header_len);
		} else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_READ;
		} else {
			return GSOCKET_HANDSHAKE_ERR;
		}

		if (res < 0) {
			return GSOCKET_HANDSHAKE_WANT_READ;
		}
	}

	/* Store target information */
	if (res == 0 && target_addr_storage.ss_family == AF_INET) {
		memcpy(&ctx->target_addr, &target_addr_storage, sizeof(target_addr_storage));
		ctx->target_type = 0; /* IP */
	} else if (res == 1) {
		/* Domain name */
		ctx->target_type = 1;
		int dlen = (unsigned char)ctx->buffer[4];
		if (dlen > 0 && dlen < (int)sizeof(ctx->target_domain)) {
			memcpy(ctx->target_domain, ctx->buffer + 5, dlen);
			ctx->target_domain[dlen] = '\0';
		}
		/* Extract port */
		uint16_t port;
		memcpy(&port, ctx->buffer + 5 + dlen, 2);
		ctx->target_port = ntohs(port);

		if (target_addr_storage.ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&target_addr_storage;
			struct sockaddr_in *target = (struct sockaddr_in *)&ctx->target_addr;
			memcpy(target, sin, sizeof(struct sockaddr_in));
		} else {
			memcpy(&ctx->target_addr, &target_addr_storage, sizeof(struct sockaddr_storage));
		}
	}

	char reply[22]; /* Max possible reply size (IPv6) */
	_s5_srv_build_reply(io, ctx, reply);
	int reply_len = 10; /* FIXME: support IPv6 reply length if needed */

	int needed = 3 + header_len;
	/* Prepare reply in buffer start, shifting any extra data */
	if (ctx->buf_len > needed) {
		if (reply_len + ctx->buf_len - needed > (int)sizeof(ctx->buffer)) {
			return GSOCKET_HANDSHAKE_ERR;
		}
		memmove(ctx->buffer + reply_len, ctx->buffer + needed, ctx->buf_len - needed);
		ctx->buf_len = ctx->buf_len - needed + reply_len;
	} else {
		ctx->buf_len = reply_len;
	}

	memcpy(ctx->buffer, reply, reply_len);
	ctx->state = S5_SRV_REQ_ACK;
	ctx->buf_sent = 0;
	return 0; /* Continue */
}

static int _s5_srv_handle_req_ack(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int reply_len = 10; /* FIXME: should be dynamic */
	int ret = io->lower->send(io->lower, ctx->buffer + ctx->buf_sent, reply_len - ctx->buf_sent, MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}
	ctx->buf_sent += ret;
	if (ctx->buf_sent < reply_len) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	if (ctx->buf_len > reply_len) {
		memmove(ctx->buffer, ctx->buffer + reply_len, ctx->buf_len - reply_len);
		ctx->buf_len -= reply_len;
	} else {
		ctx->buf_len = 0;
	}

	ctx->state = S5_DONE;
	return GSOCKET_HANDSHAKE_DONE;
}

static int _socks5_server_handshake(struct gsocket_io *io)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;
	int ret;

	while (1) {
		switch (ctx->state) {
		case S5_SRV_INIT:
			ret = _s5_srv_handle_init(io, ctx);
			break;
		case S5_SRV_INIT_ACK:
			ret = _s5_srv_handle_init_ack(io, ctx);
			break;
		case S5_SRV_AUTH:
			ret = _s5_srv_handle_auth(io, ctx);
			break;
		case S5_SRV_AUTH_ACK:
			ret = _s5_srv_handle_auth_ack(io, ctx);
			break;
		case S5_SRV_REQ:
			ret = _s5_srv_handle_req(io, ctx);
			break;
		case S5_SRV_REQ_ACK:
			ret = _s5_srv_handle_req_ack(io, ctx);
			break;
		case S5_DONE:
			return GSOCKET_HANDSHAKE_DONE;
		default:
			return GSOCKET_HANDSHAKE_ERR;
		}

		if (ret != 0) {
			return ret;
		}
		/* If ret == 0, loop to next state immediately (Greedy Handshake) */
	}
}

static int _s5_cli_recv_buffer(struct gsocket_io *io, struct socks5_ctx *ctx, int needed)
{
	if (ctx->buf_len >= needed) {
		return 0;
	}

	int ret = _s5_hs_recv(io, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - ctx->buf_len, 0);
	if (ret > 0) {
		ctx->buf_len += ret;
		if (ctx->buf_len >= needed) {
			return 0;
		}
		return GSOCKET_HANDSHAKE_WANT_READ;
	} else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		return GSOCKET_HANDSHAKE_WANT_READ;
	} else {
		snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Connection closed by proxy server");
		return GSOCKET_HANDSHAKE_ERR;
	}
}

static int _s5_cli_handle_init(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	if (ctx->buf_sent == 0) {
		ctx->buffer[0] = SOCKS5_VERSION;
		int nmethods = 1;
		ctx->buffer[2] = SOCKS5_AUTH_NONE;
		if (ctx->user && ctx->pass) {
			nmethods++;
			ctx->buffer[3] = SOCKS5_AUTH_USERPASS;
		}
		ctx->buffer[1] = nmethods;
		ctx->buf_len = 2 + nmethods;
	}

	int ret = _s5_hs_send(io, ctx->buffer + ctx->buf_sent, ctx->buf_len - ctx->buf_sent, MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}
	ctx->buf_sent += ret;
	if (ctx->buf_sent < ctx->buf_len) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	ctx->buf_len = 0;
	ctx->buf_sent = 0;
	ctx->state = S5_INIT_ACK;
	return 0; /* Continue */
}

static int _s5_cli_handle_init_ack(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = _s5_cli_recv_buffer(io, ctx, 2);
	if (ret != 0) {
		return ret;
	}

	if (ctx->buffer[0] != SOCKS5_VERSION) {
		return GSOCKET_HANDSHAKE_ERR;
	}

	char method = ctx->buffer[1];
	if (ctx->buf_len > 2) {
		memmove(ctx->buffer, ctx->buffer + 2, ctx->buf_len - 2);
		ctx->buf_len -= 2;
	} else {
		ctx->buf_len = 0;
	}

	if (method == SOCKS5_AUTH_USERPASS) {
		if (!ctx->user || !ctx->pass) {
			return GSOCKET_HANDSHAKE_ERR;
		}
		ctx->state = S5_AUTH;
	} else if (method == SOCKS5_AUTH_NONE) {
		ctx->state = S5_REQ;
	} else {
		return GSOCKET_HANDSHAKE_ERR;
	}
	return 0; /* Continue */
}

static int _s5_cli_handle_auth(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	if (ctx->buf_sent == 0) {
		int ulen = (int)strlen(ctx->user);
		int plen = (int)strlen(ctx->pass);
		if (ulen > 255 || plen > 255) {
			return GSOCKET_HANDSHAKE_ERR;
		}

		ctx->buffer[0] = SOCKS5_USERPASS_VER;
		ctx->buffer[1] = (unsigned char)ulen;
		memcpy(ctx->buffer + 2, ctx->user, ulen);
		ctx->buffer[2 + ulen] = (unsigned char)plen;
		memcpy(ctx->buffer + 2 + ulen + 1, ctx->pass, plen);
		ctx->buf_len = 3 + ulen + plen;
	}

	int ret = _s5_hs_send(io, ctx->buffer + ctx->buf_sent, ctx->buf_len - ctx->buf_sent, MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}
	ctx->buf_sent += ret;
	if (ctx->buf_sent < ctx->buf_len) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	ctx->buf_len = 0;
	ctx->buf_sent = 0;
	ctx->state = S5_AUTH_ACK;
	return 0; /* Continue */
}

static int _s5_cli_handle_auth_ack(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = _s5_cli_recv_buffer(io, ctx, 2);
	if (ret != 0) {
		return ret;
	}

	if (ctx->buffer[1] != SOCKS5_USERPASS_SUCCESS) {
		return GSOCKET_HANDSHAKE_ERR;
	}

	if (ctx->buf_len > 2) {
		memmove(ctx->buffer, ctx->buffer + 2, ctx->buf_len - 2);
		ctx->buf_len -= 2;
	} else {
		ctx->buf_len = 0;
	}

	ctx->state = S5_REQ;
	return 0; /* Continue */
}

static int _s5_cli_handle_req(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	if (ctx->buf_sent == 0) {
		char cmd = ctx->is_udp ? SOCKS5_CMD_UDP_ASSOCIATE : SOCKS5_CMD_CONNECT;
		ctx->buffer[0] = SOCKS5_VERSION;
		ctx->buffer[1] = cmd;
		ctx->buffer[2] = 0x00;

		if (ctx->target_type == 1) { /* Domain */
			ctx->buffer[3] = SOCKS5_ATYP_DOMAIN;
			int dlen = strlen(ctx->target_domain);
			ctx->buffer[4] = dlen;
			memcpy(ctx->buffer + 5, ctx->target_domain, dlen);

			uint16_t nport = htons(ctx->target_port);
			memcpy(ctx->buffer + 5 + dlen, &nport, 2);
			ctx->buf_len = 5 + dlen + 2;
		} else if (ctx->target_type == 2) { /* IPv6 */
			ctx->buffer[3] = SOCKS5_ATYP_IPV6;
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ctx->target_addr;
			if (ctx->is_udp) {
				memset(ctx->buffer + 4, 0, 16);
				memset(ctx->buffer + 20, 0, 2);
			} else {
				memcpy(ctx->buffer + 4, &addr6->sin6_addr, 16);
				memcpy(ctx->buffer + 20, &addr6->sin6_port, 2);
			}
			ctx->buf_len = 22;
		} else { /* IPv4 */
			ctx->buffer[3] = SOCKS5_ATYP_IPV4;
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&ctx->target_addr;
			if (ctx->is_udp) {
				memset(ctx->buffer + 4, 0, 4);
				memset(ctx->buffer + 8, 0, 2);
			} else {
				memcpy(ctx->buffer + 4, &addr4->sin_addr, 4);
				memcpy(ctx->buffer + 8, &addr4->sin_port, 2);
			}
			ctx->buf_len = 10;
		}
	}

	int ret = _s5_hs_send(io, ctx->buffer + ctx->buf_sent, ctx->buf_len - ctx->buf_sent, MSG_NOSIGNAL);
	if (ret <= 0) {
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_WRITE;
		}
		return GSOCKET_HANDSHAKE_ERR;
	}
	ctx->buf_sent += ret;
	if (ctx->buf_sent < ctx->buf_len) {
		return GSOCKET_HANDSHAKE_WANT_WRITE;
	}

	ctx->buf_len = 0;
	ctx->buf_sent = 0;
	ctx->state = S5_REQ_ACK;
	return 0; /* Continue */
}

static int _s5_cli_handle_req_ack(struct gsocket_io *io, struct socks5_ctx *ctx)
{
	int ret = _s5_cli_recv_buffer(io, ctx, 4);
	if (ret != 0) {
		return ret;
	}

	if (ctx->buffer[1] != SOCKS5_REPLY_SUCCESS) {
		/* Capture SOCKS5 error code */
		ctx->last_error_code = (unsigned char)ctx->buffer[1];

		/* Map SOCKS5 error to errno and error message */
		switch (ctx->last_error_code) {
		case SOCKS5_ERR_CONN_REFUSED:
			errno = ECONNREFUSED;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Connection refused by target server");
			break;
		case SOCKS5_ERR_HOST_UNREACHABLE:
			errno = EHOSTUNREACH;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Host unreachable");
			break;
		case SOCKS5_ERR_NET_UNREACHABLE:
			errno = ENETUNREACH;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Network unreachable");
			break;
		case SOCKS5_ERR_NOT_ALLOWED:
			errno = EACCES;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Connection not allowed by ruleset");
			break;
		case SOCKS5_ERR_TTL_EXPIRED:
			errno = ETIMEDOUT;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "TTL expired");
			break;
		case SOCKS5_ERR_CMD_NOT_SUPPORTED:
			errno = EOPNOTSUPP;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Command not supported");
			break;
		case SOCKS5_ERR_ADDR_NOT_SUPPORTED:
			errno = EAFNOSUPPORT;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Address type not supported");
			break;
		case SOCKS5_ERR_GENERAL_FAILURE:
		default:
			errno = EIO;
			snprintf(ctx->error_msg, sizeof(ctx->error_msg), "General SOCKS5 failure (code: 0x%02x)",
					 ctx->last_error_code);
			break;
		}

		return GSOCKET_HANDSHAKE_ERR;
	}

	struct sockaddr_storage raddr = {};
	int header_len = 0;
	int res = _socks5_parse_address(ctx->buffer + 3, ctx->buf_len - 3, &raddr, &header_len);
	if (res < 0) {
		/* Needs more data */
		int r = _s5_hs_recv(io, ctx->buffer + ctx->buf_len, sizeof(ctx->buffer) - ctx->buf_len, 0);
		if (r > 0) {
			ctx->buf_len += r;
			return 0; /* Try Loop Again */
		} else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return GSOCKET_HANDSHAKE_WANT_READ;
		} else {
			return GSOCKET_HANDSHAKE_ERR;
		}
	}

	if (ctx->is_udp) {
		if (res == 0 && raddr.ss_family == AF_INET) {
			ctx->relay_addr = *(struct sockaddr_in *)&raddr;

			/* NAT Traversal for SOCKS5 Client:
			   Override returned IP with the address we connected to */
			if (inet_pton(AF_INET, ctx->proxy_host, &ctx->relay_addr.sin_addr) != 1) {
				struct sockaddr_storage peer;
				socklen_t plen = sizeof(peer);
				int _fd = io->lower->get_fd(io->lower);
				if (getpeername(_fd, (struct sockaddr *)&peer, &plen) == 0 && peer.ss_family == AF_INET) {
					ctx->relay_addr.sin_addr = ((struct sockaddr_in *)&peer)->sin_addr;
				}
			}
		}
	}

	int total_rep = 3 + header_len;
	if (ctx->buf_len > total_rep) {
		memmove(ctx->buffer, ctx->buffer + total_rep, ctx->buf_len - total_rep);
		ctx->buf_len -= total_rep;
	} else {
		ctx->buf_len = 0;
	}

	ctx->state = S5_DONE;
	return GSOCKET_HANDSHAKE_DONE;
}

static int _socks5_client_handshake(struct gsocket_io *io)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;
	int ret;

	while (1) {
		switch (ctx->state) {
		case S5_INIT:
			ret = _s5_cli_handle_init(io, ctx);
			break;
		case S5_INIT_ACK:
			ret = _s5_cli_handle_init_ack(io, ctx);
			break;
		case S5_AUTH:
			ret = _s5_cli_handle_auth(io, ctx);
			break;
		case S5_AUTH_ACK:
			ret = _s5_cli_handle_auth_ack(io, ctx);
			break;
		case S5_REQ:
			ret = _s5_cli_handle_req(io, ctx);
			break;
		case S5_REQ_ACK:
			ret = _s5_cli_handle_req_ack(io, ctx);
			break;
		case S5_DONE:
			return GSOCKET_HANDSHAKE_DONE;
		default:
			return GSOCKET_HANDSHAKE_ERR;
		}

		if (ret != 0) {
			return ret;
		}
	}
}

static int _socks5_handshake(struct gsocket_io *io)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (io->lower && io->lower->handshake) {
		int res = io->lower->handshake(io->lower);
		if (res != GSOCKET_HANDSHAKE_DONE) {
			return res;
		}
	}

	if (ctx->is_server) {
		return _socks5_server_handshake(io);
	}
	return _socks5_client_handshake(io);
}

static int _socks5_connect(struct gsocket_io *io, const char *host, int port)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->is_server) {
		return -1;
	}

	/* Store Target Information */
	ctx->target_port = port;
	struct sockaddr_in *addr4 = (struct sockaddr_in *)&ctx->target_addr;
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ctx->target_addr;

	if (inet_pton(AF_INET, host, &addr4->sin_addr) == 1) {
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(port);
		ctx->target_type = 0; /* IPv4 */
	} else if (inet_pton(AF_INET6, host, &addr6->sin6_addr) == 1) {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(port);
		ctx->target_type = 2; /* IPv6 */
	} else {
		if (strlen(host) >= sizeof(ctx->target_domain)) {
			return -1;
		}
		strncpy(ctx->target_domain, host, sizeof(ctx->target_domain) - 1);
		ctx->target_domain[sizeof(ctx->target_domain) - 1] = '\0';
		ctx->target_type = 1; /* Domain */
	}

	int type = 0;
	socklen_t l = sizeof(type);
	if (getsockopt(io->lower->get_fd(io->lower), SOL_SOCKET, SO_TYPE, &type, &l) != 0) {
		type = SOCK_STREAM;
	}
	if (type == SOCK_DGRAM) {
		ctx->is_udp = 1;
		if (ctx->control_fd == -1) {
			ctx->control_fd = socket(AF_INET, SOCK_STREAM, 0);
			if (ctx->control_fd < 0) {
				return -1;
			}
			int sflags = fcntl(ctx->control_fd, F_GETFL, 0);
			fcntl(ctx->control_fd, F_SETFL, sflags | O_NONBLOCK);

			/* Resolve Proxy Host for raw connect */
			struct addrinfo hints, *res;
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			char p_str[16];
			sprintf(p_str, "%d", ctx->proxy_port);

			if (getaddrinfo(ctx->proxy_host, p_str, &hints, &res) == 0) {
				int ret = connect(ctx->control_fd, res->ai_addr, res->ai_addrlen);
				freeaddrinfo(res);
				if (ret != 0 && errno != EINPROGRESS) {
					close(ctx->control_fd);
					ctx->control_fd = -1;
					return ret;
				}
			} else {
				close(ctx->control_fd);
				ctx->control_fd = -1;
				return -1;
			}
		}
	} else {
		if (ctx->is_udp && ctx->udp_fd == -1) {
			ctx->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
			if (ctx->udp_fd < 0) {
				return -1;
			}
			fcntl(ctx->udp_fd, F_SETFL, O_NONBLOCK);
		}
		int ret = io->lower->connect(io->lower, ctx->proxy_host, ctx->proxy_port);
		if (ret != 0 && errno != EINPROGRESS) {
			return ret;
		}
	}

	int flags = fcntl(io->lower->get_fd(io->lower), F_GETFL, 0);
	if (!(flags & O_NONBLOCK)) {
		while (ctx->state != S5_DONE) {
			int res = _socks5_handshake(io);
			if (res == GSOCKET_HANDSHAKE_ERR) {
				errno = EPROTO;
				return -1;
			}

			if (res == GSOCKET_HANDSHAKE_DONE) {
				break;
			}

			if (ctx->is_udp) {
				usleep(1000);
			}
		}
	}
	return 0;
}

static void _socks5_free(struct gsocket_io *io)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->control_fd >= 0) {
		close(ctx->control_fd);
		ctx->control_fd = -1;
	}

	if (ctx->udp_fd >= 0) {
		close(ctx->udp_fd);
		ctx->udp_fd = -1;
	}

	if (ctx->user) {
		free(ctx->user);
	}

	if (ctx->pass) {
		free(ctx->pass);
	}

	free(ctx);
	free(io);
}

static int _socks5_get_target(struct gsocket_io *io, struct gsocket_address *target)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->target_type == 1) {
		/* Domain */
		strncpy(target->host, ctx->target_domain, sizeof(target->host) - 1);
		target->host[sizeof(target->host) - 1] = '\0';
		target->port = ctx->target_port;
	} else if (ctx->target_type == 2) {
		/* IPv6 - Convert back to string */
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&ctx->target_addr;
		inet_ntop(AF_INET6, &addr6->sin6_addr, target->host, sizeof(target->host));
		target->port = ntohs(addr6->sin6_port);
	} else {
		/* IPv4 - Convert back to string */
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&ctx->target_addr;
		inet_ntop(AF_INET, &addr4->sin_addr, target->host, sizeof(target->host));
		target->port = ntohs(addr4->sin_port);
	}

	return 0;
}

struct gsocket_io *gsocket_io_socks5_udp_new(const char *proxy_ip, int proxy_port, const char *user, const char *pass)
{
	struct gsocket_io *io = gsocket_io_socks5_new(proxy_ip, proxy_port, user, pass);

	if (io) {
		((struct socks5_ctx *)io->ctx)->is_udp = 1;
	}

	return io;
}

static int _socks5_getsockopt(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (level == SOL_SOCKS5) {
		if (optname == SO_SOCKS5_CMD) {
			if (*optlen < sizeof(int)) {
				return -1;
			}
			*(int *)optval = ctx->is_udp ? SOCKS5_CMD_UDP_ASSOCIATE : SOCKS5_CMD_CONNECT;
			return 0;
		} else if (optname == SO_SOCKS5_UDP_FD) {
			if (*optlen < sizeof(int)) {
				return -1;
			}
			*(int *)optval = ctx->udp_fd;
			return 0;
		}
	} else if (level == SOL_PROTO_ERROR) {
		if (optname == SO_ERROR_DETAIL) {
			if (*optlen < sizeof(struct gsocket_error)) {
				return -1;
			}
			struct gsocket_error *err = (struct gsocket_error *)optval;
			memset(err, 0, sizeof(*err));
			err->layer = SOL_SOCKS5;
			err->error_code = ctx->last_error_code;
			safe_strncpy(err->message, ctx->error_msg, sizeof(err->message));
			return 0;
		}
	}

	if (io->lower && io->lower->getsockopt) {
		return io->lower->getsockopt(io->lower, level, optname, optval, optlen);
	}
	return -1;
}

static ssize_t _socks5_recvfrom(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
								socklen_t *addrlen)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (!ctx->is_udp) {
		return io->lower->recvfrom(io->lower, buf, len, flags, src_addr, addrlen);
	}

	char packet[65536];
	ssize_t n = -1;
	struct sockaddr_storage saddr;
	socklen_t slen = sizeof(saddr);

	if (ctx->is_server) {
		if (ctx->udp_fd >= 0) {
			n = recvfrom(ctx->udp_fd, packet, sizeof(packet), flags, (struct sockaddr *)&saddr, &slen);
			if (n > 0 && saddr.ss_family == AF_INET) {
				ctx->relay_addr = *(struct sockaddr_in *)&saddr;
			}
		}
	} else {
		if (ctx->udp_fd >= 0) {
			n = recvfrom(ctx->udp_fd, packet, sizeof(packet), flags, (struct sockaddr *)&saddr, &slen);
		} else {
			n = io->lower->recvfrom(io->lower, packet, sizeof(packet), flags, (struct sockaddr *)&saddr, &slen);
		}
	}

	if (n <= 0) {
		return n;
	}

	if (n < 4 || packet[2] != 0) {
		return -1;
	}

	struct sockaddr_storage peer_storage = {};
	int hlen = 0;
	if (_socks5_parse_address(packet + 3, n - 3, &peer_storage, &hlen) < 0) {
		return -1;
	}

	int offset = 3 + hlen;
	size_t plen = n - offset;
	if (plen > len) {
		plen = len;
	}

	memcpy(buf, packet + offset, plen);
	if (src_addr && addrlen) {
		socklen_t clen = *addrlen;
		if (peer_storage.ss_family == AF_INET) {
			if (clen > sizeof(struct sockaddr_in)) {
				clen = sizeof(struct sockaddr_in);
			}
		} else {
			if (clen > sizeof(struct sockaddr_in6)) {
				clen = sizeof(struct sockaddr_in6);
			}
		}
		memcpy(src_addr, &peer_storage, clen);
		*addrlen = clen;
	}

	return (ssize_t)plen;
}

static ssize_t _socks5_sendto(struct gsocket_io *io, const void *buf, size_t len, int flags,
							  const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (!ctx->is_udp) {
		return io->lower->sendto(io->lower, buf, len, flags, dest_addr, addrlen);
	}

	char packet[65536];
	int hlen = 0;
	packet[0] = 0;
	packet[1] = 0;
	packet[2] = 0;

	const struct sockaddr *target = dest_addr;
	if (!target) {
		target = (const struct sockaddr *)&ctx->target_addr;
	}

	if (_socks5_format_address(packet + 3, sizeof(packet) - 3, target, &hlen) < 0) {
		return -1;
	}

	int offset = 3 + hlen;
	if (offset + len > sizeof(packet)) {
		return -1;
	}

	memcpy(packet + offset, buf, len);
	if (ctx->is_server) {
		if (ctx->relay_addr.sin_port == 0) {
			return -1;
		}
		if (ctx->udp_fd >= 0) {
			return sendto(ctx->udp_fd, packet, offset + len, flags, (struct sockaddr *)&ctx->relay_addr,
						  sizeof(ctx->relay_addr));
		}
	} else {
		if (ctx->udp_fd >= 0) {
			return sendto(ctx->udp_fd, packet, offset + len, flags, (struct sockaddr *)&ctx->relay_addr,
						  sizeof(ctx->relay_addr));
		} else {
			return io->lower->sendto(io->lower, packet, offset + len, flags, (struct sockaddr *)&ctx->relay_addr,
									 sizeof(ctx->relay_addr));
		}
	}

	return -1;
}

static ssize_t _socks5_recv(struct gsocket_io *io, void *buf, size_t len, int flags)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->state == S5_DONE && ctx->buf_len > 0) {
		size_t copy = (len < (size_t)ctx->buf_len) ? len : (size_t)ctx->buf_len;
		memcpy(buf, ctx->buffer, copy);
		memmove(ctx->buffer, ctx->buffer + copy, ctx->buf_len - copy);
		ctx->buf_len -= (int)copy;
		tlog(TLOG_DEBUG, "[SOCKS5] _socks5_recv pulled %zu bytes from internal buffer, remaining: %d", copy, ctx->buf_len);
		return (ssize_t)copy;
	}

	if (ctx->is_udp) {
		return _socks5_recvfrom(io, buf, len, flags, NULL, NULL);
	}

	ssize_t ret = io->lower->recv(io->lower, buf, len, flags);
	return ret;
}

static ssize_t _socks5_recvmsg(struct gsocket_io *io, struct msghdr *msg, int flags)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->state == S5_DONE && ctx->buf_len > 0) {
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

static ssize_t _socks5_send(struct gsocket_io *io, const void *b, size_t l, int f)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;

	if (ctx->is_udp) {
		return _socks5_sendto(io, b, l, f, (struct sockaddr *)&ctx->target_addr, sizeof(ctx->target_addr));
	}
	return io->lower->send(io->lower, b, l, f);
}

static int _socks5_get_error(struct gsocket_io *io, void *err_struct)
{
	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;
	struct gsocket_error *err = (struct gsocket_error *)err_struct;

	err->layer = SOL_SOCKS5;
	err->error_code = ctx->last_error_code;
	err->errno_val = errno;
	strncpy(err->message, ctx->error_msg, sizeof(err->message) - 1);
	err->message[sizeof(err->message) - 1] = '\0';

	return 0;
}

struct gsocket_io *gsocket_io_socks5_new(const char *proxy_ip, int proxy_port, const char *user, const char *pass)
{
	struct gsocket_io *io = calloc(1, sizeof(struct gsocket_io));
	if (!io) {
		return NULL;
	}
	struct socks5_ctx *ctx = calloc(1, sizeof(struct socks5_ctx));
	if (!ctx) {
		goto err;
	}

	ctx->control_fd = ctx->udp_fd = -1;

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
	io->handshake = _socks5_handshake;
	io->connect = _socks5_connect;
	io->recv = _socks5_recv;
	io->send = _socks5_send;
	io->recvfrom = _socks5_recvfrom;
	io->sendto = _socks5_sendto;
	io->recvmsg = _socks5_recvmsg;
	io->sendmsg = _io_proxy_sendmsg;
	io->close = _io_proxy_close;
	io->get_fd = _io_proxy_get_fd;
	io->shutdown = _io_proxy_shutdown;
	io->free = _socks5_free;
	io->get_proxy_target = _socks5_get_target;
	io->getsockopt = _socks5_getsockopt;
	io->getpeername = _io_proxy_getpeername;
	io->getsockname = _io_proxy_getsockname;
	io->get_error = _socks5_get_error;

	return io;

err:
	if (ctx) {
		if (ctx->user) {
			free(ctx->user);
		}
		if (ctx->pass) {
			free(ctx->pass);
		}
		free(ctx);
	}
	if (io) {
		free(io);
	}
	return NULL;
}

static struct gsocket_io *_socks5_accept(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen)
{
	if (!io->lower || !io->lower->accept) {
		return NULL;
	}

	struct gsocket_io *client_lower = io->lower->accept(io->lower, addr, addrlen);
	if (!client_lower) {
		return NULL;
	}

	struct socks5_ctx *ctx = (struct socks5_ctx *)io->ctx;
	struct gsocket_io *server_io = gsocket_io_socks5_server_new(ctx->user, ctx->pass);
	if (!server_io) {
		client_lower->close(client_lower);
		client_lower->free(client_lower);
		return NULL;
	}

	server_io->lower = client_lower;
	return server_io;
}

struct gsocket_io *gsocket_io_socks5_server_new(const char *user, const char *pass)
{
	struct gsocket_io *io = zalloc(1, sizeof(struct gsocket_io));
	if (!io) {
		return NULL;
	}
	struct socks5_ctx *ctx = zalloc(1, sizeof(struct socks5_ctx));
	if (!ctx) {
		goto err;
	}

	ctx->is_server = 1;
	ctx->state = S5_SRV_INIT;
	ctx->control_fd = -1;
	ctx->udp_fd = -1;

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
	io->handshake = _socks5_handshake;
	io->recv = _socks5_recv;
	io->send = _socks5_send;
	io->recvfrom = _socks5_recvfrom;
	io->sendto = _socks5_sendto;
	io->recvmsg = _socks5_recvmsg;
	io->sendmsg = _io_proxy_sendmsg;
	io->close = _io_proxy_close;
	io->get_fd = _io_proxy_get_fd;
	io->shutdown = _io_proxy_shutdown;
	io->free = _socks5_free;
	io->get_proxy_target = _socks5_get_target;
	io->accept = _socks5_accept;
	io->getsockopt = _socks5_getsockopt;
	io->getpeername = _io_proxy_getpeername;
	io->getsockname = _io_proxy_getsockname;
	io->get_error = _socks5_get_error;

	return io;

err:
	if (ctx) {
		if (ctx->user) {
			free(ctx->user);
		}
		if (ctx->pass) {
			free(ctx->pass);
		}
		free(ctx);
	}
	if (io) {
		free(io);
	}
	return NULL;
}
