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
#ifndef _GSOCKET_H_
#define _GSOCKET_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gsocket;
struct gsocket_io;

/* Stream poll item for polling multiple streams on a QUIC connection */
struct gstream_poll_item {
	struct gsocket *stream; /* QUIC stream to poll */
	int events;             /* Events to wait for (POLLIN, POLLOUT, etc.) */
	int revents;            /* Returned events */
};

/* IO Interface for Layered Architecture */
/* Address structure (internal representation can be kept simple) */
struct gsocket_address {
	char host[256];
	uint16_t port;
};

struct gsocket_io {
	void *ctx;
	struct gsocket_io *lower;

	/* I/O Operations */
	ssize_t (*recv)(struct gsocket_io *io, void *buf, size_t len, int flags);
	ssize_t (*send)(struct gsocket_io *io, const void *buf, size_t len, int flags);
	ssize_t (*recvfrom)(struct gsocket_io *io, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						socklen_t *addrlen);
	ssize_t (*sendto)(struct gsocket_io *io, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
					  socklen_t addrlen);
	ssize_t (*recvmsg)(struct gsocket_io *io, struct msghdr *msg, int flags);
	ssize_t (*sendmsg)(struct gsocket_io *io, const struct msghdr *msg, int flags);

	/* Control & State Management */
	int (*handshake)(struct gsocket_io *io);
	int (*connect)(struct gsocket_io *io, const char *host, int port);
	int (*bind)(struct gsocket_io *io, const char *host, int port);
	int (*listen)(struct gsocket_io *io, int backlog);
	struct gsocket_io *(*accept)(struct gsocket_io *io, struct sockaddr *addr, socklen_t *addrlen);
	int (*shutdown)(struct gsocket_io *io, int how);
	int (*close)(struct gsocket_io *io);

	/* Utilities */
	int (*getsockname)(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
	int (*getpeername)(struct gsocket_io *io, struct sockaddr *addr, socklen_t *len);
	int (*getsockopt)(struct gsocket_io *io, int level, int optname, void *optval, socklen_t *optlen);
	int (*setsockopt)(struct gsocket_io *io, int level, int optname, const void *optval, socklen_t optlen);
	int (*get_fd)(struct gsocket_io *io);

	/* Multiplexing / QUIC - Stream management on this connection */
	struct gsocket_io *(*open_stream)(struct gsocket_io *io);

	/* Poll multiple streams on this connection (for QUIC) */
	int (*stream_poll)(struct gsocket_io *io, struct gstream_poll_item *items, int count, int timeout_ms);

	int (*get_proxy_target)(struct gsocket_io *io, struct gsocket_address *addr);
	/* Get required poll events (for QUIC: EPOLLIN|EPOLLOUT based on SSL_net_*_desired) */
	int (*get_poll_events)(struct gsocket_io *io);

	/* Get protocol-specific error information */
	int (*get_error)(struct gsocket_io *io, void *err_struct);

	void (*free)(struct gsocket_io *io);
};

/* Core GSocket API */
struct gsocket *gsocket_new(int fd);
void gsocket_free(struct gsocket *sock);
int gsocket_close(struct gsocket *sock);

/*
 * Note: no call this function for gsocket poll or socket operations
 * call gsocket_*() instead
 */
int gsocket_get_fd(struct gsocket *sock);

/* Layer Management */
int gsocket_push_layer(struct gsocket *sock, struct gsocket_io *layer);
struct gsocket_io *gsocket_get_top_layer(struct gsocket *sock);

/* Standard Socket Wrappers */
int gsocket_connect(struct gsocket *sock, const char *host, int port);
int gsocket_bind(struct gsocket *sock, const char *host, int port);
int gsocket_bind_device(struct gsocket *sock, const char *dev);
int gsocket_listen(struct gsocket *sock, int backlog);
struct gsocket *gsocket_accept(struct gsocket *sock, struct sockaddr *addr, socklen_t *addrlen);
int gsocket_shutdown(struct gsocket *sock, int how);

ssize_t gsocket_recv(struct gsocket *sock, void *buf, size_t len, int flags);
ssize_t gsocket_send(struct gsocket *sock, const void *buf, size_t len, int flags);
int gsocket_send_all(struct gsocket *sock, const void *buf, int len, int flags);
ssize_t gsocket_recvfrom(struct gsocket *sock, void *buf, size_t len, int flags, struct sockaddr *src_addr,
						 socklen_t *addrlen);
ssize_t gsocket_sendto(struct gsocket *sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr,
					   socklen_t addrlen);
ssize_t gsocket_recvmsg(struct gsocket *sock, struct msghdr *msg, int flags);
ssize_t gsocket_sendmsg(struct gsocket *sock, const struct msghdr *msg, int flags);
int gsocket_handshake(struct gsocket *sock);

/* Multiplexing API */
struct gsocket *gsocket_open_stream(struct gsocket *sock);

/* Group / Load Balancing API */
enum gsocket_group_policy {
	GSOCKET_GROUP_FAILOVER = 0, /* Active-Standby: Use first, failover to next */
	GSOCKET_GROUP_RR,           /* Round Robin: Rotate per connection */
	GSOCKET_GROUP_RACE,         /* Racing: Connect to all, use first success */
	GSOCKET_GROUP_HASH          /* Sticky: Hash-based selection */
};

struct gsocket *gsocket_group_new(enum gsocket_group_policy policy);
int gsocket_group_add(struct gsocket *group, struct gsocket *member, int weight);

/* Socket Options */
int gsocket_getsockname(struct gsocket *sock, struct sockaddr *addr, socklen_t *len);
int gsocket_getpeername(struct gsocket *sock, struct sockaddr *addr, socklen_t *len);
int gsocket_getsockopt(struct gsocket *sock, int level, int optname, void *optval, socklen_t *optlen);
int gsocket_setsockopt(struct gsocket *sock, int level, int optname, const void *optval, socklen_t optlen);
int gsocket_set_nonblock(struct gsocket *sock, int enable);
int gsocket_set_fastopen(struct gsocket *sock, int enable);
int gsocket_set_keepalive(struct gsocket *sock, int idle, int intvl, int cnt);
int gsocket_set_reuseport(struct gsocket *sock, int enable);
int gsocket_set_reuseaddr(struct gsocket *sock, int enable);
int gsocket_set_mark(struct gsocket *sock, int mark);
int gsocket_set_defer_accept(struct gsocket *sock, int enable);
int gsocket_set_quickack(struct gsocket *sock, int enable);

/* Handshake Return Codes */
#define GSOCKET_HANDSHAKE_DONE 0
#define GSOCKET_HANDSHAKE_WANT_READ 1
#define GSOCKET_HANDSHAKE_WANT_WRITE 2
#define GSOCKET_HANDSHAKE_ERR -1
#define GSOCKET_HANDSHAKE_EOF -2

#define GS_INVALID_FD -1

/* Flags for send/recv */
#define GS_MSG_FIN 0x1000 /* QUIC/Stream FIN (conclude) */

/* Factory Functions */
struct gsocket_io *gsocket_io_ssl_new(void *ssl_ctx, int is_server);
struct gsocket_io *gsocket_io_ssl_quic_new(void *ssl_ctx, int is_server);
int gsocket_get_poll_events(struct gsocket *sock);
struct gsocket_io *gsocket_io_socks5_new(const char *proxy_ip, int proxy_port, const char *user, const char *pass);
struct gsocket_io *gsocket_io_socks5_udp_new(const char *proxy_ip, int proxy_port, const char *user, const char *pass);
struct gsocket_io *gsocket_io_httpproxy_new(const char *proxy_ip, int proxy_port, const char *user, const char *pass);

struct gsocket_io *gsocket_io_socks5_server_new(const char *user, const char *pass);
struct gsocket_io *gsocket_io_httpproxy_server_new(const char *user, const char *pass);
struct gsocket_io *gsocket_io_tproxy_server_new(void);
struct gsocket_io *gsocket_io_sniproxy_server_new(uint16_t target_port);

struct gsocket_io *gsocket_io_http1_new(int is_server);
struct gsocket_io *gsocket_io_http2_new(int is_server);
struct gsocket_io *gsocket_io_http3_new(int is_server);

/* SOCKS5 Options */
#define GSOCKET_OPT_BASE 0x5000
#define SOL_SOCKS5 (GSOCKET_OPT_BASE + 0)
#define SO_SOCKS5_CMD 1
#define SO_SOCKS5_UDP_FD 2

#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* SSL Options */
#define SOL_SSL (GSOCKET_OPT_BASE + 1)
#define SO_SSL_SNI 1
#define SO_SSL_VERIFY 2
#define SO_SSL_SPKI 3
#define SO_SSL_ALPN 4
#define SO_SSL_VERIFY_HOSTNAME 5
#define SO_SSL_ADD_VERIFY_HOSTNAME 6
#define SO_SSL_SESSION 7
#define SO_SSL_GET_SESSION 8
#define SO_SSL_SESSION_REUSE 9
#define SO_SSL_SESSION_CACHE_SIZE 10
#define SO_SSL_0RTT 11
#define SO_SSL_0RTT_ANTI_REPLAY 12

/* HTTP Options */
#define SOL_HTTP (GSOCKET_OPT_BASE + 2)
#define SO_HTTP_METHOD 1
#define SO_HTTP_URL 2
#define SO_HTTP_STATUS 3
#define SO_HTTP_HEADER 4
#define SO_HTTP_BODY_LEN 5
#define SO_HTTP_VERSION 6

/* Protocol Error Reporting */
#define SOL_PROTO_ERROR (GSOCKET_OPT_BASE + 10)
#define SO_LAST_ERROR 1   /* Get last error code */
#define SO_ERROR_STRING 2 /* Get error description string */
#define SO_ERROR_DETAIL 3 /* Get detailed error structure */

/* Generic protocol error structure */
struct gsocket_error {
	int layer;         /* Which layer: SOL_SOCKS5, SOL_SSL, SOL_HTTP, etc. */
	int error_code;    /* Protocol-specific error code */
	char message[256]; /* Human-readable error message */
	int errno_val;     /* Associated errno if applicable */
};

/* SOCKS5 Error Codes (RFC 1928) */
#define SOCKS5_ERR_SUCCESS 0x00
#define SOCKS5_ERR_GENERAL_FAILURE 0x01
#define SOCKS5_ERR_NOT_ALLOWED 0x02
#define SOCKS5_ERR_NET_UNREACHABLE 0x03
#define SOCKS5_ERR_HOST_UNREACHABLE 0x04
#define SOCKS5_ERR_CONN_REFUSED 0x05
#define SOCKS5_ERR_TTL_EXPIRED 0x06
#define SOCKS5_ERR_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_ERR_ADDR_NOT_SUPPORTED 0x08

/* HTTP Proxy Error Codes */
#define HTTP_PROXY_ERR_BAD_REQUEST 400
#define HTTP_PROXY_ERR_AUTH_REQUIRED 407
#define HTTP_PROXY_ERR_FORBIDDEN 403
#define HTTP_PROXY_ERR_NOT_FOUND 404
#define HTTP_PROXY_ERR_BAD_GATEWAY 502
#define HTTP_PROXY_ERR_UNAVAILABLE 503
#define HTTP_PROXY_ERR_TIMEOUT 504

int gsocket_get_proxy_target(struct gsocket *gs, struct gsocket_address *target);

/* Stream poll manager for non-fd streams (QUIC) */
struct gstream_poll;

/* Event with user data for gstream_poll_wait */
struct gstream_event {
	struct gsocket *stream; /* stream socket */
	int events;             /* requested events (EPOLLIN | EPOLLOUT) */
	int revents;            /* returned events */
	void *user_data;        /* user data */
};

/* Create stream poll manager for a QUIC connection */
struct gstream_poll *gstream_poll_create(struct gsocket *quic_connection);
int gstream_poll_add(struct gstream_poll *sp, struct gsocket *stream, int events, void *user_data);
int gstream_poll_mod(struct gstream_poll *sp, struct gsocket *stream, int events, void *user_data);
int gstream_poll_del(struct gstream_poll *sp, struct gsocket *stream);
int gstream_poll_wait(struct gstream_poll *sp, struct gstream_event *events, int maxevents, int timeout_ms);
void gstream_poll_destroy(struct gstream_poll *sp);
/* Get required network events (EPOLLIN|EPOLLOUT) for the QUIC connection */
int gstream_poll_get_net_events(struct gstream_poll *sp);

#ifdef __cplusplus
}
#endif

#endif
