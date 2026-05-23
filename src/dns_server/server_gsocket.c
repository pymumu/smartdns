/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "server_gsocket.h"

#include "connection.h"
#include "dns_server.h"
#include "server_doh_gsocket.h"
#include "server_doq_gsocket.h"
#include "server_gsocket_factory.h"
#include "server_gsocket_proto.h"
#include "server_gsocket_stream.h"

#include "smartdns/dns_conf.h"
#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/in.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
#include <openssl/quic.h>
#endif
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void _dns_server_gsocket_free_bind_resources(struct gsocket **gs, SSL_CTX **ssl_ctx)
{
	if (gs != NULL && *gs != NULL) {
		gsocket_close(*gs);
		gsocket_free(*gs);
		*gs = NULL;
	}

	if (ssl_ctx != NULL && *ssl_ctx != NULL) {
		SSL_CTX_free(*ssl_ctx);
		*ssl_ctx = NULL;
	}
}

static int _dns_server_gsocket_push_layer(struct gsocket *gs, struct gsocket_io *layer, const char *name)
{
	if (gsocket_push_layer(gs, layer) != 0) {
		tlog(TLOG_ERROR, "create %s layer failed", name);
		return -1;
	}

	return 0;
}

int _dns_server_gsocket_bind(struct dns_bind_ip *bind_ip)
{
	int fd = -1;
	SSL_CTX *ssl_ctx = NULL;
	struct gsocket *gs = NULL;
	const struct dns_server_gsocket_bind_proto *proto = dns_server_gsocket_bind_proto_get(bind_ip->type);
	int need_tls = 0;
	int need_quic = 0;
	int need_http2 = 0;
	int need_http3 = 0;
	if (proto == NULL) {
		tlog(TLOG_WARN, "unknown bind type %d", bind_ip->type);
		return 0;
	}

	need_tls = dns_gsocket_layer_spec_has(proto->layers, DNS_GSOCKET_LAYER_TLS);
	need_quic = dns_gsocket_layer_spec_has(proto->layers, DNS_GSOCKET_LAYER_QUIC);
	need_http2 = dns_gsocket_layer_spec_has(proto->layers, DNS_GSOCKET_LAYER_HTTP2);
	need_http3 = dns_gsocket_layer_spec_has(proto->layers, DNS_GSOCKET_LAYER_HTTP3);

	if (need_tls || need_quic) {
		ssl_ctx = _dns_server_gsocket_create_ssl_ctx(bind_ip, need_quic, need_http3);
		if (ssl_ctx == NULL) {
			goto errout;
		}
	}

	fd = _dns_server_gsocket_create_socket(bind_ip->ip, proto->socket_type);
	if (fd < 0) {
		goto errout;
	}

	gs = gsocket_new(fd);
	if (gs == NULL) {
		goto errout;
	}
	fd = -1;

	if (need_tls || need_quic) {
		struct gsocket_io *ssl_layer;
		if (need_quic) {
			ssl_layer = gsocket_io_ssl_quic_new(ssl_ctx, 1 /*server*/);
		} else {
			ssl_layer = gsocket_io_ssl_new(ssl_ctx, 1 /*server*/);
		}
		if (_dns_server_gsocket_push_layer(gs, ssl_layer, "SSL") != 0) {
			goto errout;
		}
	}

	if (need_http2) {
		struct gsocket_io *http2_layer = gsocket_io_http2_new(1 /*server*/);
		if (_dns_server_gsocket_push_layer(gs, http2_layer, "HTTP2") != 0) {
			goto errout;
		}
	}

	if (need_http3) {
		struct gsocket_io *http3_layer = gsocket_io_http3_new(1 /*server*/);
		if (_dns_server_gsocket_push_layer(gs, http3_layer, "HTTP3") != 0) {
			goto errout;
		}
	}

	if (need_quic) {
		if (gsocket_listen(gs, 256) != 0) {
			tlog(TLOG_ERROR, "QUIC listen failed");
			goto errout;
		}
	}

	if (bind_ip->type == DNS_BIND_TYPE_UDP) {
		struct dns_server_conn_udp *udpconn = zalloc(1, sizeof(*udpconn));
		if (!udpconn) {
			goto errout;
		}
		udpconn->head.type = DNS_CONN_TYPE_UDP_SERVER;
		udpconn->head.gs = gs;
		atomic_set(&udpconn->head.refcnt, 0);
		INIT_LIST_HEAD(&udpconn->head.list);
		_dns_server_set_flags(&udpconn->head, bind_ip);
		_dns_server_conn_get(&udpconn->head);
		tlog(TLOG_INFO, "bind UDP %s", bind_ip->ip);
		gs = NULL;
		return 0;
	}

	struct dns_server_listener *listener = zalloc(1, sizeof(*listener));
	if (!listener) {
		goto errout;
	}

	listener->head.type = proto->listener_type;
	listener->head.gs = gs;
	listener->ssl_ctx = ssl_ctx;
	INIT_LIST_HEAD(&listener->head.list);
	INIT_LIST_HEAD(&listener->list);
	_dns_server_set_flags(&listener->head, bind_ip);
	atomic_set(&listener->head.refcnt, 1);
	pthread_mutex_lock(&server.conn_list_lock);
	list_del_init(&listener->head.list);
	pthread_mutex_unlock(&server.conn_list_lock);

	list_add_tail(&listener->list, &server.listener_list);

	tlog(TLOG_INFO, "bind %s %s type=%d", proto->name, bind_ip->ip, bind_ip->type);
	gs = NULL;
	ssl_ctx = NULL;
	return 0;

errout:
	_dns_server_gsocket_free_bind_resources(&gs, &ssl_ctx);
	if (fd >= 0) {
		close(fd);
	}
	return -1;
}
