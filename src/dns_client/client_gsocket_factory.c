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

#define _GNU_SOURCE

#include "client_gsocket.h"
#include "client_socket.h"
#include "server_info.h"

#include "smartdns/dns_conf.h"
#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/util.h"

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DNS_MAX_SERVERS 64

int dns_client_spki_decode(const char *spki, unsigned char *spki_data_out, int spki_data_out_max_len)
{
	int spki_data_len = SSL_base64_decode(spki, spki_data_out, spki_data_out_max_len);
	if (spki_data_len != SHA256_DIGEST_LENGTH) {
		return -1;
	}
	return spki_data_len;
}

static int _dns_client_set_trusted_cert(SSL_CTX *ssl_ctx)
{
	char *cafile = NULL;
	char *capath = NULL;
	int cert_path_set = 0;

	if (ssl_ctx == NULL) {
		return -1;
	}

	if (dns_conf.ca_file[0]) {
		cafile = dns_conf.ca_file;
	}
	if (dns_conf.ca_path[0]) {
		capath = dns_conf.ca_path;
	}

	if (cafile == NULL && capath == NULL) {
		if (SSL_CTX_set_default_verify_paths(ssl_ctx)) {
			cert_path_set = 1;
		}

		const STACK_OF(X509_NAME) *cas = SSL_CTX_get_client_CA_list(ssl_ctx);
		if (cas && sk_X509_NAME_num(cas) == 0) {
			cafile = "/etc/ssl/certs/ca-certificates.crt";
			capath = "/etc/ssl/certs";
			cert_path_set = 0;
		}
	}

	if (cert_path_set == 0) {
		if (SSL_CTX_load_verify_locations(ssl_ctx, cafile, capath) == 0) {
			tlog(TLOG_WARN, "load certificate from %s:%s failed.", cafile, capath);
			return -1;
		}
	}

	return 0;
}

static int _dns_client_has_explicit_ca_config(void)
{
	return dns_conf.ca_file[0] || dns_conf.ca_path[0];
}

static pthread_mutex_t _ssl_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

SSL_CTX *_ssl_ctx_get(int is_quic)
{
	SSL_CTX **ssl_ctx_ptr = NULL;
	int explicit_ca_config = _dns_client_has_explicit_ca_config();

	pthread_mutex_lock(&_ssl_ctx_mutex);
	if (is_quic) {
		ssl_ctx_ptr = &client.ssl_quic_ctx;
	} else {
		ssl_ctx_ptr = &client.ssl_ctx;
	}

	if (*ssl_ctx_ptr) {
		pthread_mutex_unlock(&_ssl_ctx_mutex);
		return *ssl_ctx_ptr;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#if (OPENSSL_VERSION_NUMBER >= 0x30200000L) && !defined(OPENSSL_NO_QUIC)
	if (is_quic) {
		*ssl_ctx_ptr = SSL_CTX_new(OSSL_QUIC_client_method());
	} else {
		*ssl_ctx_ptr = SSL_CTX_new(TLS_client_method());
	}
#else
	if (is_quic) {
		pthread_mutex_unlock(&_ssl_ctx_mutex);
		return NULL;
	}
	*ssl_ctx_ptr = SSL_CTX_new(TLS_client_method());
#endif
#else
	*ssl_ctx_ptr = SSL_CTX_new(SSLv23_client_method());
#endif

	if (*ssl_ctx_ptr == NULL) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

	SSL_CTX_set_options(*ssl_ctx_ptr, SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
	SSL_CTX_set_session_cache_mode(*ssl_ctx_ptr, SSL_SESS_CACHE_CLIENT);
	SSL_CTX_sess_set_cache_size(*ssl_ctx_ptr, DNS_MAX_SERVERS);

	if (_dns_client_set_trusted_cert(*ssl_ctx_ptr) != 0) {
		if (explicit_ca_config) {
			tlog(TLOG_ERROR, "load configured CA certificate failed.");
			goto errout;
		}

		tlog(TLOG_WARN, "load system CA certificate failed, disable upstream certificate verification.");
		SSL_CTX_set_verify(*ssl_ctx_ptr, SSL_VERIFY_NONE, NULL);
		client.ssl_verify_skip = 1;
	} else {
		SSL_CTX_set_verify(*ssl_ctx_ptr, SSL_VERIFY_PEER, NULL);
	}

	pthread_mutex_unlock(&_ssl_ctx_mutex);
	return *ssl_ctx_ptr;

errout:
	if (*ssl_ctx_ptr) {
		SSL_CTX_free(*ssl_ctx_ptr);
		*ssl_ctx_ptr = NULL;
	}
	pthread_mutex_unlock(&_ssl_ctx_mutex);
	return NULL;
}

void _ssl_shutdown(struct dns_server_info *server_info)
{
	if (server_info == NULL || server_info->gs == NULL) {
		return;
	}
	gsocket_shutdown(server_info->gs, SHUT_RDWR);
}

static int _dns_client_push_layer(struct gsocket *gs, struct gsocket_io *layer, const char *name)
{
	if (gsocket_push_layer(gs, layer) != 0) {
		tlog(TLOG_ERROR, "create %s layer failed", name);
		return -1;
	}

	return 0;
}

static struct dns_proxy_servers *_dns_client_get_proxy_server(struct dns_server_info *server_info)
{
	if (server_info->proxy_name[0] == '\0') {
		return NULL;
	}

	struct dns_proxy_names *pn = dns_server_get_proxy_names(server_info->proxy_name);
	if (!pn || list_empty(&pn->server_list)) {
		return NULL;
	}

	struct dns_proxy_servers *ps = NULL;
	struct dns_proxy_servers *iter = NULL;
	int attempt = server_info->proxy_attempt;

	int idx = 0;
	list_for_each_entry(iter, &pn->server_list, list)
	{
		if (idx == attempt) {
			ps = iter;
			break;
		}
		idx++;
	}
	if (ps == NULL) {
		ps = list_first_entry(&pn->server_list, struct dns_proxy_servers, list);
	}

	return ps;
}

static int _dns_client_proxy_has_target_override(struct dns_proxy_servers *ps)
{
	if (ps == NULL || ps->type != PROXY_PASSTHROUGH) {
		return 0;
	}

	return ps->server[0] != '\0' && strcmp(ps->server, "0.0.0.0") != 0;
}

static void _dns_client_get_socket_connect_host(struct dns_server_info *server_info, const char **host_out)
{
	struct dns_proxy_servers *ps = _dns_client_get_proxy_server(server_info);

	*host_out = server_info->ip;
	if (ps == NULL) {
		return;
	}

	if (ps->type != PROXY_PASSTHROUGH || _dns_client_proxy_has_target_override(ps)) {
		*host_out = ps->server;
	}
}

static int _dns_client_get_socket_family(struct dns_server_info *server_info)
{
	const char *connect_host = NULL;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	_dns_client_get_socket_connect_host(server_info, &connect_host);

	if (connect_host == NULL || connect_host[0] == '\0') {
		return server_info->ai_family;
	}

	memset(&addr, 0, sizeof(addr));
	if (getaddr_by_host(connect_host, (struct sockaddr *)&addr, &addr_len) != 0) {
		return server_info->ai_family;
	}

	return addr.ss_family;
}

static int _dns_client_push_proxy_layer(struct gsocket *gs, struct dns_server_info *server_info)
{
	if (server_info->proxy_name[0] == '\0') {
		return 0;
	}

	struct dns_proxy_servers *ps = _dns_client_get_proxy_server(server_info);
	if (ps == NULL) {
		tlog(TLOG_ERROR, "proxy name '%s' not found", server_info->proxy_name);
		return -1;
	}

	const char *user = (ps->username[0] == '\0') ? NULL : ps->username;
	const char *pass = (ps->password[0] == '\0') ? NULL : ps->password;

	switch (ps->type) {
	case PROXY_SOCKS5:
		return _dns_client_push_layer(gs, gsocket_io_socks5_new(ps->server, ps->port, user, pass), "socks5 proxy");
	case PROXY_SOCKS5S: {
		SSL_CTX *ssl_ctx = _ssl_ctx_get(0);
		if (ssl_ctx == NULL) {
			return -1;
		}
		if (_dns_client_push_layer(gs, gsocket_io_ssl_new(ssl_ctx, 0), "proxy ssl") != 0) {
			return -1;
		}
		if (ps->skip_cert_verify) {
			int verify = 0;
			gsocket_setsockopt(gs, SOL_SSL, SO_SSL_VERIFY, &verify, sizeof(verify));
		}
		if (ps->tls_host[0] != '\0') {
			gsocket_setsockopt(gs, SOL_SSL, SO_SSL_SNI, ps->tls_host, strlen(ps->tls_host));
			if (!ps->skip_cert_verify) {
				gsocket_setsockopt(gs, SOL_SSL, SO_SSL_VERIFY_HOSTNAME, ps->tls_host, strlen(ps->tls_host) + 1);
			}
		}
		return _dns_client_push_layer(gs, gsocket_io_socks5_new(ps->server, ps->port, user, pass), "socks5 proxy");
	}
	case PROXY_HTTP:
		return _dns_client_push_layer(gs, gsocket_io_httpproxy_new(ps->server, ps->port, user, pass), "http proxy");
	case PROXY_HTTPS: {
		SSL_CTX *ssl_ctx = _ssl_ctx_get(0);
		if (ssl_ctx == NULL) {
			return -1;
		}
		if (_dns_client_push_layer(gs, gsocket_io_ssl_new(ssl_ctx, 0), "proxy ssl") != 0) {
			return -1;
		}
		if (ps->skip_cert_verify) {
			int verify = 0;
			gsocket_setsockopt(gs, SOL_SSL, SO_SSL_VERIFY, &verify, sizeof(verify));
		}
		if (ps->tls_host[0] != '\0') {
			gsocket_setsockopt(gs, SOL_SSL, SO_SSL_SNI, ps->tls_host, strlen(ps->tls_host));
			if (!ps->skip_cert_verify) {
				gsocket_setsockopt(gs, SOL_SSL, SO_SSL_VERIFY_HOSTNAME, ps->tls_host, strlen(ps->tls_host) + 1);
			}
		}
		return _dns_client_push_layer(gs, gsocket_io_httpproxy_new(ps->server, ps->port, user, pass), "http proxy");
	}
	default:
		break;
	}

	return 0;
}

static int _dns_client_get_connect_target(struct dns_server_info *server_info, const char **host_out, int *port_out)
{
	*host_out = server_info->ip;
	*port_out = server_info->port;

	if (server_info->proxy_name[0] == '\0') {
		return 0;
	}

	struct dns_proxy_servers *ps = _dns_client_get_proxy_server(server_info);
	if (ps == NULL) {
		return 0;
	}

	if (ps->type == PROXY_PASSTHROUGH) {
		if (_dns_client_proxy_has_target_override(ps)) {
			*host_out = ps->server;
		}
		if (ps->port > 0) {
			*port_out = ps->port;
		}
	}

	return 0;
}

static void _dns_client_set_socket_opts(int fd, struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_TCP || server_info->type == DNS_SERVER_TLS ||
		server_info->type == DNS_SERVER_HTTPS) {
		int yes = 1;
		const int priority = SOCKET_PRIORITY;
		const int ip_tos = SOCKET_IP_TOS;

		setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &yes, sizeof(yes));
		set_sock_keepalive(fd, 30, 3, 5);
		setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
		setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	}

	if (server_info->so_mark >= 0) {
		unsigned int mark = (unsigned int)server_info->so_mark;
		setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	}

	if (server_info->flags.ifname[0] != '\0') {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		safe_strncpy(ifr.ifr_name, server_info->flags.ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
	}

	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(int));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(int));
	}
}

static void _dns_client_free_gsocket(struct gsocket **gs)
{
	if (gs == NULL || *gs == NULL) {
		return;
	}

	gsocket_close(*gs);
	gsocket_free(*gs);
	*gs = NULL;
}

static void _dns_client_socket_mark_disconnected(struct dns_server_info *server_info)
{
	server_info->gs = NULL;
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
	server_info->security_status = DNS_CLIENT_SERVER_SECURITY_UNKNOW;
}

static void _dns_client_socket_create_cleanup(struct dns_server_info *server_info, struct gsocket **gs, int *fd)
{
	if (gs != NULL && server_info->gs == *gs) {
		server_info->gs = NULL;
	}
	_dns_client_free_gsocket(gs);

	if (fd != NULL && *fd >= 0) {
		close(*fd);
		*fd = -1;
	}

	_dns_client_socket_mark_disconnected(server_info);
}

static void _dns_client_set_ssl_opts(struct gsocket *gs, struct dns_server_info *server_info, const char *hostname,
									 const char *alpn, dns_server_type_t server_type)
{
	const unsigned char *spki_data = NULL;
	int spki_len = 0;
	int has_spki_pin = 0;
	int disable_verify = 0;

	if (alpn && alpn[0]) {
		gsocket_setsockopt(gs, SOL_SSL, SO_SSL_ALPN, alpn, strlen(alpn) + 1);
	}

	switch (server_type) {
	case DNS_SERVER_HTTPS:
	case DNS_SERVER_HTTP3:
		spki_data = (const unsigned char *)server_info->flags.https.spki;
		spki_len = server_info->flags.https.spi_len;
		break;
	case DNS_SERVER_TLS:
	case DNS_SERVER_QUIC:
		spki_data = (const unsigned char *)server_info->flags.tls.spki;
		spki_len = server_info->flags.tls.spi_len;
		break;
	default:
		break;
	}
	if (spki_data != NULL && spki_len > 0) {
		has_spki_pin = 1;
		gsocket_setsockopt(gs, SOL_SSL, SO_SSL_SPKI, spki_data, spki_len);
	}

	disable_verify = (server_info->skip_check_cert || has_spki_pin);
	if (hostname == NULL || hostname[0] == '\0') {
		hostname = server_info->host;
	}
	if (hostname && hostname[0]) {
		gsocket_setsockopt(gs, SOL_SSL, SO_SSL_SNI, hostname, strlen(hostname) + 1);
		if (!disable_verify) {
			gsocket_setsockopt(gs, SOL_SSL, SO_SSL_VERIFY_HOSTNAME, hostname, strlen(hostname) + 1);
		}
	}

	if (disable_verify) {
		int skip = 0;
		gsocket_setsockopt(gs, SOL_SSL, SO_SSL_VERIFY, &skip, sizeof(skip));
	}
}

int _dns_client_create_socket_udp(struct dns_server_info *server_info)
{
	const int on = 1;
	const int val = 255;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	struct gsocket *gs = NULL;
	int fd = socket(server_info->ai_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create udp socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set udp socket non block failed, %s", strerror(errno));
		goto errout;
	}

	_dns_client_set_socket_opts(fd, server_info);

	if (connect(fd, &server_info->addr, server_info->ai_addrlen) != 0) {
		if (errno != EINPROGRESS) {
			tlog(TLOG_DEBUG, "connect udp %s failed, %s", server_info->ip, strerror(errno));
			goto errout;
		}
	}

	gs = gsocket_new(fd);
	if (gs == NULL) {
		goto errout;
	}

	setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	setsockopt(fd, SOL_IP, IP_TTL, &val, sizeof(val));
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (server_info->ai_family == AF_INET6) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof(on));
	}
	fd = -1;

	server_info->gs = gs;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	server_info->security_status = DNS_CLIENT_SERVER_SECURITY_NOT_APPLICABLE;

	if (gepoll_add(client.gepoll, gs, EPOLLIN, server_info) != 0) {
		tlog(TLOG_ERROR, "gepoll add udp failed.");
		goto errout;
	}

	return 0;

errout:
	_dns_client_socket_create_cleanup(server_info, &gs, &fd);
	return -1;
}

int _dns_client_create_socket_tcp(struct dns_server_info *server_info)
{
	struct gsocket *gs = NULL;
	int fd = socket(_dns_client_get_socket_family(server_info), SOCK_STREAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create tcp socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set tcp socket non block failed, %s", strerror(errno));
		goto errout;
	}

	_dns_client_set_socket_opts(fd, server_info);

	gs = gsocket_new(fd);
	if (gs == NULL) {
		goto errout;
	}
	fd = -1;

	if (server_info->tcp_keepalive > 0) {
		gsocket_set_keepalive(gs, server_info->tcp_keepalive, 3, 5);
	}

	if (_dns_client_push_proxy_layer(gs, server_info) != 0) {
		goto errout;
	}

	const char *connect_host;
	int connect_port;
	_dns_client_get_connect_target(server_info, &connect_host, &connect_port);

	if (gsocket_connect(gs, connect_host, connect_port) != 0 && errno != EINPROGRESS) {
		tlog(TLOG_DEBUG, "connect tcp %s failed, %s", connect_host, strerror(errno));
		goto errout;
	}

	server_info->gs = gs;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;

	if (gepoll_add(client.gepoll, gs, EPOLLIN | EPOLLOUT, server_info) != 0) {
		tlog(TLOG_ERROR, "gepoll add tcp failed.");
		goto errout;
	}

	return 0;

errout:
	_dns_client_socket_create_cleanup(server_info, &gs, &fd);
	return -1;
}

int _dns_client_create_socket_tls(struct dns_server_info *server_info, const char *hostname, const char *alpn)
{
	int fd = -1;
	struct gsocket *gs = NULL;
	SSL_CTX *ssl_ctx = _ssl_ctx_get(0);
	if (ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "get ssl ctx failed for %s", server_info->ip);
		goto errout;
	}

	fd = socket(_dns_client_get_socket_family(server_info), SOCK_STREAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create tls socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set tls socket non block failed, %s", strerror(errno));
		goto errout;
	}

	_dns_client_set_socket_opts(fd, server_info);

	gs = gsocket_new(fd);
	if (gs == NULL) {
		goto errout;
	}
	fd = -1;

	if (_dns_client_push_proxy_layer(gs, server_info) != 0) {
		goto errout;
	}

	const char *connect_host;
	int connect_port;
	_dns_client_get_connect_target(server_info, &connect_host, &connect_port);

	struct gsocket_io *ssl_io = gsocket_io_ssl_new(ssl_ctx, 0);
	if (_dns_client_push_layer(gs, ssl_io, "ssl") != 0) {
		goto errout;
	}

	_dns_client_set_ssl_opts(gs, server_info, hostname, alpn, server_info->type);

	if (server_info->type == DNS_SERVER_HTTPS) {
		struct gsocket_io *http2_io = gsocket_io_http2_new(0);
		if (_dns_client_push_layer(gs, http2_io, "http2") != 0) {
			goto errout;
		}
	}

	if (gsocket_connect(gs, connect_host, connect_port) != 0 && errno != EINPROGRESS) {
		tlog(TLOG_DEBUG, "connect tls %s failed, %s", connect_host, strerror(errno));
		goto errout;
	}

	server_info->gs = gs;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	if (gepoll_add(client.gepoll, gs, EPOLLIN | EPOLLOUT, server_info) != 0) {
		tlog(TLOG_ERROR, "gepoll add tls failed.");
		goto errout;
	}

	return 0;

errout:
	_dns_client_socket_create_cleanup(server_info, &gs, &fd);
	return -1;
}

int _dns_client_create_socket_quic(struct dns_server_info *server_info, const char *hostname, const char *alpn)
{
	int fd = -1;
	struct gsocket *gs = NULL;
	struct gstream_poll *sp = NULL;
	SSL_CTX *ssl_ctx = _ssl_ctx_get(1);
	if (ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "get quic ssl ctx failed for %s", server_info->ip);
		goto errout;
	}

	fd = socket(server_info->ai_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create quic socket failed, %s", strerror(errno));
		goto errout;
	}

	if (set_fd_nonblock(fd, 1) != 0) {
		tlog(TLOG_ERROR, "set quic socket non block failed, %s", strerror(errno));
		goto errout;
	}

	_dns_client_set_socket_opts(fd, server_info);

	gs = gsocket_new(fd);
	if (gs == NULL) {
		goto errout;
	}
	fd = -1;

	if (_dns_client_push_proxy_layer(gs, server_info) != 0) {
		goto errout;
	}

	struct gsocket_io *quic_io = gsocket_io_ssl_quic_new(ssl_ctx, 0);
	if (_dns_client_push_layer(gs, quic_io, "quic") != 0) {
		goto errout;
	}

	_dns_client_set_ssl_opts(gs, server_info, hostname, alpn, server_info->type);

	if (server_info->type == DNS_SERVER_HTTP3) {
		struct gsocket_io *http3_io = gsocket_io_http3_new(0);
		if (_dns_client_push_layer(gs, http3_io, "http3") != 0) {
			goto errout;
		}
	}

	const char *connect_host;
	int connect_port;
	_dns_client_get_connect_target(server_info, &connect_host, &connect_port);

	if (gsocket_connect(gs, connect_host, connect_port) != 0 && errno != EINPROGRESS) {
		tlog(TLOG_DEBUG, "connect quic %s failed, %s", connect_host, strerror(errno));
		goto errout;
	}

	sp = gstream_poll_create(gs);
	if (sp == NULL) {
		tlog(TLOG_ERROR, "create gstream_poll for %s failed", server_info->ip);
		goto errout;
	}

	server_info->gs = gs;
	server_info->sp = sp;
	server_info->status = DNS_SERVER_STATUS_CONNECTING;

	if (gepoll_add(client.gepoll, gs, EPOLLIN | EPOLLOUT, server_info) != 0) {
		tlog(TLOG_ERROR, "gepoll add quic failed.");
		goto errout;
	}

	return 0;

errout:
	if (server_info->sp == sp) {
		server_info->sp = NULL;
	}
	if (sp != NULL) {
		gstream_poll_destroy(sp);
	}
	_dns_client_socket_create_cleanup(server_info, &gs, &fd);
	return -1;
}
