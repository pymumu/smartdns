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

#include "server_gsocket_factory.h"

#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

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
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int _alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
						   unsigned int inlen, void *arg)
{
	(void)ssl;
	struct dns_bind_ip *bind_ip = (struct dns_bind_ip *)arg;
	const char *alpn = bind_ip->alpn;
	if (alpn == NULL || alpn[0] == '\0') {
		alpn = "h2,http/1.1";
	}

	char alpn_copy[256];
	safe_strncpy(alpn_copy, alpn, sizeof(alpn_copy));
	char *saveptr = NULL;
	char *proto = strtok_r(alpn_copy, ",", &saveptr);
	while (proto) {
		unsigned int proto_len = (unsigned int)strlen(proto);
		for (unsigned int i = 0; i < inlen;) {
			unsigned int len = in[i++];
			if (i + len > inlen) {
				break;
			}
			if (len == proto_len && memcmp(&in[i], proto, len) == 0) {
				*out = &in[i];
				*outlen = (unsigned char)len;
				return SSL_TLSEXT_ERR_OK;
			}
			i += len;
		}
		proto = strtok_r(NULL, ",", &saveptr);
	}
	return SSL_TLSEXT_ERR_NOACK;
}

static int _ssl_pass_callback(char *buf, int size, int rwflag, void *userdata)
{
	(void)rwflag;
	struct dns_bind_ip *bind_ip = (struct dns_bind_ip *)userdata;
	if (bind_ip->ssl_cert_key_pass == NULL || bind_ip->ssl_cert_key_pass[0] == '\0') {
		return 0;
	}
	safe_strncpy(buf, bind_ip->ssl_cert_key_pass, size);
	return (int)strlen(buf);
}

SSL_CTX *_dns_server_gsocket_create_ssl_ctx(struct dns_bind_ip *bind_ip, int is_quic, int is_http3)
{
	const char *ssl_cert_file = bind_ip->ssl_cert_file;
	const char *ssl_cert_key_file = bind_ip->ssl_cert_key_file;

	if (ssl_cert_file == NULL || ssl_cert_file[0] == '\0' || ssl_cert_key_file == NULL ||
		ssl_cert_key_file[0] == '\0') {
		tlog(TLOG_WARN, "bind %s: no cert or key file", bind_ip->ip);
		return NULL;
	}

	SSL_CTX *ssl_ctx = NULL;
	if (is_quic) {
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
		ssl_ctx = SSL_CTX_new(OSSL_QUIC_server_method());
#else
		tlog(TLOG_WARN, "QUIC not supported in this OpenSSL build");
		return NULL;
#endif
	} else {
		ssl_ctx = SSL_CTX_new(TLS_server_method());
	}

	if (ssl_ctx == NULL) {
		tlog(TLOG_ERROR, "SSL_CTX_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	SSL_CTX_set_session_cache_mode(ssl_ctx,
								   SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL | SSL_SESS_CACHE_NO_AUTO_CLEAR);
	SSL_CTX_set_default_passwd_cb(ssl_ctx, _ssl_pass_callback);
	SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, bind_ip);

	if (SSL_CTX_use_certificate_chain_file(ssl_ctx, ssl_cert_file) <= 0) {
		tlog(TLOG_ERROR, "load cert %s failed: %s", ssl_cert_file, ERR_error_string(ERR_get_error(), NULL));
		goto errout;
	}

	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, ssl_cert_key_file, SSL_FILETYPE_PEM) <= 0) {
		tlog(TLOG_ERROR, "load key %s failed: %s", ssl_cert_key_file, ERR_error_string(ERR_get_error(), NULL));
		goto errout;
	}

	if (!is_quic) {
		SSL_CTX_set_alpn_select_cb(ssl_ctx, _alpn_select_cb, bind_ip);
	} else {
		if (bind_ip->alpn[0] == '\0') {
			safe_strncpy(bind_ip->alpn, is_http3 ? "h3" : "doq", sizeof(bind_ip->alpn));
		}
		SSL_CTX_set_alpn_select_cb(ssl_ctx, _alpn_select_cb, bind_ip);
	}

	return ssl_ctx;

errout:
	SSL_CTX_free(ssl_ctx);
	return NULL;
}

int _dns_server_gsocket_create_socket(const char *host_ip, int type)
{
	char ip[MAX_IP_LEN];
	char host_ip_copy[MAX_IP_LEN * 2];
	int port = DEFAULT_DNS_PORT;
	const char *ifname = NULL;
	int fd = -1;
	int optval = 1;
	int yes = 1;
	const int priority = SOCKET_PRIORITY;
	const int ip_tos = SOCKET_IP_TOS;

	safe_strncpy(host_ip_copy, host_ip, sizeof(host_ip_copy));
	char *at = strstr(host_ip_copy, "@");
	if (at) {
		*at = '\0';
		ifname = at + 1;
	}

	ip[0] = '\0';
	if (parse_ip(host_ip_copy, ip, &port) != 0) {
		if (host_ip_copy[0] == ':' && host_ip_copy[1] != '\0') {
			port = atoi(host_ip_copy + 1);
			ip[0] = '\0';
		} else {
			safe_strncpy(ip, host_ip_copy, sizeof(ip));
		}
	}
	if (port <= 0) {
		port = DEFAULT_DNS_PORT;
	}

	struct addrinfo hints, *res = NULL;
	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(ip[0] ? ip : NULL, port_str, &hints, &res) != 0) {
		tlog(TLOG_ERROR, "getaddrinfo failed for %s", host_ip);
		return -1;
	}

	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		tlog(TLOG_ERROR, "socket() failed: %s", strerror(errno));
		goto errout;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
#ifdef SO_REUSEPORT
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
#endif

	if (type == SOCK_STREAM) {
		setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
	} else {
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(optval));
	}

	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
	setsockopt(fd, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
	if (dns_conf.dns_socket_buff_size > 0) {
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &dns_conf.dns_socket_buff_size, sizeof(dns_conf.dns_socket_buff_size));
	}

	if (ifname != NULL && ifname[0] != '\0') {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		safe_strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		ioctl(fd, SIOCGIFINDEX, &ifr);
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
			tlog(TLOG_ERROR, "bind device %s failed: %s", ifr.ifr_name, strerror(errno));
			goto errout;
		}
	}

	if (bind(fd, res->ai_addr, res->ai_addrlen) != 0) {
		tlog(TLOG_ERROR, "bind %s failed: %s", host_ip, strerror(errno));
		goto errout;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 256) != 0) {
			tlog(TLOG_ERROR, "listen failed: %s", strerror(errno));
			goto errout;
		}
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	freeaddrinfo(res);
	return fd;

errout:
	if (fd > 0) {
		close(fd);
	}
	if (res) {
		freeaddrinfo(res);
	}
	return -1;
}
