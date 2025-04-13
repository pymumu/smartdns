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

#include "server_info.h"
#include "client_tls.h"
#include "conn_stream.h"
#include "group.h"
#include "ecs.h"
#include "pending_server.h"

#include "smartdns/fast_ping.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <net/if.h>
#include <pthread.h>
#include <sys/epoll.h>

unsigned int dns_client_server_result_flag(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return 0;
	}

	return server_info->flags.result_flag;
}

const char *dns_client_get_server_ip(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return NULL;
	}

	return server_info->ip;
}

const char *dns_client_get_server_host(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return NULL;
	}

	return server_info->host;
}

int dns_client_get_server_port(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return 0;
	}

	return server_info->port;
}

static inline void _dns_server_inc_server_num(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_MDNS) {
		return;
	}

	atomic_inc(&client.dns_server_num);
}

static inline void _dns_server_dec_server_num(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_MDNS) {
		return;
	}

	atomic_dec(&client.dns_server_num);
}

void _dns_server_inc_prohibit_server_num(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_MDNS) {
		return;
	}

	atomic_inc(&client.dns_server_prohibit_num);
}

void _dns_server_dec_prohibit_server_num(struct dns_server_info *server_info)
{
	if (server_info->type == DNS_SERVER_MDNS) {
		return;
	}

	atomic_dec(&client.dns_server_prohibit_num);
}

dns_server_type_t dns_client_get_server_type(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return DNS_SERVER_TYPE_END;
	}

	return server_info->type;
}

struct dns_server_stats *dns_client_get_server_stats(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return NULL;
	}

	return &server_info->stats;
}

int dns_client_server_is_alive(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return 0;
	}

	return atomic_read(&server_info->is_alive);
}

static void _dns_client_server_free(struct dns_server_info *server_info)
{
	pthread_mutex_lock(&client.server_list_lock);
	if (!list_empty(&server_info->list)) {
		list_del_init(&server_info->list);
		_dns_server_dec_server_num(server_info);
	}
	pthread_mutex_unlock(&client.server_list_lock);

	list_del_init(&server_info->check_list);
	_dns_client_server_close(server_info);
	pthread_mutex_destroy(&server_info->lock);
	free(server_info);
}

void dns_client_server_info_get(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return;
	}

	atomic_inc(&server_info->refcnt);
}

void dns_client_server_info_release(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return;
	}

	int refcnt = atomic_dec_return(&server_info->refcnt);
	if (refcnt > 0) {
		return;
	}

	_dns_client_server_free(server_info);
}

static void _dns_client_server_info_remove(struct dns_server_info *server_info)
{
	if (server_info == NULL) {
		return;
	}

	pthread_mutex_lock(&client.server_list_lock);
	if (!list_empty(&server_info->list)) {
		list_del_init(&server_info->list);
		_dns_server_dec_server_num(server_info);
	}
	pthread_mutex_unlock(&client.server_list_lock);

	_dns_client_server_close(server_info);
	dns_client_server_info_release(server_info);
}

int dns_client_get_server_info_lists(struct dns_server_info **server_info, int max_server_num)
{
	struct dns_server_info *server = NULL;
	struct dns_server_info *tmp = NULL;
	int i = 0;

	if (server_info == NULL) {
		return -1;
	}

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server, tmp, &client.dns_server_list, list)
	{
		if (i >= max_server_num) {
			break;
		}

		server_info[i] = server;
		dns_client_server_info_get(server_info[i]);
		i++;
	}
	pthread_mutex_unlock(&client.server_list_lock);

	return i;
}

/* check whether server exists */
static int _dns_client_server_exist(const char *server_ip, int port, dns_server_type_t server_type,
									struct client_dns_server_flags *flags)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_info *tmp = NULL;
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->port != port || server_info->type != server_type) {
			continue;
		}

		if (memcmp(&server_info->flags, flags, sizeof(*flags)) != 0) {
			continue;
		}

		if (strncmp(server_info->ip, server_ip, DNS_HOSTNAME_LEN) != 0) {
			continue;
		}

		pthread_mutex_unlock(&client.server_list_lock);
		return 0;
	}

	pthread_mutex_unlock(&client.server_list_lock);
	return -1;
}

static void _dns_client_server_update_ttl(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
										  struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl,
										  struct timeval *tv, int error, void *userptr)
{
	struct dns_server_info *server_info = userptr;
	if (result != PING_RESULT_RESPONSE || server_info == NULL) {
		return;
	}

	double rtt = tv->tv_sec * 1000.0 + tv->tv_usec / 1000.0;
	tlog(TLOG_DEBUG, "from %s: seq=%d ttl=%d time=%.3f\n", host, seqno, ttl, rtt);
	server_info->ttl = ttl;
}

/* get server control block by ip and port, type */
struct dns_server_info *_dns_client_get_server(const char *server_ip, int port, dns_server_type_t server_type,
											   const struct client_dns_server_flags *flags)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_info *tmp = NULL;
	struct dns_server_info *server_info_return = NULL;

	if (server_ip == NULL) {
		return NULL;
	}

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->port != port || server_info->type != server_type) {
			continue;
		}

		if (strncmp(server_info->ip, server_ip, DNS_HOSTNAME_LEN) != 0) {
			continue;
		}

		if (memcmp(&server_info->flags, flags, sizeof(*flags)) != 0) {
			continue;
		}

		server_info_return = server_info;
		break;
	}

	pthread_mutex_unlock(&client.server_list_lock);

	return server_info_return;
}

/* add dns server information */
int _dns_client_server_add(const char *server_ip, const char *server_host, int port, dns_server_type_t server_type,
						   struct client_dns_server_flags *flags)
{
	struct dns_server_info *server_info = NULL;
	struct addrinfo *gai = NULL;
	int spki_data_len = 0;
	int ttl = 0;
	char port_s[8];
	int sock_type = 0;
	char skip_check_cert = 0;
	char ifname[IFNAMSIZ * 2] = {0};
	char default_is_alive = 0;

	switch (server_type) {
	case DNS_SERVER_UDP: {
		struct client_dns_server_flag_udp *flag_udp = &flags->udp;
		ttl = flag_udp->ttl;
		if (ttl > 255) {
			ttl = 255;
		} else if (ttl < -32) {
			ttl = -32;
		}

		sock_type = SOCK_DGRAM;
	} break;
	case DNS_SERVER_HTTP3: {
		struct client_dns_server_flag_https *flag_https = &flags->https;
		spki_data_len = flag_https->spi_len;
		if (flag_https->httphost[0] == 0) {
			if (server_host) {
				safe_strncpy(flag_https->httphost, server_host, DNS_MAX_CNAME_LEN);
			} else {
				set_http_host(server_ip, port, DEFAULT_DNS_HTTPS_PORT, flag_https->httphost);
			}
		}
		sock_type = SOCK_DGRAM;
		skip_check_cert = flag_https->skip_check_cert;
	} break;
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_https = &flags->https;
		spki_data_len = flag_https->spi_len;
		if (flag_https->httphost[0] == 0) {
			if (server_host) {
				safe_strncpy(flag_https->httphost, server_host, DNS_MAX_CNAME_LEN);
			} else {
				set_http_host(server_ip, port, DEFAULT_DNS_HTTPS_PORT, flag_https->httphost);
			}
		}
		sock_type = SOCK_STREAM;
		skip_check_cert = flag_https->skip_check_cert;
	} break;
	case DNS_SERVER_QUIC: {
		struct client_dns_server_flag_tls *flag_tls = &flags->tls;
		spki_data_len = flag_tls->spi_len;
		sock_type = SOCK_DGRAM;
		skip_check_cert = flag_tls->skip_check_cert;
	} break;
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &flags->tls;
		spki_data_len = flag_tls->spi_len;
		sock_type = SOCK_STREAM;
		skip_check_cert = flag_tls->skip_check_cert;
	} break;
	case DNS_SERVER_TCP:
		sock_type = SOCK_STREAM;
		break;
	case DNS_SERVER_MDNS: {
		if (flags->ifname[0] == '\0') {
			tlog(TLOG_ERROR, "mdns server must set ifname.");
			return -1;
		}
		sock_type = SOCK_DGRAM;
		default_is_alive = 1;
	} break;
	default:
		return -1;
		break;
	}

	if (spki_data_len > DNS_SERVER_SPKI_LEN) {
		tlog(TLOG_ERROR, "spki data length is invalid.");
		return -1;
	}

	/* if server exist, return */
	if (_dns_client_server_exist(server_ip, port, server_type, flags) == 0) {
		return 0;
	}

	snprintf(port_s, sizeof(port_s), "%d", port);
	gai = _dns_client_getaddr(server_ip, port_s, sock_type, 0);
	if (gai == NULL) {
		tlog(TLOG_DEBUG, "get address failed, %s:%d", server_ip, port);
		goto errout;
	}

	server_info = malloc(sizeof(*server_info));
	if (server_info == NULL) {
		goto errout;
	}

	if (server_type != DNS_SERVER_UDP) {
		flags->result_flag &= (~DNSSERVER_FLAG_CHECK_TTL);
	}

	memset(server_info, 0, sizeof(*server_info));
	safe_strncpy(server_info->ip, server_ip, sizeof(server_info->ip));
	server_info->port = port;
	server_info->ai_family = gai->ai_family;
	server_info->ai_addrlen = gai->ai_addrlen;
	server_info->type = server_type;
	server_info->fd = 0;
	server_info->status = DNS_SERVER_STATUS_INIT;
	server_info->ttl = ttl;
	server_info->ttl_range = 0;
	server_info->skip_check_cert = skip_check_cert;
	server_info->prohibit = 0;
	server_info->so_mark = flags->set_mark;
	server_info->drop_packet_latency_ms = flags->drop_packet_latency_ms;
	atomic_set(&server_info->refcnt, 0);
	atomic_set(&server_info->is_alive, default_is_alive);
	INIT_LIST_HEAD(&server_info->check_list);
	INIT_LIST_HEAD(&server_info->list);
	safe_strncpy(server_info->proxy_name, flags->proxyname, sizeof(server_info->proxy_name));
	if (server_host && server_host[0]) {
		safe_strncpy(server_info->host, server_host, sizeof(server_info->host));
	} else {
		safe_strncpy(server_info->host, server_ip, sizeof(server_info->host));
	}

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&server_info->lock, &attr);
	pthread_mutexattr_destroy(&attr);

	memcpy(&server_info->flags, flags, sizeof(server_info->flags));
	INIT_LIST_HEAD(&server_info->list);
	INIT_LIST_HEAD(&server_info->conn_stream_list);

	if (_dns_client_server_add_ecs(server_info, flags) != 0) {
		tlog(TLOG_ERROR, "add %s ecs failed.", server_ip);
		goto errout;
	}

	/* exclude this server from default group */
	if ((server_info->flags.server_flag & SERVER_FLAG_EXCLUDE_DEFAULT) == 0) {
		if (_dns_client_add_to_group(DNS_SERVER_GROUP_DEFAULT, server_info) != 0) {
			tlog(TLOG_ERROR, "add server %s to default group failed.", server_ip);
			goto errout;
		}
	}

	/* if server type is TLS, create ssl context */
	if (server_type == DNS_SERVER_TLS || server_type == DNS_SERVER_HTTPS || server_type == DNS_SERVER_QUIC ||
		server_type == DNS_SERVER_HTTP3) {
		if (server_type == DNS_SERVER_QUIC || server_type == DNS_SERVER_HTTP3) {
			server_info->ssl_ctx = _ssl_ctx_get(1);
		} else {
			server_info->ssl_ctx = _ssl_ctx_get(0);
		}
		if (server_info->ssl_ctx == NULL) {
			tlog(TLOG_ERROR, "init ssl failed.");
			goto errout;
		}

		if (client.ssl_verify_skip) {
			server_info->skip_check_cert = 1;
		}
	}

	/* safe address info */
	if (gai->ai_addrlen > sizeof(server_info->in6)) {
		tlog(TLOG_ERROR, "addr len invalid, %d, %zd, %d", gai->ai_addrlen, sizeof(server_info->addr),
			 server_info->ai_family);
		goto errout;
	}
	memcpy(&server_info->addr, gai->ai_addr, gai->ai_addrlen);

	/* start ping task */
	if (server_type == DNS_SERVER_UDP) {
		if (ttl <= 0 && (server_info->flags.result_flag & DNSSERVER_FLAG_CHECK_TTL)) {
			server_info->ping_host =
				fast_ping_start(PING_TYPE_DNS, server_ip, 0, 60000, 1000, _dns_client_server_update_ttl, server_info);
			if (server_info->ping_host == NULL) {
				tlog(TLOG_ERROR, "start ping failed.");
				goto errout;
			}

			if (ttl < 0) {
				server_info->ttl_range = -ttl;
			}
		}
	}

	/* add to list */
	pthread_mutex_lock(&client.server_list_lock);
	list_add(&server_info->list, &client.dns_server_list);
	dns_client_server_info_get(server_info);
	pthread_mutex_unlock(&client.server_list_lock);

	_dns_server_inc_server_num(server_info);
	freeaddrinfo(gai);

	if (flags->ifname[0]) {
		snprintf(ifname, sizeof(ifname), "@%s", flags->ifname);
	}

	tlog(TLOG_INFO, "add server %s:%d%s, type: %s", server_ip, port, ifname,
		 _dns_server_get_type_string(server_info->type));

	return 0;
errout:
	if (server_info) {
		if (server_info->ping_host) {
			fast_ping_stop(server_info->ping_host);
		}

		pthread_mutex_destroy(&server_info->lock);
		free(server_info);
	}

	if (gai) {
		freeaddrinfo(gai);
	}

	return -1;
}

const char *_dns_server_get_type_string(dns_server_type_t type)
{
	const char *type_str = "";

	switch (type) {
	case DNS_SERVER_UDP:
		type_str = "udp";
		break;
	case DNS_SERVER_TCP:
		type_str = "tcp";
		break;
	case DNS_SERVER_TLS:
		type_str = "tls";
		break;
	case DNS_SERVER_HTTPS:
		type_str = "https";
		break;
	case DNS_SERVER_MDNS:
		type_str = "mdns";
		break;
	case DNS_SERVER_HTTP3:
		type_str = "http3";
		break;
	case DNS_SERVER_QUIC:
		type_str = "quic";
		break;
	default:
		break;
	}

	return type_str;
}

void _dns_client_close_socket_ext(struct dns_server_info *server_info, int no_del_conn_list)
{
	if (server_info->fd <= 0) {
		return;
	}

	if (server_info->ssl) {
		/* Shutdown ssl */
		if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
			_ssl_shutdown(server_info);
		}

		if (server_info->type == DNS_SERVER_QUIC || server_info->type == DNS_SERVER_HTTP3) {
			struct dns_conn_stream *conn_stream = NULL;
			struct dns_conn_stream *tmp = NULL;

			pthread_mutex_lock(&server_info->lock);
			list_for_each_entry_safe(conn_stream, tmp, &server_info->conn_stream_list, server_list)
			{
				if (conn_stream->quic_stream) {
#ifdef OSSL_QUIC1_VERSION
					SSL_stream_reset(conn_stream->quic_stream, NULL, 0);
#endif
					SSL_free(conn_stream->quic_stream);
					conn_stream->quic_stream = NULL;
				}

				if (no_del_conn_list == 1) {
					continue;
				}

				conn_stream->server_info = NULL;
				list_del_init(&conn_stream->server_list);
				_dns_client_conn_stream_put(conn_stream);
			}

			pthread_mutex_unlock(&server_info->lock);
		}

		SSL_free(server_info->ssl);
		server_info->ssl = NULL;
		server_info->ssl_write_len = -1;
	}

	if (server_info->bio_method) {
		BIO_meth_free(server_info->bio_method);
		server_info->bio_method = NULL;
	}

	/* remove fd from epoll */
	if (server_info->fd > 0) {
		epoll_ctl(client.epoll_fd, EPOLL_CTL_DEL, server_info->fd, NULL);
	}

	if (server_info->proxy) {
		proxy_conn_free(server_info->proxy);
		server_info->proxy = NULL;
	} else {
		close(server_info->fd);
	}

	server_info->fd = -1;
	server_info->status = DNS_SERVER_STATUS_DISCONNECTED;
	/* update send recv time */
	time(&server_info->last_send);
	time(&server_info->last_recv);
	tlog(TLOG_DEBUG, "server %s:%d closed.", server_info->ip, server_info->port);
}

void _dns_client_close_socket(struct dns_server_info *server_info)
{
	_dns_client_close_socket_ext(server_info, 0);
}

void _dns_client_shutdown_socket(struct dns_server_info *server_info)
{
	if (server_info->fd <= 0) {
		return;
	}

	switch (server_info->type) {
	case DNS_SERVER_UDP:
		server_info->status = DNS_SERVER_STATUS_CONNECTING;
		atomic_set(&server_info->is_alive, 0);
		return;
		break;
	case DNS_SERVER_TCP:
		if (server_info->fd > 0) {
			shutdown(server_info->fd, SHUT_RDWR);
		}
		break;
	case DNS_SERVER_QUIC:
	case DNS_SERVER_TLS:
	case DNS_SERVER_HTTP3:
	case DNS_SERVER_HTTPS:
		if (server_info->ssl) {
			/* Shutdown ssl */
			if (server_info->status == DNS_SERVER_STATUS_CONNECTED) {
				_ssl_shutdown(server_info);
			}
			shutdown(server_info->fd, SHUT_RDWR);
		}
		atomic_set(&server_info->is_alive, 0);
		break;
	case DNS_SERVER_MDNS:
		break;
	default:
		break;
	}
}

void _dns_client_server_close(struct dns_server_info *server_info)
{
	/* stop ping task */
	if (server_info->ping_host) {
		if (fast_ping_stop(server_info->ping_host) != 0) {
			tlog(TLOG_ERROR, "stop ping failed.\n");
		}

		server_info->ping_host = NULL;
	}

	_dns_client_close_socket(server_info);

	if (server_info->ssl_session) {
		SSL_SESSION_free(server_info->ssl_session);
		server_info->ssl_session = NULL;
	}

	server_info->ssl_ctx = NULL;
}

/* remove all servers information */
void _dns_client_server_remove_all(void)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_info *tmp = NULL;
	LIST_HEAD(free_list);

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		list_add(&server_info->check_list, &free_list);
		dns_client_server_info_get(server_info);
	}
	pthread_mutex_unlock(&client.server_list_lock);

	list_for_each_entry_safe(server_info, tmp, &free_list, check_list)
	{
		list_del_init(&server_info->check_list);
		_dns_client_server_info_remove(server_info);
		dns_client_server_info_release(server_info);
	}
}

/* remove single server */
static int _dns_client_server_remove(const char *server_ip, int port, dns_server_type_t server_type)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_info *tmp = NULL;
	LIST_HEAD(free_list);

	/* find server and remove */
	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		if (server_info->port != port || server_info->type != server_type) {
			continue;
		}

		if (strncmp(server_info->ip, server_ip, DNS_HOSTNAME_LEN) != 0) {
			continue;
		}

		list_add(&server_info->check_list, &free_list);
		dns_client_server_info_get(server_info);
		return 0;
	}
	pthread_mutex_unlock(&client.server_list_lock);

	list_for_each_entry_safe(server_info, tmp, &free_list, check_list)
	{
		list_del_init(&server_info->check_list);
		_dns_client_remove_server_from_groups(server_info);
		_dns_client_server_info_remove(server_info);
		dns_client_server_info_release(server_info);
	}

	return -1;
}

void _dns_client_check_servers(void)
{
	struct dns_server_info *server_info = NULL;
	struct dns_server_info *tmp = NULL;
	static unsigned int second_count = 0;

	second_count++;
	if (second_count % 10 != 0) {
		return;
	}

	pthread_mutex_lock(&client.server_list_lock);
	list_for_each_entry_safe(server_info, tmp, &client.dns_server_list, list)
	{
		dns_stats_server_stats_avg_time_update(&server_info->stats);
		if (server_info->type != DNS_SERVER_UDP) {
			continue;
		}

		if (server_info->last_send - 600 > server_info->last_recv) {
			server_info->recv_buff.len = 0;
			server_info->send_buff.len = 0;
			tlog(TLOG_DEBUG, "server %s may failure.", server_info->ip);
			_dns_client_close_socket(server_info);
		}
	}
	pthread_mutex_unlock(&client.server_list_lock);
}

int dns_client_add_server(const char *server_ip, int port, dns_server_type_t server_type,
						  struct client_dns_server_flags *flags)
{
	return _dns_client_add_server_pending(server_ip, NULL, port, server_type, flags, 1);
}

int dns_client_remove_server(const char *server_ip, int port, dns_server_type_t server_type)
{
	return _dns_client_server_remove(server_ip, port, server_type);
}

int dns_server_num(void)
{
	return atomic_read(&client.dns_server_num);
}

int dns_server_alive_num(void)
{
	return atomic_read(&client.dns_server_num) - atomic_read(&client.dns_server_prohibit_num);
}
