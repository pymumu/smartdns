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
 *************************************************************************/

#define _GNU_SOURCE
#include "smartdns/proxy_server.h"
#include "firewall.h"
#include "smartdns/dns_conf.h"
#include "smartdns/dns_server.h"
#include "smartdns/lib/gepoll.h"
#include "smartdns/lib/gsocket.h"
#include "smartdns/proxy.h"
#include "smartdns/smartdns.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"
#include "smartdns/lib/jhash.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#define PROXY_UDP_IDLE_TIMEOUT 60
#define PROXY_BUF_INIT (64 * 1024)
#define PROXY_BUF_MAX (1024 * 1024)
#define PROXY_WORKER_BUF_SIZE (128 * 1024)

enum proxy_conn_state_local {
	PSTATE_HANDSHAKE = 0,
	PSTATE_GET_TARGET,
	PSTATE_RESOLVE,
	PSTATE_RESOLVING,
	PSTATE_CONNECTING,
	PSTATE_REMOTE_HANDSHAKE,
	PSTATE_PIPE,
	PSTATE_CLOSE
};

#define PROXY_MAGIC 0x50525859
enum proxy_type_id { PROXY_TYPE_LISTENER = 1, PROXY_TYPE_CONN };
enum listener_type { LISTENER_TPROXY, LISTENER_SNIPROXY, LISTENER_SOCKS5, LISTENER_HTTP, LISTENER_FORWARD };

struct proxy_common_head {
	uint32_t magic;
	enum proxy_type_id type;
};

struct proxy_conn;

struct relay_gsock {
	struct proxy_common_head head; /* Must be first */
	struct gsocket *gs;
	struct proxy_conn *conn;
	int is_remote;
	char *buf;
	int buf_len;
	int buf_size;
	int read_paused;
};

struct proxy_conn {
	struct list_head node;
	struct relay_gsock client;
	struct relay_gsock remote;
	struct gsocket_address target;
	time_t last_active;
	enum proxy_conn_state_local state;
	enum listener_type type;
	char proxy_name[PROXY_NAME_LEN];
	char group_name[PROXY_NAME_LEN];
	int remote_dns;
	int so_mark;
	int target_ssl;
	int closing;
	struct proxy_worker *worker;
	char client_ip[DNS_MAX_IPLEN];
	int client_port;
	char tls_host[DNS_MAX_CNAME_LEN];
	time_t connect_start;
	int is_udp;
	struct sockaddr_storage client_addr;
	struct sockaddr_storage target_addr;
	struct gsocket *remote_udp_gs;
	struct hlist_node h_node;
	int skip_cert_verify;
	int force_aaaa_soa;
	char proxy_server[DNS_MAX_IPLEN];
	int ref_count;
};

struct proxy_listener {
	struct proxy_common_head head; /* Must be first */
	struct list_head node;
	struct gsocket *gs;
	SSL_CTX *ssl_ctx;
	enum listener_type type;
	char name[PROXY_NAME_LEN];
	char proxy_name[PROXY_NAME_LEN];
	char group_name[PROXY_NAME_LEN];
	int remote_dns;
	int so_mark;
	int target_ssl;
	struct gsocket_address forward_target;
	char tls_host[DNS_MAX_CNAME_LEN];
	struct proxy_worker *worker;
	int is_udp;
	int skip_cert_verify;
	int force_aaaa_soa;
	int target_port;
	char proxy_server[DNS_MAX_IPLEN];
};

struct proxy_worker {
	struct gepoll *gepoll;
	struct list_head listeners;
	struct list_head conns;
	struct list_head connecting_conns;
	struct list_head closing_conns;
	struct list_head conn_pool;
	DECLARE_HASHTABLE(udp_sessions, 8);
	time_t last_cleanup_time;
	pthread_mutex_t lock;
	pthread_t tid;
	int id;
	char *io_buf;
	time_t now;
	int wakeup_fd;
	struct gsocket *gs_wakeup;
};

struct proxy_server_ctx {
	struct proxy_worker *workers;
	int worker_num;
	int run;
	SSL_CTX *ssl_srv_ctx;
	SSL_CTX *ssl_cli_ctx;
};

static struct proxy_server_ctx g_proxy_ctx;
static int is_proxy_server_init = 0;

static int get_addr_from_string(const char *host, struct sockaddr_storage *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

	if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
		ss->ss_family = AF_INET;
		return 0;
	}
	if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
		ss->ss_family = AF_INET6;
		return 0;
	}
	return -1;
}

/* --- Firewall Helpers --- */

static void _proxy_conn_setup_remote_udp_gs(struct proxy_worker *worker, struct proxy_conn *conn);

static int _proxy_server_setup_firewall_rules(void)
{
	struct dns_tproxy_server_conf *t_conf = NULL;
	unsigned long idx;
	hash_for_each(dns_proxy_table.tproxy, idx, t_conf, node)
	{
		if (firewall_setup_rules(t_conf) != 0) {
			return -1;
		}
	}
	return 0;
}

static void _proxy_server_cleanup_firewall_rules(void)
{
	struct dns_tproxy_server_conf *t_conf = NULL;
	unsigned long idx;
	hash_for_each(dns_proxy_table.tproxy, idx, t_conf, node)
	{
		firewall_cleanup_rules(t_conf);
	}
}

int tproxy_server_get_firewall_sets(const char *proxy_name, struct firewall_sets *sets)
{
	struct dns_tproxy_server_conf *t_conf;
	if (!proxy_name || !sets) {
		return -1;
	}
	memset(sets, 0, sizeof(*sets));
	t_conf = dns_conf_get_tproxy_server(proxy_name);
	if (!t_conf || t_conf->firewall_type == FIREWALL_NONE) {
		return -1;
	}

	if (t_conf->firewall_type == FIREWALL_NFTABLES) {
		if (t_conf->nftset_names.ip_enable) {
			sets->nftset_ipv4 = &t_conf->nftset_names.ip;
		}
		if (t_conf->nftset_names.ip6_enable) {
			sets->nftset_ipv6 = &t_conf->nftset_names.ip6;
		}
	} else if (t_conf->firewall_type == FIREWALL_IPTABLES || t_conf->firewall_type == FIREWALL_IPTABLES_REDIRECT ||
			   t_conf->firewall_type == FIREWALL_IPTABLES_TPROXY) {
		if (t_conf->ipset_names.ipv4_enable) {
			sets->ipset_ipv4 = &t_conf->ipset_names.ipv4;
		}
		if (t_conf->ipset_names.ipv6_enable) {
			sets->ipset_ipv6 = &t_conf->ipset_names.ipv6;
		}
	} else {
		return -1;
	}
	return 0;
}

const char *tproxy_server_get_group_name(const char *proxy_name)
{
	struct dns_tproxy_server_conf *t_conf = dns_conf_get_tproxy_server(proxy_name);
	if (t_conf) {
		return t_conf->group_name;
	}
	return NULL;
}

const char *sniproxy_server_get_group_name(const char *proxy_name)
{
	struct dns_sniproxy_server_conf *s_conf = dns_conf_get_sniproxy_server(proxy_name);
	if (s_conf) {
		return s_conf->group_name;
	}
	return NULL;
}

/* --- Core Helpers --- */

static void _proxy_optimize_gsocket(struct gsocket *gs, int is_listener)
{
	if (!gs) {
		return;
	}

	const int yes = 1;
	gsocket_setsockopt(gs, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

#ifdef IPTOS_LOWDELAY
	const int ip_tos = IPTOS_LOWDELAY | IPTOS_RELIABILITY;
	gsocket_setsockopt(gs, IPPROTO_IP, IP_TOS, &ip_tos, sizeof(ip_tos));
#endif

#ifdef TCP_THIN_DUPACK
	gsocket_setsockopt(gs, IPPROTO_TCP, TCP_THIN_DUPACK, &yes, sizeof(yes));
#endif
#ifdef TCP_THIN_LINEAR_TIMEOUTS
	gsocket_setsockopt(gs, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, &yes, sizeof(yes));
#endif

	gsocket_set_keepalive(gs, 30, 3, 5);
	gsocket_set_fastopen(gs, 1);
	if (!is_listener) {
		gsocket_set_quickack(gs, 1);
	}
}

static struct proxy_conn *__proxy_conn_get(struct proxy_worker *worker)
{
	struct proxy_conn *conn = NULL;
	if (!list_empty(&worker->conn_pool)) {
		conn = list_first_entry(&worker->conn_pool, struct proxy_conn, node);
		list_del(&conn->node);
	}

	if (conn == NULL) {
		conn = zalloc(1, sizeof(*conn));
	} else {
		void *old_buf_c = conn->client.buf;
		void *old_buf_r = conn->remote.buf;
		int old_size_c = conn->client.buf_size;
		int old_size_r = conn->remote.buf_size;
		memset(conn, 0, sizeof(*conn));
		conn->client.buf = old_buf_c;
		conn->remote.buf = old_buf_r;
		conn->client.buf_size = old_size_c;
		conn->remote.buf_size = old_size_r;
	}

	if (conn) {
		conn->worker = worker;
		conn->ref_count = 1;
	}
	return conn;
}


static void __proxy_conn_put(struct proxy_worker *worker, struct proxy_conn *conn)
{
	if (!conn) {
		return;
	}

	conn->ref_count--;
	if (conn->ref_count > 0) {
		return; /* Still referenced by async callbacks */
	}

	if (worker) {
		list_add(&conn->node, &worker->conn_pool);
	} else {
		if (conn->client.buf) {
			free(conn->client.buf);
		}
		if (conn->remote.buf) {
			free(conn->remote.buf);
		}
		free(conn);
	}
}


static void _proxy_conn_pool_clear(struct proxy_worker *worker)
{
	struct proxy_conn *pc, *ptmp;
	pthread_mutex_lock(&worker->lock);
	list_for_each_entry_safe(pc, ptmp, &worker->conn_pool, node)
	{
		list_del(&pc->node);
		__proxy_conn_put(NULL, pc);
	}
	pthread_mutex_unlock(&worker->lock);
}

static void __proxy_conn_free(struct proxy_conn *conn)
{
	if (!conn) {
		return;
	}

	if (conn->ref_count > 1) {
		/* Still referenced by async callbacks, delay closure */
		return;
	}

	struct proxy_worker *worker = conn->worker;

	if (conn->client.gs) {
		if (worker) {
			gepoll_del(worker->gepoll, conn->client.gs);
		}
		gsocket_close(conn->client.gs);
		gsocket_free(conn->client.gs);
		conn->client.gs = NULL;
	}
	if (conn->remote.gs) {
		if (worker) {
			gepoll_del(worker->gepoll, conn->remote.gs);
		}
		gsocket_close(conn->remote.gs);
		gsocket_free(conn->remote.gs);
		conn->remote.gs = NULL;
	}
	
	if (conn->remote_udp_gs) {
		if (worker) {
			gepoll_del(worker->gepoll, conn->remote_udp_gs);
		}
		gsocket_close(conn->remote_udp_gs);
		gsocket_free(conn->remote_udp_gs);
		conn->remote_udp_gs = NULL;
	}

	if (conn->is_udp) {
		hash_del(&conn->h_node);
	}

	__proxy_conn_put(worker, conn);
}

static void _proxy_conn_set_closing(struct proxy_conn *conn)
{
	if (!conn || conn->closing) {
		return;
	}
	conn->closing = 1;
	list_move_tail(&conn->node, &conn->worker->closing_conns);
}

static struct gsocket *_create_gsocket_listener(const char *host, int port, int type, int reuseport, int is_tproxy)
{
	int fd = socket(AF_INET, type, 0);
	if (fd < 0) {
		return NULL;
	}

	struct gsocket *gs = gsocket_new(fd);
	if (!gs) {
		close(fd);
		return NULL;
	}

	gsocket_set_reuseaddr(gs, 1);
	if (reuseport) {
		gsocket_set_reuseport(gs, 1);
	}

	if (is_tproxy) {
		int opt = 1;
		setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
		setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt));
#ifdef AF_INET6
		setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &opt, sizeof(opt));
		setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &opt, sizeof(opt));
#endif
	}

	gsocket_set_defer_accept(gs, 1);

	_proxy_optimize_gsocket(gs, 1);

	char ip[DNS_MAX_IPLEN] = {0};
	if (port == 0) {
		parse_ip(host, ip, &port);
	} else {
		safe_strncpy(ip, host, sizeof(ip));
	}

	const char *bind_ip = (ip[0] == '\0') ? NULL : ip;
	if (gsocket_bind(gs, bind_ip, port) != 0) {
		gsocket_close(gs);
		gsocket_free(gs);
		return NULL;
	}

	if (type == SOCK_STREAM) {
		gsocket_listen(gs, 128);
	}
	gsocket_set_nonblock(gs, 1);
	return gs;
}

struct listener_args {
	struct gsocket *gs;
	struct gsocket_io *proto_layer;
	SSL_CTX *ssl_ctx;
	enum listener_type type;
	const char *type_name;
	char name[PROXY_NAME_LEN];
	const char *proxy_server;
	const char *proxy_name;
	const char *group_name;
	int remote_dns;
	int so_mark;
	int target_ssl;
	const char *tls_host;
	const char *forward_target;
	struct proxy_worker *worker;
	int is_udp;
	int skip_cert_verify;
	int force_aaaa_soa;
	int target_port;
};

static int _add_listener(struct listener_args *args)
{
	if (!args->gs) {
		tlog(TLOG_ERROR, "%s: create proxy listener %s failed", args->type_name, args->proxy_server);
		return -1;
	}

	if (args->worker->id == 0) {
		tlog(TLOG_INFO, "proxy-server %s, type: %s, name: %s, proxy_name: %s, ssl: %s", args->proxy_server,
			 args->type_name, args->name,
			 (!args->proxy_name || args->proxy_name[0] == '\0') ? "default" : args->proxy_name,
			 args->ssl_ctx ? "yes" : "no");
	}

	if (args->so_mark > 0) {
		gsocket_set_mark(args->gs, args->so_mark);
	}

	if (args->ssl_ctx) {
		gsocket_push_layer(args->gs, gsocket_io_ssl_new(args->ssl_ctx, 1));
	}
	if (args->proto_layer) {
		gsocket_push_layer(args->gs, args->proto_layer);
	}

	struct proxy_listener *l = zalloc(1, sizeof(*l));
	if (!l) {
		tlog(TLOG_ERROR, "zalloc for proxy listener failed");
		return -1;
	}
	l->head.magic = PROXY_MAGIC;
	l->head.type = PROXY_TYPE_LISTENER;
	l->gs = args->gs;
	l->ssl_ctx = args->ssl_ctx;
	l->type = args->type;
	safe_strncpy(l->name, args->name, sizeof(l->name));
	l->target_ssl = args->target_ssl;
	l->is_udp = args->is_udp;
	l->skip_cert_verify = args->skip_cert_verify;
	l->force_aaaa_soa = args->force_aaaa_soa;
	l->target_port = args->target_port;
	safe_strncpy(l->proxy_name, args->proxy_name, sizeof(l->proxy_name));
	if (args->group_name) {
		safe_strncpy(l->group_name, args->group_name, sizeof(l->group_name));
	}
	safe_strncpy(l->proxy_server, args->proxy_server, sizeof(l->proxy_server));
	l->remote_dns = args->remote_dns;
	l->so_mark = args->so_mark;
	l->target_ssl = args->target_ssl;
	if (args->tls_host) {
		safe_strncpy(l->tls_host, args->tls_host, sizeof(l->tls_host));
	}
	l->worker = args->worker;
	if (args->forward_target) {
		char ip[DNS_MAX_IPLEN] = {0};
		int port = 0;
		parse_ip(args->forward_target, ip, &port);
		safe_strncpy(l->forward_target.host, ip, sizeof(l->forward_target.host));
		if (port == PORT_NOT_DEFINED) {
			char listen_ip[DNS_MAX_IPLEN] = {0};
			int listen_port = 0;
			parse_ip(args->proxy_server, listen_ip, &listen_port);
			l->forward_target.port = listen_port;
		} else {
			l->forward_target.port = port;
		}
	}
	l->is_udp = args->is_udp;

	pthread_mutex_lock(&l->worker->lock);
	list_add_tail(&l->node, &l->worker->listeners);
	if (gepoll_add(l->worker->gepoll, args->gs, EPOLLIN, l) != 0) {
		tlog(TLOG_ERROR, "%s: gepoll add failed for proxy listener %s", args->type_name, args->proxy_server);
		list_del(&l->node);
		pthread_mutex_unlock(&l->worker->lock);
		free(l);
		return -1;
	}
	pthread_mutex_unlock(&l->worker->lock);
	return 0;
}

/* --- Relay logic --- */

static int _proxy_flush_buffer(struct relay_gsock *src, struct relay_gsock *dst)
{
	if (dst->buf_len == 0) {
		return 0;
	}

	ssize_t n = gsocket_send(dst->gs, dst->buf, dst->buf_len, MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 1;
		}
		_proxy_conn_set_closing(dst->conn);
		return -1;
	}

	if (n < dst->buf_len) {
		memmove(dst->buf, dst->buf + n, dst->buf_len - n);
		dst->buf_len -= n;
		return 1;
	}

	dst->buf_len = 0;
	if (src->read_paused) {
		src->read_paused = 0;
		gepoll_mod(src->conn->worker->gepoll, src->gs, EPOLLIN, src);
	}
	gepoll_mod(dst->conn->worker->gepoll, dst->gs, EPOLLIN, dst); /* Stop waiting for OUT */
	return 0;
}

static void _proxy_relay_data(struct relay_gsock *src, struct relay_gsock *dst, int caller_locked)
{
	struct proxy_worker *worker = src->conn->worker;
	if (dst->buf_len > 0) {
		if (_proxy_flush_buffer(src, dst) != 0) {
			return;
		}
	}

	ssize_t n;
	int received = 0;
	struct gsocket *read_gs = src->gs;
	
	if (src->is_remote && src->conn->is_udp && src->conn->remote_udp_gs) {
		read_gs = src->conn->remote_udp_gs;
	}

	int loops = 0;
	while (loops < 16 && (n = gsocket_recv(read_gs, worker->io_buf, PROXY_WORKER_BUF_SIZE, 0)) > 0) {
		loops++;
		if (!received) {
			gsocket_set_quickack(read_gs, 1);
			received = 1;
		}

		ssize_t data_len = n;
		char *send_buf = worker->io_buf;

		ssize_t sent = gsocket_send(dst->gs, send_buf, data_len, MSG_NOSIGNAL);
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				sent = 0;
			} else {
				if (!caller_locked) pthread_mutex_lock(&src->conn->worker->lock);
				_proxy_conn_set_closing(src->conn);
				if (!caller_locked) pthread_mutex_unlock(&src->conn->worker->lock);
				return; /* Error */
			}
		}

		if (sent < data_len) {
			/* Buffer remaining data */
			int remain = data_len - sent;
			if (dst->buf_len + remain > dst->buf_size) {
				int new_size = dst->buf_size ? dst->buf_size * 2 : PROXY_BUF_INIT;
				while (dst->buf_len + remain > new_size) {
					new_size *= 2;
				}
				if (new_size > PROXY_BUF_MAX) {
					new_size = PROXY_BUF_MAX;
				}
				if (dst->buf_len + remain > new_size) {
					_proxy_conn_set_closing(src->conn);
					return; /* Overflow */
				}
				char *nb = realloc(dst->buf, new_size);
				if (!nb) {
					_proxy_conn_set_closing(src->conn);
					return; /* OOM */
				}
				dst->buf = nb;
				dst->buf_size = new_size;
			}
			memcpy(dst->buf + dst->buf_len, send_buf + sent, remain);
			dst->buf_len += remain;

			/* Backpressure: pause reading from source, wait for OUT on destination */
			src->read_paused = 1;
			gepoll_mod(worker->gepoll, src->gs, 0, src);
			gepoll_mod(worker->gepoll, dst->gs, EPOLLIN | EPOLLOUT, dst);
			return;
		}
	}

	if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		if (!caller_locked) pthread_mutex_lock(&src->conn->worker->lock);
		_proxy_conn_set_closing(src->conn);
		if (!caller_locked) pthread_mutex_unlock(&src->conn->worker->lock);
	}
}

static void _proxy_worker_wakeup(struct proxy_worker *worker)
{
	if (!worker || worker->wakeup_fd < 0) {
		return;
	}
	uint64_t val = 1;
	int unused __attribute__((unused));
	unused = write(worker->wakeup_fd, &val, sizeof(val));
}

static int _dns_resolve_callback(const struct dns_result *result, void *user_ptr)
{
	struct proxy_conn *conn = (struct proxy_conn *)user_ptr;
	pthread_mutex_lock(&conn->worker->lock);
	if (conn->closing) {
		pthread_mutex_unlock(&conn->worker->lock);
		__proxy_conn_put(conn->worker, conn);
		return 0;
	}

	if (result->ip_num > 0) {
		/* Use first IP for simplicity */
		safe_strncpy(conn->target.host, result->ip, sizeof(conn->target.host));
		conn->state = PSTATE_CONNECTING;
	} else if (result->addr_type == DNS_T_AAAA) {
		/* AAAA failed, try A */
		struct dns_server_query_option opt = {0};
		opt.dns_group_name = conn->group_name;
		opt.server_flags = BIND_FLAG_NO_SPEED_CHECK;
		if (conn->force_aaaa_soa) {
			opt.server_flags |= BIND_FLAG_FORCE_AAAA_SOA;
		}
		
		pthread_mutex_unlock(&conn->worker->lock);
		dns_server_query(conn->target.host, DNS_T_A, &opt, _dns_resolve_callback, conn);
		return 0;
	} else {
		tlog(TLOG_DEBUG, "proxy %p resolve failed, no IPs for type %d", conn, result->addr_type);
		_proxy_conn_set_closing(conn);
	}

	/* Targeted signaling: wake up worker to check state transition */
	_proxy_worker_wakeup(conn->worker);
	pthread_mutex_unlock(&conn->worker->lock);
	__proxy_conn_put(conn->worker, conn);
	return 0;
}

static int _proxy_server_process_handshake(struct proxy_conn *conn)
{
	int ret = gsocket_handshake(conn->client.gs);
	if (ret == GSOCKET_HANDSHAKE_DONE) {
		conn->state = PSTATE_GET_TARGET;
		conn->connect_start = conn->worker->now;
		list_move_tail(&conn->node, &conn->worker->connecting_conns);
		return 0;
	} else if (ret == GSOCKET_HANDSHAKE_WANT_READ || ret == GSOCKET_HANDSHAKE_WANT_WRITE) {
		int events = (ret == GSOCKET_HANDSHAKE_WANT_READ) ? EPOLLIN : EPOLLOUT;
		gepoll_mod(conn->worker->gepoll, conn->client.gs, events, &conn->client);
		return 1; /* Still handshaking */
	}
	struct gsocket_error err = {0};
	socklen_t len = sizeof(err);
	if (gsocket_getsockopt(conn->client.gs, SOL_PROTO_ERROR, SO_ERROR_DETAIL, &err, &len) == 0 && err.message[0] != '\0') {
		tlog(TLOG_DEBUG, "proxy client handshake failed, error: %s", err.message);
	} else {
		tlog(TLOG_DEBUG, "proxy client handshake failed");
	}
	return -1; /* Error */
}

static int _proxy_server_process_get_target(struct proxy_conn *conn)
{
	if (conn->type == LISTENER_FORWARD) {
		/* Target already set from listener */
		conn->state = PSTATE_RESOLVE;
		return 0;
	}

	if (conn->is_udp && conn->type == LISTENER_TPROXY) {
		/* UDP TProxy target is already extracted on listener accept */
		conn->state = PSTATE_RESOLVE;
		return 0;
	}

	int res = gsocket_get_proxy_target(conn->client.gs, &conn->target);
	if (res == 0) {
		if (conn->target.port != 0) {
			conn->state = PSTATE_RESOLVE;
			return 0;
		}
	}

	/* If we reach here, target might not be available yet or handshake incomplete */
	return -1;
}

static int _proxy_server_process_resolve(struct proxy_conn *conn)
{
	/* 1. Check if target is already an IP */
	struct sockaddr_storage ss;
	if (get_addr_from_string(conn->target.host, &ss) == 0) {
		conn->state = PSTATE_CONNECTING;
		return 0;
	}

	/* 2. Check if remote DNS is preferred */
	if (conn->remote_dns) {
		conn->state = PSTATE_CONNECTING;
		return 0;
	}

	/* 3. Local Resolution via SmartDNS */
	struct dns_server_query_option opt = {0};
	opt.dns_group_name = conn->group_name;
	opt.server_flags = BIND_FLAG_NO_SPEED_CHECK | BIND_FLAG_NO_DUALSTACK_SELECTION;
	if (conn->force_aaaa_soa) {
		opt.server_flags |= BIND_FLAG_FORCE_AAAA_SOA;
	}

	conn->state = PSTATE_RESOLVING;
	conn->ref_count++;
	pthread_mutex_unlock(&conn->worker->lock);
	int ret = dns_server_query(conn->target.host, DNS_T_AAAA, &opt, _dns_resolve_callback, conn);
	pthread_mutex_lock(&conn->worker->lock);
	
	if (ret != 0) {
		conn->ref_count--;
		return -1;
	}
	if (conn->closing) {
		return -1;
	}

	if (conn->state == PSTATE_RESOLVING) {
		/* Async resolving: silence client until result or timeout */
		gepoll_mod(conn->worker->gepoll, conn->client.gs, 0, &conn->client);
		return 1;
	}

	return 0; /* Synchronous resolving done */
}

static void _proxy_conn_print_log(struct proxy_conn *conn)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char client_ip[DNS_MAX_IPLEN] = "unknown";
	int client_port = 0;

	if (gsocket_getpeername(conn->client.gs, (struct sockaddr *)&addr, &addr_len) == 0) {
		get_host_by_addr(client_ip, sizeof(client_ip), (struct sockaddr *)&addr);
		if (addr.ss_family == AF_INET) {
			client_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
		} else if (addr.ss_family == AF_INET6) {
			client_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
		}
	}

	tlog(TLOG_INFO, "proxy %s:%d connecting to %s:%d via %s", client_ip, client_port, conn->target.host,
		 conn->target.port, conn->proxy_name[0] ? conn->proxy_name : "direct");
}

static void _proxy_server_push_outbound_proxy(struct proxy_conn *conn)
{
	if (!conn->proxy_name[0]) {
		return;
	}
	struct dns_proxy_names *pn = dns_server_get_proxy_names(conn->proxy_name);
	if (!pn || list_empty(&pn->server_list)) {
		return;
	}
	struct dns_proxy_servers *ps = list_first_entry(&pn->server_list, struct dns_proxy_servers, list);
	if (conn->is_udp && ps->type != PROXY_SOCKS5 && ps->type != PROXY_SOCKS5S) {
		return; /* UDP is only supported over SOCKS5, fallback to 1:1 forward */
	}
	const char *user = (ps->username[0] == '\0') ? NULL : ps->username;
	const char *pass = (ps->password[0] == '\0') ? NULL : ps->password;

	if (ps->type == PROXY_SOCKS5) {
		if (conn->is_udp) {
			gsocket_push_layer(conn->remote.gs, gsocket_io_socks5_udp_new(ps->server, ps->port, user, pass));
		} else {
			gsocket_push_layer(conn->remote.gs, gsocket_io_socks5_new(ps->server, ps->port, user, pass));
		}
	} else if (ps->type == PROXY_SOCKS5S) {
		if (ps->tls_host[0] != '\0') {
			gsocket_setsockopt(conn->remote.gs, SOL_SSL, SO_SSL_SNI, ps->tls_host, strlen(ps->tls_host));
		}
		gsocket_push_layer(conn->remote.gs, gsocket_io_ssl_new(g_proxy_ctx.ssl_cli_ctx, 0));
		if (conn->skip_cert_verify) {
			int verify = 0;
			gsocket_setsockopt(conn->remote.gs, SOL_SSL, SO_SSL_VERIFY, &verify, sizeof(verify));
		}
		if (conn->is_udp) {
			gsocket_push_layer(conn->remote.gs, gsocket_io_socks5_udp_new(ps->server, ps->port, user, pass));
		} else {
			gsocket_push_layer(conn->remote.gs, gsocket_io_socks5_new(ps->server, ps->port, user, pass));
		}
	} else if (ps->type == PROXY_HTTP) {
		gsocket_push_layer(conn->remote.gs, gsocket_io_httpproxy_new(ps->server, ps->port, user, pass));
	} else if (ps->type == PROXY_HTTPS) {
		if (ps->tls_host[0] != '\0') {
			gsocket_setsockopt(conn->remote.gs, SOL_SSL, SO_SSL_SNI, ps->tls_host, strlen(ps->tls_host));
		}
		gsocket_push_layer(conn->remote.gs, gsocket_io_ssl_new(g_proxy_ctx.ssl_cli_ctx, 0));
		if (conn->skip_cert_verify) {
			int verify = 0;
			gsocket_setsockopt(conn->remote.gs, SOL_SSL, SO_SSL_VERIFY, &verify, sizeof(verify));
		}
		gsocket_push_layer(conn->remote.gs, gsocket_io_httpproxy_new(ps->server, ps->port, user, pass));
	} else if (ps->type == PROXY_PASSTHROUGH) {
		if (ps->server[0] != '\0' && strcmp(ps->server, "0.0.0.0") != 0) {
			safe_strncpy(conn->target.host, ps->server, sizeof(conn->target.host));
		}
		if (ps->port != (unsigned short)-1) {
			conn->target.port = ps->port;
		}
	}
}

static int _proxy_server_process_connect_remote(struct proxy_conn *conn)
{
	if (conn->remote.gs == NULL) {
		int family = AF_INET;
		struct sockaddr_storage ss;
		if (get_addr_from_string(conn->target.host, &ss) == 0) {
			family = ss.ss_family;
		}

		int is_udp_to_socket = conn->is_udp;
		if (conn->proxy_name[0]) {
			struct dns_proxy_names *pn = dns_server_get_proxy_names(conn->proxy_name);
			if (pn && !list_empty(&pn->server_list)) {
				struct dns_proxy_servers *ps = list_first_entry(&pn->server_list, struct dns_proxy_servers, list);
				if (ps->type == PROXY_SOCKS5 || ps->type == PROXY_SOCKS5S) {
					is_udp_to_socket = 0; /* SOCKS5 UDP requires TCP control node streams! */
				}
			}
		}

		int fd = socket(family, is_udp_to_socket ? SOCK_DGRAM : SOCK_STREAM, 0);
		if (fd < 0) {
			return -1;
		}

		conn->remote.gs = gsocket_new(fd);
		if (!conn->remote.gs) {
			close(fd);
			return -1;
		}

		if (conn->so_mark > 0 && conn->type != LISTENER_TPROXY) {
			gsocket_set_mark(conn->remote.gs, conn->so_mark);
		}

		conn->remote.conn = conn;
		conn->remote.is_remote = 1;
		_proxy_optimize_gsocket(conn->remote.gs, 0);

		/* Setup Outbound Proxy Chaining */
		_proxy_server_push_outbound_proxy(conn);

		if (conn->type == LISTENER_FORWARD && conn->target_ssl) {
			if (conn->tls_host[0] != '\0') {
				gsocket_setsockopt(conn->remote.gs, SOL_SSL, SO_SSL_SNI, conn->tls_host, strlen(conn->tls_host));
			}
			gsocket_push_layer(conn->remote.gs, gsocket_io_ssl_new(g_proxy_ctx.ssl_cli_ctx, 0));
		}

		gsocket_set_nonblock(conn->remote.gs, 1);
		gepoll_add(conn->worker->gepoll, conn->remote.gs, EPOLLIN | EPOLLOUT, &conn->remote);

		_proxy_conn_print_log(conn);
	}

	/* Disable client reading while connecting and handshaking remote */
	gepoll_mod(conn->worker->gepoll, conn->client.gs, 0, &conn->client);

	int ret = gsocket_connect(conn->remote.gs, conn->target.host, conn->target.port);
	if (ret != 0) {
		if (errno == EINPROGRESS || errno == EALREADY) {
			/* Connection initiated, wait for completion */
			return 1;
		} else if (errno == EISCONN) {
			ret = 0;
		} else {
			tlog(TLOG_DEBUG, "proxy gsocket_connect failed, error: %s", strerror(errno));
			return -1;
		}
	}

	if (ret == 0) {
		conn->state = PSTATE_REMOTE_HANDSHAKE;
		return 0;
	}

	return 1;
}

static int _proxy_server_process_remote_handshake(struct proxy_conn *conn)
{
	int ret = gsocket_handshake(conn->remote.gs);
	if (ret == GSOCKET_HANDSHAKE_DONE) {
		conn->state = PSTATE_PIPE;
		list_move_tail(&conn->node, &conn->worker->conns);
		_proxy_conn_setup_remote_udp_gs(conn->worker, conn);

		/* Trigger initial relay pump immediately upon establishing link */
		_proxy_relay_data(&conn->client, &conn->remote, 1);
		_proxy_relay_data(&conn->remote, &conn->client, 1);

		gepoll_mod(conn->worker->gepoll, conn->client.gs, (conn->client.buf_len > 0) ? (EPOLLIN | EPOLLOUT) : EPOLLIN, &conn->client);
		gepoll_mod(conn->worker->gepoll, conn->remote.gs, (conn->remote.buf_len > 0) ? (EPOLLIN | EPOLLOUT) : EPOLLIN, &conn->remote);
		return 0;
	} else if (ret == GSOCKET_HANDSHAKE_WANT_READ || ret == GSOCKET_HANDSHAKE_WANT_WRITE) {
		int events = (ret == GSOCKET_HANDSHAKE_WANT_READ) ? EPOLLIN : EPOLLOUT;
		gepoll_mod(conn->worker->gepoll, conn->remote.gs, events, &conn->remote);
		return 1; /* Still handshaking */
	}
	tlog(TLOG_DEBUG, "proxy remote handshake failed");
	struct gsocket_error err = {0};
	socklen_t len = sizeof(err);
	if (gsocket_getsockopt(conn->remote.gs, SOL_PROTO_ERROR, SO_ERROR_DETAIL, &err, &len) == 0) {
		tlog(TLOG_DEBUG, "proxy remote handshake error: %s", err.message);
	}
	return -1; /* Error */
}

static int _proxy_server_conn_process(struct proxy_conn *conn)
{
	int loop = 0;
	while (conn->state != PSTATE_PIPE && conn->state != PSTATE_CLOSE) {
		if (++loop > 10) {
			return -1;
		}

		int ret = 0;
		switch (conn->state) {
		case PSTATE_HANDSHAKE:
			ret = _proxy_server_process_handshake(conn);
			break;
		case PSTATE_GET_TARGET:
			ret = _proxy_server_process_get_target(conn);
			break;
		case PSTATE_RESOLVE:
			ret = _proxy_server_process_resolve(conn);
			break;
		case PSTATE_RESOLVING:
			return 0; /* Wait for callback */
		case PSTATE_CONNECTING:
			ret = _proxy_server_process_connect_remote(conn);
			break;
		case PSTATE_REMOTE_HANDSHAKE:
			ret = _proxy_server_process_remote_handshake(conn);
			break;
		default:
			return -1;
		}
		if (ret != 0) {
			return (ret > 0) ? 0 : -1;
		}
	}
	return 0;
}

static void _proxy_conn_set_client_addr(struct proxy_conn *conn, struct sockaddr_storage *addr)
{
	if (addr) {
		memcpy(&conn->client_addr, addr, sizeof(struct sockaddr_storage));
	}
	get_host_by_addr(conn->client_ip, sizeof(conn->client_ip), (struct sockaddr *)addr);
	if (addr->ss_family == AF_INET) {
		conn->client_port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	} else if (addr->ss_family == AF_INET6) {
		conn->client_port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	} else {
		conn->client_port = 0;
	}
}

static int _sockaddr_cmp(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family) return -1;
	if (a->ss_family == AF_INET) {
		struct sockaddr_in *sin_a = (struct sockaddr_in *)a;
		struct sockaddr_in *sin_b = (struct sockaddr_in *)b;
		if (sin_a->sin_port != sin_b->sin_port) return -1;
		return memcmp(&sin_a->sin_addr, &sin_b->sin_addr, sizeof(sin_a->sin_addr));
	} else if (a->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6_a = (struct sockaddr_in6 *)a;
		struct sockaddr_in6 *sin6_b = (struct sockaddr_in6 *)b;
		if (sin6_a->sin6_port != sin6_b->sin6_port) return -1;
		return memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr, sizeof(sin6_a->sin6_addr));
	}
	return -1;
}

static inline uint32_t _sockaddr_hash(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		return jhash_2words(sin->sin_addr.s_addr, sin->sin_port, 0);
	} else if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		uint32_t *idx = (uint32_t *)&sin6->sin6_addr;
		return jhash_3words(idx[0] ^ idx[1], idx[2] ^ idx[3], sin6->sin6_port, 0);
	}
	return 0;
}

static struct proxy_conn *_proxy_conn_find_udp(struct proxy_worker *worker, const struct sockaddr_storage *client_addr, const struct sockaddr_storage *target_addr)
{
	struct proxy_conn *conn;
	uint32_t key = _sockaddr_hash(client_addr) ^ _sockaddr_hash(target_addr);
	hash_for_each_possible(worker->udp_sessions, conn, h_node, key) {
		if (conn->is_udp && _sockaddr_cmp(&conn->client_addr, client_addr) == 0 &&
			_sockaddr_cmp(&conn->target_addr, target_addr) == 0) {
			return conn;
		}
	}
	return NULL;
}

static struct proxy_conn *__proxy_conn_init_from_listener(struct proxy_worker *worker, struct proxy_listener *l, const struct sockaddr *addr)
{
	struct proxy_conn *conn = __proxy_conn_get(worker);
	if (!conn) {
		return NULL;
	}

	if (addr) {
		_proxy_conn_set_client_addr(conn, (struct sockaddr_storage *)addr);
	}

	conn->worker = worker;
	conn->client.head.magic = PROXY_MAGIC;
	conn->client.head.type = PROXY_TYPE_CONN;
	conn->remote.head.magic = PROXY_MAGIC;
	conn->remote.head.type = PROXY_TYPE_CONN;

	conn->client.conn = conn;
	conn->client.is_remote = 0;
	conn->remote.conn = conn;
	conn->remote.is_remote = 1;

	conn->state = PSTATE_HANDSHAKE;
	conn->type = l->type;
	safe_strncpy(conn->proxy_name, l->proxy_name, sizeof(conn->proxy_name));
	safe_strncpy(conn->group_name, l->group_name, sizeof(conn->group_name));
	safe_strncpy(conn->proxy_server, l->proxy_server, sizeof(conn->proxy_server));
	conn->remote_dns = l->remote_dns;
	conn->so_mark = l->so_mark;
	conn->target_ssl = l->target_ssl;
	conn->skip_cert_verify = l->skip_cert_verify;
	conn->force_aaaa_soa = l->force_aaaa_soa;
	safe_strncpy(conn->tls_host, l->tls_host, sizeof(conn->tls_host));
	conn->last_active = worker->now;

	return conn;
}

static struct proxy_conn *_proxy_conn_init_from_listener(struct proxy_worker *worker, struct proxy_listener *l, const struct sockaddr *addr)
{
	struct proxy_conn *conn;
	pthread_mutex_lock(&worker->lock);
	conn = __proxy_conn_init_from_listener(worker, l, addr);
	pthread_mutex_unlock(&worker->lock);
	return conn;
}

static int _proxy_conn_create_udp_client_gs(struct proxy_conn *conn, const struct sockaddr *addr)
{
	int fd = socket(addr->sa_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		tlog(TLOG_DEBUG, "socket() failed for client_gs");
		return -1;
	}
	int opt = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	if (conn->type == LISTENER_TPROXY) {
		setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
	}
	
	conn->client.gs = gsocket_new(fd);
	if (!conn->client.gs) {
		tlog(TLOG_DEBUG, "gsocket_new failed for client_gs");
		close(fd);
		return -1;
	}

	if (conn->type == LISTENER_TPROXY) {
		if (gsocket_bind(conn->client.gs, conn->target.host, conn->target.port) != 0) {
			tlog(TLOG_DEBUG, "gsocket_bind failed for target %s:%d, errno: %s", conn->target.host, conn->target.port, strerror(errno));
			gsocket_close(conn->client.gs);
			gsocket_free(conn->client.gs);
			conn->client.gs = NULL;
			return -1;
		}
	} else if (conn->type == LISTENER_FORWARD) {
		char listen_ip[DNS_MAX_IPLEN] = {0};
		int listen_port = 0;
		parse_ip(conn->proxy_server, listen_ip, &listen_port);
		if (gsocket_bind(conn->client.gs, listen_ip, listen_port) != 0) {
			tlog(TLOG_DEBUG, "gsocket_bind failed for Forward listener %s:%d, errno: %s", listen_ip, listen_port, strerror(errno));
			gsocket_close(conn->client.gs);
			gsocket_free(conn->client.gs);
			conn->client.gs = NULL;
			return -1;
		}
	}

	if (gsocket_connect(conn->client.gs, conn->client_ip, conn->client_port) != 0) {
		tlog(TLOG_DEBUG, "gsocket_connect failed for client %s:%d, errno: %s", conn->client_ip, conn->client_port, strerror(errno));
		gsocket_close(conn->client.gs);
		gsocket_free(conn->client.gs);
		conn->client.gs = NULL;
		return -1;
	}

	return 0;
}

static struct proxy_conn *_proxy_conn_create_udp_session(struct proxy_worker *worker, struct proxy_listener *found_l, struct sockaddr *addr, struct sockaddr_storage *original_dst, void *buf, ssize_t n)
{
	/* worker->lock is held by caller */
	struct proxy_conn *conn = __proxy_conn_init_from_listener(worker, found_l, addr);
	if (!conn) {
		tlog(TLOG_DEBUG, "__proxy_conn_init_from_listener failed");
		return NULL;
	}

	conn->is_udp = 1;
	if (found_l->forward_target.host[0]) {
		get_addr_from_string(found_l->forward_target.host, &conn->target_addr);
		if (conn->target_addr.ss_family == AF_INET) {
			((struct sockaddr_in *)&conn->target_addr)->sin_port = htons(found_l->forward_target.port);
		} else if (conn->target_addr.ss_family == AF_INET6) {
			((struct sockaddr_in6 *)&conn->target_addr)->sin6_port = htons(found_l->forward_target.port);
		}
		conn->target = found_l->forward_target;
	} else {
		conn->target_addr = *original_dst;
		get_host_by_addr(conn->target.host, sizeof(conn->target.host), (struct sockaddr *)original_dst);
		if (original_dst->ss_family == AF_INET) {
			conn->target.port = ntohs(((struct sockaddr_in *)original_dst)->sin_port);
		} else if (original_dst->ss_family == AF_INET6) {
			conn->target.port = ntohs(((struct sockaddr_in6 *)original_dst)->sin6_port);
		}
	}

	if (_proxy_conn_create_udp_client_gs(conn, addr) != 0) {
		tlog(TLOG_DEBUG, "_proxy_conn_create_udp_client_gs failed for target %s:%d", conn->target.host, conn->target.port);
		__proxy_conn_free(conn);
		return NULL;
	}

	list_add_tail(&conn->node, &worker->conns);
	uint32_t key = _sockaddr_hash((const struct sockaddr_storage *)addr) ^ _sockaddr_hash(&conn->target_addr);
	hash_add(worker->udp_sessions, &conn->h_node, key);
	gsocket_set_nonblock(conn->client.gs, 1);
	gepoll_add(worker->gepoll, conn->client.gs, EPOLLIN, &conn->client);

	if (conn->remote.buf_size < (int)n) {
		char *nb = realloc(conn->remote.buf, n);
		if (nb) {
			conn->remote.buf = nb;
			conn->remote.buf_size = (int)n;
		} else {
			tlog(TLOG_DEBUG, "realloc failed for UDP initial packet buffer");
			__proxy_conn_free(conn);
			return NULL;
		}
	}
	memcpy(conn->remote.buf, buf, n);
	conn->remote.buf_len = (int)n;

	_proxy_server_conn_process(conn);
	return conn;
}

static void _proxy_server_handle_udp_listener(struct proxy_listener *found_l)
{
	struct proxy_worker *worker = found_l->worker;
	char buf[65536];
	struct msghdr msg = {0};
	struct iovec iov[1];
	struct sockaddr_storage addr;
	char control[256];

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ssize_t n = gsocket_recvmsg(found_l->gs, &msg, 0);
	if (n <= 0) {
		return;
	}

	struct gsocket_address target_addr = {0};
	if (found_l->type == LISTENER_FORWARD) {
		target_addr = found_l->forward_target;
	} else {
		if (gsocket_get_proxy_target(found_l->gs, &target_addr) != 0) {
			return;
		}
	}

	struct sockaddr_storage target_ss = {0};
	get_addr_from_string(target_addr.host, &target_ss);
	if (target_ss.ss_family == AF_INET) {
		((struct sockaddr_in *)&target_ss)->sin_port = htons(target_addr.port);
	} else if (target_ss.ss_family == AF_INET6) {
		((struct sockaddr_in6 *)&target_ss)->sin6_port = htons(target_addr.port);
	}

	pthread_mutex_lock(&worker->lock);
	struct proxy_conn *conn = _proxy_conn_find_udp(worker, &addr, &target_ss);
	if (conn) {
		conn->last_active = worker->now;
		list_move_tail(&conn->node, &worker->conns);
		if (conn->remote.gs) {
			if (conn->state == PSTATE_PIPE) {
				gsocket_send(conn->remote.gs, buf, n, MSG_NOSIGNAL);
			} else {
				if (conn->remote.buf_len + n <= PROXY_BUF_MAX) {
					char *nb = realloc(conn->remote.buf, conn->remote.buf_len + n);
					if (nb) {
						conn->remote.buf = nb;
						memcpy(conn->remote.buf + conn->remote.buf_len, buf, n);
						conn->remote.buf_len += n;
						conn->remote.buf_size = conn->remote.buf_len;
					}
				}
			}
		}
		pthread_mutex_unlock(&worker->lock);
		return;
	}

	/* Create New Session */
	conn = _proxy_conn_create_udp_session(worker, found_l, (struct sockaddr *)&addr, &target_ss, buf, n);
	if (!conn) {
		pthread_mutex_unlock(&worker->lock);
		return;
	}

	pthread_mutex_unlock(&worker->lock);
}

static void _proxy_server_accept_conn(struct proxy_listener *found_l)
{
	struct proxy_worker *worker = found_l->worker;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	struct gsocket *client = gsocket_accept(found_l->gs, (struct sockaddr *)&addr, &addr_len);
	if (!client) {
		return;
	}

	struct proxy_conn *conn = _proxy_conn_init_from_listener(worker, found_l, (struct sockaddr *)&addr);
	if (!conn) {
		gsocket_close(client);
		gsocket_free(client);
		return;
	}

	conn->client.gs = client;
	conn->target = found_l->forward_target;

	_proxy_optimize_gsocket(client, 0);

	pthread_mutex_lock(&worker->lock);
	list_add_tail(&conn->node, &worker->conns);
	gsocket_set_nonblock(client, 1);
	gepoll_add(worker->gepoll, client, EPOLLIN, &conn->client);
	_proxy_server_conn_process(conn);
	pthread_mutex_unlock(&worker->lock);
}

static void _proxy_conn_setup_remote_udp_gs(struct proxy_worker *worker, struct proxy_conn *conn)
{
	if (conn->is_udp && !conn->remote_udp_gs) {
		int udp_fd = -1;
		socklen_t len = sizeof(udp_fd);
		if (gsocket_getsockopt(conn->remote.gs, SOL_SOCKS5, SO_SOCKS5_UDP_FD, &udp_fd, &len) == 0 && udp_fd != -1) {
			int dup_fd = dup(udp_fd);
			if (dup_fd >= 0) {
				conn->remote_udp_gs = gsocket_new(dup_fd);
				if (conn->remote_udp_gs) {
					gsocket_set_nonblock(conn->remote_udp_gs, 1);
					gepoll_add(worker->gepoll, conn->remote_udp_gs, EPOLLIN, &conn->remote);
				} else {
					close(dup_fd);
				}
			}
		}
		/* Flush any buffered UDP packets immediately upon connection setup */
		if (conn->remote.buf_len > 0) {
			_proxy_relay_data(&conn->client, &conn->remote, 0);
		}
	}
}

static void _proxy_handle_event(struct relay_gsock *rg, uint32_t events)
{
	struct proxy_conn *conn = rg->conn;
	struct proxy_worker *worker = conn->worker;

	pthread_mutex_lock(&worker->lock);
	if (!conn || conn->closing) {
		pthread_mutex_unlock(&worker->lock);
		return;
	}

	conn->last_active = worker->now;
	list_move_tail(&conn->node, &worker->conns);

	if (conn->state != PSTATE_PIPE) {
		if (conn->state == PSTATE_CONNECTING && rg->is_remote) {
			if (events & EPOLLOUT) {
				int err = 0;
				socklen_t len = sizeof(err);
				if (gsocket_getsockopt(conn->remote.gs, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
					conn->state = PSTATE_REMOTE_HANDSHAKE;
				} else {
					tlog(TLOG_DEBUG, "proxy remote connection failed, error: %s", strerror(err));
					goto close_conn;
				}
			}
		}

		if (_proxy_server_conn_process(conn) != 0) {
			goto close_conn;
		}
		if (conn->state == PSTATE_PIPE) {
			/* First time entering PIPE state, trigger mandatory relay to flush gsocket buffers */
			pthread_mutex_unlock(&worker->lock);
			_proxy_relay_data(&conn->client, &conn->remote, 0);
			_proxy_relay_data(&conn->remote, &conn->client, 0);
			return;
		}
		pthread_mutex_unlock(&worker->lock);
		return;
	}

	/* Regular PIPE state logic - handle subsequent epoll events */
	if (conn->closing) {
		/* If closing, only handle write events to drain buffers */
		pthread_mutex_unlock(&worker->lock);
		if (events & EPOLLOUT) {
			if (!rg->is_remote) {
				_proxy_relay_data(&conn->remote, &conn->client, 0);
			} else {
				_proxy_relay_data(&conn->client, &conn->remote, 0);
			}
		}
		return;
	}
	pthread_mutex_unlock(&worker->lock);

	if (events & EPOLLIN) {
		if (!rg->is_remote) {
			_proxy_relay_data(&conn->client, &conn->remote, 0);
		} else {
			_proxy_relay_data(&conn->remote, &conn->client, 0);
		}
	}
	if (events & EPOLLOUT) {
		if (!rg->is_remote) {
			/* Client is ready to send, flush from remote source */
			_proxy_relay_data(&conn->remote, &conn->client, 0);
		} else {
			/* Remote is ready to send, flush from client source */
			_proxy_relay_data(&conn->client, &conn->remote, 0);
		}
	}

	if (conn->closing) {
		pthread_mutex_lock(&worker->lock);
		goto close_conn;
	}
	return;

close_conn:
	_proxy_conn_set_closing(conn);
	pthread_mutex_unlock(&worker->lock);
}

static void _proxy_server_cleanup(struct proxy_worker *worker)
{
	struct proxy_conn *conn, *tmp;
	int idle_timeout = dns_conf.proxy_server_idle_timeout;

	/* 1. Promptly clean up connections already marked for closing */
	list_for_each_entry_safe(conn, tmp, &worker->closing_conns, node)
	{
		if (conn->client.buf_len == 0 && conn->remote.buf_len == 0) {
			list_del(&conn->node);
			__proxy_conn_free(conn);
		} else {
			/* Still has data to drain, check for timeout */
			if (worker->now - conn->last_active > 10) {
				tlog(TLOG_DEBUG, "proxy %p connection closed, reason: drain timeout", conn);
				list_del(&conn->node);
				__proxy_conn_free(conn);
			} else {
				/* Try to flush again */
				if (conn->client.buf_len > 0) {
					_proxy_flush_buffer(&conn->remote, &conn->client);
				}
				if (conn->remote.buf_len > 0) {
					_proxy_flush_buffer(&conn->client, &conn->remote);
				}
			}
		}
	}

	/* 2. Throttled scan for idle/connect timeouts (1Hz) */
	if (worker->now - worker->last_cleanup_time >= 1) {
		worker->last_cleanup_time = worker->now;

		/* A. Connect timeout scan */
		list_for_each_entry_safe(conn, tmp, &worker->connecting_conns, node)
		{
			if (worker->now - conn->connect_start > 10) {
				tlog(TLOG_DEBUG, "proxy %p connection closed, reason: connect timeout, state %d, age %ld", 
					conn, conn->state, worker->now - conn->connect_start);
				list_del(&conn->node);
				__proxy_conn_free(conn);
			}
		}

		/* B. Idle timeout scan with LRU early-exit */
		if (idle_timeout > 0 || 1) { // Always scan if UDP sessions might exist
			list_for_each_entry_safe(conn, tmp, &worker->conns, node)
			{
				int age = (int)(worker->now - conn->last_active);
				int timeout = conn->is_udp ? PROXY_UDP_IDLE_TIMEOUT : idle_timeout;
				if (timeout > 0 && age > timeout) {
					tlog(TLOG_DEBUG, "proxy connection closed, reason: %s timeout", conn->is_udp ? "udp" : "idle");
					list_del(&conn->node);
					__proxy_conn_free(conn);
				} else {
					int min_possible_timeout = PROXY_UDP_IDLE_TIMEOUT;
					if (idle_timeout > 0 && idle_timeout < PROXY_UDP_IDLE_TIMEOUT) {
						min_possible_timeout = idle_timeout;
					}

					if (age < min_possible_timeout) {
						break;
					}
				}
			}
		}
	}
}

static void *_proxy_server_work(void *arg)
{
	struct proxy_worker *worker = (struct proxy_worker *)arg;
	struct gepoll_event events[256];
	while (g_proxy_ctx.run) {
		worker->now = time(NULL);
		int timeout = (list_empty(&worker->conns) && list_empty(&worker->connecting_conns)) ? -1 : 1000;
		int n = gepoll_wait(worker->gepoll, events, 256, timeout);
		for (int i = 0; i < n; i++) {
			void *user_data = events[i].user_data;
			if (user_data == worker->gs_wakeup) {
				uint64_t val;
				int unused __attribute__((unused));
				unused = read(worker->wakeup_fd, &val, sizeof(val));
				continue;
			}

			struct proxy_common_head *head = (struct proxy_common_head *)user_data;
			if (!head || head->magic != PROXY_MAGIC) {
				continue;
			}

			if (head->type == PROXY_TYPE_LISTENER) {
				struct proxy_listener *l = (struct proxy_listener *)head;
				if (l->is_udp) {
					_proxy_server_handle_udp_listener(l);
				} else {
					_proxy_server_accept_conn(l);
				}
			} else {
				_proxy_handle_event((struct relay_gsock *)head, events[i].events);
			}
		}

		/* Process any connections waiting for state transition (e.g. after DNS resolve) */
		struct proxy_conn *conn, *tmp;
		pthread_mutex_lock(&worker->lock);
		list_for_each_entry_safe(conn, tmp, &worker->connecting_conns, node)
		{
			if (conn->state != PSTATE_REMOTE_HANDSHAKE) {
				if (_proxy_server_conn_process(conn) != 0) {
					_proxy_conn_set_closing(conn);
				}
			}
		}
		_proxy_server_cleanup(worker);
		pthread_mutex_unlock(&worker->lock);
	}
	return NULL;
}

static SSL_CTX *_init_ssl_server_ctx(void)
{
	char key[PATH_MAX] = {0}, cert[PATH_MAX] = {0};
	smartdns_get_cert(key, cert);
	if (key[0] == '\0' || cert[0] == '\0') {
		return NULL;
	}

	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx) {
		return NULL;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ||
		SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx);
		return NULL;
	}
	return ctx;
}

static void _proxy_server_need_ssl(int *server, int *client)
{
	unsigned long idx;
	struct dns_socks5_proxy_server_conf *s_conf;
	struct dns_http_proxy_server_conf *h_conf;
	struct dns_forward_server_conf *f_conf;
	struct dns_proxy_names *pn;
	struct dns_proxy_servers *ps;

	*server = 0;
	*client = 0;

	hash_for_each(dns_proxy_table.socks5_proxy, idx, s_conf, node)
	{
		if (s_conf->ssl_support) {
			*server = 1;
		}
	}
	hash_for_each(dns_proxy_table.http_proxy, idx, h_conf, node)
	{
		if (h_conf->ssl_support) {
			*server = 1;
		}
	}
	hash_for_each(dns_proxy_table.forward, idx, f_conf, node)
	{
		if (f_conf->ssl_listen) {
			*server = 1;
		}
		if (f_conf->ssl_target) {
			*client = 1;
		}
	}
	hash_for_each(dns_proxy_table.proxy, idx, pn, node)
	{
		list_for_each_entry(ps, &pn->server_list, list)
		{
			if (ps->type == PROXY_SOCKS5S || ps->type == PROXY_HTTPS) {
				*client = 1;
			}
		}
	}
}

static int _proxy_server_init_listeners(struct proxy_worker *worker, SSL_CTX *ssl_srv_ctx)
{
	struct listener_args args = {0};
	unsigned long idx;
	struct dns_tproxy_server_conf *t_conf;
	struct dns_sniproxy_server_conf *sn_conf;
	struct dns_socks5_proxy_server_conf *s_conf;
	struct dns_http_proxy_server_conf *h_conf;
	struct dns_forward_server_conf *f_conf;

	hash_for_each(dns_proxy_table.tproxy, idx, t_conf, node)
	{
		if (t_conf->tcp_support) {
			memset(&args, 0, sizeof(args));
			args.gs = _create_gsocket_listener(t_conf->server, 0, SOCK_STREAM, 1, 1);
			args.proto_layer = gsocket_io_tproxy_server_new();
			args.type = LISTENER_TPROXY;
			args.type_name = "tproxy";
			args.proxy_server = t_conf->server;
			args.proxy_name = t_conf->proxy_name;
			args.group_name = t_conf->group_name;
			safe_strncpy(args.name, t_conf->group_name, sizeof(args.name));
			args.remote_dns = t_conf->remote_dns;
			args.so_mark = t_conf->so_mark;
			args.worker = worker;
			args.force_aaaa_soa = t_conf->force_aaaa_soa;
			if (_add_listener(&args) != 0) {
				return -1;
			}
		}

		if (t_conf->udp_support) {
			memset(&args, 0, sizeof(args));
			args.gs = _create_gsocket_listener(t_conf->server, 0, SOCK_DGRAM, 1, 1);
			args.proto_layer = gsocket_io_tproxy_server_new();
			args.type = LISTENER_TPROXY;
			args.type_name = "tproxy-udp";
			args.proxy_server = t_conf->server;
			args.proxy_name = t_conf->proxy_name;
			args.group_name = t_conf->group_name;
			safe_strncpy(args.name, t_conf->group_name, sizeof(args.name));
			args.remote_dns = t_conf->remote_dns;
			args.so_mark = t_conf->so_mark;
			args.worker = worker;
			args.is_udp = 1;
			args.force_aaaa_soa = t_conf->force_aaaa_soa;
			if (_add_listener(&args) != 0) {
				return -1;
			}
		}
	}

	hash_for_each(dns_proxy_table.sniproxy, idx, sn_conf, node)
	{
		memset(&args, 0, sizeof(args));
		args.gs = _create_gsocket_listener(sn_conf->server, 0, SOCK_STREAM, 1, 0);
		args.proto_layer = gsocket_io_sniproxy_server_new(sn_conf->target_port);
		args.type = LISTENER_SNIPROXY;
		args.type_name = "sni-proxy";
		args.proxy_server = sn_conf->server;
		safe_strncpy(args.name, sn_conf->name, sizeof(args.name));
		args.proxy_name = sn_conf->proxy_name;
		args.group_name = sn_conf->group_name;
		args.remote_dns = sn_conf->remote_dns;
		args.so_mark = sn_conf->so_mark;
		args.worker = worker;
		args.force_aaaa_soa = sn_conf->force_aaaa_soa;
		args.target_port = sn_conf->target_port;
		if (_add_listener(&args) != 0) {
			return -1;
		}
	}

	hash_for_each(dns_proxy_table.socks5_proxy, idx, s_conf, node)
	{
		memset(&args, 0, sizeof(args));
		const char *user = (s_conf->username[0] == '\0') ? NULL : s_conf->username;
		const char *pass = (s_conf->password[0] == '\0') ? NULL : s_conf->password;
		args.gs = _create_gsocket_listener(s_conf->server, 0, SOCK_STREAM, 1, 0);
		args.proto_layer = gsocket_io_socks5_server_new(user, pass);
		args.ssl_ctx = s_conf->ssl_support ? ssl_srv_ctx : NULL;
		if (s_conf->ssl_support && !ssl_srv_ctx) {
			tlog(TLOG_WARN, "socks5s listener configured but no certificate found, check server-cert");
		}
		args.type = LISTENER_SOCKS5;
		args.type_name = s_conf->ssl_support ? "socks5s" : "socks5";
		args.proxy_server = s_conf->server;
		args.proxy_name = s_conf->proxy_name;
		args.group_name = (s_conf->group_name[0] != '\0') ? s_conf->group_name : s_conf->name;
		safe_strncpy(args.name, s_conf->name, sizeof(args.name));
		args.remote_dns = s_conf->remote_dns;
		args.so_mark = s_conf->so_mark;
		args.tls_host = s_conf->tls_host;
		args.skip_cert_verify = s_conf->skip_cert_verify;
		args.worker = worker;
		args.force_aaaa_soa = s_conf->force_aaaa_soa;
		if (_add_listener(&args) != 0) {
			return -1;
		}
	}

	hash_for_each(dns_proxy_table.http_proxy, idx, h_conf, node)
	{
		memset(&args, 0, sizeof(args));
		const char *user = (h_conf->username[0] == '\0') ? NULL : h_conf->username;
		const char *pass = (h_conf->password[0] == '\0') ? NULL : h_conf->password;
		args.gs = _create_gsocket_listener(h_conf->server, 0, SOCK_STREAM, 1, 0);
		args.proto_layer = gsocket_io_httpproxy_server_new(user, pass);
		args.ssl_ctx = h_conf->ssl_support ? ssl_srv_ctx : NULL;
		if (h_conf->ssl_support && !ssl_srv_ctx) {
			tlog(TLOG_WARN, "https listener configured but no certificate found, check server-cert");
		}
		args.type = LISTENER_HTTP;
		args.type_name = h_conf->ssl_support ? "https" : "http";
		args.proxy_server = h_conf->server;
		args.proxy_name = h_conf->proxy_name;
		args.group_name = (h_conf->group_name[0] != '\0') ? h_conf->group_name : h_conf->name;
		safe_strncpy(args.name, h_conf->name, sizeof(args.name));
		args.remote_dns = h_conf->remote_dns;
		args.so_mark = h_conf->so_mark;
		args.tls_host = h_conf->tls_host;
		args.skip_cert_verify = h_conf->skip_cert_verify;
		args.worker = worker;
		args.force_aaaa_soa = h_conf->force_aaaa_soa;
		if (_add_listener(&args) != 0) {
			return -1;
		}
	}

	hash_for_each(dns_proxy_table.forward, idx, f_conf, node)
	{
		if (f_conf->tcp_support) {
			memset(&args, 0, sizeof(args));
			args.gs = _create_gsocket_listener(f_conf->server, 0, SOCK_STREAM, 1, 0);
			args.ssl_ctx = f_conf->ssl_listen ? ssl_srv_ctx : NULL;
			if (f_conf->ssl_listen && !ssl_srv_ctx) {
				tlog(TLOG_WARN, "forwards listener configured but no certificate found, check server-cert");
			}
			args.type = LISTENER_FORWARD;
			args.type_name = "forward";
			args.proxy_server = f_conf->server;
			args.proxy_name = f_conf->proxy_name;
			args.group_name = f_conf->name;
			args.so_mark = f_conf->so_mark;
			args.target_ssl = f_conf->ssl_target;
			args.tls_host = f_conf->tls_host;
			args.forward_target = f_conf->target;
			args.skip_cert_verify = f_conf->skip_cert_verify;
			args.worker = worker;
			if (_add_listener(&args) != 0) {
				return -1;
			}
		}

		if (f_conf->udp_support) {
			memset(&args, 0, sizeof(args));
			args.gs = _create_gsocket_listener(f_conf->server, 0, SOCK_DGRAM, 1, 0);
			args.type = LISTENER_FORWARD;
			args.type_name = "forward-udp";
			args.proxy_server = f_conf->server;
			args.proxy_name = f_conf->proxy_name;
			args.group_name = f_conf->name;
			args.so_mark = f_conf->so_mark;
			args.target_ssl = f_conf->ssl_target;
			args.tls_host = f_conf->tls_host;
			args.forward_target = f_conf->target;
			args.skip_cert_verify = f_conf->skip_cert_verify;
			args.worker = worker;
			args.is_udp = 1;
			if (_add_listener(&args) != 0) {
				return -1;
			}
		}
	}
	return 0;
}
static int _proxy_worker_create(struct proxy_worker *worker, int id, SSL_CTX *ssl_srv_ctx)
{
	if (worker == NULL) {
		return -1;
	}

	worker->id = id;
	INIT_LIST_HEAD(&worker->listeners);
	INIT_LIST_HEAD(&worker->conns);
	INIT_LIST_HEAD(&worker->connecting_conns);
	INIT_LIST_HEAD(&worker->closing_conns);
	INIT_LIST_HEAD(&worker->conn_pool);
	hash_init(worker->udp_sessions);

	worker->now = time(NULL);

	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutex_init(&worker->lock, &attr);
	pthread_mutexattr_destroy(&attr);

	worker->io_buf = zalloc(1, PROXY_WORKER_BUF_SIZE);
	if (worker->io_buf == NULL) {
		return -1;
	}

	worker->gepoll = gepoll_create(0);
	if (worker->gepoll == NULL) {
		return -1;
	}

	worker->wakeup_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (worker->wakeup_fd < 0) {
		return -1;
	}
	worker->gs_wakeup = gsocket_new(worker->wakeup_fd);
	if (worker->gs_wakeup == NULL) {
		close(worker->wakeup_fd);
		worker->wakeup_fd = -1;
		return -1;
	}
	gepoll_add(worker->gepoll, worker->gs_wakeup, EPOLLIN, worker->gs_wakeup);

	if (_proxy_server_init_listeners(worker, ssl_srv_ctx) != 0) {
		return -1;
	}

	if (list_empty(&worker->listeners)) {
		return 0;
	}

	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	if (pthread_create(&worker->tid, &tattr, _proxy_server_work, worker) != 0) {
		pthread_attr_destroy(&tattr);
		return -1;
	}
#ifdef __linux__
	cpu_set_t cpuset;
	long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	CPU_ZERO(&cpuset);
	if (num_cpus > 0) {
		CPU_SET((num_cpus - 1 - id) % num_cpus, &cpuset);
	} else {
		CPU_SET(id, &cpuset);
	}
	pthread_setaffinity_np(worker->tid, sizeof(cpu_set_t), &cpuset);
#endif
	pthread_attr_destroy(&tattr);

	return 0;
}

static void _proxy_worker_free(struct proxy_worker *worker)
{
	if (worker == NULL) {
		return;
	}

	if (worker->tid != 0) {
		pthread_join(worker->tid, NULL);
	}

	pthread_mutex_lock(&worker->lock);
	struct proxy_listener *l, *ltmp;
	list_for_each_entry_safe(l, ltmp, &worker->listeners, node)
	{
		list_del(&l->node);
		gepoll_del(worker->gepoll, l->gs);
		gsocket_close(l->gs);
		gsocket_free(l->gs);
		free(l);
	}

	struct proxy_conn *c, *ctmp;
	list_for_each_entry_safe(c, ctmp, &worker->conns, node)
	{
		list_del(&c->node);
		__proxy_conn_free(c);
	}
	list_for_each_entry_safe(c, ctmp, &worker->connecting_conns, node)
	{
		list_del(&c->node);
		__proxy_conn_free(c);
	}
	list_for_each_entry_safe(c, ctmp, &worker->closing_conns, node)
	{
		list_del(&c->node);
		__proxy_conn_free(c);
	}
	pthread_mutex_unlock(&worker->lock);

	if (worker->gepoll != NULL) {
		gepoll_destroy(worker->gepoll);
	}

	_proxy_conn_pool_clear(worker);

	if (worker->gs_wakeup != NULL) {
		gsocket_close(worker->gs_wakeup);
		gsocket_free(worker->gs_wakeup);
		worker->gs_wakeup = NULL;
		worker->wakeup_fd = -1;
	}

	pthread_mutex_destroy(&worker->lock);
	if (worker->io_buf) {
		free(worker->io_buf);
		worker->io_buf = NULL;
	}
}

int proxy_server_init(void)
{
	memset(&g_proxy_ctx, 0, sizeof(g_proxy_ctx));

	int need_srv_ssl = 0, need_cli_ssl = 0;
	_proxy_server_need_ssl(&need_srv_ssl, &need_cli_ssl);

	if (need_srv_ssl) {
		g_proxy_ctx.ssl_srv_ctx = _init_ssl_server_ctx();
	}
	if (need_cli_ssl) {
		g_proxy_ctx.ssl_cli_ctx = SSL_CTX_new(TLS_client_method());
		if (g_proxy_ctx.ssl_cli_ctx) {
			if (dns_conf.ca_file[0] || dns_conf.ca_path[0]) {
				SSL_CTX_load_verify_locations(g_proxy_ctx.ssl_cli_ctx,
											  dns_conf.ca_file[0] ? dns_conf.ca_file : NULL,
											  dns_conf.ca_path[0] ? dns_conf.ca_path : NULL);
				SSL_CTX_set_verify(g_proxy_ctx.ssl_cli_ctx, SSL_VERIFY_PEER, NULL);
			} else {
				SSL_CTX_set_verify(g_proxy_ctx.ssl_cli_ctx, SSL_VERIFY_NONE, NULL);
			}
		}
	}

	g_proxy_ctx.worker_num = dns_conf.proxy_server_workers;
	if (g_proxy_ctx.worker_num <= 0) {
		g_proxy_ctx.worker_num = 1;
	}

	g_proxy_ctx.workers = zalloc(g_proxy_ctx.worker_num, sizeof(struct proxy_worker));
	if (g_proxy_ctx.workers == NULL) {
		return -1;
	}

	g_proxy_ctx.run = 1;
	for (int i = 0; i < g_proxy_ctx.worker_num; i++) {
		if (_proxy_worker_create(&g_proxy_ctx.workers[i], i, g_proxy_ctx.ssl_srv_ctx) != 0) {
			proxy_server_exit();
			return -1;
		}
	}

	if (_proxy_server_setup_firewall_rules() != 0) {
		tlog(TLOG_ERROR, "failed to setup firewall rules for transparent proxying");
		return -1;
	}

	is_proxy_server_init = 1;
	return 0;
}

void proxy_server_exit(void)
{
	if (is_proxy_server_init == 0) {
		return;
	}
	g_proxy_ctx.run = 0;

	for (int i = 0; i < g_proxy_ctx.worker_num; i++) {
		uint64_t val = 1;
		int unused __attribute__((unused));
		unused = write(g_proxy_ctx.workers[i].wakeup_fd, &val, sizeof(val));
	}

	for (int i = 0; i < g_proxy_ctx.worker_num; i++) {
		_proxy_worker_free(&g_proxy_ctx.workers[i]);
	}

	if (g_proxy_ctx.workers != NULL) {
		free(g_proxy_ctx.workers);
		g_proxy_ctx.workers = NULL;
	}

	if (g_proxy_ctx.ssl_srv_ctx != NULL) {
		SSL_CTX_free(g_proxy_ctx.ssl_srv_ctx);
		g_proxy_ctx.ssl_srv_ctx = NULL;
	}
	if (g_proxy_ctx.ssl_cli_ctx != NULL) {
		SSL_CTX_free(g_proxy_ctx.ssl_cli_ctx);
		g_proxy_ctx.ssl_cli_ctx = NULL;
	}

	/* Cleanup firewall rules */
	_proxy_server_cleanup_firewall_rules();

	is_proxy_server_init = 0;
}
