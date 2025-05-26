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

#include "server.h"
#include "client_subnet.h"
#include "dns_conf_group.h"
#include "proxy_names.h"
#include "server_group.h"
#include "smartdns/util.h"

#include <getopt.h>

static int _config_server(int argc, char *argv[], dns_server_type_t type, int default_port)
{
	int index = dns_conf.server_num;
	struct dns_servers *server = NULL;
	int port = -1;
	char *ip = NULL;
	char scheme[DNS_MAX_CNAME_LEN] = {0};
	int opt = 0;
	int optind_last = 0;
	unsigned int result_flag = 0;
	unsigned int server_flag = 0;
	unsigned char *spki = NULL;
	int drop_packet_latency_ms = 0;
	int tcp_keepalive = -1;
	int is_bootstrap_dns = 0;
	char host_ip[DNS_MAX_IPLEN] = {0};
	int no_tls_host_name = 0;
	int no_tls_host_verify = 0;
	const char *group_name = NULL;

	int ttl = 0;
	/* clang-format off */
	static struct option long_options[] = {
		{"drop-packet-latency", required_argument, NULL, 'D'},
		{"exclude-default-group", no_argument, NULL, 'e'}, /* exclude this from default group */
		{"group", required_argument, NULL, 'g'}, /* add to group */
		{"proxy", required_argument, NULL, 'p'}, /* proxy server */
		{"no-check-certificate", no_argument, NULL, 'k'}, /* do not check certificate */
		{"bootstrap-dns", no_argument, NULL, 'b'}, /* set as bootstrap dns */
		{"interface", required_argument, NULL, 250}, /* interface */
#ifdef FEATURE_CHECK_EDNS
		/* experimental feature */
		{"check-edns", no_argument, NULL, 251},   /* check edns */
#endif 
		{"whitelist-ip", no_argument, NULL, 252}, /* filtering with whitelist-ip */
		{"blacklist-ip", no_argument, NULL, 253}, /* filtering with blacklist-ip */
		{"set-mark", required_argument, NULL, 254}, /* set mark */
		{"subnet", required_argument, NULL, 256}, /* set subnet */
		{"hitchhiking", no_argument, NULL, 257}, /* hitchhiking */
		{"host-ip", required_argument, NULL, 258}, /* host ip */
		{"spki-pin", required_argument, NULL, 259}, /* check SPKI pin */
		{"host-name", required_argument, NULL, 260}, /* host name */
		{"http-host", required_argument, NULL, 261}, /* http host */
		{"tls-host-verify", required_argument, NULL, 262 }, /* verify tls hostname */
		{"tcp-keepalive", required_argument, NULL, 263}, /* tcp keepalive */
		{"subnet-all-query-types", no_argument, NULL, 264}, /* send subnent for all query types.*/
		{"fallback", no_argument, NULL, 265}, /* fallback */
		{"alpn", required_argument, NULL, 266}, /* alpn */
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	ip = argv[1];
	if (index >= DNS_MAX_SERVERS) {
		tlog(TLOG_WARN, "exceeds max server number, %s", ip);
		return 0;
	}

	server = &dns_conf.servers[index];
	server->spki[0] = '\0';
	server->path[0] = '\0';
	server->hostname[0] = '\0';
	server->httphost[0] = '\0';
	server->tls_host_verify[0] = '\0';
	server->proxyname[0] = '\0';
	server->set_mark = -1;
	server->drop_packet_latency_ms = drop_packet_latency_ms;
	server->tcp_keepalive = tcp_keepalive;
	server->subnet_all_query_types = 0;

	if (parse_uri(ip, scheme, server->server, &port, server->path) != 0) {
		return -1;
	}

	if (scheme[0] != '\0') {
		if (strcasecmp(scheme, "https") == 0) {
			type = DNS_SERVER_HTTPS;
			default_port = DEFAULT_DNS_HTTPS_PORT;
		} else if (strcasecmp(scheme, "http3") == 0) {
			type = DNS_SERVER_HTTP3;
			default_port = DEFAULT_DNS_HTTPS_PORT;
		} else if (strcasecmp(scheme, "h3") == 0) {
			type = DNS_SERVER_HTTP3;
			default_port = DEFAULT_DNS_HTTPS_PORT;
		} else if (strcasecmp(scheme, "quic") == 0) {
			type = DNS_SERVER_QUIC;
			default_port = DEFAULT_DNS_QUIC_PORT;
		} else if (strcasecmp(scheme, "tls") == 0) {
			type = DNS_SERVER_TLS;
			default_port = DEFAULT_DNS_TLS_PORT;
		} else if (strcasecmp(scheme, "tcp") == 0) {
			type = DNS_SERVER_TCP;
			default_port = DEFAULT_DNS_PORT;
		} else if (strcasecmp(scheme, "udp") == 0) {
			type = DNS_SERVER_UDP;
			default_port = DEFAULT_DNS_PORT;
		} else {
			tlog(TLOG_ERROR, "invalid scheme: %s", scheme);
			return -1;
		}
	}

	if (dns_is_quic_supported() == 0) {
		if (type == DNS_SERVER_QUIC || type == DNS_SERVER_HTTP3) {
			tlog(TLOG_ERROR, "QUIC/HTTP3 is not supported in this version.");
			tlog(TLOG_ERROR, "Please install the latest release with QUIC/HTTP3 support.");
			return -1;
		}
	}

	/* if port is not defined, set port to default 53 */
	if (port == PORT_NOT_DEFINED) {
		port = default_port;
	}

	/* get current group */
	if (_config_current_group()) {
		group_name = _config_current_group()->group_name;
	}

	/* if server is defined in a group, exclude from default group */
	if (group_name && group_name[0] != '\0') {
		server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "D:kg:p:eb", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'D': {
			drop_packet_latency_ms = atoi(optarg);
			break;
		}
		case 'e': {
			server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
			break;
		}
		case 'g': {
			/* first group, add later */
			if (group_name == NULL) {
				group_name = optarg;
				break;
			}

			if (_dns_conf_get_group_set(optarg, server) != 0) {
				tlog(TLOG_ERROR, "add group failed.");
				goto errout;
			}
			break;
		}
		case 'p': {
			if (_dns_conf_get_proxy_name(optarg) == NULL) {
				tlog(TLOG_ERROR, "add proxy server failed.");
				goto errout;
			}
			safe_strncpy(server->proxyname, optarg, PROXY_NAME_LEN);
			break;
		}

		case 'k': {
			server->skip_check_cert = 1;
			no_tls_host_verify = 1;
			break;
		}
		case 'b': {
			is_bootstrap_dns = 1;
			break;
		}
		case 250: {
			safe_strncpy(server->ifname, optarg, MAX_INTERFACE_LEN);
			break;
		}
		case 251: {
			result_flag |= DNSSERVER_FLAG_CHECK_EDNS;
			break;
		}
		case 252: {
			result_flag |= DNSSERVER_FLAG_WHITELIST_IP;
			break;
		}
		case 253: {
			result_flag |= DNSSERVER_FLAG_BLACKLIST_IP;
			break;
		}
		case 254: {
			server->set_mark = atoll(optarg);
			break;
		}
		case 256: {
			_conf_client_subnet(optarg, &server->ipv4_ecs, &server->ipv6_ecs);
			break;
		}
		case 257: {
			server_flag |= SERVER_FLAG_HITCHHIKING;
			break;
		}
		case 258: {
			if (check_is_ipaddr(optarg) != 0) {
				goto errout;
			}
			safe_strncpy(host_ip, optarg, DNS_MAX_IPLEN);
			break;
		}
		case 259: {
			safe_strncpy(server->spki, optarg, DNS_MAX_SPKI_LEN);
			break;
		}
		case 260: {
			safe_strncpy(server->hostname, optarg, DNS_MAX_CNAME_LEN);
			if (strncmp(server->hostname, "-", 2) == 0) {
				server->hostname[0] = '\0';
				no_tls_host_name = 1;
			}
			break;
		}
		case 261: {
			safe_strncpy(server->httphost, optarg, DNS_MAX_CNAME_LEN);
			break;
		}
		case 262: {
			safe_strncpy(server->tls_host_verify, optarg, DNS_MAX_CNAME_LEN);
			if (strncmp(server->tls_host_verify, "-", 2) == 0) {
				server->tls_host_verify[0] = '\0';
				no_tls_host_verify = 1;
			}
			break;
		}
		case 263: {
			server->tcp_keepalive = atoi(optarg);
			break;
		}
		case 264: {
			server->subnet_all_query_types = 1;
			break;
		}
		case 265: {
			server->fallback = 1;
			break;
		}
		case 266: {
			safe_strncpy(server->alpn, optarg, DNS_MAX_ALPN_LEN);
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown server option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	if (check_is_ipaddr(server->server) != 0) {
		/* if server is domain name, then verify domain */
		if (server->tls_host_verify[0] == '\0' && no_tls_host_verify == 0) {
			safe_strncpy(server->tls_host_verify, server->server, DNS_MAX_CNAME_LEN);
		}

		if (server->hostname[0] == '\0' && no_tls_host_name == 0) {
			safe_strncpy(server->hostname, server->server, DNS_MAX_CNAME_LEN);
		}

		if (server->httphost[0] == '\0') {
			safe_strncpy(server->httphost, server->server, DNS_MAX_CNAME_LEN);
		}

		if (host_ip[0] != '\0') {
			safe_strncpy(server->server, host_ip, DNS_MAX_IPLEN);
		}
	}

	/* if server is domain name, then verify domain */
	if (server->tls_host_verify[0] == '\0' && server->hostname[0] != '\0' && no_tls_host_verify == 0) {
		safe_strncpy(server->tls_host_verify, server->hostname, DNS_MAX_CNAME_LEN);
	}

	/* add new server */
	server->type = type;
	server->port = port;
	server->result_flag = result_flag;
	server->server_flag = server_flag;
	server->ttl = ttl;
	server->drop_packet_latency_ms = drop_packet_latency_ms;

	if (server->type == DNS_SERVER_HTTPS || server->type == DNS_SERVER_HTTP3) {
		if (server->path[0] == 0) {
			safe_strncpy(server->path, "/", sizeof(server->path));
		}

		if (server->httphost[0] == '\0') {
			set_http_host(server->server, server->port, DEFAULT_DNS_HTTPS_PORT, server->httphost);
		}
	}

	if (group_name) {
		if (_dns_conf_get_group_set(group_name, server) != 0) {
			tlog(TLOG_ERROR, "add group failed.");
			goto errout;
		}
	}

	dns_conf.server_num++;
	tlog(TLOG_DEBUG, "add server %s, flag: %X, ttl: %d", ip, result_flag, ttl);

	if (is_bootstrap_dns) {
		server->server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
		_dns_conf_get_group_set("bootstrap-dns", server);
		dns_conf_exist_bootstrap_dns = 1;
	}

	return 0;

errout:
	if (spki) {
		free(spki);
	}

	return -1;
}

int _config_server_udp(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_UDP, DEFAULT_DNS_PORT);
}

int _config_server_tcp(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_TCP, DEFAULT_DNS_PORT);
}

int _config_server_tls(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_TLS, DEFAULT_DNS_TLS_PORT);
}

int _config_server_https(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_HTTPS, DEFAULT_DNS_HTTPS_PORT);

	return ret;
}

int _config_server_quic(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_QUIC, DEFAULT_DNS_QUIC_PORT);

	return ret;
}

int _config_server_http3(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_HTTP3, DEFAULT_DNS_HTTPS_PORT);

	return ret;
}