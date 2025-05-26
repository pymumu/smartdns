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

#include "proxy_server.h"
#include "proxy_names.h"
#include "smartdns/util.h"

#include <getopt.h>

int _config_proxy_server(void *data, int argc, char *argv[])
{
	char *servers_name = NULL;
	struct dns_proxy_servers *server = NULL;
	proxy_type_t type = PROXY_TYPE_END;

	char *ip = NULL;
	int opt = 0;
	int use_domain = 0;
	char scheme[DNS_MAX_CNAME_LEN] = {0};
	int port = PORT_NOT_DEFINED;

	/* clang-format off */
	static struct option long_options[] = {
		{"name", required_argument, NULL, 'n'}, 
		{"use-domain", no_argument, NULL, 'd'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		return 0;
	}

	server = malloc(sizeof(*server));
	if (server == NULL) {
		tlog(TLOG_WARN, "malloc memory failed.");
		goto errout;
	}
	memset(server, 0, sizeof(*server));

	ip = argv[1];
	if (parse_uri_ext(ip, scheme, server->username, server->password, server->server, &port, NULL) != 0) {
		goto errout;
	}

	/* process extra options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:d", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n': {
			servers_name = optarg;
			break;
		}
		case 'd': {
			use_domain = 1;
			break;
		}
		default:
			break;
		}
	}

	if (strcasecmp(scheme, "socks5") == 0) {
		if (port == PORT_NOT_DEFINED) {
			port = 1080;
		}

		type = PROXY_SOCKS5;
	} else if (strcasecmp(scheme, "http") == 0) {
		if (port == PORT_NOT_DEFINED) {
			port = 3128;
		}

		type = PROXY_HTTP;
	} else {
		tlog(TLOG_ERROR, "invalid scheme %s", scheme);
		return -1;
	}

	if (servers_name == NULL) {
		tlog(TLOG_ERROR, "please set name");
		goto errout;
	}

	if (_dns_conf_proxy_servers_add(servers_name, server) != 0) {
		tlog(TLOG_ERROR, "add group failed.");
		goto errout;
	}

	/* add new server */
	server->type = type;
	server->port = port;
	server->use_domain = use_domain;
	tlog(TLOG_DEBUG, "add proxy server %s", ip);

	return 0;

errout:
	if (server) {
		free(server);
	}

	return -1;
}
