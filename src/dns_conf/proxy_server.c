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

#include "smartdns/proxy_server.h"
#include "bind.h"
#include "proxy_names.h"
#include "proxy_server.h"
#include "smartdns/util.h"

#include <getopt.h>
#include <unistd.h> // for access

static int _default_so_mark = 1104;

static enum firewall_type _detect_firewall_type_enum(void)
{
	if (check_tool("nft")) {
		return FIREWALL_NFTABLES;
	} else if (check_tool("iptables")) {
		return FIREWALL_IPTABLES;
	}
	return FIREWALL_NONE;
}



static int _config_proxy_detect_speed_check(const char *proxy_name)
{
	struct dns_proxy_servers *server;
	struct dns_proxy_names *proxy = dns_server_get_proxy_names(proxy_name);

	if (proxy == NULL) {
		return 1;
	}

	list_for_each_entry(server, &proxy->server_list, list)
	{
		if (server->type == PROXY_PASSTHROUGH) {
			return 1;
		}

		return 0;
	}
	return 1;
}

int _config_proxy_server(void *data, int argc, char *argv[])
{
	char *servers_name = NULL;
	struct dns_proxy_servers *server = NULL;
	proxy_type_t type = PROXY_TYPE_END;

	char *ip = NULL;
	int opt = 0;
	char scheme[DNS_MAX_CNAME_LEN] = {0};
	int port = PORT_NOT_DEFINED;

	/* clang-format off */
	static struct option long_options[] = {
		{"name", required_argument, NULL, 'n'}, 
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		return 0;
	}

	server = zalloc(1, sizeof(*server));
	if (server == NULL) {
		tlog(TLOG_WARN, "malloc memory failed.");
		goto errout;
	}

	ip = argv[1];
	if (parse_uri_ext(ip, scheme, server->username, server->password, server->server, &port, NULL) != 0) {
		goto errout;
	}

	/* process extra options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n': {
			servers_name = optarg;
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
	} else if (strcasecmp(scheme, "passthrough") == 0 || strcasecmp(scheme, "direct") == 0) {
		if (port == PORT_NOT_DEFINED) {
			port = -1;
		}
		type = PROXY_PASSTHROUGH;
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
	tlog(TLOG_DEBUG, "add proxy server %s", ip);

	return 0;

errout:
	if (server) {
		free(server);
	}

	return -1;
}

int _config_tproxy_server(void *data, int argc, char *argv[])
{
	struct dns_tproxy_server_conf *conf = NULL;
	struct dns_tproxy_server_conf *old_conf = NULL;
	int opt = 0;
	char *ip = NULL;
	int speed_check = 0;
	char firewall_type[32] = {0};

	static struct option long_options[] = {{"name", required_argument, NULL, 'n'},
										   {"proxy", required_argument, NULL, 'p'},
										   {"group", required_argument, NULL, 'g'},
										   {"firewall-type", required_argument, NULL, 'f'},
										   {"udp", no_argument, NULL, 'u'},
										   {"set-mark", required_argument, NULL, 'm'},
										   {"outbound-tproxy", required_argument, NULL, 'o'},
										   {"speed-check", required_argument, NULL, 's'},
										   {"force-aaaa-soa", no_argument, NULL, 'F'},
										   {"no-rule", no_argument, NULL, 'R'},
										   {"no-server", no_argument, NULL, 'S'},
										   {"no-rule-clean", no_argument, NULL, 'L'},
										   {"remote-dns", no_argument, NULL, 'r'},
										   {"rule-script", required_argument, NULL, 'C'},
										   {"start-rule", required_argument, NULL, 'T'},
										   {"stop-rule", required_argument, NULL, 'P'},
										   {NULL, no_argument, NULL, 0}};

	if (argc < 2) {
		tlog(TLOG_ERROR, "invalid parameter, usage: tproxy-server [IP]:port -name name -proxy proxyname [-set-mark "
						 "mark] [-outbound-tproxy enable|disable] [-speed-test yes|no|auto] [-force-aaaa-soa] "
						 "[-no-rule] [-no-server] [-no-rule-clean] [-remote-dns] [-rule-script script] [-start-rule command] [-stop-rule command] "
						 "[-firewall-type none|auto|nftables|iptables|iptables-redirect|iptables-tproxy]");
		return -1;
	}

	conf = zalloc(1, sizeof(*conf));
	if (conf == NULL) {
		return -1;
	}

	// Set default values
	conf->output_chain_enable = 1; // Default to enable OUTPUT chain

	ip = argv[1];

	if (_bind_is_ip_valid(ip) != 0) {
		tlog(TLOG_ERROR, "tproxy-server ip address invalid: %s", ip);
		goto errout;
	}

	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:p:g:f:u:m:o:s:FRSL:rC:TP:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n':
			safe_strncpy(conf->name, optarg, sizeof(conf->name));
			break;
		case 'p':
			safe_strncpy(conf->proxy_name, optarg, sizeof(conf->proxy_name));
			break;
		case 'g':
			safe_strncpy(conf->group_name, optarg, sizeof(conf->group_name));
			break;
		case 'f':
			safe_strncpy(firewall_type, optarg, sizeof(firewall_type));
			break;
		case 'u':
			conf->udp_support = 1;
			break;
		case 'm':
			conf->so_mark = atoi(optarg);
			break;
		case 'o':
			if (strcmp(optarg, "enable") == 0 || strcmp(optarg, "yes") == 0 || strcmp(optarg, "1") == 0) {
				conf->output_chain_enable = 1;
			} else if (strcmp(optarg, "disable") == 0 || strcmp(optarg, "no") == 0 || strcmp(optarg, "0") == 0) {
				conf->output_chain_enable = 0;
			} else {
				tlog(TLOG_ERROR, "invalid outbound-tproxy value: %s, use 'enable' or 'disable'", optarg);
				goto errout;
			}
			break;
		case 's':
			if (strcmp(optarg, "yes") == 0) {
				speed_check = 1;
			} else if (strcmp(optarg, "no") == 0) {
				speed_check = 0;
			} else if (strcmp(optarg, "auto") == 0) {
				speed_check = -1;
			} else {
				tlog(TLOG_ERROR, "invalid speed-test value: %s", optarg);
				goto errout;
			}
			break;
		case 'F':
			conf->force_aaaa_soa = 1;
			break;
		case 'R':
			conf->no_rules = 1;
			break;
		case 'S':
			conf->no_server = 1;
			break;
		case 'L':
			conf->no_rule_clean = 1;
			break;
		case 'r':
			conf->remote_dns = 1;
			break;
		case 'C':
			safe_strncpy(conf->rule_script, optarg, sizeof(conf->rule_script));
			conf->no_rules = 1; // rule-script implies no internal rules
			break;
		case 'T':
			safe_strncpy(conf->start_rule, optarg, sizeof(conf->start_rule));
			conf->no_rules = 1; // start-rule implies no internal rules
			break;
		case 'P':
			safe_strncpy(conf->stop_rule, optarg, sizeof(conf->stop_rule));
			break;
		default:
			break;
		}
	}

	if (conf->name[0] == '\0') {
		tlog(TLOG_ERROR, "please set tproxy-server name");
		goto errout;
	}

	if (check_is_valid_config_name(conf->name) == 0) {
		tlog(TLOG_ERROR, "tproxy-server name %s is invalid, only support [a-zA-Z0-9_-]", conf->name);
		goto errout;
	}

	if (firewall_type[0] == '\0') {
		safe_strncpy(firewall_type, "auto", sizeof(firewall_type));
	}

	// Set firewall_type based on firewall string
	if (strncmp(firewall_type, "none", sizeof("none") - 1) == 0) {
		conf->firewall_type = FIREWALL_NONE;
	} else if (strncmp(firewall_type, "auto", sizeof("auto") - 1) == 0) {
		conf->firewall_type = _detect_firewall_type_enum();
		if (conf->firewall_type == FIREWALL_NONE) {
			tlog(TLOG_WARN, "no firewall tool detected, disabling firewall for tproxy-server %s", conf->name);
			conf->firewall_type = FIREWALL_NONE;
		} else if (conf->firewall_type == FIREWALL_IPTABLES) {
			// For iptables, choose redirect or tproxy based on UDP support
			if (conf->udp_support) {
				conf->firewall_type = FIREWALL_IPTABLES_TPROXY;
			} else {
				conf->firewall_type = FIREWALL_IPTABLES_REDIRECT;
			}
		}
	} else if (strncmp(firewall_type, "nftables", sizeof("nftables") - 1) == 0) {
		conf->firewall_type = FIREWALL_NFTABLES;
	} else if (strncmp(firewall_type, "iptables-redirect", sizeof("iptables-redirect") - 1) == 0) {
		conf->firewall_type = FIREWALL_IPTABLES_REDIRECT;
	} else if (strncmp(firewall_type, "iptables-tproxy", sizeof("iptables-tproxy") - 1) == 0) {
		conf->firewall_type = FIREWALL_IPTABLES_TPROXY;
	} else if (strncmp(firewall_type, "iptables", sizeof("iptables") - 1) == 0) {
		conf->firewall_type = FIREWALL_IPTABLES;
	} else {
		tlog(TLOG_ERROR, "invalid firewall type %s", firewall_type);
		goto errout;
	}

	if (conf->so_mark == 0) {
		conf->so_mark = _default_so_mark++;
	}

	if (speed_check == -1) {
		// Auto-detect speed check based on proxy servers
		conf->speed_check = _config_proxy_detect_speed_check(conf->proxy_name);
	} else {
		conf->speed_check = speed_check;
	}

	old_conf = dns_conf_get_tproxy_server(conf->name);
	if (old_conf) {
		hash_del(&old_conf->node);
		dns_proxy_table.tproxy_num--;
		free(old_conf);
	}

	uint32_t key = hash_string(conf->name);
	safe_strncpy(conf->server, ip, sizeof(conf->server));
	hash_add(dns_proxy_table.tproxy, &conf->node, key);
	dns_proxy_table.tproxy_num++;
	return 0;

errout:
	if (conf) {
		free(conf);
	}
	return -1;
}

int _config_sniproxy_server(void *data, int argc, char *argv[])
{
	struct dns_sniproxy_server_conf *conf = NULL;
	struct dns_sniproxy_server_conf *old_conf = NULL;
	int opt = 0;
	char *ip = NULL;
	int speed_check = 0;

	static struct option long_options[] = {{"name", required_argument, NULL, 'n'},
										   {"proxy", required_argument, NULL, 'p'},
										   {"group", required_argument, NULL, 'g'},
										   {"remote-dns", no_argument, NULL, 'r'},
										   {"set-mark", required_argument, NULL, 'm'},
										   {"speed-check", required_argument, NULL, 's'},
										   {"force-aaaa-soa", no_argument, NULL, 'F'},
										   {NULL, no_argument, NULL, 0}};

	if (argc < 2) {
		tlog(TLOG_ERROR, "invalid parameter, usage: sni-proxy-server [IP]:port -name name -proxy proxyname "
						 "[-speed-test yes|no|auto]");
		return -1;
	}

	conf = zalloc(1, sizeof(*conf));
	if (conf == NULL) {
		return -1;
	}

	ip = argv[1];

	if (_bind_is_ip_valid(ip) != 0) {
		tlog(TLOG_ERROR, "sni-proxy-server ip address invalid: %s", ip);
		goto errout;
	}

	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:p:g:r:s", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n':
			safe_strncpy(conf->name, optarg, sizeof(conf->name));
			break;
		case 'p':
			safe_strncpy(conf->proxy_name, optarg, sizeof(conf->proxy_name));
			break;
		case 'g':
			safe_strncpy(conf->group_name, optarg, sizeof(conf->group_name));
			break;
		case 'r':
			conf->remote_dns = 1;
			break;
		case 'm':
			conf->so_mark = atoi(optarg);
			break;
		case 's':
			if (strcmp(optarg, "yes") == 0) {
				speed_check = 1;
			} else if (strcmp(optarg, "no") == 0) {
				speed_check = 0;
			} else if (strcmp(optarg, "auto") == 0) {
				speed_check = -1;
			} else {
				tlog(TLOG_ERROR, "invalid speed-test value: %s", optarg);
				goto errout;
			}
			break;
		case 'F':
			conf->force_aaaa_soa = 1;;
			break;
		default:
			break;
		}
	}

	if (conf->name[0] == '\0') {
		tlog(TLOG_ERROR, "please set sni-proxy-server name");
		goto errout;
	}

	if (check_is_valid_config_name(conf->name) == 0) {
		tlog(TLOG_ERROR, "sni-proxy-server name %s is invalid, only support [a-zA-Z0-9_-]", conf->name);
		goto errout;
	}

	old_conf = dns_conf_get_sniproxy_server(conf->name);
	if (old_conf) {
		hash_del(&old_conf->node);
		dns_proxy_table.sniproxy_num--;
		free(old_conf);
	}

	if (speed_check == -1) {
		// Auto-detect speed check based on proxy servers
		conf->speed_check = _config_proxy_detect_speed_check(conf->proxy_name);
	} else {
		conf->speed_check = speed_check;
	}

	safe_strncpy(conf->server, ip, sizeof(conf->server));
	uint32_t key = hash_string(conf->name);
	hash_add(dns_proxy_table.sniproxy, &conf->node, key);
	dns_proxy_table.sniproxy_num++;
	return 0;

errout:
	if (conf) {
		free(conf);
	}
	return -1;
}

struct dns_tproxy_server_conf *dns_conf_get_tproxy_server(const char *name)
{
	uint32_t key = hash_string(name);
	struct dns_tproxy_server_conf *conf = NULL;

	hash_for_each_possible(dns_proxy_table.tproxy, conf, node, key)
	{
		if (strncmp(conf->name, name, PROXY_NAME_LEN) == 0) {
			return conf;
		}
	}

	return NULL;
}

struct dns_sniproxy_server_conf *dns_conf_get_sniproxy_server(const char *name)
{
	uint32_t key = hash_string(name);
	struct dns_sniproxy_server_conf *conf = NULL;

	hash_for_each_possible(dns_proxy_table.sniproxy, conf, node, key)
	{
		if (strncmp(conf->name, name, PROXY_NAME_LEN) == 0) {
			return conf;
		}
	}

	return NULL;
}

static void _config_proxy_tproxy_table_destroy(void)
{
	struct dns_tproxy_server_conf *t_conf = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_proxy_table.tproxy, i, tmp, t_conf, node)
	{
		hlist_del_init(&t_conf->node);
		free(t_conf);
	}
}

static void _config_proxy_sniproxy_table_destroy(void)
{
	struct dns_sniproxy_server_conf *s_conf = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_proxy_table.sniproxy, i, tmp, s_conf, node)
	{
		hlist_del_init(&s_conf->node);
		free(s_conf);
	}
}

int _config_proxy_server_table_destroy(void)
{
	_config_proxy_sniproxy_table_destroy();
	_config_proxy_tproxy_table_destroy();
	return 0;
}

int dns_conf_tproxy_server_num(void)
{
	return dns_proxy_table.tproxy_num;
}

int dns_conf_sniproxy_server_num(void)
{
	return dns_proxy_table.sniproxy_num;
}