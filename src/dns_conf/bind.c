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

#include "bind.h"
#include "dns_conf_group.h"
#include "domain_rule.h"
#include "ipset.h"
#include "nftset.h"
#include "server_group.h"
#include "smartdns/util.h"

#include <getopt.h>

static int _config_bind_ip_parser_nftset(struct dns_bind_ip *bind_ip, unsigned int *server_flag, const char *nftsetname)
{
	struct dns_nftset_rule *nftset_rule = NULL;
	struct dns_nftset_rule **bind_nftset_rule = NULL;
	const struct dns_nftset_name *nftset_name = NULL;
	enum domain_rule type = DOMAIN_RULE_MAX;

	char *setname = NULL;
	char *tablename = NULL;
	char *family = NULL;
	char copied_name[DNS_MAX_NFTSET_NAMELEN + 1];

	safe_strncpy(copied_name, nftsetname, DNS_MAX_NFTSET_NAMELEN);
	for (char *tok = strtok(copied_name, ","); tok; tok = strtok(NULL, ",")) {
		char *saveptr = NULL;
		char *tok_set = NULL;

		if (strncmp(tok, "#4:", 3U) == 0) {
			bind_nftset_rule = &bind_ip->nftset_ipset_rule.nftset_ip;
			type = DOMAIN_RULE_NFTSET_IP;
		} else if (strncmp(tok, "#6:", 3U) == 0) {
			bind_nftset_rule = &bind_ip->nftset_ipset_rule.nftset_ip6;
			type = DOMAIN_RULE_NFTSET_IP6;
		} else if (strncmp(tok, "-", 2U) == 0) {
			continue;
		} else {
			return -1;
		}

		tok_set = tok + 3;

		if (strncmp(tok_set, "-", 2U) == 0) {
			*server_flag |= BIND_FLAG_NO_RULE_NFTSET;
			continue;
		}

		family = strtok_r(tok_set, "#", &saveptr);
		if (family == NULL) {
			return -1;
		}

		tablename = strtok_r(NULL, "#", &saveptr);
		if (tablename == NULL) {
			return -1;
		}

		setname = strtok_r(NULL, "#", &saveptr);
		if (setname == NULL) {
			return -1;
		}

		/* new nftset domain */
		nftset_name = _dns_conf_get_nftable(family, tablename, setname);
		if (nftset_name == NULL) {
			return -1;
		}

		nftset_rule = _new_dns_rule(type);
		if (nftset_rule == NULL) {
			return -1;
		}

		nftset_rule->nfttablename = nftset_name->nfttablename;
		nftset_rule->nftsetname = nftset_name->nftsetname;
		nftset_rule->familyname = nftset_name->nftfamilyname;
		/* reference is 1 here */
		*bind_nftset_rule = nftset_rule;

		nftset_rule = NULL;
	}

	return 0;
}

static int _config_bind_ip_parser_ipset(struct dns_bind_ip *bind_ip, unsigned int *server_flag, const char *ipsetname)
{
	struct dns_ipset_rule **bind_ipset_rule = NULL;
	struct dns_ipset_rule *ipset_rule = NULL;
	const char *ipset = NULL;
	enum domain_rule type = DOMAIN_RULE_MAX;

	char copied_name[DNS_MAX_NFTSET_NAMELEN + 1];

	safe_strncpy(copied_name, ipsetname, DNS_MAX_NFTSET_NAMELEN);

	for (char *tok = strtok(copied_name, ","); tok; tok = strtok(NULL, ",")) {
		if (tok[0] == '#') {
			if (strncmp(tok, "#6:", 3U) == 0) {
				bind_ipset_rule = &bind_ip->nftset_ipset_rule.ipset_ip6;
				type = DOMAIN_RULE_IPSET_IPV6;
			} else if (strncmp(tok, "#4:", 3U) == 0) {
				bind_ipset_rule = &bind_ip->nftset_ipset_rule.ipset_ip;
				type = DOMAIN_RULE_IPSET_IPV4;
			} else {
				goto errout;
			}
			tok += 3;
		} else {
			type = DOMAIN_RULE_IPSET;
			bind_ipset_rule = &bind_ip->nftset_ipset_rule.ipset;
		}

		if (strncmp(tok, "-", 1) == 0) {
			*server_flag |= BIND_FLAG_NO_RULE_IPSET;
			continue;
		}

		if (bind_ipset_rule == NULL) {
			continue;
		}

		/* new ipset domain */
		ipset = _dns_conf_get_ipset(tok);
		if (ipset == NULL) {
			goto errout;
		}

		ipset_rule = _new_dns_rule(type);
		if (ipset_rule == NULL) {
			goto errout;
		}

		ipset_rule->ipsetname = ipset;
		/* reference is 1 here */
		*bind_ipset_rule = ipset_rule;
		ipset_rule = NULL;
	}

	return 0;
errout:
	if (ipset_rule) {
		_dns_rule_put(&ipset_rule->head);
	}

	return -1;
}

static int _bind_is_ip_valid(const char *ip)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char ip_check[MAX_IP_LEN];
	int port_check = -1;

	if (parse_ip(ip, ip_check, &port_check) != 0) {
		if (port_check != -1 && ip_check[0] == '\0') {
			return 0;
		}
		return -1;
	}

	if (getaddr_by_host(ip_check, (struct sockaddr *)&addr, &addr_len) != 0) {
		return -1;
	}

	return 0;
}

static int _config_bind_ip(int argc, char *argv[], DNS_BIND_TYPE type)
{
	int index = dns_conf.bind_ip_num;
	struct dns_bind_ip *bind_ip = NULL;
	char *ip = NULL;
	int opt = 0;
	int optind_last = 0;
	char group_name[DNS_GROUP_NAME_LEN];
	const char *group = NULL;
	unsigned int server_flag = 0;
	int i = 0;

	/* clang-format off */
	static struct option long_options[] = {
		{"group", required_argument, NULL, 'g'}, /* add to group */
		{"no-rule-addr", no_argument, NULL, 'A'},   
		{"no-rule-nameserver", no_argument, NULL, 'N'},   
		{"no-rule-ipset", no_argument, NULL, 'I'},   
		{"no-rule-sni-proxy", no_argument, NULL, 'P'},   
		{"no-rule-soa", no_argument, NULL, 'O'},
		{"no-speed-check", no_argument, NULL, 'S'},  
		{"no-cache", no_argument, NULL, 'C'},  
		{"no-dualstack-selection", no_argument, NULL, 'D'},
		{"no-ip-alias", no_argument, NULL, 'a'},
		{"force-aaaa-soa", no_argument, NULL, 'F'},
		{"acl", no_argument, NULL, 251},
		{"no-rules", no_argument, NULL, 252},
		{"no-serve-expired", no_argument, NULL, 253},
		{"force-https-soa", no_argument, NULL, 254},
		{"ipset", required_argument, NULL, 255},
		{"nftset", required_argument, NULL, 256},
		{"alpn", required_argument, NULL, 257},
		{"ddr", no_argument, NULL, 258},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */
	if (argc <= 1) {
		tlog(TLOG_ERROR, "bind: invalid parameter.");
		goto errout;
	}

	ip = argv[1];
	if (index >= DNS_MAX_BIND_IP) {
		tlog(TLOG_WARN, "exceeds max server number, %s", ip);
		return 0;
	}

	if (_bind_is_ip_valid(ip) != 0) {
		tlog(TLOG_ERROR, "bind ip address invalid: %s", ip);
		return -1;
	}

	for (i = 0; i < dns_conf.bind_ip_num; i++) {
		bind_ip = &dns_conf.bind_ip[i];
		if (bind_ip->type != type) {
			continue;
		}

		if (strncmp(bind_ip->ip, ip, DNS_MAX_IPLEN) != 0) {
			continue;
		}

		tlog(TLOG_WARN, "bind server %s, type %d, already configured, skip.", ip, type);
		return 0;
	}

	bind_ip = &dns_conf.bind_ip[index];
	bind_ip->type = type;
	bind_ip->flags = 0;
	safe_strncpy(bind_ip->ip, ip, DNS_MAX_IPLEN);
	/* get current group */
	if (_config_current_group()) {
		group = _config_current_group()->group_name;
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'g': {
			safe_strncpy(group_name, optarg, DNS_GROUP_NAME_LEN);
			group = _dns_conf_get_group_name(group_name);
			break;
		}
		case 'A': {
			server_flag |= BIND_FLAG_NO_RULE_ADDR;
			break;
		}
		case 'a': {
			server_flag |= BIND_FLAG_NO_IP_ALIAS;
			break;
		}
		case 'N': {
			server_flag |= BIND_FLAG_NO_RULE_NAMESERVER;
			break;
		}
		case 'I': {
			server_flag |= BIND_FLAG_NO_RULE_IPSET;
			break;
		}
		case 'P': {
			server_flag |= BIND_FLAG_NO_RULE_SNIPROXY;
			break;
		}
		case 'S': {
			server_flag |= BIND_FLAG_NO_SPEED_CHECK;
			break;
		}
		case 'C': {
			server_flag |= BIND_FLAG_NO_CACHE;
			break;
		}
		case 'O': {
			server_flag |= BIND_FLAG_NO_RULE_SOA;
			break;
		}
		case 'D': {
			server_flag |= BIND_FLAG_NO_DUALSTACK_SELECTION;
			break;
		}
		case 'F': {
			server_flag |= BIND_FLAG_FORCE_AAAA_SOA;
			break;
		}
		case 251: {
			server_flag |= BIND_FLAG_ACL;
			break;
		}
		case 252: {
			server_flag |= BIND_FLAG_NO_RULES;
			break;
		}
		case 253: {
			server_flag |= BIND_FLAG_NO_SERVE_EXPIRED;
			break;
		}
		case 254: {
			server_flag |= BIND_FLAG_FORCE_HTTPS_SOA;
			break;
		}
		case 255: {
			_config_bind_ip_parser_ipset(bind_ip, &server_flag, optarg);
			server_flag |= BIND_FLAG_NO_DUALSTACK_SELECTION;
			server_flag |= BIND_FLAG_NO_PREFETCH;
			server_flag |= BIND_FLAG_NO_SERVE_EXPIRED;
			break;
		}
		case 256: {
			_config_bind_ip_parser_nftset(bind_ip, &server_flag, optarg);
			server_flag |= BIND_FLAG_NO_DUALSTACK_SELECTION;
			server_flag |= BIND_FLAG_NO_PREFETCH;
			server_flag |= BIND_FLAG_NO_SERVE_EXPIRED;
			break;
		}
		case 257: {
			safe_strncpy(bind_ip->alpn, optarg, DNS_MAX_ALPN_LEN);
			break;
		}
		case 258: {
			server_flag |= BIND_FLAG_DDR;
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown bind option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	/* add new server */
	bind_ip->flags = server_flag;
	bind_ip->group = group;
	dns_conf.bind_ip_num++;
	if (bind_ip->type == DNS_BIND_TYPE_TLS || bind_ip->type == DNS_BIND_TYPE_HTTPS) {
		if (bind_ip->ssl_cert_file == NULL || bind_ip->ssl_cert_key_file == NULL) {
			bind_ip->ssl_cert_file = dns_conf.bind_ca_file;
			bind_ip->ssl_cert_key_file = dns_conf.bind_ca_key_file;
			bind_ip->ssl_cert_key_pass = dns_conf.bind_ca_key_pass;
			dns_conf.need_cert = 1;
		}
	}
	tlog(TLOG_DEBUG, "bind ip %s, type: %d, flag: %X", ip, type, server_flag);

	return 0;

errout:
	return -1;
}

void dns_server_bind_destroy(void)
{
	for (int i = 0; i < dns_conf.bind_ip_num; i++) {
		struct dns_bind_ip *bind_ip = &dns_conf.bind_ip[i];

		if (bind_ip->nftset_ipset_rule.ipset) {
			_dns_rule_put(&bind_ip->nftset_ipset_rule.ipset->head);
		}

		if (bind_ip->nftset_ipset_rule.ipset_ip) {
			_dns_rule_put(&bind_ip->nftset_ipset_rule.ipset_ip->head);
		}

		if (bind_ip->nftset_ipset_rule.ipset_ip6) {
			_dns_rule_put(&bind_ip->nftset_ipset_rule.ipset_ip6->head);
		}

		if (bind_ip->nftset_ipset_rule.nftset_ip) {
			_dns_rule_put(&bind_ip->nftset_ipset_rule.nftset_ip->head);
		}

		if (bind_ip->nftset_ipset_rule.nftset_ip6) {
			_dns_rule_put(&bind_ip->nftset_ipset_rule.nftset_ip6->head);
		}
	}
	memset(dns_conf.bind_ip, 0, sizeof(dns_conf.bind_ip));
	dns_conf.bind_ip_num = 0;
}

int _config_add_default_server_if_needed(void)
{
	if (dns_conf.bind_ip_num > 0) {
		return 0;
	}

	/* add default server */
	char *argv[] = {"bind", "[::]:53", NULL};
	int argc = sizeof(argv) / sizeof(char *) - 1;
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_UDP);
}

int _config_bind_ip_udp(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_UDP);
}

int _config_bind_ip_tcp(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_TCP);
}

int _config_bind_ip_tls(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_TLS);
}

int _config_bind_ip_https(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_HTTPS);
}
