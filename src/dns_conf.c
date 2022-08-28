/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "dns_conf.h"
#include "list.h"
#include "rbtree.h"
#include "tlog.h"
#include "util.h"
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define DEFAULT_DNS_CACHE_SIZE 512
#define DNS_MAX_REPLY_IP_NUM 8

/* ipset */
struct dns_ipset_table {
	DECLARE_HASHTABLE(ipset, 8);
};
static struct dns_ipset_table dns_ipset_table;

struct dns_qtype_soa_table dns_qtype_soa_table;

/* dns groups */
struct dns_group_table dns_group_table;

struct dns_ptr_table dns_ptr_table;

static char dns_conf_dnsmasq_lease_file[DNS_MAX_PATH];
static time_t dns_conf_dnsmasq_lease_file_time;

struct dns_hosts_table dns_hosts_table;
int dns_hosts_record_num;

/* server ip/port  */
struct dns_bind_ip dns_conf_bind_ip[DNS_MAX_BIND_IP];
int dns_conf_bind_ip_num = 0;
int dns_conf_tcp_idle_time = 120;

int dns_conf_max_reply_ip_num = DNS_MAX_REPLY_IP_NUM;

static struct config_enum_list dns_conf_response_mode_enum[] = {
	{"first-ping", DNS_RESPONSE_MODE_FIRST_PING_IP},
	{"fastest-ip", DNS_RESPONSE_MODE_FASTEST_IP},
	{"fastest-response", DNS_RESPONSE_MODE_FASTEST_RESPONSE},
	{0, 0}};

enum response_mode_type dns_conf_response_mode;

/* cache */
int dns_conf_cachesize = DEFAULT_DNS_CACHE_SIZE;
int dns_conf_prefetch = 0;
int dns_conf_serve_expired = 1;
int dns_conf_serve_expired_ttl = 24 * 3600; /* 1 day */
int dns_conf_serve_expired_prefetch_time;
int dns_conf_serve_expired_reply_ttl = 3;

/* upstream servers */
struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
char dns_conf_server_name[DNS_MAX_SERVER_NAME_LEN];
int dns_conf_server_num;

struct dns_domain_check_orders dns_conf_check_orders = {
	.orders =
		{
			{.type = DOMAIN_CHECK_ICMP, .tcp_port = 0},
			{.type = DOMAIN_CHECK_TCP, .tcp_port = 80},
			{.type = DOMAIN_CHECK_TCP, .tcp_port = 443},
		},
};
static int dns_has_cap_ping = 0;

/* logging */
int dns_conf_log_level = TLOG_ERROR;
char dns_conf_log_file[DNS_MAX_PATH];
size_t dns_conf_log_size = 1024 * 1024;
int dns_conf_log_num = 8;

/* CA file */
char dns_conf_ca_file[DNS_MAX_PATH];
char dns_conf_ca_path[DNS_MAX_PATH];

char dns_conf_cache_file[DNS_MAX_PATH];
int dns_conf_cache_persist = 2;

/* auditing */
int dns_conf_audit_enable = 0;
int dns_conf_audit_log_SOA;
char dns_conf_audit_file[DNS_MAX_PATH];
size_t dns_conf_audit_size = 1024 * 1024;
int dns_conf_audit_num = 2;

/* address rules */
art_tree dns_conf_domain_rule;
struct dns_conf_address_rule dns_conf_address_rule;

/* dual-stack selection */
int dns_conf_dualstack_ip_selection = 1;
int dns_conf_dualstack_ip_allow_force_AAAA;
int dns_conf_dualstack_ip_selection_threshold = 15;

/* TTL */
int dns_conf_rr_ttl;
int dns_conf_rr_ttl_reply_max;
int dns_conf_rr_ttl_min = 600;
int dns_conf_rr_ttl_max;
int dns_conf_local_ttl;
int dns_conf_force_AAAA_SOA;
int dns_conf_force_no_cname;
int dns_conf_ipset_timeout_enable;

char dns_conf_user[DNS_CONF_USRNAME_LEN];

int dns_save_fail_packet;
char dns_save_fail_packet_dir[DNS_MAX_PATH];

/* ECS */
struct dns_edns_client_subnet dns_conf_ipv4_ecs;
struct dns_edns_client_subnet dns_conf_ipv6_ecs;

char dns_conf_sni_proxy_ip[DNS_MAX_IPLEN];

static int _get_domain(char *value, char *domain, int max_dmain_size, char **ptr_after_domain)
{
	char *begin = NULL;
	char *end = NULL;
	int len = 0;

	if (value == NULL || domain == NULL) {
		goto errout;
	}

	/* first field */
	begin = strstr(value, "/");
	if (begin == NULL) {
		goto errout;
	}

	/* second field */
	begin++;
	end = strstr(begin, "/");
	if (end == NULL) {
		goto errout;
	}

	/* remove prefix . */
	while (*begin == '.') {
		begin++;
	}

	/* Get domain */
	len = end - begin;
	if (len >= max_dmain_size) {
		tlog(TLOG_ERROR, "domain name %s too long", value);
		goto errout;
	}

	memcpy(domain, begin, len);
	domain[len] = '\0';

	if (ptr_after_domain) {
		*ptr_after_domain = end + 1;
	}

	return 0;
errout:
	return -1;
}

/* create and get dns server group */
static struct dns_server_groups *_dns_conf_get_group(const char *group_name)
{
	uint32_t key = 0;
	struct dns_server_groups *group = NULL;

	key = hash_string(group_name);
	hash_for_each_possible(dns_group_table.group, group, node, key)
	{
		if (strncmp(group->group_name, group_name, DNS_MAX_IPLEN) == 0) {
			return group;
		}
	}

	group = malloc(sizeof(*group));
	if (group == NULL) {
		goto errout;
	}

	memset(group, 0, sizeof(*group));
	safe_strncpy(group->group_name, group_name, DNS_GROUP_NAME_LEN);
	hash_add(dns_group_table.group, &group->node, key);

	return group;
errout:
	if (group) {
		free(group);
	}

	return NULL;
}

static int _dns_conf_get_group_set(const char *group_name, struct dns_servers *server)
{
	struct dns_server_groups *group = NULL;
	int i = 0;

	group = _dns_conf_get_group(group_name);
	if (group == NULL) {
		return -1;
	}

	for (i = 0; i < group->server_num; i++) {
		if (group->servers[i] == server) {
			return 0;
		}
	}

	if (group->server_num >= DNS_MAX_SERVERS) {
		return -1;
	}

	group->servers[group->server_num] = server;
	group->server_num++;

	return 0;
}

static const char *_dns_conf_get_group_name(const char *group_name)
{
	struct dns_server_groups *group = NULL;

	group = _dns_conf_get_group(group_name);
	if (group == NULL) {
		return NULL;
	}

	return group->group_name;
}

static void _config_group_table_destroy(void)
{
	struct dns_server_groups *group = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_group_table.group, i, tmp, group, node)
	{
		hlist_del_init(&group->node);
		free(group);
	}
}

static int _config_server(int argc, char *argv[], dns_server_type_t type, int default_port)
{
	int index = dns_conf_server_num;
	struct dns_servers *server = NULL;
	int port = -1;
	char *ip = NULL;
	int opt = 0;
	unsigned int result_flag = 0;
	unsigned int server_flag = 0;
	unsigned char *spki = NULL;

	int ttl = 0;
	/* clang-format off */
	static struct option long_options[] = {
		{"blacklist-ip", no_argument, NULL, 'b'}, /* filtering with blacklist-ip */
		{"whitelist-ip", no_argument, NULL, 'w'}, /* filtering with whitelist-ip */
#ifdef FEATURE_CHECK_EDNS
		/* experimental feature */
		{"check-edns", no_argument, NULL, 'e'},   /* check edns */
#endif 
		{"spki-pin", required_argument, NULL, 'p'}, /* check SPKI pin */
		{"host-name", required_argument, NULL, 'h'}, /* host name */
		{"http-host", required_argument, NULL, 'H'}, /* http host */
		{"no-check-certificate", no_argument, NULL, 'N'}, /* do not check certificate */
		{"tls-host-verify", required_argument, NULL, 'V' }, /* verify tls hostname */
		{"group", required_argument, NULL, 'g'}, /* add to group */
		{"exclude-default-group", no_argument, NULL, 'E'}, /* ecluse this from default group */
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

	server = &dns_conf_servers[index];
	server->spki[0] = '\0';
	server->path[0] = '\0';
	server->hostname[0] = '\0';
	server->httphost[0] = '\0';
	server->tls_host_verify[0] = '\0';

	if (type == DNS_SERVER_HTTPS) {
		if (parse_uri(ip, NULL, server->server, &port, server->path) != 0) {
			return -1;
		}
		safe_strncpy(server->hostname, server->server, sizeof(server->hostname));
		safe_strncpy(server->httphost, server->server, sizeof(server->httphost));
		if (server->path[0] == 0) {
			safe_strncpy(server->path, "/", sizeof(server->path));
		}
	} else {
		/* parse ip, port from ip */
		if (parse_ip(ip, server->server, &port) != 0) {
			return -1;
		}
	}

	/* if port is not defined, set port to default 53 */
	if (port == PORT_NOT_DEFINED) {
		port = default_port;
	}

	/* process extra options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'b': {
			result_flag |= DNSSERVER_FLAG_BLACKLIST_IP;
			break;
		}
		case 'w': {
			result_flag |= DNSSERVER_FLAG_WHITELIST_IP;
			break;
		}
		case 'e': {
			result_flag |= DNSSERVER_FLAG_CHECK_EDNS;
			break;
		}
		case 'h': {
			safe_strncpy(server->hostname, optarg, DNS_MAX_CNAME_LEN);
			break;
		}
		case 'H': {
			safe_strncpy(server->httphost, optarg, DNS_MAX_CNAME_LEN);
			break;
		}
		case 'E': {
			server_flag |= SERVER_FLAG_EXCLUDE_DEFAULT;
			break;
		}
		case 'g': {
			if (_dns_conf_get_group_set(optarg, server) != 0) {
				tlog(TLOG_ERROR, "add group failed.");
				goto errout;
			}
			break;
		}
		case 'p': {
			safe_strncpy(server->spki, optarg, DNS_MAX_SPKI_LEN);
			break;
		}
		case 'V': {
			safe_strncpy(server->tls_host_verify, optarg, DNS_MAX_CNAME_LEN);
			break;
		}
		case 'N': {
			server->skip_check_cert = 1;
			break;
		}
		default:
			break;
		}
	}

	/* add new server */
	server->type = type;
	server->port = port;
	server->result_flag = result_flag;
	server->server_flag = server_flag;
	server->ttl = ttl;
	dns_conf_server_num++;
	tlog(TLOG_DEBUG, "add server %s, flag: %X, ttl: %d", ip, result_flag, ttl);

	return 0;

errout:
	if (spki) {
		free(spki);
	}

	return -1;
}

static int _config_domain_iter_free(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct dns_domain_rule *domain_rule = value;
	int i = 0;

	if (domain_rule == NULL) {
		return 0;
	}

	for (i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (domain_rule->rules[i] == NULL) {
			continue;
		}

		free(domain_rule->rules[i]);
	}

	free(domain_rule);
	return 0;
}

static void _config_domain_destroy(void)
{
	art_iter(&dns_conf_domain_rule, _config_domain_iter_free, NULL);
	art_tree_destroy(&dns_conf_domain_rule);
}

static void _config_address_destroy(radix_node_t *node, void *cbctx)
{
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	free(node->data);
	node->data = NULL;
}

static int _config_domain_rule_add(char *domain, enum domain_rule type, void *rule)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;

	/* Reverse string, for suffix match */
	len = strlen(domain);
	if (len >= (int)sizeof(domain_key)) {
		tlog(TLOG_ERROR, "domain name %s too long", domain);
		goto errout;
	}
	reverse_string(domain_key, domain, len, 1);
	domain_key[len] = '.';
	len++;
	domain_key[len] = 0;

	if (type >= DOMAIN_RULE_MAX) {
		goto errout;
	}

	/* Get existing or create domain rule */
	domain_rule = art_search(&dns_conf_domain_rule, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		add_domain_rule = malloc(sizeof(*add_domain_rule));
		if (add_domain_rule == NULL) {
			goto errout;
		}
		memset(add_domain_rule, 0, sizeof(*add_domain_rule));
		domain_rule = add_domain_rule;
	}

	/* add new rule to domain */
	if (domain_rule->rules[type]) {
		free(domain_rule->rules[type]);
		domain_rule->rules[type] = NULL;
	}

	domain_rule->rules[type] = rule;

	/* update domain rule */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&dns_conf_domain_rule, (unsigned char *)domain_key, len, add_domain_rule);
		if (old_domain_rule) {
			free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add doamin %s rule failed", domain);
	return -1;
}

static int _config_domain_rule_flag_set(char *domain, unsigned int flag, unsigned int is_clear)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;
	struct dns_rule_flags *rule_flags = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;

	len = strlen(domain);
	if (len >= (int)sizeof(domain_key)) {
		tlog(TLOG_ERROR, "domain %s too long", domain);
		return -1;
	}
	reverse_string(domain_key, domain, len, 1);
	domain_key[len] = '.';
	len++;
	domain_key[len] = 0;

	/* Get existing or create domain rule */
	domain_rule = art_search(&dns_conf_domain_rule, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		add_domain_rule = malloc(sizeof(*add_domain_rule));
		if (add_domain_rule == NULL) {
			goto errout;
		}
		memset(add_domain_rule, 0, sizeof(*add_domain_rule));
		domain_rule = add_domain_rule;
	}

	/* add new rule to domain */
	if (domain_rule->rules[DOMAIN_RULE_FLAGS] == NULL) {
		rule_flags = malloc(sizeof(*rule_flags));
		memset(rule_flags, 0, sizeof(*rule_flags));
		rule_flags->flags = 0;
		domain_rule->rules[DOMAIN_RULE_FLAGS] = rule_flags;
	}

	rule_flags = domain_rule->rules[DOMAIN_RULE_FLAGS];
	if (is_clear == false) {
		rule_flags->flags |= flag;
	} else {
		rule_flags->flags &= ~flag;
	}
	rule_flags->is_flag_set |= flag;

	/* update domain rule */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&dns_conf_domain_rule, (unsigned char *)domain_key, len, add_domain_rule);
		if (old_domain_rule) {
			free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add doamin %s rule failed", domain);
	return 0;
}

static void _config_ipset_table_destroy(void)
{
	struct dns_ipset_name *ipset_name = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ipset_table.ipset, i, tmp, ipset_name, node)
	{
		hlist_del_init(&ipset_name->node);
		free(ipset_name);
	}
}

static const char *_dns_conf_get_ipset(const char *ipsetname)
{
	uint32_t key = 0;
	struct dns_ipset_name *ipset_name = NULL;

	key = hash_string(ipsetname);
	hash_for_each_possible(dns_ipset_table.ipset, ipset_name, node, key)
	{
		if (strncmp(ipset_name->ipsetname, ipsetname, DNS_MAX_IPSET_NAMELEN) == 0) {
			return ipset_name->ipsetname;
		}
	}

	ipset_name = malloc(sizeof(*ipset_name));
	if (ipset_name == NULL) {
		goto errout;
	}

	key = hash_string(ipsetname);
	safe_strncpy(ipset_name->ipsetname, ipsetname, DNS_MAX_IPSET_NAMELEN);
	hash_add(dns_ipset_table.ipset, &ipset_name->node, key);

	return ipset_name->ipsetname;
errout:
	if (ipset_name) {
		free(ipset_name);
	}

	return NULL;
}

static int _conf_domain_rule_ipset(char *domain, const char *ipsetname)
{
	struct dns_ipset_rule *ipset_rule = NULL;
	const char *ipset = NULL;
	char *copied_name = NULL;
	enum domain_rule type = 0;
	int ignore_flag = 0;

	copied_name = strdup(ipsetname);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok; tok = strtok(NULL, ",")) {
		if (tok[0] == '#') {
			if (strncmp(tok, "#6:", 3U) == 0) {
				type = DOMAIN_RULE_IPSET_IPV6;
				ignore_flag = DOMAIN_FLAG_IPSET_IPV6_IGN;
			} else if (strncmp(tok, "#4:", 3U) == 0) {
				type = DOMAIN_RULE_IPSET_IPV4;
				ignore_flag = DOMAIN_FLAG_IPSET_IPV4_IGN;
			} else {
				goto errout;
			}
			tok += 3;
		} else {
			type = DOMAIN_RULE_IPSET;
			ignore_flag = DOMAIN_FLAG_IPSET_IGN;
		}

		if (strncmp(tok, "-", 1) == 0) {
			_config_domain_rule_flag_set(domain, ignore_flag, 0);
			continue;
		}

		/* new ipset domain */
		ipset = _dns_conf_get_ipset(tok);
		if (ipset == NULL) {
			goto errout;
		}

		ipset_rule = malloc(sizeof(*ipset_rule));
		if (ipset_rule == NULL) {
			goto errout;
		}

		ipset_rule->ipsetname = ipset;

		if (_config_domain_rule_add(domain, type, ipset_rule) != 0) {
			goto errout;
		}
	}

	goto clear;

errout:
	tlog(TLOG_ERROR, "add ipset %s failed", ipsetname);

	if (ipset_rule) {
		free(ipset_rule);
	}

clear:
	if (copied_name) {
		free(copied_name);
	}

	return 0;
}

static int _config_ipset(void *data, int argc, char *argv[])
{
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_ipset(domain, value);
errout:
	tlog(TLOG_ERROR, "add ipset %s failed", value);
	return 0;
}

static int _conf_domain_rule_address(char *domain, const char *domain_address)
{
	struct dns_address_IPV4 *address_ipv4 = NULL;
	struct dns_address_IPV6 *address_ipv6 = NULL;
	void *address = NULL;
	char ip[MAX_IP_LEN];
	int port = 0;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	enum domain_rule type = 0;
	unsigned int flag = 0;

	if (*(domain_address) == '#') {
		if (strncmp(domain_address, "#4", sizeof("#4")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV4_SOA;
		} else if (strncmp(domain_address, "#6", sizeof("#6")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV6_SOA;
		} else if (strncmp(domain_address, "#", sizeof("#")) == 0) {
			flag = DOMAIN_FLAG_ADDR_SOA;
		} else {
			goto errout;
		}

		/* add SOA rule */
		if (_config_domain_rule_flag_set(domain, flag, 0) != 0) {
			goto errout;
		}

		return 0;
	} else if (*(domain_address) == '-') {
		if (strncmp(domain_address, "-4", sizeof("-4")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV4_IGN;
		} else if (strncmp(domain_address, "-6", sizeof("-6")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV6_IGN;
		} else if (strncmp(domain_address, "-", sizeof("-")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IGN;
		} else {
			goto errout;
		}

		/* ignore rule */
		if (_config_domain_rule_flag_set(domain, flag, 0) != 0) {
			goto errout;
		}

		return 0;
	} else {
		/* set address to domain */
		if (parse_ip(domain_address, ip, &port) != 0) {
			goto errout;
		}

		if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
			goto errout;
		}

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in = NULL;
			address_ipv4 = malloc(sizeof(*address_ipv4));
			if (address_ipv4 == NULL) {
				goto errout;
			}

			addr_in = (struct sockaddr_in *)&addr;
			memcpy(address_ipv4->ipv4_addr, &addr_in->sin_addr.s_addr, 4);
			type = DOMAIN_RULE_ADDRESS_IPV4;
			address = address_ipv4;
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
				address_ipv4 = malloc(sizeof(*address_ipv4));
				if (address_ipv4 == NULL) {
					goto errout;
				}
				memcpy(address_ipv4->ipv4_addr, addr_in6->sin6_addr.s6_addr + 12, 4);
				type = DOMAIN_RULE_ADDRESS_IPV4;
				address = address_ipv4;
			} else {
				address_ipv6 = malloc(sizeof(*address_ipv6));
				if (address_ipv6 == NULL) {
					goto errout;
				}
				memcpy(address_ipv6->ipv6_addr, addr_in6->sin6_addr.s6_addr, 16);
				type = DOMAIN_RULE_ADDRESS_IPV6;
				address = address_ipv6;
			}
		} break;
		default:
			goto errout;
		}
	}

	/* add domain to ART-tree */
	if (_config_domain_rule_add(domain, type, address) != 0) {
		goto errout;
	}

	return 0;
errout:
	if (address) {
		free(address);
	}

	tlog(TLOG_ERROR, "add address %s, %s  failed", domain, domain_address);
	return 0;
}

static int _config_address(void *data, int argc, char *argv[])
{
	char *value = argv[1];
	char domain[DNS_MAX_CONF_CNAME_LEN];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_address(domain, value);
errout:
	tlog(TLOG_ERROR, "add address %s failed", value);
	return 0;
}

static int _config_speed_check_mode_parser(struct dns_domain_check_orders *check_orders, const char *mode)
{
	char tmpbuff[DNS_MAX_OPT_LEN];
	char *field = NULL;
	char *ptr = NULL;
	int order = 0;
	int port = 80;
	int i = 0;

	safe_strncpy(tmpbuff, mode, DNS_MAX_OPT_LEN);
	memset(check_orders, 0, sizeof(*check_orders));

	ptr = tmpbuff;
	do {
		field = ptr;
		ptr = strstr(ptr, ",");
		if (field == NULL || order >= DOMAIN_CHECK_NUM) {
			return 0;
		}

		if (ptr) {
			*ptr = 0;
		}

		if (strncmp(field, "ping", sizeof("ping")) == 0) {
			if (dns_has_cap_ping == 0) {
				if (ptr) {
					ptr++;
				}
				continue;
			}
			check_orders->orders[order].type = DOMAIN_CHECK_ICMP;
			check_orders->orders[order].tcp_port = 0;
		} else if (strstr(field, "tcp") == field) {
			char *port_str = strstr(field, ":");
			if (port_str) {
				port = atoi(port_str + 1);
				if (port <= 0 || port >= 65535) {
					port = 80;
				}
			}

			check_orders->orders[order].type = DOMAIN_CHECK_TCP;
			check_orders->orders[order].tcp_port = port;
		} else if (strncmp(field, "none", sizeof("none")) == 0) {
			for (i = order; i < DOMAIN_CHECK_NUM; i++) {
				check_orders->orders[i].type = DOMAIN_CHECK_NONE;
				check_orders->orders[i].tcp_port = 0;
			}

			return 0;
		}
		order++;
		if (ptr) {
			ptr++;
		}

	} while (ptr);

	return 0;
}

static int _config_speed_check_mode(void *data, int argc, char *argv[])
{
	char mode[DNS_MAX_OPT_LEN];

	if (argc <= 1) {
		return -1;
	}

	safe_strncpy(mode, argv[1], sizeof(mode));
	return _config_speed_check_mode_parser(&dns_conf_check_orders, mode);
}

static int _config_bind_ip(int argc, char *argv[], DNS_BIND_TYPE type)
{
	int index = dns_conf_bind_ip_num;
	struct dns_bind_ip *bind_ip = NULL;
	char *ip = NULL;
	int opt = 0;
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
		{"force-aaaa-soa", no_argument, NULL, 'F'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	ip = argv[1];
	if (index >= DNS_MAX_SERVERS) {
		tlog(TLOG_WARN, "exceeds max server number, %s", ip);
		return 0;
	}

	for (i = 0; i < dns_conf_bind_ip_num; i++) {
		bind_ip = &dns_conf_bind_ip[i];
		if (bind_ip->type != type) {
			continue;
		}

		if (strncmp(bind_ip->ip, ip, DNS_MAX_IPLEN) != 0) {
			continue;
		}

		tlog(TLOG_WARN, "Bind server %s, type %d, already configured, skip.", ip, type);
		return 0;
	}

	bind_ip = &dns_conf_bind_ip[index];
	bind_ip->type = type;
	bind_ip->flags = 0;
	safe_strncpy(bind_ip->ip, ip, DNS_MAX_IPLEN);

	/* process extra options */
	optind = 1;
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
		default:
			break;
		}
	}

	/* add new server */
	bind_ip->flags = server_flag;
	bind_ip->group = group;
	dns_conf_bind_ip_num++;
	tlog(TLOG_DEBUG, "bind ip %s, type: %d, flag: %X", ip, type, server_flag);

	return 0;

errout:
	return -1;
}

static int _config_bind_ip_udp(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_UDP);
}

static int _config_bind_ip_tcp(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_TCP);
}

static int _config_server_udp(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_UDP, DEFAULT_DNS_PORT);
}

static int _config_server_tcp(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_TCP, DEFAULT_DNS_PORT);
}

static int _config_server_tls(void *data, int argc, char *argv[])
{
	return _config_server(argc, argv, DNS_SERVER_TLS, DEFAULT_DNS_TLS_PORT);
}

static int _config_server_https(void *data, int argc, char *argv[])
{
	int ret = 0;
	ret = _config_server(argc, argv, DNS_SERVER_HTTPS, DEFAULT_DNS_HTTPS_PORT);

	return ret;
}

static int _conf_domain_rule_nameserver(char *domain, const char *group_name)
{
	struct dns_nameserver_rule *nameserver_rule = NULL;
	const char *group = NULL;

	if (strncmp(group_name, "-", sizeof("-")) != 0) {
		group = _dns_conf_get_group_name(group_name);
		if (group == NULL) {
			goto errout;
		}

		nameserver_rule = malloc(sizeof(*nameserver_rule));
		if (nameserver_rule == NULL) {
			goto errout;
		}

		nameserver_rule->group_name = group;
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_NAMESERVER_IGNORE, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_NAMESERVER, nameserver_rule) != 0) {
		goto errout;
	}

	return 0;
errout:
	if (nameserver_rule) {
		free(nameserver_rule);
	}

	tlog(TLOG_ERROR, "add nameserver %s, %s failed", domain, group_name);
	return 0;
}

static int _conf_domain_rule_dualstack_selection(char *domain, const char *yesno)
{
	if (strncmp(yesno, "yes", sizeof("yes")) == 0 || strncmp(yesno, "Yes", sizeof("Yes")) == 0) {
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_DUALSTACK_SELECT, 0) != 0) {
			goto errout;
		}
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_DUALSTACK_SELECT, 1) != 0) {
			goto errout;
		}
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "set dualstack for %s failed. ", domain);
	return 1;
}

static int _config_nameserver(void *data, int argc, char *argv[])
{
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_nameserver(domain, value);
errout:
	tlog(TLOG_ERROR, "add nameserver %s failed", value);
	return 0;
}

static radix_node_t *_create_addr_node(char *addr)
{
	radix_node_t *node = NULL;
	void *p = NULL;
	prefix_t prefix;
	const char *errmsg = NULL;
	radix_tree_t *tree = NULL;

	p = prefix_pton(addr, -1, &prefix, &errmsg);
	if (p == NULL) {
		return NULL;
	}

	switch (prefix.family) {
	case AF_INET:
		tree = dns_conf_address_rule.ipv4;
		break;
	case AF_INET6:
		tree = dns_conf_address_rule.ipv6;
		break;
	}

	node = radix_lookup(tree, &prefix);
	return node;
}

static int _config_iplist_rule(char *subnet, enum address_rule rule)
{
	radix_node_t *node = NULL;
	struct dns_ip_address_rule *ip_rule = NULL;

	node = _create_addr_node(subnet);
	if (node == NULL) {
		return -1;
	}

	if (node->data == NULL) {
		ip_rule = malloc(sizeof(*ip_rule));
		if (ip_rule == NULL) {
			return -1;
		}

		node->data = ip_rule;
		memset(ip_rule, 0, sizeof(*ip_rule));
	}

	ip_rule = node->data;

	switch (rule) {
	case ADDRESS_RULE_BLACKLIST:
		ip_rule->blacklist = 1;
		break;
	case ADDRESS_RULE_WHITELIST:
		ip_rule->whitelist = 1;
		break;
	case ADDRESS_RULE_BOGUS:
		ip_rule->bogus = 1;
		break;
	case ADDRESS_RULE_IP_IGNORE:
		ip_rule->ip_ignore = 1;
		break;
	default:
		return -1;
	}

	return 0;
}

static int _config_qtype_soa(void *data, int argc, char *argv[])
{
	struct dns_qtype_soa_list *soa_list = NULL;
	int i = 0;

	if (argc <= 1) {
		return -1;
	}

	for (i = 1; i < argc; i++) {
		soa_list = malloc(sizeof(*soa_list));
		if (soa_list == NULL) {
			tlog(TLOG_ERROR, "cannot malloc memory");
			return -1;
		}

		memset(soa_list, 0, sizeof(*soa_list));
		soa_list->qtypeid = atol(argv[i]);
		if (soa_list->qtypeid == DNS_T_AAAA) {
			dns_conf_force_AAAA_SOA = 1;
		}
		uint32_t key = hash_32_generic(soa_list->qtypeid, 32);
		hash_add(dns_qtype_soa_table.qtype, &soa_list->node, key);
	}

	return 0;
}

static void _config_qtype_soa_table_destroy(void)
{
	struct dns_qtype_soa_list *soa_list = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_qtype_soa_table.qtype, i, tmp, soa_list, node)
	{
		hlist_del_init(&soa_list->node);
		free(soa_list);
	}
}

static int _config_blacklist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_iplist_rule(argv[1], ADDRESS_RULE_BLACKLIST);
}

static int _conf_bogus_nxdomain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_iplist_rule(argv[1], ADDRESS_RULE_BOGUS);
}

static int _conf_ip_ignore(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_iplist_rule(argv[1], ADDRESS_RULE_IP_IGNORE);
}

static int _conf_whitelist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_iplist_rule(argv[1], ADDRESS_RULE_WHITELIST);
}

static int _conf_edns_client_subnet(void *data, int argc, char *argv[])
{
	char *slash = NULL;
	char *value = NULL;
	int subnet = 0;
	struct dns_edns_client_subnet *ecs = NULL;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (argc <= 1) {
		return -1;
	}

	value = argv[1];

	slash = strstr(value, "/");
	if (slash) {
		*slash = 0;
		slash++;
		subnet = atoi(slash);
		if (subnet < 0 || subnet > 128) {
			return -1;
		}
	}

	if (getaddr_by_host(value, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET:
		ecs = &dns_conf_ipv4_ecs;
		break;
	case AF_INET6:
		ecs = &dns_conf_ipv6_ecs;
		break;
	default:
		goto errout;
	}

	safe_strncpy(ecs->ip, value, DNS_MAX_IPLEN);
	ecs->subnet = subnet;
	ecs->enable = 1;

	return 0;

errout:
	return -1;
}

static int _conf_domain_rule_speed_check(char *domain, const char *mode)
{
	struct dns_domain_check_orders *check_orders = NULL;

	check_orders = malloc(sizeof(*check_orders) * DOMAIN_CHECK_NUM);
	if (check_orders == NULL) {
		goto errout;
	}
	memset(check_orders, 0, sizeof(*check_orders));

	if (_config_speed_check_mode_parser(check_orders, mode) != 0) {
		goto errout;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_CHECKSPEED, check_orders) != 0) {
		goto errout;
	}

	return 0;
errout:
	if (check_orders) {
		free(check_orders);
	}
	return 0;
}

static int _conf_domain_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];

	/* clang-format off */
	static struct option long_options[] = {
		{"speed-check-mode", required_argument, NULL, 'c'},
		{"address", required_argument, NULL, 'a'},
		{"ipset", required_argument, NULL, 'p'},
		{"nameserver", required_argument, NULL, 'n'},
		{"dualstack-ip-selection", required_argument, NULL, 'd'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	/* process extra options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "c:a:p:n:d:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'c': {
			const char *check_mode = optarg;
			if (check_mode == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_speed_check(domain, check_mode) != 0) {
				tlog(TLOG_ERROR, "add check-speed-rule rule failed.");
				goto errout;
			}

			break;
		}
		case 'a': {
			const char *address = optarg;
			if (address == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_address(domain, address) != 0) {
				tlog(TLOG_ERROR, "add address rule failed.");
				goto errout;
			}

			break;
		}
		case 'p': {
			const char *ipsetname = optarg;
			if (ipsetname == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_ipset(domain, ipsetname) != 0) {
				tlog(TLOG_ERROR, "add ipset rule failed.");
				goto errout;
			}

			break;
		}
		case 'n': {
			const char *nameserver_group = optarg;
			if (nameserver_group == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_nameserver(domain, nameserver_group) != 0) {
				tlog(TLOG_ERROR, "add nameserver rule failed.");
				goto errout;
			}

			break;
		}
		case 'd': {
			const char *yesno = optarg;
			if (_conf_domain_rule_dualstack_selection(domain, yesno) != 0) {
				tlog(TLOG_ERROR, "set dualstack selection rule failed.");
				goto errout;
			}

			break;
		}
		default:
			break;
		}
	}

	return 0;
errout:
	return -1;
}

static struct dns_ptr *_dns_conf_get_ptr(const char *ptr_domain)
{
	uint32_t key = 0;
	struct dns_ptr *ptr = NULL;

	key = hash_string(ptr_domain);
	hash_for_each_possible(dns_ptr_table.ptr, ptr, node, key)
	{
		if (strncmp(ptr->ptr_domain, ptr_domain, DNS_MAX_PTR_LEN) != 0) {
			continue;
		}

		return ptr;
	}

	ptr = malloc(sizeof(*ptr));
	if (ptr == NULL) {
		goto errout;
	}

	safe_strncpy(ptr->ptr_domain, ptr_domain, DNS_MAX_PTR_LEN);
	hash_add(dns_ptr_table.ptr, &ptr->node, key);

	return ptr;
errout:
	if (ptr) {
		free(ptr);
	}

	return NULL;
}

static int _conf_ptr_add(const char *hostname, const char *ip)
{
	struct dns_ptr *ptr = NULL;
	struct sockaddr_storage addr;
	unsigned char *paddr = NULL;
	socklen_t addr_len = sizeof(addr);
	char ptr_domain[DNS_MAX_PTR_LEN];

	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		paddr = (unsigned char *)&(addr_in->sin_addr.s_addr);
		snprintf(ptr_domain, sizeof(ptr_domain), "%d.%d.%d.%d.in-addr.arpa", paddr[3], paddr[2], paddr[1], paddr[0]);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			paddr = addr_in6->sin6_addr.s6_addr + 12;
			snprintf(ptr_domain, sizeof(ptr_domain), "%d.%d.%d.%d.in-addr.arpa", paddr[3], paddr[2], paddr[1],
					 paddr[0]);
		} else {
			paddr = addr_in6->sin6_addr.s6_addr;
			snprintf(ptr_domain, sizeof(ptr_domain),
					 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
					 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
					 "%x.ip6.arpa",
					 paddr[15] & 0xF, (paddr[15] >> 4) & 0xF, paddr[14] & 0xF, (paddr[14] >> 4) & 0xF, paddr[13] & 0xF,
					 (paddr[13] >> 4) & 0xF, paddr[12] & 0xF, (paddr[12] >> 4) & 0xF, paddr[11] & 0xF,
					 (paddr[11] >> 4) & 0xF, paddr[10] & 0xF, (paddr[10] >> 4) & 0xF, paddr[9] & 0xF,
					 (paddr[9] >> 4) & 0xF, paddr[8] & 0xF, (paddr[8] >> 4) & 0xF, paddr[7] & 0xF,
					 (paddr[7] >> 4) & 0xF, paddr[6] & 0xF, (paddr[6] >> 4) & 0xF, paddr[5] & 0xF,
					 (paddr[5] >> 4) & 0xF, paddr[4] & 0xF, (paddr[4] >> 4) & 0xF, paddr[3] & 0xF,
					 (paddr[3] >> 4) & 0xF, paddr[2] & 0xF, (paddr[2] >> 4) & 0xF, paddr[1] & 0xF,
					 (paddr[1] >> 4) & 0xF, paddr[0] & 0xF, (paddr[0] >> 4) & 0xF);
		}
	} break;
	default:
		goto errout;
		break;
	}

	ptr = _dns_conf_get_ptr(ptr_domain);
	if (ptr == NULL) {
		goto errout;
	}

	safe_strncpy(ptr->hostname, hostname, DNS_MAX_CNAME_LEN);

	return 0;

errout:
	return -1;
}

static void _config_ptr_table_destroy(void)
{
	struct dns_ptr *ptr = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ptr_table.ptr, i, tmp, ptr, node)
	{
		hlist_del_init(&ptr->node);
		free(ptr);
	}
}

static struct dns_hosts *_dns_conf_get_hosts(const char *hostname, int dns_type)
{
	uint32_t key = 0;
	struct dns_hosts *host = NULL;
	char hostname_lower[DNS_MAX_CNAME_LEN];

	key = hash_string(to_lower_case(hostname_lower, hostname, DNS_MAX_CNAME_LEN));
	key = jhash(&dns_type, sizeof(dns_type), key);
	hash_for_each_possible(dns_hosts_table.hosts, host, node, key)
	{
		if (host->dns_type != dns_type) {
			continue;
		}
		if (strncmp(host->domain, hostname_lower, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		return host;
	}

	host = malloc(sizeof(*host));
	if (host == NULL) {
		goto errout;
	}

	safe_strncpy(host->domain, hostname_lower, DNS_MAX_CNAME_LEN);
	host->dns_type = dns_type;
	host->is_soa = 1;
	hash_add(dns_hosts_table.hosts, &host->node, key);

	return host;
errout:
	if (host) {
		free(host);
	}

	return NULL;
}

static int _conf_host_add(const char *hostname, const char *ip, dns_hosts_type host_type)
{
	struct dns_hosts *host = NULL;
	struct dns_hosts *host_other __attribute__((unused));

	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int dns_type = 0;
	int dns_type_other = 0;

	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET:
		dns_type = DNS_T_A;
		dns_type_other = DNS_T_AAAA;
		break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			dns_type = DNS_T_A;
			dns_type_other = DNS_T_AAAA;
		} else {
			dns_type = DNS_T_AAAA;
			dns_type_other = DNS_T_A;
		}
	} break;
	default:
		goto errout;
		break;
	}

	host = _dns_conf_get_hosts(hostname, dns_type);
	if (host == NULL) {
		goto errout;
	}

	/* add this to return SOA when addr is not exist */
	host_other = _dns_conf_get_hosts(hostname, dns_type_other);

	host->host_type = host_type;

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		memcpy(host->ipv4_addr, &addr_in->sin_addr.s_addr, 4);
		host->is_soa = 0;
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			memcpy(host->ipv4_addr, addr_in6->sin6_addr.s6_addr + 12, 4);
		} else {
			memcpy(host->ipv6_addr, addr_in6->sin6_addr.s6_addr, 16);
		}
		host->is_soa = 0;
	} break;
	default:
		goto errout;
	}

	dns_hosts_record_num++;
	return 0;

errout:
	return -1;
}

static int _conf_dhcp_lease_dnsmasq_add(const char *file)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char ip[DNS_MAX_IPLEN];
	char hostname[DNS_MAX_CNAME_LEN];
	int ret = 0;
	int line_no = 0;
	int filed_num = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_WARN, "open file %s error, %s", file, strerror(errno));
		return 0;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_no++;
		filed_num = sscanf(line, "%*s %*s %64s %256s %*s", ip, hostname);
		if (filed_num <= 0) {
			continue;
		}

		if (strncmp(hostname, "*", DNS_MAX_CNAME_LEN - 1) == 0) {
			continue;
		}

		ret = _conf_host_add(hostname, ip, DNS_HOST_TYPE_DNSMASQ);
		if (ret != 0) {
			tlog(TLOG_WARN, "add host %s/%s at %d failed", hostname, ip, line_no);
		}

		ret = _conf_ptr_add(hostname, ip);
		if (ret != 0) {
			tlog(TLOG_WARN, "add ptr %s/%s at %d failed.", hostname, ip, line_no);
		}
	}

	fclose(fp);

	return 0;
}

static int _conf_dhcp_lease_dnsmasq_file(void *data, int argc, char *argv[])
{
	struct stat statbuf;

	if (argc < 1) {
		return -1;
	}

	conf_get_conf_fullpath(argv[1], dns_conf_dnsmasq_lease_file, sizeof(dns_conf_dnsmasq_lease_file));
	if (_conf_dhcp_lease_dnsmasq_add(dns_conf_dnsmasq_lease_file) != 0) {
		return -1;
	}

	if (stat(dns_conf_dnsmasq_lease_file, &statbuf) != 0) {
		return 0;
	}

	dns_conf_dnsmasq_lease_file_time = statbuf.st_mtime;
	return 0;
}

static int _conf_hosts_file(void *data, int argc, char *argv[])
{
	return 0;
}

static void _config_host_table_destroy(void)
{
	struct dns_hosts *host = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_hosts_table.hosts, i, tmp, host, node)
	{
		hlist_del_init(&host->node);
		free(host);
	}

	dns_hosts_record_num = 0;
}

int dns_server_check_update_hosts(void)
{
	struct stat statbuf;
	time_t now = 0;

	if (dns_conf_dnsmasq_lease_file[0] == '\0') {
		return -1;
	}

	if (stat(dns_conf_dnsmasq_lease_file, &statbuf) != 0) {
		return -1;
	}

	if (dns_conf_dnsmasq_lease_file_time == statbuf.st_mtime) {
		return -1;
	}

	time(&now);

	if (now - statbuf.st_mtime < 30) {
		return -1;
	}

	_config_ptr_table_destroy();
	_config_host_table_destroy();

	if (_conf_dhcp_lease_dnsmasq_add(dns_conf_dnsmasq_lease_file) != 0) {
		return -1;
	}

	dns_conf_dnsmasq_lease_file_time = statbuf.st_mtime;
	return 0;
}

static int _config_log_level(void *data, int argc, char *argv[])
{
	/* read log level and set */
	char *value = argv[1];

	if (strncmp("debug", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_DEBUG;
	} else if (strncmp("info", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_INFO;
	} else if (strncmp("notice", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_NOTICE;
	} else if (strncmp("warn", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_WARN;
	} else if (strncmp("error", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_ERROR;
	} else if (strncmp("fatal", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_FATAL;
	} else {
		return -1;
	}

	return 0;
}

static void _config_setup_smartdns_domain(void)
{
	char hostname[DNS_MAX_CNAME_LEN];
	/* get local host name */
	if (getdomainname(hostname, DNS_MAX_CNAME_LEN) != 0) {
		gethostname(hostname, DNS_MAX_CNAME_LEN);
	}

	/* get host name again */
	if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
		gethostname(hostname, DNS_MAX_CNAME_LEN);
	}

	/* if hostname is (none), return smartdns */
	if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
		safe_strncpy(hostname, "smartdns", DNS_MAX_CNAME_LEN);
	}

	if (hostname[0] != '\0') {
		_config_domain_rule_flag_set(hostname, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
	}

	if (dns_conf_server_name[0] != '\0') {
		_config_domain_rule_flag_set(dns_conf_server_name, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
	}

	_config_domain_rule_flag_set("smartdns", DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
}

static struct config_item _config_item[] = {
	CONF_STRING("server-name", (char *)dns_conf_server_name, DNS_MAX_SERVER_NAME_LEN),
	CONF_CUSTOM("bind", _config_bind_ip_udp, NULL),
	CONF_CUSTOM("bind-tcp", _config_bind_ip_tcp, NULL),
	CONF_CUSTOM("server", _config_server_udp, NULL),
	CONF_CUSTOM("server-tcp", _config_server_tcp, NULL),
	CONF_CUSTOM("server-tls", _config_server_tls, NULL),
	CONF_CUSTOM("server-https", _config_server_https, NULL),
	CONF_CUSTOM("nameserver", _config_nameserver, NULL),
	CONF_CUSTOM("address", _config_address, NULL),
	CONF_YESNO("ipset-timeout", &dns_conf_ipset_timeout_enable),
	CONF_CUSTOM("ipset", _config_ipset, NULL),
	CONF_CUSTOM("speed-check-mode", _config_speed_check_mode, NULL),
	CONF_INT("tcp-idle-time", &dns_conf_tcp_idle_time, 0, 3600),
	CONF_INT("cache-size", &dns_conf_cachesize, 0, CONF_INT_MAX),
	CONF_STRING("cache-file", (char *)&dns_conf_cache_file, DNS_MAX_PATH),
	CONF_YESNO("cache-persist", &dns_conf_cache_persist),
	CONF_YESNO("prefetch-domain", &dns_conf_prefetch),
	CONF_YESNO("serve-expired", &dns_conf_serve_expired),
	CONF_INT("serve-expired-ttl", &dns_conf_serve_expired_ttl, 0, CONF_INT_MAX),
	CONF_INT("serve-expired-reply-ttl", &dns_conf_serve_expired_reply_ttl, 0, CONF_INT_MAX),
	CONF_INT("serve-expired-prefetch-time", &dns_conf_serve_expired_prefetch_time, 0, CONF_INT_MAX),
	CONF_YESNO("dualstack-ip-selection", &dns_conf_dualstack_ip_selection),
	CONF_YESNO("dualstack-ip-allow-force-AAAA", &dns_conf_dualstack_ip_allow_force_AAAA),
	CONF_INT("dualstack-ip-selection-threshold", &dns_conf_dualstack_ip_selection_threshold, 0, 1000),
	CONF_CUSTOM("log-level", _config_log_level, NULL),
	CONF_STRING("log-file", (char *)dns_conf_log_file, DNS_MAX_PATH),
	CONF_SIZE("log-size", &dns_conf_log_size, 0, 1024 * 1024 * 1024),
	CONF_INT("log-num", &dns_conf_log_num, 0, 1024),
	CONF_YESNO("audit-enable", &dns_conf_audit_enable),
	CONF_YESNO("audit-SOA", &dns_conf_audit_log_SOA),
	CONF_STRING("audit-file", (char *)&dns_conf_audit_file, DNS_MAX_PATH),
	CONF_SIZE("audit-size", &dns_conf_audit_size, 0, 1024 * 1024 * 1024),
	CONF_INT("audit-num", &dns_conf_audit_num, 0, 1024),
	CONF_INT("rr-ttl", &dns_conf_rr_ttl, 0, CONF_INT_MAX),
	CONF_INT("rr-ttl-min", &dns_conf_rr_ttl_min, 0, CONF_INT_MAX),
	CONF_INT("rr-ttl-max", &dns_conf_rr_ttl_max, 0, CONF_INT_MAX),
	CONF_INT("rr-ttl-reply-max", &dns_conf_rr_ttl_reply_max, 0, CONF_INT_MAX),
	CONF_INT("local-ttl", &dns_conf_local_ttl, 0, CONF_INT_MAX),
	CONF_INT("max-reply-ip-num", &dns_conf_max_reply_ip_num, 1, CONF_INT_MAX),
	CONF_ENUM("response-mode", &dns_conf_response_mode, &dns_conf_response_mode_enum),
	CONF_YESNO("force-AAAA-SOA", &dns_conf_force_AAAA_SOA),
	CONF_YESNO("force-no-CNAME", &dns_conf_force_no_cname),
	CONF_CUSTOM("force-qtype-SOA", _config_qtype_soa, NULL),
	CONF_CUSTOM("blacklist-ip", _config_blacklist_ip, NULL),
	CONF_CUSTOM("whitelist-ip", _conf_whitelist_ip, NULL),
	CONF_CUSTOM("bogus-nxdomain", _conf_bogus_nxdomain, NULL),
	CONF_CUSTOM("ignore-ip", _conf_ip_ignore, NULL),
	CONF_CUSTOM("edns-client-subnet", _conf_edns_client_subnet, NULL),
	CONF_CUSTOM("domain-rules", _conf_domain_rules, NULL),
	CONF_CUSTOM("dnsmasq-lease-file", _conf_dhcp_lease_dnsmasq_file, NULL),
	CONF_CUSTOM("hosts-file", _conf_hosts_file, NULL),
	CONF_STRING("ca-file", (char *)&dns_conf_ca_file, DNS_MAX_PATH),
	CONF_STRING("ca-path", (char *)&dns_conf_ca_path, DNS_MAX_PATH),
	CONF_STRING("user", (char *)&dns_conf_user, sizeof(dns_conf_user)),
	CONF_YESNO("debug-save-fail-packet", &dns_save_fail_packet),
	CONF_STRING("debug-save-fail-packet-dir", (char *)&dns_save_fail_packet_dir, sizeof(dns_save_fail_packet_dir)),
	CONF_CUSTOM("conf-file", config_addtional_file, NULL),
	CONF_END(),
};

static int _conf_printf(const char *file, int lineno, int ret)
{
	switch (ret) {
	case CONF_RET_ERR:
	case CONF_RET_WARN:
	case CONF_RET_BADCONF:
		tlog(TLOG_WARN, "process config file '%s' failed at line %d.", file, lineno);
		syslog(LOG_NOTICE, "process config file '%s' failed at line %d.", file, lineno);
		return -1;
		break;
	default:
		break;
	}

	return 0;
}

int config_addtional_file(void *data, int argc, char *argv[])
{
	char *conf_file = NULL;
	char file_path[DNS_MAX_PATH];
	char file_path_dir[DNS_MAX_PATH];

	if (argc < 1) {
		return -1;
	}

	conf_file = argv[1];
	if (conf_file[0] != '/') {
		safe_strncpy(file_path_dir, conf_get_conf_file(), DNS_MAX_PATH);
		dirname(file_path_dir);
		if (strncmp(file_path_dir, conf_get_conf_file(), sizeof(file_path_dir)) == 0) {
			if (snprintf(file_path, DNS_MAX_PATH, "%s", conf_file) < 0) {
				return -1;
			}
		} else {
			if (snprintf(file_path, DNS_MAX_PATH, "%s/%s", file_path_dir, conf_file) < 0) {
				return -1;
			}
		}
	} else {
		safe_strncpy(file_path, conf_file, DNS_MAX_PATH);
	}

	if (access(file_path, R_OK) != 0) {
		tlog(TLOG_WARN, "conf file %s is not readable.", file_path);
		syslog(LOG_NOTICE, "conf file %s is not readable.", file_path);
		return 0;
	}

	return load_conf(file_path, _config_item, _conf_printf);
}

static int _dns_server_load_conf_init(void)
{
	dns_conf_address_rule.ipv4 = New_Radix();
	dns_conf_address_rule.ipv6 = New_Radix();
	if (dns_conf_address_rule.ipv4 == NULL || dns_conf_address_rule.ipv6 == NULL) {
		tlog(TLOG_WARN, "init radix tree failed.");
		return -1;
	}

	art_tree_init(&dns_conf_domain_rule);

	hash_init(dns_ipset_table.ipset);
	hash_init(dns_qtype_soa_table.qtype);
	hash_init(dns_group_table.group);
	hash_init(dns_hosts_table.hosts);
	hash_init(dns_ptr_table.ptr);

	_config_setup_smartdns_domain();

	return 0;
}

void dns_server_load_exit(void)
{
	_config_domain_destroy();
	Destroy_Radix(dns_conf_address_rule.ipv4, _config_address_destroy, NULL);
	Destroy_Radix(dns_conf_address_rule.ipv6, _config_address_destroy, NULL);
	_config_ipset_table_destroy();
	_config_group_table_destroy();
	_config_ptr_table_destroy();
	_config_host_table_destroy();
	_config_qtype_soa_table_destroy();
}

static int _dns_conf_speed_check_mode_verify(void)
{
	int i = 0;
	int j = 0;
	int print_log = 0;

	if (dns_has_cap_ping == 1) {
		return 0;
	}

	for (i = 0; i < DOMAIN_CHECK_NUM; i++) {
		if (dns_conf_check_orders.orders[i].type == DOMAIN_CHECK_ICMP) {
			for (j = i + 1; j < DOMAIN_CHECK_NUM; j++) {
				dns_conf_check_orders.orders[j - 1].type = dns_conf_check_orders.orders[j].type;
				dns_conf_check_orders.orders[j - 1].tcp_port = dns_conf_check_orders.orders[j].tcp_port;
			}
			dns_conf_check_orders.orders[j - 1].type = DOMAIN_CHECK_NONE;
			dns_conf_check_orders.orders[j - 1].tcp_port = 0;
			print_log = 1;
		}
	}

	if (print_log) {
		tlog(TLOG_WARN, "speed check by ping is disabled because smartdns does not have network raw privileges");
	}

	return 0;
}

static int _dns_ping_cap_check(void)
{
	int has_ping = 0;
	int has_raw_cap = 0;

	has_raw_cap = has_network_raw_cap();
	has_ping = has_unprivileged_ping();
	if (has_ping == 0) {
		if (errno == EACCES && has_raw_cap == 0) {
			tlog(TLOG_WARN, "unpriviledged ping is disabled, please enable by setting net.ipv4.ping_group_range");
		}
	}

	if (has_ping == 1 || has_raw_cap == 1) {
		dns_has_cap_ping = 1;
	}

	return 0;
}

static int _dns_conf_load_pre(void)
{
	if (_dns_server_load_conf_init() != 0) {
		goto errout;
	}

	_dns_ping_cap_check();

	safe_strncpy(dns_save_fail_packet_dir, SMARTDNS_DEBUG_DIR, sizeof(dns_save_fail_packet_dir));

	return 0;

errout:
	return -1;
}

static int _dns_conf_load_post(void)
{
	_dns_conf_speed_check_mode_verify();

	if (dns_conf_cachesize == 0 && dns_conf_response_mode == DNS_RESPONSE_MODE_FASTEST_RESPONSE) {
		dns_conf_response_mode = DNS_RESPONSE_MODE_FASTEST_IP;
		tlog(TLOG_WARN, "force set response to %s as cache size is 0",
			 dns_conf_response_mode_enum[dns_conf_response_mode].name);
	}


	if ((dns_conf_rr_ttl_min > dns_conf_rr_ttl_max) && dns_conf_rr_ttl_max > 0) {
		dns_conf_rr_ttl_min = dns_conf_rr_ttl_max;
	}

	if ((dns_conf_rr_ttl_max < dns_conf_rr_ttl_min) && dns_conf_rr_ttl_max > 0) {
		dns_conf_rr_ttl_max = dns_conf_rr_ttl_min;
	}

	if (dns_conf_local_ttl == 0) {
		dns_conf_local_ttl = dns_conf_rr_ttl_min;
	}

	return 0;
}

int dns_server_load_conf(const char *file)
{
	int ret = 0;
	_dns_conf_load_pre();
	openlog("smartdns", LOG_CONS | LOG_NDELAY, LOG_LOCAL1);
	ret = load_conf(file, _config_item, _conf_printf);
	closelog();
	_dns_conf_load_post();
	return ret;
}
