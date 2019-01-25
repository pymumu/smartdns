#include "dns_conf.h"
#include "list.h"
#include "rbtree.h"
#include "tlog.h"
#include "util.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
 #include <syslog.h>

#define DEFAULT_DNS_CACHE_SIZE 512

struct dns_ipset_table {
	DECLARE_HASHTABLE(ipset, 8);
};
struct dns_ipset_table dns_ipset_table;

char dns_conf_server_ip[DNS_MAX_IPLEN];
char dns_conf_server_tcp_ip[DNS_MAX_IPLEN];
int dns_conf_tcp_idle_time = 120;
int dns_conf_cachesize = DEFAULT_DNS_CACHE_SIZE;
int dns_conf_prefetch = 0;
struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
char dns_conf_server_name[DNS_MAX_CONF_CNAME_LEN];
int dns_conf_server_num;
int dns_conf_log_level = TLOG_ERROR;
char dns_conf_log_file[DNS_MAX_PATH];
size_t dns_conf_log_size = 1024 * 1024;
int dns_conf_log_num = 8;
int dns_conf_audit_enable = 0;
char dns_conf_audit_file[DNS_MAX_PATH];
size_t dns_conf_audit_size = 1024 * 1024;
int dns_conf_audit_num = 2;

art_tree dns_conf_domain_rule;
radix_tree_t *dns_conf_address_rule;

int dns_conf_dualstack_ip_selection;
int dns_conf_dualstack_ip_selection_threshold = 30;

int dns_conf_rr_ttl;
int dns_conf_rr_ttl_min;
int dns_conf_rr_ttl_max;
int dns_conf_force_AAAA_SOA;

struct dns_edns_client_subnet dns_conf_ipv4_ecs;
struct dns_edns_client_subnet dns_conf_ipv6_ecs;

int config_server(int argc, char *argv[], dns_server_type_t type, int default_port)
{
	int index = dns_conf_server_num;
	struct dns_servers *server;
	int port = -1;
	char *ip = NULL;
	int opt = 0;
	int result_flag = 0;
	int ttl = 0;
	/* clang-format off */
	static struct option long_options[] = {
		{"blacklist-ip", 0, 0, 'b'},
		{"check-edns", 0, 0, 'e'},
		{"check-ttl", required_argument, 0, 't'},
		{0, 0, 0, 0}
	};
	/* clang-format on */
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	ip = argv[1];
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
		case 'e': {
			result_flag |= DNSSERVER_FLAG_CHECK_EDNS;
			break;
		}
		case 't': {
			if (DNS_SERVER_UDP != type) {
				break;
			}

			ttl = atoi(optarg);
			if (ttl < -255 || ttl > 255) {
				tlog(TLOG_ERROR, "ttl value is invalid.");
				return -1;
			}
			result_flag |= DNSSERVER_FLAG_CHECK_TTL;
		}
		}
	}

	if (index >= DNS_MAX_SERVERS) {
		tlog(TLOG_WARN, "exceeds max server number, %s", ip);
		return 0;
	}

	server = &dns_conf_servers[index];
	/* parse ip, port from ip */
	if (parse_ip(ip, server->server, &port) != 0) {
		return -1;
	}

	/* if port is not defined, set port to default 53 */
	if (port == PORT_NOT_DEFINED) {
		port = default_port;
	}

	server->type = type;
	server->port = port;
	server->result_flag = result_flag;
	server->ttl = ttl;
	dns_conf_server_num++;
	tlog(TLOG_DEBUG, "add server %s, flag: %X, ttl: %d", ip, result_flag, ttl);

	return 0;
}

int config_domain_iter_cb(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct dns_domain_rule *domain_rule = value;
	int i = 0;

	if (domain_rule == NULL) {
		return 0;
	}

	for (i = 0; i < DOMAIN_RULE_MAX; i++) {
		free(domain_rule->rules[i]);
	}

	free(domain_rule);
	return 0;
}

void config_domain_destroy(void)
{
	art_iter(&dns_conf_domain_rule, config_domain_iter_cb, 0);
	art_tree_destroy(&dns_conf_domain_rule);
}

void config_address_destroy(radix_node_t *node, void *cbctx)
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

int config_domain_rule_add(char *domain, enum domain_rule type, void *rule)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;

	len = strlen(domain);
	reverse_string(domain_key, domain, len);
	domain_key[len] = '.';
	len++;
	domain_key[len] = 0;

	if (type >= DOMAIN_RULE_MAX) {
		goto errout;
	}

	domain_rule = art_search(&dns_conf_domain_rule, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		add_domain_rule = malloc(sizeof(*add_domain_rule));
		if (add_domain_rule == NULL) {
			goto errout;
		}
		memset(add_domain_rule, 0, sizeof(*add_domain_rule));
		domain_rule = add_domain_rule;
	}

	if (domain_rule->rules[type]) {
		free(domain_rule->rules[type]);
		domain_rule->rules[type] = NULL;
	}

	domain_rule->rules[type] = rule;

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

int config_domain_rule_flag_set(char *domain, unsigned int flag)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;
	struct dns_rule_flags *rule_flags = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;

	len = strlen(domain);
	reverse_string(domain_key, domain, len);
	domain_key[len] = '.';
	len++;
	domain_key[len] = 0;

	domain_rule = art_search(&dns_conf_domain_rule, (unsigned char *)domain_key, len);
	if (domain_rule == NULL) {
		add_domain_rule = malloc(sizeof(*add_domain_rule));
		if (add_domain_rule == NULL) {
			goto errout;
		}
		memset(add_domain_rule, 0, sizeof(*add_domain_rule));
		domain_rule = add_domain_rule;
	}

	if (domain_rule->rules[DOMAIN_RULE_FLAGS] == NULL) {
		rule_flags = malloc(sizeof(*rule_flags));
		rule_flags->flags = 0;
		domain_rule->rules[DOMAIN_RULE_FLAGS] = rule_flags;
	}

	rule_flags = domain_rule->rules[DOMAIN_RULE_FLAGS];
	rule_flags->flags |= flag;

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

void config_ipset_table_destroy(void)
{
	struct dns_ipset_name *ipset_name = NULL;
	struct hlist_node *tmp = NULL;
	int i;

	hash_for_each_safe(dns_ipset_table.ipset, i, tmp, ipset_name, node)
	{
		hlist_del_init(&ipset_name->node);
		free(ipset_name);
	}
}

const char *dns_conf_get_ipset(const char *ipsetname)
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
	strncpy(ipset_name->ipsetname, ipsetname, DNS_MAX_IPSET_NAMELEN);
	hash_add(dns_ipset_table.ipset, &ipset_name->node, key);

	return ipset_name->ipsetname;
errout:
	if (ipset_name) {
		free(ipset_name);
	}

	return NULL;
}

int config_ipset(void *data, int argc, char *argv[])
{
	struct dns_ipset_rule *ipset_rule = NULL;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char ipsetname[DNS_MAX_CONF_CNAME_LEN];
	const char *ipset = NULL;
	char *begin = NULL;
	char *end = NULL;
	int len = 0;
	char *value = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	begin = strstr(value, "/");
	if (begin == NULL) {
		goto errout;
	}

	begin++;
	end = strstr(begin, "/");
	if (end == NULL) {
		goto errout;
	}

	/* remove prefix . */
	while (*begin == '.') {
		begin++;
	}

	len = end - begin;
	memcpy(domain, begin, len);
	domain[len] = '\0';

	len = strlen(end + 1);
	if (len <= 0) {
		goto errout;
	}

	if (strncmp(end + 1, "-", sizeof("-")) != 0) {
		strncpy(ipsetname, end + 1, DNS_MAX_IPSET_NAMELEN);
		ipset = dns_conf_get_ipset(ipsetname);
		if (ipset == NULL) {
			goto errout;
		}

		ipset_rule = malloc(sizeof(*ipset_rule));
		if (ipset_rule == NULL) {
			goto errout;
		}

		ipset_rule->ipsetname = ipset;
	} else {
		if (config_domain_rule_flag_set(domain, DOMAIN_FLAG_IPSET_IGNORE) != 0 ) {
			goto errout;
		}

		return 0;
	}

	if (config_domain_rule_add(domain, DOMAIN_RULE_IPSET, ipset_rule) != 0) {
		goto errout;
	}

	return 0;
errout:
	if (ipset_rule) {
		free(ipset_rule);
	}

	tlog(TLOG_ERROR, "add ipset %s failed", value);
	return 0;
}

int config_address(void *data, int argc, char *argv[])
{
	struct dns_address_IPV4 *address_ipv4 = NULL;
	struct dns_address_IPV6 *address_ipv6 = NULL;
	void *address = NULL;
	char *value = argv[1];
	char ip[MAX_IP_LEN];
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *begin = NULL;
	char *end = NULL;
	int len = 0;
	int port;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	enum domain_rule type = 0;
	unsigned int flag = 0;

	if (argc <= 1) {
		goto errout;
	}

	begin = strstr(value, "/");
	if (begin == NULL) {
		goto errout;
	}

	begin++;
	end = strstr(begin, "/");
	if (end == NULL) {
		goto errout;
	}

	/* remove prefix . */
	while (*begin == '.') {
		begin++;
	}

	len = end - begin;
	memcpy(domain, begin, len);
	domain[len] = 0;

	if (strncmp(end + 1, "#", sizeof("#")) == 0) {
		if (strncmp(end + 1, "#4", sizeof("#4")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV4_SOA;
		} else if (strncmp(end + 1, "#6", sizeof("#6")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV6_SOA;
		} else {
			flag = DOMAIN_FLAG_ADDR_SOA;
		}

		if (config_domain_rule_flag_set(domain, flag) != 0 ) {
			goto errout;
		}

		return 0;
	} else if (strncmp(end + 1, "-", sizeof("-")) == 0) {
		if (strncmp(end + 1, "-4", sizeof("-4")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV4_IGN;
		} else if (strncmp(end + 1, "-6", sizeof("-6")) == 0) {
			flag = DOMAIN_FLAG_ADDR_IPV6_IGN;
		} else {
			flag = DOMAIN_FLAG_ADDR_IGN;
		}

		if (config_domain_rule_flag_set(domain, flag) != 0 ) {
			goto errout;
		}

		return 0;
	} else {
		if (parse_ip(end + 1, ip, &port) != 0) {
			goto errout;
		}

		if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
			goto errout;
		}

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in;
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
			struct sockaddr_in6 *addr_in6;
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

	if (config_domain_rule_add(domain, type, address) != 0) {
		goto errout;
	}

	return 0;
errout:
	if (address) {
		free(address);
	}

	tlog(TLOG_ERROR, "add address %s failed", value);
	return 0;
}

int config_server_udp(void *data, int argc, char *argv[])
{
	return config_server(argc, argv, DNS_SERVER_UDP, DEFAULT_DNS_PORT);
}

int config_server_tcp(void *data, int argc, char *argv[])
{
	return config_server(argc, argv, DNS_SERVER_TCP, DEFAULT_DNS_PORT);
}

int config_server_tls(void *data, int argc, char *argv[])
{
	return config_server(argc, argv, DNS_SERVER_TLS, DEFAULT_DNS_TLS_PORT);
}

radix_node_t *create_addr_node(radix_tree_t *tree, char *addr)
{
	radix_node_t *node;
	void *p;
	prefix_t prefix;
	const char *errmsg = NULL;

	p = prefix_pton(addr, -1, &prefix, &errmsg);
	if (p == NULL) {
		return NULL;
	}

	node = radix_lookup(tree, &prefix);
	return node;
}

int config_iplist_rule(char *subnet, enum address_rule rule)
{
	radix_node_t *node = NULL;
	struct dns_ip_address_rule *ip_rule = NULL;

	node = create_addr_node(dns_conf_address_rule, subnet);
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
	case ADDRESS_RULE_BOGUS:
		ip_rule->bogus = 1;
		break;
	case ADDRESS_RULE_IP_IGNORE:
		ip_rule->ip_ignore = 1;
	}

	return 0;
}

int config_blacklist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return config_iplist_rule(argv[1], ADDRESS_RULE_BLACKLIST);
}

int conf_bogus_nxdomain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return config_iplist_rule(argv[1], ADDRESS_RULE_BOGUS);
}

int conf_ip_ignore(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return config_iplist_rule(argv[1], ADDRESS_RULE_IP_IGNORE);
}

int conf_edns_client_subnet(void *data, int argc, char *argv[])
{
	char *slash = NULL;
	char *value = NULL;
	int subnet = 0;
	struct dns_edns_client_subnet *ecs = data;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	if (argc <= 1 || data == NULL) {
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

	strncpy(ecs->ip, value, DNS_MAX_IPLEN);
	ecs->subnet = subnet;
	ecs->enable = 1;

	return 0;

errout:
	return -1;
}

int config_log_level(void *data, int argc, char *argv[])
{
	/* read log level and set */
	char *value = argv[1];

	if (strncmp("debug", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_DEBUG;
	} else if (strncmp("info", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_INFO;
	} else if (strncmp("warn", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_WARN;
	} else if (strncmp("error", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_ERROR;
	} else {
		return -1;
	}

	return 0;
}

struct config_item config_item[] = {
	CONF_STRING("server-name", (char *)dns_conf_server_name, DNS_MAX_CONF_CNAME_LEN),
	CONF_STRING("bind", dns_conf_server_ip, DNS_MAX_IPLEN),
	CONF_STRING("bind-tcp", dns_conf_server_tcp_ip, DNS_MAX_IPLEN),
	CONF_CUSTOM("server", config_server_udp, NULL),
	CONF_CUSTOM("server-tcp", config_server_tcp, NULL),
	CONF_CUSTOM("server-tls", config_server_tls, NULL),
	CONF_CUSTOM("address", config_address, NULL),
	CONF_CUSTOM("ipset", config_ipset, NULL),
	CONF_INT("tcp-idle-time", &dns_conf_tcp_idle_time, 0, 3600),
	CONF_INT("cache-size", &dns_conf_cachesize, 0, CONF_INT_MAX),
	CONF_YESNO("prefetch-domain", &dns_conf_prefetch),
	CONF_YESNO("dualstack-ip-selection", &dns_conf_dualstack_ip_selection),
	CONF_INT("dualstack-ip-selection-threshold", &dns_conf_dualstack_ip_selection_threshold, 0, 1000),
	CONF_CUSTOM("log-level", config_log_level, NULL),
	CONF_STRING("log-file", (char *)dns_conf_log_file, DNS_MAX_PATH),
	CONF_SIZE("log-size", &dns_conf_log_size, 0, 1024 * 1024 * 1024),
	CONF_INT("log-num", &dns_conf_log_num, 0, 1024),
	CONF_YESNO("audit-enable", &dns_conf_audit_enable),
	CONF_STRING("audit-file", (char *)&dns_conf_audit_file, DNS_MAX_PATH),
	CONF_SIZE("audit-size", &dns_conf_audit_size, 0, 1024 * 1024 * 1024),
	CONF_INT("audit-num", &dns_conf_audit_num, 0, 1024),
	CONF_INT("rr-ttl", &dns_conf_rr_ttl, 0, CONF_INT_MAX),
	CONF_INT("rr-ttl-min", &dns_conf_rr_ttl_min, 0, CONF_INT_MAX),
	CONF_INT("rr-ttl-max", &dns_conf_rr_ttl_max, 0, CONF_INT_MAX),
	CONF_YESNO("force-AAAA-SOA", &dns_conf_force_AAAA_SOA),
	CONF_CUSTOM("blacklist-ip", config_blacklist_ip, NULL),
	CONF_CUSTOM("bogus-nxdomain", conf_bogus_nxdomain, NULL),
	CONF_CUSTOM("ignore-ip", conf_ip_ignore, NULL),
	CONF_CUSTOM("edns-client-subnet-ipv4", conf_edns_client_subnet, &dns_conf_ipv6_ecs),
	CONF_CUSTOM("edns-client-subnet-ipv6", conf_edns_client_subnet, &dns_conf_ipv6_ecs),
	CONF_CUSTOM("conf-file", config_addtional_file, NULL),
	CONF_END(),
};

int conf_printf(const char *file, int lineno, int ret)
{
	if (ret == CONF_RET_ERR) {
		tlog(TLOG_ERROR, "process config file '%s' failed at line %d.", file, lineno);
		syslog(LOG_NOTICE, "process config file '%s' failed at line %d.", file, lineno);
		return -1;
	} else if (ret == CONF_RET_WARN) {
		tlog(TLOG_WARN, "process config file '%s' failed at line %d.", file, lineno);
		syslog(LOG_NOTICE, "process config file '%s' failed at line %d.", file, lineno);
		return -1;
	}

	return 0;
}

int config_addtional_file(void *data, int argc, char *argv[])
{
	char *file_path = argv[1];

	if (access(file_path, R_OK) != 0) {
		tlog(TLOG_WARN, "conf file %s is not readable.", file_path);
		return 0;
	}

	return load_conf(file_path, config_item, conf_printf);
}

int _dns_server_load_conf_init(void)
{
	dns_conf_address_rule = New_Radix();
	art_tree_init(&dns_conf_domain_rule);
	if (dns_conf_address_rule == NULL) {
		return -1;
	}

	hash_init(dns_ipset_table.ipset);

	return 0;
}

void dns_server_load_exit(void)
{
	config_domain_destroy();
	Destroy_Radix(dns_conf_address_rule, config_address_destroy, NULL);
	config_ipset_table_destroy();
}

int dns_server_load_conf(const char *file)
{
	int ret = 0;
	_dns_server_load_conf_init();
	openlog ("smartdns", LOG_CONS | LOG_NDELAY, LOG_LOCAL1);
	ret = load_conf(file, config_item, conf_printf);
	closelog();
	return ret;
}
