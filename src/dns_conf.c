/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "idna.h"
#include "list.h"
#include "rbtree.h"
#include "tlog.h"
#include "util.h"
#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define TMP_BUFF_LEN 1024

/* ipset */
struct dns_ipset_table {
	DECLARE_HASHTABLE(ipset, 8);
};
static struct dns_ipset_table dns_ipset_table;

struct dns_nftset_table {
	DECLARE_HASHTABLE(nftset, 8);
};
static struct dns_nftset_table dns_nftset_table;

struct dns_domain_set_name_table dns_domain_set_name_table;

struct dns_ip_set_name_table dns_ip_set_name_table;

/* dns groups */
struct dns_group_table dns_group_table;
struct dns_proxy_table dns_proxy_table;

struct dns_ptr_table dns_ptr_table;

static char dns_conf_dnsmasq_lease_file[DNS_MAX_PATH];
static time_t dns_conf_dnsmasq_lease_file_time;

struct dns_hosts_table dns_hosts_table;
int dns_hosts_record_num;

/* SRV-HOST */
struct dns_srv_record_table dns_conf_srv_record_table;

/* server ip/port  */
struct dns_bind_ip dns_conf_bind_ip[DNS_MAX_BIND_IP];
int dns_conf_bind_ip_num = 0;
int dns_conf_tcp_idle_time = 120;
char dns_conf_bind_ca_file[DNS_MAX_PATH];
char dns_conf_bind_ca_key_file[DNS_MAX_PATH];
char dns_conf_bind_ca_key_pass[DNS_MAX_PATH];
char dns_conf_need_cert = 0;

int dns_conf_max_query_limit = DNS_MAX_QUERY_LIMIT;

static struct config_enum_list dns_conf_response_mode_enum[] = {
	{"first-ping", DNS_RESPONSE_MODE_FIRST_PING_IP},
	{"fastest-ip", DNS_RESPONSE_MODE_FASTEST_IP},
	{"fastest-response", DNS_RESPONSE_MODE_FASTEST_RESPONSE},
	{NULL, 0}};

enum response_mode_type dns_conf_default_response_mode = DNS_RESPONSE_MODE_FIRST_PING_IP;

/* cache */
ssize_t dns_conf_cachesize = -1;
ssize_t dns_conf_cache_max_memsize = -1;

/* upstream servers */
struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
char dns_conf_server_name[DNS_MAX_SERVER_NAME_LEN];
int dns_conf_server_num;
static int dns_conf_resolv_hostname = 1;
static char dns_conf_exist_bootstrap_dns;

int dns_conf_has_icmp_check;
int dns_conf_has_tcp_check;
struct dns_domain_check_orders dns_conf_default_check_orders = {
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
int dns_conf_log_file_mode;
int dns_conf_log_console;
int dns_conf_log_syslog;

/* CA file */
char dns_conf_ca_file[DNS_MAX_PATH];
char dns_conf_ca_path[DNS_MAX_PATH];

char dns_conf_cache_file[DNS_MAX_PATH];
int dns_conf_cache_persist = 2;
int dns_conf_cache_checkpoint_time = DNS_DEFAULT_CHECKPOINT_TIME;

/* auditing */
int dns_conf_audit_enable = 0;
int dns_conf_audit_log_SOA;
int dns_conf_audit_syslog;
char dns_conf_audit_file[DNS_MAX_PATH];
size_t dns_conf_audit_size = 1024 * 1024;
int dns_conf_audit_num = 2;
int dns_conf_audit_file_mode;
int dns_conf_audit_console;
int dns_conf_audit_syslog;

/* address rules */
struct dns_conf_group_info {
	struct list_head list;
	const char *group_name;
	struct dns_conf_group *rule;
};
struct dns_conf_group_info *dns_conf_current_group_info;
struct dns_conf_group_info *dns_conf_default_group_info;
static LIST_HEAD(dns_conf_group_info_list);

struct dns_conf_rule dns_conf_rule;
struct dns_conf_client_rule dns_conf_client_rule;

static int dns_conf_expand_ptr_from_address = 0;
int dns_conf_local_ttl;
int dns_conf_nftset_debug_enable;
int dns_conf_mdns_lookup;
int dns_conf_local_ptr_enable = 1;
int dns_conf_acl_enable;

char dns_conf_user[DNS_CONF_USERNAME_LEN];

int dns_save_fail_packet;
char dns_save_fail_packet_dir[DNS_MAX_PATH];
char dns_resolv_file[DNS_MAX_PATH];
int dns_no_pidfile;
int dns_no_daemon;
int dns_restart_on_crash;
size_t dns_socket_buff_size;

struct hash_table conf_file_table;
struct conf_file_path {
	struct hlist_node node;
	char file[DNS_MAX_PATH];
};

struct dns_conf_plugin_table dns_conf_plugin_table;

char dns_conf_sni_proxy_ip[DNS_MAX_IPLEN];

static int _conf_domain_rule_nameserver(const char *domain, const char *group_name);
static int _conf_domain_rule_group(const char *domain, const char *group_name);
static int _conf_ptr_add(const char *hostname, const char *ip, int is_dynamic);
static int _conf_client_subnet(char *subnet, struct dns_edns_client_subnet *ipv4_ecs,
							   struct dns_edns_client_subnet *ipv6_ecs);
static int _conf_domain_rule_address(char *domain, const char *domain_address);
static struct dns_domain_rule *_config_domain_rule_get(const char *domain);
typedef int (*set_rule_add_func)(const char *value, void *priv);
static int _config_ip_rule_set_each(const char *ip_set, set_rule_add_func callback, void *priv);
static struct dns_conf_group *_config_rule_group_get(const char *group_name);
static struct dns_conf_group *_config_rule_group_new(const char *group_name);
static struct dns_conf_group *_config_current_rule_group(void);
static void _config_ip_iter_free(radix_node_t *node, void *cbctx);
static int _config_nftset_setvalue(struct dns_nftset_names *nftsets, const char *nftsetvalue);
static int _config_client_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear);
static int _config_client_rule_group_add(const char *client, const char *group_name);

#define group_member(m) ((void *)offsetof(struct dns_conf_group, m))

static __attribute__((unused)) int _dns_conf_group_int(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

static __attribute__((unused)) int _dns_conf_group_int_base(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

static __attribute__((unused)) int _dns_conf_group_string(const char *value, char *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	char *ptr = (char *)conf_group + (size_t)data;
	safe_strncpy(ptr, value, DNS_MAX_PATH);

	return 0;
}

static __attribute__((unused)) int _dns_conf_group_yesno(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

static __attribute__((unused)) int _dns_conf_group_size(size_t value, size_t *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(size_t *)ptr = value;

	return 0;
}

static __attribute__((unused)) int _dns_conf_group_ssize(ssize_t value, ssize_t *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(ssize_t *)ptr = value;

	return 0;
}

static __attribute__((unused)) int _dns_conf_group_enum(int value, int *data)
{
	struct dns_conf_group *conf_group = _config_current_rule_group();
	if (conf_group == NULL) {
		return -1;
	}

	void *ptr = (char *)conf_group + (size_t)data;
	*(int *)ptr = value;

	return 0;
}

static void *_new_dns_rule_ext(enum domain_rule domain_rule, int ext_size)
{
	struct dns_rule *rule;
	int size = 0;

	if (domain_rule >= DOMAIN_RULE_MAX) {
		return NULL;
	}

	switch (domain_rule) {
	case DOMAIN_RULE_FLAGS:
		size = sizeof(struct dns_rule_flags);
		break;
	case DOMAIN_RULE_ADDRESS_IPV4:
		size = sizeof(struct dns_rule_address_IPV4);
		break;
	case DOMAIN_RULE_ADDRESS_IPV6:
		size = sizeof(struct dns_rule_address_IPV6);
		break;
	case DOMAIN_RULE_IPSET:
	case DOMAIN_RULE_IPSET_IPV4:
	case DOMAIN_RULE_IPSET_IPV6:
		size = sizeof(struct dns_ipset_rule);
		break;
	case DOMAIN_RULE_NFTSET_IP:
	case DOMAIN_RULE_NFTSET_IP6:
		size = sizeof(struct dns_nftset_rule);
		break;
	case DOMAIN_RULE_NAMESERVER:
		size = sizeof(struct dns_nameserver_rule);
		break;
	case DOMAIN_RULE_GROUP:
		size = sizeof(struct dns_group_rule);
		break;
	case DOMAIN_RULE_CHECKSPEED:
		size = sizeof(struct dns_domain_check_orders);
		break;
	case DOMAIN_RULE_RESPONSE_MODE:
		size = sizeof(struct dns_response_mode_rule);
		break;
	case DOMAIN_RULE_CNAME:
		size = sizeof(struct dns_cname_rule);
		break;
	case DOMAIN_RULE_HTTPS:
		size = sizeof(struct dns_https_record_rule);
		break;
	case DOMAIN_RULE_TTL:
		size = sizeof(struct dns_ttl_rule);
		break;
	default:
		return NULL;
	}

	size += ext_size;
	rule = malloc(size);
	if (!rule) {
		return NULL;
	}
	memset(rule, 0, size);
	rule->rule = domain_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

static void *_new_dns_rule(enum domain_rule domain_rule)
{
	return _new_dns_rule_ext(domain_rule, 0);
}

static void _dns_rule_get(struct dns_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static void _dns_rule_put(struct dns_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt)) {
		free(rule);
	}
}

static void _dns_iplist_ip_address_add(struct dns_iplist_ip_addresses *iplist, unsigned char addr[], int addr_len)
{
	iplist->ipaddr = realloc(iplist->ipaddr, (iplist->ipaddr_num + 1) * sizeof(struct dns_iplist_ip_address));
	if (iplist->ipaddr == NULL) {
		return;
	}
	memset(&iplist->ipaddr[iplist->ipaddr_num], 0, sizeof(struct dns_iplist_ip_address));
	iplist->ipaddr[iplist->ipaddr_num].addr_len = addr_len;
	memcpy(iplist->ipaddr[iplist->ipaddr_num].addr, addr, addr_len);
	iplist->ipaddr_num++;
}

static int _get_domain(char *value, char *domain, int max_domain_size, char **ptr_after_domain)
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
		safe_strncpy(domain, ".", max_domain_size);
		return 0;
	}

	/* second field */
	begin++;
	end = strstr(begin, "/");
	if (end == NULL) {
		goto errout;
	}

	/* remove prefix . */
	while (*begin == '.') {
		if (begin + 1 == end) {
			break;
		}
		begin++;
	}

	/* Get domain */
	len = end - begin;
	if (len >= max_domain_size) {
		tlog(TLOG_ERROR, "domain name %s too long", value);
		goto errout;
	}

	size_t domain_len = max_domain_size;
	if (strncmp(begin, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		memcpy(domain, begin, len);
		domain_len = len;
	} else {
		domain_len = utf8_to_punycode(begin, len, domain, domain_len);
		if (domain_len <= 0) {
			tlog(TLOG_ERROR, "domain name %s invalid", value);
			goto errout;
		}
	}

	domain[domain_len] = '\0';

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
		if (strncmp(group->group_name, group_name, DNS_GROUP_NAME_LEN) == 0) {
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

struct dns_proxy_names *dns_server_get_proxy_nams(const char *proxyname)
{
	uint32_t key = 0;
	struct dns_proxy_names *proxy = NULL;

	key = hash_string(proxyname);
	hash_for_each_possible(dns_proxy_table.proxy, proxy, node, key)
	{
		if (strncmp(proxy->proxy_name, proxyname, DNS_GROUP_NAME_LEN) == 0) {
			return proxy;
		}
	}

	return NULL;
}

static struct dns_conf_group *_config_current_rule_group(void)
{
	if (dns_conf_current_group_info == NULL) {
		return NULL;
	}

	return dns_conf_current_group_info->rule;
}

static struct dns_conf_group_info *_config_current_group(void)
{
	return dns_conf_current_group_info;
}

static void _config_current_group_pop(void)
{
	struct dns_conf_group_info *group_info = NULL;

	group_info = list_last_entry(&dns_conf_group_info_list, struct dns_conf_group_info, list);
	if (group_info == NULL) {
		return;
	}

	if (group_info == dns_conf_default_group_info) {
		dns_conf_current_group_info = dns_conf_default_group_info;
		return;
	}

	list_del(&group_info->list);
	free(group_info);

	group_info = list_last_entry(&dns_conf_group_info_list, struct dns_conf_group_info, list);
	if (group_info == NULL) {
		dns_conf_current_group_info = NULL;
		return;
	}

	dns_conf_current_group_info = group_info;
}

static int _config_rule_group_setup_value(struct dns_conf_group_info *group_info)
{
	struct dns_conf_group *group_rule = group_info->rule;
	int soa_talbe_size = MAX_QTYPE_NUM / 8 + 1;
	uint8_t *soa_table = NULL;

	soa_table = malloc(soa_talbe_size);
	if (soa_table == NULL) {
		tlog(TLOG_WARN, "malloc qtype soa table failed.");
		return -1;
	}
	group_rule->soa_table = soa_table;

	if (_config_current_rule_group() != NULL) {
		/* copy parent group data. */
		memcpy(&group_rule->copy_data_section_begin, &_config_current_rule_group()->copy_data_section_begin,
			   offsetof(struct dns_conf_group, copy_data_section_end) -
				   offsetof(struct dns_conf_group, copy_data_section_begin));
		memcpy(group_rule->soa_table, _config_current_rule_group()->soa_table, soa_talbe_size);
		return 0;
	}

	memset(soa_table, 0, soa_talbe_size);
	memcpy(&group_rule->check_orders, &dns_conf_default_check_orders, sizeof(group_rule->check_orders));
	group_rule->dualstack_ip_selection = 1;
	group_rule->dns_dualstack_ip_selection_threshold = 10;
	group_rule->dns_rr_ttl_min = 600;
	group_rule->dns_serve_expired = 1;
	group_rule->dns_serve_expired_ttl = 24 * 3600 * 3;
	group_rule->dns_serve_expired_reply_ttl = 3;
	group_rule->dns_max_reply_ip_num = DNS_MAX_REPLY_IP_NUM;
	group_rule->dns_response_mode = dns_conf_default_response_mode;

	return 0;
}

static int _config_current_group_push(const char *group_name)
{
	struct dns_conf_group_info *group_info = NULL;
	struct dns_conf_group *group_rule = NULL;

	group_info = malloc(sizeof(*group_info));
	if (group_info == NULL) {
		goto errout;
	}

	if (dns_conf_default_group_info != NULL) {
		group_name = _dns_conf_get_group_name(group_name);
		if (group_name == NULL) {
			goto errout;
		}
	}

	memset(group_info, 0, sizeof(*group_info));
	INIT_LIST_HEAD(&group_info->list);
	list_add_tail(&group_info->list, &dns_conf_group_info_list);

	group_rule = _config_rule_group_get(group_name);
	if (group_rule == NULL) {
		group_rule = _config_rule_group_new(group_name);
		if (group_rule == NULL) {
			goto errout;
		}
	}

	group_info->group_name = group_name;
	group_info->rule = group_rule;
	_config_rule_group_setup_value(group_info);

	dns_conf_current_group_info = group_info;
	if (dns_conf_default_group_info == NULL) {
		dns_conf_default_group_info = group_info;
	}

	return 0;

errout:
	if (group_info) {
		free(group_info);
	}
	return -1;
}

static int _config_group_begin(void *data, int argc, char *argv[])
{
	const char *group_name = NULL;
	if (argc < 2) {
		return -1;
	}

	group_name = argv[1];
	if (group_name[0] == '\0') {
		group_name = NULL;
	}

	if (_config_current_group_push(group_name) != 0) {
		return -1;
	}

	return 0;
}

static int _config_current_group_push_default(void)
{
	return _config_current_group_push(NULL);
}

static int _config_current_group_pop_to(struct dns_conf_group_info *group_info)
{
	while (dns_conf_current_group_info != NULL && dns_conf_current_group_info != group_info) {
		_config_current_group_pop();
	}

	return 0;
}

static int _config_current_group_pop_all(void)
{
	while (dns_conf_current_group_info != NULL && dns_conf_current_group_info != dns_conf_default_group_info) {
		_config_current_group_pop();
	}

	if (dns_conf_default_group_info == NULL) {
		return 0;
	}

	list_del(&dns_conf_default_group_info->list);
	free(dns_conf_default_group_info);
	dns_conf_default_group_info = NULL;
	dns_conf_current_group_info = NULL;

	return 0;
}

static int _config_group_end(void *data, int argc, char *argv[])
{
	_config_current_group_pop();
	return 0;
}

static int _config_group_match(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	struct dns_conf_group_info *saved_group_info = dns_conf_current_group_info;
	const char *group_name = saved_group_info->group_name;
	char group_name_buf[DNS_MAX_CONF_CNAME_LEN];

	/* clang-format off */
	static struct option long_options[] = {
		{"domain", required_argument, NULL, 'd'},
		{"client-ip", required_argument, NULL, 'c'},
		{"group", required_argument, NULL, 'g'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1 || group_name == NULL) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	dns_conf_current_group_info = dns_conf_default_group_info;

	for (int i = 1; i < argc - 1; i++) {
		if (strncmp(argv[i], "-g", sizeof("-g")) == 0 || strncmp(argv[i], "--group", sizeof("--group")) == 0 ||
			strncmp(argv[i], "-group", sizeof("-group")) == 0) {
			safe_strncpy(group_name_buf, argv[i + 1], DNS_MAX_CONF_CNAME_LEN);
			group_name = group_name_buf;
			break;
		}
	}

	while (1) {
		opt = getopt_long_only(argc, argv, "g:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'g': {
			group_name = optarg;
			break;
		}
		case 'd': {
			const char *domain = optarg;

			if (_conf_domain_rule_group(domain, group_name) != 0) {
				tlog(TLOG_ERROR, "set group match for domain %s failed.", optarg);
				goto errout;
			}
			break;
		}
		case 'c': {
			char *client_ip = optarg;
			if (_config_client_rule_group_add(client_ip, group_name) != 0) {
				tlog(TLOG_ERROR, "add group rule failed.");
				goto errout;
			}
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown group-match option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}
		optind_last = optind;
	}

	dns_conf_current_group_info = saved_group_info;

	return 0;
errout:
	dns_conf_current_group_info = saved_group_info;
	return -1;
}

/* create and get dns server group */
static struct dns_proxy_names *_dns_conf_get_proxy(const char *proxy_name)
{
	uint32_t key = 0;
	struct dns_proxy_names *proxy = NULL;

	key = hash_string(proxy_name);
	hash_for_each_possible(dns_proxy_table.proxy, proxy, node, key)
	{
		if (strncmp(proxy->proxy_name, proxy_name, PROXY_NAME_LEN) == 0) {
			return proxy;
		}
	}

	proxy = malloc(sizeof(*proxy));
	if (proxy == NULL) {
		goto errout;
	}

	memset(proxy, 0, sizeof(*proxy));
	safe_strncpy(proxy->proxy_name, proxy_name, PROXY_NAME_LEN);
	hash_add(dns_proxy_table.proxy, &proxy->node, key);
	INIT_LIST_HEAD(&proxy->server_list);

	return proxy;
errout:
	if (proxy) {
		free(proxy);
	}

	return NULL;
}

static int _dns_conf_proxy_servers_add(const char *proxy_name, struct dns_proxy_servers *server)
{
	struct dns_proxy_names *proxy = NULL;

	proxy = _dns_conf_get_proxy(proxy_name);
	if (proxy == NULL) {
		return -1;
	}

	list_add_tail(&server->list, &proxy->server_list);

	return 0;
}

static const char *_dns_conf_get_proxy_name(const char *proxy_name)
{
	struct dns_proxy_names *proxy = NULL;

	proxy = _dns_conf_get_proxy(proxy_name);
	if (proxy == NULL) {
		return NULL;
	}

	return proxy->proxy_name;
}

static void _config_proxy_table_destroy(void)
{
	struct dns_proxy_names *proxy = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int i;
	struct dns_proxy_servers *server = NULL;
	struct dns_proxy_servers *server_tmp = NULL;

	hash_for_each_safe(dns_proxy_table.proxy, i, tmp, proxy, node)
	{
		hlist_del_init(&proxy->node);
		list_for_each_entry_safe(server, server_tmp, &proxy->server_list, list)
		{
			list_del(&server->list);
			free(server);
		}
		free(proxy);
	}
}

static void _config_srv_record_table_destroy(void)
{
	struct dns_srv_records *srv_records = NULL;
	struct dns_srv_record *srv_record, *tmp1 = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int i;

	hash_for_each_safe(dns_conf_srv_record_table.srv, i, tmp, srv_records, node)
	{
		list_for_each_entry_safe(srv_record, tmp1, &srv_records->list, list)
		{
			list_del(&srv_record->list);
			free(srv_record);
		}

		hlist_del_init(&srv_records->node);
		free(srv_records);
	}
}

static int _config_server(int argc, char *argv[], dns_server_type_t type, int default_port)
{
	int index = dns_conf_server_num;
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
	server->proxyname[0] = '\0';
	server->set_mark = -1;
	server->drop_packet_latency_ms = drop_packet_latency_ms;

	if (parse_uri(ip, scheme, server->server, &port, server->path) != 0) {
		return -1;
	}

	if (scheme[0] != '\0') {
		if (strcasecmp(scheme, "https") == 0) {
			type = DNS_SERVER_HTTPS;
			default_port = DEFAULT_DNS_HTTPS_PORT;
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
			group_name = optarg;
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

	if (server->type == DNS_SERVER_HTTPS) {
		if (server->path[0] == 0) {
			safe_strncpy(server->path, "/", sizeof(server->path));
		}

		if (server->httphost[0] == '\0') {
			safe_strncpy(server->httphost, server->server, DNS_MAX_CNAME_LEN);
		}
	}

	if (group_name) {
		if (_dns_conf_get_group_set(group_name, server) != 0) {
			tlog(TLOG_ERROR, "add group failed.");
			goto errout;
		}
	}

	dns_conf_server_num++;
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

static int _config_update_bootstrap_dns_rule(void)
{
	struct dns_servers *server = NULL;

	if (dns_conf_exist_bootstrap_dns == 0) {
		return 0;
	}

	for (int i = 0; i < dns_conf_server_num; i++) {
		server = &dns_conf_servers[i];
		if (check_is_ipaddr(server->server) == 0) {
			continue;
		}

		_conf_domain_rule_nameserver(server->server, "bootstrap-dns");
	}

	return 0;
}

static int _config_domain_rule_free(struct dns_domain_rule *domain_rule)
{
	int i = 0;

	if (domain_rule == NULL) {
		return 0;
	}

	for (i = 0; i < DOMAIN_RULE_MAX; i++) {
		if (domain_rule->rules[i] == NULL) {
			continue;
		}

		_dns_rule_put(domain_rule->rules[i]);
		domain_rule->rules[i] = NULL;
	}

	free(domain_rule);
	return 0;
}

static int _config_domain_iter_free(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	struct dns_domain_rule *domain_rule = value;
	return _config_domain_rule_free(domain_rule);
}

static struct dns_conf_group *_config_rule_group_get(const char *group_name)
{
	uint32_t key = 0;
	struct dns_conf_group *rule_group = NULL;
	if (group_name == NULL) {
		group_name = "";
	}

	key = hash_string(group_name);
	hash_for_each_possible(dns_conf_rule.group, rule_group, node, key)
	{
		if (strncmp(rule_group->group_name, group_name, DNS_GROUP_NAME_LEN) == 0) {
			return rule_group;
		}
	}

	return NULL;
}

struct dns_conf_group *dns_server_get_rule_group(const char *group_name)
{
	if (dns_conf_rule.group_num <= 1) {
		return dns_conf_rule.default_conf;
	}

	struct dns_conf_group *rule_group = _config_rule_group_get(group_name);
	if (rule_group) {
		return rule_group;
	}

	return dns_conf_rule.default_conf;
}

struct dns_conf_group *dns_server_get_default_rule_group(void)
{
	return dns_conf_rule.default_conf;
}

static struct dns_conf_group *_config_rule_group_new(const char *group_name)
{
	struct dns_conf_group *rule_group = NULL;
	uint32_t key = 0;

	if (group_name == NULL) {
		return NULL;
	}

	rule_group = malloc(sizeof(*rule_group));
	if (rule_group == NULL) {
		return NULL;
	}

	memset(rule_group, 0, sizeof(*rule_group));
	rule_group->group_name = group_name;

	INIT_HLIST_NODE(&rule_group->node);
	art_tree_init(&rule_group->domain_rule.tree);

	rule_group->address_rule.ipv4 = New_Radix();
	rule_group->address_rule.ipv6 = New_Radix();

	key = hash_string(group_name);
	hash_add(dns_conf_rule.group, &rule_group->node, key);
	dns_conf_rule.group_num++;

	return rule_group;
}

static void _config_rule_group_remove(struct dns_conf_group *rule_group)
{
	hlist_del_init(&rule_group->node);
	art_iter(&rule_group->domain_rule.tree, _config_domain_iter_free, NULL);
	art_tree_destroy(&rule_group->domain_rule.tree);
	Destroy_Radix(rule_group->address_rule.ipv4, _config_ip_iter_free, NULL);
	Destroy_Radix(rule_group->address_rule.ipv6, _config_ip_iter_free, NULL);
	free(rule_group->soa_table);
	dns_conf_rule.group_num--;

	free(rule_group);
}

static void _config_rule_group_destroy(void)
{
	struct dns_conf_group *group;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_rule.group, i, tmp, group, node)
	{
		_config_rule_group_remove(group);
	}

	dns_conf_rule.default_conf = NULL;
}

static int _config_set_rule_each_from_list(const char *file, set_rule_add_func callback, void *priv)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char value[DNS_MAX_CNAME_LEN];
	int ret = 0;
	int line_no = 0;
	int filed_num = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "open file %s error, %s", file, strerror(errno));
		return -1;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_no++;
		filed_num = sscanf(line, "%255s", value);
		if (filed_num <= 0) {
			continue;
		}

		if (value[0] == '#' || value[0] == '\n') {
			continue;
		}

		ret = callback(value, priv);
		if (ret != 0) {
			tlog(TLOG_WARN, "process file %s failed at line %d.", file, line_no);
			continue;
		}
	}

	fclose(fp);
	return ret;
}

static struct dns_domain_set_name_list *_config_get_domain_set_name_list(const char *name)
{
	uint32_t key = 0;
	struct dns_domain_set_name_list *set_name_list = NULL;

	key = hash_string(name);
	hash_for_each_possible(dns_domain_set_name_table.names, set_name_list, node, key)
	{
		if (strcmp(set_name_list->name, name) == 0) {
			return set_name_list;
		}
	}

	return NULL;
}

static int _config_domain_rule_set_each(const char *domain_set, set_rule_add_func callback, void *priv)
{
	struct dns_domain_set_name_list *set_name_list = NULL;
	struct dns_domain_set_name *set_name_item = NULL;

	set_name_list = _config_get_domain_set_name_list(domain_set);
	if (set_name_list == NULL) {
		tlog(TLOG_WARN, "domain set %s not found.", domain_set);
		return -1;
	}

	list_for_each_entry(set_name_item, &set_name_list->set_name_list, list)
	{
		switch (set_name_item->type) {
		case DNS_DOMAIN_SET_LIST:
			if (_config_set_rule_each_from_list(set_name_item->file, callback, priv) != 0) {
				return -1;
			}
			break;
		case DNS_DOMAIN_SET_GEOSITE:
			break;
		default:
			tlog(TLOG_WARN, "domain set %s type %d not support.", set_name_list->name, set_name_item->type);
			break;
		}
	}

	return 0;
}

static int _config_domain_rule_add(const char *domain, enum domain_rule type, void *rule);
static int _config_domain_rule_add_callback(const char *domain, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_domain_rule_add(domain, args->type, args->rule);
}

static int _config_setup_domain_key(const char *domain, char *domain_key, int domain_key_max_len, int *domain_key_len,
									int *root_rule_only, int *sub_rule_only)
{
	int tmp_root_rule_only = 0;
	int tmp_sub_rule_only = 0;
	int domain_len = 0;

	int len = strlen(domain);
	domain_len = len;
	if (len >= domain_key_max_len - 3) {
		tlog(TLOG_ERROR, "domain %s too long", domain);
		return -1;
	}

	while (len > 0 && domain[len - 1] == '.') {
		len--;
	}

	reverse_string(domain_key + 1, domain, len, 1);
	if (domain[0] == '*' && domain_len > 1) {
		/* prefix wildcard */
		len--;
		if (domain[1] == '.') {
			tmp_sub_rule_only = 1;
		} else if ((domain[1] == '-') && (domain[2] == '.')) {
			len--;
			tmp_sub_rule_only = 1;
			tmp_root_rule_only = 1;
		}
	} else if (domain[0] == '-' && domain_len > 1) {
		/* root match only */
		len--;
		if (domain[1] == '.') {
			tmp_root_rule_only = 1;
		}
	} else if (len > 0) {
		/* suffix match */
		domain_key[len + 1] = '.';
		len++;
	}

	domain_key[len + 1] = 0;
	domain_key[0] = '.';

	*domain_key_len = len + 1;
	if (root_rule_only) {
		*root_rule_only = tmp_root_rule_only;
	}

	if (sub_rule_only) {
		*sub_rule_only = tmp_sub_rule_only;
	}

	return 0;
}

static __attribute__((unused)) struct dns_domain_rule *_config_domain_rule_get(const char *domain)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
		return NULL;
	}

	return art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
}

static int _config_domain_rule_add(const char *domain, enum domain_rule type, void *rule)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		struct dns_set_rule_add_callback_args args;
		args.type = type;
		args.rule = rule;
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_add_callback,
											&args);
	}

	/* Reverse string, for suffix match */
	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		goto errout;
	}

	if (type >= DOMAIN_RULE_MAX) {
		goto errout;
	}

	/* Get existing or create domain rule */
	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
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
		_dns_rule_put(domain_rule->rules[type]);
		domain_rule->rules[type] = NULL;
	}

	domain_rule->rules[type] = rule;
	domain_rule->sub_rule_only = sub_rule_only;
	domain_rule->root_rule_only = root_rule_only;
	_dns_rule_get(rule);

	/* update domain rule */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len,
									 add_domain_rule);
		if (old_domain_rule) {
			_config_domain_rule_free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add domain %s rule failed", domain);
	return -1;
}

static int _config_domain_rule_delete(const char *domain);
static int _config_domain_rule_delete_callback(const char *domain, void *priv)
{
	return _config_domain_rule_delete(domain);
}

static int _config_domain_rule_delete(const char *domain)
{
	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_delete_callback,
											NULL);
	}
	/* Reverse string, for suffix match */

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, NULL, NULL) != 0) {
		goto errout;
	}

	/* delete existing rules */
	void *rule = art_delete(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
	if (rule) {
		_config_domain_rule_free(rule);
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "delete domain %s rule failed", domain);
	return -1;
}

static int _config_domain_rule_flag_set(const char *domain, unsigned int flag, unsigned int is_clear);
static int _config_domain_rule_flag_callback(const char *domain, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_domain_rule_flag_set(domain, args->flags, args->is_clear_flag);
}

static int _config_domain_rule_flag_set(const char *domain, unsigned int flag, unsigned int is_clear)
{
	struct dns_domain_rule *domain_rule = NULL;
	struct dns_domain_rule *old_domain_rule = NULL;
	struct dns_domain_rule *add_domain_rule = NULL;
	struct dns_rule_flags *rule_flags = NULL;

	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	int len = 0;
	int sub_rule_only = 0;
	int root_rule_only = 0;

	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		struct dns_set_rule_flags_callback_args args;
		args.flags = flag;
		args.is_clear_flag = is_clear;
		return _config_domain_rule_set_each(domain + sizeof("domain-set:") - 1, _config_domain_rule_flag_callback,
											&args);
	}

	if (_config_setup_domain_key(domain, domain_key, sizeof(domain_key), &len, &root_rule_only, &sub_rule_only) != 0) {
		goto errout;
	}

	/* Get existing or create domain rule */
	domain_rule = art_search(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len);
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
		rule_flags = _new_dns_rule(DOMAIN_RULE_FLAGS);
		rule_flags->flags = 0;
		domain_rule->rules[DOMAIN_RULE_FLAGS] = (struct dns_rule *)rule_flags;
	}

	domain_rule->sub_rule_only = sub_rule_only;
	domain_rule->root_rule_only = root_rule_only;

	rule_flags = (struct dns_rule_flags *)domain_rule->rules[DOMAIN_RULE_FLAGS];
	if (is_clear == false) {
		rule_flags->flags |= flag;
	} else {
		rule_flags->flags &= ~flag;
	}
	rule_flags->is_flag_set |= flag;

	/* update domain rule */
	if (add_domain_rule) {
		old_domain_rule = art_insert(&_config_current_rule_group()->domain_rule.tree, (unsigned char *)domain_key, len,
									 add_domain_rule);
		if (old_domain_rule) {
			_config_domain_rule_free(old_domain_rule);
		}
	}

	return 0;
errout:
	if (add_domain_rule) {
		free(add_domain_rule);
	}

	tlog(TLOG_ERROR, "add domain %s rule failed", domain);
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
	int ret = -1;

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

		ipset_rule = _new_dns_rule(type);
		if (ipset_rule == NULL) {
			goto errout;
		}

		ipset_rule->ipsetname = ipset;

		if (_config_domain_rule_add(domain, type, ipset_rule) != 0) {
			goto errout;
		}
		_dns_rule_put(&ipset_rule->head);
		ipset_rule = NULL;
	}

	ret = 0;
	goto clear;

errout:
	tlog(TLOG_ERROR, "add ipset %s failed", ipsetname);

	if (ipset_rule) {
		_dns_rule_put(&ipset_rule->head);
	}

clear:
	if (copied_name) {
		free(copied_name);
	}

	return ret;
}

static int _config_ipset_setvalue(struct dns_ipset_names *ipsets, const char *ipsetvalue)
{
	char *copied_name = NULL;
	const char *ipset = NULL;
	struct dns_ipset_rule *ipset_rule_array[2] = {NULL, NULL};
	char *ipset_rule_enable_array[2] = {NULL, NULL};
	int ipset_num = 0;

	copied_name = strdup(ipsetvalue);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok && ipset_num <= 2; tok = strtok(NULL, ",")) {
		if (tok[0] == '#') {
			if (strncmp(tok, "#6:", 3U) == 0) {
				ipset_rule_array[ipset_num] = &ipsets->ipv6;
				ipset_rule_enable_array[ipset_num] = &ipsets->ipv6_enable;
				ipset_num++;
			} else if (strncmp(tok, "#4:", 3U) == 0) {
				ipset_rule_array[ipset_num] = &ipsets->ipv4;
				ipset_rule_enable_array[ipset_num] = &ipsets->ipv4_enable;
				ipset_num++;
			} else {
				goto errout;
			}
			tok += 3;
		}

		if (ipset_num == 0) {
			ipset_rule_array[0] = &ipsets->inet;
			ipset_rule_enable_array[0] = &ipsets->inet_enable;
			ipset_num = 1;
		}

		if (strncmp(tok, "-", 1) == 0) {
			continue;
		}

		/* new ipset domain */
		ipset = _dns_conf_get_ipset(tok);
		if (ipset == NULL) {
			goto errout;
		}

		for (int i = 0; i < ipset_num; i++) {
			ipset_rule_array[i]->ipsetname = ipset;
			*ipset_rule_enable_array[i] = 1;
		}

		ipset_num = 0;
	}

	free(copied_name);
	return 0;
errout:
	if (copied_name) {
		free(copied_name);
	}

	return 0;
}

static int _config_ipset(void *data, int argc, char *argv[])
{
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];
	int ret = 0;

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	ret = _conf_domain_rule_ipset(domain, value);
	if (ret != 0) {
		goto errout;
	}

	return 0;
errout:
	tlog(TLOG_WARN, "add ipset %s failed.", value);
	return ret;
}

static int _config_ipset_no_speed(void *data, int argc, char *argv[])
{
	char *ipsetname = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_config_ipset_setvalue(&_config_current_rule_group()->ipset_nftset.ipset_no_speed, ipsetname) != 0) {
		goto errout;
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "add ipset-no-speed %s failed", ipsetname);
	return 0;
}

static void _config_nftset_table_destroy(void)
{
	struct dns_nftset_name *nftset = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_nftset_table.nftset, i, tmp, nftset, node)
	{
		hlist_del_init(&nftset->node);
		free(nftset);
	}
}

static const struct dns_nftset_name *_dns_conf_get_nftable(const char *familyname, const char *tablename,
														   const char *setname)
{
	uint32_t key = 0;
	struct dns_nftset_name *nftset_name = NULL;

	if (familyname == NULL || tablename == NULL || setname == NULL) {
		return NULL;
	}

	const char *hasher[4] = {familyname, tablename, setname, NULL};

	key = hash_string_array(hasher);
	hash_for_each_possible(dns_nftset_table.nftset, nftset_name, node, key)
	{
		if (strncmp(nftset_name->nftfamilyname, familyname, DNS_MAX_NFTSET_FAMILYLEN) == 0 &&
			strncmp(nftset_name->nfttablename, tablename, DNS_MAX_NFTSET_NAMELEN) == 0 &&
			strncmp(nftset_name->nftsetname, setname, DNS_MAX_NFTSET_NAMELEN) == 0) {
			return nftset_name;
		}
	}

	nftset_name = malloc(sizeof(*nftset_name));
	if (nftset_name == NULL) {
		goto errout;
	}

	safe_strncpy(nftset_name->nftfamilyname, familyname, DNS_MAX_NFTSET_FAMILYLEN);
	safe_strncpy(nftset_name->nfttablename, tablename, DNS_MAX_NFTSET_NAMELEN);
	safe_strncpy(nftset_name->nftsetname, setname, DNS_MAX_NFTSET_NAMELEN);
	hash_add(dns_nftset_table.nftset, &nftset_name->node, key);

	return nftset_name;
errout:
	if (nftset_name) {
		free(nftset_name);
	}

	return NULL;
}

static int _conf_domain_rule_nftset(char *domain, const char *nftsetname)
{
	struct dns_nftset_rule *nftset_rule = NULL;
	const struct dns_nftset_name *nftset = NULL;
	char *copied_name = NULL;
	enum domain_rule type = 0;
	int ignore_flag = 0;
	char *setname = NULL;
	char *tablename = NULL;
	char *family = NULL;
	int ret = -1;

	copied_name = strdup(nftsetname);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok; tok = strtok(NULL, ",")) {
		char *saveptr = NULL;
		char *tok_set = NULL;
		nftset_rule = NULL;

		if (strncmp(tok, "#4:", 3U) == 0) {
			type = DOMAIN_RULE_NFTSET_IP;
			ignore_flag = DOMAIN_FLAG_NFTSET_IP_IGN;
		} else if (strncmp(tok, "#6:", 3U) == 0) {
			type = DOMAIN_RULE_NFTSET_IP6;
			ignore_flag = DOMAIN_FLAG_NFTSET_IP6_IGN;
		} else if (strncmp(tok, "-", 2U) == 0) {
			_config_domain_rule_flag_set(domain, DOMAIN_FLAG_NFTSET_INET_IGN, 0);
			continue;
		} else {
			goto errout;
		}

		tok_set = tok + 3;

		if (strncmp(tok_set, "-", 2U) == 0) {
			_config_domain_rule_flag_set(domain, ignore_flag, 0);
			continue;
		}

		family = strtok_r(tok_set, "#", &saveptr);
		if (family == NULL) {
			goto errout;
		}

		tablename = strtok_r(NULL, "#", &saveptr);
		if (tablename == NULL) {
			goto errout;
		}

		setname = strtok_r(NULL, "#", &saveptr);
		if (setname == NULL) {
			goto errout;
		}

		/* new nftset domain */
		nftset = _dns_conf_get_nftable(family, tablename, setname);
		if (nftset == NULL) {
			goto errout;
		}

		nftset_rule = _new_dns_rule(type);
		if (nftset_rule == NULL) {
			goto errout;
		}

		nftset_rule->nfttablename = nftset->nfttablename;
		nftset_rule->nftsetname = nftset->nftsetname;
		nftset_rule->familyname = nftset->nftfamilyname;

		if (_config_domain_rule_add(domain, type, nftset_rule) != 0) {
			goto errout;
		}
		_dns_rule_put(&nftset_rule->head);
		nftset_rule = NULL;
	}

	ret = 0;
	goto clear;

errout:
	tlog(TLOG_ERROR, "add nftset %s %s failed.", domain, nftsetname);

	if (nftset_rule) {
		_dns_rule_put(&nftset_rule->head);
	}

clear:
	if (copied_name) {
		free(copied_name);
	}

	return ret;
}

static int _config_nftset(void *data, int argc, char *argv[])
{
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];
	int ret = 0;

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_nftset(domain, value);
errout:
	tlog(TLOG_ERROR, "add nftset %s failed", value);
	return ret;
}

static int _config_nftset_setvalue(struct dns_nftset_names *nftsets, const char *nftsetvalue)
{
	const struct dns_nftset_name *nftset = NULL;
	char *copied_name = NULL;
	int nftset_num = 0;
	char *setname = NULL;
	char *tablename = NULL;
	char *family = NULL;
	int ret = -1;
	struct dns_nftset_rule *nftset_rule_array[2] = {NULL, NULL};
	char *nftset_rule_enable_array[2] = {NULL, NULL};

	if (nftsetvalue == NULL) {
		goto errout;
	}

	copied_name = strdup(nftsetvalue);

	if (copied_name == NULL) {
		goto errout;
	}

	for (char *tok = strtok(copied_name, ","); tok && nftset_num <= 2; tok = strtok(NULL, ",")) {
		char *saveptr = NULL;
		char *tok_set = NULL;

		if (strncmp(tok, "#4:", 3U) == 0) {
			nftsets->ip_enable = 1;
			nftset_rule_array[nftset_num] = &nftsets->ip;
			nftset_rule_enable_array[nftset_num] = &nftsets->ip_enable;
			nftset_num++;
		} else if (strncmp(tok, "#6:", 3U) == 0) {
			nftset_rule_enable_array[nftset_num] = &nftsets->ip6_enable;
			nftset_rule_array[nftset_num] = &nftsets->ip6;
			nftset_num++;
		} else if (strncmp(tok, "-", 2U) == 0) {
			continue;
			continue;
		} else {
			goto errout;
		}

		tok_set = tok + 3;

		if (nftset_num == 0) {
			nftset_rule_array[0] = &nftsets->ip;
			nftset_rule_enable_array[0] = &nftsets->ip_enable;
			nftset_rule_array[1] = &nftsets->ip6;
			nftset_rule_enable_array[1] = &nftsets->ip6_enable;
			nftset_num = 2;
		}

		if (strncmp(tok_set, "-", 2U) == 0) {
			continue;
		}

		family = strtok_r(tok_set, "#", &saveptr);
		if (family == NULL) {
			goto errout;
		}

		tablename = strtok_r(NULL, "#", &saveptr);
		if (tablename == NULL) {
			goto errout;
		}

		setname = strtok_r(NULL, "#", &saveptr);
		if (setname == NULL) {
			goto errout;
		}

		/* new nftset domain */
		nftset = _dns_conf_get_nftable(family, tablename, setname);
		if (nftset == NULL) {
			goto errout;
		}

		for (int i = 0; i < nftset_num; i++) {
			nftset_rule_array[i]->familyname = nftset->nftfamilyname;
			nftset_rule_array[i]->nfttablename = nftset->nfttablename;
			nftset_rule_array[i]->nftsetname = nftset->nftsetname;
			*nftset_rule_enable_array[i] = 1;
		}

		nftset_num = 0;
	}

	ret = 0;
	goto clear;

errout:
	ret = -1;
clear:
	if (copied_name) {
		free(copied_name);
	}

	return ret;
}

static int _config_nftset_no_speed(void *data, int argc, char *argv[])
{
	char *nftsetname = argv[1];

	if (argc <= 1) {
		goto errout;
	}

	if (_config_nftset_setvalue(&_config_current_rule_group()->ipset_nftset.nftset_no_speed, nftsetname) != 0) {
		goto errout;
	}

	return 0;
errout:
	tlog(TLOG_ERROR, "add nftset %s failed", nftsetname);
	return -1;
}

static int _conf_domain_rule_address(char *domain, const char *domain_address)
{
	struct dns_rule_address_IPV4 *address_ipv4 = NULL;
	struct dns_rule_address_IPV6 *address_ipv6 = NULL;
	struct dns_rule *address = NULL;

	char ip[MAX_IP_LEN];
	int port = 0;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	unsigned int flag = 0;
	char *ptr = NULL;
	char *field = NULL;
	char tmpbuff[TMP_BUFF_LEN] = {0};

	char ipv6_addr[DNS_MAX_REPLY_IP_NUM][DNS_RR_AAAA_LEN];
	int ipv6_num = 0;
	char ipv4_addr[DNS_MAX_REPLY_IP_NUM][DNS_RR_A_LEN];
	int ipv4_num = 0;

	safe_strncpy(tmpbuff, domain_address, sizeof(tmpbuff));

	ptr = tmpbuff;

	do {
		field = ptr;
		ptr = strstr(ptr, ",");

		if (field == NULL || *field == '\0') {
			break;
		}

		if (ptr) {
			*ptr = 0;
		}

		if (*(field) == '#') {
			if (strncmp(field, "#4", sizeof("#4")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV4_SOA;
			} else if (strncmp(field, "#6", sizeof("#6")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV6_SOA;
			} else if (strncmp(field, "#", sizeof("#")) == 0) {
				flag = DOMAIN_FLAG_ADDR_SOA;
			} else {
				goto errout;
			}

			/* add SOA rule */
			if (_config_domain_rule_flag_set(domain, flag, 0) != 0) {
				goto errout;
			}

			if (ptr) {
				ptr++;
			}
			continue;
		} else if (*(field) == '-') {
			if (strncmp(field, "-4", sizeof("-4")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV4_IGN;
			} else if (strncmp(field, "-6", sizeof("-6")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV6_IGN;
			} else if (strncmp(field, "-", sizeof("-")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IGN;
			} else {
				goto errout;
			}

			/* ignore rule */
			if (_config_domain_rule_flag_set(domain, flag, 0) != 0) {
				goto errout;
			}

			if (ptr) {
				ptr++;
			}
			continue;
		}

		/* set address to domain */
		if (parse_ip(field, ip, &port) != 0) {
			goto errout;
		}

		addr_len = sizeof(addr);
		if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
			goto errout;
		}

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)&addr;
			if (ipv4_num < DNS_MAX_REPLY_IP_NUM) {
				memcpy(ipv4_addr[ipv4_num], &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
				ipv4_num++;
			}
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr) && ipv4_num < DNS_MAX_REPLY_IP_NUM) {
				memcpy(ipv4_addr[ipv4_num], addr_in6->sin6_addr.s6_addr + 12, DNS_RR_A_LEN);
				ipv4_num++;
			} else if (ipv6_num < DNS_MAX_REPLY_IP_NUM) {
				memcpy(ipv6_addr[ipv6_num], addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
				ipv6_num++;
			}
		} break;
		default:
			ip[0] = '\0';
			break;
		}

		/* add PTR */
		if (dns_conf_expand_ptr_from_address == 1 && ip[0] != '\0' && _conf_ptr_add(domain, ip, 0) != 0) {
			goto errout;
		}

		if (ptr) {
			ptr++;
		}
	} while (ptr);

	if (ipv4_num > 0) {
		address_ipv4 = _new_dns_rule_ext(DOMAIN_RULE_ADDRESS_IPV4, ipv4_num * DNS_RR_A_LEN);
		if (address_ipv4 == NULL) {
			goto errout;
		}

		memcpy(address_ipv4->ipv4_addr, ipv4_addr[0], ipv4_num * DNS_RR_A_LEN);
		address_ipv4->addr_num = ipv4_num;
		address = (struct dns_rule *)address_ipv4;

		if (_config_domain_rule_add(domain, DOMAIN_RULE_ADDRESS_IPV4, address) != 0) {
			goto errout;
		}

		_dns_rule_put(address);
	}

	if (ipv6_num > 0) {
		address_ipv6 = _new_dns_rule_ext(DOMAIN_RULE_ADDRESS_IPV6, ipv6_num * DNS_RR_AAAA_LEN);
		if (address_ipv6 == NULL) {
			goto errout;
		}

		memcpy(address_ipv6->ipv6_addr, ipv6_addr[0], ipv6_num * DNS_RR_AAAA_LEN);
		address_ipv6->addr_num = ipv6_num;
		address = (struct dns_rule *)address_ipv6;

		if (_config_domain_rule_add(domain, DOMAIN_RULE_ADDRESS_IPV6, address) != 0) {
			goto errout;
		}

		_dns_rule_put(address);
	}

	return 0;
errout:
	if (address) {
		_dns_rule_put(address);
	}

	tlog(TLOG_ERROR, "add address %s, %s at %s:%d failed", domain, domain_address, conf_get_conf_file(),
		 conf_get_current_lineno());
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

static int _conf_domain_rule_cname(const char *domain, const char *cname)
{
	struct dns_cname_rule *cname_rule = NULL;
	enum domain_rule type = DOMAIN_RULE_CNAME;

	cname_rule = _new_dns_rule(type);
	if (cname_rule == NULL) {
		goto errout;
	}

	/* ignore this domain */
	if (*cname == '-') {
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_CNAME_IGN, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	safe_strncpy(cname_rule->cname, cname, DNS_MAX_CONF_CNAME_LEN);

	if (_config_domain_rule_add(domain, type, cname_rule) != 0) {
		goto errout;
	}
	_dns_rule_put(&cname_rule->head);
	cname_rule = NULL;

	return 0;

errout:
	tlog(TLOG_ERROR, "add cname %s:%s failed", domain, cname);

	if (cname_rule) {
		_dns_rule_put(&cname_rule->head);
	}

	return 0;
}

static int _config_cname(void *data, int argc, char *argv[])
{
	char *value = argv[1];
	char domain[DNS_MAX_CONF_CNAME_LEN];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_cname(domain, value);
errout:
	tlog(TLOG_ERROR, "add cname %s:%s failed", domain, value);
	return 0;
}

struct dns_srv_records *dns_server_get_srv_record(const char *domain)
{
	uint32_t key = 0;

	key = hash_string(domain);
	struct dns_srv_records *srv_records = NULL;
	hash_for_each_possible(dns_conf_srv_record_table.srv, srv_records, node, key)
	{
		if (strncmp(srv_records->domain, domain, DNS_MAX_CONF_CNAME_LEN) == 0) {
			return srv_records;
		}
	}

	return NULL;
}

static int _confg_srv_record_add(const char *domain, const char *host, unsigned short priority, unsigned short weight,
								 unsigned short port)
{
	struct dns_srv_records *srv_records = NULL;
	struct dns_srv_record *srv_record = NULL;
	uint32_t key = 0;

	srv_records = dns_server_get_srv_record(domain);
	if (srv_records == NULL) {
		srv_records = malloc(sizeof(*srv_records));
		if (srv_records == NULL) {
			goto errout;
		}
		memset(srv_records, 0, sizeof(*srv_records));
		safe_strncpy(srv_records->domain, domain, DNS_MAX_CONF_CNAME_LEN);
		INIT_LIST_HEAD(&srv_records->list);
		key = hash_string(domain);
		hash_add(dns_conf_srv_record_table.srv, &srv_records->node, key);
	}

	srv_record = malloc(sizeof(*srv_record));
	if (srv_record == NULL) {
		goto errout;
	}
	memset(srv_record, 0, sizeof(*srv_record));
	safe_strncpy(srv_record->host, host, DNS_MAX_CONF_CNAME_LEN);
	srv_record->priority = priority;
	srv_record->weight = weight;
	srv_record->port = port;
	list_add_tail(&srv_record->list, &srv_records->list);

	return 0;
errout:
	if (srv_record != NULL) {
		free(srv_record);
	}
	return -1;
}

static int _config_srv_record(void *data, int argc, char *argv[])
{
	char *value = NULL;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char buff[DNS_MAX_CONF_CNAME_LEN];
	char *ptr = NULL;
	int ret = -1;

	char *host_s;
	char *priority_s;
	char *weight_s;
	char *port_s;

	unsigned short priority = 0;
	unsigned short weight = 0;
	unsigned short port = 1;

	if (argc < 2) {
		goto errout;
	}

	value = argv[1];
	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	safe_strncpy(buff, value, sizeof(buff));

	host_s = strtok_r(buff, ",", &ptr);
	if (host_s == NULL) {
		host_s = "";
		goto out;
	}

	port_s = strtok_r(NULL, ",", &ptr);
	if (port_s != NULL) {
		port = atoi(port_s);
	}

	priority_s = strtok_r(NULL, ",", &ptr);
	if (priority_s != NULL) {
		priority = atoi(priority_s);
	}

	weight_s = strtok_r(NULL, ",", &ptr);
	if (weight_s != NULL) {
		weight = atoi(weight_s);
	}
out:
	ret = _confg_srv_record_add(domain, host_s, priority, weight, port);
	if (ret != 0) {
		goto errout;
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "add srv-record %s:%s failed", domain, value);
	return -1;
}

static int _conf_domain_rule_https_copy_alpn(char *alpn_data, int max_alpn_len, const char *alpn_str)
{
	const char *ptr = NULL;
	int alpn_len = 0;
	char *alpn_len_ptr = NULL;
	char *alpn_ptr = NULL;
	int total_len = 0;

	ptr = alpn_str;
	alpn_len_ptr = alpn_data;
	alpn_ptr = alpn_data + 1;
	total_len++;

	while (*ptr != '\0') {
		total_len++;
		if (total_len > max_alpn_len) {
			return -1;
		}

		if (*ptr == ',') {
			*alpn_len_ptr = alpn_len;
			alpn_len = 0;
			alpn_len_ptr = alpn_ptr;
			ptr++;
			alpn_ptr++;
			continue;
		}

		*alpn_ptr = *ptr;
		alpn_len++;
		alpn_ptr++;
		ptr++;
	}

	*alpn_len_ptr = alpn_len;
	return total_len;
}

static int _conf_domain_rule_https_record(const char *domain, const char *host)
{
	struct dns_https_record_rule *https_record_rule = NULL;
	enum domain_rule type = DOMAIN_RULE_HTTPS;
	char buff[4096];
	int key_num = 0;
	char *keys[16];
	char *value[16];
	int priority = -1;
	/*mode_type, 0: alias mode, 1: service mode */
	int mode_type = 0;

	safe_strncpy(buff, host, sizeof(buff));

	https_record_rule = _new_dns_rule(type);
	if (https_record_rule == NULL) {
		goto errout;
	}

	if (conf_parse_key_values(buff, &key_num, keys, value) != 0) {
		tlog(TLOG_ERROR, "input format error, don't have key-value.");
		goto errout;
	}

	if (key_num < 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	for (int i = 0; i < key_num; i++) {
		const char *key = keys[i];
		const char *val = value[i];
		if (strncmp(key, "#", sizeof("#")) == 0) {
			if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_ADDR_HTTPS_SOA, 0) != 0) {
				goto errout;
			}
			break;
		} else if (strncmp(key, "-", sizeof("-")) == 0) {
			if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_ADDR_HTTPS_IGN, 0) != 0) {
				goto errout;
			}
		} else if (strncmp(key, "target", sizeof("target")) == 0) {
			safe_strncpy(https_record_rule->record.target, val, DNS_MAX_CONF_CNAME_LEN);
			https_record_rule->record.enable = 1;
		} else if (strncmp(key, "noipv4hint", sizeof("noipv4hint")) == 0) {
			https_record_rule->filter.no_ipv4hint = 1;
		} else if (strncmp(key, "noipv6hint", sizeof("noipv6hint")) == 0) {
			https_record_rule->filter.no_ipv6hint = 1;
		} else {
			mode_type = 1;
			https_record_rule->record.enable = 1;
			if (strncmp(key, "priority", sizeof("priority")) == 0) {
				priority = atoi(val);
			} else if (strncmp(key, "port", sizeof("port")) == 0) {
				https_record_rule->record.port = atoi(val);

			} else if (strncmp(key, "alpn", sizeof("alpn")) == 0) {
				int alpn_len = _conf_domain_rule_https_copy_alpn(https_record_rule->record.alpn, DNS_MAX_ALPN_LEN, val);
				if (alpn_len <= 0) {
					tlog(TLOG_ERROR, "invalid option value for %s.", key);
					goto errout;
				}
				https_record_rule->record.alpn_len = alpn_len;
			} else if (strncmp(key, "ech", sizeof("ech")) == 0) {
				int ech_len = SSL_base64_decode(val, https_record_rule->record.ech, DNS_MAX_ECH_LEN);
				if (ech_len < 0) {
					tlog(TLOG_ERROR, "invalid option value for %s.", key);
					goto errout;
				}
				https_record_rule->record.ech_len = ech_len;
			} else if (strncmp(key, "ipv4hint", sizeof("ipv4hint")) == 0) {
				int addr_len = DNS_RR_A_LEN;
				if (get_raw_addr_by_ip(val, https_record_rule->record.ipv4_addr, &addr_len) != 0) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}

				if (addr_len != DNS_RR_A_LEN) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}
				https_record_rule->record.has_ipv4 = 1;
			} else if (strncmp(key, "ipv6hint", sizeof("ipv6hint")) == 0) {
				int addr_len = DNS_RR_AAAA_LEN;
				if (get_raw_addr_by_ip(val, https_record_rule->record.ipv6_addr, &addr_len) != 0) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}

				if (addr_len != DNS_RR_AAAA_LEN) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}
				https_record_rule->record.has_ipv6 = 1;
			} else {
				tlog(TLOG_WARN, "invalid parameter %s for https-record.", key);
				continue;
			}
		}
	}

	if (mode_type == 0) {
		if (priority < 0) {
			priority = 0;
		}
	} else {
		if (priority < 0) {
			priority = 1;
		} else if (priority == 0) {
			tlog(TLOG_WARN, "invalid priority %d for https-record.", priority);
			goto errout;
		}
	}

	https_record_rule->record.priority = priority;

	if (_config_domain_rule_add(domain, type, https_record_rule) != 0) {
		goto errout;
	}

	_dns_rule_put(&https_record_rule->head);
	https_record_rule = NULL;

	return 0;
errout:
	if (https_record_rule) {
		_dns_rule_put(&https_record_rule->head);
	}

	return -1;
}

static int _config_https_record(void *data, int argc, char *argv[])
{
	char *value = NULL;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	int ret = -1;

	if (argc < 2) {
		goto errout;
	}

	value = argv[1];
	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	ret = _conf_domain_rule_https_record(domain, value);
	if (ret != 0) {
		goto errout;
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "add https-record %s:%s failed", domain, value);
	return -1;
}

static void _config_speed_check_mode_clear(struct dns_domain_check_orders *check_orders)
{
	memset(check_orders->orders, 0, sizeof(check_orders->orders));
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
	_config_speed_check_mode_clear(check_orders);

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
			dns_conf_has_icmp_check = 1;
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
			dns_conf_has_tcp_check = 1;
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

	return _config_speed_check_mode_parser(&_config_current_rule_group()->check_orders, mode);
}

static int _config_dns64(void *data, int argc, char *argv[])
{
	prefix_t prefix;
	char *subnet = NULL;
	const char *errmsg = NULL;
	void *p = NULL;

	if (argc <= 1) {
		return -1;
	}

	subnet = argv[1];

	if (strncmp(subnet, "-", 2U) == 0) {
		memset(&_config_current_rule_group()->dns_dns64, 0, sizeof(struct dns_dns64));
		return 0;
	}

	p = prefix_pton(subnet, -1, &prefix, &errmsg);
	if (p == NULL) {
		goto errout;
	}

	if (prefix.family != AF_INET6) {
		tlog(TLOG_ERROR, "dns64 subnet %s is not ipv6", subnet);
		goto errout;
	}

	if (prefix.bitlen <= 0 || prefix.bitlen > 96) {
		tlog(TLOG_ERROR, "dns64 subnet %s is not valid", subnet);
		goto errout;
	}

	struct dns_dns64 *dns64 = &(_config_current_rule_group()->dns_dns64);
	memcpy(&dns64->prefix, &prefix.add.sin6.s6_addr, sizeof(dns64->prefix));
	dns64->prefix_len = prefix.bitlen;

	return 0;

errout:
	return -1;
}

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
	int index = dns_conf_bind_ip_num;
	struct dns_bind_ip *bind_ip = NULL;
	char *ip = NULL;
	int opt = 0;
	int optind = 0;
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

	for (i = 0; i < dns_conf_bind_ip_num; i++) {
		bind_ip = &dns_conf_bind_ip[i];
		if (bind_ip->type != type) {
			continue;
		}

		if (strncmp(bind_ip->ip, ip, DNS_MAX_IPLEN) != 0) {
			continue;
		}

		tlog(TLOG_WARN, "bind server %s, type %d, already configured, skip.", ip, type);
		return 0;
	}

	bind_ip = &dns_conf_bind_ip[index];
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
	dns_conf_bind_ip_num++;
	if (bind_ip->type == DNS_BIND_TYPE_TLS || bind_ip->type == DNS_BIND_TYPE_HTTPS) {
		if (bind_ip->ssl_cert_file == NULL || bind_ip->ssl_cert_key_file == NULL) {
			bind_ip->ssl_cert_file = dns_conf_bind_ca_file;
			bind_ip->ssl_cert_key_file = dns_conf_bind_ca_key_file;
			bind_ip->ssl_cert_key_pass = dns_conf_bind_ca_key_pass;
			dns_conf_need_cert = 1;
		}
	}
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

static int _config_bind_ip_tls(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_TLS);
}

static int _config_bind_ip_https(void *data, int argc, char *argv[])
{
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_HTTPS);
}

static int _config_option_parser_filepath(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	conf_get_conf_fullpath(argv[1], data, DNS_MAX_PATH);

	return 0;
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

static int _conf_domain_rule_nameserver(const char *domain, const char *group_name)
{
	struct dns_nameserver_rule *nameserver_rule = NULL;
	const char *group = NULL;

	if (strncmp(group_name, "-", sizeof("-")) != 0) {
		group = _dns_conf_get_group_name(group_name);
		if (group == NULL) {
			goto errout;
		}

		nameserver_rule = _new_dns_rule(DOMAIN_RULE_NAMESERVER);
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

	_dns_rule_put(&nameserver_rule->head);

	return 0;
errout:
	if (nameserver_rule) {
		_dns_rule_put(&nameserver_rule->head);
	}

	tlog(TLOG_ERROR, "add nameserver %s, %s failed", domain, group_name);
	return 0;
}

static int _conf_domain_rule_group(const char *domain, const char *group_name)
{
	struct dns_group_rule *group_rule = NULL;
	const char *group = NULL;

	if (strncmp(group_name, "-", sizeof("-")) != 0) {
		group = _dns_conf_get_group_name(group_name);
		if (group == NULL) {
			goto errout;
		}

		group_rule = _new_dns_rule(DOMAIN_RULE_GROUP);
		if (group_rule == NULL) {
			goto errout;
		}

		group_rule->group_name = group;
	} else {
		/* ignore this domain */
		if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_GROUP_IGNORE, 0) != 0) {
			goto errout;
		}

		return 0;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_GROUP, group_rule) != 0) {
		goto errout;
	}

	_dns_rule_put(&group_rule->head);

	return 0;
errout:
	if (group_rule) {
		_dns_rule_put(&group_rule->head);
	}

	tlog(TLOG_ERROR, "add group %s, %s failed", domain, group_name);
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

static int _config_proxy_server(void *data, int argc, char *argv[])
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

static radix_node_t *_create_addr_node(const char *addr)
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
		tree = _config_current_rule_group()->address_rule.ipv4;
		break;
	case AF_INET6:
		tree = _config_current_rule_group()->address_rule.ipv6;
		break;
	}

	node = radix_lookup(tree, &prefix);
	return node;
}

static void *_new_dns_ip_rule_ext(enum ip_rule ip_rule, int ext_size)
{
	struct dns_ip_rule *rule;
	int size = 0;

	if (ip_rule >= IP_RULE_MAX) {
		return NULL;
	}

	switch (ip_rule) {
	case IP_RULE_FLAGS:
		size = sizeof(struct ip_rule_flags);
		break;
	case IP_RULE_ALIAS:
		size = sizeof(struct ip_rule_alias);
		break;
	default:
		return NULL;
	}

	size += ext_size;
	rule = malloc(size);
	if (!rule) {
		return NULL;
	}
	memset(rule, 0, size);
	rule->rule = ip_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

static void *_new_dns_ip_rule(enum ip_rule ip_rule)
{
	return _new_dns_ip_rule_ext(ip_rule, 0);
}

static void _dns_ip_rule_get(struct dns_ip_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static void _dns_ip_rule_put(struct dns_ip_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt)) {
		if (rule->rule == IP_RULE_ALIAS) {
			struct ip_rule_alias *alias = container_of(rule, struct ip_rule_alias, head);
			if (alias->ip_alias.ipaddr) {
				free(alias->ip_alias.ipaddr);
				alias->ip_alias.ipaddr = NULL;
				alias->ip_alias.ipaddr_num = 0;
			}
		}
		free(rule);
	}
}

static radix_node_t *_create_client_rules_node(const char *addr)
{
	radix_node_t *node = NULL;
	void *p = NULL;
	prefix_t prefix;
	const char *errmsg = NULL;

	p = prefix_pton(addr, -1, &prefix, &errmsg);
	if (p == NULL) {
		return NULL;
	}

	node = radix_lookup(dns_conf_client_rule.rule, &prefix);
	return node;
}

static void *_new_dns_client_rule_ext(enum client_rule client_rule, int ext_size)
{
	struct dns_client_rule *rule;
	int size = 0;

	if (client_rule >= CLIENT_RULE_MAX) {
		return NULL;
	}

	switch (client_rule) {
	case CLIENT_RULE_FLAGS:
		size = sizeof(struct client_rule_flags);
		break;
	case CLIENT_RULE_GROUP:
		size = sizeof(struct client_rule_group);
		break;
	default:
		return NULL;
	}

	size += ext_size;
	rule = malloc(size);
	if (!rule) {
		return NULL;
	}
	memset(rule, 0, size);
	rule->rule = client_rule;
	atomic_set(&rule->refcnt, 1);
	return rule;
}

static void *_new_dns_client_rule(enum client_rule client_rule)
{
	return _new_dns_client_rule_ext(client_rule, 0);
}

static void _dns_client_rule_get(struct dns_client_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static void _dns_client_rule_put(struct dns_client_rule *rule)
{
	int refcount = atomic_dec_return(&rule->refcnt);
	if (refcount > 0) {
		return;
	}

	free(rule);
}

static int _config_client_rules_free(struct dns_client_rules *client_rules)
{
	int i = 0;

	if (client_rules == NULL) {
		return 0;
	}

	for (i = 0; i < CLIENT_RULE_MAX; i++) {
		if (client_rules->rules[i] == NULL) {
			continue;
		}

		_dns_client_rule_put(client_rules->rules[i]);
		client_rules->rules[i] = NULL;
	}

	free(client_rules);
	return 0;
}

static struct client_roue_group_mac *_config_client_rule_group_mac_new(uint8_t mac[6])
{
	struct client_roue_group_mac *group_mac = NULL;
	uint32_t key;

	group_mac = malloc(sizeof(*group_mac));
	if (group_mac == NULL) {
		return NULL;
	}
	memset(group_mac, 0, sizeof(*group_mac));
	memcpy(group_mac->mac, mac, 6);

	key = jhash(mac, 6, 0);
	hash_add(dns_conf_client_rule.mac, &group_mac->node, key);
	dns_conf_client_rule.mac_num++;

	return group_mac;
}

struct client_roue_group_mac *dns_server_rule_group_mac_get(const uint8_t mac[6])
{
	struct client_roue_group_mac *group_mac = NULL;
	uint32_t key;

	key = jhash(mac, 6, 0);
	hash_for_each_possible(dns_conf_client_rule.mac, group_mac, node, key)
	{
		if (memcmp(group_mac->mac, mac, 6) == 0) {
			return group_mac;
		}
	}

	return NULL;
}

static struct client_roue_group_mac *_config_client_rule_group_mac_get_or_add(uint8_t mac[6])
{
	struct client_roue_group_mac *group_mac = dns_server_rule_group_mac_get(mac);
	if (group_mac == NULL) {
		group_mac = _config_client_rule_group_mac_new(mac);
	}

	return group_mac;
}

static int _config_client_rule_flag_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_client_rule_flag_set(ip_cidr, args->flags, args->is_clear_flag);
}

static int _config_client_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear)
{
	struct dns_client_rules *client_rules = NULL;
	struct dns_client_rules *add_client_rules = NULL;
	struct client_rule_flags *client_rule_flags = NULL;
	struct client_roue_group_mac *group_mac = NULL;
	radix_node_t *node = NULL;
	uint8_t mac[6];
	int is_mac_address = 0;

	is_mac_address = parser_mac_address(ip_cidr, mac);
	if (is_mac_address == 0) {
		group_mac = _config_client_rule_group_mac_get_or_add(mac);
		if (group_mac == NULL) {
			tlog(TLOG_ERROR, "get or add mac %s failed", ip_cidr);
			goto errout;
		}

		client_rules = group_mac->rules;
	} else {
		if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
			struct dns_set_rule_flags_callback_args args;
			args.flags = flag;
			args.is_clear_flag = is_clear;
			return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_client_rule_flag_callback, &args);
		}

		/* Get existing or create domain rule */
		node = _create_client_rules_node(ip_cidr);
		if (node == NULL) {
			tlog(TLOG_ERROR, "create addr node failed.");
			goto errout;
		}

		client_rules = node->data;
	}

	if (client_rules == NULL) {
		add_client_rules = malloc(sizeof(*add_client_rules));
		if (add_client_rules == NULL) {
			goto errout;
		}
		memset(add_client_rules, 0, sizeof(*add_client_rules));
		client_rules = add_client_rules;
		if (is_mac_address == 0) {
			group_mac->rules = client_rules;
		} else {
			node->data = client_rules;
		}
	}

	/* add new rule to domain */
	if (client_rules->rules[CLIENT_RULE_FLAGS] == NULL) {
		client_rule_flags = _new_dns_client_rule(CLIENT_RULE_FLAGS);
		client_rule_flags->flags = 0;
		client_rules->rules[CLIENT_RULE_FLAGS] = &client_rule_flags->head;
	}

	client_rule_flags = container_of(client_rules->rules[CLIENT_RULE_FLAGS], struct client_rule_flags, head);
	if (is_clear == false) {
		client_rule_flags->flags |= flag;
	} else {
		client_rule_flags->flags &= ~flag;
	}
	client_rule_flags->is_flag_set |= flag;

	return 0;
errout:
	if (add_client_rules) {
		free(add_client_rules);
	}

	tlog(TLOG_ERROR, "set ip %s flags failed", ip_cidr);

	return -1;
}

static int _config_client_rule_add(const char *ip_cidr, enum client_rule type, void *rule);
static int _config_client_rule_add_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_client_rule_add(ip_cidr, args->type, args->rule);
}

static int _config_client_rule_add(const char *ip_cidr, enum client_rule type, void *rule)
{
	struct dns_client_rules *client_rules = NULL;
	struct dns_client_rules *add_client_rules = NULL;
	struct client_roue_group_mac *group_mac = NULL;
	radix_node_t *node = NULL;

	if (ip_cidr == NULL) {
		goto errout;
	}

	if (type >= CLIENT_RULE_MAX) {
		goto errout;
	}

	uint8_t mac[6];
	int is_mac_address = 0;

	is_mac_address = parser_mac_address(ip_cidr, mac);
	if (is_mac_address == 0) {
		group_mac = _config_client_rule_group_mac_get_or_add(mac);
		if (group_mac == NULL) {
			tlog(TLOG_ERROR, "get or add mac %s failed", ip_cidr);
			goto errout;
		}

		client_rules = group_mac->rules;
	} else {
		if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
			struct dns_set_rule_add_callback_args args;
			args.type = type;
			args.rule = rule;
			return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_client_rule_add_callback, &args);
		}

		/* Get existing or create domain rule */
		node = _create_client_rules_node(ip_cidr);
		if (node == NULL) {
			tlog(TLOG_ERROR, "create addr node failed.");
			goto errout;
		}

		client_rules = node->data;
	}

	if (client_rules == NULL) {
		add_client_rules = malloc(sizeof(*add_client_rules));
		if (add_client_rules == NULL) {
			goto errout;
		}
		memset(add_client_rules, 0, sizeof(*add_client_rules));
		client_rules = add_client_rules;
		if (is_mac_address == 0) {
			group_mac->rules = client_rules;
		} else {
			node->data = client_rules;
		}
	}

	/* add new rule to domain */
	if (client_rules->rules[type]) {
		_dns_client_rule_put(client_rules->rules[type]);
		client_rules->rules[type] = NULL;
	}

	client_rules->rules[type] = rule;
	_dns_client_rule_get(rule);

	return 0;
errout:
	if (add_client_rules) {
		free(add_client_rules);
	}

	tlog(TLOG_ERROR, "add client %s rule failed", ip_cidr);
	return -1;
}

static int _conf_qtype_soa(uint8_t *soa_table, int argc, char *argv[])
{
	int i = 0;
	int j = 0;
	int is_clear = 0;

	if (argc <= 1) {
		return -1;
	}

	if (argc >= 2) {
		if (strncmp(argv[1], "-", sizeof("-")) == 0) {
			if (argc == 2) {
				memset(soa_table, 0, MAX_QTYPE_NUM / 8 + 1);
				return 0;
			}

			is_clear = 1;
		}

		if (strncmp(argv[1], "-,", sizeof(",")) == 0) {
			is_clear = 1;
		}
	}

	for (i = 1; i < argc; i++) {
		char sub_arg[1024];
		safe_strncpy(sub_arg, argv[i], sizeof(sub_arg));
		for (char *tok = strtok(sub_arg, ","); tok; tok = strtok(NULL, ",")) {
			char *dash = strstr(tok, "-");
			if (dash != NULL) {
				*dash = '\0';
			}

			if (*tok == '\0') {
				continue;
			}

			long start = atol(tok);
			long end = start;

			if (start > MAX_QTYPE_NUM || start < 0) {
				tlog(TLOG_ERROR, "invalid qtype %ld", start);
				continue;
			}

			if (dash != NULL && *(dash + 1) != '\0') {
				end = atol(dash + 1);
				if (end > MAX_QTYPE_NUM) {
					end = MAX_QTYPE_NUM;
				}
			}

			for (j = start; j <= end; j++) {
				int offset = j / 8;
				int bit = j % 8;
				if (is_clear) {
					soa_table[offset] &= ~(1 << bit);
				} else {
					soa_table[offset] |= (1 << bit);
				}
			}
		}
	}

	return 0;
}

static int _config_qtype_soa(void *data, int argc, char *argv[])
{
	return _conf_qtype_soa(_config_current_rule_group()->soa_table, argc, argv);
}

static void _config_domain_set_name_table_destroy(void)
{
	struct dns_domain_set_name_list *set_name_list = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_domain_set_name *set_name = NULL;
	struct dns_domain_set_name *tmp1 = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_domain_set_name_table.names, i, tmp, set_name_list, node)
	{
		hlist_del_init(&set_name_list->node);
		list_for_each_entry_safe(set_name, tmp1, &set_name_list->set_name_list, list)
		{
			list_del(&set_name->list);
			free(set_name);
		}

		free(set_name_list);
	}
}

static int _conf_client_subnet(char *subnet, struct dns_edns_client_subnet *ipv4_ecs,
							   struct dns_edns_client_subnet *ipv6_ecs)
{
	char *slash = NULL;
	int subnet_len = 0;
	struct dns_edns_client_subnet *ecs = NULL;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char str_subnet[128];

	if (subnet == NULL) {
		return -1;
	}

	safe_strncpy(str_subnet, subnet, sizeof(str_subnet));
	slash = strstr(str_subnet, "/");
	if (slash) {
		*slash = 0;
		slash++;
		subnet_len = atoi(slash);
	}

	if (getaddr_by_host(str_subnet, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET:
		if (subnet_len < 0 || subnet_len > 32) {
			return -1;
		}

		if (subnet_len == 0) {
			subnet_len = 32;
		}
		ecs = ipv4_ecs;
		break;
	case AF_INET6:
		if (subnet_len < 0 || subnet_len > 128) {
			return -1;
		}

		if (subnet_len == 0) {
			subnet_len = 128;
		}
		ecs = ipv6_ecs;
		break;
	default:
		goto errout;
	}

	if (ecs == NULL) {
		return 0;
	}

	safe_strncpy(ecs->ip, str_subnet, DNS_MAX_IPLEN);
	ecs->subnet = subnet_len;
	ecs->enable = 1;

	return 0;

errout:
	return -1;
}

static int _conf_edns_client_subnet(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _conf_client_subnet(argv[1], &_config_current_rule_group()->ipv4_ecs,
							   &_config_current_rule_group()->ipv6_ecs);
}

static int _conf_domain_rule_speed_check(char *domain, const char *mode)
{
	struct dns_domain_check_orders *check_orders = NULL;

	check_orders = _new_dns_rule(DOMAIN_RULE_CHECKSPEED);
	if (check_orders == NULL) {
		goto errout;
	}

	if (_config_speed_check_mode_parser(check_orders, mode) != 0) {
		goto errout;
	}

	if (_config_domain_rule_add(domain, DOMAIN_RULE_CHECKSPEED, check_orders) != 0) {
		goto errout;
	}

	_dns_rule_put(&check_orders->head);
	return 0;
errout:
	if (check_orders) {
		_dns_rule_put(&check_orders->head);
	}
	return 0;
}

static int _conf_domain_rule_response_mode(char *domain, const char *mode)
{
	enum response_mode_type response_mode_type = DNS_RESPONSE_MODE_FIRST_PING_IP;
	struct dns_response_mode_rule *response_mode = NULL;

	for (int i = 0; dns_conf_response_mode_enum[i].name != NULL; i++) {
		if (strcmp(mode, dns_conf_response_mode_enum[i].name) == 0) {
			response_mode_type = dns_conf_response_mode_enum[i].id;
			break;
		}
	}

	response_mode = _new_dns_rule(DOMAIN_RULE_RESPONSE_MODE);
	if (response_mode == NULL) {
		goto errout;
	}
	response_mode->mode = response_mode_type;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_RESPONSE_MODE, response_mode) != 0) {
		goto errout;
	}

	_dns_rule_put(&response_mode->head);
	return 0;
errout:
	if (response_mode) {
		_dns_rule_put(&response_mode->head);
	}

	return 0;
}

static int _conf_domain_set(void *data, int argc, char *argv[])
{
	int opt = 0;
	uint32_t key = 0;
	struct dns_domain_set_name *domain_set = NULL;
	struct dns_domain_set_name_list *domain_set_name_list = NULL;
	char set_name[DNS_MAX_CNAME_LEN] = {0};

	/* clang-format off */
	static struct option long_options[] = {
		{"name", required_argument, NULL, 'n'},
		{"type", required_argument, NULL, 't'},
		{"file", required_argument, NULL, 'f'},
		{NULL, 0, NULL, 0}
	};

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	domain_set = malloc(sizeof(*domain_set));
	if (domain_set == NULL) {
		tlog(TLOG_ERROR, "cannot malloc memory.");
		goto errout;
	}
	memset(domain_set, 0, sizeof(*domain_set));
	INIT_LIST_HEAD(&domain_set->list);

	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:t:f:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n':
			safe_strncpy(set_name, optarg, DNS_MAX_CNAME_LEN);
			break;
		case 't': {
			const char *type = optarg;
			if (strncmp(type, "list", 5) == 0) {
				domain_set->type = DNS_DOMAIN_SET_LIST;
			} else if (strncmp(type, "geosite", 7) == 0) {
				domain_set->type = DNS_DOMAIN_SET_GEOSITE;
			} else {
				tlog(TLOG_ERROR, "invalid domain set type.");
				goto errout;
			}
			break;
		}
		case 'f':
			conf_get_conf_fullpath(optarg, domain_set->file, DNS_MAX_PATH);
			break;
		default:
			break;
		}
	}
	/* clang-format on */

	if (set_name[0] == 0 || domain_set->file[0] == 0) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	if (access(domain_set->file, F_OK) != 0) {
		tlog(TLOG_ERROR, "domain set file %s not readable. %s", domain_set->file, strerror(errno));
		goto errout;
	}

	key = hash_string(set_name);
	hash_for_each_possible(dns_domain_set_name_table.names, domain_set_name_list, node, key)
	{
		if (strcmp(domain_set_name_list->name, set_name) == 0) {
			break;
		}
	}

	if (domain_set_name_list == NULL) {
		domain_set_name_list = malloc(sizeof(*domain_set_name_list));
		if (domain_set_name_list == NULL) {
			tlog(TLOG_ERROR, "cannot malloc memory.");
			goto errout;
		}
		memset(domain_set_name_list, 0, sizeof(*domain_set_name_list));
		INIT_LIST_HEAD(&domain_set_name_list->set_name_list);
		safe_strncpy(domain_set_name_list->name, set_name, DNS_MAX_CNAME_LEN);
		hash_add(dns_domain_set_name_table.names, &domain_set_name_list->node, key);
	}

	list_add_tail(&domain_set->list, &domain_set_name_list->set_name_list);
	return 0;

errout:
	if (domain_set) {
		free(domain_set);
	}
	return -1;
}

static int _config_ip_rule_set_each(const char *ip_set, set_rule_add_func callback, void *priv)
{
	struct dns_ip_set_name_list *set_name_list = NULL;
	struct dns_ip_set_name *set_name_item = NULL;

	uint32_t key = 0;

	key = hash_string(ip_set);
	hash_for_each_possible(dns_ip_set_name_table.names, set_name_list, node, key)
	{
		if (strcmp(set_name_list->name, ip_set) == 0) {
			break;
		}
	}

	if (set_name_list == NULL) {
		tlog(TLOG_WARN, "ip set %s not found.", ip_set);
		return -1;
	}

	list_for_each_entry(set_name_item, &set_name_list->set_name_list, list)
	{
		switch (set_name_item->type) {
		case DNS_IP_SET_LIST:
			if (_config_set_rule_each_from_list(set_name_item->file, callback, priv) != 0) {
				return -1;
			}
			break;
		default:
			tlog(TLOG_WARN, "ip set %s type %d not support.", set_name_list->name, set_name_item->type);
			break;
		}
	}

	return 0;
}

static int _config_ip_rules_free(struct dns_ip_rules *ip_rules)
{
	int i = 0;

	if (ip_rules == NULL) {
		return 0;
	}

	for (i = 0; i < IP_RULE_MAX; i++) {
		if (ip_rules->rules[i] == NULL) {
			continue;
		}

		_dns_ip_rule_put(ip_rules->rules[i]);
		ip_rules->rules[i] = NULL;
	}

	free(ip_rules);
	return 0;
}

static int _config_ip_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear);
static int _config_ip_rule_flag_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_flags_callback_args *args = (struct dns_set_rule_flags_callback_args *)priv;
	return _config_ip_rule_flag_set(ip_cidr, args->flags, args->is_clear_flag);
}

static int _config_ip_rule_flag_set(const char *ip_cidr, unsigned int flag, unsigned int is_clear)
{
	struct dns_ip_rules *ip_rules = NULL;
	struct dns_ip_rules *add_ip_rules = NULL;
	struct ip_rule_flags *ip_rule_flags = NULL;
	radix_node_t *node = NULL;

	if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		struct dns_set_rule_flags_callback_args args;
		args.flags = flag;
		args.is_clear_flag = is_clear;
		return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_ip_rule_flag_callback, &args);
	}

	/* Get existing or create domain rule */
	node = _create_addr_node(ip_cidr);
	if (node == NULL) {
		tlog(TLOG_ERROR, "create addr node failed.");
		goto errout;
	}

	ip_rules = node->data;
	if (ip_rules == NULL) {
		add_ip_rules = malloc(sizeof(*add_ip_rules));
		if (add_ip_rules == NULL) {
			goto errout;
		}
		memset(add_ip_rules, 0, sizeof(*add_ip_rules));
		ip_rules = add_ip_rules;
		node->data = ip_rules;
	}

	/* add new rule to domain */
	if (ip_rules->rules[IP_RULE_FLAGS] == NULL) {
		ip_rule_flags = _new_dns_ip_rule(IP_RULE_FLAGS);
		ip_rule_flags->flags = 0;
		ip_rules->rules[IP_RULE_FLAGS] = &ip_rule_flags->head;
	}

	ip_rule_flags = container_of(ip_rules->rules[IP_RULE_FLAGS], struct ip_rule_flags, head);
	if (is_clear == false) {
		ip_rule_flags->flags |= flag;
	} else {
		ip_rule_flags->flags &= ~flag;
	}
	ip_rule_flags->is_flag_set |= flag;

	return 0;
errout:
	if (add_ip_rules) {
		free(add_ip_rules);
	}

	tlog(TLOG_ERROR, "set ip %s flags failed", ip_cidr);

	return 0;
}

static int _config_ip_rule_add(const char *ip_cidr, enum ip_rule type, void *rule);
static int _config_ip_rule_add_callback(const char *ip_cidr, void *priv)
{
	struct dns_set_rule_add_callback_args *args = (struct dns_set_rule_add_callback_args *)priv;
	return _config_ip_rule_add(ip_cidr, args->type, args->rule);
}

static int _config_ip_rule_add(const char *ip_cidr, enum ip_rule type, void *rule)
{
	struct dns_ip_rules *ip_rules = NULL;
	struct dns_ip_rules *add_ip_rules = NULL;
	radix_node_t *node = NULL;

	if (ip_cidr == NULL) {
		goto errout;
	}

	if (type >= IP_RULE_MAX) {
		goto errout;
	}

	if (strncmp(ip_cidr, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		struct dns_set_rule_add_callback_args args;
		args.type = type;
		args.rule = rule;
		return _config_ip_rule_set_each(ip_cidr + sizeof("ip-set:") - 1, _config_ip_rule_add_callback, &args);
	}

	/* Get existing or create domain rule */
	node = _create_addr_node(ip_cidr);
	if (node == NULL) {
		tlog(TLOG_ERROR, "create addr node failed.");
		goto errout;
	}

	ip_rules = node->data;
	if (ip_rules == NULL) {
		add_ip_rules = malloc(sizeof(*add_ip_rules));
		if (add_ip_rules == NULL) {
			goto errout;
		}
		memset(add_ip_rules, 0, sizeof(*add_ip_rules));
		ip_rules = add_ip_rules;
		node->data = ip_rules;
	}

	/* add new rule to domain */
	if (ip_rules->rules[type]) {
		_dns_ip_rule_put(ip_rules->rules[type]);
		ip_rules->rules[type] = NULL;
	}

	ip_rules->rules[type] = rule;
	_dns_ip_rule_get(rule);

	return 0;
errout:
	if (add_ip_rules) {
		free(add_ip_rules);
	}

	tlog(TLOG_ERROR, "add ip %s rule failed", ip_cidr);
	return -1;
}

static int _config_ip_rule_alias_add_ip(const char *ip, struct ip_rule_alias *ip_alias)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	unsigned char *paddr = NULL;
	int ret = 0;

	ret = getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len);
	if (ret != 0) {
		tlog(TLOG_ERROR, "ip is invalid: %s", ip);
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		paddr = (unsigned char *)&(addr_in->sin_addr.s_addr);
		_dns_iplist_ip_address_add(&ip_alias->ip_alias, paddr, DNS_RR_A_LEN);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			paddr = addr_in6->sin6_addr.s6_addr + 12;
			_dns_iplist_ip_address_add(&ip_alias->ip_alias, paddr, DNS_RR_A_LEN);
		} else {
			paddr = addr_in6->sin6_addr.s6_addr;
			_dns_iplist_ip_address_add(&ip_alias->ip_alias, paddr, DNS_RR_AAAA_LEN);
		}
	} break;
	default:
		goto errout;
		break;
	}

	return 0;

errout:
	return -1;
}

static int _config_ip_alias_add_ip_callback(const char *ip_cidr, void *priv)
{
	return _config_ip_rule_alias_add_ip(ip_cidr, (struct ip_rule_alias *)priv);
}

static int _config_ip_alias(const char *ip_cidr, const char *ips)
{
	struct ip_rule_alias *ip_alias = NULL;
	char *target_ips = NULL;
	int ret = 0;

	if (ip_cidr == NULL || ips == NULL) {
		goto errout;
	}

	ip_alias = _new_dns_ip_rule(IP_RULE_ALIAS);
	if (ip_alias == NULL) {
		goto errout;
	}

	if (strncmp(ips, "ip-set:", sizeof("ip-set:") - 1) == 0) {
		if (_config_ip_rule_set_each(ips + sizeof("ip-set:") - 1, _config_ip_alias_add_ip_callback, ip_alias) != 0) {
			goto errout;
		}
	} else {
		target_ips = strdup(ips);
		if (target_ips == NULL) {
			goto errout;
		}

		for (char *tok = strtok(target_ips, ","); tok != NULL; tok = strtok(NULL, ",")) {
			ret = _config_ip_rule_alias_add_ip(tok, ip_alias);
			if (ret != 0) {
				goto errout;
			}
		}
	}

	if (_config_ip_rule_add(ip_cidr, IP_RULE_ALIAS, ip_alias) != 0) {
		goto errout;
	}

	_dns_ip_rule_put(&ip_alias->head);
	if (target_ips) {
		free(target_ips);
	}

	return 0;
errout:

	if (ip_alias) {
		_dns_ip_rule_put(&ip_alias->head);
	}

	if (target_ips) {
		free(target_ips);
	}

	return -1;
}

static int _config_blacklist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_BLACKLIST, 0);
}

static int _conf_bogus_nxdomain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_BOGUS, 0);
}

static int _conf_ip_ignore(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_IP_IGNORE, 0);
}

static int _conf_whitelist_ip(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	return _config_ip_rule_flag_set(argv[1], IP_RULE_FLAG_WHITELIST, 0);
}

static int _conf_ip_alias(void *data, int argc, char *argv[])
{
	if (argc <= 2) {
		return -1;
	}

	return _config_ip_alias(argv[1], argv[2]);
}

static int _conf_ip_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	char *ip_cidr = argv[1];

	/* clang-format off */
	static struct option long_options[] = {
		{"blacklist-ip", no_argument, NULL, 'b'},
		{"whitelist-ip", no_argument, NULL, 'w'},
		{"bogus-nxdomain", no_argument, NULL, 'n'},
		{"ignore-ip", no_argument, NULL, 'i'},
		{"ip-alias", required_argument, NULL, 'a'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
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
		case 'b': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_BLACKLIST, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'w': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_WHITELIST, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'n': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_BOGUS, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'i': {
			if (_config_ip_rule_flag_set(ip_cidr, IP_RULE_FLAG_IP_IGNORE, 0) != 0) {
				goto errout;
			}
			break;
		}
		case 'a': {
			if (_config_ip_alias(ip_cidr, optarg) != 0) {
				goto errout;
			}
			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown ip-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	return 0;
errout:
	return -1;
}

static int _conf_ip_set(void *data, int argc, char *argv[])
{
	int opt = 0;
	uint32_t key = 0;
	struct dns_ip_set_name *ip_set = NULL;
	struct dns_ip_set_name_list *ip_set_name_list = NULL;
	char set_name[DNS_MAX_CNAME_LEN] = {0};

	/* clang-format off */
	static struct option long_options[] = {
		{"name", required_argument, NULL, 'n'},
		{"type", required_argument, NULL, 't'},
		{"file", required_argument, NULL, 'f'},
		{NULL, 0, NULL, 0}
	};

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	ip_set = malloc(sizeof(*ip_set));
	if (ip_set == NULL) {
		tlog(TLOG_ERROR, "cannot malloc memory.");
		goto errout;
	}
	memset(ip_set, 0, sizeof(*ip_set));
	INIT_LIST_HEAD(&ip_set->list);

	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "n:t:f:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'n':
			safe_strncpy(set_name, optarg, DNS_MAX_CNAME_LEN);
			break;
		case 't': {
			const char *type = optarg;
			if (strncmp(type, "list", 5) == 0) {
				ip_set->type = DNS_IP_SET_LIST;
			} else {
				tlog(TLOG_ERROR, "invalid domain set type.");
				goto errout;
			}
			break;
		}
		case 'f':
			conf_get_conf_fullpath(optarg, ip_set->file, DNS_MAX_PATH);
			break;
		default:
			break;
		}
	}
	/* clang-format on */

	if (access(ip_set->file, F_OK) != 0) {
		tlog(TLOG_ERROR, "ip set file %s not readable. %s", ip_set->file, strerror(errno));
		goto errout;
	}

	if (set_name[0] == 0 || ip_set->file[0] == 0) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	key = hash_string(set_name);
	hash_for_each_possible(dns_ip_set_name_table.names, ip_set_name_list, node, key)
	{
		if (strcmp(ip_set_name_list->name, set_name) == 0) {
			break;
		}
	}

	if (ip_set_name_list == NULL) {
		ip_set_name_list = malloc(sizeof(*ip_set_name_list));
		if (ip_set_name_list == NULL) {
			tlog(TLOG_ERROR, "cannot malloc memory.");
			goto errout;
		}
		memset(ip_set_name_list, 0, sizeof(*ip_set_name_list));
		INIT_LIST_HEAD(&ip_set_name_list->set_name_list);
		safe_strncpy(ip_set_name_list->name, set_name, DNS_MAX_CNAME_LEN);
		hash_add(dns_ip_set_name_table.names, &ip_set_name_list->node, key);
	}

	list_add_tail(&ip_set->list, &ip_set_name_list->set_name_list);
	return 0;

errout:
	if (ip_set) {
		free(ip_set);
	}

	if (ip_set_name_list != NULL) {
		free(ip_set_name_list);
	}
	return -1;
}

static void _config_ip_iter_free(radix_node_t *node, void *cbctx)
{
	struct dns_ip_rules *ip_rules = NULL;
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	ip_rules = node->data;
	_config_ip_rules_free(ip_rules);
	node->data = NULL;
}

static void _config_client_rule_iter_free_cb(radix_node_t *node, void *cbctx)
{
	struct dns_client_rules *client_rules = NULL;
	if (node == NULL) {
		return;
	}

	if (node->data == NULL) {
		return;
	}

	client_rules = node->data;
	_config_client_rules_free(client_rules);
	node->data = NULL;
}

static void _config_ip_set_name_table_destroy(void)
{
	struct dns_ip_set_name_list *set_name_list = NULL;
	struct hlist_node *tmp = NULL;
	struct dns_ip_set_name *set_name = NULL;
	struct dns_ip_set_name *tmp1 = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ip_set_name_table.names, i, tmp, set_name_list, node)
	{
		hlist_del_init(&set_name_list->node);
		list_for_each_entry_safe(set_name, tmp1, &set_name_list->set_name_list, list)
		{
			list_del(&set_name->list);
			free(set_name);
		}

		free(set_name_list);
	}
}

static int _conf_ddns_domain(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		return -1;
	}

	const char *domain = argv[1];
	_config_domain_rule_flag_set(domain, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
	return 0;
}

static int _conf_domain_rule_rr_ttl(const char *domain, int ttl, int ttl_min, int ttl_max)
{
	struct dns_ttl_rule *rr_ttl = NULL;

	if (ttl < 0 || ttl_min < 0 || ttl_max < 0) {
		tlog(TLOG_ERROR, "invalid ttl value.");
		goto errout;
	}

	rr_ttl = _new_dns_rule(DOMAIN_RULE_TTL);
	if (rr_ttl == NULL) {
		goto errout;
	}

	rr_ttl->ttl = ttl;
	rr_ttl->ttl_min = ttl_min;
	rr_ttl->ttl_max = ttl_max;

	if (_config_domain_rule_add(domain, DOMAIN_RULE_TTL, rr_ttl) != 0) {
		goto errout;
	}

	_dns_rule_put(&rr_ttl->head);

	return 0;
errout:
	if (rr_ttl != NULL) {
		_dns_rule_put(&rr_ttl->head);
	}

	return -1;
}

static int _conf_domain_rule_no_serve_expired(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_SERVE_EXPIRED, 0);
}

static int _conf_domain_rule_delete(const char *domain)
{
	return _config_domain_rule_delete(domain);
}

static int _conf_domain_rule_no_cache(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_CACHE, 0);
}

static int _conf_domain_rule_enable_cache(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_ENABLE_CACHE, 0);
}

static int _conf_domain_rule_no_ipalias(const char *domain)
{
	return _config_domain_rule_flag_set(domain, DOMAIN_FLAG_NO_IPALIAS, 0);
}

static int _conf_domain_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind = 0;
	int optind_last = 0;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *value = argv[1];
	int rr_ttl = 0;
	int rr_ttl_min = 0;
	int rr_ttl_max = 0;
	const char *group = NULL;
	char group_name[DNS_MAX_CONF_CNAME_LEN];

	/* clang-format off */
	static struct option long_options[] = {
		{"speed-check-mode", required_argument, NULL, 'c'},
		{"response-mode", required_argument, NULL, 'r'},
		{"address", required_argument, NULL, 'a'},
		{"https-record", required_argument, NULL, 'h'},
		{"ipset", required_argument, NULL, 'p'},
		{"nftset", required_argument, NULL, 't'},
		{"nameserver", required_argument, NULL, 'n'},
		{"group", required_argument, NULL, 'g'},
		{"dualstack-ip-selection", required_argument, NULL, 'd'},
		{"cname", required_argument, NULL, 'A'},
		{"rr-ttl", required_argument, NULL, 251},
		{"rr-ttl-min", required_argument, NULL, 252},
		{"rr-ttl-max", required_argument, NULL, 253},
		{"no-serve-expired", no_argument, NULL, 254},
		{"delete", no_argument, NULL, 255},
		{"no-cache", no_argument, NULL, 256},
		{"no-ip-alias", no_argument, NULL, 257},
		{"enable-cache", no_argument, NULL, 258},
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

	/* check domain set exists. */
	if (strncmp(domain, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		const char *set_name = domain + sizeof("domain-set:") - 1;
		struct dns_domain_set_name_list *name = _config_get_domain_set_name_list(set_name);
		if (name == NULL) {
			tlog(TLOG_ERROR, "domain set '%s' not found.", set_name);
			goto errout;
		}
	}

	for (int i = 2; i < argc - 1; i++) {
		if (strncmp(argv[i], "-g", sizeof("-g")) == 0 || strncmp(argv[i], "--group", sizeof("--group")) == 0 ||
			strncmp(argv[i], "-group", sizeof("-group")) == 0) {
			safe_strncpy(group_name, argv[i + 1], DNS_MAX_CONF_CNAME_LEN);
			group = group_name;
			break;
		}
	}

	if (group != NULL) {
		_config_current_group_push(group);
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "c:a:p:t:n:d:A:r:g:h:", long_options, NULL);
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
		case 'r': {
			const char *response_mode = optarg;
			if (response_mode == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_response_mode(domain, response_mode) != 0) {
				tlog(TLOG_ERROR, "add response-mode rule failed.");
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
		case 'h': {
			const char *https_record = optarg;
			if (https_record == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_https_record(domain, https_record) != 0) {
				tlog(TLOG_ERROR, "add https-record rule failed.");
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
		case 'A': {
			const char *cname = optarg;

			if (_conf_domain_rule_cname(domain, cname) != 0) {
				tlog(TLOG_ERROR, "add cname rule failed.");
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
		case 't': {
			const char *nftsetname = optarg;
			if (nftsetname == NULL) {
				goto errout;
			}

			if (_conf_domain_rule_nftset(domain, nftsetname) != 0) {
				tlog(TLOG_ERROR, "add nftset rule failed.");
				goto errout;
			}

			break;
		}
		case 'g': {
			break;
		}
		case 251: {
			rr_ttl = atoi(optarg);
			break;
		}
		case 252: {
			rr_ttl_min = atoi(optarg);
			break;
		}
		case 253: {
			rr_ttl_max = atoi(optarg);
			break;
		}
		case 254: {
			if (_conf_domain_rule_no_serve_expired(domain) != 0) {
				tlog(TLOG_ERROR, "set no-serve-expired rule failed.");
				goto errout;
			}

			break;
		}
		case 255: {
			if (_conf_domain_rule_delete(domain) != 0) {
				tlog(TLOG_ERROR, "delete domain rule failed.");
				goto errout;
			}

			return 0;
		}
		case 256: {
			if (_conf_domain_rule_no_cache(domain) != 0) {
				tlog(TLOG_ERROR, "set no-cache rule failed.");
				goto errout;
			}

			break;
		}
		case 257: {
			if (_conf_domain_rule_no_ipalias(domain) != 0) {
				tlog(TLOG_ERROR, "set no-ipalias rule failed.");
				goto errout;
			}

			break;
		}
		case 258: {
			if (_conf_domain_rule_enable_cache(domain) != 0) {
				tlog(TLOG_ERROR, "set enable-cache rule failed.");
				goto errout;
			}

			break;
		}
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown domain-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	if (rr_ttl > 0 || rr_ttl_min > 0 || rr_ttl_max > 0) {
		if (_conf_domain_rule_rr_ttl(domain, rr_ttl, rr_ttl_min, rr_ttl_max) != 0) {
			tlog(TLOG_ERROR, "set rr-ttl rule failed.");
			goto errout;
		}
	}

	if (group != NULL) {
		_config_current_group_pop();
	}

	return 0;
errout:
	if (group != NULL) {
		_config_current_group_pop();
	}
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
	ptr->is_soa = 1;

	return ptr;
errout:
	if (ptr) {
		free(ptr);
	}

	return NULL;
}

static int _conf_ptr_add(const char *hostname, const char *ip, int is_dynamic)
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

	if (is_dynamic == 1 && ptr->is_soa == 0 && ptr->is_dynamic == 0) {
		/* already set fix PTR, skip */
		return 0;
	}

	ptr->is_dynamic = is_dynamic;
	ptr->is_soa = 0;
	safe_strncpy(ptr->hostname, hostname, DNS_MAX_CNAME_LEN);

	return 0;

errout:
	return -1;
}

static void _config_ptr_table_destroy(int only_dynamic)
{
	struct dns_ptr *ptr = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ptr_table.ptr, i, tmp, ptr, node)
	{
		if (only_dynamic != 0 && ptr->is_dynamic == 0) {
			continue;
		}

		hlist_del_init(&ptr->node);
		free(ptr);
	}
}

static struct dns_hosts *_dns_conf_get_hosts(const char *hostname, int dns_type)
{
	uint32_t key = 0;
	struct dns_hosts *host = NULL;

	key = hash_string_case(hostname);
	key = jhash(&dns_type, sizeof(dns_type), key);
	hash_for_each_possible(dns_hosts_table.hosts, host, node, key)
	{
		if (host->dns_type != dns_type) {
			continue;
		}
		if (strncasecmp(host->domain, hostname, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		return host;
	}

	host = malloc(sizeof(*host));
	if (host == NULL) {
		goto errout;
	}

	safe_strncpy(host->domain, hostname, DNS_MAX_CNAME_LEN);
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

static int _conf_host_add(const char *hostname, const char *ip, dns_hosts_type host_type, int is_dynamic)
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

	if (is_dynamic == 1 && host->is_soa == 0 && host->is_dynamic == 0) {
		/* already set fixed PTR, skip */
		return 0;
	}

	/* add this to return SOA when addr is not exist */
	host_other = _dns_conf_get_hosts(hostname, dns_type_other);
	host->is_dynamic = is_dynamic;
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
		filed_num = sscanf(line, "%*s %*s %63s %255s %*s", ip, hostname);
		if (filed_num <= 0) {
			continue;
		}

		if (strncmp(hostname, "*", DNS_MAX_CNAME_LEN - 1) == 0) {
			continue;
		}

		ret = _conf_host_add(hostname, ip, DNS_HOST_TYPE_DNSMASQ, 1);
		if (ret != 0) {
			tlog(TLOG_WARN, "add host %s/%s at %d failed", hostname, ip, line_no);
		}

		ret = _conf_ptr_add(hostname, ip, 1);
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

static int _config_foreach_file(const char *file_pattern, int (*callback)(const char *file, void *priv), void *priv)
{
	char file_path[DNS_MAX_PATH];
	char file_path_dir[DNS_MAX_PATH];
	glob_t globbuf = {0};

	if (file_pattern == NULL) {
		return -1;
	}

	if (file_pattern[0] != '/') {
		safe_strncpy(file_path_dir, conf_get_conf_file(), DNS_MAX_PATH);
		dir_name(file_path_dir);
		if (strncmp(file_path_dir, conf_get_conf_file(), sizeof(file_path_dir)) == 0) {
			if (snprintf(file_path, DNS_MAX_PATH, "%s", file_pattern) < 0) {
				return -1;
			}
		} else {
			if (snprintf(file_path, DNS_MAX_PATH, "%s/%s", file_path_dir, file_pattern) < 0) {
				return -1;
			}
		}
	} else {
		safe_strncpy(file_path, file_pattern, DNS_MAX_PATH);
	}

	errno = 0;
	if (glob(file_path, 0, NULL, &globbuf) != 0) {
		if (errno == 0) {
			return 0;
		}

		tlog(TLOG_ERROR, "open config file '%s' failed, %s", file_path, strerror(errno));
		return -1;
	}

	for (size_t i = 0; i != globbuf.gl_pathc; ++i) {
		const char *file = globbuf.gl_pathv[i];
		struct stat statbuf;

		if (stat(file, &statbuf) != 0) {
			continue;
		}

		if (!S_ISREG(statbuf.st_mode)) {
			continue;
		}

		if (callback(file, priv) != 0) {
			tlog(TLOG_ERROR, "load config file '%s' failed.", file);
			globfree(&globbuf);
			return -1;
		}
	}

	globfree(&globbuf);

	return 0;
}

static int _conf_hosts_file_add(const char *file, void *priv)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char ip[DNS_MAX_IPLEN];
	char hostname[DNS_MAX_CNAME_LEN];
	int ret = 0;
	int line_no = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_WARN, "open file %s error, %s", file, strerror(errno));
		return -1;
	}

	line_no = 0;
	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_no++;
		int is_ptr_add = 0;

		char *token = strtok(line, " \t\n");
		if (token == NULL) {
			continue;
		}

		safe_strncpy(ip, token, sizeof(ip) - 1);
		if (ip[0] == '#') {
			continue;
		}

		while ((token = strtok(NULL, " \t\n")) != NULL) {
			safe_strncpy(hostname, token, sizeof(hostname) - 1);
			char *skip_hostnames[] = {
				"*",
			};

			int skip = 0;
			for (size_t i = 0; i < sizeof(skip_hostnames) / sizeof(skip_hostnames[0]); i++) {
				if (strncmp(hostname, skip_hostnames[i], DNS_MAX_CNAME_LEN - 1) == 0) {
					skip = 1;
					break;
				}
			}

			if (skip == 1) {
				continue;
			}

			ret = _conf_host_add(hostname, ip, DNS_HOST_TYPE_HOST, 0);
			if (ret != 0) {
				tlog(TLOG_WARN, "add hosts-file failed at '%s:%d'.", file, line_no);
				continue;
			}

			if (is_ptr_add == 1) {
				continue;
			}

			ret = _conf_ptr_add(hostname, ip, 0);
			if (ret != 0) {
				tlog(TLOG_WARN, "add hosts-file failed at '%s:%d'.", file, line_no);
				continue;
			}

			is_ptr_add = 1;
		}
	}

	fclose(fp);

	return 0;
}

static int _conf_hosts_file(void *data, int argc, char *argv[])
{
	const char *file_pattern = NULL;
	if (argc < 1) {
		return -1;
	}

	file_pattern = argv[1];
	if (file_pattern == NULL) {
		return -1;
	}

	return _config_foreach_file(file_pattern, _conf_hosts_file_add, NULL);
}

static void _config_host_table_destroy(int only_dynamic)
{
	struct dns_hosts *host = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_hosts_table.hosts, i, tmp, host, node)
	{
		if (only_dynamic != 0 && host->is_dynamic == 0) {
			continue;
		}

		hlist_del_init(&host->node);
		free(host);
	}

	dns_hosts_record_num = 0;
}

static int _config_client_rule_group_add(const char *client, const char *group_name)
{
	struct client_rule_group *client_rule = NULL;
	const char *group = NULL;

	client_rule = _new_dns_client_rule(CLIENT_RULE_GROUP);
	if (client_rule == NULL) {
		goto errout;
	}

	group = _dns_conf_get_group_name(group_name);
	if (group == NULL) {
		goto errout;
	}

	client_rule->group_name = group;
	if (_config_client_rule_add(client, CLIENT_RULE_GROUP, client_rule) != 0) {
		goto errout;
	}

	_dns_client_rule_put(&client_rule->head);

	return 0;
errout:
	if (client_rule != NULL) {
		_dns_client_rule_put(&client_rule->head);
	}
	return -1;
}

static int _config_client_rules(void *data, int argc, char *argv[])
{
	int opt = 0;
	int optind_last = 0;
	const char *client = argv[1];
	unsigned int server_flag = 0;
	const char *group = NULL;

	/* clang-format off */
	static struct option long_options[] = {
		{"group", required_argument, NULL, 'g'},
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
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	if (argc <= 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	/* get current group */
	if (_config_current_group()) {
		group = _config_current_group()->group_name;
	}

	/* process extra options */
	optind = 1;
	optind_last = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "g:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'g': {
			group = optarg;
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
		default:
			if (optind > optind_last) {
				tlog(TLOG_WARN, "unknown client-rules option: %s at '%s:%d'.", argv[optind - 1], conf_get_conf_file(),
					 conf_get_current_lineno());
			}
			break;
		}

		optind_last = optind;
	}

	if (group != NULL) {
		if (_config_client_rule_group_add(client, group) != 0) {
			tlog(TLOG_ERROR, "add group rule failed.");
			goto errout;
		}
	}

	if (_config_client_rule_flag_set(client, server_flag, 0) != 0) {
		tlog(TLOG_ERROR, "set client rule flags failed.");
		goto errout;
	}

	return 0;
errout:
	return -1;
}

static struct dns_conf_plugin *_config_get_plugin(const char *file)
{
	uint32_t key = 0;
	struct dns_conf_plugin *plugin = NULL;

	key = hash_string(file);
	hash_for_each_possible(dns_conf_plugin_table.plugins, plugin, node, key)
	{
		if (strncmp(plugin->file, file, DNS_MAX_PATH) != 0) {
			continue;
		}

		return plugin;
	}

	return NULL;
}

static int _config_plugin(void *data, int argc, char *argv[])
{
#ifdef BUILD_STATIC
	tlog(TLOG_ERROR, "plugin not support in static release, please install dynamic release.");
	goto errout;
#endif
	char file[DNS_MAX_PATH];
	unsigned int key = 0;
	int i = 0;
	char *ptr = NULL;
	char *ptr_end = NULL;

	if (argc < 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	conf_get_conf_fullpath(argv[1], file, sizeof(file));
	if (file[0] == '\0') {
		tlog(TLOG_ERROR, "plugin: invalid parameter.");
		goto errout;
	}

	struct dns_conf_plugin *plugin = _config_get_plugin(file);
	if (plugin != NULL) {
		tlog(TLOG_ERROR, "plugin '%s' already exists.", file);
		goto errout;
	}

	if (access(file, F_OK) != 0) {
		tlog(TLOG_ERROR, "plugin '%s' not exists.", file);
		goto errout;
	}

	plugin = malloc(sizeof(*plugin));
	if (plugin == NULL) {
		goto errout;
	}
	memset(plugin, 0, sizeof(*plugin));
	safe_strncpy(plugin->file, file, sizeof(plugin->file) - 1);
	ptr = plugin->args;
	ptr_end = plugin->args + sizeof(plugin->args) - 2;
	for (i = 1; i < argc && ptr < ptr_end; i++) {
		safe_strncpy(ptr, argv[i], ptr_end - ptr - 1);
		ptr += strlen(argv[i]) + 1;
	}
	plugin->argc = argc - 1;
	plugin->args_len = ptr - plugin->args;

	key = hash_string(file);
	hash_add(dns_conf_plugin_table.plugins, &plugin->node, key);

	return 0;
errout:
	return -1;
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

	_config_ptr_table_destroy(1);
	_config_host_table_destroy(1);

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

	if (strncasecmp("debug", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_DEBUG;
	} else if (strncasecmp("info", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_INFO;
	} else if (strncasecmp("notice", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_NOTICE;
	} else if (strncasecmp("warn", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_WARN;
	} else if (strncasecmp("error", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_ERROR;
	} else if (strncasecmp("fatal", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_FATAL;
	} else if (strncasecmp("off", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_OFF;
	} else {
		return -1;
	}

	return 0;
}

static void _config_setup_smartdns_domain(void)
{
	char hostname[DNS_MAX_CNAME_LEN];
	char domainname[DNS_MAX_CNAME_LEN];

	hostname[0] = '\0';
	domainname[0] = '\0';

	/* get local domain name */
	if (getdomainname(domainname, DNS_MAX_CNAME_LEN - 1) == 0) {
		/* check domain is valid */
		if (strncmp(domainname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
			domainname[0] = '\0';
		}
	}

	if (gethostname(hostname, DNS_MAX_CNAME_LEN - 1) == 0) {
		/* check hostname is valid */
		if (strncmp(hostname, "(none)", DNS_MAX_CNAME_LEN - 1) == 0) {
			hostname[0] = '\0';
		}
	}

	if (dns_conf_resolv_hostname == 1) {
		/* add hostname to rule table */
		if (hostname[0] != '\0') {
			_config_domain_rule_flag_set(hostname, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
		}

		/* add domainname to rule table */
		if (domainname[0] != '\0') {
			char full_domain[DNS_MAX_CNAME_LEN];
			snprintf(full_domain, DNS_MAX_CNAME_LEN, "%.64s.%.128s", hostname, domainname);
			_config_domain_rule_flag_set(full_domain, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
		}
	}

	/* add server name to rule table */
	if (dns_conf_server_name[0] != '\0' &&
		strncmp(dns_conf_server_name, "smartdns", DNS_MAX_SERVER_NAME_LEN - 1) != 0) {
		_config_domain_rule_flag_set(dns_conf_server_name, DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
	}

	_config_domain_rule_flag_set("smartdns", DOMAIN_FLAG_SMARTDNS_DOMAIN, 0);
}

static int _dns_conf_setup_mdns(void)
{
	if (dns_conf_mdns_lookup != 1) {
		return 0;
	}

	return _conf_domain_rule_nameserver(DNS_SERVER_GROUP_LOCAL, DNS_SERVER_GROUP_MDNS);
}

static struct config_item _config_item[] = {
	CONF_STRING("server-name", (char *)dns_conf_server_name, DNS_MAX_SERVER_NAME_LEN),
	CONF_YESNO("resolv-hostname", &dns_conf_resolv_hostname),
	CONF_CUSTOM("bind", _config_bind_ip_udp, NULL),
	CONF_CUSTOM("bind-tcp", _config_bind_ip_tcp, NULL),
	CONF_CUSTOM("bind-tls", _config_bind_ip_tls, NULL),
	CONF_CUSTOM("bind-https", _config_bind_ip_https, NULL),
	CONF_CUSTOM("bind-cert-file", _config_option_parser_filepath, &dns_conf_bind_ca_file),
	CONF_CUSTOM("bind-cert-key-file", _config_option_parser_filepath, &dns_conf_bind_ca_key_file),
	CONF_STRING("bind-cert-key-pass", dns_conf_bind_ca_key_pass, DNS_MAX_PATH),
	CONF_CUSTOM("server", _config_server_udp, NULL),
	CONF_CUSTOM("server-tcp", _config_server_tcp, NULL),
	CONF_CUSTOM("server-tls", _config_server_tls, NULL),
	CONF_CUSTOM("server-https", _config_server_https, NULL),
	CONF_YESNO("mdns-lookup", &dns_conf_mdns_lookup),
	CONF_YESNO("local-ptr-enable", &dns_conf_local_ptr_enable),
	CONF_CUSTOM("nameserver", _config_nameserver, NULL),
	CONF_YESNO("expand-ptr-from-address", &dns_conf_expand_ptr_from_address),
	CONF_CUSTOM("address", _config_address, NULL),
	CONF_CUSTOM("cname", _config_cname, NULL),
	CONF_CUSTOM("srv-record", _config_srv_record, NULL),
	CONF_CUSTOM("https-record", _config_https_record, NULL),
	CONF_CUSTOM("proxy-server", _config_proxy_server, NULL),
	CONF_YESNO_FUNC("ipset-timeout", _dns_conf_group_yesno, group_member(ipset_nftset.ipset_timeout_enable)),
	CONF_CUSTOM("ipset", _config_ipset, NULL),
	CONF_CUSTOM("ipset-no-speed", _config_ipset_no_speed, NULL),
	CONF_YESNO_FUNC("nftset-timeout", _dns_conf_group_yesno, group_member(ipset_nftset.nftset_timeout_enable)),
	CONF_YESNO("nftset-debug", &dns_conf_nftset_debug_enable),
	CONF_CUSTOM("nftset", _config_nftset, NULL),
	CONF_CUSTOM("nftset-no-speed", _config_nftset_no_speed, NULL),
	CONF_CUSTOM("speed-check-mode", _config_speed_check_mode, NULL),
	CONF_INT("tcp-idle-time", &dns_conf_tcp_idle_time, 0, 3600),
	CONF_SSIZE("cache-size", &dns_conf_cachesize, -1, CONF_INT_MAX),
	CONF_SSIZE("cache-mem-size", &dns_conf_cache_max_memsize, 0, CONF_INT_MAX),
	CONF_CUSTOM("cache-file", _config_option_parser_filepath, (char *)&dns_conf_cache_file),
	CONF_YESNO("cache-persist", &dns_conf_cache_persist),
	CONF_INT("cache-checkpoint-time", &dns_conf_cache_checkpoint_time, 0, 3600 * 24 * 7),
	CONF_YESNO_FUNC("prefetch-domain", _dns_conf_group_yesno, group_member(dns_prefetch)),
	CONF_YESNO_FUNC("serve-expired", _dns_conf_group_yesno, group_member(dns_serve_expired)),
	CONF_INT_FUNC("serve-expired-ttl", _dns_conf_group_int, group_member(dns_serve_expired_ttl), 0, CONF_INT_MAX),
	CONF_INT_FUNC("serve-expired-reply-ttl", _dns_conf_group_int, group_member(dns_serve_expired_reply_ttl), 0,
				  CONF_INT_MAX),
	CONF_INT_FUNC("serve-expired-prefetch-time", _dns_conf_group_int, group_member(dns_serve_expired_prefetch_time), 0,
				  CONF_INT_MAX),
	CONF_YESNO_FUNC("dualstack-ip-selection", _dns_conf_group_yesno, group_member(dualstack_ip_selection)),
	CONF_YESNO_FUNC("dualstack-ip-allow-force-AAAA", _dns_conf_group_yesno,
					group_member(dns_dualstack_ip_allow_force_AAAA)),
	CONF_INT_FUNC("dualstack-ip-selection-threshold", _dns_conf_group_int,
				  group_member(dns_dualstack_ip_selection_threshold), 0, 1000),
	CONF_CUSTOM("dns64", _config_dns64, NULL),
	CONF_CUSTOM("log-level", _config_log_level, NULL),
	CONF_CUSTOM("log-file", _config_option_parser_filepath, (char *)dns_conf_log_file),
	CONF_SIZE("log-size", &dns_conf_log_size, 0, 1024 * 1024 * 1024),
	CONF_INT("log-num", &dns_conf_log_num, 0, 1024),
	CONF_YESNO("log-console", &dns_conf_log_console),
	CONF_YESNO("log-syslog", &dns_conf_log_syslog),
	CONF_INT_BASE("log-file-mode", &dns_conf_log_file_mode, 0, 511, 8),
	CONF_YESNO("audit-enable", &dns_conf_audit_enable),
	CONF_YESNO("audit-SOA", &dns_conf_audit_log_SOA),
	CONF_CUSTOM("audit-file", _config_option_parser_filepath, (char *)&dns_conf_audit_file),
	CONF_INT_BASE("audit-file-mode", &dns_conf_audit_file_mode, 0, 511, 8),
	CONF_SIZE("audit-size", &dns_conf_audit_size, 0, 1024 * 1024 * 1024),
	CONF_INT("audit-num", &dns_conf_audit_num, 0, 1024),
	CONF_YESNO("audit-console", &dns_conf_audit_console),
	CONF_YESNO("audit-syslog", &dns_conf_audit_syslog),
	CONF_YESNO("acl-enable", &dns_conf_acl_enable),
	CONF_INT_FUNC("rr-ttl", _dns_conf_group_int, group_member(dns_rr_ttl), 0, CONF_INT_MAX),
	CONF_INT_FUNC("rr-ttl-min", _dns_conf_group_int, group_member(dns_rr_ttl_min), 0, CONF_INT_MAX),
	CONF_INT_FUNC("rr-ttl-max", _dns_conf_group_int, group_member(dns_rr_ttl_max), 0, CONF_INT_MAX),
	CONF_INT_FUNC("rr-ttl-reply-max", _dns_conf_group_int, group_member(dns_rr_ttl_reply_max), 0, CONF_INT_MAX),
	CONF_INT_FUNC("local-ttl", _dns_conf_group_int, group_member(dns_local_ttl), 0, CONF_INT_MAX),
	CONF_INT_FUNC("max-reply-ip-num", _dns_conf_group_int, group_member(dns_max_reply_ip_num), 1, CONF_INT_MAX),
	CONF_INT("max-query-limit", &dns_conf_max_query_limit, 0, CONF_INT_MAX),
	CONF_ENUM_FUNC("response-mode", _dns_conf_group_enum, group_member(dns_response_mode),
				   &dns_conf_response_mode_enum),
	CONF_YESNO_FUNC("force-AAAA-SOA", _dns_conf_group_yesno, group_member(force_AAAA_SOA)),
	CONF_YESNO_FUNC("force-no-CNAME", _dns_conf_group_yesno, group_member(dns_force_no_cname)),
	CONF_CUSTOM("force-qtype-SOA", _config_qtype_soa, NULL),
	CONF_CUSTOM("blacklist-ip", _config_blacklist_ip, NULL),
	CONF_CUSTOM("whitelist-ip", _conf_whitelist_ip, NULL),
	CONF_CUSTOM("ip-alias", _conf_ip_alias, NULL),
	CONF_CUSTOM("ip-rules", _conf_ip_rules, NULL),
	CONF_CUSTOM("ip-set", _conf_ip_set, NULL),
	CONF_CUSTOM("bogus-nxdomain", _conf_bogus_nxdomain, NULL),
	CONF_CUSTOM("ignore-ip", _conf_ip_ignore, NULL),
	CONF_CUSTOM("edns-client-subnet", _conf_edns_client_subnet, NULL),
	CONF_CUSTOM("domain-rules", _conf_domain_rules, NULL),
	CONF_CUSTOM("domain-set", _conf_domain_set, NULL),
	CONF_CUSTOM("ddns-domain", _conf_ddns_domain, NULL),
	CONF_CUSTOM("dnsmasq-lease-file", _conf_dhcp_lease_dnsmasq_file, NULL),
	CONF_CUSTOM("hosts-file", _conf_hosts_file, NULL),
	CONF_CUSTOM("group-begin", _config_group_begin, NULL),
	CONF_CUSTOM("group-end", _config_group_end, NULL),
	CONF_CUSTOM("group-match", _config_group_match, NULL),
	CONF_CUSTOM("client-rules", _config_client_rules, NULL),
	CONF_STRING("ca-file", (char *)&dns_conf_ca_file, DNS_MAX_PATH),
	CONF_STRING("ca-path", (char *)&dns_conf_ca_path, DNS_MAX_PATH),
	CONF_STRING("user", (char *)&dns_conf_user, sizeof(dns_conf_user)),
	CONF_YESNO("debug-save-fail-packet", &dns_save_fail_packet),
	CONF_YESNO("no-pidfile", &dns_no_pidfile),
	CONF_YESNO("no-daemon", &dns_no_daemon),
	CONF_YESNO("restart-on-crash", &dns_restart_on_crash),
	CONF_SIZE("socket-buff-size", &dns_socket_buff_size, 0, 1024 * 1024 * 8),
	CONF_CUSTOM("plugin", _config_plugin, NULL),
	CONF_STRING("resolv-file", (char *)&dns_resolv_file, sizeof(dns_resolv_file)),
	CONF_STRING("debug-save-fail-packet-dir", (char *)&dns_save_fail_packet_dir, sizeof(dns_save_fail_packet_dir)),
	CONF_CUSTOM("conf-file", config_additional_file, NULL),
	CONF_END(),
};

static int _conf_printf(const char *file, int lineno, int ret)
{
	switch (ret) {
	case CONF_RET_ERR:
	case CONF_RET_WARN:
	case CONF_RET_BADCONF:
		tlog(TLOG_WARN, "process config failed at '%s:%d'.", file, lineno);
		return -1;
		break;
	case CONF_RET_NOENT:
		tlog(TLOG_WARN, "unsupported config at '%s:%d'.", file, lineno);
		return -1;
		break;
	default:
		break;
	}

	return 0;
}

static int conf_file_check_duplicate(const char *conf_file)
{
	struct conf_file_path *file = NULL;
	uint32_t key = 0;

	key = hash_string(conf_file);
	hash_table_for_each_possible(conf_file_table, file, node, key)
	{
		if (strncmp(file->file, conf_file, DNS_MAX_PATH) != 0) {
			continue;
		}

		return 0;
	}

	file = malloc(sizeof(*file));
	if (file == NULL) {
		return -1;
	}

	safe_strncpy(file->file, conf_file, DNS_MAX_PATH);
	hash_table_add(conf_file_table, &file->node, key);
	return -1;
}

static int conf_additional_file(const char *conf_file)
{
	char file_path[DNS_MAX_PATH];
	char file_path_dir[DNS_MAX_PATH];

	if (conf_file == NULL) {
		return -1;
	}

	if (conf_file[0] != '/') {
		safe_strncpy(file_path_dir, conf_get_conf_file(), DNS_MAX_PATH);
		dir_name(file_path_dir);
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
		tlog(TLOG_ERROR, "config file '%s' is not readable, %s", conf_file, strerror(errno));
		return -1;
	}

	if (conf_file_check_duplicate(file_path) == 0) {
		return 0;
	}

	return load_conf(file_path, _config_item, _conf_printf);
}

static int _config_additional_file_callback(const char *file, void *priv)
{
	return conf_additional_file(file);
}

int config_additional_file(void *data, int argc, char *argv[])
{
	const char *conf_pattern = NULL;
	int opt = 0;
	const char *group_name = NULL;
	int ret = 0;
	struct dns_conf_group_info *last_group_info;

	if (argc < 1) {
		return -1;
	}

	conf_pattern = argv[1];
	if (conf_pattern == NULL) {
		return -1;
	}

	/* clang-format off */
	static struct option long_options[] = {
		{"group", required_argument, NULL, 'g'},
		{NULL, no_argument, NULL, 0}
	};
	/* clang-format on */

	/* process extra options */
	optind = 1;
	while (1) {
		opt = getopt_long_only(argc, argv, "g:", long_options, NULL);
		if (opt == -1) {
			break;
		}

		switch (opt) {
		case 'g': {
			group_name = optarg;
			break;
		}
		}
	}

	last_group_info = _config_current_group();
	if (group_name != NULL) {
		ret = _config_current_group_push(group_name);
		if (ret != 0) {
			tlog(TLOG_ERROR, "begin group '%s' failed.", group_name);
			return -1;
		}
	}

	ret = _config_foreach_file(conf_pattern, _config_additional_file_callback, NULL);
	if (group_name != NULL) {
		_config_current_group_pop_to(last_group_info);
	}

	return ret;
}

const char *dns_conf_get_cache_dir(void)
{
	if (dns_conf_cache_file[0] == '\0') {
		return SMARTDNS_CACHE_FILE;
	}

	return dns_conf_cache_file;
}

static int _dns_server_load_conf_init(void)
{
	dns_conf_client_rule.rule = New_Radix();
	if (dns_conf_client_rule.rule == NULL) {
		tlog(TLOG_WARN, "init client rule radix tree failed.");
		return -1;
	}
	hash_init(dns_conf_client_rule.mac);
	hash_init(dns_conf_rule.group);
	dns_conf_rule.default_conf = _config_rule_group_new("");
	if (dns_conf_rule.default_conf == NULL) {
		tlog(TLOG_WARN, "init default domain rule failed.");
		return -1;
	}

	hash_init(dns_ipset_table.ipset);
	hash_init(dns_nftset_table.nftset);
	hash_init(dns_group_table.group);
	hash_init(dns_hosts_table.hosts);
	hash_init(dns_ptr_table.ptr);
	hash_init(dns_domain_set_name_table.names);
	hash_init(dns_ip_set_name_table.names);
	hash_init(dns_conf_srv_record_table.srv);
	hash_init(dns_conf_plugin_table.plugins);

	if (_config_current_group_push_default() != 0) {
		tlog(TLOG_ERROR, "init default group failed.");
		return -1;
	}

	return 0;
}

static void dns_server_bind_destroy(void)
{
	for (int i = 0; i < dns_conf_bind_ip_num; i++) {
		struct dns_bind_ip *bind_ip = &dns_conf_bind_ip[i];

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
	memset(dns_conf_bind_ip, 0, sizeof(dns_conf_bind_ip));
	dns_conf_bind_ip_num = 0;
}

static void _config_client_rule_destroy_mac(void)
{
	struct hlist_node *tmp = NULL;
	unsigned int i;
	struct client_roue_group_mac *group_mac = NULL;

	hash_for_each_safe(dns_conf_client_rule.mac, i, tmp, group_mac, node)
	{
		hlist_del_init(&group_mac->node);
		_config_client_rules_free(group_mac->rules);
		free(group_mac);
	}
}

static void _config_client_rule_destroy(void)
{
	Destroy_Radix(dns_conf_client_rule.rule, _config_client_rule_iter_free_cb, NULL);
	_config_client_rule_destroy_mac();
}

static void _config_plugin_table_destroy(void)
{
	struct dns_conf_plugin *plugin = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_plugin_table.plugins, i, tmp, plugin, node)
	{
		hlist_del_init(&plugin->node);
		free(plugin);
	}
}

void dns_server_load_exit(void)
{
	_config_rule_group_destroy();
	_config_client_rule_destroy();
	_config_ipset_table_destroy();
	_config_nftset_table_destroy();
	_config_group_table_destroy();
	_config_ptr_table_destroy(0);
	_config_host_table_destroy(0);
	_config_proxy_table_destroy();
	_config_srv_record_table_destroy();
	_config_plugin_table_destroy();

	dns_conf_server_num = 0;
	dns_server_bind_destroy();

	if (dns_conf_log_syslog == 1 || dns_conf_audit_syslog == 1) {
		closelog();
	}
}

static int _config_add_default_server_if_needed(void)
{
	if (dns_conf_bind_ip_num > 0) {
		return 0;
	}

	/* add default server */
	char *argv[] = {"bind", "[::]:53", NULL};
	int argc = sizeof(argv) / sizeof(char *) - 1;
	return _config_bind_ip(argc, argv, DNS_BIND_TYPE_UDP);
}

static int _dns_conf_speed_check_mode_verify(void)
{
	struct dns_conf_group *group;
	struct hlist_node *tmp = NULL;
	unsigned long k = 0;
	int i = 0;
	int j = 0;
	int print_log = 0;

	hash_for_each_safe(dns_conf_rule.group, k, tmp, group, node)
	{
		struct dns_domain_check_orders *check_orders = &group->check_orders;
		for (i = 0; i < DOMAIN_CHECK_NUM; i++) {
			if (check_orders->orders[i].type == DOMAIN_CHECK_ICMP) {
				if (dns_has_cap_ping == 0) {
					for (j = i + 1; j < DOMAIN_CHECK_NUM; j++) {
						check_orders->orders[j - 1].type = check_orders->orders[j].type;
						check_orders->orders[j - 1].tcp_port = check_orders->orders[j].tcp_port;
					}
					check_orders->orders[j - 1].type = DOMAIN_CHECK_NONE;
					check_orders->orders[j - 1].tcp_port = 0;
					print_log = 1;
				}
				dns_conf_has_icmp_check = 1;
			}

			if (check_orders->orders[i].type == DOMAIN_CHECK_TCP) {
				dns_conf_has_tcp_check = 1;
			}
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
			tlog(TLOG_WARN, "unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range");
		}
	}

	if (has_ping == 1 || has_raw_cap == 1) {
		dns_has_cap_ping = 1;
	}

	return 0;
}

static void _config_file_hash_table_destroy(void)
{
	struct conf_file_path *file = NULL;
	struct hlist_node *tmp = NULL;
	int i = 0;

	hash_table_for_each_safe(conf_file_table, i, tmp, file, node)
	{
		hlist_del_init(&file->node);
		free(file);
	}

	hash_table_free(conf_file_table, free);
}

static int _dns_conf_load_pre(void)
{
	if (_dns_server_load_conf_init() != 0) {
		goto errout;
	}

	_dns_ping_cap_check();

	safe_strncpy(dns_save_fail_packet_dir, SMARTDNS_DEBUG_DIR, sizeof(dns_save_fail_packet_dir));

	hash_table_init(conf_file_table, 8, malloc);

	return 0;

errout:
	return -1;
}

static void _dns_conf_auto_set_cache_size(void)
{
	uint64_t memsize = get_system_mem_size();
	if (dns_conf_cachesize >= 0) {
		return;
	}

	if (memsize <= 16 * 1024 * 1024) {
		dns_conf_cachesize = 2048; /* 1MB memory */
	} else if (memsize <= 32 * 1024 * 1024) {
		dns_conf_cachesize = 8192; /* 4MB memory*/
	} else if (memsize <= 64 * 1024 * 1024) {
		dns_conf_cachesize = 16384; /* 8MB memory*/
	} else if (memsize <= 128 * 1024 * 1024) {
		dns_conf_cachesize = 32768; /* 16MB memory*/
	} else if (memsize <= 256 * 1024 * 1024) {
		dns_conf_cachesize = 65536; /* 32MB memory*/
	} else if (memsize <= 512 * 1024 * 1024) {
		dns_conf_cachesize = 131072; /* 64MB memory*/
	} else {
		dns_conf_cachesize = 262144; /* 128MB memory*/
	}
}

static void _dns_conf_group_post(void)
{
	struct dns_conf_group *group;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_rule.group, i, tmp, group, node)
	{
		if (dns_conf_cachesize == 0 && group->dns_response_mode == DNS_RESPONSE_MODE_FASTEST_RESPONSE) {
			group->dns_response_mode = DNS_RESPONSE_MODE_FASTEST_IP;
			tlog(TLOG_WARN, "force set response of group %s to %s as cache size is 0", group->group_name,
				 dns_conf_response_mode_enum[group->dns_response_mode].name);
		}

		if ((group->dns_rr_ttl_min > group->dns_rr_ttl_max) && group->dns_rr_ttl_max > 0) {
			group->dns_rr_ttl_min = group->dns_rr_ttl_max;
		}

		if ((group->dns_rr_ttl_max < group->dns_rr_ttl_min) && group->dns_rr_ttl_max > 0) {
			group->dns_rr_ttl_max = group->dns_rr_ttl_min;
		}

		if (group->dns_serve_expired == 1 && group->dns_serve_expired_ttl == 0) {
			group->dns_serve_expired_ttl = DNS_MAX_SERVE_EXPIRED_TIME;
		}
	}
}

static int _dns_conf_load_post(void)
{
	_config_setup_smartdns_domain();
	_dns_conf_speed_check_mode_verify();

	_dns_conf_auto_set_cache_size();

	_dns_conf_setup_mdns();

	if (dns_resolv_file[0] == '\0') {
		safe_strncpy(dns_resolv_file, DNS_RESOLV_FILE, sizeof(dns_resolv_file));
	}

	_dns_conf_group_post();

	_config_domain_set_name_table_destroy();

	_config_ip_set_name_table_destroy();

	_config_update_bootstrap_dns_rule();

	_config_add_default_server_if_needed();

	_config_file_hash_table_destroy();

	_config_current_group_pop_all();

	if (dns_conf_log_syslog == 0 && dns_conf_audit_syslog == 0) {
		closelog();
	}

	return 0;
}

int dns_server_load_conf(const char *file)
{
	int ret = 0;
	ret = _dns_conf_load_pre();
	if (ret != 0) {
		return ret;
	}

	openlog("smartdns", LOG_CONS, LOG_USER);
	ret = load_conf(file, _config_item, _conf_printf);
	if (ret != 0) {
		closelog();
		return ret;
	}

	ret = _dns_conf_load_post();
	return ret;
}
