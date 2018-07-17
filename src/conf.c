#include "conf.h"
#include "tlog.h"
#include "list.h"
#include "rbtree.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LINE_LEN 1024
#define MAX_KEY_LEN 64

#define DEFAULT_DNS_CACHE_SIZE 512

char dns_conf_server_ip[DNS_MAX_IPLEN];
int dns_conf_cachesize = DEFAULT_DNS_CACHE_SIZE;
struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
char dns_conf_server_name[DNS_MAX_CONF_CNAME_LEN];
int dns_conf_server_num;
int dns_conf_log_level = TLOG_ERROR;
char dns_conf_log_file[DNS_MAX_PATH];
int dns_conf_log_size = 1024 * 1024;
int dns_conf_log_num = 8;

art_tree dns_conf_address;
int dns_conf_rr_ttl;
int dns_conf_rr_ttl_min;
int dns_conf_rr_ttl_max;

int config_bind(char *value)
{
	/* server bind address */
	strncpy(dns_conf_server_ip, value, DNS_MAX_IPLEN);

	return 0;
}

int config_server_name(char *value)
{
	strncpy(dns_conf_server_name, value, DNS_MAX_CNAME_LEN);
	return 0;
}

int config_server(char *value, dns_server_type_t type)
{
	int index = dns_conf_server_num;
	struct dns_servers *server;
	int port = -1;

	if (index >= DNS_MAX_SERVERS) {
		tlog(TLOG_ERROR, "exceeds max server number");
		return -1;
	}

	server = &dns_conf_servers[index];
	/* parse ip, port from value */
	if (parse_ip(value, server->server, &port) != 0) {
		return -1;
	}

	/* if port is not defined, set port to default 53 */
	if (port == PORT_NOT_DEFINED) {
		port = DEFAULT_DNS_PORT;
	}

	server->type = type;
	server->port = port;
	dns_conf_server_num++;

	return 0;
}

int config_address_iter_cb(void *data, const unsigned char *key, uint32_t key_len, void *value)
{
	free(value);
	return 0;
}

void config_address_destroy(void)
{
	art_iter(&dns_conf_address, config_address_iter_cb, 0);
	art_tree_destroy(&dns_conf_address);
}

int config_address(char *value)
{
	struct dns_address *address = NULL;
	struct dns_address *oldaddress;
	char ip[MAX_IP_LEN];
	char domain_key[DNS_MAX_CONF_CNAME_LEN];
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char *begin = NULL;
	char *end = NULL;
	int len = 0;
	int port;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	char type = '4';

	begin = strstr(value, "/");
	if (begin == NULL) {
		goto errout;
	}

	begin++;
	end = strstr(begin, "/");
	if (end == NULL) {
		goto errout;
	}

	address = malloc(sizeof(*address));
	if (address == NULL) {
		goto errout;
	}

	memset(address, 0, sizeof(*address));
	len = end - begin;
	memcpy(domain, begin, len);
	domain[len] = 0;
	reverse_string(domain_key + 1, domain, len);

	if (parse_ip(end + 1, ip, &port) != 0) {
		goto errout;
	}

	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in;
		addr_in = (struct sockaddr_in *)&addr;
		memcpy(address->ipv4_addr, &addr_in->sin_addr.s_addr, 4);
		address->addr_type = DNS_T_A;
		type = '4';
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			memcpy(address->ipv4_addr, addr_in6->sin6_addr.s6_addr + 12, 4);
			address->addr_type = DNS_T_A;
			type = '4';
		} else {
			memcpy(address->ipv6_addr, addr_in6->sin6_addr.s6_addr, 16);
			address->addr_type = DNS_T_AAAA;
			type = '6';
		}
	} break;
	default:
		goto errout;
	}

	domain_key[0] = type;
	len++;
	oldaddress = art_insert(&dns_conf_address, (unsigned char *)domain_key, len, address);
	if (oldaddress) {
		free(oldaddress);
	}

	return 0;
errout:
	if (address) {
		free(address);
	}

	tlog(TLOG_ERROR, "add address %s failed", value);
	return 0;
}

int config_server_udp(char *value)
{
	return config_server(value, DNS_SERVER_UDP);
}

int config_server_tcp(char *value)
{
	return config_server(value, DNS_SERVER_TCP);
}

int config_server_http(char *value)
{
	return config_server(value, DNS_SERVER_HTTP);
}

int config_cache_size(char *value)
{
	/* read dns cache size */
	int cache_size = atoi(value);
	if (cache_size < 0) {
		return -1;
	}

	dns_conf_cachesize = cache_size;

	return 0;
}

int config_log_level(char *value)
{
	/* read log level and set */
	if (strncmp("debug", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_DEBUG;
	} else if (strncmp("info", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_INFO;
	} else if (strncmp("warn", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_WARN;
	} else if (strncmp("error", value, MAX_LINE_LEN) == 0) {
		dns_conf_log_level = TLOG_ERROR;
	}

	return 0;
}

int config_log_file(char *value)
{
	/* read dns cache size */
	strncpy(dns_conf_log_file, value, DNS_MAX_PATH);

	return 0;
}

int config_log_size(char *value)
{
	/* read dns cache size */
	int base = 1;

	if (strstr(value, "k") || strstr(value, "K")) {
		base = 1024;
	} else if (strstr(value, "m") || strstr(value, "M")) {
		base = 1024 * 1024;
	} else if (strstr(value, "g") || strstr(value, "G")) {
		base = 1024 * 1024 * 1024;
	}

	int size = atoi(value);
	if (size < 0) {
		return -1;
	}

	dns_conf_log_size = size * base;

	return 0;
}

int config_log_num(char *value)
{
	/* read dns cache size */
	int num = atoi(value);
	if (num < 0) {
		return -1;
	}

	dns_conf_log_num = num;

	return 0;
}

int config_rr_ttl(char *value)
{
	/* read dns cache size */
	int ttl = atoi(value);
	if (ttl < 0) {
		return -1;
	}

	dns_conf_rr_ttl = ttl;

	return 0;
}

int config_rr_ttl_min(char *value)
{
	/* read dns cache size */
	int ttl = atoi(value);
	if (ttl < 0) {
		return -1;
	}

	dns_conf_rr_ttl_min = ttl;

	return 0;
}

int config_rr_ttl_max(char *value)
{
	/* read dns cache size */
	int ttl = atoi(value);
	if (ttl < 0) {
		return -1;
	}

	dns_conf_rr_ttl_max = ttl;

	return 0;
}


struct config_item {
	const char *item;
	int (*item_func)(char *value);
};

struct config_item config_item[] = {
	{"bind", config_bind},
	{"server", config_server_udp},
	{"address", config_address},
	{"server-tcp", config_server_tcp},
	{"server-http", config_server_http},
	{"cache-size", config_cache_size},
	{"log-level", config_log_level},
	{"log-file", config_log_file},
	{"log-size", config_log_size},
	{"log-num", config_log_num},
	{"rr-ttl", config_rr_ttl},
	{"rr-ttl-min", config_rr_ttl_min},
	{"rr-ttl-max", config_rr_ttl_max},
};
int config_item_num = sizeof(config_item) / sizeof(struct config_item);

int load_conf_init(void)
{
	art_tree_init(&dns_conf_address);

	return 0;
}

void load_exit(void)
{
	config_address_destroy();
}

int load_conf(const char *file)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char key[MAX_KEY_LEN];
	char value[MAX_LINE_LEN];
	int filed_num = 0;
	int line_num = 0;
	int i;

	load_conf_init();

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "config file %s not exist.", file);
		return -1;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_num++;
		filed_num = sscanf(line, "%63s %1023[^\r\n]s", key, value);
		if (filed_num <= 0) {
			continue;
		}

		/* comment, skip */
		if (key[0] == '#') {
			continue;
		}

		/* if field format is not key = value, error */
		if (filed_num != 2) {
			goto errout;
		}

		for (i = 0; i < config_item_num; i++) {
			if (strncmp(config_item[i].item, key, MAX_KEY_LEN) != 0) {
				continue;
			}

			/* call item function */
			if (config_item[i].item_func(value) != 0) {
				goto errout;
			}

			break;
		}
	}

	fclose(fp);

	return 0;
errout:
	printf("invalid config at line %d: %s", line_num, line);
	if (fp) {
		fclose(fp);
	}
	return -1;
}
