#include "conf.h"
#include "tlog.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LINE_LEN 1024
#define MAX_KEY_LEN 64

#define DEFAULT_DNS_CACHE_SIZE 512

int dns_conf_port = DEFAULT_DNS_PORT;
int dns_conf_cachesize = DEFAULT_DNS_CACHE_SIZE;
struct dns_servers dns_conf_servers[DNS_MAX_SERVERS];
int dns_conf_server_num;

int config_port(char *value)
{
	int port = atoi(value);
	if (port <= 0 || port >= 65535) {
		return -1;
	}

	dns_conf_port = port;

	return 0;
}

int config_server(char *value, dns_conf_server_type_t type)
{
	int index = dns_conf_server_num;
	struct dns_servers *server;
	int port = -1;

	if (index >= DNS_MAX_SERVERS) {
		tlog(TLOG_ERROR, "exceeds max server number");
		return -1;
	}

	server = &dns_conf_servers[index];
    if (parse_ip(value, server->server, &port) != 0) {
		return -1;
    }

	if (port == PORT_NOT_DEFINED) {
		port= DEFAULT_DNS_PORT;
	} 
	
	server->type = type;
	server->port = port;
	dns_conf_server_num++;

	return 0;
}

int config_server_udp(char *value)
{
	return config_server(value, DNS_CONF_TYPE_UDP);
}

int config_server_tcp(char *value)
{
	return config_server(value, DNS_CONF_TYPE_TCP);
}

int config_server_http(char *value)
{
	return config_server(value, DNS_CONF_TYPE_HTTP);
}

int config_cache_size(char *value)
{
	int cache_size = atoi(value);
	if (cache_size < 0) {
		return -1;
	}

	dns_conf_cachesize = cache_size;

	return 0;
}

struct config_item {
	const char *item;
	int (*item_func)(char *value);
};

struct config_item config_item[] = {
	{"port", config_port},
	{"server", config_server_udp},
    {"server-tcp", config_server_tcp},
    {"server-http", config_server_http},
	{"cache-size", config_cache_size},
};
int config_item_num = sizeof(config_item) / sizeof(struct config_item);

int load_conf(const char *file)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char key[MAX_KEY_LEN];
	char value[MAX_LINE_LEN];
	int filed_num = 0;
	int line_num = 0;
	int i;

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

		if (key[0] == '#') {
			continue;
		}

		if (filed_num != 2) {
			goto errout;
		}

		for (i = 0; i < config_item_num; i++) {
			if (strncmp(config_item[i].item, key, MAX_KEY_LEN) != 0) {
				continue;
			}

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