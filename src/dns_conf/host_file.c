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

#include "host_file.h"
#include "ptr.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

struct dns_hosts_table dns_hosts_table;
int dns_hosts_record_num;

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

int _config_hosts_file(void *data, int argc, char *argv[])
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

void _config_host_table_init(void)
{
	hash_init(dns_hosts_table.hosts);
}

void _config_host_table_destroy(int only_dynamic)
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

int _conf_host_add(const char *hostname, const char *ip, dns_hosts_type host_type, int is_dynamic)
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
