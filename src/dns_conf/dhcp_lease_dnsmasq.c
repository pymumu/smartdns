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

#include "dhcp_lease_dnsmasq.h"
#include "host_file.h"
#include "ptr.h"
#include "smartdns/lib/stringutil.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef int (*dns_conf_dhcp_lease_add_fn)(const char *file);

struct dns_conf_dhcp_lease_source {
	char file[DNS_MAX_PATH];
	time_t mtime;
	dns_conf_dhcp_lease_add_fn add;
};

static struct dns_conf_dhcp_lease_source dns_conf_dnsmasq_lease;
static struct dns_conf_dhcp_lease_source dns_conf_odhcpd_lease;

static int _conf_dhcp_lease_add_host(const char *hostname, const char *ip, dns_hosts_type host_type, int line_no)
{
	int ret = 0;

	ret = _conf_host_add(hostname, ip, host_type, 1);
	if (ret != 0) {
		tlog(TLOG_WARN, "add host %s/%s at %d failed", hostname, ip, line_no);
	}

	ret = _conf_ptr_add(hostname, ip, 1);
	if (ret != 0) {
		tlog(TLOG_WARN, "add ptr %s/%s at %d failed.", hostname, ip, line_no);
	}

	return 0;
}

static int _conf_dhcp_lease_hostname_is_valid(const char *hostname)
{
	int label_len = 0;

	if (hostname == NULL || hostname[0] == '\0') {
		return 0;
	}

	if (strncmp(hostname, "*", DNS_MAX_CNAME_LEN - 1) == 0 || strncmp(hostname, "-", DNS_MAX_CNAME_LEN - 1) == 0 ||
		strncmp(hostname, "0", DNS_MAX_CNAME_LEN - 1) == 0) {
		return 0;
	}

	for (const unsigned char *p = (const unsigned char *)hostname; *p; p++) {
		if (*p == '.') {
			if (label_len == 0) {
				return 0;
			}
			label_len = 0;
			continue;
		}

		if (isalnum(*p) || *p == '-' || *p == '_') {
			label_len++;
			continue;
		}

		return 0;
	}

	return label_len > 0;
}

static int _conf_dhcp_lease_dnsmasq_add(const char *file)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char ip[DNS_MAX_IPLEN];
	char hostname[DNS_MAX_CNAME_LEN];
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

		_conf_dhcp_lease_add_host(hostname, ip, DNS_HOST_TYPE_DNSMASQ, line_no);
	}

	fclose(fp);

	return 0;
}

static int _conf_dhcp_lease_odhcpd_add(const char *file)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char ip[DNS_MAX_IPLEN];
	char hostname[DNS_MAX_CNAME_LEN];
	int line_no = 0;

	fp = fopen(file, "r");
	if (fp == NULL) {
		tlog(TLOG_WARN, "open file %s error, %s", file, strerror(errno));
		return 0;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		char *tokens[16] = {0};
		int token_num = 0;
		int offset = 0;
		char *slash = NULL;
		char *token = NULL;

		line_no++;
		token = strtok(line, " \t\r\n");
		while (token != NULL && token_num < (int)(sizeof(tokens) / sizeof(tokens[0]))) {
			tokens[token_num++] = token;
			token = strtok(NULL, " \t\r\n");
		}

		if (token_num <= 0) {
			continue;
		}

		if (strncmp(tokens[0], "#", 2) == 0) {
			offset = 1;
		} else if (tokens[0][0] == '#') {
			continue;
		}

		if (token_num - offset < 8) {
			continue;
		}

		safe_strncpy(hostname, tokens[offset + 3], sizeof(hostname));
		if (_conf_dhcp_lease_hostname_is_valid(hostname) == 0) {
			continue;
		}

		safe_strncpy(ip, tokens[token_num - 1], sizeof(ip));
		slash = strchr(ip, '/');
		if (slash != NULL) {
			*slash = '\0';
		}

		_conf_dhcp_lease_add_host(hostname, ip, DNS_HOST_TYPE_ODHCPD, line_no);
	}

	fclose(fp);

	return 0;
}

static int _conf_dhcp_lease_file(struct dns_conf_dhcp_lease_source *lease, char *file)
{
	struct stat statbuf;

	conf_get_conf_fullpath(file, lease->file, sizeof(lease->file));
	if (lease->add(lease->file) != 0) {
		return -1;
	}

	if (stat(lease->file, &statbuf) != 0) {
		return 0;
	}

	lease->mtime = statbuf.st_mtime;
	return 0;
}

int _conf_dhcp_lease_dnsmasq_file(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	dns_conf_dnsmasq_lease.add = _conf_dhcp_lease_dnsmasq_add;
	return _conf_dhcp_lease_file(&dns_conf_dnsmasq_lease, argv[1]);
}

int _conf_dhcp_lease_odhcpd_file(void *data, int argc, char *argv[])
{
	if (argc <= 1) {
		return -1;
	}

	dns_conf_odhcpd_lease.add = _conf_dhcp_lease_odhcpd_add;
	return _conf_dhcp_lease_file(&dns_conf_odhcpd_lease, argv[1]);
}

static int _conf_dhcp_lease_need_update(struct dns_conf_dhcp_lease_source *lease, time_t now)
{
	struct stat statbuf;

	if (lease->file[0] == '\0') {
		return -1;
	}

	if (stat(lease->file, &statbuf) != 0) {
		return -1;
	}

	if (lease->mtime == statbuf.st_mtime) {
		return -1;
	}

	if (now - statbuf.st_mtime < 30) {
		return -1;
	}

	return 0;
}

static int _conf_dhcp_lease_reload(struct dns_conf_dhcp_lease_source *lease)
{
	struct stat statbuf;

	if (lease->file[0] == '\0') {
		return -1;
	}

	if (lease->add(lease->file) != 0) {
		return -1;
	}

	if (stat(lease->file, &statbuf) == 0) {
		lease->mtime = statbuf.st_mtime;
	}

	return 0;
}

int dns_server_check_update_hosts(void)
{
	time_t now = 0;

	time(&now);
	if (_conf_dhcp_lease_need_update(&dns_conf_dnsmasq_lease, now) != 0 &&
		_conf_dhcp_lease_need_update(&dns_conf_odhcpd_lease, now) != 0) {
		return -1;
	}

	_config_ptr_table_destroy(1);
	_config_host_table_destroy(1);

	_conf_dhcp_lease_reload(&dns_conf_dnsmasq_lease);
	_conf_dhcp_lease_reload(&dns_conf_odhcpd_lease);

	return 0;
}
