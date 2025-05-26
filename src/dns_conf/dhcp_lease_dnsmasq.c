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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static char dns_conf_dnsmasq_lease_file[DNS_MAX_PATH];
static time_t dns_conf_dnsmasq_lease_file_time;

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

int _conf_dhcp_lease_dnsmasq_file(void *data, int argc, char *argv[])
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