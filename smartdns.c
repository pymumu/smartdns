/*************************************************************************
 *
 * Copyright (C) 2018 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "atomic.h"
#include "conf.h"
#include "dns_client.h"
#include "dns_server.h"
#include "fast_ping.h"
#include "hashtable.h"
#include "list.h"
#include "tlog.h"
#include "util.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESOLVE_FILE "/etc/resolv.conf"
#define MAX_LINE_LEN 1024
#define MAX_KEY_LEN 64

int smartdns_load_from_resolv(void)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char key[MAX_KEY_LEN];
	char value[MAX_LINE_LEN];
	char ns_ip[DNS_MAX_IPLEN];
	int port = PORT_NOT_DEFINED;
	int ret = -1;

	int filed_num = 0;
	int line_num = 0;

	fp = fopen(RESOLVE_FILE, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "open %s failed, %s", RESOLVE_FILE, strerror(errno));
		return -1;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_num++;
		filed_num = sscanf(line, "%63s %1023[^\r\n]s", key, value);

		if (filed_num != 2) {
			continue;
		}

		if (strncmp(key, "nameserver", MAX_KEY_LEN) != 0) {
			continue;
		}

		if (parse_ip(value, ns_ip, &port) != 0) {
			continue;
		}

		if (port == PORT_NOT_DEFINED) {
			port = DEFAULT_DNS_PORT;
		}

		strncpy(dns_conf_servers[dns_conf_server_num].server, ns_ip, DNS_MAX_IPLEN);
		dns_conf_servers[dns_conf_server_num].port = port;
		dns_conf_servers[dns_conf_server_num].type = DNS_SERVER_UDP;
		dns_conf_server_num++;
		ret = 0;
	}

	fclose(fp);

	return ret;
}

int smartdns_add_servers(void)
{
	int i = 0;
	int ret = 0;
	for (i = 0; i < dns_conf_server_num; i++) {
		ret = dns_add_server(dns_conf_servers[i].server, dns_conf_servers[i].port, dns_conf_servers[i].type);
		if (ret != 0) {
			tlog(TLOG_ERROR, "add server failed, %s:%d", dns_conf_servers[i].server, dns_conf_servers[i].port);
			return -1;
		}
	}

	return 0;
}

int smartdns_init()
{
	int ret;

	if (load_conf("smartdns.conf") != 0) {
		fprintf(stderr, "load config failed.");
	}

	ret = tlog_init(".", "smartdns.log", 1024 * 1024, 8, 1, 0, 0);
	if (ret != 0) {
		tlog(TLOG_ERROR, "start tlog failed.\n");
		goto errout;
	}

	tlog_setlogscreen(1);
	tlog_setlevel(TLOG_ERROR);

	if (dns_conf_server_num <= 0) {
		if (smartdns_load_from_resolv() != 0) {
			tlog(TLOG_ERROR, "load dns from resolv failed.");
			goto errout;
		}
	}

	ret = fast_ping_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "start ping failed.\n");
		goto errout;
	}

	ret = dns_server_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "start dns server failed.\n");
		goto errout;
	}

	ret = dns_client_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "start dns client failed.\n");
		goto errout;
	}
	ret = smartdns_add_servers();
	if (ret != 0) {
		tlog(TLOG_ERROR, "add servers failed.");
		goto errout;
	}

	return 0;
errout:

	return -1;
}

int smartdns_run()
{
	return dns_server_run();
}

void smartdns_exit()
{
	dns_server_exit();
	dns_client_exit();
	fast_ping_exit();
	tlog_exit();
}

void sig_handle(int sig)
{

	switch (sig) {
	case SIGINT:
		dns_server_stop();
		return;
		break;
	default:
		break;
	}
	tlog(TLOG_ERROR, "process exit.\n");
	_exit(0);
}

int main(int argc, char *argv[])
{
	int ret;

	signal(SIGABRT, sig_handle);
	
	ret = smartdns_init();
	if (ret != 0) {
		goto errout;
	}

	signal(SIGINT, sig_handle);
	atexit(smartdns_exit);

	return smartdns_run();

errout:

	return 1;
}