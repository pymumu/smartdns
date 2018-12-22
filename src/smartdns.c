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

#define _GNU_SOURCE
#include "art.h"
#include "atomic.h"
#include "dns_conf.h"
#include "dns_client.h"
#include "dns_server.h"
#include "fast_ping.h"
#include "hashtable.h"
#include "list.h"
#include "rbtree.h"
#include "tlog.h"
#include "util.h"
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define RESOLVE_FILE "/etc/resolv.conf"
#define MAX_LINE_LEN 1024
#define MAX_KEY_LEN 64
#define SMARTDNS_PID_FILE "/var/run/smartdns.pid"
#define TMP_BUFF_LEN_32 32

static int verbose_screen;

void help(void)
{
	/* clang-format off */
	char *help = ""
		"Usage: smartdns [OPTION]...\n"
		"Start smartdns server.\n"
		"  -f            run forground.\n"
		"  -c [conf]     config file.\n"
		"  -p [pid]      pid file path\n"
		"  -S            ignore segment fault signal.\n"
		"  -v            verbose screent.\n"
		"  -h            show this help message.\n"

		"Online help: http://pymumu.github.io/smartdns\n"
		"Copyright (C) Nick Peng <pymumu@gmail.com>\n"
		;
	/* clang-format on */
	printf("%s", help);
}

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
		ret = dns_add_server(dns_conf_servers[i].server, dns_conf_servers[i].port, dns_conf_servers[i].type, dns_conf_servers[i].result_flag, 
			dns_conf_servers[i].ttl);
		if (ret != 0) {
			tlog(TLOG_ERROR, "add server failed, %s:%d", dns_conf_servers[i].server, dns_conf_servers[i].port);
			return -1;
		}
	}

	return 0;
}

int smartdns_set_ecs_ip(void)
{
	int ret = 0;
	if (dns_conf_ipv4_ecs.enable) {
		ret |= dns_client_set_ecs(dns_conf_ipv4_ecs.ip, dns_conf_ipv4_ecs.subnet);
	}

	if (dns_conf_ipv6_ecs.enable) {
		ret |= dns_client_set_ecs(dns_conf_ipv6_ecs.ip, dns_conf_ipv6_ecs.subnet);
	}

	return ret;
}

int create_pid_file(const char *pid_file)
{
	int fd;
	int flags;
	char buff[TMP_BUFF_LEN_32];

	/*  create pid file, and lock this file */
	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "create pid file failed, %s\n", strerror(errno));
		return -1;
	}

	flags = fcntl(fd, F_GETFD);
	if (flags < 0) {
		fprintf(stderr, "Could not get flags for PID file %s\n", pid_file);
		goto errout;
	}

	flags |= FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flags) == -1) {
		fprintf(stderr, "Could not set flags for PID file %s\n", pid_file);
		goto errout;
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		fprintf(stderr, "Server is already running.\n");
		goto errout;
	}

	snprintf(buff, TMP_BUFF_LEN_32, "%d\n", getpid());

	if (write(fd, buff, strnlen(buff, TMP_BUFF_LEN_32)) < 0) {
		fprintf(stderr, "write pid to file failed, %s.\n", strerror(errno));
		goto errout;
	}

	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

int smartdns_init_ssl(void)
{
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	return 0;
}

int smartdns_destroy_ssl(void)
{
	ERR_free_strings();
	EVP_cleanup();

	return 0;
}

int smartdns_init(void)
{
	int ret;
	char *logfile = SMARTDNS_LOG_FILE;

	if (dns_conf_log_file[0] != 0) {
		logfile = dns_conf_log_file;
	}

	ret = tlog_init(logfile, dns_conf_log_size, dns_conf_log_num, 1, 0, 0);
	if (ret != 0) {
		tlog(TLOG_ERROR, "start tlog failed.\n");
		goto errout;
	}

	tlog_setlogscreen(verbose_screen);
	tlog_setlevel(dns_conf_log_level);

	tlog(TLOG_NOTICE, "smartdns starting...(Copyright (C) Nick Peng <pymumu@gmail.com>, build:%s %s)", __DATE__, __TIME__);

	if (smartdns_init_ssl() != 0) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

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

	ret = smartdns_set_ecs_ip();
	if (ret != 0 ) {
		tlog(TLOG_WARN, "set ecs ip address failed.");
	}

	return 0;
errout:

	return -1;
}

int smartdns_run(void)
{
	return dns_server_run();
}

void smartdns_exit(void)
{
	dns_server_exit();
	dns_client_exit();
	fast_ping_exit();
	smartdns_destroy_ssl();
	tlog_exit();
	dns_server_load_exit();
}

void sig_exit(int signo)
{
	dns_server_stop();
}

void sig_error_exit(int signo, siginfo_t *siginfo, void *context)
{
	tlog(TLOG_ERROR, "process exit with signal %d, code = %d, errno = %d, pid = %d, self = %d, addr = %p\n", signo, 
		siginfo->si_code, siginfo->si_errno, siginfo->si_pid, getpid(), siginfo->si_addr);
	sleep(1);
	_exit(0);
}

int sig_list[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};

int sig_num = sizeof(sig_list) / sizeof(int);

void reg_signal(void)
{
	struct sigaction act, old;
	int i = 0;
	act.sa_sigaction = sig_error_exit;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART | SA_SIGINFO;

	for (i = 0; i < sig_num; i++) {
		sigaction(sig_list[i], &act, &old);
	}
}

int main(int argc, char *argv[])
{
	int ret;
	int is_forground = 0;
	int opt;
	char config_file[MAX_LINE_LEN];
	char pid_file[MAX_LINE_LEN];
	int signal_ignore = 0;

	strncpy(config_file, SMARTDNS_CONF_FILE, MAX_LINE_LEN);
	strncpy(pid_file, SMARTDNS_PID_FILE, MAX_LINE_LEN);

	while ((opt = getopt(argc, argv, "fhc:p:Sv")) != -1) {
		switch (opt) {
		case 'f':
			is_forground = 1;
			break;
		case 'c':
			snprintf(config_file, sizeof(config_file), "%s", optarg);
			break;
		case 'p':
			snprintf(pid_file, sizeof(pid_file), "%s", optarg);
			break;
		case 'S':
			signal_ignore = 1;
			break;
		case 'v':
			verbose_screen = 1;
			break;
		case 'h':
			help();
			return 1;
		}
	}

	if (is_forground == 0) {
		if (daemon(0, 0) < 0) {
			fprintf(stderr, "run daemon process failed, %s\n", strerror(errno));
			return 1;
		}
	}

	if (signal_ignore == 0) {
		reg_signal();
	}

	if (dns_server_load_conf(config_file) != 0) {
	}

	if (create_pid_file(pid_file) != 0) {
		goto errout;
	}

	ret = smartdns_init();
	if (ret != 0) {
		usleep(100000);
		goto errout;
	}

	signal(SIGINT, sig_exit);
	signal(SIGPIPE, SIG_IGN);
	atexit(smartdns_exit);

	return smartdns_run();
	
errout:

	return 1;
}
