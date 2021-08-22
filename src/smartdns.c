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

#define _GNU_SOURCE
#include "art.h"
#include "atomic.h"
#include "dns_client.h"
#include "dns_conf.h"
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
#include <ucontext.h>

#define RESOLVE_FILE "/etc/resolv.conf"
#define MAX_LINE_LEN 1024
#define MAX_KEY_LEN 64
#define SMARTDNS_PID_FILE "/var/run/smartdns.pid"
#define TMP_BUFF_LEN_32 32

static int verbose_screen;

static void _help(void)
{
	/* clang-format off */
	char *help = ""
		"Usage: smartdns [OPTION]...\n"
		"Start smartdns server.\n"
		"  -f            run forground.\n"
		"  -c [conf]     config file.\n"
		"  -p [pid]      pid file path\n"
		"  -S            ignore segment fault signal.\n"
		"  -x            verbose screen.\n"
		"  -v            dispaly version.\n"
		"  -h            show this help message.\n"

		"Online help: http://pymumu.github.io/smartdns\n"
		"Copyright (C) Nick Peng <pymumu@gmail.com>\n"
		;
	/* clang-format on */
	printf("%s", help);
}

static void _show_version(void)
{
	char str_ver[256] = {0};
#ifdef SMARTDNS_VERION
	const char *ver = SMARTDNS_VERION;
	snprintf(str_ver, sizeof(str_ver), "%s", ver);
#else
	struct tm tm;
	get_compiled_time(&tm);
	snprintf(str_ver, sizeof(str_ver), "1.%.4d%.2d%.2d-%.2d%.2d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			 tm.tm_hour, tm.tm_min);
#endif
	printf("smartdns %s\n", str_ver);
}

static int _smartdns_load_from_resolv(void)
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

		safe_strncpy(dns_conf_servers[dns_conf_server_num].server, ns_ip, DNS_MAX_IPLEN);
		dns_conf_servers[dns_conf_server_num].port = port;
		dns_conf_servers[dns_conf_server_num].type = DNS_SERVER_UDP;
		dns_conf_server_num++;
		ret = 0;
	}

	fclose(fp);

	return ret;
}

static int _smartdns_add_servers(void)
{
	int i = 0;
	int j = 0;
	int ret = 0;
	struct dns_server_groups *group = NULL;
	struct dns_servers *server = NULL;
	struct client_dns_server_flags flags;

	for (i = 0; i < dns_conf_server_num; i++) {
		memset(&flags, 0, sizeof(flags));
		switch (dns_conf_servers[i].type) {
		case DNS_SERVER_UDP: {
			struct client_dns_server_flag_udp *flag_udp = &flags.udp;
			flag_udp->ttl = dns_conf_servers[i].ttl;
		} break;
		case DNS_SERVER_HTTPS: {
			struct client_dns_server_flag_https *flag_http = &flags.https;
			flag_http->spi_len = dns_client_spki_decode(dns_conf_servers[i].spki, (unsigned char *)flag_http->spki);
			safe_strncpy(flag_http->hostname, dns_conf_servers[i].hostname, sizeof(flag_http->hostname));
			safe_strncpy(flag_http->path, dns_conf_servers[i].path, sizeof(flag_http->path));
			safe_strncpy(flag_http->httphost, dns_conf_servers[i].httphost, sizeof(flag_http->httphost));
			safe_strncpy(flag_http->tls_host_verify, dns_conf_servers[i].tls_host_verify,
						 sizeof(flag_http->tls_host_verify));
			flag_http->skip_check_cert = dns_conf_servers[i].skip_check_cert;
		} break;
		case DNS_SERVER_TLS: {
			struct client_dns_server_flag_tls *flag_tls = &flags.tls;
			flag_tls->spi_len = dns_client_spki_decode(dns_conf_servers[i].spki, (unsigned char *)flag_tls->spki);
			safe_strncpy(flag_tls->hostname, dns_conf_servers[i].hostname, sizeof(flag_tls->hostname));
			safe_strncpy(flag_tls->tls_host_verify, dns_conf_servers[i].tls_host_verify,
						 sizeof(flag_tls->tls_host_verify));
			flag_tls->skip_check_cert = dns_conf_servers[i].skip_check_cert;

		} break;
		case DNS_SERVER_TCP:
			break;
		default:
			return -1;
			break;
		}

		flags.type = dns_conf_servers[i].type;
		flags.server_flag = dns_conf_servers[i].server_flag;
		flags.result_flag = dns_conf_servers[i].result_flag;
		ret = dns_client_add_server(dns_conf_servers[i].server, dns_conf_servers[i].port, dns_conf_servers[i].type,
									&flags);
		if (ret != 0) {
			tlog(TLOG_ERROR, "add server failed, %s:%d", dns_conf_servers[i].server, dns_conf_servers[i].port);
			return -1;
		}
	}

	hash_for_each(dns_group_table.group, i, group, node)
	{
		ret = dns_client_add_group(group->group_name);
		if (ret != 0) {
			tlog(TLOG_ERROR, "add group failed, %s", group->group_name);
			return -1;
		}

		for (j = 0; j < group->server_num; j++) {
			server = group->servers[j];
			if (server == NULL) {
				continue;
			}
			ret = dns_client_add_to_group(group->group_name, server->server, server->port, server->type);
			if (ret != 0) {
				tlog(TLOG_ERROR, "add server %s to group %s failed", server->server, group->group_name);
				return -1;
			}
		}
	}

	return 0;
}

static int _smartdns_set_ecs_ip(void)
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

static int _smartdns_init_ssl(void)
{
#if OPENSSL_API_COMPAT < 0x10100000L
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_CRYPTO_thread_setup();
#endif
	return 0;
}

static int _smartdns_destroy_ssl(void)
{
#if OPENSSL_API_COMPAT < 0x10100000L
	SSL_CRYPTO_thread_cleanup();
	ERR_free_strings();
	EVP_cleanup();
#endif
	return 0;
}

static int _smartdns_init(void)
{
	int ret;
	char *logfile = SMARTDNS_LOG_FILE;

	if (dns_conf_log_file[0] != 0) {
		logfile = dns_conf_log_file;
	}

	ret = tlog_init(logfile, dns_conf_log_size, dns_conf_log_num, 0, 0);
	if (ret != 0) {
		tlog(TLOG_ERROR, "start tlog failed.\n");
		goto errout;
	}

	tlog_setlogscreen(verbose_screen);
	tlog_setlevel(dns_conf_log_level);

	tlog(TLOG_NOTICE, "smartdns starting...(Copyright (C) Nick Peng <pymumu@gmail.com>, build:%s %s)", __DATE__,
		 __TIME__);

	if (_smartdns_init_ssl() != 0) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

	if (dns_conf_server_num <= 0) {
		if (_smartdns_load_from_resolv() != 0) {
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
	ret = _smartdns_add_servers();
	if (ret != 0) {
		tlog(TLOG_ERROR, "add servers failed.");
		goto errout;
	}

	ret = _smartdns_set_ecs_ip();
	if (ret != 0) {
		tlog(TLOG_WARN, "set ecs ip address failed.");
	}

	return 0;
errout:

	return -1;
}

static int _smartdns_run(void)
{
	return dns_server_run();
}

static void _smartdns_exit(void)
{
	dns_server_exit();
	dns_client_exit();
	fast_ping_exit();
	_smartdns_destroy_ssl();
	tlog_exit();
	dns_server_load_exit();
}

static void _sig_exit(int signo)
{
	dns_server_stop();
}

static void _sig_error_exit(int signo, siginfo_t *siginfo, void *ct)
{
	unsigned long PC = 0;
	ucontext_t *context = ct;
	const char *arch = NULL;
#if defined(__i386__)
	int *pgregs = (int *)(&(context->uc_mcontext.gregs));
	PC = pgregs[REG_EIP];
	arch = "i386";
#elif defined(__x86_64__)
	int *pgregs = (int *)(&(context->uc_mcontext.gregs));
	PC = pgregs[REG_RIP];
	arch = "x86_64";
#elif defined(__arm__)
	PC = context->uc_mcontext.arm_pc;
	arch = "arm";
#elif defined(__aarch64__)
	PC = context->uc_mcontext.pc;
	arch = "arm64";
#elif defined(__mips__)
	PC = context->uc_mcontext.pc;
	arch = "mips";
#endif
	tlog(TLOG_FATAL,
		 "process exit with signal %d, code = %d, errno = %d, pid = %d, self = %d, pc = %#lx, addr = %#lx, build(%s "
		 "%s %s)\n",
		 signo, siginfo->si_code, siginfo->si_errno, siginfo->si_pid, getpid(), PC, (unsigned long)siginfo->si_addr,
		 __DATE__, __TIME__, arch);
	print_stack();
	sleep(1);
	_exit(0);
}

static int sig_list[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE};

static int sig_num = sizeof(sig_list) / sizeof(int);

static void _reg_signal(void)
{
	struct sigaction act, old;
	int i = 0;
	act.sa_sigaction = _sig_error_exit;
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

	safe_strncpy(config_file, SMARTDNS_CONF_FILE, MAX_LINE_LEN);
	safe_strncpy(pid_file, SMARTDNS_PID_FILE, MAX_LINE_LEN);

	while ((opt = getopt(argc, argv, "fhc:p:Svx")) != -1) {
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
		case 'x':
			verbose_screen = 1;
			break;
		case 'v':
			_show_version();
			return 0;
			break;
		case 'h':
			_help();
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
		_reg_signal();
	}

	if (create_pid_file(pid_file) != 0) {
		goto errout;
	}

	signal(SIGPIPE, SIG_IGN);
	if (dns_server_load_conf(config_file) != 0) {
		fprintf(stderr, "load config failed.\n");
		goto errout;
	}

	ret = _smartdns_init();
	if (ret != 0) {
		usleep(100000);
		goto errout;
	}

	signal(SIGINT, _sig_exit);
	signal(SIGTERM, _sig_exit);
	atexit(_smartdns_exit);

	return _smartdns_run();

errout:

	return 1;
}
