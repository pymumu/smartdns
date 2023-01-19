/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include <linux/capability.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ucontext.h>

#define MAX_LINE_LEN 1024
#define MAX_KEY_LEN 64
#define SMARTDNS_PID_FILE "/var/run/smartdns.pid"
#define TMP_BUFF_LEN_32 32

static int verbose_screen;

int capget(struct __user_cap_header_struct *header, struct __user_cap_data_struct *cap);
int capset(struct __user_cap_header_struct *header, struct __user_cap_data_struct *cap);

static int get_uid_gid(int *uid, int *gid)
{
	struct passwd *result = NULL;
	struct passwd pwd;
	char *buf = NULL;
	ssize_t bufsize = 0;
	int ret = -1;

	if (dns_conf_user[0] == '\0') {
		return -1;
	}

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1) {
		bufsize = 1024 * 16;
	}

	buf = malloc(bufsize);
	if (buf == NULL) {
		goto out;
	}

	ret = getpwnam_r(dns_conf_user, &pwd, buf, bufsize, &result);
	if (ret != 0) {
		goto out;
	}

	if (result == NULL) {
		ret = -1;
		goto out;
	}

	*uid = result->pw_uid;
	*gid = result->pw_gid;

out:
	if (buf) {
		free(buf);
	}

	return ret;
}

static int drop_root_privilege(void)
{
	struct __user_cap_data_struct cap[2];
	struct __user_cap_header_struct header;
#ifdef _LINUX_CAPABILITY_VERSION_3
	header.version = _LINUX_CAPABILITY_VERSION_3;
#else
	header.version = _LINUX_CAPABILITY_VERSION;
#endif
	header.pid = 0;
	int uid = 0;
	int gid = 0;
	int unused __attribute__((unused)) = 0;

	if (get_uid_gid(&uid, &gid) != 0) {
		return -1;
	}

	memset(cap, 0, sizeof(cap));
	if (capget(&header, cap) < 0) {
		return -1;
	}

	prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	for (int i = 0; i < 2; i++) {
		cap[i].effective = (1 << CAP_NET_RAW | 1 << CAP_NET_ADMIN | 1 << CAP_NET_BIND_SERVICE);
		cap[i].permitted = (1 << CAP_NET_RAW | 1 << CAP_NET_ADMIN | 1 << CAP_NET_BIND_SERVICE);
	}

	unused = setgid(gid);
	unused = setuid(uid);
	if (capset(&header, cap) < 0) {
		return -1;
	}

	prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
	return 0;
}

static void _help(void)
{
	/* clang-format off */
	char *help = ""
		"Usage: smartdns [OPTION]...\n"
		"Start smartdns server.\n"
		"  -f            run foreground.\n"
		"  -c [conf]     config file.\n"
		"  -p [pid]      pid file path, '-' means don't create pid file.\n"
		"  -S            ignore segment fault signal.\n"
		"  -x            verbose screen.\n"
		"  -v            display version.\n"
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

	fp = fopen(dns_resolv_file, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "open %s failed, %s", dns_resolv_file, strerror(errno));
		return -1;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		line_num++;
		filed_num = sscanf(line, "%63s %1023[^\r\n]s", key, value);

		if (filed_num != 2) {
			continue;
		}

		if (strncmp(key, "nameserver", MAX_KEY_LEN - 1) != 0) {
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
	unsigned long i = 0;
	int j = 0;
	int ret = 0;
	struct dns_server_groups *group = NULL;
	struct dns_servers *server = NULL;
	struct client_dns_server_flags flags;

	for (i = 0; i < (unsigned int)dns_conf_server_num; i++) {
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
		flags.set_mark = dns_conf_servers[i].set_mark;
		safe_strncpy(flags.proxyname, dns_conf_servers[i].proxyname, sizeof(flags.proxyname));
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

static int _proxy_add_servers(void)
{
	unsigned long i = 0;
	struct hlist_node *tmp = NULL;
	struct dns_proxy_names *proxy = NULL;
	struct dns_proxy_servers *server = NULL;
	struct dns_proxy_servers *server_tmp = NULL;

	hash_for_each_safe(dns_proxy_table.proxy, i, tmp, proxy, node)
	{
		list_for_each_entry_safe(server, server_tmp, &proxy->server_list, list)
		{
			struct proxy_info info;
			memset(&info, 0, sizeof(info));
			info.type = server->type;
			info.port = server->port;
			safe_strncpy(info.server, server->server, PROXY_MAX_IPLEN);
			safe_strncpy(info.username, server->username, PROXY_MAX_NAMELEN);
			safe_strncpy(info.password, server->password, PROXY_MAX_NAMELEN);
			info.use_domain = server->use_domain;
			proxy_add(proxy->proxy_name, &info);
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

static const char *_smartdns_log_path(void)
{
	char *logfile = SMARTDNS_LOG_FILE;

	if (dns_conf_log_file[0] != 0) {
		logfile = dns_conf_log_file;
	}

	return logfile;
}

static int _smartdns_init(void)
{
	int ret = 0;
	const char *logfile = _smartdns_log_path();
	int i = 0;

	ret = tlog_init(logfile, dns_conf_log_size, dns_conf_log_num, 0, 0);
	if (ret != 0) {
		tlog(TLOG_ERROR, "start tlog failed.\n");
		goto errout;
	}

	tlog_setlogscreen(verbose_screen);
	tlog_setlevel(dns_conf_log_level);
	if (dns_conf_log_file_mode > 0) {
		tlog_set_permission(tlog_get_root(), dns_conf_log_file_mode, dns_conf_log_file_mode);
	}

	tlog(TLOG_NOTICE, "smartdns starting...(Copyright (C) Nick Peng <pymumu@gmail.com>, build: %s %s)", __DATE__,
		 __TIME__);

	if (_smartdns_init_ssl() != 0) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

	for (i = 0; i < 60 && dns_conf_server_num <= 0; i++) {
		ret = _smartdns_load_from_resolv();
		if (ret == 0) {
			continue;
		}

		tlog(TLOG_DEBUG, "load dns from resolv failed, retry after 1s, retry times %d.", i + 1);
		sleep(1);
	}

	if (dns_conf_server_num <= 0) {
		tlog(TLOG_ERROR, "no dns server found, exit...");
		goto errout;
	}

	ret = fast_ping_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "start ping failed.\n");
		goto errout;
	}

	ret = proxy_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "start proxy failed.\n");
		goto errout;
	}

	ret = _proxy_add_servers();
	if (ret != 0) {
		tlog(TLOG_ERROR, "add proxy servers failed.");
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
	tlog(TLOG_INFO, "smartdns exit...");
	dns_client_exit();
	proxy_exit();
	fast_ping_exit();
	dns_server_exit();
	_smartdns_destroy_ssl();
	tlog_exit();
	dns_server_load_exit();
}

static void _sig_exit(int signo)
{
	tlog(TLOG_INFO, "stop smartdns by signal %d", signo);
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
	struct sigaction act;
	struct sigaction old;
	int i = 0;
	act.sa_sigaction = _sig_error_exit;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART | SA_SIGINFO;

	for (i = 0; i < sig_num; i++) {
		sigaction(sig_list[i], &act, &old);
	}
}

static int _smartdns_create_logdir(void)
{
	int uid = 0;
	int gid = 0;
	char logdir[PATH_MAX] = {0};
	safe_strncpy(logdir, _smartdns_log_path(), PATH_MAX);
	dirname(logdir);

	if (access(logdir, F_OK) == 0) {
		return 0;
	}

	if (mkdir(logdir, 0750) != 0) {
		if (errno == EEXIST) {
			return 0;
		}

		return -1;
	}

	int unused __attribute__((unused)) = 0;

	if (get_uid_gid(&uid, &gid) != 0) {
		return -1;
	}

	unused = chown(logdir, uid, gid);
	return 0;
}

static int _set_rlimit(void)
{
	struct rlimit value;
	value.rlim_cur = 40;
	value.rlim_max = 40;
	setrlimit(RLIMIT_NICE, &value);
	return 0;
}

static int _smartdns_init_pre(void)
{
	_smartdns_create_logdir();

	_set_rlimit();

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	int is_foreground = 0;
	int opt = 0;
	char config_file[MAX_LINE_LEN];
	char pid_file[MAX_LINE_LEN];
	int signal_ignore = 0;
	sigset_t empty_sigblock;

	safe_strncpy(config_file, SMARTDNS_CONF_FILE, MAX_LINE_LEN);
	safe_strncpy(pid_file, SMARTDNS_PID_FILE, MAX_LINE_LEN);

	/* patch for Asus router:  unblock all signal*/
	sigemptyset(&empty_sigblock);
	sigprocmask(SIG_SETMASK, &empty_sigblock, NULL);

	while ((opt = getopt(argc, argv, "fhc:p:SvxN:")) != -1) {
		switch (opt) {
		case 'f':
			is_foreground = 1;
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
#ifdef DEBUG
		case 'N':
			return dns_packet_debug(optarg);
#endif
		case 'h':
			_help();
			return 1;
		}
	}

	if (dns_server_load_conf(config_file) != 0) {
		fprintf(stderr, "load config failed.\n");
		goto errout;
	}

	if (is_foreground == 0) {
		if (daemon(0, 0) < 0) {
			fprintf(stderr, "run daemon process failed, %s\n", strerror(errno));
			return 1;
		}
	}

	if (signal_ignore == 0) {
		_reg_signal();
	}

	if (strncmp(pid_file, "-", 2) != 0 && create_pid_file(pid_file) != 0) {
		goto errout;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, _sig_exit);
	signal(SIGTERM, _sig_exit);

	if (_smartdns_init_pre() != 0) {
		fprintf(stderr, "init failed.\n");
		return 1;
	}

	drop_root_privilege();

	ret = _smartdns_init();
	if (ret != 0) {
		usleep(100000);
		goto errout;
	}

	atexit(_smartdns_exit);

	return _smartdns_run();

errout:

	return 1;
}
