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

#define _GNU_SOURCE
#include "smartdns.h"
#include "art.h"
#include "atomic.h"
#include "dns_cache.h"
#include "dns_client.h"
#include "dns_conf.h"
#include "dns_plugin.h"
#include "dns_server.h"
#include "fast_ping.h"
#include "hashtable.h"
#include "list.h"
#include "rbtree.h"
#include "timer.h"
#include "tlog.h"
#include "util.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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
#include <sys/wait.h>
#include <syslog.h>
#include <ucontext.h>

#define MAX_KEY_LEN 64
#define SMARTDNS_PID_FILE "/run/smartdns.pid"
#define SMARTDNS_LEGACY_PID_FILE "/var/run/smartdns.pid"
#define TMP_BUFF_LEN_32 32
#define SMARTDNS_CRASH_CODE 254

typedef enum {
	SMARTDNS_RUN_MONITOR_OK = 0,
	SMARTDNS_RUN_MONITOR_ERROR = 1,
	SMARTDNS_RUN_MONITOR_EXIT = 2,
} smartdns_run_monitor_ret;

static int verbose_screen;
static int exit_status;
static int exit_restart;

int capget(struct __user_cap_header_struct *header, struct __user_cap_data_struct *cap);
int capset(struct __user_cap_header_struct *header, struct __user_cap_data_struct *cap);

static int get_uid_gid(uid_t *uid, gid_t *gid)
{
	struct passwd *result = NULL;
	struct passwd pwd;
	char *buf = NULL;
	ssize_t bufsize = 0;
	int ret = -1;

	if (dns_conf_user[0] == '\0') {
		*uid = getuid();
		*gid = getgid();
		return 0;
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
	uid_t uid = 0;
	gid_t gid = 0;
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
		"  -R            restart smartdns when crash.\n"
		"  -S            ignore segment fault signal.\n"
		"  -x            verbose screen.\n"
		"  -v            display version.\n"
		"  -h            show this help message.\n"

		"Online help: https://pymumu.github.io/smartdns\n"
		"Copyright (C) Nick Peng <pymumu@gmail.com>\n"
		;
	/* clang-format on */
	printf("%s", help);
}

static void _smartdns_get_version(char *str_ver, int str_ver_len)
{
	char commit_ver[TMP_BUFF_LEN_32] = {0};
#ifdef COMMIT_VERION
	snprintf(commit_ver, sizeof(commit_ver), " (%s)", COMMIT_VERION);
#endif

#ifdef SMARTDNS_VERION
	const char *ver = SMARTDNS_VERION;
	snprintf(str_ver, str_ver_len, "%s%s", ver, commit_ver);
#else
	struct tm tm;
	get_compiled_time(&tm);
	snprintf(str_ver, str_ver_len, "1.%.4d%.2d%.2d-%.2d%.2d%s", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			 tm.tm_hour, tm.tm_min, commit_ver);
#endif
}

static void _show_version(void)
{
	char str_ver[256] = {0};
	_smartdns_get_version(str_ver, sizeof(str_ver));
	printf("smartdns %s\n", str_ver);
}

static int _smartdns_load_from_resolv_file(const char *resolv_file)
{
	FILE *fp = NULL;
	char line[MAX_LINE_LEN];
	char key[MAX_KEY_LEN] = {0};
	char value[MAX_LINE_LEN];
	char ns_ip[DNS_MAX_IPLEN];
	int port = PORT_NOT_DEFINED;
	int ret = -1;

	int filed_num = 0;
	int line_num = 0;

	fp = fopen(resolv_file, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "open %s failed, %s", resolv_file, strerror(errno));
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
		dns_conf_servers[dns_conf_server_num].set_mark = -1;
		dns_conf_server_num++;
		ret = 0;
	}

	fclose(fp);

	return ret;
}

static int _smartdns_load_from_resolv(void)
{
	return _smartdns_load_from_resolv_file(dns_resolv_file);
}

static int _smartdns_load_from_default_resolv(void)
{
	return _smartdns_load_from_resolv_file(DNS_RESOLV_FILE);
}

static int _smartdns_prepare_server_flags(struct client_dns_server_flags *flags, struct dns_servers *server)
{
	memset(flags, 0, sizeof(*flags));
	switch (server->type) {
	case DNS_SERVER_UDP: {
		struct client_dns_server_flag_udp *flag_udp = &flags->udp;
		flag_udp->ttl = server->ttl;
	} break;
	case DNS_SERVER_HTTPS: {
		struct client_dns_server_flag_https *flag_http = &flags->https;
		if (server->spki[0] != 0) {
			flag_http->spi_len =
				dns_client_spki_decode(server->spki, (unsigned char *)flag_http->spki, sizeof(flag_http->spki));
			if (flag_http->spi_len <= 0) {
				tlog(TLOG_ERROR, "decode spki failed, %s:%d", server->server, server->port);
				return -1;
			}
		}
		safe_strncpy(flag_http->hostname, server->hostname, sizeof(flag_http->hostname));
		safe_strncpy(flag_http->path, server->path, sizeof(flag_http->path));
		safe_strncpy(flag_http->httphost, server->httphost, sizeof(flag_http->httphost));
		safe_strncpy(flag_http->tls_host_verify, server->tls_host_verify, sizeof(flag_http->tls_host_verify));
		flag_http->skip_check_cert = server->skip_check_cert;
	} break;
	case DNS_SERVER_TLS: {
		struct client_dns_server_flag_tls *flag_tls = &flags->tls;
		if (server->spki[0] != 0) {
			flag_tls->spi_len =
				dns_client_spki_decode(server->spki, (unsigned char *)flag_tls->spki, sizeof(flag_tls->spki));
			if (flag_tls->spi_len <= 0) {
				tlog(TLOG_ERROR, "decode spki failed, %s:%d", server->server, server->port);
				return -1;
			}
		}
		safe_strncpy(flag_tls->hostname, server->hostname, sizeof(flag_tls->hostname));
		safe_strncpy(flag_tls->tls_host_verify, server->tls_host_verify, sizeof(flag_tls->tls_host_verify));
		flag_tls->skip_check_cert = server->skip_check_cert;
	} break;
	case DNS_SERVER_TCP:
		break;
	default:
		return -1;
		break;
	}

	flags->type = server->type;
	flags->server_flag = server->server_flag;
	flags->result_flag = server->result_flag;
	flags->set_mark = server->set_mark;
	flags->drop_packet_latency_ms = server->drop_packet_latency_ms;
	safe_strncpy(flags->proxyname, server->proxyname, sizeof(flags->proxyname));
	safe_strncpy(flags->ifname, server->ifname, sizeof(flags->ifname));
	if (server->ipv4_ecs.enable) {
		flags->ipv4_ecs.enable = 1;
		safe_strncpy(flags->ipv4_ecs.ip, server->ipv4_ecs.ip, sizeof(flags->ipv4_ecs.ip));
		flags->ipv4_ecs.subnet = server->ipv4_ecs.subnet;
	}

	if (server->ipv6_ecs.enable) {
		flags->ipv6_ecs.enable = 1;
		safe_strncpy(flags->ipv6_ecs.ip, server->ipv6_ecs.ip, sizeof(flags->ipv6_ecs.ip));
		flags->ipv6_ecs.subnet = server->ipv6_ecs.subnet;
	}

	return 0;
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
		if (_smartdns_prepare_server_flags(&flags, &dns_conf_servers[i]) != 0) {
			tlog(TLOG_ERROR, "prepare server flags failed, %s:%d", dns_conf_servers[i].server,
				 dns_conf_servers[i].port);
			return -1;
		}

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

			if (_smartdns_prepare_server_flags(&flags, server) != 0) {
				tlog(TLOG_ERROR, "prepare server flags failed, %s:%d", server->server, server->port);
				return -1;
			}

			ret = dns_client_add_to_group(group->group_name, server->server, server->port, server->type, &flags);
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

static int _smartdns_plugin_init(void)
{
	int ret = 0;
	unsigned long i = 0;
	struct dns_conf_plugin *plugin = NULL;
	struct hlist_node *tmp = NULL;

	ret = dns_server_plugin_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "init plugin failed.");
		goto errout;
	}

	hash_for_each_safe(dns_conf_plugin_table.plugins, i, tmp, plugin, node)
	{
		ret = dns_plugin_add(plugin->file, plugin->argc, plugin->args, plugin->args_len);
		if (ret != 0) {
			goto errout;
		}
	}

	return 0;
errout:
	return -1;
}

static int _smartdns_plugin_exit(void)
{
	dns_server_plugin_exit();
	return 0;
}

static int _smartdns_create_cert(void)
{
	uid_t uid = 0;
	gid_t gid = 0;

	if (dns_conf_need_cert == 0) {
		return 0;
	}

	if (dns_conf_bind_ca_file[0] != 0 && dns_conf_bind_ca_key_file[0] != 0) {
		return 0;
	}

	conf_get_conf_fullpath("smartdns-cert.pem", dns_conf_bind_ca_file, sizeof(dns_conf_bind_ca_file));
	conf_get_conf_fullpath("smartdns-key.pem", dns_conf_bind_ca_key_file, sizeof(dns_conf_bind_ca_key_file));
	if (access(dns_conf_bind_ca_file, F_OK) == 0 && access(dns_conf_bind_ca_key_file, F_OK) == 0) {
		return 0;
	}

	if (generate_cert_key(dns_conf_bind_ca_key_file, dns_conf_bind_ca_file, NULL, 365 * 3) != 0) {
		tlog(TLOG_WARN, "Generate default ssl cert and key file failed. %s", strerror(errno));
		return -1;
	}

	int unused __attribute__((unused)) = 0;

	if (get_uid_gid(&uid, &gid) != 0) {
		return 0;
	}

	unused = chown(dns_conf_bind_ca_file, uid, gid);
	unused = chown(dns_conf_bind_ca_key_file, uid, gid);

	return 0;
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

static int _smartdns_tlog_output_syslog_callback(struct tlog_loginfo *info, const char *buff, int bufflen,
												 void *private_data)
{
	int syslog_level = LOG_INFO;
	switch (info->level) {
	case TLOG_ERROR:
		syslog_level = LOG_ERR;
		break;
	case TLOG_WARN:
		syslog_level = LOG_WARNING;
		break;
	case TLOG_NOTICE:
		syslog_level = LOG_NOTICE;
		break;
	case TLOG_INFO:
		syslog_level = LOG_INFO;
		break;
	case TLOG_DEBUG:
		syslog_level = LOG_DEBUG;
		break;
	default:
		syslog_level = LOG_INFO;
		break;
	}

	syslog(syslog_level, "%.*s", bufflen, buff);
	return bufflen;
}

static int _smartdns_init_log(void)
{
	const char *logfile = _smartdns_log_path();
	char logdir[PATH_MAX] = {0};
	int logbuffersize = 0;
	int enable_log_screen = 0;
	int ret = 0;

	if (get_system_mem_size() > 1024 * 1024 * 1024) {
		logbuffersize = 1024 * 1024;
	}

	safe_strncpy(logdir, _smartdns_log_path(), PATH_MAX);
	if (verbose_screen != 0 || dns_conf_log_console != 0 || access(dir_name(logdir), W_OK) != 0) {
		enable_log_screen = 1;
	}

	unsigned int tlog_flag = TLOG_NONBLOCK;
	if (enable_log_screen == 1) {
		tlog_flag |= TLOG_SCREEN_COLOR;
	}

	if (dns_conf_log_syslog) {
		tlog_flag |= TLOG_SEGMENT;
		tlog_flag |= TLOG_FORMAT_NO_PREFIX;
	}

	ret = tlog_init(logfile, dns_conf_log_size, dns_conf_log_num, logbuffersize, tlog_flag);
	if (ret != 0) {
		tlog(TLOG_ERROR, "start tlog failed.\n");
		goto errout;
	}

	if (enable_log_screen) {
		tlog_setlogscreen(1);
	}

	if (dns_conf_log_syslog) {
		tlog_reg_log_output_func(_smartdns_tlog_output_syslog_callback, NULL);
	}

	tlog_setlevel(dns_conf_log_level);
	if (dns_conf_log_file_mode > 0) {
		tlog_set_permission(tlog_get_root(), dns_conf_log_file_mode, dns_conf_log_file_mode);
	}

	return 0;

errout:
	return -1;
}

static int _smartdns_init_load_from_resolv(void)
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < 180 && dns_conf_server_num <= 0; i++) {
		ret = _smartdns_load_from_resolv();
		if (ret == 0) {
			continue;
		}

		/* try load from default resolv.conf file */
		if (i > 30 && strncmp(dns_resolv_file, DNS_RESOLV_FILE, MAX_LINE_LEN) != 0) {
			ret = _smartdns_load_from_default_resolv();
			if (ret == 0) {
				continue;
			}
		}

		tlog(TLOG_DEBUG, "load dns from resolv failed, retry after 1s, retry times %d.", i + 1);
		sleep(1);
	}

	if (dns_conf_server_num <= 0) {
		goto errout;
	}

	return 0;
errout:
	return -1;
}

static int _smartdns_init(void)
{
	int ret = 0;
	char str_ver[256] = {0};

	if (_smartdns_init_log() != 0) {
		tlog(TLOG_ERROR, "init log failed.");
		goto errout;
	}

	_smartdns_get_version(str_ver, sizeof(str_ver));

	tlog(TLOG_NOTICE, "smartdns starting...(Copyright (C) Nick Peng <pymumu@gmail.com>, build: %s)", str_ver);

	if (dns_timer_init() != 0) {
		tlog(TLOG_ERROR, "init timer failed.");
		goto errout;
	}

	if (_smartdns_init_ssl() != 0) {
		tlog(TLOG_ERROR, "init ssl failed.");
		goto errout;
	}

	if (_smartdns_init_load_from_resolv() != 0) {
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

	ret = _smartdns_plugin_init();
	if (ret != 0) {
		tlog(TLOG_ERROR, "init plugin failed.");
		goto errout;
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
	_smartdns_plugin_exit();
	dns_client_exit();
	proxy_exit();
	fast_ping_exit();
	dns_server_exit();
	_smartdns_destroy_ssl();
	dns_timer_destroy();
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
	const char *build_info = "";
#ifdef SMARTDNS_VERION
	build_info = SMARTDNS_VERION;
#else
	build_info = __DATE__ " " __TIME__;
#endif
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
		 "process exit with signal %d, code = %d, errno = %d, pid = %d, self = %d, pc = %#lx, addr = %#lx, build("
		 "%s %s)\n",
		 signo, siginfo->si_code, siginfo->si_errno, siginfo->si_pid, getpid(), PC, (unsigned long)siginfo->si_addr,
		 build_info, arch);
	print_stack();
	sleep(1);
	_exit(SMARTDNS_CRASH_CODE);
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
	uid_t uid = 0;
	gid_t gid = 0;
	struct stat sb;
	char logdir[PATH_MAX] = {0};
	int unused __attribute__((unused)) = 0;

	safe_strncpy(logdir, _smartdns_log_path(), PATH_MAX);
	dir_name(logdir);

	if (get_uid_gid(&uid, &gid) != 0) {
		return -1;
	}

	mkdir(logdir, 0750);
	if (stat(logdir, &sb) == 0 && sb.st_uid == uid && sb.st_gid == gid && (sb.st_mode & 0700) == 0700) {
		return 0;
	}

	if (chown(logdir, uid, gid) != 0) {
		/* disable log */
		tlog_set_maxlog_count(0);
	}

	unused = chmod(logdir, 0750);
	unused = chown(_smartdns_log_path(), uid, gid);
	return 0;
}

static int _smartdns_create_cache_dir(void)
{
	uid_t uid = 0;
	gid_t gid = 0;
	struct stat sb;
	char cache_dir[PATH_MAX] = {0};
	int unused __attribute__((unused)) = 0;

	safe_strncpy(cache_dir, dns_conf_get_cache_dir(), PATH_MAX);
	dir_name(cache_dir);

	if (get_uid_gid(&uid, &gid) != 0) {
		return -1;
	}

	mkdir(cache_dir, 0750);
	if (stat(cache_dir, &sb) == 0 && sb.st_uid == uid && sb.st_gid == gid && (sb.st_mode & 0700) == 0700) {
		return 0;
	}

	if (chown(cache_dir, uid, gid) != 0) {
		if (dns_conf_cache_file[0] == '\0') {
			safe_strncpy(dns_conf_cache_file, SMARTDNS_TMP_CACHE_FILE, sizeof(dns_conf_cache_file));
		}
	}

	unused = chmod(cache_dir, 0750);
	unused = chown(dns_conf_get_cache_dir(), uid, gid);
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
	_smartdns_create_cache_dir();

	_set_rlimit();

	if (_smartdns_create_cert() != 0) {
		tlog(TLOG_ERROR, "create cert failed.");
		return -1;
	}

	return 0;
}

static int _smartdns_child_pid = 0;
static int _smartdns_child_restart = 0;

static void _smartdns_run_monitor_sig(int sig)
{
	if (_smartdns_child_pid > 0) {
		if (sig == SIGHUP) {
			_smartdns_child_restart = 1;
			kill(_smartdns_child_pid, SIGTERM);
			return;
		}
		kill(_smartdns_child_pid, SIGTERM);
	}
	waitpid(_smartdns_child_pid, NULL, 0);

	_exit(0);
}

static smartdns_run_monitor_ret _smartdns_run_monitor(int restart_when_crash, int is_run_as_daemon)
{
	pid_t pid;
	int status;

	if (restart_when_crash == 0) {
		return SMARTDNS_RUN_MONITOR_OK;
	}

	if (is_run_as_daemon) {
		switch (daemon_run(NULL)) {
		case DAEMON_RET_CHILD_OK:
			break;
		case DAEMON_RET_PARENT_OK:
			return SMARTDNS_RUN_MONITOR_EXIT;
		default:
			return SMARTDNS_RUN_MONITOR_ERROR;
		}
	}

	daemon_kickoff(0, 1);

restart:
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed, %s\n", strerror(errno));
		return SMARTDNS_RUN_MONITOR_ERROR;
	} else if (pid == 0) {
		return SMARTDNS_RUN_MONITOR_OK;
	}

	_smartdns_child_pid = pid;

	signal(SIGTERM, _smartdns_run_monitor_sig);
	signal(SIGHUP, _smartdns_run_monitor_sig);
	while (true) {
		pid = waitpid(-1, &status, 0);
		if (pid == _smartdns_child_pid) {
			int need_restart = 0;
			char signalmsg[64] = {0};

			if (_smartdns_child_restart == 1) {
				_smartdns_child_restart = 0;
				goto restart;
			}

			if (WEXITSTATUS(status) == SMARTDNS_CRASH_CODE) {
				need_restart = 1;
			} else if (WEXITSTATUS(status) == 255) {
				fprintf(stderr, "run daemon failed, please check log.\n");
			} else if (WIFSIGNALED(status)) {
				switch (WTERMSIG(status)) {
				case SIGSEGV:
				case SIGABRT:
				case SIGBUS:
				case SIGILL:
				case SIGFPE:
					snprintf(signalmsg, sizeof(signalmsg), " with signal %d", WTERMSIG(status));
					need_restart = 1;
					break;
				default:
					break;
				}
			}

			if (need_restart == 1) {
				printf("smartdns crashed%s, restart...\n", signalmsg);
				goto restart;
			}
			break;
		}

		if (pid < 0) {
			sleep(1);
		}
	}

	return SMARTDNS_RUN_MONITOR_ERROR;
}

static void _smartdns_print_error_tip(void)
{
	char buff[4096];
	char *log_path = realpath(_smartdns_log_path(), buff);

	if (log_path != NULL && access(log_path, F_OK) == 0) {
		fprintf(stderr, "run daemon failed, please check log at %s\n", log_path);
	}
}

void smartdns_exit(int status)
{
	dns_server_stop();
	exit_status = status;
}

void smartdns_restart(void)
{
	dns_server_stop();
	exit_restart = 1;
}

static int smartdns_enter_monitor_mode(int argc, char *argv[], int no_deamon)
{
	setenv("SMARTDNS_RESTART_ON_CRASH", "1", 1);
	if (no_deamon == 1) {
		setenv("SMARTDNS_NO_DAEMON", "1", 1);
	}
	execv(argv[0], argv);
	tlog(TLOG_ERROR, "execv failed, %s", strerror(errno));
	return -1;
}

#ifdef TEST

static smartdns_post_func _smartdns_post = NULL;
static void *_smartdns_post_arg = NULL;

int smartdns_reg_post_func(smartdns_post_func func, void *arg)
{
	_smartdns_post = func;
	_smartdns_post_arg = arg;
	return 0;
}

#define smartdns_test_notify(retval) smartdns_test_notify_func(fd_notify, retval)
static void smartdns_test_notify_func(int fd_notify, uint64_t retval)
{
	/* notify parent kickoff */
	if (fd_notify > 0) {
		write(fd_notify, &retval, sizeof(retval));
	}

	if (_smartdns_post != NULL) {
		_smartdns_post(_smartdns_post_arg);
	}
}

#define smartdns_close_allfds()                                                                                        \
	if (no_close_allfds == 0) {                                                                                        \
		close_all_fd(fd_notify);                                                                                       \
	}

int smartdns_main(int argc, char *argv[], int fd_notify, int no_close_allfds)
#else
#define smartdns_test_notify(retval)
#define smartdns_close_allfds() close_all_fd(-1)
int main(int argc, char *argv[])
#endif
{
	int ret = 0;
	int is_run_as_daemon = 1;
	int opt = 0;
	char config_file[MAX_LINE_LEN];
	char pid_file[MAX_LINE_LEN];
	int is_pid_file_set = 0;
	int signal_ignore = 0;
	int restart_when_crash = getpid() == 1 ? 1 : 0;
	sigset_t empty_sigblock;
	struct stat sb;

	static struct option long_options[] = {
		{"cache-print", required_argument, NULL, 256}, {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}};

	safe_strncpy(config_file, SMARTDNS_CONF_FILE, MAX_LINE_LEN);

	if (stat("/run", &sb) == 0 && S_ISDIR(sb.st_mode)) {
		safe_strncpy(pid_file, SMARTDNS_PID_FILE, MAX_LINE_LEN);
	} else {
		safe_strncpy(pid_file, SMARTDNS_LEGACY_PID_FILE, MAX_LINE_LEN);
	}

	/* patch for Asus router:  unblock all signal*/
	sigemptyset(&empty_sigblock);
	sigprocmask(SIG_SETMASK, &empty_sigblock, NULL);
	smartdns_close_allfds();

	while ((opt = getopt_long(argc, argv, "fhc:p:SvxN:R", long_options, NULL)) != -1) {
		switch (opt) {
		case 'f':
			is_run_as_daemon = 0;
			break;
		case 'c':
			if (full_path(config_file, sizeof(config_file), optarg) != 0) {
				snprintf(config_file, sizeof(config_file), "%s", optarg);
			}
			break;
		case 'p':
			if (strncmp(optarg, "-", 2) == 0 || full_path(pid_file, sizeof(pid_file), optarg) != 0) {
				snprintf(pid_file, sizeof(pid_file), "%s", optarg);
				is_pid_file_set = 1;
			}
			break;
		case 'R':
			restart_when_crash = 1;
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
			return 0;
		case 256:
			return dns_cache_print(optarg);
			break;
		default:
			fprintf(stderr, "unknown option, please run %s -h for help.\n", argv[0]);
			return 1;
		}
	}

	if (getenv("SMARTDNS_RESTART_ON_CRASH") != NULL) {
		restart_when_crash = 1;
		unsetenv("SMARTDNS_RESTART_ON_CRASH");
	}

	if (getenv("SMARTDNS_NO_DAEMON") != NULL) {
		is_run_as_daemon = 0;
		unsetenv("SMARTDNS_NO_DAEMON");
	}

	smartdns_run_monitor_ret init_ret = _smartdns_run_monitor(restart_when_crash, is_run_as_daemon);
	if (init_ret != SMARTDNS_RUN_MONITOR_OK) {
		if (init_ret == SMARTDNS_RUN_MONITOR_EXIT) {
			return 0;
		}
		return 1;
	}

	srand(time(NULL));

	tlog_set_early_printf(1, 1, 1);
	tlog_reg_early_printf_output_callback(_smartdns_tlog_output_syslog_callback, 1, NULL);

	ret = dns_server_load_conf(config_file);
	if (ret != 0) {
		fprintf(stderr, "load config failed.\n");
		goto errout;
	}

	if (dns_restart_on_crash && restart_when_crash == 0) {
		return smartdns_enter_monitor_mode(argc, argv, dns_no_daemon || !is_run_as_daemon);
	}

	if (dns_no_daemon || restart_when_crash) {
		is_run_as_daemon = 0;
	}

	if (is_run_as_daemon) {
		int child_status = -1;
		switch (daemon_run(&child_status)) {
		case DAEMON_RET_CHILD_OK:
			break;
		case DAEMON_RET_PARENT_OK: {
			if (child_status != 0 && child_status != -3) {
				_smartdns_print_error_tip();
			}

			return child_status;
		} break;
		case DAEMON_RET_ERR:
		default:
			fprintf(stderr, "run daemon failed.\n");
			goto errout;
		}
	}

	if (signal_ignore == 0) {
		_reg_signal();
	}

	if (is_pid_file_set == 0) {
		char pid_file_path[MAX_LINE_LEN];
		safe_strncpy(pid_file_path, pid_file, MAX_LINE_LEN);
		dir_name(pid_file_path);

		if (access(pid_file_path, W_OK) != 0) {
			dns_no_pidfile = 1;
		}
	}

	if (strncmp(pid_file, "-", 2) != 0 && dns_no_pidfile == 0 && create_pid_file(pid_file) != 0) {
		ret = -3;
		goto errout;
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, _sig_exit);
	signal(SIGTERM, _sig_exit);

	ret = _smartdns_init_pre();
	if (ret != 0) {
		fprintf(stderr, "init failed.\n");
		goto errout;
	}

	drop_root_privilege();

	ret = _smartdns_init();
	if (ret != 0) {
		usleep(100000);
		goto errout;
	}

	if (is_run_as_daemon) {
		ret = daemon_kickoff(0, dns_conf_log_console | dns_conf_audit_console | verbose_screen);
		if (ret != 0) {
			goto errout;
		}
	} else if (dns_conf_log_console == 0 && dns_conf_audit_console == 0 && verbose_screen == 0) {
		daemon_close_stdfds();
	}

	smartdns_test_notify(1);
	ret = _smartdns_run();
	if (ret == 0 && exit_status != 0) {
		ret = exit_status;
	}

	if (exit_restart == 0) {
		tlog(TLOG_INFO, "smartdns exit...");
		_smartdns_exit();
	} else {
		tlog(TLOG_INFO, "smartdns restart...");
		_smartdns_exit();
		if (restart_when_crash == 0) {
			execve(argv[0], argv, environ);
		}
	}
	return ret;
errout:
	if (is_run_as_daemon) {
		daemon_kickoff(ret, dns_conf_log_console | dns_conf_audit_console | verbose_screen);
	} else if (dns_conf_log_console == 0 && dns_conf_audit_console == 0 && verbose_screen == 0) {
		_smartdns_print_error_tip();
	}
	smartdns_test_notify(2);
	_smartdns_exit();
	return ret;
}
