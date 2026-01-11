/*
 * firewall.c - Firewall rules management for smartdns
 */

#include "firewall.h"
#include "../dns_conf/ipset.h"
#include "../dns_conf/nftset.h"
#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

// Function prototypes for internal functions
int _setup_iptables_redirect_rules(const char *ip, const char *port, int so_mark, int is_ipv6,
								   struct dns_tproxy_server_conf *t_conf);
int _setup_iptables_tproxy_rules(const char *set_name, const char *ip, const char *port, int is_ipv6, int udp_support,
								 int so_mark, struct dns_tproxy_server_conf *t_conf);
void _cleanup_iptables_tproxy_rules(struct dns_tproxy_server_conf *t_conf);
void _cleanup_iptables_redirect_rules(struct dns_tproxy_server_conf *t_conf);
static int _prepare_firewall_names(struct dns_tproxy_server_conf *t_conf);

// clang-format off
const char *SCRIPT_NFTABLES_SETUP =
	"set -e\n"
	"nft add table ${family} ${table_name}\n"
	"nft add set ${family} ${table_name} ${set_name} { type ${addr_type}; flags interval; auto-merge; }\n"
	"nft add chain ${family} ${table_name} ${chain_name} { type filter hook prerouting priority mangle; }\n"
	"nft add rule ${family} ${table_name} ${chain_name} meta l4proto tcp ${daddr} @${set_name} tproxy to ${tproxy_addr} mark set ${mark}\n"
	// Optional UDP
	"if [ \"${udp_support}\" = \"1\" ]; then\n"
	"    nft add rule ${family} ${table_name} ${chain_name} meta l4proto udp ${daddr} @${set_name} tproxy to ${tproxy_addr} mark set ${mark}\n"
	"fi\n"
	// Output Chain (Conditional)
	"if [ \"${output_chain_enable}\" = \"1\" ]; then\n"
	"    OUTPUT_CHAIN=\"${chain_name}_output\"\n"
	"    nft add chain ${family} ${table_name} ${OUTPUT_CHAIN} { type filter hook output priority mangle; }\n"
	"    nft add rule ${family} ${table_name} ${OUTPUT_CHAIN} meta l4proto tcp ${daddr} @${set_name} tproxy to ${tproxy_addr} mark set ${mark}\n"
	"    if [ \"${udp_support}\" = \"1\" ]; then\n"
	"        nft add rule ${family} ${table_name} ${OUTPUT_CHAIN} meta l4proto udp ${daddr} @${set_name} tproxy to ${tproxy_addr} mark set ${mark}\n"
	"    fi\n"
	"fi\n";

const char *SCRIPT_NFTABLES_CLEANUP =
	"nft delete table ${family} ${table_name} 2>/dev/null || true\n";

const char *SCRIPT_IPTABLES_REDIRECT_SETUP =
	"set -e\n"
	"ipset create ${set_name} hash:net family ${family} timeout 3600 -exist\n"
	// PREROUTING
	"${iptables_cmd} -t nat -C PREROUTING -p tcp -m set --match-set ${set_name} dst -j REDIRECT --to-ports ${port} 2>/dev/null || \\\n"
	"${iptables_cmd} -t nat -I PREROUTING -p tcp -m set --match-set ${set_name} dst -j REDIRECT --to-ports ${port}\n"
	// OUTPUT (Conditional)
	"if [ \"${output_chain_enable}\" = \"1\" ]; then\n"
	// Logic to handle mark exclude. Since simple variable replacement doesn't support conditional string format easily without more advanced templates, 
	// we pass the raw mark hex. But we need to know IF we should exclude.
	// Actually, easier to let shell handle it:
	"    MARK_OPT=\"\"\n"
	"    if [ \"${mark}\" != \"0\" ]; then MARK_OPT=\"-m mark ! --mark ${mark}\"; fi\n"
	"    ${iptables_cmd} -t nat -C OUTPUT -p tcp -m set --match-set ${set_name} dst ${MARK_OPT} -j REDIRECT --to-ports ${port} 2>/dev/null || \\\n"
	"    ${iptables_cmd} -t nat -I OUTPUT -p tcp -m set --match-set ${set_name} dst ${MARK_OPT} -j REDIRECT --to-ports ${port}\n"
	"fi\n";

const char *SCRIPT_IPTABLES_REDIRECT_CLEANUP =
	"${iptables_cmd} -t nat -D PREROUTING -p tcp -m set --match-set ${set_name} dst -j REDIRECT --to-ports ${port} 2>/dev/null || true\n"
	"MARK_OPT=\"\"\n"
	"if [ \"${mark}\" != \"0\" ]; then MARK_OPT=\"-m mark ! --mark ${mark}\"; fi\n"
	"${iptables_cmd} -t nat -D OUTPUT -p tcp -m set --match-set ${set_name} dst ${MARK_OPT} -j REDIRECT --to-ports ${port} 2>/dev/null || true\n"
	"ipset destroy ${set_name} 2>/dev/null || true\n";

const char *SCRIPT_IPTABLES_TPROXY_SETUP =
	"set -e\n"
	"ipset create ${set_name} hash:net family ${family} timeout 3600 -exist\n"
	// IP Rule: Avoid duplicates by checking existence
	"if ! ip ${family_opt} rule show | grep -q 'fwmark ${mark}'; then\n"
	"    ip ${family_opt} rule add fwmark ${mark} lookup ${mark}\n"
	"fi\n"
	// IP Route: Avoid duplicates
	"if ! ip ${family_opt} route show table ${mark} 2>/dev/null | grep -q 'local'; then\n"
	"    ip ${family_opt} route add local ${local_range} dev lo table ${mark}\n"
	"fi\n"
	// Define Helper Args
	"TPROXY_ARGS=\"--on-port ${port} --on-ip ${tproxy_ip} --tproxy-mark ${mark}/0xffffffff\"\n"
	// Iptables (TCP)
	"${iptables_cmd} -t mangle -C PREROUTING -p tcp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || \\\n"
	"${iptables_cmd} -t mangle -A PREROUTING -p tcp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS}\n"
	// Optional UDP
	"if [ \"${udp_support}\" = \"1\" ]; then\n"
	"    ${iptables_cmd} -t mangle -C PREROUTING -p udp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || \\\n"
	"    ${iptables_cmd} -t mangle -A PREROUTING -p udp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS}\n"
	"fi\n"
	// Output Chain (Conditional)
	"if [ \"${output_chain_enable}\" = \"1\" ]; then\n"
	"    ${iptables_cmd} -t mangle -C OUTPUT -p tcp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || \\\n"
	"    ${iptables_cmd} -t mangle -A OUTPUT -p tcp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS}\n"
	"    if [ \"${udp_support}\" = \"1\" ]; then\n"
	"        ${iptables_cmd} -t mangle -C OUTPUT -p udp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || \\\n"
	"        ${iptables_cmd} -t mangle -A OUTPUT -p udp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS}\n"
	"    fi\n"
	"fi\n";

const char *SCRIPT_IPTABLES_TPROXY_CLEANUP =
	// Define Helper Args
	"TPROXY_ARGS=\"--on-port ${port} --on-ip ${tproxy_ip} --tproxy-mark ${mark}/0xffffffff\"\n"
	// Delete rules
	"${iptables_cmd} -t mangle -D PREROUTING -p tcp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || true\n"
	"${iptables_cmd} -t mangle -D PREROUTING -p udp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || true\n"
	"${iptables_cmd} -t mangle -D OUTPUT -p tcp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || true\n"
	"${iptables_cmd} -t mangle -D OUTPUT -p udp -m set --match-set ${set_name} dst -j TPROXY ${TPROXY_ARGS} 2>/dev/null || true\n"
	"ipset destroy ${set_name} 2>/dev/null || true\n"
	"ip ${family_opt} route del local ${local_range} dev lo table ${mark} 2>/dev/null || true\n"
	"ip ${family_opt} rule del fwmark ${mark} lookup ${mark} 2>/dev/null || true\n";
// clang-format on

int firewall_get_ip_port(const char *server_str, char *ip, size_t ip_size, char *port, size_t port_size)
{
	int port_int;

	if (parse_ip(server_str, ip, &port_int) != 0) {
		if (ip[0] != '\0') {
			tlog(TLOG_ERROR, "invalid proxy server address: %s", server_str);
			return -1;
		}
		safe_strncpy(ip, "[::1]", ip_size);
	}
	snprintf(port, port_size, "%d", port_int);
	return 0;
}

int _parse_tproxy_ip(const char *ip, const char *port, int is_ipv6, char *tproxy_addr, size_t addr_size)
{
	char ip_check[MAX_IP_LEN];
	int port_check = -1;

	// Parse IP address and port
	if (parse_ip(ip, ip_check, &port_check) != 0) {
		if (port_check != -1 && ip_check[0] == '\0') {
			// Port-only format like ":1088"
			snprintf(ip_check, sizeof(ip_check), "%s", is_ipv6 ? "::" : "0.0.0.0");
		} else {
			return -1;
		}
	}

	// For IPv6 rules, convert IPv4 loopback to IPv6
	if (is_ipv6 && strcmp(ip_check, "127.0.0.1") == 0) {
		snprintf(ip_check, sizeof(ip_check), "%s", "::1");
	}

	// For IPv4 rules, convert IPv6 loopback to IPv4
	if (!is_ipv6 && strcmp(ip_check, "::1") == 0) {
		snprintf(ip_check, sizeof(ip_check), "%s", "127.0.0.1");
	}

	// Copy the parsed IP to output
	snprintf(tproxy_addr, addr_size, "%s", ip_check);
	return 0;
}

struct script_param {
	const char *key;
	const char *value;
};

static const char *_lookup_param(const struct script_param *params, size_t param_count, const char *key, size_t key_len)
{
	for (size_t i = 0; i < param_count; i++) {
		if (strncmp(params[i].key, key, key_len) == 0 && params[i].key[key_len] == '\0') {
			return params[i].value;
		}
	}
	return NULL;
}

static int _resolve_script_params(const char *template, const struct script_param *params, size_t param_count,
								  char *output, size_t output_size)
{
	const char *str = template;
	size_t len = 0;

	while (*str && len < output_size - 1) {
		if (*str == '$' && *(str + 1) == '{') {
			const char *end = strchr(str + 2, '}');
			if (end) {
				size_t key_len = end - (str + 2);
				const char *val = _lookup_param(params, param_count, str + 2, key_len);
				if (val) {
					size_t val_len = strlen(val);
					if (len + val_len >= output_size - 1) {
						tlog(TLOG_ERROR, "script buffer overflow");
						return -1;
					}
					memcpy(output + len, val, val_len);
					len += val_len;
					str = end + 1;
					continue;
				}
			}
		}
		output[len++] = *str++;
	}
	output[len] = '\0';
	return 0;
}

void _construct_tproxy_addr(const char *ip, const char *port, int is_ipv6, char *tproxy_addr, size_t addr_size)
{
	// Always use :port to preserve original destination address which is required for TProxy
	snprintf(tproxy_addr, addr_size, ":%s", port);
}

static int _run_shell_script_wrap(const char *script, int timeout)
{
#ifdef DEBUG
	tlog(TLOG_DEBUG, "executing script (timeout %d): %s", timeout, script);
#endif
	return run_shell_script(script, timeout);
}

static void _cleanup_nftables_family(const char *family, const char *table_name)
{
	if (table_name == NULL)
		return;
	char script[4096];
	struct script_param params[] = {{"family", family}, {"table_name", table_name}};
	if (_resolve_script_params(SCRIPT_NFTABLES_CLEANUP, params, sizeof(params) / sizeof(params[0]), script,
							   sizeof(script)) == 0) {
		_run_shell_script_wrap(script, 3000);
	}
}

int _setup_nftables_rules(const char *table_name, const char *set_name, const char *ip, const char *port, int is_ipv6,
						  int udp_support, int so_mark, struct dns_tproxy_server_conf *t_conf)
{
	char tproxy_ip[128];
	char tproxy_addr[256];
	char chain_name[256];
	char mark_str[32];
	char udp_support_str[2];
	char output_chain_enable_str[2];
	char script[4096];

	const char *ip_family = is_ipv6 ? "ip6" : "ip";
	const char *addr_type = is_ipv6 ? "ipv6_addr" : "ipv4_addr";
	const char *daddr = is_ipv6 ? "ip6 daddr" : "ip daddr";

	// Get nftset from pre-prepared configuration
	const struct dns_nftset_rule *nftset;
	if (is_ipv6) {
		nftset = (t_conf->nftset_names.ip6_enable) ? &t_conf->nftset_names.ip6 : NULL;
	} else {
		nftset = (t_conf->nftset_names.ip_enable) ? &t_conf->nftset_names.ip : NULL;
	}
	if (nftset == NULL) {
		tlog(TLOG_ERROR, "nftset not prepared for %s", ip_family);
		return -1;
	}

	// Clean up existing rules first (only for this family)
	_cleanup_nftables_family(ip_family, table_name);

	// Parse IP address
	if (_parse_tproxy_ip(ip, port, is_ipv6, tproxy_ip, sizeof(tproxy_ip)) != 0) {
		return -1;
	}

	// Construct tproxy target address
	_construct_tproxy_addr(tproxy_ip, port, is_ipv6, tproxy_addr, sizeof(tproxy_addr));
	snprintf(chain_name, sizeof(chain_name), "%s", t_conf->name);
	snprintf(mark_str, sizeof(mark_str), "%d", so_mark);
	snprintf(udp_support_str, sizeof(udp_support_str), "%d", udp_support);
	snprintf(output_chain_enable_str, sizeof(output_chain_enable_str), "%d", t_conf->output_chain_enable);

	struct script_param params[] = {{"family", ip_family},
									{"table_name", table_name},
									{"set_name", set_name},
									{"chain_name", chain_name},
									{"addr_type", addr_type},
									{"daddr", daddr},
									{"tproxy_addr", tproxy_addr},
									{"mark", mark_str},
									{"udp_support", udp_support_str},
									{"output_chain_enable", output_chain_enable_str}};

	if (_resolve_script_params(SCRIPT_NFTABLES_SETUP, params, sizeof(params) / sizeof(params[0]), script,
							   sizeof(script)) != 0) {
		return -1;
	}

	return _run_shell_script_wrap(script, 3000);
}

int _setup_iptables_redirect_rules(const char *ip, const char *port, int so_mark, int is_ipv6,
								   struct dns_tproxy_server_conf *t_conf)
{
	char mark_str[32];
	char output_chain_enable_str[2];
	char script[4096];

	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";
	const char *family = is_ipv6 ? "inet6" : "inet";

	// Get ipset name from pre-prepared configuration
	const char *ipset_name;
	if (is_ipv6) {
		ipset_name = (t_conf->ipset_names.ipv6_enable) ? t_conf->ipset_names.ipv6.ipsetname : NULL;
	} else {
		ipset_name = (t_conf->ipset_names.ipv4_enable) ? t_conf->ipset_names.ipv4.ipsetname : NULL;
	}
	if (ipset_name == NULL) {
		tlog(TLOG_ERROR, "ipset not prepared for %s", t_conf->name);
		return -1;
	}

	// Create ipset
	// Note: We don't need explicit _setup_ipset call anymore, the script handles it.

	snprintf(mark_str, sizeof(mark_str), "0x%x", so_mark);
	snprintf(output_chain_enable_str, sizeof(output_chain_enable_str), "%d", t_conf->output_chain_enable);

	struct script_param params[] = {
		{"set_name", ipset_name}, {"family", family}, {"iptables_cmd", iptables_cmd},
		{"port", port},           {"mark", mark_str}, {"output_chain_enable", output_chain_enable_str}};

	if (_resolve_script_params(SCRIPT_IPTABLES_REDIRECT_SETUP, params, sizeof(params) / sizeof(params[0]), script,
							   sizeof(script)) != 0) {
		return -1;
	}

	return _run_shell_script_wrap(script, 3000);
}

int _setup_iptables_tproxy_rules(const char *set_name, const char *ip, const char *port, int is_ipv6, int udp_support,
								 int so_mark, struct dns_tproxy_server_conf *t_conf)
{
	char tproxy_ip[64];
	char mark_str[32];
	char udp_support_str[2];
	char output_chain_enable_str[2];
	char script[4096];

	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";
	const char *family = is_ipv6 ? "inet6" : "inet";
	const char *family_opt = is_ipv6 ? "-6" : "";
	const char *local_range = is_ipv6 ? "::/0" : "0.0.0.0/0";

	// Get ipset name from pre-prepared configuration
	const char *ipset_name;
	if (is_ipv6) {
		ipset_name = (t_conf->ipset_names.ipv6_enable) ? t_conf->ipset_names.ipv6.ipsetname : NULL;
	} else {
		ipset_name = (t_conf->ipset_names.ipv4_enable) ? t_conf->ipset_names.ipv4.ipsetname : NULL;
	}
	if (ipset_name == NULL) {
		tlog(TLOG_ERROR, "ipset not prepared for %s", set_name);
		return -1;
	}

	// Parse IP address
	if (_parse_tproxy_ip(ip, port, is_ipv6, tproxy_ip, sizeof(tproxy_ip)) != 0) {
		return -1;
	}

	snprintf(mark_str, sizeof(mark_str), "0x%x", so_mark);
	snprintf(udp_support_str, sizeof(udp_support_str), "%d", udp_support);
	snprintf(output_chain_enable_str, sizeof(output_chain_enable_str), "%d", t_conf->output_chain_enable);

	struct script_param params[] = {{"set_name", set_name},
									{"family", family},
									{"family_opt", family_opt},
									{"mark", mark_str},
									{"local_range", local_range},
									{"iptables_cmd", iptables_cmd},
									{"port", port},
									{"tproxy_ip", tproxy_ip},
									{"udp_support", udp_support_str},
									{"output_chain_enable", output_chain_enable_str}};

	if (_resolve_script_params(SCRIPT_IPTABLES_TPROXY_SETUP, params, sizeof(params) / sizeof(params[0]), script,
							   sizeof(script)) != 0) {
		return -1;
	}

	return _run_shell_script_wrap(script, 3000);
}

void _cleanup_nftables_rules(struct dns_tproxy_server_conf *t_conf)
{
	if (t_conf->nftset_names.ip.nfttablename) {
		_cleanup_nftables_family("ip", t_conf->nftset_names.ip.nfttablename);
	}
	if (t_conf->nftset_names.ip6.nfttablename) {
		_cleanup_nftables_family("ip6", t_conf->nftset_names.ip6.nfttablename);
	}
}

static void _cleanup_iptables_tproxy_family(int is_ipv6, const char *server_ip, const char *port, int so_mark,
											const struct dns_ipset_rule *ipset_conf)
{
	char tproxy_ip[64];

	char mark_str[32];
	char script[4096];
	const char *ipset_name = ipset_conf->ipsetname;

	if (!ipset_name) {
		return;
	}

	if (_parse_tproxy_ip(server_ip, port, is_ipv6, tproxy_ip, sizeof(tproxy_ip)) != 0) {
		return;
	}

	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";
	const char *family_opt = is_ipv6 ? "-6" : "";
	const char *local_range = is_ipv6 ? "::/0" : "0.0.0.0/0";

	snprintf(mark_str, sizeof(mark_str), "0x%x", so_mark);

	struct script_param params[] = {{"set_name", ipset_name},     {"family_opt", family_opt},     {"mark", mark_str},
									{"local_range", local_range}, {"iptables_cmd", iptables_cmd}, {"port", port},
									{"tproxy_ip", tproxy_ip}};

	if (_resolve_script_params(SCRIPT_IPTABLES_TPROXY_CLEANUP, params, sizeof(params) / sizeof(params[0]), script,
							   sizeof(script)) == 0) {
		// For cleanup, we ignore failures (firewall might already be clean)
		_run_shell_script_wrap(script, 3000);
	}
}

void _cleanup_iptables_tproxy_rules(struct dns_tproxy_server_conf *t_conf)
{
	char ip[64];
	char port[16];

	if (firewall_get_ip_port(t_conf->server, ip, sizeof(ip), port, sizeof(port)) != 0) {
		tlog(TLOG_ERROR, "failed to get ip and port for %s", t_conf->name);
		return;
	}

	_cleanup_iptables_tproxy_family(0, ip, port, t_conf->so_mark, &t_conf->ipset_names.ipv4);
	_cleanup_iptables_tproxy_family(1, ip, port, t_conf->so_mark, &t_conf->ipset_names.ipv6);
}

static void _cleanup_iptables_redirect_family(int is_ipv6, int so_mark, const char *port, int output_chain_enable,
											  const struct dns_ipset_rule *ipset_conf)
{
	char mark_str[32];
	char script[4096];
	const char *ipset_name = ipset_conf->ipsetname;

	if (!ipset_name) {
		return;
	}

	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";

	snprintf(mark_str, sizeof(mark_str), "0x%x", so_mark);

	struct script_param params[] = {
		{"set_name", ipset_name}, {"iptables_cmd", iptables_cmd}, {"port", port}, {"mark", mark_str}};

	if (_resolve_script_params(SCRIPT_IPTABLES_REDIRECT_CLEANUP, params, sizeof(params) / sizeof(params[0]), script,
							   sizeof(script)) == 0) {
		_run_shell_script_wrap(script, 3000);
	}
}

void _cleanup_iptables_redirect_rules(struct dns_tproxy_server_conf *t_conf)
{
	char ip[64];
	char port[16];

	if (firewall_get_ip_port(t_conf->server, ip, sizeof(ip), port, sizeof(port)) != 0) {
		tlog(TLOG_ERROR, "failed to get ip and port for %s", t_conf->name);
		return;
	}

	_cleanup_iptables_redirect_family(0, t_conf->so_mark, port, t_conf->output_chain_enable, &t_conf->ipset_names.ipv4);
	_cleanup_iptables_redirect_family(1, t_conf->so_mark, port, t_conf->output_chain_enable, &t_conf->ipset_names.ipv6);
}

void _cleanup_iptables_rules(struct dns_tproxy_server_conf *t_conf)
{
	if (t_conf->firewall_type == FIREWALL_IPTABLES_REDIRECT) {
		_cleanup_iptables_redirect_rules(t_conf);
	} else {
		_cleanup_iptables_tproxy_rules(t_conf);
	}
}

static int _prepare_firewall_names(struct dns_tproxy_server_conf *t_conf)
{
	if (t_conf->firewall_type == FIREWALL_NFTABLES) {
		// For nftables, table_name is "smartdns", set_name is t_conf->name
		const struct dns_nftset_name *nftset_ipv4 = _dns_conf_get_nftable("ip", "smartdns", t_conf->name);
		if (nftset_ipv4) {
			t_conf->nftset_names.ip_enable = 1;
			t_conf->nftset_names.ip.familyname = nftset_ipv4->nftfamilyname;
			t_conf->nftset_names.ip.nfttablename = nftset_ipv4->nfttablename;
			t_conf->nftset_names.ip.nftsetname = nftset_ipv4->nftsetname;
		}
		const struct dns_nftset_name *nftset_ipv6 = _dns_conf_get_nftable("ip6", "smartdns", t_conf->name);
		if (nftset_ipv6) {
			t_conf->nftset_names.ip6_enable = 1;
			t_conf->nftset_names.ip6.familyname = nftset_ipv6->nftfamilyname;
			t_conf->nftset_names.ip6.nfttablename = nftset_ipv6->nfttablename;
			t_conf->nftset_names.ip6.nftsetname = nftset_ipv6->nftsetname;
		}
	} else if (t_conf->firewall_type == FIREWALL_IPTABLES_REDIRECT ||
			   t_conf->firewall_type == FIREWALL_IPTABLES_TPROXY || t_conf->firewall_type == FIREWALL_IPTABLES) {
		char ipv4_set_name[64];
		char ipv6_set_name[64];
		snprintf(ipv4_set_name, sizeof(ipv4_set_name), "smartdns_ipv4_%s", t_conf->name);
		snprintf(ipv6_set_name, sizeof(ipv6_set_name), "smartdns_ipv6_%s", t_conf->name);
		const char *ipset_ipv4 = _dns_conf_get_ipset(ipv4_set_name);
		if (ipset_ipv4) {
			t_conf->ipset_names.ipv4_enable = 1;
			t_conf->ipset_names.ipv4.ipsetname = ipset_ipv4;
		}
		const char *ipset_ipv6 = _dns_conf_get_ipset(ipv6_set_name);
		if (ipset_ipv6) {
			t_conf->ipset_names.ipv6_enable = 1;
			t_conf->ipset_names.ipv6.ipsetname = ipset_ipv6;
		}
	}
	return 0;
}

static int _run_custom_script(const char *script_template, struct dns_tproxy_server_conf *t_conf, const char *ip,
							  const char *port)
{
	char cmd[4096];
	char setname[256];
	char mark_str[32];
	char udp_support_str[2];
	char ipv6_str[2];

	snprintf(setname, sizeof(setname), "%s", t_conf->name);
	snprintf(mark_str, sizeof(mark_str), "%d", t_conf->so_mark);
	snprintf(udp_support_str, sizeof(udp_support_str), "%d", t_conf->udp_support);

	for (int i = 0; i < 2; i++) {
		int is_ipv6 = i;
		snprintf(ipv6_str, sizeof(ipv6_str), "%d", is_ipv6);

		struct script_param params[] = {{"so_mark", mark_str}, {"setname", setname},  {"ip", ip},
										{"port", port},        {"is_ipv6", ipv6_str}, {"udp_support", udp_support_str}};

		if (_resolve_script_params(script_template, params, sizeof(params) / sizeof(params[0]), cmd, sizeof(cmd)) ==
			0) {
			if (_run_shell_script_wrap(cmd, 3000) != 0) {
				tlog(TLOG_ERROR, "failed to execute custom script for %s (IPv%d)", t_conf->name, is_ipv6 ? 6 : 4);
				return -1;
			}
		}
	}
	return 0;
}

static int _setup_builtin_rules(struct dns_tproxy_server_conf *t_conf, const char *ip, const char *port)
{
	if (t_conf->firewall_type == FIREWALL_NFTABLES) {

		_cleanup_nftables_rules(t_conf);

		// IPv4
		if (_setup_nftables_rules("smartdns", t_conf->name, ip, port, 0, t_conf->udp_support, t_conf->so_mark,
								  t_conf) != 0) {
			tlog(TLOG_ERROR, "failed to setup nftables rules for %s", t_conf->name);
			return -1;
		}

		// IPv6
		if (_setup_nftables_rules("smartdns", t_conf->name, ip, port, 1, t_conf->udp_support, t_conf->so_mark,
								  t_conf) != 0) {
			tlog(TLOG_ERROR, "failed to setup nftables rules for %s", t_conf->name);
			return -1;
		}
	} else if (t_conf->firewall_type == FIREWALL_IPTABLES_REDIRECT) {
		// REDIRECT mode - separate rules for IPv4 and IPv6
		// IPv4
		if (_setup_iptables_redirect_rules(ip, port, t_conf->so_mark, 0, t_conf) != 0) {
			tlog(TLOG_ERROR, "failed to setup iptables redirect rules for %s (IPv4)", t_conf->name);
			return -1;
		}

		// IPv6
		if (_setup_iptables_redirect_rules(ip, port, t_conf->so_mark, 1, t_conf) != 0) {
			tlog(TLOG_ERROR, "failed to setup iptables redirect rules for %s (IPv6)", t_conf->name);
			return -1;
		}
	} else if (t_conf->firewall_type == FIREWALL_IPTABLES_TPROXY || t_conf->firewall_type == FIREWALL_IPTABLES) {
		// IPv4
		if (_setup_iptables_tproxy_rules(t_conf->ipset_names.ipv4.ipsetname, ip, port, 0, t_conf->udp_support,
										 t_conf->so_mark, t_conf) != 0) {
			tlog(TLOG_ERROR, "failed to setup iptables tproxy rules for %s", t_conf->name);
			return -1;
		}

		// IPv6
		if (_setup_iptables_tproxy_rules(t_conf->ipset_names.ipv6.ipsetname, ip, port, 1, t_conf->udp_support,
										 t_conf->so_mark, t_conf) != 0) {
			tlog(TLOG_ERROR, "failed to setup iptables tproxy rules for %s", t_conf->name);
			return -1;
		}
	}

	return 0;
}

int firewall_setup_rules(struct dns_tproxy_server_conf *t_conf)
{
	char ip[64];
	char port[16];

	if (firewall_get_ip_port(t_conf->server, ip, sizeof(ip), port, sizeof(port)) != 0) {
		return -1;
	}

	// Initialize firewall set names only for built-in rules
	memset(&t_conf->nftset_names, 0, sizeof(t_conf->nftset_names));
	memset(&t_conf->ipset_names, 0, sizeof(t_conf->ipset_names));

	if (_prepare_firewall_names(t_conf) != 0) {
		return -1;
	}

	// Check for custom rules first - these don't need firewall type initialization
	if (t_conf->rule_script[0] != '\0') {
		// Execute custom script
		tlog(TLOG_INFO, "executing custom rule script %s for %s", t_conf->rule_script, t_conf->name);
		// Construct the "setup" command template for compatibility with old script format
		// Old format was: script setup mark setname ip port ipv6 udp_support


		// Need to pass the script path itself as a param for this special case
		// Or simpler: just use _run_custom_script but we need to inject the script path logic.
		// Actually, the user wants deduplication.
		// Let's create a temporary template buffer.
		char script_cmd_template[4096];
		snprintf(script_cmd_template, sizeof(script_cmd_template),
				 "%s setup ${so_mark} ${setname} ${ip} ${port} ${is_ipv6} ${udp_support}", t_conf->rule_script);

		return _run_custom_script(script_cmd_template, t_conf, ip, port);
	} else if (t_conf->start_rule[0] != '\0') {
		// Execute custom start command
		return _run_custom_script(t_conf->start_rule, t_conf, ip, port);
	} else if (t_conf->no_rules || t_conf->firewall_type == FIREWALL_NONE) {
		// Skip built-in rules
		return 0;
	} else {
		return _setup_builtin_rules(t_conf, ip, port);
	}

	return 0;
}

static void _cleanup_builtin_rules(struct dns_tproxy_server_conf *t_conf)
{
	if (t_conf->firewall_type == FIREWALL_NFTABLES) {
		// nftables
		_cleanup_nftables_rules(t_conf);
	} else if (t_conf->firewall_type == FIREWALL_IPTABLES || t_conf->firewall_type == FIREWALL_IPTABLES_TPROXY ||
			   t_conf->firewall_type == FIREWALL_IPTABLES_REDIRECT) {
		// iptables
		_cleanup_iptables_rules(t_conf);
	}
}

int firewall_cleanup_rules(struct dns_tproxy_server_conf *t_conf)
{
	char ip[64];
	char port[16];

	tlog(TLOG_DEBUG, "cleaning up firewall rules for %s", t_conf->name);

	if (firewall_get_ip_port(t_conf->server, ip, sizeof(ip), port, sizeof(port)) != 0) {
		return 0;
	}

	// Check for custom cleanup rules first
	if (t_conf->rule_script[0] != '\0') {
		// Execute custom script cleanup
		tlog(TLOG_INFO, "executing custom script cleanup %s for %s", t_conf->rule_script, t_conf->name);
		char script_cmd_template[4096];
		snprintf(script_cmd_template, sizeof(script_cmd_template),
				 "%s cleanup ${so_mark} ${setname} ${ip} ${port} ${is_ipv6} ${udp_support}", t_conf->rule_script);
		_run_custom_script(script_cmd_template, t_conf, ip, port);
		return 0;
	} else if (t_conf->stop_rule[0] != '\0') {
		// Execute custom stop command
		_run_custom_script(t_conf->stop_rule, t_conf, ip, port);
		return 0;
	} else if (t_conf->no_rule_clean) {
		// Skip built-in rules cleanup
		return 0;
	}

	_cleanup_builtin_rules(t_conf);

	return 0;
}