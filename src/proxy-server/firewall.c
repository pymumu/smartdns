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

static void _firewall_replace_rule_params(char *command, size_t command_size, const char *setname, int so_mark,
										  const char *ip, const char *port, int is_ipv6, int udp_support)
{
	char temp[4096];
	char *pos = command;
	char *dest = temp;
	size_t remaining = sizeof(temp) - 1;

	while (*pos && remaining > 0) {
		if (strncmp(pos, "${so_mark}", 10) == 0) {
			int len = snprintf(dest, remaining, "%d", so_mark);
			dest += len;
			remaining -= len;
			pos += 10;
		} else if (strncmp(pos, "${setname}", 10) == 0) {
			int len = snprintf(dest, remaining, "%s", setname);
			dest += len;
			remaining -= len;
			pos += 10;
		} else if (strncmp(pos, "${ip}", 5) == 0) {
			int len = snprintf(dest, remaining, "%s", ip);
			dest += len;
			remaining -= len;
			pos += 5;
		} else if (strncmp(pos, "${port}", 7) == 0) {
			int len = snprintf(dest, remaining, "%s", port);
			dest += len;
			remaining -= len;
			pos += 7;
		} else if (strncmp(pos, "${is_ipv6}", 10) == 0) {
			int len = snprintf(dest, remaining, "%d", is_ipv6);
			dest += len;
			remaining -= len;
			pos += 10;
		} else if (strncmp(pos, "${udp_support}", 14) == 0) {
			int len = snprintf(dest, remaining, "%d", udp_support);
			dest += len;
			remaining -= len;
			pos += 14;
		} else {
			*dest++ = *pos++;
			remaining--;
		}
	}
	*dest = '\0';
	safe_strncpy(command, temp, command_size);
}

int _execute_firewall_command(const char *cmd, const char *cmd_name, int log_error)
{
	FILE *fp;
	char output[4096] = {0};
	int ret = -1;
	int status;

	fp = popen(cmd, "r");
	if (fp == NULL) {
		tlog(TLOG_ERROR, "popen %s command failed: %s", cmd_name, strerror(errno));
		return -1;
	}

	// Read all output for logging purposes
	size_t output_len = 0;
	while (fgets(output + output_len, sizeof(output) - output_len, fp) != NULL) {
		output_len = strlen(output);
		if (output_len >= sizeof(output) - 1) {
			break; // Buffer full
		}
	}

	status = pclose(fp);
	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
	} else {
		ret = -1; // Command terminated abnormally
	}

	if (log_error) {
		if (ret != 0) {
			tlog(TLOG_ERROR, "executing %s command failed, exit code %d", cmd_name, ret);
			tlog(TLOG_ERROR, "%s", cmd);
			if (output[0] != '\0') {
				tlog(TLOG_ERROR, "%s", output);
			}
		} else if (output[0] != '\0') {
			tlog(TLOG_DEBUG, "%s: %s", cmd_name, output);
		}
	}

	return ret;
}

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

void _construct_tproxy_addr(const char *ip, const char *port, int is_ipv6, char *tproxy_addr, size_t addr_size)
{
	// Always use :port to preserve original destination address which is required for TProxy
	snprintf(tproxy_addr, addr_size, ":%s", port);
}

int _setup_nftables_rules(const char *table_name, const char *set_name, const char *ip, const char *port, int is_ipv6,
						  int udp_support, int so_mark, struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	char tproxy_ip[128];
	char tproxy_addr[256];
	char chain_name[256];

	const char *ip_family = is_ipv6 ? "ip6" : "ip";
	const char *addr_type = is_ipv6 ? "ipv6_addr" : "ipv4_addr";
	const char *daddr = is_ipv6 ? "ip6 daddr" : "ip daddr";

	// Clean up existing rules first
	_cleanup_nftables_rules(t_conf);

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

	// Parse IP address
	if (_parse_tproxy_ip(ip, port, is_ipv6, tproxy_ip, sizeof(tproxy_ip)) != 0) {
		return -1;
	}

	// Construct tproxy target address
	_construct_tproxy_addr(tproxy_ip, port, is_ipv6, tproxy_addr, sizeof(tproxy_addr));

	// Create table (ignore error if table already exists)
	snprintf(cmd, sizeof(cmd), "nft add table %s %s 2>&1 || true", ip_family, table_name);
	_execute_firewall_command(cmd, "nft", 1);

	// Create set
	snprintf(cmd, sizeof(cmd), "nft add set %s %s %s '{ type %s; flags interval; auto-merge; }' 2>&1", ip_family,
			 table_name, set_name, addr_type);
	if (_execute_firewall_command(cmd, "nft", 1) != 0) {
		return -1;
	}

	// Create chain with tproxy server name
	snprintf(chain_name, sizeof(chain_name), "%s", t_conf->name);
	snprintf(cmd, sizeof(cmd), "nft add chain %s %s %s '{ type filter hook prerouting priority mangle; }' 2>&1",
			 ip_family, table_name, chain_name);
	if (_execute_firewall_command(cmd, "nft", 1) != 0) {
		return -1;
	}

	// Add TCP rule for prerouting
	snprintf(cmd, sizeof(cmd), "nft add rule %s %s %s 'meta l4proto tcp %s @%s tproxy to %s mark set %d' 2>&1",
			 ip_family, table_name, chain_name, daddr, set_name, tproxy_addr, so_mark);
	if (_execute_firewall_command(cmd, "nft", 1) != 0) {
		return -1;
	}

	if (udp_support) {
		// Add UDP rule for prerouting
		snprintf(cmd, sizeof(cmd), "nft add rule %s %s %s 'meta l4proto udp %s @%s tproxy to %s mark set %d' 2>&1",
				 ip_family, table_name, chain_name, daddr, set_name, tproxy_addr, so_mark);
		if (_execute_firewall_command(cmd, "nft", 1) != 0) {
			return -1;
		}
	}

	// Output chain and rules for outgoing traffic (only if enabled)
	if (t_conf->output_chain_enable) {
		// Create output chain for outgoing traffic
		char output_chain_name[256];
		snprintf(output_chain_name, sizeof(output_chain_name), "%s_output", t_conf->name);
		snprintf(cmd, sizeof(cmd), "nft add chain %s %s %s '{ type filter hook output priority mangle; }' 2>&1",
				 ip_family, table_name, output_chain_name);
		if (_execute_firewall_command(cmd, "nft", 0) != 0) {
			tlog(TLOG_WARN, "failed to create output chain for %s, skipping output rules", t_conf->name);
		} else {
			// Add TCP rule for output
			snprintf(cmd, sizeof(cmd), "nft add rule %s %s %s 'meta l4proto tcp %s @%s tproxy to %s mark set %d' 2>&1",
					 ip_family, table_name, output_chain_name, daddr, set_name, tproxy_addr, so_mark);
			if (_execute_firewall_command(cmd, "nft", 0) != 0) {
				tlog(TLOG_WARN, "failed to add TCP output rule for %s, TPROXY may not be supported in output chain",
					 t_conf->name);
			}

			if (udp_support) {
				// Add UDP rule for output
				snprintf(cmd, sizeof(cmd),
						 "nft add rule %s %s %s 'meta l4proto udp %s @%s tproxy to %s mark set %d' 2>&1", ip_family,
						 table_name, output_chain_name, daddr, set_name, tproxy_addr, so_mark);
				if (_execute_firewall_command(cmd, "nft", 0) != 0) {
					tlog(TLOG_WARN, "failed to add UDP output rule for %s, TPROXY may not be supported in output chain",
						 t_conf->name);
				}
			}
		}
	}

	return 0;
}

static int _run_iptables_rule(const char *cmd_name, const char *table, const char *chain, const char *proto,
							  const char *match_set, const char *target, const char *extra_args, int log_error)
{
	char cmd[1024];
	const char *redirect = log_error ? "2>&1" : "2>/dev/null || true";
	snprintf(cmd, sizeof(cmd), "%s -t %s %s -p %s -m set --match-set %s dst -j %s %s %s", cmd_name, table, chain, proto,
			 match_set, target, extra_args, redirect);
	return _execute_firewall_command(cmd, cmd_name, log_error);
}

int _setup_iptables_redirect_rules(const char *ip, const char *port, int so_mark, int is_ipv6,
								   struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";

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
	if (is_ipv6) {
		snprintf(cmd, sizeof(cmd), "ipset create %s hash:net family inet6 timeout 3600", ipset_name);
	} else {
		snprintf(cmd, sizeof(cmd), "ipset create %s hash:net timeout 3600", ipset_name);
	}
	if (_execute_firewall_command(cmd, "ipset", 1) != 0) {
		tlog(TLOG_ERROR, "create %s ipset failed", ipset_name);
		return -1;
	}

	// Add REDIRECT rule for PREROUTING
	snprintf(cmd, sizeof(cmd), "%s -t nat -I PREROUTING -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %s",
			 iptables_cmd, ipset_name, port);
	if (_execute_firewall_command(cmd, iptables_cmd, 1) != 0) {
		return -1;
	}

	// Add REDIRECT rule for OUTPUT
	if (t_conf->output_chain_enable) {
		const char *mark_exclude = "";
		char mark_str[64] = {0};
		if (so_mark != 0) {
			snprintf(mark_str, sizeof(mark_str), "-m mark ! --mark 0x%x", so_mark);
			mark_exclude = mark_str;
		}

		snprintf(cmd, sizeof(cmd), "%s -t nat -I OUTPUT -p tcp -m set --match-set %s dst %s -j REDIRECT --to-ports %s",
				 iptables_cmd, ipset_name, mark_exclude, port);
		if (_execute_firewall_command(cmd, iptables_cmd, 0) != 0) {
			tlog(TLOG_WARN, "failed to add TCP OUTPUT rule for %s, REDIRECT may not be supported in output chain",
				 t_conf->name);
		}
	}

	return 0;
}

int _setup_iptables_tproxy_rules(const char *set_name, const char *ip, const char *port, int is_ipv6, int udp_support,
								 int so_mark, struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	char extra_args[512];
	char tproxy_ip[64];
	const char *ipset_name;

	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";
	const char *family = is_ipv6 ? "inet6" : "inet";

	// Get ipset name from pre-prepared configuration
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

	// Create ipset
	snprintf(cmd, sizeof(cmd), "ipset create  %s hash:net timeout 3600 family %s 2>&1", set_name, family);
	if (_execute_firewall_command(cmd, "ipset", 1) != 0) {
		tlog(TLOG_ERROR, "create ipset failed");
		tlog(TLOG_ERROR, "try run as root or flush iptable with 'iptable -t mangle -F' and 'ip6table -t mangle -F'");
		return -1;
	}

	// Add ip rule and route for TPROXY
	if (!is_ipv6) {
		// IPv4
		snprintf(cmd, sizeof(cmd), "ip rule add fwmark 0x%x lookup 0x%x 2>&1", so_mark, so_mark);
		if (_execute_firewall_command(cmd, "ip", 1) != 0) {
			return -1;
		}

		snprintf(cmd, sizeof(cmd), "ip route add local 0.0.0.0/0 dev lo table 0x%x 2>&1", so_mark);
		if (_execute_firewall_command(cmd, "ip", 1) != 0) {
			return -1;
		}
	} else {
		// IPv6
		snprintf(cmd, sizeof(cmd), "ip -6 rule add fwmark 0x%x lookup 0x%x 2>&1", so_mark, so_mark);
		if (_execute_firewall_command(cmd, "ip", 1) != 0) {
			return -1;
		}

		snprintf(cmd, sizeof(cmd), "ip -6 route add local ::/0 dev lo table 0x%x 2>&1", so_mark);
		if (_execute_firewall_command(cmd, "ip", 1) != 0) {
			return -1;
		}
	}

	// Prepare common TPROXY arguments
	snprintf(extra_args, sizeof(extra_args), "--on-port %s --on-ip %s --tproxy-mark 0x%x/0xffffffff", port, tproxy_ip,
			 so_mark);

	// Add TCP rule for PREROUTING
	if (_run_iptables_rule(iptables_cmd, "mangle", "-A PREROUTING", "tcp", set_name, "TPROXY", extra_args, 1) != 0) {
		return -1;
	}

	if (udp_support) {
		// Add UDP rule for PREROUTING
		if (_run_iptables_rule(iptables_cmd, "mangle", "-A PREROUTING", "udp", set_name, "TPROXY", extra_args, 1) !=
			0) {
			return -1;
		}
	}

	// Output rules for outgoing traffic (only if enabled)
	if (t_conf->output_chain_enable) {
		// Add TCP rule for OUTPUT
		if (_run_iptables_rule(iptables_cmd, "mangle", "-A OUTPUT", "tcp", set_name, "TPROXY", extra_args, 0) != 0) {
			tlog(TLOG_WARN, "failed to add TCP OUTPUT rule for %s, TPROXY may not be supported", t_conf->name);
		}

		if (udp_support) {
			// Add UDP rule for OUTPUT
			if (_run_iptables_rule(iptables_cmd, "mangle", "-A OUTPUT", "udp", set_name, "TPROXY", extra_args, 0) !=
				0) {
				tlog(TLOG_WARN, "failed to add UDP OUTPUT rule for %s, TPROXY may not be supported", t_conf->name);
			}
		}
	}

	return 0;
}

void _cleanup_nftables_rules(struct dns_tproxy_server_conf *t_conf)
{
	char cmd[4096];
	const char *table_name_ipv4 = NULL;
	const char *table_name_ipv6 = NULL;

	if (t_conf->nftset_names.ip.nfttablename) {
		table_name_ipv4 = t_conf->nftset_names.ip.nfttablename;
	}
	if (t_conf->nftset_names.ip6.nfttablename) {
		table_name_ipv6 = t_conf->nftset_names.ip6.nfttablename;
	}

	// Delete IPv4 table
	if (table_name_ipv4) {
		snprintf(cmd, sizeof(cmd), "nft delete table ip %s 2>/dev/null || true", table_name_ipv4);
		_execute_firewall_command(cmd, "nft", 0);
	}

	// Delete IPv6 table
	if (table_name_ipv6) {
		snprintf(cmd, sizeof(cmd), "nft delete table ip6 %s 2>/dev/null || true", table_name_ipv6);
		_execute_firewall_command(cmd, "nft", 0);
	}
}

void _cleanup_iptables_tproxy_rules(struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	char ipv4_set_name[256];
	char ipv6_set_name[256];
	char ip[64];
	char port[16];
	char extra_args[512];
	char tproxy_ip[64];

	if (firewall_get_ip_port(t_conf->server, ip, sizeof(ip), port, sizeof(port)) != 0) {
		tlog(TLOG_ERROR, "failed to get ip and port for %s", t_conf->name);
		return;
	}

	// Reconstruct ipset names
	snprintf(ipv4_set_name, sizeof(ipv4_set_name), "smartdns_ipv4_%s", t_conf->name);
	snprintf(ipv6_set_name, sizeof(ipv6_set_name), "smartdns_ipv6_%s", t_conf->name);

	// Delete IPv4 rules and set
	if (ipv4_set_name[0]) {
		// Parse TProxy IP for IPv4 (handles [::1] -> 127.0.0.1 conversion)
		if (_parse_tproxy_ip(ip, port, 0, tproxy_ip, sizeof(tproxy_ip)) == 0) {
			snprintf(extra_args, sizeof(extra_args), "--on-port %s --on-ip %s --tproxy-mark 0x%x/0xffffffff", port,
					 tproxy_ip, t_conf->so_mark);

			// Delete TCP rule from PREROUTING
			_run_iptables_rule("iptables", "mangle", "-D PREROUTING", "tcp", ipv4_set_name, "TPROXY", extra_args, 0);

			// Delete UDP rule from PREROUTING
			_run_iptables_rule("iptables", "mangle", "-D PREROUTING", "udp", ipv4_set_name, "TPROXY", extra_args, 0);

			// Delete TCP rule from OUTPUT
			_run_iptables_rule("iptables", "mangle", "-D OUTPUT", "tcp", ipv4_set_name, "TPROXY", extra_args, 0);

			// Delete UDP rule from OUTPUT
			_run_iptables_rule("iptables", "mangle", "-D OUTPUT", "udp", ipv4_set_name, "TPROXY", extra_args, 0);
		}

		// Destroy ipset
		snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null || true", ipv4_set_name);
		_execute_firewall_command(cmd, "ipset", 0);

		// Delete ip route and rule
		snprintf(cmd, sizeof(cmd), "ip route del local 0.0.0.0/0 dev lo table 0x%x 2>/dev/null || true",
				 t_conf->so_mark);
		_execute_firewall_command(cmd, "ip", 0);

		snprintf(cmd, sizeof(cmd), "ip rule del fwmark 0x%x lookup 0x%x 2>/dev/null || true", t_conf->so_mark,
				 t_conf->so_mark);
		_execute_firewall_command(cmd, "ip", 0);
	}

	// Delete IPv6 rules and set
	if (ipv6_set_name[0]) {
		// Parse TProxy IP for IPv6
		if (_parse_tproxy_ip(ip, port, 1, tproxy_ip, sizeof(tproxy_ip)) == 0) {
			snprintf(extra_args, sizeof(extra_args), "--on-port %s --on-ip %s --tproxy-mark 0x%x/0xffffffff", port,
					 tproxy_ip, t_conf->so_mark);

			// Delete TCP rule from PREROUTING
			_run_iptables_rule("ip6tables", "mangle", "-D PREROUTING", "tcp", ipv6_set_name, "TPROXY", extra_args, 0);

			// Delete UDP rule from PREROUTING
			_run_iptables_rule("ip6tables", "mangle", "-D PREROUTING", "udp", ipv6_set_name, "TPROXY", extra_args, 0);

			// Delete TCP rule from OUTPUT
			_run_iptables_rule("ip6tables", "mangle", "-D OUTPUT", "tcp", ipv6_set_name, "TPROXY", extra_args, 0);

			// Delete UDP rule from OUTPUT
			_run_iptables_rule("ip6tables", "mangle", "-D OUTPUT", "udp", ipv6_set_name, "TPROXY", extra_args, 0);
		}

		// Destroy ipset
		snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null || true", ipv6_set_name);
		_execute_firewall_command(cmd, "ipset", 0);

		// Delete ip route and rule
		snprintf(cmd, sizeof(cmd), "ip -6 route del local ::/0 dev lo table 0x%x 2>/dev/null || true", t_conf->so_mark);
		_execute_firewall_command(cmd, "ip", 0);

		snprintf(cmd, sizeof(cmd), "ip -6 rule del fwmark 0x%x lookup 0x%x 2>/dev/null || true", t_conf->so_mark,
				 t_conf->so_mark);
		_execute_firewall_command(cmd, "ip", 0);
	}
}

void _cleanup_iptables_redirect_rules(struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	char ip[64];
	char port[16];
	char ipset_name[64];

	if (firewall_get_ip_port(t_conf->server, ip, sizeof(ip), port, sizeof(port)) != 0) {
		tlog(TLOG_ERROR, "failed to get ip and port for %s", t_conf->name);
		return;
	}

	// Cleanup IPv4
	if (t_conf->ipset_names.ipv4.ipsetname) {
		safe_strncpy(ipset_name, t_conf->ipset_names.ipv4.ipsetname, sizeof(ipset_name));

		// Delete REDIRECT rule from PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "iptables -t nat -D PREROUTING -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %s 2>&1",
				 ipset_name, port);
		_execute_firewall_command(cmd, "iptables", 0);

		// Delete REDIRECT rule from OUTPUT
		if (t_conf->output_chain_enable) {
			const char *mark_exclude = "";
			char mark_str[64] = {0};
			if (t_conf->so_mark != 0) {
				snprintf(mark_str, sizeof(mark_str), "-m mark ! --mark 0x%x", t_conf->so_mark);
				mark_exclude = mark_str;
			}

			snprintf(cmd, sizeof(cmd),
					 "iptables -t nat -D OUTPUT -p tcp -m set --match-set %s dst %s -j REDIRECT --to-ports %s 2>&1",
					 ipset_name, mark_exclude, port);
			_execute_firewall_command(cmd, "iptables", 0);
		}

		// Destroy ipset
		snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>&1", ipset_name);
		_execute_firewall_command(cmd, "ipset", 0);
	}

	// Cleanup IPv6
	if (t_conf->ipset_names.ipv6.ipsetname) {
		safe_strncpy(ipset_name, t_conf->ipset_names.ipv6.ipsetname, sizeof(ipset_name));

		// Delete REDIRECT rule from PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "ip6tables -t nat -D PREROUTING -p tcp -m set --match-set %s dst -j REDIRECT --to-ports %s 2>&1",
				 ipset_name, port);
		_execute_firewall_command(cmd, "ip6tables", 0);

		// Delete REDIRECT rule from OUTPUT
		if (t_conf->output_chain_enable) {
			const char *mark_exclude = "";
			char mark_str[64] = {0};
			if (t_conf->so_mark != 0) {
				snprintf(mark_str, sizeof(mark_str), "-m mark ! --mark 0x%x", t_conf->so_mark);
				mark_exclude = mark_str;
			}

			snprintf(cmd, sizeof(cmd),
					 "ip6tables -t nat -D OUTPUT -p tcp -m set --match-set %s dst %s -j REDIRECT --to-ports %s 2>&1",
					 ipset_name, mark_exclude, port);
			_execute_firewall_command(cmd, "ip6tables", 0);
		}

		// Destroy ipset
		snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>&1", ipset_name);
		_execute_firewall_command(cmd, "ipset", 0);
	}
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

		_cleanup_iptables_rules(t_conf);

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

		_cleanup_iptables_rules(t_conf);

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

		char cmd[4096];
		char setname[256];
		snprintf(setname, sizeof(setname), "%s", t_conf->name);
		snprintf(cmd, sizeof(cmd), "%s setup %d %s %s %s %d %d", t_conf->rule_script, t_conf->so_mark, setname, ip,
				 port, 0, t_conf->udp_support);
		if (_execute_firewall_command(cmd, "custom script", 1) != 0) {
			tlog(TLOG_ERROR, "failed to execute custom rule script for %s", t_conf->name);
			return -1;
		}
		// IPv6
		snprintf(cmd, sizeof(cmd), "%s setup %d %s %s %s %d %d", t_conf->rule_script, t_conf->so_mark, setname, ip,
				 port, 1, t_conf->udp_support);
		if (_execute_firewall_command(cmd, "custom script", 1) != 0) {
			tlog(TLOG_ERROR, "failed to execute custom rule script for %s", t_conf->name);
			return -1;
		}
		return 0; // Skip built-in rules
	} else if (t_conf->start_rule[0] != '\0') {
		// Execute custom start command
		char cmd[4096];
		char setname[256];
		snprintf(setname, sizeof(setname), "%s", t_conf->name);
		safe_strncpy(cmd, t_conf->start_rule, sizeof(cmd));
		_firewall_replace_rule_params(cmd, sizeof(cmd), setname, t_conf->so_mark, ip, port, 0, t_conf->udp_support);
		if (_execute_firewall_command(cmd, "custom start rule", 1) != 0) {
			tlog(TLOG_ERROR, "failed to execute custom start rule for %s", t_conf->name);
			return -1;
		}
		// IPv6 version if needed
		safe_strncpy(cmd, t_conf->start_rule, sizeof(cmd));
		_firewall_replace_rule_params(cmd, sizeof(cmd), setname, t_conf->so_mark, ip, port, 1, t_conf->udp_support);
		if (_execute_firewall_command(cmd, "custom start rule", 1) != 0) {
			tlog(TLOG_ERROR, "failed to execute custom start rule for %s", t_conf->name);
			return -1;
		}
		return 0; // Skip built-in rules
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
		char cmd[4096];
		char setname[256];
		snprintf(setname, sizeof(setname), "%s", t_conf->name);
		tlog(TLOG_INFO, "executing custom script cleanup %s for %s", t_conf->rule_script, t_conf->name);
		snprintf(cmd, sizeof(cmd), "%s cleanup %d %s %s %s %d %d", t_conf->rule_script, t_conf->so_mark, setname, ip,
				 port, 0, t_conf->udp_support);
		_execute_firewall_command(cmd, "custom script cleanup", 1);
		snprintf(cmd, sizeof(cmd), "%s cleanup %d %s %s %s %d %d", t_conf->rule_script, t_conf->so_mark, setname, ip,
				 port, 1, t_conf->udp_support);
		_execute_firewall_command(cmd, "custom script cleanup", 1);
		return 0;
	} else if (t_conf->stop_rule[0] != '\0') {
		// Execute custom stop command
		char cmd[4096];
		char setname[256];
		snprintf(setname, sizeof(setname), "%s", t_conf->name);
		tlog(TLOG_INFO, "executing custom stop rule for %s", t_conf->name);
		safe_strncpy(cmd, t_conf->stop_rule, sizeof(cmd));
		_firewall_replace_rule_params(cmd, sizeof(cmd), setname, t_conf->so_mark, ip, port, 0, t_conf->udp_support);
		_execute_firewall_command(cmd, "custom stop rule", 1);
		safe_strncpy(cmd, t_conf->stop_rule, sizeof(cmd));
		_firewall_replace_rule_params(cmd, sizeof(cmd), setname, t_conf->so_mark, ip, port, 1, t_conf->udp_support);
		_execute_firewall_command(cmd, "custom stop rule", 1);
		return 0;
	} else if (t_conf->no_rule_clean) {
		// Skip built-in rules cleanup
		return 0;
	}

	_cleanup_builtin_rules(t_conf);

	return 0;
}