/*
 * firewall.c - Firewall rules management for smartdns
 */

#include "firewall.h"
#include "../dns_conf/ipset.h"
#include "../dns_conf/nftset.h"
#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int _execute_firewall_command(const char *cmd, const char *cmd_name, int log_error)
{
	FILE *fp;
	char output[4096] = {0};

	fp = popen(cmd, "r");
	if (fp == NULL) {
		return -1;
	}

	if (fgets(output, sizeof(output), fp) != NULL) {
		goto errout;
	}

	if (pclose(fp) != 0) {
		goto errout;
	}

	return 0;

errout:
	if (log_error) {
		tlog(TLOG_ERROR, "executing %s command failed:", cmd_name);
		tlog(TLOG_ERROR, "%s", cmd);
		if (output[0] != '\0') {
			tlog(TLOG_ERROR, "%s", output);
		}
	}

	if (fp) {
		pclose(fp);
	}

	return -1;
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

int _setup_nftables_rules(const char *table_name, const char *set_name, const char *ip, const char *port,
						 int is_ipv6, int udp_support, int so_mark, struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	char tproxy_ip[128];
	char tproxy_addr[256];
	char chain_name[256];
	const struct dns_nftset_name *nftset = NULL;

	const char *ip_family = is_ipv6 ? "ip6" : "ip";
	const char *addr_type = is_ipv6 ? "ipv6_addr" : "ipv4_addr";
	const char *daddr = is_ipv6 ? "ip6 daddr" : "ip daddr";

	// Get nftset name from memory pool
	nftset = _dns_conf_get_nftable(ip_family, table_name, set_name);
	if (nftset == NULL) {
		tlog(TLOG_ERROR, "failed to get nftset for %s %s", ip_family, set_name);
		return -1;
	}

	// Store nftset names in configuration
	if (is_ipv6) {
		t_conf->nftset_names.ip6_enable = 1;
		t_conf->nftset_names.ip6.familyname = nftset->nftfamilyname;
		t_conf->nftset_names.ip6.nfttablename = nftset->nfttablename;
		t_conf->nftset_names.ip6.nftsetname = nftset->nftsetname;
	} else {
		t_conf->nftset_names.ip_enable = 1;
		t_conf->nftset_names.ip.familyname = nftset->nftfamilyname;
		t_conf->nftset_names.ip.nfttablename = nftset->nfttablename;
		t_conf->nftset_names.ip.nftsetname = nftset->nftsetname;
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
	snprintf(cmd, sizeof(cmd), "nft add set %s %s %s '{ type %s; flags interval; auto-merge; }' 2>&1",
			 ip_family, table_name, set_name, addr_type);
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
				tlog(TLOG_WARN, "failed to add TCP output rule for %s, TPROXY may not be supported in output chain", t_conf->name);
			}

			if (udp_support) {
				// Add UDP rule for output
				snprintf(cmd, sizeof(cmd), "nft add rule %s %s %s 'meta l4proto udp %s @%s tproxy to %s mark set %d' 2>&1",
						 ip_family, table_name, output_chain_name, daddr, set_name, tproxy_addr, so_mark);
				if (_execute_firewall_command(cmd, "nft", 0) != 0) {
					tlog(TLOG_WARN, "failed to add UDP output rule for %s, TPROXY may not be supported in output chain", t_conf->name);
				}
			}
		}
	}

	return 0;
}

int _setup_iptables_rules(const char *set_name, const char *ip, const char *port, int is_ipv6, int udp_support,
						 int so_mark, struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	char tproxy_ip[64];
	const char *ipset_name = NULL;

	const char *iptables_cmd = is_ipv6 ? "ip6tables" : "iptables";
	const char *family = is_ipv6 ? "inet6" : "inet";

	// Get ipset name from memory pool
	ipset_name = _dns_conf_get_ipset(set_name);
	if (ipset_name == NULL) {
		tlog(TLOG_ERROR, "failed to get ipset for %s", set_name);
		return -1;
	}

	// Store ipset names in configuration
	if (is_ipv6) {
		t_conf->ipset_names.ipv6_enable = 1;
		t_conf->ipset_names.ipv6.ipsetname = ipset_name;
	} else {
		t_conf->ipset_names.ipv4_enable = 1;
		t_conf->ipset_names.ipv4.ipsetname = ipset_name;
	}

	// Parse IP address
	if (_parse_tproxy_ip(ip, port, is_ipv6, tproxy_ip, sizeof(tproxy_ip)) != 0) {
		return -1;
	}

	// Create ipset
	snprintf(cmd, sizeof(cmd), "ipset create -exist %s hash:net family timeout 3600%s 2>&1", set_name, family);
	if (_execute_firewall_command(cmd, "ipset", 1) != 0) {
		return -1;
	}

	// Add TCP rule for PREROUTING
	snprintf(cmd, sizeof(cmd),
			 "%s -t mangle -A PREROUTING -p tcp -m set --match-set %s dst -j TPROXY --on-port %s --on-ip %s "
			 "--tproxy-mark 0x%x/0x%x 2>&1",
			 iptables_cmd, set_name, port, tproxy_ip, so_mark, so_mark);
	if (_execute_firewall_command(cmd, iptables_cmd, 1) != 0) {
		return -1;
	}

	if (udp_support) {
		// Add UDP rule for PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "%s -t mangle -A PREROUTING -p udp -m set --match-set %s dst -j TPROXY --on-port %s --on-ip %s "
				 "--tproxy-mark 0x%x/0x%x 2>&1",
				 iptables_cmd, set_name, port, tproxy_ip, so_mark, so_mark);
		if (_execute_firewall_command(cmd, iptables_cmd, 1) != 0) {
			return -1;
		}
	}

	// Output rules for outgoing traffic (only if enabled)
	if (t_conf->output_chain_enable) {
		// Add TCP rule for OUTPUT
		snprintf(cmd, sizeof(cmd),
				 "%s -t mangle -A OUTPUT -p tcp -m set --match-set %s dst -j TPROXY --on-port %s --on-ip %s "
				 "--tproxy-mark 0x%x/0x%x 2>&1",
				 iptables_cmd, set_name, port, tproxy_ip, so_mark, so_mark);
		if (_execute_firewall_command(cmd, iptables_cmd, 0) != 0) {
			tlog(TLOG_WARN, "failed to add TCP OUTPUT rule for %s, TPROXY may not be supported", t_conf->name);
		}

		if (udp_support) {
			// Add UDP rule for OUTPUT
			snprintf(cmd, sizeof(cmd),
					 "%s -t mangle -A OUTPUT -p udp -m set --match-set %s dst -j TPROXY --on-port %s --on-ip %s "
					 "--tproxy-mark 0x%x/0x%x 2>&1",
					 iptables_cmd, set_name, port, tproxy_ip, so_mark, so_mark);
			if (_execute_firewall_command(cmd, iptables_cmd, 0) != 0) {
				tlog(TLOG_WARN, "failed to add UDP OUTPUT rule for %s, TPROXY may not be supported", t_conf->name);
			}
		}
	}

	return 0;
}

void _cleanup_nftables_rules(struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
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
		system(cmd);
	}

	// Delete IPv6 table
	if (table_name_ipv6) {
		snprintf(cmd, sizeof(cmd), "nft delete table ip6 %s 2>/dev/null || true", table_name_ipv6);
		system(cmd);
	}
}

void _cleanup_iptables_rules(struct dns_tproxy_server_conf *t_conf)
{
	char cmd[1024];
	const char *set_name_ipv4 = NULL;
	const char *set_name_ipv6 = NULL;

	if (t_conf->ipset_names.ipv4.ipsetname) {
		set_name_ipv4 = t_conf->ipset_names.ipv4.ipsetname;
	}
	if (t_conf->ipset_names.ipv6.ipsetname) {
		set_name_ipv6 = t_conf->ipset_names.ipv6.ipsetname;
	}

	// Delete IPv4 rules and set
	if (set_name_ipv4) {
		// Delete TCP rule from PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "iptables -t mangle -D PREROUTING -p tcp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv4);
		system(cmd);

		// Delete UDP rule from PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "iptables -t mangle -D PREROUTING -p udp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv4);
		system(cmd);

		// Delete TCP rule from OUTPUT
		snprintf(cmd, sizeof(cmd),
				 "iptables -t mangle -D OUTPUT -p tcp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv4);
		system(cmd);

		// Delete UDP rule from OUTPUT
		snprintf(cmd, sizeof(cmd),
				 "iptables -t mangle -D OUTPUT -p udp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv4);
		system(cmd);

		// Destroy ipset
		snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null || true", set_name_ipv4);
		system(cmd);
	}

	// Delete IPv6 rules and set
	if (set_name_ipv6) {
		// Delete TCP rule from PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "ip6tables -t mangle -D PREROUTING -p tcp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv6);
		system(cmd);

		// Delete UDP rule from PREROUTING
		snprintf(cmd, sizeof(cmd),
				 "ip6tables -t mangle -D PREROUTING -p udp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv6);
		system(cmd);

		// Delete TCP rule from OUTPUT
		snprintf(cmd, sizeof(cmd),
				 "ip6tables -t mangle -D OUTPUT -p tcp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv6);
		system(cmd);

		// Delete UDP rule from OUTPUT
		snprintf(cmd, sizeof(cmd),
				 "ip6tables -t mangle -D OUTPUT -p udp -m set --match-set %s dst -j TPROXY 2>/dev/null || true",
				 set_name_ipv6);
		system(cmd);

		// Destroy ipset
		snprintf(cmd, sizeof(cmd), "ipset destroy %s 2>/dev/null || true", set_name_ipv6);
		system(cmd);
	}
}