/*
 * firewall.h - Firewall rules management for smartdns
 */

#ifndef _FIREWALL_H
#define _FIREWALL_H

#include "smartdns/dns_conf.h"

int _execute_firewall_command(const char *cmd, const char *tool, int log_error);
int _parse_tproxy_ip(const char *ip, const char *port, int is_ipv6, char *tproxy_addr, size_t addr_size);
void _construct_tproxy_addr(const char *ip, const char *port, int is_ipv6, char *tproxy_addr, size_t addr_size);
int _setup_nftables_rules(const char *table_name, const char *set_name, const char *ip, const char *port, int is_ipv6, int udp_support, int so_mark, struct dns_tproxy_server_conf *t_conf);
int _setup_iptables_rules(const char *set_name, const char *ip, const char *port, int is_ipv6, int udp_support, int so_mark, struct dns_tproxy_server_conf *t_conf);
void _cleanup_nftables_rules(struct dns_tproxy_server_conf *t_conf);
void _cleanup_iptables_rules(struct dns_tproxy_server_conf *t_conf);
int firewall_get_ip_port(const char *server_str, char *ip, size_t ip_size, char *port, size_t port_size);
int firewall_setup_rules(struct dns_tproxy_server_conf *t_conf);
int firewall_cleanup_rules(struct dns_tproxy_server_conf *t_conf);

#endif /* _FIREWALL_H */