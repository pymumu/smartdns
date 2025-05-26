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

#include "speed_check_mode.h"
#include "dns_conf_group.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <errno.h>
#include <string.h>

static int dns_has_cap_ping = 0;
int dns_ping_cap_force_enable = 0;

static void _config_speed_check_mode_clear(struct dns_domain_check_orders *check_orders)
{
	memset(check_orders->orders, 0, sizeof(check_orders->orders));
}

int _config_speed_check_mode_parser(struct dns_domain_check_orders *check_orders, const char *mode)
{
	char tmpbuff[DNS_MAX_OPT_LEN];
	char *field = NULL;
	char *ptr = NULL;
	int order = 0;
	int port = 80;
	int i = 0;

	safe_strncpy(tmpbuff, mode, DNS_MAX_OPT_LEN);
	_config_speed_check_mode_clear(check_orders);

	ptr = tmpbuff;
	do {
		field = ptr;
		ptr = strstr(ptr, ",");
		if (field == NULL || order >= DOMAIN_CHECK_NUM) {
			return 0;
		}

		if (ptr) {
			*ptr = 0;
		}

		if (strncmp(field, "ping", sizeof("ping")) == 0) {
			if (dns_has_cap_ping == 0) {
				if (ptr) {
					ptr++;
				}
				continue;
			}
			check_orders->orders[order].type = DOMAIN_CHECK_ICMP;
			check_orders->orders[order].tcp_port = 0;
			dns_conf.has_icmp_check = 1;
		} else if (strstr(field, "tcp") == field) {
			char *port_str = strstr(field, ":");
			if (port_str) {
				port = atoi(port_str + 1);
				if (port <= 0 || port >= 65535) {
					port = 80;
				}
			}

			check_orders->orders[order].type = DOMAIN_CHECK_TCP;
			check_orders->orders[order].tcp_port = port;
			dns_conf.has_tcp_check = 1;
		} else if (strncmp(field, "none", sizeof("none")) == 0) {
			for (i = order; i < DOMAIN_CHECK_NUM; i++) {
				check_orders->orders[i].type = DOMAIN_CHECK_NONE;
				check_orders->orders[i].tcp_port = 0;
			}

			return 0;
		}

		order++;
		if (ptr) {
			ptr++;
		}
	} while (ptr);

	return 0;
}

int _config_speed_check_mode(void *data, int argc, char *argv[])
{
	char mode[DNS_MAX_OPT_LEN];

	if (argc <= 1) {
		return -1;
	}

	safe_strncpy(mode, argv[1], sizeof(mode));

	return _config_speed_check_mode_parser(&_config_current_rule_group()->check_orders, mode);
}

int _dns_conf_speed_check_mode_verify(void)
{
	struct dns_conf_group *group;
	struct hlist_node *tmp = NULL;
	unsigned long k = 0;
	int i = 0;
	int j = 0;
	int print_log = 0;

	hash_for_each_safe(dns_conf_rule.group, k, tmp, group, node)
	{
		struct dns_domain_check_orders *check_orders = &group->check_orders;
		for (i = 0; i < DOMAIN_CHECK_NUM; i++) {
			if (check_orders->orders[i].type == DOMAIN_CHECK_ICMP) {
				if (dns_has_cap_ping == 0) {
					for (j = i + 1; j < DOMAIN_CHECK_NUM; j++) {
						check_orders->orders[j - 1].type = check_orders->orders[j].type;
						check_orders->orders[j - 1].tcp_port = check_orders->orders[j].tcp_port;
					}
					check_orders->orders[j - 1].type = DOMAIN_CHECK_NONE;
					check_orders->orders[j - 1].tcp_port = 0;
					print_log = 1;
				}
				dns_conf.has_icmp_check = 1;
			}

			if (check_orders->orders[i].type == DOMAIN_CHECK_TCP) {
				dns_conf.has_tcp_check = 1;
			}
		}
	}

	if (print_log) {
		tlog(TLOG_WARN, "speed check by ping is disabled because smartdns does not have network raw privileges");
	}

	return 0;
}

int _dns_ping_cap_check(void)
{
	int has_ping = 0;
	int has_raw_cap = 0;

	has_raw_cap = has_network_raw_cap();
	has_ping = has_unprivileged_ping();
	if (has_ping == 0) {
		if (errno == EACCES && has_raw_cap == 0) {
			tlog(TLOG_WARN, "unprivileged ping is disabled, please enable by setting net.ipv4.ping_group_range");
		}
	}

	if (has_ping == 1 || has_raw_cap == 1) {
		dns_has_cap_ping = 1;
	}

	if (dns_ping_cap_force_enable) {
		dns_has_cap_ping = 1;
	}

	return 0;
}
