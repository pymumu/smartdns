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

#include "audit.h"
#include "dns_server.h"
#include <syslog.h>

static tlog_log *dns_audit;

void _dns_server_audit_log(struct dns_server_post_context *context)
{
	char req_host[MAX_IP_LEN];
	char req_result[1024] = {0};
	char *ip_msg = req_result;
	char req_time[MAX_IP_LEN] = {0};
	struct tlog_time tm;
	int i = 0;
	int j = 0;
	int rr_count = 0;
	struct dns_rrs *rrs = NULL;
	char name[DNS_MAX_CNAME_LEN] = {0};
	int ttl = 0;
	int len = 0;
	int left_len = sizeof(req_result);
	int total_len = 0;
	int ip_num = 0;
	struct dns_request *request = context->request;
	int has_soa = request->has_soa;

	if (atomic_read(&request->notified) == 1) {
		request->query_time = get_tick_count() - request->send_tick;
	}

	if (dns_audit == NULL || !dns_conf.audit_enable || context->do_audit == 0) {
		return;
	}

	if (request->conn == NULL) {
		return;
	}

	for (j = 1; j < DNS_RRS_OPT && context->packet; j++) {
		rrs = dns_get_rrs_start(context->packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs && left_len > 0; i++, rrs = dns_get_rrs_next(context->packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char ipv4_addr[4];
				if (dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv4_addr) != 0) {
					continue;
				}

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				const char *fmt = "%d.%d.%d.%d";
				if (ip_num > 0) {
					fmt = ", %d.%d.%d.%d";
				}

				len =
					snprintf(ip_msg + total_len, left_len, fmt, ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
				ip_num++;
				has_soa = 0;
			} break;
			case DNS_T_AAAA: {
				unsigned char ipv6_addr[16];
				if (dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv6_addr) != 0) {
					continue;
				}

				if (strncasecmp(name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(name, request->cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}

				const char *fmt = "%s";
				if (ip_num > 0) {
					fmt = ", %s";
				}
				req_host[0] = '\0';
				inet_ntop(AF_INET6, ipv6_addr, req_host, sizeof(req_host));
				len = snprintf(ip_msg + total_len, left_len, fmt, req_host);
				ip_num++;
				has_soa = 0;
			} break;
			case DNS_T_SOA: {
				if (ip_num == 0) {
					has_soa = 1;
				}
			} break;
			default:
				continue;
			}

			if (len < 0 || len >= left_len) {
				left_len = 0;
				break;
			}

			left_len -= len;
			total_len += len;
		}
	}

	if (has_soa && ip_num == 0) {
		if (!dns_conf.audit_log_SOA) {
			return;
		}

		if (request->dualstack_selection_force_soa) {
			snprintf(req_result, left_len, "dualstack soa");
		} else {
			snprintf(req_result, left_len, "soa");
		}
	}

	get_host_by_addr(req_host, sizeof(req_host), &request->addr);
	tlog_localtime(&tm);

	if (req_host[0] == '\0') {
		safe_strncpy(req_host, "API", MAX_IP_LEN);
	}

	if (dns_conf.audit_syslog == 0) {
		snprintf(req_time, sizeof(req_time), "[%.4d-%.2d-%.2d %.2d:%.2d:%.2d,%.3d] ", tm.year, tm.mon, tm.mday, tm.hour,
				 tm.min, tm.sec, tm.usec / 1000);
	}

	tlog_printf(dns_audit, "%s%s query %s, type %d, time %dms, speed: %.1fms, group %s, result %s\n", req_time,
				req_host, request->domain, request->qtype, request->query_time, ((float)request->ping_time) / 10,
				request->dns_group_name[0] != '\0' ? request->dns_group_name : DNS_SERVER_GROUP_DEFAULT, req_result);
}

static int _dns_server_audit_syslog(struct tlog_log *log, const char *buff, int bufflen)
{
	syslog(LOG_INFO, "%.*s", bufflen, buff);
	return 0;
}

int _dns_server_audit_init(void)
{
	char *audit_file = SMARTDNS_AUDIT_FILE;
	unsigned int tlog_flag = 0;

	if (dns_conf.audit_enable == 0) {
		return 0;
	}

	if (dns_conf.audit_file[0] != 0) {
		audit_file = dns_conf.audit_file;
	}

	if (dns_conf.audit_syslog) {
		tlog_flag |= TLOG_SEGMENT;
	}

	dns_audit = tlog_open(audit_file, dns_conf.audit_size, dns_conf.audit_num, 0, tlog_flag);
	if (dns_audit == NULL) {
		return -1;
	}

	if (dns_conf.audit_syslog) {
		tlog_reg_output_func(dns_audit, _dns_server_audit_syslog);
	}

	if (dns_conf.audit_file_mode > 0) {
		tlog_set_permission(dns_audit, dns_conf.audit_file_mode, dns_conf.audit_file_mode);
	}

	if (dns_conf.audit_console != 0) {
		tlog_logscreen(dns_audit, 1);
	}

	return 0;
}