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

#include "answer.h"
#include "address.h"
#include "dns_server.h"
#include "ip_rule.h"
#include "request.h"
#include "rules.h"
#include "soa.h"
#include "speed_check.h"

#include <math.h>

static int _dns_server_process_answer_A_IP(struct dns_request *request, char *cname, unsigned char addr[4], int ttl,
										   unsigned int result_flag)
{
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ip_check_result = 0;
	unsigned char *paddrs[MAX_IP_NUM];
	int paddr_num = 0;
	struct dns_iplist_ip_addresses *alias = NULL;

	paddrs[paddr_num] = addr;
	paddr_num = 1;

	/* ip rule check */
	ip_check_result = _dns_server_process_ip_rule(request, addr, 4, DNS_T_A, result_flag, &alias);
	if (ip_check_result == 0) {
		/* match */
		return -1;
	} else if (ip_check_result == -2 || ip_check_result == -3) {
		/* skip, nxdomain */
		return ip_check_result;
	}

	int ret = _dns_server_process_ip_alias(request, alias, paddrs, &paddr_num, MAX_IP_NUM, DNS_RR_A_LEN);
	if (ret != 0) {
		return ret;
	}

	for (int i = 0; i < paddr_num; i++) {
		unsigned char *paddr = paddrs[i];
		if (atomic_read(&request->ip_map_num) == 0) {
			request->has_ip = 1;
			request->ip_addr_type = DNS_T_A;
			memcpy(request->ip_addr, paddr, DNS_RR_A_LEN);
			request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			if (cname[0] != 0 && request->has_cname == 0 && request->conf->dns_force_no_cname == 0) {
				request->has_cname = 1;
				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
			}
		} else {
			if (ttl < request->ip_ttl) {
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			}
		}

		/* Ad blocking result */
		if (paddr[0] == 0 || paddr[0] == 127) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_inc_return(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				request->rcode = DNS_RC_NOERROR;
				return -1;
			}
		}

		/* add this ip to request */
		if (_dns_ip_address_check_add(request, cname, paddr, DNS_T_A, 0, NULL) != 0) {
			/* skip result */
			return -2;
		}

		snprintf(ip, sizeof(ip), "%d.%d.%d.%d", paddr[0], paddr[1], paddr[2], paddr[3]);

		/* start ping */
		_dns_server_request_get(request);
		if (_dns_server_check_speed(request, ip) != 0) {
			_dns_server_request_release(request);
		}
	}

	return 0;
}

static int _dns_server_process_answer_AAAA_IP(struct dns_request *request, char *cname, unsigned char addr[16], int ttl,
											  unsigned int result_flag)
{
	char ip[DNS_MAX_CNAME_LEN] = {0};
	int ip_check_result = 0;
	unsigned char *paddrs[MAX_IP_NUM];
	struct dns_iplist_ip_addresses *alias = NULL;
	int paddr_num = 0;

	paddrs[paddr_num] = addr;
	paddr_num = 1;

	ip_check_result = _dns_server_process_ip_rule(request, addr, 16, DNS_T_AAAA, result_flag, &alias);
	if (ip_check_result == 0) {
		/* match */
		return -1;
	} else if (ip_check_result == -2 || ip_check_result == -3) {
		/* skip, nxdomain */
		return ip_check_result;
	}

	int ret = _dns_server_process_ip_alias(request, alias, paddrs, &paddr_num, MAX_IP_NUM, DNS_RR_AAAA_LEN);
	if (ret != 0) {
		return ret;
	}

	for (int i = 0; i < paddr_num; i++) {
		unsigned char *paddr = paddrs[i];
		if (atomic_read(&request->ip_map_num) == 0) {
			request->has_ip = 1;
			request->ip_addr_type = DNS_T_AAAA;
			memcpy(request->ip_addr, paddr, DNS_RR_AAAA_LEN);
			request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			if (cname[0] != 0 && request->has_cname == 0 && request->conf->dns_force_no_cname == 0) {
				request->has_cname = 1;
				safe_strncpy(request->cname, cname, DNS_MAX_CNAME_LEN);
			}
		} else {
			if (ttl < request->ip_ttl) {
				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
			}
		}

		/* Ad blocking result */
		if (_dns_server_is_adblock_ipv6(paddr) == 0) {
			/* If half of the servers return the same result, then ignore this address */
			if (atomic_inc_return(&request->adblock) <= (dns_server_alive_num() / 2 + dns_server_alive_num() % 2)) {
				request->rcode = DNS_RC_NOERROR;
				return -1;
			}
		}

		/* add this ip to request */
		if (_dns_ip_address_check_add(request, cname, paddr, DNS_T_AAAA, 0, NULL) != 0) {
			/* skip result */
			return -2;
		}

		snprintf(ip, sizeof(ip), "[%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x]", paddr[0],
				 paddr[1], paddr[2], paddr[3], paddr[4], paddr[5], paddr[6], paddr[7], paddr[8], paddr[9], paddr[10],
				 paddr[11], paddr[12], paddr[13], paddr[14], paddr[15]);

		/* start ping */
		_dns_server_request_get(request);
		if (_dns_server_check_speed(request, ip) != 0) {
			_dns_server_request_release(request);
		}
	}

	return 0;
}

static int _dns_server_process_answer_A(struct dns_rrs *rrs, struct dns_request *request, const char *domain,
										char *cname, unsigned int result_flag)
{
	int ttl = 0;
	unsigned char addr[4];
	char name[DNS_MAX_CNAME_LEN] = {0};

	if (request->qtype != DNS_T_A) {
		return -1;
	}

	/* get A result */
	dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

	tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %d.%d.%d.%d", name, ttl, addr[0], addr[1], addr[2], addr[3]);

	/* if domain is not match */
	if (strncasecmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncasecmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
		return -1;
	}

	_dns_server_request_get(request);
	int ret = _dns_server_process_answer_A_IP(request, cname, addr, ttl, result_flag);
	_dns_server_request_release(request);

	return ret;
}

static int _dns_server_process_answer_AAAA(struct dns_rrs *rrs, struct dns_request *request, const char *domain,
										   char *cname, unsigned int result_flag)
{
	unsigned char addr[16];

	char name[DNS_MAX_CNAME_LEN] = {0};

	int ttl = 0;

	if (request->qtype != DNS_T_AAAA) {
		/* ignore non-matched query type */
		return -1;
	}

	dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);

	tlog(TLOG_DEBUG, "domain: %s TTL: %d IP: %.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
		 name, ttl, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10],
		 addr[11], addr[12], addr[13], addr[14], addr[15]);

	/* if domain is not match */
	if (strncmp(name, domain, DNS_MAX_CNAME_LEN) != 0 && strncmp(cname, name, DNS_MAX_CNAME_LEN) != 0) {
		return -1;
	}

	_dns_server_request_get(request);
	int ret = _dns_server_process_answer_AAAA_IP(request, cname, addr, ttl, result_flag);
	_dns_server_request_release(request);

	return ret;
}

static int _dns_server_process_answer_HTTPS(struct dns_rrs *rrs, struct dns_request *request, const char *domain,
											char *cname, unsigned int result_flag)
{
	int ttl = 0;
	int ret = -1;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char target[DNS_MAX_CNAME_LEN] = {0};
	struct dns_https_param *p = NULL;
	int priority = 0;
	struct dns_request_https *https_svcb;
	int no_ipv4 = 0;
	int no_ipv6 = 0;
	struct dns_https_record_rule *https_record_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_HTTPS);
	if (https_record_rule) {
		if (https_record_rule->filter.no_ipv4hint) {
			no_ipv4 = 1;
		}

		if (https_record_rule->filter.no_ipv6hint) {
			no_ipv6 = 1;
		}
	}

	ret = dns_get_HTTPS_svcparm_start(rrs, &p, name, DNS_MAX_CNAME_LEN, &ttl, &priority, target, DNS_MAX_CNAME_LEN);
	if (ret != 0) {
		tlog(TLOG_WARN, "get HTTPS svcparm failed");
		return -1;
	}

	https_svcb = request->https_svcb;
	if (https_svcb == 0) {
		/* ignore non-matched query type */
		tlog(TLOG_WARN, "https svcb not set");
		return -1;
	}

	tlog(TLOG_DEBUG, "domain: %s HTTPS: %s TTL: %d priority: %d", name, target, ttl, priority);
	https_svcb->ttl = ttl;
	https_svcb->priority = priority;
	safe_strncpy(https_svcb->target, target, sizeof(https_svcb->target));
	safe_strncpy(https_svcb->domain, name, sizeof(https_svcb->domain));
	request->ip_ttl = ttl;

	_dns_server_request_get(request);
	for (; p; p = dns_get_HTTPS_svcparm_next(rrs, p)) {
		switch (p->key) {
		case DNS_HTTPS_T_MANDATORY: {
		} break;
		case DNS_HTTPS_T_ALPN: {
			memcpy(https_svcb->alpn, p->value, sizeof(https_svcb->alpn));
			https_svcb->alpn_len = p->len;
		} break;
		case DNS_HTTPS_T_NO_DEFAULT_ALPN: {
		} break;
		case DNS_HTTPS_T_PORT: {
			int port = *(unsigned short *)(p->value);
			https_svcb->port = ntohs(port);
		} break;
		case DNS_HTTPS_T_IPV4HINT: {
			struct dns_rule_address_IPV4 *address_ipv4 = NULL;
			if (_dns_server_is_return_soa_qtype(request, DNS_T_A) || no_ipv4 == 1) {
				break;
			}

			if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
				break;
			}

			address_ipv4 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV4);
			if (address_ipv4 != NULL) {
				memcpy(request->ip_addr, address_ipv4->ipv4_addr, DNS_RR_A_LEN);
				request->has_ip = 1;
				request->ip_addr_type = DNS_T_A;
				break;
			}

			for (int k = 0; k < p->len / 4; k++) {
				_dns_server_process_answer_A_IP(request, cname, p->value + k * 4, ttl, result_flag);
			}
		} break;
		case DNS_HTTPS_T_ECH: {
			if (p->len > sizeof(https_svcb->ech)) {
				tlog(TLOG_WARN, "ech too long");
				break;
			}
			memcpy(https_svcb->ech, p->value, p->len);
			https_svcb->ech_len = p->len;
		} break;
		case DNS_HTTPS_T_IPV6HINT: {
			struct dns_rule_address_IPV6 *address_ipv6 = NULL;

			if (_dns_server_is_return_soa_qtype(request, DNS_T_AAAA) || no_ipv6 == 1) {
				break;
			}

			if (_dns_server_has_bind_flag(request, BIND_FLAG_NO_RULE_ADDR) == 0) {
				break;
			}

			address_ipv6 = _dns_server_get_dns_rule(request, DOMAIN_RULE_ADDRESS_IPV6);
			if (address_ipv6 != NULL) {
				memcpy(request->ip_addr, address_ipv6->ipv6_addr, DNS_RR_AAAA_LEN);
				request->has_ip = 1;
				request->ip_addr_type = DNS_T_AAAA;
				break;
			}

			for (int k = 0; k < p->len / 16; k++) {
				_dns_server_process_answer_AAAA_IP(request, cname, p->value + k * 16, ttl, result_flag);
			}
		} break;
		}
	}

	_dns_server_request_release(request);

	return 0;
}

int _dns_server_process_answer(struct dns_request *request, const char *domain, struct dns_packet *packet,
							   unsigned int result_flag, int *need_passthrouh)
{
	int ttl = 0;
	char name[DNS_MAX_CNAME_LEN] = {0};
	char cname[DNS_MAX_CNAME_LEN] = {0};
	int rr_count = 0;
	int i = 0;
	int j = 0;
	struct dns_rrs *rrs = NULL;
	int ret = 0;
	int is_skip = 0;
	int has_result = 0;
	int is_rcode_set = 0;

	if (packet->head.rcode != DNS_RC_NOERROR && packet->head.rcode != DNS_RC_NXDOMAIN) {
		if (request->rcode == DNS_RC_SERVFAIL) {
			request->rcode = packet->head.rcode;
			request->remote_server_fail = 1;
		}

		tlog(TLOG_DEBUG, "inquery failed, %s, rcode = %d, id = %d\n", domain, packet->head.rcode, packet->head.id);

		if (request->remote_server_fail == 0) {
			return DNS_CLIENT_ACTION_DROP;
		}

		return DNS_CLIENT_ACTION_UNDEFINE;
	}

	/* when QTYPE is HTTPS, check if support */
	if (request->qtype == DNS_T_HTTPS) {
		int https_svcb_record_num = 0;
		for (j = 1; j < DNS_RRS_OPT; j++) {
			rrs = dns_get_rrs_start(packet, j, &rr_count);
			for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
				switch (rrs->type) {
				case DNS_T_HTTPS: {
					https_svcb_record_num++;
					if (https_svcb_record_num <= 1) {
						continue;
					}

					/* CURRENT NOT SUPPORT MUTI HTTPS RECORD */
					*need_passthrouh = 1;
					return DNS_CLIENT_ACTION_OK;
				}
				}
			}
		}
	}

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			has_result = 1;
			switch (rrs->type) {
			case DNS_T_A: {
				ret = _dns_server_process_answer_A(rrs, request, domain, cname, result_flag);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					is_skip = 1;
					continue;
				} else if (ret == -3) {
					return -1;
				}
				request->rcode = packet->head.rcode;
				is_rcode_set = 1;
			} break;
			case DNS_T_AAAA: {
				ret = _dns_server_process_answer_AAAA(rrs, request, domain, cname, result_flag);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					is_skip = 1;
					continue;
				} else if (ret == -3) {
					return -1;
				}
				request->rcode = packet->head.rcode;
				is_rcode_set = 1;
			} break;
			case DNS_T_NS: {
				char nsname[DNS_MAX_CNAME_LEN];
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, nsname, DNS_MAX_CNAME_LEN);
				tlog(TLOG_DEBUG, "NS: %s ttl: %d nsname: %s\n", name, ttl, nsname);
			} break;
			case DNS_T_CNAME: {
				char domain_name[DNS_MAX_CNAME_LEN] = {0};
				char domain_cname[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, domain_name, DNS_MAX_CNAME_LEN, &ttl, domain_cname, DNS_MAX_CNAME_LEN);
				if (strncasecmp(domain_name, request->domain, DNS_MAX_CNAME_LEN - 1) != 0 &&
					strncasecmp(domain_name, cname, DNS_MAX_CNAME_LEN - 1) != 0) {
					continue;
				}
				safe_strncpy(cname, domain_cname, DNS_MAX_CNAME_LEN);
				request->ttl_cname = _dns_server_get_conf_ttl(request, ttl);
				tlog(TLOG_DEBUG, "name: %s ttl: %d cname: %s\n", domain_name, ttl, cname);
			} break;
			case DNS_T_HTTPS: {
				ret = _dns_server_process_answer_HTTPS(rrs, request, domain, cname, result_flag);
				if (ret == -1) {
					break;
				} else if (ret == -2) {
					is_skip = 1;
					continue;
				}
				request->rcode = packet->head.rcode;
				is_rcode_set = 1;
				if (request->has_ip == 0) {
					request->passthrough = 1;
					_dns_server_request_complete(request);
				}
			} break;
			case DNS_T_SOA: {
				/* if DNS64 enabled, skip check SOA. */
				if (_dns_server_is_dns64_request(request)) {
					if (request->has_ip) {
						_dns_server_request_complete(request);
					}
					break;
				}

				request->has_soa = 1;
				if (request->rcode != DNS_RC_NOERROR) {
					request->rcode = packet->head.rcode;
					is_rcode_set = 1;
				}
				dns_get_SOA(rrs, name, 128, &ttl, &request->soa);
				tlog(TLOG_DEBUG,
					 "domain: %s, qtype: %d, SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, "
					 "expire: "
					 "%d, minimum: %d",
					 domain, request->qtype, request->soa.mname, request->soa.rname, request->soa.serial,
					 request->soa.refresh, request->soa.retry, request->soa.expire, request->soa.minimum);

				request->ip_ttl = _dns_server_get_conf_ttl(request, ttl);
				int soa_num = atomic_inc_return(&request->soa_num);
				if ((soa_num >= ((int)ceilf((float)dns_server_alive_num() / 3) + 1) || soa_num > 4) &&
					atomic_read(&request->ip_map_num) <= 0) {
					request->ip_ttl = ttl;
					_dns_server_request_complete(request);
				}
			} break;
			default:
				tlog(TLOG_DEBUG, "%s, qtype: %d, rrstype = %d", name, rrs->type, j);
				break;
			}
		}
	}

	request->remote_server_fail = 0;
	if (request->rcode == DNS_RC_SERVFAIL && is_skip == 0) {
		request->rcode = packet->head.rcode;
	}

	if (has_result == 0 && request->rcode == DNS_RC_NOERROR && packet->head.tc == 1 && request->has_ip == 0 &&
		request->has_soa == 0) {
		tlog(TLOG_DEBUG, "result is truncated, %s qtype: %d, rcode: %d, id: %d, retry.", domain, request->qtype,
			 packet->head.rcode, packet->head.id);
		return DNS_CLIENT_ACTION_RETRY;
	}

	if (is_rcode_set == 0 && has_result == 1 && is_skip == 0) {
		/* need retry for some server. */
		return DNS_CLIENT_ACTION_MAY_RETRY;
	}

	return DNS_CLIENT_ACTION_OK;
}
