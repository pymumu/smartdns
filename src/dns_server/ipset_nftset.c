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

#include "ipset_nftset.h"
#include "dns_server.h"
#include "smartdns/lib/nftset.h"
#include "smartdns/util.h"

void _dns_server_add_ipset_nftset(struct dns_request *request, struct dns_ipset_rule *ipset_rule,
								  struct dns_nftset_rule *nftset_rule, const unsigned char addr[], int addr_len,
								  int ipset_timeout_value, int nftset_timeout_value)
{
	if (ipset_rule != NULL) {
		/* add IPV4 to ipset */
		if (addr_len == DNS_RR_A_LEN) {
			tlog(TLOG_DEBUG, "IPSET-MATCH: domain: %s, ipset: %s, IP: %d.%d.%d.%d", request->domain,
				 ipset_rule->ipsetname, addr[0], addr[1], addr[2], addr[3]);
			ipset_add(ipset_rule->ipsetname, addr, DNS_RR_A_LEN, ipset_timeout_value);
		} else if (addr_len == DNS_RR_AAAA_LEN) {
			tlog(TLOG_DEBUG,
				 "IPSET-MATCH: domain: %s, ipset: %s, IP: "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, ipset_rule->ipsetname, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6],
				 addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
			ipset_add(ipset_rule->ipsetname, addr, DNS_RR_AAAA_LEN, ipset_timeout_value);
		}
	}

	if (nftset_rule != NULL) {
		/* add IPV4 to ipset */
		if (addr_len == DNS_RR_A_LEN) {
			tlog(TLOG_DEBUG, "NFTSET-MATCH: domain: %s, nftset: %s %s %s, IP: %d.%d.%d.%d", request->domain,
				 nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr[0], addr[1], addr[2],
				 addr[3]);
			nftset_add(nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr, DNS_RR_A_LEN,
					   nftset_timeout_value);
		} else if (addr_len == DNS_RR_AAAA_LEN) {
			tlog(TLOG_DEBUG,
				 "NFTSET-MATCH: domain: %s, nftset: %s %s %s, IP: "
				 "%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x",
				 request->domain, nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr[0],
				 addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8], addr[9], addr[10], addr[11],
				 addr[12], addr[13], addr[14], addr[15]);
			nftset_add(nftset_rule->familyname, nftset_rule->nfttablename, nftset_rule->nftsetname, addr,
					   DNS_RR_AAAA_LEN, nftset_timeout_value);
		}
	}
}

void *_dns_server_get_bind_ipset_nftset_rule(struct dns_request *request, enum domain_rule type)
{
	if (request->conn == NULL) {
		return NULL;
	}

	if (request->conn->ipset_nftset_rule == NULL) {
		return NULL;
	}

	switch (type) {
	case DOMAIN_RULE_IPSET:
		return request->conn->ipset_nftset_rule->ipset;
	case DOMAIN_RULE_IPSET_IPV4:
		return request->conn->ipset_nftset_rule->ipset_ip;
	case DOMAIN_RULE_IPSET_IPV6:
		return request->conn->ipset_nftset_rule->ipset_ip6;
	case DOMAIN_RULE_NFTSET_IP:
		return request->conn->ipset_nftset_rule->nftset_ip;
	case DOMAIN_RULE_NFTSET_IP6:
		return request->conn->ipset_nftset_rule->nftset_ip6;
	default:
		break;
	}

	return NULL;
}