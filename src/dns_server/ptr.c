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

#include "ptr.h"
#include "context.h"
#include "dns_server.h"
#include "mdns.h"
#include "request.h"
#include "rules.h"
#include "soa.h"

#include <ifaddrs.h>

static int _dns_server_is_private_address(const unsigned char *addr, int addr_len)
{
	if (addr_len == 4) {
		if (addr[0] == 10 || (addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31) || (addr[0] == 192 && addr[1] == 168)) {
			return 0;
		}
	} else if (addr_len == 16) {
		if (addr[0] == 0xfe && addr[1] == 0x80) {
			return 0;
		}
	}

	return -1;
}

int _dns_server_get_inet_by_addr(struct sockaddr_storage *localaddr, struct sockaddr_storage *addr, int family)
{
	struct ifaddrs *ifaddr = NULL;
	struct ifaddrs *ifa = NULL;
	char ethname[16] = {0};

	if (getifaddrs(&ifaddr) == -1) {
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (localaddr->ss_family != ifa->ifa_addr->sa_family) {
			continue;
		}

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in_1 = NULL;
			struct sockaddr_in *addr_in_2 = NULL;
			addr_in_1 = (struct sockaddr_in *)ifa->ifa_addr;
			addr_in_2 = (struct sockaddr_in *)localaddr;
			if (memcmp(&(addr_in_1->sin_addr.s_addr), &(addr_in_2->sin_addr.s_addr), 4) != 0) {
				continue;
			}
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6_1 = NULL;
			struct sockaddr_in6 *addr_in6_2 = NULL;
			addr_in6_1 = (struct sockaddr_in6 *)ifa->ifa_addr;
			addr_in6_2 = (struct sockaddr_in6 *)localaddr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6_1->sin6_addr)) {
				unsigned char *addr1 = addr_in6_1->sin6_addr.s6_addr + 12;
				unsigned char *addr2 = addr_in6_2->sin6_addr.s6_addr + 12;
				if (memcmp(addr1, addr2, 4) != 0) {
					continue;
				}
			} else {
				unsigned char *addr1 = addr_in6_1->sin6_addr.s6_addr;
				unsigned char *addr2 = addr_in6_2->sin6_addr.s6_addr;
				if (memcmp(addr1, addr2, 16) != 0) {
					continue;
				}
			}
		} break;
		default:
			continue;
			break;
		}

		safe_strncpy(ethname, ifa->ifa_name, sizeof(ethname));
		break;
	}

	if (ethname[0] == '\0') {
		goto errout;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		if (ifa->ifa_addr->sa_family != family) {
			continue;
		}

		if (strncmp(ethname, ifa->ifa_name, sizeof(ethname)) != 0) {
			continue;
		}

		if (family == AF_INET) {
			memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in));
		} else if (family == AF_INET6) {
			memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
		}

		break;
	}

	if (ifa == NULL) {
		goto errout;
	}

	freeifaddrs(ifaddr);
	return 0;
errout:
	if (ifaddr) {
		freeifaddrs(ifaddr);
	}

	return -1;
}

static int _dns_server_parser_addr_from_apra(const char *arpa, unsigned char *addr, int *addr_len, int max_addr_len)
{
	int high, low;
	char *endptr = NULL;

	if (arpa == NULL || addr == NULL || addr_len == NULL || max_addr_len < 4) {
		return -1;
	}

	int ret = sscanf(arpa, "%hhd.%hhd.%hhd.%hhd.in-addr.arpa", &addr[3], &addr[2], &addr[1], &addr[0]);
	if (ret == 4 && strstr(arpa, ".in-addr.arpa") != NULL) {
		*addr_len = 4;
		return 0;
	}

	if (max_addr_len != 16) {
		return -1;
	}

	for (int i = 15; i >= 0; i--) {
		low = strtol(arpa, &endptr, 16);
		if (endptr == NULL || *endptr != '.' || *endptr == '\0') {
			return -1;
		}

		arpa = endptr + 1;
		high = strtol(arpa, &endptr, 16);
		if (endptr == NULL || *endptr != '.' || *endptr == '\0') {
			return -1;
		}

		arpa = endptr + 1;
		addr[i] = (high << 4) | low;
	}

	if (strstr(arpa, "ip6.arpa") == NULL) {
		return -1;
	}

	*addr_len = 16;

	return 0;
}

int _dns_server_process_ptr_query(struct dns_request *request)
{
	if (request->qtype != DNS_T_PTR) {
		return -1;
	}

	if (_dns_server_process_ptr(request) == 0) {
		return 0;
	}

	request->passthrough = 1;
	return -1;
}

int _dns_server_process_ptrs(struct dns_request *request)
{
	uint32_t key = 0;
	struct dns_ptr *ptr = NULL;
	struct dns_ptr *ptr_tmp = NULL;
	key = hash_string(request->domain);
	hash_for_each_possible(dns_ptr_table.ptr, ptr_tmp, node, key)
	{
		if (strncmp(ptr_tmp->ptr_domain, request->domain, DNS_MAX_PTR_LEN) != 0) {
			continue;
		}

		ptr = ptr_tmp;
		break;
	}

	if (ptr == NULL) {
		goto errout;
	}

	request->has_ptr = 1;
	safe_strncpy(request->ptr_hostname, ptr->hostname, DNS_MAX_CNAME_LEN);
	return 0;
errout:
	return -1;
}

int _dns_server_process_ptr(struct dns_request *request)
{
	if (_dns_server_process_ptrs(request) == 0) {
		goto reply_exit;
	}

	if (_dns_server_process_local_ptr(request) == 0) {
		goto reply_exit;
	}

	return -1;

reply_exit:
	request->rcode = DNS_RC_NOERROR;
	request->ip_ttl = _dns_server_get_local_ttl(request);
	struct dns_server_post_context context;
	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;
	context.do_audit = 0;
	context.do_cache = 1;
	_dns_request_post(&context);
	return 0;
}

int _dns_server_process_local_ptr(struct dns_request *request)
{
	unsigned char ptr_addr[16];
	int ptr_addr_len = 0;
	int found = 0;
	prefix_t prefix;
	radix_node_t *node = NULL;
	struct local_addr_cache_item *addr_cache_item = NULL;
	struct dns_nameserver_rule *ptr_nameserver_rule;

	if (_dns_server_parser_addr_from_apra(request->domain, ptr_addr, &ptr_addr_len, sizeof(ptr_addr)) != 0) {
		/* Determine if the smartdns service is in effect. */
		if (strncasecmp(request->domain, "smartdns", sizeof("smartdns")) != 0) {
			return -1;
		}
		found = 1;
		goto out;
	}

	if (dns_conf.local_ptr_enable == 0) {
		goto out;
	}

	if (prefix_from_blob(ptr_addr, ptr_addr_len, ptr_addr_len * 8, &prefix) == NULL) {
		goto out;
	}

	node = radix_search_best(server.local_addr_cache.addr, &prefix);
	if (node == NULL) {
		goto out;
	}

	if (node->data == NULL) {
		goto out;
	}

	addr_cache_item = node->data;
	if (addr_cache_item->mask_len == ptr_addr_len * 8) {
		found = 1;
		goto out;
	}

	if (dns_conf.mdns_lookup) {
		_dns_server_set_request_mdns(request);
		goto errout;
	}

out:
	ptr_nameserver_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_NAMESERVER);
	if (ptr_nameserver_rule != NULL && ptr_nameserver_rule->group_name[0] != 0) {
		goto errout;
	}

	if (found == 0 && _dns_server_is_private_address(ptr_addr, ptr_addr_len) == 0) {
		request->has_soa = 1;
		_dns_server_setup_soa(request);
		goto clear;
	}

	if (found == 0) {
		goto errout;
	}

	char full_hostname[DNS_MAX_CNAME_LEN];
	if (dns_server_get_server_name(full_hostname, sizeof(full_hostname)) != 0) {
		goto errout;
	}

	request->has_ptr = 1;
	safe_strncpy(request->ptr_hostname, full_hostname, DNS_MAX_CNAME_LEN);
clear:
	return 0;
errout:
	return -1;
}

int _dns_server_get_local_ttl(struct dns_request *request)
{
	struct dns_ttl_rule *ttl_rule;

	/* get domain rule flag */
	ttl_rule = _dns_server_get_dns_rule(request, DOMAIN_RULE_TTL);
	if (ttl_rule != NULL) {
		if (ttl_rule->ttl > 0) {
			return ttl_rule->ttl;
		}
	}

	if (dns_conf.local_ttl > 0) {
		return dns_conf.local_ttl;
	}

	if (request->conf->dns_rr_ttl > 0) {
		return request->conf->dns_rr_ttl;
	}

	if (request->conf->dns_rr_ttl_min > 0) {
		return request->conf->dns_rr_ttl_min;
	}

	return DNS_SERVER_ADDR_TTL;
}
