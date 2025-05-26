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
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

#include <stdio.h>

struct dns_ptr_table dns_ptr_table;

static struct dns_ptr *_dns_conf_get_ptr(const char *ptr_domain)
{
	uint32_t key = 0;
	struct dns_ptr *ptr = NULL;

	key = hash_string(ptr_domain);
	hash_for_each_possible(dns_ptr_table.ptr, ptr, node, key)
	{
		if (strncmp(ptr->ptr_domain, ptr_domain, DNS_MAX_PTR_LEN) != 0) {
			continue;
		}

		return ptr;
	}

	ptr = malloc(sizeof(*ptr));
	if (ptr == NULL) {
		goto errout;
	}

	safe_strncpy(ptr->ptr_domain, ptr_domain, DNS_MAX_PTR_LEN);
	hash_add(dns_ptr_table.ptr, &ptr->node, key);
	ptr->is_soa = 1;

	return ptr;
errout:
	if (ptr) {
		free(ptr);
	}

	return NULL;
}

int _conf_ptr_add(const char *hostname, const char *ip, int is_dynamic)
{
	struct dns_ptr *ptr = NULL;
	struct sockaddr_storage addr;
	unsigned char *paddr = NULL;
	socklen_t addr_len = sizeof(addr);
	char ptr_domain[DNS_MAX_PTR_LEN];

	if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
		goto errout;
	}

	switch (addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr_in = NULL;
		addr_in = (struct sockaddr_in *)&addr;
		paddr = (unsigned char *)&(addr_in->sin_addr.s_addr);
		snprintf(ptr_domain, sizeof(ptr_domain), "%d.%d.%d.%d.in-addr.arpa", paddr[3], paddr[2], paddr[1], paddr[0]);
	} break;
	case AF_INET6: {
		struct sockaddr_in6 *addr_in6 = NULL;
		addr_in6 = (struct sockaddr_in6 *)&addr;
		if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
			paddr = addr_in6->sin6_addr.s6_addr + 12;
			snprintf(ptr_domain, sizeof(ptr_domain), "%d.%d.%d.%d.in-addr.arpa", paddr[3], paddr[2], paddr[1],
					 paddr[0]);
		} else {
			paddr = addr_in6->sin6_addr.s6_addr;
			snprintf(ptr_domain, sizeof(ptr_domain),
					 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
					 "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x."
					 "%x.ip6.arpa",
					 paddr[15] & 0xF, (paddr[15] >> 4) & 0xF, paddr[14] & 0xF, (paddr[14] >> 4) & 0xF, paddr[13] & 0xF,
					 (paddr[13] >> 4) & 0xF, paddr[12] & 0xF, (paddr[12] >> 4) & 0xF, paddr[11] & 0xF,
					 (paddr[11] >> 4) & 0xF, paddr[10] & 0xF, (paddr[10] >> 4) & 0xF, paddr[9] & 0xF,
					 (paddr[9] >> 4) & 0xF, paddr[8] & 0xF, (paddr[8] >> 4) & 0xF, paddr[7] & 0xF,
					 (paddr[7] >> 4) & 0xF, paddr[6] & 0xF, (paddr[6] >> 4) & 0xF, paddr[5] & 0xF,
					 (paddr[5] >> 4) & 0xF, paddr[4] & 0xF, (paddr[4] >> 4) & 0xF, paddr[3] & 0xF,
					 (paddr[3] >> 4) & 0xF, paddr[2] & 0xF, (paddr[2] >> 4) & 0xF, paddr[1] & 0xF,
					 (paddr[1] >> 4) & 0xF, paddr[0] & 0xF, (paddr[0] >> 4) & 0xF);
		}
	} break;
	default:
		goto errout;
		break;
	}

	ptr = _dns_conf_get_ptr(ptr_domain);
	if (ptr == NULL) {
		goto errout;
	}

	if (is_dynamic == 1 && ptr->is_soa == 0 && ptr->is_dynamic == 0) {
		/* already set fix PTR, skip */
		return 0;
	}

	ptr->is_dynamic = is_dynamic;
	ptr->is_soa = 0;
	safe_strncpy(ptr->hostname, hostname, DNS_MAX_CNAME_LEN);

	return 0;

errout:
	return -1;
}

void _config_ptr_table_init(void)
{
	hash_init(dns_ptr_table.ptr);
}

void _config_ptr_table_destroy(int only_dynamic)
{
	struct dns_ptr *ptr = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_ptr_table.ptr, i, tmp, ptr, node)
	{
		if (only_dynamic != 0 && ptr->is_dynamic == 0) {
			continue;
		}

		hlist_del_init(&ptr->node);
		free(ptr);
	}
}
