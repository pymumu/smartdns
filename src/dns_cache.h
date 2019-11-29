/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef _SMARTDNS_CACHE_H
#define _SMARTDNS_CACHE_H

#include "atomic.h"
#include "dns.h"
#include "hash.h"
#include "hashtable.h"
#include "list.h"
#include <stdlib.h>
#include <time.h>

#ifdef __cpluscplus
extern "C" {
#endif

#define DNS_CACHE_TTL_MIN 30

struct dns_cache {
	struct hlist_node node;
	struct list_head list;
	struct list_head check_list;
	atomic_t ref;
	char domain[DNS_MAX_CNAME_LEN];
	char cname[DNS_MAX_CNAME_LEN];
	unsigned int cname_ttl;
	unsigned int ttl;
	int speed;
	atomic_t hitnum;
	int hitnum_update_add;
	int del_pending;
	time_t insert_time;
	dns_type_t qtype;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

int dns_cache_init(int size);

int dns_cache_replace(char *domain, char *cname, int cname_ttl, int ttl, dns_type_t qtype, unsigned char *addr, int addr_len, int speed);

int dns_cache_insert(char *domain, char *cname, int cname_ttl, int ttl, dns_type_t qtype, unsigned char *addr, int addr_len, int speed);

struct dns_cache *dns_cache_lookup(char *domain, dns_type_t qtype);

void dns_cache_delete(struct dns_cache *dns_cache);

void dns_cache_get(struct dns_cache *dns_cache);

void dns_cache_release(struct dns_cache *dns_cache);

int dns_cache_hitnum_dec_get(struct dns_cache *dns_cache);

void dns_cache_update(struct dns_cache *dns_cache);

typedef void dns_cache_preinvalid_callback(struct dns_cache *dns_cache);

void dns_cache_invalidate(dns_cache_preinvalid_callback callback, int ttl_pre);

int dns_cache_get_ttl(struct dns_cache *dns_cache);

void dns_cache_destroy(void);

#ifdef __cpluscplus
}
#endif
#endif // !_SMARTDNS_CACHE_H
