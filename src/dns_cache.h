#ifndef _SMARTDNS_CACHE_H
#define _SMARTDNS_CACHE_H

#include "dns.h"
#include "hashtable.h"
#include "hash.h"
#include "list.h"
#include "atomic.h"

struct dns_cache {
	struct hlist_node node;
	struct list_head list;
	atomic_t ref;
	char domain[DNS_MAX_CNAME_LEN];
	unsigned ttl;
	time_t insert_time;
	dns_type_t qtype;
	union {
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		unsigned char addr[0];
	};
};

int dns_cache_init(int size);

int dns_cache_insert(char *domain, int ttl, dns_type_t qtype, unsigned char *addr, int addr_len);

struct dns_cache *dns_cache_get(char *domain, dns_type_t qtype);

void dns_cache_delete(struct dns_cache *dns_cache);

void dns_cache_release(struct dns_cache *dns_cache);

void dns_cache_update(struct dns_cache *dns_cache);

void dns_cache_invalidate(void);

int dns_cache_get_ttl(struct dns_cache *dns_cache);

void dns_cache_destroy(void);

#endif // !_SMARTDNS_CACHE_H