#ifndef _SMARTDNS_CACHE_H
#define _SMARTDNS_CACHE_H

#include "atomic.h"
#include "dns.h"
#include "hash.h"
#include "hashtable.h"
#include "list.h"
#include <stdlib.h>
#include <time.h>

#define DNS_CACHE_TTL_MIN 30

struct dns_cache {
	struct hlist_node node;
	struct list_head list;
	struct list_head check_list;
	atomic_t ref;
	char domain[DNS_MAX_CNAME_LEN];
	char cname[DNS_MAX_CNAME_LEN];
	unsigned int cname_ttl;
	unsigned int ttl;;
	int speed;
	int hitnum;
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

void dns_cache_update(struct dns_cache *dns_cache);

typedef void dns_cache_preinvalid_callback(struct dns_cache *dns_cache);

void dns_cache_invalidate(dns_cache_preinvalid_callback callback, int ttl_pre);

int dns_cache_get_ttl(struct dns_cache *dns_cache);

void dns_cache_destroy(void);

#endif // !_SMARTDNS_CACHE_H
