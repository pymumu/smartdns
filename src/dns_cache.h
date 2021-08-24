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
#define DNS_CACHE_VERSION_LEN 32
#define MAGIC_NUMBER 0x6548634163536e44
#define MAGIC_CACHE_DATA 0x44615461

enum CACHE_TYPE {
	CACHE_TYPE_NONE,
	CACHE_TYPE_ADDR,
	CACHE_TYPE_PACKET,
};

enum CACHE_RECORD_TYPE {
	CACHE_RECORD_TYPE_ACTIVE,
	CACHE_RECORD_TYPE_INACTIVE,
};

struct dns_cache_data_head {
	uint32_t cache_flag;
	enum CACHE_TYPE cache_type;
	size_t size;
};

struct dns_cache_data {
	struct dns_cache_data_head head;
	unsigned char data[0];
};

struct dns_cache_addr {
	struct dns_cache_data_head head;
	struct dns_cache_addr_data {
		unsigned int cname_ttl;
		char soa;
		char cname[DNS_MAX_CNAME_LEN];
		union {
			unsigned char ipv4_addr[DNS_RR_A_LEN];
			unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
			unsigned char addr[0];
		};
	} addr_data;
};

struct dns_cache_packet {
	struct dns_cache_data_head head;
	unsigned char data[0];
};

struct dns_cache_info {
	char domain[DNS_MAX_CNAME_LEN];
	int ttl;
	int hitnum;
	int speed;
	int hitnum_update_add;
	time_t insert_time;
	dns_type_t qtype;
};

struct dns_cache_record {
	uint32_t magic;
	enum CACHE_RECORD_TYPE type;
	struct dns_cache_info info;
};

struct dns_cache {
	struct hlist_node node;
	struct list_head list;
	struct list_head check_list;

	atomic_t ref;
	int del_pending;

	struct dns_cache_info info;
	struct dns_cache_data *cache_data;
};

struct dns_cache_file {
	uint64_t magic;
	char version[DNS_CACHE_VERSION_LEN];
	uint32_t cache_number;
};

enum CACHE_TYPE dns_cache_data_type(struct dns_cache_data *cache_data);

uint32_t dns_cache_get_cache_flag(struct dns_cache_data *cache_data);

void dns_cache_data_free(struct dns_cache_data *data);

struct dns_cache_data *dns_cache_new_data_packet(uint32_t cache_flag, void *packet, size_t packet_len);

int dns_cache_init(int size, int enable_inactive, int inactive_list_expired);

int dns_cache_replace(char *domain, int ttl, dns_type_t qtype, int speed, struct dns_cache_data *cache_data);

int dns_cache_insert(char *domain, int ttl, dns_type_t qtype, int speed, struct dns_cache_data *cache_data);

struct dns_cache *dns_cache_lookup(char *domain, dns_type_t qtype);

void dns_cache_delete(struct dns_cache *dns_cache);

void dns_cache_get(struct dns_cache *dns_cache);

void dns_cache_release(struct dns_cache *dns_cache);

int dns_cache_hitnum_dec_get(struct dns_cache *dns_cache);

void dns_cache_update(struct dns_cache *dns_cache);

typedef void dns_cache_preinvalid_callback(struct dns_cache *dns_cache);

void dns_cache_invalidate(dns_cache_preinvalid_callback callback, int ttl_pre);

int dns_cache_get_ttl(struct dns_cache *dns_cache);

int dns_cache_is_soa(struct dns_cache *dns_cache);

struct dns_cache_data *dns_cache_new_data(void);

struct dns_cache_data *dns_cache_get_data(struct dns_cache *dns_cache);

void dns_cache_set_data_addr(struct dns_cache_data *dns_cache, uint32_t cache_flag, char *cname, int cname_ttl,
							 unsigned char *addr, int addr_len);

void dns_cache_set_data_soa(struct dns_cache_data *dns_cache, int32_t cache_flag, char *cname, int cname_ttl);

void dns_cache_destroy(void);

int dns_cache_load(const char *file);

int dns_cache_save(const char *file);

#ifdef __cpluscplus
}
#endif
#endif // !_SMARTDNS_CACHE_H
