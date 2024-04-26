/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "dns_conf.h"
#include "hash.h"
#include "hashtable.h"
#include "list.h"
#include "timer.h"
#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_CACHE_TTL_MIN 1
#define DNS_CACHE_VERSION_LEN 32
#define DNS_CACHE_GROUP_NAME_LEN 32
#define MAGIC_NUMBER 0x6548634163536e44
#define MAGIC_CACHE_DATA 0x61546144
#define MAGIC_RECORD 0x64526352

struct dns_cache_data_head {
	atomic_t ref;
	ssize_t size;
	uint32_t magic;
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
	dns_type_t qtype;
	char dns_group_name[DNS_GROUP_NAME_LEN];
	uint32_t query_flag;
	int ttl;
	int rcode;
	int hitnum;
	int speed;
	int timeout;
	int hitnum_update_add;
	int is_visited;
	time_t insert_time;
	time_t replace_time;
};

struct dns_cache_record {
	uint32_t magic;
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

	struct tw_timer_list timer;
};

struct dns_cache_file {
	uint64_t magic;
	char version[DNS_CACHE_VERSION_LEN];
	uint32_t cache_number;
};

struct dns_cache_key {
	const char *domain;
	dns_type_t qtype;
	const char *dns_group_name;
	uint32_t query_flag;
};

uint32_t dns_cache_get_query_flag(struct dns_cache *dns_cache);

const char *dns_cache_get_dns_group_name(struct dns_cache *dns_cache);

struct dns_cache_data *dns_cache_new_data_packet(void *packet, size_t packet_len);

typedef enum DNS_CACHE_TMOUT_ACTION {
	DNS_CACHE_TMOUT_ACTION_OK = 0,
	DNS_CACHE_TMOUT_ACTION_DEL = 1,
	DNS_CACHE_TMOUT_ACTION_RETRY = 2,
	DNS_CACHE_TMOUT_ACTION_UPDATE = 3,
} dns_cache_tmout_action_t;

typedef dns_cache_tmout_action_t (*dns_cache_callback)(struct dns_cache *dns_cache);

int dns_cache_init(int size, int mem_size, dns_cache_callback timeout_callback);

int dns_cache_replace(struct dns_cache_key *key, int rcode, int ttl, int speed, int timeout, int update_time,
					  struct dns_cache_data *cache_data);

int dns_cache_insert(struct dns_cache_key *key, int rcode, int ttl, int speed, int timeout,
					 struct dns_cache_data *cache_data);

struct dns_cache *dns_cache_lookup(struct dns_cache_key *key);

int dns_cache_total_num(void);

long dns_cache_total_memsize(void);

int dns_cache_update_timer(struct dns_cache_key *key, int timeout);

void dns_cache_delete(struct dns_cache *dns_cache);

void dns_cache_get(struct dns_cache *dns_cache);

void dns_cache_release(struct dns_cache *dns_cache);

int dns_cache_hitnum_dec_get(struct dns_cache *dns_cache);

int dns_cache_is_visited(struct dns_cache *dns_cache);

void dns_cache_update(struct dns_cache *dns_cache);

int dns_cache_get_ttl(struct dns_cache *dns_cache);

struct dns_cache_data *dns_cache_get_data(struct dns_cache *dns_cache);

void dns_cache_data_get(struct dns_cache_data *cache_data);

void dns_cache_data_put(struct dns_cache_data *cache_data);

void dns_cache_flush(void);

void dns_cache_destroy(void);

int dns_cache_load(const char *file);

int dns_cache_save(const char *file, int check_lock);

int dns_cache_print(const char *file);

const char *dns_cache_file_version(void);

#ifdef __cplusplus
}
#endif
#endif // !_SMARTDNS_CACHE_H
