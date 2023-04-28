/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "dns_cache.h"
#include "stringutil.h"
#include "tlog.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

#define DNS_CACHE_MAX_HITNUM 5000
#define DNS_CACHE_HITNUM_STEP 2
#define DNS_CACHE_HITNUM_STEP_MAX 6

struct dns_cache_head {
	DECLARE_HASHTABLE(cache_hash, 16);
	struct list_head cache_list;
	struct list_head inactive_list;
	atomic_t num;
	int size;
	int enable_inactive;
	int inactive_list_expired;
	pthread_mutex_t lock;
};

static struct dns_cache_head dns_cache_head;

int dns_cache_init(int size, int enable_inactive, int inactive_list_expired)
{
	INIT_LIST_HEAD(&dns_cache_head.cache_list);
	INIT_LIST_HEAD(&dns_cache_head.inactive_list);
	hash_init(dns_cache_head.cache_hash);
	atomic_set(&dns_cache_head.num, 0);
	dns_cache_head.size = size;
	dns_cache_head.enable_inactive = enable_inactive;
	dns_cache_head.inactive_list_expired = inactive_list_expired;

	pthread_mutex_init(&dns_cache_head.lock, NULL);

	return 0;
}

static __attribute__((unused)) struct dns_cache *_dns_cache_last(void)
{
	struct dns_cache *dns_cache = NULL;

	dns_cache = list_last_entry(&dns_cache_head.inactive_list, struct dns_cache, list);
	if (dns_cache) {
		return dns_cache;
	}

	return list_last_entry(&dns_cache_head.cache_list, struct dns_cache, list);
}

static struct dns_cache *_dns_inactive_cache_first(void)
{
	struct dns_cache *dns_cache = NULL;

	dns_cache = list_first_entry_or_null(&dns_cache_head.inactive_list, struct dns_cache, list);
	if (dns_cache) {
		return dns_cache;
	}

	return list_first_entry_or_null(&dns_cache_head.cache_list, struct dns_cache, list);
}

static void _dns_cache_delete(struct dns_cache *dns_cache)
{
	hash_del(&dns_cache->node);
	list_del_init(&dns_cache->list);
	atomic_dec(&dns_cache_head.num);
	dns_cache_data_free(dns_cache->cache_data);
	free(dns_cache);
}

void dns_cache_get(struct dns_cache *dns_cache)
{
	if (atomic_inc_return(&dns_cache->ref) == 1) {
		tlog(TLOG_ERROR, "BUG: dns_cache is invalid.");
		return;
	}
}

void dns_cache_release(struct dns_cache *dns_cache)
{
	if (dns_cache == NULL) {
		return;
	}
	if (!atomic_dec_and_test(&dns_cache->ref)) {
		return;
	}

	_dns_cache_delete(dns_cache);
}

static void _dns_cache_remove(struct dns_cache *dns_cache)
{
	hash_del(&dns_cache->node);
	list_del_init(&dns_cache->list);
	dns_cache_release(dns_cache);
}

static void _dns_cache_move_inactive(struct dns_cache *dns_cache)
{
	list_del_init(&dns_cache->list);
	list_add_tail(&dns_cache->list, &dns_cache_head.inactive_list);
}

enum CACHE_TYPE dns_cache_data_type(struct dns_cache_data *cache_data)
{
	return cache_data->head.cache_type;
}

uint32_t dns_cache_get_query_flag(struct dns_cache *dns_cache)
{
	return dns_cache->info.query_flag;
}

const char *dns_cache_get_dns_group_name(struct dns_cache *dns_cache)
{
	return dns_cache->info.dns_group_name;
}

void dns_cache_data_free(struct dns_cache_data *data)
{
	if (data == NULL) {
		return;
	}

	free(data);
}

struct dns_cache_data *dns_cache_new_data_addr(void)
{
	struct dns_cache_addr *cache_addr = malloc(sizeof(struct dns_cache_addr));
	memset(cache_addr, 0, sizeof(struct dns_cache_addr));
	if (cache_addr == NULL) {
		return NULL;
	}

	cache_addr->head.cache_type = CACHE_TYPE_NONE;
	cache_addr->head.size = sizeof(struct dns_cache_addr) - sizeof(struct dns_cache_data_head);
	cache_addr->head.magic = MAGIC_CACHE_DATA;

	return (struct dns_cache_data *)cache_addr;
}

void dns_cache_set_data_soa(struct dns_cache_data *dns_cache, char *cname, int cname_ttl)
{
	if (dns_cache == NULL) {
		goto errout;
	}

	dns_cache->head.is_soa = 1;
	if (dns_cache->head.cache_type == CACHE_TYPE_PACKET) {
		return;
	}

	struct dns_cache_addr *cache_addr = (struct dns_cache_addr *)dns_cache;
	if (cache_addr == NULL) {
		goto errout;
	}

	memset(cache_addr->addr_data.addr, 0, sizeof(cache_addr->addr_data.addr));

	if (cname) {
		safe_strncpy(cache_addr->addr_data.cname, cname, DNS_MAX_CNAME_LEN);
		cache_addr->addr_data.cname_ttl = cname_ttl;
	}

	cache_addr->addr_data.soa = 1;
	cache_addr->head.cache_type = CACHE_TYPE_ADDR;
	cache_addr->head.size = sizeof(struct dns_cache_addr) - sizeof(struct dns_cache_data_head);
errout:
	return;
}

void dns_cache_set_data_addr(struct dns_cache_data *dns_cache, char *cname, int cname_ttl, unsigned char *addr,
							 int addr_len)
{
	if (dns_cache == NULL) {
		goto errout;
	}

	struct dns_cache_addr *cache_addr = (struct dns_cache_addr *)dns_cache;
	if (cache_addr == NULL) {
		goto errout;
	}

	if (addr_len == DNS_RR_A_LEN) {
		memcpy(cache_addr->addr_data.addr, addr, DNS_RR_A_LEN);
	} else if (addr_len != DNS_RR_AAAA_LEN) {
		memcpy(cache_addr->addr_data.addr, addr, DNS_RR_AAAA_LEN);
	} else {
		goto errout;
	}

	if (cname) {
		safe_strncpy(cache_addr->addr_data.cname, cname, DNS_MAX_CNAME_LEN);
		cache_addr->addr_data.cname_ttl = cname_ttl;
	}

	cache_addr->head.cache_type = CACHE_TYPE_ADDR;
	cache_addr->head.size = sizeof(struct dns_cache_addr) - sizeof(struct dns_cache_data_head);
errout:
	return;
}

struct dns_cache_data *dns_cache_new_data_packet(void *packet, size_t packet_len)
{
	struct dns_cache_packet *cache_packet = NULL;
	size_t data_size = 0;
	if (packet == NULL || packet_len <= 0) {
		return NULL;
	}

	data_size = sizeof(*cache_packet) + packet_len;
	cache_packet = malloc(data_size);
	if (cache_packet == NULL) {
		return NULL;
	}

	memcpy(cache_packet->data, packet, packet_len);
	memset(&cache_packet->head, 0, sizeof(cache_packet->head));

	cache_packet->head.cache_type = CACHE_TYPE_PACKET;
	cache_packet->head.size = packet_len;
	cache_packet->head.magic = MAGIC_CACHE_DATA;

	return (struct dns_cache_data *)cache_packet;
}

static int _dns_cache_replace(struct dns_cache_key *cache_key, int ttl, int speed, int no_inactive, int inactive,
							  struct dns_cache_data *cache_data)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache_data *old_cache_data = NULL;

	if (dns_cache_head.size <= 0) {
		return 0;
	}

	/* lookup existing cache */
	dns_cache = dns_cache_lookup(cache_key);
	if (dns_cache == NULL) {
		return dns_cache_insert(cache_key, ttl, speed, no_inactive, cache_data);
	}

	if (ttl < DNS_CACHE_TTL_MIN) {
		ttl = DNS_CACHE_TTL_MIN;
	}

	/* update cache data */
	pthread_mutex_lock(&dns_cache_head.lock);
	dns_cache->del_pending = 0;
	dns_cache->info.ttl = ttl;
	dns_cache->info.qtype = cache_key->qtype;
	dns_cache->info.query_flag = cache_key->query_flag;
	dns_cache->info.ttl = ttl;
	dns_cache->info.speed = speed;
	dns_cache->info.no_inactive = no_inactive;
	dns_cache->info.is_visited = 1;
	old_cache_data = dns_cache->cache_data;
	dns_cache->cache_data = cache_data;
	list_del_init(&dns_cache->list);

	if (inactive == 0) {
		time(&dns_cache->info.insert_time);
		time(&dns_cache->info.replace_time);
		list_add_tail(&dns_cache->list, &dns_cache_head.cache_list);
	} else {
		time(&dns_cache->info.replace_time);
		list_add_tail(&dns_cache->list, &dns_cache_head.inactive_list);
	}

	pthread_mutex_unlock(&dns_cache_head.lock);

	dns_cache_data_free(old_cache_data);
	dns_cache_release(dns_cache);
	return 0;
}

int dns_cache_replace(struct dns_cache_key *cache_key, int ttl, int speed, int no_inactive,
					  struct dns_cache_data *cache_data)
{
	return _dns_cache_replace(cache_key, ttl, speed, no_inactive, 0, cache_data);
}

int dns_cache_replace_inactive(struct dns_cache_key *cache_key, int ttl, int speed, int no_inactive,
							   struct dns_cache_data *cache_data)
{
	return _dns_cache_replace(cache_key, ttl, speed, no_inactive, 1, cache_data);
}

static void _dns_cache_remove_by_domain(struct dns_cache_key *cache_key)
{
	uint32_t key = 0;
	struct dns_cache *dns_cache = NULL;

	key = hash_string(cache_key->domain);
	key = jhash(&cache_key->qtype, sizeof(cache_key->qtype), key);
	key = hash_string_initval(cache_key->dns_group_name, key);
	key = jhash(&cache_key->query_flag, sizeof(cache_key->query_flag), key);

	pthread_mutex_lock(&dns_cache_head.lock);
	hash_for_each_possible(dns_cache_head.cache_hash, dns_cache, node, key)
	{
		if (dns_cache->info.qtype != cache_key->qtype) {
			continue;
		}

		if (dns_cache->info.query_flag != cache_key->query_flag) {
			continue;
		}

		if (strncmp(cache_key->domain, dns_cache->info.domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		if (strncmp(dns_cache->info.dns_group_name, cache_key->dns_group_name, DNS_GROUP_NAME_LEN) != 0) {
			continue;
		}

		_dns_cache_remove(dns_cache);
		break;
	}

	pthread_mutex_unlock(&dns_cache_head.lock);
}

static int _dns_cache_insert(struct dns_cache_info *info, struct dns_cache_data *cache_data, struct list_head *head)
{
	uint32_t key = 0;
	struct dns_cache *dns_cache = NULL;

	/* if cache already exists, free */
	struct dns_cache_key cache_key;
	cache_key.qtype = info->qtype;
	cache_key.query_flag = info->query_flag;
	cache_key.domain = info->domain;
	cache_key.dns_group_name = info->dns_group_name;
	_dns_cache_remove_by_domain(&cache_key);

	dns_cache = malloc(sizeof(*dns_cache));
	if (dns_cache == NULL) {
		goto errout;
	}

	memset(dns_cache, 0, sizeof(*dns_cache));
	key = hash_string(info->domain);
	key = jhash(&info->qtype, sizeof(info->qtype), key);
	key = hash_string_initval(info->dns_group_name, key);
	key = jhash(&info->query_flag, sizeof(info->query_flag), key);
	atomic_set(&dns_cache->ref, 1);
	memcpy(&dns_cache->info, info, sizeof(*info));
	dns_cache->del_pending = 0;
	dns_cache->cache_data = cache_data;
	pthread_mutex_lock(&dns_cache_head.lock);
	hash_add(dns_cache_head.cache_hash, &dns_cache->node, key);
	list_add_tail(&dns_cache->list, head);
	INIT_LIST_HEAD(&dns_cache->check_list);

	/* Release extra cache, remove oldest cache record */
	if (atomic_inc_return(&dns_cache_head.num) > dns_cache_head.size) {
		struct dns_cache *del_cache = NULL;
		del_cache = _dns_inactive_cache_first();
		if (del_cache) {
			_dns_cache_remove(del_cache);
		}
	}
	pthread_mutex_unlock(&dns_cache_head.lock);

	return 0;
errout:
	if (dns_cache) {
		free(dns_cache);
	}

	return -1;
}

int dns_cache_insert(struct dns_cache_key *cache_key, int ttl, int speed, int no_inactive,
					 struct dns_cache_data *cache_data)
{
	struct dns_cache_info info;

	if (cache_data == NULL || cache_key == NULL || cache_key->dns_group_name == NULL || cache_key->domain == NULL) {
		return -1;
	}

	if (dns_cache_head.size <= 0) {
		dns_cache_data_free(cache_data);
		return 0;
	}

	if (ttl < DNS_CACHE_TTL_MIN) {
		ttl = DNS_CACHE_TTL_MIN;
	}

	memset(&info, 0, sizeof(info));
	info.hitnum = 3;
	safe_strncpy(info.domain, cache_key->domain, DNS_MAX_CNAME_LEN);
	info.qtype = cache_key->qtype;
	safe_strncpy(info.dns_group_name, cache_key->dns_group_name, DNS_GROUP_NAME_LEN);
	info.query_flag = cache_key->query_flag;
	info.ttl = ttl;
	info.hitnum_update_add = DNS_CACHE_HITNUM_STEP;
	info.speed = speed;
	info.no_inactive = no_inactive;
	info.is_visited = 1;
	time(&info.insert_time);
	time(&info.replace_time);

	return _dns_cache_insert(&info, cache_data, &dns_cache_head.cache_list);
}

struct dns_cache *dns_cache_lookup(struct dns_cache_key *cache_key)
{
	uint32_t key = 0;
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *dns_cache_ret = NULL;
	time_t now = 0;

	if (dns_cache_head.size <= 0) {
		return NULL;
	}

	key = hash_string(cache_key->domain);
	key = jhash(&cache_key->qtype, sizeof(cache_key->qtype), key);
	key = hash_string_initval(cache_key->dns_group_name, key);
	key = jhash(&cache_key->query_flag, sizeof(cache_key->query_flag), key);

	time(&now);
	/* find cache */
	pthread_mutex_lock(&dns_cache_head.lock);
	hash_for_each_possible(dns_cache_head.cache_hash, dns_cache, node, key)
	{
		if (dns_cache->info.qtype != cache_key->qtype) {
			continue;
		}

		if (strncmp(cache_key->domain, dns_cache->info.domain, DNS_MAX_CNAME_LEN) != 0) {
			continue;
		}

		if (strncmp(cache_key->dns_group_name, dns_cache->info.dns_group_name, DNS_GROUP_NAME_LEN) != 0) {
			continue;
		}

		if (cache_key->query_flag != dns_cache->info.query_flag) {
			continue;
		}

		dns_cache_ret = dns_cache;
		break;
	}

	if (dns_cache_ret) {
		/* Return NULL if the cache times out */
		if (dns_cache_head.enable_inactive == 0 && (now - dns_cache_ret->info.insert_time > dns_cache_ret->info.ttl)) {
			_dns_cache_remove(dns_cache_ret);
			dns_cache_ret = NULL;
		} else {
			dns_cache_get(dns_cache_ret);
		}
	}

	pthread_mutex_unlock(&dns_cache_head.lock);

	return dns_cache_ret;
}

int dns_cache_get_ttl(struct dns_cache *dns_cache)
{
	time_t now = 0;
	int ttl = 0;
	time(&now);

	ttl = dns_cache->info.insert_time + dns_cache->info.ttl - now;
	if (ttl < 0) {
		return 0;
	}

	return ttl;
}

int dns_cache_get_cname_ttl(struct dns_cache *dns_cache)
{
	time_t now = 0;
	int ttl = 0;
	time(&now);

	struct dns_cache_addr *cache_addr = (struct dns_cache_addr *)dns_cache_get_data(dns_cache);

	if (cache_addr->head.cache_type != CACHE_TYPE_ADDR) {
		return 0;
	}

	ttl = dns_cache->info.insert_time + cache_addr->addr_data.cname_ttl - now;
	if (ttl < 0) {
		return 0;
	}

	int addr_ttl = dns_cache_get_ttl(dns_cache);
	if (ttl < addr_ttl && ttl < 0) {
		return addr_ttl;
	}

	if (ttl < 0) {
		return 0;
	}

	return ttl;
}

int dns_cache_is_soa(struct dns_cache *dns_cache)
{
	if (dns_cache == NULL) {
		return 0;
	}

	if (dns_cache->cache_data->head.is_soa) {
		return 1;
	}

	return 0;
}

struct dns_cache_data *dns_cache_get_data(struct dns_cache *dns_cache)
{
	return dns_cache->cache_data;
}

int dns_cache_is_visited(struct dns_cache *dns_cache)
{
	return dns_cache->info.is_visited;
}

void dns_cache_delete(struct dns_cache *dns_cache)
{
	pthread_mutex_lock(&dns_cache_head.lock);
	_dns_cache_remove(dns_cache);
	pthread_mutex_unlock(&dns_cache_head.lock);
}

int dns_cache_hitnum_dec_get(struct dns_cache *dns_cache)
{
	pthread_mutex_lock(&dns_cache_head.lock);
	dns_cache->info.hitnum--;
	if (dns_cache->info.hitnum_update_add > DNS_CACHE_HITNUM_STEP) {
		dns_cache->info.hitnum_update_add--;
	}
	pthread_mutex_unlock(&dns_cache_head.lock);

	return dns_cache->info.hitnum;
}

void dns_cache_update(struct dns_cache *dns_cache)
{
	pthread_mutex_lock(&dns_cache_head.lock);
	if (!list_empty(&dns_cache->list)) {
		list_del_init(&dns_cache->list);
		list_add_tail(&dns_cache->list, &dns_cache_head.cache_list);
		dns_cache->info.hitnum += dns_cache->info.hitnum_update_add;
		if (dns_cache->info.hitnum > DNS_CACHE_MAX_HITNUM) {
			dns_cache->info.hitnum = DNS_CACHE_MAX_HITNUM;
		}

		if (dns_cache->info.hitnum_update_add < DNS_CACHE_HITNUM_STEP_MAX) {
			dns_cache->info.hitnum_update_add++;
		}
		dns_cache->info.is_visited = 1;
	}
	pthread_mutex_unlock(&dns_cache_head.lock);
}

static void _dns_cache_remove_expired_ttl(dns_cache_callback inactive_precallback, int ttl_inactive_pre,
										  unsigned int max_callback_num, const time_t *now)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *tmp = NULL;
	unsigned int callback_num = 0;
	int ttl = 0;
	LIST_HEAD(checklist);

	pthread_mutex_lock(&dns_cache_head.lock);
	list_for_each_entry_safe(dns_cache, tmp, &dns_cache_head.inactive_list, list)
	{
		ttl = dns_cache->info.insert_time + dns_cache->info.ttl - *now;
		if (ttl > 0) {
			continue;
		}

		if (dns_cache_head.inactive_list_expired + ttl < 0) {
			_dns_cache_remove(dns_cache);
			continue;
		}

		ttl = *now - dns_cache->info.replace_time;
		if (ttl < ttl_inactive_pre || inactive_precallback == NULL) {
			continue;
		}

		if (callback_num >= max_callback_num) {
			continue;
		}

		if (dns_cache->del_pending == 1) {
			continue;
		}

		/* If the TTL time is in the pre-timeout range, call callback function */
		dns_cache_get(dns_cache);
		list_add_tail(&dns_cache->check_list, &checklist);
		dns_cache->del_pending = 1;
		callback_num++;
	}
	pthread_mutex_unlock(&dns_cache_head.lock);

	list_for_each_entry_safe(dns_cache, tmp, &checklist, check_list)
	{
		/* run inactive_precallback */
		if (inactive_precallback) {
			inactive_precallback(dns_cache);
		}
		dns_cache_release(dns_cache);
	}
}

void dns_cache_invalidate(dns_cache_callback precallback, int ttl_pre, unsigned int max_callback_num,
						  dns_cache_callback inactive_precallback, int ttl_inactive_pre)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *tmp = NULL;
	time_t now = 0;
	int ttl = 0;
	LIST_HEAD(checklist);
	unsigned int callback_num = 0;

	if (max_callback_num <= 0) {
		max_callback_num = -1;
	}

	if (dns_cache_head.size <= 0) {
		return;
	}

	time(&now);
	pthread_mutex_lock(&dns_cache_head.lock);
	list_for_each_entry_safe(dns_cache, tmp, &dns_cache_head.cache_list, list)
	{
		ttl = dns_cache->info.insert_time + dns_cache->info.ttl - now;
		if (ttl > 0 && ttl < ttl_pre) {
			/* If the TTL time is in the pre-timeout range, call callback function */
			if (precallback && dns_cache->del_pending == 0 && callback_num < max_callback_num) {
				list_add_tail(&dns_cache->check_list, &checklist);
				dns_cache_get(dns_cache);
				dns_cache->del_pending = 1;
				callback_num++;
				continue;
			}
		}

		if (ttl < 0) {
			if (dns_cache_head.enable_inactive && dns_cache->info.no_inactive == 0) {
				_dns_cache_move_inactive(dns_cache);
			} else {
				_dns_cache_remove(dns_cache);
			}
		}
	}
	pthread_mutex_unlock(&dns_cache_head.lock);

	if (dns_cache_head.enable_inactive && dns_cache_head.inactive_list_expired != 0) {
		_dns_cache_remove_expired_ttl(inactive_precallback, ttl_inactive_pre, max_callback_num, &now);
	}

	list_for_each_entry_safe(dns_cache, tmp, &checklist, check_list)
	{
		/* run callback */
		if (precallback) {
			precallback(dns_cache);
		}
		list_del(&dns_cache->check_list);
		dns_cache_release(dns_cache);
	}
}

static int _dns_cache_read_record(int fd, uint32_t cache_number)
{

	unsigned int i = 0;
	ssize_t ret = 0;
	struct dns_cache_record cache_record;
	struct dns_cache_data_head data_head;
	struct dns_cache_data *cache_data = NULL;
	struct list_head *head = NULL;

	for (i = 0; i < cache_number; i++) {
		ret = read(fd, &cache_record, sizeof(cache_record));
		if (ret != sizeof(cache_record)) {
			tlog(TLOG_ERROR, "read cache failed, %s", strerror(errno));
			goto errout;
		}

		if (cache_record.magic != MAGIC_RECORD) {
			tlog(TLOG_ERROR, "magic is invalid.");
			goto errout;
		}

		if (cache_record.type == CACHE_RECORD_TYPE_ACTIVE) {
			head = &dns_cache_head.cache_list;
		} else if (cache_record.type == CACHE_RECORD_TYPE_INACTIVE) {
			head = &dns_cache_head.inactive_list;
		} else {
			tlog(TLOG_ERROR, "read cache record type is invalid.");
			goto errout;
		}

		ret = read(fd, &data_head, sizeof(data_head));
		if (ret != sizeof(data_head)) {
			tlog(TLOG_ERROR, "read data head failed, %s", strerror(errno));
			goto errout;
		}

		if (data_head.magic != MAGIC_CACHE_DATA) {
			tlog(TLOG_ERROR, "data magic is invalid.");
			goto errout;
		}

		if (data_head.size > 1024 * 8) {
			tlog(TLOG_ERROR, "data may invalid, skip load cache.");
			goto errout;
		}

		cache_data = malloc(data_head.size + sizeof(data_head));
		if (cache_data == NULL) {
			tlog(TLOG_ERROR, "malloc cache data failed %s", strerror(errno));
			goto errout;
		}

		memcpy(&cache_data->head, &data_head, sizeof(data_head));
		ret = read(fd, cache_data->data, data_head.size);
		if (ret != data_head.size) {
			tlog(TLOG_ERROR, "read cache data failed, %s", strerror(errno));
			goto errout;
		}

		/* set cache unvisited, so that when refreshing ipset/nftset, reload ipset list by restarting smartdns */
		cache_record.info.is_visited = 0;
		cache_record.info.domain[DNS_MAX_CNAME_LEN - 1] = '\0';
		cache_record.info.dns_group_name[DNS_GROUP_NAME_LEN - 1] = '\0';
		if (cache_record.type >= CACHE_RECORD_TYPE_END) {
			tlog(TLOG_ERROR, "read cache record type is invalid.");
			goto errout;
		}

		if (_dns_cache_insert(&cache_record.info, cache_data, head) != 0) {
			tlog(TLOG_ERROR, "insert cache data failed.");
			cache_data = NULL;
			goto errout;
		}

		cache_data = NULL;
	}

	return 0;
errout:
	if (cache_data) {
		free(cache_data);
	}
	return -1;
}

int dns_cache_load(const char *file)
{
	int fd = -1;
	ssize_t ret = 0;
	off_t filesize = 0;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		return 0;
	}

	filesize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	posix_fadvise(fd, 0, filesize, POSIX_FADV_WILLNEED | POSIX_FADV_SEQUENTIAL);

	struct dns_cache_file cache_file;
	ret = read(fd, &cache_file, sizeof(cache_file));
	if (ret != sizeof(cache_file)) {
		tlog(TLOG_ERROR, "read cache head failed.");
		goto errout;
	}

	if (cache_file.magic != MAGIC_NUMBER) {
		tlog(TLOG_ERROR, "cache file is invalid.");
		goto errout;
	}

	if (strncmp(cache_file.version, dns_cache_file_version(), DNS_CACHE_VERSION_LEN) != 0) {
		tlog(TLOG_WARN, "cache version is different, skip load cache.");
		goto errout;
	}

	tlog(TLOG_INFO, "load cache file %s, total %d records", file, cache_file.cache_number);
	if (_dns_cache_read_record(fd, cache_file.cache_number) != 0) {
		goto errout;
	}

	close(fd);
	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

static int _dns_cache_write_record(int fd, uint32_t *cache_number, enum CACHE_RECORD_TYPE type, struct list_head *head)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *tmp = NULL;
	struct dns_cache_record cache_record;

	pthread_mutex_lock(&dns_cache_head.lock);
	list_for_each_entry_safe_reverse(dns_cache, tmp, head, list)
	{
		cache_record.magic = MAGIC_RECORD;
		cache_record.type = type;
		memcpy(&cache_record.info, &dns_cache->info, sizeof(struct dns_cache_info));
		ssize_t ret = write(fd, &cache_record, sizeof(cache_record));
		if (ret != sizeof(cache_record)) {
			tlog(TLOG_ERROR, "write cache failed, %s", strerror(errno));
			goto errout;
		}

		struct dns_cache_data *cache_data = dns_cache->cache_data;
		ret = write(fd, cache_data, sizeof(*cache_data) + cache_data->head.size);
		if (ret != (int)sizeof(*cache_data) + cache_data->head.size) {
			tlog(TLOG_ERROR, "write cache data failed, %s", strerror(errno));
			goto errout;
		}

		(*cache_number)++;
	}

	pthread_mutex_unlock(&dns_cache_head.lock);
	return 0;

errout:
	pthread_mutex_unlock(&dns_cache_head.lock);
	return -1;
}

static int _dns_cache_write_records(int fd, uint32_t *cache_number)
{

	if (_dns_cache_write_record(fd, cache_number, CACHE_RECORD_TYPE_ACTIVE, &dns_cache_head.cache_list) != 0) {
		return -1;
	}

	if (_dns_cache_write_record(fd, cache_number, CACHE_RECORD_TYPE_INACTIVE, &dns_cache_head.inactive_list) != 0) {
		return -1;
	}

	return 0;
}

int dns_cache_save(const char *file, int check_lock)
{
	int fd = -1;
	uint32_t cache_number = 0;
	tlog(TLOG_DEBUG, "write cache file %s", file);

	/* check lock */
	if (check_lock == 1) {
		if (pthread_mutex_trylock(&dns_cache_head.lock) != 0) {
			return -1;
		}
		pthread_mutex_unlock(&dns_cache_head.lock);
	}

	fd = open(file, O_TRUNC | O_CREAT | O_WRONLY, 0640);
	if (fd < 0) {
		tlog(TLOG_ERROR, "create file %s failed, %s", file, strerror(errno));
		goto errout;
	}

	struct dns_cache_file cache_file;
	memset(&cache_file, 0, sizeof(cache_file));
	cache_file.magic = MAGIC_NUMBER;
	safe_strncpy(cache_file.version, dns_cache_file_version(), DNS_CACHE_VERSION_LEN);
	cache_file.cache_number = 0;

	if (lseek(fd, sizeof(cache_file), SEEK_SET) < 0) {
		tlog(TLOG_ERROR, "seek file %s failed, %s", file, strerror(errno));
		goto errout;
	}

	if (_dns_cache_write_records(fd, &cache_number) != 0) {
		tlog(TLOG_ERROR, "write record to file %s failed.", file);
		goto errout;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		tlog(TLOG_ERROR, "seek file %s failed, %s", file, strerror(errno));
		goto errout;
	}

	cache_file.cache_number = cache_number;
	if (write(fd, &cache_file, sizeof(cache_file)) != sizeof(cache_file)) {
		tlog(TLOG_ERROR, "write file head %s failed, %s, %d", file, strerror(errno), fd);
		goto errout;
	}

	tlog(TLOG_DEBUG, "wrote total %d records.", cache_number);

	close(fd);
	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

void dns_cache_destroy(void)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *tmp = NULL;

	pthread_mutex_lock(&dns_cache_head.lock);
	list_for_each_entry_safe(dns_cache, tmp, &dns_cache_head.inactive_list, list)
	{
		_dns_cache_delete(dns_cache);
	}

	list_for_each_entry_safe(dns_cache, tmp, &dns_cache_head.cache_list, list)
	{
		_dns_cache_delete(dns_cache);
	}
	pthread_mutex_unlock(&dns_cache_head.lock);

	pthread_mutex_destroy(&dns_cache_head.lock);
}

const char *dns_cache_file_version(void)
{
	const char *version = "cache ver 1.0";
	return version;
}
