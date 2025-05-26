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

#define _GNU_SOURCE

#include "smartdns/dns_cache.h"
#include "smartdns/dns_stats.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/timer.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define DNS_CACHE_MAX_HITNUM 6000
#define DNS_CACHE_HITNUM_STEP 3
#define DNS_CACHE_HITNUM_STEP_MAX 6
#define DNS_CACHE_READ_TIMEOUT 60
#define DNS_CACHE_FAIL_TIMEOUT (60 * 5)
#define EXPIRED_DOMAIN_PREFETCH_TIME (3600 * 8)

struct dns_cache_head {
	struct hash_table cache_hash;
	struct list_head cache_list;
	atomic_t num;
	atomic_t mem_size;
	int size;
	long max_mem_size;
	pthread_mutex_t lock;
	dns_cache_callback timeout_callback;
};

typedef int (*dns_cache_read_callback)(struct dns_cache_record *cache_record, struct dns_cache_data *cache_data);

static int is_cache_init;
static struct dns_cache_head dns_cache_head;

int dns_cache_init(int size, int mem_size, dns_cache_callback timeout_callback)
{
	int bits = 0;
	pthread_mutexattr_t mta;
	if (is_cache_init == 1) {
		return -1;
	}

	INIT_LIST_HEAD(&dns_cache_head.cache_list);

	bits = ilog2(size) - 1;
	if (bits >= 20) {
		bits = 20;
	} else if (bits < 12) {
		bits = 12;
	}

	hash_table_init(dns_cache_head.cache_hash, bits, malloc);
	atomic_set(&dns_cache_head.num, 0);
	atomic_set(&dns_cache_head.mem_size, 0);
	dns_cache_head.size = size;
	dns_cache_head.max_mem_size = mem_size;
	if (mem_size > 0) {
		dns_cache_head.size = INT32_MAX;
	}
	dns_cache_head.timeout_callback = timeout_callback;
	pthread_mutexattr_init(&mta);
	pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&dns_cache_head.lock, &mta);
	pthread_mutexattr_destroy(&mta);

	is_cache_init = 1;
	return 0;
}

static struct dns_cache *_dns_cache_first(void)
{
	return list_first_entry_or_null(&dns_cache_head.cache_list, struct dns_cache, list);
}

static void _dns_cache_delete(struct dns_cache *dns_cache)
{
	pthread_mutex_lock(&dns_cache_head.lock);
	hash_del(&dns_cache->node);
	list_del_init(&dns_cache->list);
	dns_timer_del(&dns_cache->timer);
	pthread_mutex_unlock(&dns_cache_head.lock);
	atomic_dec(&dns_cache_head.num);
	atomic_sub(sizeof(*dns_cache), &dns_cache_head.mem_size);
	if (dns_cache->cache_data) {
		dns_cache_data_put(dns_cache->cache_data);
	}

	dns_cache->cache_data = NULL;
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
	dns_timer_del(&dns_cache->timer);
	dns_cache_release(dns_cache);
}

uint32_t dns_cache_get_query_flag(struct dns_cache *dns_cache)
{
	return dns_cache->info.query_flag;
}

const char *dns_cache_get_dns_group_name(struct dns_cache *dns_cache)
{
	return dns_cache->info.dns_group_name;
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

	cache_packet->head.size = packet_len;
	cache_packet->head.magic = MAGIC_CACHE_DATA;
	atomic_set(&cache_packet->head.ref, 1);
	atomic_add(data_size, &dns_cache_head.mem_size);

	return (struct dns_cache_data *)cache_packet;
}

static void dns_cache_timer_release(struct tw_base *base, struct tw_timer_list *timer, void *data)
{
	struct dns_cache *dns_cache = data;
	dns_cache_delete(dns_cache);
}

static void dns_cache_expired(struct tw_base *base, struct tw_timer_list *timer, void *data, unsigned long timestamp)
{
	struct dns_cache *dns_cache = data;

	if (dns_cache->del_pending == 1) {
		dns_cache_delete(dns_cache);
		return;
	}

	if (dns_cache_head.timeout_callback) {
		dns_cache_tmout_action_t tmout_act = dns_cache_head.timeout_callback(dns_cache);
		switch (tmout_act) {
		case DNS_CACHE_TMOUT_ACTION_OK:
			break;
		case DNS_CACHE_TMOUT_ACTION_UPDATE:
			dns_timer_mod(&dns_cache->timer, dns_cache->info.timeout);
			return;
		case DNS_CACHE_TMOUT_ACTION_DEL:
			dns_cache_delete(dns_cache);
			return;
		case DNS_CACHE_TMOUT_ACTION_RETRY:
			dns_timer_mod(&dns_cache->timer, DNS_CACHE_FAIL_TIMEOUT);
			return;
		default:
			break;
		}
	}

	dns_cache->del_pending = 1;
	dns_timer_mod(&dns_cache->timer, 5);
}

static struct dns_cache *_dns_cache_lookup(struct dns_cache_key *cache_key)
{
	uint32_t key = 0;
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *dns_cache_ret = NULL;
	time_t now = 0;

	key = hash_string(cache_key->domain);
	key = jhash(&cache_key->qtype, sizeof(cache_key->qtype), key);
	key = hash_string_initval(cache_key->dns_group_name, key);
	key = jhash(&cache_key->query_flag, sizeof(cache_key->query_flag), key);

	time(&now);
	/* find cache */
	pthread_mutex_lock(&dns_cache_head.lock);
	hash_table_for_each_possible(dns_cache_head.cache_hash, dns_cache, node, key)
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
		dns_cache_get(dns_cache_ret);
	}

	pthread_mutex_unlock(&dns_cache_head.lock);

	return dns_cache_ret;
}

struct dns_cache *dns_cache_lookup(struct dns_cache_key *cache_key)
{
	struct dns_cache *dns_cache_ret = NULL;

	if (dns_cache_head.size <= 0) {
		return NULL;
	}

	stats_inc(&dns_stats.cache.check_count);
	dns_cache_ret = _dns_cache_lookup(cache_key);

	if (dns_cache_ret) {
		stats_inc(&dns_stats.cache.hit_count);
	}

	return dns_cache_ret;
}

static int _dns_cache_replace(struct dns_cache_key *cache_key, int rcode, int ttl, int speed, int timeout,
							  int update_time, struct dns_cache_data *cache_data)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache_data *old_cache_data = NULL;

	if (dns_cache_head.size <= 0) {
		return 0;
	}

	/* lookup existing cache */
	dns_cache = _dns_cache_lookup(cache_key);
	if (dns_cache == NULL) {
		return -1;
	}

	if (ttl < DNS_CACHE_TTL_MIN) {
		ttl = DNS_CACHE_TTL_MIN;
	}

	/* update cache data */
	pthread_mutex_lock(&dns_cache_head.lock);
	dns_cache->del_pending = 0;
	dns_cache->info.rcode = rcode;
	dns_cache->info.qtype = cache_key->qtype;
	dns_cache->info.query_flag = cache_key->query_flag;
	dns_cache->info.ttl = ttl;
	dns_cache->info.speed = speed;
	dns_cache->info.timeout = timeout;
	dns_cache->info.is_visited = 1;
	if (cache_data) {
		old_cache_data = dns_cache->cache_data;
		dns_cache->cache_data = cache_data;
	}

	if (update_time) {
		time(&dns_cache->info.insert_time);
	}
	time(&dns_cache->info.replace_time);
	list_del(&dns_cache->list);
	list_add_tail(&dns_cache->list, &dns_cache_head.cache_list);
	dns_timer_mod(&dns_cache->timer, timeout);
	pthread_mutex_unlock(&dns_cache_head.lock);

	if (old_cache_data) {
		dns_cache_data_put(old_cache_data);
	}
	dns_cache_release(dns_cache);
	return 0;
}

int dns_cache_replace(struct dns_cache_key *cache_key, int rcode, int ttl, int speed, int timeout, int update_time,
					  struct dns_cache_data *cache_data)
{
	return _dns_cache_replace(cache_key, rcode, ttl, speed, timeout, update_time, cache_data);
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
	hash_table_for_each_possible(dns_cache_head.cache_hash, dns_cache, node, key)
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

static int _dns_cache_insert(struct dns_cache_info *info, struct dns_cache_data *cache_data, struct list_head *head,
							 int timeout)
{
	uint32_t key = 0;
	struct dns_cache *dns_cache = NULL;
	int loop_count = 0;

	if (cache_data == NULL || info == NULL) {
		goto errout;
	}

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
	dns_cache->timer.function = dns_cache_expired;
	dns_cache->timer.del_function = dns_cache_timer_release;
	dns_cache->timer.expires = timeout;
	dns_cache->timer.data = dns_cache;
	INIT_LIST_HEAD(&dns_cache->check_list);

	pthread_mutex_lock(&dns_cache_head.lock);
	hash_table_add(dns_cache_head.cache_hash, &dns_cache->node, key);
	list_add_tail(&dns_cache->list, head);
	atomic_add(sizeof(*dns_cache), &dns_cache_head.mem_size);
	atomic_inc(&dns_cache_head.num);

	/* Release extra cache, remove oldest cache record */
	do {
		int need_remove = 0;

		if (dns_cache_head.max_mem_size > 0 && atomic_read(&dns_cache_head.mem_size) > dns_cache_head.max_mem_size) {
			need_remove = 1;
		}

		if (atomic_read(&dns_cache_head.num) > dns_cache_head.size) {
			need_remove = 1;
		}

		if (need_remove == 0) {
			break;
		}

		struct dns_cache *del_cache = _dns_cache_first();
		if (del_cache == NULL) {
			break;
		}

		_dns_cache_remove(del_cache);
	} while (loop_count++ < 32);

	dns_cache_get(dns_cache);
	dns_timer_add(&dns_cache->timer);
	pthread_mutex_unlock(&dns_cache_head.lock);

	return 0;
errout:
	if (dns_cache) {
		dns_cache_release(dns_cache);
	}

	return -1;
}

int dns_cache_insert(struct dns_cache_key *cache_key, int rcode, int ttl, int speed, int timeout,
					 struct dns_cache_data *cache_data)
{
	struct dns_cache_info info;

	if (cache_data == NULL || cache_key == NULL || cache_key->dns_group_name == NULL || cache_key->domain == NULL) {
		return -1;
	}

	if (dns_cache_head.size <= 0) {
		dns_cache_data_put(cache_data);
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
	info.timeout = timeout;
	info.is_visited = 1;
	info.rcode = rcode;
	time(&info.insert_time);
	time(&info.replace_time);

	return _dns_cache_insert(&info, cache_data, &dns_cache_head.cache_list, timeout);
}

int dns_cache_update_timer(struct dns_cache_key *key, int timeout)
{
	struct dns_cache *dns_cache = _dns_cache_lookup(key);
	if (dns_cache == NULL) {
		return -1;
	}

	pthread_mutex_lock(&dns_cache_head.lock);
	dns_timer_mod(&dns_cache->timer, timeout);
	dns_cache->del_pending = 0;
	pthread_mutex_unlock(&dns_cache_head.lock);

	dns_cache_release(dns_cache);

	return 0;
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

struct dns_cache_data *dns_cache_get_data(struct dns_cache *dns_cache)
{
	struct dns_cache_data *cache_data;
	pthread_mutex_lock(&dns_cache_head.lock);
	if (dns_cache->cache_data == NULL) {
		pthread_mutex_unlock(&dns_cache_head.lock);
		return NULL;
	}

	dns_cache_data_get(dns_cache->cache_data);
	cache_data = dns_cache->cache_data;
	pthread_mutex_unlock(&dns_cache_head.lock);
	return cache_data;
}

void dns_cache_data_get(struct dns_cache_data *cache_data)
{
	if (atomic_inc_return(&cache_data->head.ref) == 1) {
		tlog(TLOG_ERROR, "BUG: dns_cache data is invalid.");
		return;
	}

	return;
}

void dns_cache_flush(void)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *tmp = NULL;

	pthread_mutex_lock(&dns_cache_head.lock);
	list_for_each_entry_safe(dns_cache, tmp, &dns_cache_head.cache_list, list)
	{
		_dns_cache_remove(dns_cache);
	}
	pthread_mutex_unlock(&dns_cache_head.lock);
}

void dns_cache_data_put(struct dns_cache_data *cache_data)
{
	if (cache_data == NULL) {
		return;
	}

	if (!atomic_dec_and_test(&cache_data->head.ref)) {
		return;
	}

	atomic_sub(cache_data->head.size + sizeof(*cache_data), &dns_cache_head.mem_size);
	free(cache_data);
}

int dns_cache_is_visited(struct dns_cache *dns_cache)
{
	return dns_cache->info.is_visited;
}

int dns_cache_total_num(void)
{
	return atomic_read(&dns_cache_head.num);
}

long dns_cache_total_memsize(void)
{
	return atomic_read(&dns_cache_head.mem_size);
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

static int _dns_cache_read_to_cache(struct dns_cache_record *cache_record, struct dns_cache_data *cache_data)
{
	struct list_head *head = NULL;
	head = &dns_cache_head.cache_list;
	struct dns_cache_info *info = &cache_record->info;
	int expired_time = 0;

	time_t now = time(NULL);
	if (now < info->replace_time) {
		info->replace_time = now;
	}

	struct dns_conf_group *rule_group = dns_server_get_rule_group(info->dns_group_name);
	expired_time = rule_group->dns_serve_expired_prefetch_time;
	if (expired_time == 0) {
		expired_time = rule_group->dns_serve_expired_ttl / 2;
		if (expired_time == 0 || expired_time > EXPIRED_DOMAIN_PREFETCH_TIME) {
			expired_time = EXPIRED_DOMAIN_PREFETCH_TIME;
		}
	}

	int passed_time = now - info->replace_time;
	int timeout = info->timeout - passed_time;
	if ((timeout > expired_time + info->ttl) && expired_time >= 0) {
		timeout = expired_time + info->ttl;
	}

	if (timeout < DNS_CACHE_READ_TIMEOUT * 2) {
		timeout = DNS_CACHE_READ_TIMEOUT + (rand() % DNS_CACHE_READ_TIMEOUT);
	}

	dns_cache_data_get(cache_data);
	if (_dns_cache_insert(&cache_record->info, cache_data, head, timeout) != 0) {
		tlog(TLOG_ERROR, "insert cache data failed.");
		dns_cache_data_put(cache_data);
		cache_data = NULL;
		goto errout;
	}

	daemon_keepalive();

	return 0;
errout:
	return -1;
}

static int _dns_cache_read_record(int fd, uint32_t cache_number, dns_cache_read_callback callback)
{
	unsigned int i = 0;
	ssize_t ret = 0;
	int data_size = 0;
	struct dns_cache_record cache_record;
	struct dns_cache_data_head data_head;
	struct dns_cache_data *cache_data = NULL;

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

		data_size = data_head.size + sizeof(data_head);
		cache_data = malloc(data_size);
		if (cache_data == NULL) {
			tlog(TLOG_ERROR, "malloc cache data failed %s", strerror(errno));
			goto errout;
		}

		memcpy(&cache_data->head, &data_head, sizeof(data_head));
		atomic_set(&cache_data->head.ref, 1);
		ret = read(fd, cache_data->data, data_head.size);
		if (ret != data_head.size) {
			tlog(TLOG_ERROR, "read cache data failed, %s", strerror(errno));
			goto errout;
		}

		/* set cache unvisited, so that when refreshing ipset/nftset, reload ipset list by restarting smartdns */
		cache_record.info.is_visited = 0;
		cache_record.info.domain[DNS_MAX_CNAME_LEN - 1] = '\0';
		cache_record.info.dns_group_name[DNS_GROUP_NAME_LEN - 1] = '\0';
		atomic_add(data_size, &dns_cache_head.mem_size);
		ret = callback(&cache_record, cache_data);
		dns_cache_data_put(cache_data);
		cache_data = NULL;
		if (ret != 0) {
			goto errout;
		}
	}

	return 0;
errout:
	if (cache_data) {
		dns_cache_data_put(cache_data);
	}
	return -1;
}

static int _dns_cache_file_read(const char *file, dns_cache_read_callback callback)
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
	if (_dns_cache_read_record(fd, cache_file.cache_number, callback) != 0) {
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

int dns_cache_load(const char *file)
{
	return _dns_cache_file_read(file, _dns_cache_read_to_cache);
}

static int _dns_cache_write_record(int fd, uint32_t *cache_number, struct list_head *head)
{
	struct dns_cache *dns_cache = NULL;
	struct dns_cache *tmp = NULL;
	struct dns_cache_record cache_record;

	memset(&cache_record, 0, sizeof(cache_record));

	pthread_mutex_lock(&dns_cache_head.lock);
	list_for_each_entry_safe(dns_cache, tmp, head, list)
	{
		struct dns_cache_data *cache_data = dns_cache->cache_data;
		if (cache_data == NULL) {
			continue;
		}

		cache_record.magic = MAGIC_RECORD;
		memcpy(&cache_record.info, &dns_cache->info, sizeof(struct dns_cache_info));
		ssize_t ret = write(fd, &cache_record, sizeof(cache_record));
		if (ret != sizeof(cache_record)) {
			tlog(TLOG_ERROR, "write cache failed, %s", strerror(errno));
			goto errout;
		}

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
	if (_dns_cache_write_record(fd, cache_number, &dns_cache_head.cache_list) != 0) {
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

static int _dns_cache_print(struct dns_cache_record *cache_record, struct dns_cache_data *cache_data)
{
	char req_result[1024] = {0};
	int left_len = sizeof(req_result);
	char *ip_msg = req_result;
	long i, j;

	if (cache_record->info.qtype == DNS_T_A || cache_record->info.qtype == DNS_T_AAAA) {
		char buff[DNS_PACKSIZE];
		struct dns_packet *packet = (struct dns_packet *)buff;
		struct dns_rrs *rrs = NULL;
		int rr_count = 0;
		int ttl = 0;
		int ip_num = 0;
		int total_len = 0;
		int len = 0;
		int has_result = 0;
		char req_host[MAX_IP_LEN];
		char name[DNS_MAX_CNAME_LEN] = {0};

		if (dns_decode(packet, DNS_PACKSIZE, cache_data->data, cache_data->head.size) == 0) {
			total_len = snprintf(ip_msg, left_len, ", result: ");
			for (j = 1; j < DNS_RRS_OPT && packet; j++) {
				rrs = dns_get_rrs_start(packet, j, &rr_count);
				for (i = 0; i < rr_count && rrs && left_len > 0; i++, rrs = dns_get_rrs_next(packet, rrs)) {
					switch (rrs->type) {
					case DNS_T_A: {
						unsigned char ipv4_addr[4];
						if (dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv4_addr) != 0) {
							continue;
						}

						const char *fmt = "%d.%d.%d.%d";
						if (ip_num > 0) {
							fmt = ", %d.%d.%d.%d";
						}

						len = snprintf(ip_msg + total_len, left_len, fmt, ipv4_addr[0], ipv4_addr[1], ipv4_addr[2],
									   ipv4_addr[3]);
						ip_num++;
						has_result = 1;
					} break;
					case DNS_T_AAAA: {
						unsigned char ipv6_addr[16];
						if (dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, ipv6_addr) != 0) {
							continue;
						}

						const char *fmt = "%s";
						if (ip_num > 0) {
							fmt = ", %s";
						}
						req_host[0] = '\0';
						inet_ntop(AF_INET6, ipv6_addr, req_host, sizeof(req_host));
						len = snprintf(ip_msg + total_len, left_len, fmt, req_host);
						ip_num++;
						has_result = 1;
					} break;
					default:
						continue;
					}

					if (len < 0 || len >= left_len) {
						left_len = 0;
						break;
					}

					left_len -= len;
					total_len += len;
				}
			}
		}

		if (has_result == 0) {
			req_result[0] = '\0';
		}
	}

	printf("domain: %s, qtype: %d, rcode: %d, ttl: %d, speed: %.1fms%s\n", cache_record->info.domain,
		   cache_record->info.qtype, cache_record->info.rcode, cache_record->info.ttl,
		   (float)cache_record->info.speed / 10, ip_msg);
	return 0;
}

int dns_cache_print(const char *file)
{
	if (access(file, F_OK) != 0) {
		tlog(TLOG_ERROR, "cache file %s not exist.", file);
		return -1;
	}

	return _dns_cache_file_read(file, _dns_cache_print);
}

void dns_cache_destroy(void)
{
	if (is_cache_init == 0) {
		return;
	}

	dns_cache_flush();

	pthread_mutex_destroy(&dns_cache_head.lock);
	hash_table_free(dns_cache_head.cache_hash, free);

	is_cache_init = 0;
}

const char *dns_cache_file_version(void)
{
	const char *version = "cache ver 1.3";
	return version;
}
