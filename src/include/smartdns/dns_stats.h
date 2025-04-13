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

#ifndef SMART_DNS_STATS_H
#define SMART_DNS_STATS_H

#include "smartdns/lib/atomic.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

struct dns_stats_avg_time {
	uint64_t total; /* Hight 4 bytes, count, Low 4 bytes time*/
	float avg_time;
};

struct dns_request_stats {
	uint64_t total;
	uint64_t success_count;
	uint64_t from_client_count;
	uint64_t blocked_count;
};

struct dns_cache_stats {
	uint64_t check_count;
	uint64_t hit_count;
};

struct dns_stats {
	struct dns_request_stats request;
	struct dns_cache_stats cache;
	struct dns_stats_avg_time avg_time;
};

struct dns_server_stats {
	uint64_t total;
	uint64_t success_count;
	uint64_t recv_count;
	struct dns_stats_avg_time avg_time;
};

extern struct dns_stats dns_stats;

static inline uint64_t stats_read(const uint64_t *s)
{
	return READ_ONCE((*s));
}

static inline uint64_t stats_read_and_set(uint64_t *s, uint64_t v)
{
	return __sync_lock_test_and_set(s, v);
}

static inline void stats_set(uint64_t *s, uint64_t v)
{
	*s = v;
}

static inline void stats_add(uint64_t *s, uint64_t v)
{
	(void)__sync_add_and_fetch(s, v);
}

static inline void stats_inc(uint64_t *s)
{
	(void)__sync_add_and_fetch(s, 1);
}

static inline void stats_sub(uint64_t *s, uint64_t v)
{
	(void)__sync_sub_and_fetch(s, v);
}

static inline void stats_dec(uint64_t *s)
{
	(void)__sync_sub_and_fetch(s, 1);
}

void dns_stats_avg_time_update(struct dns_stats_avg_time *avg_time);

void dns_stats_avg_time_update_add(struct dns_stats_avg_time *avg_time, uint64_t time);

static inline void dns_stats_avg_time_add(uint64_t time)
{
	dns_stats_avg_time_update_add(&dns_stats.avg_time, time);
}

float dns_stats_avg_time_get(void);

uint64_t dns_stats_request_total_get(void);

uint64_t dns_stats_request_success_get(void);

uint64_t dns_stats_request_from_client_get(void);

uint64_t dns_stats_request_blocked_get(void);

uint64_t dns_stats_cache_hit_get(void);

float dns_stats_cache_hit_rate_get(void);

void dns_stats_period_run_second(void);

void dns_stats_server_stats_avg_time_add(struct dns_server_stats *server_stats, uint64_t time);

void dns_stats_server_stats_avg_time_update(struct dns_server_stats *server_stats);

uint64_t dns_stats_server_stats_total_get(struct dns_server_stats *server_stats);

uint64_t dns_stats_server_stats_success_get(struct dns_server_stats *server_stats);

uint64_t dns_stats_server_stats_recv_get(struct dns_server_stats *server_stats);

float dns_stats_server_stats_avg_time_get(struct dns_server_stats *server_stats);

int dns_stats_init(void);

void dns_stats_exit(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
