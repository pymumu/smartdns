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

#include "dns_stats.h"
#include "stddef.h"
#include "string.h"

struct dns_stats dns_stats;

#define SAMPLE_PERIOD 5

void dns_stats_avg_time_update(void)
{
	uint64_t total = stats_read_and_set(&dns_stats.avg_time.total, 0);
	uint64_t count = total >> 32;
	uint64_t time = total & 0xFFFFFFFF;

	if (count == 0) {
		return;
	}

	float sample_avg = (float)time / count;

	if (dns_stats.avg_time.avg_time == 0) {
		dns_stats.avg_time.avg_time = sample_avg;
	} else {
		int base = 1000;
		if (count > 100) {
			count = 100;
		}

		float weight_new = (float)count / base;
		float weight_prev = 1.0 - weight_new;

		dns_stats.avg_time.avg_time = (dns_stats.avg_time.avg_time * weight_prev) + (sample_avg * weight_new);
	}
}

void dns_stats_period_run_second(void)
{
	static int last_total = 0;
	last_total++;
	if (last_total % SAMPLE_PERIOD == 0) {
		dns_stats_avg_time_update();
		dns_stats_avg_time_get();
	}
}

float dns_stats_avg_time_get(void)
{
	return dns_stats.avg_time.avg_time;
}

uint64_t dns_stats_request_total_get(void)
{
	return stats_read(&dns_stats.request.total);
}

uint64_t dns_stats_request_success_get(void)
{
	return stats_read(&dns_stats.request.success_count);
}

uint64_t dns_stats_request_from_client_get(void)
{
	return stats_read(&dns_stats.request.from_client_count);
}

uint64_t dns_stats_request_blocked_get(void)
{
	return stats_read(&dns_stats.request.blocked_count);
}

uint64_t dns_stats_cache_hit_get(void)
{
	return stats_read(&dns_stats.cache.hit_count);
}

float dns_stats_cache_hit_rate_get(void)
{
	uint64_t total = stats_read(&dns_stats.request.from_client_count);
	uint64_t hit = stats_read(&dns_stats.cache.hit_count);

	if (total == 0) {
		return 0;
	}

	return (float)(hit * 100) / total;
}

int dns_stats_init(void)
{
	memset(&dns_stats, 0, sizeof(dns_stats));
	return 0;
}

void dns_stats_exit(void)
{	
	memset(&dns_stats, 0, sizeof(dns_stats));
	return;
}