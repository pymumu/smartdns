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

#include "bitops.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "timer_wheel.h"

#define TVR_BITS 10
#define TVN_BITS 6
#define TVR_SIZE (1 << TVR_BITS)
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_MASK (TVR_SIZE - 1)
#define TVN_MASK (TVN_SIZE - 1)
#define INDEX(N) ((base->jiffies >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK)
#define MAX_TVAL ((unsigned long)((1ULL << (TVR_BITS + 4 * TVN_BITS)) - 1))

struct tvec {
	struct list_head vec[TVN_SIZE];
};

struct tvec_root {
	struct list_head vec[TVR_SIZE];
};

struct tw_base {
	pthread_spinlock_t lock;

	pthread_t runner;

	unsigned long jiffies;

	struct tvec_root tv1;
	struct tvec tv2;
	struct tvec tv3;
	struct tvec tv4;
	struct tvec tv5;
};

static inline void _tw_add_timer(struct tw_base *base, struct tw_timer_list *timer)
{
	int i;
	unsigned long idx;
	unsigned long expires;
	struct list_head *vec;

	expires = timer->expires;
	idx = expires - base->jiffies;

	if (idx < TVR_SIZE) {
		i = expires & TVR_MASK;
		vec = base->tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		i = (expires >> TVR_BITS) & TVN_MASK;
		vec = base->tv2.vec + i;
	} else if (idx < 1 << (TVR_BITS + 2 * TVN_BITS)) {
		i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec = base->tv3.vec + i;
	} else if (idx < 1 << (TVR_BITS + 3 * TVN_BITS)) {
		i = (expires >> (TVR_BITS + 2 * TVN_BITS)) & TVN_MASK;
		vec = base->tv4.vec + i;
	} else if ((signed long)idx < 0) {
		vec = base->tv1.vec + (base->jiffies & TVR_MASK);
	} else {
		if (idx > MAX_TVAL) {
			idx = MAX_TVAL;
			expires = idx + base->jiffies;
		}
		i = (expires >> (TVR_BITS + 3 * TVN_BITS)) & TVN_MASK;
		vec = base->tv5.vec + i;
	}

	list_add_tail(&timer->entry, vec);
}

static inline void _tw_detach_timer(struct tw_timer_list *timer)
{
	struct list_head *entry = &timer->entry;

	list_del(entry);
	entry->next = NULL;
}

static inline int _tw_cascade(struct tw_base *base, struct tvec *tv, int index)
{
	struct tw_timer_list *timer, *tmp;
	struct list_head tv_list;

	list_replace_init(tv->vec + index, &tv_list);

	list_for_each_entry_safe(timer, tmp, &tv_list, entry)
	{
		_tw_add_timer(base, timer);
	}

	return index;
}

static inline int timer_pending(struct tw_timer_list *timer)
{
	struct list_head *entry = &timer->entry;

	return (entry->next != NULL);
}

static inline int __detach_if_pending(struct tw_timer_list *timer)
{
	if (!timer_pending(timer)) {
		return 0;
	}

	_tw_detach_timer(timer);
	return 1;
}

static inline int __mod_timer(struct tw_base *base, struct tw_timer_list *timer, int pending_only)
{
	int ret = 0;

	ret = __detach_if_pending(timer);
	if (!ret && pending_only) {
		goto done;
	}

	ret = 1;
	_tw_add_timer(base, timer);

done:
	return ret;
}

void tw_add_timer(struct tw_base *base, struct tw_timer_list *timer)
{
	if (timer->function == NULL) {
		return;
	}

	pthread_spin_lock(&base->lock);
	{
		timer->expires += base->jiffies - 1;
		_tw_add_timer(base, timer);
	}
	pthread_spin_unlock(&base->lock);
}

int tw_del_timer(struct tw_base *base, struct tw_timer_list *timer)
{
	int ret = 0;

	pthread_spin_lock(&base->lock);
	{
		if (timer_pending(timer)) {
			ret = 1;
			_tw_detach_timer(timer);
		}
	}
	pthread_spin_unlock(&base->lock);

	if (ret == 1 && timer->del_function) {
		timer->del_function(base, timer, timer->data);
	}

	return ret;
}

int tw_mod_timer_pending(struct tw_base *base, struct tw_timer_list *timer, unsigned long expires)
{
	int ret = 1;

	pthread_spin_lock(&base->lock);
	{
		timer->expires = expires + base->jiffies - 1;
		ret = __mod_timer(base, timer, 1);
	}
	pthread_spin_unlock(&base->lock);

	return ret;
}

int tw_mod_timer(struct tw_base *base, struct tw_timer_list *timer, unsigned long expires)
{
	int ret = 1;

	pthread_spin_lock(&base->lock);
	{
		if (timer_pending(timer) && timer->expires == expires) {
			goto unblock;
		}

		timer->expires = expires + base->jiffies - 1;

		ret = __mod_timer(base, timer, 0);
	}
unblock:
	pthread_spin_unlock(&base->lock);

	return ret;
}

int tw_cleanup_timers(struct tw_base *base)
{
	int ret = 0;
	void *res = NULL;

	ret = pthread_cancel(base->runner);
	if (ret != 0) {
		goto errout;
	}
	ret = pthread_join(base->runner, &res);
	if (ret != 0) {
		goto errout;
	}
	if (res != PTHREAD_CANCELED) {
		goto errout;
	}

	ret = pthread_spin_destroy(&base->lock);
	if (ret != 0) {
		goto errout;
	}

	free(base);
	return 0;

errout:
	return -1;
}

static inline void run_timers(struct tw_base *base)
{
	unsigned long index, call_time;
	struct tw_timer_list *timer;

	struct list_head work_list;
	struct list_head *head = &work_list;

	pthread_spin_lock(&base->lock);
	{
		index = base->jiffies & TVR_MASK;

		if (!index && (!_tw_cascade(base, &base->tv2, INDEX(0))) && (!_tw_cascade(base, &base->tv3, INDEX(1))) &&
			(!_tw_cascade(base, &base->tv4, INDEX(2))))
			_tw_cascade(base, &base->tv5, INDEX(3));

		call_time = base->jiffies++;
		list_replace_init(base->tv1.vec + index, head);
		while (!list_empty(head)) {
			tw_func fn;
			void *data;

			timer = list_first_entry(head, struct tw_timer_list, entry);
			fn = timer->function;
			data = timer->data;

			_tw_detach_timer(timer);
			pthread_spin_unlock(&base->lock);
			{
				fn(base, timer, data, call_time);
			}

			pthread_spin_lock(&base->lock);
			if ((timer_pending(timer) == 0 && timer->del_function)) {
				pthread_spin_unlock(&base->lock);
				timer->del_function(base, timer, timer->data);
				pthread_spin_lock(&base->lock);
			}
		}
	}
	pthread_spin_unlock(&base->lock);
}

static unsigned long _tw_tick_count(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

static void *timer_work(void *arg)
{
	struct tw_base *base = arg;
	int sleep = 1000;
	int sleep_time = 0;
	unsigned long now = {0};
	unsigned long last = {0};
	unsigned long expect_time = 0;

	sleep_time = sleep;
	now = _tw_tick_count() - sleep;
	last = now;
	expect_time = now + sleep;
	while (1) {
		run_timers(base);

		now = _tw_tick_count();
		if (sleep_time > 0) {
			sleep_time -= now - last;
			if (sleep_time <= 0) {
				sleep_time = 0;
			}

			int cnt = sleep_time / sleep;
			expect_time -= cnt * sleep;
			sleep_time -= cnt * sleep;
		}

		if (now >= expect_time) {
			sleep_time = sleep - (now - expect_time);
			if (sleep_time < 0) {
				sleep_time = 0;
				expect_time = now;
			}
			expect_time += sleep;
		}
		last = now;

		usleep(sleep_time * 1000);
	}

	return NULL;
}

struct tw_base *tw_init_timers(void)
{
	int j = 0;
	int ret = 0;
	struct timeval tv = {
		0,
	};
	struct tw_base *base = NULL;

	base = malloc(sizeof(*base));
	if (!base) {
		goto errout;
	}

	ret = pthread_spin_init(&base->lock, 0);
	if (ret != 0) {
		goto errout2;
	}

	for (j = 0; j < TVN_SIZE; j++) {
		INIT_LIST_HEAD(base->tv5.vec + j);
		INIT_LIST_HEAD(base->tv4.vec + j);
		INIT_LIST_HEAD(base->tv3.vec + j);
		INIT_LIST_HEAD(base->tv2.vec + j);
	}

	for (j = 0; j < TVR_SIZE; j++) {
		INIT_LIST_HEAD(base->tv1.vec + j);
	}

	ret = gettimeofday(&tv, 0);
	if (ret < 0) {
		goto errout1;
	}
	base->jiffies = tv.tv_sec;

	ret = pthread_create(&base->runner, NULL, timer_work, base);
	if (ret != 0) {
		goto errout1;
	}
	return base;

errout1:
	(void)pthread_spin_destroy(&base->lock);
errout2:
	free(base);
errout:
	return NULL;
}
