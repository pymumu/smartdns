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

#ifndef __TIMER_WHEEL_H
#define __TIMER_WHEEL_H

#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tw_base;
struct tw_timer_list;

typedef void (*tw_func)(struct tw_base *, struct tw_timer_list *, void *, unsigned long);
typedef void (*tw_del_func)(struct tw_base *, struct tw_timer_list *, void *);

struct tw_timer_list {
	void *data;
	unsigned long expires;
	tw_func function;
	tw_del_func del_function;
	struct list_head entry;
};

struct tw_base *tw_init_timers(void);

int tw_cleanup_timers(struct tw_base *);

void tw_add_timer(struct tw_base *, struct tw_timer_list *);

int tw_del_timer(struct tw_base *, struct tw_timer_list *);

int tw_mod_timer_pending(struct tw_base *, struct tw_timer_list *, unsigned long);

int tw_mod_timer(struct tw_base *, struct tw_timer_list *, unsigned long);

#ifdef __cplusplus
}
#endif
#endif
