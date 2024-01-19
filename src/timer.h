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

#ifndef SMART_DNS_TIMER_H
#define SMART_DNS_TIMER_H

#include "timer_wheel.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

int dns_timer_init(void);

void dns_timer_add(struct tw_timer_list *timer);

int dns_timer_del(struct tw_timer_list *timer);

int dns_timer_mod(struct tw_timer_list *timer, unsigned long expires);

void dns_timer_destroy(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
