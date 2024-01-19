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

#include "timer.h"
#include "timer_wheel.h"

static struct tw_base *dns_timer_base = NULL;

int dns_timer_init(void)
{
	struct tw_base *tw = tw_init_timers();
	if (tw == NULL) {
		return -1;
	}

	dns_timer_base = tw;

	return 0;
}

void dns_timer_destroy(void)
{
	if (dns_timer_base != NULL) {
		tw_cleanup_timers(dns_timer_base);
		dns_timer_base = NULL;
	}
}

void dns_timer_add(struct tw_timer_list *timer)
{
	if (dns_timer_base == NULL) {
		return;
	}

	tw_add_timer(dns_timer_base, timer);
}

int dns_timer_del(struct tw_timer_list *timer)
{
	if (dns_timer_base == NULL) {
		return 0;
	}

	return tw_del_timer(dns_timer_base, timer);
}

int dns_timer_mod(struct tw_timer_list *timer, unsigned long expires)
{
	if (dns_timer_base == NULL) {
		return 0;
	}

	return tw_mod_timer(dns_timer_base, timer, expires);
}

