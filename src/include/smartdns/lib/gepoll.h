/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#ifndef _GEPOLL_H_
#define _GEPOLL_H_

#include "smartdns/lib/gsocket.h"
#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gepoll;

struct gepoll_event {
	uint32_t events;
	void *user_data;
};

struct gepoll *gepoll_create(int flags);
void gepoll_destroy(struct gepoll *ep);

/* Wrappers for epoll_ctl.
   user_data is passed back in gepoll_event.
   Internal mapping handles gsocket -> FD translation only.
*/
int gepoll_add(struct gepoll *ep, struct gsocket *sock, int events, void *user_data);
int gepoll_mod(struct gepoll *ep, struct gsocket *sock, int events, void *user_data);
int gepoll_del(struct gepoll *ep, struct gsocket *sock);

/* Waits for events and returns the underlying epoll readiness.
   Handshake/protocol state progression is handled by callers.
*/
int gepoll_wait(struct gepoll *ep, struct gepoll_event *events, int maxevents, int timeout);

#ifdef __cplusplus
}
#endif

#endif
