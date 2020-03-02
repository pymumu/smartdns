/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef FAST_PING_H
#define FAST_PING_H

#include <netdb.h>
#include <sys/time.h>
#ifdef __cpluscplus
extern "C" {
#endif

typedef enum {
	PING_TYPE_ICMP = 1,
	PING_TYPE_TCP = 2,
	PING_TYPE_DNS = 3,
} PING_TYPE;

typedef enum {
	PING_RESULT_RESPONSE = 1,
	PING_RESULT_TIMEOUT = 2,
	PING_RESULT_END = 3,
} FAST_PING_RESULT;

struct ping_host_struct;
typedef void (*fast_ping_result)(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
								 struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv,
								 void *userptr);

/* start ping */
struct ping_host_struct *fast_ping_start(PING_TYPE type, const char *host, int count, int interval, int timeout,
										 fast_ping_result ping_callback, void *userptr);

/* stop ping */
int fast_ping_stop(struct ping_host_struct *ping_host);

int fast_ping_init(void);

void fast_ping_exit(void);

#ifdef __cpluscplus
}
#endif

#endif // !FAST_PING_H
