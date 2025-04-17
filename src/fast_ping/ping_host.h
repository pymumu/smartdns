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

#ifndef _FAST_PING_HOST_H_
#define _FAST_PING_HOST_H_

#include "fast_ping.h"

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

void _fast_ping_host_remove(struct ping_host_struct *ping_host);

void _fast_ping_host_put(struct ping_host_struct *ping_host);

void _fast_ping_host_get(struct ping_host_struct *ping_host);

void _fast_ping_close_host_sock(struct ping_host_struct *ping_host);

void _fast_ping_remove_all(void);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif // !_FAST_PING_HOST_H_
