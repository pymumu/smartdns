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

#ifndef _DNS_SERVER_DOH_GSOCKET_H_
#define _DNS_SERVER_DOH_GSOCKET_H_

#include "server_gsocket.h"

int dns_server_doh_process_request(struct dns_server_conn_gsocket *parent, struct gsocket *stream_gs);
int dns_server_doh_reply(struct gsocket *stream, unsigned char *inpacket, int inpacket_len);

#endif
