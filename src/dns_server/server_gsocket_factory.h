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

#ifndef _DNS_SERVER_GSOCKET_FACTORY_H_
#define _DNS_SERVER_GSOCKET_FACTORY_H_

#include "dns_server.h"

#include <openssl/ssl.h>

SSL_CTX *_dns_server_gsocket_create_ssl_ctx(struct dns_bind_ip *bind_ip, int is_quic, int is_http3);
int _dns_server_gsocket_create_socket(const char *host_ip, int type);

#endif /* _DNS_SERVER_GSOCKET_FACTORY_H_ */
