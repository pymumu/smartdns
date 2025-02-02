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

#ifndef _SMARTDNS_COMMON_H
#define _SMARTDNS_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

// from dns
#define DNS_RR_A_LEN 4
#define DNS_RR_AAAA_LEN 16
#define DNS_MAX_CNAME_LEN 256
#define DNS_MAX_OPT_LEN 256
#define DNS_IN_PACKSIZE (512 * 8)
#define DNS_PACKSIZE (512 * 16)
#define DNS_DEFAULT_PACKET_SIZE 512
#define DNS_MAX_ALPN_LEN 32
#define DNS_MAX_ECH_LEN 512

#define DNS_OPT_FLAG_DO 0x8000

#define DNS_ADDR_FAMILY_IP 1
#define DNS_ADDR_FAMILY_IPV6 2

// from dns_conf
#define DNS_MAX_BIND_IP 32
#define DNS_MAX_SERVERS 64
#define DNS_MAX_SERVER_NAME_LEN 128
#define DNS_MAX_PTR_LEN 128
#define DNS_MAX_IPSET_NAMELEN 32
#define DNS_MAX_NFTSET_FAMILYLEN 8
#define DNS_MAX_NFTSET_NAMELEN 256
#define DNS_GROUP_NAME_LEN 32

#define PROXY_NAME_LEN 32
#define PROXY_MAX_SERVERS 128

#define DNS_NAX_GROUP_NUMBER 16
#define DNS_MAX_IPLEN 64
#define DNS_PROXY_MAX_LEN 128
#define DNS_CONF_USERNAME_LEN 32
#define DNS_MAX_SPKI_LEN 64
#define DNS_MAX_URL_LEN 256
#define DNS_MAX_PATH 1024
#define DEFAULT_DNS_PORT 53
#define DEFAULT_DNS_TLS_PORT 853
#define DEFAULT_DNS_HTTPS_PORT 443
#define DNS_MAX_CONF_CNAME_LEN 256
#define MAX_QTYPE_NUM 65535
#define DNS_MAX_REPLY_IP_NUM 8
#define DNS_MAX_QUERY_LIMIT 65535
#define DNS_DEFAULT_CHECKPOINT_TIME (3600 * 24)
#define DNS_MAX_SERVE_EXPIRED_TIME (3600 * 24 * 365)
#define MAX_INTERFACE_LEN 16

#define SMARTDNS_CONF_FILE "/etc/smartdns/smartdns.conf"
#define SMARTDNS_LOG_FILE "/var/log/smartdns/smartdns.log"
#define SMARTDNS_AUDIT_FILE "/var/log/smartdns/smartdns-audit.log"
#define SMARTDNS_CACHE_FILE "/var/cache/smartdns/smartdns.cache"
#define SMARTDNS_TMP_CACHE_FILE "/tmp/smartdns.cache"
#define SMARTDNS_DEBUG_DIR "/tmp/smartdns"
#define DNS_RESOLV_FILE "/etc/resolv.conf"

#ifdef __cplusplus
}
#endif
#endif // !_SMART_DNS_COMMON_H