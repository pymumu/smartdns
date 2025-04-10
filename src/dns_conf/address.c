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

#include "address.h"
#include "domain_rule.h"
#include "get_domain.h"
#include "ptr.h"
#include "smartdns/util.h"

#define TMP_BUFF_LEN 1024

int _conf_domain_rule_address(char *domain, const char *domain_address)
{
	struct dns_rule_address_IPV4 *address_ipv4 = NULL;
	struct dns_rule_address_IPV6 *address_ipv6 = NULL;
	struct dns_rule *address = NULL;

	char ip[MAX_IP_LEN];
	int port = 0;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	unsigned int flag = 0;
	char *ptr = NULL;
	char *field = NULL;
	char tmpbuff[TMP_BUFF_LEN] = {0};

	char ipv6_addr[DNS_MAX_REPLY_IP_NUM][DNS_RR_AAAA_LEN];
	int ipv6_num = 0;
	char ipv4_addr[DNS_MAX_REPLY_IP_NUM][DNS_RR_A_LEN];
	int ipv4_num = 0;

	safe_strncpy(tmpbuff, domain_address, sizeof(tmpbuff));

	ptr = tmpbuff;

	do {
		field = ptr;
		ptr = strstr(ptr, ",");

		if (field == NULL || *field == '\0') {
			break;
		}

		if (ptr) {
			*ptr = 0;
		}

		if (*(field) == '#') {
			if (strncmp(field, "#4", sizeof("#4")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV4_SOA;
			} else if (strncmp(field, "#6", sizeof("#6")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV6_SOA;
			} else if (strncmp(field, "#", sizeof("#")) == 0) {
				flag = DOMAIN_FLAG_ADDR_SOA;
			} else {
				goto errout;
			}

			/* add SOA rule */
			if (_config_domain_rule_flag_set(domain, flag, 0) != 0) {
				goto errout;
			}

			if (ptr) {
				ptr++;
			}
			continue;
		} else if (*(field) == '-') {
			if (strncmp(field, "-4", sizeof("-4")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV4_IGN;
			} else if (strncmp(field, "-6", sizeof("-6")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IPV6_IGN;
			} else if (strncmp(field, "-", sizeof("-")) == 0) {
				flag = DOMAIN_FLAG_ADDR_IGN;
			} else {
				goto errout;
			}

			/* ignore rule */
			if (_config_domain_rule_flag_set(domain, flag, 0) != 0) {
				goto errout;
			}

			if (ptr) {
				ptr++;
			}
			continue;
		}

		/* set address to domain */
		if (parse_ip(field, ip, &port) != 0) {
			goto errout;
		}

		addr_len = sizeof(addr);
		if (getaddr_by_host(ip, (struct sockaddr *)&addr, &addr_len) != 0) {
			goto errout;
		}

		switch (addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *addr_in = NULL;
			addr_in = (struct sockaddr_in *)&addr;
			if (ipv4_num < DNS_MAX_REPLY_IP_NUM) {
				memcpy(ipv4_addr[ipv4_num], &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
				ipv4_num++;
			}
		} break;
		case AF_INET6: {
			struct sockaddr_in6 *addr_in6 = NULL;
			addr_in6 = (struct sockaddr_in6 *)&addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr) && ipv4_num < DNS_MAX_REPLY_IP_NUM) {
				memcpy(ipv4_addr[ipv4_num], addr_in6->sin6_addr.s6_addr + 12, DNS_RR_A_LEN);
				ipv4_num++;
			} else if (ipv6_num < DNS_MAX_REPLY_IP_NUM) {
				memcpy(ipv6_addr[ipv6_num], addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
				ipv6_num++;
			}
		} break;
		default:
			ip[0] = '\0';
			break;
		}

		/* add PTR */
		if (dns_conf.expand_ptr_from_address == 1 && ip[0] != '\0' && _conf_ptr_add(domain, ip, 0) != 0) {
			goto errout;
		}

		if (ptr) {
			ptr++;
		}
	} while (ptr);

	if (ipv4_num > 0) {
		address_ipv4 = _new_dns_rule_ext(DOMAIN_RULE_ADDRESS_IPV4, ipv4_num * DNS_RR_A_LEN);
		if (address_ipv4 == NULL) {
			goto errout;
		}

		memcpy(address_ipv4->ipv4_addr, ipv4_addr[0], ipv4_num * DNS_RR_A_LEN);
		address_ipv4->addr_num = ipv4_num;
		address = (struct dns_rule *)address_ipv4;

		if (_config_domain_rule_add(domain, DOMAIN_RULE_ADDRESS_IPV4, address) != 0) {
			goto errout;
		}

		_dns_rule_put(address);
	}

	if (ipv6_num > 0) {
		address_ipv6 = _new_dns_rule_ext(DOMAIN_RULE_ADDRESS_IPV6, ipv6_num * DNS_RR_AAAA_LEN);
		if (address_ipv6 == NULL) {
			goto errout;
		}

		memcpy(address_ipv6->ipv6_addr, ipv6_addr[0], ipv6_num * DNS_RR_AAAA_LEN);
		address_ipv6->addr_num = ipv6_num;
		address = (struct dns_rule *)address_ipv6;

		if (_config_domain_rule_add(domain, DOMAIN_RULE_ADDRESS_IPV6, address) != 0) {
			goto errout;
		}

		_dns_rule_put(address);
	}

	return 0;
errout:
	if (address) {
		_dns_rule_put(address);
	}

	tlog(TLOG_ERROR, "add address %s, %s at %s:%d failed", domain, domain_address, conf_get_conf_file(),
		 conf_get_current_lineno());
	return 0;
}

int _config_address(void *data, int argc, char *argv[])
{
	char *value = argv[1];
	char domain[DNS_MAX_CONF_CNAME_LEN];

	if (argc <= 1) {
		goto errout;
	}

	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	return _conf_domain_rule_address(domain, value);
errout:
	tlog(TLOG_ERROR, "add address %s failed", value);
	return 0;
}