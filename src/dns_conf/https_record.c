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

#include "https_record.h"
#include "domain_rule.h"
#include "get_domain.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

static int _conf_domain_rule_https_copy_alpn(char *alpn_data, int max_alpn_len, const char *alpn_str)
{
	const char *ptr = NULL;
	int alpn_len = 0;
	char *alpn_len_ptr = NULL;
	char *alpn_ptr = NULL;
	int total_len = 0;

	ptr = alpn_str;
	alpn_len_ptr = alpn_data;
	alpn_ptr = alpn_data + 1;
	total_len++;

	while (*ptr != '\0') {
		total_len++;
		if (total_len > max_alpn_len) {
			return -1;
		}

		if (*ptr == ',') {
			*alpn_len_ptr = alpn_len;
			alpn_len = 0;
			alpn_len_ptr = alpn_ptr;
			ptr++;
			alpn_ptr++;
			continue;
		}

		*alpn_ptr = *ptr;
		alpn_len++;
		alpn_ptr++;
		ptr++;
	}

	*alpn_len_ptr = alpn_len;
	return total_len;
}

int _conf_domain_rule_https_record(const char *domain, const char *host)
{
	struct dns_https_record_rule *https_record_rule = NULL;
	enum domain_rule type = DOMAIN_RULE_HTTPS;
	char buff[4096];
	int key_num = 0;
	char *keys[16];
	char *value[16];
	int priority = -1;
	/*mode_type, 0: alias mode, 1: service mode */
	int mode_type = 0;

	safe_strncpy(buff, host, sizeof(buff));

	https_record_rule = _new_dns_rule(type);
	if (https_record_rule == NULL) {
		goto errout;
	}

	if (conf_parse_key_values(buff, &key_num, keys, value) != 0) {
		tlog(TLOG_ERROR, "input format error, don't have key-value.");
		goto errout;
	}

	if (key_num < 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	for (int i = 0; i < key_num; i++) {
		const char *key = keys[i];
		const char *val = value[i];
		if (strncmp(key, "#", sizeof("#")) == 0) {
			if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_ADDR_HTTPS_SOA, 0) != 0) {
				goto errout;
			}
			break;
		} else if (strncmp(key, "-", sizeof("-")) == 0) {
			if (_config_domain_rule_flag_set(domain, DOMAIN_FLAG_ADDR_HTTPS_IGN, 0) != 0) {
				goto errout;
			}
		} else if (strncmp(key, "target", sizeof("target")) == 0) {
			safe_strncpy(https_record_rule->record.target, val, DNS_MAX_CONF_CNAME_LEN);
			https_record_rule->record.enable = 1;
		} else if (strncmp(key, "noipv4hint", sizeof("noipv4hint")) == 0) {
			https_record_rule->filter.no_ipv4hint = 1;
		} else if (strncmp(key, "noipv6hint", sizeof("noipv6hint")) == 0) {
			https_record_rule->filter.no_ipv6hint = 1;
		} else {
			mode_type = 1;
			https_record_rule->record.enable = 1;
			if (strncmp(key, "priority", sizeof("priority")) == 0) {
				priority = atoi(val);
			} else if (strncmp(key, "port", sizeof("port")) == 0) {
				https_record_rule->record.port = atoi(val);

			} else if (strncmp(key, "alpn", sizeof("alpn")) == 0) {
				int alpn_len = _conf_domain_rule_https_copy_alpn(https_record_rule->record.alpn, DNS_MAX_ALPN_LEN, val);
				if (alpn_len <= 0) {
					tlog(TLOG_ERROR, "invalid option value for %s.", key);
					goto errout;
				}
				https_record_rule->record.alpn_len = alpn_len;
			} else if (strncmp(key, "ech", sizeof("ech")) == 0) {
				int ech_len = SSL_base64_decode(val, https_record_rule->record.ech, DNS_MAX_ECH_LEN);
				if (ech_len < 0) {
					tlog(TLOG_ERROR, "invalid option value for %s.", key);
					goto errout;
				}
				https_record_rule->record.ech_len = ech_len;
			} else if (strncmp(key, "ipv4hint", sizeof("ipv4hint")) == 0) {
				int addr_len = DNS_RR_A_LEN;
				if (get_raw_addr_by_ip(val, https_record_rule->record.ipv4_addr, &addr_len) != 0) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}

				if (addr_len != DNS_RR_A_LEN) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}
				https_record_rule->record.has_ipv4 = 1;
			} else if (strncmp(key, "ipv6hint", sizeof("ipv6hint")) == 0) {
				int addr_len = DNS_RR_AAAA_LEN;
				if (get_raw_addr_by_ip(val, https_record_rule->record.ipv6_addr, &addr_len) != 0) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}

				if (addr_len != DNS_RR_AAAA_LEN) {
					tlog(TLOG_ERROR, "invalid option value for %s, value: %s", key, val);
					goto errout;
				}
				https_record_rule->record.has_ipv6 = 1;
			} else {
				tlog(TLOG_WARN, "invalid parameter %s for https-record.", key);
				continue;
			}
		}
	}

	if (mode_type == 0) {
		if (priority < 0) {
			priority = 0;
		}
	} else {
		if (priority < 0) {
			priority = 1;
		} else if (priority == 0) {
			tlog(TLOG_WARN, "invalid priority %d for https-record.", priority);
			goto errout;
		}
	}

	https_record_rule->record.priority = priority;

	if (_config_domain_rule_add(domain, type, https_record_rule) != 0) {
		goto errout;
	}

	_dns_rule_put(&https_record_rule->head);
	https_record_rule = NULL;

	return 0;
errout:
	if (https_record_rule) {
		_dns_rule_put(&https_record_rule->head);
	}

	return -1;
}

int _config_https_record(void *data, int argc, char *argv[])
{
	char *value = NULL;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	int ret = -1;

	if (argc < 2) {
		goto errout;
	}

	value = argv[1];
	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	ret = _conf_domain_rule_https_record(domain, value);
	if (ret != 0) {
		goto errout;
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "add https-record %s:%s failed", domain, value);
	return -1;
}