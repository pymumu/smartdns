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

#include "txt_record.h"
#include "domain_rule.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

int _conf_domain_rule_txt_record(const char *domain, const char *text)
{
	struct dns_txt_record_rule *txt_rule = NULL;
	struct dns_txt_record *txt_record = NULL;
	int is_new = 0;
	enum domain_rule type = DOMAIN_RULE_TXT;
	int text_len = text == NULL ? 0 : strnlen(text, DNS_MAX_CNAME_LEN);

	if (text_len <= 0 || text_len > DNS_MAX_CNAME_LEN - 1) {
		goto errout;
	}

	txt_rule = dns_conf_get_domain_rule(domain, type);
	if (txt_rule == NULL) {
		txt_rule = _new_dns_rule(type);
		if (txt_rule == NULL) {
			goto errout;
		}
		INIT_LIST_HEAD(&txt_rule->record_list);
		is_new = 1;
	}

	txt_record = zalloc(1, sizeof(*txt_record));
	if (txt_record == NULL) {
		goto errout;
	}

	safe_strncpy(txt_record->text, text, sizeof(txt_record->text));
	list_add_tail(&txt_record->list, &txt_rule->record_list);

	if (is_new) {
		if (_config_domain_rule_add(domain, type, txt_rule) != 0) {
			goto errout;
		}
		_dns_rule_put(&txt_rule->head);
		txt_rule = NULL;
	}

	return 0;
errout:
	if (is_new && txt_rule != NULL) {
		_dns_rule_put(&txt_rule->head);
	}
	if (txt_record && txt_record->list.next == NULL) {
		free(txt_record);
	}
	return -1;
}

int _config_txt_record(void *data, int argc, char *argv[])
{
	char *value = NULL;
	char domain[DNS_MAX_CONF_CNAME_LEN] = {0};
	int ret = -1;

	if (argc < 2) {
		goto errout;
	}

	value = argv[1];
	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	ret = _conf_domain_rule_txt_record(domain, value);
	if (ret != 0) {
		goto errout;
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "add txt-record %s:%s failed", domain, value);
	return -1;
}
