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

#include "srv_record.h"
#include "set_file.h"
#include "smartdns/lib/stringutil.h"

/* SRV-HOST */
struct dns_srv_record_table dns_conf_srv_record_table;

struct dns_srv_records *dns_server_get_srv_record(const char *domain)
{
	uint32_t key = 0;

	key = hash_string(domain);
	struct dns_srv_records *srv_records = NULL;
	hash_for_each_possible(dns_conf_srv_record_table.srv, srv_records, node, key)
	{
		if (strncmp(srv_records->domain, domain, DNS_MAX_CONF_CNAME_LEN) == 0) {
			return srv_records;
		}
	}

	return NULL;
}

static int _confg_srv_record_add(const char *domain, const char *host, unsigned short priority, unsigned short weight,
								 unsigned short port)
{
	struct dns_srv_records *srv_records = NULL;
	struct dns_srv_record *srv_record = NULL;
	uint32_t key = 0;

	srv_records = dns_server_get_srv_record(domain);
	if (srv_records == NULL) {
		srv_records = malloc(sizeof(*srv_records));
		if (srv_records == NULL) {
			goto errout;
		}
		memset(srv_records, 0, sizeof(*srv_records));
		safe_strncpy(srv_records->domain, domain, DNS_MAX_CONF_CNAME_LEN);
		INIT_LIST_HEAD(&srv_records->list);
		key = hash_string(domain);
		hash_add(dns_conf_srv_record_table.srv, &srv_records->node, key);
	}

	srv_record = malloc(sizeof(*srv_record));
	if (srv_record == NULL) {
		goto errout;
	}
	memset(srv_record, 0, sizeof(*srv_record));
	safe_strncpy(srv_record->host, host, DNS_MAX_CONF_CNAME_LEN);
	srv_record->priority = priority;
	srv_record->weight = weight;
	srv_record->port = port;
	list_add_tail(&srv_record->list, &srv_records->list);

	return 0;
errout:
	if (srv_record != NULL) {
		free(srv_record);
	}
	return -1;
}

int _config_srv_record(void *data, int argc, char *argv[])
{
	char *value = NULL;
	char domain[DNS_MAX_CONF_CNAME_LEN];
	char buff[DNS_MAX_CONF_CNAME_LEN];
	char *ptr = NULL;
	int ret = -1;

	char *host_s;
	char *priority_s;
	char *weight_s;
	char *port_s;

	unsigned short priority = 0;
	unsigned short weight = 0;
	unsigned short port = 1;

	if (argc < 2) {
		goto errout;
	}

	value = argv[1];
	if (_get_domain(value, domain, DNS_MAX_CONF_CNAME_LEN, &value) != 0) {
		goto errout;
	}

	safe_strncpy(buff, value, sizeof(buff));

	host_s = strtok_r(buff, ",", &ptr);
	if (host_s == NULL) {
		host_s = "";
		goto out;
	}

	port_s = strtok_r(NULL, ",", &ptr);
	if (port_s != NULL) {
		port = atoi(port_s);
	}

	priority_s = strtok_r(NULL, ",", &ptr);
	if (priority_s != NULL) {
		priority = atoi(priority_s);
	}

	weight_s = strtok_r(NULL, ",", &ptr);
	if (weight_s != NULL) {
		weight = atoi(weight_s);
	}
out:
	ret = _confg_srv_record_add(domain, host_s, priority, weight, port);
	if (ret != 0) {
		goto errout;
	}

	return 0;

errout:
	tlog(TLOG_ERROR, "add srv-record %s:%s failed", domain, value);
	return -1;
}

void _config_srv_record_table_init(void)
{
	hash_init(dns_conf_srv_record_table.srv);
}

void _config_srv_record_table_destroy(void)
{
	struct dns_srv_records *srv_records = NULL;
	struct dns_srv_record *srv_record, *tmp1 = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int i;

	hash_for_each_safe(dns_conf_srv_record_table.srv, i, tmp, srv_records, node)
	{
		list_for_each_entry_safe(srv_record, tmp1, &srv_records->list, list)
		{
			list_del(&srv_record->list);
			free(srv_record);
		}

		hlist_del_init(&srv_records->node);
		free(srv_records);
	}
}