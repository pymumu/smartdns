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

#include "proxy_names.h"
#include "smartdns/lib/stringutil.h"

struct dns_proxy_table dns_proxy_table;

struct dns_proxy_names *dns_server_get_proxy_names(const char *proxyname)
{
	uint32_t key = 0;
	struct dns_proxy_names *proxy = NULL;

	key = hash_string(proxyname);
	hash_for_each_possible(dns_proxy_table.proxy, proxy, node, key)
	{
		if (strncmp(proxy->proxy_name, proxyname, DNS_GROUP_NAME_LEN) == 0) {
			return proxy;
		}
	}

	return NULL;
}

/* create and get dns server group */
static struct dns_proxy_names *_dns_conf_get_proxy(const char *proxy_name)
{
	uint32_t key = 0;
	struct dns_proxy_names *proxy = NULL;

	key = hash_string(proxy_name);
	hash_for_each_possible(dns_proxy_table.proxy, proxy, node, key)
	{
		if (strncmp(proxy->proxy_name, proxy_name, PROXY_NAME_LEN) == 0) {
			return proxy;
		}
	}

	proxy = malloc(sizeof(*proxy));
	if (proxy == NULL) {
		goto errout;
	}

	memset(proxy, 0, sizeof(*proxy));
	safe_strncpy(proxy->proxy_name, proxy_name, PROXY_NAME_LEN);
	hash_add(dns_proxy_table.proxy, &proxy->node, key);
	INIT_LIST_HEAD(&proxy->server_list);

	return proxy;
errout:
	if (proxy) {
		free(proxy);
	}

	return NULL;
}

int _dns_conf_proxy_servers_add(const char *proxy_name, struct dns_proxy_servers *server)
{
	struct dns_proxy_names *proxy = NULL;

	proxy = _dns_conf_get_proxy(proxy_name);
	if (proxy == NULL) {
		return -1;
	}

	list_add_tail(&server->list, &proxy->server_list);

	return 0;
}

const char *_dns_conf_get_proxy_name(const char *proxy_name)
{
	struct dns_proxy_names *proxy = NULL;

	proxy = _dns_conf_get_proxy(proxy_name);
	if (proxy == NULL) {
		return NULL;
	}

	return proxy->proxy_name;
}

void _config_proxy_table_destroy(void)
{
	struct dns_proxy_names *proxy = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int i;
	struct dns_proxy_servers *server = NULL;
	struct dns_proxy_servers *server_tmp = NULL;

	hash_for_each_safe(dns_proxy_table.proxy, i, tmp, proxy, node)
	{
		hlist_del_init(&proxy->node);
		list_for_each_entry_safe(server, server_tmp, &proxy->server_list, list)
		{
			list_del(&server->list);
			free(server);
		}
		free(proxy);
	}
}
