/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "dns_plugin.h"

#include "include/conf.h"
#include "include/hashtable.h"
#include "include/list.h"
#include "util.h"
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tlog.h"

struct dns_plugin_ops {
	struct list_head list;
	struct smartdns_operations ops;
};

#define DNS_PLUGIN_MAX_ARGS 32
struct dns_plugin {
	struct hlist_node node;
	char file[PATH_MAX];
	char args[PATH_MAX];
	int argc;
	char *argv[DNS_PLUGIN_MAX_ARGS];
	void *handle;
	dns_plugin_init_func init_func;
	dns_plugin_exit_func exit_func;
};

struct dns_plugins {
	struct list_head list;
	DECLARE_HASHTABLE(plugin, 4);
};

static struct dns_plugins plugins;
static int is_plugin_init;

int smartdns_plugin_func_server_recv(struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									 struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
									 socklen_t from_len)
{
	struct dns_plugin_ops *chain = NULL;
	int ret = 0;

	list_for_each_entry(chain, &plugins.list, list)
	{
		if (!chain->ops.server_recv) {
			continue;
		}

		ret = chain->ops.server_recv(packet, inpacket, inpacket_len, local, local_len, from, from_len);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

void smartdns_plugin_func_server_complete_request(struct dns_request *request)
{
	struct dns_plugin_ops *chain = NULL;

	list_for_each_entry(chain, &plugins.list, list)
	{
		if (!chain->ops.server_query_complete) {
			continue;
		}

		chain->ops.server_query_complete(request);
	}

	return;
}

int smartdns_operations_register(struct smartdns_operations *operations)
{
	struct dns_plugin_ops *chain = NULL;

	chain = (struct dns_plugin_ops *)malloc(sizeof(struct dns_plugin_ops));
	if (!chain) {
		return -1;
	}

	memcpy(&chain->ops, operations, sizeof(struct smartdns_operations));
	list_add_tail(&chain->list, &plugins.list);

	return 0;
}

int smartdns_operations_unregister(struct smartdns_operations *operations)
{
	struct dns_plugin_ops *chain = NULL;
	struct dns_plugin_ops *tmp = NULL;

	list_for_each_entry_safe(chain, tmp, &plugins.list, list)
	{
		if (memcmp(&chain->ops, operations, sizeof(struct smartdns_operations)) == 0) {
			list_del(&chain->list);
			free(chain);
			return 0;
		}
	}

	return -1;
}

static struct dns_plugin *_dns_plugin_get(const char *plugin_file)
{
	struct dns_plugin *plugin = NULL;
	unsigned int key = 0;

	key = hash_string(plugin_file);
	hash_for_each_possible(plugins.plugin, plugin, node, key)
	{
		if (strncmp(plugin->file, plugin_file, PATH_MAX - 1) == 0) {
			return plugin;
		}
	}

	return NULL;
}

static int _dns_plugin_load_library(struct dns_plugin *plugin)
{
	void *handle = NULL;
	dns_plugin_init_func init_func = NULL;
	dns_plugin_exit_func exit_func = NULL;

	handle = dlopen(plugin->file, RTLD_LAZY | RTLD_LOCAL);
	if (!handle) {
		tlog(TLOG_ERROR, "load plugin %s failed: %s", plugin->file, dlerror());
		return -1;
	}

	init_func = (dns_plugin_init_func)dlsym(handle, DNS_PLUGIN_INIT_FUNC);
	if (!init_func) {
		tlog(TLOG_ERROR, "load plugin %s failed: %s", plugin->file, dlerror());
		goto errout;
	}

	exit_func = (dns_plugin_exit_func)dlsym(handle, DNS_PLUGIN_EXIT_FUNC);
	if (!exit_func) {
		tlog(TLOG_ERROR, "load plugin %s failed: %s", plugin->file, dlerror());
		goto errout;
	}

	conf_getopt_reset();
	int ret = init_func(plugin);
	conf_getopt_reset();
	if (ret != 0) {
		tlog(TLOG_ERROR, "init plugin %s failed", plugin->file);
		goto errout;
	}

	plugin->handle = handle;
	plugin->init_func = init_func;
	plugin->exit_func = exit_func;

	return 0;

errout:
	if (handle) {
		dlclose(handle);
	}
	return -1;
}

static int _dns_plugin_unload_library(struct dns_plugin *plugin)
{
	int ret = 0;
	if (plugin->exit_func) {
		ret = plugin->exit_func(plugin);
		if (ret != 0) {
			tlog(TLOG_ERROR, "exit plugin %s failed", plugin->file);
		}
	}

	if (plugin->handle) {
		dlclose(plugin->handle);
		plugin->handle = NULL;
	}

	return 0;
}

static struct dns_plugin *_dns_plugin_new(const char *plugin_file)
{
	struct dns_plugin *plugin = NULL;

	plugin = _dns_plugin_get(plugin_file);
	if (plugin) {
		return NULL;
	}

	plugin = (struct dns_plugin *)malloc(sizeof(struct dns_plugin));
	if (!plugin) {
		return NULL;
	}

	memset(plugin, 0, sizeof(struct dns_plugin));
	strncpy(plugin->file, plugin_file, PATH_MAX - 1);

	return plugin;
}

static int _dns_plugin_remove(struct dns_plugin *plugin)
{
	_dns_plugin_unload_library(plugin);
	hash_del(&plugin->node);
	free(plugin);

	return 0;
}

int dns_plugin_get_argc(struct dns_plugin *plugin)
{
	return plugin->argc;
}

const char **dns_plugin_get_argv(struct dns_plugin *plugin)
{
	return (const char **)plugin->argv;
}

int dns_plugin_add(const char *plugin_file, int argc, const char *args, int args_len)
{
	struct dns_plugin *plugin = NULL;
	const char *plugin_args = NULL;

	plugin = _dns_plugin_new(plugin_file);
	if (!plugin) {
		tlog(TLOG_ERROR, "add plugin %s failed", plugin_file);
		return -1;
	}

	memcpy(plugin->args, args, PATH_MAX - 1);
	plugin->argc = argc;
	plugin_args = plugin->args;
	for (int i = 0; i < argc && i < DNS_PLUGIN_MAX_ARGS; i++) {
		plugin->argv[i] = (char *)plugin_args;
		plugin_args += strlen(plugin_args) + 1;
	}

	if (_dns_plugin_load_library(plugin) != 0) {
		goto errout;
	}

	hash_add(plugins.plugin, &plugin->node, hash_string(plugin_file));

	return 0;
errout:
	if (plugin) {
		_dns_plugin_remove(plugin);
	}
	return -1;
}

int dns_plugin_remove(const char *plugin_file)
{
	struct dns_plugin *plugin = NULL;

	plugin = _dns_plugin_get(plugin_file);
	if (plugin == NULL) {
		return 0;
	}

	return _dns_plugin_remove(plugin);
}

static int _dns_plugin_remove_all_ops(void)
{
	struct dns_plugin_ops *chain = NULL;
	struct dns_plugin_ops *tmp = NULL;

	list_for_each_entry_safe(chain, tmp, &plugins.list, list)
	{
		list_del(&chain->list);
		free(chain);
	}

	return 0;
}

static int _dns_plugin_remove_all(void)
{
	struct dns_plugin *plugin = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int key = 0;

	hash_for_each_safe(plugins.plugin, key, tmp, plugin, node)
	{
		_dns_plugin_remove(plugin);
	}

	return -1;
}

int dns_server_plugin_init(void)
{
	if (is_plugin_init == 1) {
		return 0;
	}

	hash_init(plugins.plugin);
	INIT_LIST_HEAD(&plugins.list);
	is_plugin_init = 1;
	return 0;
}

void dns_server_plugin_exit(void)
{
	if (is_plugin_init == 0) {
		return;
	}

	_dns_plugin_remove_all_ops();
	_dns_plugin_remove_all();
	return;
}

void smartdns_plugin_log(smartdns_log_level level, const char *file, int line, const char *func, const char *msg)
{
	tlog_ext((tlog_level)level, file, line, func, NULL, "%s", msg);
}
