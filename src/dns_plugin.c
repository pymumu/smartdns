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

#define _GNU_SOURCE

#include "smartdns/dns_plugin.h"

#include "smartdns/dns_conf.h"
#include "smartdns/lib/conf.h"
#include "smartdns/lib/hashtable.h"
#include "smartdns/lib/list.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"
#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	pthread_rwlock_t lock;
	DECLARE_HASHTABLE(plugin, 4);
};

static struct dns_plugins plugins;
static atomic_t is_plugin_init = ATOMIC_INIT(0);

int smartdns_plugin_func_server_recv(struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									 struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
									 socklen_t from_len)
{
	struct dns_plugin_ops *chain = NULL;
	int ret = 0;

	if (unlikely(atomic_read(&is_plugin_init) == 0)) {
		return 0;
	}

	pthread_rwlock_rdlock(&plugins.lock);
	list_for_each_entry(chain, &plugins.list, list)
	{
		if (!chain->ops.server_recv) {
			continue;
		}

		ret = chain->ops.server_recv(packet, inpacket, inpacket_len, local, local_len, from, from_len);
		if (ret != 0) {
			pthread_rwlock_unlock(&plugins.lock);
			return ret;
		}
	}
	pthread_rwlock_unlock(&plugins.lock);

	return 0;
}

void smartdns_plugin_func_server_complete_request(struct dns_request *request)
{
	struct dns_plugin_ops *chain = NULL;

	if (unlikely(atomic_read(&is_plugin_init) == 0)) {
		return;
	}

	pthread_rwlock_rdlock(&plugins.lock);
	list_for_each_entry(chain, &plugins.list, list)
	{
		if (!chain->ops.server_query_complete) {
			continue;
		}

		chain->ops.server_query_complete(request);
	}
	pthread_rwlock_unlock(&plugins.lock);

	return;
}

void smartdns_plugin_func_server_log_callback(smartdns_log_level level, const char *msg, int msg_len)
{
	struct dns_plugin_ops *chain = NULL;

	if (unlikely(atomic_read(&is_plugin_init) == 0)) {
		return;
	}

	pthread_rwlock_rdlock(&plugins.lock);
	list_for_each_entry(chain, &plugins.list, list)
	{
		if (!chain->ops.server_log) {
			continue;
		}

		chain->ops.server_log(level, msg, msg_len);
	}
	pthread_rwlock_unlock(&plugins.lock);

	return;
}

void smartdns_plugin_func_server_audit_log_callback(const char *msg, int msg_len)
{
	struct dns_plugin_ops *chain = NULL;

	if (unlikely(atomic_read(&is_plugin_init) == 0)) {
		return;
	}

	pthread_rwlock_rdlock(&plugins.lock);
	list_for_each_entry(chain, &plugins.list, list)
	{
		if (!chain->ops.server_audit_log) {
			continue;
		}

		chain->ops.server_audit_log(msg, msg_len);
	}
	pthread_rwlock_unlock(&plugins.lock);

	return;
}

int smartdns_operations_register(const struct smartdns_operations *operations)
{
	struct dns_plugin_ops *chain = NULL;

	chain = (struct dns_plugin_ops *)malloc(sizeof(struct dns_plugin_ops));
	if (!chain) {
		return -1;
	}

	memcpy(&chain->ops, operations, sizeof(struct smartdns_operations));
	pthread_rwlock_wrlock(&plugins.lock);
	list_add_tail(&chain->list, &plugins.list);
	pthread_rwlock_unlock(&plugins.lock);

	return 0;
}

int smartdns_operations_unregister(const struct smartdns_operations *operations)
{
	struct dns_plugin_ops *chain = NULL;
	struct dns_plugin_ops *tmp = NULL;

	pthread_rwlock_wrlock(&plugins.lock);
	list_for_each_entry_safe(chain, tmp, &plugins.list, list)
	{
		if (memcmp(&chain->ops, operations, sizeof(struct smartdns_operations)) == 0) {
			list_del(&chain->list);
			pthread_rwlock_unlock(&plugins.lock);
			free(chain);
			return 0;
		}
	}
	pthread_rwlock_unlock(&plugins.lock);

	return -1;
}

static struct dns_plugin *_dns_plugin_get(const char *plugin_file)
{
	struct dns_plugin *plugin = NULL;
	unsigned int key = 0;

	key = hash_string(plugin_file);
	pthread_rwlock_rdlock(&plugins.lock);
	hash_for_each_possible(plugins.plugin, plugin, node, key)
	{
		if (strncmp(plugin->file, plugin_file, PATH_MAX - 1) == 0) {
			pthread_rwlock_unlock(&plugins.lock);
			return plugin;
		}
	}
	pthread_rwlock_unlock(&plugins.lock);

	return NULL;
}

static int _dns_plugin_load_library(struct dns_plugin *plugin)
{
	void *handle = NULL;
	dns_plugin_api_version_func version_func = NULL;
	dns_plugin_init_func init_func = NULL;
	dns_plugin_exit_func exit_func = NULL;
	unsigned int api_version = 0;

	tlog(TLOG_DEBUG, "load plugin %s", plugin->file);

	handle = dlopen(plugin->file, RTLD_LAZY | RTLD_LOCAL);
	if (!handle) {
		tlog(TLOG_ERROR, "load plugin %s failed: %s", plugin->file, dlerror());
		return -1;
	}

	version_func = (dns_plugin_api_version_func)dlsym(handle, DNS_PLUGIN_API_VERSION_FUNC);
	if (!version_func) {
		tlog(TLOG_ERROR,
			 "plugin %s has no api version function, maybe an old version plugin, please download latest version.",
			 plugin->file);
		goto errout;
	}

	init_func = (dns_plugin_init_func)dlsym(handle, DNS_PLUGIN_INIT_FUNC);
	if (!init_func) {
		tlog(TLOG_ERROR, "load plugin failed: %s", dlerror());
		tlog(TLOG_ERROR, "%s is not a valid smartdns plugin, please check 'plugin' option.", plugin->file);
		goto errout;
	}

	exit_func = (dns_plugin_exit_func)dlsym(handle, DNS_PLUGIN_EXIT_FUNC);
	if (!exit_func) {
		tlog(TLOG_ERROR, "load plugin failed: %s", dlerror());
		tlog(TLOG_ERROR, "%s not a valid smartdns plugin, please check 'plugin' option.", plugin->file);
		goto errout;
	}

	api_version = version_func();
	if (SMARTDNS_PLUGIN_API_VERSION_MAJOR(api_version) !=
		SMARTDNS_PLUGIN_API_VERSION_MAJOR(SMARTDNS_PLUGIN_API_VERSION)) {
		tlog(TLOG_ERROR,
			 "plugin %s api version %u.%u not compatible with smartdns api version %u.%u, please download matching "
			 "version.",
			 plugin->file, SMARTDNS_PLUGIN_API_VERSION_MAJOR(api_version),
			 SMARTDNS_PLUGIN_API_VERSION_MINOR(api_version),
			 SMARTDNS_PLUGIN_API_VERSION_MAJOR(SMARTDNS_PLUGIN_API_VERSION),
			 SMARTDNS_PLUGIN_API_VERSION_MINOR(SMARTDNS_PLUGIN_API_VERSION));
		goto errout;
	} else if (SMARTDNS_PLUGIN_API_VERSION_MINOR(api_version) >
			   SMARTDNS_PLUGIN_API_VERSION_MINOR(SMARTDNS_PLUGIN_API_VERSION)) {
		tlog(TLOG_ERROR,
			 "plugin %s api version %u.%u is newer than smartdns api version %u.%u, please download matching version.",
			 plugin->file, SMARTDNS_PLUGIN_API_VERSION_MAJOR(api_version),
			 SMARTDNS_PLUGIN_API_VERSION_MINOR(api_version),
			 SMARTDNS_PLUGIN_API_VERSION_MAJOR(SMARTDNS_PLUGIN_API_VERSION),
			 SMARTDNS_PLUGIN_API_VERSION_MINOR(SMARTDNS_PLUGIN_API_VERSION));
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
	pthread_rwlock_wrlock(&plugins.lock);
	hash_del(&plugin->node);
	pthread_rwlock_unlock(&plugins.lock);
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

	pthread_rwlock_wrlock(&plugins.lock);
	list_for_each_entry_safe(chain, tmp, &plugins.list, list)
	{
		list_del(&chain->list);
		free(chain);
	}
	pthread_rwlock_unlock(&plugins.lock);

	return 0;
}

static int _dns_plugin_remove_all(void)
{
	struct dns_plugin *plugin = NULL;
	struct hlist_node *tmp = NULL;
	unsigned int key = 0;

	pthread_rwlock_wrlock(&plugins.lock);
	/* avoid hang */
	while (!hash_empty(plugins.plugin)) {
		pthread_rwlock_unlock(&plugins.lock);
		hash_for_each_safe(plugins.plugin, key, tmp, plugin, node)
		{
			_dns_plugin_remove(plugin);
			break;
		}
		pthread_rwlock_wrlock(&plugins.lock);
	}
	pthread_rwlock_unlock(&plugins.lock);

	return -1;
}

int dns_server_plugin_init(void)
{
	if (atomic_read(&is_plugin_init) == 1) {
		return 0;
	}

	hash_init(plugins.plugin);
	INIT_LIST_HEAD(&plugins.list);
	if (pthread_rwlock_init(&plugins.lock, NULL) != 0) {
		tlog(TLOG_ERROR, "init plugin rwlock failed.");
		return -1;
	}
	atomic_set(&is_plugin_init, 1);
	return 0;
}

void dns_server_plugin_exit(void)
{
	if (atomic_read(&is_plugin_init) == 0) {
		return;
	}

	_dns_plugin_remove_all_ops();
	_dns_plugin_remove_all();

	pthread_rwlock_destroy(&plugins.lock);
	atomic_set(&is_plugin_init, 0);
	return;
}

void smartdns_plugin_log(smartdns_log_level level, const char *file, int line, const char *func, const char *msg)
{
	tlog_ext((tlog_level)level, file, line, func, NULL, "%s", msg);
}

int smartdns_plugin_can_log(smartdns_log_level level)
{
	return tlog_getlevel() <= (tlog_level)level;
}

void smartdns_plugin_log_setlevel(smartdns_log_level level)
{
	tlog_setlevel((tlog_level)level);
}

int smartdns_plugin_log_getlevel(void)
{
	return tlog_getlevel();
}

int smartdns_plugin_is_audit_enabled(void)
{
	return dns_conf.audit_enable;
}

const char *smartdns_plugin_get_config(const char *key)
{
	return dns_conf_get_plugin_conf(key);
}

void smartdns_plugin_clear_all_config(void)
{
	dns_conf_clear_all_plugin_conf();
}