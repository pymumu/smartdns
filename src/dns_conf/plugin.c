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

#include "plugin.h"
#include "smartdns/lib/stringutil.h"

struct dns_conf_plugin_table dns_conf_plugin_table;

static struct dns_conf_plugin *_config_get_plugin(const char *file)
{
	uint32_t key = 0;
	struct dns_conf_plugin *plugin = NULL;

	key = hash_string(file);
	hash_for_each_possible(dns_conf_plugin_table.plugins, plugin, node, key)
	{
		if (strncmp(plugin->file, file, DNS_MAX_PATH) != 0) {
			continue;
		}

		return plugin;
	}

	return NULL;
}

static struct dns_conf_plugin_conf *_config_get_plugin_conf(const char *key)
{
	uint32_t hash = 0;
	struct dns_conf_plugin_conf *conf = NULL;

	hash = hash_string(key);
	hash_for_each_possible(dns_conf_plugin_table.plugins_conf, conf, node, hash)
	{
		if (strncmp(conf->key, key, DNS_MAX_PATH) != 0) {
			continue;
		}

		return conf;
	}

	return NULL;
}

const char *dns_conf_get_plugin_conf(const char *key)
{
	struct dns_conf_plugin_conf *conf = _config_get_plugin_conf(key);
	if (conf == NULL) {
		return NULL;
	}

	return conf->value;
}

int _config_plugin(void *data, int argc, char *argv[])
{
#ifdef BUILD_STATIC
	tlog(TLOG_ERROR, "plugin not support in static release, please install dynamic release.");
	goto errout;
#endif
	char file[DNS_MAX_PATH];
	unsigned int key = 0;
	int i = 0;
	char *ptr = NULL;
	char *ptr_end = NULL;

	if (argc < 1) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	conf_get_conf_fullpath(argv[1], file, sizeof(file));
	if (file[0] == '\0') {
		tlog(TLOG_ERROR, "plugin: invalid parameter.");
		goto errout;
	}

	struct dns_conf_plugin *plugin = _config_get_plugin(file);
	if (plugin != NULL) {
		tlog(TLOG_ERROR, "plugin '%s' already exists.", file);
		goto errout;
	}

	if (access(file, F_OK) != 0) {
		tlog(TLOG_ERROR, "plugin '%s' not exists.", file);
		goto errout;
	}

	plugin = malloc(sizeof(*plugin));
	if (plugin == NULL) {
		goto errout;
	}
	memset(plugin, 0, sizeof(*plugin));
	safe_strncpy(plugin->file, file, sizeof(plugin->file) - 1);
	ptr = plugin->args;
	ptr_end = plugin->args + sizeof(plugin->args) - 2;
	for (i = 1; i < argc && ptr < ptr_end; i++) {
		safe_strncpy(ptr, argv[i], ptr_end - ptr - 1);
		ptr += strlen(argv[i]) + 1;
	}
	plugin->argc = argc - 1;
	plugin->args_len = ptr - plugin->args;

	key = hash_string(file);
	hash_add(dns_conf_plugin_table.plugins, &plugin->node, key);

	return 0;
errout:
	return -1;
}

int _config_plugin_conf_add(const char *key, const char *value)
{
	uint32_t hash = 0;
	struct dns_conf_plugin_conf *conf = NULL;

	if (key == NULL || value == NULL) {
		tlog(TLOG_ERROR, "invalid parameter.");
		goto errout;
	}

	conf = _config_get_plugin_conf(key);
	if (conf == NULL) {

		hash = hash_string(key);
		conf = malloc(sizeof(*conf));
		if (conf == NULL) {
			goto errout;
		}
		memset(conf, 0, sizeof(*conf));
		safe_strncpy(conf->key, key, sizeof(conf->key) - 1);
		hash_add(dns_conf_plugin_table.plugins_conf, &conf->node, hash);
	}
	safe_strncpy(conf->value, value, sizeof(conf->value) - 1);

	return 0;

errout:
	return -1;
}

void _config_plugin_table_init(void)
{
	hash_init(dns_conf_plugin_table.plugins);
	hash_init(dns_conf_plugin_table.plugins_conf);
}

void _config_plugin_table_destroy(void)
{
	struct dns_conf_plugin *plugin = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_plugin_table.plugins, i, tmp, plugin, node)
	{
		hlist_del_init(&plugin->node);
		free(plugin);
	}
}

void _config_plugin_table_conf_destroy(void)
{
	struct dns_conf_plugin_conf *plugin_conf = NULL;
	struct hlist_node *tmp = NULL;
	unsigned long i = 0;

	hash_for_each_safe(dns_conf_plugin_table.plugins_conf, i, tmp, plugin_conf, node)
	{
		hlist_del_init(&plugin_conf->node);
		free(plugin_conf);
	}
}

void dns_conf_clear_all_plugin_conf(void)
{
	_config_plugin_table_conf_destroy();
}