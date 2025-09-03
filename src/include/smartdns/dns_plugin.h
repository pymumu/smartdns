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

#ifndef SMART_DNS_PLUGIN_H
#define SMART_DNS_PLUGIN_H

#include "smartdns/dns.h"
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define DNS_PLUGIN_INIT_FUNC "dns_plugin_init"
#define DNS_PLUGIN_EXIT_FUNC "dns_plugin_exit"

struct dns_plugin;
struct dns_plugin_ops;
struct dns_request;

typedef int (*dns_plugin_init_func)(struct dns_plugin *plugin);
typedef int (*dns_plugin_exit_func)(struct dns_plugin *plugin);

struct dns_plugin;
int dns_plugin_init(struct dns_plugin *plugin);

int dns_plugin_exit(struct dns_plugin *plugin);

int dns_server_plugin_init(void);

void dns_server_plugin_exit(void);

int dns_plugin_add(const char *plugin_file, int argc, const char *args, int args_len);

int dns_plugin_remove(const char *plugin_file);

typedef enum {
	SMARTDNS_LOG_DEBUG = 0,
	SMARTDNS_LOG_INFO = 1,
	SMARTDNS_LOG_NOTICE = 2,
	SMARTDNS_LOG_WARN = 3,
	SMARTDNS_LOG_ERROR = 4,
	SMARTDNS_LOG_FATAL = 5,
	SMARTDNS_LOG_OFF = 6,
	SMARTDNS_LOG_END = 7
} smartdns_log_level;

int dns_plugin_get_argc(struct dns_plugin *plugin);

const char **dns_plugin_get_argv(struct dns_plugin *plugin);

void smartdns_plugin_log(smartdns_log_level level, const char *file, int line, const char *func, const char *msg);

int smartdns_plugin_can_log(smartdns_log_level level);

void smartdns_plugin_log_setlevel(smartdns_log_level level);

int smartdns_plugin_log_getlevel(void);

const char *smartdns_plugin_get_config(const char *key);

void smartdns_plugin_clear_all_config(void);

int smartdns_plugin_func_server_recv(struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
									 struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
									 socklen_t from_len);
void smartdns_plugin_func_server_complete_request(struct dns_request *request);

void smartdns_plugin_func_server_log_callback(smartdns_log_level level, const char *msg, int msg_len);

void smartdns_plugin_func_server_audit_log_callback(const char *msg, int msg_len);

struct smartdns_operations {
	int (*server_recv)(struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
					   struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
					   socklen_t from_len);
	void (*server_query_complete)(struct dns_request *request);

	void (*server_log)(smartdns_log_level level, const char *msg, int msg_len);

	void (*server_audit_log)(const char *msg, int msg_len);
};

int smartdns_operations_register(const struct smartdns_operations *operations);

int smartdns_operations_unregister(const struct smartdns_operations *operations);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
