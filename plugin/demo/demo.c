#include "demo.h"
#include "dns_server.h"
#include "util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <tlog.h>

static int demo_server_recv(struct dns_packet *packet, unsigned char *inpacket, int inpacket_len,
							struct sockaddr_storage *local, socklen_t local_len, struct sockaddr_storage *from,
							socklen_t from_len)
{
	char hostname[256] = {0};
	tlog(TLOG_INFO, "recv packet from %s", get_host_by_addr(hostname, sizeof(hostname), (struct sockaddr *)from));
	return 0;
}

static void demo_server_request_complete(struct dns_request *request)
{
	tlog(TLOG_INFO, "server complete request, request domain is %s", dns_server_request_get_domain(request));
}

struct smartdns_operations demo_ops = {
	.server_recv = demo_server_recv,
	.server_query_complete = demo_server_request_complete,
};

int dns_plugin_init(struct dns_plugin *plugin)
{
	char options[4096] = {0};
	int argc = dns_plugin_get_argc(plugin);
	const char **argv = dns_plugin_get_argv(plugin);

	for (int i = 0; i < argc; i++) {
		snprintf(options + strlen(options), sizeof(options) - strlen(options), "%s ", argv[i]);
	}

	tlog(TLOG_INFO, "demo plugin init, options: %s", options);
	smartdns_operations_register(&demo_ops);
	return 0;
}

int dns_plugin_exit(struct dns_plugin *plugin)
{
	tlog(TLOG_INFO, "demo plugin exit.");
	smartdns_operations_unregister(&demo_ops);
	return 0;
}
