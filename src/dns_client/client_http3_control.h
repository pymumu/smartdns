#ifndef SMARTDNS_CLIENT_HTTP3_CONTROL_H
#define SMARTDNS_CLIENT_HTTP3_CONTROL_H
#include "dns_client.h"
#ifdef __cplusplus
extern "C" {
#endif
int _dns_http3_control_poll(struct dns_server_info *server);
int _dns_http3_control_pending(struct dns_server_info *server);
int _dns_http3_request_allowed(struct dns_server_info *server, SSL *stream);
int _dns_http3_drain_complete(struct dns_server_info *server);
int _dns_http3_control_shutdown(struct dns_server_info *server);
void _dns_http3_control_free(struct dns_server_info *server);
int _dns_http3_connection_error(struct dns_server_info *server, uint64_t code);
#ifdef TEST
size_t _dns_http3_control_test_pending_bytes(struct dns_server_info *server);
int _dns_http3_control_test_feed(struct dns_server_info *server, unsigned slot, const unsigned char *data, size_t len);
#endif
#ifdef __cplusplus
}
#endif
#endif
