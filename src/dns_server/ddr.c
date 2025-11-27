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

#include "ddr.h"
#include "context.h"
#include "dns_server.h"
#include "request.h"
#include "smartdns/dns.h"
#include "smartdns/util.h"
#include "soa.h"
#include <netinet/in.h>

static const char *_ddr_get_alpn(const struct dns_bind_ip *bind_ip)
{
	if (bind_ip->alpn[0] != '\0') {
		return bind_ip->alpn;
	}

	switch (bind_ip->type) {
	case DNS_BIND_TYPE_TLS:
		return "dot";
	case DNS_BIND_TYPE_HTTPS:
		return "h2,http/1.1";
	default:
		return NULL;
	}
}

static void _ddr_extract_local_addresses(const struct sockaddr_storage *addr, unsigned char *ipv4_addr, int *ipv4_num,
										 unsigned char *ipv6_addr, int *ipv6_num)
{
	*ipv4_num = 0;
	*ipv6_num = 0;

	if (addr == NULL) {
		return;
	}

	switch (addr->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *addr_in = (const struct sockaddr_in *)addr;
		memcpy(ipv4_addr, &addr_in->sin_addr.s_addr, DNS_RR_A_LEN);
		*ipv4_num = 1;
	} break;
	case AF_INET6: {
		const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)addr;
		memcpy(ipv6_addr, addr_in6->sin6_addr.s6_addr, DNS_RR_AAAA_LEN);
		*ipv6_num = 1;
	} break;
	default:
		break;
	}
}

static int _ddr_build_svcb_record(struct dns_packet *packet, const char *domain, int ttl, int priority,
								  const char *alpn, int port, unsigned char *ipv4_addr, int ipv4_num,
								  unsigned char *ipv6_addr, int ipv6_num)
{
	struct dns_rr_nested svcparam_buffer;

	if (dns_add_SVCB_start(&svcparam_buffer, packet, DNS_RRS_AN, domain, ttl, priority, NULL) != 0) {
		return -1;
	}

	/* Add ALPN parameter */
	if (alpn != NULL) {
		uint8_t alpn_data[DNS_MAX_ALPN_LEN];
		int alpn_data_len = encode_alpn_protos(alpn, alpn_data, sizeof(alpn_data));
		if (alpn_data_len > 0) {
			dns_SVCB_add_alpn(&svcparam_buffer, alpn_data, alpn_data_len);
		}
	}

	/* Add port parameter */
	if (port > 0) {
		dns_SVCB_add_port(&svcparam_buffer, port);
	}

	/* Add IPv4 hint */
	if (ipv4_num > 0 && ipv4_addr != NULL) {
		unsigned char *ip_addr[1] = {ipv4_addr};
		dns_SVCB_add_ipv4hint(&svcparam_buffer, ip_addr, ipv4_num);
	}

	/* Add IPv6 hint */
	if (ipv6_num > 0 && ipv6_addr != NULL) {
		unsigned char *ip_addr[1] = {ipv6_addr};
		dns_SVCB_add_ipv6hint(&svcparam_buffer, ip_addr, ipv6_num);
	}

	dns_add_SVCB_end(&svcparam_buffer);
	return 0;
}

int _dns_server_process_DDR(struct dns_request *request)
{
	struct dns_server_post_context context;
	int ret = 0;
	int added_svcb = 0;
	int ttl = request->ip_ttl;

	_dns_server_post_context_init(&context, request);
	context.do_reply = 1;

	/* Initialize DNS response head */
	struct dns_head head;
	memset(&head, 0, sizeof(head));
	head.id = request->id;
	head.qr = DNS_QR_ANSWER;
	head.opcode = DNS_OP_QUERY;
	head.aa = 0;
	head.rd = 0;
	head.ra = 1;
	head.rcode = DNS_RC_NOERROR;

	/* Initialize DNS packet */
	ret = dns_packet_init(context.packet, context.packet_maxlen, &head);
	if (ret != 0) {
		return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
	}

	/* Add request domain */
	ret = dns_add_domain(context.packet, request->domain, request->qtype, request->qclass);
	if (ret != 0) {
		return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
	}

	/* Set default TTL if not set */
	if (ttl <= 0) {
		ttl = 60;
	}

	/* Get local address for IP hints */
	struct sockaddr_storage *local_addr = (struct sockaddr_storage *)dns_server_request_get_local_addr(request);

	/* Iterate through all bind IPs and create SVCB records for DDR-enabled bindings */
	int priority = 1;
	for (int i = 0; i < dns_conf.bind_ip_num; i++) {
		struct dns_bind_ip *bind_ip = &dns_conf.bind_ip[i];
		const char *alpn = NULL;
		int port = 0;
		char ip[DNS_MAX_IPLEN];
		unsigned char ipv4_addr[DNS_RR_A_LEN];
		int ipv4_num = 0;
		unsigned char ipv6_addr[DNS_RR_AAAA_LEN];
		int ipv6_num = 0;

		/* Skip if DDR is not enabled for this binding */
		if ((bind_ip->flags & BIND_FLAG_DDR) == 0) {
			continue;
		}

		/* Determine ALPN */
		alpn = _ddr_get_alpn(bind_ip);
		if (alpn == NULL) {
			continue;
		}

		/* Extract port from IP string */
		if (parse_ip(bind_ip->ip, ip, &port) != 0) {
			continue;
		}

		/* Extract local addresses for IP hints */
		_ddr_extract_local_addresses(local_addr, ipv4_addr, &ipv4_num, ipv6_addr, &ipv6_num);

		/* Build SVCB record */
		ret = _ddr_build_svcb_record(context.packet, request->domain, ttl, priority, alpn, port, ipv4_addr, ipv4_num,
									 ipv6_addr, ipv6_num);
		if (ret == 0) {
			added_svcb++;
			priority++;
		}
	}

	/* If no SVCB records were added, return SOA */
	if (added_svcb == 0) {
		return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
	}

	/* Encode to binary data */
	int encode_len = dns_encode(context.inpacket, context.inpacket_maxlen, context.packet);
	if (encode_len <= 0) {
		return _dns_server_reply_SOA(DNS_RC_NOERROR, request);
	}

	context.inpacket_len = encode_len;
	context.do_cache = 0;
	context.do_ipset = 0;
	_dns_server_reply_passthrough(&context);
	return 0;
}
