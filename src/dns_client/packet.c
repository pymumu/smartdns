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

#include "packet.h"

#include "smartdns/util.h"

int _dns_client_setup_server_packet(struct dns_server_info *server_info, struct dns_query_struct *query,
									void *default_packet, int default_packet_len, unsigned char *packet_data_buffer,
									void **packet_data, int *packet_data_len)
{
	unsigned char packet_buff[DNS_PACKSIZE];
	struct dns_packet *packet = (struct dns_packet *)packet_buff;
	struct dns_head head;
	int encode_len = 0;
	int repack = 0;
	int hitchhiking = 0;

	*packet_data = default_packet;
	*packet_data_len = default_packet_len;

	if (server_info->ecs_ipv4.enable == true || server_info->ecs_ipv6.enable == true) {
		repack = 1;
	}

	if ((server_info->flags.server_flag & SERVER_FLAG_HITCHHIKING) != 0) {
		hitchhiking = 1;
		repack = 1;
	}

	if (repack == 0) {
		/* no need to encode packet */
		return 0;
	}

	/* init dns packet head */
	memset(&head, 0, sizeof(head));
	head.id = query->sid;
	head.qr = DNS_QR_QUERY;
	head.opcode = DNS_OP_QUERY;
	head.aa = 0;
	head.rd = 1;
	head.ra = 0;
	head.ad = query->edns0_do;
	head.rcode = 0;

	if (dns_packet_init(packet, DNS_PACKSIZE, &head) != 0) {
		tlog(TLOG_ERROR, "init packet failed.");
		return -1;
	}

	if (hitchhiking != 0 && dns_add_domain(packet, "-", query->qtype, DNS_C_IN) != 0) {
		tlog(TLOG_ERROR, "add domain to packet failed.");
		return -1;
	}

	/* add question */
	if (dns_add_domain(packet, query->domain, query->qtype, DNS_C_IN) != 0) {
		tlog(TLOG_ERROR, "add domain to packet failed.");
		return -1;
	}

	dns_set_OPT_payload_size(packet, DNS_IN_PACKSIZE);
	if (query->edns0_do) {
		dns_set_OPT_option(packet, DNS_OPT_FLAG_DO);
	}

	if (server_info->flags.tcp_keepalive > 0) {
		dns_add_OPT_TCP_KEEPALIVE(packet, server_info->flags.tcp_keepalive);
	}

	if ((query->qtype == DNS_T_A && server_info->ecs_ipv4.enable)) {
		dns_add_OPT_ECS(packet, &server_info->ecs_ipv4.ecs);
	} else if ((query->qtype == DNS_T_AAAA && server_info->ecs_ipv6.enable)) {
		dns_add_OPT_ECS(packet, &server_info->ecs_ipv6.ecs);
	} else if (query->qtype == DNS_T_AAAA || query->qtype == DNS_T_A || server_info->flags.subnet_all_query_types) {
		if (server_info->ecs_ipv6.enable) {
			dns_add_OPT_ECS(packet, &server_info->ecs_ipv6.ecs);
		} else if (server_info->ecs_ipv4.enable) {
			dns_add_OPT_ECS(packet, &server_info->ecs_ipv4.ecs);
		}
	}

	/* encode packet */
	encode_len = dns_encode(packet_data_buffer, DNS_IN_PACKSIZE, packet);
	if (encode_len <= 0) {
		tlog(TLOG_ERROR, "encode query failed.");
		return -1;
	}

	if (encode_len > DNS_IN_PACKSIZE) {
		BUG("size is invalid.");
		return -1;
	}

	*packet_data = packet_data_buffer;
	*packet_data_len = encode_len;

	return 0;
}
