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

#include "smartdns/util.h"

#include "notify_event.h"
#include "ping_host.h"
#include "ping_icmp.h"
#include "ping_tcp_syn.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

/* TCP/IP header structures */
struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
} __attribute__((packed));

struct pseudo_header6 {
	struct in6_addr source_address;
	struct in6_addr dest_address;
	uint32_t tcp_length;
	uint8_t zeros[3];
	uint8_t next_header;
} __attribute__((packed));

struct tcp_syn_packet {
	struct tcphdr tcp;
	uint32_t data; /* Store sid for packet identification */
} __attribute__((packed));

/* Get local IP address based on destination address and routing table */
static int _tcp_syn_get_local_addr(int family, struct sockaddr *dest, struct sockaddr_storage *local)
{
	int sock = -1;
	socklen_t addr_len;
	int ret = -1;

	sock = socket(family, SOCK_DGRAM, 0);
	if (sock < 0) {
		return -1;
	}

	addr_len = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

	getsocket_inet(sock, (struct sockaddr *)local, &addr_len);
	/* Connect to determine which local interface will be used */
	if (connect(sock, dest, addr_len) != 0) {
		goto cleanup;
	}

	if (getsocket_inet(sock, (struct sockaddr *)local, &addr_len) != 0) {
		goto cleanup;
	}

	ret = 0;

cleanup:
	close(sock);
	return ret;
}

/* Reserve a TCP port by binding a SOCK_STREAM socket */
static int _tcp_syn_reserve_port(int family, int *out_fd, uint16_t *out_port, struct sockaddr_storage *out_addr)
{
	int sock = -1;
	socklen_t addr_len;
	struct sockaddr_storage bind_addr;

	memset(&bind_addr, 0, sizeof(bind_addr));

	sock = socket(family, SOCK_STREAM, 0);
	if (sock < 0) {
		tlog(TLOG_ERROR, "create TCP socket for port reservation failed, %s", strerror(errno));
		return -1;
	}

	/* Bind to any address with port 0 (kernel will assign an available port) */
	if (family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)&bind_addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = INADDR_ANY;
		addr_in->sin_port = 0;
		addr_len = sizeof(struct sockaddr_in);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&bind_addr;
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_addr = in6addr_any;
		addr_in6->sin6_port = 0;
		addr_len = sizeof(struct sockaddr_in6);
	} else {
		close(sock);
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&bind_addr, addr_len) < 0) {
		tlog(TLOG_ERROR, "bind socket for port reservation failed, %s", strerror(errno));
		close(sock);
		return -1;
	}

	/* Retrieve the assigned port */
	if (getsockname(sock, (struct sockaddr *)&bind_addr, &addr_len) != 0) {
		tlog(TLOG_ERROR, "getsockname failed, %s", strerror(errno));
		close(sock);
		return -1;
	}

	/* Extract port number */
	if (family == AF_INET) {
		*out_port = ntohs(((struct sockaddr_in *)&bind_addr)->sin_port);
	} else {
		*out_port = ntohs(((struct sockaddr_in6 *)&bind_addr)->sin6_port);
	}

	*out_fd = sock;
	memcpy(out_addr, &bind_addr, addr_len);

	return 0;
}
/* Install BPF filter for IPv4 to reduce unwanted TCP packets */
static int _tcp_syn_install_bpf_ipv4(int fd, uint16_t port)
{
	/* Filter logic (same pattern as ICMP):
	 * Accept packets where TCP destination port == our port
	 * This filters out most unwanted TCP traffic
	 */
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),          /* X = IP header length */
		BPF_STMT(BPF_LD | BPF_H | BPF_IND, 2),           /* A = TCP dst port at [X+2] */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1), /* if (A == port) skip 0 else skip 1 */
		BPF_STMT(BPF_RET | BPF_K, ~0U),                  /* accept: return -1 (pass) */
		BPF_STMT(BPF_RET | BPF_K, 0)                     /* reject: return 0 (drop) */
	};

	struct sock_fprog filter = {sizeof insns / sizeof(insns[0]), insns};

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
		tlog(TLOG_WARN, "WARNING: failed to install TCP SYN socket filter: %s", strerror(errno));
		return -1;
	}

	return 0;
}

/* Install BPF filter for IPv6 to reduce unwanted TCP packets */
static int _tcp_syn_install_bpf_ipv6(int fd, uint16_t port)
{
	/* Filter logic (same pattern as ICMP6):
	 * Accept packets where TCP destination port == our port
	 * IPv6 raw sockets don't include IP header, so use BPF_ABS mode
	 */
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 2),           /* A = TCP dst port at offset 2 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1), /* if (A == port) skip 0 else skip 1 */
		BPF_STMT(BPF_RET | BPF_K, ~0U),                  /* accept: return -1 (pass) */
		BPF_STMT(BPF_RET | BPF_K, 0),                    /* reject: return 0 (drop) */
	};

	struct sock_fprog filter = {sizeof insns / sizeof(insns[0]), insns};

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0) {
		tlog(TLOG_WARN, "ERROR: failed to install TCP SYN IPv6 socket filter: %s", strerror(errno));
		return -1;
	}

	return 0;
}

/* Build and send IPv4 RST packet */
static int _tcp_syn_send_rst_ipv4(struct ping_host_struct *ping_host, struct sockaddr_storage *local_addr, uint32_t seq,
								  uint32_t ack_seq)
{
	char packet[4096];
	struct tcphdr *tcp_packet;
	int packet_len;
	char *pseudo_packet = NULL;
	int ret = -1;

	/* Verify address family */
	if (local_addr->ss_family != AF_INET) {
		return -1;
	}

	struct iphdr *ip = (struct iphdr *)packet;
	struct sockaddr_in *local_in = (struct sockaddr_in *)local_addr;
	struct sockaddr_in *dest_in = (struct sockaddr_in *)&ping_host->addr;

	memset(packet, 0, sizeof(packet));
	tcp_packet = (struct tcphdr *)(packet + sizeof(struct iphdr));
	packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr); /* RST packet should only contain TCP header, no data */

	/* Fill IP header */
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(packet_len);
	ip->id = htons(ping_host->sid);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = local_in->sin_addr.s_addr;
	ip->daddr = dest_in->sin_addr.s_addr;
	ip->check = _fast_ping_checksum((uint16_t *)packet, sizeof(struct iphdr));

	/* Fill TCP header */
	tcp_packet->source = htons(ping_host->tcp_local_port); /* Use the same source port as SYN packet */
	tcp_packet->dest = dest_in->sin_port;
	tcp_packet->seq = htonl(seq);
	tcp_packet->ack_seq = htonl(ack_seq);
	tcp_packet->doff = 5;
	tcp_packet->rst = 1;
	tcp_packet->ack = 1;
	tcp_packet->window = 0;
	tcp_packet->check = 0;
	tcp_packet->urg_ptr = 0;

	/* Calculate TCP checksum with pseudo header */
	pseudo_packet = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr));
	if (pseudo_packet == NULL) {
		goto errout;
	}

	memset(pseudo_packet, 0, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
	struct pseudo_header *psh = (struct pseudo_header *)pseudo_packet;
	psh->source_address = local_in->sin_addr.s_addr;
	psh->dest_address = dest_in->sin_addr.s_addr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(sizeof(struct tcphdr));

	memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp_packet, sizeof(struct tcphdr));

	tcp_packet->check =
		_fast_ping_checksum((uint16_t *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

	if (sendto(ping.fd_tcp_syn, packet, packet_len, 0, &ping_host->addr, ping_host->addr_len) < 0) {
		tlog(TLOG_DEBUG, "send IPv4 RST packet failed, %s", strerror(errno));
		goto errout;
	}

	ret = 0;

errout:
	if (pseudo_packet) {
		free(pseudo_packet);
	}
	return ret;
}

/* Build and send IPv6 RST packet */
static int _tcp_syn_send_rst_ipv6(struct ping_host_struct *ping_host, struct sockaddr_storage *local_addr, uint32_t seq,
								  uint32_t ack_seq)
{
	char packet[4096];
	struct tcphdr *tcp_packet;
	int packet_len;
	char *pseudo_packet = NULL;
	int ret = -1;

	/* Verify address family */
	if (local_addr->ss_family != AF_INET6) {
		return -1;
	}

	struct sockaddr_in6 *local_in6 = (struct sockaddr_in6 *)local_addr;
	struct sockaddr_in6 *dest_in6 = (struct sockaddr_in6 *)&ping_host->addr;

	memset(packet, 0, sizeof(packet));
	tcp_packet = (struct tcphdr *)packet;
	packet_len = sizeof(struct tcphdr); /* RST packet should only contain TCP header, no data */

	/* Fill TCP header */
	tcp_packet->source = htons(ping_host->tcp_local_port); /* Use the same source port as SYN packet */
	tcp_packet->dest = dest_in6->sin6_port;
	tcp_packet->seq = htonl(seq);
	tcp_packet->ack_seq = htonl(ack_seq);
	tcp_packet->doff = 5;
	tcp_packet->rst = 1;
	tcp_packet->ack = 1;
	tcp_packet->window = 0;
	tcp_packet->check = 0;
	tcp_packet->urg_ptr = 0;

	/* Calculate TCP checksum with pseudo header */
	pseudo_packet = malloc(sizeof(struct pseudo_header6) + sizeof(struct tcphdr));
	if (pseudo_packet == NULL) {
		goto errout;
	}

	struct pseudo_header6 *psh6 = (struct pseudo_header6 *)pseudo_packet;
	memcpy(&psh6->source_address, &local_in6->sin6_addr, sizeof(struct in6_addr));
	memcpy(&psh6->dest_address, &dest_in6->sin6_addr, sizeof(struct in6_addr));
	psh6->tcp_length = htonl(sizeof(struct tcphdr));
	memset(psh6->zeros, 0, 3);
	psh6->next_header = IPPROTO_TCP;

	memcpy(pseudo_packet + sizeof(struct pseudo_header6), tcp_packet, sizeof(struct tcphdr));

	tcp_packet->check =
		_fast_ping_checksum((uint16_t *)pseudo_packet, sizeof(struct pseudo_header6) + sizeof(struct tcphdr));

	/* For IPv6 raw TCP socket, sin6_port must be 0 */
	struct sockaddr_storage dest_addr;
	memcpy(&dest_addr, &ping_host->addr, ping_host->addr_len);
	((struct sockaddr_in6 *)&dest_addr)->sin6_port = 0;

	if (sendto(ping.fd_tcp_syn6, packet, packet_len, 0, (struct sockaddr *)&dest_addr, ping_host->addr_len) < 0) {
		tlog(TLOG_DEBUG, "send IPv6 RST packet failed, %s", strerror(errno));
		goto errout;
	}

	ret = 0;

errout:
	if (pseudo_packet) {
		free(pseudo_packet);
	}
	return ret;
}

/* Send RST packet to close connection */
__attribute__((unused)) static int _tcp_syn_send_rst(struct ping_host_struct *ping_host, uint32_t seq, uint32_t ack_seq)
{
	struct sockaddr_storage local_addr;

	memset(&local_addr, 0, sizeof(local_addr));
	if (_tcp_syn_get_local_addr(ping_host->ss_family, &ping_host->addr, &local_addr) != 0) {
		return -1;
	}

	if (ping_host->ss_family == AF_INET) {
		return _tcp_syn_send_rst_ipv4(ping_host, &local_addr, seq, ack_seq);
	} else if (ping_host->ss_family == AF_INET6) {
		return _tcp_syn_send_rst_ipv6(ping_host, &local_addr, seq, ack_seq);
	}

	return -1;
}

/* Build IPv4 SYN packet */
static int _tcp_syn_build_packet_ipv4(char *packet, struct ping_host_struct *ping_host,
									  struct sockaddr_storage *local_addr, uint16_t local_port, uint32_t seq_num)
{
	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcph;
	struct sockaddr_in *local_in = (struct sockaddr_in *)local_addr;
	struct sockaddr_in *dest_in = (struct sockaddr_in *)&ping_host->addr;
	char *pseudo_packet = NULL;
	int packet_len;
	int ret = -1;

	tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

	/* Fill IP header */
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(packet_len);
	ip->id = htons(ping_host->sid);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->saddr = local_in->sin_addr.s_addr;
	ip->daddr = dest_in->sin_addr.s_addr;
	ip->check = _fast_ping_checksum((uint16_t *)packet, sizeof(struct iphdr));

	/* Fill TCP header - use reserved port */
	memset(tcph, 0, sizeof(struct tcphdr));
	tcph->source = htons(local_port);
	tcph->dest = dest_in->sin_port;
	tcph->seq = htonl(seq_num);
	tcph->ack_seq = htonl(0);
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(65535);
	tcph->check = 0;
	tcph->urg_ptr = htons(0);

	/* Calculate TCP checksum with pseudo header */
	pseudo_packet = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr));
	if (pseudo_packet == NULL) {
		goto errout;
	}

	struct pseudo_header *psh = (struct pseudo_header *)pseudo_packet;
	memset(psh, 0, sizeof(struct pseudo_header));
	psh->source_address = local_in->sin_addr.s_addr;
	psh->dest_address = dest_in->sin_addr.s_addr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(sizeof(struct tcphdr));

	tcph->check = 0;
	memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

	tcph->check = _fast_ping_checksum((uint16_t *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

	ret = packet_len;

errout:
	if (pseudo_packet) {
		free(pseudo_packet);
	}
	return ret;
}

/* Build IPv6 SYN packet */
static int _tcp_syn_build_packet_ipv6(char *packet, struct ping_host_struct *ping_host,
									  struct sockaddr_storage *local_addr, uint16_t local_port, uint32_t seq_num)
{
	struct tcphdr *tcph;
	struct sockaddr_in6 *local_in6 = (struct sockaddr_in6 *)local_addr;
	struct sockaddr_in6 *dest_in6 = (struct sockaddr_in6 *)&ping_host->addr;
	char *pseudo_packet = NULL;
	int packet_len;
	int ret = -1;

	tcph = (struct tcphdr *)packet;
	packet_len = sizeof(struct tcphdr);

	memset(tcph, 0, sizeof(struct tcphdr));
	tcph->source = htons(local_port);
	tcph->dest = dest_in6->sin6_port;
	tcph->seq = htonl(seq_num);
	tcph->ack_seq = 0;
	tcph->doff = 5; /* TCP header length: 5 * 4 = 20 bytes */
	tcph->syn = 1;
	tcph->window = htons(8192);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	/* Calculate TCP checksum with pseudo header */
	pseudo_packet = malloc(sizeof(struct pseudo_header6) + sizeof(struct tcphdr));
	if (pseudo_packet == NULL) {
		goto errout;
	}

	struct pseudo_header6 *psh6 = (struct pseudo_header6 *)pseudo_packet;
	memcpy(&psh6->source_address, &local_in6->sin6_addr, sizeof(struct in6_addr));
	memcpy(&psh6->dest_address, &dest_in6->sin6_addr, sizeof(struct in6_addr));
	psh6->tcp_length = htonl(sizeof(struct tcphdr));
	memset(psh6->zeros, 0, 3);
	psh6->next_header = IPPROTO_TCP;

	memcpy(pseudo_packet + sizeof(struct pseudo_header6), tcph, sizeof(struct tcphdr));

	tcph->check = _fast_ping_checksum((uint16_t *)pseudo_packet, sizeof(struct pseudo_header6) + sizeof(struct tcphdr));

	ret = packet_len;

errout:
	if (pseudo_packet) {
		free(pseudo_packet);
	}
	return ret;
}

int _fast_ping_sendping_tcp_syn(struct ping_host_struct *ping_host)
{
	char packet[4096];
	int packet_len = 0;
	int fd = -1;
	struct sockaddr_storage local_addr;
	uint32_t seq_num = 0;
	uint16_t local_port = 0;

	/* Create socket on first use */
	if (_fast_ping_tcp_syn_create_socket(ping_host) < 0) {
		return -1;
	}

	memset(&local_addr, 0, sizeof(local_addr));
	if (_tcp_syn_get_local_addr(ping_host->ss_family, &ping_host->addr, &local_addr) != 0) {
		return -1;
	}

	/* Use the reserved port instead of getting a new one each time */
	if (ping_host->ss_family == AF_INET) {
		if (ping.tcp_syn_bind_port == 0) {
			tlog(TLOG_ERROR, "TCP SYN bind port not initialized");
			return -1;
		}
		local_port = ping.tcp_syn_bind_port;
		ping_host->tcp_local_port = local_port;
		fd = ping.fd_tcp_syn;
	} else if (ping_host->ss_family == AF_INET6) {
		if (ping.tcp_syn6_bind_port == 0) {
			tlog(TLOG_ERROR, "TCP SYN IPv6 bind port not initialized");
			return -1;
		}
		local_port = ping.tcp_syn6_bind_port;
		ping_host->tcp_local_port = local_port;
		fd = ping.fd_tcp_syn6;
	} else {
		return -1;
	}

	memset(packet, 0, sizeof(packet));

	/* Generate sequence number: combine sid and timestamp for uniqueness */
	seq_num = (ping_host->sid << 16) | (get_tick_count() & 0xFFFF);
	ping_host->seq++;

	/* Build packet based on address family */
	if (ping_host->ss_family == AF_INET) {
		packet_len = _tcp_syn_build_packet_ipv4(packet, ping_host, &local_addr, local_port, seq_num);
	} else if (ping_host->ss_family == AF_INET6) {
		packet_len = _tcp_syn_build_packet_ipv6(packet, ping_host, &local_addr, local_port, seq_num);
	} else {
		return -1;
	}

	if (packet_len < 0 || fd < 0) {
		return -1;
	}

	/* Send SYN packet */
	gettimeofday(&ping_host->last, NULL);
	struct sockaddr_storage dest_addr;
	memcpy(&dest_addr, &ping_host->addr, ping_host->addr_len);

	if (ping_host->ss_family == AF_INET6) {
		struct sockaddr_in6 *dest_in6 = (struct sockaddr_in6 *)&dest_addr;
		dest_in6->sin6_port = 0; /* Must be 0 for raw TCP socket */
	}

	ssize_t len = sendto(fd, packet, packet_len, 0, (struct sockaddr *)&dest_addr, ping_host->addr_len);
	if (len < 0) {
		tlog(TLOG_DEBUG, "send SYN packet failed, %s", strerror(errno));
		return -1;
	}

	return 0;
}

int _fast_ping_get_addr_by_tcp_syn(const char *ip_str, int port, struct addrinfo **out_gai,
								   FAST_PING_TYPE *out_ping_type)
{
	struct addrinfo *gai = NULL;
	char port_str[MAX_IP_LEN];

	if (port <= 0) {
		port = 80;
	}

	snprintf(port_str, sizeof(port_str), "%d", port);

	gai = _fast_ping_getaddr(ip_str, port_str, SOCK_STREAM, 0);
	if (gai == NULL) {
		return -1;
	}

	*out_gai = gai;
	*out_ping_type = FAST_PING_TCP_SYN;

	return 0;
}

int _fast_ping_process_tcp_syn(struct ping_host_struct *ping_host, struct timeval *now)
{
	char packet[4096];
	struct sockaddr_storage from_addr;
	socklen_t from_len = sizeof(from_addr);
	int fd = -1;
	ssize_t recv_len = 0;
	struct ping_host_struct *recv_ping_host = NULL;

	/* Determine which socket received data */
	if (ping_host->type == FAST_PING_TCP_SYN && ping_host->fd == ping.fd_tcp_syn) {
		fd = ping.fd_tcp_syn;
	} else if (ping_host->type == FAST_PING_TCP_SYN && ping_host->fd == ping.fd_tcp_syn6) {
		fd = ping.fd_tcp_syn6;
	} else {
		return 0;
	}

	if (fd < 0) {
		return -1;
	}

	/* Receive all available packets */
	while (1) {
		memset(packet, 0, sizeof(packet));
		from_len = sizeof(from_addr);
		recv_len = recvfrom(fd, packet, sizeof(packet), MSG_DONTWAIT, (struct sockaddr *)&from_addr, &from_len);
		if (recv_len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}
			tlog(TLOG_DEBUG, "recvfrom error: %s", strerror(errno));
			return -1;
		}

		/* Parse packet based on socket type */
		struct tcphdr *tcp = NULL;

		/* For IPv4 raw socket, packet includes IP header */
		if (fd == ping.fd_tcp_syn) {
			if (recv_len < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
				continue;
			}
			struct iphdr *ip = (struct iphdr *)packet;

			/* Validate IP header length */
			if (ip->ihl < 5 || ip->ihl > 15) {
				continue;
			}

			/* Ensure we have enough data for the full IP header */
			size_t ip_header_len = ip->ihl * 4;
			if (recv_len < (ssize_t)(ip_header_len + sizeof(struct tcphdr))) {
				continue;
			}

			tcp = (struct tcphdr *)(packet + ip_header_len);

			/* Extract source address from IP header */
			struct sockaddr_in *from_in = (struct sockaddr_in *)&from_addr;
			from_in->sin_family = AF_INET;
			from_in->sin_addr.s_addr = ip->saddr;
		} else if (fd == ping.fd_tcp_syn6) {
			/* For IPv6 raw socket, packet starts with TCP header */
			if (recv_len < (ssize_t)(sizeof(struct tcphdr))) {
				continue;
			}
			tcp = (struct tcphdr *)packet;
		} else {
			continue;
		}

		/* Validate TCP header data offset */
		if (tcp->doff < 5 || tcp->doff > 15) {
			continue;
		}

		/* Ensure we have enough data for the full TCP header */
		size_t tcp_header_len = tcp->doff * 4;
		if (fd == ping.fd_tcp_syn) {
			/* For IPv4, account for IP header */
			size_t ip_header_len = ((struct iphdr *)packet)->ihl * 4;
			if (recv_len < (ssize_t)(ip_header_len + tcp_header_len)) {
				continue;
			}
		} else {
			/* For IPv6 */
			if (recv_len < (ssize_t)tcp_header_len) {
				continue;
			}
		}

		/* Check if SYN-ACK or RST */
		if (!((tcp->syn && tcp->ack) || tcp->rst)) {
			continue;
		}

		/* Extract sid from ack_seq
		 * We sent: seq = (sid << 16) | timestamp
		 * Server responds: ack_seq = our_seq + 1
		 * So: (ack_seq - 1) >> 16 should equal our sid */
		uint32_t received_ack = ntohl(tcp->ack_seq);
		uint16_t received_sid = (received_ack - 1) >> 16;

		/* Calculate hash key using sid and source address */
		uint32_t addrkey = _fast_ping_hash_key(received_sid, (struct sockaddr *)&from_addr);

		/* Find matching ping_host using hash table lookup */
		pthread_mutex_lock(&ping.map_lock);
		recv_ping_host = NULL;
		hash_for_each_possible(ping.addrmap, recv_ping_host, addr_node, addrkey)
		{
			if (recv_ping_host->type != FAST_PING_TCP_SYN) {
				continue;
			}

			/* Verify sid matches */
			if (recv_ping_host->sid != received_sid) {
				continue;
			}

			/* Verify address matches */
			if (_fast_ping_sockaddr_ip_cmp(&recv_ping_host->addr, recv_ping_host->addr_len,
										   (struct sockaddr *)&from_addr, from_len) != 0) {
				continue;
			}

			/* Check if currently sending - skip old entries */
			if (recv_ping_host->send == 0) {
				continue;
			}

			/* Found matching ping_host */
			_fast_ping_host_get(recv_ping_host);
			break;
		}
		pthread_mutex_unlock(&ping.map_lock);

		if (recv_ping_host == NULL) {
			continue;
		}

		/* No need to send RST, the linux kernel will send RST automatically for raw TCP sockets */

		/* Calculate RTT */
		struct timeval tvresult = *now;
		struct timeval *tvsend = &recv_ping_host->last;
		tv_sub(&tvresult, tvsend);

		/* Report success */
		_fast_ping_send_notify_event(recv_ping_host, PING_RESULT_RESPONSE, recv_ping_host->seq, 64, &tvresult);
		recv_ping_host->send = 0;

		if (recv_ping_host->count == 1) {
			/* Remove this ping_host */
			_fast_ping_host_remove(recv_ping_host);
		}

		_fast_ping_host_put(recv_ping_host);
	}

	return 0;
}

/* Create IPv4 TCP SYN raw socket with port reservation and BPF filter */
static int _fast_ping_create_tcp_syn_sock_ipv4(void)
{
	int fd = -1;
	const int on = 1;
	uint16_t bind_port = 0;

	/* Reserve a port for IPv4 TCP SYN ping */
	if (ping.fd_tcp_syn_bind <= 0) {
		if (_tcp_syn_reserve_port(AF_INET, &ping.fd_tcp_syn_bind, &ping.tcp_syn_bind_port,
								  (struct sockaddr_storage *)&ping.tcp_syn_bind_addr) != 0) {
			tlog(TLOG_ERROR, "failed to reserve IPv4 port for TCP SYN");
			goto errout;
		}
	}
	bind_port = ping.tcp_syn_bind_port;

	/* Create IPv4 raw socket */
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			tlog(TLOG_DEBUG, "create TCP SYN raw socket failed, %s (need root or CAP_NET_RAW capability)",
				 strerror(errno));
		} else {
			tlog(TLOG_ERROR, "create TCP SYN raw socket failed, %s", strerror(errno));
		}
		goto errout;
	}

	/* Set socket options */
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		tlog(TLOG_ERROR, "setsockopt IP_HDRINCL failed, %s", strerror(errno));
		goto errout;
	}

	/* Install BPF filter */
	_tcp_syn_install_bpf_ipv4(fd, bind_port);

	/* Set non-blocking */
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		tlog(TLOG_ERROR, "fcntl set non-blocking failed, %s", strerror(errno));
		goto errout;
	}

	return fd;

errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

/* Create IPv6 TCP SYN raw socket with port reservation and BPF filter */
static int _fast_ping_create_tcp_syn_sock_ipv6(void)
{
	int fd = -1;
	uint16_t bind_port = 0;

	/* Reserve a port for IPv6 TCP SYN ping */
	if (ping.fd_tcp_syn6_bind <= 0) {
		if (_tcp_syn_reserve_port(AF_INET6, &ping.fd_tcp_syn6_bind, &ping.tcp_syn6_bind_port,
								  (struct sockaddr_storage *)&ping.tcp_syn6_bind_addr) != 0) {
			tlog(TLOG_ERROR, "failed to reserve IPv6 port for TCP SYN");
			goto errout;
		}
	}
	bind_port = ping.tcp_syn6_bind_port;

	/* Create IPv6 raw socket */
	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
	if (fd < 0) {
		if (errno != EAFNOSUPPORT) {
			tlog(TLOG_DEBUG, "create TCP SYN IPv6 raw socket failed, %s", strerror(errno));
		}
		goto errout;
	}

	/* Install BPF filter */
	_tcp_syn_install_bpf_ipv6(fd, bind_port);

	/* Set non-blocking */
	if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		tlog(TLOG_ERROR, "fcntl set non-blocking failed, %s", strerror(errno));
		goto errout;
	}

	return fd;

errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

static int _fast_ping_create_tcp_syn_sock(FAST_PING_TYPE type)
{
	int fd = -1;
	struct epoll_event event;
	struct ping_host_struct *tcp_syn_host = NULL;
	int is_ipv6 = 0;

	/* FAST_PING_END is used internally to indicate IPv6 */
	if (type == FAST_PING_END) {
		is_ipv6 = 1;
		type = FAST_PING_TCP_SYN;
	}

	if (!is_ipv6) {
		fd = _fast_ping_create_tcp_syn_sock_ipv4();
		if (fd < 0) {
			goto errout;
		}
		tcp_syn_host = &ping.tcp_syn_host;
	} else {
		fd = _fast_ping_create_tcp_syn_sock_ipv6();
		if (fd < 0) {
			goto errout;
		}
		tcp_syn_host = &ping.tcp_syn6_host;
	}

	/* Add to epoll */
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = tcp_syn_host;
	if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
		tlog(TLOG_ERROR, "add TCP SYN socket to epoll failed, %s", strerror(errno));
		goto errout;
	}

	tcp_syn_host->fd = fd;
	tcp_syn_host->type = type;

	return fd;

errout:
	if (fd > 0) {
		close(fd);
	}
	if (tcp_syn_host) {
		tcp_syn_host->fd = -1;
		tcp_syn_host->type = 0;
	}
	return -1;
}

static int _fast_ping_create_tcp_syn(FAST_PING_TYPE type)
{
	int fd = -1;
	int *set_fd = NULL;

	pthread_mutex_lock(&ping.lock);

	if (type == FAST_PING_TCP_SYN) {
		set_fd = &ping.fd_tcp_syn;
	} else {
		/* IPv6 */
		set_fd = &ping.fd_tcp_syn6;
	}

	if (*set_fd > 0) {
		goto out;
	}

	fd = _fast_ping_create_tcp_syn_sock(type);
	if (fd < 0) {
		goto errout;
	}

	*set_fd = fd;
out:
	pthread_mutex_unlock(&ping.lock);
	return *set_fd;
errout:
	if (fd > 0) {
		close(fd);
	}
	pthread_mutex_unlock(&ping.lock);
	return -1;
}

int _fast_ping_tcp_syn_create_socket(struct ping_host_struct *ping_host)
{
	FAST_PING_TYPE type = ping_host->type;

	if (type != FAST_PING_TCP_SYN) {
		goto errout;
	}

	/* Determine IPv4 or IPv6 based on address family */
	if (ping_host->ss_family == AF_INET) {
		if (_fast_ping_create_tcp_syn(FAST_PING_TCP_SYN) < 0) {
			goto errout;
		}
		if (ping.fd_tcp_syn <= 0) {
			errno = EADDRNOTAVAIL;
			goto errout;
		}
	} else if (ping_host->ss_family == AF_INET6) {
		/* For IPv6, we need to create a separate socket */
		/* Use a special internal type indicator */
		pthread_mutex_lock(&ping.lock);
		if (ping.fd_tcp_syn6 <= 0) {
			/* Pass FAST_PING_END as indicator for IPv6 */
			int fd = _fast_ping_create_tcp_syn_sock(FAST_PING_END);
			if (fd > 0) {
				ping.fd_tcp_syn6 = fd;
			}
		}
		pthread_mutex_unlock(&ping.lock);

		if (ping.fd_tcp_syn6 <= 0) {
			errno = EADDRNOTAVAIL;
			goto errout;
		}
	} else {
		goto errout;
	}

	return 0;
errout:
	return -1;
}

void _fast_ping_close_tcp_syn(void)
{
	if (ping.fd_tcp_syn > 0) {
		close(ping.fd_tcp_syn);
		ping.fd_tcp_syn = -1;
	}

	if (ping.fd_tcp_syn6 > 0) {
		close(ping.fd_tcp_syn6);
		ping.fd_tcp_syn6 = -1;
	}

	/* Close bind sockets */
	if (ping.fd_tcp_syn_bind > 0) {
		close(ping.fd_tcp_syn_bind);
		ping.fd_tcp_syn_bind = -1;
		ping.tcp_syn_bind_port = 0;
	}

	if (ping.fd_tcp_syn6_bind > 0) {
		close(ping.fd_tcp_syn6_bind);
		ping.fd_tcp_syn6_bind = -1;
		ping.tcp_syn6_bind_port = 0;
	}
}
