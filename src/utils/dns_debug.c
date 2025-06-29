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

#include "smartdns/dns.h"
#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BUFF_SZ 1024
#define PACKET_BUF_SIZE 8192
#define PACKET_MAGIC 0X11040918

int write_file(const char *filename, void *data, int data_len)
{
	int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0644);
	if (fd < 0) {
		return -1;
	}

	int len = write(fd, data, data_len);
	if (len < 0) {
		goto errout;
	}

	close(fd);
	return 0;
errout:
	if (fd > 0) {
		close(fd);
	}

	return -1;
}

int dns_packet_save(const char *dir, const char *type, const char *from, const void *packet, int packet_len)
{
	char *data = NULL;
	int data_len = 0;
	char filename[BUFF_SZ];
	char time_s[BUFF_SZ];
	int ret = -1;

	struct tm *ptm;
	struct tm tm;
	struct timeval tm_val;
	struct stat sb;

	if (stat(dir, &sb) != 0) {
		mkdir(dir, 0750);
	}

	if (gettimeofday(&tm_val, NULL) != 0) {
		return -1;
	}

	ptm = localtime_r(&tm_val.tv_sec, &tm);
	if (ptm == NULL) {
		return -1;
	}

	snprintf(time_s, sizeof(time_s) - 1, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d.%.3d", ptm->tm_year + 1900, ptm->tm_mon + 1,
			 ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec, (int)(tm_val.tv_usec / 1000));
	snprintf(filename, sizeof(filename) - 1, "%s/%s-%.4d%.2d%.2d-%.2d%.2d%.2d%.3d.packet", dir, type,
			 ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec,
			 (int)(tm_val.tv_usec / 1000));

	data = malloc(PACKET_BUF_SIZE);
	if (data == NULL) {
		return -1;
	}

	data_len = snprintf(data, PACKET_BUF_SIZE,
						"type: %s\n"
						"from: %s\n"
						"time: %s\n"
						"packet-len: %d\n",
						type, from, time_s, packet_len);
	if (data_len <= 0 || data_len >= PACKET_BUF_SIZE) {
		goto out;
	}

	data[data_len] = 0;
	data_len++;
	uint32_t magic = htonl(PACKET_MAGIC);
	memcpy(data + data_len, &magic, sizeof(magic));
	data_len += sizeof(magic);
	int len_in_h = htonl(packet_len);
	memcpy(data + data_len, &len_in_h, sizeof(len_in_h));
	data_len += 4;
	memcpy(data + data_len, packet, packet_len);
	data_len += packet_len;

	ret = write_file(filename, data, data_len);
	if (ret != 0) {
		goto out;
	}

	ret = 0;
out:
	if (data) {
		free(data);
	}

	return ret;
}

#if defined(DEBUG) || defined(TEST)
struct _dns_read_packet_info {
	int data_len;
	int message_len;
	char *message;
	int packet_len;
	uint8_t *packet;
	uint8_t data[0];
};

static struct _dns_read_packet_info *_dns_read_packet_file(const char *packet_file)
{
	struct _dns_read_packet_info *info = NULL;
	int fd = -1;
	int len = 0;
	int message_len = 0;
	uint8_t *ptr = NULL;

	info = malloc(sizeof(struct _dns_read_packet_info) + PACKET_BUF_SIZE);
	fd = open(packet_file, O_RDONLY);
	if (fd < 0) {
		printf("open file %s failed, %s\n", packet_file, strerror(errno));
		goto errout;
	}

	len = read(fd, info->data, PACKET_BUF_SIZE);
	if (len < 0) {
		printf("read file %s failed, %s\n", packet_file, strerror(errno));
		goto errout;
	}

	message_len = strnlen((char *)info->data, PACKET_BUF_SIZE);
	if (message_len >= 512 || message_len >= len) {
		printf("invalid packet file, bad message len\n");
		goto errout;
	}

	info->message_len = message_len;
	info->message = (char *)info->data;

	ptr = info->data + message_len + 1;
	uint32_t magic = 0;
	if (ptr - (uint8_t *)info + sizeof(magic) >= (size_t)len) {
		printf("invalid packet file, magic length is invalid.\n");
		goto errout;
	}

	memcpy(&magic, ptr, sizeof(magic));
	if (magic != htonl(PACKET_MAGIC)) {
		printf("invalid packet file, bad magic\n");
		goto errout;
	}
	ptr += sizeof(magic);

	uint32_t packet_len = 0;
	if (ptr - info->data + sizeof(packet_len) >= (size_t)len) {
		printf("invalid packet file, packet length is invalid.\n");
		goto errout;
	}

	memcpy(&packet_len, ptr, sizeof(packet_len));
	packet_len = ntohl(packet_len);
	ptr += sizeof(packet_len);
	if (packet_len != (size_t)len - (ptr - info->data)) {
		printf("invalid packet file, packet length is invalid\n");
		goto errout;
	}

	info->packet_len = packet_len;
	info->packet = ptr;

	close(fd);
	return info;
errout:

	if (fd > 0) {
		close(fd);
	}

	if (info) {
		free(info);
	}

	return NULL;
}

static int _dns_debug_display(struct dns_packet *packet)
{
	int i = 0;
	int j = 0;
	int ttl = 0;
	struct dns_rrs *rrs = NULL;
	int rr_count = 0;
	char req_host[MAX_IP_LEN];
	int ret;

	for (j = 1; j < DNS_RRS_OPT; j++) {
		rrs = dns_get_rrs_start(packet, j, &rr_count);
		printf("section: %d\n", j);
		for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
			switch (rrs->type) {
			case DNS_T_A: {
				unsigned char addr[4];
				char name[DNS_MAX_CNAME_LEN] = {0};
				/* get A result */
				dns_get_A(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);
				req_host[0] = '\0';
				inet_ntop(AF_INET, addr, req_host, sizeof(req_host));
				printf("domain: %s A: %s TTL: %d\n", name, req_host, ttl);
			} break;
			case DNS_T_AAAA: {
				unsigned char addr[16];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_AAAA(rrs, name, DNS_MAX_CNAME_LEN, &ttl, addr);
				req_host[0] = '\0';
				inet_ntop(AF_INET6, addr, req_host, sizeof(req_host));
				printf("domain: %s AAAA: %s TTL:%d\n", name, req_host, ttl);
			} break;
			case DNS_T_SRV: {
				unsigned short priority = 0;
				unsigned short weight = 0;
				unsigned short port = 0;

				char name[DNS_MAX_CNAME_LEN] = {0};
				char target[DNS_MAX_CNAME_LEN];

				ret = dns_get_SRV(rrs, name, DNS_MAX_CNAME_LEN, &ttl, &priority, &weight, &port, target,
								  DNS_MAX_CNAME_LEN);
				if (ret < 0) {
					tlog(TLOG_DEBUG, "decode SRV failed, %s", name);
					return -1;
				}

				printf("domain: %s SRV: %s TTL: %d priority: %d weight: %d port: %d\n", name, target, ttl, priority,
					   weight, port);
			} break;
			case DNS_T_HTTPS: {
				char name[DNS_MAX_CNAME_LEN] = {0};
				char target[DNS_MAX_CNAME_LEN] = {0};
				struct dns_https_param *p = NULL;
				int priority = 0;

				ret = dns_get_HTTPS_svcparm_start(rrs, &p, name, DNS_MAX_CNAME_LEN, &ttl, &priority, target,
												  DNS_MAX_CNAME_LEN);
				if (ret != 0) {
					printf("get HTTPS svcparm failed\n");
					break;
				}

				printf("domain: %s HTTPS: %s TTL: %d priority: %d\n", name, target, ttl, priority);

				for (; p; p = dns_get_HTTPS_svcparm_next(rrs, p)) {
					switch (p->key) {
					case DNS_HTTPS_T_MANDATORY: {
						printf("  HTTPS: mandatory: %s\n", p->value);
					} break;
					case DNS_HTTPS_T_ALPN: {
						char alph[64] = {0};
						int total_alph_len = 0;
						char *ptr = (char *)p->value;
						do {
							int alphlen = *ptr;
							memcpy(alph + total_alph_len, ptr + 1, alphlen);
							total_alph_len += alphlen;
							ptr += alphlen + 1;
							alph[total_alph_len] = ',';
							total_alph_len++;
							alph[total_alph_len] = ' ';
							total_alph_len++;
						} while (ptr - (char *)p->value < p->len);
						if (total_alph_len > 2) {
							alph[total_alph_len - 2] = '\0';
						}
						printf("  HTTPS: alpn: %s\n", alph);
					} break;
					case DNS_HTTPS_T_NO_DEFAULT_ALPN: {
						printf("  HTTPS: no_default_alpn: %s\n", p->value);
					} break;
					case DNS_HTTPS_T_PORT: {
						int port = *(unsigned short *)(p->value);
						printf("  HTTPS: port: %d\n", port);
					} break;
					case DNS_HTTPS_T_IPV4HINT: {
						printf("  HTTPS: ipv4hint: %d\n", p->len / 4);
						for (int k = 0; k < p->len / 4; k++) {
							char ip[16] = {0};
							inet_ntop(AF_INET, p->value + k * 4, ip, sizeof(ip));
							printf("    ipv4: %s\n", ip);
						}
					} break;
					case DNS_HTTPS_T_ECH: {
						printf("  HTTPS: ech: ");
						for (int k = 0; k < p->len; k++) {
							printf("%02x ", p->value[k]);
						}
						printf("\n");
					} break;
					case DNS_HTTPS_T_IPV6HINT: {
						printf("  HTTPS: ipv6hint: %d\n", p->len / 16);
						for (int k = 0; k < p->len / 16; k++) {
							char ip[64] = {0};
							inet_ntop(AF_INET6, p->value + k * 16, ip, sizeof(ip));
							printf("    ipv6: %s\n", ip);
						}
					} break;
					}
				}
			} break;
			case DNS_T_NS: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				printf("domain: %s TTL: %d NS: %s\n", name, ttl, cname);
			} break;
			case DNS_T_CNAME: {
				char cname[DNS_MAX_CNAME_LEN];
				char name[DNS_MAX_CNAME_LEN] = {0};
				dns_get_CNAME(rrs, name, DNS_MAX_CNAME_LEN, &ttl, cname, DNS_MAX_CNAME_LEN);
				printf("domain: %s TTL: %d CNAME: %s\n", name, ttl, cname);
			} break;
			case DNS_T_SOA: {
				char name[DNS_MAX_CNAME_LEN] = {0};
				struct dns_soa soa;
				dns_get_SOA(rrs, name, 128, &ttl, &soa);
				printf("domain: %s SOA: mname: %s, rname: %s, serial: %d, refresh: %d, retry: %d, expire: "
					   "%d, minimum: %d",
					   name, soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum);
			} break;
			default:
				break;
			}
		}
		printf("\n");
	}

	rr_count = 0;
	rrs = dns_get_rrs_start(packet, DNS_RRS_OPT, &rr_count);
	if (rr_count <= 0) {
		return 0;
	}

	printf("section opt:\n");
	for (i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		switch (rrs->type) {
		case DNS_OPT_T_TCP_KEEPALIVE: {
			unsigned short idle_timeout = 0;
			ret = dns_get_OPT_TCP_KEEPALIVE(rrs, &idle_timeout);
			if (idle_timeout == 0) {
				continue;
			}

			printf("tcp keepalive: %d\n", idle_timeout);
		} break;
		case DNS_OPT_T_ECS: {
			struct dns_opt_ecs ecs;
			memset(&ecs, 0, sizeof(ecs));
			ret = dns_get_OPT_ECS(rrs, &ecs);
			if (ret != 0) {
				continue;
			}
			printf("ecs family: %d, src_prefix: %d, scope_prefix: %d, ", ecs.family, ecs.source_prefix,
				   ecs.scope_prefix);
			if (ecs.family == 1) {
				char ip[16] = {0};
				inet_ntop(AF_INET, ecs.addr, ip, sizeof(ip));
				printf("ecs address: %s\n", ip);
			} else if (ecs.family == 2) {
				char ip[64] = {0};
				inet_ntop(AF_INET6, ecs.addr, ip, sizeof(ip));
				printf("ecs address: %s\n", ip);
			}
		} break;
		default:
			break;
		}
	}

	return 0;
}

int dns_packet_debug(const char *packet_file)
{
	struct _dns_read_packet_info *info = NULL;
	char buff[DNS_PACKSIZE];

	tlog_set_maxlog_count(0);
	tlog_setlogscreen(1);
	tlog_setlevel(TLOG_DEBUG);

	info = _dns_read_packet_file(packet_file);
	if (info == NULL) {
		goto errout;
	}

	const char *send_env = getenv("SMARTDNS_DEBUG_SEND");
	if (send_env != NULL) {
		char ip[32];
		int port = 53;
		if (parse_ip(send_env, ip, &port) == 0) {
			int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
			if (sockfd > 0) {
				struct sockaddr_in server;
				server.sin_family = AF_INET;
				server.sin_port = htons(port);
				server.sin_addr.s_addr = inet_addr(ip);
				sendto(sockfd, info->packet, info->packet_len, 0, (struct sockaddr *)&server, sizeof(server));
				close(sockfd);
			}
		}
	}

	struct dns_packet *packet = (struct dns_packet *)buff;
	if (dns_decode(packet, DNS_PACKSIZE, info->packet, info->packet_len) != 0) {
		printf("decode failed.\n");
		goto errout;
	}

	_dns_debug_display(packet);

	free(info);
	return 0;

errout:
	if (info) {
		free(info);
	}

	return -1;
}

#endif
