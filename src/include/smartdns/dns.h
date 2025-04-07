/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef _DNS_HEAD_H
#define _DNS_HEAD_H

#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus */

#define DNS_RR_A_LEN 4
#define DNS_RR_AAAA_LEN 16
#define DNS_MAX_CNAME_LEN 256
#define DNS_MAX_OPT_LEN 256
#define DNS_IN_PACKSIZE (512 * 8)
#define DNS_PACKSIZE (512 * 16)
#define DNS_DEFAULT_PACKET_SIZE 512
#define DNS_MAX_ALPN_LEN 32
#define DNS_MAX_ECH_LEN 512

#define DNS_OPT_FLAG_DO 0x8000

#define DNS_ADDR_FAMILY_IP 1
#define DNS_ADDR_FAMILY_IPV6 2

/*
DNS parameters:
https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
*/

typedef enum dns_qr {
	DNS_QR_QUERY = 0,
	DNS_QR_ANSWER = 1,
} dns_qr;

typedef enum dns_rr_type {
	DNS_RRS_QD = 0,
	DNS_RRS_AN = 1,
	DNS_RRS_NS = 2,
	DNS_RRS_NR = 3,
	DNS_RRS_OPT = 4,
	DNS_RRS_END,
} dns_rr_type;

typedef enum dns_class {
	DNS_C_IN = 1, // DNS C IN
	DNS_C_ANY = 255
} dns_class_t;

typedef enum dns_type {
	DNS_T_A = 1,
	DNS_T_NS = 2,
	DNS_T_CNAME = 5,
	DNS_T_SOA = 6,
	DNS_T_PTR = 12,
	DNS_T_MX = 15,
	DNS_T_TXT = 16,
	DNS_T_AAAA = 28,
	DNS_T_SRV = 33,
	DNS_T_OPT = 41,
	DNS_T_SSHFP = 44,
	DNS_T_SVCB = 64,
	DNS_T_HTTPS = 65,
	DNS_T_SPF = 99,
	DNS_T_AXFR = 252,
	DNS_T_ALL = 255
} dns_type_t;

typedef enum dns_opt_code {
	DNS_OPT_T_ECS = 8,     // OPT ECS
	DNS_OPT_T_COOKIE = 10, // OPT Cookie
	DNS_OPT_T_TCP_KEEPALIVE = 11,
	DNS_OPT_T_PADDING = 12,
	DNS_OPT_T_ALL = 255
} dns_opt_code_t;

/* https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/11/ */
typedef enum dns_https_svcparam {
	DNS_HTTPS_T_MANDATORY = 0,
	DNS_HTTPS_T_ALPN = 1,
	DNS_HTTPS_T_NO_DEFAULT_ALPN = 2,
	DNS_HTTPS_T_PORT = 3,
	DNS_HTTPS_T_IPV4HINT = 4,
	DNS_HTTPS_T_ECH = 5,
	DNS_HTTPS_T_IPV6HINT = 6,
	DNS_HTTPS_T_ALL = 255
} dns_https_svcparam_t;

typedef enum dns_opcode {
	DNS_OP_QUERY = 0,
	DNS_OP_IQUERY = 1,
	DNS_OP_STATUS = 2,
	DNS_OP_NOTIFY = 4,
	DNS_OP_UPDATE = 5,
} dns_opcode_t; /* dns_opcode */

typedef enum dns_rtcode {
	DNS_RC_NOERROR = 0,
	DNS_RC_FORMERR = 1,
	DNS_RC_SERVFAIL = 2,
	DNS_RC_NXDOMAIN = 3,
	DNS_RC_NOTIMP = 4,
	DNS_RC_REFUSED = 5,
	DNS_RC_YXDOMAIN = 6,
	DNS_RC_YXRRSET = 7,
	DNS_RC_NXRRSET = 8,
	DNS_RC_NOTAUTH = 9,
	DNS_RC_NOTZONE = 10,
	/* EDNS(0) extended RCODEs */
	DNS_RC_BADVERS = 16,
} dns_rtcode_t; /* dns_rcode */

/* dns packet head */
struct dns_head {
	unsigned short id;      /* identification number */
	unsigned short qr;      /* Query/Response Flag */
	unsigned short opcode;  /* Operation Code */
	unsigned char aa;       /* Authoritative Answer Flag */
	unsigned char tc;       /* Truncation Flag */
	unsigned char rd;       /* Recursion Desired */
	unsigned char ra;       /* Recursion Available */
	unsigned char z;        /* Reserved for future use.  Must be Zero! */
	unsigned char ad;       /* Authentic Data Flag */
	unsigned char cd;       /* Checking Disabled Flag */
	unsigned char padding;  /* Padding */
	unsigned short rcode;   /* Response Code */
	unsigned short qdcount; /* number of question entries */
	unsigned short ancount; /* number of answer entries */
	unsigned short nscount; /* number of authority entries */
	unsigned short nrcount; /* number of additional resource entries */
} __attribute__((packed, aligned(2)));

#define DNS_PACKET_DICT_SIZE 16
struct dns_packet_dict_item {
	unsigned short pos;
	unsigned int hash;
} __attribute__((packed));

struct dns_packet_dict {
	short dict_count;
	struct dns_packet_dict_item names[DNS_PACKET_DICT_SIZE];
} __attribute__((packed));

/* packet head */
struct dns_packet {
	struct dns_head head;
	unsigned short questions;
	unsigned short answers;
	unsigned short nameservers;
	unsigned short additional;
	unsigned short optcount;
	unsigned short optional;
	unsigned short payloadsize;
	unsigned int opt_option;
	struct dns_packet_dict namedict;
	int size;
	int len;
	unsigned char data[0];
};

struct dns_rrs {
	struct dns_packet *packet;
	unsigned short next;
	unsigned short len;
	int type;
	unsigned char data[0];
} __attribute__((packed));

/* packet encode/decode context */
struct dns_context {
	struct dns_packet *packet;
	struct dns_packet_dict *namedict;
	unsigned char *data;
	int maxsize;
	unsigned char *ptr;
};

/* SOA data */
struct dns_soa {
	char mname[DNS_MAX_CNAME_LEN];
	char rname[DNS_MAX_CNAME_LEN];
	unsigned int serial;
	unsigned int refresh;
	unsigned int retry;
	unsigned int expire;
	unsigned int minimum;
} __attribute__((packed));

#define DNS_OPT_ECS_FAMILY_IPV4 1
#define DNS_OPT_ECS_FAMILY_IPV6 2

/* OPT ECS */
struct dns_opt_ecs {
	unsigned short family;
	unsigned char source_prefix;
	unsigned char scope_prefix;
	unsigned char addr[DNS_RR_AAAA_LEN];
} __attribute__((packed));

/* OPT COOKIE */
struct dns_opt_cookie {
	char server_cookie_len;
	unsigned char client_cookie[8];
	unsigned char server_cookie[32];
};

/* OPT */
struct dns_opt {
	unsigned short code;
	unsigned short length;
	unsigned char data[0];
} __attribute__((packed));

struct dns_rr_nested {
	struct dns_context context;
	unsigned char *rr_start;
	unsigned char *rr_len_ptr;
	unsigned short rr_head_len;
	dns_rr_type type;
};

struct dns_https_param {
	unsigned short key;
	unsigned short len;
	unsigned char value[0];
};

struct dns_rrs *dns_get_rrs_next(struct dns_packet *packet, struct dns_rrs *rrs);
struct dns_rrs *dns_get_rrs_start(struct dns_packet *packet, dns_rr_type type, int *count);

struct dns_rr_nested *dns_add_rr_nested_start(struct dns_rr_nested *rr_nested_buffer, struct dns_packet *packet,
											  dns_rr_type type, dns_type_t rtype, const char *domain, int ttl);
int dns_add_rr_nested_end(struct dns_rr_nested *rr_nested, dns_type_t rtype);
int dns_add_rr_nested_memcpy(struct dns_rr_nested *rr_nested, const void *data, int data_len);

void *dns_get_rr_nested_start(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *ttl, int *rr_len);
void *dns_get_rr_nested_next(struct dns_rrs *rrs, void *rr_nested, int rr_nested_len);

/*
 * Question
 */
int dns_add_domain(struct dns_packet *packet, const char *domain, int qtype, int qclass);
int dns_get_domain(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *qclass);

/*
 * Answers
 */
int dns_add_CNAME(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, const char *cname);
int dns_get_CNAME(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size);

int dns_add_A(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl,
			  unsigned char addr[DNS_RR_A_LEN]);
int dns_get_A(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[DNS_RR_A_LEN]);

int dns_add_PTR(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, const char *cname);
int dns_get_PTR(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size);

int dns_add_TXT(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, const char *text);
int dns_get_TXT(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *text, int txt_size);

int dns_add_AAAA(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl,
				 unsigned char addr[DNS_RR_AAAA_LEN]);
int dns_get_AAAA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[DNS_RR_AAAA_LEN]);

int dns_add_SOA(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, struct dns_soa *soa);
int dns_get_SOA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, struct dns_soa *soa);

int dns_add_NS(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, const char *cname);
int dns_get_NS(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size);

int dns_set_OPT_option(struct dns_packet *packet, unsigned int option);
unsigned int dns_get_OPT_option(struct dns_packet *packet);

int dns_set_OPT_payload_size(struct dns_packet *packet, int payload_size);
int dns_get_OPT_payload_size(struct dns_packet *packet);

int dns_add_OPT_ECS(struct dns_packet *packet, struct dns_opt_ecs *ecs);
int dns_get_OPT_ECS(struct dns_rrs *rrs, struct dns_opt_ecs *ecs);

int dns_add_OPT_TCP_KEEPALIVE(struct dns_packet *packet, unsigned short timeout);
int dns_get_OPT_TCP_KEEPALIVE(struct dns_rrs *rrs, unsigned short *timeout);

int dns_add_SRV(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, int priority, int weight,
				int port, const char *target);
int dns_get_SRV(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned short *priority,
				unsigned short *weight, unsigned short *port, char *target, int target_size);

/* the key must be added in orders, or dig will report FORMERR */
int dns_add_HTTPS_start(struct dns_rr_nested *svcparam_buffer, struct dns_packet *packet, dns_rr_type type,
						const char *domain, int ttl, int priority, const char *target);
int dns_HTTPS_add_raw(struct dns_rr_nested *svcparam, unsigned short key, unsigned char *value, unsigned short len);
/* key 1, alph */
int dns_HTTPS_add_alpn(struct dns_rr_nested *svcparam, const char *alpn, int alpn_len);
/* key 2, no default alph */
int dns_HTTPS_add_no_default_alpn(struct dns_rr_nested *svcparam);
/* key 3, port */
int dns_HTTPS_add_port(struct dns_rr_nested *svcparam, unsigned short port);
/* key 4, ipv4 */
int dns_HTTPS_add_ipv4hint(struct dns_rr_nested *svcparam, unsigned char *addr[], int addr_num);
/* key 5, ech */
int dns_HTTPS_add_ech(struct dns_rr_nested *svcparam, void *ech, int ech_len);
/* key 6, ipv6*/
int dns_HTTPS_add_ipv6hint(struct dns_rr_nested *svcparam, unsigned char *addr[], int addr_num);
int dns_add_HTTPS_end(struct dns_rr_nested *svcparam);

int dns_get_HTTPS_svcparm_start(struct dns_rrs *rrs, struct dns_https_param **https_param, char *domain, int maxsize,
								int *ttl, int *priority, char *target, int target_size);
struct dns_https_param *dns_get_HTTPS_svcparm_next(struct dns_rrs *rrs, struct dns_https_param *param);

/*
 * Packet operation
 */
int dns_decode_head_only(struct dns_packet *packet, int maxsize, unsigned char *data, int size);
int dns_decode(struct dns_packet *packet, int maxsize, unsigned char *data, int size);
int dns_encode(unsigned char *data, int size, struct dns_packet *packet);

int dns_packet_init(struct dns_packet *packet, int size, struct dns_head *head);

struct dns_update_param {
	int id;
	int ip_ttl;
	int cname_ttl;
};

int dns_packet_update(unsigned char *data, int size, struct dns_update_param *param);

#ifdef __cplusplus
}
#endif /*__cplusplus */
#endif
