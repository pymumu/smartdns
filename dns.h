#ifndef _DNS_HEAD_H
#define _DNS_HEAD_H

#include <arpa/inet.h>
#include <linux/filter.h>
#include <netdb.h>
#include <stdint.h>

#define QR_MASK 0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK 0x0400
#define TC_MASK 0x0200
#define RD_MASK 0x0100
#define RA_MASK 0x8000
#define RCODE_MASK 0x000F

typedef enum dns_section { DNS_S_QD = 0x01, DNS_S_AN = 0x02, DNS_S_NS = 0x04, DNS_S_AR = 0x08, DNS_S_ALL = 0x0f } dns_section_t;

typedef enum dns_class { DNS_C_IN = 1, DNS_C_ANY = 255 } dns_class_t;

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
	DNS_T_SPF = 99,
	DNS_T_AXFR = 252,
	DNS_T_ALL = 255
} dns_type_t;

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

struct dns_head {
	unsigned short id;      // identification number
	unsigned short qr;      /* Query/Response Flag */
	unsigned short opcode;  /* Operation Code */
	unsigned short aa;      /* Authoritative Answer Flag */
	unsigned short tc;      /* Truncation Flag */
	unsigned short rd;      /* Recursion Desired */
	unsigned short ra;      /* Recursion Available */
	unsigned short rcode;   /* Response Code */
	unsigned short qdcount; // number of question entries
	unsigned short ancount; // number of answer entries
	unsigned short nscount; // number of authority entries
	unsigned short nrcount; // number of addititional resource entries
} __attribute__((packed));

struct dns_qds {
	unsigned short type;
	unsigned short classes;
};

typedef uint32_t TTL;

typedef struct dns_question_t /* RFC-1035 */
{
	const char *name;
	dns_type_t type;
	dns_class_t class;
} dns_question_t;

typedef struct dns_generic_t /* RFC-1035 */
{
	const char *name;
	dns_type_t type;
	dns_class_t class;
	TTL ttl;
} dns_generic_t;

typedef struct dns_a_t /* RFC-1035 */
{
	const char *name;
	dns_type_t type;
	dns_class_t class;
	TTL ttl;
	in_addr_t address;
} dns_a_t;

typedef struct dns_aaaa_t /* RFC-1886 */
{
	const char *name;
	dns_type_t type;
	dns_class_t class;
	TTL ttl;
	struct in6_addr address;
} dns_aaaa_t;

typedef struct dns_cname_t /* RFC-1035 */
{
	const char *name;
	dns_type_t type;
	dns_class_t class;
	TTL ttl;
	const char *cname;
} dns_cname_t;

typedef struct dns_ptr_t /* RFC-1035 */
{
	const char *name;
	dns_type_t type;
	dns_class_t class;
	TTL ttl;
	const char *ptr;
} dns_ptr_t;

typedef union dns_answer_t {
	dns_generic_t generic;
	dns_a_t a;
	dns_cname_t cname;
	dns_ptr_t ptr;
	dns_aaaa_t aaaa;
} dns_answer_t;

#define DNS_RR_QD 0
#define DNS_RR_AN 1
#define DNS_RR_NS 2
#define DNS_RR_NR 3

struct dns_rrs {
	unsigned short next;
	unsigned short len;
	dns_type_t type;
	unsigned char data[0];
};

struct dns_packet {
	struct dns_head head;
	unsigned short questions;
	unsigned short answers;
	unsigned short nameservers;
	unsigned short additional;
	int size;
	int len;
	unsigned char data[0];
};

int dns_decode(struct dns_packet *packet, unsigned char *data, int size);

int dns_encode(unsigned char *data, int size, struct dns_packet *packet);

int dns_packet_init(struct dns_packet *packet, int size);

int dns_get_domain(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *qclass);

int dns_add_domain(struct dns_packet *packet, char *domain, int qtype, int qclass);

struct dns_rrs *dns_rr_get_next(struct dns_packet *packet, struct dns_rrs *rrs);

struct dns_rrs *dns_rr_get_start(struct dns_packet *packet, int type, int *count);

#endif