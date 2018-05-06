#ifndef _DNS_HEAD_H
#define _DNS_HEAD_H

#include <stdint.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <netdb.h>

typedef enum dns_section { 
    DNS_S_QD = 0x01, 
    DNS_S_AN = 0x02, 
    DNS_S_NS = 0x04, 
    DNS_S_AR = 0x08, 
    DNS_S_ALL = 0x0f 
} dns_section_t;

typedef enum dns_class { 
    DNS_C_IN = 1, 
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
} dns_rtcode_t ; /* dns_rcode */

struct idns_head
{
  unsigned short id;
  unsigned char  opcode;
  unsigned char  rcode;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
} __attribute__ ((packed));

struct dns_head {
	unsigned short id;        // identification number
	unsigned char rd : 1;     // recursion desired
	unsigned char tc : 1;     // truncated message
	unsigned char aa : 1;     // authoritive answer
	unsigned char opcode : 4; // purpose of message
	unsigned char query : 1;     // query/response flag
	unsigned char rcode : 4;  // response code
	unsigned char cd : 1;     // checking disabled
	unsigned char ad : 1;     // authenticated data
	unsigned char z : 1;      // its z! reserved
	unsigned char ra : 1;     // recursion available
	unsigned short qdcount;  // number of question entries
	unsigned short ancount;  // number of answer entries
	unsigned short nscount;  // number of authority entries
	unsigned short nrcount;  // number of resource entries
} __attribute__ ((packed));

struct dns_qds {
	unsigned short type;
	unsigned short classes;
};

struct dns_rrs {
	unsigned short type;
	unsigned short classes;
	unsigned int ttl;
	unsigned short rd_length;
	char rd_data[0];
};

typedef uint32_t TTL;

typedef struct dns_question_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
} dns_question_t;

typedef struct dns_generic_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
} dns_generic_t;

typedef struct dns_a_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  in_addr_t    address;
} dns_a_t;

typedef struct dns_aaaa_t	/* RFC-1886 */
{
  const char      *name;
  dns_type_t       type;
  dns_class_t      class;
  TTL              ttl;
  struct in6_addr  address;
} dns_aaaa_t;

typedef struct dns_cname_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *cname;
} dns_cname_t;

typedef struct dns_ptr_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *ptr;
} dns_ptr_t;


typedef union dns_answer_t
{
  dns_generic_t  generic;
  dns_a_t        a;
  dns_cname_t    cname;
  dns_ptr_t      ptr;
  dns_aaaa_t     aaaa;
} dns_answer_t;

struct dns_packet {
	struct dns_head head;
	dns_question_t *questions;
    dns_answer_t   *answers;
    dns_answer_t   *nameservers;
    dns_answer_t   *additional;
};

int dns_decode(struct dns_packet *packet, char *data, int size);

#endif