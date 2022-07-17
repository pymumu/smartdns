/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "dns.h"
#include "stringutil.h"
#include "tlog.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define QR_MASK 0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK 0x0400
#define TC_MASK 0x0200
#define RD_MASK 0x0100
#define RA_MASK 0x0080
#define RCODE_MASK 0x000F
#define DNS_RR_END (0XFFFF)

#define UNUSED(expr)                                                                                                   \
	do {                                                                                                               \
		(void)(expr);                                                                                                  \
	} while (0)

/* read short and move pointer */
static short _dns_read_short(unsigned char **buffer)
{
	unsigned short value = 0;

	value = ntohs(*((unsigned short *)(*buffer)));
	*buffer += 2;
	return value;
}

/* write char and move pointer */
static __attribute__((unused)) void _dns_write_char(unsigned char **buffer, unsigned char value)
{
	**buffer = value;
	*buffer += 1;
}

/* read char and move pointer */
static unsigned char _dns_read_char(unsigned char **buffer)
{
	unsigned char value = **buffer;
	*buffer += 1;
	return value;
}

/* write short and move pointer */
static void _dns_write_short(unsigned char **buffer, unsigned short value)
{
	value = htons(value);
	*((unsigned short *)(*buffer)) = value;
	*buffer += 2;
}

/* write int and move pointer */
static void _dns_write_int(unsigned char **buffer, unsigned int value)
{
	value = htonl(value);
	*((unsigned int *)(*buffer)) = value;
	*buffer += 4;
}

/* read int and move pointer */
static unsigned int _dns_read_int(unsigned char **buffer)
{
	unsigned int value = 0;

	value = ntohl(*((unsigned int *)(*buffer)));
	*buffer += 4;

	return value;
}

static inline int _dns_left_len(struct dns_context *context)
{
	return context->maxsize - (context->ptr - context->data);
}

static int _dns_get_domain_from_packet(unsigned char *packet, int packet_size, unsigned char **domain_ptr, char *output,
									   int size)
{
	int output_len = 0;
	int copy_len = 0;
	int len = 0;
	unsigned char *ptr = *domain_ptr;
	int is_compressed = 0;
	int ptr_jump = 0;

	/*[len]string[len]string...[0]0 */
	while (1) {
		if (ptr >= packet + packet_size || ptr < packet || output_len >= size - 1 || ptr_jump > 4) {
			return -1;
		}

		len = *ptr;
		if (len == 0) {
			*output = 0;
			ptr++;
			break;
		}

		/* compressed domain */
		if (len >= 0xC0) {
			if ((ptr + 2) > (packet + packet_size)) {
				return -1;
			}
			/*
			0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
			+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			| 1  1|                OFFSET                   |
			+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
			*/
			/* read offset */
			len = _dns_read_short(&ptr) & 0x3FFF;
			if (is_compressed == 0) {
				*domain_ptr = ptr;
			}

			ptr = packet + len;
			if (ptr > packet + packet_size) {
				tlog(TLOG_DEBUG, "length is not enough %u:%ld, %p, %p", packet_size, (long)(ptr - packet), *domain_ptr,
					 packet);
				return -1;
			}
			is_compressed = 1;
			ptr_jump++;
			continue;
		}

		ptr_jump = 0;

		/* change [len] to '.' */
		if (output_len > 0) {
			*output = '.';
			output++;
			output_len += 1;
		}

		if (ptr > packet + packet_size) {
			tlog(TLOG_DEBUG, "length is not enough %u:%ld, %p, %p", packet_size, (long)(ptr - packet), *domain_ptr,
				 packet);
			return -1;
		}

		ptr++;
		if (output_len < size - 1) {
			/* copy sub string */
			copy_len = (len < size - output_len) ? len : size - 1 - output_len;
			if ((ptr + copy_len) > (packet + packet_size)) {
				tlog(TLOG_DEBUG, "length is not enough %u:%ld, %p, %p", packet_size, (long)(ptr - packet), *domain_ptr,
					 packet);
				return -1;
			}
			memcpy(output, ptr, copy_len);
		}

		ptr += len;
		output += len;
		output_len += len;
	}

	if (is_compressed == 0) {
		*domain_ptr = ptr;
	}

	return 0;
}

static int _dns_decode_domain(struct dns_context *context, char *output, int size)
{
	return _dns_get_domain_from_packet(context->data, context->maxsize, &(context->ptr), output, size);
}

static unsigned int dict_hash(const char *s)
{
	unsigned int hashval = 0;
	for (hashval = 0; *s != '\0'; s++) {
		hashval = *s + 31 * hashval;
	}
	return hashval;
}

static int _dns_add_domain_dict(struct dns_context *context, unsigned int hash, int pos)
{
	struct dns_packet_dict *dict = context->namedict;

	if (dict->dict_count >= DNS_PACKET_DICT_SIZE) {
		return -1;
	}

	if (hash == 0) {
		return -1;
	}

	if (pos >= context->maxsize) {
		return -1;
	}

	int index = dict->dict_count;
	dict->names[index].hash = hash;
	dict->names[index].pos = pos;
	dict->dict_count++;

	return 0;
}

static int _dns_get_domain_offset(struct dns_context *context, const char *domain)
{
	int i = 0;

	char domain_check[DNS_MAX_CNAME_LEN];
	struct dns_packet_dict *dict = context->namedict;

	if (*domain == '\0') {
		return -1;
	}

	unsigned int hash = dict_hash(domain);
	for (i = 0; i < dict->dict_count; i++) {
		if (dict->names[i].hash != hash) {
			continue;
		}

		unsigned char *domain_check_ptr = dict->names[i].pos + context->data;
		if (_dns_get_domain_from_packet(context->data, context->maxsize, &domain_check_ptr, domain_check,
										DNS_MAX_CNAME_LEN) != 0) {
			return -1;
		}

		return dict->names[i].pos;
	}

	_dns_add_domain_dict(context, hash, context->ptr - 1 - context->data);
	return -1;
}

static int _dns_encode_domain(struct dns_context *context, const char *domain)
{
	int num = 0;
	int total_len = 0;
	unsigned char *ptr_num = context->ptr++;
	int dict_offset = 0;

	dict_offset = _dns_get_domain_offset(context, domain);
	total_len++;

	/*[len]string[len]string...[0]0 */
	while (_dns_left_len(context) > 1 && *domain != 0) {
		total_len++;
		if (dict_offset >= 0) {
			int offset = 0xc000 | dict_offset;
			_dns_write_short(&ptr_num, offset);
			context->ptr++;
			ptr_num = NULL;
			return total_len;
		}

		if (*domain == '.') {
			*ptr_num = num;
			num = 0;
			ptr_num = context->ptr;
			domain++;
			context->ptr++;
			dict_offset = _dns_get_domain_offset(context, domain);
			continue;
		}
		*context->ptr = *domain;
		num++;
		context->ptr++;
		domain++;
	}

	*ptr_num = num;

	if (total_len > 1) {
		/* if domain is '\0', [domain] is '\0' */
		*(context->ptr) = 0;
		total_len++;
		context->ptr++;
	}

	if (_dns_left_len(context) <= 0) {
		return -1;
	}

	return total_len;
}

/* iterator get rrs begin */
struct dns_rrs *dns_get_rrs_start(struct dns_packet *packet, dns_rr_type type, int *count)
{
	unsigned short start = 0;
	struct dns_head *head = &packet->head;

	/* get rrs count by rrs type */
	switch (type) {
	case DNS_RRS_QD:
		*count = head->qdcount;
		start = packet->questions;
		break;
	case DNS_RRS_AN:
		*count = head->ancount;
		start = packet->answers;
		break;
	case DNS_RRS_NS:
		*count = head->nscount;
		start = packet->nameservers;
		break;
	case DNS_RRS_NR:
		*count = head->nrcount;
		start = packet->additional;
		break;
	case DNS_RRS_OPT:
		*count = packet->optcount;
		start = packet->optional;
		break;
	default:
		return NULL;
		break;
	}

	/* if not resource record, return null */
	if (start == DNS_RR_END) {
		return NULL;
	}

	/* return rrs data start address */
	return (struct dns_rrs *)(packet->data + start);
}

/* iterator next rrs */
struct dns_rrs *dns_get_rrs_next(struct dns_packet *packet, struct dns_rrs *rrs)
{
	if (rrs->next == DNS_RR_END) {
		return NULL;
	}

	return (struct dns_rrs *)(packet->data + rrs->next);
}

static void _dns_init_context_by_rrs(struct dns_rrs *rrs, struct dns_context *context)
{
	context->packet = rrs->packet;
	context->data = rrs->packet->data;
	context->ptr = rrs->data;
	context->namedict = &rrs->packet->namedict;
	context->maxsize = rrs->data - rrs->packet->data + rrs->len;
}

/* iterator add rrs begin */
static int _dns_add_rrs_start(struct dns_packet *packet, struct dns_context *context)
{
	struct dns_rrs *rrs = NULL;
	unsigned char *end = packet->data + packet->len;

	if ((packet->len + (int)sizeof(*rrs)) >= packet->size) {
		return -1;
	}
	rrs = (struct dns_rrs *)end;

	context->ptr = rrs->data;
	context->packet = packet;
	context->maxsize = packet->size - sizeof(*packet);
	context->data = packet->data;
	context->namedict = &packet->namedict;

	return 0;
}

/* iterator add rrs end */
static int _dns_rr_add_end(struct dns_packet *packet, int type, dns_type_t rtype, int len)
{
	struct dns_rrs *rrs = NULL;
	struct dns_rrs *rrs_next = NULL;
	struct dns_head *head = &packet->head;
	unsigned char *end = packet->data + packet->len;
	unsigned short *count = NULL;
	unsigned short *start = NULL;

	rrs = (struct dns_rrs *)end;
	if (packet->len + len > packet->size - (int)sizeof(*packet) - (int)sizeof(*rrs)) {
		return -1;
	}

	switch (type) {
	case DNS_RRS_QD:
		count = &head->qdcount;
		start = &packet->questions;
		break;
	case DNS_RRS_AN:
		count = &head->ancount;
		start = &packet->answers;
		break;
	case DNS_RRS_NS:
		count = &head->nscount;
		start = &packet->nameservers;
		break;
	case DNS_RRS_NR:
		count = &head->nrcount;
		start = &packet->additional;
		break;
	case DNS_RRS_OPT:
		count = &packet->optcount;
		start = &packet->optional;
		break;
	default:
		return -1;
		break;
	}

	/* add data to end of dns_packet, and set previous rrs point to this rrs */
	if (*start != DNS_RR_END) {
		rrs_next = (struct dns_rrs *)(packet->data + *start);
		while (rrs_next->next != DNS_RR_END) {
			rrs_next = (struct dns_rrs *)(packet->data + rrs_next->next);
		}
		rrs_next->next = packet->len;
	} else {
		*start = packet->len;
	}

	/* update rrs head info */
	rrs->packet = packet;
	rrs->len = len;
	rrs->type = rtype;
	rrs->next = DNS_RR_END;

	/* update total data length */
	*count += 1;
	packet->len += len + sizeof(*rrs);
	return 0;
}

static int _dns_add_qr_head(struct dns_context *context, const char *domain, int qtype, int qclass)
{
	int ret = _dns_encode_domain(context, domain);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 4) {
		return -1;
	}

	_dns_write_short(&context->ptr, qtype);
	_dns_write_short(&context->ptr, qclass);

	return ret + 4;
}

static int _dns_get_qr_head(struct dns_context *context, char *domain, int maxsize, int *qtype, int *qclass)
{
	int ret = 0;

	if (domain == NULL || context == NULL) {
		return -1;
	}

	ret = _dns_decode_domain(context, domain, maxsize);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 4) {
		return -1;
	}

	*qtype = _dns_read_short(&context->ptr);
	*qclass = _dns_read_short(&context->ptr);

	return 0;
}

static int _dns_add_rr_head(struct dns_context *context, const char *domain, int qtype, int qclass, int ttl, int rr_len)
{
	int len = 0;

	/* resource record head */
	/* |domain          |
	 * |qtype  | qclass |
	 * |       ttl      |
	 * | rrlen | rrdata |
	 */
	len = _dns_add_qr_head(context, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 6) {
		return -1;
	}

	_dns_write_int(&context->ptr, ttl);
	_dns_write_short(&context->ptr, rr_len);

	return len + 6;
}

static int _dns_get_rr_head(struct dns_context *context, char *domain, int maxsize, int *qtype, int *qclass, int *ttl,
							int *rr_len)
{
	int len = 0;

	/* resource record head */
	/* |domain          |
	 * |qtype  | qclass |
	 * |       ttl      |
	 * | rrlen | rrdata |
	 */
	len = _dns_get_qr_head(context, domain, maxsize, qtype, qclass);

	if (_dns_left_len(context) < 6) {
		return -1;
	}

	*ttl = _dns_read_int(&context->ptr);
	*rr_len = _dns_read_short(&context->ptr);

	return len;
}

static int _dns_add_RAW(struct dns_packet *packet, dns_rr_type rrtype, dns_type_t rtype, const char *domain, int ttl,
						const void *raw, int raw_len)
{
	int len = 0;
	struct dns_context context;
	int ret = 0;

	/* resource record */
	/* |domain          |
	 * |qtype  | qclass |
	 * |       ttl      |
	 * | rrlen | rrdata |
	 */
	ret = _dns_add_rrs_start(packet, &context);
	if (ret < 0) {
		return -1;
	}

	/* add rr head */
	len = _dns_add_rr_head(&context, domain, rtype, DNS_C_IN, ttl, raw_len);
	if (len < 0) {
		return -1;
	}

	if (_dns_left_len(&context) < raw_len) {
		return -1;
	}

	/* add rr data */
	memcpy(context.ptr, raw, raw_len);
	context.ptr += raw_len;
	len += raw_len;

	return _dns_rr_add_end(packet, rrtype, rtype, len);
}

static int _dns_get_RAW(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, void *raw, int *raw_len)
{
	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int ret = 0;
	struct dns_context context;

	/* resource record head */
	/* |domain          |
	 * |qtype  | qclass |
	 * |       ttl      |
	 * | rrlen | rrdata |
	 */
	_dns_init_context_by_rrs(rrs, &context);

	/* get rr head */
	ret = _dns_get_rr_head(&context, domain, maxsize, &qtype, &qclass, ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (qtype != rrs->type || rr_len > *raw_len) {
		return -1;
	}

	/* get rr data */
	memcpy(raw, context.ptr, rr_len);
	context.ptr += rr_len;
	*raw_len = rr_len;

	return 0;
}

static int _dns_add_opt_RAW(struct dns_packet *packet, dns_opt_code_t opt_rrtype, void *raw, int raw_len)
{
	unsigned char opt_data[DNS_MAX_OPT_LEN];
	struct dns_opt *opt = (struct dns_opt *)opt_data;
	int len = 0;

	opt->code = DNS_OPT_T_TCP_KEEPALIVE;
	opt->length = sizeof(unsigned short);

	memcpy(opt->data, raw, raw_len);
	len += raw_len;
	len += sizeof(*opt);

	return _dns_add_RAW(packet, DNS_RRS_OPT, (dns_type_t)DNS_OPT_T_TCP_KEEPALIVE, "", 0, opt_data, len);
}

static int _dns_get_opt_RAW(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, struct dns_opt *dns_opt,
							int *dns_optlen)
{
	*dns_optlen = DNS_MAX_OPT_LEN;

	return _dns_get_RAW(rrs, domain, maxsize, ttl, dns_opt, dns_optlen);
}

static int __attribute__((unused)) _dns_add_OPT(struct dns_packet *packet, dns_rr_type type, unsigned short opt_code,
												unsigned short opt_len, struct dns_opt *opt)
{
	// TODO

	int ret = 0;
	int len = 0;
	struct dns_context context;
	int total_len = sizeof(*opt) + opt->length;
	int ttl = 0;

	/*
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0: |                          OPTION-CODE                          |
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  2: |                         OPTION-LENGTH                         |
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  4: |                                                               |
	 /                          OPTION-DATA                          /
	 /                                                               /
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	*/
	ret = _dns_add_rrs_start(packet, &context);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(&context) < total_len) {
		return -1;
	}

	ttl = (opt_code << 16) | opt_len;

	/* add rr head */
	len = _dns_add_rr_head(&context, "", type, DNS_C_IN, ttl, total_len);
	if (len < 0) {
		return -1;
	}

	/* add rr data */
	memcpy(context.ptr, opt, total_len);
	context.ptr += total_len;
	len = context.ptr - context.data - packet->len;

	return _dns_rr_add_end(packet, type, DNS_T_OPT, len);
}

static int __attribute__((unused)) _dns_get_OPT(struct dns_rrs *rrs, unsigned short *opt_code, unsigned short *opt_len,
												struct dns_opt *opt, int *opt_maxlen)
{
	// TODO

	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int ret = 0;
	struct dns_context context;
	char domain[DNS_MAX_CNAME_LEN];
	int maxsize = DNS_MAX_CNAME_LEN;
	int ttl = 0;

	_dns_init_context_by_rrs(rrs, &context);

	/* get rr head */
	ret = _dns_get_rr_head(&context, domain, maxsize, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (qtype != rrs->type || rr_len > *opt_len) {
		return -1;
	}

	/* get rr data */
	*opt_code = ttl >> 16;
	*opt_len = ttl & 0xFFFF;
	memcpy(opt, context.ptr, rr_len);
	context.ptr += rr_len;
	*opt_maxlen = rr_len;

	return 0;
}

int dns_add_CNAME(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, const char *cname)
{
	int rr_len = strnlen(cname, DNS_MAX_CNAME_LEN) + 1;
	return _dns_add_RAW(packet, type, DNS_T_CNAME, domain, ttl, cname, rr_len);
}

int dns_get_CNAME(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size)
{
	int len = cname_size;
	return _dns_get_RAW(rrs, domain, maxsize, ttl, cname, &len);
}

int dns_add_A(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, unsigned char addr[DNS_RR_A_LEN])
{
	return _dns_add_RAW(packet, type, DNS_T_A, domain, ttl, addr, DNS_RR_A_LEN);
}

int dns_get_A(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[DNS_RR_A_LEN])
{
	int len = DNS_RR_A_LEN;
	return _dns_get_RAW(rrs, domain, maxsize, ttl, addr, &len);
}

int dns_add_PTR(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, char *cname)
{
	int rr_len = strnlen(cname, DNS_MAX_CNAME_LEN) + 1;
	return _dns_add_RAW(packet, type, DNS_T_PTR, domain, ttl, cname, rr_len);
}

int dns_get_PTR(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size)
{
	int len = cname_size;
	return _dns_get_RAW(rrs, domain, maxsize, ttl, cname, &len);
}

int dns_add_NS(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, const char *cname)
{
	int rr_len = strnlen(cname, DNS_MAX_CNAME_LEN) + 1;
	return _dns_add_RAW(packet, type, DNS_T_NS, domain, ttl, cname, rr_len);
}

int dns_get_NS(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size)
{
	int len = cname_size;
	return _dns_get_RAW(rrs, domain, maxsize, ttl, cname, &len);
}

int dns_add_AAAA(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl,
				 unsigned char addr[DNS_RR_AAAA_LEN])
{
	return _dns_add_RAW(packet, type, DNS_T_AAAA, domain, ttl, addr, DNS_RR_AAAA_LEN);
}

int dns_get_AAAA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[DNS_RR_AAAA_LEN])
{
	int len = DNS_RR_AAAA_LEN;
	return _dns_get_RAW(rrs, domain, maxsize, ttl, addr, &len);
}

int dns_add_SOA(struct dns_packet *packet, dns_rr_type type, const char *domain, int ttl, struct dns_soa *soa)
{
	/* SOA */
	/*| mname        |
	 *| rname        |
	 *| serial       |
	 *| refersh      |
	 *| retry        |
	 *| expire       |
	 *| minimum      |
	 */
	unsigned char data[sizeof(*soa)];
	unsigned char *ptr = data;
	int len = 0;
	safe_strncpy((char *)ptr, soa->mname, DNS_MAX_CNAME_LEN);
	ptr += strnlen(soa->mname, DNS_MAX_CNAME_LEN - 1) + 1;
	safe_strncpy((char *)ptr, soa->rname, DNS_MAX_CNAME_LEN);
	ptr += strnlen(soa->rname, DNS_MAX_CNAME_LEN - 1) + 1;
	memcpy(ptr, &soa->serial, sizeof(unsigned int));
	ptr += 4;
	memcpy(ptr, &soa->refresh, sizeof(unsigned int));
	ptr += 4;
	memcpy(ptr, &soa->retry, sizeof(unsigned int));
	ptr += 4;
	memcpy(ptr, &soa->expire, sizeof(unsigned int));
	ptr += 4;
	memcpy(ptr, &soa->minimum, sizeof(unsigned int));
	ptr += 4;
	len = ptr - data;

	return _dns_add_RAW(packet, type, DNS_T_SOA, domain, ttl, data, len);
}

int dns_get_SOA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, struct dns_soa *soa)
{
	unsigned char data[sizeof(*soa)];
	unsigned char *ptr = data;
	int len = sizeof(data);

	/* SOA */
	/*| mname        |
	 *| rname        |
	 *| serial       |
	 *| refersh      |
	 *| retry        |
	 *| expire       |
	 *| minimum      |
	 */
	if (_dns_get_RAW(rrs, domain, maxsize, ttl, data, &len) != 0) {
		return -1;
	}

	safe_strncpy(soa->mname, (char *)ptr, DNS_MAX_CNAME_LEN - 1);
	ptr += strnlen(soa->mname, DNS_MAX_CNAME_LEN - 1) + 1;
	if (ptr - data >= len) {
		return -1;
	}
	safe_strncpy(soa->rname, (char *)ptr, DNS_MAX_CNAME_LEN - 1);
	ptr += strnlen(soa->rname, DNS_MAX_CNAME_LEN - 1) + 1;
	if (ptr - data + 20 > len) {
		return -1;
	}
	memcpy(&soa->serial, ptr, 4);
	ptr += 4;
	memcpy(&soa->refresh, ptr, 4);
	ptr += 4;
	memcpy(&soa->retry, ptr, 4);
	ptr += 4;
	memcpy(&soa->expire, ptr, 4);
	ptr += 4;
	memcpy(&soa->minimum, ptr, 4);

	return 0;
}

int dns_set_OPT_payload_size(struct dns_packet *packet, int payload_size)
{
	if (payload_size < 512) {
		payload_size = 512;
	}

	packet->payloadsize = payload_size;
	return 0;
}

int dns_get_OPT_payload_size(struct dns_packet *packet)
{
	return packet->payloadsize;
}

int dns_add_OPT_ECS(struct dns_packet *packet, struct dns_opt_ecs *ecs)
{
	unsigned char opt_data[DNS_MAX_OPT_LEN];
	struct dns_opt *opt = (struct dns_opt *)opt_data;
	int len = 0;

	/* ecs size 4 + bit of address*/
	len = 4;
	len += (ecs->source_prefix / 8);
	len += (ecs->source_prefix % 8 > 0) ? 1 : 0;

	opt->length = len;
	opt->code = DNS_OPT_T_ECS;
	memcpy(opt->data, ecs, len);
	len += sizeof(*opt);

	return _dns_add_RAW(packet, DNS_RRS_OPT, (dns_type_t)DNS_OPT_T_ECS, "", 0, opt_data, len);
}

int dns_get_OPT_ECS(struct dns_rrs *rrs, unsigned short *opt_code, unsigned short *opt_len, struct dns_opt_ecs *ecs)
{
	unsigned char opt_data[DNS_MAX_OPT_LEN];
	char domain[DNS_MAX_CNAME_LEN] = {0};
	struct dns_opt *opt = (struct dns_opt *)opt_data;
	int len = DNS_MAX_OPT_LEN;
	int ttl = 0;

	if (_dns_get_RAW(rrs, domain, DNS_MAX_CNAME_LEN, &ttl, opt_data, &len) != 0) {
		return -1;
	}

	if (len < (int)sizeof(*opt)) {
		return -1;
	}

	if (opt->code != DNS_OPT_T_ECS) {
		return -1;
	}

	memcpy(ecs, opt->data, opt->length);

	return 0;
}

int dns_add_OPT_TCP_KEEYALIVE(struct dns_packet *packet, unsigned short timeout)
{
	unsigned short timeout_net = htons(timeout);
	int data_len = 0;

	if (timeout > 0) {
		data_len = sizeof(timeout);
	}

	return _dns_add_opt_RAW(packet, DNS_OPT_T_TCP_KEEPALIVE, &timeout_net, data_len);
}

int dns_get_OPT_TCP_KEEYALIVE(struct dns_rrs *rrs, unsigned short *opt_code, unsigned short *opt_len,
							  unsigned short *timeout)
{
	unsigned char opt_data[DNS_MAX_OPT_LEN];
	struct dns_opt *opt = (struct dns_opt *)opt_data;
	int len = DNS_MAX_OPT_LEN;
	int ttl = 0;
	unsigned char *data = NULL;

	if (_dns_get_opt_RAW(rrs, NULL, 0, &ttl, opt, &len) != 0) {
		return -1;
	}

	if (len < (int)sizeof(*opt)) {
		return -1;
	}

	if (opt->code != DNS_OPT_T_TCP_KEEPALIVE) {
		return -1;
	}

	if (opt->length == 0) {
		*timeout = 0;
		return 0;
	}

	if (opt->length != sizeof(unsigned short)) {
		return -1;
	}

	data = opt->data;

	*timeout = _dns_read_short(&data);

	return 0;
}

/*
 * Format:
 * |DNS_NAME\0(string)|qtype(short)|qclass(short)|
 */
int dns_add_domain(struct dns_packet *packet, const char *domain, int qtype, int qclass)
{
	int len = 0;
	int ret = 0;
	struct dns_context context;

	ret = _dns_add_rrs_start(packet, &context);
	if (ret < 0) {
		return -1;
	}

	len = _dns_add_qr_head(&context, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}

	return _dns_rr_add_end(packet, DNS_RRS_QD, DNS_T_CNAME, len);
}

int dns_get_domain(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *qclass)
{
	struct dns_context context;

	if (rrs->type != DNS_T_CNAME) {
		return -1;
	}

	_dns_init_context_by_rrs(rrs, &context);
	return _dns_get_qr_head(&context, domain, maxsize, qtype, qclass);
}

static int _dns_decode_head(struct dns_context *context)
{
	unsigned int fields = 0;
	int len = 12;
	struct dns_head *head = &context->packet->head;

	if (_dns_left_len(context) < len) {
		return -1;
	}

	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      ID                       |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    QDCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ANCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    NSCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ARCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/

	head->id = _dns_read_short(&context->ptr);
	fields = _dns_read_short(&context->ptr);
	head->qr = (fields & QR_MASK) >> 15;
	head->opcode = (fields & OPCODE_MASK) >> 11;
	head->aa = (fields & AA_MASK) >> 10;
	head->tc = (fields & TC_MASK) >> 9;
	head->rd = (fields & RD_MASK) >> 8;
	head->ra = (fields & RA_MASK) >> 7;
	head->rcode = (fields & RCODE_MASK) >> 0;
	head->qdcount = _dns_read_short(&context->ptr);
	head->ancount = _dns_read_short(&context->ptr);
	head->nscount = _dns_read_short(&context->ptr);
	head->nrcount = _dns_read_short(&context->ptr);

	return 0;
}

static int _dns_encode_head(struct dns_context *context)
{
	int len = 12;
	struct dns_head *head = &context->packet->head;

	if (_dns_left_len(context) < len) {
		return -1;
	}

	_dns_write_short(&context->ptr, head->id);

	int fields = 0;
	fields |= (head->qr << 15) & QR_MASK;
	fields |= (head->opcode << 11) & OPCODE_MASK;
	fields |= (head->aa << 10) & AA_MASK;
	fields |= (head->tc << 9) & TC_MASK;
	fields |= (head->rd << 8) & RD_MASK;
	fields |= (head->ra << 7) & RA_MASK;
	fields |= (head->rcode << 0) & RCODE_MASK;
	_dns_write_short(&context->ptr, fields);

	_dns_write_short(&context->ptr, head->qdcount);
	_dns_write_short(&context->ptr, head->ancount);
	_dns_write_short(&context->ptr, head->nscount);
	_dns_write_short(&context->ptr, head->nrcount);
	return len;
}

static int _dns_encode_head_count(struct dns_context *context)
{
	int len = 12;
	struct dns_head *head = &context->packet->head;
	unsigned char *ptr = context->data;

	ptr += 4;
	_dns_write_short(&ptr, head->qdcount);
	_dns_write_short(&ptr, head->ancount);
	_dns_write_short(&ptr, head->nscount);
	_dns_write_short(&ptr, head->nrcount);
	return len;
}

static int _dns_decode_qr_head(struct dns_context *context, char *domain, int domain_size, int *qtype, int *qclass)
{
	int ret = 0;
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                                               /
	/                      NAME                     /
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     CLASS                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/
	ret = _dns_decode_domain(context, domain, domain_size);
	if (ret < 0) {
		tlog(TLOG_DEBUG, "decode domain failed.");
		return -1;
	}

	if (_dns_left_len(context) < 4) {
		tlog(TLOG_DEBUG, "left length is not enough, %s.", domain);
		return -1;
	}

	*qtype = _dns_read_short(&context->ptr);
	*qclass = _dns_read_short(&context->ptr);

	return 0;
}

static int _dns_encode_qr_head(struct dns_context *context, char *domain, int qtype, int qclass)
{
	int ret = 0;
	ret = _dns_encode_domain(context, domain);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 4) {
		return -1;
	}

	_dns_write_short(&context->ptr, qtype);
	_dns_write_short(&context->ptr, qclass);

	return 0;
}

static int _dns_decode_rr_head(struct dns_context *context, char *domain, int domain_size, int *qtype, int *qclass,
							   int *ttl, int *rr_len)
{
	int len = 0;

	len = _dns_decode_qr_head(context, domain, domain_size, qtype, qclass);
	if (len < 0) {
		tlog(TLOG_DEBUG, "decode qr head failed.");
		return -1;
	}

	if (_dns_left_len(context) < 6) {
		tlog(TLOG_DEBUG, "left length is not enough.");
		return -1;
	}

	*ttl = _dns_read_int(&context->ptr);
	*rr_len = _dns_read_short(&context->ptr);

	return 0;
}

static int _dns_encode_rr_head(struct dns_context *context, char *domain, int qtype, int qclass, int ttl, int rr_len,
							   unsigned char **rr_len_ptr)
{
	int ret = 0;
	ret = _dns_encode_qr_head(context, domain, qtype, qclass);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 6) {
		return -1;
	}

	_dns_write_int(&context->ptr, ttl);
	if (rr_len_ptr) {
		*rr_len_ptr = context->ptr;
	}
	_dns_write_short(&context->ptr, rr_len);

	return 0;
}

static int _dns_encode_raw(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_len = 0;
	unsigned char *rr_len_ptr = NULL;
	struct dns_context data_context;
	/*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                                               /
	/                      NAME                     /
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     CLASS                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TTL                      |
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                   RDLENGTH                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
	/                     RDATA                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/
	_dns_init_context_by_rrs(rrs, &data_context);
	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_rr_head(context, domain, qtype, qclass, ttl, rr_len, &rr_len_ptr);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < rr_len) {
		return -1;
	}

	memcpy(context->ptr, data_context.ptr, rr_len);
	context->ptr += rr_len;
	data_context.ptr += rr_len;

	return 0;
}

static int _dns_decode_raw(struct dns_context *context, unsigned char *raw, int len)
{
	if (_dns_left_len(context) < len) {
		return -1;
	}

	memcpy(raw, context->ptr, len);
	context->ptr += len;
	return 0;
}

static int _dns_decode_CNAME(struct dns_context *context, char *cname, int cname_size)
{
	int ret = 0;
	ret = _dns_decode_domain(context, cname, cname_size);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int _dns_encode_CNAME(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_len = 0;
	unsigned char *rr_len_ptr = NULL;
	struct dns_context data_context;

	_dns_init_context_by_rrs(rrs, &data_context);
	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	/* when code domain, len must plus 1, because of length at the begining */
	rr_len = 1;
	ret = _dns_encode_rr_head(context, domain, qtype, qclass, ttl, rr_len, &rr_len_ptr);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_domain(context, (char *)data_context.ptr);
	if (ret < 0) {
		return -1;
	}
	rr_len += ret;
	data_context.ptr += strnlen((char *)(data_context.ptr), DNS_MAX_CNAME_LEN) + 1;

	if (rr_len > rrs->len) {
		return -1;
	}
	_dns_write_short(&rr_len_ptr, ret);

	return 0;
}

static int _dns_decode_SOA(struct dns_context *context, struct dns_soa *soa)
{
	int ret = 0;
	ret = _dns_decode_domain(context, soa->mname, DNS_MAX_CNAME_LEN - 1);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_decode_domain(context, soa->rname, DNS_MAX_CNAME_LEN - 1);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 20) {
		return -1;
	}

	soa->serial = _dns_read_int(&context->ptr);
	soa->refresh = _dns_read_int(&context->ptr);
	soa->retry = _dns_read_int(&context->ptr);
	soa->expire = _dns_read_int(&context->ptr);
	soa->minimum = _dns_read_int(&context->ptr);

	return 0;
}

static int _dns_encode_SOA(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_len = 0;
	unsigned char *rr_len_ptr = NULL;
	struct dns_context data_context;

	_dns_init_context_by_rrs(rrs, &data_context);
	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_rr_head(context, domain, qtype, qclass, ttl, rr_len, &rr_len_ptr);
	if (ret < 0) {
		return -1;
	}

	rr_len = 0;
	/* mname */
	ret = _dns_encode_domain(context, (char *)data_context.ptr);
	if (ret < 0) {
		return -1;
	}
	rr_len += ret;
	data_context.ptr += strnlen((char *)(data_context.ptr), DNS_MAX_CNAME_LEN) + 1;

	/* rname */
	ret = _dns_encode_domain(context, (char *)data_context.ptr);
	if (ret < 0) {
		return -1;
	}

	rr_len += ret;
	data_context.ptr += strnlen((char *)(data_context.ptr), DNS_MAX_CNAME_LEN) + 1;
	if (rr_len > rrs->len) {
		return -1;
	}

	rr_len += 20;
	_dns_write_short(&rr_len_ptr, rr_len);
	if (_dns_left_len(context) < 20) {
		return -1;
	}

	_dns_write_int(&context->ptr, *(unsigned int *)data_context.ptr);
	data_context.ptr += 4;
	_dns_write_int(&context->ptr, *(unsigned int *)data_context.ptr);
	data_context.ptr += 4;
	_dns_write_int(&context->ptr, *(unsigned int *)data_context.ptr);
	data_context.ptr += 4;
	_dns_write_int(&context->ptr, *(unsigned int *)data_context.ptr);
	data_context.ptr += 4;
	_dns_write_int(&context->ptr, *(unsigned int *)data_context.ptr);
	data_context.ptr += 4;

	return 0;
}

static int _dns_decode_opt_ecs(struct dns_context *context, struct dns_opt_ecs *ecs)
{
	// TODO

	int len = 0;
	if (_dns_left_len(context) < 4) {
		return -1;
	}

	ecs->family = _dns_read_short(&context->ptr);
	ecs->source_prefix = _dns_read_char(&context->ptr);
	ecs->scope_prefix = _dns_read_char(&context->ptr);
	len = (ecs->source_prefix / 8);
	len += (ecs->source_prefix % 8 > 0) ? 1 : 0;

	if (_dns_left_len(context) < len || len > (int)sizeof(ecs->addr)) {
		return -1;
	}

	memcpy(ecs->addr, context->ptr, len);
	context->ptr += len;

	tlog(TLOG_DEBUG, "ECS: family:%d, source_prefix:%d, scope_prefix:%d, len:%d", ecs->family, ecs->source_prefix,
		 ecs->scope_prefix, len);
	tlog(TLOG_DEBUG, "%d.%d.%d.%d", ecs->addr[0], ecs->addr[1], ecs->addr[2], ecs->addr[3]);

	return 0;
}

static int _dns_decode_opt_cookie(struct dns_context *context, struct dns_opt_cookie *cookie)
{
	// TODO
	int len = _dns_left_len(context);
	if (len < 8) {
		return -1;
	}

	len = 8;
	memcpy(cookie->client_cookie, context->ptr, len);
	context->ptr += len;

	len = _dns_left_len(context);
	if (len == 0) {
		cookie->server_cookie_len = 0;
		return 0;
	}

	if (len < 8) {
		return -1;
	}

	memcpy(cookie->server_cookie, context->ptr, len);
	cookie->server_cookie_len = len;
	context->ptr += len;

	tlog(TLOG_DEBUG, "OPT COOKIE");
	return 0;
}

static int _dns_encode_OPT(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret = 0;
	int opt_code = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_context data_context;
	int rr_len = 0;
	int ttl = 0;
	struct dns_opt *dns_opt = NULL;

	_dns_init_context_by_rrs(rrs, &data_context);
	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &opt_code, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (rr_len < (int)sizeof(*dns_opt)) {
		return -1;
	}

	if (_dns_left_len(context) < (rr_len)) {
		return -1;
	}

	dns_opt = (struct dns_opt *)data_context.ptr;
	_dns_write_short(&context->ptr, dns_opt->code);
	_dns_write_short(&context->ptr, dns_opt->length);

	if (_dns_left_len(context) < dns_opt->length) {
		return -1;
	}

	switch (dns_opt->code) {
	case DNS_OPT_T_ECS: {
		struct dns_opt_ecs *ecs = (struct dns_opt_ecs *)&(dns_opt->data);
		_dns_write_short(&context->ptr, ecs->family);
		_dns_write_char(&context->ptr, ecs->source_prefix);
		_dns_write_char(&context->ptr, ecs->scope_prefix);
		memcpy(context->ptr, ecs->addr, dns_opt->length - 4);
		context->ptr += dns_opt->length - 4;
	} break;
	default:
		memcpy(context->ptr, dns_opt->data, dns_opt->length);
		context->ptr += dns_opt->length;
		break;
	}
	return 0;
}

static int _dns_get_opts_data_len(struct dns_packet *packet, struct dns_rrs *rrs, int count)
{
	int i = 0;
	int len = 0;
	int opt_code = 0;
	int qclass = 0;
	int ttl = 0;
	int ret = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_context data_context;
	int rr_len = 0;

	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		_dns_init_context_by_rrs(rrs, &data_context);
		ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &opt_code, &qclass, &ttl, &rr_len);
		if (ret < 0) {
			return -1;
		}

		len += rr_len;
	}

	return len;
}

static int _dns_encode_opts(struct dns_packet *packet, struct dns_context *context, struct dns_rrs *rrs, int count)
{
	int i = 0;
	int len = 0;
	int ret = 0;
	unsigned int rcode = 0;
	int rr_len = 0;
	int payloadsize = packet->payloadsize;
	unsigned char *rr_len_ptr = NULL;

	rr_len = _dns_get_opts_data_len(packet, rrs, count);
	if (rr_len < 0) {
		return -1;
	}

	if (payloadsize < DNS_DEFAULT_PACKET_SIZE) {
		payloadsize = DNS_DEFAULT_PACKET_SIZE;
	}

	ret = _dns_encode_rr_head(context, "", DNS_T_OPT, payloadsize, rcode, rr_len, &rr_len_ptr);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < rr_len) {
		return -1;
	}

	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_OPT(context, rrs);
		if (len < 0) {
			return -1;
		}
	}

	return 0;
}

static int _dns_decode_opt(struct dns_context *context, dns_rr_type type, unsigned int ttl, int rr_len)
{
	unsigned short opt_code = 0;
	unsigned short opt_len = 0;
	unsigned short ercode = (ttl >> 16) & 0xFFFF;
	unsigned short ever = (ttl)&0xFFFF;
	unsigned char *start = context->ptr;
	struct dns_packet *packet = context->packet;
	int ret = 0;

	UNUSED(ever);

	/*
		 Field Name   Field Type     Description
	 ------------------------------------------------------
	 NAME         domain name    empty (root domain)
	 TYPE         u_int16_t      OPT
	 CLASS        u_int16_t      sender's UDP payload size
	 TTL          u_int32_t      extended RCODE and flags
	 RDLEN        u_int16_t      describes RDATA
	 RDATA        octet stream   {attribute,value} pairs

					 +0 (MSB)                            +1 (LSB)
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0: |                          OPTION-CODE                          |
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  2: |                         OPTION-LENGTH                         |
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  4: |                                                               |
	 /                          OPTION-DATA                          /
	 /                                                               /
	 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

	TTL
				 +0 (MSB)                            +1 (LSB)
	  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   0: |         EXTENDED-RCODE        |            VERSION            |
	  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   2: |                               Z                               |
	  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	*/

	if (ercode != 0) {
		tlog(TLOG_ERROR, "extend rcode invalid.");
		return -1;
	}

	while (context->ptr - start < rr_len) {
		if (_dns_left_len(context) < 4) {
			tlog(TLOG_WARN, "data length is invalid, %d:%d", _dns_left_len(context),
				 (int)(context->ptr - context->data));
			return -1;
		}
		opt_code = _dns_read_short(&context->ptr);
		opt_len = _dns_read_short(&context->ptr);

		if (_dns_left_len(context) < opt_len) {
			tlog(TLOG_ERROR, "read opt data failed, opt_code = %d, opt_le = %d", opt_code, opt_len);
			return -1;
		}

		tlog(TLOG_DEBUG, "opt type %d", opt_code);
		switch (opt_code) {
		case DNS_OPT_T_ECS: {
			struct dns_opt_ecs ecs;
			ret = _dns_decode_opt_ecs(context, &ecs);
			if (ret != 0) {
				tlog(TLOG_ERROR, "decode ecs failed.");
				return -1;
			}

			ret = dns_add_OPT_ECS(packet, &ecs);
			if (ret != 0) {
				tlog(TLOG_ERROR, "add ecs failed.");
				return -1;
			}
		} break;
		case DNS_OPT_T_COOKIE: {
			struct dns_opt_cookie cookie;
			ret = _dns_decode_opt_cookie(context, &cookie);
			if (ret != 0) {
				tlog(TLOG_ERROR, "decode cookie failed.");
				return -1;
			}
		} break;
		default:
			context->ptr += opt_len;
			tlog(TLOG_DEBUG, "DNS opt type = %d not supported", opt_code);
			break;
		}
	}

	return 0;
}

static int _dns_decode_qd(struct dns_context *context)
{
	struct dns_packet *packet = context->packet;
	int len = 0;
	int qtype = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN];

	len = _dns_decode_qr_head(context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
	if (len < 0) {
		return -1;
	}

	len = dns_add_domain(packet, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}

	return 0;
}

static int _dns_decode_an(struct dns_context *context, dns_rr_type type)
{
	int ret = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	int rr_len = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = context->packet;
	unsigned char *start = NULL;

	/* decode rr head */
	ret = _dns_decode_rr_head(context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		tlog(TLOG_DEBUG, "decode head failed.");
		return -1;
	}
	start = context->ptr;

	/* decode answer */
	switch (qtype) {
	case DNS_T_A: {
		unsigned char addr[DNS_RR_A_LEN];
		ret = _dns_decode_raw(context, addr, sizeof(addr));
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode A failed, %s", domain);
			return -1;
		}

		ret = dns_add_A(packet, type, domain, ttl, addr);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add A failed, %s", domain);
			return -1;
		}
	} break;
	case DNS_T_CNAME: {
		char cname[DNS_MAX_CNAME_LEN];
		ret = _dns_decode_CNAME(context, cname, DNS_MAX_CNAME_LEN);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode CNAME failed, %s", domain);
			return -1;
		}

		ret = dns_add_CNAME(packet, type, domain, ttl, cname);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add CNAME failed, %s", domain);
			return -1;
		}
	} break;
	case DNS_T_SOA: {
		struct dns_soa soa;
		ret = _dns_decode_SOA(context, &soa);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode SOA failed, %s", domain);
			return -1;
		}

		ret = dns_add_SOA(packet, type, domain, ttl, &soa);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add SOA failed, %s", domain);
			return -1;
		}
	} break;
	case DNS_T_NS: {
		char ns[DNS_MAX_CNAME_LEN];
		ret = _dns_decode_CNAME(context, ns, DNS_MAX_CNAME_LEN);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode NS failed, %s", domain);
			return -1;
		}

		ret = dns_add_NS(packet, type, domain, ttl, ns);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add NS failed, %s", domain);
			return -1;
		}
	} break;
	case DNS_T_PTR: {
		char name[DNS_MAX_CNAME_LEN];
		ret = _dns_decode_CNAME(context, name, DNS_MAX_CNAME_LEN);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode PTR failed, %s", domain);
			return -1;
		}

		ret = dns_add_PTR(packet, type, domain, ttl, name);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add PTR failed, %s", domain);
			return -1;
		}
	} break;
	case DNS_T_AAAA: {
		unsigned char addr[DNS_RR_AAAA_LEN];
		ret = _dns_decode_raw(context, addr, sizeof(addr));
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode AAAA failed, %s", domain);
			return -1;
		}

		ret = dns_add_AAAA(packet, type, domain, ttl, addr);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add AAAA failed, %s", domain);
			return -1;
		}
	} break;
	case DNS_T_OPT: {
		unsigned char *opt_start = context->ptr;
		ret = _dns_decode_opt(context, type, ttl, rr_len);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode opt failed, %s", domain);
			return -1;
		}

		if (context->ptr - opt_start != rr_len) {
			tlog(TLOG_ERROR, "opt length mismatch, %s\n", domain);
			return -1;
		}

		dns_set_OPT_payload_size(packet, qclass);
	} break;
	default: {
		unsigned char raw_data[1024];
		if (_dns_left_len(context) < rr_len || rr_len >= (int)sizeof(raw_data)) {
			tlog(TLOG_DEBUG, "length mismatch\n");
			return -1;
		}

		ret = _dns_decode_raw(context, raw_data, rr_len);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode A failed, %s", domain);
			return -1;
		}

		ret = _dns_add_RAW(packet, type, qtype, domain, ttl, raw_data, rr_len);
		if (ret < 0) {
			tlog(TLOG_ERROR, "add raw failed, %s", domain);
			return -1;
		}

		tlog(TLOG_DEBUG, "DNS type = %d not supported", qtype);
		break;
	}
	}

	if (context->ptr - start != rr_len) {
		tlog(TLOG_ERROR, "length mismatch, %s, %ld:%d", domain, (long)(context->ptr - start), rr_len);
		return -1;
	}

	return 0;
}

static int _dns_encode_qd(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret = 0;
	int qtype = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_context data_context;

	_dns_init_context_by_rrs(rrs, &data_context);
	ret = _dns_get_qr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_qr_head(context, domain, qtype, qclass);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int _dns_encode_an(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret = 0;
	switch (rrs->type) {
	case DNS_T_A:
	case DNS_T_AAAA: {
		ret = _dns_encode_raw(context, rrs);
		if (ret < 0) {
			return -1;
		}
	} break;
	case DNS_T_CNAME:
	case DNS_T_PTR:
		ret = _dns_encode_CNAME(context, rrs);
		if (ret < 0) {
			return -1;
		}
		break;
	case DNS_T_SOA:
		ret = _dns_encode_SOA(context, rrs);
		if (ret < 0) {
			return -1;
		}
		break;
	default:
		ret = _dns_encode_raw(context, rrs);
		if (ret < 0) {
			return -1;
		}
		break;
	}

	return 0;
}

static int _dns_decode_body(struct dns_context *context)
{
	struct dns_packet *packet = context->packet;
	struct dns_head *head = &packet->head;
	int i = 0;
	int ret = 0;
	int count = 0;

	count = head->qdcount;
	head->qdcount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_decode_qd(context);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "decode qd failed.");
			return -1;
		}
	}

	count = head->ancount;
	head->ancount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_decode_an(context, DNS_RRS_AN);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "decode an failed.");
			return -1;
		}
	}

	count = head->nscount;
	head->nscount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_decode_an(context, DNS_RRS_NS);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "decode ns failed.");
			return -1;
		}
	}

	count = head->nrcount;
	head->nrcount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_decode_an(context, DNS_RRS_NR);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "decode nr failed.");
			return -1;
		}
	}

	return 0;
}

static int _dns_encode_body(struct dns_context *context)
{
	struct dns_packet *packet = context->packet;
	struct dns_head *head = &packet->head;
	int i = 0;
	int len = 0;
	struct dns_rrs *rrs = NULL;
	int count = 0;

	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &count);
	head->qdcount = count;
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_qd(context, rrs);
		if (len < 0) {
			return -1;
		}
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	head->ancount = count;
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_an(context, rrs);
		if (len < 0) {
			return -1;
		}
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_NS, &count);
	head->nscount = count;
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_an(context, rrs);
		if (len < 0) {
			return -1;
		}
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_NR, &count);
	head->nrcount = count;
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_an(context, rrs);
		if (len < 0) {
			return -1;
		}
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_OPT, &count);
	if (count > 0 || packet->payloadsize > 0) {
		len = _dns_encode_opts(packet, context, rrs, count);
		if (len < 0) {
			return -1;
		}
		head->nrcount++;
	}

	return 0;
}

int dns_packet_init(struct dns_packet *packet, int size, struct dns_head *head)
{
	struct dns_head *init_head = &packet->head;
	if (size < (int)sizeof(*packet)) {
		return -1;
	}

	memset(packet, 0, size);
	packet->size = size;
	init_head->id = head->id;
	init_head->qr = head->qr;
	init_head->opcode = head->opcode;
	init_head->aa = head->aa;
	init_head->tc = head->tc;
	init_head->rd = head->rd;
	init_head->ra = head->ra;
	init_head->rcode = head->rcode;
	packet->questions = DNS_RR_END;
	packet->answers = DNS_RR_END;
	packet->nameservers = DNS_RR_END;
	packet->additional = DNS_RR_END;
	packet->optional = DNS_RR_END;
	packet->optcount = 0;
	packet->payloadsize = 0;

	return 0;
}

int dns_decode(struct dns_packet *packet, int maxsize, unsigned char *data, int size)
{
	struct dns_head *head = &packet->head;
	struct dns_context context;
	int ret = 0;

	memset(&context, 0, sizeof(context));
	memset(packet, 0, sizeof(*packet));

	context.data = data;
	context.packet = packet;
	context.ptr = data;
	context.maxsize = size;
	context.namedict = &packet->namedict;

	ret = dns_packet_init(packet, maxsize, head);
	if (ret != 0) {
		return -1;
	}

	ret = _dns_decode_head(&context);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_decode_body(&context);
	if (ret < 0) {
		tlog(TLOG_DEBUG, "decode body failed.\n");
		return -1;
	}

	packet->size = context.ptr - context.data + sizeof(*packet);

	return 0;
}

int dns_encode(unsigned char *data, int size, struct dns_packet *packet)
{
	int ret = 0;
	struct dns_context context;
	struct dns_packet_dict namedict;

	memset(&context, 0, sizeof(context));
	memset(&namedict, 0, sizeof(namedict));
	context.data = data;
	context.packet = packet;
	context.ptr = data;
	context.maxsize = size;
	context.namedict = &namedict;

	ret = _dns_encode_head(&context);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_body(&context);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_head_count(&context);
	if (ret < 0) {
		return -1;
	}

	return context.ptr - context.data;
}

static int _dns_update_an(struct dns_context *context, dns_rr_type type, struct dns_update_param *param)
{
	int ret = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	int rr_len = 0;
	char domain[DNS_MAX_CNAME_LEN];
	unsigned char *start = NULL;

	/* decode rr head */
	ret = _dns_decode_rr_head(context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		tlog(TLOG_DEBUG, "decode head failed.");
		return -1;
	}

	start = context->ptr;
	switch (qtype) {
	case DNS_T_OPT:
		break;
	default: {
		unsigned char *ttl_ptr = start - sizeof(int) - sizeof(short);
		if (param->ip_ttl < 0) {
			break;
		}
		_dns_write_int(&ttl_ptr, param->ip_ttl);
	} break;
	}
	context->ptr += rr_len;
	if (context->ptr - start != rr_len) {
		tlog(TLOG_ERROR, "length mismatch , %s, %ld:%d", domain, (long)(context->ptr - start), rr_len);
		return -1;
	}

	return 0;
}

static int _dns_update_body(struct dns_context *context, struct dns_update_param *param)
{
	struct dns_packet *packet = context->packet;
	struct dns_head *head = &packet->head;
	int i = 0;
	int ret = 0;
	int count = 0;

	count = head->qdcount;
	head->qdcount = 0;
	for (i = 0; i < count; i++) {
		char domain[DNS_MAX_CNAME_LEN];
		int qtype = 0;
		int qclass = 0;
		int len = 0;
		len = _dns_decode_qr_head(context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
		if (len < 0) {
			tlog(TLOG_DEBUG, "update qd failed.");
			return -1;
		}
	}

	count = head->ancount;
	head->ancount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_update_an(context, DNS_RRS_AN, param);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "update an failed.");
			return -1;
		}
	}

	count = head->nscount;
	head->nscount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_update_an(context, DNS_RRS_NS, param);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "update ns failed.");
			return -1;
		}
	}

	count = head->nrcount;
	head->nrcount = 0;
	for (i = 0; i < count; i++) {
		ret = _dns_update_an(context, DNS_RRS_NR, param);
		if (ret < 0) {
			tlog(TLOG_DEBUG, "update nr failed.");
			return -1;
		}
	}

	return 0;
}

static int _dns_update_id(unsigned char *data, int size, struct dns_update_param *param)
{
	unsigned char *ptr = data;
	_dns_write_short(&ptr, param->id);
	return 0;
}

int dns_packet_update(unsigned char *data, int size, struct dns_update_param *param)
{
	struct dns_packet packet;
	int maxsize = sizeof(packet);
	struct dns_head *head = &packet.head;
	struct dns_context context;
	int ret = 0;

	memset(&context, 0, sizeof(context));
	memset(&packet, 0, sizeof(packet));

	context.data = data;
	context.packet = &packet;
	context.ptr = data;
	context.maxsize = size;

	ret = dns_packet_init(&packet, maxsize, head);
	if (ret != 0) {
		return -1;
	}

	ret = _dns_decode_head(&context);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_update_id(data, size, param);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_update_body(&context, param);
	if (ret < 0) {
		tlog(TLOG_DEBUG, "decode body failed.\n");
		return -1;
	}

	return 0;
}

#if 0
void dns_debug(void)
{
	unsigned char data[1024];
	ssize_t len;
	char buff[4096];

	int fd = open("dns.bin", O_RDWR);
	if (fd < 0) {
		return;
	}
	len = read(fd, data, 1024);
	close(fd);
	if (len < 0) {
		return;
	}

	struct dns_packet *packet = (struct dns_packet *)buff;
	if (dns_decode(packet, 4096, data, len) != 0) {
		tlog(TLOG_ERROR, "decode failed.\n");
	}

	memset(data, 0, sizeof(data));
	len = dns_encode(data, 1024, packet);
	if (len < 0) {
		tlog(TLOG_ERROR, "encode failed.");
	}

	fd = open("dns-cmp.bin", O_CREAT | O_TRUNC | O_RDWR, 0660);
	write(fd, data, len);
	close(fd);

	packet = (struct dns_packet *)buff;
	if (dns_decode(packet, 4096, data, len) != 0) {
		tlog(TLOG_ERROR, "decode failed.\n");
	}

}
#endif
