/*************************************************************************
 *
 * Copyright (C) 2018 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "dns.h"
#include "tlog.h"
#include <stdio.h>
#include <string.h>

#define QR_MASK 0x8000
#define OPCODE_MASK 0x7800
#define AA_MASK 0x0400
#define TC_MASK 0x0200
#define RD_MASK 0x0100
#define RA_MASK 0x0080
#define RCODE_MASK 0x000F

#define DNS_RR_END (0XFFFF)

short dns_read_short(unsigned char **buffer)
{
	unsigned short value;

	value = *((unsigned short *)(*buffer));
	*buffer += 2;

	return ntohs(value);
}

void dns_write_char(unsigned char **buffer, unsigned char value)
{
	**buffer = value;
	*buffer += 1;
}

unsigned char dns_read_char(unsigned char **buffer)
{
	unsigned char value = **buffer;
	*buffer += 1;
	return value;
}

void dns_write_short(unsigned char **buffer, unsigned short value)
{
	value = htons(value);
	*((unsigned short *)(*buffer)) = value;
	*buffer += 2;
}

void dns_write_int(unsigned char **buffer, unsigned int value)
{
	value = htons(value);
	*((unsigned int *)(*buffer)) = value;
	*buffer += 4;
}

unsigned int dns_read_int(unsigned char **buffer)
{
	unsigned int value;

	value = *((unsigned int *)(*buffer));
	*buffer += 4;

	return ntohs(value);
}

struct dns_rrs *dns_get_rrs_start(struct dns_packet *packet, dns_rr_type type, int *count)
{
	unsigned short start;
	struct dns_head *head = &packet->head;

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
	default:
		return NULL;
		break;
	}

	if (start == DNS_RR_END) {
		return NULL;
	}

	return (struct dns_rrs *)(packet->data + start);
}

struct dns_rrs *dns_get_rrs_next(struct dns_packet *packet, struct dns_rrs *rrs)
{
	if (rrs->next == DNS_RR_END) {
		return NULL;
	}

	return (struct dns_rrs *)(packet->data + rrs->next);
}

unsigned char *_dns_add_rrs_start(struct dns_packet *packet, int *maxlen)
{
	struct dns_rrs *rrs;
	unsigned char *end = packet->data + packet->len;
	rrs = (struct dns_rrs *)end;
	*maxlen = packet->size - packet->len - sizeof(*packet);
	if (packet->len >= packet->size - sizeof(*packet)) {
		return NULL;
	}
	return rrs->data;
}

int dns_rr_add_end(struct dns_packet *packet, int type, dns_type_t rtype, int len)
{
	struct dns_rrs *rrs;
	struct dns_rrs *rrs_next;
	struct dns_head *head = &packet->head;
	unsigned char *end = packet->data + packet->len;
	rrs = (struct dns_rrs *)end;
	unsigned short *count;
	unsigned short *start;

	if (packet->len + len > packet->size - sizeof(*packet)) {
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
	default:
		return -1;
		break;
	}

	if (*start != DNS_RR_END) {
		rrs_next = (struct dns_rrs *)(packet->data + *start);
		while (rrs_next->next != DNS_RR_END) {
			rrs_next = (struct dns_rrs *)(packet->data + rrs_next->next);
		}
		rrs_next->next = packet->len;
	} else {
		*start = packet->len;
	}

	rrs->next = DNS_RR_END; //*start;
	*count += 1;
	rrs->len = len;
	rrs->type = rtype;
	packet->len += len + sizeof(*rrs);
	return 0;
}

static inline int _dns_data_left_len(struct dns_data_context *data_context)
{
	return data_context->maxsize - (data_context->ptr - data_context->data);
}

int _dns_add_qr_head(struct dns_data_context *data_context, char *domain, int qtype, int qclass)
{
	while (1) {
		if (_dns_data_left_len(data_context) < 1) {
			return -1;
		}
		*data_context->ptr = *domain;
		if (*domain == '\0') {
			data_context->ptr++;
			break;
		}
		data_context->ptr++;
		domain++;
	}

	if (_dns_data_left_len(data_context) < 4) {
		return -1;
	}

	*((unsigned short *)(data_context->ptr)) = qtype;
	data_context->ptr += 2;

	*((unsigned short *)(data_context->ptr)) = qclass;
	data_context->ptr += 2;

	return 0;
}

int _dns_get_qr_head(struct dns_data_context *data_context, char *domain, int maxsize, int *qtype, int *qclass)
{
	int i;

	for (i = 0; i < maxsize; i++) {
		if (_dns_data_left_len(data_context) < 1) {
			return -1;
		}
		*domain = *data_context->ptr;
		if (*data_context->ptr == '\0') {
			domain++;
			data_context->ptr++;
			i++;
			break;
		}
		*domain = *data_context->ptr;
		domain++;
		data_context->ptr++;
	}

	if (_dns_data_left_len(data_context) < 4) {
		return -1;
	}

	*qtype = *((unsigned short *)(data_context->ptr));
	data_context->ptr += 2;

	*qclass = *((unsigned short *)(data_context->ptr));
	data_context->ptr += 2;

	return 0;
}

int _dns_add_rr_head(struct dns_data_context *data_context, char *domain, int qtype, int qclass, int ttl, int rr_len)
{
	int len = 0;

	len = _dns_add_qr_head(data_context, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}

	if (_dns_data_left_len(data_context) < 6) {
		return -1;
	}

	*((unsigned int *)(data_context->ptr)) = ttl;
	data_context->ptr += 4;

	*((unsigned short *)(data_context->ptr)) = rr_len;
	data_context->ptr += 2;

	return 0;
}

int _dns_get_rr_head(struct dns_data_context *data_context, char *domain, int maxsize, int *qtype, int *qclass, int *ttl, int *rr_len)
{
	int len = 0;

	len = _dns_get_qr_head(data_context, domain, maxsize, qtype, qclass);

	if (_dns_data_left_len(data_context) < 6) {
		return -1;
	}

	*ttl = *((unsigned int *)(data_context->ptr));
	data_context->ptr += 4;

	*rr_len = *((unsigned short *)(data_context->ptr));
	data_context->ptr += 2;

	return len;
}

int dns_add_RAW(struct dns_packet *packet, dns_rr_type rrtype, dns_type_t rtype, char *domain, int ttl, void *raw, int raw_len)
{
	int maxlen = 0;
	int len = 0;
	struct dns_data_context data_context;

	unsigned char *data = _dns_add_rrs_start(packet, &maxlen);
	if (data == NULL) {
		return -1;
	}

	if (raw_len >= maxlen) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = maxlen;

	len = _dns_add_rr_head(&data_context, domain, rtype, DNS_C_IN, ttl, raw_len);
	if (len < 0) {
		return -1;
	}

	memcpy(data_context.ptr, raw, raw_len);
	data_context.ptr += raw_len;
	len = data_context.ptr - data_context.data;

	return dns_rr_add_end(packet, rrtype, rtype, len);
}

int dns_get_RAW(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, void *raw, int raw_len)
{
	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int ret = 0;
	struct dns_data_context data_context;

	unsigned char *data = rrs->data;

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = rrs->len;

	ret = _dns_get_rr_head(&data_context, domain, maxsize, &qtype, &qclass, ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (qtype != rrs->type || rr_len > raw_len) {
		return -1;
	}

	memcpy(raw, data_context.ptr, rr_len);
	data_context.ptr += rr_len;

	return 0;
}

int dns_add_CNAME(struct dns_packet *packet, dns_rr_type type, char *domain, int ttl, char *cname)
{
	int rr_len = strnlen(cname, DNS_MAX_CNAME_LEN) + 1;
	return dns_add_RAW(packet, type, DNS_T_CNAME, domain, ttl, cname, rr_len);
}

int dns_get_CNAME(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size)
{
	return dns_get_RAW(rrs, domain, maxsize, ttl, cname, cname_size);
}

int dns_add_A(struct dns_packet *packet, dns_rr_type type, char *domain, int ttl, unsigned char addr[DNS_RR_A_LEN])
{
	return dns_add_RAW(packet, type, DNS_T_A, domain, ttl, addr, DNS_RR_A_LEN);
}

int dns_get_A(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[DNS_RR_A_LEN])
{
	return dns_get_RAW(rrs, domain, maxsize, ttl, addr, DNS_RR_A_LEN);
}

int dns_add_PTR(struct dns_packet *packet, dns_rr_type type, char *domain, int ttl, char *cname)
{
	int rr_len = strnlen(cname, DNS_MAX_CNAME_LEN) + 1;
	return dns_add_RAW(packet, type, DNS_T_PTR, domain, ttl, cname, rr_len);
}

int dns_get_PTR(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size)
{
	return dns_get_RAW(rrs, domain, maxsize, ttl, cname, cname_size);
}

int dns_add_NS(struct dns_packet *packet, dns_rr_type type, char *domain, int ttl, char *cname)
{
	int rr_len = strnlen(cname, DNS_MAX_CNAME_LEN) + 1;
	return dns_add_RAW(packet, type, DNS_T_NS, domain, ttl, cname, rr_len);
}

int dns_get_NS(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, char *cname, int cname_size)
{
	return dns_get_RAW(rrs, domain, maxsize, ttl, cname, cname_size);
}

int dns_add_AAAA(struct dns_packet *packet, dns_rr_type type, char *domain, int ttl, unsigned char addr[DNS_RR_AAAA_LEN])
{
	return dns_add_RAW(packet, type, DNS_T_AAAA, domain, ttl, addr, DNS_RR_AAAA_LEN);
}

int dns_get_AAAA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[DNS_RR_AAAA_LEN])
{
	return dns_get_RAW(rrs, domain, maxsize, ttl, addr, DNS_RR_AAAA_LEN);
}

/*
 * Format:
 * |DNS_NAME\0(string)|qtype(short)|qclass(short)|
 */
int dns_add_domain(struct dns_packet *packet, char *domain, int qtype, int qclass)
{
	int len = 0;
	int maxlen = 0;
	unsigned char *data = _dns_add_rrs_start(packet, &maxlen);
	struct dns_data_context data_context;

	if (data == NULL) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = maxlen;

	len = _dns_add_qr_head(&data_context, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}

	len = data_context.ptr - data_context.data;

	return dns_rr_add_end(packet, DNS_RRS_QD, DNS_T_CNAME, len);
}

int dns_get_domain(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *qclass)
{
	struct dns_data_context data_context;
	unsigned char *data = rrs->data;

	if (rrs->type != DNS_T_CNAME) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = rrs->len;

	return _dns_get_qr_head(&data_context, domain, maxsize, qtype, qclass);
}

static inline int _dns_left_len(struct dns_context *context)
{
	return context->maxsize - (context->ptr - context->data);
}

int _dns_decode_head(struct dns_context *context)
{
	unsigned int fields;
	int len = 12;
	struct dns_head *head = &context->packet->head;

	if (_dns_left_len(context) < len) {
		return -1;
	}

	head->id = dns_read_short(&context->ptr);
	fields = dns_read_short(&context->ptr);
	head->qr = (fields & QR_MASK) >> 15;
	head->opcode = (fields & OPCODE_MASK) >> 11;
	head->aa = (fields & AA_MASK) >> 10;
	head->tc = (fields & TC_MASK) >> 9;
	head->rd = (fields & RD_MASK) >> 8;
	head->ra = (fields & RA_MASK) >> 7;
	head->rcode = (fields & RCODE_MASK) >> 0;
	head->qdcount = dns_read_short(&context->ptr);
	head->ancount = dns_read_short(&context->ptr);
	head->nscount = dns_read_short(&context->ptr);
	head->nrcount = dns_read_short(&context->ptr);

	return 0;
}

int _dns_encode_head(struct dns_context *context)
{
	int len = 12;
	struct dns_head *head = &context->packet->head;

	if (_dns_left_len(context) < len) {
		return -1;
	}

	dns_write_short(&context->ptr, head->id);

	int fields = 0;
	fields |= (head->qr << 15) & QR_MASK;
	fields |= (head->opcode << 11) & OPCODE_MASK;
	fields |= (head->aa << 10) & AA_MASK;
	fields |= (head->tc << 9) & TC_MASK;
	fields |= (head->rd << 8) & RD_MASK;
	fields |= (head->ra << 7) & RA_MASK;
	fields |= (head->rcode << 0) & RCODE_MASK;
	dns_write_short(&context->ptr, fields);

	dns_write_short(&context->ptr, head->qdcount);
	dns_write_short(&context->ptr, head->ancount);
	dns_write_short(&context->ptr, head->nscount);
	dns_write_short(&context->ptr, head->nrcount);
	return len;
}

int _dns_decode_domain(struct dns_context *context, char *output, int size)
{
	int output_len = 0;
	int copy_len = 0;
	int len = *(context->ptr);
	unsigned char *ptr = context->ptr;
	int is_compressed = 0;

	while (1) {
		if (ptr > context->data + context->maxsize || ptr < context->data) {
			return -1;
		}
		len = *ptr;
		if (len == 0) {
			*(output - 1) = 0;
			ptr++;
			break;
		}

		if (len >= 0xC0) {
			len = dns_read_short(&ptr) & 0x3FFF;
			if (is_compressed == 0) {
				context->ptr = ptr;
			}
			ptr = context->data + len;
			if (context->maxsize - (ptr - context->data) < 0) {
				tlog(TLOG_ERROR, "length is not enouth %d:%d, %p, %p", context->maxsize, ptr-context->data, 
					context->ptr, context->data);
				return -1;
			}
			is_compressed = 1;
			continue;
		}

		if (context->maxsize - (ptr - context->data) < 0) {
			tlog(TLOG_ERROR, "length is not enouth %d:%d, %p, %p", context->maxsize, ptr-context->data, 
					context->ptr, context->data);
			return -1;
		}

		ptr++;
		if (output_len < size - 1) {
			copy_len = (len < size - output_len) ? len : size - 1 - output_len;
			if (context->maxsize - (ptr - context->data) < 0) {
				tlog(TLOG_ERROR, "length is not enouth %d:%d, %p, %p", context->maxsize, ptr-context->data, 
					context->ptr, context->data);
				return -1;
			}
			memcpy(output, ptr, copy_len);
		}

		ptr += len;
		output += len;
		output_len += len;
		*output = '.';
		output++;
	}

	if (is_compressed == 0) {
		context->ptr = ptr;
	}

	return 0;
}

int _dns_encode_domain(struct dns_context *context, char *domain)
{
	int num = 0;
	unsigned char *ptr_num = context->ptr++;

	while (_dns_left_len(context) > 1 && *domain != 0) {
		if (*domain == '.') {
			*ptr_num = num;
			num = 0;
			ptr_num = context->ptr;
			domain++;
			context->ptr++;
			continue;
		}
		*context->ptr = *domain;
		num++;
		context->ptr++;
		domain++;
	}

	*ptr_num = num;
	*(context->ptr) = 0;
	context->ptr++;
	return 0;
}

int _dns_decode_qr_head(struct dns_context *context, char *domain, int domain_size, int *qtype, int *qclass)
{
	int ret = 0;

	ret = _dns_decode_domain(context, domain, domain_size);
	if (ret < 0) {
		tlog(TLOG_ERROR, "decode domain failed.");
		return -1;
	}

	if (_dns_left_len(context) < 4) {
		tlog(TLOG_ERROR, "left length is not enough, %s.", domain);
		return -1;
	}

	*qtype = dns_read_short(&context->ptr);
	*qclass = dns_read_short(&context->ptr);

	return 0;
}

int _dns_encode_qr_head(struct dns_context *context, char *domain, int qtype, int qclass)
{
	int ret = 0;
	ret = _dns_encode_domain(context, domain);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 4) {
		return -1;
	}

	dns_write_short(&context->ptr, qtype);
	dns_write_short(&context->ptr, qclass);

	return 0;
}

int _dns_decode_rr_head(struct dns_context *context, char *domain, int domain_size, int *qtype, int *qclass, int *ttl, int *rr_len)
{
	int len = 0;

	len = _dns_decode_qr_head(context, domain, domain_size, qtype, qclass);
	if (len < 0) {
		tlog(TLOG_ERROR, "decode qr head failed.");
		return -1;
	}

	if (_dns_left_len(context) < 6) {
		tlog(TLOG_ERROR, "left length is not enough.");
		return -1;
	}

	*ttl = dns_read_int(&context->ptr);
	*rr_len = dns_read_short(&context->ptr);

	return 0;
}

int _dns_encode_rr_head(struct dns_context *context, char *domain, int qtype, int qclass, int ttl, int rr_len)
{
	int ret = 0;
	ret = _dns_encode_qr_head(context, domain, qtype, qclass);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 6) {
		return -1;
	}

	dns_write_int(&context->ptr, ttl);
	dns_write_short(&context->ptr, rr_len);

	return 0;
}

int _dns_decode_CNAME(struct dns_context *context, char *cname, int cname_size)
{
	int ret = 0;
	ret = _dns_decode_domain(context, cname, cname_size);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

int _dns_encode_CNAME(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_len;
	struct dns_data_context data_context;

	data_context.data = rrs->data;
	data_context.ptr = rrs->data;
	data_context.maxsize = rrs->len;

	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (rr_len > rrs->len) {
		return -1;
	}

	ret = _dns_encode_rr_head(context, domain, qtype, qclass, ttl, rr_len);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_domain(context, (char *)data_context.ptr);
	if (ret < 0) {
		return -1;
	}
	data_context.ptr += strnlen((char*)(data_context.ptr), DNS_MAX_CNAME_LEN) + 1;

	return 0;
}

int _dns_decode_A(struct dns_context *context, unsigned char addr[4])
{
	if (_dns_left_len(context) < DNS_RR_A_LEN) {
		return -1;
	}

	memcpy(addr, context->ptr, DNS_RR_A_LEN);
	context->ptr += DNS_RR_A_LEN;
	return 0;
}

int _dns_encode_A(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_len;
	struct dns_data_context data_context;

	data_context.data = rrs->data;
	data_context.ptr = rrs->data;
	data_context.maxsize = rrs->len;

	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (rr_len != DNS_RR_A_LEN) {
		return -1;
	}

	ret = _dns_encode_rr_head(context, domain, qtype, qclass, ttl, DNS_RR_A_LEN);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < DNS_RR_A_LEN) {
		return -1;
	}

	memcpy(context->ptr, data_context.ptr, DNS_RR_A_LEN);
	context->ptr += DNS_RR_A_LEN;
	data_context.ptr += DNS_RR_A_LEN;

	return 0;
}

int _dns_decode_PTR(struct dns_context *context, char *name, int name_size)
{
	int ret;

	ret = _dns_decode_domain(context, name, name_size);
	return ret;
}

int _dns_encode_PTR(struct dns_context *context, struct dns_rrs *rrs)
{
	return _dns_encode_CNAME(context, rrs);
}

int _dns_decode_AAAA(struct dns_context *context, unsigned char addr[DNS_RR_AAAA_LEN])
{
	if (_dns_left_len(context) < DNS_RR_AAAA_LEN) {
		return -1;
	}

	memcpy(addr, context->ptr, DNS_RR_AAAA_LEN);
	context->ptr += DNS_RR_AAAA_LEN;
	return 0;
}

int _dns_encode_AAAA(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int rr_len;
	struct dns_data_context data_context;

	data_context.data = rrs->data;
	data_context.ptr = rrs->data;
	data_context.maxsize = rrs->len;

	ret = _dns_get_rr_head(&data_context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (rr_len != DNS_RR_AAAA_LEN) {
		return -1;
	}

	ret = _dns_encode_rr_head(context, domain, qtype, qclass, ttl, DNS_RR_AAAA_LEN);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < DNS_RR_AAAA_LEN) {
		return -1;
	}

	memcpy(context->ptr, data_context.ptr, DNS_RR_AAAA_LEN);
	context->ptr += DNS_RR_AAAA_LEN;
	data_context.ptr += DNS_RR_AAAA_LEN;

	return 0;
}

int _dns_decode_NS(struct dns_context *context, unsigned char addr[4])
{
	if (_dns_left_len(context) < DNS_RR_A_LEN) {
		return -1;
	}

	memcpy(addr, context->ptr, DNS_RR_A_LEN);
	context->ptr += DNS_RR_A_LEN;
	return 0;
}

int _dns_encode_NS(struct dns_context *context, struct dns_rrs *rrs)
{
	return _dns_encode_CNAME(context, rrs);
}

int _dns_decode_qd(struct dns_context *context)
{
	struct dns_packet *packet = context->packet;
	int len;
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

int _dns_decode_an(struct dns_context *context, dns_rr_type type)
{
	int ret;
	int qtype = 0;
	int qclass = 0;
	int ttl;
	int rr_len = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = context->packet;
	unsigned char *start;

	ret = _dns_decode_rr_head(context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		tlog(TLOG_ERROR, "decode head failed.");
		return -1;
	}
	start = context->ptr;

	switch (qtype) {
	case DNS_T_A: {
		unsigned char addr[DNS_RR_A_LEN];
		ret = _dns_decode_A(context, addr);
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
		ret = _dns_decode_PTR(context, name, DNS_MAX_CNAME_LEN);
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
		ret = _dns_decode_AAAA(context, addr);
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
	default:
		context->ptr += rr_len;
		break;
	}

	if (context->ptr - start != rr_len) {
		tlog(TLOG_ERROR, "length mitchmatch , %s, %d:%d", domain, 
			context->ptr - start, rr_len);
		return -1;
	}

	return 0;
}

int _dns_encode_qd(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret;
	int qtype = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_data_context data_context;

	data_context.data = rrs->data;
	data_context.ptr = rrs->data;
	data_context.maxsize = rrs->len;

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

int _dns_encode_an(struct dns_context *context, struct dns_rrs *rrs)
{
	int ret;
	switch (rrs->type) {
	case DNS_T_A: {
		ret = _dns_encode_A(context, rrs);
		if (ret < 0) {
			return -1;
		}
	} break;
	case DNS_T_PTR:
		ret = _dns_encode_PTR(context, rrs);
		if (ret < 0) {
			return -1;
		}
		break;
	case DNS_T_AAAA:
		ret = _dns_encode_AAAA(context, rrs);
		if (ret < 0) {
			return -1;
		}
		break;
	default:
		break;
	}

	return 0;
}

int _dns_decode_body(struct dns_context *context)
{
	struct dns_packet *packet = context->packet;
	struct dns_head *head = &packet->head;
	int i = 0;
	int ret = 0;

	for (i = 0; i < head->qdcount; i++) {
		ret = _dns_decode_qd(context);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode qd failed.");
			return -1;
		}
		head->qdcount--;
	}

	for (i = 0; i < head->ancount; i++) {
		ret = _dns_decode_an(context, DNS_RRS_AN);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode an failed.");
			return -1;
		}
		head->ancount--;
	}

	for (i = 0; i < head->nscount; i++) {
		ret = _dns_decode_an(context, DNS_RRS_NS);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode ns failed.");
			return -1;
		}
		head->nscount--;
	}

	for (i = 0; i < head->nrcount; i++) {
		ret = _dns_decode_an(context, DNS_RRS_NR);
		if (ret < 0) {
			tlog(TLOG_ERROR, "decode nr failed.");
			return -1;
		}
		head->nrcount--;
	}

	return 0;
}

int _dns_encode_body(struct dns_context *context)
{
	struct dns_packet *packet = context->packet;
	struct dns_head *head = &packet->head;
	int i = 0;
	int len = 0;
	struct dns_rrs *rrs;
	int count;

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

	return 0;
}

int dns_packet_init(struct dns_packet *packet, int size, struct dns_head *head)
{
	struct dns_head *init_head = &packet->head;
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

	dns_packet_init(packet, maxsize, head);
	ret = _dns_decode_head(&context);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_decode_body(&context);
	if (ret < 0) {
		tlog(TLOG_ERROR, "decode body failed.\n");
		return -1;
	}

	return 0;
}

int dns_encode(unsigned char *data, int size, struct dns_packet *packet)
{
	int ret = 0;
	struct dns_context context;

	memset(&context, 0, sizeof(context));
	context.data = data;
	context.packet = packet;
	context.ptr = data;
	context.maxsize = size;

	ret = _dns_encode_head(&context);
	if (ret < 0) {
		return -1;
	}

	ret = _dns_encode_body(&context);
	if (ret < 0) {
		return -1;
	}

	return context.ptr - context.data;
}
