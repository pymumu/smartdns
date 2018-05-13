#include "dns.h"
#include <stdio.h>
#include <string.h>

#define DNS_MAX_CNAME_LEN 128

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

struct dns_rrs *dns_get_rrs_start(struct dns_packet *packet, int type, int *count)
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

int dns_rr_add_end(struct dns_packet *packet, int type, dns_type_t rrtype, int len)
{
	struct dns_rrs *rrs;
	struct dns_head *head = &packet->head;
	unsigned char *end = packet->data + packet->len;
	rrs = (struct dns_rrs *)end;
	unsigned short *count;
	unsigned short *start;

	len += sizeof(*rrs);
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

	*count += 1;
	rrs->next = *start;
	rrs->len = len;
	rrs->type = rrtype;
	*start = packet->len;
	packet->len += len;
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

int dns_add_A(struct dns_packet *packet, char *domain, int ttl, unsigned char addr[4])
{
	int maxlen = 0;
	int len = 0;
	struct dns_data_context data_context;

	unsigned char *data = _dns_add_rrs_start(packet, &maxlen);
	if (data == NULL) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = maxlen;

	len = _dns_add_rr_head(&data_context, domain, DNS_T_A, DNS_C_IN, ttl, DNS_RR_A_LEN);
	if (len < 0) {
		return -1;
	}

	memcpy(data_context.ptr, addr, DNS_RR_A_LEN);
	data_context.ptr += DNS_RR_A_LEN;
	len = data_context.ptr - data_context.data;

	return dns_rr_add_end(packet, DNS_RRS_AN, DNS_T_A, len);
}

int dns_get_A(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[4])
{
	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int ret = 0;
	struct dns_data_context data_context;

	unsigned char *data = rrs->data;

	if (rrs->type != DNS_T_A) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = rrs->len;

	ret = _dns_get_rr_head(&data_context, domain, maxsize, &qtype, &qclass, ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (qtype != DNS_T_A || rr_len != DNS_RR_A_LEN) {
		return -1;
	}

	memcpy(addr, rrs->data, DNS_RR_A_LEN);

	return 0;
}

int dns_add_AAAA(struct dns_packet *packet, char *domain, int ttl, unsigned char addr[16])
{
	int maxlen = 0;
	int len = 0;
	struct dns_data_context data_context;

	unsigned char *data = _dns_add_rrs_start(packet, &maxlen);
	if (data == NULL) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = maxlen;

	len = _dns_add_rr_head(&data_context, domain, DNS_T_AAAA, DNS_C_IN, ttl, DNS_RR_AAAA_LEN);
	if (len < 0) {
		return -1;
	}

	memcpy(data_context.ptr, addr, DNS_RR_AAAA_LEN);
	data_context.ptr += DNS_RR_AAAA_LEN;
	len = data_context.ptr - data_context.data;

	return dns_rr_add_end(packet, DNS_RRS_AN, DNS_T_AAAA, len);
}

int dns_get_AAAA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[16])
{
	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int ret = 0;
	struct dns_data_context data_context;

	if (rrs->type != DNS_T_AAAA) {
		return -1;
	}

	unsigned char *data = rrs->data;

	if (rrs->type != DNS_T_AAAA) {
		return -1;
	}

	data_context.data = data;
	data_context.ptr = data;
	data_context.maxsize = rrs->len;

	ret = _dns_get_rr_head(&data_context, domain, maxsize, &qtype, &qclass, ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	if (qtype != DNS_T_AAAA || rr_len != DNS_RR_AAAA_LEN) {
		return -1;
	}

	memcpy(addr, rrs->data, DNS_RR_AAAA_LEN);

	return 0;
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

	while (*(context->ptr)) {
		if (_dns_left_len(context) < 1) {
			return -1;
		}

		context->ptr++;
		if (output_len < size - 1) {
			copy_len = (len < size - output_len) ? len : size - 1 - output_len;
			if (_dns_left_len(context) < copy_len) {
				return -1;
			}
			memcpy(output, context->ptr, copy_len);
		}

		context->ptr += len;
		output += len;
		output_len += len;

		len = *(context->ptr);
		if (len == 0) {
			break;
		}
		*output = '.';
		output++;

	}

	*output = 0;
	context->ptr++;

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
	*context->ptr = 0;
	return 0;
}

int _dns_decode_qr_head(struct dns_context *context, char *domain, int domain_size, int *qtype, int *qclass)
{
	int ret = 0;
	ret = _dns_decode_domain(context, domain, domain_size);
	if (ret < 0) {
		return -1;
	}

	if (_dns_left_len(context) < 4) {
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
		return -1;
	}

	if (_dns_left_len(context) < 6) {
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

	memcpy(context->ptr, rrs->data, DNS_RR_A_LEN);
	context->ptr += DNS_RR_A_LEN;

	return 0;
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

	memcpy(context->ptr, rrs->data, DNS_RR_AAAA_LEN);
	context->ptr += DNS_RR_AAAA_LEN;

	return 0;
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

int _dns_decode_an(struct dns_context *context)
{
	int ret;
	int qtype = 0;
	int qclass = 0;
	int ttl;
	int rr_len = 0;
	char domain[DNS_MAX_CNAME_LEN];
	struct dns_packet *packet = context->packet;

	ret = _dns_decode_rr_head(context, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (ret < 0) {
		return -1;
	}

	switch (qtype) {
	case DNS_T_A: {
		unsigned char addr[DNS_RR_A_LEN];
		ret = _dns_decode_A(context, addr);
		if (ret < 0) {
			return -1;
		}

		ret = dns_add_A(packet, domain, ttl, addr);
		if (ret < 0) {
			return -1;
		}
	} break;
	case DNS_T_AAAA: {
		unsigned char addr[DNS_RR_AAAA_LEN];
		ret = _dns_decode_AAAA(context, addr);
		if (ret < 0) {
			return -1;
		}

		ret = dns_add_AAAA(packet, domain, ttl, addr);
		if (ret < 0) {
			return -1;
		}
	} break;
	default:
		break;
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
			return -1;
		}
		head->qdcount--;
	}

	for (i = 0; i < head->ancount; i++) {
		ret = _dns_decode_an(context);
		if (ret < 0) {
			return -1;
		}
		head->ancount--;
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
	init_head->tc = 0;
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
