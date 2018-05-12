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
	return sizeof(*rrs) + len;
}

int _dns_add_qr_head(unsigned char *data, int maxlen, char *domain, int qtype, int qclass)
{
	int i;
	int len = 0;

	for (i = 0; i < maxlen; i++) {
		*data = *domain;
		if (*domain == '\0') {
			data++;
			i++;
			break;
		}
		data++;
		domain++;
	}
	len += i;

	if (maxlen - len < 4) {
		return -1;
	}

	*((unsigned short *)(data)) = qtype;
	data += 2;
	len += 2;

	*((unsigned short *)(data)) = qclass;
	data += 2;
	len += 2;

	return len;
}

int _dns_get_qr_head(unsigned char *data, char *domain, int maxsize, int *qtype, int *qclass)
{
	int i;
	int len = 0;
	for (i = 0; i < maxsize; i++) {
		*domain = *data;
		if (*data == '\0') {
			domain++;
			data++;
			i++;
			break;
		}
		*domain = *data;
		domain++;
		data++;
	}
	len += i;
	if (len >= maxsize) {
		return -1;
	}

	*qtype = *((unsigned short *)(data));
	data += 2;
	len += 2;

	*qclass = *((unsigned short *)(data));
	data += 2;
	len += 2;

	return len;
}

int _dns_add_rr_head(unsigned char *data, int maxlen, char *domain, int qtype, int qclass, int ttl, int rr_len)
{
	int len = 0;

	len = _dns_add_qr_head(data, maxlen, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}
	data += len;
	if (maxlen - len < 6) {
		return -1;
	}

	*((unsigned int *)(data)) = ttl;
	data += 4;
	len += 4;

	*((unsigned short *)(data)) = rr_len;
	data += 2;
	len += 2;

	return len;
}

int _dns_get_rr_head(unsigned char *data, char *domain, int maxsize, int *qtype, int *qclass, int *ttl, int *rr_len)
{
	int len = 0;

	len = _dns_get_qr_head(data, domain, maxsize, qtype, qclass);
	data += len;

	*ttl = *((unsigned int *)(data));
	data += 4;
	len += 4;

	*rr_len = *((unsigned short *)(data));
	data += 2;
	len += 2;

	return len;
}

int dns_add_A(struct dns_packet *packet, char *domain, int ttl, unsigned char addr[4])
{
	int maxlen = 0;
	int len = 0;

	unsigned char *data = _dns_add_rrs_start(packet, &maxlen);
	if (data == NULL) {
		return -1;
	}

	len = _dns_add_rr_head(data, maxlen, domain, DNS_T_A, DNS_C_IN, ttl, DNS_RR_A_LEN);
	if (len < 0) {
		return -1;
	}
	data += len;

	memcpy(data, addr, DNS_RR_A_LEN);
	data += DNS_RR_A_LEN;
	len += DNS_RR_A_LEN;

	return dns_rr_add_end(packet, DNS_RRS_AN, DNS_T_A, len);
}

int dns_get_A(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[4])
{
	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int len = 0;
	int total_len = 0;

	unsigned char *data = rrs->data;

	if (rrs->type != DNS_T_A) {
		return -1;
	}

	len = _dns_get_rr_head(data, domain, maxsize, &qtype, &qclass, ttl, &rr_len);
	if (len <= 0) {
		return -1;
	}
	data += len;
	total_len += len;

	if (qtype != DNS_T_A || rr_len != DNS_RR_A_LEN) {
		return -1;
	}

	memcpy(addr, data, DNS_RR_A_LEN);
	total_len += rr_len;
	data += rr_len;

	return total_len;
}

int dns_add_AAAA(struct dns_packet *packet, char *domain, int ttl, unsigned char addr[16])
{
	int maxlen = 0;
	int len = 0;
	unsigned char *data = _dns_add_rrs_start(packet, &maxlen);
	if (data == NULL) {
		return -1;
	}

	len = _dns_add_rr_head(data, maxlen, domain, DNS_T_AAAA, DNS_C_IN, ttl, DNS_RR_AAAA_LEN);
	if (len < 0) {
		return -1;
	}
	data += len;

	memcpy(data, addr, DNS_RR_AAAA_LEN);
	data += DNS_RR_AAAA_LEN;
	len += DNS_RR_AAAA_LEN;

	return dns_rr_add_end(packet, DNS_RRS_AN, DNS_T_AAAA, len);
}

int dns_get_AAAA(struct dns_rrs *rrs, char *domain, int maxsize, int *ttl, unsigned char addr[16])
{
	int qtype = 0;
	int qclass = 0;
	int rr_len = 0;
	int len = 0;
	int total_len = 0;

	if (rrs->type != DNS_T_AAAA) {
		return -1;
	}

	unsigned char *data = rrs->data;

	len = _dns_get_rr_head(data, domain, maxsize, &qtype, &qclass, ttl, &rr_len);
	if (len <= 0) {
		return -1;
	}
	data += len;
	total_len += len;

	if (qtype != DNS_T_AAAA || rr_len != DNS_RR_AAAA_LEN) {
		return -1;
	}

	memcpy(addr, rrs->data, DNS_RR_AAAA_LEN);
	total_len += DNS_RR_AAAA_LEN;

	return total_len;
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

	if (data == NULL) {
		return -1;
	}

	len = _dns_add_qr_head(data, maxlen, domain, qtype, qclass);
	if (len < 0) {
		return -1;
	}

	return dns_rr_add_end(packet, DNS_RRS_QD, DNS_T_CNAME, len);
}

int dns_get_domain(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *qclass)
{
	if (rrs->type != DNS_T_CNAME) {
		return -1;
	}

	return _dns_get_qr_head(rrs->data, domain, maxsize, qtype, qclass);
}

int _dns_decode_head(struct dns_head *head, unsigned char *data)
{
	unsigned int fields;
	unsigned char *start = data;
	unsigned char *end = data;

	head->id = dns_read_short(&data);
	fields = dns_read_short(&data);
	head->qr = (fields & QR_MASK) >> 15;
	head->opcode = (fields & OPCODE_MASK) >> 11;
	head->aa = (fields & AA_MASK) >> 10;
	head->tc = (fields & TC_MASK) >> 9;
	head->rd = (fields & RD_MASK) >> 8;
	head->ra = (fields & RA_MASK) >> 7;
	head->rcode = (fields & RCODE_MASK) >> 0;
	head->qdcount = dns_read_short(&data);
	head->ancount = dns_read_short(&data);
	head->nscount = dns_read_short(&data);
	head->nrcount = dns_read_short(&data);

	end = data;
	return end - start;
}

int _dns_encode_head(unsigned char *data, int size, struct dns_head *head)
{
	int len = 12;

	if (size < len) {
		return -1;
	}

	dns_write_short(&data, head->id);

	int fields = 0;
	fields |= (head->qr << 15) & QR_MASK;
	fields |= (head->rcode << 0) & RCODE_MASK;
	dns_write_short(&data, fields);

	dns_write_short(&data, head->qdcount);
	dns_write_short(&data, head->ancount);
	dns_write_short(&data, head->nscount);
	dns_write_short(&data, head->nrcount);
	return len;
}

int _dns_decode_domain(char *output, int size, unsigned char *data)
{
	int i = 0;
	int output_len = 0;
	int copy_len = 0;
	int total_len = 0;

	while (data[i]) {
		int len = data[i];

		if (i != 0) {
			*output = '.';
			output++;
		}

		i++;
		total_len++;
		if (output_len < size - 1) {
			copy_len = (len < size - output_len) ? len : size - 1 - output_len;
			memcpy(output, data + i, copy_len);
		}
		i += len;
		output += len;
		output_len += len;
		total_len += len;
	}

	*output = 0;
	total_len++;
	return total_len;
}

int _dns_encode_domain(unsigned char *output, int size, char *domain)
{
	int i = 0;
	int num = 0;
	int total_len = 0;
	unsigned char *ptr_num = output++;
	total_len++;
	while (i < size && *domain != 0) {
		if (*domain == '.') {
			*ptr_num = num;
			num = 0;
			ptr_num = output;
			domain++;
			output++;
			total_len++;
			continue;
		}
		*output = *domain;
		num++;
		output++;
		domain++;
		total_len++;
	}
	*ptr_num = num;
	*output = 0;
	total_len++;
	return total_len;
}

int _dns_decode_qr_head(unsigned char *data, int size, char *domain, int domain_size, int *qtype, int *qclass)
{
	int len = 0;
	len = _dns_decode_domain(domain, domain_size, data);
	if (len <= 0) {
		return -1;
	}

	data += len;
	*qtype = dns_read_short(&data);
	len += 2;
	*qclass = dns_read_short(&data);
	len += 2;

	return len;
}

int _dns_encode_qr_head(unsigned char *data, int size, char *domain, int qtype, int qclass)
{
	int len = 0;
	len = _dns_encode_domain(data, size, domain);
	if (len <= 0) {
		return -1;
	}
	data += len;

	if (size - len < 4) {
		return -1;
	}

	dns_write_short(&data, qtype);
	len += 2;
	dns_write_short(&data, qclass);
	len += 2;

	return len;
}

int _dns_decode_rr_head(unsigned char *data, int size, char *domain, int domain_size, int *qtype, int *qclass, int *ttl, int *rr_len)
{
	int len = 0;
	int total_len = 0;

	len = _dns_decode_qr_head(data, size, domain, domain_size, qtype, qclass);
	if (len <= 0) {
		return -1;
	}

	data += len;
	total_len += len;

	*ttl = dns_read_int(&data);
	len += 4;
	total_len += 4;

	*rr_len = dns_read_short(&data);
	len += 2;
	total_len += 2;

	return total_len;
}

int _dns_encode_rr_head(unsigned char *data, int size, char *domain, int qtype, int qclass, int ttl, int rr_len)
{
	int len = 0;
	int total_len = 0;
	len = _dns_encode_qr_head(data, size, domain, qtype, qclass);
	if (len <= 0) {
		return -1;
	}

	data += len;
	total_len += len;

	if (size - len < 6) {
		return -1;
	}

	dns_write_int(&data, ttl);
	len += 4;
	total_len += 4;

	dns_write_short(&data, rr_len);
	len += 2;
	total_len += 2;

	return total_len;
}

int _dns_decode_A(unsigned char addr[4], unsigned char *data)
{
	memcpy(addr, data, DNS_RR_A_LEN);
	return DNS_RR_A_LEN;
}

int _dns_encode_A(unsigned char *output, int size, struct dns_rrs *rrs)
{
	int len;
	int len_rrs;
	int total_len = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	unsigned char *data_rrs;
	int rr_len;

	data_rrs = rrs->data;
	len_rrs = _dns_get_rr_head(data_rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (len_rrs <= 0) {
		return -1;
	}
	data_rrs += len_rrs;

	if (rr_len != DNS_RR_A_LEN) {
		return -1;
	}

	len = _dns_encode_rr_head(output, size, domain, qtype, qclass, ttl, DNS_RR_A_LEN);
	if (len <= 0) {
		return -1;
	}
	output += len;
	total_len += len;

	if (size - total_len < rr_len + DNS_RR_A_LEN) {
		return -1;
	}

	memcpy(output, data_rrs, DNS_RR_A_LEN);
	output += DNS_RR_A_LEN;
	data_rrs += DNS_RR_A_LEN;
	total_len += DNS_RR_A_LEN;

	return total_len;
}

int _dns_decode_AAAA(unsigned char addr[DNS_RR_AAAA_LEN], unsigned char *data)
{
	memcpy(addr, data, DNS_RR_AAAA_LEN);
	return DNS_RR_AAAA_LEN;
}

int _dns_encode_AAAA(unsigned char *output, int size, struct dns_rrs *rrs)
{
	int len;
	int len_rrs;
	int total_len = 0;
	int qtype = 0;
	int qclass = 0;
	int ttl = 0;
	char domain[DNS_MAX_CNAME_LEN];
	unsigned char *data_rrs;
	int rr_len;

	data_rrs = rrs->data;
	len_rrs = _dns_get_rr_head(data_rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (len_rrs <= 0) {
		return -1;
	}
	data_rrs += len_rrs;

	if (rr_len != DNS_RR_AAAA_LEN) {
		return -1;
	}

	len = _dns_encode_rr_head(output, size, domain, qtype, qclass, ttl, DNS_RR_AAAA_LEN);
	if (len <= 0) {
		return -1;
	}
	output += len;
	total_len += len;

	if (size - total_len < rr_len + DNS_RR_AAAA_LEN) {
		return -1;
	}

	memcpy(output, data_rrs, DNS_RR_AAAA_LEN);
	output += DNS_RR_AAAA_LEN;
	data_rrs += DNS_RR_AAAA_LEN;
	total_len += DNS_RR_AAAA_LEN;

	return total_len;
}

int _dns_decode_qd(struct dns_packet *packet, unsigned char *data, int size)
{
	int len;
	int decode_len = 0;
	int qtype = 0;
	int qclass = 0;
	char domain[DNS_MAX_CNAME_LEN];

	int ttl;
	int rr_len;
	len = _dns_decode_qr_head(data, size, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
	if (len <= 0) {
		return -1;
	}
	decode_len += len;

	len = dns_add_domain(packet, domain, qtype, qclass);
	if ( len <= 0 ) {
		return -1;
	}

	return decode_len;
}

int _dns_decode_an(struct dns_packet *packet, unsigned char *data, int size)
{
	int len;
	int qtype = 0;
	int qclass = 0;
	int ttl;
	int rr_len = 0;
	char domain[DNS_MAX_CNAME_LEN];
	int decode_len = 0;

	len = _dns_decode_rr_head(data, size, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass, &ttl, &rr_len);
	if (len <= 0) {
		return -1;
	}

	data += len;
	decode_len += len;
	switch (qtype) {
	case DNS_T_A: {
		unsigned char addr[DNS_RR_A_LEN];
		len = _dns_decode_A(addr, data);
		if (len < 0) {
			return -1;
		}
		data += len;
		decode_len += len;
		len = dns_add_A(packet, domain, ttl, addr);
		if (len < 0) {
			return -1;
		}
	} break;
	case DNS_T_AAAA: {
		unsigned char addr[DNS_RR_AAAA_LEN];
		len = _dns_decode_AAAA(addr, data);
		if (len < 0) {
			return -1;
		}
		data += len;
		decode_len += len;
		len = dns_add_AAAA(packet, domain, ttl, addr);
		if (len < 0) {
			return -1;
		}
	} break;
	default:
		break;
	}

	return decode_len;
}

int _dns_encode_qd(unsigned char *data, int size, struct dns_rrs *rrs)
{
	int len;
	int len_rrs;
	int qtype = 0;
	int qclass = 0;
	int total_len = 0;
	char domain[DNS_MAX_CNAME_LEN];
	unsigned char *data_rrs = rrs->data;
	len_rrs = _dns_get_qr_head(data_rrs, domain, DNS_MAX_CNAME_LEN, &qtype, &qclass);
	if (len_rrs <= 0) {
		return -1;
	}

	len = _dns_encode_qr_head(data, size, domain, qtype, qclass);
	if (len <= 0) {
		return -1;
	}
	total_len += len;

	return total_len;
}

int _dns_encode_an(unsigned char *data, int size, struct dns_rrs *rrs)
{
	int len;
	int total_len = 0;
	switch (rrs->type) {
	case DNS_T_A: {
		len = _dns_encode_A(data, size, rrs);
		if (len < 0) {
			return -1;
		}
		total_len += len;
	} break;
	case DNS_T_AAAA:
		len = _dns_encode_AAAA(data, size, rrs);
		if (len < 0) {
			return -1;
		}
		total_len += len;
		break;
	default:
		break;
	}

	return total_len;
}

int _dns_decode_body(struct dns_packet *packet, unsigned char *data, int size)
{
	struct dns_head *head = &packet->head;
	int i = 0;
	int len = 0;
	int decode_len = 0;

	for (i = 0; i < head->qdcount; i++) {
		len = _dns_decode_qd(packet, data, size - decode_len);
		if (len <= 0) {
			return -1;
		}
		head->qdcount--;
		decode_len += len;
		data += len;
	}

	for (i = 0; i < head->ancount; i++) {
		len = _dns_decode_an(packet, data, size - decode_len);
		if (len <= 0) {
			return -1;
		}
		head->ancount--;
		decode_len += len;
		data += len;
	}

	return decode_len;
}

int _dns_encode_body(unsigned char *data, int size, struct dns_packet *packet)
{
	struct dns_head *head = &packet->head;
	int i = 0;
	int len = 0;
	int encode_len = 0;
	struct dns_rrs *rrs;
	int count;

	rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &count);
	head->qdcount = count;
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_qd(data, size - encode_len, rrs);
		if (len <= 0) {
			return -1;
		}
		encode_len += len;
		data += len;
	}

	rrs = dns_get_rrs_start(packet, DNS_RRS_AN, &count);
	head->ancount = count;
	for (i = 0; i < count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
		len = _dns_encode_an(data, size - encode_len, rrs);
		if (len <= 0) {
			return -1;
		}
		encode_len += len;
		data += len;
	}

	return encode_len;
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
	int decode_len = 0;
	int len = 0;

	memset(packet, 0, sizeof(*packet));
	dns_packet_init(packet, maxsize, head);
	len = _dns_decode_head(head, data);
	if (len < 0) {
		return -1;
	}
	data += len;
	decode_len += len;

	len = _dns_decode_body(packet, data, size - decode_len);
	if (len < 0) {
		return -1;
	}
	decode_len += len;

	return decode_len;
}

int dns_encode(unsigned char *data, int size, struct dns_packet *packet)
{
	int len = 0;
	int total_len = 0;

	len = _dns_encode_head(data, size, &packet->head);
	if (len <= 0) {
		return -1;
	}
	data += len;
	total_len += len;

	len = _dns_encode_body(data, size - len, packet);
	if (len <= 0) {
		return -1;
	}
	total_len += len;
	return total_len;
}
