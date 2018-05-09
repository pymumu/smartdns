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

int dns_decode_head(struct dns_head *head, unsigned char **data)
{
	unsigned int fields;
	unsigned char *start = *data;
	unsigned char *end = start;

	head->id = dns_read_short(data);
	fields = dns_read_short(data);
	head->qr = (fields & QR_MASK) >> 15;
	head->opcode = (fields & OPCODE_MASK) >> 11;
	head->aa = (fields & AA_MASK) >> 10;
	head->tc = (fields & TC_MASK) >> 9;
	head->rd = (fields & RD_MASK) >> 8;
	head->ra = (fields & RA_MASK) >> 7;
	head->rcode = (fields & RCODE_MASK) >> 0;
	head->qdcount = dns_read_short(data);
	head->ancount = dns_read_short(data);
	head->nscount = dns_read_short(data);
	head->nrcount = dns_read_short(data);

	end = *data;
	return start - end;
}

int dns_encode_head(unsigned char **data, struct dns_head *head)
{
	dns_write_short(data, head->id);

	int fields = 0;
	fields |= (head->qr << 15) & QR_MASK;
	fields |= (head->rcode << 0) & RCODE_MASK;
	dns_write_short(data, fields);

	dns_write_short(data, head->qdcount);
	dns_write_short(data, head->ancount);
	dns_write_short(data, head->nscount);
	dns_write_short(data, head->nrcount);
	return 0;
}

int dns_get_domain(char *output, int size, unsigned char *data)
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

int dns_encode_domain(unsigned char *output, int size, char *domain)
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

int dns_decode_qd(unsigned char *data, int size, char *domain, int domain_size, int *qtype, int *qclass)
{
	int len = 0;
	len = dns_get_domain(domain, domain_size, data);
	data += len;
	*qtype = dns_read_short(&data);
	*qclass = dns_read_short(&data);

	return len;
}

int dns_decode_body(struct dns_packet *packet, unsigned char *data, int size)
{
	struct dns_head *head = &packet->head;
	int i = 0;
	int len = 0;
	int decode_len = 0;
	int qtype = 0;
	int qclass = 0;
	char name[DNS_MAX_CNAME_LEN];

	if (head->nrcount || head->nscount || head->ancount) {
		return -1;
	}

	for (i = 0; i < head->qdcount; i++) {
		len = dns_decode_qd(data, size - decode_len, name, DNS_MAX_CNAME_LEN, &qtype, &qclass);
		printf("QR: %d, domain: %s, qtype = %d, qclass = %d\n", head->qr, name, qtype, qclass);
		decode_len += len;
		data += len;
	}

	return 0;
}

int dns_decode(struct dns_packet *packet, unsigned char *data, int size)
{
	struct dns_head *head = &packet->head;
	int decode_len = 0;
	int ret = 0;

	decode_len = dns_decode_head(head, &data);
	ret = dns_decode_body(packet, data, size - decode_len);
	return ret;
}


int dns_encode(unsigned char *data, int size, struct dns_packet *packet)
{
	int rc;
	int len = 0;

	len = dns_encode_head(&data, &packet->head);

	while (1) {
		len = dns_encode_domain(data, size, "www.baidu.com");
		data += len;
		dns_write_short(&data, /*qType*/12);
		dns_write_short(&data, /*qClass*/ 1);
	}

	/*
	rc |= dns_encode_resource_records(packet->answers, data);
	rc |= dns_encode_resource_records(packet->nameservers, data);
	rc |= dns_encode_resource_records(packet->additional, data);
	*/
	return rc;
}