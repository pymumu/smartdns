#include "dns.h"

#define DNS_MAX_CNAME_LEN 128

int dns_decode_head(struct dns_head *head, struct idns_head *ihead)
{
	head->id = ntohs(ihead->id);
	head->opcode = (ihead->opcode >> 3) & 0x0F;
	head->query = (ihead->opcode & 0x80) != 0x80;
	head->aa = (ihead->opcode & 0x04) == 0x04;
	head->tc = (ihead->opcode & 0x02) == 0x02;
	head->rd = (ihead->opcode & 0x01) == 0x01;
	head->ra = (ihead->rcode & 0x80) == 0x80;
	head->z = (ihead->rcode & 0x40) == 0x40;
	head->ad = (ihead->rcode & 0x20) == 0x20;
	head->cd = (ihead->rcode & 0x10) == 0x10;
	head->rcode = (ihead->rcode & 0x0F);
	head->qdcount = ntohs(ihead->qdcount);
	head->ancount = ntohs(ihead->ancount);
	head->nscount = ntohs(ihead->nscount);
	head->nrcount = ntohs(ihead->arcount);

	return 0;
}

int dns_decode_rr(char *data, int size)
{
	int ret;
	int len = 0;

	return len;
}

int dns_get_domain(char *data, int size, char *output)
{
    int i = 0;

    while (data[i]) {
        int len = data[i];
		*output = '.';
		output++;
		i++;
		memcpy(output, data + i, len);
		i += len;
		output += len;
	}

    int qtype = (unsigned short) data[i+1];
    int qclass = (unsigned short) data[i+3];

	return 0;
}

int dns_decode_qd(char *data, int size)
{
	int ret;
	int len = 0;
	char name[DNS_MAX_CNAME_LEN];
	len = dns_get_domain(data, size, name);
	printf("%s\n", name);

	return len;
}

int dns_decode_body(struct dns_packet *packet, char *data, int size)
{
	struct dns_head *head = &packet->head;
	int i = 0;
	int len = 0;
	int decode_len = 0;

	for (i = 0; i < head->qdcount; i++) {
		len = dns_decode_qd(data, size - decode_len);

		decode_len += len;
		data += len;
	}

	for (i = 0; i < head->qdcount; i++) {
	}

	for (i = 0; i < head->qdcount; i++) {
	}

	for (i = 0; i < head->qdcount; i++) {
	}

	return 0;
}

int dns_decode(struct dns_packet *packet, char *data, int size)
{
	struct idns_head *ihead = (struct idns_head *)data;
	struct dns_head *head = &packet->head;
	int decode_len = 0;

	dns_decode_head(head, ihead);
	decode_len += sizeof(struct idns_head);
	data += sizeof(struct idns_head);
	dns_decode_body(packet, data, size - decode_len);
	return -1;
}