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

struct dns_rrs *dns_rr_get_start(struct dns_packet *packet, int type, int *count)
{
    unsigned short start;
    struct dns_head *head = &packet->head;

    switch (type) {
    case DNS_RR_QD:
        *count = head->qdcount;
        start = packet->questions;
        break;
    case DNS_RR_AN:
        *count = head->ancount;
        start = packet->answers;
        break;
    case DNS_RR_NS:
        *count = head->nscount;
        start = packet->nameservers;
        break;
    case DNS_RR_NR:
        *count = head->nrcount;
        start = packet->additional;
        break;
    default:
        return NULL;
        break;
    }

    return (struct dns_rrs *)(packet->data + start);
}

struct dns_rrs *dns_rr_get_next(struct dns_packet *packet, struct dns_rrs *rrs)
{
    if (rrs->next == 0) {
        return NULL;
    }

    return (struct dns_rrs *)(packet->data + rrs->next);
}

unsigned char *dns_rr_add_start(struct dns_packet *packet, int *maxlen)
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

    if (packet->len + len > packet->size - sizeof(*packet)) {
        return -1;
    }

    switch (type) {
    case DNS_RR_QD:
        count = &head->qdcount;
        start = &packet->questions;
        break;
    case DNS_RR_AN:
        count = &head->ancount;
        start = &packet->answers;
        break;
    case DNS_RR_NS:
        count = &head->nscount;
        start = &packet->nameservers;
        break;
    case DNS_RR_NR:
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

int dns_decode_domain(char *output, int size, unsigned char *data)
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
    len = dns_decode_domain(domain, domain_size, data);
    data += len;
    *qtype = dns_read_short(&data);
    *qclass = dns_read_short(&data);

    return len;
}

/*
 * Format:
 * |DNS_NAME\0(string)|qtype(short)|qclass(short)|
 */
int dns_add_domain(struct dns_packet *packet, char *domain, int qtype, int qclass)
{
    int maxlen = 0;
    int i;
    int len = 0;
    unsigned char *data = dns_rr_add_start(packet, &maxlen);

    if (data == NULL) {
        return -1;
    }

    for (i = 0; i < maxlen - 4; i++) {
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
    *((unsigned short *)(data)) = qtype;
    data += 2;
    len += 2;

    *((unsigned short *)(data)) = qclass;
    data += 2;
    len += 2;

    return dns_rr_add_end(packet, DNS_RR_QD, DNS_T_CNAME, len);
}

int dns_add_A(struct dns_packet *packet, unsigned char addr[4])
{
    int maxlen = 0;
    int len = 0;
    unsigned char *data = dns_rr_add_start(packet, &maxlen);
    unsigned char *data_ptr = data;
    if (data == NULL) {
        return -1;
    }

	memcpy(data, addr, 4);
	data += 4;
	len += 4;

	return dns_rr_add_end(packet, DNS_RR_AN, DNS_T_A, len);
}

int dns_add_AAAA(struct dns_packet *packet, unsigned char addr[16])
{
    int maxlen = 0;
    int len = 0;
    unsigned char *data = dns_rr_add_start(packet, &maxlen);
    if (data == NULL) {
        return -1;
    }

	memcpy(data, addr, 4);
	data += 4;
	len += 4;

    return dns_rr_add_end(packet, DNS_RR_AN, DNS_T_AAAA, len);
}

int dns_get_domain(struct dns_rrs *rrs, char *domain, int maxsize, int *qtype, int *qclass)
{
    int i = 0;
    unsigned char *data = rrs->data;
    for (i = 0; i < maxsize; i++) {
        *domain = *data;
        if (*data == '\0') {
            domain++;
            data++;
            break;
        }
        *domain = *data;
        domain++;
        data++;
    }

    *qtype = *((unsigned short *)(data));
    data += 2;

    *qclass = *((unsigned short *)(data));
    data += 2;

    return 0;
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
        if (dns_add_domain(packet, name, qtype, qclass) != 0) {
            return -1;
        }
        head->qdcount--;
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

    struct dns_rrs *rrs;
    int count = 0;
    int i = 0;

    rrs = dns_rr_get_start(packet, DNS_RR_QD, &count);
    for (i = 0; i < count && rrs; i++, rrs = dns_rr_get_next(packet, rrs)) {
        char name[128];
        int qclass = 0;
        int qtype = 0;

        dns_get_domain(rrs, name, 128, &qtype, &qclass);

        printf("QR: %d, domain: %s, qtype = %d, qclass = %d\n", head->qr, name, qtype, qclass);
    }

    return ret;
}

int dns_packet_init(struct dns_packet *packet, int size)
{
    memset(packet, 0, size);
    packet->size = size;

    return 0;
}

int dns_encode(unsigned char *data, int size, struct dns_packet *packet)
{
    int rc;
    int len = 0;

    len = dns_encode_head(&data, &packet->head);

    while (1) {
        len = dns_encode_domain(data, size, "www.baidu.com");
        data += len;
        dns_write_short(&data, /*qType*/ 12);
        dns_write_short(&data, /*qClass*/ 1);
    }

    /*
	rc |= dns_encode_resource_records(packet->answers, data);
	rc |= dns_encode_resource_records(packet->nameservers, data);
	rc |= dns_encode_resource_records(packet->additional, data);
	*/
    return rc;
}