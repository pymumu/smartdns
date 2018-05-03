#ifndef _DNS_HEAD_H
#define _DNS_HEAD_H

#pragma pack(push, 1)

struct dns_head {
    unsigned short id; // identification number
    unsigned char rd : 1; // recursion desired
    unsigned char tc : 1; // truncated message
    unsigned char aa : 1; // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1; // query/response flag
    unsigned char rcode : 4; // response code
    unsigned char cd : 1; // checking disabled
    unsigned char ad : 1; // authenticated data
    unsigned char z : 1; // its z! reserved
    unsigned char ra : 1; // recursion available
    unsigned short qd_count; // number of question entries
    unsigned short an_count; // number of answer entries
    unsigned short ns_count; // number of authority entries
    unsigned short nr_count; // number of resource entries
};

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

#pragma pack(pop)

#endif