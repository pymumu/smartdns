#ifndef FAST_PING_H
#define FAST_PING_H

#include <sys/time.h>
#include <netdb.h>
#ifdef __cpluscplus
extern "C" {
#endif

typedef enum {
	FAST_PING_ICMP = 1,
	FAST_PING_TCP,
	FAST_PING_UDP
} FAST_PING_TYPE;

typedef enum {
	PING_RESULT_RESPONSE = 1,
	PING_RESULT_TIMEOUT = 2,
} FAST_PING_RESULT;

typedef void (*fast_ping_result)(const char *host, FAST_PING_RESULT result, struct sockaddr *addr, socklen_t addr_len, int seqno, struct timeval *tv, void *userptr);

int fast_ping_start(const char *host, int count, int timeout, fast_ping_result ping_callback, void *userptr);

int fast_ping_stop(const char *host);

int fast_ping_init();

void fast_ping_exit();

#ifdef __cpluscplus
}
#endif

#endif // !FAST_PING_H
