#include "dns_server.h"
#include "hashtable.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define DNS_MAX_EVENTS 256

#define DNS_INPACKET_SIZE 512

struct dns_server {
    int run;
    int epoll_fd;

    int fd;

    pthread_mutex_t map_lock;
    DECLARE_HASHTABLE(hostmap, 6);
};

static struct dns_server server;

static void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

void _dns_server_period_run()
{
}

static int _dns_server_process(struct timeval *now)
{
    int len;
    u_char inpacket[DNS_INPACKET_SIZE];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);

    len = recvfrom(server.fd, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
    if (len < 0) {
        fprintf(stderr, "recvfrom failed, %s\n", strerror(errno));
        goto errout;
    }

    return 0;
errout:
    return -1;
}

int dns_server_run(void)
{
    struct epoll_event events[DNS_MAX_EVENTS + 1];
    int num;
    int i;
    struct timeval last = { 0 };
    struct timeval now = { 0 };
    struct timeval diff = { 0 };
    uint millisec = 0;

    while (server.run) {
        diff = now;
        tv_sub(&diff, &last);
        millisec = diff.tv_sec * 1000 + diff.tv_usec / 1000;
        if (millisec >= 100) {
            _dns_server_period_run();
            last = now;
        }

        num = epoll_wait(server.epoll_fd, events, DNS_MAX_EVENTS, 100);
        if (num < 0) {
            gettimeofday(&now, 0);
            usleep(100000);
            continue;
        }

        if (num == 0) {
            gettimeofday(&now, 0);
            continue;
        }

        gettimeofday(&now, 0);
        for (i = 0; i < num; i++) {
            struct epoll_event *event = &events[i];
            _dns_server_process(&now);
        }
    }

    close(server.epoll_fd);
    server.epoll_fd = -1;

    return 0;
}

static struct addrinfo *_dns_server_getaddr(const char *host, int port, int type, int protocol)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_protocol = protocol;
    if (getaddrinfo(host, port, &hints, &result) != 0) {
        fprintf(stderr, "get addr info failed. %s\n", strerror(errno));
        goto errout;
    }

    return result;
errout:
    if (result) {
        freeaddrinfo(result);
    }
    return NULL;
}

int dns_server_socket(void)
{
    int fd = -1;
    struct addrinfo *gai = NULL;

    gai = _dns_server_getaddr(NULL, 53, SOCK_DGRAM, 0);

    fd = socket(gai->ai_family, gai->ai_socktype, gai->ai_protocol);
    if (fd < 0) {
        fprintf(stderr, "create socket failed.\n");
        goto errout;
    }

    if (bind(fd, ) != 0) {
        fprintf(stderr, "bind failed.\n");
        goto errout;
    }

    server.fd = fd;
    freeaddrinfo(gai);

    return 0;
errout:
    if (fd > 0) {
        close(fd);
    }

    if (gai) {
        freeaddrinfo(gai);
    }
    return -1;
}

int dns_server_init(void)
{
    pthread_attr_t attr;
    int epollfd = -1;
    int fd = -1;

    if (server.epoll_fd > 0) {
        return -1;
    }

    memset(&server, 0, sizeof(server));
    pthread_attr_init(&attr);

    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd < 0) {
        fprintf(stderr, "create epoll failed, %s\n", strerror(errno));
        goto errout;
    }

    pthread_mutex_init(&server.map_lock, 0);
    hash_init(server.hostmap);
    server.epoll_fd = epollfd;
    server.fd = fd;
    server.run = 1;

    return 0;
errout:
    server.run = 0;

    if (fd > 0) {
        close(fd);
    }

    if (epollfd) {
        close(epollfd);
    }

    pthread_mutex_destroy(&server.map_lock);

    return -1;
}

void dns_server_exit(void)
{
    server.run = 0;

    if (server.fd > 0) {
        close(server.fd);
        server.fd = -1;
    }

    pthread_mutex_destroy(&server.map_lock);
}