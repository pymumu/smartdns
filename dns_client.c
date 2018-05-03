#include "dns_client.h"
#include "atomic.h"
#include "fast_ping.h"
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
#include <sys/types.h>
#include <unistd.h>

#define DNS_MAX_HOSTNAME 256

#define DNS_INPACKET_SIZE 512

#define DNS_MAX_EVENTS 64

#define DNS_HOSTNAME_LEN 128  

struct dns_query_server {
    int fd;
    int type;
    char host[DNS_HOSTNAME_LEN];
    struct list_head list;
};

struct dns_client {
    pthread_t tid;
    int run;
    int epoll_fd;

    struct list_head dns_server_list;

    pthread_mutex_t map_lock;
    DECLARE_HASHTABLE(hostmap, 6);

    int udp;
    int tcp;
};
struct dns_query_struct {
    char host[DNS_MAX_HOSTNAME];
    struct hlist_node host_node;
};

static struct dns_client client;

static void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

void _dns_client_period_run()
{
}

static int _dns_client_process(struct dns_query_struct *dns_query, struct timeval *now)
{
    int len;
    u_char inpacket[DNS_INPACKET_SIZE];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);

    len = recvfrom(client.udp, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
    if (len < 0) {
        fprintf(stderr, "recvfrom failed, %s\n", strerror(errno));
        goto errout;
    }

    return 0;
errout:
    return -1;
}

static void *_dns_client_work(void *arg)
{
    struct epoll_event events[DNS_MAX_EVENTS + 1];
    int num;
    int i;
    struct timeval last = { 0 };
    struct timeval now = { 0 };
    struct timeval diff = { 0 };
    uint millisec = 0;

    while (client.run) {
        diff = now;
        tv_sub(&diff, &last);
        millisec = diff.tv_sec * 1000 + diff.tv_usec / 1000;
        if (millisec >= 100) {
            _dns_client_period_run();
            last = now;
        }

        num = epoll_wait(client.epoll_fd, events, DNS_MAX_EVENTS, 100);
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
            struct dns_query_struct *dns_query = (struct dns_query_struct *)event->data.ptr;
            _dns_client_process(dns_query, &now);
        }
    }

    close(client.epoll_fd);
    client.epoll_fd = -1;

    return NULL;
}

int dns_client_init()
{
    pthread_attr_t attr;
    int epollfd = -1;
    int ret;

    if (client.epoll_fd > 0) {
        return -1;
    }

    memset(&client, 0, sizeof(client));
    pthread_attr_init(&attr);

    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd < 0) {
        fprintf(stderr, "create epoll failed, %s\n", strerror(errno));
        goto errout;
    }

    client.run = 1;
    ret = pthread_create(&client.tid, &attr, _dns_client_work, NULL);
    if (ret != 0) {
        fprintf(stderr, "create client work thread failed, %s\n", strerror(errno));
        goto errout;
    }

    pthread_mutex_init(&client.map_lock, 0);
    hash_init(client.hostmap);
    client.epoll_fd = epollfd;

    return 0;
errout:
    if (client.tid > 0) {
        void *retval = NULL;
        client.run = 0;
        pthread_join(client.tid, &retval);
    }

    if (epollfd) {
        close(epollfd);
    }

    pthread_mutex_destroy(&client.map_lock);

    return -1;
}

int dns_client_query(char *host)
{
    return 0;
errout:
    return -1;
}

void dns_client_exit()
{
    if (client.tid > 0) {
        void *ret = NULL;
        client.run = 0;
        pthread_join(client.tid, &ret);
    }

    pthread_mutex_destroy(&client.map_lock);
}