#include "fast_ping.h"
#include "atomic.h"
#include "hashtable.h"
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

#define PING_MAX_EVENTS 128
#define PING_MAX_HOSTLEN 128
#define ICMP_PACKET_SIZE (1024 * 64)
#define ICMP_INPACKET_SIZE 1024

struct fast_ping_packet_msg {
    struct timeval tv;
};

struct fast_ping_packet {
    union {
        struct icmp icmp;
        struct icmp6_hdr icmp6;
    };
    struct fast_ping_packet_msg msg;
};

struct ping_host_struct {
    atomic_t ref;
    struct hlist_node host_node;
    struct hlist_node addr_node;
    int type;

    void *userptr;
    char host[PING_MAX_HOSTLEN];

    int fd;
    unsigned int seq;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    struct fast_ping_packet packet;
};

struct fast_ping_struct {
    int run;
    pthread_t tid;
    pthread_mutex_t lock;
    int ident;

    int epoll_fd;
    int fd_icmp;
    struct ping_host_struct icmp_host;
    int fd_icmp6;
    struct ping_host_struct icmp6_host;

    pthread_mutex_t map_lock;
    DECLARE_HASHTABLE(hostmap, 6);
    DECLARE_HASHTABLE(addrmap, 6);
};

static struct fast_ping_struct ping;
static fast_ping_result ping_callback;

uint16_t _fast_ping_checksum(uint16_t *header, size_t len)
{
    uint32_t sum = 0;
    int i;

    for (i = 0; i < len / sizeof(uint16_t); i++) {
        sum += ntohs(header[i]);
    }

    return htons(~((sum >> 16) + (sum & 0xffff)));
}

int fast_ping_result_callback(fast_ping_result result)
{
    ping_callback = result;
}

void _fast_ping_install_filter_v6(int sock)
{
    struct icmp6_filter icmp6_filter;
    ICMP6_FILTER_SETBLOCKALL(&icmp6_filter);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &icmp6_filter);
    setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &icmp6_filter, sizeof(struct icmp6_filter));

    static int once;
    static struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 4), /* Load icmp echo ident */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1), /* Ours? */
        BPF_STMT(BPF_RET | BPF_K, ~0U), /* Yes, it passes. */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0), /* Load icmp type */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP6_ECHO_REPLY, 1, 0), /* Echo? */
        BPF_STMT(BPF_RET | BPF_K, ~0U), /* No. It passes. This must not happen. */
        BPF_STMT(BPF_RET | BPF_K, 0), /* Echo with wrong ident. Reject. */
    };
    static struct sock_fprog filter = { sizeof insns / sizeof(insns[0]), insns };

    if (once) {
        return;
    }
    once = 1;

    /* Patch bpflet for current identifier. */
    insns[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(getpid()), 0, 1);

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
        perror("WARNING: failed to install socket filter\n");
    }
}

void _fast_ping_install_filter_v4(int sock)
{
    static int once;
    static struct sock_filter insns[] = {
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0), /* Skip IP header. F..g BSD... Look into ping6. */
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 4), /* Load icmp echo ident */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1), /* Ours? */
        BPF_STMT(BPF_RET | BPF_K, ~0U), /* Yes, it passes. */
        BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0), /* Load icmp type */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFF), /* No. It passes. */
        BPF_STMT(BPF_RET | BPF_K, 0) /* Echo with wrong ident. Reject. */
    };

    static struct sock_fprog filter = { sizeof insns / sizeof(insns[0]), insns };

    if (once) {
        return;
    }
    once = 1;

    /* Patch bpflet for current identifier. */
    insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(getpid()), 0, 1);

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
        perror("WARNING: failed to install socket filter\n");
    }
}

static struct addrinfo *_fast_ping_getaddr(const u_char *host, int type, int protocol)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_protocol = protocol;
    if (getaddrinfo(host, NULL, &hints, &result) != 0) {
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

static int _fast_ping_getdomain(const u_char *host)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int domain = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    if (getaddrinfo(host, NULL, &hints, &result) != 0) {
        fprintf(stderr, "get addr info failed. %s\n", strerror(errno));
        goto errout;
    }

    domain = result->ai_family;

    freeaddrinfo(result);

    return domain;
errout:
    if (result) {
        freeaddrinfo(result);
    }
    return -1;
}

int _fast_ping_host_get(struct ping_host_struct *ping_host)
{
    atomic_inc(&ping_host->ref);
}

int _fast_ping_host_put(struct ping_host_struct *ping_host)
{
    pthread_mutex_lock(&ping.map_lock);
    if (atomic_dec_and_test(&ping_host->ref)) {
        hlist_del(&ping_host->host_node);
        hlist_del(&ping_host->addr_node);
    } else {
        ping_host = NULL;
    }
    pthread_mutex_unlock(&ping.map_lock);

    if (ping_host == NULL) {
        return -1;
    }

    free(ping_host);
}

static int _fast_ping_sendping_v6(struct ping_host_struct *ping_host)
{
    struct fast_ping_packet *packet = &ping_host->packet;
    struct icmp6_hdr *icmp6 = &packet->icmp6;
    int len = 0;

    ping_host->seq++;
    memset(icmp6, 0, sizeof(*icmp6));
    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_id = getpid();
    icmp6->icmp6_seq = htons(ping_host->seq);

    gettimeofday(&packet->msg.tv, 0);
    icmp6->icmp6_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

    len = sendto(ping_host->fd, &ping_host->packet, sizeof(struct fast_ping_packet), 0, (struct sockaddr *)&ping_host->addr, ping_host->addr_len);
    if (len < 0 || len != sizeof(struct fast_ping_packet)) {
        fprintf(stderr, "sendto %s\n", strerror(errno));
        goto errout;
    }

    return 0;

errout:
    return -1;
}

static int _fast_ping_sendping_v4(struct ping_host_struct *ping_host)
{
    struct fast_ping_packet *packet = &ping_host->packet;
    struct icmp *icmp = &packet->icmp;
    int len;

    ping_host->seq++;
    memset(icmp, 0, sizeof(*icmp));
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = ping.ident;
    icmp->icmp_seq = htons(ping_host->seq);

    gettimeofday(&packet->msg.tv, 0);
    icmp->icmp_cksum = _fast_ping_checksum((void *)packet, sizeof(struct fast_ping_packet));

    len = sendto(ping_host->fd, packet, sizeof(struct fast_ping_packet), 0, (struct sockaddr *)&ping_host->addr, ping_host->addr_len);
    if (len < 0 || len != sizeof(struct fast_ping_packet)) {
        fprintf(stderr, "sendto %s\n", strerror(errno));
        goto errout;
    }

    return 0;

errout:
    return -1;
}

static int _fast_ping_sendping(struct ping_host_struct *ping_host)
{
    if (ping_host->type == AF_INET) {
        return _fast_ping_sendping_v4(ping_host);
    } else if (ping_host->type == AF_INET6) {
        return _fast_ping_sendping_v6(ping_host);
    }

    return -1;
}

static int _fast_ping_create_sock(int protocol)
{
    int fd;
    struct ping_host_struct *icmp_host = NULL;
    struct epoll_event event;

    fd = socket(AF_INET, SOCK_RAW, protocol);
    if (fd < 0) {
        fprintf(stderr, "create icmp socket failed.\n");
        goto errout;
    }
    switch (protocol) {
    case IPPROTO_ICMP:
        _fast_ping_install_filter_v4(fd);
        icmp_host = &ping.icmp_host;
        break;
    case IPPROTO_ICMPV6:
        _fast_ping_install_filter_v6(fd);
        icmp_host = &ping.icmp_host;
        break;
    }

    event.events = EPOLLIN;
    event.data.ptr = icmp_host;
    if (epoll_ctl(ping.epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) {
        goto errout;
    }

    icmp_host->fd = fd;
    icmp_host->type = AF_PACKET;
    return fd;

errout:
    close(fd);
    return -1;
}

static int _fast_ping_create_icmp(int protocol)
{
    int fd = 0;
    int *set_fd = NULL;

    pthread_mutex_lock(&ping.lock);
    switch (protocol) {
    case IPPROTO_ICMP:
        set_fd = &ping.fd_icmp;
        break;
    case IPPROTO_ICMPV6:
        set_fd = &ping.fd_icmp6;
        break;
    default:
        goto errout;
        break;
    }

    if (*set_fd > 0) {
        goto out;
    }

    fd = _fast_ping_create_sock(protocol);
    if (fd < 0) {
        goto errout;
    }

    *set_fd = fd;
out:
    pthread_mutex_unlock(&ping.lock);
    return *set_fd;
errout:
    if (fd > 0) {
        close(fd);
    }
    pthread_mutex_unlock(&ping.lock);
    return -1;
}

int fast_ping_start(const char *host, int timeout, void *userptr)
{
    struct ping_host_struct *ping_host = NULL;
    struct addrinfo *gai = NULL;
    int domain = -1;
    int icmp_proto = 0;
    char ip[PING_MAX_HOSTLEN];
    uint32_t hostkey;
    uint32_t addrkey;

    domain = _fast_ping_getdomain(host);
    if (domain < 0) {
        return -1;
    }

    switch (domain) {
    case AF_INET:
        icmp_proto = IPPROTO_ICMP;
        break;
    case AF_INET6:
        icmp_proto = IPPROTO_ICMPV6;
        break;
    default:
        return -1;
        break;
    }

    gai = _fast_ping_getaddr(host, SOCK_RAW, icmp_proto);
    if (gai == NULL) {
        return -1;
    }

    ping_host = malloc(sizeof(*ping_host));
    if (ping_host == NULL) {
        goto errout;
    }

    memset(ping_host, 0, sizeof(ping_host));
    strncpy(ping_host->host, host, PING_MAX_HOSTLEN);
    ping_host->type = domain;
    ping_host->fd = _fast_ping_create_icmp(icmp_proto);
    memcpy(&ping_host->addr, gai->ai_addr, gai->ai_addrlen);
    ping_host->addr_len = gai->ai_addrlen;

    atomic_set(&ping_host->ref, 0);

    hostkey = hash_string(ping_host->host);
	addrkey = jhash(&ping_host->addr, ping_host->addr_len, 0);
    pthread_mutex_lock(&ping.map_lock);
    _fast_ping_host_get(ping_host);
    hash_add(ping.hostmap, &ping_host->host_node, hostkey);
    hash_add(ping.addrmap, &ping_host->addr_node, addrkey);
    pthread_mutex_unlock(&ping.map_lock);

    freeaddrinfo(gai);

    _fast_ping_sendping(ping_host);
    return 0;
errout:
    if (gai) {
        freeaddrinfo(gai);
    }

    if (ping_host) {
        free(ping_host);
    }

    return -1;
}

int fast_ping_stop(const char *host)
{
    struct ping_host_struct *ping_host;
    uint32_t key;
    key = hash_string(host);
    pthread_mutex_lock(&ping.map_lock);
    hash_for_each_possible(ping.hostmap, ping_host, host_node, key)
    {
        if (strncmp(host, ping_host->host, PING_MAX_HOSTLEN) == 0) {
            break;
        }
    }
    if (ping_host == NULL) {
        pthread_mutex_unlock(&ping.map_lock);
        return -1;
    }
    pthread_mutex_unlock(&ping.map_lock);
    _fast_ping_host_put(ping_host);
    return 0;
}

void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

static int _fast_ping_icmp6_packet(struct ping_host_struct *ping_host, u_char *packet_data, int data_len, struct timeval *tvrecv)
{
    int hlen;
    int icmp_len;
    struct fast_ping_packet *packet = (struct fast_ping_packet *)packet_data;
    struct icmp6_hdr *icmp6 = &packet->icmp6;
    struct timeval tvresult = *tvrecv;
    double rtt;

    if (icmp6->icmp6_type != ICMP6_ECHO_REPLY) {
        return -1;
    }

    icmp_len = data_len;
    if (icmp_len < 16) {
        return -1;
    }

    if (icmp6->icmp6_id != ping.ident) {
        return -1;
    }

    struct timeval *tvsend = &packet->msg.tv;
    tv_sub(&tvresult, tvsend);
    ping_callback(ping_host->host, ping_host->seq, &tvresult, ping_host->userptr);

    return 0;
}

static int _fast_ping_icmp_packet(struct ping_host_struct *ping_host, u_char *packet_data, int data_len, struct timeval *tvrecv)
{
    struct ip *ip = (struct ip *)packet_data;
    struct fast_ping_packet *packet;
    struct icmp *icmp;
    struct timeval tvresult = *tvrecv;
    int hlen;
    int icmp_len;

    if (ip->ip_p != IPPROTO_ICMP) {
        return -1;
    }

    hlen = ip->ip_hl << 2;
    packet = (struct fast_ping_packet *)(packet_data + hlen);
    icmp = &packet->icmp;
    icmp_len = data_len - hlen;

    if (icmp_len < 16) {
        return -1;
    }

    if (icmp->icmp_type != ICMP_ECHOREPLY) {
        return -1;
    }

    if (icmp->icmp_id != ping.ident) {
        return -1;
    }

    struct timeval *tvsend = &packet->msg.tv;
    tv_sub(&tvresult, tvsend);

    ping_callback(ping_host->host, ping_host->seq, &tvresult, ping_host->userptr);

    return 0;
}

static int _fast_ping_recvping(struct ping_host_struct *ping_host, u_char *inpacket, int len, struct timeval *tvrecv)
{

    if (ping_host->type == AF_INET6) {
        if (_fast_ping_icmp6_packet(ping_host, inpacket, len, tvrecv)) {
            goto errout;
        }
    } else if (ping_host->type == AF_INET) {

        if (_fast_ping_icmp_packet(ping_host, inpacket, len, tvrecv)) {
            goto errout;
        }
    }

    return 0;
errout:
    return -1;
}

static int _fast_ping_create_tcp(struct ping_host_struct *ping_host)
{
    return -1;
}

static int _fast_ping_ping_host(struct ping_host_struct *ping_host) {}

static int _fast_ping_gethost_by_addr(u_char *host, struct sockaddr *addr, socklen_t addr_len)
{
    struct sockaddr_storage *addr_store = (struct sockaddr_storage *)addr;
    host[0] = 0;
    switch (addr_store->ss_family) {
    case AF_INET: {
        struct sockaddr_in *addr_in;
        addr_in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, host, addr_len);
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *addr_in6;
        addr_in6 = (struct sockaddr_in6 *)addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
            struct sockaddr_in addr_in4;
            memset(&addr_in4, 0, sizeof(addr_in4));
            memcpy(&addr_in4.sin_addr.s_addr, addr_in6->sin6_addr.s6_addr + 12, sizeof(addr_in4.sin_addr.s_addr));
        } else {
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, host, addr_len);
        }
    } break;
    default:
        goto errout;
        break;
    }
    return 0;
errout:
    return -1;
}

static int _fast_ping_process(struct ping_host_struct *ping_host, struct timeval *now)
{
    int len;
    u_char inpacket[ICMP_INPACKET_SIZE];
    struct sockaddr_storage from;
    struct ping_host_struct *recv_ping_host;
    socklen_t from_len = sizeof(from);
    uint32_t addrkey;

    len = recvfrom(ping_host->fd, inpacket, sizeof(inpacket), 0, (struct sockaddr *)&from, (socklen_t *)&from_len);
    if (len < 0) {
        fprintf(stderr, "recvfrom failed, %s\n", strerror(errno));
        goto errout;
    }

	addrkey = jhash(&from, from_len, 0);
    pthread_mutex_lock(&ping.map_lock);
    hash_for_each_possible(ping.addrmap, recv_ping_host, addr_node, addrkey)
    {
        if (recv_ping_host->addr_len == from_len && memcmp(&recv_ping_host->addr, &from, from_len) == 0) {
            break;
        }
    }
    pthread_mutex_unlock(&ping.map_lock);

    if (recv_ping_host == NULL) {
        return -1;
    }

    _fast_ping_recvping(recv_ping_host, inpacket, len, now);
    return 0;
errout:
    return -1;
}

static void _fast_ping_period_run()
{
    struct ping_host_struct *ping_host;
    struct hlist_node *tmp;
    int i = 0;
    pthread_mutex_lock(&ping.map_lock);
    hash_for_each_safe(ping.addrmap, i, tmp, ping_host, addr_node)
    {
        _fast_ping_sendping(ping_host);
    }
    pthread_mutex_unlock(&ping.map_lock);
}

static void *_fast_ping_work(void *arg)
{
    struct epoll_event events[PING_MAX_EVENTS + 1];
    int num;
    int i;
    struct timeval last = { 0 };
    struct timeval now = { 0 };

    while (ping.run) {
        if (last.tv_sec != now.tv_sec) {
            _fast_ping_period_run();
            last = now;
        }

        num = epoll_wait(ping.epoll_fd, events, PING_MAX_EVENTS, 1000);
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
            struct ping_host_struct *ping_host = (struct ping_host_struct *)event->data.ptr;
            _fast_ping_process(ping_host, &now);
        }
    }

    close(ping.epoll_fd);
    ping.epoll_fd = -1;

    return NULL;
}

int fast_ping_init()
{
    pthread_attr_t attr;
    int epollfd = -1;
    int ret;

    if (ping.epoll_fd > 0) {
        return -1;
    }

    memset(&ping, 0, sizeof(ping));
    pthread_attr_init(&attr);

    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd < 0) {
        fprintf(stderr, "create epoll failed, %s\n", strerror(errno));
        goto errout;
    }

    ping.run = 1;
    ret = pthread_create(&ping.tid, &attr, _fast_ping_work, NULL);
    if (ret != 0) {
        fprintf(stderr, "create ping work thread failed, %s\n", strerror(errno));
        goto errout;
    }

    pthread_mutex_init(&ping.map_lock, 0);
    pthread_mutex_init(&ping.lock, 0);
    hash_init(ping.hostmap);
    hash_init(ping.addrmap);
    ping.epoll_fd = epollfd;
    ping.ident = getpid();

    return 0;
errout:
    if (ping.tid > 0) {
        void *retval = NULL;
        ping.run = 0;
        pthread_join(ping.tid, &retval);
    }

    if (epollfd) {
        close(epollfd);
    }

    pthread_mutex_destroy(&ping.lock);
    pthread_mutex_destroy(&ping.map_lock);

    return -1;
}

int fast_ping_exit()
{
    if (ping.tid > 0) {
        void *ret = NULL;
        ping.run = 0;
        pthread_join(ping.tid, &ret);
    }

    if (ping.fd_icmp > 0) {
        close(ping.fd_icmp);
        ping.fd_icmp < 0;
    }

    if (ping.fd_icmp6 > 0) {
        close(ping.fd_icmp6);
        ping.fd_icmp6 < 0;
    }

    pthread_mutex_destroy(&ping.lock);
    pthread_mutex_destroy(&ping.map_lock);
}