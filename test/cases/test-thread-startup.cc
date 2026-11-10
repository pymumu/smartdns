#include "gtest/gtest.h"
extern "C" {
#include "smartdns/fast_ping.h"
#include "dns_client/dns_client.h"
}
#undef min
#undef max
#include "include/utils.h"
#include <cerrno>
#include <cstring>
#include <pthread.h>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

namespace {
thread_local bool fail_thread_start;
thread_local bool used_default_attributes;
thread_local bool fail_epoll, fail_wakeup;
thread_local int created_epoll = -1, replacement_fd = -1;
}
extern "C" int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
extern "C" int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                                    void *(*start)(void *), void *argument)
{
    if (!fail_thread_start) return __real_pthread_create(thread, attributes, start, argument);
    used_default_attributes = attributes == nullptr;
    // pthread functions return their error directly and need not set errno.
    errno = ENOENT;
    return EAGAIN;
}
extern "C" int __real_epoll_create1(int);
extern "C" int __wrap_epoll_create1(int flags)
{
    if (fail_epoll) { errno = EMFILE; return -1; }
    int result = __real_epoll_create1(flags);
    if (fail_wakeup) created_epoll = result;
    return result;
}
extern "C" int __real_eventfd(unsigned int, int);
extern "C" int __wrap_eventfd(unsigned int value, int flags)
{
    if (fail_wakeup) { errno = EMFILE; return -1; }
    return __real_eventfd(value, flags);
}
extern "C" int __real_pthread_join(pthread_t, void **);
extern "C" int __wrap_pthread_join(pthread_t thread, void **result)
{
    int status = __real_pthread_join(thread, result);
    if (status == 0 && fail_wakeup) replacement_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    return status;
}
TEST(ThreadStartup, PingThreadFailureUsesDefaultAttributesAndCanRetry)
{
    used_default_attributes = false;
    fail_thread_start = true;
    int result = fast_ping_init();
    fail_thread_start = false;
    EXPECT_EQ(result, -1);
    EXPECT_TRUE(used_default_attributes);
    result = fast_ping_init();
    EXPECT_EQ(result, 0);
    if (result == 0) fast_ping_exit();
}
namespace {
void check_client_failure_recovery(bool &fail)
{
    int mdns = dns_conf.mdns_lookup;
    dns_conf.mdns_lookup = 0;
    Defer { dns_conf.mdns_lookup = mdns; };
    fail = true;
    int result = dns_client_init();
    fail = false;
    EXPECT_EQ(result, -1);
    EXPECT_EQ(client.epoll_fd, -1);
    EXPECT_EQ(client.fd_wakeup, -1);
    EXPECT_EQ(client.default_group, nullptr);
    EXPECT_EQ(atomic_read(&client.run), 0);
    bool groups_empty = true;
    for (auto &bucket : client.group) if (!hlist_empty(&bucket)) groups_empty = false;
    EXPECT_TRUE(groups_empty);
    result = dns_client_init();
    EXPECT_EQ(result, 0);
    if (result == 0) dns_client_exit();
}
}
TEST(ThreadStartup, ClientThreadFailureCanRetryWithoutLeakingGroups)
{
    used_default_attributes = false;
    check_client_failure_recovery(fail_thread_start);
    EXPECT_TRUE(used_default_attributes);
}
TEST(ThreadStartup, ClientEpollFailureCanRetry)
{
    check_client_failure_recovery(fail_epoll);
}
TEST(ThreadStartup, ClientWakeupFailureJoinsWorkerAndCanRetry)
{
    created_epoll = replacement_fd = -1;
    check_client_failure_recovery(fail_wakeup);
    ASSERT_GE(replacement_fd, 0);
    EXPECT_EQ(replacement_fd, created_epoll);
    EXPECT_NE(fcntl(replacement_fd, F_GETFD), -1);
    close(replacement_fd);
}
