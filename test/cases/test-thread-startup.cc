#include "gtest/gtest.h"
extern "C" {
#include "smartdns/tlog.h"
#include "smartdns/fast_ping.h"
}
#include <cerrno>
#include <cstring>
#include <pthread.h>
#include <string>

namespace {
thread_local bool fail_thread_start;
thread_local bool used_default_attributes;
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
TEST(ThreadStartup, LoggerReportsPthreadErrorInsteadOfUnrelatedErrno)
{
    testing::internal::CaptureStderr();
    used_default_attributes = false;
    fail_thread_start = true;
    int result = tlog_init("/dev/null", 1024, 1, 0, TLOG_NOCOMPRESS);
    fail_thread_start = false;
    std::string output = testing::internal::GetCapturedStderr();
    EXPECT_EQ(result, -1);
    EXPECT_TRUE(used_default_attributes);
    EXPECT_NE(output.find(strerror(EAGAIN)), std::string::npos);
    EXPECT_EQ(output.find(strerror(ENOENT)), std::string::npos);
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
