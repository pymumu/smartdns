#include "gtest/gtest.h"
extern "C" {
#include "dns_server/cache.h"
#include "smartdns/dns_conf.h"
#include "smartdns/tlog.h"
}
#include <csetjmp>
#include <cstring>
#include <cerrno>
#include <sys/wait.h>
#include <unistd.h>

namespace {
thread_local bool checkpoint_mock;
enum ForkResult { Parent, Child, Failure } fork_result;
enum WaitResult { Running, Finished, Missing } wait_result;
time_t mock_now = 100000;
int fork_calls, wait_calls, kill_calls, close_calls, save_calls, child_exit;
int save_check_lock;
std::jmp_buf child_return;
constexpr pid_t fake_child = 2147483000;
}
extern "C" time_t __real_time(time_t *);
extern "C" pid_t __real_fork(void);
extern "C" pid_t __real_waitpid(pid_t, int *, int);
extern "C" int __real_kill(pid_t, int);
extern "C" int __real_close(int);
extern "C" int __real_dns_cache_save(const char *, int);
extern "C" void __real__exit(int) __attribute__((noreturn));
extern "C" time_t __wrap_time(time_t *p) {
    if (!checkpoint_mock) return __real_time(p);
    if (p) *p = mock_now;
    return mock_now;
}
extern "C" pid_t __wrap_fork(void) {
    if (!checkpoint_mock) return __real_fork();
    fork_calls++;
    if (fork_result == Child) return 0;
    if (fork_result == Failure) { errno = EAGAIN; return -1; }
    return fake_child;
}
extern "C" pid_t __wrap_waitpid(pid_t p, int *s, int options) {
    if (!checkpoint_mock) return __real_waitpid(p, s, options);
    wait_calls++;
    if (wait_result == Running) return 0;
    if (wait_result == Missing) { errno = ECHILD; return -1; }
    return p;
}
extern "C" int __wrap_kill(pid_t p, int s) {
    if (!checkpoint_mock) return __real_kill(p, s);
    kill_calls++; return 0;
}
extern "C" int __wrap_close(int fd) {
    if (!checkpoint_mock || fork_result != Child) return __real_close(fd);
    close_calls++; return 0;
}
extern "C" int __wrap_dns_cache_save(const char *p, int lock) {
    if (!checkpoint_mock) return __real_dns_cache_save(p, lock);
    save_calls++; save_check_lock = lock; return 0;
}
extern "C" void __wrap__exit(int s) {
    if (checkpoint_mock && fork_result == Child) {
        child_exit = s; std::longjmp(child_return, 1);
    }
    __real__exit(s);
}

class CacheCheckpoint : public ::testing::Test {
    int old_persist, old_size, old_interval;
    time_t old_time;
    pid_t old_pid;
    char old_file[DNS_MAX_PATH];
    tlog_level old_level;
protected:
    void SetUp() override {
        old_persist = dns_conf.cache_persist; old_size = dns_conf.cachesize;
        old_interval = dns_conf.cache_checkpoint_time;
        old_time = server.cache_save_time; old_pid = server.cache_save_pid;
        memcpy(old_file, dns_conf.cache_file, sizeof(old_file)); old_level = tlog_getlevel();
        ASSERT_EQ(pthread_mutex_init(&server.request_list_lock, nullptr), 0);
        INIT_LIST_HEAD(&server.request_list);
        dns_conf.cache_persist = 1; dns_conf.cachesize = 16; dns_conf.cache_checkpoint_time = 120;
        strcpy(dns_conf.cache_file, "/tmp/smartdns-checkpoint-mock-only.cache");
        server.cache_save_pid = 0; server.cache_save_time = mock_now - 121;
        fork_calls = wait_calls = kill_calls = close_calls = save_calls = 0;
        child_exit = -1; save_check_lock = -1;
        fork_result = Parent; wait_result = Running; checkpoint_mock = true;
    }
    void TearDown() override {
        checkpoint_mock = false;
        dns_conf.cache_persist = old_persist; dns_conf.cachesize = old_size;
        dns_conf.cache_checkpoint_time = old_interval;
        memcpy(dns_conf.cache_file, old_file, sizeof(old_file)); tlog_setlevel(old_level);
        server.cache_save_time = old_time; server.cache_save_pid = old_pid;
        INIT_LIST_HEAD(&server.request_list);
        pthread_mutex_destroy(&server.request_list_lock);
    }
};
TEST_F(CacheCheckpoint, DueIdleServerForksOneSaver) {
    _dns_server_save_cache_to_file();
    EXPECT_EQ(fork_calls, 1); EXPECT_EQ(server.cache_save_pid, fake_child);
    EXPECT_EQ(server.cache_save_time, mock_now);
}
TEST_F(CacheCheckpoint, BusyServerDefersWithoutChangingCheckpointTime) {
    list_head request; INIT_LIST_HEAD(&request); list_add(&request, &server.request_list);
    _dns_server_save_cache_to_file();
    EXPECT_EQ(fork_calls, 0); EXPECT_EQ(server.cache_save_time, mock_now - 121);
    list_del_init(&request);
}
TEST_F(CacheCheckpoint, DisabledAndNotDueNeverFork) {
    dns_conf.cache_persist = 0; _dns_server_save_cache_to_file();
    dns_conf.cache_persist = 1; server.cache_save_time = mock_now - 119;
    _dns_server_save_cache_to_file(); EXPECT_EQ(fork_calls, 0);
}
TEST_F(CacheCheckpoint, RunningChildPreventsDuplicateSaverAndHasBoundedKill) {
    server.cache_save_pid = fake_child; server.cache_save_time = mock_now - 10;
    _dns_server_save_cache_to_file();
    EXPECT_EQ(wait_calls, 1); EXPECT_EQ(fork_calls, 0); EXPECT_EQ(kill_calls, 0);
    server.cache_save_time = mock_now - 31; _dns_server_save_cache_to_file();
    EXPECT_EQ(fork_calls, 0); EXPECT_EQ(kill_calls, 1);
}
TEST_F(CacheCheckpoint, CompletedChildReapedBeforeNextDueSave) {
    server.cache_save_pid = fake_child; wait_result = Finished;
    _dns_server_save_cache_to_file(); EXPECT_EQ(wait_calls, 1); EXPECT_EQ(fork_calls, 1);
}
TEST_F(CacheCheckpoint, ChildBranchClosesDescriptorsSavesAndExitsWithoutRealFork) {
    fork_result = Child;
    if (setjmp(child_return) == 0) {
        _dns_server_save_cache_to_file();
        FAIL() << "child branch must exit";
    }
    EXPECT_EQ(close_calls, 1021); EXPECT_EQ(save_calls, 1);
    EXPECT_EQ(save_check_lock, 1); EXPECT_EQ(child_exit, 0);
}
