#include "client.h"
#include "fast_ping.h"
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"
#include "tlog.h"

class Ping : public ::testing::Test
{
  protected:
	virtual void SetUp()
	{
		EXPECT_EQ(fast_ping_init(), 0);
        loglevel = tlog_getlevel();
        tlog_setlevel(TLOG_DEBUG);
	}
	virtual void TearDown()
	{
		fast_ping_exit();
        tlog_setlevel(loglevel);
	}
    private:
        tlog_level loglevel;
};

void ping_result_callback(struct ping_host_struct *ping_host, const char *host, FAST_PING_RESULT result,
						  struct sockaddr *addr, socklen_t addr_len, int seqno, int ttl, struct timeval *tv, int error,
						  void *userptr)
{
	int *count = (int *)userptr;
	*count = 1;
}

TEST_F(Ping, DISABLED_icmp)
{
	struct ping_host_struct *ping_host;
	int count = 0;
	ping_host = fast_ping_start(PING_TYPE_ICMP, "127.0.0.1", 1, 1, 200, ping_result_callback, &count);
	ASSERT_NE(ping_host, nullptr);
	usleep(10000);
    fast_ping_stop(ping_host);
    EXPECT_EQ(count, 1);
}

TEST_F(Ping, DISABLED_tcp)
{
	struct ping_host_struct *ping_host;
	int count = 0;
	ping_host = fast_ping_start(PING_TYPE_TCP, "127.0.0.1:1", 1, 1, 200, ping_result_callback, &count);
	ASSERT_NE(ping_host, nullptr);
	usleep(10000);
    fast_ping_stop(ping_host);
    EXPECT_EQ(count, 1);
}
