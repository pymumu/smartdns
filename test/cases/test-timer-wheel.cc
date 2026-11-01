/*************************************************************************
 *
 * Copyright (C) 2018-2026 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "smartdns/lib/timer_wheel.h"
#include "gtest/gtest.h"
#include <atomic>
#include <chrono>
#include <unistd.h>

static void TimerWheelCount(struct tw_base *base, struct tw_timer_list *timer, void *data, unsigned long timestamp)
{
	auto *count = (std::atomic<int> *)data;
	(*count)++;
}

TEST(TimerWheel, FiresBeforeStop)
{
	std::atomic<int> count{0};
	struct tw_timer_list timer = {};
	struct tw_base *base = tw_init_timers();
	ASSERT_NE(base, nullptr);

	INIT_LIST_HEAD(&timer.entry);
	timer.function = TimerWheelCount;
	timer.data = &count;
	timer.expires = 1;
	tw_add_timer(base, &timer);

	for (int i = 0; i < 30 && count == 0; i++) {
		usleep(100 * 1000);
	}
	EXPECT_EQ(count, 1);
	EXPECT_EQ(tw_cleanup_timers(base), 0);
}

TEST(TimerWheel, StopIsPromptAndNoTimerFiresAfterStop)
{
	std::atomic<int> count{0};
	struct tw_timer_list timer = {};
	struct tw_base *base = tw_init_timers();
	ASSERT_NE(base, nullptr);

	INIT_LIST_HEAD(&timer.entry);
	timer.function = TimerWheelCount;
	timer.data = &count;
	timer.expires = 2; /* next tick + 1s, so it cannot fire before stop */
	tw_add_timer(base, &timer);

	auto start = std::chrono::steady_clock::now();
	tw_stop_timers(base);
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
	EXPECT_LT(elapsed.count(), 500);

	/* stopped base stays usable for add/del, but nothing fires */
	usleep(2500 * 1000);
	EXPECT_EQ(count, 0);
	EXPECT_EQ(tw_del_timer(base, &timer), 1);
	tw_stop_timers(base);
	EXPECT_EQ(tw_cleanup_timers(base), 0);
}
