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


#include "include/utils.h"
extern "C" {
#include "smartdns/lib/conf.h"
}
#include "gtest/gtest.h"
#include <cstring>
#include <string>

static int LibConfAnyItem(const char *item, void *data, int argc, char *argv[])
{
	return 0;
}

static int LibConfNoError(const char *key, const char *value, const char *file, int lineno, int ret)
{
	return 0;
}

/* After a load, conf_get_conf_file() names the loaded top-level file. A later load must not keep the
 * earlier load's pointer, whose buffer may be gone (a server run in-process before this one). */
TEST(LibConf, LoadDoesNotKeepPreviousFile)
{
	static struct config_item items[] = {{"item", LibConfAnyItem, nullptr}, {nullptr, nullptr, nullptr}};
	smartdns::TempFile first;
	smartdns::TempFile second;
	ASSERT_TRUE(first.Write("item a\n"));
	ASSERT_TRUE(second.Write("item b\n"));

	char first_path[256];
	strncpy(first_path, first.GetPath().c_str(), sizeof(first_path) - 1);
	first_path[sizeof(first_path) - 1] = '\0';
	ASSERT_EQ(load_conf(first_path, items, LibConfNoError), 0);
	ASSERT_STREQ(conf_get_conf_file(), first_path);

	/* the first load's file name buffer is reused for something else */
	memset(first_path, 'x', sizeof(first_path) - 1);

	std::string second_path = second.GetPath();
	ASSERT_EQ(load_conf(second_path.c_str(), items, LibConfNoError), 0);
	ASSERT_NE(conf_get_conf_file(), nullptr);
	EXPECT_STREQ(conf_get_conf_file(), second_path.c_str());
}
