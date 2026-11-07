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


/* Configuration context ownership, including nested callbacks and failure paths. */
#include "gtest/gtest.h"
#include "include/utils.h"
extern "C" {
#include "smartdns/lib/conf.h"
}
#include <string>
#include <thread>
#include <vector>

namespace {
struct Location {
	std::string file;
	int line;
	std::string value;
};

struct Context {
	std::vector<Location> locations;
	std::string child;
	const config_item *items = nullptr;
};

int check_handler(const char *, const char *value, const char *file, int line, int result)
{
	EXPECT_STREQ(conf_get_conf_file(), file);
	EXPECT_EQ(conf_get_current_lineno(), line);
	return std::string(value) == "abort" ? -1 : result;
}

void capture(Context &context, const char *value)
{
	const char *file = conf_get_conf_file();
	context.locations.push_back({file ? file : "", conf_get_current_lineno(), value});
}

int directive(const char *, void *data, int argc, char **argv)
{
	if (argc != 2) return -1;
	auto &context = *static_cast<Context *>(data);
	capture(context, argv[1]);
	if (std::string(argv[1]) == "include") {
		int result = load_conf(context.child.c_str(), context.items, check_handler);
		capture(context, "after-child");
		return result;
	}
	return std::string(argv[1]) == "reject" ? -1 : 0;
}

void expect_outside_context()
{
	EXPECT_EQ(static_cast<const void *>(conf_get_conf_file()), nullptr);
	EXPECT_EQ(conf_get_current_lineno(), 0);
	char path[128];
	ASSERT_NE(conf_get_conf_fullpath("relative.conf", path, sizeof(path)), nullptr);
	EXPECT_STREQ(path, "relative.conf");
}
} // namespace

TEST(LibConf, CompletedThreadDoesNotLeaveBorrowedFilename)
{
	smartdns::TempFile file;
	ASSERT_TRUE(file.Write("scope leaf\n"));
	Context context;
	config_item items[] = {{"scope", directive, &context}, {nullptr, nullptr, nullptr}};
	std::string expected = file.GetPath();
	std::thread worker([&]() {
		/* The getter must stop borrowing this filename before the thread exits. */
		std::string local = expected;
		EXPECT_EQ(load_conf(local.c_str(), items, check_handler), 0);
	});
	worker.join();
	ASSERT_EQ(context.locations.size(), 1U);
	EXPECT_EQ(context.locations[0].file, expected);
	EXPECT_EQ(context.locations[0].line, 1);
	expect_outside_context();
}

TEST(LibConf, CallbackAndHandlerFailuresRestoreEmptyContext)
{
	for (const char *value : {"reject", "abort"}) {
		smartdns::TempFile file;
		ASSERT_TRUE(file.Write(std::string("scope ") + value + "\n"));
		Context context;
		config_item items[] = {{"scope", directive, &context}, {nullptr, nullptr, nullptr}};
		EXPECT_EQ(load_conf(file.GetPath().c_str(), items, check_handler), -1);
		expect_outside_context();
	}
}

TEST(LibConf, NestedIncludeRestoresOuterFilenameAndLineOnSuccessAndFailure)
{
	for (bool reject : {false, true}) {
		smartdns::TempFile child, parent;
		ASSERT_TRUE(child.Write(reject ? "# child\n# child\nscope reject\n" : "# child\n# child\nscope leaf\n"));
		ASSERT_TRUE(parent.Write("# parent\nscope include\nscope tail\n"));
		Context context;
		context.child = child.GetPath();
		config_item items[] = {{"scope", directive, &context}, {nullptr, nullptr, nullptr}};
		context.items = items;
		EXPECT_EQ(load_conf(parent.GetPath().c_str(), items, check_handler), reject ? -1 : 0);
		ASSERT_EQ(context.locations.size(), reject ? 3U : 4U);
		EXPECT_EQ(context.locations[0].file, parent.GetPath());
		EXPECT_EQ(context.locations[0].line, 2);
		EXPECT_EQ(context.locations[1].file, child.GetPath());
		EXPECT_EQ(context.locations[1].line, 3);
		EXPECT_EQ(context.locations[2].file, parent.GetPath());
		EXPECT_EQ(context.locations[2].line, 2);
		EXPECT_EQ(context.locations[2].value, "after-child");
		if (!reject) {
			EXPECT_EQ(context.locations[3].file, parent.GetPath());
			EXPECT_EQ(context.locations[3].line, 3);
		}
		expect_outside_context();
	}
}

#include <cstring>
static int LibConfAnyItem(const char *item, void *data, int argc, char *argv[])
{
	return 0;
}

static int LibConfNoError(const char *key, const char *value, const char *file, int lineno, int ret)
{
	return 0;
}

/* Outside a directive, never retain a caller-owned filename across loads. */
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
	EXPECT_EQ(conf_get_conf_file(), nullptr);

	/* the first load's file name buffer is reused for something else */
	memset(first_path, 'x', sizeof(first_path) - 1);

	std::string second_path = second.GetPath();
	ASSERT_EQ(load_conf(second_path.c_str(), items, LibConfNoError), 0);
	EXPECT_EQ(conf_get_conf_file(), nullptr);
}
