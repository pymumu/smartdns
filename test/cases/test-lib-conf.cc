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
#include "server.h"
extern "C" {
#include "smartdns/lib/conf.h"
}
#include <string>
#include <thread>
#include <vector>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

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

void expect_top_context(const std::string &file)
{
	EXPECT_STREQ(conf_get_conf_file(), file.c_str());
	char path[PATH_MAX];
	ASSERT_NE(conf_get_conf_fullpath("relative.conf", path, sizeof(path)), nullptr);
	EXPECT_EQ(path, file.substr(0, file.find_last_of('/') + 1) + "relative.conf");
}
} // namespace

TEST(LibConf, CompletedThreadDoesNotLeaveBorrowedFilename)
{
	smartdns::TempFile file;
	ASSERT_TRUE(file.Write("scope leaf\n"));
	Context context;
	config_item items[] = {{"scope", directive, &context}, {nullptr, nullptr, nullptr}};
	std::string expected = file.GetPath();
	const char *borrowed = nullptr;
	std::thread worker([&]() {
		/* The getter must stop borrowing this filename before the thread exits. */
		std::string local = expected;
		borrowed = local.c_str();
		EXPECT_EQ(load_conf(local.c_str(), items, check_handler), 0);
	});
	worker.join();
	ASSERT_EQ(context.locations.size(), 1U);
	EXPECT_EQ(context.locations[0].file, expected);
	EXPECT_EQ(context.locations[0].line, 1);
	ASSERT_NE(conf_get_conf_file(), borrowed);
	expect_top_context(expected);
}

TEST(LibConf, CallbackAndHandlerFailuresRetainOwnedTopContext)
{
	for (const char *value : {"reject", "abort"}) {
		smartdns::TempFile file;
		ASSERT_TRUE(file.Write(std::string("scope ") + value + "\n"));
		Context context;
		config_item items[] = {{"scope", directive, &context}, {nullptr, nullptr, nullptr}};
		EXPECT_EQ(load_conf(file.GetPath().c_str(), items, check_handler), -1);
		expect_top_context(file.GetPath());
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
		expect_top_context(parent.GetPath());
	}
}

static int LibConfAnyItem(const char *item, void *data, int argc, char *argv[])
{
	return 0;
}

static int LibConfNoError(const char *key, const char *value, const char *file, int lineno, int ret)
{
	return 0;
}

/* Preserve the top-level path without borrowing the caller's buffer. */
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
	EXPECT_STREQ(conf_get_conf_file(), first_path);

	/* the first load's file name buffer is reused for something else */
	memset(first_path, 'x', sizeof(first_path) - 1);
	EXPECT_STREQ(conf_get_conf_file(), first.GetPath().c_str());

	std::string second_path = second.GetPath();
	ASSERT_EQ(load_conf(second_path.c_str(), items, LibConfNoError), 0);
	EXPECT_STREQ(conf_get_conf_file(), second_path.c_str());
}

TEST(LibConf, UnknownChildDirectiveRestoresParentLocation)
{
	smartdns::TempFile child, parent;
	ASSERT_TRUE(child.Write("# child\nunknown value\n"));
	ASSERT_TRUE(parent.Write("# parent\n# parent\nscope include\n"));
	Context context;
	context.child = child.GetPath();
	config_item items[] = {{"scope", directive, &context}, {nullptr, nullptr, nullptr}};
	context.items = items;
	std::string parent_path = parent.GetPath();
	EXPECT_EQ(load_conf(parent_path.c_str(), items, check_handler), -1);
	ASSERT_EQ(context.locations.size(), 2U);
	EXPECT_EQ(context.locations[1].file, parent.GetPath());
	EXPECT_EQ(context.locations[1].line, 3);
	expect_top_context(parent_path);
}

TEST(LibConf, TooLongTopPathDoesNotOverwriteOwnedContext)
{
	smartdns::TempFile file;
	ASSERT_TRUE(file.Write("item a\n"));
	config_item items[] = {{"item", LibConfAnyItem, nullptr}, {nullptr, nullptr, nullptr}};
	ASSERT_EQ(load_conf(file.GetPath().c_str(), items, LibConfNoError), 0);
	std::string long_path(PATH_MAX, 'a');
	EXPECT_EQ(load_conf(long_path.c_str(), items, LibConfNoError), -1);
	EXPECT_EQ(errno, ENAMETOOLONG);
	expect_top_context(file.GetPath());
}

TEST(LibConf, DefaultTlsCertificatesStayBesideTheTopConfiguration)
{
	char directory[] = "/tmp/smartdns-conf-path.XXXXXX";
	ASSERT_NE(mkdtemp(directory), nullptr);
	std::string root = directory, config_dir = root + "/config", work_dir = root + "/work";
	ASSERT_EQ(mkdir(config_dir.c_str(), 0700), 0);
	ASSERT_EQ(mkdir(work_dir.c_str(), 0700), 0);
	const char *old_workdir = getenv("SMARTDNS_WORKDIR");
	bool had_workdir = old_workdir != nullptr;
	std::string saved_workdir = old_workdir ? old_workdir : "";
	Defer {
		if (had_workdir) setenv("SMARTDNS_WORKDIR", saved_workdir.c_str(), 1);
		else unsetenv("SMARTDNS_WORKDIR");
		unlink((config_dir + "/smartdns.conf").c_str());
		for (const auto &dir : {config_dir, work_dir}) {
			for (const char *name : {"smartdns-cert.pem", "smartdns-key.pem", "smartdns-root-key.pem"})
				unlink((dir + "/" + name).c_str());
		}
		rmdir(config_dir.c_str()); rmdir(work_dir.c_str()); rmdir(root.c_str());
	};
	std::string config_file = config_dir + "/smartdns.conf";
	std::ofstream conf(config_file);
	conf << "bind-tls 127.0.0.1:60053\nserver 127.0.0.1:61053\n"
		"cache-persist no\nlog-console yes\nlog-num 0\n";
	conf.close();
	ASSERT_TRUE(conf.good());
	ASSERT_EQ(setenv("SMARTDNS_WORKDIR", work_dir.c_str(), 1), 0);
	smartdns::Server server;
	ASSERT_TRUE(server.Start(config_file, smartdns::Server::CONF_TYPE_FILE));
	for (const char *name : {"smartdns-cert.pem", "smartdns-key.pem", "smartdns-root-key.pem"}) {
		EXPECT_EQ(access((config_dir + "/" + name).c_str(), F_OK), 0);
		EXPECT_NE(access((work_dir + "/" + name).c_str(), F_OK), 0);
	}
	server.Stop();
}
