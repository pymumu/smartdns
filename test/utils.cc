#include "include/utils.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace smartdns
{

TempFile::TempFile()
{
	pattern_ = "/tmp/smartdns-test-tmp.XXXXXX";
}

TempFile::TempFile(const std::string &line)
{
	pattern_ = "/tmp/smartdns-test-tmp.XXXXXX";
}

TempFile::~TempFile()
{
	if (ofs_.is_open()) {
		ofs_.close();
		ofs_.clear();
	}

	if (path_.length() > 0) {
		unlink(path_.c_str());
	}
}

void TempFile::SetPattern(const std::string &pattern)
{
	pattern_ = pattern;
}

bool TempFile::Write(const std::string &line)
{
	if (ofs_.is_open() == false) {
		if (NewTempFile() == false) {
			return false;
		}
	}

	ofs_.write(line.data(), line.size());
	if (ofs_.fail()) {
		return false;
	}
	ofs_.flush();

	return true;
}

bool TempFile::NewTempFile()
{
	char filename[128];
	strncpy(filename, "/tmp/smartdns-test-tmp.XXXXXX", sizeof(filename));
	int fd = mkstemp(filename);
	if (fd < 0) {
		return false;
	}
	Defer
	{
		close(fd);
	};

	std::ofstream ofs(filename);
	if (ofs.is_open() == false) {
		return false;
	}
	ofs_ = std::move(ofs);
	path_ = filename;

	return true;
}

std::string TempFile::GetPath()
{
	if (ofs_.is_open() == false) {
		if (NewTempFile() == false) {
			return "";
		}
	}

	return path_;
}

Commander::Commander() {}
Commander::~Commander()
{
	Kill();
}

bool Commander::Run(const std::string &cmd)
{
	std::vector<std::string> args;
	if (ParserArg(cmd, args) != 0) {
		return false;
	}

	return Run(args);
}

bool Commander::Run(const std::vector<std::string> &cmds)
{
	pid_t pid;

	if (pid_ > 0) {
		return false;
	}

	pid = fork();
	if (pid < 0) {
		return false;
	}

	if (pid == 0) {
		char *argv[cmds.size() + 1];
		for (int i = 0; i < cmds.size(); i++) {
			argv[i] = (char *)cmds[i].c_str();
		}
		argv[cmds.size()] = nullptr;
		execvp(argv[0], argv);
		_exit(1);
	}

	pid_ = pid;

	return true;
}

void Commander::Kill()
{
	if (pid_ <= 0) {
		return;
	}

	kill(pid_, SIGKILL);
}

void Commander::Terminate()
{
	if (pid_ <= 0) {
		return;
	}

	kill(pid_, SIGTERM);
}

int Commander::ExitCode()
{
	int wstatus = 0;
	if (exit_code_ >= 0) {
		return exit_code_;
	}

	if (pid_ <= 0) {
		return -1;
	}

	if (waitpid(pid_, &wstatus, 0) == -1) {
		return -1;
	}

	exit_code_ = WEXITSTATUS(wstatus);

	return exit_code_;
}

int Commander::GetPid()
{
	return pid_;
}

bool IsCommandExists(const std::string &cmd)
{
	char *copy_path = nullptr;
	char cmd_path[4096];
	const char *env_path = getenv("PATH");
	char *save_ptr = nullptr;

	if (env_path == nullptr) {
		env_path = "/bin:/usr/bin:/usr/local/bin";
	}

	copy_path = strdup(env_path);
	if (copy_path == nullptr) {
		return false;
	}

	Defer
	{
		free(copy_path);
	};

	for (char *tok = strtok_r(copy_path, ":", &save_ptr); tok; tok = strtok_r(nullptr, ":", &save_ptr)) {
		snprintf(cmd_path, sizeof(cmd_path), "%s/%s", tok, cmd.c_str());
		if (access(cmd_path, X_OK) != 0) {
			continue;
		}

		return true;
	}

	return false;
}

std::string GenerateRandomString(int len)
{
	std::string result;
	static const char alphanum[] = "0123456789"
								   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
								   "abcdefghijklmnopqrstuvwxyz";
	result.resize(len);

	for (int i = 0; i < len; ++i) {
		result[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return result;
}

int ParserArg(const std::string &cmd, std::vector<std::string> &args)
{
	std::string arg;
	char quoteChar = 0;

	for (char ch : cmd) {
		if (quoteChar == '\\') {
			arg.push_back(ch);
			quoteChar = 0;
			continue;
		}

		if (quoteChar && ch != quoteChar) {
			arg.push_back(ch);
			continue;
		}

		switch (ch) {
		case '\'':
		case '\"':
		case '\\':
			quoteChar = quoteChar ? 0 : ch;
			break;
		case ' ':
		case '\t':
		case '\n':
			if (!arg.empty()) {
				args.push_back(arg);
				arg.clear();
			}
			break;
		default:
			arg.push_back(ch);
			break;
		}
	}

	if (!arg.empty()) {
		args.push_back(arg);
	}

	return 0;
}

std::vector<std::string> GetAvailableIPAddresses()
{
	std::vector<std::string> ipAddresses;

	struct ifaddrs *ifAddrStruct = nullptr;
	struct ifaddrs *ifa = nullptr;
	void *tmpAddrPtr = nullptr;

	getifaddrs(&ifAddrStruct);

	for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr) {
			continue;
		}

		if (ifa->ifa_addr->sa_family == AF_INET) { // IPv4 address
			tmpAddrPtr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			char addressBuffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
			std::string ipAddress(addressBuffer);

			if (!ipAddress.empty() && ipAddress.substr(0, 4) != "127.") {
				ipAddresses.push_back(ipAddress);
			}
		}
	}

	if (ifAddrStruct != nullptr) {
		freeifaddrs(ifAddrStruct);
	}

	return ipAddresses;
}

} // namespace smartdns