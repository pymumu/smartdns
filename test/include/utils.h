/*************************************************************************
 *
 * Copyright (C) 2018-2023 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#ifndef _SMARTDNS_TEST_UTILS_
#define _SMARTDNS_TEST_UTILS_

#include <fstream>
#include <functional>
#include <string>
#include <vector>

namespace smartdns
{

class DeferGuard
{
  public:
	template <class Callable>

	DeferGuard(Callable &&fn) noexcept : fn_(std::forward<Callable>(fn))
	{
	}
	DeferGuard(DeferGuard &&other) noexcept
	{
		fn_ = std::move(other.fn_);
		other.fn_ = nullptr;
	}

	virtual ~DeferGuard()
	{
		if (fn_) {
			fn_();
		}
	};
	DeferGuard(const DeferGuard &) = delete;
	void operator=(const DeferGuard &) = delete;

  private:
	std::function<void()> fn_;
};

#define SMARTDNS_CONCAT_(a, b) a##b
#define SMARTDNS_CONCAT(a, b) SMARTDNS_CONCAT_(a, b)
#define Defer ::smartdns::DeferGuard SMARTDNS_CONCAT(__defer__, __LINE__) = [&]()

class TempFile
{
  public:
	TempFile();
	TempFile(const std::string &line);
	virtual ~TempFile();

	bool Write(const std::string &line);

	std::string GetPath();

	void SetPattern(const std::string &pattern);

  private:
	bool NewTempFile();
	std::string path_;
	std::ofstream ofs_;
	std::string pattern_;
};

class Commander
{
  public:
	Commander();
	virtual ~Commander();

	bool Run(const std::vector<std::string> &cmds);

	bool Run(const std::string &cmd);

	void Kill();

	void Terminate();

	int ExitCode();

	int GetPid();

  private:
	pid_t pid_{-1};
	int exit_code_ = {-1};
};

bool IsCommandExists(const std::string &cmd);

std::string GenerateRandomString(int len);

int ParserArg(const std::string &cmd, std::vector<std::string> &args);

std::vector<std::string> GetAvailableIPAddresses();

} // namespace smartdns
#endif // _SMARTDNS_TEST_UTILS_
