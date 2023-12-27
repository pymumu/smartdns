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

#ifndef _SMARTDNS_CLIENT_
#define _SMARTDNS_CLIENT_

#include <string>
#include <unistd.h>
#include <vector>

namespace smartdns
{

class DNSRecord
{
  public:
	DNSRecord();
	virtual ~DNSRecord();

	bool Parser(const std::string &line);

	std::string GetName();

	std::string GetType();

	std::string GetClass();

	int GetTTL();

	std::string GetData();

  private:
	std::string name_;
	std::string type_;
	std::string class_;
	int ttl_;
	std::string data_;
};

class Client
{
  public:
	Client();
	virtual ~Client();
	bool Query(const std::string &dig_cmds, int port = 0, const std::string &ip = "");

	std::string GetResult();

	std::vector<DNSRecord> GetQuery();

	std::vector<DNSRecord> GetAnswer();

	std::vector<DNSRecord> GetAuthority();

	std::vector<DNSRecord> GetAdditional();

	std::vector<std::string> GetOpt();

	int GetAnswerNum();

	int GetAuthorityNum();

	std::string GetStatus();

	std::string GetServer();

	int GetQueryTime();

	int GetMsgSize();

	std::string GetFlags();

	void Clear();

	void PrintResult();

  private:
	bool ParserResult();
	bool ParserRecord(const std::string &record_str, std::vector<DNSRecord> &record);
	std::string result_;
	int answer_num_{0};
	int authority_num_{0};
	std::string status_;
	std::string server_;
	int query_time_{0};
	int msg_size_{0};
	std::string flags_;

	std::vector<DNSRecord> records_query_;
	std::vector<DNSRecord> records_answer_;
	std::vector<DNSRecord> records_authority_;
	std::vector<DNSRecord> records_additional_;
	std::vector<std::string> records_opt_;
};

} // namespace smartdns
#endif // _SMARTDNS_CLIENT_