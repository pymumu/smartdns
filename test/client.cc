/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#include "client.h"
#include <iostream>
#include <memory>
#include <regex>
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>

namespace smartdns
{

std::vector<std::string> StringSplit(const std::string &s, const char delim)
{
	std::vector<std::string> ret;
	std::string::size_type lastPos = s.find_first_not_of(delim, 0);
	std::string::size_type pos = s.find_first_of(delim, lastPos);
	while (std::string::npos != pos || std::string::npos != lastPos) {
		ret.push_back(s.substr(lastPos, pos - lastPos));
		lastPos = s.find_first_not_of(delim, pos);
		pos = s.find_first_of(delim, lastPos);
	}

	return ret;
}

DNSRecord::DNSRecord() {}

DNSRecord::~DNSRecord() {}

bool DNSRecord::Parser(const std::string &line)
{
	std::vector<std::string> fields_first = StringSplit(line, '\t');
	std::vector<std::string> fields;

	for (const auto &f : fields_first) {
		std::vector<std::string> fields_second = StringSplit(f, ' ');
		for (const auto &s : fields_second) {
			if (s.length() > 0) {
				fields.push_back(s);
			}
		}
	}

	if (fields.size() < 3) {
		std::cerr << "Invalid DNS record: " << line << ", size: " << fields.size() << std::endl;
		return false;
	}

	if (fields.size() == 3) {
		name_ = fields[0];
		if (name_.size() > 1) {
			name_.resize(name_.size() - 1);
		}
		class_ = fields[1];
		type_ = fields[2];
		return true;
	}

	name_ = fields[0];
	if (name_.size() > 1) {
		name_.resize(name_.size() - 1);
	}
	ttl_ = std::stoi(fields[1]);
	class_ = fields[2];
	type_ = fields[3];
	data_ = fields[4];

	for (int i = 5; i < fields.size(); i++) {
		data_ += " " + fields[i];
	}

	return true;
}

std::string DNSRecord::GetName()
{
	return name_;
}

std::string DNSRecord::GetType()
{
	return type_;
}

std::string DNSRecord::GetClass()
{
	return class_;
}

int DNSRecord::GetTTL()
{
	return ttl_;
}

std::string DNSRecord::GetData()
{
	return data_;
}

Client::Client() {}

bool Client::Query(const std::string &dig_cmds, int port, const std::string &ip)
{
	Clear();

	std::string cmd = "dig ";
	if (port > 0) {
		cmd += "-p " + std::to_string(port);
	}

	if (ip.length() > 0) {
		cmd += " @" + ip;
	} else {
		cmd += " @127.0.0.1";
	}

	cmd += " " + dig_cmds;
	cmd += " +tries=1";
	FILE *fp = nullptr;

	fp = popen(cmd.c_str(), "r");
	if (fp == nullptr) {
		return false;
	}

	std::shared_ptr<FILE> pipe(fp, pclose);
	result_.clear();
	char buffer[4096];
	usleep(10000);
	while (fgets(buffer, 4096, pipe.get())) {
		result_ += buffer;
	}

	if (ParserResult() == false) {
		Clear();
		return false;
	}

	return true;
}

std::vector<DNSRecord> Client::GetQuery()
{
	return records_query_;
}

std::vector<DNSRecord> Client::GetAnswer()
{
	return records_answer_;
}

std::vector<DNSRecord> Client::GetAuthority()
{
	return records_authority_;
}

std::vector<DNSRecord> Client::GetAdditional()
{
	return records_additional_;
}

std::vector<std::string> Client::GetOpt()
{
	return records_opt_;
}

int Client::GetAnswerNum()
{
	return answer_num_;
}

int Client::GetAuthorityNum()
{
	return authority_num_;
}

std::string Client::GetStatus()
{
	return status_;
}

std::string Client::GetServer()
{
	return server_;
}

int Client::GetQueryTime()
{
	return query_time_;
}

int Client::GetMsgSize()
{
	return msg_size_;
}

std::string Client::GetFlags()
{
	return flags_;
}

std::string Client::GetResult()
{
	return result_;
}

void Client::Clear()
{
	result_.clear();
	answer_num_ = 0;
	status_.clear();
	server_.clear();
	query_time_ = 0;
	msg_size_ = 0;
	flags_.clear();
	records_query_.clear();
	records_answer_.clear();
	records_authority_.clear();
	records_additional_.clear();
}

void Client::PrintResult()
{
	std::cout << result_ << std::endl;
}

bool Client::ParserRecord(const std::string &record_str, std::vector<DNSRecord> &record)
{
	DNSRecord r;

	std::vector<std::string> lines = StringSplit(record_str, '\n');

	for (auto &line : lines) {
		if (r.Parser(line) == false) {
			return false;
		}

		record.push_back(r);
	}

	return true;
}

bool Client::ParserResult()
{
	std::smatch match;

	std::regex reg_goanswer(";; Got answer:");
	if (std::regex_search(result_, match, reg_goanswer) == false) {
		std::cout << "DIG FAILED:\n" << result_ << std::endl;
		return false;
	}

	std::regex reg_opt(";; OPT PSEUDOSECTION:\\n((?:.|\\n|\\r\\n)+?)\\n;;",
							std::regex::ECMAScript | std::regex::optimize);
	if (std::regex_search(result_, match, reg_opt)) {
		std::string opt_str = match[1];

		std::vector<std::string> lines = StringSplit(opt_str, '\n');
		for (auto &line : lines) {
			if (line.length() <= 0) {
				continue;
			}

			line = line.substr(2);
			records_opt_.push_back(line);
		}
	}

	std::regex reg_answer_num(", ANSWER: ([0-9]+),");
	if (std::regex_search(result_, match, reg_answer_num)) {
		answer_num_ = std::stoi(match[1]);
	}

	std::regex reg_authority_num(", AUTHORITY: ([0-9]+),");
	if (std::regex_search(result_, match, reg_authority_num)) {
		authority_num_ = std::stoi(match[1]);
	}

	std::regex reg_status(", status: ([A-Z]+),");
	if (std::regex_search(result_, match, reg_status)) {
		status_ = match[1];
	}

	std::regex reg_server(";; SERVER: ([0-9.]+)#");
	if (std::regex_search(result_, match, reg_server)) {
		server_ = match[1];
	}

	std::regex reg_querytime(";; Query time: ([0-9]+) msec");
	if (std::regex_search(result_, match, reg_querytime)) {
		query_time_ = std::stoi(match[1]);
	}

	std::regex reg_msg_size(";; MSG SIZE  rcvd: ([0-9]+)");
	if (std::regex_search(result_, match, reg_msg_size)) {
		msg_size_ = std::stoi(match[1]);
	}

	std::regex reg_flags(";; flags: ([a-z A-Z]+);");
	if (std::regex_search(result_, match, reg_flags)) {
		flags_ = match[1];
	}

	std::regex reg_question(";; QUESTION SECTION:\\n((?:.|\\n|\\r\\n)+?)\\n{2,}",
							std::regex::ECMAScript | std::regex::optimize);
	if (std::regex_search(result_, match, reg_question)) {
		if (ParserRecord(match[1], records_query_) == false) {
			return false;
		}
	}

	std::regex reg_answer(";; ANSWER SECTION:\\n((?:.|\\n|\\r\\n)+?)\\n{2,}",
						  std::regex::ECMAScript | std::regex::optimize);
	if (std::regex_search(result_, match, reg_answer)) {
		if (ParserRecord(match[1], records_answer_) == false) {
			return false;
		}

		if (answer_num_ != records_answer_.size()) {
			std::cout << "DIG FAILED: Num Not Match\n" << result_ << std::endl;
			return false;
		}
	}

	std::regex reg_authority(";; AUTHORITY SECTION:\\n((?:.|\\n|\\r\\n)+?)\\n{2,}",
							 std::regex::ECMAScript | std::regex::optimize);
	if (std::regex_search(result_, match, reg_authority)) {
		if (ParserRecord(match[1], records_authority_) == false) {
			return false;
		}

		if (authority_num_ != records_authority_.size()) {
			std::cout << "DIG FAILED: Num Not Match\n" << result_ << std::endl;
			return false;
		}
	}

	std::regex reg_addition(";; ADDITIONAL SECTION:\\n((?:.|\\n|\\r\\n)+?)\\n{2,}",
							std::regex::ECMAScript | std::regex::optimize);
	if (std::regex_search(result_, match, reg_answer)) {
		if (ParserRecord(match[1], records_additional_) == false) {
			return false;
		}
	}

	return true;
}

Client::~Client() {}

} // namespace smartdns