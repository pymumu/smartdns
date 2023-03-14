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

#ifndef _SMARTDNS_SERVER_
#define _SMARTDNS_SERVER_

#include "dns.h"
#include <functional>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <thread>

namespace smartdns
{

class Server
{
  public:
	enum CONF_TYPE {
		CONF_TYPE_STRING,
		CONF_TYPE_FILE,
	};
	Server();
	virtual ~Server();

	bool Start(const std::string &conf, enum CONF_TYPE type = CONF_TYPE_STRING);
	void Stop(bool graceful = true);
	bool IsRunning();

  private:
	pid_t pid_;
	int fd_;
	std::string conf_file_;
	bool clean_conf_file_{false};
};

struct ServerRequestContext {
	std::string domain;
	dns_type qtype;
	int qclass;
	struct sockaddr_storage *from;
	socklen_t fromlen;
	struct dns_packet *packet;
	uint8_t *request_data;
	int request_data_len;
	uint8_t *response_data;
    struct dns_packet *response_packet;
	int response_data_max_len;
	int response_data_len;
};

using ServerRequest = std::function<bool(struct ServerRequestContext *request)>;

class MockServer
{
  public:
	MockServer();
	virtual ~MockServer();

	bool Start(const std::string &url, ServerRequest callback);
	void Stop();
	bool IsRunning();

  private:
	void Run();

	bool GetAddr(const std::string &host, const std::string port, int type, int protocol, struct sockaddr_storage *addr,
				 socklen_t *addrlen);
	int fd_;
	std::thread thread_;
	bool run_;
	ServerRequest callback_;
};

} // namespace smartdns
#endif // _SMARTDNS_SERVER_