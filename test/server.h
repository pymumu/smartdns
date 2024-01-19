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

#ifndef _SMARTDNS_SERVER_
#define _SMARTDNS_SERVER_

#include "dns.h"
#include "fast_ping.h"
#include "include/utils.h"
#include <functional>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace smartdns
{

class Server
{
  public:
	struct MockPingIP {
		PING_TYPE type;
		std::string host;
		int ttl;
		float time;
	};
	enum CONF_TYPE {
		CONF_TYPE_STRING,
		CONF_TYPE_FILE,
	};
	enum CREATE_MODE {
		CREATE_MODE_FORK,
		CREATE_MODE_THREAD,
	};
	Server();
	Server(enum CREATE_MODE mode);
	virtual ~Server();

	void MockPing(PING_TYPE type, const std::string &host, int ttl, float time);
	bool Start(const std::string &conf, enum CONF_TYPE type = CONF_TYPE_STRING);
	void Stop(bool graceful = true);
	bool IsRunning();

  private:
	static void StartPost(void *arg);
	pid_t pid_;
	std::thread thread_;
	int fd_;
	std::string conf_file_;
	TempFile conf_temp_file_;
	std::vector<MockPingIP> mock_ping_ips_;
	enum CREATE_MODE mode_;
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

typedef enum {
	SERVER_REQUEST_OK = 0,
	SERVER_REQUEST_ERROR,
	SERVER_REQUEST_NO_RESPONSE,
	SERVER_REQUEST_SOA,
} ServerRequestResult;

using ServerRequest = std::function<ServerRequestResult(struct ServerRequestContext *request)>;

class MockServer
{
  public:
	MockServer();
	virtual ~MockServer();

	bool Start(const std::string &url, ServerRequest callback);
	void Stop();
	bool IsRunning();

	static bool AddIP(struct ServerRequestContext *request, const std::string &domain, const std::string &ip,
					  int ttl = 60);

  private:
	void Run();

	static bool GetAddr(const std::string &host, const std::string port, int type, int protocol,
						struct sockaddr_storage *addr, socklen_t *addrlen);
	int fd_{0};
	std::thread thread_;
	bool run_{false};
	ServerRequest callback_{nullptr};
};

} // namespace smartdns
#endif // _SMARTDNS_SERVER_