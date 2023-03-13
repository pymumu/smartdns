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

#include "server.h"
#include "include/utils.h"
#include "util.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <fstream>

namespace smartdns
{

extern "C" int smartdns_main(int argc, char *argv[], int fd_notify);

MockServer::MockServer() {}

MockServer::~MockServer()
{
	Stop();
}

bool MockServer::IsRunning()
{
	if (fd_ > 0) {
		return true;
	}

	return false;
}

void MockServer::Stop()
{
	if (run_ == true) {
		run_ = false;
		if (thread_.joinable()) {
			thread_.join();
		}
	}

	if (fd_ > 0) {
		close(fd_);
		fd_;
	}
}

void MockServer::Run()
{
	while (run_ == true) {
		struct pollfd fds[1];
		fds[0].fd = fd_;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		int ret = poll(fds, 1, 100);
		if (ret == 0) {
			continue;
		} else if (ret < 0) {
			sleep(1);
			continue;
		}

		if (fds[0].revents & POLLIN) {
			struct sockaddr_storage from;
			socklen_t addrlen = sizeof(from);
			unsigned char in_buff[4096];
			int len = recvfrom(fd_, in_buff, sizeof(in_buff), 0, (struct sockaddr *)&from, &addrlen);
			if (len < 0) {
				continue;
			}

			char packet_buff[4096];
			unsigned char out_buff[4096];
			memset(packet_buff, 0, sizeof(packet_buff));
			struct dns_packet *packet = (struct dns_packet *)packet_buff;
			struct ServerRequestContext request;
			memset(&request, 0, sizeof(request));

			int ret = dns_decode(packet, sizeof(packet_buff), in_buff, len);
			if (ret == 0) {
				request.packet = packet;
				if (packet->head.qr == DNS_QR_QUERY) {
					struct dns_rrs *rrs = NULL;
					int rr_count = 0;
					int qtype = 0;
					int qclass = 0;
					char domain[256];

					rrs = dns_get_rrs_start(packet, DNS_RRS_QD, &rr_count);
					for (int i = 0; i < rr_count && rrs; i++, rrs = dns_get_rrs_next(packet, rrs)) {
						ret = dns_get_domain(rrs, domain, sizeof(domain), &qtype, &qclass);
						if (ret == 0) {
							request.domain = domain;
							request.qtype = (dns_type)qtype;
							request.qclass = qclass;
							break;
						}
					}
				}
			}

			request.from = (struct sockaddr_storage *)&from;
			request.fromlen = addrlen;
			request.request_data = in_buff;
			request.request_data_len = len;
			request.response_data = out_buff;
			request.response_data_len = 0;
			request.response_data_max_len = sizeof(out_buff);

			auto callback_ret = callback_(&request);
			if (callback_ret == false) {
				unsigned char out_packet_buff[4096];
				struct dns_packet *out_packet = (struct dns_packet *)out_packet_buff;
				struct dns_head head;
				memset(&head, 0, sizeof(head));
				head.id = packet->head.id;
				head.qr = DNS_QR_ANSWER;
				head.opcode = DNS_OP_QUERY;
				head.aa = 0;
				head.rd = 1;
				head.ra = 0;
				head.rcode = DNS_RC_SERVFAIL;

				dns_packet_init(out_packet, sizeof(out_packet_buff), &head);
				request.response_data_len =
					dns_encode(request.response_data, request.response_data_max_len, out_packet);
			}

			sendto(fd_, request.response_data, request.response_data_len, MSG_NOSIGNAL, (struct sockaddr *)&from,
				   addrlen);
		}
	}
}

bool MockServer::GetAddr(const std::string &host, const std::string port, int type, int protocol,
						 struct sockaddr_storage *addr, socklen_t *addrlen)

{
	struct addrinfo hints;
	struct addrinfo *result = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) {
		goto errout;
	}

	memcpy(addr, result->ai_addr, result->ai_addrlen);
	*addrlen = result->ai_addrlen;
	return true;
errout:
	if (result) {
		freeaddrinfo(result);
	}
	return NULL;
}

bool MockServer::Start(const std::string &url, ServerRequest callback)
{
	char c_scheme[256];
	char c_host[256];
	int port;
	char c_path[256];
	int fd;
	struct sockaddr_storage addr;
	socklen_t addrlen;

	if (callback == nullptr) {
		return false;
	}

	if (parse_uri(url.c_str(), c_scheme, c_host, &port, c_path) != 0) {
		return false;
	}

	std::string scheme(c_scheme);
	std::string host(c_host);
	std::string path(c_path);

	if (scheme != "udp") {
		return false;
	}

	if (GetAddr(host, std::to_string(port), SOCK_DGRAM, IPPROTO_UDP, &addr, &addrlen) == false) {
		return false;
	}

	fd = socket(addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return false;
	}

	if (bind(fd, (struct sockaddr *)&addr, addrlen) != 0) {
		close(fd);
		return false;
	}

	run_ = true;
	thread_ = std::thread(&MockServer::Run, this);
	fd_ = fd;
	callback_ = callback;
	return true;
}

Server::Server() {}

bool Server::Start(const std::string &conf, enum CONF_TYPE type)
{
	int fds[2];
	std::string conf_file;

	fds[0] = 0;
	fds[1] = 0;
	Defer
	{
		if (fds[0] > 0) {
			close(fds[0]);
		}

		if (fds[0] > 0) {
			close(fds[1]);
		}
	};

	if (type == CONF_TYPE_STRING) {
		char filename[128];
		strncpy(filename, "/tmp/smartdns_conf.XXXXXX", sizeof(filename));
		int fd = mkstemp(filename);
		if (fd < 0) {
			return false;
		}
		Defer {
			close(fd);
		};

		std::ofstream ofs(filename);
		if (ofs.is_open() == false) {
			return false;
		}
		ofs.write(conf.data(), conf.size());
		ofs.flush();
		ofs.close();
		conf_file = filename;
		clean_conf_file_ = true;
	} else if (type == CONF_TYPE_FILE) {
		conf_file = conf;
	} else {
		return false;
	}

	if (access(conf_file.c_str(), F_OK) != 0) {
		return false;
	}

	conf_file_ = conf_file;

	if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) != 0) {
		return false;
	}

	pid_t pid = fork();
	if (pid == 0) {
		std::vector<std::string> args = {
			"smartdns", "-f", "-x", "-c", conf_file, "-p", "-",
		};
		char *argv[args.size() + 1];
		for (size_t i = 0; i < args.size(); i++) {
			argv[i] = (char *)args[i].c_str();
		}

		smartdns_main(args.size(), argv, fds[1]);
		_exit(1);
	} else if (pid < 0) {
		return false;
	}

	struct pollfd pfd[1];
	pfd[0].fd = fds[0];
	pfd[0].events = POLLIN;

	int ret = poll(pfd, 1, 10000);
	if (ret == 0) {
		kill(pid, SIGKILL);
		return false;
	}

	pid_ = pid;
	return pid > 0;
}

void Server::Stop(bool graceful)
{
	if (pid_ > 0) {
		if (graceful) {
			kill(pid_, SIGTERM);
		} else {
			kill(pid_, SIGKILL);
		}
	}

	waitpid(pid_, NULL, 0);

	pid_ = 0;
	if (clean_conf_file_ == true) {
		unlink(conf_file_.c_str());
		conf_file_.clear();
		clean_conf_file_ = false;
	}
}

bool Server::IsRunning()
{
	if (pid_ <= 0) {
		return false;
	}

	if (waitpid(pid_, NULL, WNOHANG) == 0) {
		return true;
	}

	return kill(pid_, 0) == 0;
}

Server::~Server()
{
	Stop(false);
}

} // namespace smartdns