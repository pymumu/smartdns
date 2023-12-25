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
#include "dns_server.h"
#include "fast_ping.h"
#include "include/utils.h"
#include "smartdns.h"
#include "util.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <fstream>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace smartdns
{

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
			int query_id = 0;
			int len = recvfrom(fd_, in_buff, sizeof(in_buff), 0, (struct sockaddr *)&from, &addrlen);
			if (len < 0) {
				continue;
			}

			char packet_buff[4096];
			unsigned char response_data_buff[4096];
			unsigned char response_packet_buff[4096];
			memset(packet_buff, 0, sizeof(packet_buff));
			struct dns_packet *packet = (struct dns_packet *)packet_buff;
			struct ServerRequestContext request;
			memset(&request, 0, sizeof(request));

			int ret = dns_decode(packet, sizeof(packet_buff), in_buff, len);
			if (ret == 0) {
				request.packet = packet;
				query_id = packet->head.id;
				if (packet->head.qr == DNS_QR_QUERY) {
					struct dns_rrs *rrs = nullptr;
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
			request.response_packet = (struct dns_packet *)response_packet_buff;
			request.response_data = response_data_buff;
			request.response_data_len = 0;
			request.response_data_max_len = sizeof(response_data_buff);

			struct dns_head head;
			memset(&head, 0, sizeof(head));
			head.id = query_id;
			head.qr = DNS_QR_ANSWER;
			head.opcode = DNS_OP_QUERY;
			head.aa = 0;
			head.rd = 0;
			head.ra = 1;
			head.rcode = DNS_RC_NOERROR;
			dns_packet_init(request.response_packet, sizeof(response_packet_buff), &head);

			auto callback_ret = callback_(&request);
			if (callback_ret == SERVER_REQUEST_ERROR) {
				dns_packet_init(request.response_packet, sizeof(response_packet_buff), &head);
				request.response_packet->head.rcode = DNS_RC_SERVFAIL;
				dns_add_domain(request.response_packet, request.domain.c_str(), request.qtype, request.qclass);
				request.response_data_len =
					dns_encode(request.response_data, request.response_data_max_len, request.response_packet);
			} else if (callback_ret == SERVER_REQUEST_NO_RESPONSE) {
				continue;
			} else if (request.response_data_len == 0) {
				if (callback_ret == SERVER_REQUEST_OK) {
					request.response_data_len =
						dns_encode(request.response_data, request.response_data_max_len, request.response_packet);
				} else if (callback_ret == SERVER_REQUEST_SOA) {
					struct dns_soa soa;
					memset(&soa, 0, sizeof(soa));
					strncpy(soa.mname, "ns1.example.com", sizeof(soa.mname));
					strncpy(soa.rname, "hostmaster.example.com", sizeof(soa.rname));
					soa.serial = 1;
					soa.refresh = 3600;
					soa.retry = 600;
					soa.expire = 86400;
					soa.minimum = 3600;
					dns_packet_init(request.response_packet, sizeof(response_packet_buff), &head);
					dns_add_domain(request.response_packet, request.domain.c_str(), request.qtype, request.qclass);
					request.response_packet->head.rcode = DNS_RC_NXDOMAIN;
					dns_add_SOA(request.response_packet, DNS_RRS_AN, request.domain.c_str(), 1, &soa);
					request.response_data_len =
						dns_encode(request.response_data, request.response_data_max_len, request.response_packet);
				}
			}

			sendto(fd_, request.response_data, request.response_data_len, MSG_NOSIGNAL, (struct sockaddr *)&from,
				   addrlen);
		}
	}
}

bool MockServer::AddIP(struct ServerRequestContext *request, const std::string &domain, const std::string &ip, int ttl)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));

	if (GetAddr(ip, "53", SOCK_DGRAM, IPPROTO_UDP, &addr, &addrlen)) {
		if (addr.ss_family == AF_INET) {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
			dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), ttl,
					  (unsigned char *)&addr4->sin_addr.s_addr);
		} else if (addr.ss_family == AF_INET6) {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
			if (IN6_IS_ADDR_V4MAPPED(&addr6->sin6_addr)) {
				dns_add_A(request->response_packet, DNS_RRS_AN, domain.c_str(), ttl,
						  (unsigned char *)&addr6->sin6_addr.s6_addr[12]);
				return true;
			}
			dns_add_AAAA(request->response_packet, DNS_RRS_AN, domain.c_str(), ttl,
						 (unsigned char *)&addr6->sin6_addr.s6_addr);
		}
		return true;
	}

	return false;
}

bool MockServer::GetAddr(const std::string &host, const std::string port, int type, int protocol,
						 struct sockaddr_storage *addr, socklen_t *addrlen)

{
	struct addrinfo hints;
	struct addrinfo *result = nullptr;

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

	return false;
}

bool MockServer::Start(const std::string &url, ServerRequest callback)
{
	char c_scheme[256];
	char c_host[256];
	int port;
	char c_path[256];
	int fd;
	int yes = 1;
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

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));

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

Server::Server()
{
	mode_ = Server::CREATE_MODE_FORK;
}

Server::Server(enum Server::CREATE_MODE mode)
{
	mode_ = mode;
}

void Server::MockPing(PING_TYPE type, const std::string &host, int ttl, float time)
{
	struct MockPingIP ping_ip;
	ping_ip.type = type;
	ping_ip.host = host;
	ping_ip.ttl = ttl;
	ping_ip.time = time;
	mock_ping_ips_.push_back(ping_ip);
}

void Server::StartPost(void *arg)
{
	Server *server = (Server *)arg;
	bool has_ipv6 = false;
	for (auto &it : server->mock_ping_ips_) {
		if (has_ipv6 == false && check_is_ipv6(it.host.c_str()) == 0) {
			has_ipv6 = true;
		}

		fast_ping_fake_ip_add(it.type, it.host.c_str(), it.ttl, it.time);
	}

	if (has_ipv6 == true) {
		fast_ping_fake_ip_add(PING_TYPE_ICMP, "2001::", 64, 10);
		dns_server_check_ipv6_ready();
	}
}

bool Server::Start(const std::string &conf, enum CONF_TYPE type)
{
	pid_t pid = 0;
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

	const char *default_conf = R"""(
log-num 0
log-console yes
log-level debug
cache-persist no
)""";

	if (type == CONF_TYPE_STRING) {
		conf_temp_file_.SetPattern("/tmp/smartdns_conf.XXXXXX");
		conf_temp_file_.Write(default_conf);
		conf_temp_file_.Write(conf);
		conf_file = conf_temp_file_.GetPath();
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

	if (mode_ == CREATE_MODE_FORK) {
		pid = fork();
		if (pid == 0) {
			std::vector<std::string> args = {
				"smartdns", "-f", "-x", "-c", conf_file, "-p", "-",
			};
			char *argv[args.size() + 1];
			for (size_t i = 0; i < args.size(); i++) {
				argv[i] = (char *)args[i].c_str();
			}

			smartdns_reg_post_func(Server::StartPost, this);
			smartdns_main(args.size(), argv, fds[1], 0);
			_exit(1);
		} else if (pid < 0) {
			return false;
		}
	} else if (mode_ == CREATE_MODE_THREAD) {
		thread_ = std::thread([&]() {
			std::vector<std::string> args = {"smartdns", "-f", "-x", "-c", conf_file_, "-p", "-", "-S"};
			char *argv[args.size() + 1];
			for (size_t i = 0; i < args.size(); i++) {
				argv[i] = (char *)args[i].c_str();
			}

			smartdns_reg_post_func(Server::StartPost, this);
			smartdns_main(args.size(), argv, fds[1], 1);
			smartdns_reg_post_func(nullptr, nullptr);
		});
	} else {
		return false;
	}

	struct pollfd pfd[1];
	pfd[0].fd = fds[0];
	pfd[0].events = POLLIN;

	int ret = poll(pfd, 1, 10000);
	if (ret == 0) {
		if (thread_.joinable()) {
			thread_.join();
		}

		if (pid > 0) {
			kill(pid, SIGKILL);
		}
		return false;
	}

	pid_ = pid;
	return pid > 0;
}

void Server::Stop(bool graceful)
{
	if (thread_.joinable()) {
		dns_server_stop();
		thread_.join();
	}

	if (pid_ > 0) {
		if (graceful) {
			kill(pid_, SIGTERM);
		} else {
			kill(pid_, SIGKILL);
		}
	}

	waitpid(pid_, nullptr, 0);

	pid_ = 0;
}

bool Server::IsRunning()
{
	if (pid_ <= 0) {
		return false;
	}

	if (waitpid(pid_, nullptr, WNOHANG) == 0) {
		return true;
	}

	return kill(pid_, 0) == 0;
}

Server::~Server()
{
	Stop(false);
}

} // namespace smartdns