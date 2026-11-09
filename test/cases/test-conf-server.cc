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

#include "gtest/gtest.h"
#include <string>

#include "dns_conf/server.h"
#include "smartdns/util.h"

class ConfServer : public ::testing::Test
{
  protected:
	int saved_server_num = 0;
	virtual void SetUp()
	{
		saved_server_num = dns_conf.server_num;
	}
	virtual void TearDown()
	{
		dns_conf.server_num = saved_server_num;
	}

	struct dns_servers *Add(int (*config_func)(void *, int, char **), const std::string &url)
	{
		std::string keyword = "server";
		std::string arg = url;
		char *argv[] = {&keyword[0], &arg[0], nullptr};
		int num = dns_conf.server_num;

		if (config_func(nullptr, 2, argv) != 0 || dns_conf.server_num != num + 1) {
			return nullptr;
		}

		return &dns_conf.servers[num];
	}
};

/* The keyword picks the transport and a URL scheme naming another transport overrides it.
 * https:// names no HTTP version, so it must not turn server-http3 / server-h3 into HTTP/2,
 * except on builds without QUIC, where it falls back to HTTPS instead of failing. */
TEST_F(ConfServer, scheme_and_keyword_type)
{
	const int REJECTED = -1;
	struct {
		int (*config_func)(void *, int, char **);
		const char *url;
		int type;
		int type_no_quic;
		int port;
	} cases[] = {
		{_config_server_http3, "https://127.0.0.1/dns-query", DNS_SERVER_HTTP3, DNS_SERVER_HTTPS, 443},
		{_config_server_http3, "https://127.0.0.1:8443/dns-query", DNS_SERVER_HTTP3, DNS_SERVER_HTTPS, 8443},
		{_config_server_http3, "h3://127.0.0.1/dns-query", DNS_SERVER_HTTP3, REJECTED, 443},
		{_config_server_http3, "http3://127.0.0.1/dns-query", DNS_SERVER_HTTP3, REJECTED, 443},
		{_config_server_http3, "127.0.0.1", DNS_SERVER_HTTP3, REJECTED, 443},
		{_config_server_https, "https://127.0.0.1/dns-query", DNS_SERVER_HTTPS, DNS_SERVER_HTTPS, 443},
		{_config_server_https, "h3://127.0.0.1/dns-query", DNS_SERVER_HTTP3, REJECTED, 443},
		{_config_server_udp, "https://127.0.0.1/dns-query", DNS_SERVER_HTTPS, DNS_SERVER_HTTPS, 443},
		{_config_server_udp, "h3://127.0.0.1/dns-query", DNS_SERVER_HTTP3, REJECTED, 443},
		{_config_server_udp, "quic://127.0.0.1", DNS_SERVER_QUIC, REJECTED, 853},
		{_config_server_quic, "tls://127.0.0.1", DNS_SERVER_TLS, DNS_SERVER_TLS, 853},
		{_config_server_tls, "https://127.0.0.1/dns-query", DNS_SERVER_HTTPS, DNS_SERVER_HTTPS, 443},
	};

	for (auto &c : cases) {
		SCOPED_TRACE(c.url);
		int type = dns_is_quic_supported() ? c.type : c.type_no_quic;
		struct dns_servers *server = Add(c.config_func, c.url);
		if (type == REJECTED) {
			EXPECT_EQ(server, nullptr);
			continue;
		}

		ASSERT_NE(server, nullptr);
		EXPECT_EQ(server->type, type);
		EXPECT_EQ(server->port, c.port);
	}
}
