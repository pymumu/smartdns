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
#include "include/utils.h"
#include "server.h"
#include "gtest/gtest.h"

TEST(MockServer, query_fail)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		request->response_data_len = 0;
		return smartdns::SERVER_REQUEST_ERROR;
	});

	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "SERVFAIL");
}

TEST(MockServer, soa)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:61053",
				 [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
}

TEST(MockServer, noerror)
{
	smartdns::MockServer server;
	smartdns::Client client;
	server.Start("udp://0.0.0.0:61053",
				 [](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_OK; });

	ASSERT_TRUE(client.Query("example.com", 61053));
	std::cout << client.GetResult() << std::endl;
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}
