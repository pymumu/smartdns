/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
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
#include "smartdns/dns.h"
#include "gtest/gtest.h"

class Audit : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Audit, log)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;

	Defer
	{
		unlink("/tmp/audit.log");
	};

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->qtype != DNS_T_A) {
			return smartdns::SERVER_REQUEST_SOA;
		}

		smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 611);
		return smartdns::SERVER_REQUEST_OK;
	});

	server.Start(R"""(bind [::]:60053
 audit-file /tmp/audit.log
 audit-enable yes
 server 127.0.0.1:61053
 )""");
	smartdns::Client client;
	ASSERT_TRUE(client.Query("a.com", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	std::ifstream audit_file("/tmp/audit.log");
	std::string line;
	bool found = false;
	while (std::getline(audit_file, line)) {
		if (line.find("a.com") != std::string::npos) {
			found = true;
			break;
		}
	}

	audit_file.close();

	ASSERT_TRUE(found) << "Audit log for a.com not found";
}
