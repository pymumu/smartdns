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

#include "client.h"
#include "dns.h"
#include "include/utils.h"
#include "server.h"
#include "util.h"
#include "gtest/gtest.h"
#include <fstream>

class Hosts : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Hosts, read)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	std::string file = "/tmp/smartdns_test_hosts" + smartdns::GenerateRandomString(5) + ".hosts";
	std::string file2 = "/tmp/smartdns_test_hosts" + smartdns::GenerateRandomString(5) + ".hosts";
	std::string file3 = "/tmp/smartdns_test_hosts" + smartdns::GenerateRandomString(5) + ".hosts";
	std::ofstream ofs(file);
	std::ofstream ofs2(file2);
	std::ofstream ofs3(file3);
	ASSERT_TRUE(ofs.is_open());
	ASSERT_TRUE(ofs2.is_open());
	ASSERT_TRUE(ofs3.is_open());
	Defer
	{
		ofs.close();
		unlink(file.c_str());

		ofs2.close();
		unlink(file2.c_str());

		ofs3.close();
		unlink(file3.c_str());
	};

	ofs << "1.2.3.4   b.com\n";
	ofs << "64:ff9b::102:304   b.com\n";
	ofs.flush();

	ofs2 << "1.1.1.1 a.com 1.a.com 2.a.com\n";
	ofs2 << "# 4.5.6.7 c.com\n";
	ofs2.flush();

	ofs3 << "127.0.0.1 d.com\n";
	ofs3 << "::1 d.com\n";
	ofs3 << "0.0.0.0 e.com\n";
	ofs3 << ":: e.com\n";
	ofs3.flush();

	server_upstream.Start("udp://0.0.0.0:61053",
						  [&](struct smartdns::ServerRequestContext *request) { return smartdns::SERVER_REQUEST_SOA; });

	server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
speed-check-mode none
hosts-file /tmp/*.hosts
)""");
	smartdns::Client client;

	ASSERT_TRUE(client.Query("b.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.2.3.4");

	ASSERT_TRUE(client.Query("b.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "b.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "64:ff9b::102:304");

	ASSERT_TRUE(client.Query("-x 64:ff9b::102:304", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(),
			  "4.0.3.0.2.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "PTR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "b.com.");

	ASSERT_TRUE(client.Query("a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");

	ASSERT_TRUE(client.Query("-x 1.1.1.1", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "1.1.1.1.in-addr.arpa");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "PTR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "a.com.");

	ASSERT_TRUE(client.Query("1.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "1.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");

	ASSERT_TRUE(client.Query("2.a.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "2.a.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");

	ASSERT_TRUE(client.Query("c.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 0);
	EXPECT_EQ(client.GetStatus(), "NXDOMAIN");
	EXPECT_EQ(client.GetAuthority()[0].GetName(), "c.com");
	EXPECT_EQ(client.GetAuthority()[0].GetTTL(), 60);
	EXPECT_EQ(client.GetAuthority()[0].GetType(), "SOA");

	ASSERT_TRUE(client.Query("d.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "d.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "127.0.0.1");

	ASSERT_TRUE(client.Query("d.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "d.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "::1");

	ASSERT_TRUE(client.Query("e.com A", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "e.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "0.0.0.0");

	ASSERT_TRUE(client.Query("e.com AAAA", 60053));
	std::cout << client.GetResult() << std::endl;
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "e.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "::");
}
