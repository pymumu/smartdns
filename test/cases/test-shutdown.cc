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


#include "client.h"
#include "server.h"
#include "gtest/gtest.h"
#include <string>
#include <sys/wait.h>
#include <thread>
#include <vector>

/*
 * Exit with upstream queries still pending (dns_client_exit completes them into the server/cache)
 * while short-TTL cache entries keep the cache timers firing.
 */
TEST(Shutdown, ExitWithPendingQueriesAndExpiringCache)
{
	smartdns::MockServer server_upstream;

	server_upstream.Start("udp://0.0.0.0:61053", [](struct smartdns::ServerRequestContext *request) {
		if (request->domain.rfind("slow", 0) == 0) {
			return smartdns::SERVER_REQUEST_NO_RESPONSE;
		}
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4", 1);
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	for (int round = 0; round < 3; round++) {
		smartdns::Server server;
		ASSERT_TRUE(server.Start(R"""(bind [::]:60053
server 127.0.0.1:61053
prefetch-domain yes
serve-expired yes
serve-expired-ttl 2
rr-ttl-max 1
speed-check-mode none
log-level error
)"""));

		for (int i = 0; i < 20; i++) {
			smartdns::Client client;
			ASSERT_TRUE(client.Query("fast" + std::to_string(i) + ".com A", 60053));
		}

		/* let cache entries expire so timer callbacks are running around shutdown */
		usleep(1100 * 1000);

		std::vector<std::thread> pending;
		for (int i = 0; i < 10; i++) {
			pending.emplace_back([i]() {
				smartdns::Client client;
				client.Query("slow" + std::to_string(i) + ".com A +time=2", 60053);
			});
		}
		usleep(300 * 1000);

		server.Stop();
		for (auto &t : pending) {
			t.join();
		}

		int status = server.GetWaitStatus();
		ASSERT_TRUE(WIFEXITED(status)) << "round " << round << " status " << status;
		EXPECT_EQ(WEXITSTATUS(status), 0) << "round " << round;
	}
}
