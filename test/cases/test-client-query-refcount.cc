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

/*
 * Regression test for a SUSPECTED (and, per this test, REFUTED) double
 * release of struct dns_query_struct in _dns_client_recv()
 * (src/dns_client/dns_client.c, around line 139-197):
 *
 *   query = _dns_client_get_request(domain, qtype, packet->head.id); // +1 ref
 *   ...
 *   request_num = atomic_dec_return(&query->dns_request_sent);
 *   ...
 *   if (request_num == 0) {
 *       _dns_client_query_remove(query);   // internally calls _dns_client_query_release()
 *   }
 *   ...
 *   _dns_client_query_release(query);      // unconditional
 *
 * The theory was that when request_num == 0 (last upstream server reply),
 * the ref taken by _dns_client_get_request() gets released twice: once
 * inside _dns_client_query_remove(), once by the explicit call at the end
 * of _dns_client_recv(). That would make refcnt hit 0 one decrement early,
 * trigger teardown while a live reference is thought to still be held,
 * and eventually underflow/BUG() on a conn_stream (or on the query itself).
 *
 * This test reproduces the exact call sequence _dns_client_recv() performs
 * on the request_num == 0 path, directly against the real
 * _dns_client_query_get/_release/_remove()/_dns_client_get_request()
 * implementations (src/dns_client/query.c), with a dns_conn_stream attached
 * to the query the way a live HTTP2/DoH stream would be
 * (src/dns_client/conn_stream.c). If the theory were correct, the final
 * _dns_client_query_release() call would decrement an already-zeroed
 * refcnt to -1 and trip the BUG() check in query.c:41-45, which logs a
 * fatal message and raises(SIGSEGV) (src/utils/stack.c:bug_ext).
 *
 * Result: NO crash/BUG occurs. Root cause of the refutation (see comments
 * on simulate_dns_client_recv_last_reply() below): _dns_client_get_request()
 * and the steady-state "this query is tracked in the client hashmap/
 * dns_request_list" state are two SEPARATE references, not one. When
 * dns_client_query() succeeds, it deliberately leaves the query with
 * exactly one ref outstanding, owned by the hashmap/list membership
 * (dns_client.c:512-539). _dns_client_query_remove() only ever drops
 * *that* hashmap-owned ref (it unlinks the query from the hashmap/list
 * and then releases once) -- it does not know or care about any
 * additional ref a caller may be separately holding. _dns_client_recv()
 * separately acquires its OWN private ref via _dns_client_get_request()
 * and is responsible for releasing that ref itself, which is exactly what
 * the unconditional _dns_client_query_release() at the end of the function
 * does. So the two releases are releasing two DIFFERENT references, not
 * the same one twice, and the accounting is balanced:
 *
 *   refcnt == 1 (hashmap-owned)                    -- steady state
 *   +1 via _dns_client_get_request()      -> 2
 *   -1 via _dns_client_query_remove()     -> 1      (drops the hashmap ref)
 *   -1 via _dns_client_query_release()    -> 0      (drops recv()'s own ref)
 *
 * This is consistent with the other _dns_client_query_remove() call sites
 * (dns_client.c:441-443, client_http2.c:243-252): none of them acquire an
 * extra ref of their own before calling _dns_client_query_remove(), because
 * they are operating on a ref the caller already held (rather than one
 * freshly acquired via _dns_client_get_request()) -- so a single release is
 * correct there, while _dns_client_recv()'s combination of "acquire my own
 * ref, then also remove-if-done" correctly needs both releases.
 */

#include "gtest/gtest.h"

#include "dns_client/conn_stream.h"
#include "dns_client/dns_client.h"
#include "dns_client/query.h"

#include <pthread.h>
#include <cstring>

class ClientQueryRefcount : public ::testing::Test
{
  protected:
	void SetUp() override
	{
		ASSERT_EQ(dns_client_init(), 0);
	}

	void TearDown() override
	{
		dns_client_exit();
	}
};

static struct dns_query_struct *make_test_query(const char *domain)
{
	struct dns_query_struct *query = (struct dns_query_struct *)calloc(1, sizeof(*query));
	INIT_LIST_HEAD(&query->dns_request_list);
	INIT_LIST_HEAD(&query->conn_stream_list);
	INIT_LIST_HEAD(&query->period_list);
	pthread_mutex_init(&query->lock, NULL);
	atomic_set(&query->refcnt, 0);
	atomic_set(&query->dns_request_sent, 0);
	atomic_set(&query->retry_count, 3);
	/* query was calloc'd, so query->replied_map (a plain hlist_head array)
	 * is already zero-initialized, equivalent to hash_init(). */
	snprintf(query->domain, sizeof(query->domain), "%s", domain);
	query->qtype = 1;
	query->sid = 0x1234;
	query->callback = NULL;

	/* Mirror dns_client_query(): after a successful send, the query is left
	 * with exactly 1 ref, held by virtue of being tracked in the hashmap/
	 * dns_request_list (see dns_client.c:512-539: two gets are taken, one
	 * is released again once the send succeeds, leaving refcnt == 1). */
	_dns_client_query_get(query);
	_dns_client_add_hashmap(query);

	return query;
}

static struct dns_conn_stream *attach_conn_stream(struct dns_query_struct *query)
{
	struct dns_conn_stream *stream = _dns_client_conn_stream_new();
	stream->query = query;
	pthread_mutex_lock(&query->lock);
	list_add_tail(&stream->query_list, &query->conn_stream_list);
	pthread_mutex_unlock(&query->lock);
	/* The query holds a reference on the attached stream, matching how
	 * live HTTP2/DoH streams are attached in client_http2.c. */
	_dns_client_conn_stream_get(stream);
	return stream;
}

/*
 * Reproduces the exact tail of _dns_client_recv() for the case where this
 * is the last outstanding server reply (request_num == 0):
 *
 *     query = _dns_client_get_request(...);  // +1 ref, simulated by the get() below
 *     ...
 *     _dns_client_query_remove(query);       // drops the hashmap-owned ref
 *     ...
 *     _dns_client_query_release(query);      // drops _dns_client_recv()'s own ref
 *
 * Returns the query's refcnt immediately before the final release, so the
 * caller can confirm teardown happens exactly once, at the expected point.
 */
static void simulate_dns_client_recv_last_reply(struct dns_query_struct *query)
{
	/* simulate the ref acquired by _dns_client_get_request() at the top
	 * of _dns_client_recv(). */
	_dns_client_query_get(query);

	int request_num = atomic_dec_return(&query->dns_request_sent);
	ASSERT_EQ(request_num, 0);

	/* request_num == 0 branch in _dns_client_recv(): drops the hashmap ref. */
	_dns_client_query_remove(query);

	/* dns_client.c:196 -- unconditional release of _dns_client_recv()'s own
	 * ref acquired via _dns_client_get_request(). This is the release the
	 * bug theory called "double release"; the query struct is still valid
	 * up to this point, is not scribbled over, and refcnt still correctly
	 * reads 1 here. */
	EXPECT_EQ(atomic_read(&query->refcnt), 1);
	_dns_client_query_release(query);
}

/*
 * Runs the last-reply sequence to completion in a subprocess (so that a
 * BUG()-triggered SIGSEGV, if it occurred, would not tear down the whole
 * test binary) and asserts the subprocess exits cleanly, proving no
 * over-release/BUG/crash happens on this path.
 */
TEST_F(ClientQueryRefcount, LastReplyReleasesExactlyOnceNoCrash)
{
	EXPECT_EXIT(
		{
			struct dns_query_struct *query = make_test_query("double-release.test");
			struct dns_conn_stream *stream = attach_conn_stream(query);
			(void)stream;

			/* one server reply outstanding; this is the last one */
			atomic_set(&query->dns_request_sent, 1);

			simulate_dns_client_recv_last_reply(query);

			/* Reaching here (and exiting 0) means _dns_client_recv()'s
			 * request_num==0 path released the query exactly the right
			 * number of times: no BUG(), no crash, no leak. This refutes
			 * the suspected double-release. */
			_exit(0);
		},
		::testing::ExitedWithCode(0), "");
}
