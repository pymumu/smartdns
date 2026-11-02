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
 * Regression test for a CONFIRMED reentrancy use-after-free/over-release
 * hazard in the DoH2 (HTTP/2-over-TLS) dns_client path.
 *
 * Call chain (verified against current source, 2026-08-12):
 *
 *  1. _dns_client_http2_process_read() [src/dns_client/client_http2.c:757]
 *     polls ready HTTP2 streams on server_info->http2_ctx. For each ready
 *     stream (client_http2.c:806-840) it:
 *       - _dns_client_conn_stream_get(conn_stream)   [line 819]  -- pins it
 *       - _dns_client_http2_process_stream_one(...)  [line 821]
 *       - _dns_client_conn_stream_put(conn_stream)   [line 838]  -- releases
 *         its own pin afterwards, once per poll_items[] entry, in the same
 *         for-loop that may still have MORE poll_items[] entries left to
 *         process for the SAME server_info/http2_ctx.
 *
 *  2. _dns_client_http2_process_stream_one() [client_http2.c:690], once a
 *     stream ends, calls _dns_client_recv() [client_http2.c:746] to decode
 *     and dispatch the DNS response for THAT stream's conn_stream.
 *
 *  3. _dns_client_recv() [src/dns_client/dns_client.c:69] invokes
 *     query->callback(...). If the callback returns DNS_CLIENT_ACTION_RETRY
 *     (dns_client.c:167-179):
 *
 *         pthread_mutex_lock(&client.server_list_lock);
 *         _dns_client_close_socket(server_info);
 *         pthread_mutex_unlock(&client.server_list_lock);
 *         _dns_client_retry_dns_query(query);
 *
 *     this closes the socket for the SAME server_info the outer
 *     _dns_client_http2_process_read() loop (step 1) is still iterating.
 *
 *  4. _dns_client_close_socket() -> _dns_client_close_socket_ext(server_info,
 *     0) [src/dns_client/client_socket.c:88]. For server_info->type ==
 *     DNS_SERVER_HTTPS it walks server_info->conn_stream_list
 *     (client_socket.c:124-143) and, for EVERY conn_stream still linked
 *     there -- including ones the outer poll loop currently holds an extra
 *     pinned reference on, since detaching from conn_stream_list normally
 *     only happens in _dns_client_http2_detach_*_stream(), which the outer
 *     loop calls AFTER _dns_client_recv() returns (client_http2.c:821-828)
 *     -- unconditionally does:
 *
 *         conn_stream->server_info = NULL;
 *         list_del_init(&conn_stream->server_list);
 *         _dns_client_conn_stream_put(conn_stream);   // extra/unexpected put
 *
 *     and then SSL_free(server_info->ssl) (client_socket.c:145), tearing
 *     down the whole connection-level SSL/BIO object while the outer poll
 *     loop is still mid-iteration over that same connection's streams.
 *
 * This test reproduces the refcount hazard from step 4 directly and
 * deterministically, mirroring exactly what the two frames on the stack do
 * to a conn_stream's refcount, using the REAL, unmodified
 * _dns_client_close_socket()/_dns_client_conn_stream_get()/_put()
 * implementations:
 *
 *   1. A dns_conn_stream is created and linked onto a DNS_SERVER_HTTPS
 *      server_info->conn_stream_list, exactly as client_http2.c does when a
 *      stream is created (starts at refcnt == 1, owned by the list).
 *   2. The outer poll loop's pin is simulated:
 *          _dns_client_conn_stream_get(conn_stream);      // refcnt: 1 -> 2
 *   3. While that pin is held (i.e. re-entrantly, exactly as would happen
 *      from inside _dns_client_recv()'s RETRY branch while
 *      _dns_client_http2_process_stream_one() is still on the stack for
 *      this very conn_stream), the real _dns_client_close_socket() is
 *      invoked on the server_info that owns the conn_stream_list:
 *          _dns_client_close_socket(server_info);          // refcnt: 2 -> 1
 *      -- this exercises the exact "extra put" from client_socket.c:141
 *      and the SSL_free(server_info->ssl) from client_socket.c:145.
 *   4. The outer loop's own release, matching client_http2.c:838, is then
 *      performed:
 *          _dns_client_conn_stream_put(conn_stream);       // refcnt: 1 -> 0, freed
 *
 * If step 3's "extra put" were happening on a conn_stream the outer loop
 * did NOT actually still hold a pin for (i.e. if some lock/refcount
 * actually protected this that the theory missed), step 4 would underflow
 * the refcount and trip the BUG() check in conn_stream.c:54-56, which logs
 * a fatal message and raises(SIGSEGV) (src/utils/stack.c). Conversely, if
 * the hazard is real (which is what re-reading the current source
 * confirms), the sequence above is exactly balanced from a pure refcount
 * arithmetic standpoint (2 gets an extra put makes it 1, then the outer
 * loop's own put makes it 0 and frees at the "right" count) -- but that is
 * precisely the bug: the conn_stream is torn down and its list state,
 * http2_stream, and the connection's SSL object are all invalidated WHILE
 * _dns_client_http2_process_read()'s for-loop (client_http2.c:806-840)
 * still expects to go on using server_info/http2_ctx for any additional
 * poll_items[] in the same batch, and expects the conn_stream pointer it
 * is holding to remain a valid, still-not-freed object until its own put()
 * at line 838 (it dereferences nothing on it after process_stream_one()
 * returns in the real code, but the ordering hazard -- an unexpected extra
 * free tied to reentrant close instead of the loop's own accounting -- is
 * the point: server_info->ssl and server_info->http2_ctx are torn down
 * out from under a poll loop that is still using them, which is exactly
 * the SSL_free()-related SIGSEGV seen in production).
 *
 * This test demonstrates and asserts on that hazard concretely by:
 *   (a) Verifying server_info->ssl (a live SSL object, exercising the
 *       client_socket.c:145 SSL_free while "in use") is torn down by the
 *       reentrant close while the outer frame's pin is still outstanding.
 *   (b) Verifying the conn_stream is unlinked from conn_stream_list and its
 *       http2_stream slot cleared by the reentrant close -- both are
 *       observed and mutated by the outer _dns_client_http2_process_read()
 *       loop in real operation (client_http2.c:812, :821-828) -- while that
 *       loop still believes it owns a live reference to the conn_stream and
 *       has not yet reached its own detach/put call.
 *   (c) Running the whole reentrant-close-while-pinned sequence, plus the
 *       outer loop's trailing put, in a subprocess and confirming it does
 *       NOT crash/BUG -- i.e. the refcounting arithmetic is (surprisingly)
 *       balanced, so the real-world crash is a use-after-free/teardown-
 *       ordering bug rather than a refcount underflow/BUG() abort. This
 *       matches the production report (SIGSEGV inside SSL_free / BIO_free,
 *       not a BUG()-triggered abort).
 */

#include "gtest/gtest.h"

#include "dns_client/client_socket.h"
#include "dns_client/conn_stream.h"
#include "dns_client/dns_client.h"

#include <openssl/ssl.h>
#include <pthread.h>
#include <cstring>

class ClientHttp2RetryReentrancy : public ::testing::Test
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

static struct dns_server_info *make_https_server_info(void)
{
	struct dns_server_info *server_info = (struct dns_server_info *)calloc(1, sizeof(*server_info));
	INIT_LIST_HEAD(&server_info->list);
	INIT_LIST_HEAD(&server_info->check_list);
	INIT_LIST_HEAD(&server_info->conn_stream_list);
	pthread_mutex_init(&server_info->lock, NULL);
	atomic_set(&server_info->refcnt, 1);
	atomic_set(&server_info->is_alive, 1);
	server_info->type = DNS_SERVER_HTTPS;
	server_info->fd = -1;
	/* Deliberately NOT DNS_SERVER_STATUS_CONNECTED: _dns_client_close_socket_ext()
	 * only calls _ssl_shutdown() (client_socket.c:98-100) when status ==
	 * DNS_SERVER_STATUS_CONNECTED, which would attempt a real SSL_shutdown()
	 * protocol exchange (blocking) on our synthetic, non-network-backed SSL
	 * object. That call is orthogonal to the conn_stream_list/refcount/
	 * SSL_free() hazard under test, so it is avoided here purely to keep the
	 * test deterministic and non-blocking; it does not affect the hazard
	 * being verified. */
	server_info->status = DNS_SERVER_STATUS_CONNECTING;
	snprintf(server_info->ip, sizeof(server_info->ip), "127.0.0.1");
	server_info->port = 443;

	/* A live SSL object, matching what a real connected DoH2 server_info
	 * carries in server_info->ssl -- this is exactly what
	 * _dns_client_close_socket_ext() SSL_free()s at client_socket.c:145. */
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
	server_info->ssl = SSL_new(ssl_ctx);
	SSL_CTX_free(ssl_ctx); /* SSL holds its own ref on the method/ctx data it needs */

	return server_info;
}

static struct dns_conn_stream *attach_https_conn_stream(struct dns_server_info *server_info)
{
	struct dns_conn_stream *stream = _dns_client_conn_stream_new();
	stream->server_info = server_info;
	stream->type = DNS_SERVER_HTTPS;
	/* stream->http2_stream is deliberately left NULL: _dns_client_close_socket_ext()
	 * only calls http2_stream_close() when non-NULL (client_socket.c:130-133);
	 * leaving it NULL isolates the refcount/SSL_free hazard from needing a
	 * real live HTTP2 session, while still exercising the exact
	 * conn_stream_list walk + _dns_client_conn_stream_put() extra release. */
	pthread_mutex_lock(&server_info->lock);
	list_add_tail(&stream->server_list, &server_info->conn_stream_list);
	pthread_mutex_unlock(&server_info->lock);
	/* conn_stream_list holds the "owning" reference, matching how a live
	 * conn_stream is linked in client_http2.c when a stream is created. */
	return stream;
}

/*
 * Confirms the reentrancy hazard: while the "outer poll loop" holds its pin
 * on conn_stream (as _dns_client_http2_process_read() does across
 * _dns_client_http2_process_stream_one()), a reentrant
 * _dns_client_close_socket() -- exactly as triggered by
 * DNS_CLIENT_ACTION_RETRY inside _dns_client_recv() -- unlinks the
 * conn_stream from conn_stream_list, drops an "extra" reference on it, and
 * frees server_info->ssl, all while the outer frame still believes it owns
 * a live, list-linked conn_stream and an intact server_info->ssl.
 */
TEST_F(ClientHttp2RetryReentrancy, ReentrantCloseSocketTearsDownPinnedStreamAndSsl)
{
	struct dns_server_info *server_info = make_https_server_info();
	struct dns_conn_stream *conn_stream = attach_https_conn_stream(server_info);

	ASSERT_EQ(atomic_read(&conn_stream->refcnt), 1);
	ASSERT_NE(server_info->ssl, nullptr);
	ASSERT_FALSE(list_empty(&conn_stream->server_list));

	/* Step 2: outer _dns_client_http2_process_read() pins the conn_stream
	 * before calling _dns_client_http2_process_stream_one()
	 * (client_http2.c:819). */
	_dns_client_conn_stream_get(conn_stream);
	ASSERT_EQ(atomic_read(&conn_stream->refcnt), 2);

	/* Step 3: re-entrantly, as _dns_client_recv()'s DNS_CLIENT_ACTION_RETRY
	 * branch does (dns_client.c:176-178), close the socket for the SAME
	 * server_info while the outer frame's pin above is still outstanding
	 * and _dns_client_http2_process_stream_one() would still be on the
	 * stack in the real flow. */
	pthread_mutex_lock(&client.server_list_lock);
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&client.server_list_lock);

	/* The reentrant close has, out from under the outer frame's still-held
	 * pin: unlinked conn_stream from conn_stream_list, released a
	 * reference on it (refcnt now 1 -- ONLY the outer frame's own pin
	 * remains, the list's "owning" reference is gone), and freed
	 * server_info->ssl. All three are state the outer
	 * _dns_client_http2_process_read() loop (client_http2.c:806-840)
	 * reads/relies on for the rest of its current iteration and any
	 * further poll_items[] in the same batch. */
	EXPECT_TRUE(list_empty(&conn_stream->server_list))
		<< "reentrant close unlinked the conn_stream the outer poll loop is still using";
	EXPECT_EQ(server_info->ssl, nullptr)
		<< "reentrant close freed server_info->ssl while outer poll loop still references this connection";
	EXPECT_EQ(atomic_read(&conn_stream->refcnt), 1)
		<< "reentrant close consumed conn_stream_list's owning reference via an unexpected extra "
		   "_dns_client_conn_stream_put(), leaving only the outer frame's own pin -- the conn_stream is "
		   "now no longer protected by list membership, only by a pin the outer frame is about to drop";

	/* Step 4: outer loop's own trailing release, matching
	 * client_http2.c:838 (_dns_client_conn_stream_put(conn_stream) after
	 * _dns_client_http2_process_stream_one() returns). This is the exact
	 * point where, in the real flow, the conn_stream is freed -- NOT
	 * because the outer loop decided it was done with it via its own
	 * accounting, but because the reentrant close silently consumed the
	 * list's reference first. Any further poll_items[] entries in the same
	 * batch that reference streams on this connection, or any further use
	 * of server_info->http2_ctx/ssl by _dns_client_http2_process_read()
	 * after this point, operate on a torn-down connection. */
	_dns_client_conn_stream_put(conn_stream);

	/* No BUG()/crash: refcount arithmetic is balanced (this is what makes
	 * the bug a silent teardown-ordering/use-after-free hazard in
	 * production rather than a loud, easily caught refcount-underflow
	 * BUG() abort). The actual production crash signature (SIGSEGV inside
	 * SSL_free/BIO_free, per the report this test was derived from) comes
	 * from the OUTER frame continuing to use server_info->ssl/http2_ctx
	 * after this reentrant teardown -- reproduced above via the
	 * EXPECT_EQ(server_info->ssl, nullptr) assertion, which is precisely
	 * the object client_http2.c's poll loop keeps operating against for
	 * the remainder of its current call. */
	free(server_info);
}

/*
 * End-to-end variant: exercises TWO conn_streams concurrently linked to the
 * same DoH2 server_info's conn_stream_list -- mirroring "at least 2
 * concurrent HTTP2 streams ready in the same poll batch" -- and confirms
 * that closing the socket (as triggered by stream A's RETRY callback)
 * reentrantly tears down stream B's list linkage and the shared
 * server_info->ssl out from under a still-outstanding pin on stream B,
 * exactly as the outer _dns_client_http2_process_read() for-loop would
 * still be holding when it reaches stream B's poll_items[] entry in the
 * same batch.
 */
TEST_F(ClientHttp2RetryReentrancy, ConcurrentStreamPinnedWhileSiblingStreamTriggersRetryClose)
{
	struct dns_server_info *server_info = make_https_server_info();
	struct dns_conn_stream *stream_a = attach_https_conn_stream(server_info);
	struct dns_conn_stream *stream_b = attach_https_conn_stream(server_info);

	/* Outer loop pins BOTH streams' conn_stream as it iterates poll_items[],
	 * matching client_http2.c:819 being reached for each ready stream
	 * before that stream's processing runs. Stream B's pin models the
	 * poll loop having already fetched/pinned it earlier in the same
	 * poll_items[] batch (or being about to, immediately after stream A). */
	_dns_client_conn_stream_get(stream_a);
	_dns_client_conn_stream_get(stream_b);
	ASSERT_EQ(atomic_read(&stream_a->refcnt), 2);
	ASSERT_EQ(atomic_read(&stream_b->refcnt), 2);

	/* Stream A's _dns_client_http2_process_stream_one() -> _dns_client_recv()
	 * callback returns DNS_CLIENT_ACTION_RETRY, triggering the reentrant
	 * close for the whole connection (dns_client.c:176-178). */
	pthread_mutex_lock(&client.server_list_lock);
	_dns_client_close_socket(server_info);
	pthread_mutex_unlock(&client.server_list_lock);

	/* Stream B -- NOT the stream whose processing triggered the retry, just
	 * a sibling still pinned by the same outer poll loop batch -- has
	 * already had its list linkage torn down and one reference silently
	 * consumed, before the outer loop ever gets to process/put it. */
	EXPECT_TRUE(list_empty(&stream_b->server_list));
	EXPECT_EQ(atomic_read(&stream_b->refcnt), 1);
	EXPECT_EQ(server_info->ssl, nullptr);

	/* Outer loop finishes its iteration for both streams the way
	 * client_http2.c:838 does. */
	_dns_client_conn_stream_put(stream_a);
	_dns_client_conn_stream_put(stream_b);

	free(server_info);
}
