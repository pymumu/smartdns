#include "gtest/gtest.h"
extern "C" {
#include "smartdns/http2.h"
#include "dns_client/conn_stream.h"
}
#undef min
#undef max
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

class Http2Cancellation : public ::testing::Test {
protected:
    http2_ctx *ctx = nullptr;
    std::vector<uint8_t> input, output;
    std::vector<http2_stream *> owned;
    static int Read(void *p, uint8_t *data, int length) {
        auto &v = static_cast<Http2Cancellation *>(p)->input;
        if (v.empty()) { errno = EAGAIN; return -1; }
        int n = std::min(length, static_cast<int>(v.size()));
        memcpy(data, v.data(), n); v.erase(v.begin(), v.begin()+n); return n;
    }
    static int Write(void *p, const uint8_t *data, int length) {
        auto &v = static_cast<Http2Cancellation *>(p)->output;
        v.insert(v.end(), data, data+length); return length;
    }
    void Frame(unsigned type, unsigned flags, unsigned id, std::vector<uint8_t> payload) {
        unsigned n = payload.size();
        input.insert(input.end(), {uint8_t(n>>16),uint8_t(n>>8),uint8_t(n),uint8_t(type),uint8_t(flags),
            uint8_t(id>>24),uint8_t(id>>16),uint8_t(id>>8),uint8_t(id)});
        input.insert(input.end(), payload.begin(), payload.end());
    }
    void SetUp() override {
        ctx = http2_ctx_client_new("test", Read, Write, this, nullptr);
        ASSERT_NE(ctx, nullptr);
        Frame(4, 0, 0, {0,4,0,0,0,0}); // peer stream window is zero
        ASSERT_EQ(http2_ctx_handshake(ctx), 1);
        output.clear();
    }
    void TearDown() override {
        for (auto *stream : owned) http2_stream_close(stream);
        http2_ctx_close(ctx);
    }
    http2_stream *Request() {
        auto *s = http2_stream_new(ctx);
        if (s) {
            owned.push_back(s);
            EXPECT_EQ(http2_stream_set_request(s,"POST","/dns-query","https",nullptr),0);
        }
        return s;
    }
    void Release(http2_stream *s, bool abort) {
        owned.erase(std::find(owned.begin(),owned.end(),s));
        if (abort) http2_stream_abort(s); else http2_stream_close(s);
    }
    unsigned Frames(unsigned type) {
        unsigned count = 0;
        for (size_t p = 0; p+9 <= output.size();) {
            size_t n = (output[p]<<16)|(output[p+1]<<8)|output[p+2];
            if (p+9+n > output.size()) break;
            count += output[p+3] == type; p += 9+n;
        }
        return count;
    }
    void Window(unsigned id) {
        Frame(8, 0, id, {0,0,1,0});
        http2_ctx_poll(ctx,nullptr,0,nullptr);
    }
};
TEST_F(Http2Cancellation, AbortDiscardsUnscheduledBodyAndReleasesCapacity) {
    auto *s = Request(); ASSERT_NE(s,nullptr);
    unsigned id = http2_stream_get_id(s);
    const uint8_t body[] = {1,2,3};
    EXPECT_EQ(http2_stream_write_body(s,body,sizeof(body),1),sizeof(body));
    EXPECT_EQ(Frames(0),0U);
    Release(s,true);
    Window(id);
    EXPECT_EQ(Frames(0),0U);
    EXPECT_EQ(Frames(3),1U);
    auto *replacement = Request(); ASSERT_NE(replacement,nullptr);
}
TEST_F(Http2Cancellation, NormalCloseStillFlushesAfterWindowUpdate) {
    auto *s = Request(); ASSERT_NE(s,nullptr);
    unsigned id = http2_stream_get_id(s);
    const uint8_t body[] = {1,2,3};
    EXPECT_EQ(http2_stream_write_body(s,body,sizeof(body),1),sizeof(body));
    Release(s,false);
    Window(id);
    EXPECT_EQ(Frames(0),1U);
}
TEST_F(Http2Cancellation, ResetIsDistinctFromFinishedBodyAndSurvivesContextTeardown) {
    auto *s = Request(); ASSERT_NE(s,nullptr);
    unsigned id = http2_stream_get_id(s);
    Frame(1,4,id,{0x88});
    Frame(0,0,id,{1,2,3});
    Frame(3,0,id,{0,0,0,8});
    http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_EQ(http2_stream_is_reset(s),1);
    http2_ctx_close(ctx); ctx = nullptr;
    EXPECT_EQ(http2_stream_is_reset(s),1);
}
TEST_F(Http2Cancellation, QueryCancellationDetachesEndpointOwnership) {
    dns_server_info endpoint{};
    pthread_mutex_init(&endpoint.lock,nullptr);
    INIT_LIST_HEAD(&endpoint.conn_stream_list);
    auto *conn = _dns_client_conn_stream_new(); ASSERT_NE(conn,nullptr);
    conn->type = DNS_SERVER_HTTPS;
    conn->server_info = &endpoint;
    conn->http2_stream = Request(); ASSERT_NE(conn->http2_stream,nullptr);
    auto *stream = conn->http2_stream;
    unsigned id = http2_stream_get_id(stream);
    owned.erase(std::find(owned.begin(),owned.end(),stream));
    list_add_tail(&conn->server_list,&endpoint.conn_stream_list);
    _dns_client_conn_stream_get(conn);
    _dns_client_conn_stream_cancel(conn);
    EXPECT_TRUE(list_empty(&endpoint.conn_stream_list));
    EXPECT_EQ(conn->http2_stream,nullptr);
    Window(id);
    EXPECT_EQ(Frames(3),1U);
    _dns_client_conn_stream_put(conn);
    pthread_mutex_destroy(&endpoint.lock);
}
TEST_F(Http2Cancellation, DetachedStreamHasExactlyOneClosingOwner) {
    auto *conn = _dns_client_conn_stream_new(); ASSERT_NE(conn,nullptr);
    conn->type=DNS_SERVER_HTTPS;
    auto *stream=Request(); ASSERT_NE(stream,nullptr);
    owned.erase(std::find(owned.begin(),owned.end(),stream));
    conn->http2_stream=stream; // endpoint already transferred close ownership
    _dns_client_conn_stream_cancel(conn);
    EXPECT_EQ(Frames(3),0U);
    EXPECT_EQ(conn->http2_stream,stream);
    // The transferred owner takes and closes it once, outside the endpoint lock.
    conn->http2_stream=nullptr;
    http2_stream_abort(stream);
    EXPECT_EQ(Frames(3),1U);
    _dns_client_conn_stream_put(conn);
}
TEST_F(Http2Cancellation, IdleAbortDoesNotResetAnUnopenedStream) {
    auto *stream=http2_stream_new(ctx); ASSERT_NE(stream,nullptr);
    owned.push_back(stream);
    Release(stream,true);
    EXPECT_EQ(Frames(1),0U);
    EXPECT_EQ(Frames(3),0U);
}
TEST_F(Http2Cancellation, ReceivedResetDoesNotGenerateAnotherReset) {
    auto *stream=Request(); ASSERT_NE(stream,nullptr);
    Frame(3,0,http2_stream_get_id(stream),{0,0,0,8});
    http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_EQ(http2_stream_is_reset(stream),1);
    Release(stream,true);
    EXPECT_EQ(Frames(3),0U);
}
TEST_F(Http2Cancellation, CompletedResponseSurvivesFollowingNoErrorReset) {
    auto *stream=Request(); ASSERT_NE(stream,nullptr);
    unsigned id=http2_stream_get_id(stream);
    Frame(1,4,id,{0x88});
    Frame(0,1,id,{1,2,3});
    Frame(3,0,id,{0,0,0,0});
    http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_EQ(http2_stream_is_reset(stream),0);
    EXPECT_EQ(http2_stream_is_remote_end(stream),1);
    EXPECT_EQ(http2_stream_is_end(stream),0); // buffered content is still readable
    uint8_t body[3]; EXPECT_EQ(http2_stream_read_body(stream,body,sizeof(body)),3);
    EXPECT_EQ(body[0],1); EXPECT_EQ(body[2],3);
    EXPECT_EQ(http2_stream_is_end(stream),1);
}
TEST_F(Http2Cancellation, CompletedServerRequestStillHonorsPeerCancellation) {
    http2_ctx_close(ctx); ctx=http2_ctx_server_new("server.test",Read,Write,this,nullptr);
    ASSERT_NE(ctx,nullptr); input.clear(); output.clear();
    const char preface[]="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    input.insert(input.end(),preface,preface+sizeof(preface)-1);
    Frame(4,0,0,{});
    Frame(1,5,1,{0x82,0x84,0x87,0x01,9,'l','o','c','a','l','h','o','s','t'});
    ASSERT_EQ(http2_ctx_handshake(ctx),1);
    auto *stream=http2_ctx_accept_stream(ctx); ASSERT_NE(stream,nullptr); owned.push_back(stream);
    EXPECT_EQ(http2_stream_is_remote_end(stream),1);
    EXPECT_EQ(http2_stream_is_reset(stream),0);
    Frame(3,0,1,{0,0,0,8}); http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_EQ(http2_stream_is_reset(stream),1);
}
