#include "gtest/gtest.h"
extern "C" {
#include "dns_client/client_quic.h"
#include "dns_client/client_http3_control.h"
#include "dns_client/conn_stream.h"
#include "dns_client/client_socket.h"
#include "smartdns/util.h"
}
#undef min
#undef max
#include "include/utils.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <functional>
#include <poll.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <vector>

namespace {
thread_local bool fail_quic_read, capture_quic_response;
thread_local dns_query_struct *cancel_quic_query = nullptr;
thread_local std::vector<unsigned char> captured_response;
}
extern "C" int __real__dns_client_socket_ssl_recv_ext(dns_server_info *, SSL *, void *, int);
extern "C" int __wrap__dns_client_socket_ssl_recv_ext(dns_server_info *server, SSL *ssl, void *data, int size)
{
    if (fail_quic_read) { errno = EIO; return -1; }
    return __real__dns_client_socket_ssl_recv_ext(server,ssl,data,size);
}
extern "C" int __real__dns_client_recv(dns_server_info *, unsigned char *, int, sockaddr *, socklen_t);
extern "C" int __wrap__dns_client_recv(dns_server_info *server, unsigned char *data, int size, sockaddr *from, socklen_t len)
{
    if (capture_quic_response) {
        captured_response.assign(data,data+size);
        if (cancel_quic_query) { auto *q=cancel_quic_query; cancel_quic_query=nullptr; _dns_client_conn_server_streams_free(server,q); }
        return 0;
    }
    return __real__dns_client_recv(server,data,size,from,len);
}

#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC) && OPENSSL_VERSION_NUMBER >= 0x30500000L
class QuicLifecycle : public ::testing::Test {
protected:
    dns_server_info endpoint{};
    SSL_CTX *server_ctx = nullptr, *client_ctx = nullptr;
    SSL *listener = nullptr, *peer = nullptr;
    int listener_fd = -1, old_epoll = -1, own_epoll = -1;
    smartdns::TempFile cert, key;
    std::vector<SSL *> peer_streams;
    std::vector<dns_conn_stream *> requests;
    dns_query_struct query{};
    void SetUp() override {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr); pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&endpoint.lock,&attr); pthread_mutexattr_destroy(&attr);
        INIT_LIST_HEAD(&endpoint.conn_stream_list);
        pthread_mutex_init(&query.lock,nullptr); INIT_LIST_HEAD(&query.conn_stream_list);
        query.sid = 0x1234;
        endpoint.fd = -1;
        captured_response.clear();
    }
    void TearDown() override {
        fail_quic_read = capture_quic_response = false; cancel_quic_query=nullptr;
        for (auto *r : requests) {
            if (!list_empty(&r->query_list)) { list_del_init(&r->query_list); r->query = nullptr; _dns_client_conn_stream_put(r); }
            if (!list_empty(&r->server_list)) { list_del_init(&r->server_list); r->server_info = nullptr; _dns_client_conn_stream_put(r); }
            _dns_client_conn_stream_put(r);
        }
#ifndef UPSTREAM_BASELINE
        _dns_http3_control_free(&endpoint);
#endif
        for (auto *s : peer_streams) SSL_free(s);
        SSL_free(endpoint.ssl); SSL_free(peer); SSL_free(listener);
        SSL_CTX_free(client_ctx); SSL_CTX_free(server_ctx);
        if (endpoint.fd >= 0) close(endpoint.fd);
        if (listener_fd >= 0) close(listener_fd);
        if (own_epoll >= 0) { close(own_epoll); client.epoll_fd = old_epoll; }
        pthread_mutex_destroy(&endpoint.lock); pthread_mutex_destroy(&query.lock);
    }
    void Pump() {
        SSL_handle_events(listener);
        if (!peer) {
            peer = SSL_accept_connection(listener,SSL_ACCEPT_CONNECTION_NO_BLOCK);
            if (peer) {
                SSL_set_blocking_mode(peer,0);
                SSL_set_default_stream_mode(peer,SSL_DEFAULT_STREAM_MODE_NONE);
                SSL_set_incoming_stream_policy(peer,SSL_INCOMING_STREAM_POLICY_ACCEPT,0);
            }
        }
        if (peer) { SSL_do_handshake(peer); SSL_handle_events(peer); }
        if (endpoint.ssl) SSL_handle_events(endpoint.ssl);
    }
    bool Until(const std::function<bool()> &done) {
        auto limit = std::chrono::steady_clock::now()+std::chrono::seconds(3);
        do { Pump(); if (done()) return true; poll(nullptr,0,1); }
        while (std::chrono::steady_clock::now()<limit);
        return false;
    }
    void Connect(bool h3) {
        ASSERT_TRUE(cert.Write("")); ASSERT_TRUE(key.Write(""));
        ASSERT_EQ(generate_cert_key(key.GetPath().c_str(),cert.GetPath().c_str(),nullptr,"DNS:localhost,IP:127.0.0.1",1),0);
        server_ctx = SSL_CTX_new(OSSL_QUIC_server_method()); ASSERT_NE(server_ctx,nullptr);
        ASSERT_EQ(SSL_CTX_use_certificate_file(server_ctx,cert.GetPath().c_str(),SSL_FILETYPE_PEM),1);
        ASSERT_EQ(SSL_CTX_use_PrivateKey_file(server_ctx,key.GetPath().c_str(),SSL_FILETYPE_PEM),1);
        SSL_CTX_set_alpn_select_cb(server_ctx,[](SSL *, const unsigned char **out,unsigned char *n,
            const unsigned char *in,unsigned length,void *) {
            static const unsigned char protocols[] = {2,'h','3',3,'d','o','q'};
            return SSL_select_next_proto(const_cast<unsigned char **>(out),n,protocols,sizeof(protocols),in,length)
                == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        },nullptr);
        listener_fd = socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); ASSERT_GE(listener_fd,0);
        sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        ASSERT_EQ(bind(listener_fd,reinterpret_cast<sockaddr *>(&addr),sizeof(addr)),0);
        socklen_t len=sizeof(addr); ASSERT_EQ(getsockname(listener_fd,reinterpret_cast<sockaddr *>(&addr),&len),0);
        listener = SSL_new_listener(server_ctx,0); ASSERT_NE(listener,nullptr);
        ASSERT_EQ(SSL_set_fd(listener,listener_fd),1); ASSERT_EQ(SSL_set_blocking_mode(listener,0),1);
        ASSERT_EQ(SSL_listen(listener),1);
        endpoint.fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); ASSERT_GE(endpoint.fd,0);
        ASSERT_EQ(connect(endpoint.fd,reinterpret_cast<sockaddr *>(&addr),sizeof(addr)),0);
        endpoint.type=h3?DNS_SERVER_HTTP3:DNS_SERVER_QUIC;
        client_ctx=SSL_CTX_new(OSSL_QUIC_client_method()); ASSERT_NE(client_ctx,nullptr);
        SSL_CTX_set_verify(client_ctx,SSL_VERIFY_NONE,nullptr);
        endpoint.ssl=SSL_new(client_ctx); ASSERT_NE(endpoint.ssl,nullptr);
        ASSERT_EQ(SSL_set_fd(endpoint.ssl,endpoint.fd),1);
        ASSERT_EQ(SSL_set_blocking_mode(endpoint.ssl,0),1);
        SSL_set_default_stream_mode(endpoint.ssl,SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_set_incoming_stream_policy(endpoint.ssl,SSL_INCOMING_STREAM_POLICY_ACCEPT,0);
        const unsigned char h3_alpn[]={2,'h','3'},doq[]={3,'d','o','q'};
        ASSERT_EQ(SSL_set_alpn_protos(endpoint.ssl,h3?h3_alpn:doq,h3?sizeof(h3_alpn):sizeof(doq)),0);
        SSL_set_connect_state(endpoint.ssl);
        ASSERT_TRUE(Until([&] { SSL_do_handshake(endpoint.ssl); return peer && SSL_is_init_finished(peer) && SSL_is_init_finished(endpoint.ssl); }));
        endpoint.status=DNS_SERVER_STATUS_CONNECTED;
        old_epoll=client.epoll_fd; own_epoll=epoll_create1(EPOLL_CLOEXEC); ASSERT_GE(own_epoll,0); client.epoll_fd=own_epoll;
        epoll_event event{}; event.events=EPOLLIN; event.data.ptr=&endpoint;
        ASSERT_EQ(epoll_ctl(own_epoll,EPOLL_CTL_ADD,endpoint.fd,&event),0);
    }
    SSL *PeerStream(bool uni) {
        SSL *s=SSL_new_stream(peer,uni?SSL_STREAM_FLAG_UNI:0);
        if (s) peer_streams.push_back(s);
        return s;
    }
    bool Send(SSL *s,const std::vector<unsigned char> &data) {
        size_t n=0;
        return SSL_write_ex(s,data.data(),data.size(),&n)==1 && n==data.size();
    }
    dns_conn_stream *Request(bool uni=false) {
        auto *r=_dns_client_conn_stream_new();
        if (!r) return nullptr;
        requests.push_back(r); r->server_info=&endpoint; r->query=&query;
#ifndef UPSTREAM_BASELINE
        r->query_id=query.sid;
#endif
        r->type=endpoint.type;
        r->quic_stream=SSL_new_stream(endpoint.ssl,uni?SSL_STREAM_FLAG_UNI:0);
        if (!r->quic_stream) return nullptr;
        SSL_set_ex_data(r->quic_stream,0,r);
        list_add_tail(&r->server_list,&endpoint.conn_stream_list); _dns_client_conn_stream_get(r);
        list_add_tail(&r->query_list,&query.conn_stream_list); _dns_client_conn_stream_get(r);
        if (!Send(r->quic_stream,{0})) return nullptr;
        return r;
    }
    SSL *AcceptRequest() {
        SSL *s=nullptr;
        if (!Until([&] { s=SSL_accept_stream(peer,SSL_ACCEPT_STREAM_NO_BLOCK); return s!=nullptr; })) return nullptr;
        peer_streams.push_back(s); return s;
    }
    void Service() {
        epoll_event event{}; event.events=EPOLLIN;
        EXPECT_EQ(_dns_client_process_quic(&endpoint,&event,get_tick_count()),0);
    }
};
TEST_F(QuicLifecycle, LocalControlStartsWithSettingsAndRemainsOpen) {
    Connect(true); ASSERT_NE(endpoint.ssl,nullptr);
    Service();
    SSL *control=AcceptRequest(); ASSERT_NE(control,nullptr);
    unsigned char bytes[32]; size_t got=0;
    ASSERT_TRUE(Until([&] { return SSL_read_ex(control,bytes,sizeof(bytes),&got)==1 && got; }));
    EXPECT_EQ(std::vector<unsigned char>(bytes,bytes+got),(std::vector<unsigned char>{0,4,4,1,0,7,0}));
    EXPECT_NE(SSL_get_stream_read_state(control),SSL_STREAM_STATE_FINISHED);
}
TEST_F(QuicLifecycle, FragmentedPeerControlAndGoawayDrainStartedRequests) {
    Connect(true); ASSERT_EQ(_dns_http3_control_poll(&endpoint),0);
    SSL *request=SSL_new_stream(endpoint.ssl,0); ASSERT_NE(request,nullptr);
    auto *r=_dns_client_conn_stream_new(); ASSERT_NE(r,nullptr); r->quic_stream=request; requests.push_back(r);
    ASSERT_TRUE(Send(request,{0}));
    SSL *control=PeerStream(true); ASSERT_NE(control,nullptr);
    for (unsigned char b : {0,4,0,0x21,2,0,0}) {
        ASSERT_TRUE(Send(control,{b}));
        ASSERT_TRUE(Until([&] { return _dns_http3_control_poll(&endpoint)==0; }));
    }
    ASSERT_TRUE(Send(control,{7,1,4}));
    ASSERT_TRUE(Until([&] { _dns_http3_control_poll(&endpoint); return !_dns_http3_request_allowed(&endpoint,nullptr); }));
    EXPECT_TRUE(_dns_http3_request_allowed(&endpoint,request));
    ASSERT_TRUE(Send(control,{7,1,8}));
    ASSERT_TRUE(Until([&] { return _dns_http3_control_poll(&endpoint)<0; }));
}
TEST_F(QuicLifecycle, DrainedGoawayRetiresTheConnectionForRetry) {
    Connect(true); ASSERT_TRUE(endpoint.ssl && peer);
    ASSERT_EQ(_dns_http3_control_poll(&endpoint),0);
    SSL *control=PeerStream(true); ASSERT_NE(control,nullptr);
    Send(control,{0,4,0,7,1,0});
    ASSERT_TRUE(Until([&] { _dns_http3_control_poll(&endpoint); return !_dns_http3_request_allowed(&endpoint,nullptr); }));
    Service();
    EXPECT_EQ(endpoint.ssl,nullptr);
    EXPECT_EQ(endpoint.status,DNS_SERVER_STATUS_DISCONNECTED);
}
TEST_F(QuicLifecycle, CriticalControlFinIsAConnectionError) {
    Connect(true); ASSERT_EQ(_dns_http3_control_poll(&endpoint),0);
    SSL *control=PeerStream(true); ASSERT_NE(control,nullptr);
    ASSERT_TRUE(Send(control,{0,4,0}));
    for (int i=0;i<10;i++) { Pump(); ASSERT_GE(_dns_http3_control_poll(&endpoint),0); }
    ASSERT_EQ(SSL_stream_conclude(control,0),1);
    EXPECT_TRUE(Until([&] { return _dns_http3_control_poll(&endpoint)<0; }));
}
TEST_F(QuicLifecycle, ResetIsProcessedWithoutKernelReadability) {
    Connect(false); auto *r=Request(); ASSERT_NE(r,nullptr);
    SSL *s=AcceptRequest(); ASSERT_NE(s,nullptr);
    ASSERT_EQ(SSL_stream_reset(s,nullptr,0),1);
    ASSERT_TRUE(Until([&] { return SSL_get_stream_read_state(r->quic_stream)==SSL_STREAM_STATE_RESET_REMOTE; }));
    pollfd fd{endpoint.fd,POLLIN,0}; EXPECT_EQ(poll(&fd,1,0),0);
#ifndef UPSTREAM_BASELINE
    EXPECT_EQ(_dns_client_quic_timeout(&endpoint,1000),0);
#endif
    Service();
    EXPECT_TRUE(list_empty(&r->server_list));
    EXPECT_NE(endpoint.ssl,nullptr);
}
TEST_F(QuicLifecycle, StopSendingAloneRetiresTheWriteSide) {
    Connect(false); ASSERT_TRUE(endpoint.ssl && peer);
    // A write-only stream isolates EW: the peer cannot also send RESET_STREAM.
    auto *r=Request(true); ASSERT_TRUE(r && r->quic_stream);
    SSL *remote=AcceptRequest(); ASSERT_NE(remote,nullptr);
    peer_streams.erase(std::remove(peer_streams.begin(),peer_streams.end(),remote),peer_streams.end());
    SSL_free(remote); // abandon the unread receive-only side: STOP_SENDING
    ASSERT_TRUE(Until([&] {
        SSL_POLL_ITEM pending{}; pending.desc=SSL_as_poll_descriptor(r->quic_stream);
        pending.events=SSL_POLL_EVENT_EW; const timeval zero{}; size_t ready=0;
        return SSL_poll(&pending,1,sizeof(pending),&zero,SSL_POLL_FLAG_NO_HANDLE_EVENTS,&ready)==1 && ready;
    }));
    SSL_POLL_ITEM item{}; item.desc=SSL_as_poll_descriptor(r->quic_stream);
    item.events=SSL_POLL_EVENT_ER|SSL_POLL_EVENT_EW; const timeval zero{}; size_t ready=0;
    ASSERT_EQ(SSL_poll(&item,1,sizeof(item),&zero,SSL_POLL_FLAG_NO_HANDLE_EVENTS,&ready),1);
    EXPECT_TRUE(item.revents&SSL_POLL_EVENT_EW);
    EXPECT_FALSE(item.revents&SSL_POLL_EVENT_ER);
    Service();
    EXPECT_TRUE(list_empty(&r->server_list));
    EXPECT_NE(endpoint.ssl,nullptr);
}
TEST_F(QuicLifecycle, HardReadErrorRetiresTheStream) {
    Connect(false); auto *r=Request(); ASSERT_NE(r,nullptr);
    SSL *s=AcceptRequest(); ASSERT_NE(s,nullptr); ASSERT_TRUE(Send(s,{0}));
    ASSERT_TRUE(Until([&] { return SSL_pending(r->quic_stream)>0; }));
    fail_quic_read=true; Service(); fail_quic_read=false;
    EXPECT_TRUE(list_empty(&r->server_list));
}
TEST_F(QuicLifecycle, CompleteDoqPayloadWaitsForNormalFin) {
    Connect(false); auto *r=Request(); ASSERT_NE(r,nullptr);
    SSL *s=AcceptRequest(); ASSERT_NE(s,nullptr);
    ASSERT_TRUE(Send(s,{0,12,0,0,0x80,0,0,0,0,0,0,0,0,0}));
    ASSERT_TRUE(Until([&] { return SSL_pending(r->quic_stream)>0; }));
    capture_quic_response=true; Service();
    EXPECT_TRUE(captured_response.empty());
    ASSERT_EQ(SSL_stream_conclude(s,0),1);
    ASSERT_TRUE(Until([&] {
        SSL_POLL_ITEM item{}; item.desc=SSL_as_poll_descriptor(r->quic_stream); item.events=SSL_POLL_EVENT_R;
        const timeval zero{}; size_t ready=0;
        return SSL_poll(&item,1,sizeof(item),&zero,SSL_POLL_FLAG_NO_HANDLE_EVENTS,&ready)==1 && ready;
    }));
    Service(); capture_quic_response=false;
    ASSERT_EQ(captured_response.size(),12U);
    EXPECT_EQ(captured_response[0],0x12); EXPECT_EQ(captured_response[1],0x34);
}
TEST_F(QuicLifecycle, CallbackCanCancelAnotherStreamInTheSameSnapshot) {
    Connect(false); ASSERT_TRUE(endpoint.ssl && peer);
    auto *first=Request(); ASSERT_TRUE(first && first->quic_stream);
    SSL *a=AcceptRequest(); ASSERT_NE(a,nullptr);
    auto *second=Request(); ASSERT_TRUE(second && second->quic_stream);
    SSL *b=AcceptRequest(); ASSERT_NE(b,nullptr);
    const std::vector<unsigned char> packet={0,12,0,0,0x80,0,0,0,0,0,0,0,0,0};
    Send(a,packet); Send(b,packet);
    ASSERT_EQ(SSL_stream_conclude(a,0),1); ASSERT_EQ(SSL_stream_conclude(b,0),1);
    ASSERT_TRUE(Until([&] { return SSL_pending(first->quic_stream)>0 && SSL_pending(second->quic_stream)>0; }));
    capture_quic_response=true; cancel_quic_query=&query;
    Service();
    EXPECT_EQ(captured_response.size(),12U);
    EXPECT_EQ(cancel_quic_query,nullptr);
    EXPECT_TRUE(list_empty(&endpoint.conn_stream_list));
}
TEST_F(QuicLifecycle, PartialControlPrefixDoesNotStayReady) {
    Connect(true); ASSERT_EQ(_dns_http3_control_poll(&endpoint),0);
    SSL *control=PeerStream(true); ASSERT_NE(control,nullptr); ASSERT_TRUE(Send(control,{0x40}));
    for (int i=0;i<20;i++) { Pump(); ASSERT_GE(_dns_http3_control_poll(&endpoint),0); }
    EXPECT_FALSE(_dns_http3_control_pending(&endpoint));
}
#endif
