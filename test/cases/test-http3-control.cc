#include "gtest/gtest.h"
extern "C" {
#include "dns_client/client_http3_control.h"
#include "smartdns/http_parse.h"
}
#undef min
#undef max
#include <vector>
#include <cstring>
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
namespace {
struct Control {
    dns_server_info server{};
    ~Control() { _dns_http3_control_free(&server); }
    int Feed(unsigned slot, const std::vector<unsigned char> &v) {
        return _dns_http3_control_test_feed(&server, slot, v.data(), v.size());
    }
};
}
TEST(Http3Control, SettingsAtEverySplitAndLegalNonminimalVarints) {
    const std::vector<unsigned char> bytes = {0x40,0,0x80,0,0,4,0xc0,0,0,0,0,0,0,0};
    for (size_t split = 0; split <= bytes.size(); split++) {
        Control c;
        EXPECT_EQ(c.Feed(0, {bytes.begin(), bytes.begin()+split}), 0);
        EXPECT_EQ(c.Feed(0, {bytes.begin()+split, bytes.end()}), 0);
    }
}
TEST(Http3Control, MissingRepeatedAndDuplicateUnknownSettingsFail) {
    { Control c; EXPECT_LT(c.Feed(0, {0,7,1,0}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {0,4,0,4,0}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {0,4,4,0x21,0,0x21,1}), 0); }
    { Control c; EXPECT_LT(c.Feed(0, {0,4,2,2,0}), 0); }
}
TEST(Http3Control, UnknownFramesSkipIncrementally) {
    Control c;
    EXPECT_EQ(c.Feed(0, {0,4,0,0x21,4,1}), 0);
    EXPECT_EQ(c.Feed(0, {2,3,4,7,1,0}), 0);
    EXPECT_FALSE(_dns_http3_request_allowed(&c.server, nullptr));
}
TEST(Http3Control, DuplicateCriticalStreamsAndPushRejected) {
    Control c;
    EXPECT_EQ(c.Feed(0, {2}), 0);
    EXPECT_LT(c.Feed(1, {2}), 0);
    Control push;
    EXPECT_LT(push.Feed(0, {1}), 0);
}
TEST(Http3Control, ZeroCapacityRejectsEveryEncoderInstruction) {
    for (unsigned char byte : {0x00,0x1f,0x20,0x21,0x3f,0x40,0x80,0xc0}) {
        Control c;
        EXPECT_EQ(c.Feed(0,{2}),0);
        EXPECT_LT(c.Feed(0,{byte}),0);
    }
}
TEST(Http3Control, StaticEncoderAcceptsOnlyLegalDecoderCancellation) {
    { Control c; EXPECT_EQ(c.Feed(0,{3,0x40}),0); }
    { Control c; EXPECT_EQ(c.Feed(0,{3,0x7f}),0); EXPECT_EQ(c.Feed(0,{1}),0); }
    { Control c; EXPECT_LT(c.Feed(0,{3,0x80}),0); }
    { Control c; EXPECT_LT(c.Feed(0,{3,1}),0); }
}
TEST(Http3Control, DecoderCancellationUsesOnlyQuicStreamIdentifiers) {
    auto cancellation = [](uint64_t id) {
        std::vector<unsigned char> bytes={3,0x7f}; id-=63;
        while (id>=128) { bytes.push_back((id&127)|128); id>>=7; }
        bytes.push_back(id); return bytes;
    };
    { Control c; EXPECT_EQ(c.Feed(0,cancellation((UINT64_C(1)<<62)-4)),0); }
    { Control c; EXPECT_LT(c.Feed(0,cancellation(UINT64_C(1)<<62)),0); }
}
TEST(Http3Control, GoawayStopsNewAndMustNotIncrease) {
    Control c;
    EXPECT_EQ(c.Feed(0, {0,4,0,7,1,8}), 0);
    EXPECT_FALSE(_dns_http3_request_allowed(&c.server, nullptr));
    EXPECT_EQ(c.Feed(0, {7,1,4}), 0);
    EXPECT_LT(c.Feed(0, {7,1,8}), 0);
}
#endif
TEST(Http3RequestFraming, RejectSettingsOnRequestStream) {
    const unsigned char bytes[] = {4,0};
    http_head *head = http_head_init(4096, HTTP_VERSION_3_0);
    ASSERT_NE(head, nullptr);
    EXPECT_LT(http_head_parse(head, bytes, sizeof(bytes)), 0);
    http_head_destroy(head);
}
