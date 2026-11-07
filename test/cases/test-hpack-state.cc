#include "gtest/gtest.h"
#include "http_parse/hpack.h"
#include <cerrno>
#include <string>
namespace {
int Count(void *ctx, const char *, const char *) { ++*static_cast<int *>(ctx); return 0; }
int Save(void *ctx, const char *, const char *value) { *static_cast<std::string *>(ctx) = value; return 0; }
}
TEST(HeaderCompression, EncoderSettingsShrinkAndGrowSynchronizeNextHeaderBlock) {
    hpack_context encoder{},decoder{}; hpack_init_context(&encoder); hpack_init_context(&decoder);
    unsigned char wire[256] = {}; std::string value;
    int n=hpack_encode_header(&encoder,"x-test","first",wire,sizeof(wire)); ASSERT_GT(n,0);
    ASSERT_EQ(hpack_decode_headers(&decoder,wire,n,Save,&value),0);
    hpack_set_encoder_table_size(&encoder,0);
    hpack_set_encoder_table_size(&encoder,4096);
    EXPECT_EQ(encoder.entry_count,0);
    EXPECT_LT(hpack_encode_header(&encoder,"x-test","second",wire,1),0);
    EXPECT_TRUE(encoder.pending_size_update); // failed encode must not lose required update
    n=hpack_encode_header(&encoder,"x-test","second",wire,sizeof(wire)); ASSERT_GT(n,0);
    EXPECT_EQ(wire[0],0x20); EXPECT_EQ(wire[1]&0xe0,0x20);
    EXPECT_EQ(hpack_decode_headers(&decoder,wire,n,Save,&value),0);
    EXPECT_EQ(value,"second"); EXPECT_EQ(decoder.entry_count,1);
    EXPECT_EQ(decoder.dynamic_table_size,encoder.dynamic_table_size);
    n=hpack_encode_header(&encoder,"x-test","second",wire,sizeof(wire)); ASSERT_GT(n,0);
    EXPECT_EQ(wire[0],0xbe); // both peers now reference the same single entry
    EXPECT_EQ(hpack_decode_headers(&decoder,wire,n,Save,&value),0);
    EXPECT_EQ(value,"second"); hpack_free_context(&encoder); hpack_free_context(&decoder);
}

namespace {
thread_local int fail_hpack_strdup;
}
extern "C" char *__real_strdup(const char *);
extern "C" char *__wrap_strdup(const char *s)
{
    if (fail_hpack_strdup > 0 && --fail_hpack_strdup == 0) {
        errno = ENOMEM;
        return nullptr;
    }
    return __real_strdup(s);
}
TEST(HeaderCompression, DynamicInsertionFailureIsNotReportedAsSuccess)
{
    for (int failed_copy : {1, 2}) {
        hpack_context ctx{};
        hpack_init_context(&ctx);
        unsigned char encoded[128];
        fail_hpack_strdup = failed_copy;
        int result = hpack_encode_header(&ctx, "x-test", "value", encoded, sizeof(encoded));
        fail_hpack_strdup = 0;
        EXPECT_LT(result, 0);
        EXPECT_EQ(ctx.entry_count, 0);
        hpack_free_context(&ctx);

        // Literal with incremental indexing: x-test: value.
        const unsigned char block[] = {0x40,6,'x','-','t','e','s','t',5,'v','a','l','u','e'};
        int count = 0;
        hpack_init_context(&ctx);
        fail_hpack_strdup = failed_copy;
        result = hpack_decode_headers(&ctx, block, sizeof(block), Count, &count);
        fail_hpack_strdup = 0;
        EXPECT_LT(result, 0);
        EXPECT_EQ(count, 0);
        EXPECT_EQ(ctx.entry_count, 0);
        hpack_free_context(&ctx);
    }
}
