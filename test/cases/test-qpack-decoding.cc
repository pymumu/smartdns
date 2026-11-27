#include "gtest/gtest.h"
extern "C" {
#include "http_parse/hpack.h"
#include "http_parse/qpack.h"
#include "smartdns/http_parse.h"
}
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>

namespace {
// RFC 7541 Appendix B, independently frozen; HPACK and QPACK use the same code.
const uint32_t codes[] = {
    0x1ff8,0x7fffd8,0xfffffe2,0xfffffe3,0xfffffe4,0xfffffe5,0xfffffe6,0xfffffe7,
    0xfffffe8,0xffffea,0x3ffffffc,0xfffffe9,0xfffffea,0x3ffffffd,0xfffffeb,0xfffffec,
    0xfffffed,0xfffffee,0xfffffef,0xffffff0,0xffffff1,0xffffff2,0x3ffffffe,0xffffff3,
    0xffffff4,0xffffff5,0xffffff6,0xffffff7,0xffffff8,0xffffff9,0xffffffa,0xffffffb,
    0x14,0x3f8,0x3f9,0xffa,0x1ff9,0x15,0xf8,0x7fa,
    0x3fa,0x3fb,0xf9,0x7fb,0xfa,0x16,0x17,0x18,
    0x0,0x1,0x2,0x19,0x1a,0x1b,0x1c,0x1d,
    0x1e,0x1f,0x5c,0xfb,0x7ffc,0x20,0xffb,0x3fc,
    0x1ffa,0x21,0x5d,0x5e,0x5f,0x60,0x61,0x62,
    0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,
    0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,
    0xfc,0x73,0xfd,0x1ffb,0x7fff0,0x1ffc,0x3ffc,0x22,
    0x7ffd,0x3,0x23,0x4,0x24,0x5,0x25,0x26,
    0x27,0x6,0x74,0x75,0x28,0x29,0x2a,0x7,
    0x2b,0x76,0x2c,0x8,0x9,0x2d,0x77,0x78,
    0x79,0x7a,0x7b,0x7ffe,0x7fc,0x3ffd,0x1ffd,0xffffffc,
    0xfffe6,0x3fffd2,0xfffe7,0xfffe8,0x3fffd3,0x3fffd4,0x3fffd5,0x7fffd9,
    0x3fffd6,0x7fffda,0x7fffdb,0x7fffdc,0x7fffdd,0x7fffde,0xffffeb,0x7fffdf,
    0xffffec,0xffffed,0x3fffd7,0x7fffe0,0xffffee,0x7fffe1,0x7fffe2,0x7fffe3,
    0x7fffe4,0x1fffdc,0x3fffd8,0x7fffe5,0x3fffd9,0x7fffe6,0x7fffe7,0xffffef,
    0x3fffda,0x1fffdd,0xfffe9,0x3fffdb,0x3fffdc,0x7fffe8,0x7fffe9,0x1fffde,
    0x7fffea,0x3fffdd,0x3fffde,0xfffff0,0x1fffdf,0x3fffdf,0x7fffeb,0x7fffec,
    0x1fffe0,0x1fffe1,0x3fffe0,0x1fffe2,0x7fffed,0x3fffe1,0x7fffee,0x7fffef,
    0xfffea,0x3fffe2,0x3fffe3,0x3fffe4,0x7ffff0,0x3fffe5,0x3fffe6,0x7ffff1,
    0x3ffffe0,0x3ffffe1,0xfffeb,0x7fff1,0x3fffe7,0x7ffff2,0x3fffe8,0x1ffffec,
    0x3ffffe2,0x3ffffe3,0x3ffffe4,0x7ffffde,0x7ffffdf,0x3ffffe5,0xfffff1,0x1ffffed,
    0x7fff2,0x1fffe3,0x3ffffe6,0x7ffffe0,0x7ffffe1,0x3ffffe7,0x7ffffe2,0xfffff2,
    0x1fffe4,0x1fffe5,0x3ffffe8,0x3ffffe9,0xffffffd,0x7ffffe3,0x7ffffe4,0x7ffffe5,
    0xfffec,0xfffff3,0xfffed,0x1fffe6,0x3fffe9,0x1fffe7,0x1fffe8,0x7ffff3,
    0x3fffea,0x3fffeb,0x1ffffee,0x1ffffef,0xfffff4,0xfffff5,0x3ffffea,0x7ffff4,
    0x3ffffeb,0x7ffffe6,0x3ffffec,0x3ffffed,0x7ffffe7,0x7ffffe8,0x7ffffe9,0x7ffffea,
    0x7ffffeb,0xffffffe,0x7ffffec,0x7ffffed,0x7ffffee,0x7ffffef,0x7fffff0,0x3ffffee,
    0x3fffffff,
};
const unsigned char lengths[] = {
    13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,
    28,28,28,28,28,28,30,28,28,28,28,28,28,28,28,28,
    6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,
    5,5,5,6,6,6,6,6,6,6,7,8,15,6,12,10,
    13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,8,7,8,13,19,13,14,6,
    15,5,6,5,6,5,6,6,6,5,7,7,6,6,6,5,
    6,7,6,5,5,6,7,7,7,7,7,15,11,14,13,28,
    20,22,20,20,22,22,22,23,22,23,23,23,23,23,24,23,
    24,24,22,23,24,23,23,23,23,21,22,23,22,23,23,24,
    22,21,20,22,22,23,23,21,23,22,22,24,21,22,23,23,
    21,21,22,21,23,22,23,23,20,22,22,22,23,22,22,23,
    26,26,20,19,22,23,22,25,26,26,26,27,27,26,24,25,
    19,21,26,27,27,26,27,24,21,21,26,26,28,27,27,27,
    20,24,20,21,22,21,21,23,22,22,25,25,24,24,26,23,
    26,27,26,26,27,27,27,27,27,28,27,27,27,27,27,26,
    30,
};
std::vector<unsigned char> Huffman(unsigned symbol) {
    unsigned n = lengths[symbol], padding = (8 - n % 8) % 8;
    uint64_t bits = ((uint64_t)codes[symbol] << padding) | ((1U << padding) - 1);
    std::vector<unsigned char> out((n + padding) / 8);
    for (size_t i = out.size(); i; i--) { out[i-1] = bits & 255; bits >>= 8; }
    return out;
}
int Count(void *ctx, const char *, const char *) { ++*static_cast<int *>(ctx); return 0; }
int Save(void *ctx, const char *, const char *value) { *static_cast<std::string *>(ctx) = value; return 0; }
void Integer(std::vector<unsigned char> &out, uint64_t value, unsigned bits, unsigned char flags) {
    uint64_t maximum = (1U << bits) - 1;
    if (value < maximum) { out.push_back(flags | value); return; }
    out.push_back(flags | maximum); value -= maximum;
    while (value >= 128) { out.push_back((value & 127) | 128); value >>= 7; }
    out.push_back(value);
}
int ParseH3(const std::vector<unsigned char> &payload, std::string *value = nullptr) {
    EXPECT_LT(payload.size(), 64U);
    std::vector<unsigned char> frame = {1,static_cast<unsigned char>(payload.size())};
    frame.insert(frame.end(), payload.begin(), payload.end());
    http_head *head = http_head_init(4096, HTTP_VERSION_3_0);
    if (!head) return -999;
    int ret = http_head_parse(head, frame.data(), frame.size());
    if (ret >= 0 && value) {
        const char *v = http_head_get_fields_value(head, "a");
        *value = v ? v : "";
    }
    http_head_destroy(head); return ret;
}
}

TEST(HeaderCompression, EveryOctetUsesTheSameCompleteRfcHuffmanCode) {
    for (unsigned symbol = 0; symbol < 256; symbol++) {
        SCOPED_TRACE(symbol);
        auto wire = Huffman(symbol);
        unsigned char decoded[8] = {}; size_t count = 0;
        EXPECT_EQ(qpack_huffman_decode(wire.data(), wire.data()+wire.size(), decoded, sizeof(decoded), &count), 0);
        EXPECT_EQ(count, 1U); EXPECT_EQ(decoded[0], symbol);
        std::vector<unsigned char> block = {0x01,static_cast<unsigned char>(0x80 | wire.size())};
        block.insert(block.end(), wire.begin(), wire.end());
        hpack_context ctx{}; hpack_init_context(&ctx); std::string value;
        EXPECT_EQ(hpack_decode_headers(&ctx, block.data(), block.size(), Save, &value), 0);
        if (symbol) EXPECT_EQ(value, std::string(1, static_cast<char>(symbol)));
        else EXPECT_TRUE(value.empty()); // C-string callback; the codec still decodes zero.
        hpack_free_context(&ctx);
    }
}
TEST(HeaderCompression, BothHuffmanDecodersRejectEosAndInvalidPadding) {
    for (const auto &wire : std::vector<std::vector<unsigned char>>{{0xff},{0xff,0xff},{0xff,0xff,0xff,0xff},{0x00},{0x1f,0xff}}) {
        unsigned char decoded[32] = {}; size_t count = 0;
        EXPECT_LT(qpack_huffman_decode(wire.data(), wire.data()+wire.size(), decoded, sizeof(decoded), &count), 0);
        std::vector<unsigned char> block = {0x01,static_cast<unsigned char>(0x80 | wire.size())};
        block.insert(block.end(), wire.begin(), wire.end());
        hpack_context ctx{}; hpack_init_context(&ctx); int seen = 0;
        EXPECT_LT(hpack_decode_headers(&ctx, block.data(), block.size(), Count, &seen), 0);
        EXPECT_EQ(seen, 0); hpack_free_context(&ctx);
    }
    auto wire = Huffman('a'); unsigned char decoded[1]; size_t count = 0;
    EXPECT_EQ(qpack_huffman_decode(wire.data(), wire.data()+wire.size(), decoded, 1, &count), 0);
    EXPECT_EQ(count, 1U);
    EXPECT_LT(qpack_huffman_decode(wire.data(), wire.data()+wire.size(), decoded, 0, &count), 0);
}
TEST(HeaderCompression, QpackLiteralNameAndValueHaveIndependentHuffmanFlags) {
    // Literal Huffman name "a", followed by a plain value "hello".
    std::string value;
    EXPECT_GE(ParseH3({0,0,0xd9,0x29,0x1f,5,'h','e','l','l','o'},&value),0);
    EXPECT_EQ(value,"hello");
    EXPECT_LT(ParseH3({0,0,0xd9,0x29,0x1f}),0); // missing value prefix
    EXPECT_LT(ParseH3({0,0,0xd9,0x50}),0); // static-name literal without value
}
TEST(HeaderCompression, QpackStaticIndicesNeverNarrowFromLargeIntegers) {
    for (unsigned char representation : {0xc0,0x50}) {
        std::vector<unsigned char> payload={0,0};
        Integer(payload,(uint64_t(1)<<32)+25,representation==0xc0?6:4,representation);
        if (representation==0x50) { payload.push_back(3); payload.insert(payload.end(),{'2','0','0'}); }
        EXPECT_LT(ParseH3(payload),0);
    }
}
TEST(HeaderCompression, StaticOnlyQpackAllowsPositiveMultibyteBase)
{
    EXPECT_GE(ParseH3({0, 0x7f, 1, 0xd9}), 0);
    EXPECT_LT(ParseH3({0, 0x80, 0xd9}), 0);
    EXPECT_LT(ParseH3({0, 0x7f}), 0);
}
TEST(HeaderCompression, QpackIntegersCannotWrapToValidStaticIndices)
{
    for (unsigned char representation : {0xc0, 0x50}) {
        std::vector<unsigned char> block = {0, 0};
        block.push_back(representation | (representation == 0xc0 ? 0x3f : 0x0f));
        block.insert(block.end(), {0x99,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01});
        EXPECT_LT(ParseH3(block), 0);
    }
}
