#include "smartdns/bloom.h"
#include <stdlib.h>
#include <string.h>

// FNV-1a 哈希函数常量
#define FNV_PRIME_32 16777619
#define FNV_OFFSET_BASIS_32 2166136261U

// 第一个哈希函数 (FNV-1a)
static uint32_t hash_fnv1a(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    uint32_t hash = FNV_OFFSET_BASIS_32;
    for (size_t i = 0; i < len; ++i) {
        hash ^= (uint32_t)p[i];
        hash *= FNV_PRIME_32;
    }
    return hash;
}

// 第二个哈希函数 (基于 FNV-1a 和简单的位移)
// 注意: 这种方式生成的哈希函数独立性可能不够好，仅作示例。
// 在实际应用中，更推荐使用像 MurmurHash3 这样为生成多个独立哈希值设计的算法，
// 或者使用不同的种子多次调用同一个高质量哈希函数。
static uint32_t hash_fnv1a_seeded(const void *data, size_t len, uint32_t seed) {
    const unsigned char *p = (const unsigned char *)data;
    uint32_t hash = FNV_OFFSET_BASIS_32 ^ seed; // Incorporate seed
    for (size_t i = 0; i < len; ++i) {
        hash ^= (uint32_t)p[i];
        hash *= FNV_PRIME_32;
    }
    return hash;
}


bloom_filter_t *bloom_filter_new(size_t size, size_t num_hashes) {
    if (size == 0 || num_hashes == 0) {
        return NULL;
    }
    bloom_filter_t *bf = (bloom_filter_t *)malloc(sizeof(bloom_filter_t));
    if (!bf) {
        return NULL;
    }
    // 位数组大小向上取整到字节
    bf->bit_array = (uint8_t *)calloc((size + 7) / 8, sizeof(uint8_t));
    if (!bf->bit_array) {
        free(bf);
        return NULL;
    }
    bf->size = size;
    bf->num_hashes = num_hashes;
    return bf;
}

void bloom_filter_free(bloom_filter_t *bf) {
    if (bf) {
        free(bf->bit_array);
        free(bf);
    }
}

// 内部函数，用于设置位数组中的某一位
static inline void set_bit(uint8_t *bit_array, size_t bit_index) {
    bit_array[bit_index / 8] |= (1 << (bit_index % 8));
}

// 内部函数，用于检查位数组中的某一位是否被设置
static inline int get_bit(const uint8_t *bit_array, size_t bit_index) {
    return (bit_array[bit_index / 8] & (1 << (bit_index % 8))) != 0;
}

void bloom_filter_add(bloom_filter_t *bf, const void *item, size_t item_len) {
    if (!bf || !item || item_len == 0) {
        return;
    }
    uint32_t hash1 = hash_fnv1a(item, item_len);
    uint32_t hash2 = hash_fnv1a_seeded(item, item_len, hash1); // 使用 hash1 作为第二个哈希的种子，增加变化

    for (size_t i = 0; i < bf->num_hashes; ++i) {
        // Kirsch-Mitzenmacher 优化：使用两个哈希函数生成 k 个哈希值
        // h_i(x) = (h1(x) + i * h2(x)) % m
        // 其中 m 是布隆过滤器的大小 (bf->size)
        // 注意：如果 h2(x) 是0，可能会导致所有哈希值都相同或聚集。
        // 一个更健壮的方法是确保 h2(x) 不为0，或者使用其他生成 k 个哈希值的方法。
        // 为简单起见，这里假设 h2 不太可能为0。
        uint32_t combined_hash = hash1 + (uint32_t)i * hash2;
        if (hash2 == 0 && i > 0) { // 简单的保护，如果h2是0，后续哈希会相同
            combined_hash = hash1 + (uint32_t)i * (hash1 >> 16 | 1); // 引入一些变化
        }
        size_t bit_to_set = combined_hash % bf->size;
        set_bit(bf->bit_array, bit_to_set);
    }
}

int bloom_filter_check(bloom_filter_t *bf, const void *item, size_t item_len) {
    if (!bf || !item || item_len == 0) {
        return 0; // 通常表示不在集合中或无效输入
    }
    uint32_t hash1 = hash_fnv1a(item, item_len);
    uint32_t hash2 = hash_fnv1a_seeded(item, item_len, hash1);

    for (size_t i = 0; i < bf->num_hashes; ++i) {
        uint32_t combined_hash = hash1 + (uint32_t)i * hash2;
        if (hash2 == 0 && i > 0) { 
            combined_hash = hash1 + (uint32_t)i * (hash1 >> 16 | 1); 
        }
        size_t bit_to_check = combined_hash % bf->size;
        if (!get_bit(bf->bit_array, bit_to_check)) {
            return 0; // 如果任何一个位未被设置，则元素肯定不在过滤器中
        }
    }
    return 1; // 所有相关位都被设置，元素可能在过滤器中
} 