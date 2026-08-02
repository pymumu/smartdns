#ifndef BLOOM_H
#define BLOOM_H

#include <stdint.h>
#include <stddef.h>

// 布隆过滤器结构体
typedef struct {
    uint8_t *bit_array;  // 位数组
    size_t size;         // 位数组大小 (bits)
    size_t num_hashes;   // 哈希函数数量
} bloom_filter_t;

/**
 * @brief 创建并初始化一个新的布隆过滤器。
 *
 * @param size 布隆过滤器的大小（位数）。
 * @param num_hashes 哈希函数的数量。
 * @return 指向新创建的布隆过滤器的指针，如果失败则返回 NULL。
 */
bloom_filter_t *bloom_filter_new(size_t size, size_t num_hashes);

/**
 * @brief 释放布隆过滤器占用的内存。
 *
 * @param bf 指向要释放的布隆过滤器的指针。
 */
void bloom_filter_free(bloom_filter_t *bf);

/**
 * @brief 向布隆过滤器中添加一个元素。
 *
 * @param bf 指向布隆过滤器的指针。
 * @param item 指向要添加的元素的指针。
 * @param item_len 要添加的元素的长度（字节）。
 */
void bloom_filter_add(bloom_filter_t *bf, const void *item, size_t item_len);

/**
 * @brief 检查一个元素是否可能在布隆过滤器中。
 *
 * @param bf 指向布隆过滤器的指针。
 * @param item 指向要检查的元素的指针。
 * @param item_len 要检查的元素的长度（字节）。
 * @return 如果元素可能在过滤器中，则返回 1；否则返回 0。
 */
int bloom_filter_check(bloom_filter_t *bf, const void *item, size_t item_len);

#endif // BLOOM_H 