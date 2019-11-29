/*************************************************************************
 *
 * Copyright (C) 2018-2020 Ruilin Peng (Nick) <pymumu@gmail.com>.
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


#ifndef _GENERIC_BITOPS_H_
#define _GENERIC_BITOPS_H_

#include <unistd.h>
#include <stdint.h>
#include "gcc_builtin.h"

#ifndef __WORDSIZE
#define __WORDSIZE (__SIZEOF_LONG__ * 8)
#endif

#ifndef BITS_PER_LONG
# define BITS_PER_LONG __WORDSIZE
#endif

#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BITS_TO_U64(nr)		DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u64))
#define BITS_TO_U32(nr)		DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(u32))
#define BITS_TO_BYTES(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE)

extern unsigned int __sw_hweight8(unsigned int w);
extern unsigned int __sw_hweight16(unsigned int w);
extern unsigned int __sw_hweight32(unsigned int w);
extern unsigned long __sw_hweight64(uint64_t w);


#define ffz(x)  __ffs(~(x))

/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */

/**
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word)
{
	int num = 0;

#if __BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
#endif
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static inline int fls(int x)
{
	return 32 - __builtin_clz(x);
}

/**
 * fls64 - find last set bit in a 64-bit word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffsll, but returns the position of the most significant set bit.
 *
 * fls64(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 64.
 */
#if BITS_PER_LONG == 32
static inline int fls64(uint64_t x)
{
	uint32_t h = x >> 32;
	if (h)
		return fls(h) + 32;
	return fls(x);
}
#elif BITS_PER_LONG == 64
static inline int fls64(uint64_t x)
{
	return 64 - __builtin_clzll(x);
}
#else
#error BITS_PER_LONG not 32 or 64
#endif

/**
 * hweightN - returns the hamming weight of a N-bit word
 * @x: the word to weigh
 *
 * The Hamming Weight of a number is the total number of bits set in it.
 */

static inline unsigned int hweight32(unsigned int w)
{
	unsigned int res = w - ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
}

static inline unsigned int hweight16(unsigned int w)
{
	unsigned int res = w - ((w >> 1) & 0x5555);
	res = (res & 0x3333) + ((res >> 2) & 0x3333);
	res = (res + (res >> 4)) & 0x0F0F;
	return (res + (res >> 8)) & 0x00FF;
}

static inline unsigned int hweight8(unsigned int w)
{
	unsigned int res = w - ((w >> 1) & 0x55);
	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res + (res >> 4)) & 0x0F;
}

static inline unsigned long hweight64(uint64_t w)
{
#if BITS_PER_LONG == 32
	return hweight32((unsigned int)(w >> 32)) + hweight32((unsigned int)w);
#elif BITS_PER_LONG == 64
#ifdef ARCH_HAS_FAST_MULTIPLIER
	w -= (w >> 1) & 0x5555555555555555ul;
	w =  (w & 0x3333333333333333ul) + ((w >> 2) & 0x3333333333333333ul);
	w =  (w + (w >> 4)) & 0x0f0f0f0f0f0f0f0ful;
	return (w * 0x0101010101010101ul) >> 56;
#else
	uint64_t res = w - ((w >> 1) & 0x5555555555555555ul);
	res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
	res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0Ful;
	res = res + (res >> 8);
	res = res + (res >> 16);
	return (res + (res >> 32)) & 0x00000000000000FFul;
#endif
#endif
}

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_first_zero_bit((addr), (size));       \
	     (bit) < (size);                                    \
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))

/* same as for_each_set_bit() but use bit as value to start with */
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

static inline unsigned long hweight_long(unsigned long w)
{
	return sizeof(w) == 4 ? hweight32(w) : hweight64(w);
}

static inline unsigned fls_long(unsigned long l)
{
	if (sizeof(l) == 4)
		return fls(l);
	return fls64(l);
}

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

#endif
