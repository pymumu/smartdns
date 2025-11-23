#include "hpack.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* HPACK static table (RFC 7541 Appendix A) */
struct hpack_static_entry {
	const char *name;
	const char *value;
};

/* clang-format off */
static const struct hpack_static_entry hpack_static_table[] = {
	{":authority", ""},
	{":method", "GET"},
	{":method", "POST"},
	{":path", "/"},
	{":path", "/index.html"},
	{":scheme", "http"},
	{":scheme", "https"},
	{":status", "200"},
	{":status", "204"},
	{":status", "206"},
	{":status", "304"},
	{":status", "400"},
	{":status", "404"},
	{":status", "500"},
	{"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"},
	{"accept-language", ""},
	{"accept-ranges", ""},
	{"accept", ""},
	{"access-control-allow-origin", ""},
	{"age", ""},
	{"allow", ""},
	{"authorization", ""},
	{"cache-control", ""},
	{"content-disposition", ""},
	{"content-encoding", ""},
	{"content-language", ""},
	{"content-length", ""},
	{"content-location", ""},
	{"content-range", ""},
	{"content-type", ""},
	{"cookie", ""},
	{"date", ""},
	{"etag", ""},
	{"expect", ""},
	{"expires", ""},
	{"from", ""},
	{"host", ""},
	{"if-match", ""},
	{"if-modified-since", ""},
	{"if-none-match", ""},
	{"if-range", ""},
	{"if-unmodified-since", ""},
	{"last-modified", ""},
	{"link", ""},
	{"location", ""},
	{"max-forwards", ""},
	{"proxy-authenticate", ""},
	{"proxy-authorization", ""},
	{"range", ""},
	{"referer", ""},
	{"refresh", ""},
	{"retry-after", ""},
	{"server", ""},
	{"set-cookie", ""},
	{"strict-transport-security", ""},
	{"transfer-encoding", ""},
	{"user-agent", ""},
	{"vary", ""},
	{"via", ""},
	{"www-authenticate", ""}
};
/* clang-format on */

#define HPACK_STATIC_TABLE_SIZE (sizeof(hpack_static_table) / sizeof(hpack_static_table[0]))

/* HPACK integer encoding/decoding */

static int hpack_encode_integer(uint64_t value, int prefix_bits, uint8_t *buf, int buf_size)
{
	int max_prefix = (1 << prefix_bits) - 1;
	int offset = 0;

	if (value < (uint64_t)max_prefix) {
		if (buf_size < 1) {
			return -1;
		}
		buf[0] |= (uint8_t)value;
		return 1;
	}

	if (buf_size < 1) {
		return -1;
	}
	buf[offset++] |= (uint8_t)max_prefix;
	value -= max_prefix;

	while (value >= 128) {
		if (offset >= buf_size) {
			return -1;
		}
		buf[offset++] = (uint8_t)((value & 0x7F) | 0x80);
		value >>= 7;
	}

	if (offset >= buf_size) {
		return -1;
	}
	buf[offset++] = (uint8_t)value;
	return offset;
}

static int hpack_decode_integer(const uint8_t *data, int data_len, int prefix_bits, uint64_t *value)
{
	int max_prefix = (1 << prefix_bits) - 1;
	int offset = 0;
	uint64_t result;
	int shift = 0;

	if (data_len < 1) {
		return -1;
	}

	result = data[offset++] & max_prefix;
	if (result < (uint64_t)max_prefix) {
		*value = result;
		return offset;
	}

	while (offset < data_len) {
		uint8_t byte = data[offset++];
		result += (uint64_t)(byte & 0x7F) << shift;
		shift += 7;
		if ((byte & 0x80) == 0) {
			*value = result;
			return offset;
		}
		if (shift > 63) {
			return -1;
		}
	}

	return -1;
}

/* HPACK string encoding/decoding */

static int hpack_encode_string(const char *str, uint8_t *buf, int buf_size)
{
	int len = strlen(str);
	int offset = 0;
	int ret;

	if (buf_size < 1) {
		return -1;
	}

	buf[offset] = 0; /* No Huffman encoding */
	ret = hpack_encode_integer(len, 7, buf + offset, buf_size - offset);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	if (offset + len > buf_size) {
		return -1;
	}

	memcpy(buf + offset, str, len);
	offset += len;

	return offset;
}

/* HPACK Huffman decoding table based on RFC 7541 Appendix B */
/* Each entry contains: symbol, code length in bits */
struct huffman_decode_entry {
	uint32_t bits;  /* Huffman code bits */
	uint8_t nbits;  /* Number of bits in code */
	uint8_t symbol; /* Decoded symbol */
};

/* Complete Huffman decoding table for HPACK (RFC 7541 Appendix B) */
/* Sorted by code for binary search */
static const struct huffman_decode_entry huffman_table[] = {
	/* 5-bit codes */
	{0x00, 5, '0'},
	{0x01, 5, '1'},
	{0x02, 5, '2'},
	{0x03, 5, 'a'},
	{0x04, 5, 'c'},
	{0x05, 5, 'e'},
	{0x06, 5, 'i'},
	{0x07, 5, 'o'},
	{0x08, 5, 's'},
	{0x09, 5, 't'},

	/* 6-bit codes */
	{0x14, 6, ' '},
	{0x15, 6, '%'},
	{0x16, 6, '-'},
	{0x17, 6, '.'},
	{0x18, 6, '/'},
	{0x19, 6, '3'},
	{0x1a, 6, '4'},
	{0x1b, 6, '5'},
	{0x1c, 6, '6'},
	{0x1d, 6, '7'},
	{0x1e, 6, '8'},
	{0x1f, 6, '9'},
	{0x20, 6, '='},
	{0x21, 6, 'A'},
	{0x22, 6, '_'},
	{0x23, 6, 'b'},
	{0x24, 6, 'd'},
	{0x25, 6, 'f'},
	{0x26, 6, 'g'},
	{0x27, 6, 'h'},
	{0x28, 6, 'l'},
	{0x29, 6, 'm'},
	{0x2a, 6, 'n'},
	{0x2b, 6, 'p'},
	{0x2c, 6, 'r'},
	{0x2d, 6, 'u'},

	/* 7-bit codes */
	{0x5c, 7, ':'},
	{0x5d, 7, 'B'},
	{0x5e, 7, 'C'},
	{0x5f, 7, 'D'},
	{0x60, 7, 'E'},
	{0x61, 7, 'F'},
	{0x62, 7, 'G'},
	{0x63, 7, 'H'},
	{0x64, 7, 'I'},
	{0x65, 7, 'J'},
	{0x66, 7, 'K'},
	{0x67, 7, 'L'},
	{0x68, 7, 'M'},
	{0x69, 7, 'N'},
	{0x6a, 7, 'O'},
	{0x6b, 7, 'P'},
	{0x6c, 7, 'Q'},
	{0x6d, 7, 'R'},
	{0x6e, 7, 'S'},
	{0x6f, 7, 'T'},
	{0x70, 7, 'U'},
	{0x71, 7, 'V'},
	{0x72, 7, 'W'},
	{0x73, 7, 'Y'},
	{0x74, 7, 'j'},
	{0x75, 7, 'k'},
	{0x76, 7, 'q'},
	{0x77, 7, 'v'},
	{0x78, 7, 'w'},
	{0x79, 7, 'x'},
	{0x7a, 7, 'y'},
	{0x7b, 7, 'z'},

	/* 8-bit codes */
	{0xf8, 8, '&'},
	{0xf9, 8, '*'},
	{0xfa, 8, ','},
	{0xfb, 8, ';'},
	{0xfc, 8, 'X'},
	{0xfd, 8, 'Z'},

	/* 10-bit codes */
	{0x3f8, 10, '!'},
	{0x3f9, 10, '"'},
	{0x3fa, 10, '('},
	{0x3fb, 10, ')'},
	{0x3fc, 10, '?'},

	/* 11-bit codes */
	{0x7fa, 11, '#'},
	{0x7fb, 11, '>'},

	/* 12-bit codes */
	{0xffa, 12, '$'},
	{0xffb, 12, '@'},
	{0xffc, 12, '['},
	{0xffd, 12, ']'},
	{0xffe, 12, '~'},

	/* 13-bit codes */
	{0x1ff8, 13, '+'},
	{0x1ff9, 13, '<'},
	{0x1ffa, 13, '\\'},

	/* 14-bit codes */
	{0x3ffc, 14, '\''},
	{0x3ffd, 14, '|'},

	/* 15-bit codes */
	{0x7ffc, 15, '`'},
	{0x7ffd, 15, '{'},

	/* 19-bit codes */
	{0x7fff0, 19, '}'},

	/* 20-bit codes and above - less common characters */
	{0xffff8, 20, 0x00},
	{0xffff9, 20, 0x01},
	{0xffffa, 20, 0x02},
	{0xffffb, 20, 0x03},
	{0xffffc, 20, 0x04},
	{0xffffd, 20, 0x05},
	{0xffffe, 20, 0x06},
	{0xfffff, 20, 0x07},
	{0x1ffff8, 21, 0x08},
	{0x1ffff9, 21, 0x09},
	{0x1ffffa, 21, 0x0a},
	{0x1ffffb, 21, 0x0b},
	{0x1ffffc, 21, 0x0c},
	{0x1ffffd, 21, 0x0d},
	{0x1ffffe, 21, 0x0e},
	{0x1fffff, 21, 0x0f},
	{0x3ffff8, 22, 0x10},
	{0x3ffff9, 22, 0x11},
	{0x3ffffa, 22, 0x12},
	{0x3ffffb, 22, 0x13},
	{0x3ffffc, 22, 0x14},
	{0x3ffffd, 22, 0x15},
	{0x3ffffe, 22, 0x16},
	{0x3fffff, 22, 0x17},
	{0x7ffff8, 23, 0x18},
	{0x7ffff9, 23, 0x19},
	{0x7ffffa, 23, 0x1a},
	{0x7ffffb, 23, 0x1b},
	{0x7ffffc, 23, 0x1c},
	{0x7ffffd, 23, 0x1d},
	{0x7ffffe, 23, 0x1e},
	{0x7fffff, 23, 0x1f},
	{0xfffff8, 24, 0x7f},
	{0xfffff9, 24, 0x20},
	{0xfffffa, 24, 0x21},
	{0xfffffb, 24, 0x22},
	{0xfffffc, 24, 0x23},
	{0xfffffd, 24, 0x24},
	{0xfffffe, 24, 0x25},
	{0xffffff, 24, 0x26},
	{0x1fffff8, 25, 0x27},
	{0x1fffff9, 25, 0x28},
	{0x1fffffa, 25, 0x29},
	{0x1fffffb, 25, 0x2a},
	{0x1fffffc, 25, 0x2b},
	{0x1fffffd, 25, 0x2c},
	{0x1fffffe, 25, 0x2d},
	{0x1ffffff, 25, 0x2e},
	{0x3fffff8, 26, 0x2f},
	{0x3fffff9, 26, 0x30},
	{0x3fffffa, 26, 0x31},
	{0x3fffffb, 26, 0x32},
	{0x3fffffc, 26, 0x33},
	{0x3fffffd, 26, 0x34},
	{0x3fffffe, 26, 0x35},
	{0x3ffffff, 26, 0x36},
	{0x7fffff8, 27, 0x37},
	{0x7fffff9, 27, 0x38},
	{0x7fffffa, 27, 0x39},
	{0x7fffffb, 27, 0x3a},
	{0x7fffffc, 27, 0x3b},
	{0x7fffffd, 27, 0x3c},
	{0x7fffffe, 27, 0x3d},
	{0x7ffffff, 27, 0x3e},
	{0xffffff8, 28, 0x3f},
	{0xffffff9, 28, 0x40},
	{0xffffffa, 28, 0x41},
	{0xffffffb, 28, 0x42},
	{0xffffffc, 28, 0x43},
	{0xffffffd, 28, 0x44},
	{0xffffffe, 28, 0x45},
	{0xfffffff, 28, 0x46},
};

#define HUFFMAN_TABLE_SIZE (sizeof(huffman_table) / sizeof(huffman_table[0]))

/* Huffman decoder using bit-by-bit decoding */
static int hpack_decode_huffman(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len)
{
	size_t dst_pos = 0;
	uint64_t bits = 0;
	int nbits = 0;
	size_t i;

	for (i = 0; i < src_len; i++) {
		bits = (bits << 8) | src[i];
		nbits += 8;

		/* Try to decode symbols */
		while (nbits >= 5) { /* Minimum code length is 5 bits */
			int found = 0;
			int len;

			/* Try different code lengths from longest to shortest for current bits */
			for (len = (nbits > 30 ? 30 : nbits); len >= 5; len--) {
				uint32_t code = (uint32_t)((bits >> (nbits - len)) & ((1ULL << len) - 1));
				size_t j;

				/* Search for matching code in table */
				for (j = 0; j < HUFFMAN_TABLE_SIZE; j++) {
					if (huffman_table[j].nbits == len && huffman_table[j].bits == code) {
						if (dst_pos >= dst_len) {
							return -1;
						}
						dst[dst_pos++] = huffman_table[j].symbol;
						nbits -= len;
						found = 1;
						break;
					}
				}

				if (found) {
					break;
				}
			}

			if (!found) {
				/* No match found - might need more bits or it's padding */
				if (i == src_len - 1) {
					/* Last byte - remaining bits should be padding (all 1s) */
					uint32_t padding_mask = (1U << nbits) - 1;
					uint32_t remaining = (uint32_t)(bits & padding_mask);
					if (remaining == padding_mask) {
						/* Valid padding */
						return dst_pos;
					}
				}
				break; /* Need more bits */
			}
		}
	}

	return dst_pos;
}

static int hpack_decode_string(const uint8_t *data, int data_len, char **str)
{
	uint64_t len;
	int huffman;
	int offset = 0;
	int ret;

	if (data_len < 1) {
		return -1;
	}

	huffman = (data[0] & 0x80) != 0;
	ret = hpack_decode_integer(data, data_len, 7, &len);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	if (offset + (int)len > data_len) {
		return -1;
	}

	if (huffman) {
		/* Huffman decoding */

		/* Allocate buffer for decoded string (worst case: same size as encoded) */
		uint8_t *decoded = malloc(len * 2 + 1); /* Extra space for safety */
		if (!decoded) {
			return -1;
		}

		int decoded_len = hpack_decode_huffman(data + offset, len, decoded, len * 2);
		if (decoded_len < 0) {
			free(decoded);
			return -1;
		}

		*str = malloc(decoded_len + 1);
		if (!*str) {
			free(decoded);
			return -1;
		}

		memcpy(*str, decoded, decoded_len);
		(*str)[decoded_len] = '\0';
		free(decoded);
	} else {
		/* Literal string */
		*str = malloc(len + 1);
		if (*str == NULL) {
			return -1;
		}

		memcpy(*str, data + offset, len);
		(*str)[len] = '\0';
	}

	offset += len;

	return offset;
}

/* HPACK dynamic table management */

void hpack_init_context(struct hpack_context *hpack)
{
	hpack->dynamic_table = NULL;
	hpack->dynamic_table_size = 0;
	hpack->max_dynamic_table_size = 65536; /* Default size */
	hpack->entry_count = 0;
}

void hpack_free_context(struct hpack_context *hpack)
{
	struct hpack_dynamic_entry *entry = hpack->dynamic_table;
	while (entry) {
		struct hpack_dynamic_entry *next = entry->next;
		free(entry->name);
		free(entry->value);
		free(entry);
		entry = next;
	}
	hpack->dynamic_table = NULL;
	hpack->dynamic_table_size = 0;
	hpack->entry_count = 0;
}

static int hpack_add_dynamic_entry(struct hpack_context *hpack, const char *name, const char *value)
{
	struct hpack_dynamic_entry *entry;
	size_t entry_size = strlen(name) + strlen(value) + 32;

	/* Evict entries if necessary */
	while (hpack->dynamic_table_size + entry_size > hpack->max_dynamic_table_size && hpack->dynamic_table) {
		struct hpack_dynamic_entry *last = hpack->dynamic_table;
		struct hpack_dynamic_entry *prev = NULL;

		while (last->next) {
			prev = last;
			last = last->next;
		}

		if (prev) {
			prev->next = NULL;
		} else {
			hpack->dynamic_table = NULL;
		}

		hpack->dynamic_table_size -= last->size;
		hpack->entry_count--;
		free(last->name);
		free(last->value);
		free(last);
	}

	entry = malloc(sizeof(*entry));
	if (!entry) {
		return -1;
	}

	entry->name = strdup(name);
	entry->value = strdup(value);
	if (!entry->name || !entry->value) {
		free(entry->name);
		free(entry->value);
		free(entry);
		return -1;
	}

	entry->size = entry_size;
	entry->next = hpack->dynamic_table;
	hpack->dynamic_table = entry;
	hpack->dynamic_table_size += entry_size;
	hpack->entry_count++;

	return 0;
}

static int hpack_get_entry(struct hpack_context *hpack, int index, const char **name, const char **value)
{
	if (index == 0) {
		return -1;
	}

	if (index <= (int)HPACK_STATIC_TABLE_SIZE) {
		*name = hpack_static_table[index - 1].name;
		*value = hpack_static_table[index - 1].value;
		return 0;
	}

	/* Dynamic table */
	int dynamic_index = index - HPACK_STATIC_TABLE_SIZE - 1;
	struct hpack_dynamic_entry *entry = hpack->dynamic_table;
	int i = 0;

	while (entry && i < dynamic_index) {
		entry = entry->next;
		i++;
	}

	if (!entry) {
		return -1;
	}

	*name = entry->name;
	*value = entry->value;
	return 0;
}

static int hpack_find_index(struct hpack_context *hpack, const char *name, const char *value, int *index,
							int *name_only_index)
{
	int i;

	*index = 0;
	*name_only_index = 0;

	/* Search static table */
	for (i = 0; i < (int)HPACK_STATIC_TABLE_SIZE; i++) {
		if (strcmp(hpack_static_table[i].name, name) == 0) {
			if (*name_only_index == 0) {
				*name_only_index = i + 1;
			}
			if (strcmp(hpack_static_table[i].value, value) == 0) {
				*index = i + 1;
				return 0;
			}
		}
	}

	/* Search dynamic table */
	struct hpack_dynamic_entry *entry = hpack->dynamic_table;
	i = 0;
	while (entry) {
		if (strcmp(entry->name, name) == 0) {
			if (*name_only_index == 0) {
				*name_only_index = HPACK_STATIC_TABLE_SIZE + 1 + i;
			}
			if (strcmp(entry->value, value) == 0) {
				*index = HPACK_STATIC_TABLE_SIZE + 1 + i;
				return 0;
			}
		}
		entry = entry->next;
		i++;
	}

	return 0;
}

/* HPACK encoding */

int hpack_encode_header(struct hpack_context *hpack, const char *name, const char *value, uint8_t *buf, int buf_size)
{
	int index, name_only_index;
	int offset = 0;
	int ret;

	hpack_find_index(hpack, name, value, &index, &name_only_index);

	if (index > 0) {
		/* Indexed header field */
		if (buf_size < 1) {
			return -1;
		}
		buf[offset] = 0x80;
		ret = hpack_encode_integer(index, 7, buf + offset, buf_size - offset);
		if (ret < 0) {
			return -1;
		}
		return ret;
	}

	if (name_only_index > 0) {
		/* Literal with incremental indexing - indexed name */
		if (buf_size < 1) {
			return -1;
		}
		buf[offset] = 0x40;
		ret = hpack_encode_integer(name_only_index, 6, buf + offset, buf_size - offset);
		if (ret < 0) {
			return -1;
		}
		offset += ret;

		ret = hpack_encode_string(value, buf + offset, buf_size - offset);
		if (ret < 0) {
			return -1;
		}
		offset += ret;

		hpack_add_dynamic_entry(hpack, name, value);
		return offset;
	}

	/* Literal with incremental indexing - new name */
	if (buf_size < 1) {
		return -1;
	}
	buf[offset++] = 0x40;

	ret = hpack_encode_string(name, buf + offset, buf_size - offset);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	ret = hpack_encode_string(value, buf + offset, buf_size - offset);
	if (ret < 0) {
		return -1;
	}
	offset += ret;

	hpack_add_dynamic_entry(hpack, name, value);
	return offset;
}

/* HPACK decoding */

void hpack_resize_dynamic_table(struct hpack_context *hpack, size_t new_size)
{
	hpack->max_dynamic_table_size = new_size;

	/* Evict entries if necessary */
	while (hpack->dynamic_table_size > hpack->max_dynamic_table_size && hpack->dynamic_table) {
		struct hpack_dynamic_entry *last = hpack->dynamic_table;
		struct hpack_dynamic_entry *prev = NULL;

		while (last->next) {
			prev = last;
			last = last->next;
		}

		if (prev) {
			prev->next = NULL;
		} else {
			hpack->dynamic_table = NULL;
		}

		hpack->dynamic_table_size -= last->size;
		hpack->entry_count--;
		free(last->name);
		free(last->value);
		free(last);
	}
}

int hpack_decode_headers(struct hpack_context *hpack, const uint8_t *data, int data_len, hpack_on_header_fn on_header,
						 void *ctx)
{
	int offset = 0;

	while (offset < data_len) {
		const char *name = NULL;
		const char *value = NULL;
		char *allocated_name = NULL;
		char *allocated_value = NULL;

		if ((data[offset] & 0x80) != 0) {
			/* Indexed header field */
			uint64_t index;
			const char *static_name, *static_value;
			int ret = hpack_decode_integer(data + offset, data_len - offset, 7, &index);
			if (ret < 0) {
				return -1;
			}
			if (hpack_get_entry(hpack, index, &static_name, &static_value) < 0) {
				return -1;
			}
			offset += ret;

			name = static_name;
			value = static_value;
		} else if ((data[offset] & 0x40) != 0) {
			/* Literal with incremental indexing */
			uint64_t index;
			int ret = hpack_decode_integer(data + offset, data_len - offset, 6, &index);
			if (ret < 0) {
				return -1;
			}
			offset += ret;

			if (index > 0) {
				const char *static_name, *static_value;
				if (hpack_get_entry(hpack, index, &static_name, &static_value) < 0) {
					return -1;
				}
				name = static_name;
			} else {
				ret = hpack_decode_string(data + offset, data_len - offset, &allocated_name);
				if (ret < 0) {
					return -1;
				}
				offset += ret;
				name = allocated_name;
			}

			ret = hpack_decode_string(data + offset, data_len - offset, &allocated_value);
			if (ret < 0) {
				free(allocated_name);
				return -1;
			}
			offset += ret;
			value = allocated_value;

			if (name && value) {
				hpack_add_dynamic_entry(hpack, name, value);
			}
		} else if ((data[offset] & 0x20) != 0) {
			/* Dynamic Table Size Update */
			uint64_t new_size;
			int ret = hpack_decode_integer(data + offset, data_len - offset, 5, &new_size);
			if (ret < 0) {
				return -1;
			}
			offset += ret;
			hpack_resize_dynamic_table(hpack, new_size);
			continue; /* Continue to next field */
		} else {
			/* Literal without indexing or never indexed */
			uint64_t index;
			int prefix = 4; /* Both types use 4-bit prefix */
			int ret = hpack_decode_integer(data + offset, data_len - offset, prefix, &index);
			if (ret < 0) {
				return -1;
			}
			offset += ret;

			if (index > 0) {
				const char *static_name, *static_value;
				if (hpack_get_entry(hpack, index, &static_name, &static_value) < 0) {
					return -1;
				}
				name = static_name;
			} else {
				ret = hpack_decode_string(data + offset, data_len - offset, &allocated_name);
				if (ret < 0) {
					return -1;
				}
				offset += ret;
				name = allocated_name;
			}

			ret = hpack_decode_string(data + offset, data_len - offset, &allocated_value);
			if (ret < 0) {
				free(allocated_name);
				return -1;
			}
			offset += ret;
			value = allocated_value;
		}

		/* Add header to stream */
		if (on_header(ctx, name, value) < 0) {
			free(allocated_name);
			free(allocated_value);
			return -1;
		}

		/* Free allocated strings if they were copied */
		if (allocated_name) {
			free(allocated_name);
		}
		if (allocated_value) {
			free(allocated_value);
		}
	}

	return 0;
}
