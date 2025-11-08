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

#include "hpack.h"
#include <string.h>

/* HPACK static table (RFC 7541 Appendix A) - indices 1-61 */
static struct hpack_header_field hpack_static_table[] = {
	{":authority", ""},                   /* 1 */
	{":method", "GET"},                   /* 2 */
	{":method", "POST"},                  /* 3 */
	{":path", "/"},                       /* 4 */
	{":path", "/index.html"},             /* 5 */
	{":scheme", "http"},                  /* 6 */
	{":scheme", "https"},                 /* 7 */
	{":status", "200"},                   /* 8 */
	{":status", "204"},                   /* 9 */
	{":status", "206"},                   /* 10 */
	{":status", "304"},                   /* 11 */
	{":status", "400"},                   /* 12 */
	{":status", "404"},                   /* 13 */
	{":status", "500"},                   /* 14 */
	{"accept-charset", ""},               /* 15 */
	{"accept-encoding", "gzip, deflate"}, /* 16 */
	{"accept-language", ""},              /* 17 */
	{"accept-ranges", ""},                /* 18 */
	{"accept", ""},                       /* 19 */
	{"access-control-allow-origin", ""},  /* 20 */
	{"age", ""},                          /* 21 */
	{"allow", ""},                        /* 22 */
	{"authorization", ""},                /* 23 */
	{"cache-control", ""},                /* 24 */
	{"content-disposition", ""},          /* 25 */
	{"content-encoding", ""},             /* 26 */
	{"content-language", ""},             /* 27 */
	{"content-length", ""},               /* 28 */
	{"content-location", ""},             /* 29 */
	{"content-range", ""},                /* 30 */
	{"content-type", ""},                 /* 31 */
	{"cookie", ""},                       /* 32 */
	{"date", ""},                         /* 33 */
	{"etag", ""},                         /* 34 */
	{"expect", ""},                       /* 35 */
	{"expires", ""},                      /* 36 */
	{"from", ""},                         /* 37 */
	{"host", ""},                         /* 38 */
	{"if-match", ""},                     /* 39 */
	{"if-modified-since", ""},            /* 40 */
	{"if-none-match", ""},                /* 41 */
	{"if-range", ""},                     /* 42 */
	{"if-unmodified-since", ""},          /* 43 */
	{"last-modified", ""},                /* 44 */
	{"link", ""},                         /* 45 */
	{"location", ""},                     /* 46 */
	{"max-forwards", ""},                 /* 47 */
	{"proxy-authenticate", ""},           /* 48 */
	{"proxy-authorization", ""},          /* 49 */
	{"range", ""},                        /* 50 */
	{"referer", ""},                      /* 51 */
	{"refresh", ""},                      /* 52 */
	{"retry-after", ""},                  /* 53 */
	{"server", ""},                       /* 54 */
	{"set-cookie", ""},                   /* 55 */
	{"strict-transport-security", ""},    /* 56 */
	{"transfer-encoding", ""},            /* 57 */
	{"user-agent", ""},                   /* 58 */
	{"vary", ""},                         /* 59 */
	{"via", ""},                          /* 60 */
	{"www-authenticate", ""},             /* 61 */
};

struct hpack_header_field *hpack_get_static_header_field(int index)
{
	if (index < 1 || index > 61) {
		return NULL;
	}
	return &hpack_static_table[index - 1];
}

/* Huffman decode - reuse the QPACK huffman decoder as they share the same encoding */
/* HPACK and QPACK use the same Huffman coding table from RFC 7541 */
extern int qpack_huffman_decode(const uint8_t *bytes, const uint8_t *bytes_max, uint8_t *decoded, size_t max_decoded,
								size_t *nb_decoded);

int hpack_huffman_decode(const uint8_t *bytes, const uint8_t *bytes_max, uint8_t *decoded, size_t max_decoded,
						 size_t *nb_decoded)
{
	/* HPACK and QPACK use the same Huffman coding, so we can reuse the QPACK decoder */
	return qpack_huffman_decode(bytes, bytes_max, decoded, max_decoded, nb_decoded);
}

int hpack_huffman_encode(const uint8_t *input, size_t input_len, uint8_t *output, size_t max_output,
						 size_t *output_len)
{
	/* For now, we don't encode with Huffman - just copy the input */
	/* This is acceptable for DoH as the messages are small */
	if (input_len > max_output) {
		return -1;
	}
	memcpy(output, input, input_len);
	*output_len = input_len;
	return 0;
}
