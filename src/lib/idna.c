
/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
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

#define _GNU_SOURCE
#include "idna.h"
#include <limits.h>

static unsigned _utf8_decode_slow(const char **p, const char *pe, unsigned a)
{
	unsigned b;
	unsigned c;
	unsigned d;
	unsigned min;

	if (a > 0xF7) {
		return -1;
	}

	switch (pe - *p) {
	default:
		if (a > 0xEF) {
			min = 0x10000;
			a = a & 7;
			b = (unsigned char)*(*p)++;
			c = (unsigned char)*(*p)++;
			d = (unsigned char)*(*p)++;
			break;
		}
	case 2:
		if (a > 0xDF) {
			min = 0x800;
			b = 0x80 | (a & 15);
			c = (unsigned char)*(*p)++;
			d = (unsigned char)*(*p)++;
			a = 0;
			break;
		}
	case 1:
		if (a > 0xBF) {
			min = 0x80;
			b = 0x80;
			c = 0x80 | (a & 31);
			d = (unsigned char)*(*p)++;
			a = 0;
			break;
		}
	case 0:
		return -1;
	}

	if (0x80 != (0xC0 & (b ^ c ^ d))) {
		return -1;
	}

	b &= 63;
	c &= 63;
	d &= 63;
	a = (a << 18) | (b << 12) | (c << 6) | d;

	if (a < min) {
		return -1;
	}

	if (a > 0x10FFFF) {
		return -1;
	}

	if (a >= 0xD800 && a <= 0xDFFF) {
		return -1;
	}

	return a;
}

static unsigned _utf8_decode(const char **p, const char *pe)
{
	unsigned a;

	a = (unsigned char)*(*p)++;

	if (a < 128) {
		return a;
	}

	return _utf8_decode_slow(p, pe, a);
}

static int _utf8_to_punycode_label(const char *s, const char *se, char **d, char *de)
{
	static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	const char *ss;
	unsigned c;
	unsigned h;
	unsigned k;
	unsigned n;
	unsigned m;
	unsigned q;
	unsigned t;
	unsigned x;
	unsigned y;
	unsigned bias;
	unsigned delta;
	unsigned todo;
	int first;

	h = 0;
	ss = s;
	todo = 0;

	while (s < se) {
		c = _utf8_decode(&s, se);
		if (c == UINT_MAX) {
			return -1;
		}

		if (c < 128) {
			h++;
		} else {
			todo++;
		}
	}

	if (todo > 0) {
		if (*d < de) {
			*(*d)++ = 'x';
		}
		if (*d < de) {
			*(*d)++ = 'n';
		}
		if (*d < de) {
			*(*d)++ = '-';
		}
		if (*d < de) {
			*(*d)++ = '-';
		}
	}

	x = 0;
	s = ss;
	while (s < se) {
		c = _utf8_decode(&s, se);

		if (c > 127) {
			continue;
		}

		if (*d < de) {
			*(*d)++ = c;
		}

		if (++x == h) {
			break;
		}
	}

	if (todo == 0) {
		return h;
	}

	if (h > 0) {
		if (*d < de) {
			*(*d)++ = '-';
		}
	}

	n = 128;
	bias = 72;
	delta = 0;
	first = 1;

	while (todo > 0) {
		m = -1;
		s = ss;

		while (s < se) {
			c = _utf8_decode(&s, se);

			if (c >= n) {
				if (c < m) {
					m = c;
				}
			}
		}

		x = m - n;
		y = h + 1;

		if (x > ~delta / y) {
			return -1;
		}

		delta += x * y;
		n = m;

		s = ss;
		while (s < se) {
			c = _utf8_decode(&s, se);

			if (c < n) {
				if (++delta == 0) {
					return -1;
				}
			}

			if (c != n) {
				continue;
			}

			for (k = 36, q = delta;; k += 36) {
				t = 1;

				if (k > bias) {
					t = k - bias;
				}

				if (t > 26) {
					t = 26;
				}

				if (q < t) {
					break;
				}

				x = q - t;
				y = 36 - t;
				q = x / y;
				t = t + x % y;

				if (*d < de) {
					*(*d)++ = alphabet[t];
				}
			}

			if (*d < de) {
				*(*d)++ = alphabet[q];
			}

			delta /= 2;

			if (first) {
				delta /= 350;
				first = 0;
			}

			h++;
			delta += delta / h;

			for (bias = 0; delta > 35 * 26 / 2; bias += 36) {
				delta /= 35;
			}

			bias += 36 * delta / (delta + 38);
			delta = 0;
			todo--;
		}

		delta++;
		n++;
	}

	return 0;
}

int utf8_to_punycode(const char *src, int src_len, char *dst, int dst_len)
{
	const char *si;
	const char *se;
	const char *st;
	unsigned c;
	char *ds;
	char *de;
	int rc;

	ds = dst;
	si = src;
	se = src + src_len;
	de = dst + dst_len;

	while (si < se) {
		st = si;
		c = _utf8_decode(&si, se);

		if (c == UINT_MAX) {
			return -1;
		}

		if (c != '.') {
			if (c != 0x3002) {
				if (c != 0xFF0E) {
					if (c != 0xFF61) {
						continue;
					}
				}
			}
		}

		rc = _utf8_to_punycode_label(src, st, &dst, de);

		if (rc < 0) {
			return rc;
		}

		if (dst < de) {
			*dst++ = '.';
		}

		src = si;
	}

	if (src < se) {
		rc = _utf8_to_punycode_label(src, se, &dst, de);

		if (rc < 0) {
			return rc;
		}
	}

	if (dst < de) {
		*dst++ = '\0';
	}

	return dst - ds;
}