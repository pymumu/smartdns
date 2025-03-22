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

#ifndef _QPACK_H
#define _QPACK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct qpack_header_field {
	const char *name;
	const char *value;
};

struct qpack_header_field *qpack_get_static_header_field(int index);

int qpack_huffman_decode(const uint8_t *bytes, const uint8_t *bytes_max, uint8_t *decoded, size_t max_decoded,
						 size_t *nb_decoded);

#ifdef __cplusplus
}
#endif

#endif // !_QPACK_H
