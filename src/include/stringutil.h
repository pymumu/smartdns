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

#ifndef _GENERIC_STRING_UITL_H
#define _GENERIC_STRING_UITL_H

#include <stddef.h>
#include <string.h>

static inline char *safe_strncpy(char *dest, const char *src, size_t n) 
{
#if __GNUC__  > 7
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
	char *ret = strncpy(dest, src, n - 1);
    if (n > 0) {
	    dest[n - 1] = '\0';
    }
#if __GNUC__  > 7
#pragma GCC diagnostic pop
#endif
	return ret;
}


#endif
