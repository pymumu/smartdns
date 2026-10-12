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

#ifndef _GENERIC_STRING_UITL_H
#define _GENERIC_STRING_UITL_H

#include <stddef.h>
#include <string.h>

static inline char *safe_strncpy(char *dest, const char *src, size_t n) 
{
	if (src == NULL) {
		dest[0] = '\0';
		return dest;
	}

	if (n <= 0) {
		return NULL;
	}
	
/*
 * -Wstringop-truncation was introduced in GCC 8. clang is excluded explicitly
 * because it reports __GNUC__ as 4 and has no such warning.
 * Deliberately not using SMARTDNS_GCC_VERSION here: pulling in gcc_builtin.h
 * would also drag the min()/max() macros into every translation unit.
 */
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 8
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
	char *ret = strncpy(dest, src, n - 1);
	if (n > 0) {
		dest[n - 1] = '\0';
	}
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
	return ret;
}

static inline char *safe_strncpy_lower(char *dest, const char *src, size_t n, int *case_changed) 
{
	if (src == NULL) {
		dest[0] = '\0';
		return dest;
	}

	if (n <= 0) {
		return NULL;
	}
	
	while (n > 1 && *src) {
		*dest = *src;
		if (*dest >= 'A' && *dest <= 'Z') {
			*dest = *dest + 32;
			if (case_changed) {
				*case_changed = 1;
			}
		}
		dest++;
		src++;
		n--;
	}
	*dest = '\0';
	return dest;
}


#endif
