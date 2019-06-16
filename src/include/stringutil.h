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