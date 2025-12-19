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

#include "smartdns/util.h"

#include <ctype.h>
#include <linux/limits.h>
#include <stdlib.h>

int parse_uri(const char *value, char *scheme, char *host, int *port, char *path)
{
	return parse_uri_ext(value, scheme, NULL, NULL, host, port, path);
}

int urldecode(char *dst, int dst_maxlen, const char *src)
{
	char a, b;
	int len = 0;
	while (*src) {
		if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
			if (a >= 'a') {
				a -= 'a' - 'A';
			}

			if (a >= 'A') {
				a -= ('A' - 10);
			} else {
				a -= '0';
			}

			if (b >= 'a') {
				b -= 'a' - 'A';
			}

			if (b >= 'A') {
				b -= ('A' - 10);
			} else {
				b -= '0';
			}
			*dst++ = 16 * a + b;
			src += 3;
		} else if (*src == '+') {
			*dst++ = ' ';
			src++;
		} else {
			*dst++ = *src++;
		}

		len++;
		if (len >= dst_maxlen - 1) {
			return -1;
		}
	}
	*dst++ = '\0';

	return len;
}

int parse_uri_ext(const char *value, char *scheme, char *user, char *password, char *host, int *port, char *path)
{
	char *scheme_end = NULL;
	int field_len = 0;
	const char *process_ptr = value;
	char user_pass_host_part[PATH_MAX];
	char *user_password = NULL;
	char *host_part = NULL;

	const char *host_end = NULL;

	scheme_end = strstr(value, "://");
	if (scheme_end) {
		field_len = scheme_end - value;
		if (scheme) {
			memcpy(scheme, value, field_len);
			scheme[field_len] = 0;
		}
		process_ptr += field_len + 3;
	} else {
		if (scheme) {
			scheme[0] = '\0';
		}
	}

	host_end = strstr(process_ptr, "/");
	if (host_end == NULL) {
		host_end = process_ptr + strlen(process_ptr);
	};

	field_len = host_end - process_ptr;
	if (field_len >= (int)sizeof(user_pass_host_part)) {
		return -1;
	}
	memcpy(user_pass_host_part, process_ptr, field_len);
	user_pass_host_part[field_len] = 0;

	host_part = strstr(user_pass_host_part, "@");
	if (host_part != NULL) {
		*host_part = '\0';
		host_part = host_part + 1;
		user_password = user_pass_host_part;
		char *sep = strstr(user_password, ":");
		if (sep != NULL) {
			*sep = '\0';
			sep = sep + 1;
			if (password) {
				if (urldecode(password, 128, sep) < 0) {
					return -1;
				}
			}
		}
		if (user) {
			if (urldecode(user, 128, user_password) < 0) {
				return -1;
			}
		}
	} else {
		host_part = user_pass_host_part;
	}

	if (host != NULL && parse_ip(host_part, host, port) != 0) {
		return -1;
	}

	process_ptr += field_len;

	if (path) {
		/* Safe to use strcpy here because:
		 * 1. process_ptr points to a substring of the original 'value' parameter
		 * 2. The remaining length has been validated earlier (field_len < PATH_MAX)
		 * 3. Callers are expected to provide a buffer of at least PATH_MAX size
		 * However, we add a length check for extra safety.
		 */
		size_t remaining_len = strlen(process_ptr);
		if (remaining_len >= PATH_MAX) {
			return -1;
		}
		memcpy(path, process_ptr, remaining_len);
		path[remaining_len] = '\0';
	}
	return 0;
}

int parse_ip(const char *value, char *ip, int *port)
{
	int offset = 0;
	char *colon = NULL;

	colon = strstr(value, ":");

	if (strstr(value, "[")) {
		/* ipv6 with port */
		char *bracket_end = strstr(value, "]");
		if (bracket_end == NULL) {
			return -1;
		}

		offset = bracket_end - value - 1;
		memcpy(ip, value + 1, offset);
		ip[offset] = 0;

		colon = strstr(bracket_end, ":");
		if (colon) {
			colon++;
		}
	} else if (colon && strstr(colon + 1, ":")) {
		/* ipv6 without port */
		strncpy(ip, value, MAX_IP_LEN);
		colon = NULL;
	} else {
		/* ipv4 */
		colon = strstr(value, ":");
		if (colon == NULL) {
			/* without port */
			strncpy(ip, value, MAX_IP_LEN);
		} else {
			/* with port */
			offset = colon - value;
			colon++;
			memcpy(ip, value, offset);
			ip[offset] = 0;
		}
	}

	if (colon) {
		/* get port num */
		*port = atoi(colon);
	} else {
		*port = PORT_NOT_DEFINED;
	}

	if (ip[0] == 0) {
		return -1;
	}

	return 0;
}
