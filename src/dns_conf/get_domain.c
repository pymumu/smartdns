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

#include "get_domain.h"
#include "smartdns/lib/idna.h"
#include "smartdns/lib/stringutil.h"
#include "smartdns/util.h"

int _get_domain(char *value, char *domain, int max_domain_size, char **ptr_after_domain)
{
	char *begin = NULL;
	char *end = NULL;
	int len = 0;

	if (value == NULL || domain == NULL) {
		goto errout;
	}

	/* first field */
	begin = strstr(value, "/");
	if (begin == NULL) {
		safe_strncpy(domain, ".", max_domain_size);
		return 0;
	}

	/* second field */
	begin++;
	end = strstr(begin, "/");
	if (end == NULL) {
		goto errout;
	}

	/* remove prefix . */
	while (*begin == '.') {
		if (begin + 1 == end) {
			break;
		}
		begin++;
	}

	/* Get domain */
	len = end - begin;
	if (len >= max_domain_size) {
		tlog(TLOG_ERROR, "domain name %s too long", value);
		goto errout;
	}

	size_t domain_len = max_domain_size;
	if (strncmp(begin, "domain-set:", sizeof("domain-set:") - 1) == 0) {
		memcpy(domain, begin, len);
		domain_len = len;
	} else {
		domain_len = utf8_to_punycode(begin, len, domain, domain_len);
		if (domain_len <= 0) {
			tlog(TLOG_ERROR, "domain name %s invalid", value);
			goto errout;
		}
	}

	domain[domain_len] = '\0';

	if (ptr_after_domain) {
		*ptr_after_domain = end + 1;
	}

	return 0;
errout:
	return -1;
}