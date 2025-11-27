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

#include "smartdns/tlog.h"
#include "smartdns/util.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

int encode_alpn_protos(const char *alpn, uint8_t *alpn_data, int alpn_data_max)
{
	int alpn_data_len = 0;
	const char *alpn_str = alpn;

	if (alpn == NULL || alpn[0] == 0 || alpn_data == NULL || alpn_data_max <= 0) {
		return 0;
	}

	/* Parse comma-separated ALPN protocols and encode in wire format */
	while (*alpn_str && alpn_data_len < alpn_data_max - 1) {
		const char *comma = strchr(alpn_str, ',');
		int proto_len;

		if (comma) {
			proto_len = comma - alpn_str;
		} else {
			proto_len = strnlen(alpn_str, alpn_data_max - alpn_data_len - 1);
		}

		/* Skip empty protocols */
		if (proto_len == 0) {
			alpn_str = comma ? comma + 1 : alpn_str + proto_len;
			continue;
		}

		/* Check if we have space for length byte + protocol */
		if (alpn_data_len + 1 + proto_len > alpn_data_max) {
			tlog(TLOG_WARN, "ALPN string too long, truncating.");
			break;
		}

		/* Write length-prefixed protocol */
		alpn_data[alpn_data_len++] = (uint8_t)proto_len;
		memcpy(alpn_data + alpn_data_len, alpn_str, proto_len);
		alpn_data_len += proto_len;

		/* Move to next protocol */
		alpn_str = comma ? comma + 1 : alpn_str + proto_len;
		if (!comma) {
			break;
		}
	}

	return alpn_data_len;
}
