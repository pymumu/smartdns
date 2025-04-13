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

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static int parse_extensions(const char *, size_t, char *, const char **);
static int parse_server_name_extension(const char *, size_t, char *, const char **);

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first server name found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
int parse_tls_header(const char *data, size_t data_len, char *hostname, const char **hostname_ptr)
{
	char tls_content_type = 0;
	char tls_version_major = 0;
	char tls_version_minor = 0;
	size_t pos = TLS_HEADER_LEN;
	size_t len = 0;

	if (hostname == NULL) {
		return -3;
	}

	/* Check that our TCP payload is at least large enough for a TLS header */
	if (data_len < TLS_HEADER_LEN) {
		return -1;
	}

	/* SSL 2.0 compatible Client Hello
	 *
	 * High bit of first byte (length) and content type is Client Hello
	 *
	 * See RFC5246 Appendix E.2
	 */
	if (data[0] & 0x80 && data[2] == 1) {
		return -2;
	}

	tls_content_type = data[0];
	if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
		return -5;
	}

	tls_version_major = data[1];
	tls_version_minor = data[2];
	if (tls_version_major < 3) {
		return -2;
	}

	/* TLS record length */
	len = ((unsigned char)data[3] << 8) + (unsigned char)data[4] + TLS_HEADER_LEN;
	data_len = MIN(data_len, len);

	/* Check we received entire TLS record length */
	if (data_len < len) {
		return -1;
	}

	/*
	 * Handshake
	 */
	if (pos + 1 > data_len) {
		return -5;
	}
	if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		return -5;
	}

	/* Skip past fixed length records:
	 * 1	Handshake Type
	 * 3	Length
	 * 2	Version (again)
	 * 32	Random
	 * to	Session ID Length
	 */
	pos += 38;

	/* Session ID */
	if (pos + 1 > data_len) {
		return -5;
	}
	len = (unsigned char)data[pos];
	pos += 1 + len;

	/* Cipher Suites */
	if (pos + 2 > data_len) {
		return -5;
	}
	len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
	pos += 2 + len;

	/* Compression Methods */
	if (pos + 1 > data_len) {
		return -5;
	}
	len = (unsigned char)data[pos];
	pos += 1 + len;

	if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
		return -2;
	}

	/* Extensions */
	if (pos + 2 > data_len) {
		return -5;
	}
	len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
	pos += 2;

	if (pos + len > data_len) {
		return -5;
	}
	return parse_extensions(data + pos, len, hostname, hostname_ptr);
}

static int parse_extensions(const char *data, size_t data_len, char *hostname, const char **hostname_ptr)
{
	size_t pos = 0;
	size_t len = 0;

	/* Parse each 4 bytes for the extension header */
	while (pos + 4 <= data_len) {
		/* Extension Length */
		len = ((unsigned char)data[pos + 2] << 8) + (unsigned char)data[pos + 3];

		/* Check if it's a server name extension */
		if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
			/* There can be only one extension of each type, so we break
			 * our state and move p to beginning of the extension here */
			if (pos + 4 + len > data_len) {
				return -5;
			}
			return parse_server_name_extension(data + pos + 4, len, hostname, hostname_ptr);
		}
		pos += 4 + len; /* Advance to the next extension header */
	}
	/* Check we ended where we expected to */
	if (pos != data_len) {
		return -5;
	}

	return -2;
}

static int parse_server_name_extension(const char *data, size_t data_len, char *hostname, const char **hostname_ptr)
{
	size_t pos = 2; /* skip server name list length */
	size_t len = 0;

	while (pos + 3 < data_len) {
		len = ((unsigned char)data[pos + 1] << 8) + (unsigned char)data[pos + 2];

		if (pos + 3 + len > data_len) {
			return -5;
		}

		switch (data[pos]) { /* name type */
		case 0x00:           /* host_name */
			strncpy(hostname, data + pos + 3, len);
			if (hostname_ptr) {
				*hostname_ptr = data + pos + 3;
			}
			hostname[len] = '\0';

			return len;
		default:
			break;
		}
		pos += 3 + len;
	}
	/* Check we ended where we expected to */
	if (pos != data_len) {
		return -5;
	}

	return -2;
}