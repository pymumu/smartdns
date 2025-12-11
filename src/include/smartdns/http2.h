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

#ifndef _HTTP2_H_
#define _HTTP2_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque structures */
struct http2_ctx;
struct http2_stream;

/* HTTP/2 Settings structure */
struct http2_settings {
	int max_concurrent_streams; /* -1 = use default (4096), 0 = unlimited */
};

/* Error codes */
enum {
	HTTP2_ERR_NONE = 0,
	HTTP2_ERR_EAGAIN = -1,
	HTTP2_ERR_EOF = -2,
	HTTP2_ERR_IO = -3,
	HTTP2_ERR_PROTOCOL = -4,
	HTTP2_ERR_HTTP1 = -5,
};

/* Convert error code to string */
const char *http2_error_to_string(int ret);

/* BIO callback types */
typedef int (*http2_bio_read_fn)(void *private_data, uint8_t *buf, int len);
typedef int (*http2_bio_write_fn)(void *private_data, const uint8_t *buf, int len);

/* Poll item for checking stream readiness */
struct http2_poll_item {
	struct http2_stream *stream;
	int readable; /* 1 if stream has data to read, 0 otherwise */
	int writable; /* 1 if stream can accept writes, 0 otherwise */
};

/* Connection Lifecycle APIs */

/**
 * Create a new HTTP/2 client context
 * @param server Server name (for debugging/logging)
 * @param bio_read Read callback function
 * @param bio_write Write callback function
 * @param private_data User data passed to BIO callbacks
 * @param settings HTTP/2 settings to use (NULL for defaults)
 * @return New context or NULL on error
 */
struct http2_ctx *http2_ctx_client_new(const char *server, http2_bio_read_fn bio_read, http2_bio_write_fn bio_write,
									   void *private_data, const struct http2_settings *settings);

/**
 * Create a new HTTP/2 server context
 * @param server Server name (for debugging/logging)
 * @param bio_read Read callback function
 * @param bio_write Write callback function
 * @param private_data User data passed to BIO callbacks
 * @param settings HTTP/2 settings to use (NULL for defaults)
 * @return New context or NULL on error
 */
struct http2_ctx *http2_ctx_server_new(const char *server, http2_bio_read_fn bio_read, http2_bio_write_fn bio_write,
									   void *private_data, const struct http2_settings *settings);

/**
 * Close an HTTP/2 context, release all streams and release ownership.
 * This is used to break circular references between context and streams
 * @param ctx Context to close
 */
void http2_ctx_close(struct http2_ctx *ctx);

/**
 * Increase reference count of HTTP/2 context
 * @param ctx HTTP/2 context
 * @return The same context pointer
 */
struct http2_ctx *http2_ctx_get(struct http2_ctx *ctx);

/**
 * Decrease reference count of HTTP/2 context
 * Frees the context when reference count reaches zero
 * @param ctx HTTP/2 context
 */
void http2_ctx_put(struct http2_ctx *ctx);

/**
 * Perform HTTP/2 handshake (SETTINGS exchange)
 * @param ctx HTTP/2 context
 * @return 1 if handshake complete, 0 if in progress, -1 on error
 */
int http2_ctx_handshake(struct http2_ctx *ctx);

/**
 * Server: Accept an incoming stream
 * @param ctx HTTP/2 context
 * @return New stream or NULL if no stream available
 */
struct http2_stream *http2_ctx_accept_stream(struct http2_ctx *ctx);

/**
 * Poll streams for readiness
 * @param ctx HTTP/2 context
 * @param items Array to fill with poll results
 * @param max_items Maximum number of items to return
 * @param ret_count Output: number of items returned
 * @return 0 on success, -1 on error
 */
int http2_ctx_poll(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items, int *ret_count);

/**
 * Poll streams for readiness (only readable streams)
 * @param ctx HTTP/2 context
 * @param items Array to fill with poll results
 * @param max_items Maximum number of items to return
 * @param ret_count Output: number of items returned
 * @return 0 on success, -1 on error
 */
int http2_ctx_poll_readable(struct http2_ctx *ctx, struct http2_poll_item *items, int max_items, int *ret_count);

/**
 * Check if context wants to read (EAGAIN on last read)
 * @param ctx HTTP/2 context
 * @return 1 if wants read, 0 otherwise
 */
int http2_ctx_want_read(struct http2_ctx *ctx);

/**
 * Check if context wants to write (has pending buffered writes)
 * @param ctx HTTP/2 context
 * @return 1 if wants write, 0 otherwise
 */
int http2_ctx_want_write(struct http2_ctx *ctx);

/**
 * Check if connection is closed or has encountered an error
 * @param ctx HTTP/2 context
 * @return 1 if connection is closed/errored, 0 if still active
 */
int http2_ctx_is_closed(struct http2_ctx *ctx);

/* Stream Management APIs */

/**
 * Client: Create a new stream
 * @param ctx HTTP/2 context
 * @return New stream or NULL on error
 */
struct http2_stream *http2_stream_new(struct http2_ctx *ctx);

/**
 * Free a stream
 * @param stream Stream to free
 */

/**
 * Close a stream and release ownership
 * @param stream Stream to close
 */
void http2_stream_close(struct http2_stream *stream);

/**
 * Increase reference count of stream
 * @param stream Stream
 * @return The same stream pointer
 */
struct http2_stream *http2_stream_get(struct http2_stream *stream);

/**
 * Decrease reference count of stream
 * Frees the stream when reference count reaches zero
 * @param stream Stream
 */
void http2_stream_put(struct http2_stream *stream);

/**
 * Get stream ID
 * @param stream Stream
 * @return Stream ID or -1 on error
 */
int http2_stream_get_id(struct http2_stream *stream);

/* Header name-value pair for building header lists */
struct http2_header_pair {
	const char *name;
	const char *value;
};

/* Stream Header APIs */

/**
 * Client: Set request headers
 * @param stream Stream
 * @param method HTTP method (e.g., "GET", "POST")
 * @param path Request path
 * @param headers Array of additional headers (NULL-terminated, last element must have name=NULL)
 * @return 0 on success, -1 on error
 */
int http2_stream_set_request(struct http2_stream *stream, const char *method, const char *path,
							 const struct http2_header_pair *headers);

/**
 * Server: Set response headers
 * @param stream Stream
 * @param status HTTP status code (e.g., 200, 404)
 * @param headers Array of additional headers
 * @param header_count Number of headers in the array
 * @return 0 on success, -1 on error
 */
int http2_stream_set_response(struct http2_stream *stream, int status, const struct http2_header_pair *headers,
							  int header_count);

/**
 * Get HTTP method from request
 * @param stream Stream
 * @return Method string or NULL
 */
const char *http2_stream_get_method(struct http2_stream *stream);

/**
 * Get query parameter from request path
 * @param stream Stream
 * @param name Parameter name
 * @return Parameter value (must be freed by caller) or NULL if not found
 */
char *http2_stream_get_query_param(struct http2_stream *stream, const char *name);

/**
 * Get request path
 * @param stream Stream
 * @return Path string or NULL
 */
const char *http2_stream_get_path(struct http2_stream *stream);

/**
 * Get response status code
 * @param stream Stream
 * @return Status code or -1 if not set
 */
int http2_stream_get_status(struct http2_stream *stream);

/**
 * Get header value by name
 * @param stream Stream
 * @param name Header name
 * @return Header value or NULL if not found
 */
const char *http2_stream_get_header(struct http2_stream *stream, const char *name);

/**
 * Walk all headers in the stream
 * @param stream Stream
 * @param fn Callback function to call for each header
 * @param arg User data passed to callback
 */
typedef void (*header_walk_fn)(void *arg, const char *name, const char *value);
void http2_stream_headers_walk(struct http2_stream *stream, header_walk_fn fn, void *arg);

/* Stream Body APIs */

/**
 * Write body data to stream
 * @param stream Stream
 * @param data Data to write
 * @param len Length of data
 * @param end_stream 1 to mark end of stream, 0 otherwise
 * @return Number of bytes written or -1 on error
 */
int http2_stream_write_body(struct http2_stream *stream, const uint8_t *data, int len, int end_stream);

/**
 * Read body data from stream
 * @param stream Stream
 * @param data Buffer to read into
 * @param len Maximum length to read
 * @return Number of bytes read, 0 if no data available, -1 on error
 */
int http2_stream_read_body(struct http2_stream *stream, uint8_t *data, int len);

/**
 * Check if body data is available to read
 * @param stream Stream
 * @return 1 if data available, 0 otherwise
 */
int http2_stream_body_available(struct http2_stream *stream);

/**
 * Check if stream has ended
 * @param stream Stream
 * @return 1 if stream ended, 0 otherwise
 */
int http2_stream_is_end(struct http2_stream *stream);

/* Stream Metadata APIs */

/**
 * Set user data on stream
 * @param stream Stream
 * @param data User data pointer
 */
void http2_stream_set_ex_data(struct http2_stream *stream, void *data);

/**
 * Get user data from stream
 * @param stream Stream
 * @return User data pointer or NULL
 */
void *http2_stream_get_ex_data(struct http2_stream *stream);

#ifdef __cplusplus
}
#endif

#endif /* _HTTP2_H_ */
