#ifndef _HPACK_H_
#define _HPACK_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* HPACK dynamic table entry */
struct hpack_dynamic_entry {
	char *name;
	char *value;
	size_t size; /* name_len + value_len + 32 */
	struct hpack_dynamic_entry *next;
};

/* HPACK context */
struct hpack_context {
	struct hpack_dynamic_entry *dynamic_table;
	size_t dynamic_table_size;
	size_t max_dynamic_table_size;
	int entry_count;
};

/* Callback function for decoded headers */
typedef int (*hpack_on_header_fn)(void *ctx, const char *name, const char *value);

/**
 * Initialize HPACK context
 * @param hpack HPACK context
 */
void hpack_init_context(struct hpack_context *hpack);

/**
 * Free HPACK context
 * @param hpack HPACK context
 */
void hpack_free_context(struct hpack_context *hpack);

/**
 * Resize dynamic table
 * @param hpack HPACK context
 * @param new_size New size
 */
void hpack_resize_dynamic_table(struct hpack_context *hpack, size_t new_size);

/**
 * Encode a header
 * @param hpack HPACK context
 * @param name Header name
 * @param value Header value
 * @param buf Output buffer
 * @param buf_size Output buffer size
 * @return Number of bytes written, or -1 on error
 */
int hpack_encode_header(struct hpack_context *hpack, const char *name, const char *value, uint8_t *buf, int buf_size);

/**
 * Decode headers
 * @param hpack HPACK context
 * @param data Input data
 * @param data_len Input data length
 * @param on_header Callback function for each decoded header
 * @param ctx User context passed to callback
 * @return 0 on success, -1 on error
 */
int hpack_decode_headers(struct hpack_context *hpack, const uint8_t *data, int data_len, hpack_on_header_fn on_header,
						 void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _HPACK_H_ */
