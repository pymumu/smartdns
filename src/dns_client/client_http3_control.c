/* HTTP/3 control and static-only QPACK streams (RFC 9114 / RFC 9204). */
#include "client_http3_control.h"
#include "conn_stream.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(OSSL_QUIC1_VERSION) && !defined(OPENSSL_NO_QUIC)
#define H3_SLOTS 8
#define H3_BUFFER 8192
struct h3_peer_stream {
    SSL *ssl;
    unsigned char data[H3_BUFFER];
    size_t used;
    uint64_t type, skip;
    int typed, settings;
};
struct dns_http3_control {
    SSL *local;
    size_t sent;
    struct h3_peer_stream peer[H3_SLOTS];
    unsigned seen, transitions, rotate;
    int goaway, pending;
    uint64_t goaway_id, fatal;
};
static int h3_fail(struct dns_http3_control *c, uint64_t code)
{
    if (!c->fatal) c->fatal = code;
    return -1;
}
/* 0 incomplete, otherwise bytes consumed. QUIC varints need not be minimal. */
static int h3_varint(const unsigned char *p, size_t n, uint64_t *v)
{
    if (!n) return 0;
    unsigned int bytes = 1U << (p[0] >> 6);
    if (n < bytes) return 0;
    *v = p[0] & 63;
    for (unsigned int i = 1; i < bytes; i++) *v = (*v << 8) | p[i];
    return bytes;
}
static void h3_consume(struct h3_peer_stream *p, size_t n)
{
    p->used -= n;
    if (p->used) memmove(p->data, p->data + n, p->used);
}
static int h3_id_compare(const void *a, const void *b)
{
    uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;
    return left < right ? -1 : left > right;
}
static int h3_settings(const unsigned char *p, size_t n)
{
    uint64_t ids[2048];
    size_t count = 0, offset = 0;
    while (offset < n) {
        uint64_t id, value;
        int a = h3_varint(p + offset, n - offset, &id);
        if (!a) return -1;
        offset += a;
        int b = h3_varint(p + offset, n - offset, &value);
        if (!b || count == 2048) return -1;
        offset += b;
        ids[count++] = id;
        if (id >= 2 && id <= 5) return -1; /* prohibited HTTP/2 settings */
        if ((id == 8 || id == 0x33) && value > 1) return -1;
        /* Peer QPACK capacity limits our encoder, which always uses zero. */
    }
    qsort(ids, count, sizeof(ids[0]), h3_id_compare);
    for (size_t i = 1; i < count; i++) if (ids[i] == ids[i - 1]) return -1;
    return 0;
}
static int h3_parse(struct dns_http3_control *c, struct h3_peer_stream *p)
{
    if (!p->typed) {
        int n = h3_varint(p->data, p->used, &p->type);
        if (!n) return 0;
        p->typed = 1; h3_consume(p, n);
        if (p->type == 1) return h3_fail(c, 0x108); /* no MAX_PUSH_ID has been sent */
        if (p->type != 0 && p->type != 2 && p->type != 3) return 1;
        unsigned int bit = 1U << p->type;
        if (c->seen & bit) return h3_fail(c, 0x103);
        c->seen |= bit;
    }
    if (p->type == 2) {
        /* RFC 9204 section 3.2.3: capacity zero forbids every encoder instruction. */
        return p->used ? h3_fail(c, 0x201) : 0;
    }
    if (p->type == 3) {
        while (p->used) {
            if (c->transitions >= 64) return 0;
            if ((p->data[0] & 0xc0) != 0x40) return h3_fail(c, 0x202); /* only Stream Cancellation is legal */
            uint64_t id = p->data[0] & 0x3f;
            size_t n = 1;
            if (id == 0x3f) {
                unsigned int shift = 0;
                for (;;) {
                    if (n == p->used) return 0;
                    unsigned int byte = p->data[n++];
                    if (shift >= 63 || (uint64_t)(byte & 127) > (UINT64_MAX - id) >> shift) return h3_fail(c, 0x202);
                    id += (uint64_t)(byte & 127) << shift;
                    if (!(byte & 128)) break;
                    shift += 7;
                }
            }
            if ((id & 3) || id > (UINT64_C(1) << 62) - 1) return h3_fail(c, 0x202);
            h3_consume(p, n);
            c->transitions++;
        }
        return 0;
    }
    for (;;) {
        if (c->transitions >= 64) return 0;
        if (p->skip) {
            size_t n = p->skip < p->used ? (size_t)p->skip : p->used;
            p->skip -= n; h3_consume(p, n);
            if (p->skip) return 0;
        }
        uint64_t type, len;
        int a = h3_varint(p->data, p->used, &type);
        if (!a) return 0;
        int b = h3_varint(p->data + a, p->used - a, &len);
        if (!b) return 0;
        size_t header = a + b;
        if (!p->settings && type != 4) return h3_fail(c, 0x10a);
        if (type == 4) {
            if (p->settings) return h3_fail(c, 0x105);
            if (len > 4096) return h3_fail(c, 0x107);
            if (len > p->used - header) return 0;
            if (h3_settings(p->data + header, len)) return h3_fail(c, 0x109);
            p->settings = 1;
        } else if (type == 7) {
            uint64_t id;
            if (len > 8) return h3_fail(c, 0x106);
            if (len > p->used - header) return 0;
            int bytes = h3_varint(p->data + header, len, &id);
            if (!bytes || (uint64_t)bytes != len) return h3_fail(c, 0x106);
            if ((id & 3) || (c->goaway && id > c->goaway_id)) return h3_fail(c, 0x108);
            c->goaway = 1; c->goaway_id = id;
        } else {
            if (type == 0 || type == 1 || type == 3 || type == 5 || type == 13 || type == 2 || type == 6 || type == 8 || type == 9) return h3_fail(c, 0x105);
            h3_consume(p, header); p->skip = len; c->transitions++; continue;
        }
        h3_consume(p, header + (size_t)len);
        c->transitions++;
    }
}

static int h3_poll(struct dns_server_info *s)
{
    if (!s->ssl || s->status != DNS_SERVER_STATUS_CONNECTED) return 1;
    if (!s->http3_control) s->http3_control = calloc(1, sizeof(*s->http3_control));
    struct dns_http3_control *c = s->http3_control;
    if (!c || c->fatal) return -1;
    c->transitions = 0; c->pending = 0;
    if (!c->local) {
        c->local = SSL_new_stream(s->ssl, SSL_STREAM_FLAG_UNI);
        if (!c->local) return 1;
    }
    if (SSL_get_stream_write_state(c->local) != SSL_STREAM_STATE_OK) return h3_fail(c, 0x104);
    static const unsigned char settings[] = {0, 4, 4, 1, 0, 7, 0};
    if (c->sent < sizeof(settings)) {
        size_t sent = 0;
        int ok = SSL_write_ex(c->local, settings + c->sent, sizeof(settings) - c->sent, &sent);
        if (!ok) {
            int error = SSL_get_error(c->local, ok);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return h3_fail(c, 0x104);
        }
        c->sent += sent;
    }
    for (unsigned accepted = 0; accepted < H3_SLOTS; accepted++) {
        unsigned slot;
        for (slot = 0; slot < H3_SLOTS && c->peer[slot].ssl; slot++) {}
        if (slot == H3_SLOTS) {
            if (SSL_get_accept_stream_queue_len(s->ssl)) return h3_fail(c, 0x107);
            break;
        }
        SSL *peer = SSL_accept_stream(s->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
        if (!peer) break;
        if ((SSL_get_stream_id(peer) & 3) != 3) { SSL_free(peer); return h3_fail(c, 0x103); }
        c->peer[slot].ssl = peer;
    }
    size_t bytes = 0;
    for (unsigned i = 0; i < H3_SLOTS && bytes < 16384 && c->transitions < 64; i++) {
        struct h3_peer_stream *p = &c->peer[(i + c->rotate) % H3_SLOTS];
        if (!p->ssl) continue;
        int parsed = h3_parse(c, p);
        if (parsed < 0) return -1;
        if (parsed > 0) { SSL_free(p->ssl); memset(p, 0, sizeof(*p)); continue; }
        if (c->transitions >= 64) break;
        size_t room = sizeof(p->data) - p->used, got = 0;
        if (!room) return h3_fail(c, 0x107);
        if (room > 16384 - bytes) room = 16384 - bytes;
        int ok = SSL_read_ex(p->ssl, p->data + p->used, room, &got);
        if (!ok) {
            int error = SSL_get_error(p->ssl, ok);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) return h3_fail(c, 0x104);
        }
        p->used += got; bytes += got;
        parsed = h3_parse(c, p);
        if (parsed < 0) return -1;
        if (parsed > 0) { SSL_free(p->ssl); memset(p, 0, sizeof(*p)); }
    }
    if (c->transitions >= 64) {
        for (unsigned i = 0; i < H3_SLOTS; i++) if (c->peer[i].used) c->pending = 1;
    }
    c->rotate = (c->rotate + 1) % H3_SLOTS;
    return c->sent == sizeof(settings) ? 0 : 1;
}
int _dns_http3_control_poll(struct dns_server_info *s)
{
    pthread_mutex_lock(&s->lock);
    int result = h3_poll(s);
    pthread_mutex_unlock(&s->lock);
    return result;
}
int _dns_http3_request_allowed(struct dns_server_info *s, SSL *stream)
{
    struct dns_http3_control *c = s->http3_control;
    return c && c->sent == 7 && !c->fatal &&
        (!c->goaway || (stream && SSL_get_stream_id(stream) < c->goaway_id));
}
/* Caller holds the endpoint mutex. A drained GOAWAY connection must retire so
 * pending queries can reconnect through the existing retry path. */
int _dns_http3_drain_complete(struct dns_server_info *s)
{
    struct dns_http3_control *c = s->http3_control;
    if (!c || !c->goaway || c->fatal) return 0;
    struct dns_conn_stream *stream;
    list_for_each_entry(stream, &s->conn_stream_list, server_list) {
        if (stream->query && stream->quic_stream && SSL_get_stream_id(stream->quic_stream) < c->goaway_id)
            return 0;
    }
    return 1;
}
int _dns_http3_connection_error(struct dns_server_info *s, uint64_t code)
{
    pthread_mutex_lock(&s->lock);
    if (!s->http3_control) s->http3_control = calloc(1, sizeof(*s->http3_control));
    int result = s->http3_control ? h3_fail(s->http3_control, code) : -1;
    pthread_mutex_unlock(&s->lock);
    return result;
}
int _dns_http3_control_pending(struct dns_server_info *s)
{
    struct dns_http3_control *c = s->http3_control;
    SSL_POLL_ITEM items[H3_SLOTS + 1] = {0};
    size_t count = 0, ready = 0;
    const struct timeval zero = {0};
    if (!c || !c->local) {
        items[count++] = (SSL_POLL_ITEM){.desc = SSL_as_poll_descriptor(s->ssl), .events = SSL_POLL_EVENT_OSU};
    } else {
        if (c->fatal || c->pending) return 1;
        items[count++] = (SSL_POLL_ITEM){.desc = SSL_as_poll_descriptor(c->local),
            .events = SSL_POLL_EVENT_EW | (c->sent < 7 ? SSL_POLL_EVENT_W : 0)};
        for (unsigned i = 0; i < H3_SLOTS; i++) if (c->peer[i].ssl) {
            items[count++] = (SSL_POLL_ITEM){.desc = SSL_as_poll_descriptor(c->peer[i].ssl),
                .events = SSL_POLL_EVENT_R | SSL_POLL_EVENT_ER};
        }
    }
    return SSL_poll(items, count, sizeof(items[0]), &zero, SSL_POLL_FLAG_NO_HANDLE_EVENTS, &ready) == 1 && ready;
}
int _dns_http3_control_shutdown(struct dns_server_info *s)
{
    pthread_mutex_lock(&s->lock);
    if (!s->http3_control || !s->http3_control->fatal || !s->ssl) {
        pthread_mutex_unlock(&s->lock);
        return 0;
    }
    SSL_SHUTDOWN_EX_ARGS args = {0};
    args.quic_error_code = s->http3_control->fatal;
    args.quic_reason = "HTTP/3 protocol error";
    SSL_shutdown_ex(s->ssl, SSL_SHUTDOWN_FLAG_NO_BLOCK | SSL_SHUTDOWN_FLAG_NO_STREAM_FLUSH, &args, sizeof(args));
    pthread_mutex_unlock(&s->lock);
    return 1;
}
void _dns_http3_control_free(struct dns_server_info *s)
{
    struct dns_http3_control *c = s->http3_control;
    if (!c) return;
    for (unsigned i = 0; i < H3_SLOTS; i++) SSL_free(c->peer[i].ssl);
    SSL_free(c->local); free(c); s->http3_control = NULL;
}
#ifdef TEST
size_t _dns_http3_control_test_pending_bytes(struct dns_server_info *s)
{
    size_t bytes = 0;
    if (s->http3_control)
        for (unsigned i = 0; i < H3_SLOTS; i++) bytes += s->http3_control->peer[i].used;
    return bytes;
}
int _dns_http3_control_test_feed(struct dns_server_info *s, unsigned slot, const unsigned char *data, size_t len)
{
    if (slot >= H3_SLOTS) return -1;
    if (!s->http3_control) s->http3_control = calloc(1, sizeof(*s->http3_control));
    struct dns_http3_control *c = s->http3_control;
    if (!c || c->fatal) return -1;
    struct h3_peer_stream *p = &c->peer[slot];
    c->sent = 7; c->transitions = 0;
    if (len > sizeof(p->data) - p->used) return -1;
    if (len) memcpy(p->data + p->used, data, len);
    p->used += len;
    return h3_parse(c, p);
}
#endif
#else
int _dns_http3_control_poll(struct dns_server_info *s) { (void)s; return -1; }
int _dns_http3_control_pending(struct dns_server_info *s) { (void)s; return 0; }
int _dns_http3_drain_complete(struct dns_server_info *s) { (void)s; return 0; }
int _dns_http3_request_allowed(struct dns_server_info *s, SSL *stream) { (void)s; (void)stream; return 0; }
int _dns_http3_connection_error(struct dns_server_info *s, uint64_t code) { (void)s; (void)code; return -1; }
int _dns_http3_control_shutdown(struct dns_server_info *s) { (void)s; return 0; }
void _dns_http3_control_free(struct dns_server_info *s) { (void)s; }
#endif
