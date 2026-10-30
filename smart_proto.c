/*
 * smart_proto.c - shared protocol library: CRC-32, framing, packed-binary and
 * SON codecs, small socket helpers.  No dynamic allocation.
 *
 * The codecs are table driven: each message type is described once as a list
 * of fields (JSON key, wire type, offset in the C struct).  The same table
 * drives binary encode/decode and JSON encode/decode, so the two encodings can
 * never drift apart.
 */
#define _POSIX_C_SOURCE 200809L
#include "iot_proto.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0          /* e.g. macOS; the programs also ignore SIGPIPE */
#endif

/* Time */
uint64_t now_real_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t now_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320) */
static uint32_t g_crc_table[256];
static int      g_crc_ready;

uint32_t proto_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    if (!g_crc_ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            g_crc_table[i] = c;
        }
        g_crc_ready = 1;
    }
    while (len--)
        crc = g_crc_table[(crc ^ *data++) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* Big-endian writer / reader with sticky error flag */
typedef struct { uint8_t *p; size_t cap, len; int err; } wr_t;
typedef struct { const uint8_t *p; size_t len, pos; int err; } rd_t;

static void w_bytes(wr_t *w, const void *src, size_t n) {
    if (w->err || w->cap - w->len < n) { w->err = 1; return; }
    if (n) memcpy(w->p + w->len, src, n);
    w->len += n;
}
static void w_u8(wr_t *w, uint8_t v) { w_bytes(w, &v, 1); }
static void w_u16(wr_t *w, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    w_bytes(w, b, 2);
}
static void w_u32(wr_t *w, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    w_bytes(w, b, 4);
}
static void w_u64(wr_t *w, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8 * i));
    w_bytes(w, b, 8);
}

static void r_bytes(rd_t *r, void *dst, size_t n) {
    if (r->err || r->len - r->pos < n) { r->err = 1; memset(dst, 0, n); return; }
    memcpy(dst, r->p + r->pos, n);
    r->pos += n;
}
static uint8_t r_u8(rd_t *r) { uint8_t v; r_bytes(r, &v, 1); return v; }
static uint16_t r_u16(rd_t *r) {
    uint8_t b[2];
    r_bytes(r, b, 2);
    return (uint16_t)((b[0] << 8) | b[1]);
}
static uint32_t r_u32(rd_t *r) {
    uint8_t b[4];
    r_bytes(r, b, 4);
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static uint64_t r_u64(rd_t *r) {
    uint8_t b[8];
    uint64_t v = 0;
    r_bytes(r, b, 8);
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

/* Frames */
size_t frame_build(uint8_t *out, size_t cap, uint8_t type, uint8_t enc,
                   uint32_t seq, const uint8_t *payload, size_t plen) {
    wr_t w = { out, cap, 0, 0 };

    if (plen > PROTO_MAX_PAYLOAD) return 0;
    w_u8(&w, PROTO_MAGIC_0);
    w_u8(&w, PROTO_MAGIC_1);
    w_u8(&w, PROTO_VERSION);
    w_u8(&w, type);
    w_u8(&w, enc);
    w_u8(&w, 0);                         /* flags */
    w_u32(&w, seq);
    w_u16(&w, (uint16_t)plen);
    w_bytes(&w, payload, plen);
    if (w.err) return 0;
    w_u32(&w, proto_crc32(out, w.len));
    return w.err ? 0 : w.len;
}

frame_status_t frame_parse(const uint8_t *buf, size_t len, frame_t *f, size_t *frame_len) {
    rd_t r = { buf, len, 3, 0 };
    uint8_t type, enc, flags;
    uint32_t seq, want;
    uint16_t plen;
    size_t total;

    /* Reject as early as possible so a garbage prefix never makes us wait. */
    if (len >= 1 && buf[0] != PROTO_MAGIC_0) return FRAME_BAD_MAGIC;
    if (len >= 2 && buf[1] != PROTO_MAGIC_1) return FRAME_BAD_MAGIC;
    if (len >= 3 && buf[2] != PROTO_VERSION) return FRAME_BAD_VERSION;
    if (len < PROTO_HEADER_LEN)              return FRAME_INCOMPLETE;

    type  = r_u8(&r);
    enc   = r_u8(&r);
    flags = r_u8(&r);
    seq   = r_u32(&r);
    plen  = r_u16(&r);
    if (plen > PROTO_MAX_PAYLOAD) return FRAME_TOO_LARGE;

    total = PROTO_HEADER_LEN + (size_t)plen + PROTO_CRC_LEN;
    if (len < total) return FRAME_INCOMPLETE;
    if (frame_len) *frame_len = total;

    want = ((uint32_t)buf[total - 4] << 24) | ((uint32_t)buf[total - 3] << 16) |
           ((uint32_t)buf[total - 2] << 8)  |  (uint32_t)buf[total - 1];
    if (want != proto_crc32(buf, total - PROTO_CRC_LEN)) return FRAME_BAD_CRC;
    if (enc != ENC_BINARY && enc != ENC_JSON)            return FRAME_BAD_ENCODING;

    if (f) {
        f->type = type;
        f->encoding = enc;
        f->flags = flags;
        f->seq = seq;
        f->payload_len = plen;
        f->payload = buf + PROTO_HEADER_LEN;
    }
    return FRAME_OK;
}

size_t frame_resync(const uint8_t *buf, size_t len) {
    /* Look for the next 0xA5 0x5A after position 0.  A trailing lone 0xA5 is
     * kept because its partner byte may simply not have arrived yet. */
    for (size_t i = 1; i < len; i++)
        if (buf[i] == PROTO_MAGIC_0 && (i + 1 == len || buf[i + 1] == PROTO_MAGIC_1))
            return i;
    return len;
}

/* Minimal flat-JSON reader: one object, string / number / literal values */
#define JSON_MAX_PAIRS 16
#define JSON_KEY_LEN   24
#define JSON_VAL_LEN   40

typedef struct { char key[JSON_KEY_LEN]; char val[JSON_VAL_LEN]; int is_str; } json_kv_t;
typedef struct { json_kv_t kv[JSON_MAX_PAIRS]; int n; } json_obj_t;

static void js_skip_ws(const char *s, size_t n, size_t *i) {
    while (*i < n && (s[*i] == ' ' || s[*i] == '\t' || s[*i] == '\r' || s[*i] == '\n'))
        (*i)++;
}

static int js_is_delim(char c) {
    return c == ',' || c == '}' || c == ']' || c == '[' || c == '{' || c == ':' ||
           c == '"' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\0';
}

/* Parse a JSON string starting at s[*i]=='"' into dst (NUL terminated). */
static int js_string(const char *s, size_t n, size_t *i, char *dst, size_t cap) {
    size_t o = 0;

    if (*i >= n || s[*i] != '"') return -1;
    (*i)++;
    while (*i < n) {
        unsigned char c = (unsigned char)s[(*i)++];
        if (c == '"') { dst[o] = '\0'; return 0; }
        if (c < 0x20) return -1;                      /* raw control character */
        if (c == '\\') {
            if (*i >= n) return -1;
            c = (unsigned char)s[(*i)++];
            switch (c) {
            case '"': case '\\': case '/': break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u': {
                unsigned v = 0;
                if (n - *i < 4) return -1;
                for (int k = 0; k < 4; k++) {
                    char h = s[(*i)++];
                    v <<= 4;
                    if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
                    else return -1;
                }
                if (v == 0) return -1;
                c = v < 0x80 ? (unsigned char)v : '?';   /* we only need ASCII */
                break;
            }
            default: return -1;
            }
        }
        if (o + 1 >= cap) return -1;                  /* longer than our buffers */
        dst[o++] = (char)c;
    }
    return -1;                                        /* unterminated string */
}

/* Parse '{ "k": v, ... }' (no nesting). Returns 0 on success, -1 if malformed. */
static int js_parse(const char *s, size_t n, json_obj_t *o) {
    size_t i = 0;

    o->n = 0;
    js_skip_ws(s, n, &i);
    if (i >= n || s[i] != '{') return -1;
    i++;
    js_skip_ws(s, n, &i);
    if (i < n && s[i] == '}') {
        i++;
    } else {
        for (;;) {
            json_kv_t *kv;
            if (o->n >= JSON_MAX_PAIRS) return -1;
            kv = &o->kv[o->n];
            js_skip_ws(s, n, &i);
            if (js_string(s, n, &i, kv->key, sizeof kv->key) < 0) return -1;
            js_skip_ws(s, n, &i);
            if (i >= n || s[i] != ':') return -1;
            i++;
            js_skip_ws(s, n, &i);
            if (i < n && s[i] == '"') {
                kv->is_str = 1;
                if (js_string(s, n, &i, kv->val, sizeof kv->val) < 0) return -1;
            } else {
                size_t st = i, len;
                while (i < n && !js_is_delim(s[i])) i++;
                len = i - st;
                if (len == 0 || len >= sizeof kv->val) return -1;
                memcpy(kv->val, s + st, len);
                kv->val[len] = '\0';
                kv->is_str = 0;
            }
            o->n++;
            js_skip_ws(s, n, &i);
            if (i >= n) return -1;
            if (s[i] == ',') { i++; continue; }
            if (s[i] == '}') { i++; break; }
            return -1;
        }
    }
    js_skip_ws(s, n, &i);
    return i == n ? 0 : -1;                           /* trailing junk = malformed */
}

static const json_kv_t *js_find(const json_obj_t *o, const char *key) {
    for (int i = 0; i < o->n; i++)
        if (strcmp(o->kv[i].key, key) == 0) return &o->kv[i];
    return NULL;
}

static int js_to_u64(const json_kv_t *kv, uint64_t max, uint64_t *out) {
    char *end;
    unsigned long long v;

    if (kv->is_str || !isdigit((unsigned char)kv->val[0])) return -1;   /* no sign, no strings */
    errno = 0;
    v = strtoull(kv->val, &end, 10);
    if (errno != 0 || *end != '\0' || v > max) return -1;
    *out = v;
    return 0;
}

/* Decimal number -> value in 1/100 units, rounded half away from zero. */
static int js_to_fx2(const json_kv_t *kv, int32_t lo, int32_t hi, int32_t *out) {
    char *end;
    double d;

    if (kv->is_str) return -1;
    for (const char *p = kv->val; *p; p++)
        if (!strchr("0123456789+-.eE", *p)) return -1;   /* no hex, inf, nan */
    d = strtod(kv->val, &end);
    if (end == kv->val || *end != '\0') return -1;
    d = d * 100.0;
    d += d < 0 ? -0.5 : 0.5;
    if (!(d >= (double)lo && d <= (double)hi)) return -1; /* also rejects inf/ERANGE */
    *out = (int32_t)d;
    return 0;
}

/* Field tables */
typedef enum { FT_U8, FT_U16, FT_U32, FT_U64, FT_FX2_I16, FT_FX2_U16, FT_CMD } ftype_t;
typedef struct { const char *name; ftype_t type; size_t off; } field_t;
typedef struct { const field_t *f; size_t n; size_t size; } msg_desc_t;

#define FIELD(nm, ty, st, mem) { nm, ty, offsetof(st, mem) }
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const field_t hello_fields[] = {
    FIELD("device_id",   FT_U32, hello_msg_t, device_id),
    FIELD("fw",          FT_U16, hello_msg_t, fw_version),
    FIELD("interval_ms", FT_U32, hello_msg_t, interval_ms),
};
static const field_t hello_ack_fields[] = {
    FIELD("heartbeat_ms", FT_U32, hello_ack_msg_t, heartbeat_ms),
};
static const field_t telemetry_fields[] = {
    FIELD("device_id",   FT_U32,      telemetry_msg_t, device_id),
    FIELD("ts",          FT_U64,      telemetry_msg_t, timestamp_ms),
    FIELD("temp",        FT_FX2_I16,  telemetry_msg_t, temperature_c100),
    FIELD("hum",         FT_FX2_U16,  telemetry_msg_t, humidity_pct100),
    FIELD("batt",        FT_U8,       telemetry_msg_t, battery_pct),
    FIELD("alert",       FT_U8,       telemetry_msg_t, alert_level),
    FIELD("status",      FT_U16,      telemetry_msg_t, status_flags),
    FIELD("interval_ms", FT_U32,      telemetry_msg_t, interval_ms),
};
static const field_t command_fields[] = {
    FIELD("id",  FT_U32, command_msg_t, cmd_id),
    FIELD("cmd", FT_CMD, command_msg_t, cmd),
    FIELD("arg", FT_U32, command_msg_t, arg),
};
static const field_t cmd_ack_fields[] = {
    FIELD("device_id", FT_U32, cmd_ack_msg_t, device_id),
    FIELD("id",        FT_U32, cmd_ack_msg_t, cmd_id),
    FIELD("cmd",       FT_CMD, cmd_ack_msg_t, cmd),
    FIELD("status",    FT_U8,  cmd_ack_msg_t, status),
};
static const field_t error_fields[] = {
    FIELD("code", FT_U8, error_msg_t, code),
};

static const msg_desc_t *desc_for(uint8_t type) {
    static const msg_desc_t d_hello     = { hello_fields,     COUNT(hello_fields),     sizeof(hello_msg_t) };
    static const msg_desc_t d_hello_ack = { hello_ack_fields, COUNT(hello_ack_fields), sizeof(hello_ack_msg_t) };
    static const msg_desc_t d_telemetry = { telemetry_fields, COUNT(telemetry_fields), sizeof(telemetry_msg_t) };
    static const msg_desc_t d_command   = { command_fields,   COUNT(command_fields),   sizeof(command_msg_t) };
    static const msg_desc_t d_cmd_ack   = { cmd_ack_fields,   COUNT(cmd_ack_fields),   sizeof(cmd_ack_msg_t) };
    static const msg_desc_t d_error     = { error_fields,     COUNT(error_fields),     sizeof(error_msg_t) };
    static const msg_desc_t d_heartbeat = { NULL, 0, 0 };

    switch (type) {
    case MSG_HELLO:       return &d_hello;
    case MSG_HELLO_ACK:   return &d_hello_ack;
    case MSG_TELEMETRY:   return &d_telemetry;
    case MSG_COMMAND:     return &d_command;
    case MSG_COMMAND_ACK: return &d_cmd_ack;
    case MSG_HEARTBEAT:   return &d_heartbeat;
    case MSG_ERROR:       return &d_error;
    default:              return NULL;
    }
}

/* Binary ("struct") codec */
static int bin_encode(const msg_desc_t *d, const void *msg, uint8_t *out, size_t cap) {
    wr_t w = { out, cap, 0, 0 };
    const uint8_t *base = msg;

    for (size_t i = 0; i < d->n; i++) {
        const field_t *f = &d->f[i];
        switch (f->type) {
        case FT_U8: case FT_CMD:
            { uint8_t v;  memcpy(&v, base + f->off, sizeof v); w_u8(&w, v); break; }
        case FT_U16: case FT_FX2_U16:
            { uint16_t v; memcpy(&v, base + f->off, sizeof v); w_u16(&w, v); break; }
        case FT_FX2_I16:
            { int16_t v;  memcpy(&v, base + f->off, sizeof v); w_u16(&w, (uint16_t)v); break; }
        case FT_U32:
            { uint32_t v; memcpy(&v, base + f->off, sizeof v); w_u32(&w, v); break; }
        case FT_U64:
            { uint64_t v; memcpy(&v, base + f->off, sizeof v); w_u64(&w, v); break; }
        }
    }
    return w.err ? -1 : (int)w.len;
}

static int bin_decode(const msg_desc_t *d, const uint8_t *in, size_t len, void *msg) {
    rd_t r = { in, len, 0, 0 };
    uint8_t *base = msg;

    if (d->size) memset(msg, 0, d->size);          /* heartbeat has no body (msg may be NULL) */
    for (size_t i = 0; i < d->n; i++) {
        const field_t *f = &d->f[i];
        switch (f->type) {
        case FT_U8: case FT_CMD:
            { uint8_t v = r_u8(&r);   memcpy(base + f->off, &v, sizeof v); break; }
        case FT_U16: case FT_FX2_U16:
            { uint16_t v = r_u16(&r); memcpy(base + f->off, &v, sizeof v); break; }
        case FT_FX2_I16:
            { int16_t v = (int16_t)r_u16(&r); memcpy(base + f->off, &v, sizeof v); break; }
        case FT_U32:
            { uint32_t v = r_u32(&r); memcpy(base + f->off, &v, sizeof v); break; }
        case FT_U64:
            { uint64_t v = r_u64(&r); memcpy(base + f->off, &v, sizeof v); break; }
        }
    }
    return (r.err || r.pos != len) ? -1 : 0;     /* truncated OR trailing bytes = malformed */
}

/* JSON codec */
void proto_fmt_fx2(char *dst, size_t cap, int32_t v) {
    int64_t a = v < 0 ? -(int64_t)v : (int64_t)v;
    snprintf(dst, cap, "%s%" PRId64 ".%02" PRId64, v < 0 ? "-" : "", a / 100, a % 100);
}

static int json_encode(const msg_desc_t *d, const void *msg, uint8_t *out, size_t cap) {
    char *p = (char *)out;
    size_t n = 0;
    const uint8_t *base = msg;

#define APPEND(...)                                                          \
    do {                                                                     \
        int r_ = snprintf(p + n, cap - n, __VA_ARGS__);                      \
        if (r_ < 0 || (size_t)r_ >= cap - n) return -1;                      \
        n += (size_t)r_;                                                     \
    } while (0)

    APPEND("{");
    for (size_t i = 0; i < d->n; i++) {
        const field_t *f = &d->f[i];
        char tmp[24];
        if (i) APPEND(",");
        switch (f->type) {
        case FT_U8:
            { uint8_t v;  memcpy(&v, base + f->off, sizeof v); APPEND("\"%s\":%u", f->name, (unsigned)v); break; }
        case FT_U16:
            { uint16_t v; memcpy(&v, base + f->off, sizeof v); APPEND("\"%s\":%u", f->name, (unsigned)v); break; }
        case FT_U32:
            { uint32_t v; memcpy(&v, base + f->off, sizeof v); APPEND("\"%s\":%" PRIu32, f->name, v); break; }
        case FT_U64:
            { uint64_t v; memcpy(&v, base + f->off, sizeof v); APPEND("\"%s\":%" PRIu64, f->name, v); break; }
        case FT_FX2_I16:
            { int16_t v;  memcpy(&v, base + f->off, sizeof v); proto_fmt_fx2(tmp, sizeof tmp, v);
              APPEND("\"%s\":%s", f->name, tmp); break; }
        case FT_FX2_U16:
            { uint16_t v; memcpy(&v, base + f->off, sizeof v); proto_fmt_fx2(tmp, sizeof tmp, v);
              APPEND("\"%s\":%s", f->name, tmp); break; }
        case FT_CMD:
            { uint8_t v;  memcpy(&v, base + f->off, sizeof v); APPEND("\"%s\":\"%s\"", f->name, cmd_name(v)); break; }
        }
    }
    APPEND("}");
#undef APPEND
    return (int)n;
}

static int json_decode(const msg_desc_t *d, const uint8_t *in, size_t len, void *msg) {
    json_obj_t o;
    uint8_t *base = msg;

    if (js_parse((const char *)in, len, &o) < 0) return -1;
    if (d->size) memset(msg, 0, d->size);          /* heartbeat has no body (msg may be NULL) */
    for (size_t i = 0; i < d->n; i++) {
        const field_t *f = &d->f[i];
        const json_kv_t *kv = js_find(&o, f->name);
        uint64_t u = 0;
        int32_t x = 0;

        if (!kv) return -1;                               /* mandatory field missing */
        switch (f->type) {
        case FT_U8:
            { uint8_t v;  if (js_to_u64(kv, UINT8_MAX, &u))  return -1; v = (uint8_t)u;  memcpy(base + f->off, &v, sizeof v); break; }
        case FT_U16:
            { uint16_t v; if (js_to_u64(kv, UINT16_MAX, &u)) return -1; v = (uint16_t)u; memcpy(base + f->off, &v, sizeof v); break; }
        case FT_U32:
            { uint32_t v; if (js_to_u64(kv, UINT32_MAX, &u)) return -1; v = (uint32_t)u; memcpy(base + f->off, &v, sizeof v); break; }
        case FT_U64:
            { uint64_t v; if (js_to_u64(kv, UINT64_MAX, &u)) return -1; v = u;           memcpy(base + f->off, &v, sizeof v); break; }
        case FT_FX2_I16:
            { int16_t v;  if (js_to_fx2(kv, INT16_MIN, INT16_MAX, &x)) return -1; v = (int16_t)x;  memcpy(base + f->off, &v, sizeof v); break; }
        case FT_FX2_U16:
            { uint16_t v; if (js_to_fx2(kv, 0, UINT16_MAX, &x)) return -1;        v = (uint16_t)x; memcpy(base + f->off, &v, sizeof v); break; }
        case FT_CMD:
            {
                int c;
                uint8_t v;
                if (kv->is_str)                                        c = cmd_from_name(kv->val);
                else if (js_to_u64(kv, CMD__COUNT - 1, &u) == 0)       c = (int)u;
                else                                                   c = -1;
                if (c < 0) return -1;
                v = (uint8_t)c;
                memcpy(base + f->off, &v, sizeof v);
                break;
            }
        }
    }
    return 0;
}

/* Message API */
int msg_encode(uint8_t type, uint8_t enc, const void *msg, uint8_t *out, size_t cap) {
    const msg_desc_t *d = desc_for(type);
    if (!d) return -1;
    if (enc == ENC_BINARY) return bin_encode(d, msg, out, cap);
    if (enc == ENC_JSON)   return json_encode(d, msg, out, cap);
    return -1;
}

int msg_decode(uint8_t type, uint8_t enc, const uint8_t *in, size_t len, void *msg) {
    const msg_desc_t *d = desc_for(type);
    if (!d) return -1;
    if (enc == ENC_BINARY) return bin_decode(d, in, len, msg);
    if (enc == ENC_JSON)   return json_decode(d, in, len, msg);
    return -1;
}

int proto_pack(uint8_t *out, size_t cap, uint8_t type, uint8_t enc, uint32_t seq, const void *msg) {
    uint8_t payload[PROTO_MAX_PAYLOAD];
    int n = msg_encode(type, enc, msg, payload, sizeof payload);
    size_t total;

    if (n < 0) return -1;
    total = frame_build(out, cap, type, enc, seq, payload, (size_t)n);
    return total ? (int)total : -1;
}

/* Names */
const char *msg_type_name(uint8_t t) {
    static const char *const n[] = { "?", "HELLO", "HELLO_ACK", "TELEMETRY",
                                     "COMMAND", "COMMAND_ACK", "HEARTBEAT", "ERROR" };
    return t < COUNT(n) ? n[t] : "?";
}

const char *cmd_name(uint8_t c) {
    static const char *const n[CMD__COUNT] = { "NONE", "SET_INTERVAL", "ALERT_TRIGGER",
                                               "ALERT_CLEAR", "REPORT_NOW", "SHUTDOWN" };
    return c < CMD__COUNT ? n[c] : "UNKNOWN";
}

int cmd_from_name(const char *s) {
    for (int i = 1; i < CMD__COUNT; i++)
        if (strcmp(s, cmd_name((uint8_t)i)) == 0) return i;
    return -1;
}

const char *ack_name(uint8_t s) {
    static const char *const n[] = { "OK", "BAD_ARG", "UNSUPPORTED" };
    return s < COUNT(n) ? n[s] : "?";
}

const char *err_name(uint8_t c) {
    static const char *const n[] = { "NONE", "BAD_FRAME", "BAD_CRC", "BAD_PAYLOAD",
                                     "UNKNOWN_TYPE", "BAD_VALUE", "BUSY" };
    return c < COUNT(n) ? n[c] : "?";
}

const char *frame_status_name(frame_status_t s) {
    static const char *const n[] = { "ok", "incomplete", "bad magic", "bad version",
                                     "payload too large", "bad CRC", "bad encoding" };
    return (unsigned)s < COUNT(n) ? n[s] : "?";
}

/* Socket helpers */
int net_set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void net_addr_str(const struct sockaddr_in *sa, char *dst, size_t cap) {
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof ip);
    snprintf(dst, cap, "%s:%u", ip, (unsigned)ntohs(sa->sin_port));
}

int outbuf_append(outbuf_t *q, const uint8_t *src, size_t n) {
    if (q->head == q->tail) q->head = q->tail = 0;
    if (q->tail + n > OUTBUF_CAP) {                       /* compact, then retry */
        size_t pending = q->tail - q->head;
        memmove(q->data, q->data + q->head, pending);
        q->head = 0;
        q->tail = pending;
        if (q->tail + n > OUTBUF_CAP) return -1;          /* peer is not draining */
    }
    memcpy(q->data + q->tail, src, n);
    q->tail += n;
    return 0;
}

int outbuf_flush(outbuf_t *q, int fd) {
    while (q->head < q->tail) {
        ssize_t r = send(fd, q->data + q->head, q->tail - q->head, MSG_NOSIGNAL);
        if (r > 0) { q->head += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;   /* try later */
        return -1;
    }
    q->head = q->tail = 0;
    return 0;
}