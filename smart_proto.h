/*
 * smart_proto.h is a shared wire protocol and helpers for the Smart Environmental &
 * Asset Monitoring System (sensor node <-> monitoring gateway).
 *
 * FRAME LAYOUT (all multi-byte integers are big-endian / network order)
 *
 *   offset  size  field
 *   ------  ----  --------------------------------------------------------------
 *      0     2     magic        0xA5 0x5A
 *      2     1     version      1
 *      3     1     type         MSG_*
 *      4     1     encoding     ENC_BINARY (packed "struct" layout) or ENC_JSON
 *      5     1     flags        reserved, 0
 *      6     4     seq          sender's counter (telemetry: consecutive per channel)
 *     10     2     payload_len  0 .. PROTO_MAX_PAYLOAD
 *     12     N     payload      the message, encoded as selected by 'encoding'
 *   12+N     4     crc32        IEEE CRC-32 over bytes [0, 12+N)
 *
 * TCP is a byte stream. The receivers re-assemble frames using payload_len and
 * re-synchronise on the magic bytes after corruption.  UDP carries exactly one
 * frame per datagram.
 */
#ifndef IOT_PROTO_H
#define IOT_PROTO_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Constants */
#define PROTO_MAGIC_0      0xA5
#define PROTO_MAGIC_1      0x5A
#define PROTO_VERSION      1
#define PROTO_HEADER_LEN   12
#define PROTO_CRC_LEN      4
#define PROTO_MAX_PAYLOAD  512
#define PROTO_MAX_FRAME    (PROTO_HEADER_LEN + PROTO_MAX_PAYLOAD + PROTO_CRC_LEN)

#define MIN_INTERVAL_MS    100u        /* fastest reporting period a device accepts */
#define MAX_INTERVAL_MS    3600000u    /* slowest (1 hour)                          */

enum { ENC_BINARY = 0, ENC_JSON = 1 };

enum msg_type {
    MSG_HELLO = 1,      /* device  -> gateway : registration                       */
    MSG_HELLO_ACK,      /* gateway -> device  : registration accepted              */
    MSG_TELEMETRY,      /* device  -> gateway : sensor reading                     */
    MSG_COMMAND,        /* gateway -> device  : control signal                     */
    MSG_COMMAND_ACK,    /* device  -> gateway : result of a command                */
    MSG_HEARTBEAT,      /* device  -> gateway : TCP keep-alive (empty payload)     */
    MSG_ERROR           /* either direction   : "I could not process your frame"   */
};

enum cmd_code {
    CMD_NONE = 0,
    CMD_SET_INTERVAL,   /* arg = new reporting interval in ms                      */
    CMD_ALERT_TRIGGER,  /* arg = alarm level: 1 warning, 2 critical                */
    CMD_ALERT_CLEAR,    /* switch the local alarm off                              */
    CMD_REPORT_NOW,     /* send a reading immediately                              */
    CMD_SHUTDOWN,       /* close down gracefully                                   */
    CMD__COUNT
};

enum ack_status { ACK_OK = 0, ACK_BAD_ARG, ACK_UNSUPPORTED };

enum err_code {
    ERR_NONE = 0,
    ERR_BAD_FRAME,      /* magic / version / length / encoding problem */
    ERR_BAD_CRC,
    ERR_BAD_PAYLOAD,    /* frame fine, payload could not be decoded    */
    ERR_UNKNOWN_TYPE,
    ERR_BAD_VALUE,      /* decoded fine but value out of physical range */
    ERR_BUSY            /* gateway cannot take more devices             */
};

#define ST_LOW_BATTERY  0x0001u   /* telemetry status_flags bits */
#define ST_ALARM_ACTIVE 0x0004u

/* Messages (in-memory form; the wire form is produced by msg_encode) */
typedef struct {
    uint32_t device_id;
    uint16_t fw_version;          /* major<<8 | minor                          */
    uint32_t interval_ms;         /* the device's configured (base) period     */
} hello_msg_t;

typedef struct {
    uint32_t heartbeat_ms;        /* how often the gateway wants TCP heartbeats */
} hello_ack_msg_t;

typedef struct {
    uint32_t device_id;
    uint64_t timestamp_ms;        /* device clock, ms since the Unix epoch      */
    int16_t  temperature_c100;    /* 1/100 degC  (2453 -> 24.53 C)              */
    uint16_t humidity_pct100;     /* 1/100 %RH   (5520 -> 55.20 %)              */
    uint8_t  battery_pct;         /* 0..100                                     */
    uint8_t  alert_level;         /* local alarm now active: 0 none, 1, 2       */
    uint16_t status_flags;        /* ST_* bits                                  */
    uint32_t interval_ms;         /* current reporting period                   */
} telemetry_msg_t;

typedef struct {
    uint32_t cmd_id;
    uint8_t  cmd;                 /* enum cmd_code                              */
    uint32_t arg;
} command_msg_t;

typedef struct {
    uint32_t device_id;
    uint32_t cmd_id;
    uint8_t  cmd;
    uint8_t  status;              /* enum ack_status                            */
} cmd_ack_msg_t;

typedef struct {
    uint8_t code;                 /* enum err_code                              */
} error_msg_t;

/* Time */
uint64_t now_real_ms(void);       /* wall clock, ms since the Unix epoch        */
uint64_t now_mono_ms(void);       /* monotonic clock for timers                 */

/* Framing                                                                   */
uint32_t proto_crc32(const uint8_t *data, size_t len);

typedef struct {
    uint8_t        type;
    uint8_t        encoding;
    uint8_t        flags;
    uint32_t       seq;
    uint16_t       payload_len;
    const uint8_t *payload;       /* points INTO the buffer given to frame_parse */
} frame_t;

typedef enum {
    FRAME_OK = 0,
    FRAME_INCOMPLETE,             /* valid so far, need more bytes (TCP)        */
    FRAME_BAD_MAGIC,
    FRAME_BAD_VERSION,
    FRAME_TOO_LARGE,
    FRAME_BAD_CRC,
    FRAME_BAD_ENCODING
} frame_status_t;

/* Wrap an already encoded payload into a frame. Returns frame length, 0 on error. */
size_t frame_build(uint8_t *out, size_t cap, uint8_t type, uint8_t enc,
                   uint32_t seq, const uint8_t *payload, size_t plen);

/* Validate and split the first frame in buf. On FRAME_OK and FRAME_BAD_CRC,
 * *frame_len is the number of bytes the frame occupies. */
frame_status_t frame_parse(const uint8_t *buf, size_t len, frame_t *f, size_t *frame_len);

/* After a malformed frame on a byte stream: how many bytes to discard so that
 * buf starts at the next plausible frame boundary (always >= 1 if len >= 1). */
size_t frame_resync(const uint8_t *buf, size_t len);

/* Message codecs: packed binary ("struct") and flat JSON */

/* Encode/decode the payload of message 'type' (msg points at the matching
 * *_msg_t; NULL for MSG_HEARTBEAT).  Return payload length / 0, or -1 on error. */
int msg_encode(uint8_t type, uint8_t enc, const void *msg, uint8_t *out, size_t cap);
int msg_decode(uint8_t type, uint8_t enc, const uint8_t *in, size_t len, void *msg);

/* encode + frame in one call. Returns total frame length or -1. */
int proto_pack(uint8_t *out, size_t cap, uint8_t type, uint8_t enc, uint32_t seq, const void *msg);

/* Names and formatting helpers */
const char *msg_type_name(uint8_t type);
const char *cmd_name(uint8_t cmd);
int         cmd_from_name(const char *name);   /* -1 if unknown */
const char *ack_name(uint8_t status);
const char *err_name(uint8_t code);
const char *frame_status_name(frame_status_t s);

/* Format a value stored in 1/100 units as "-12.34" (no floating point). */
void proto_fmt_fx2(char *dst, size_t cap, int32_t v);

/* Small socket helpers */
int  net_set_nonblocking(int fd);
void net_addr_str(const struct sockaddr_in *sa, char *dst, size_t cap);   /* "1.2.3.4:5" */

/* Bounded FIFO of bytes waiting to be written to a non-blocking socket. */
#define OUTBUF_CAP 4096
typedef struct {
    uint8_t data[OUTBUF_CAP];
    size_t  head, tail;
} outbuf_t;

static inline size_t outbuf_pending(const outbuf_t *q) { return q->tail - q->head; }
int outbuf_append(outbuf_t *q, const uint8_t *src, size_t n);   /* 0 ok, -1 overflow            */
int outbuf_flush(outbuf_t *q, int fd);                           /* 0 ok/would-block, -1 fatal   */

#endif /* SMART_PROTO_H */
