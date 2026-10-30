/*
 * cenreal_gateway.c - Central Monitoring Gateway
 *
 * ARCHITECTURE
 *   One thread, one event loop.  A single multiplexer (epoll on Linux, poll()
 *   elsewhere) watches the TCP listening socket, every TCP client socket, the
 *   UDP socket and stdin (operator console).  Every socket is non-blocking:
 *     - partial reads are re-assembled per connection (TCP is a byte stream),
 *     - partial writes are queued per connection and flushed on writability,
 *     - one slow or malicious device can never stall the others.
 *
 *   TCP  : registration (HELLO), reliable commands + acks, heartbeats and any
 *          telemetry the device chooses to send reliably (e.g. during alarms).
 *   UDP  : lightweight periodic telemetry, one frame per datagram.
 *
 * CLOSED-LOOP CONTROL (threshold logic)
 *   For every reading the gateway decides what state the device SHOULD be in
 *   (alarm level + reporting interval) and compares it with the state the
 *   device reports about itself.  If they differ it sends SET_INTERVAL /
 *   ALERT_TRIGGER / ALERT_CLEAR - over TCP when the device has a session,
 *   otherwise back to its UDP address.  Because the device echoes its state in
 *   every reading, a lost UDP command heals itself on the next reading.
 *
 * Build: make     Run: ./gateway_server [-b addr] [-t tcp_port] [-u udp_port] [-l csv] [-q]
 */
#define _POSIX_C_SOURCE 200809L
#include "smart_proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__) && !defined(IOT_FORCE_POLL)
#include <sys/epoll.h>
#define USE_EPOLL 1
#endif

/* Tunables */
#define DEFAULT_PORT        9000
#define FD_LIMIT            65536
#define MAX_EVENTS          256
#define DEV_TABLE_SIZE      8192            /* power of two, > 2 * MAX_DEVICES    */
#define MAX_DEVICES         4096
#define CONN_RBUF_SIZE      2048
#define ACCEPT_BATCH        64              /* fairness caps per loop iteration   */
#define UDP_BATCH           128
#define TICK_MS             1000
#define HELLO_TIMEOUT_MS    10000           /* new TCP session must identify itself */
#define CONN_IDLE_MS        30000           /* TCP silence limit (devices heartbeat every HEARTBEAT_MS) */
#define HEARTBEAT_MS        10000
#define MAX_BAD_STREAK      8               /* malformed frames in a row before hang-up */
#define UDP_REORDER_WINDOW  16
#define CMD_RESEND_MS       2000            /* min gap between corrective commands */

/* Threshold policy. Values are 1/100 degC or 1/100 %RH. */
#define TEMP_WARN_C100      3000            /* 30.00 C  -> WARNING  */
#define TEMP_CRIT_C100      3500            /* 35.00 C  -> CRITICAL */
#define HUM_WARN_C100       7000            /* 70.00 %  -> WARNING  */
#define HUM_CRIT_C100       8500            /* 85.00 %  -> CRITICAL */
#define HYSTERESIS_C100      100            /* must fall 1.00 below a threshold to clear */
#define BATT_LOW_PCT          15            /* <= this: stretch the reporting interval */
#define WARN_RATE_DIVISOR      2            /* WARNING : report 2x faster */
#define CRIT_RATE_DIVISOR      5            /* CRITICAL: report 5x faster */
#define DEFAULT_INTERVAL_MS 3000u

/* Data model */
typedef enum { TR_TCP = 1, TR_UDP = 2 } transport_t;

struct device;

typedef struct conn {                       /* one TCP session */
    int                 fd;
    struct sockaddr_in  peer;
    char                peer_str[INET_ADDRSTRLEN + 8];
    struct device      *dev;                /* bound after the first valid frame */
    uint64_t            connected_ms, last_rx_ms;
    uint8_t             rbuf[CONN_RBUF_SIZE];
    size_t              rlen;
    outbuf_t            out;                /* queued bytes the socket could not take yet */
    int                 want_out;           /* currently registered for writability */
    uint8_t             enc;                /* encoding of the last frame (used for replies) */
    unsigned            bad_streak;
    int                 closing;            /* closed at the end of the current loop pass */
    struct conn        *next_closing;
} conn_t;

typedef struct device {                     /* one sensor node, known by its id */
    uint32_t            id;
    uint16_t            fw_version;
    /* how to reach it */
    conn_t             *tcp;                /* live TCP session, or NULL */
    struct sockaddr_in  udp_addr;           /* last UDP source address */
    int                 have_udp;
    uint8_t             tcp_enc, udp_enc;   /* encodings the device uses per channel */
    /* liveness */
    uint64_t            last_seen_ms;
    int                 online;
    /* counters */
    uint64_t            rx_tcp, rx_udp, udp_lost, udp_stale;
    uint32_t            udp_last_seq;
    int                 udp_seq_valid;
    /* latest reading */
    telemetry_msg_t     last;
    int                 have_last;
    /* control state: what the gateway WANTS the device to be doing */
    uint8_t             alert_desired;      /* 0 normal, 1 warning, 2 critical */
    int                 alert_manual;       /* operator forced the alarm; thresholds suspended */
    int                 low_batt;
    int                 shutting_down;
    uint32_t            normal_interval_ms; /* base reporting period */
    uint32_t            desired_interval_ms;
    uint64_t            last_cmd_ms;
    int                 cmd_sent;
} device_t;

typedef struct {                            /* where did the frame being handled come from? */
    transport_t               tr;
    conn_t                   *conn;         /* TR_TCP */
    const struct sockaddr_in *src;          /* TR_UDP */
} rx_ctx_t;

static struct {
    char    bind_addr[64];
    int     tcp_port, udp_port;
    const char *csv_path;
    int     quiet;
    size_t  max_conns;
} cfg = { "0.0.0.0", DEFAULT_PORT, DEFAULT_PORT, "telemetry.csv", 0, 1024 };

static struct {
    uint64_t tcp_accepted, tcp_rejected, frames_ok, frames_bad, udp_bad, udp_tx_dropped;
    uint64_t telemetry_tcp, telemetry_udp, bad_values, commands_sent, alerts;
} g_stats;

static volatile sig_atomic_t g_running = 1;
static int       g_tcp_fd = -1, g_udp_fd = -1;
static conn_t   *g_conns[FD_LIMIT];         /* indexed by fd */
static int       g_maxfd;
static size_t    g_nconn;
static conn_t   *g_closing;                 /* connections to free at the end of the loop pass */
static device_t *g_devtab[DEV_TABLE_SIZE];
static size_t    g_ndev;
static FILE     *g_csv;
static uint32_t  g_next_cmd_id = 1;
static uint32_t  g_tx_seq = 1;
static int       g_console;
static char      g_line[256];
static size_t    g_linelen;

/* Logging */
#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
static void logmsg(const char *tag, const char *fmt, ...) {
    struct timespec ts;
    struct tm tm;
    char hms[16];
    va_list ap;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(hms, sizeof hms, "%H:%M:%S", &tm);
    printf("%s.%03ld %-5s ", hms, ts.tv_nsec / 1000000L, tag);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}
#define LOG(tag, ...) logmsg(tag, __VA_ARGS__)

/* Allow at most one message per 'period_ms' from a noisy source. */
static int log_budget(uint64_t *last_ms, uint64_t period_ms) {
    uint64_t now = now_mono_ms();
    if (*last_ms != 0 && now - *last_ms < period_ms) return 0;
    *last_ms = now;
    return 1;
}

/* I/O multiplexer: epoll on Linux, poll() elsewhere - identical interface */
#define MUX_IN   0x1u
#define MUX_OUT  0x2u
#define MUX_ERR  0x4u
typedef struct { int fd; unsigned flags; } mux_event_t;

#ifdef USE_EPOLL
static int g_epfd = -1;

static const char *mux_name(void) { return "epoll"; }
static int mux_init(void) { g_epfd = epoll_create1(EPOLL_CLOEXEC); return g_epfd < 0 ? -1 : 0; }

static int mux_ctl(int op, int fd, int want_out) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN | (want_out ? EPOLLOUT : 0);
    ev.data.fd = fd;
    return epoll_ctl(g_epfd, op, fd, &ev);
}
static int  mux_add(int fd, int want_out) { return mux_ctl(EPOLL_CTL_ADD, fd, want_out); }
static int  mux_mod(int fd, int want_out) { return mux_ctl(EPOLL_CTL_MOD, fd, want_out); }
static void mux_del(int fd) { epoll_ctl(g_epfd, EPOLL_CTL_DEL, fd, NULL); }
static void mux_close(void) { if (g_epfd >= 0) close(g_epfd); }

static int mux_wait(mux_event_t *out, int max, int timeout_ms) {
    struct epoll_event evs[MAX_EVENTS];
    int n = epoll_wait(g_epfd, evs, max > MAX_EVENTS ? MAX_EVENTS : max, timeout_ms);
    for (int i = 0; i < n; i++) {
        out[i].fd = evs[i].data.fd;
        out[i].flags = ((evs[i].events & EPOLLIN)  ? MUX_IN  : 0u) |
                       ((evs[i].events & EPOLLOUT) ? MUX_OUT : 0u) |
                       ((evs[i].events & (EPOLLERR | EPOLLHUP)) ? MUX_ERR : 0u);
    }
    return n;
}
#else   /* ---- portable poll() implementation ---- */
static struct pollfd *g_pfds;
static size_t         g_npfds, g_cap_pfds;
static int            g_slot[FD_LIMIT];          /* fd -> index in g_pfds, or -1 */

static const char *mux_name(void) { return "poll"; }
static int mux_init(void) {
    for (int i = 0; i < FD_LIMIT; i++) g_slot[i] = -1;
    return 0;
}
static int mux_add(int fd, int want_out) {
    if (fd < 0 || fd >= FD_LIMIT) { errno = EMFILE; return -1; }
    if (g_npfds == g_cap_pfds) {
        size_t cap = g_cap_pfds ? g_cap_pfds * 2 : 64;
        struct pollfd *p = realloc(g_pfds, cap * sizeof *p);
        if (!p) return -1;
        g_pfds = p;
        g_cap_pfds = cap;
    }
    g_pfds[g_npfds].fd = fd;
    g_pfds[g_npfds].events = (short)(POLLIN | (want_out ? POLLOUT : 0));
    g_pfds[g_npfds].revents = 0;
    g_slot[fd] = (int)g_npfds++;
    return 0;
}
static int mux_mod(int fd, int want_out) {
    if (fd < 0 || fd >= FD_LIMIT || g_slot[fd] < 0) return -1;
    g_pfds[g_slot[fd]].events = (short)(POLLIN | (want_out ? POLLOUT : 0));
    return 0;
}
static void mux_del(int fd) {
    int i;
    if (fd < 0 || fd >= FD_LIMIT || (i = g_slot[fd]) < 0) return;
    g_pfds[i] = g_pfds[--g_npfds];               /* swap-remove */
    g_slot[g_pfds[i].fd] = i;
    g_slot[fd] = -1;
}
static void mux_close(void) { free(g_pfds); }

static int mux_wait(mux_event_t *out, int max, int timeout_ms) {
    int r = poll(g_pfds, (nfds_t)g_npfds, timeout_ms), n = 0;
    if (r <= 0) return r;
    for (size_t i = 0; i < g_npfds && n < max; i++) {
        short re = g_pfds[i].revents;
        if (!re) continue;
        out[n].fd = g_pfds[i].fd;
        out[n].flags = ((re & POLLIN)  ? MUX_IN  : 0u) |
                       ((re & POLLOUT) ? MUX_OUT : 0u) |
                       ((re & (POLLERR | POLLHUP | POLLNVAL)) ? MUX_ERR : 0u);
        n++;
    }
    return n;
}
#endif

/* Device registry: open-addressing hash table keyed by device id */
static device_t *dev_lookup(uint32_t id, int create) {
    uint32_t h = (id * 2654435761u) & (DEV_TABLE_SIZE - 1);

    for (uint32_t i = 0; i < DEV_TABLE_SIZE; i++) {
        device_t **slot = &g_devtab[(h + i) & (DEV_TABLE_SIZE - 1)];
        if (!*slot) {
            device_t *d;
            if (!create || g_ndev >= MAX_DEVICES) return NULL;
            d = calloc(1, sizeof *d);
            if (!d) return NULL;
            d->id = id;
            *slot = d;
            g_ndev++;
            return d;
        }
        if ((*slot)->id == id) return *slot;
    }
    return NULL;
}

/* TCP connection lifecycle */

/* Closing is two-phase so that code further up the call stack can still
 * safely look at the connection: mark now, close the fd + free at the end of
 * the loop pass (reap_closed). */
static void conn_mark_close(conn_t *c, const char *why) {
    if (c->closing) return;
    c->closing = 1;
    mux_del(c->fd);
    if (c->dev && c->dev->tcp == c) {
        c->dev->tcp = NULL;
        if (!c->dev->have_udp) c->dev->online = 0;      /* TCP-only device and its session is gone */
    }
    if (c->dev) LOG("INFO", "TCP  %s closed: %s (dev=%u)", c->peer_str, why, c->dev->id);
    else        LOG("INFO", "TCP  %s closed: %s", c->peer_str, why);
    c->next_closing = g_closing;
    g_closing = c;
    g_nconn--;
}

static void reap_closed(void) {
    while (g_closing) {
        conn_t *c = g_closing;
        g_closing = c->next_closing;
        g_conns[c->fd] = NULL;
        close(c->fd);
        free(c);
    }
}

static int conn_flush(conn_t *c) {
    int pending;

    if (c->closing) return -1;
    if (outbuf_flush(&c->out, c->fd) < 0) { conn_mark_close(c, strerror(errno)); return -1; }
    pending = outbuf_pending(&c->out) > 0;
    if (pending != c->want_out) {                 /* ask for POLLOUT only while data is queued */
        c->want_out = pending;
        mux_mod(c->fd, pending);
    }
    return 0;
}

static int conn_send(conn_t *c, const uint8_t *data, size_t n) {
    if (c->closing) return -1;
    if (outbuf_append(&c->out, data, n) < 0) {
        conn_mark_close(c, "send queue overflow (peer not reading)");
        return -1;
    }
    return conn_flush(c);
}

static void conn_note_bad(conn_t *c) {
    if (++c->bad_streak >= MAX_BAD_STREAK) conn_mark_close(c, "too many malformed frames in a row");
}

/* Sending helpers */
static int udp_send(const struct sockaddr_in *dst, const uint8_t *frame, size_t n) {
    if (sendto(g_udp_fd, frame, n, 0, (const struct sockaddr *)dst, sizeof *dst) < 0) {
        g_stats.udp_tx_dropped++;                 /* best effort: UDP never queues */
        return -1;
    }
    return 0;
}

static void reply(const rx_ctx_t *cx, uint8_t enc, uint8_t type, const void *msg) {
    uint8_t buf[PROTO_MAX_FRAME];
    int n = proto_pack(buf, sizeof buf, type, enc, g_tx_seq++, msg);

    if (n < 0) return;
    if (cx->tr == TR_TCP) conn_send(cx->conn, buf, (size_t)n);
    else                  udp_send(cx->src, buf, (size_t)n);
}

static void send_error(const rx_ctx_t *cx, uint8_t code) {
    error_msg_t e;

    /* Never answer malformed UDP: the source address may be spoofed and a
     * reply would turn the gateway into a reflector. */
    if (cx->tr != TR_TCP) return;
    e.code = code;
    reply(cx, cx->conn->enc, MSG_ERROR, &e);
}

static const char *rx_peer(const rx_ctx_t *cx, char *buf, size_t cap) {
    if (cx->tr == TR_TCP) return cx->conn->peer_str;
    net_addr_str(cx->src, buf, cap);
    return buf;
}

/* Send one control signal to a device: over its TCP session if it has one,
 * otherwise as a datagram to its last known UDP address. */
static int send_command(device_t *d, uint8_t cmd, uint32_t arg) {
    command_msg_t m;
    uint8_t buf[PROTO_MAX_FRAME];
    const char *via;
    int n;

    m.cmd_id = g_next_cmd_id++;
    m.cmd = cmd;
    m.arg = arg;
    if (d->tcp) {
        n = proto_pack(buf, sizeof buf, MSG_COMMAND, d->tcp_enc, g_tx_seq++, &m);
        if (n < 0 || conn_send(d->tcp, buf, (size_t)n) < 0) return -1;
        via = "TCP";
    } else if (d->have_udp) {
        n = proto_pack(buf, sizeof buf, MSG_COMMAND, d->udp_enc, g_tx_seq++, &m);
        if (n < 0 || udp_send(&d->udp_addr, buf, (size_t)n) < 0) return -1;
        via = "UDP";
    } else {
        return -1;
    }
    g_stats.commands_sent++;
    LOG("CMD", "dev=%u <- %s arg=%u (id %u) via %s", d->id, cmd_name(cmd), arg, m.cmd_id, via);
    return 0;
}

/* Threshold policy and closed-loop reconciliation */
static const char *level_name(unsigned l) { return l == 0 ? "NORMAL" : l == 1 ? "WARNING" : "CRITICAL"; }

static uint32_t clamp_interval(uint32_t v) {
    return v < MIN_INTERVAL_MS ? MIN_INTERVAL_MS : v > MAX_INTERVAL_MS ? MAX_INTERVAL_MS : v;
}

/* Alarm level a reading calls for. Once a level is raised it is only dropped
 * after the value falls HYSTERESIS below its threshold (no flapping). */
static uint8_t classify(const device_t *d, const telemetry_msg_t *t) {
    int hw = d->alert_desired >= 1 ? HYSTERESIS_C100 : 0;
    int hc = d->alert_desired >= 2 ? HYSTERESIS_C100 : 0;

    if (t->temperature_c100 >= TEMP_CRIT_C100 - hc || t->humidity_pct100 >= HUM_CRIT_C100 - hc) return 2;
    if (t->temperature_c100 >= TEMP_WARN_C100 - hw || t->humidity_pct100 >= HUM_WARN_C100 - hw) return 1;
    return 0;
}

/* Reporting interval that goes with an alarm level: faster while something is
 * wrong, slower when the battery is low and everything is fine. */
static uint32_t policy_interval(const device_t *d, uint8_t level) {
    uint32_t n = d->normal_interval_ms;
    if (level >= 2)      n /= CRIT_RATE_DIVISOR;
    else if (level == 1) n /= WARN_RATE_DIVISOR;
    else if (d->low_batt) n *= 2;
    return clamp_interval(n);
}

/* Compare what the device says it is doing with what we want; correct it. */
static void reconcile(device_t *d, const telemetry_msg_t *rep, uint64_t now) {
    int alert_diff = rep->alert_level != d->alert_desired;
    int rate_diff  = rep->interval_ms != d->desired_interval_ms;

    if (d->shutting_down) return;
    if (!alert_diff && !rate_diff) { d->cmd_sent = 0; return; }
    if (d->cmd_sent && now - d->last_cmd_ms < CMD_RESEND_MS) return;   /* give it time to take effect */

    if (alert_diff)
        send_command(d, d->alert_desired ? CMD_ALERT_TRIGGER : CMD_ALERT_CLEAR, d->alert_desired);
    if (rate_diff)
        send_command(d, CMD_SET_INTERVAL, d->desired_interval_ms);
    d->cmd_sent = 1;
    d->last_cmd_ms = now;
}

static void apply_policy(device_t *d, const telemetry_msg_t *t) {
    char tb[16], hb[16];

    if (!d->low_batt && t->battery_pct <= BATT_LOW_PCT) {
        d->low_batt = 1;
        LOG("WARN", "dev=%u battery low (%u%%) - stretching report interval", d->id, (unsigned)t->battery_pct);
    } else if (d->low_batt && t->battery_pct >= BATT_LOW_PCT + 5) {
        d->low_batt = 0;
        LOG("INFO", "dev=%u battery recovered (%u%%)", d->id, (unsigned)t->battery_pct);
    }

    if (!d->alert_manual) {
        uint8_t lvl = classify(d, t);
        if (lvl != d->alert_desired) {
            proto_fmt_fx2(tb, sizeof tb, t->temperature_c100);
            proto_fmt_fx2(hb, sizeof hb, t->humidity_pct100);
            LOG("ALERT", "dev=%u %s -> %s  (temp=%sC hum=%s%%)", d->id,
                level_name(d->alert_desired), level_name(lvl), tb, hb);
            if (lvl > d->alert_desired) g_stats.alerts++;
            d->alert_desired = lvl;
            d->cmd_sent = 0;                      /* act on the transition immediately */
        }
    }
    d->desired_interval_ms = policy_interval(d, d->alert_desired);
    reconcile(d, t, now_mono_ms());
}

/* Telemetry log (CSV) */
static void csv_log(const telemetry_msg_t *t, transport_t tr, uint32_t seq) {
    char tb[16], hb[16];

    if (!g_csv) return;
    proto_fmt_fx2(tb, sizeof tb, t->temperature_c100);
    proto_fmt_fx2(hb, sizeof hb, t->humidity_pct100);
    fprintf(g_csv, "%" PRIu64 ",%u,%s,%u,%" PRIu64 ",%s,%s,%u,%u,0x%04x,%u\n",
            now_real_ms(), (unsigned)t->device_id, tr == TR_TCP ? "TCP" : "UDP", (unsigned)seq,
            t->timestamp_ms, tb, hb, (unsigned)t->battery_pct, (unsigned)t->alert_level,
            (unsigned)t->status_flags, (unsigned)t->interval_ms);
}

/* Message handlers.  Each returns 0 if the frame was acceptable, -1 if not */
static void bad_payload(const rx_ctx_t *cx, const frame_t *fr) {
    static uint64_t last;
    char tmp[48];

    g_stats.frames_bad++;
    if (log_budget(&last, 1000))
        LOG("WARN", "malformed %s payload (%u bytes, %s) from %s - dropped",
            msg_type_name(fr->type), (unsigned)fr->payload_len,
            fr->encoding == ENC_JSON ? "json" : "binary", rx_peer(cx, tmp, sizeof tmp));
    send_error(cx, ERR_BAD_PAYLOAD);
}

static void device_table_full(const rx_ctx_t *cx, uint32_t id) {
    static uint64_t last;
    if (log_budget(&last, 5000)) LOG("WARN", "device table full - rejecting dev=%u", id);
    send_error(cx, ERR_BUSY);
    if (cx->conn) conn_mark_close(cx->conn, "device table full");
}

/* A TCP session belongs to exactly one device. Frames naming another device
 * are refused BEFORE any registry record is created for them. */
static int session_matches(const rx_ctx_t *cx, uint32_t id) {
    return cx->tr != TR_TCP || !cx->conn->dev || cx->conn->dev->id == id;
}

static void reject_foreign_id(const rx_ctx_t *cx, uint32_t id) {
    LOG("WARN", "TCP %s: frame for dev=%u on a session owned by dev=%u", cx->conn->peer_str, id,
        cx->conn->dev->id);
    send_error(cx, ERR_BAD_VALUE);
}

static void bind_conn(conn_t *c, device_t *d, uint8_t enc) {
    if (d->tcp && d->tcp != c) {                              /* device reconnected: old session is stale */
        LOG("WARN", "dev=%u new TCP session replaces stale %s", d->id, d->tcp->peer_str);
        conn_mark_close(d->tcp, "superseded by a newer session");
    }
    c->dev = d;
    d->tcp = c;
    d->tcp_enc = enc;
}

/* Record where the frame came from and refresh liveness. -1 if rejected. */
static int touch_device(device_t *d, const rx_ctx_t *cx, const frame_t *fr) {
    char tmp[48];

    if (!session_matches(cx, d->id)) { reject_foreign_id(cx, d->id); return -1; }
    if (cx->tr == TR_TCP) {
        bind_conn(cx->conn, d, fr->encoding);
    } else {
        d->udp_addr = *cx->src;
        d->have_udp = 1;
        d->udp_enc = fr->encoding;
    }
    if (!d->online) {
        d->online = 1;
        LOG("INFO", "dev=%u ONLINE via %s %s", d->id, cx->tr == TR_TCP ? "TCP" : "UDP", rx_peer(cx, tmp, sizeof tmp));
    }
    d->last_seen_ms = now_mono_ms();
    return 0;
}

static int on_hello(const frame_t *fr, rx_ctx_t *cx) {
    hello_msg_t h;
    hello_ack_msg_t ack;
    device_t *d;

    if (msg_decode(MSG_HELLO, fr->encoding, fr->payload, fr->payload_len, &h) < 0) { bad_payload(cx, fr); return -1; }
    if (!session_matches(cx, h.device_id)) { reject_foreign_id(cx, h.device_id); return -1; }
    if (!(d = dev_lookup(h.device_id, 1))) { device_table_full(cx, h.device_id); return -1; }
    if (touch_device(d, cx, fr) < 0) return -1;

    d->fw_version = h.fw_version;
    d->normal_interval_ms = clamp_interval(h.interval_ms);
    d->desired_interval_ms = policy_interval(d, d->alert_desired);
    d->udp_seq_valid = 0;                          /* device (re)started: restart loss accounting */
    LOG("INFO", "dev=%u HELLO fw=%u.%u base interval=%ums (%s)", d->id, h.fw_version >> 8,
        h.fw_version & 0xFF, h.interval_ms, fr->encoding == ENC_JSON ? "json" : "binary");
    ack.heartbeat_ms = HEARTBEAT_MS;
    reply(cx, fr->encoding, MSG_HELLO_ACK, &ack);
    return 0;
}

static int telemetry_in_range(const telemetry_msg_t *t) {
    return t->temperature_c100 >= -4000 && t->temperature_c100 <= 12500 &&
           t->humidity_pct100 <= 10000 && t->battery_pct <= 100 && t->alert_level <= 2 &&
           t->interval_ms >= MIN_INTERVAL_MS && t->interval_ms <= MAX_INTERVAL_MS;
}

/* UDP only: detect gaps (lost datagrams) and drop duplicates / late arrivals. */
static int udp_sequence_ok(device_t *d, uint32_t seq) {
    if (d->udp_seq_valid) {
        int32_t gap = (int32_t)(seq - d->udp_last_seq);
        if (gap <= 0 && gap > -UDP_REORDER_WINDOW) { d->udp_stale++; return 0; }
        if (gap > 1) d->udp_lost += (uint32_t)(gap - 1);
        /* gap <= -UDP_REORDER_WINDOW: the device restarted - just resynchronise */
    }
    d->udp_last_seq = seq;
    d->udp_seq_valid = 1;
    return 1;
}

static int on_telemetry(const frame_t *fr, rx_ctx_t *cx) {
    telemetry_msg_t t;
    device_t *d;
    char tb[16], hb[16], tmp[48];

    if (msg_decode(MSG_TELEMETRY, fr->encoding, fr->payload, fr->payload_len, &t) < 0) { bad_payload(cx, fr); return -1; }
    if (!telemetry_in_range(&t)) {
        static uint64_t last;
        g_stats.bad_values++;
        if (log_budget(&last, 1000))
            LOG("WARN", "dev=%u reading outside physical range - rejected (from %s)", t.device_id, rx_peer(cx, tmp, sizeof tmp));
        send_error(cx, ERR_BAD_VALUE);
        return -1;
    }
    if (!session_matches(cx, t.device_id)) { reject_foreign_id(cx, t.device_id); return -1; }
    if (!(d = dev_lookup(t.device_id, 1))) { device_table_full(cx, t.device_id); return -1; }
    if (touch_device(d, cx, fr) < 0) return -1;

    if (d->normal_interval_ms == 0)               /* no HELLO seen (UDP-only device / gateway restart) */
        d->normal_interval_ms = (t.alert_level == 0 && !(t.status_flags & ST_LOW_BATTERY))
                                    ? t.interval_ms : DEFAULT_INTERVAL_MS;

    if (cx->tr == TR_UDP && !udp_sequence_ok(d, fr->seq)) return 0;    /* duplicate / late: ignore */

    d->last = t;
    d->have_last = 1;
    if (cx->tr == TR_TCP) { d->rx_tcp++; g_stats.telemetry_tcp++; }
    else                  { d->rx_udp++; g_stats.telemetry_udp++; }
    csv_log(&t, cx->tr, fr->seq);
    if (!cfg.quiet) {
        proto_fmt_fx2(tb, sizeof tb, t.temperature_c100);
        proto_fmt_fx2(hb, sizeof hb, t.humidity_pct100);
        LOG("DATA", "dev=%u %s #%u temp=%sC hum=%s%% batt=%u%% alert=%u every=%ums", d->id,
            cx->tr == TR_TCP ? "TCP" : "UDP", (unsigned)fr->seq, tb, hb, (unsigned)t.battery_pct,
            (unsigned)t.alert_level, (unsigned)t.interval_ms);
    }
    apply_policy(d, &t);
    return 0;
}

static int on_cmd_ack(const frame_t *fr, rx_ctx_t *cx) {
    cmd_ack_msg_t a;
    device_t *d;

    if (msg_decode(MSG_COMMAND_ACK, fr->encoding, fr->payload, fr->payload_len, &a) < 0) { bad_payload(cx, fr); return -1; }
    if (!(d = dev_lookup(a.device_id, 0))) return -1;          /* ack from a device we never met */
    if (touch_device(d, cx, fr) < 0) return -1;
    LOG(a.status == ACK_OK ? "INFO" : "WARN", "dev=%u ACK  cmd#%u %s -> %s", d->id, a.cmd_id,
        cmd_name(a.cmd), ack_name(a.status));
    return 0;
}

static void handle_frame(const frame_t *fr, rx_ctx_t *cx) {
    int rc = 0;

    if (cx->conn) cx->conn->enc = fr->encoding;                /* mirror the device's encoding in replies */
    switch (fr->type) {
    case MSG_HELLO:       rc = on_hello(fr, cx);     break;
    case MSG_TELEMETRY:   rc = on_telemetry(fr, cx); break;
    case MSG_COMMAND_ACK: rc = on_cmd_ack(fr, cx);   break;
    case MSG_HEARTBEAT:
        if (cx->conn && cx->conn->dev) cx->conn->dev->last_seen_ms = now_mono_ms();
        break;
    case MSG_ERROR: {
        error_msg_t e;
        char tmp[48];
        if (msg_decode(MSG_ERROR, fr->encoding, fr->payload, fr->payload_len, &e) == 0)
            LOG("WARN", "%s reported error %s", rx_peer(cx, tmp, sizeof tmp), err_name(e.code));
        break;
    }
    default:
        rc = -1;
        send_error(cx, ERR_UNKNOWN_TYPE);
        break;
    }
    if (cx->conn) {                                            /* consecutive-garbage accounting */
        if (rc == 0) cx->conn->bad_streak = 0;
        else         conn_note_bad(cx->conn);
    }
}

/* TCP I/O */

/* Extract every complete frame from the receive buffer. Incomplete data stays
 * buffered for the next read; malformed data is skipped up to the next magic. */
static void process_rbuf(conn_t *c) {
    size_t off = 0;

    while (off < c->rlen && !c->closing) {
        frame_t fr;
        size_t flen = 0;
        frame_status_t st = frame_parse(c->rbuf + off, c->rlen - off, &fr, &flen);

        if (st == FRAME_INCOMPLETE) break;                     /* wait for more bytes */
        if (st == FRAME_OK) {
            rx_ctx_t cx = { TR_TCP, c, NULL };
            g_stats.frames_ok++;
            handle_frame(&fr, &cx);
            off += flen;
            continue;
        }
        {
            static uint64_t last;
            g_stats.frames_bad++;
            if (log_budget(&last, 1000))
                LOG("WARN", "TCP %s: %s - resynchronising", c->peer_str, frame_status_name(st));
            if (c->bad_streak == 0) {
                rx_ctx_t cx = { TR_TCP, c, NULL };
                send_error(&cx, st == FRAME_BAD_CRC ? ERR_BAD_CRC : ERR_BAD_FRAME);
            }
            conn_note_bad(c);
            off += frame_resync(c->rbuf + off, c->rlen - off);
        }
    }
    if (off > 0) {
        memmove(c->rbuf, c->rbuf + off, c->rlen - off);
        c->rlen -= off;
    }
}

static void on_conn_readable(conn_t *c) {
    ssize_t n;

    if (c->rlen == sizeof c->rbuf) { conn_mark_close(c, "receive buffer overflow"); return; }
    n = recv(c->fd, c->rbuf + c->rlen, sizeof c->rbuf - c->rlen, 0);
    if (n > 0) {
        c->rlen += (size_t)n;
        c->last_rx_ms = now_mono_ms();
        process_rbuf(c);
    } else if (n == 0) {
        conn_mark_close(c, "peer closed the connection");
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        conn_mark_close(c, strerror(errno));
    }
}

static void on_listen_readable(void) {
    for (int i = 0; i < ACCEPT_BATCH; i++) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        conn_t *c = NULL;
        int one = 1;
        int fd = accept(g_tcp_fd, (struct sockaddr *)&peer, &plen);

        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) LOG("ERROR", "accept: %s", strerror(errno));
            break;
        }
        if (fd >= FD_LIMIT || g_nconn >= cfg.max_conns) {      /* protect the gateway from overload */
            static uint64_t last;
            g_stats.tcp_rejected++;
            if (log_budget(&last, 2000)) LOG("WARN", "connection limit reached (%zu) - rejecting clients", g_nconn);
            close(fd);
            continue;
        }
        if (net_set_nonblocking(fd) < 0 || !(c = calloc(1, sizeof *c))) { close(fd); free(c); continue; }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        c->fd = fd;
        c->peer = peer;
        net_addr_str(&peer, c->peer_str, sizeof c->peer_str);
        c->connected_ms = c->last_rx_ms = now_mono_ms();
        c->enc = ENC_BINARY;
        if (mux_add(fd, 0) < 0) {
            LOG("ERROR", "cannot register client socket: %s", strerror(errno));
            close(fd);
            free(c);
            continue;
        }
        g_conns[fd] = c;
        if (fd > g_maxfd) g_maxfd = fd;
        g_nconn++;
        g_stats.tcp_accepted++;
        LOG("INFO", "TCP  %s connected (%zu active)", c->peer_str, g_nconn);
    }
}

/* UDP I/O */
static void on_udp_readable(void) {
    static uint64_t last;
    uint8_t buf[PROTO_MAX_FRAME + 64];       /* a little larger, so oversize datagrams are noticed */

    for (int i = 0; i < UDP_BATCH; i++) {
        struct sockaddr_in src;
        socklen_t sl = sizeof src;
        frame_t fr;
        size_t flen = 0;
        frame_status_t st;
        ssize_t n = recvfrom(g_udp_fd, buf, sizeof buf, 0, (struct sockaddr *)&src, &sl);

        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) LOG("ERROR", "recvfrom: %s", strerror(errno));
            break;
        }
        st = frame_parse(buf, (size_t)n, &fr, &flen);
        if (st != FRAME_OK || flen != (size_t)n) {   /* one datagram == exactly one frame */
            char tmp[48];
            g_stats.udp_bad++;
            g_stats.frames_bad++;
            if (log_budget(&last, 1000)) {
                net_addr_str(&src, tmp, sizeof tmp);
                LOG("WARN", "UDP datagram from %s dropped (%zd bytes, %s)", tmp, n,
                    st == FRAME_OK ? "trailing bytes" : frame_status_name(st));
            }
            continue;
        }
        {
            rx_ctx_t cx = { TR_UDP, NULL, &src };
            g_stats.frames_ok++;
            handle_frame(&fr, &cx);
        }
    }
}

/* Operator console (stdin) */
static const char HELP[] =
    "console commands:\n"
    "  list                     show known devices\n"
    "  stats                    show gateway counters\n"
    "  set <id> <interval_ms>   change a device's normal reporting interval\n"
    "  alert <id> <1|2>         force a device alarm (held until 'clear')\n"
    "  clear <id>               release a forced alarm, thresholds take over again\n"
    "  report <id>              ask a device for an immediate reading\n"
    "  shutdown <id>            tell a device to shut down\n"
    "  quit                     stop the gateway";

static int dev_cmp(const void *a, const void *b) {
    uint32_t x = (*(device_t *const *)a)->id, y = (*(device_t *const *)b)->id;
    return (x > y) - (x < y);
}

static uint64_t device_timeout_ms(const device_t *d) {
    uint64_t t = 4ull * d->desired_interval_ms;
    return t < 15000 ? 15000 : t;
}

static void list_devices(void) {
    device_t **v;
    size_t n = 0;
    uint64_t now = now_mono_ms();

    if (g_ndev == 0) { puts("no devices yet"); return; }
    if (!(v = malloc(g_ndev * sizeof *v))) return;
    for (size_t i = 0; i < DEV_TABLE_SIZE; i++)
        if (g_devtab[i]) v[n++] = g_devtab[i];
    qsort(v, n, sizeof *v, dev_cmp);

    printf("%-7s %-7s %-8s %7s %6s %5s %-8s %9s %8s %8s %8s %7s\n", "DEVICE", "STATE", "LINK", "TEMP_C",
           "HUM_%", "BATT", "ALARM", "INTERVAL", "RX_TCP", "RX_UDP", "UDP_LOST", "AGE_S");
    for (size_t i = 0; i < n; i++) {
        const device_t *d = v[i];
        char tb[16] = "-", hb[16] = "-";
        if (d->have_last) {
            proto_fmt_fx2(tb, sizeof tb, d->last.temperature_c100);
            proto_fmt_fx2(hb, sizeof hb, d->last.humidity_pct100);
        }
        printf("%-7u %-7s %-8s %7s %6s %5u %-8s %9u %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %7.1f\n", d->id,
               d->online ? "online" : "offline",
               d->tcp && d->have_udp ? "TCP+UDP" : d->tcp ? "TCP" : d->have_udp ? "UDP" : "none", tb, hb,
               d->have_last ? (unsigned)d->last.battery_pct : 0u, level_name(d->alert_desired),
               d->have_last ? (unsigned)d->last.interval_ms : 0u, d->rx_tcp, d->rx_udp, d->udp_lost,
               (double)(now - d->last_seen_ms) / 1000.0);
    }
    free(v);
}

static void print_stats(void) {
    printf("--- gateway statistics ---\n"
           "devices known     : %zu\n"
           "tcp sessions      : %zu active, %" PRIu64 " accepted, %" PRIu64 " rejected\n"
           "frames ok / bad   : %" PRIu64 " / %" PRIu64 "  (udp datagrams dropped: %" PRIu64 ")\n"
           "telemetry tcp/udp : %" PRIu64 " / %" PRIu64 "\n"
           "readings rejected : %" PRIu64 "\n"
           "commands sent     : %" PRIu64 "  (udp send failures: %" PRIu64 ")\n"
           "alarms raised     : %" PRIu64 "\n",
           g_ndev, g_nconn, g_stats.tcp_accepted, g_stats.tcp_rejected, g_stats.frames_ok,
           g_stats.frames_bad, g_stats.udp_bad, g_stats.telemetry_tcp, g_stats.telemetry_udp,
           g_stats.bad_values, g_stats.commands_sent, g_stats.udp_tx_dropped, g_stats.alerts);
}

/* Declarative operator actions: change the desired state, then let reconcile()
 * push whatever differs to the device. */
static void push_desired(device_t *d) {
    static const telemetry_msg_t none;
    d->desired_interval_ms = policy_interval(d, d->alert_desired);
    d->cmd_sent = 0;
    if (d->have_last) {
        if (d->last.alert_level == d->alert_desired && d->last.interval_ms == d->desired_interval_ms)
            puts("device already in the requested state");
        else
            reconcile(d, &d->last, now_mono_ms());
    } else {
        reconcile(d, &none, now_mono_ms());       /* no reading yet: send everything */
    }
}

static void console_exec(char *line) {
    char verb[16] = "";
    unsigned id = 0, arg = 0;
    int n = sscanf(line, "%15s %u %u", verb, &id, &arg);
    device_t *d;

    if (n < 1) return;
    if (!strcmp(verb, "help"))  { puts(HELP); return; }
    if (!strcmp(verb, "list"))  { list_devices(); return; }
    if (!strcmp(verb, "stats")) { print_stats(); return; }
    if (!strcmp(verb, "quit") || !strcmp(verb, "exit")) { g_running = 0; return; }
    if (n < 2 || !(d = dev_lookup(id, 0))) { puts(n < 2 ? "missing device id - try 'help'" : "unknown device"); return; }

    if (!strcmp(verb, "set") && n == 3 && arg >= MIN_INTERVAL_MS && arg <= MAX_INTERVAL_MS) {
        d->normal_interval_ms = arg;
        push_desired(d);
    } else if (!strcmp(verb, "alert") && n == 3 && (arg == 1 || arg == 2)) {
        d->alert_manual = 1;
        d->alert_desired = (uint8_t)arg;
        push_desired(d);
    } else if (!strcmp(verb, "clear")) {
        d->alert_manual = 0;
        d->alert_desired = 0;
        push_desired(d);
    } else if (!strcmp(verb, "report")) {
        if (send_command(d, CMD_REPORT_NOW, 0) < 0) puts("device unreachable");
    } else if (!strcmp(verb, "shutdown")) {
        if (send_command(d, CMD_SHUTDOWN, 0) < 0) puts("device unreachable");
        else d->shutting_down = 1;
    } else {
        puts("bad arguments - try 'help'");
    }
}

static void on_stdin_readable(void) {
    char buf[256];
    ssize_t n = read(STDIN_FILENO, buf, sizeof buf);    /* readiness was signalled: will not block */

    if (n < 0 && (errno == EINTR || errno == EAGAIN)) return;
    if (n <= 0) {                                        /* EOF (daemon, /dev/null) or error: stop watching */
        mux_del(STDIN_FILENO);
        g_console = 0;
        return;
    }
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\n') {
            g_line[g_linelen] = '\0';
            g_linelen = 0;
            console_exec(g_line);
        } else if (g_linelen < sizeof g_line - 1) {
            g_line[g_linelen++] = buf[i];
        }
    }
}

/* Housekeeping (once per TICK_MS) */
static void housekeeping(uint64_t now) {
    for (int fd = 0; fd <= g_maxfd; fd++) {
        conn_t *c = g_conns[fd];
        if (!c || c->closing) continue;
        if (!c->dev && now - c->connected_ms > HELLO_TIMEOUT_MS) conn_mark_close(c, "never identified itself");
        else if (now - c->last_rx_ms > CONN_IDLE_MS)             conn_mark_close(c, "idle timeout");
    }
    for (size_t i = 0; i < DEV_TABLE_SIZE; i++) {
        device_t *d = g_devtab[i];
        if (d && d->online && now - d->last_seen_ms > device_timeout_ms(d)) {
            d->online = 0;
            LOG("WARN", "dev=%u OFFLINE (silent for %" PRIu64 " ms)", d->id, now - d->last_seen_ms);
        }
    }
}

/* Socket setup and process plumbing */
static int make_socket(int type, const char *addr, int port) {
    struct sockaddr_in sa;
    int fd, one = 1;
    const char *what = type == SOCK_STREAM ? "TCP" : "UDP";

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) { fprintf(stderr, "bad bind address '%s'\n", addr); return -1; }
    if ((fd = socket(AF_INET, type, 0)) < 0) { fprintf(stderr, "%s socket: %s\n", what, strerror(errno)); return -1; }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (type == SOCK_DGRAM) {                              /* absorb bursts from many devices */
        int rb = 1 << 20;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0 ||
        (type == SOCK_STREAM && listen(fd, 512) < 0) ||
        net_set_nonblocking(fd) < 0) {
        fprintf(stderr, "%s %s:%d: %s\n", what, addr, port, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static size_t raise_fd_limit(void) {
    struct rlimit rl;

    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return 1024;
    if (rl.rlim_cur < FD_LIMIT) {
        rlim_t want = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > FD_LIMIT) ? FD_LIMIT : rl.rlim_max;
        if (want > rl.rlim_cur) {
            rl.rlim_cur = want;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) getrlimit(RLIMIT_NOFILE, &rl);
        }
    }
    return rl.rlim_cur > FD_LIMIT ? FD_LIMIT : (size_t)rl.rlim_cur;
}

static void on_signal(int sig) { (void)sig; g_running = 0; }

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;                  /* no SA_RESTART: epoll_wait returns EINTR and we notice */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);                   /* a dead peer must not kill the gateway */
}

static int parse_port(const char *s) {
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    return (*s && !*end && v >= 1 && v <= 65535) ? (int)v : -1;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [-b ADDR] [-t TCP_PORT] [-u UDP_PORT] [-l CSV_FILE] [-q]\n"
            "  -b ADDR   IPv4 address to bind                   (default 0.0.0.0)\n"
            "  -t PORT   TCP port: registration, commands, reliable telemetry (default %d)\n"
            "  -u PORT   UDP port: lightweight periodic telemetry             (default %d)\n"
            "  -l FILE   append telemetry to FILE as CSV  (default telemetry.csv, '-' = off)\n"
            "  -q        quiet: do not print every telemetry packet\n",
            prog, DEFAULT_PORT, DEFAULT_PORT);
}

int main(int argc, char **argv) {
    mux_event_t evs[MAX_EVENTS];
    uint64_t next_tick;
    size_t fdlim;
    int opt;

    while ((opt = getopt(argc, argv, "b:t:u:l:qh")) != -1) {
        switch (opt) {
        case 'b': snprintf(cfg.bind_addr, sizeof cfg.bind_addr, "%s", optarg); break;
        case 't': if ((cfg.tcp_port = parse_port(optarg)) < 0) { usage(argv[0]); return 2; } break;
        case 'u': if ((cfg.udp_port = parse_port(optarg)) < 0) { usage(argv[0]); return 2; } break;
        case 'l': cfg.csv_path = optarg; break;
        case 'q': cfg.quiet = 1; break;
        default:  usage(argv[0]); return opt == 'h' ? 0 : 2;
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    install_signals();
    fdlim = raise_fd_limit();
    cfg.max_conns = fdlim > 64 ? fdlim - 32 : 32;

    if (strcmp(cfg.csv_path, "-") != 0) {
        struct stat st;
        int fresh = stat(cfg.csv_path, &st) != 0 || st.st_size == 0;
        if (!(g_csv = fopen(cfg.csv_path, "a"))) { fprintf(stderr, "%s: %s\n", cfg.csv_path, strerror(errno)); return 1; }
        setvbuf(g_csv, NULL, _IOLBF, 0);
        if (fresh)
            fputs("recv_ms,device_id,transport,seq,device_ts_ms,temp_c,humidity_pct,battery_pct,"
                  "alert_level,status,interval_ms\n", g_csv);
    }

    if ((g_tcp_fd = make_socket(SOCK_STREAM, cfg.bind_addr, cfg.tcp_port)) < 0) return 1;
    if ((g_udp_fd = make_socket(SOCK_DGRAM, cfg.bind_addr, cfg.udp_port)) < 0) return 1;
    if (mux_init() < 0 || mux_add(g_tcp_fd, 0) < 0 || mux_add(g_udp_fd, 0) < 0) {
        fprintf(stderr, "cannot initialise I/O multiplexer: %s\n", strerror(errno));
        return 1;
    }
    g_console = mux_add(STDIN_FILENO, 0) == 0;       /* fails harmlessly if stdin cannot be polled */

    LOG("INFO", "gateway up: TCP %s:%d  UDP %s:%d  mux=%s  max_sessions=%zu  csv=%s", cfg.bind_addr,
        cfg.tcp_port, cfg.bind_addr, cfg.udp_port, mux_name(), cfg.max_conns,
        g_csv ? cfg.csv_path : "off");
    if (g_console) puts("type 'help' for console commands, Ctrl-C to stop");

    next_tick = now_mono_ms() + TICK_MS;
    while (g_running) {
        uint64_t now = now_mono_ms();
        int timeout = next_tick > now ? (int)(next_tick - now) : 0;
        int n = mux_wait(evs, MAX_EVENTS, timeout);

        if (n < 0) {
            if (errno == EINTR) continue;
            LOG("ERROR", "event wait failed: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; i++) {
            int fd = evs[i].fd;
            if (fd == g_tcp_fd) {
                on_listen_readable();
            } else if (fd == g_udp_fd) {
                on_udp_readable();
            } else if (fd == STDIN_FILENO) {
                if (g_console) on_stdin_readable();
            } else if (fd >= 0 && fd < FD_LIMIT && g_conns[fd] && !g_conns[fd]->closing) {
                conn_t *c = g_conns[fd];
                if (evs[i].flags & (MUX_IN | MUX_ERR)) on_conn_readable(c);
                if (!c->closing && (evs[i].flags & MUX_OUT)) conn_flush(c);
            }
        }
        reap_closed();
        now = now_mono_ms();
        if (now >= next_tick) {
            housekeeping(now);
            reap_closed();
            next_tick = now + TICK_MS;
        }
    }

    LOG("INFO", "shutting down");
    print_stats();
    reap_closed();
    for (int fd = 0; fd <= g_maxfd; fd++)
        if (g_conns[fd]) { close(fd); free(g_conns[fd]); g_conns[fd] = NULL; }
    for (size_t i = 0; i < DEV_TABLE_SIZE; i++) free(g_devtab[i]);
    close(g_tcp_fd);
    close(g_udp_fd);
    mux_close();
    if (g_csv) fclose(g_csv);
    return 0;
}
