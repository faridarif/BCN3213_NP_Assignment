/*
 * node.c - IoT Sensor Node (device simulator)
 *
 * Simulates a temperature / humidity / battery node and talks to the
 * monitoring gateway using the hybrid TCP + UDP protocol from smart_proto.h.
 *
 * MODES (-m)
 *   hybrid  (default) TCP session for registration, heartbeats and commands;
 *           periodic readings go out as lightweight UDP datagrams.  While a
 *           local alarm is active, readings switch to TCP (reliable delivery
 *           matters most during an incident).
 *   tcp     everything over the TCP session.
 *   udp     everything over UDP (commands arrive as UDP replies).
 *
 * ENCODING (-f)  auto (default): UDP = packed binary struct, TCP = JSON.
 *                bin / json force one encoding on both channels.
 *
 * ROBUSTNESS
 *   - one poll() loop, non-blocking sockets, queued TCP writes
 *   - non-blocking connect with timeout; automatic reconnect with exponential
 *     back-off (UDP readings keep flowing in hybrid mode while TCP is down)
 *   - malformed frames from the gateway are skipped, never fatal
 *   - SIGINT / SIGTERM / SHUTDOWN command: flush, close, exit cleanly
 */
#define _POSIX_C_SOURCE 200809L
#include "smart_proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FW_VERSION            0x0100u         /* 1.0 */
#define CONNECT_TIMEOUT_MS    3000u
#define BACKOFF_MIN_MS        1000u
#define BACKOFF_MAX_MS        10000u
#define RX_BUF_SIZE           2048
#define LOW_BATTERY_PCT       15
#define FIRST_REPORT_DELAY_MS 250u            /* let the TCP handshake + HELLO go first */

typedef enum { MODE_TCP, MODE_UDP, MODE_HYBRID } run_mode_t;
typedef enum { CH_TCP = 0, CH_UDP = 1 } chan_t;
typedef enum { LINK_DOWN, LINK_CONNECTING, LINK_UP } link_state_t;

static struct {
    uint32_t    id;
    const char *host;
    int         tcp_port, udp_port;
    run_mode_t  mode;
    uint8_t     tcp_enc, udp_enc;
    uint32_t    interval_ms;                  /* configured (base) reporting period */
    unsigned    event_every;                  /* force a heat event every N readings (0 = random) */
    unsigned    max_reports;                  /* stop after N readings (0 = never) */
    int         battery, humidity;
} cfg = { 1001, "127.0.0.1", 9000, 9000, MODE_HYBRID, ENC_JSON, ENC_BINARY, 3000, 0, 0, 100, 55 };

static struct {                               /* device state the gateway can change */
    uint32_t interval_ms;                     /* SET_INTERVAL */
    uint8_t  alert_level;                     /* ALERT_TRIGGER / ALERT_CLEAR */
    int      shutdown;                        /* SHUTDOWN */
    uint64_t last_tx_ms, next_tx_ms;
    uint32_t tel_seq[2];                      /* telemetry counters, per channel */
    uint32_t misc_seq;                        /* everything else */
    unsigned reports, dropped;
} node;

static struct { double temp, hum, base_temp, heat_amp; int heat_left; unsigned samples; } sim;

static struct sockaddr_in g_srv_tcp, g_srv_udp;
static int            g_tcp = -1, g_udp = -1;
static link_state_t   g_link = LINK_DOWN;
static uint64_t       g_next_connect_ms, g_connect_deadline_ms, g_next_hb_ms;
static uint32_t       g_backoff_ms = BACKOFF_MIN_MS, g_hb_ms = 10000;
static uint8_t        g_rx[RX_BUF_SIZE];
static size_t         g_rx_len;
static outbuf_t       g_txq;
static volatile sig_atomic_t g_running = 1;

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
    printf("%s.%03ld [dev %u] %-5s ", hms, ts.tv_nsec / 1000000L, (unsigned)cfg.id, tag);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}
#define LOG(tag, ...) logmsg(tag, __VA_ARGS__)

/* Sensor simulation */
static double frand(void) { return rand() / ((double)RAND_MAX + 1.0); }

static void sim_init(void) {
    sim.base_temp = 22.0 + (double)(cfg.id % 5);     /* each node sits at a slightly different temperature */
    sim.temp = sim.base_temp;
    sim.hum = cfg.humidity;
}

/* One step of the physical model: temperature chases a target that jumps up
 * during a "heat event"; a CRITICAL alarm engages cooling and ends the event. */
static void sim_step(void) {
    double target = sim.base_temp;
    int trigger;

    sim.samples++;
    trigger = cfg.event_every ? (sim.samples % cfg.event_every == 0) : (frand() < 0.02);
    if (trigger && sim.heat_left == 0 && node.alert_level == 0) {
        sim.heat_left = 8 + rand() % 5;
        sim.heat_amp = 8.0 + frand() * 9.0;
        LOG("SIM", "heat source ON  (+%.1f C for %d readings)", sim.heat_amp, sim.heat_left);
    }
    if (node.alert_level >= 2 && sim.heat_left > 0) {
        sim.heat_left = 0;
        LOG("SIM", "cooling engaged by critical alarm - heat source OFF");
    }
    if (sim.heat_left > 0) { target += sim.heat_amp; sim.heat_left--; }

    sim.temp += (target - sim.temp) * 0.45 + (frand() - 0.5) * 0.3;
    sim.hum  += ((double)cfg.humidity - sim.hum) * 0.10 + (frand() - 0.5) * 1.0;
    if (sim.hum < 5.0)  sim.hum = 5.0;
    if (sim.hum > 99.0) sim.hum = 99.0;
}

static void sensor_read(telemetry_msg_t *t) {
    int batt;

    sim_step();
    batt = cfg.battery - (int)(sim.samples / 20);    /* drains 1 % every 20 readings */
    if (batt < 0) batt = 0;

    t->device_id = cfg.id;
    t->timestamp_ms = now_real_ms();
    t->temperature_c100 = (int16_t)(sim.temp * 100.0 + (sim.temp < 0 ? -0.5 : 0.5));
    t->humidity_pct100 = (uint16_t)(sim.hum * 100.0 + 0.5);
    t->battery_pct = (uint8_t)batt;
    t->alert_level = node.alert_level;
    t->status_flags = (uint16_t)((batt <= LOW_BATTERY_PCT ? ST_LOW_BATTERY : 0u) |
                                 (node.alert_level ? ST_ALARM_ACTIVE : 0u));
    t->interval_ms = node.interval_ms;
}

/* Networking */
static int resolve_server(void) {
    struct addrinfo hints, *res = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    rc = getaddrinfo(cfg.host, NULL, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "cannot resolve '%s': %s\n", cfg.host, gai_strerror(rc));
        return -1;
    }
    memcpy(&g_srv_tcp, res->ai_addr, sizeof g_srv_tcp);
    g_srv_udp = g_srv_tcp;
    g_srv_tcp.sin_port = htons((uint16_t)cfg.tcp_port);
    g_srv_udp.sin_port = htons((uint16_t)cfg.udp_port);
    freeaddrinfo(res);
    return 0;
}

static int udp_open(void) {
    /* connect() on a UDP socket only sets the default peer: we can use send()/recv()
     * and the kernel discards datagrams from anyone else. */
    g_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp < 0 || connect(g_udp, (struct sockaddr *)&g_srv_udp, sizeof g_srv_udp) < 0 ||
        net_set_nonblocking(g_udp) < 0) {
        LOG("ERROR", "UDP socket setup failed: %s", strerror(errno));
        if (g_udp >= 0) close(g_udp);
        g_udp = -1;
        return -1;
    }
    return 0;
}

static void tcp_fail(const char *why);
static int  tcp_flush(void);

/* Encode one message and send it on the chosen channel. Returns frame length or -1. */
static int send_msg(chan_t ch, uint8_t enc, uint8_t type, const void *msg) {
    uint8_t buf[PROTO_MAX_FRAME];
    uint32_t seq = (type == MSG_TELEMETRY) ? node.tel_seq[ch]++ : node.misc_seq++;
    int n = proto_pack(buf, sizeof buf, type, enc, seq, msg);

    if (n < 0) { LOG("ERROR", "cannot encode %s", msg_type_name(type)); return -1; }
    if (ch == CH_UDP) {
        static int warned;
        if (g_udp < 0) return -1;
        if (send(g_udp, buf, (size_t)n, 0) < 0) {
            if (errno == ECONNREFUSED && !warned) { warned = 1; LOG("WARN", "gateway UDP port not reachable (will keep trying)"); }
            return -1;
        }
        warned = 0;
        return n;
    }
    if (g_link != LINK_UP) return -1;
    if (outbuf_append(&g_txq, buf, (size_t)n) < 0) { tcp_fail("transmit queue overflow"); return -1; }
    return tcp_flush() < 0 ? -1 : n;
}

static void send_hello(chan_t ch) {
    hello_msg_t h;
    h.device_id = cfg.id;
    h.fw_version = (uint16_t)FW_VERSION;
    h.interval_ms = cfg.interval_ms;
    send_msg(ch, ch == CH_TCP ? cfg.tcp_enc : cfg.udp_enc, MSG_HELLO, &h);
}

/* TCP link state machine: DOWN -> CONNECTING -> UP -> (failure) -> DOWN */
static void tcp_schedule_retry(uint64_t now) {
    g_next_connect_ms = now + g_backoff_ms;
    LOG("WARN", "TCP link down - retry in %u ms", (unsigned)g_backoff_ms);
    g_backoff_ms = g_backoff_ms * 2 > BACKOFF_MAX_MS ? BACKOFF_MAX_MS : g_backoff_ms * 2;
}

static void tcp_fail(const char *why) {
    LOG("WARN", "TCP: %s", why);
    if (g_tcp >= 0) close(g_tcp);
    g_tcp = -1;
    g_link = LINK_DOWN;
    g_rx_len = 0;
    g_txq.head = g_txq.tail = 0;
    tcp_schedule_retry(now_mono_ms());
}

static int tcp_flush(void) {
    if (g_link != LINK_UP) return -1;
    if (outbuf_flush(&g_txq, g_tcp) < 0) { tcp_fail(strerror(errno)); return -1; }
    return 0;
}

static void tcp_connected(uint64_t now) {
    int one = 1;

    setsockopt(g_tcp, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    g_link = LINK_UP;
    g_rx_len = 0;
    g_txq.head = g_txq.tail = 0;
    g_backoff_ms = BACKOFF_MIN_MS;
    g_next_hb_ms = now + g_hb_ms;
    LOG("INFO", "TCP connected to %s:%d", cfg.host, cfg.tcp_port);
    send_hello(CH_TCP);
}

static void tcp_start_connect(uint64_t now) {
    g_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (g_tcp < 0) { LOG("ERROR", "socket: %s", strerror(errno)); tcp_schedule_retry(now); return; }
    net_set_nonblocking(g_tcp);
    if (connect(g_tcp, (struct sockaddr *)&g_srv_tcp, sizeof g_srv_tcp) == 0) {
        tcp_connected(now);
    } else if (errno == EINPROGRESS) {
        g_link = LINK_CONNECTING;
        g_connect_deadline_ms = now + CONNECT_TIMEOUT_MS;
    } else {
        tcp_fail(strerror(errno));
    }
}

/* Handling what the gateway sends us */
static void handle_command(const command_msg_t *c, chan_t ch, uint8_t enc, uint64_t now) {
    uint8_t status = ACK_OK;
    cmd_ack_msg_t ack;

    LOG("CMD", "<- %s arg=%u (id %u) via %s", cmd_name(c->cmd), (unsigned)c->arg, (unsigned)c->cmd_id,
        ch == CH_TCP ? "TCP" : "UDP");
    switch (c->cmd) {
    case CMD_SET_INTERVAL:
        if (c->arg < MIN_INTERVAL_MS || c->arg > MAX_INTERVAL_MS) { status = ACK_BAD_ARG; break; }
        node.interval_ms = c->arg;
        node.next_tx_ms = node.last_tx_ms + node.interval_ms;         /* may already be due */
        LOG("INFO", "reporting interval is now %u ms", (unsigned)node.interval_ms);
        break;
    case CMD_ALERT_TRIGGER:
        if (c->arg < 1 || c->arg > 2) { status = ACK_BAD_ARG; break; }
        node.alert_level = (uint8_t)c->arg;
        LOG("ALARM", "*** LOCAL ALARM ON - %s ***",
            c->arg == 2 ? "CRITICAL: siren + red LED" : "WARNING: amber LED");
        break;
    case CMD_ALERT_CLEAR:
        if (node.alert_level) LOG("ALARM", "local alarm cleared");
        node.alert_level = 0;
        break;
    case CMD_REPORT_NOW:
        node.next_tx_ms = now;
        break;
    case CMD_SHUTDOWN:
        node.shutdown = 1;
        LOG("INFO", "shutdown requested by gateway");
        break;
    default:
        status = ACK_UNSUPPORTED;
        break;
    }
    ack.device_id = cfg.id;
    ack.cmd_id = c->cmd_id;
    ack.cmd = c->cmd;
    ack.status = status;
    send_msg(ch, enc, MSG_COMMAND_ACK, &ack);             /* answer on the channel it arrived on */
}

static void dispatch(const frame_t *fr, chan_t ch) {
    switch (fr->type) {
    case MSG_HELLO_ACK: {
        hello_ack_msg_t a;
        if (msg_decode(MSG_HELLO_ACK, fr->encoding, fr->payload, fr->payload_len, &a) == 0) {
            if (a.heartbeat_ms >= 1000 && a.heartbeat_ms <= 600000) g_hb_ms = a.heartbeat_ms;
            g_next_hb_ms = now_mono_ms() + g_hb_ms;
            LOG("INFO", "registered with gateway (heartbeat every %u ms)", (unsigned)g_hb_ms);
        }
        break;
    }
    case MSG_COMMAND: {
        command_msg_t c;
        if (msg_decode(MSG_COMMAND, fr->encoding, fr->payload, fr->payload_len, &c) == 0)
            handle_command(&c, ch, fr->encoding, now_mono_ms());
        else
            LOG("WARN", "malformed COMMAND payload ignored");
        break;
    }
    case MSG_ERROR: {
        error_msg_t e;
        if (msg_decode(MSG_ERROR, fr->encoding, fr->payload, fr->payload_len, &e) == 0)
            LOG("WARN", "gateway reported error: %s", err_name(e.code));
        break;
    }
    case MSG_HEARTBEAT:
        break;
    default:
        LOG("WARN", "unexpected %s from gateway ignored", msg_type_name(fr->type));
        break;
    }
}

static void tcp_readable(void) {
    size_t off = 0;
    ssize_t n = recv(g_tcp, g_rx + g_rx_len, sizeof g_rx - g_rx_len, 0);

    if (n == 0) { tcp_fail("gateway closed the connection"); return; }
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) tcp_fail(strerror(errno));
        return;
    }
    g_rx_len += (size_t)n;
    while (off < g_rx_len) {                              /* re-assemble frames from the byte stream */
        frame_t fr;
        size_t flen = 0;
        frame_status_t st = frame_parse(g_rx + off, g_rx_len - off, &fr, &flen);

        if (st == FRAME_INCOMPLETE) break;
        if (st == FRAME_OK) {
            dispatch(&fr, CH_TCP);
            if (g_link != LINK_UP) return;                /* an ack failed to send: link was reset */
            off += flen;
            continue;
        }
        LOG("WARN", "malformed frame from gateway (%s) - resynchronising", frame_status_name(st));
        off += frame_resync(g_rx + off, g_rx_len - off);
    }
    if (off) { memmove(g_rx, g_rx + off, g_rx_len - off); g_rx_len -= off; }
    if (g_rx_len == sizeof g_rx) g_rx_len = 0;            /* cannot happen with valid frames; never wedge */
}

static void udp_readable(void) {
    uint8_t buf[PROTO_MAX_FRAME + 16];

    for (int i = 0; i < 16; i++) {
        frame_t fr;
        size_t flen = 0;
        frame_status_t st;
        ssize_t n = recv(g_udp, buf, sizeof buf, 0);

        if (n < 0) {
            if (errno == EINTR) continue;
            break;                                         /* EAGAIN, or ICMP refused: nothing to read */
        }
        st = frame_parse(buf, (size_t)n, &fr, &flen);
        if (st != FRAME_OK || flen != (size_t)n) {
            LOG("WARN", "malformed datagram from gateway (%s) ignored", st == FRAME_OK ? "trailing bytes" : frame_status_name(st));
            continue;
        }
        dispatch(&fr, CH_UDP);
    }
}

/* Periodic work */
static void send_telemetry(uint64_t now) {
    telemetry_msg_t t;
    chan_t ch;
    char tb[16], hb[16];
    int n;

    switch (cfg.mode) {
    case MODE_TCP: ch = CH_TCP; break;
    case MODE_UDP: ch = CH_UDP; break;
    default:       ch = (node.alert_level > 0 && g_link == LINK_UP) ? CH_TCP : CH_UDP; break;
    }
    sensor_read(&t);
    node.last_tx_ms = now;
    node.next_tx_ms = now + node.interval_ms;
    node.reports++;

    n = send_msg(ch, ch == CH_TCP ? cfg.tcp_enc : cfg.udp_enc, MSG_TELEMETRY, &t);
    if (n < 0) {
        node.dropped++;
        LOG("WARN", "%s unavailable - reading dropped", ch == CH_TCP ? "TCP link" : "UDP socket");
        return;
    }
    proto_fmt_fx2(tb, sizeof tb, t.temperature_c100);
    proto_fmt_fx2(hb, sizeof hb, t.humidity_pct100);
    LOG("TX", "%s #%u temp=%sC hum=%s%% batt=%u%% alarm=%u every=%ums  [%s, %d B]",
        ch == CH_TCP ? "TCP" : "UDP", (unsigned)(node.tel_seq[ch] - 1), tb, hb, (unsigned)t.battery_pct,
        (unsigned)t.alert_level, (unsigned)t.interval_ms,
        (ch == CH_TCP ? cfg.tcp_enc : cfg.udp_enc) == ENC_JSON ? "json" : "bin", n);
}

static uint64_t next_wakeup(void) {
    uint64_t t = node.next_tx_ms;
    if (g_link == LINK_UP && g_next_hb_ms < t) t = g_next_hb_ms;
    if (g_link == LINK_DOWN && cfg.mode != MODE_UDP && g_next_connect_ms < t) t = g_next_connect_ms;
    if (g_link == LINK_CONNECTING && g_connect_deadline_ms < t) t = g_connect_deadline_ms;
    return t;
}

static void tcp_event(short revents, uint64_t now) {
    if (g_link == LINK_CONNECTING) {
        if (revents & (POLLOUT | POLLERR | POLLHUP)) {
            int err = 0;
            socklen_t el = sizeof err;
            if (getsockopt(g_tcp, SOL_SOCKET, SO_ERROR, &err, &el) < 0) err = errno;
            if (err == 0) tcp_connected(now);
            else          tcp_fail(strerror(err));
        }
        return;
    }
    if (revents & (POLLIN | POLLERR | POLLHUP)) {
        tcp_readable();
        if (g_link != LINK_UP) return;
    }
    if (revents & POLLOUT) tcp_flush();
}

static void graceful_close(void) {
    if (g_link == LINK_UP) {                               /* give queued bytes (e.g. the SHUTDOWN ack) a moment */
        uint64_t deadline = now_mono_ms() + 1000;
        while (g_link == LINK_UP && outbuf_pending(&g_txq) > 0 && now_mono_ms() < deadline) {
            struct pollfd p = { g_tcp, POLLOUT, 0 };
            if (poll(&p, 1, 100) > 0 && tcp_flush() < 0) break;
        }
        if (g_link == LINK_UP) shutdown(g_tcp, SHUT_WR);
    }
    if (g_tcp >= 0) close(g_tcp);
    if (g_udp >= 0) close(g_udp);
    g_tcp = g_udp = -1;
}

/* Command line */
static void usage(void) {
    fputs("usage: sensor_node [options]\n"
          "  -i ID      device id                              (default 1001)\n"
          "  -s HOST    gateway host or IPv4 address           (default 127.0.0.1)\n"
          "  -t PORT    gateway TCP port                       (default 9000)\n"
          "  -u PORT    gateway UDP port                       (default 9000)\n"
          "  -m MODE    tcp | udp | hybrid                     (default hybrid)\n"
          "  -f FORMAT  auto | bin | json   (auto: UDP=bin, TCP=json)\n"
          "  -I MS      reporting interval                     (default 3000)\n"
          "  -n COUNT   stop after COUNT readings              (default 0 = run until stopped)\n"
          "  -e N       force a heat event every N readings    (default 0 = random)\n"
          "  -H PCT     baseline humidity                      (default 55)\n"
          "  -B PCT     initial battery level                  (default 100)\n", stderr);
}

static unsigned long arg_num(const char *s, unsigned long lo, unsigned long hi, const char *what) {
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (!*s || *end || v < lo || v > hi) {
        fprintf(stderr, "invalid %s '%s' (expected %lu..%lu)\n", what, s, lo, hi);
        exit(2);
    }
    return v;
}

static void on_signal(int sig) { (void)sig; g_running = 0; }

int main(int argc, char **argv) {
    struct sigaction sa;
    uint64_t now;
    int opt;

    while ((opt = getopt(argc, argv, "i:s:t:u:m:f:I:n:e:H:B:h")) != -1) {
        switch (opt) {
        case 'i': cfg.id = (uint32_t)arg_num(optarg, 1, UINT32_MAX, "device id"); break;
        case 's': cfg.host = optarg; break;
        case 't': cfg.tcp_port = (int)arg_num(optarg, 1, 65535, "TCP port"); break;
        case 'u': cfg.udp_port = (int)arg_num(optarg, 1, 65535, "UDP port"); break;
        case 'm':
            if      (!strcasecmp(optarg, "tcp"))    cfg.mode = MODE_TCP;
            else if (!strcasecmp(optarg, "udp"))    cfg.mode = MODE_UDP;
            else if (!strcasecmp(optarg, "hybrid")) cfg.mode = MODE_HYBRID;
            else { usage(); return 2; }
            break;
        case 'f':
            if      (!strcasecmp(optarg, "bin"))  cfg.tcp_enc = cfg.udp_enc = ENC_BINARY;
            else if (!strcasecmp(optarg, "json")) cfg.tcp_enc = cfg.udp_enc = ENC_JSON;
            else if (strcasecmp(optarg, "auto"))  { usage(); return 2; }
            break;
        case 'I': cfg.interval_ms = (uint32_t)arg_num(optarg, MIN_INTERVAL_MS, MAX_INTERVAL_MS, "interval"); break;
        case 'n': cfg.max_reports = (unsigned)arg_num(optarg, 0, 100000000, "count"); break;
        case 'e': cfg.event_every = (unsigned)arg_num(optarg, 0, 100000, "event period"); break;
        case 'H': cfg.humidity = (int)arg_num(optarg, 5, 99, "humidity"); break;
        case 'B': cfg.battery = (int)arg_num(optarg, 0, 100, "battery"); break;
        default:  usage(); return opt == 'h' ? 0 : 2;
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned)time(NULL) ^ ((unsigned)getpid() << 8) ^ cfg.id);

    if (resolve_server() < 0) return 1;
    sim_init();

    now = now_mono_ms();
    node.interval_ms = cfg.interval_ms;
    node.last_tx_ms = now;
    node.next_tx_ms = now + FIRST_REPORT_DELAY_MS;
    node.tel_seq[CH_TCP] = node.tel_seq[CH_UDP] = node.misc_seq = 1;
    g_next_connect_ms = now;

    LOG("INFO", "starting: gateway=%s tcp=%d udp=%d mode=%s interval=%ums tcp-fmt=%s udp-fmt=%s", cfg.host,
        cfg.tcp_port, cfg.udp_port, cfg.mode == MODE_TCP ? "tcp" : cfg.mode == MODE_UDP ? "udp" : "hybrid",
        (unsigned)cfg.interval_ms, cfg.tcp_enc == ENC_JSON ? "json" : "bin", cfg.udp_enc == ENC_JSON ? "json" : "bin");

    if (cfg.mode != MODE_TCP) {
        if (udp_open() < 0) return 1;
        if (cfg.mode == MODE_UDP) send_hello(CH_UDP);      /* no TCP session to register on */
    }

    while (g_running && !node.shutdown) {
        struct pollfd pfd[2];
        int np = 0, itcp = -1, iudp = -1, timeout, r;
        uint64_t wake;

        now = now_mono_ms();
        if (cfg.mode != MODE_UDP) {
            if (g_link == LINK_DOWN && now >= g_next_connect_ms) tcp_start_connect(now);
            if (g_link == LINK_CONNECTING && now >= g_connect_deadline_ms) tcp_fail("connect timed out");
        }
        if (g_tcp >= 0) {
            itcp = np;
            pfd[np].fd = g_tcp;
            pfd[np].events = (short)(POLLIN | ((g_link == LINK_CONNECTING || outbuf_pending(&g_txq)) ? POLLOUT : 0));
            pfd[np++].revents = 0;
        }
        if (g_udp >= 0) {
            iudp = np;
            pfd[np].fd = g_udp;
            pfd[np].events = POLLIN;
            pfd[np++].revents = 0;
        }

        wake = next_wakeup();
        timeout = wake <= now ? 0 : (wake - now > 1000 ? 1000 : (int)(wake - now));
        r = poll(pfd, (nfds_t)np, timeout);
        if (r < 0 && errno != EINTR) { LOG("ERROR", "poll: %s", strerror(errno)); break; }

        now = now_mono_ms();
        if (r > 0) {
            if (itcp >= 0 && pfd[itcp].revents) tcp_event(pfd[itcp].revents, now);
            if (iudp >= 0 && pfd[iudp].revents) udp_readable();
        }
        if (node.shutdown) break;

        if (now >= node.next_tx_ms) {
            send_telemetry(now);
            if (cfg.max_reports && node.reports >= cfg.max_reports) break;
        }
        if (g_link == LINK_UP && now >= g_next_hb_ms) {
            send_msg(CH_TCP, cfg.tcp_enc, MSG_HEARTBEAT, NULL);
            g_next_hb_ms = now + g_hb_ms;
        }
    }

    graceful_close();
    LOG("INFO", "stopped after %u readings (%u dropped)", node.reports, node.dropped);
    return 0;
}
