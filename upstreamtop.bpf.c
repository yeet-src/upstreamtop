#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* upstreamtop — which backends nginx proxy_passes to, and the RPS of
 * each. nginx's upstream leg is plain HTTP, so we read it straight off
 * the wire with a pair of TC programs:
 *
 *   tcx/egress  — a TCP segment that starts with an HTTP method is a
 *                 request nginx is sending to a backend. The dest
 *                 IP:port IS the upstream endpoint. Count it, keyed by
 *                 (backend, request path).
 *   tcx/ingress — a segment that starts with "HTTP/" is a backend's
 *                 response. Match it back to the request via the
 *                 4-tuple to attribute status code and latency.
 *
 * No nginx symbols, no config changes, no log parsing. Direction does
 * the client-vs-upstream separation for free: client→nginx requests
 * arrive on ingress (skipped by the "HTTP/" check) and nginx→client
 * responses leave on egress (skipped by the method check). */

#define ROUTE_LEN 32     /* bytes of request path kept per route key */
#define BUFSZ     64      /* payload bytes pulled for the request/status line */
#define MAX_METHOD_OFF 8  /* longest method token + space ("OPTIONS ") */

#define M_GET     1
#define M_POST    2
#define M_PUT     3
#define M_DELETE  4
#define M_HEAD    5
#define M_PATCH   6
#define M_OPTIONS 7

/* Live toggle in .data, flipped from JS via DataSec.patch() on teardown. */
volatile __u32 enabled = 1;

struct route_key {
    __u32 backend_addr;          /* network byte order */
    __u16 backend_port;          /* host byte order (for display) */
    __u8  path[ROUTE_LEN];       /* request path, NUL-padded */
};

struct route_stat {
    __u64 requests;
    __u64 resp_2xx;
    __u64 resp_3xx;
    __u64 resp_4xx;
    __u64 resp_5xx;
    __u64 lat_ns_sum;
    __u64 lat_cnt;
};

/* Bridges a request to its response. Keyed by the connection 4-tuple so
 * the ingress handler can recover which (backend, route) a response
 * belongs to and stamp its latency. */
struct conn_key {
    __u32 backend_addr;
    __u32 client_addr;
    __u16 backend_port;
    __u16 client_port;
};

struct conn_req {
    __u64 ts;
    struct route_key rk;
};

struct req_event {
    __u32 backend_addr;
    __u16 backend_port;
    __u8  method;
    __u8  path[ROUTE_LEN];
};

/* clang drops BTF for a type only reached through a local pointer (how
 * bpf_ringbuf_reserve gets typed). Anchor it in a __used global so the
 * `btf_struct` ring-buf bind can find it by name. */
__attribute__((used)) static const struct req_event __req_event_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_key);
    __type(value, struct route_stat);
    __uint(max_entries, 8192);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct conn_key);
    __type(value, struct conn_req);
    __uint(max_entries, 16384);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

/* Locate the IPv4 header: Ethernet (l3 at 14) or a bare IP packet on a
 * loopback/tunnel device (l3 at 0). Returns the L3 offset or -1. */
static __always_inline int l3_offset(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP)) {
        __u8 *v = (void *)(eth + 1);
        if ((void *)(v + 1) <= data_end && (*v >> 4) == 4)
            return ETH_HLEN;
    }
    __u8 *v = data;
    if ((void *)(v + 1) <= data_end && (*v >> 4) == 4)
        return 0;
    return -1;
}

/* Identify the HTTP method at the start of `b` and return its token
 * length including the trailing space (so the path starts at b+len).
 * Returns 0 if `b` is not an HTTP request line. */
static __always_inline __u32 parse_method(const __u8 *b, __u8 *method)
{
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') {
        *method = M_GET; return 4;
    }
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') {
        *method = M_POST; return 5;
    }
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ') {
        *method = M_PUT; return 4;
    }
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ') {
        *method = M_HEAD; return 5;
    }
    if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' &&
        b[4] == 'T' && b[5] == 'E' && b[6] == ' ') {
        *method = M_DELETE; return 7;
    }
    if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' &&
        b[4] == 'H' && b[5] == ' ') {
        *method = M_PATCH; return 6;
    }
    if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' &&
        b[4] == 'O' && b[5] == 'N' && b[6] == 'S' && b[7] == ' ') {
        *method = M_OPTIONS; return 8;
    }
    return 0;
}

/* Compute the payload offset and pull BUFSZ bytes into `buf`. Returns 0
 * on success, or a negative value if the packet has no TCP payload of
 * at least BUFSZ bytes (short last segments are skipped — the request
 * and status lines we care about live in a full first segment). */
static __always_inline int load_payload(struct __sk_buff *skb,
                                         struct iphdr *ip, int l3,
                                         struct tcphdr **tcp_out, __u8 *buf)
{
    void *data_end = (void *)(long)skb->data_end;

    __u32 ip_hl = ip->ihl * 4;
    if (ip_hl < sizeof(struct iphdr))
        return -1;

    struct tcphdr *tcp = (void *)ip + ip_hl;
    if ((void *)(tcp + 1) > data_end)
        return -1;

    __u32 tcp_hl = tcp->doff * 4;
    if (tcp_hl < sizeof(struct tcphdr))
        return -1;

    __u32 poff = l3 + ip_hl + tcp_hl;
    if (poff + BUFSZ > skb->len)
        return -1;

    if (bpf_skb_load_bytes(skb, poff, buf, BUFSZ) < 0)
        return -1;

    *tcp_out = tcp;
    return 0;
}

/* Copy the request path into `dst`, stopping at the first space, '?',
 * CR/LF, or NUL. `dst` is pre-zeroed by the caller. */
static __always_inline void copy_path(const __u8 *b, __u32 off, __u8 *dst)
{
    if (off > MAX_METHOD_OFF)
        return;
#pragma unroll
    for (int i = 0; i < ROUTE_LEN; i++) {
        __u32 idx = (off + i) & (BUFSZ - 1);
        __u8 c = b[idx];
        if (c == ' ' || c == '?' || c == '\r' || c == '\n' || c == 0)
            break;
        dst[i] = c;
    }
}

SEC("tcx/egress")
int on_request(struct __sk_buff *skb)
{
    if (!enabled)
        return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    int l3 = l3_offset(data, data_end);
    if (l3 < 0)
        return TC_ACT_OK;

    struct iphdr *ip = data + l3;
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp;
    __u8 buf[BUFSZ];
    if (load_payload(skb, ip, l3, &tcp, buf) < 0)
        return TC_ACT_OK;

    __u8 method = 0;
    __u32 off = parse_method(buf, &method);
    if (off == 0)
        return TC_ACT_OK;

    struct route_key rk;
    __builtin_memset(&rk, 0, sizeof(rk));
    rk.backend_addr = ip->daddr;
    rk.backend_port = bpf_ntohs(tcp->dest);
    copy_path(buf, off, rk.path);

    struct route_stat *st = bpf_map_lookup_elem(&stats, &rk);
    if (st) {
        __sync_fetch_and_add(&st->requests, 1);
    } else {
        struct route_stat fresh = {};
        fresh.requests = 1;
        bpf_map_update_elem(&stats, &rk, &fresh, BPF_NOEXIST);
    }

    /* Remember this request so the response can be attributed back. */
    struct conn_key ck;
    __builtin_memset(&ck, 0, sizeof(ck));
    ck.backend_addr = ip->daddr;
    ck.client_addr  = ip->saddr;
    ck.backend_port = tcp->dest;
    ck.client_port  = tcp->source;

    struct conn_req cr;
    __builtin_memset(&cr, 0, sizeof(cr));
    cr.ts = bpf_ktime_get_ns();
    cr.rk = rk;
    bpf_map_update_elem(&inflight, &ck, &cr, BPF_ANY);

    struct req_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->backend_addr = rk.backend_addr;
        e->backend_port = rk.backend_port;
        e->method       = method;
        __builtin_memcpy(e->path, rk.path, ROUTE_LEN);
        bpf_ringbuf_submit(e, 0);
    }

    return TC_ACT_OK;
}

SEC("tcx/ingress")
int on_response(struct __sk_buff *skb)
{
    if (!enabled)
        return TC_ACT_OK;

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    int l3 = l3_offset(data, data_end);
    if (l3 < 0)
        return TC_ACT_OK;

    struct iphdr *ip = data + l3;
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp;
    __u8 buf[BUFSZ];
    if (load_payload(skb, ip, l3, &tcp, buf) < 0)
        return TC_ACT_OK;

    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' ||
        buf[3] != 'P' || buf[4] != '/')
        return TC_ACT_OK;

    /* Status code sits at a fixed offset for HTTP/1.x: "HTTP/1.1 NNN". */
    __u8 d0 = buf[9], d1 = buf[10], d2 = buf[11];
    if (d0 < '0' || d0 > '9' || d1 < '0' || d1 > '9' || d2 < '0' || d2 > '9')
        return TC_ACT_OK;
    __u32 status = (d0 - '0') * 100 + (d1 - '0') * 10 + (d2 - '0');

    struct conn_key ck;
    __builtin_memset(&ck, 0, sizeof(ck));
    ck.backend_addr = ip->saddr;
    ck.client_addr  = ip->daddr;
    ck.backend_port = tcp->source;
    ck.client_port  = tcp->dest;

    struct conn_req *cr = bpf_map_lookup_elem(&inflight, &ck);
    if (!cr)
        return TC_ACT_OK;

    __u64 lat = bpf_ktime_get_ns() - cr->ts;
    struct route_stat *st = bpf_map_lookup_elem(&stats, &cr->rk);
    bpf_map_delete_elem(&inflight, &ck);
    if (!st)
        return TC_ACT_OK;

    if (status < 300)      __sync_fetch_and_add(&st->resp_2xx, 1);
    else if (status < 400) __sync_fetch_and_add(&st->resp_3xx, 1);
    else if (status < 500) __sync_fetch_and_add(&st->resp_4xx, 1);
    else                   __sync_fetch_and_add(&st->resp_5xx, 1);

    __sync_fetch_and_add(&st->lat_ns_sum, lat);
    __sync_fetch_and_add(&st->lat_cnt, 1);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
