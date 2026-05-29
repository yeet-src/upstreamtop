# `upstreamtop`

> **htop for your reverse proxy's backends.** Which servers nginx is fanning requests to, in real time.

<!-- badges row: Linux / yeet / eBPF (GPL) / observability -->

![demo gif or screenshot (required, lives in assets/)]

**`upstreamtop` is a live terminal dashboard of every backend an nginx reverse proxy is `proxy_pass`-ing to, ranked by requests per second.**

> [!TIP]
> **No nginx config, no log parsing, no restart.** Two `tcx` programs attach to the kernel's egress and ingress paths and read the plain-HTTP upstream traffic as it flows past. nginx never knows it's there.

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run https://github.com/yeet-src/upstreamtop
```

Drive some traffic through nginx so it proxies to its backends. The dashboard repaints once a second. Useful flags:

- `--backends <n>` (default `8`) — max backends shown.
- `--routes <n>` (default `4`) — top routes listed per backend.
- `--ignore <port|ip:port>` — hide an endpoint when the load generator runs on the same host as nginx.

## A 60-second primer on TC and tcx

nginx talking to a backend looks like a normal TCP conversation on the wire. The trick is reading those packets without touching nginx or the backends. eBPF's TC (traffic control) hooks let a program run on every packet as it enters or leaves an interface:

| Hook | Direction | What it sees |
|---|---|---|
| `tcx/ingress` | inbound to the host | every packet arriving on the interface |
| `tcx/egress` | outbound from the host | every packet leaving the interface |

`tcx` is the modern attach point (kernel 6.6+), the successor to clsact-based TC programs. It composes cleanly with other TC programs and doesn't fight cilium or systemd-networkd for the hook.

The other half of the trick is *direction*. A request nginx sends to a backend leaves on egress. The backend's response arrives on ingress. Client-facing traffic moves the opposite way. So a TCP segment seen on egress that starts with `GET ` is, by construction, the upstream leg, with no need to ask nginx what's an upstream and what's a client.

## Common use cases

`upstreamtop` is mostly for the developer or SRE running a reverse proxy who needs to see what the proxy is actually doing, right now, without changing its config.

- One backend is slow. Which routes does it serve?
- A 5xx rate just appeared in the dashboard. Which upstream is throwing them?
- nginx says it's load-balancing across the pool. Is the split actually even?
- A new upstream was added to the config. Is traffic actually reaching it?

## What you're looking at

The dashboard is a leaderboard of backend endpoints, sorted by request rate. Each row is one `ip:port` nginx is sending traffic to.

```
upstreamtop — nginx upstreams  ·  248 req/s  ·  1s window

 BACKEND               RPS        SHARE       avg     STATUS
 10.0.1.10:8080  ▁▂▄▆█  104  ████████   42%   2.1ms   2xx 99% 5xx 1%
   /api/orders                                61/s
   /healthz                                   30/s
 10.0.1.11:8080  ▃▄▃▅▄   97  ███████    39%   2.4ms   2xx 100%
   /api/orders                                97/s
 10.0.1.12:8080  ▆▃▁▁▁   31  ██         13%   140ms   2xx 88% 5xx 12%
   /checkout                                  31/s
```

Per backend, the row shows:

- **Sparkline** — the last 24 seconds of RPS for that backend. Helpful for spotting a fast-rising or fast-collapsing endpoint without staring at the number.
- **RPS** — requests per second nginx sent to that backend in the last refresh interval.
- **SHARE** — that backend's slice of the total upstream RPS. The bar makes uneven load-balancing obvious at a glance.
- **avg** — average response latency over the interval, computed from `(response_ts - request_ts)` per matched pair.
- **STATUS** — color-coded mix of 2xx / 3xx / 4xx / 5xx response codes. A backend silently returning 5xx is the thing this column was built for.

Below each backend, the top routes (by RPS) tell you *what* nginx is sending there. A backend in an upstream pool will usually serve every route in the proxy's `location` map; a per-route `proxy_pass` will show one line.

The "recent requests" feed at the bottom is a tail of the last few proxied requests with method, path, and backend, useful for spotting a one-off curl that hit an unexpected endpoint.

## How it works

The dashboard runs on two TC programs and one JS event loop. The technical core is in [`upstreamtop.bpf.c`](upstreamtop.bpf.c) and [`main.js`](main.js).

### The BPF side

Two programs, both attached via `tcx` to all interfaces:

| Program | Hook | What it does |
|---|---|---|
| `on_request` | `tcx/egress` | When a TCP segment begins with an HTTP method token (`GET `, `POST `, `PUT `, `DELETE `, `HEAD `, `PATCH `, `OPTIONS `), record it as a request to `(dest_ip, dest_port)` with the parsed path. Stash the 4-tuple in an LRU map so the response can be matched later. |
| `on_response` | `tcx/ingress` | When a TCP segment begins with `HTTP/`, parse the 3-digit status code at the fixed offset, look up the request by 4-tuple, attribute status and latency back to its `(backend, route)` bucket, and free the inflight entry. |

Three maps connect kernel to userspace:

- `stats` — `BPF_MAP_TYPE_HASH`, keyed by `(backend_addr, backend_port, path[32])`, holding request count, per-class response counts, and a latency sum/count. This is the leaderboard's source of truth.
- `inflight` — `BPF_MAP_TYPE_LRU_HASH` keyed by the 4-tuple, bridging a request to its response so latency can be stamped on the right bucket.
- `events` — `BPF_MAP_TYPE_RINGBUF`, used for the "recent requests" feed at the bottom of the dashboard.

The L3 offset is computed dynamically: an Ethernet frame puts the IP header 14 bytes in; loopback and tunnel devices put it at offset 0. Both cases are handled, so `127.0.0.1` backends work alongside real ones.

### The JS side

- `main.js` binds the maps, attaches both programs, subscribes to the ringbuf for the request feed, and runs a once-a-second tick that snapshots `stats`, diffs it against the previous snapshot to get per-interval deltas, aggregates per-backend, and redraws the leaderboard.
- The `enabled` flag is a `volatile __u32` in `.data` that the JS side flips to `0` on teardown so the BPF programs no-op while their detach happens.

### Why count requests, not connections

nginx uses keepalive on the upstream leg by default. One TCP connection can carry hundreds of requests. Counting connections would badly undercount the actual load on each backend. Parsing request lines gives the real RPS, and as a side effect gives the route, which is what makes the per-backend route breakdown possible.

## Requirements

> [!IMPORTANT]
> Linux kernel **6.6 or newer** for `tcx` attach. (extrapolated, grounding 2 — review)
>
> The yeet daemon, which handles the privileged BPF load. `curl -fsSL https://yeet.cx | sh` installs it.

## Honest caveats

> [!NOTE]
> What `upstreamtop` doesn't do, and what it gets wrong.

- **Plain HTTP only.** If nginx talks to backends over TLS (`proxy_pass https://...`), the bytes on the wire are encrypted and there's nothing line-shaped to parse. The displacement there is a `uprobe` on `SSL_write` paired with `SSL_get_fd` to recover the backend, which is a different script.
- **IPv4 only.** IPv6 upstreams are dropped at the L3 parse. (extrapolated, grounding 2 — review)
- **Request and status line must fit in the first segment** (payloads under 64 bytes are skipped). Real HTTP requests carry headers, so the first segment is comfortably past that.
- **One request, one response per connection at a time.** Serial keepalive is matched correctly. HTTP/1.1 pipelining (rare in 2026) is not.
- **HTTP/2 / gRPC upstream is framed, not line-based.** `upstreamtop` won't see it. A separate hook decoding h2 frames for `:path` and `:status` is what to reach for. (extrapolated, grounding 3 — review)
- **Loopback works, remote backends are the intended setting.** Bare-IP frames with no Ethernet header are detected, but a dedicated reverse-proxy box talking to remote backends is what this is built for.

## Community questions

**Do I need to change my nginx config?**
No. `upstreamtop` doesn't read nginx's config and nginx doesn't know it's there. It works across `nginx -s reload` because the BPF programs are attached to the interface, not the process.

**Will this slow nginx down?**
Each request and each response triggers a small fixed amount of kernel work on the egress/ingress hook: a header parse, a map lookup, an atomic add. No syscall is trapped, no packet is copied to userspace, and the request body is never touched. (extrapolated, grounding 3 — review)

**Why don't I see hostnames, just IPs?**
The kernel sees `ip:port`, not DNS. `upstreamtop` shows what nginx actually connected to. If you want hostnames, map the IPs back in your head or pair this with a tiny PTR-resolving wrapper.

**Is it safe to run on a busy production box?**
It only reads packets the kernel was already processing. No syscall trapping, no `strace`-style overhead, no per-packet copy to userspace. On a shared host you may want to filter to the upstream prefixes you care about with an `LPM_TRIE` on the egress program. (extrapolated, grounding 3 — review)

**How is this different from nginx's stub_status or the nginx access log?**
`stub_status` gives you nginx-wide counters. The access log gives you the client-facing leg. Neither tells you how nginx fanned a single request out across its upstream pool, with per-backend status and latency, in real time. That's the gap.

## Try it with the simulator

No production nginx handy? [`simulate.py`](simulate.py) stands up a real nginx reverse proxy in front of three local Python backends and drives weighted load at it, purely with the standard library plus the `nginx` binary.

```sh
python3 simulate.py            # runs until Ctrl-C
python3 simulate.py --workers 40 --duration 120
```

In a second terminal:

```sh
make && sudo yeet run . -- --ignore 8080
```

`--ignore 8080` hides nginx's own listen port. The simulator's load generator runs on the same host, so its client→nginx requests *also* leave on egress and nginx's front door would otherwise appear as a backend. On a real instance with remote clients you don't need it.

The simulated backends have distinct profiles so the dashboard is worth looking at: `:9001` and `:9002` are a fast round-robin pool, `:9003` (`/checkout`) is slow (60 to 160ms) and returns 5xx around 12% of the time.

## Building from source

```sh
make
make clean
```

Compiles `upstreamtop.bpf.c` against the bpf headers shipped with libbpf-sys, falling back to `/usr/include`. Requires `clang`. No `vmlinux.h` needed; this script uses the standard `linux/*.h` packet headers and no CO-RE field relocations.

## License

The BPF program declares `SEC("license") = "GPL"` in [`upstreamtop.bpf.c`](upstreamtop.bpf.c), required for the kernel helpers it uses. The JS side has no separate license declaration in the source. (extrapolated, grounding 2 — review)

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=upstreamtop), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/dYZu9PjKB?utm_source=github&utm_medium=readme&utm_campaign=upstreamtop).
