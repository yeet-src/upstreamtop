# upstreamtop — which backends nginx talks to, and how fast

A live dashboard of the upstream endpoints an **nginx reverse proxy**
is `proxy_pass`-ing to, ranked by **requests per second**, broken down
per route, with per-backend status mix and average latency. Watch
nginx fan requests across its backends in real time — spot a hot
server, a slow one, or one quietly returning 5xx.

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

 recent requests
  14:31:02  GET     /api/orders                      → 10.0.1.10:8080
  14:31:02  POST    /checkout                        → 10.0.1.12:8080
```

> [!TIP]
> **No nginx config, no log parsing, no restart.** upstreamtop attaches
> two TC programs to the kernel's egress/ingress path and reads the
> plain-HTTP upstream traffic as it flows by. nginx never knows it's
> there, and it keeps working across `nginx -s reload`.

## How it works

nginx's upstream leg (`proxy_pass http://backend;`) is almost always
plain HTTP on a private network, so we read it straight off the wire
with a pair of `tcx` programs — no nginx symbols, no userspace probes:

- **`tcx/egress`** — a TCP segment that begins with an HTTP method
  (`GET `, `POST `, …) is a request nginx is sending to a backend. The
  destination IP:port *is* the upstream endpoint. It's counted in the
  `stats` hash, keyed by `(backend, request path)`, and the 4-tuple is
  stashed in an LRU map so the response can be matched later.
- **`tcx/ingress`** — a segment that begins with `HTTP/` is a backend's
  response. We parse the status code, look up the request by 4-tuple,
  and attribute status + latency back to its `(backend, route)` bucket.

Direction does the hard part for free: client→nginx requests arrive on
ingress (skipped by the `HTTP/` check) and nginx→client responses leave
on egress (skipped by the method check), so what's left on each hook is
exactly the upstream conversation.

`main.js` reads the `stats` hash once a second, diffs it against the
previous read to get per-interval RPS, and redraws the leaderboard.

Counting **request lines** rather than connections is deliberate: nginx
keepalives reuse upstream connections, so a connection count would
badly undercount. Parsing requests gives true RPS.

## Build

```sh
make
```

Dumps `vmlinux.h` from the running kernel's BTF (`bpftool btf dump`)
and compiles `upstreamtop.bpf.c` against it plus the bpf headers shipped
with libbpf-sys (falling back to `/usr/include`). Requires `clang` and
`bpftool`. CO-RE: the packet-header structs (`ethhdr`, `iphdr`,
`tcphdr`), `struct __sk_buff`, and the `IPPROTO_*` enum come from the
kernel's own types — no system `linux/*.h` packet headers needed.

## Run

```sh
yeet run .
```

Then drive some traffic through nginx so it proxies to its backends.

Flags (via `yeet run . -- --flag value`):

- `--secs <n>` — how long to run (default `600`).
- `--backends <n>` — max backends shown (default `8`).
- `--routes <n>` — top routes listed per backend (default `4`).

## Try it with the simulator

No production nginx handy? `simulate.py` stands up a real nginx reverse
proxy in front of three local Python backends and drives weighted load
at it — purely with the standard library (plus the `nginx` binary).

```sh
python3 simulate.py            # runs until Ctrl-C
python3 simulate.py --workers 40 --duration 120
```

It prints the exact command to run in a second terminal:

```sh
cd examples/upstreamtop && make
sudo yeet run . -- --ignore 8080
```

The backends have distinct profiles so the dashboard is worth looking
at: `:9001`/`:9002` are a fast round-robin pool, `:9003` (`/checkout`)
is slow (60–160ms) and returns 5xx ~12% of the time.

> [!NOTE]
> `--ignore 8080` hides nginx's own listen port. The simulator's load
> generator runs on the same host, so its client→nginx requests *also*
> leave on egress and nginx's front door would otherwise appear as a
> backend. On a real instance with remote clients you don't need it.
> This is also why all the simulated traffic rides `lo` — a good test
> of the loopback (bare-IP, no Ethernet header) parsing path.

## Requirements & scope

- **Kernel ≥ 6.6** for `tcx` attach (the modern TC hook), built with
  `CONFIG_DEBUG_INFO_BTF=y` so `make` can dump `vmlinux.h` from
  `/sys/kernel/btf/vmlinux`. Any kernel new enough for `tcx` ships it.
- **Plain-HTTP upstream.** If nginx talks to backends over TLS
  (`proxy_pass https://…`), the bytes on the wire are encrypted and
  this won't see them — switch to a `uprobe` on `SSL_write` and recover
  the backend via `SSL_get_fd` → `getpeername`.
- **IPv4 only**, and only the **request/status line in a full first
  segment** (payloads under 64 bytes are skipped). Real HTTP requests
  carry headers, so the first segment is comfortably past that.
- **One request ↔ one response per connection at a time.** Serial
  keepalive is matched correctly; HTTP/1.1 pipelining (rare) is not.
- **HTTP/2 / gRPC upstream** is framed, not line-based — decode the h2
  frames to pull `:path` and `:status`.
- For `127.0.0.1` backends the loopback path is handled (bare-IP frames
  with no Ethernet header are detected), but a dedicated reverse-proxy
  box talking to remote backends is the intended setting.

To watch only real backends on a busy box, an `LPM_TRIE` of upstream
prefixes makes an easy filter to bolt onto the egress program.
