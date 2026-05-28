#!/usr/bin/env python3
"""upstreamtop simulator — a real nginx reverse proxy fanning traffic out
to three local backends, with a built-in load generator, so you can watch
the upstreamtop dashboard light up without a production setup.

What it stands up (all on 127.0.0.1, stdlib only):

  load gen  ──►  nginx :8080  ──►  app_pool { :9001, :9002 }   (round-robin, keepalive)
                              ├──►  :9001                       (/healthz)
                              ├──►  :9002                       (/static/*)
                              └──►  :9003                       (/checkout — slow + flaky)

Backends have distinct profiles so the dashboard is interesting:
  :9001 api-a     fast, all 2xx
  :9002 api-b     fast, all 2xx
  :9003 checkout  slow (60-160ms) and ~12% 5xx

Usage:
  python3 simulate.py                 # run until Ctrl-C
  python3 simulate.py --duration 120  # run for 2 minutes
  python3 simulate.py --workers 40    # heavier load

Then, in another terminal:
  cd examples/upstreamtop && make
  sudo yeet run . -- --ignore 8080

The `--ignore 8080` hides nginx's own front door: because the load
generator runs on this same host, its client→nginx requests also leave
on egress, so :8080 would otherwise appear as a "backend". On a real box
with remote clients you wouldn't need it.
"""

import argparse
import atexit
import http.client
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# port -> (name, latency_lo_ms, latency_hi_ms, error_rate)
BACKENDS = {
    9001: ("api-a", 1, 6, 0.00),
    9002: ("api-b", 1, 8, 0.00),
    9003: ("checkout", 60, 160, 0.12),
}

# (method, path, body, weight) — the mix the load generator sends to nginx.
ROUTES = [
    ("GET", "/api/orders", None, 8),
    ("GET", "/api/users", None, 5),
    ("GET", "/healthz", None, 10),
    ("POST", "/checkout", b'{"cart":42}', 4),
    ("GET", "/static/app.js", None, 6),
    ("GET", "/", None, 3),
]

STATIC_BODY = b"// app.js\n" + (b"x" * 2048)


def free_port(port):
    """True if `port` is bindable on localhost right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def make_handler(name, lo_ms, hi_ms, err_rate, counters):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # keepalive, like a real upstream

        def _drain_body(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)

        def _serve(self):
            self._drain_body()
            time.sleep(random.uniform(lo_ms, hi_ms) / 1000.0)

            if random.random() < err_rate:
                body = b'{"error":"upstream exploded"}'
                status = 500
            elif self.path.startswith("/static/"):
                body, status = STATIC_BODY, 200
            else:
                body = b'{"ok":true,"backend":"%s"}' % name.encode()
                status = 200

            counters[name] += 1
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _serve
        do_POST = _serve
        do_PUT = _serve
        do_DELETE = _serve
        do_PATCH = _serve

        def log_message(self, *_a):
            pass

    return Handler


def nginx_conf(prefix, listen_port):
    return f"""\
worker_processes 2;
daemon on;
pid {prefix}/nginx.pid;
error_log {prefix}/error.log warn;
events {{ worker_connections 1024; }}
http {{
    access_log off;
    client_body_temp_path {prefix}/client_temp;
    proxy_temp_path        {prefix}/proxy_temp;
    fastcgi_temp_path      {prefix}/fastcgi_temp;
    uwsgi_temp_path        {prefix}/uwsgi_temp;
    scgi_temp_path         {prefix}/scgi_temp;

    upstream app_pool {{
        server 127.0.0.1:9001;
        server 127.0.0.1:9002;
        keepalive 16;
    }}

    server {{
        listen {listen_port};

        location /api/ {{
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://app_pool;
        }}
        location /healthz   {{ proxy_pass http://127.0.0.1:9001; }}
        location /static/   {{ proxy_pass http://127.0.0.1:9002; }}
        location /checkout  {{ proxy_pass http://127.0.0.1:9003; }}
        location / {{
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://app_pool;
        }}
    }}
}}
"""


def start_backends(counters):
    servers = []
    for port, (name, lo, hi, err) in BACKENDS.items():
        if not free_port(port):
            sys.exit(f"port {port} is in use — stop whatever holds it and retry")
        handler = make_handler(name, lo, hi, err, counters)
        srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def start_nginx(nginx_bin, prefix, listen_port):
    conf_path = os.path.join(prefix, "nginx.conf")
    with open(conf_path, "w") as f:
        f.write(nginx_conf(prefix, listen_port))
    for sub in ("client_temp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"):
        os.makedirs(os.path.join(prefix, sub), exist_ok=True)

    test = subprocess.run(
        [nginx_bin, "-t", "-p", prefix + "/", "-c", conf_path, "-e", prefix + "/error.log"],
        capture_output=True,
        text=True,
    )
    if test.returncode != 0:
        sys.exit("nginx config test failed:\n" + test.stderr)

    run = subprocess.run(
        [nginx_bin, "-p", prefix + "/", "-c", conf_path, "-e", prefix + "/error.log"],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        sys.exit("nginx failed to start:\n" + run.stderr)
    return os.path.join(prefix, "nginx.pid")


def stop_nginx(nginx_bin, prefix):
    conf_path = os.path.join(prefix, "nginx.conf")
    subprocess.run(
        [nginx_bin, "-p", prefix + "/", "-c", conf_path, "-e", prefix + "/error.log", "-s", "quit"],
        capture_output=True,
    )


def load_worker(listen_port, stop, counters, weights, pool):
    conn = None
    while not stop.is_set():
        method, path, body, _ = random.choices(ROUTES, weights=weights, k=1)[0]
        try:
            if conn is None:
                conn = http.client.HTTPConnection("127.0.0.1", listen_port, timeout=5)
            headers = {"Content-Type": "application/json"} if body else {}
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            counters["sent"] += 1
            if resp.status >= 500:
                counters["err5xx"] += 1
        except Exception:
            counters["failed"] += 1
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
            conn = None
            time.sleep(0.05)
        time.sleep(random.uniform(0.0, 0.02))


def main():
    ap = argparse.ArgumentParser(description="upstreamtop traffic simulator")
    ap.add_argument("--port", type=int, default=8080, help="nginx listen port (default 8080)")
    ap.add_argument("--workers", type=int, default=24, help="concurrent load clients (default 24)")
    ap.add_argument("--duration", type=int, default=0, help="seconds to run; 0 = until Ctrl-C")
    args = ap.parse_args()

    nginx_bin = shutil.which("nginx")
    if not nginx_bin:
        sys.exit(
            "nginx not found on PATH. Install it, e.g.:\n"
            "  Debian/Ubuntu: sudo apt-get install -y nginx\n"
            "  Fedora:        sudo dnf install -y nginx\n"
            "  Arch:          sudo pacman -S nginx"
        )
    if not free_port(args.port):
        sys.exit(f"nginx port {args.port} is in use — pick another with --port")

    prefix = tempfile.mkdtemp(prefix="upstreamtop-sim-")
    counters = {name: 0 for (name, *_rest) in BACKENDS.values()}
    counters.update({"sent": 0, "err5xx": 0, "failed": 0})

    backends = start_backends(counters)
    start_nginx(nginx_bin, prefix, args.port)

    cleaned = threading.Event()

    def cleanup(*_a):
        if cleaned.is_set():
            return
        cleaned.set()
        stop_nginx(nginx_bin, prefix)
        for srv in backends:
            srv.shutdown()
        shutil.rmtree(prefix, ignore_errors=True)

    atexit.register(cleanup)
    signal.signal(signal.SIGINT, lambda *_a: (cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *_a: (cleanup(), sys.exit(0)))

    print("┌─ upstreamtop simulator ───────────────────────────────────────┐")
    print(f"│ nginx  :{args.port:<5}  →  app_pool {{127.0.0.1:9001, :9002}}        │")
    print("│                       →  :9001 /healthz                       │")
    print("│                       →  :9002 /static                        │")
    print("│                       →  :9003 /checkout  (slow + 12% 5xx)    │")
    print(f"│ load   {args.workers} clients                                          │")
    print("└───────────────────────────────────────────────────────────────┘")
    print("\nIn another terminal:")
    print("  cd examples/upstreamtop && make")
    print(f"  sudo yeet run . -- --ignore {args.port}\n")
    print("Ctrl-C to stop.\n")

    stop = threading.Event()
    weights = [w for *_r, w in ROUTES]
    for _ in range(args.workers):
        threading.Thread(
            target=load_worker,
            args=(args.port, stop, counters, weights, prefix),
            daemon=True,
        ).start()

    start = time.time()
    last_sent = 0
    try:
        while True:
            time.sleep(2)
            sent = counters["sent"]
            rps = (sent - last_sent) / 2.0
            last_sent = sent
            print(
                f"[load] {sent:>7} req  ~{rps:5.0f}/s   "
                f"5xx={counters['err5xx']}  failed={counters['failed']}",
                file=sys.stderr,
            )
            if args.duration and time.time() - start >= args.duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        cleanup()


if __name__ == "__main__":
    main()
