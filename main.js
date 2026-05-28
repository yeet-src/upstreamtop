import { DataSec, HashMap, LruHashMap, RingBuf } from "yeet:bpf";
import bpf from "./upstreamtop.bpf.o";

/* upstreamtop — a live view of the backends nginx is proxy_passing to
 * and the RPS of each. Two TC programs parse the plain-HTTP upstream
 * leg off the wire: egress request lines tell us (backend, route) and
 * ingress "HTTP/" status lines give status + latency. Each second we
 * read the `stats` hash, diff it against the previous read for per-
 * interval RPS, and redraw a leaderboard grouped by backend. */

/* libbpf names the .data map `<first 8 of obj_name>.data`; obj_name is
 * the filename up to the first `.`, so `upstreamtop.bpf.o` →
 * `upstreamtop` → first 8 = `upstream`. */
const DATA_SEC = "upstream.data";

const REFRESH_MS = 1000;
const SPARK_W = 24; /* rps-history columns kept per backend */
const SPARK = "▁▂▃▄▅▆▇█";

const args = (typeof yeet !== "undefined" && yeet.args) || {};
const SECS = Number(args.secs ?? args.s ?? 600);
const TOP_BACKENDS = Number(args.backends ?? 8);
const TOP_ROUTES = Number(args.routes ?? 4);

/* Backends to hide — a port (`8080`) or a full `ip:port`. Useful when
 * the load generator runs on the same host as nginx (e.g. the
 * simulator): client→nginx requests also leave on egress, so nginx's
 * own listen endpoint shows up as a "backend". Drop it here. */
const IGNORE = new Set(
  (args.ignore != null ? String(args.ignore).split(",") : [])
    .map((s) => s.trim())
    .filter(Boolean),
);

const METHODS = ["?", "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"];

const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const YEL = "\x1b[33m";
const GRN = "\x1b[32m";
const CYAN = "\x1b[36m";
const BLU = "\x1b[34m";
const MAG = "\x1b[35m";
const GRAY = "\x1b[38;5;244m";
const RESET = "\x1b[0m";
const CLEAR = "\x1b[2J\x1b[H";

/* Browser-dev-tools palette for HTTP verbs — safe-changing verbs lean
 * green, state-changing ones yellow/orange, destructive red. */
const METHOD_COLOR = {
  GET: GRN,
  POST: YEL,
  PUT: BLU,
  DELETE: RED,
  HEAD: CYAN,
  PATCH: MAG,
  OPTIONS: GRAY,
  "?": DIM,
};

function ipv4(neBE) {
  /* backend_addr is the BPF C __u32 in network byte order, lifted to a
   * JS Number through __type(key, ...). Flip to dotted-quad. */
  const b0 = (neBE >>> 0) & 0xff;
  const b1 = (neBE >>> 8) & 0xff;
  const b2 = (neBE >>> 16) & 0xff;
  const b3 = (neBE >>> 24) & 0xff;
  return `${b0}.${b1}.${b2}.${b3}`;
}

function decodePath(u8) {
  /* The runtime lifts `__u8 path[N]` as a Uint8Array of raw bytes when
   * the element type isn't char-flagged, or as a pre-decoded JS string
   * when it is. Handle both — plus null/undefined when the field is
   * absent. */
  if (u8 == null) return "/";
  if (typeof u8 === "string") {
    const nul = u8.indexOf("\0");
    return (nul >= 0 ? u8.slice(0, nul) : u8) || "/";
  }
  let s = "";
  for (const b of u8) {
    if (b === 0) break;
    s += String.fromCharCode(b);
  }
  return s || "/";
}

function fmtRps(r) {
  if (r <= 0) return "0";
  return r < 10 ? r.toFixed(1) : String(Math.round(r));
}

function fmtMs(ns) {
  if (!ns) return "—";
  const ms = ns / 1e6;
  return ms < 10 ? `${ms.toFixed(1)}ms` : `${Math.round(ms)}ms`;
}

function hhmmss() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function sparkline(arr) {
  if (arr.length === 0) return "";
  const max = Math.max(...arr, 1);
  return arr
    .map((v) => SPARK[Math.min(SPARK.length - 1, Math.floor((v / max) * (SPARK.length - 1)))])
    .join("");
}

function shareBar(frac, width = 10) {
  const n = Math.round(frac * width);
  return "█".repeat(n) + " ".repeat(width - n);
}

function statusMix(d) {
  const total = d.r2 + d.r3 + d.r4 + d.r5;
  if (total === 0) return `${DIM}no responses yet${RESET}`;
  const pct = (n) => Math.round((n / total) * 100);
  const parts = [];
  if (d.r2) parts.push(`${GRN}2xx ${pct(d.r2)}%${RESET}`);
  if (d.r3) parts.push(`${CYAN}3xx ${pct(d.r3)}%${RESET}`);
  if (d.r4) parts.push(`${YEL}4xx ${pct(d.r4)}%${RESET}`);
  if (d.r5) parts.push(`${RED}5xx ${pct(d.r5)}%${RESET}`);
  return parts.join(" ");
}

/* Snapshot the stats map into a flat list of per-route rows. Each
 * value field is a __u64 lifted to BigInt; collapse to Number (counts
 * stay well within Number's safe range for a demo). */
async function snapshot(stats) {
  const rows = [];
  for await (const [key, value] of stats.entries()) {
    const backend = `${ipv4(key.backend_addr)}:${key.backend_port}`;
    rows.push({
      backend,
      path: decodePath(key.path),
      requests: Number(value.requests),
      r2: Number(value.resp_2xx),
      r3: Number(value.resp_3xx),
      r4: Number(value.resp_4xx),
      r5: Number(value.resp_5xx),
      latSum: Number(value.lat_ns_sum),
      latCnt: Number(value.lat_cnt),
    });
  }
  return rows;
}

function deltaField(cur, prev, field) {
  return cur[field] - (prev ? prev[field] : 0);
}

function render(backends, totalRps, feed, sparks) {
  const lines = [
    CLEAR,
    `${BOLD}upstreamtop${RESET} — nginx upstreams  ·  ${BOLD}${fmtRps(totalRps)}${RESET} req/s  ·  ${DIM}${REFRESH_MS / 1000}s window${RESET}\n`,
  ];

  if (backends.length === 0) {
    lines.push(`${DIM}  Waiting for proxied requests…${RESET}`);
    console.log(lines.join("\n"));
    return;
  }

  lines.push(
    `${DIM} BACKEND               RPS        SHARE       avg     STATUS${RESET}`,
  );

  for (const b of backends) {
    const spark = sparkline(sparks.get(b.backend) || []);
    const avg = b.d.latCnt > 0 ? fmtMs(b.d.latSum / b.d.latCnt) : "—";
    lines.push(
      ` ${BOLD}${b.backend.padEnd(20)}${RESET} ${spark.padStart(SPARK_W)} ` +
        `${fmtRps(b.rps).padStart(4)}  ${shareBar(b.share)} ${String(Math.round(b.share * 100)).padStart(3)}%  ` +
        `${avg.padStart(6)}  ${statusMix(b.d)}`,
    );
    for (const r of b.routes.slice(0, TOP_ROUTES)) {
      const path = r.path.slice(0, 40).padEnd(40);
      lines.push(`   ${CYAN}${path}${RESET} ${fmtRps(r.rps).padStart(4)}/s`);
    }
  }

  if (feed.length) {
    lines.push(`\n${DIM} recent requests${RESET}`);
    for (const f of feed) lines.push(`  ${f}`);
  }

  console.log(lines.join("\n"));
}

try {
  const control = await bpf
    .bind("stats", { kind: "hash_map" })
    .bind("inflight", { kind: "lru_hash_map" })
    .bind("events", { kind: "ringbuf", btf_struct: "req_event" })
    .bind(DATA_SEC, { kind: "data" })
    .attach("on_request", { kind: "tcx" }) /* tcx/egress, all interfaces */
    .attach("on_response", { kind: "tcx" }) /* tcx/ingress, all interfaces */
    .start();

  const knobs = new DataSec(control, DATA_SEC);
  const stats = new HashMap(control, "stats");
  const events = new RingBuf(control, "events");
  /* inflight is read kernel-side only; constructing the handle just
   * proves the bind resolved. */
  new LruHashMap(control, "inflight");

  const feed = []; /* last few proxied requests, newest last */
  const sub = await events.subscribe((wrapper) => {
    /* Ringbuf binds use `from_btf_type_id` (prefixed by struct name)
     * while hash-map keys/values use `_unprefixed`, so a ringbuf event
     * arrives wrapped as `{ <struct_name>: { …fields… } }`. Peel it. */
    const e = wrapper && wrapper.req_event ? wrapper.req_event : wrapper || {};
    const method = METHODS[e.method] || "?";
    const path = decodePath(e.path).slice(0, 32).padEnd(32);
    const line =
      `${GRAY}${hhmmss()}${RESET}  ` +
      `${METHOD_COLOR[method] || DIM}${method.padEnd(7)}${RESET} ` +
      `${CYAN}${path}${RESET} ` +
      `${DIM}→${RESET} ${ipv4(e.backend_addr)}:${e.backend_port}`;
    feed.push(line);
    if (feed.length > 6) feed.shift();
  });

  const sparks = new Map();
  let prev = new Map();
  let warmed = false;
  let lastTime = Date.now();

  console.log("Sampling nginx upstream traffic… (Ctrl-C to stop)");

  const tick = setInterval(async () => {
    try {
      const now = Date.now();
      const intervalSec = Math.max(0.001, (now - lastTime) / 1000);
      lastTime = now;

      const rows = await snapshot(stats);
      const cur = new Map(rows.map((r) => [`${r.backend}\x00${r.path}`, r]));

      if (!warmed) {
        prev = cur;
        warmed = true;
        return;
      }

      /* Per-route deltas, then fold into per-backend aggregates. */
      const byBackend = new Map();
      for (const [ck, r] of cur) {
        if (IGNORE.has(r.backend) || IGNORE.has(r.backend.split(":")[1])) continue;
        const p = prev.get(ck);
        const reqRps = deltaField(r, p, "requests") / intervalSec;

        let agg = byBackend.get(r.backend);
        if (!agg) {
          agg = {
            backend: r.backend,
            rps: 0,
            d: { latSum: 0, latCnt: 0, r2: 0, r3: 0, r4: 0, r5: 0 },
            routes: [],
          };
          byBackend.set(r.backend, agg);
        }
        agg.rps += reqRps;
        agg.d.latSum += deltaField(r, p, "latSum");
        agg.d.latCnt += deltaField(r, p, "latCnt");
        agg.d.r2 += deltaField(r, p, "r2");
        agg.d.r3 += deltaField(r, p, "r3");
        agg.d.r4 += deltaField(r, p, "r4");
        agg.d.r5 += deltaField(r, p, "r5");
        if (reqRps > 0) agg.routes.push({ path: r.path, rps: reqRps });
      }
      prev = cur;

      const backends = [...byBackend.values()].sort((a, b) => b.rps - a.rps);
      const totalRps = backends.reduce((s, b) => s + b.rps, 0);
      for (const b of backends) {
        b.share = totalRps > 0 ? b.rps / totalRps : 0;
        b.routes.sort((x, y) => y.rps - x.rps);
        const hist = sparks.get(b.backend) || [];
        hist.push(b.rps);
        if (hist.length > SPARK_W) hist.shift();
        sparks.set(b.backend, hist);
      }

      render(backends.slice(0, TOP_BACKENDS), totalRps, feed, sparks);
    } catch (err) {
      clearInterval(tick);
      console.error(err);
    }
  }, REFRESH_MS);

  await new Promise((r) => setTimeout(r, SECS * 1000));
  clearInterval(tick);
  await knobs.patch({ enabled: 0 });
  await sub.unsubscribe();
  await control.stop();
} catch (err) {
  console.error(err);
}
