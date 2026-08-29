#!/usr/bin/env node
// parse-trace.mjs — G2 harness: strace output -> JSONL event stream.
//
// Gate tooling, not product code (harness/README.md). Phase 1 rewrites this in Rust as
// recorder/strace/. Kept as throwaway Node on purpose: it must be cheap to abandon.
//
// Input:  <indir>/trace.<pid> files from `strace -f -ff -ttt -s 512 -yy`, plus session.json.
// Output: events.jsonl following Architecture.md §3, with the deviations documented in README.md:
//   1. ts_ns is nanoseconds SINCE SESSION START (epoch ns exceeds JSON safe-integer range).
//   2. new op `dns_query` with a best-effort qname read from UDP/53 payloads.
//   3. events carry pid + syscall for evidence traceability.
//
// Truth discipline (Rules.md §5): this parser never guesses. Unparseable lines are counted in
// parse_errors, not silently dropped, and a truncated DNS payload yields no event rather than a
// half-decoded hostname.

import { createReadStream, readFileSync, writeFileSync, existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { createInterface } from "node:readline";
import path from "node:path";

const PARSER_VERSION = "g2-parse-0.1.0";

// Hard cap so a pathological install cannot produce an unusable multi-GB artifact. Hitting the
// cap sets complete:false on session_end — a truncated stream must never read as a whole one.
const MAX_EVENTS = 300_000;

function fail(msg) {
  console.error(`parse-trace: FATAL: ${msg}`);
  process.exit(2);
}

function parseArgs(argv) {
  const out = { indir: null, out: null };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--indir") out.indir = argv[++i];
    else if (a === "--out") out.out = argv[++i];
    else if (a === "-h" || a === "--help") {
      console.log("Usage: parse-trace.mjs --indir <dir-with-trace.*> --out <events.jsonl>");
      process.exit(0);
    } else fail(`unknown argument: ${a}`);
  }
  if (!out.indir) fail("--indir is required");
  if (!out.out) fail("--out is required");
  return out;
}

// ---------------------------------------------------------------------------------------------
// strace string decoding
// ---------------------------------------------------------------------------------------------

// strace renders byte buffers as C-style strings: printable chars literal, others escaped as
// \n \t \r \f \v \b \a \\ \" or octal \NNN (or hex \xNN under -x). Returns raw bytes because DNS
// payloads are binary; callers decide on an encoding.
function decodeStraceBytes(raw) {
  const bytes = [];
  for (let i = 0; i < raw.length; i += 1) {
    const c = raw[i];
    if (c !== "\\") {
      // Multi-byte UTF-8 in the source line becomes its own bytes.
      const buf = Buffer.from(c, "utf8");
      for (const b of buf) bytes.push(b);
      continue;
    }
    const n = raw[i + 1];
    if (n === undefined) { bytes.push(0x5c); break; }
    switch (n) {
      case "n": bytes.push(0x0a); i += 1; break;
      case "t": bytes.push(0x09); i += 1; break;
      case "r": bytes.push(0x0d); i += 1; break;
      case "f": bytes.push(0x0c); i += 1; break;
      case "v": bytes.push(0x0b); i += 1; break;
      case "b": bytes.push(0x08); i += 1; break;
      case "a": bytes.push(0x07); i += 1; break;
      case "\\": bytes.push(0x5c); i += 1; break;
      case '"': bytes.push(0x22); i += 1; break;
      case "x": {
        const m = /^[0-9a-fA-F]{1,2}/.exec(raw.slice(i + 2));
        if (!m) { bytes.push(0x5c); i += 1; break; }
        bytes.push(parseInt(m[0], 16));
        i += 1 + m[0].length;
        break;
      }
      default: {
        const m = /^[0-7]{1,3}/.exec(raw.slice(i + 1));
        if (!m) { bytes.push(0x5c); break; }
        bytes.push(parseInt(m[0], 8) & 0xff);
        i += m[0].length;
        break;
      }
    }
  }
  return Buffer.from(bytes);
}

// Reads a double-quoted strace string starting at `start` (which must index the opening quote).
// Returns { raw, end, truncated } where truncated reflects a trailing `...` meaning strace cut
// the buffer short at its -s limit.
function readQuoted(s, start) {
  if (s[start] !== '"') return null;
  let i = start + 1;
  let raw = "";
  while (i < s.length) {
    const c = s[i];
    if (c === "\\") { raw += c + (s[i + 1] ?? ""); i += 2; continue; }
    if (c === '"') break;
    raw += c;
    i += 1;
  }
  if (i >= s.length) return null; // unterminated: strace line itself was cut
  let end = i + 1;
  let truncated = false;
  if (s.slice(end, end + 3) === "...") { truncated = true; end += 3; }
  return { raw, end, truncated };
}

// Splits a syscall argument list on top-level commas, respecting quotes and nesting.
function splitTopLevel(s) {
  const parts = [];
  let depth = 0;
  let cur = "";
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === '"') {
      const q = readQuoted(s, i);
      if (!q) { cur += s.slice(i); break; }
      cur += s.slice(i, q.end);
      i = q.end;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") { depth += 1; cur += c; i += 1; continue; }
    if (c === ")" || c === "]" || c === "}") { depth -= 1; cur += c; i += 1; continue; }
    if (c === "," && depth === 0) { parts.push(cur.trim()); cur = ""; i += 1; continue; }
    cur += c;
    i += 1;
  }
  if (cur.trim() !== "") parts.push(cur.trim());
  return parts;
}

// A quoted arg like "\"/tmp/x\"" -> /tmp/x as a JS string.
function argToPath(arg) {
  if (typeof arg !== "string") return null;
  const q = readQuoted(arg, 0);
  if (!q) return null;
  return decodeStraceBytes(q.raw).toString("utf8");
}

// -yy annotates fds as `3</abs/path>` or `4<TCP:[1.2.3.4:80]>`. Extract the annotation.
function fdAnnotation(arg) {
  const m = /^-?\d+<(.+)>$/.exec(arg ?? "");
  return m ? m[1] : null;
}

// ---------------------------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------------------------

// Best-effort qname extraction from a DNS query payload. Returns null on anything unexpected:
// a guessed hostname would be fabricated evidence (Rules.md §5).
function dnsQname(buf, truncated) {
  if (buf.length < 13) return null;
  const qdcount = buf.readUInt16BE(4);
  if (qdcount < 1) return null;
  const labels = [];
  let off = 12;
  for (let guard = 0; guard < 64; guard += 1) {
    if (off >= buf.length) return truncated ? null : null;
    const len = buf[off];
    if (len === 0) break;
    if ((len & 0xc0) !== 0) return null; // compression pointer in a question section: bail
    if (off + 1 + len > buf.length) return null; // payload cut mid-label
    const label = buf.slice(off + 1, off + 1 + len).toString("latin1");
    if (!/^[A-Za-z0-9_*-]+$/.test(label)) return null;
    labels.push(label);
    off += 1 + len;
  }
  if (labels.length === 0) return null;
  return labels.join(".");
}

// Pulls sin_port / address out of a strace-rendered sockaddr struct.
function parseSockaddr(struct) {
  if (typeof struct !== "string") return null;
  const fam = /sa_family=(AF_[A-Z0-9_]+)/.exec(struct);
  if (!fam) return null;
  const family = fam[1];
  if (family === "AF_INET") {
    const port = /sin_port=htons\((\d+)\)/.exec(struct);
    const addr = /sin_addr=inet_addr\("([^"]+)"\)/.exec(struct);
    return { family, ip: addr ? addr[1] : null, port: port ? Number(port[1]) : null };
  }
  if (family === "AF_INET6") {
    const port = /sin6_port=htons\((\d+)\)/.exec(struct);
    const addr = /inet_pton\(AF_INET6,\s*"([^"]+)"/.exec(struct);
    return { family, ip: addr ? addr[1] : null, port: port ? Number(port[1]) : null };
  }
  if (family === "AF_UNIX") {
    const p = /sun_path="([^"]*)"/.exec(struct);
    return { family, unix_path: p ? p[1] : null };
  }
  return { family };
}

function isLoopback(ip) {
  if (!ip) return false;
  return ip === "::1" || ip.startsWith("127.");
}

function isPrivateIp(ip) {
  if (!ip) return false;
  if (isLoopback(ip)) return true;
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("169.254.")) return true;
  const m = /^172\.(\d+)\./.exec(ip);
  if (m) { const o = Number(m[1]); if (o >= 16 && o <= 31) return true; }
  if (ip.startsWith("fe80:") || ip.startsWith("fd") || ip.startsWith("fc")) return true;
  return false;
}

// ---------------------------------------------------------------------------------------------
// path classification helpers (used only to set a coarse zone; policy lives in classify.mjs)
// ---------------------------------------------------------------------------------------------

const WRITE_FLAGS = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"];

function hasWriteIntent(flags) {
  if (!flags) return false;
  return WRITE_FLAGS.some((f) => flags.includes(f));
}

// Paths worth recording even on a read-only open. Recording every read would dwarf the trace and
// bury the evidence; these are the reads Architecture.md §4 calls out as findings.
const READ_OF_INTEREST = [
  /\/\.ssh\//, /\/\.ssh$/,
  /\/\.aws\//, /\/\.aws$/,
  /\/\.npmrc$/, /\/\.yarnrc/, /\/\.netrc$/,
  /\/\.docker\/config\.json$/,
  /\/\.gitconfig$/, /\/\.git-credentials$/,
  /\/\.kube\//, /\/\.config\/gcloud\//,
  /\/etc\/shadow$/, /\/etc\/passwd$/,
  /(^|\/)\.env(\.[A-Za-z0-9_.-]+)?$/,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/,
  /\/proc\/self\/environ$/, /\/proc\/\d+\/environ$/,
];

function isReadOfInterest(p) {
  if (!p) return false;
  return READ_OF_INTEREST.some((re) => re.test(p));
}

// ---------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------

const opts = parseArgs(process.argv);
const indir = path.resolve(opts.indir);
if (!existsSync(indir)) fail(`indir does not exist: ${indir}`);

const sessionPath = path.join(indir, "session.json");
let session = null;
if (existsSync(sessionPath)) {
  try {
    session = JSON.parse(readFileSync(sessionPath, "utf8"));
  } catch (err) {
    fail(`session.json is not valid JSON: ${err.message}`);
  }
} else {
  console.error("parse-trace: WARNING: no session.json; completeness cannot be verified");
}

const startEpoch = session && session.start_epoch ? Number(session.start_epoch) : null;

const traceDir = existsSync(path.join(indir, "trace")) ? path.join(indir, "trace") : indir;
const entries = await readdir(traceDir).catch(() => []);
const traceFiles = entries.filter((f) => /^trace\.\d+$/.test(f)).sort();

if (traceFiles.length === 0) {
  console.error(`parse-trace: WARNING: no trace.<pid> files found in ${traceDir}`);
}

const events = [];
const stats = {
  lines: 0,
  parsed: 0,
  parse_errors: 0,
  unfinished_unmatched: 0,
  signals: 0,
  exits: 0,
  capped: false,
  dns_payload_undecodable: 0,
};

// `1719245678.123456 openat(...) = 3` — optional leading pid for safety even though -ff omits it.
const LINE_RE = /^(?:(\d+)\s+)?(\d+\.\d+)\s+(.*)$/;
const CALL_RE = /^([a-z_0-9]+)\((.*)$/;

function tsNs(epochSeconds) {
  if (startEpoch === null) return Math.round(epochSeconds * 1e9);
  return Math.round((epochSeconds - startEpoch) * 1e9);
}

function push(ev) {
  if (events.length >= MAX_EVENTS) { stats.capped = true; return; }
  events.push(ev);
}

// Splits `args) = ret` into the argument text and the return text.
function splitCall(rest) {
  // Walk to the matching close paren of the call, honoring quotes and nesting.
  let depth = 1;
  let i = 0;
  while (i < rest.length) {
    const c = rest[i];
    if (c === '"') {
      const q = readQuoted(rest, i);
      if (!q) return null;
      i = q.end;
      continue;
    }
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]" || c === "}") {
      depth -= 1;
      if (depth === 0) return { args: rest.slice(0, i), ret: rest.slice(i + 1).trim() };
    }
    i += 1;
  }
  return null;
}

function retInfo(retText) {
  // ` = 3</tmp/x>` | ` = -1 ENOENT (No such file...)` | ` = 0` | ` = ? <unavailable>`
  const m = /^=\s*(-?\d+|\?)\s*(.*)$/.exec(retText);
  if (!m) return { ok: null, value: null, error: null, annotation: null };
  const value = m[1] === "?" ? null : Number(m[1]);
  const tail = m[2] ?? "";
  const errm = /^([A-Z][A-Z0-9_]+)\b/.exec(tail);
  const ann = /^<(.+?)>/.exec(tail);
  const error = errm ? errm[1] : null;
  // EINPROGRESS on a non-blocking connect is a real connection attempt, not a failure.
  const ok = value === null ? null : value >= 0 || error === "EINPROGRESS";
  return { ok, value, error, annotation: ann ? ann[1] : null };
}

function resolvePath(dirfdArg, rawPath, retAnnotation) {
  // The -yy return annotation is the kernel's resolved path: most trustworthy when present.
  if (retAnnotation && retAnnotation.startsWith("/")) return retAnnotation;
  if (rawPath && rawPath.startsWith("/")) return rawPath;
  const ann = fdAnnotation(dirfdArg ?? "");
  if (ann && ann.startsWith("/") && rawPath) return path.posix.join(ann, rawPath);
  return rawPath; // relative, cwd unknown — classify.mjs treats these as unresolved
}

function handleCall(pid, ts, name, argsText, retText) {
  const args = splitTopLevel(argsText);
  const ret = retInfo(retText);
  const base = { ts_ns: tsNs(ts), pid, backend: "strace", syscall: name };

  switch (name) {
    case "openat":
    case "openat2": {
      const p = resolvePath(args[0], argToPath(args[1]), ret.annotation);
      const flags = args[2] ?? "";
      if (hasWriteIntent(flags)) {
        push({ ...base, op: "fs_write", path: p, flags, ok: ret.ok, error: ret.error });
      } else if (isReadOfInterest(p)) {
        push({ ...base, op: "fs_read", path: p, flags, ok: ret.ok, error: ret.error });
      }
      return true;
    }
    case "open": {
      const p = resolvePath(null, argToPath(args[0]), ret.annotation);
      const flags = args[1] ?? "";
      if (hasWriteIntent(flags)) {
        push({ ...base, op: "fs_write", path: p, flags, ok: ret.ok, error: ret.error });
      } else if (isReadOfInterest(p)) {
        push({ ...base, op: "fs_read", path: p, flags, ok: ret.ok, error: ret.error });
      }
      return true;
    }
    case "creat":
    case "truncate": {
      const p = resolvePath(null, argToPath(args[0]), ret.annotation);
      push({ ...base, op: "fs_write", path: p, ok: ret.ok, error: ret.error });
      return true;
    }
    case "mkdir": {
      push({ ...base, op: "fs_write", path: resolvePath(null, argToPath(args[0]), null), kind: "mkdir", ok: ret.ok, error: ret.error });
      return true;
    }
    case "mkdirat": {
      push({ ...base, op: "fs_write", path: resolvePath(args[0], argToPath(args[1]), null), kind: "mkdir", ok: ret.ok, error: ret.error });
      return true;
    }
    case "rmdir":
    case "unlink": {
      push({ ...base, op: "fs_write", path: resolvePath(null, argToPath(args[0]), null), kind: "delete", ok: ret.ok, error: ret.error });
      return true;
    }
    case "unlinkat": {
      push({ ...base, op: "fs_write", path: resolvePath(args[0], argToPath(args[1]), null), kind: "delete", ok: ret.ok, error: ret.error });
      return true;
    }
    case "rename": {
      push({ ...base, op: "fs_write", path: resolvePath(null, argToPath(args[1]), null), from: argToPath(args[0]), kind: "rename", ok: ret.ok, error: ret.error });
      return true;
    }
    case "renameat":
    case "renameat2": {
      push({ ...base, op: "fs_write", path: resolvePath(args[2], argToPath(args[3]), null), from: argToPath(args[1]), kind: "rename", ok: ret.ok, error: ret.error });
      return true;
    }
    case "chmod": {
      push({ ...base, op: "fs_chmod", path: resolvePath(null, argToPath(args[0]), null), mode: args[1] ?? null, ok: ret.ok, error: ret.error });
      return true;
    }
    case "fchmodat": {
      push({ ...base, op: "fs_chmod", path: resolvePath(args[0], argToPath(args[1]), null), mode: args[2] ?? null, ok: ret.ok, error: ret.error });
      return true;
    }
    case "chown":
    case "lchown": {
      push({ ...base, op: "fs_chown", path: resolvePath(null, argToPath(args[0]), null), ok: ret.ok, error: ret.error });
      return true;
    }
    case "fchownat": {
      push({ ...base, op: "fs_chown", path: resolvePath(args[0], argToPath(args[1]), null), ok: ret.ok, error: ret.error });
      return true;
    }
    case "link": {
      push({ ...base, op: "fs_write", path: resolvePath(null, argToPath(args[1]), null), from: argToPath(args[0]), kind: "hardlink", ok: ret.ok, error: ret.error });
      return true;
    }
    case "linkat": {
      push({ ...base, op: "fs_write", path: resolvePath(args[2], argToPath(args[3]), null), from: argToPath(args[1]), kind: "hardlink", ok: ret.ok, error: ret.error });
      return true;
    }
    case "symlink": {
      push({ ...base, op: "fs_write", path: resolvePath(null, argToPath(args[1]), null), target: argToPath(args[0]), kind: "symlink", ok: ret.ok, error: ret.error });
      return true;
    }
    case "symlinkat": {
      push({ ...base, op: "fs_write", path: resolvePath(args[1], argToPath(args[2]), null), target: argToPath(args[0]), kind: "symlink", ok: ret.ok, error: ret.error });
      return true;
    }
    case "connect": {
      const sa = parseSockaddr(args[1]);
      if (!sa) return false;
      if (sa.family === "AF_UNIX") {
        push({ ...base, op: "net_connect_unix", unix_path: sa.unix_path ?? null, ok: ret.ok, error: ret.error });
        return true;
      }
      if (sa.family === "AF_INET" || sa.family === "AF_INET6") {
        push({
          ...base, op: "net_connect", ip: sa.ip, port: sa.port, family: sa.family,
          loopback: isLoopback(sa.ip), private: isPrivateIp(sa.ip),
          ok: ret.ok, error: ret.error,
        });
        return true;
      }
      return true; // AF_NETLINK etc: uninteresting, but a recognized line
    }
    case "sendto":
    case "sendmsg": {
      let sa = null;
      let payloadArg = null;
      let truncated = false;
      if (name === "sendto") {
        sa = parseSockaddr(args[4]);
        payloadArg = args[1];
      } else {
        const m = /msg_name=(\{[^}]*\})/.exec(argsText);
        sa = m ? parseSockaddr(m[1]) : null;
        const iov = /iov_base=("(?:[^"\\]|\\.)*")(\.\.\.)?/.exec(argsText);
        if (iov) { payloadArg = iov[1]; truncated = Boolean(iov[2]); }
      }
      if (!sa || sa.port !== 53) return true; // only DNS is extracted; see README
      if (!payloadArg) return true;
      const q = readQuoted(payloadArg, 0);
      if (!q) return true;
      const buf = decodeStraceBytes(q.raw);
      const qname = dnsQname(buf, truncated || q.truncated);
      if (!qname) { stats.dns_payload_undecodable += 1; return true; }
      push({ ...base, op: "dns_query", qname, resolver_ip: sa.ip, resolver_port: sa.port, ok: ret.ok, error: ret.error });
      return true;
    }
    case "execve":
    case "execveat": {
      const binIdx = name === "execve" ? 0 : 1;
      const argvIdx = binIdx + 1;
      const bin = argToPath(args[binIdx]);
      const argvRaw = args[argvIdx] ?? "";
      let argv = [];
      if (argvRaw.startsWith("[")) {
        argv = splitTopLevel(argvRaw.slice(1, -1))
          .map((a) => argToPath(a))
          .filter((a) => a !== null);
      }
      push({
        ...base, op: "proc_spawn", bin,
        argv, cmd: argv.length > 0 ? argv.join(" ") : bin,
        argv_truncated: argvRaw.includes("..."),
        ok: ret.ok, error: ret.error,
      });
      return true;
    }
    default:
      return true; // syscall outside our trace set; not an error
  }
}

for (const file of traceFiles) {
  const full = path.join(traceDir, file);
  const pid = Number(/^trace\.(\d+)$/.exec(file)[1]);
  const pending = new Map(); // syscall name -> { ts, argsText } awaiting `resumed`
  const rl = createInterface({ input: createReadStream(full), crlfDelay: Infinity });

  for await (const line of rl) {
    if (line === "") continue;
    stats.lines += 1;

    const lm = LINE_RE.exec(line);
    if (!lm) {
      // `+++ exited with 0 +++` / `--- SIGCHLD ... ---` appear without a timestamp in some builds.
      if (line.includes("+++")) stats.exits += 1;
      else if (line.includes("---")) stats.signals += 1;
      else stats.parse_errors += 1;
      continue;
    }
    const linePid = lm[1] ? Number(lm[1]) : pid;
    const ts = Number(lm[2]);
    const rest = lm[3];

    if (rest.startsWith("+++")) { stats.exits += 1; continue; }
    if (rest.startsWith("---")) { stats.signals += 1; continue; }

    // A syscall interrupted by a signal is split across two lines.
    const resumed = /^<\.\.\.\s+([a-z_0-9]+)\s+resumed>\s*(.*)$/.exec(rest);
    if (resumed) {
      const nm = resumed[1];
      const head = pending.get(nm);
      pending.delete(nm);
      if (!head) { stats.unfinished_unmatched += 1; continue; }
      const tailText = resumed[2];
      const closeIdx = tailText.indexOf(")");
      const argsTail = closeIdx >= 0 ? tailText.slice(0, closeIdx) : tailText;
      const retText = closeIdx >= 0 ? tailText.slice(closeIdx + 1).trim() : "";
      const merged = head.argsText + argsTail;
      if (handleCall(linePid, head.ts, nm, merged, retText)) stats.parsed += 1;
      else stats.parse_errors += 1;
      continue;
    }

    const cm = CALL_RE.exec(rest);
    if (!cm) { stats.parse_errors += 1; continue; }
    const name = cm[1];
    const body = cm[2];

    if (body.endsWith("<unfinished ...>")) {
      pending.set(name, { ts, argsText: body.slice(0, -"<unfinished ...>".length).trim() });
      continue;
    }

    const sc = splitCall(body);
    if (!sc) { stats.parse_errors += 1; continue; }
    if (handleCall(linePid, ts, name, sc.args, sc.ret)) stats.parsed += 1;
    else stats.parse_errors += 1;
  }

  stats.unfinished_unmatched += pending.size;
}

events.sort((a, b) => (a.ts_ns - b.ts_ns) || (a.pid - b.pid));

// Completeness is the whole point of Rules.md §2: a recording that lost data must be visibly
// incomplete. Three independent ways to be incomplete, all surfaced.
const sessionComplete = session ? session.complete === true : false;
const complete = sessionComplete && !stats.capped && traceFiles.length > 0;
const reasons = [];
if (!session) reasons.push("session.json missing");
else if (session.complete !== true) reasons.push(session.incomplete_reason || "recorder reported incomplete");
if (stats.capped) reasons.push(`event cap of ${MAX_EVENTS} reached`);
if (traceFiles.length === 0) reasons.push("no trace files");

const lines = events.map((e) => JSON.stringify(e));
lines.push(JSON.stringify({
  ts_ns: events.length > 0 ? events[events.length - 1].ts_ns : 0,
  op: "session_end",
  complete,
  incomplete_reasons: reasons,
  backend: "strace",
  parser_version: PARSER_VERSION,
  schema_version: 1,
}));

writeFileSync(opts.out, lines.join("\n") + "\n");

const statsOut = path.join(path.dirname(opts.out), "parse-stats.json");
writeFileSync(statsOut, JSON.stringify({
  parser_version: PARSER_VERSION,
  trace_files: traceFiles.length,
  events: events.length,
  complete,
  incomplete_reasons: reasons,
  ...stats,
}, null, 2) + "\n");

console.error(
  `parse-trace: ${events.length} events from ${traceFiles.length} trace files ` +
  `(lines=${stats.lines} parse_errors=${stats.parse_errors} complete=${complete})`
);

// heartbeat events (Architecture.md:50) are intentionally absent: they are a property of a live
// recorder, and this harness cannot invent them after the fact. Completeness here derives from
// session.json + the cap check above. Phase 1's recorder owns real heartbeats.
