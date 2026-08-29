#!/usr/bin/env node
// classify.mjs — G2 harness: events.jsonl -> findings.json
//
// Gate tooling, not product code. Severities follow Architecture.md §4. This is NOT the public
// YAML rule catalog (Architecture.md:63) — that is Phase 3. Kept as throwaway JS on purpose.
//
// Scoring (PRD.md §7): critical x40, high x15, medium x5, low x1, capped at 100.
//
// FP paranoia is the religion (PRD.md:43). Every rule here is written to stay quiet on ordinary
// install behavior, because a gate that flags all 50 packages has measured nothing. Where a rule
// cannot distinguish benign from suspicious, it emits `low` (informational) rather than inflating
// severity.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";

const CLASSIFIER_VERSION = "g2-classify-0.1.0";

const WEIGHTS = { critical: 40, high: 15, medium: 5, low: 1 };

function fail(msg) {
  console.error(`classify: FATAL: ${msg}`);
  process.exit(2);
}

function parseArgs(argv) {
  const out = { indir: null, out: null, events: null };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--indir") out.indir = argv[++i];
    else if (a === "--out") out.out = argv[++i];
    else if (a === "--events") out.events = argv[++i];
    else if (a === "-h" || a === "--help") {
      console.log("Usage: classify.mjs --indir <dir> [--events events.jsonl] --out <findings.json>");
      process.exit(0);
    } else fail(`unknown argument: ${a}`);
  }
  if (!out.indir) fail("--indir is required");
  if (!out.out) fail("--out is required");
  return out;
}

// ---------------------------------------------------------------------------------------------
// Registry / infrastructure allowlist
//
// TODO-verify: these are the hostnames npm and pnpm are expected to contact for package fetches
// on a default configuration. Verified only against observed harness traces, not against vendor
// documentation. Any addition must be justified by a trace, never by assumption — an over-broad
// allowlist silently deletes findings, which is the failure mode that matters here.
// ---------------------------------------------------------------------------------------------
const REGISTRY_HOSTS = [
  "registry.npmjs.org",
  "registry.npmjs.com",
  "npmjs.org",
  "www.npmjs.org",
  "registry.yarnpkg.com",
];

// Suffix-matched. A CDN that serves package tarballs is install infrastructure; a CDN that serves
// a vendor's telemetry endpoint is not, and suffix matching cannot tell them apart. Kept narrow.
const REGISTRY_SUFFIXES = [
  ".npmjs.org",
  ".npmjs.com",
  ".yarnpkg.com",
];

function isRegistryHost(host) {
  if (!host) return false;
  const h = host.toLowerCase().replace(/\.$/, "");
  if (REGISTRY_HOSTS.includes(h)) return true;
  return REGISTRY_SUFFIXES.some((s) => h.endsWith(s));
}

// Hosts that indicate a build downloading its own binaries — the behavior the product exists to
// make visible. Not "malicious": node-gyp, sharp, and puppeteer legitimately do this. Reported so
// a human can judge.
const BINARY_HOST_PATTERNS = [
  /(^|\.)github\.com$/, /(^|\.)githubusercontent\.com$/, /(^|\.)github\.io$/,
  /(^|\.)nodejs\.org$/, /(^|\.)electronjs\.org$/,
  /(^|\.)storage\.googleapis\.com$/, /(^|\.)googleapis\.com$/,
  /(^|\.)s3[.-][a-z0-9-]+\.amazonaws\.com$/, /(^|\.)s3\.amazonaws\.com$/,
  /(^|\.)cloudfront\.net$/,
  /(^|\.)jsdelivr\.net$/, /(^|\.)unpkg\.com$/,
  /(^|\.)playwright\.azureedge\.net$/, /(^|\.)azureedge\.net$/,
];

function looksLikeBinaryHost(host) {
  const h = (host || "").toLowerCase();
  return BINARY_HOST_PATTERNS.some((re) => re.test(h));
}

// Credential-bearing paths (Architecture.md:60).
const CREDENTIAL_PATTERNS = [
  { re: /\/\.ssh(\/|$)/, what: "SSH keys" },
  { re: /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/, what: "SSH private key" },
  { re: /\/\.aws(\/|$)/, what: "AWS credentials" },
  { re: /\/\.docker\/config\.json$/, what: "Docker registry auth" },
  { re: /\/\.git-credentials$/, what: "git credentials" },
  { re: /\/\.netrc$/, what: "netrc credentials" },
  { re: /\/\.kube(\/|$)/, what: "Kubernetes config" },
  { re: /\/\.config\/gcloud(\/|$)/, what: "GCP credentials" },
  { re: /(^|\/)\.env(\.[A-Za-z0-9_.-]+)?$/, what: "environment file" },
  { re: /\/etc\/shadow$/, what: "/etc/shadow" },
  { re: /\/proc\/(self|\d+)\/environ$/, what: "process environment" },
];

// .npmrc holds auth tokens, but npm reads its own config on every run. Tracked separately so it
// never produces a finding on its own; only a non-npm reader is interesting.
const NPMRC_RE = /\/\.npmrc$/;

const SHELL_BINS = new Set(["sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish"]);
const NET_BINS = new Set(["curl", "wget", "nc", "ncat", "netcat", "ftp", "scp", "sftp", "ssh"]);

// Binaries a normal npm install legitimately spawns. Suppressed to keep the spawn signal usable.
const EXPECTED_SPAWN_BINS = new Set([
  "node", "npm", "npx", "pnpm", "sh", "bash", "env", "which", "uname", "getconf",
  "node-gyp", "python", "python3", "make", "cc", "gcc", "c++", "g++", "ld", "ar", "ranlib",
  "as", "cpp", "collect2", "cc1", "cc1plus", "nm", "objdump", "strip", "install", "sed", "grep",
  "egrep", "fgrep", "awk", "cat", "cp", "mv", "rm", "mkdir", "rmdir", "ln", "chmod", "touch",
  "true", "false", "test", "expr", "basename", "dirname", "printf", "echo", "pwd", "ls", "find",
  "xargs", "sort", "uniq", "head", "tail", "tr", "wc", "date", "hostname", "id", "tar", "gzip",
  "gunzip", "unzip", "bzip2", "xz", "zstd", "git", "pkg-config", "libtool", "m4", "gmake",
  "ccache", "sccache", "prebuild-install", "node-pre-gyp", "cmake", "ninja", "rustc", "cargo",
]);

function baseName(p) {
  if (!p) return null;
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : p;
}

// A shell invoked with -c where the script text pipes a download into an interpreter. This is the
// critical case in Architecture.md:59.
function pipesDownloadToShell(argv) {
  if (!Array.isArray(argv) || argv.length < 3) return false;
  const bin = baseName(argv[0]);
  if (!SHELL_BINS.has(bin ?? "")) return false;
  const ci = argv.indexOf("-c");
  if (ci === -1 || ci + 1 >= argv.length) return false;
  const script = argv[ci + 1] ?? "";
  const downloads = /\b(curl|wget|fetch)\b/.test(script);
  const pipesToInterp = /\|\s*(sudo\s+)?(sh|bash|dash|zsh|python[0-9.]*|perl|ruby|node)\b/.test(script);
  return downloads && pipesToInterp;
}

// ---------------------------------------------------------------------------------------------

const opts = parseArgs(process.argv);
const indir = path.resolve(opts.indir);
const eventsPath = opts.events ? path.resolve(opts.events) : path.join(indir, "events.jsonl");
if (!existsSync(eventsPath)) fail(`events file not found: ${eventsPath}`);

const sessionPath = path.join(indir, "session.json");
let session = null;
if (existsSync(sessionPath)) {
  try { session = JSON.parse(readFileSync(sessionPath, "utf8")); }
  catch (err) { fail(`session.json is not valid JSON: ${err.message}`); }
}

const raw = readFileSync(eventsPath, "utf8").split("\n").filter((l) => l.trim() !== "");
const events = [];
let sessionEnd = null;
let malformed = 0;
for (const line of raw) {
  let ev;
  try { ev = JSON.parse(line); } catch { malformed += 1; continue; }
  if (ev.op === "session_end") { sessionEnd = ev; continue; }
  events.push(ev);
}

// Expected write zones. Anything the harness itself created is by definition expected; a write
// outside all of them is Architecture.md:57's critical case.
const paths = (session && session.paths) || {};
const zones = [
  { name: "project", prefix: paths.project },
  { name: "cache", prefix: paths.cache },
  { name: "home", prefix: paths.home },
  { name: "tmp", prefix: paths.tmp },
].filter((z) => typeof z.prefix === "string" && z.prefix.length > 0);

// System locations an install touches without it meaning anything. Reading these is normal;
// WRITING outside the harness zones is what gets reported, and these are excluded because they
// are runtime scaffolding (procfs, ttys, tmp) rather than persistence.
const BENIGN_WRITE_PREFIXES = [
  "/proc/", "/sys/", "/dev/null", "/dev/tty", "/dev/pts/", "/dev/urandom", "/dev/random",
  "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/fd/", "/run/", "/var/run/",
];

function zoneOf(p) {
  if (!p) return "unresolved";
  if (!p.startsWith("/")) return "unresolved"; // relative path, cwd unknown
  for (const z of zones) {
    if (p === z.prefix || p.startsWith(z.prefix.endsWith("/") ? z.prefix : z.prefix + "/")) {
      return z.name;
    }
  }
  if (BENIGN_WRITE_PREFIXES.some((pre) => p === pre || p.startsWith(pre))) return "runtime";
  // /tmp writes with a system TMPDIR still count as tmp: builds legitimately use it.
  if (p.startsWith("/tmp/") || p.startsWith("/var/tmp/")) return "tmp";
  return "outside";
}

const findings = [];
const seen = new Set();

// Only successful operations become findings. A failed openat on ~/.ssh is an *attempt*, which is
// interesting, so failures are kept but marked — attempted access is reported one level lower
// rather than dropped.
function addFinding(f) {
  const key = `${f.rule}|${f.subject}`;
  if (seen.has(key)) {
    const existing = findings.find((x) => x.rule === f.rule && x.subject === f.subject);
    if (existing) {
      existing.count += 1;
      if (existing.evidence.length < 5) existing.evidence.push(...f.evidence.slice(0, 1));
    }
    return;
  }
  seen.add(key);
  findings.push({ count: 1, ...f });
}

function ev(e) {
  return { ts_ns: e.ts_ns, pid: e.pid, syscall: e.syscall, op: e.op, ...(e.path ? { path: e.path } : {}) };
}

// ---- rule: writes outside expected zones (critical, Architecture.md:57) ----------------------
const outsideWrites = events.filter((e) => e.op === "fs_write" && e.ok !== false && zoneOf(e.path) === "outside");
for (const e of outsideWrites) {
  addFinding({
    rule: "write_outside_expected_dirs",
    severity: "critical",
    subject: e.path,
    title: `wrote outside project, cache, home, and tmp: ${e.path}`,
    evidence: [ev(e)],
  });
}

// ---- rule: network to non-registry host ------------------------------------------------------
// DNS gives hostnames; connect gives IPs. strace cannot join them, so both are reported and the
// distinction is stated rather than papered over.
const dnsQueries = events.filter((e) => e.op === "dns_query" && e.qname);
const nonRegistryQnames = new Map();
for (const e of dnsQueries) {
  const h = e.qname.toLowerCase().replace(/\.$/, "");
  if (isRegistryHost(h)) continue;
  if (!h.includes(".")) continue; // single-label: search-domain noise, not a real destination
  if (!nonRegistryQnames.has(h)) nonRegistryQnames.set(h, e);
}
for (const [host, e] of nonRegistryQnames) {
  const binary = looksLikeBinaryHost(host);
  addFinding({
    rule: binary ? "install_downloads_from_non_registry_host" : "dns_non_registry_host",
    severity: binary ? "medium" : "high",
    subject: host,
    title: binary
      ? `resolved non-registry distribution host during install: ${host}`
      : `resolved non-registry host during install: ${host}`,
    note: binary
      ? "known binary/CDN distribution host — expected for packages that fetch prebuilt artifacts, still worth showing"
      : "hostname seen in a DNS query; strace cannot prove a connection followed",
    evidence: [ev(e)],
  });
}

// External TCP connects. Ports 80/443 dominate; anything else is more interesting.
const externalConnects = events.filter((e) =>
  e.op === "net_connect" && e.ok !== false && !e.loopback && !e.private
);
const connectByKey = new Map();
for (const e of externalConnects) {
  const key = `${e.ip}:${e.port}`;
  if (!connectByKey.has(key)) connectByKey.set(key, e);
}
for (const [key, e] of connectByKey) {
  const unusualPort = ![80, 443].includes(e.port);
  addFinding({
    rule: unusualPort ? "network_connect_unusual_port" : "network_connect_external",
    severity: unusualPort ? "high" : "low",
    subject: key,
    title: unusualPort
      ? `connected to external address on unusual port: ${key}`
      : `connected to external address: ${key}`,
    note: "IP-level only; strace cannot attribute a TCP connect to a hostname",
    evidence: [ev(e)],
  });
}

// ---- rule: credential / env reads (high, Architecture.md:60) ---------------------------------
for (const e of events) {
  if (e.op !== "fs_read" && e.op !== "fs_write") continue;
  const p = e.path;
  if (!p) continue;
  const hit = CREDENTIAL_PATTERNS.find((c) => c.re.test(p));
  if (hit) {
    const attempted = e.ok === false;
    addFinding({
      rule: attempted ? "credential_path_access_attempted" : "credential_path_access",
      severity: attempted ? "medium" : "high",
      subject: p,
      title: `${attempted ? "attempted to read" : "read"} ${hit.what}: ${p}`,
      note: attempted ? `syscall failed with ${e.error ?? "error"} — the attempt is the finding` : undefined,
      evidence: [ev(e)],
    });
    continue;
  }
  if (NPMRC_RE.test(p) && e.ok !== false) {
    // npm reading its own config is not a finding. Recorded as low so the evidence exists.
    addFinding({
      rule: "npmrc_access",
      severity: "low",
      subject: p,
      title: `read npm config (may contain auth tokens): ${p}`,
      note: "npm reads its own config on every run; only surprising if a non-npm process does it",
      evidence: [ev(e)],
    });
  }
}

// ---- rule: process spawns (high / critical, Architecture.md:59) -------------------------------
const spawns = events.filter((e) => e.op === "proc_spawn" && e.ok !== false);
for (const e of spawns) {
  const bin = baseName(e.bin);
  if (pipesDownloadToShell(e.argv)) {
    addFinding({
      rule: "download_piped_to_shell",
      severity: "critical",
      subject: e.cmd ?? bin ?? "unknown",
      title: `piped a download into a shell: ${(e.cmd ?? "").slice(0, 200)}`,
      evidence: [ev(e)],
    });
    continue;
  }
  if (NET_BINS.has(bin ?? "")) {
    addFinding({
      rule: "spawned_network_tool",
      severity: "high",
      subject: bin,
      title: `spawned network tool during install: ${(e.cmd ?? bin ?? "").slice(0, 200)}`,
      evidence: [ev(e)],
    });
    continue;
  }
  if (!EXPECTED_SPAWN_BINS.has(bin ?? "")) {
    addFinding({
      rule: "spawned_unexpected_binary",
      severity: "medium",
      subject: bin ?? "unknown",
      title: `spawned unexpected binary: ${(e.cmd ?? bin ?? "").slice(0, 200)}`,
      note: "not on the harness's expected-toolchain list; many are legitimate build tools",
      evidence: [ev(e)],
    });
  }
}

// ---- rule: made a file executable outside the project ----------------------------------------
for (const e of events) {
  if (e.op !== "fs_chmod" || e.ok === false) continue;
  const mode = e.mode ?? "";
  if (!/7|5|1/.test(mode)) continue; // crude exec-bit check on strace's octal/symbolic render
  const zone = zoneOf(e.path);
  if (zone === "outside") {
    addFinding({
      rule: "chmod_exec_outside_project",
      severity: "high",
      subject: e.path,
      title: `made a file executable outside expected dirs: ${e.path} (${mode})`,
      evidence: [ev(e)],
    });
  }
}

// ---------------------------------------------------------------------------------------------
// score
// ---------------------------------------------------------------------------------------------
const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
for (const f of findings) bySeverity[f.severity] += 1;

const rawScore =
  bySeverity.critical * WEIGHTS.critical +
  bySeverity.high * WEIGHTS.high +
  bySeverity.medium * WEIGHTS.medium +
  bySeverity.low * WEIGHTS.low;
const score = Math.min(100, rawScore);

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
findings.sort((a, b) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || (b.count - a.count));

// PARTIAL is mandatory whenever the recording is not provably whole (PRD.md:58, Rules.md §2).
const complete = Boolean(sessionEnd && sessionEnd.complete === true);
const partial = !complete;
const partialReasons = [];
if (!sessionEnd) partialReasons.push("events.jsonl has no session_end event");
else if (sessionEnd.complete !== true) {
  for (const r of sessionEnd.incomplete_reasons ?? []) partialReasons.push(r);
  if (partialReasons.length === 0) partialReasons.push("recording reported incomplete");
}
if (malformed > 0) partialReasons.push(`${malformed} malformed event lines`);

// "Candidate surprise" = something a human should look at. Deliberately excludes low, and
// excludes the medium binary-download rule, so ordinary prebuilt-binary installs do not inflate
// the G2 count. A candidate is NOT a receipt until a human confirms it (harness/README.md).
const CANDIDATE_EXCLUDED_RULES = new Set([
  "install_downloads_from_non_registry_host",
  "network_connect_external",
  "npmrc_access",
]);
const candidates = findings.filter(
  (f) => (f.severity === "critical" || f.severity === "high" || f.severity === "medium") &&
    !CANDIDATE_EXCLUDED_RULES.has(f.rule)
);

const out = {
  classifier_version: CLASSIFIER_VERSION,
  gate: "G2",
  package: session ? session.package : null,
  manager: session ? session.manager : null,
  score,
  raw_score: rawScore,
  partial,
  partial_reasons: partialReasons,
  counts: {
    events: events.length,
    findings: findings.length,
    by_severity: bySeverity,
    candidate_surprises: candidates.length,
    spawns: spawns.length,
    dns_queries: dnsQueries.length,
    external_connects: externalConnects.length,
    writes_outside: outsideWrites.length,
  },
  install: session
    ? {
        exit_code: session.exit_code,
        duration_s: session.duration_s,
        timed_out: session.timed_out,
        complete: session.complete,
      }
    : null,
  candidate_surprises: candidates.map((f) => ({ rule: f.rule, severity: f.severity, subject: f.subject, title: f.title })),
  findings,
};

writeFileSync(opts.out, JSON.stringify(out, null, 2) + "\n");

console.error(
  `classify: score=${score} findings=${findings.length} candidates=${candidates.length} partial=${partial}`
);
