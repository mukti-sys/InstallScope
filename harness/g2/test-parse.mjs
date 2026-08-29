#!/usr/bin/env node
// test-parse.mjs — golden test for the G2 parser + classifier.
//
// Runs against fixtures/synthetic/ (labeled synthetic per Rules.md §5) and asserts the parser
// extracts what it should and, just as importantly, does NOT invent what it cannot know.
//
// Pure Node, no Linux dependency: this is what makes the harness verifiable off a runner.
// Usage: node harness/g2/test-parse.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync, cpSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.join(here, "fixtures", "synthetic");

let failures = 0;
let checks = 0;

function check(name, cond, detail) {
  checks += 1;
  if (cond) {
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function findEvent(events, pred) {
  return events.find(pred);
}

const work = mkdtempSync(path.join(tmpdir(), "g2-test-"));
try {
  // The parser reads trace.* from <indir>/trace or <indir>; copy the fixture into a scratch dir so
  // the test never writes into the repo.
  cpSync(fixtureDir, work, { recursive: true });

  const eventsPath = path.join(work, "events.jsonl");
  const findingsPath = path.join(work, "findings.json");

  console.log("parse-trace.mjs");
  execFileSync(process.execPath, [
    path.join(here, "parse-trace.mjs"), "--indir", work, "--out", eventsPath,
  ], { stdio: ["ignore", "inherit", "pipe"] });

  const lines = readFileSync(eventsPath, "utf8").split("\n").filter((l) => l.trim() !== "");
  const parsed = lines.map((l) => JSON.parse(l));
  const sessionEnd = parsed.find((e) => e.op === "session_end");
  const events = parsed.filter((e) => e.op !== "session_end");

  check("emits a session_end event", Boolean(sessionEnd));
  check("session_end marks the synthetic recording complete", sessionEnd && sessionEnd.complete === true,
    sessionEnd ? JSON.stringify(sessionEnd.incomplete_reasons) : "no session_end");
  check("ts_ns is session-relative, not epoch", events.every((e) => e.ts_ns < 1e12),
    `max ts_ns=${Math.max(...events.map((e) => e.ts_ns))}`);
  check("events are timestamp-ordered",
    events.every((e, i) => i === 0 || events[i - 1].ts_ns <= e.ts_ns));
  check("every event stamps backend=strace", events.every((e) => e.backend === "strace"));

  // --- writes ---
  check("records the write to /etc/cron.d (outside every expected dir)",
    Boolean(findEvent(events, (e) => e.op === "fs_write" && e.path === "/etc/cron.d/installscope-fixture")));
  check("records a cache write",
    Boolean(findEvent(events, (e) => e.op === "fs_write" && (e.path || "").includes("/work/cache/_cacache/index-v5"))));
  check("does NOT turn a read-only open of an uninteresting path into a write",
    !findEvent(events, (e) => e.op === "fs_write" && e.path === "/proc/self/status"));
  check("leaves a relative path unresolved rather than guessing a cwd",
    Boolean(findEvent(events, (e) => e.op === "fs_write" && e.path === "relative-file.txt")));
  check("records rename with its source", (() => {
    const e = findEvent(events, (x) => x.kind === "rename");
    return Boolean(e && e.from === "/work/tmp/staging-abc" && e.path === "/work/project/node_modules/fixture");
  })());
  check("records symlink with its target", (() => {
    const e = findEvent(events, (x) => x.kind === "symlink");
    return Boolean(e && e.target === "../fixture/bin.js");
  })());
  check("records unlink as a delete", Boolean(findEvent(events, (e) => e.kind === "delete")));
  check("records mkdir", Boolean(findEvent(events, (e) => e.kind === "mkdir")));

  // --- reads of interest ---
  check("records the SSH private key read",
    Boolean(findEvent(events, (e) => e.op === "fs_read" && e.path === "/work/home/.ssh/id_rsa")));
  check("records the FAILED aws credentials read as ok:false", (() => {
    const e = findEvent(events, (x) => (x.path || "").endsWith("/.aws/credentials"));
    return Boolean(e && e.ok === false && e.error === "ENOENT");
  })());
  check("records the .npmrc read", Boolean(findEvent(events, (e) => (e.path || "").endsWith("/.npmrc"))));

  // --- network ---
  const connects = events.filter((e) => e.op === "net_connect");
  check("records the unfinished/resumed connect exactly once",
    connects.filter((e) => e.ip === "104.16.0.1").length === 1,
    `got ${connects.filter((e) => e.ip === "104.16.0.1").length}`);
  check("treats EINPROGRESS as a successful connection attempt", (() => {
    const e = findEvent(connects, (x) => x.ip === "104.16.0.1");
    return Boolean(e && e.ok === true && e.error === "EINPROGRESS");
  })());
  check("flags 127.0.0.53 as loopback", (() => {
    const e = findEvent(events, (x) => x.op === "net_connect" && x.ip === "127.0.0.53");
    return Boolean(e && e.loopback === true && e.private === true);
  })());
  check("records the port 6379 connect as external", (() => {
    const e = findEvent(connects, (x) => x.port === 6379);
    return Boolean(e && e.ip === "203.0.113.10" && e.private === false);
  })());

  // --- DNS ---
  const dns = events.filter((e) => e.op === "dns_query");
  const qnames = dns.map((e) => e.qname).sort();
  check("decodes registry.npmjs.org from a sendto payload", qnames.includes("registry.npmjs.org"), JSON.stringify(qnames));
  check("decodes telemetry.example.com", qnames.includes("telemetry.example.com"), JSON.stringify(qnames));
  check("decodes github.com", qnames.includes("github.com"), JSON.stringify(qnames));
  check("emits NO event for the truncated sendmsg DNS payload",
    !qnames.some((q) => q.startsWith("registry.np") && q !== "registry.npmjs.org"),
    JSON.stringify(qnames));
  check("truncated payload counted, not silently dropped", (() => {
    const stats = JSON.parse(readFileSync(path.join(work, "parse-stats.json"), "utf8"));
    return stats.dns_payload_undecodable >= 1;
  })());

  // --- spawns ---
  const spawns = events.filter((e) => e.op === "proc_spawn");
  check("records all five execve calls", spawns.length === 5, `got ${spawns.length}`);
  check("reconstructs the curl argv", (() => {
    const e = findEvent(spawns, (x) => (x.bin || "").endsWith("/curl"));
    return Boolean(e && e.cmd.includes("https://fixture.invalid/payload.bin"));
  })());
  check("preserves the sh -c script text", (() => {
    const e = findEvent(spawns, (x) => Array.isArray(x.argv) && x.argv.includes("-c"));
    return Boolean(e && e.cmd.includes("| sh"));
  })());

  // --- chmod ---
  check("records the chmod on /usr/local/bin", (() => {
    const e = findEvent(events, (x) => x.op === "fs_chmod");
    return Boolean(e && e.path === "/usr/local/bin/fixture-tool" && (e.mode || "").includes("755"));
  })());

  // --- parse hygiene ---
  const stats = JSON.parse(readFileSync(path.join(work, "parse-stats.json"), "utf8"));
  check("reports zero parse errors on the fixture", stats.parse_errors === 0, `parse_errors=${stats.parse_errors}`);
  check("no unmatched unfinished syscalls", stats.unfinished_unmatched === 0, `unmatched=${stats.unfinished_unmatched}`);
  check("counts the signal line", stats.signals >= 1);
  check("counts the exit lines", stats.exits >= 2, `exits=${stats.exits}`);
  check("ignores non-trace files in the fixture dir", stats.trace_files === 2, `trace_files=${stats.trace_files}`);

  // --- classifier ---
  console.log("classify.mjs");
  execFileSync(process.execPath, [
    path.join(here, "classify.mjs"), "--indir", work, "--out", findingsPath,
  ], { stdio: ["ignore", "inherit", "pipe"] });

  const f = JSON.parse(readFileSync(findingsPath, "utf8"));
  const rules = new Set(f.findings.map((x) => x.rule));

  check("flags the write outside expected dirs as critical", (() => {
    const r = f.findings.find((x) => x.rule === "write_outside_expected_dirs");
    return Boolean(r && r.severity === "critical" && r.subject === "/etc/cron.d/installscope-fixture");
  })());
  check("does NOT flag project/cache/home/tmp writes as outside",
    f.findings.filter((x) => x.rule === "write_outside_expected_dirs").length === 1,
    `got ${f.findings.filter((x) => x.rule === "write_outside_expected_dirs").length}`);
  check("does NOT flag the unresolved relative path as an outside write",
    !f.findings.some((x) => x.rule === "write_outside_expected_dirs" && x.subject === "relative-file.txt"));
  check("flags download-piped-to-shell as critical", (() => {
    const r = f.findings.find((x) => x.rule === "download_piped_to_shell");
    return Boolean(r && r.severity === "critical");
  })());
  check("flags the spawned curl as high", (() => {
    const r = f.findings.find((x) => x.rule === "spawned_network_tool");
    return Boolean(r && r.severity === "high" && r.subject === "curl");
  })());
  check("flags the SSH key read as high", (() => {
    const r = f.findings.find((x) => x.rule === "credential_path_access" && x.subject.endsWith("id_rsa"));
    return Boolean(r && r.severity === "high");
  })());
  check("reports the FAILED aws read as an attempt at medium", (() => {
    const r = f.findings.find((x) => x.rule === "credential_path_access_attempted");
    return Boolean(r && r.severity === "medium" && r.subject.endsWith("/.aws/credentials"));
  })());
  check("treats telemetry.example.com as a high non-registry host", (() => {
    const r = f.findings.find((x) => x.rule === "dns_non_registry_host" && x.subject === "telemetry.example.com");
    return Boolean(r && r.severity === "high");
  })());
  check("does NOT flag registry.npmjs.org as non-registry",
    !f.findings.some((x) => x.subject === "registry.npmjs.org"));
  check("treats github.com as a known distribution host at medium", (() => {
    const r = f.findings.find((x) => x.subject === "github.com");
    return Boolean(r && r.rule === "install_downloads_from_non_registry_host" && r.severity === "medium");
  })());
  check("flags the unusual-port connect as high", (() => {
    const r = f.findings.find((x) => x.rule === "network_connect_unusual_port");
    return Boolean(r && r.severity === "high" && r.subject === "203.0.113.10:6379");
  })());
  check("does NOT report loopback connects as external network findings",
    !f.findings.some((x) => (x.subject || "").startsWith("127.")));
  check("flags chmod +x outside the project as high", rules.has("chmod_exec_outside_project"));
  check("flags the unexpected binary at medium", (() => {
    const r = f.findings.find((x) => x.rule === "spawned_unexpected_binary");
    return Boolean(r && r.severity === "medium" && r.subject === "weirdtool");
  })());
  check("does NOT flag node/npm as unexpected binaries",
    !f.findings.some((x) => x.rule === "spawned_unexpected_binary" && ["node", "npm"].includes(x.subject)));
  check("keeps .npmrc at low so it never drives the gate", (() => {
    const r = f.findings.find((x) => x.rule === "npmrc_access");
    return Boolean(r && r.severity === "low");
  })());

  // score: 2 critical (x40=80) + 4 high (x15=60) + 2 medium (x5=10) + low, capped at 100
  check("score is capped at 100", f.score === 100, `score=${f.score} raw=${f.raw_score}`);
  check("raw score exceeds the cap, proving the cap fired", f.raw_score > 100, `raw=${f.raw_score}`);
  check("recording is not marked PARTIAL", f.partial === false, JSON.stringify(f.partial_reasons));
  check("candidate surprises exclude low and known-CDN findings",
    f.candidate_surprises.every((c) => c.severity !== "low" &&
      c.rule !== "install_downloads_from_non_registry_host" &&
      c.rule !== "network_connect_external" &&
      c.rule !== "npmrc_access"),
    JSON.stringify(f.candidate_surprises.map((c) => c.rule)));
  check("finds candidate surprises in the fixture", f.candidate_surprises.length >= 6,
    `got ${f.candidate_surprises.length}`);

  // --- PARTIAL propagation: the failure mode PRD.md:58 calls the worst one -------------------
  console.log("PARTIAL propagation");
  const partialDir = mkdtempSync(path.join(tmpdir(), "g2-partial-"));
  try {
    cpSync(fixtureDir, partialDir, { recursive: true });
    const s = JSON.parse(readFileSync(path.join(partialDir, "session.json"), "utf8"));
    s.complete = false;
    s.timed_out = true;
    s.incomplete_reason = "install exceeded 300s timeout";
    const { writeFileSync } = await import("node:fs");
    writeFileSync(path.join(partialDir, "session.json"), JSON.stringify(s, null, 2));

    const pEvents = path.join(partialDir, "events.jsonl");
    const pFindings = path.join(partialDir, "findings.json");
    execFileSync(process.execPath, [path.join(here, "parse-trace.mjs"), "--indir", partialDir, "--out", pEvents],
      { stdio: ["ignore", "inherit", "pipe"] });
    execFileSync(process.execPath, [path.join(here, "classify.mjs"), "--indir", partialDir, "--out", pFindings],
      { stdio: ["ignore", "inherit", "pipe"] });

    const pf = JSON.parse(readFileSync(pFindings, "utf8"));
    check("an incomplete session produces partial:true", pf.partial === true);
    check("the PARTIAL reason is carried through to findings",
      pf.partial_reasons.some((r) => r.includes("timeout")), JSON.stringify(pf.partial_reasons));
  } finally {
    rmSync(partialDir, { recursive: true, force: true });
  }

  // --- aggregator ---------------------------------------------------------------------------
  console.log("aggregate.mjs");
  const aggRoot = mkdtempSync(path.join(tmpdir(), "g2-agg-"));
  try {
    const pkgDir = path.join(aggRoot, "SYNTHETIC-FIXTURE-not-a-real-package");
    cpSync(work, pkgDir, { recursive: true });
    const outJson = path.join(aggRoot, "g2-summary.json");
    const outMd = path.join(aggRoot, "SUMMARY.md");
    execFileSync(process.execPath, [
      path.join(here, "aggregate.mjs"), "--indir", aggRoot, "--out-json", outJson, "--out-md", outMd,
    ], { stdio: ["ignore", "inherit", "pipe"] });

    const agg = JSON.parse(readFileSync(outJson, "utf8"));
    check("aggregator finds the package", agg.totals.packages_recorded === 1, JSON.stringify(agg.totals));
    check("aggregator counts distinct package+rule pairs", agg.totals.distinct_package_rule_pairs >= 6);
    check("aggregator never declares the gate passed", agg.verdict.needs_human_review === true &&
      !("pass" in agg.verdict));
    check("aggregator writes markdown", existsSync(outMd) && readFileSync(outMd, "utf8").includes("candidates, not receipts"));
  } finally {
    rmSync(aggRoot, { recursive: true, force: true });
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log("");
console.log(`${checks - failures}/${checks} checks passed`);
if (failures > 0) {
  console.log(`${failures} FAILED`);
  process.exit(1);
}
