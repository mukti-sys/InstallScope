#!/usr/bin/env node
// aggregate.mjs — G2 harness: all per-package findings.json -> g2-summary.json + SUMMARY.md
//
// Gate tooling. Counts CANDIDATE surprises and never declares the gate passed: G2 PASS is a human
// sign-off recorded in Memory.md after reading the evidence (Rules.md §7, harness/README.md).
//
// Input layout: <indir>/<package>/findings.json (+ session.json, parse-stats.json)

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const AGGREGATOR_VERSION = "g2-aggregate-0.1.0";
const TARGET_SURPRISES = 10; // Phases.md:8

function fail(msg) {
  console.error(`aggregate: FATAL: ${msg}`);
  process.exit(2);
}

function parseArgs(argv) {
  const out = { indir: null, outJson: null, outMd: null };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--indir") out.indir = argv[++i];
    else if (a === "--out-json") out.outJson = argv[++i];
    else if (a === "--out-md") out.outMd = argv[++i];
    else if (a === "-h" || a === "--help") {
      console.log("Usage: aggregate.mjs --indir <dir-of-package-dirs> --out-json <f> --out-md <f>");
      process.exit(0);
    } else fail(`unknown argument: ${a}`);
  }
  if (!out.indir) fail("--indir is required");
  if (!out.outJson) fail("--out-json is required");
  if (!out.outMd) fail("--out-md is required");
  return out;
}

const opts = parseArgs(process.argv);
const indir = path.resolve(opts.indir);
if (!existsSync(indir)) fail(`indir does not exist: ${indir}`);

// Artifact download may nest each package in its own directory; accept either layout.
const candidateDirs = readdirSync(indir)
  .map((n) => path.join(indir, n))
  .filter((p) => { try { return statSync(p).isDirectory(); } catch { return false; } });

const packages = [];
for (const dir of candidateDirs) {
  const fPath = path.join(dir, "findings.json");
  if (!existsSync(fPath)) continue;
  let findings;
  try { findings = JSON.parse(readFileSync(fPath, "utf8")); }
  catch (err) { console.error(`aggregate: WARNING: unreadable ${fPath}: ${err.message}`); continue; }

  let parseStats = null;
  const psPath = path.join(dir, "parse-stats.json");
  if (existsSync(psPath)) {
    try { parseStats = JSON.parse(readFileSync(psPath, "utf8")); } catch { parseStats = null; }
  }

  packages.push({
    dir: path.basename(dir),
    package: findings.package ?? path.basename(dir),
    score: findings.score ?? 0,
    partial: findings.partial === true,
    partial_reasons: findings.partial_reasons ?? [],
    counts: findings.counts ?? {},
    install: findings.install ?? null,
    candidate_surprises: findings.candidate_surprises ?? [],
    findings: findings.findings ?? [],
    parse_errors: parseStats ? parseStats.parse_errors ?? null : null,
  });
}

packages.sort((a, b) => (b.score - a.score) || a.package.localeCompare(b.package));

const recorded = packages.length;
const partialCount = packages.filter((p) => p.partial).length;
const completeCount = recorded - partialCount;
const failedInstalls = packages.filter((p) => p.install && p.install.exit_code !== 0).length;

// Candidates from PARTIAL recordings are still listed, but counted separately: a truncated trace
// can produce a finding that fuller evidence would explain away, so they must not silently prop up
// the gate number.
const completePkgs = packages.filter((p) => !p.partial);
const candidatesComplete = completePkgs.flatMap((p) =>
  p.candidate_surprises.map((c) => ({ package: p.package, ...c }))
);
const candidatesPartial = packages.filter((p) => p.partial).flatMap((p) =>
  p.candidate_surprises.map((c) => ({ package: p.package, ...c }))
);

// The gate metric Phases.md:8 asks about is "documented behavioral surprises", i.e. distinct
// package-level behaviors a human can write up. Counted as distinct (package, rule) pairs from
// complete recordings only.
const distinctPairs = new Set(candidatesComplete.map((c) => `${c.package}|${c.rule}`));
const packagesWithCandidates = new Set(candidatesComplete.map((c) => c.package));

const byRule = {};
for (const c of candidatesComplete) {
  byRule[c.rule] = (byRule[c.rule] ?? 0) + 1;
}

const summary = {
  aggregator_version: AGGREGATOR_VERSION,
  gate: "G2",
  generated_at: new Date().toISOString(),
  target_surprises: TARGET_SURPRISES,
  totals: {
    packages_recorded: recorded,
    recordings_complete: completeCount,
    recordings_partial: partialCount,
    installs_nonzero_exit: failedInstalls,
    candidate_surprises_complete: candidatesComplete.length,
    candidate_surprises_partial_excluded: candidatesPartial.length,
    distinct_package_rule_pairs: distinctPairs.size,
    packages_with_candidates: packagesWithCandidates.size,
  },
  by_rule: byRule,
  // Deliberately NOT "pass": no script decides a gate.
  verdict: {
    needs_human_review: true,
    meets_target_before_review: distinctPairs.size >= TARGET_SURPRISES,
    note:
      "meets_target_before_review counts CANDIDATES only. A candidate becomes a receipt when a " +
      "human reads the evidence and confirms the behavior is genuinely surprising. G2 PASS/FAIL " +
      "is recorded in Memory.md by a human, never by this script.",
  },
  candidate_surprises: candidatesComplete,
  candidate_surprises_from_partial_recordings: candidatesPartial,
  packages,
};

writeFileSync(opts.outJson, JSON.stringify(summary, null, 2) + "\n");

// ---- markdown report -------------------------------------------------------------------------
const L = [];
L.push("# G2 — strace receipts harness results");
L.push("");
L.push(`Generated ${summary.generated_at} · aggregator \`${AGGREGATOR_VERSION}\``);
L.push("");
L.push("**These are candidates, not receipts.** A candidate becomes a receipt only after a human");
L.push("reads the evidence and confirms the behavior is genuinely surprising. No script decides");
L.push("this gate (Rules.md §7).");
L.push("");
L.push("## Totals");
L.push("");
L.push("| Metric | Value |");
L.push("|---|---|");
L.push(`| Packages recorded | ${recorded} |`);
L.push(`| Recordings complete | ${completeCount} |`);
L.push(`| Recordings PARTIAL (excluded from the gate count) | ${partialCount} |`);
L.push(`| Installs with non-zero exit | ${failedInstalls} |`);
L.push(`| Candidate surprises (complete recordings) | ${candidatesComplete.length} |`);
L.push(`| Distinct package+rule pairs | ${distinctPairs.size} |`);
L.push(`| Packages with ≥1 candidate | ${packagesWithCandidates.size} |`);
L.push(`| Target (Phases.md:8) | ≥${TARGET_SURPRISES} |`);
L.push("");
L.push(
  distinctPairs.size >= TARGET_SURPRISES
    ? `Candidate count meets the ≥${TARGET_SURPRISES} target **pending human confirmation**.`
    : `Candidate count is below the ≥${TARGET_SURPRISES} target. Per Scope.md:60, if this holds ` +
      "across the full list a human decides between repositioning and stopping. Do not widen the " +
      "rules to manufacture findings."
);
L.push("");

if (Object.keys(byRule).length > 0) {
  L.push("## Candidates by rule");
  L.push("");
  L.push("| Rule | Count |");
  L.push("|---|---|");
  for (const [rule, n] of Object.entries(byRule).sort((a, b) => b[1] - a[1])) {
    L.push(`| \`${rule}\` | ${n} |`);
  }
  L.push("");
}

L.push("## Per package");
L.push("");
L.push("| Package | Score | State | Events | Candidates | Install exit |");
L.push("|---|---|---|---|---|---|");
for (const p of packages) {
  const state = p.partial ? "**PARTIAL**" : "complete";
  const exit = p.install ? String(p.install.exit_code) : "?";
  L.push(
    `| \`${p.package}\` | ${p.score} | ${state} | ${p.counts.events ?? "?"} | ` +
    `${p.candidate_surprises.length} | ${exit} |`
  );
}
L.push("");

const interesting = packages.filter((p) => p.candidate_surprises.length > 0);
if (interesting.length > 0) {
  L.push("## Candidate detail");
  L.push("");
  for (const p of interesting) {
    L.push(`### \`${p.package}\`${p.partial ? " — PARTIAL recording, treat with suspicion" : ""}`);
    L.push("");
    if (p.partial && p.partial_reasons.length > 0) {
      L.push(`Incomplete because: ${p.partial_reasons.join("; ")}`);
      L.push("");
    }
    for (const c of p.candidate_surprises) {
      L.push(`- \`${c.severity}\` **${c.rule}** — ${c.title}`);
    }
    L.push("");
  }
}

if (partialCount > 0) {
  L.push("## PARTIAL recordings");
  L.push("");
  L.push("A recording that died must never read as clean (Rules.md §2). These need a rerun or an");
  L.push("explanation before any conclusion is drawn from them.");
  L.push("");
  for (const p of packages.filter((x) => x.partial)) {
    L.push(`- \`${p.package}\`: ${p.partial_reasons.join("; ") || "reason not recorded"}`);
  }
  L.push("");
}

L.push("## Next step");
L.push("");
L.push("1. Read the evidence for each candidate in the uploaded artifacts (`events.jsonl`).");
L.push("2. Confirm or reject each as a receipt. Rejections are as informative as confirmations.");
L.push("3. Record the human G2 verdict, the confirmed receipt count, and any rule changes in Memory.md.");
L.push("4. If confirmed receipts ≥10, pick the 3 spiciest and hold them for G3 (Phases.md:15).");
L.push("");

writeFileSync(opts.outMd, L.join("\n"));

console.error(
  `aggregate: ${recorded} packages · ${candidatesComplete.length} candidates ` +
  `· ${distinctPairs.size} distinct pairs · ${partialCount} PARTIAL`
);
