#!/usr/bin/env node
// shard.mjs — split a corpus plan into shards a CI matrix can run, and merge the results back.
//
// WHY SHARDING IS NECESSARY RATHER THAN NICE
//
// The plan is ~200 packages x ~5 versions = ~1000 recordings, each a real `npm install` with a cold
// cache. GitHub's matrix cap is 256 jobs, and one job per recording would also mean 1000 cold-cache
// npm installs of the runner's own toolchain overhead. So the unit of work is a *package* — all its
// versions in one job — which lands around 200 jobs and lets a package's versions share a VM.
//
// That grouping is not arbitrary. record-corpus.sh gives every recording a fresh cache, home, project
// and tmp, so what a shared VM can leak between versions is only state outside those zones. Versions
// of the *same* package sharing that risk is acceptable; versions of *different* packages sharing it
// is not, because then one package's postinstall could show up as another's behavior.
//
// WHY IT IS RESUMABLE
//
// A 200-job backfill will lose jobs — a runner dies, a registry has a bad minute, a package's install
// hangs. Re-running the whole thing to recover three recordings wastes hours and, worse, re-records
// the ones that succeeded, producing second recordings of identical versions that differ only in
// timestamp. `--completed` takes the merged results of a previous run and plans only what is missing.
//
// WHY THE MERGE IS A SEPARATE STEP
//
// Each shard uploads its own results; nothing writes to a shared location during the run, because
// concurrent appends to one index from 200 jobs is a corruption waiting to happen. The registry's
// index is append-only per shard, and merging is this script's `merge` mode — done once, sequentially,
// after every shard has finished.
//
// Usage:
//   node harness/corpus/shard.mjs plan   --plan corpus-plan.json --shards 20 [--completed results/]
//                                        [--out shards.json] [--limit N]
//   node harness/corpus/shard.mjs merge  --indir results/ --out merged.json

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";

function fail(message) {
  console.error(`shard: FATAL: ${message}`);
  process.exit(2);
}

function log(message) {
  console.error(`shard: ${message}`);
}

const mode = process.argv[2];
if (mode !== "plan" && mode !== "merge") {
  console.error(
    "Usage: shard.mjs plan  --plan FILE --shards N [--completed DIR] [--out FILE] [--limit N]\n" +
      "       shard.mjs merge --indir DIR [--out FILE]"
  );
  process.exit(mode === undefined || mode === "-h" || mode === "--help" ? 0 : 2);
}

const options = {
  plan: "corpus-plan.json",
  shards: 20,
  completed: "",
  indir: "",
  out: mode === "plan" ? "shards.json" : "merged.json",
  limit: 0,
};

for (let i = 3; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  switch (arg) {
    case "--plan": options.plan = process.argv[++i]; break;
    case "--shards": options.shards = Number.parseInt(process.argv[++i], 10); break;
    case "--completed": options.completed = process.argv[++i]; break;
    case "--indir": options.indir = process.argv[++i]; break;
    case "--out": options.out = process.argv[++i]; break;
    case "--limit": options.limit = Number.parseInt(process.argv[++i], 10); break;
    default: fail(`unknown argument: ${arg}`);
  }
}

// ---------------------------------------------------------------------------------------------
// Reading recording results
// ---------------------------------------------------------------------------------------------

/**
 * Collects every recording.json under a directory tree.
 *
 * Walks rather than globs so a downloaded artifact bundle nests however GitHub chose to nest it. A
 * malformed file is reported, not skipped: a backfill that quietly ignores unreadable results
 * under-reports its own failures, and "N recordings are missing" is information the dataset needs.
 */
function collectRecordings(root) {
  const found = [];
  const malformed = [];

  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      malformed.push({ path: dir, error: error.message });
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name === "recording.json") {
        try {
          const parsed = JSON.parse(readFileSync(full, "utf8"));
          if (typeof parsed.package !== "string" || typeof parsed.version !== "string") {
            malformed.push({ path: full, error: "missing package or version" });
          } else {
            found.push({ path: full, recording: parsed });
          }
        } catch (error) {
          malformed.push({ path: full, error: error.message });
        }
      }
    }
  };

  if (!existsSync(root)) return { found, malformed };
  walk(root);
  return { found, malformed };
}

// ---------------------------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------------------------

if (mode === "plan") {
  if (!Number.isInteger(options.shards) || options.shards < 1 || options.shards > 256) {
    fail(`--shards must be an integer 1-256 (GitHub's matrix cap), got: ${options.shards}`);
  }

  let plan;
  try {
    plan = JSON.parse(readFileSync(options.plan, "utf8"));
  } catch (error) {
    fail(`cannot read ${options.plan}: ${error.message}`);
  }
  if (plan.schema !== "installscope-corpus-plan/1") {
    fail(`${options.plan} is not a corpus plan (schema: ${plan.schema ?? "absent"})`);
  }
  if (!Array.isArray(plan.packages) || plan.packages.length === 0) {
    fail(`${options.plan} contains no packages`);
  }

  // Recordings already done, keyed exactly as the plan names them.
  const done = new Set();
  let previousMalformed = 0;
  if (options.completed !== "") {
    const { found, malformed } = collectRecordings(options.completed);
    previousMalformed = malformed.length;
    for (const { recording } of found) {
      // A PARTIAL recording counts as *attempted but not done*: it was refused by the registry, so the
      // corpus does not have it and a retry might succeed. A recording that succeeded is skipped.
      if (recording.complete === true) {
        done.add(`${recording.package}@${recording.version}`);
      }
    }
    log(
      `${done.size} recording(s) already complete in ${options.completed}` +
        (previousMalformed > 0 ? ` (${previousMalformed} unreadable)` : "")
    );
  }

  const work = [];
  let skipped = 0;
  for (const entry of plan.packages) {
    const versions = entry.versions
      .map((v) => v.version)
      .filter((version) => {
        if (done.has(`${entry.package}@${version}`)) { skipped += 1; return false; }
        return true;
      });
    if (versions.length > 0) work.push({ package: entry.package, versions });
  }

  if (options.limit > 0) work.splice(options.limit);

  if (work.length === 0) {
    // Not an error: a fully-completed backfill re-planned is the successful case, and the workflow
    // needs to be able to tell "nothing to do" from "something broke".
    log("nothing left to record — every planned version is already complete");
    writeFileSync(
      options.out,
      JSON.stringify({ schema: "installscope-corpus-shards/1", shards: [], totals: {
        packages: 0, recordings: 0, skipped_already_complete: skipped, shards: 0,
      } }, null, 2) + "\n"
    );
    console.log("0");
    process.exit(0);
  }

  // Longest-first bin packing by recording count. A package with 5 versions costs roughly 5x one with
  // 1, and round-robin over an unsorted list leaves one shard doing twice the work of another — which
  // in a matrix means the whole backfill waits for that shard.
  work.sort((a, b) => b.versions.length - a.versions.length || a.package.localeCompare(b.package));

  const shardCount = Math.min(options.shards, work.length);
  const shards = Array.from({ length: shardCount }, (_, index) => ({
    id: index,
    packages: [],
    recordings: 0,
  }));

  for (const item of work) {
    // Always the emptiest shard, with the lowest id as a deterministic tiebreak so two runs of this
    // script over the same plan produce identical shards.
    let target = shards[0];
    for (const shard of shards) {
      if (shard.recordings < target.recordings) target = shard;
    }
    target.packages.push(item);
    target.recordings += item.versions.length;
  }

  const totals = {
    packages: work.length,
    recordings: work.reduce((sum, item) => sum + item.versions.length, 0),
    skipped_already_complete: skipped,
    previous_results_unreadable: previousMalformed,
    shards: shardCount,
    recordings_per_shard: {
      min: Math.min(...shards.map((s) => s.recordings)),
      max: Math.max(...shards.map((s) => s.recordings)),
    },
  };

  writeFileSync(
    options.out,
    JSON.stringify(
      {
        schema: "installscope-corpus-shards/1",
        generated_at: new Date().toISOString(),
        plan: options.plan,
        totals,
        // The matrix GitHub consumes. `spec` is a compact encoding of one shard's work, because a
        // matrix value must be a scalar: "name:v1,v2;name2:v3".
        shards: shards.map((shard) => ({
          id: shard.id,
          recordings: shard.recordings,
          packages: shard.packages,
          spec: shard.packages.map((p) => `${p.package}:${p.versions.join(",")}`).join(";"),
        })),
      },
      null,
      2
    ) + "\n"
  );

  log(`wrote ${options.out}`);
  log(
    `${totals.recordings} recording(s) across ${shardCount} shard(s) ` +
      `(${totals.recordings_per_shard.min}-${totals.recordings_per_shard.max} each), ` +
      `${skipped} already complete`
  );
  // stdout is the shard count alone, so a workflow can capture it without parsing logs.
  console.log(String(shardCount));
  process.exit(0);
}

// ---------------------------------------------------------------------------------------------
// merge
// ---------------------------------------------------------------------------------------------

if (options.indir === "") fail("merge requires --indir");

const { found, malformed } = collectRecordings(options.indir);
if (found.length === 0 && malformed.length === 0) {
  fail(`no recording.json found anywhere under ${options.indir}`);
}

// Deduplicated by package@version, keeping the newest by started_at. A retried shard legitimately
// produces two recordings of the same version, and the corpus wants the one that succeeded.
const byKey = new Map();
let duplicates = 0;
for (const { path: file, recording } of found) {
  const key = `${recording.package}@${recording.version}`;
  const existing = byKey.get(key);
  if (!existing) {
    byKey.set(key, { file, recording });
    continue;
  }
  duplicates += 1;
  const better =
    // A complete recording always beats an incomplete one, whatever the timestamps say.
    (recording.complete === true && existing.recording.complete !== true) ||
    (recording.complete === existing.recording.complete &&
      String(recording.started_at ?? "") > String(existing.recording.started_at ?? ""));
  if (better) byKey.set(key, { file, recording });
}

const recordings = [...byKey.values()].map(({ recording }) => recording);
recordings.sort(
  (a, b) => a.package.localeCompare(b.package) || a.version.localeCompare(b.version)
);

const complete = recordings.filter((r) => r.complete === true);
const partial = recordings.filter((r) => r.recorded === true && r.complete !== true);
const failed = recordings.filter((r) => r.recorded !== true);
const pushed = recordings.filter((r) => r.snapshot?.pushed === true);
const mismatched = recordings.filter((r) => r.installed?.matches_requested === false);

const merged = {
  schema: "installscope-corpus-merged/1",
  merged_at: new Date().toISOString(),
  source_dir: options.indir,
  totals: {
    recordings: recordings.length,
    complete: complete.length,
    partial: partial.length,
    failed: failed.length,
    pushed_to_registry: pushed.length,
    version_mismatches: mismatched.length,
    duplicate_results_collapsed: duplicates,
    unreadable_results: malformed.length,
    packages: new Set(recordings.map((r) => r.package)).size,
  },
  // Named, not just counted. A backfill that reports "37 incomplete" without saying which ones cannot
  // be acted on, and the incomplete set is exactly what a retry needs.
  partial_recordings: partial.map((r) => ({
    spec: r.spec,
    reason: r.incomplete_reason,
    events: r.events,
  })),
  failed_recordings: failed.map((r) => ({ spec: r.spec, reason: r.incomplete_reason })),
  version_mismatches: mismatched.map((r) => ({
    requested: r.spec,
    installed: r.installed?.version ?? "unknown",
  })),
  unreadable_results: malformed,
  recordings,
};

writeFileSync(options.out, JSON.stringify(merged, null, 2) + "\n");
log(`wrote ${options.out}`);
log(
  `${recordings.length} recording(s): ${complete.length} complete, ${partial.length} PARTIAL, ` +
    `${failed.length} failed, ${pushed.length} pushed` +
    (duplicates > 0 ? `, ${duplicates} duplicate(s) collapsed` : "") +
    (malformed.length > 0 ? `, ${malformed.length} unreadable` : "")
);
if (mismatched.length > 0) {
  log(`${mismatched.length} recording(s) installed a different version than requested`);
}
