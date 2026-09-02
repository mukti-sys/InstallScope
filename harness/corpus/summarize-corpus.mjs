#!/usr/bin/env node
// summarize-corpus.mjs — turn a completed backfill into a dataset description that is true.
//
// WHAT THIS EXISTS TO PREVENT
//
// Phases.md:39 says the corpus should let us publish "we already recorded ~50k version-behaviors".
// 200 packages x 5 versions is 1000 *recordings*. Those are different quantities, and the gap between
// them is exactly the kind of number that gets rounded up in a launch post and then fact-checked.
// PRD.md:66 warns about being fact-checked on the neighbour table; the same discipline has to apply
// to our own headline.
//
// So this script computes, and refuses to compute what it cannot. It takes two inputs:
//
//   --merged   the merged recording results (from shard.mjs merge) — what was attempted and what
//              happened, including every failure
//   --corpus   the registry's own summary (from `installscope snapshot summarize --json`) — what the
//              stored evidence actually contains
//
// The behavior counts come from the registry, not from here: only the store can count behaviors,
// because only the store has the recordings. This script's job is to join the two views and notice
// where they disagree — a recording that succeeded but is not in the registry is a hole, and a
// registry entry with no recording result is a mystery. Both are worth saying out loud.
//
// WHY IT WRITES THE CLAIM SENTENCE
//
// Because the alternative is someone writing it from memory two weeks later. The generated sentence
// only contains numbers this script actually derived, and the "may NOT make" list is as prominent as
// the claim itself.
//
// Usage:
//   node harness/corpus/summarize-corpus.mjs --merged merged.json --corpus corpus.json \
//     [--plan corpus-plan.json] [--ranking ranking.json] \
//     [--out-json dataset.json] [--out-md DATASET.md]

import { existsSync, readFileSync, writeFileSync } from "node:fs";

const SUMMARIZER_VERSION = "corpus-summarize-0.1.0";

function fail(message) {
  console.error(`summarize-corpus: FATAL: ${message}`);
  process.exit(2);
}

function log(message) {
  console.error(`summarize-corpus: ${message}`);
}

const options = {
  merged: "",
  corpus: "",
  plan: "",
  ranking: "",
  outJson: "dataset.json",
  outMd: "DATASET.md",
};

for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  switch (arg) {
    case "--merged": options.merged = process.argv[++i]; break;
    case "--corpus": options.corpus = process.argv[++i]; break;
    case "--plan": options.plan = process.argv[++i]; break;
    case "--ranking": options.ranking = process.argv[++i]; break;
    case "--out-json": options.outJson = process.argv[++i]; break;
    case "--out-md": options.outMd = process.argv[++i]; break;
    case "-h":
    case "--help":
      console.log(
        "Usage: summarize-corpus.mjs --merged FILE --corpus FILE [--plan FILE] [--ranking FILE]\n" +
          "                            [--out-json FILE] [--out-md FILE]"
      );
      process.exit(0);
      break;
    default: fail(`unknown argument: ${arg}`);
  }
}

if (options.merged === "") fail("--merged is required (output of shard.mjs merge)");
if (options.corpus === "") {
  fail("--corpus is required (output of `installscope snapshot summarize --json`)");
}

function readJson(file, what) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`cannot read ${what} at ${file}: ${error.message}`);
  }
}

const merged = readJson(options.merged, "merged results");
if (merged.schema !== "installscope-corpus-merged/1") {
  fail(`${options.merged} is not merged results (schema: ${merged.schema ?? "absent"})`);
}
const corpus = readJson(options.corpus, "corpus summary");
if (typeof corpus.snapshots_readable !== "number") {
  fail(`${options.corpus} does not look like \`snapshot summarize --json\` output`);
}

const plan = options.plan !== "" && existsSync(options.plan)
  ? readJson(options.plan, "corpus plan")
  : null;
const ranking = options.ranking !== "" && existsSync(options.ranking)
  ? readJson(options.ranking, "download ranking")
  : null;

// ---------------------------------------------------------------------------------------------
// Join the two views and find where they disagree
// ---------------------------------------------------------------------------------------------

const recordings = Array.isArray(merged.recordings) ? merged.recordings : [];

// A recording the harness says succeeded, but which is not in the registry. Either the push failed or
// the registry lost it; either way the corpus is smaller than the run log suggests.
const completeButUnpushed = recordings.filter(
  (r) => r.complete === true && r.snapshot?.pushed !== true
);

// The registry holding more entries than the run produced complete recordings. Means the store carries
// something this backfill did not create — a leftover from an earlier run, most likely, which makes the
// dataset's provenance unclear.
const registryExcess = corpus.snapshots_readable - recordings.filter((r) => r.complete === true).length;

const attempted = recordings.length;
const complete = recordings.filter((r) => r.complete === true).length;
const partial = merged.totals?.partial ?? recordings.filter((r) => r.recorded === true && r.complete !== true).length;
const failed = merged.totals?.failed ?? recordings.filter((r) => r.recorded !== true).length;
const mismatched = merged.totals?.version_mismatches ?? 0;

// The completion rate is the number that decides whether the dataset is worth publishing at all. A
// backfill that lost a third of its recordings has a selection bias problem: the ones that failed are
// disproportionately the interesting ones, because a package with an elaborate postinstall is more
// likely to time out.
const completionRate = attempted > 0 ? complete / attempted : 0;

// ---------------------------------------------------------------------------------------------
// Assemble
// ---------------------------------------------------------------------------------------------

const dataset = {
  schema: "installscope-corpus-dataset/1",
  summarizer_version: SUMMARIZER_VERSION,
  generated_at: new Date().toISOString(),

  recording_run: {
    attempted,
    complete,
    partial,
    failed,
    version_mismatches: mismatched,
    completion_rate: Number(completionRate.toFixed(4)),
    duplicate_results_collapsed: merged.totals?.duplicate_results_collapsed ?? 0,
    unreadable_results: merged.totals?.unreadable_results ?? 0,
  },

  // Straight from the registry. Not recomputed here, because only the store has the recordings, and a
  // second implementation of the count would be a second thing to keep correct.
  corpus: {
    snapshots: corpus.snapshots,
    snapshots_readable: corpus.snapshots_readable,
    packages: corpus.packages,
    packages_with_multiple_versions: corpus.packages_with_multiple_versions,
    diffable_pairs: corpus.diffable_pairs,
    behavior_observations: corpus.behavior_observations,
    distinct_behaviors: corpus.distinct_behaviors,
    observations_by_class: corpus.observations_by_class ?? {},
    unresolved_paths: corpus.unresolved_paths ?? 0,
    intact: corpus.intact === true,
  },

  // Where the run log and the store disagree. Empty is the healthy state; anything here means the
  // dataset's shape is not what either view alone reports.
  discrepancies: {
    complete_but_not_in_registry: completeButUnpushed.map((r) => ({
      spec: r.spec,
      push_error: r.snapshot?.error ?? null,
    })),
    registry_entries_beyond_this_run: registryExcess > 0 ? registryExcess : 0,
    unreadable_snapshots: corpus.unreadable_snapshots ?? [],
    incomplete_snapshots: corpus.incomplete_snapshots ?? [],
  },

  plan: plan
    ? {
        selection_rule: plan.selection_rule,
        packages_requested: plan.totals?.packages_requested ?? null,
        recordings_planned: plan.totals?.recordings_planned ?? null,
        packages_unresolved: plan.totals?.packages_unresolved ?? null,
      }
    : null,

  // Only present when rank-packages.mjs was run. Its own phrasing is copied verbatim rather than
  // reworded, because the whole point of that script is that it produces a claim that survives checking.
  popularity: ranking
    ? {
        fetched_at: ranking.fetched_at ?? null,
        packages_with_counts: ranking.packages_with_counts ?? null,
        min_weekly_downloads_observed: ranking.min_weekly_downloads_observed ?? null,
        claim_you_may_make: ranking.claim_you_may_make ?? null,
      }
    : null,
};

// The claim sentence, built only from numbers derived above.
const claims = [];
if (dataset.corpus.snapshots_readable === 0) {
  claims.push("No readable recordings. Make no claim about this dataset.");
} else {
  claims.push(
    `${dataset.corpus.snapshots_readable} recordings of ${dataset.corpus.packages} npm packages, ` +
      `covering ${dataset.corpus.diffable_pairs} consecutive version pairs.`
  );
  claims.push(
    `${dataset.corpus.behavior_observations} behavior observations, of which ` +
      `${dataset.corpus.distinct_behaviors} are distinct.`
  );
  if (ranking?.claim_you_may_make) {
    claims.push(`Popularity: ${ranking.claim_you_may_make}`);
  }
  if (partial + failed > 0) {
    // Stated as part of the claim, not as a footnote. A dataset that hides its failure rate is
    // describing a subset it chose without saying so.
    claims.push(
      `${partial} recording(s) were incomplete and ${failed} could not be recorded; those are ` +
        "excluded from the corpus and from every number above."
    );
  }
}

dataset.claim_you_may_make = claims.join(" ");
dataset.claim_you_may_NOT_make = [
  '"the top N npm packages" — nothing in this pipeline establishes a ranking',
  "any behavior count taken from the plan rather than from the registry",
  dataset.corpus.intact
    ? null
    : "any claim at all while the corpus reports unreadable or incomplete snapshots",
  completionRate < 0.9 && attempted > 0
    ? `an unqualified dataset claim: the completion rate is ${(completionRate * 100).toFixed(1)}%, ` +
      "and failed recordings are likely biased toward packages with elaborate install scripts"
    : null,
].filter((entry) => entry !== null);

writeFileSync(options.outJson, JSON.stringify(dataset, null, 2) + "\n");

// ---------------------------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------------------------

const L = [];
L.push("# InstallScope corpus — dataset description");
L.push("");
L.push(`Generated ${dataset.generated_at} by \`${SUMMARIZER_VERSION}\`.`);
L.push("");
L.push("Every number here is computed from the stored recordings, not from the plan. The distinction");
L.push("matters: a plan says what was intended, and this says what exists.");
L.push("");

L.push("## What the corpus contains");
L.push("");
L.push("| | |");
L.push("|---|---|");
L.push(`| Recordings stored | ${dataset.corpus.snapshots_readable} |`);
L.push(`| Packages | ${dataset.corpus.packages} |`);
L.push(`| Packages with 2+ versions | ${dataset.corpus.packages_with_multiple_versions} |`);
L.push(`| Version pairs comparable | ${dataset.corpus.diffable_pairs} |`);
L.push(`| Behavior observations | ${dataset.corpus.behavior_observations} |`);
L.push(`| **Distinct** behaviors | ${dataset.corpus.distinct_behaviors} |`);
L.push("");
L.push("Two behavior numbers, because they answer different questions. Observations counts every");
L.push("behavior in every recording; distinct counts how many *different* behaviors exist. The second");
L.push("is much smaller — every install writes to `node_modules` — and it is the honest one for a");
L.push("claim about novelty.");
L.push("");

if (Object.keys(dataset.corpus.observations_by_class).length > 0) {
  L.push("### By class");
  L.push("");
  L.push("| Class | Observations |");
  L.push("|---|---|");
  for (const [cls, count] of Object.entries(dataset.corpus.observations_by_class).sort(
    (a, b) => b[1] - a[1]
  )) {
    L.push(`| ${cls} | ${count} |`);
  }
  L.push("");
}

L.push("## What the recording run did");
L.push("");
L.push("| | |");
L.push("|---|---|");
L.push(`| Attempted | ${attempted} |`);
L.push(`| Complete | ${complete} |`);
L.push(`| PARTIAL (refused by the registry) | ${partial} |`);
L.push(`| Could not record | ${failed} |`);
L.push(`| Installed the wrong version | ${mismatched} |`);
L.push(`| Completion rate | ${(completionRate * 100).toFixed(1)}% |`);
L.push("");

if (partial + failed > 0) {
  L.push("The failures are listed rather than counted away. They matter for a reason beyond honesty:");
  L.push("a package with an elaborate postinstall is more likely to time out, so a low completion rate");
  L.push("means the corpus is biased *against* the behaviors it exists to document.");
  L.push("");
  if (Array.isArray(merged.partial_recordings) && merged.partial_recordings.length > 0) {
    L.push("### Incomplete recordings");
    L.push("");
    for (const entry of merged.partial_recordings) {
      L.push(`- \`${entry.spec}\` — ${entry.reason ?? "reason not recorded"}`);
    }
    L.push("");
  }
  if (Array.isArray(merged.failed_recordings) && merged.failed_recordings.length > 0) {
    L.push("### Failed recordings");
    L.push("");
    for (const entry of merged.failed_recordings) {
      L.push(`- \`${entry.spec}\` — ${entry.reason ?? "reason not recorded"}`);
    }
    L.push("");
  }
}

const discrepancyCount =
  dataset.discrepancies.complete_but_not_in_registry.length +
  dataset.discrepancies.unreadable_snapshots.length +
  dataset.discrepancies.incomplete_snapshots.length +
  (dataset.discrepancies.registry_entries_beyond_this_run > 0 ? 1 : 0);

L.push("## Consistency between the run log and the store");
L.push("");
if (discrepancyCount === 0) {
  L.push("The run log and the registry agree: every complete recording is stored, every stored");
  L.push("snapshot is readable, and the store holds nothing this run did not produce.");
} else {
  L.push("**These disagree, and the dataset's shape is therefore not what either view alone reports.**");
  L.push("");
  for (const entry of dataset.discrepancies.complete_but_not_in_registry) {
    L.push(`- \`${entry.spec}\` recorded completely but is not in the registry: ${entry.push_error ?? "no reason recorded"}`);
  }
  if (dataset.discrepancies.registry_entries_beyond_this_run > 0) {
    L.push(
      `- the registry holds ${dataset.discrepancies.registry_entries_beyond_this_run} more readable ` +
        "snapshot(s) than this run produced, so it carries recordings from elsewhere"
    );
  }
  for (const [label, reason] of dataset.discrepancies.unreadable_snapshots.map((e) =>
    Array.isArray(e) ? e : [e.snapshot, e.reason]
  )) {
    L.push(`- \`${label}\` is in the index but could not be read: ${reason}`);
  }
  for (const label of dataset.discrepancies.incomplete_snapshots) {
    L.push(`- \`${label}\` is stored but incomplete, which \`snapshot push\` should have refused`);
  }
}
L.push("");

L.push("## The claim");
L.push("");
L.push("> " + dataset.claim_you_may_make);
L.push("");
L.push("### What may not be claimed");
L.push("");
for (const entry of dataset.claim_you_may_NOT_make) {
  L.push(`- ${entry}`);
}
L.push("");

L.push("## Receipts");
L.push("");
L.push("Nothing in this file is a receipt. A receipt is a *confirmed* surprising behavior of a real");
L.push("package, and confirmation is a human reading the evidence — `select-receipts.mjs` ranks");
L.push("candidates for that review and deliberately does not decide (Rules.md §7).");
L.push("");

writeFileSync(options.outMd, L.join("\n") + "\n");

log(`wrote ${options.outJson} and ${options.outMd}`);
log(
  `${dataset.corpus.snapshots_readable} stored recordings · ${dataset.corpus.distinct_behaviors} ` +
    `distinct behaviors · ${(completionRate * 100).toFixed(1)}% completion`
);
if (discrepancyCount > 0) {
  log(`${discrepancyCount} discrepancy group(s) between the run log and the store — see the report`);
}
if (!dataset.corpus.intact) {
  log("the corpus is NOT intact; no claim may be published from it in this state");
  process.exit(1);
}
