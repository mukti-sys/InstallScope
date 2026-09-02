#!/usr/bin/env node
// select-receipts.mjs — rank corpus recordings for human review. Confirms nothing.
//
// Phases.md:40 asks for "the 3 best receipts" to fire G3 with. This script's job is to make that a
// short reading task rather than a search through 1000 recordings, and its job stops there.
//
// WHY IT CANNOT DECIDE
//
// Rules.md rule 7 and harness/README.md are explicit: a candidate becomes a receipt only when a human
// reads the evidence and confirms the behavior is genuinely surprising. That is not ceremony. A rule
// firing means "this matched a pattern"; a receipt means "a maintainer would be surprised", and the
// second is a judgement about people. A script that auto-confirmed would be manufacturing the gate's
// own evidence, which is the failure Rules.md rule 7 names.
//
// So the output is a review queue with a `confirmed: null` field per entry, and the phrase "candidate"
// throughout. Nothing here prints PASS.
//
// WHAT MAKES A CANDIDATE INTERESTING, AND WHY THAT IS NOT THE SCORE
//
// The Surprise Index answers "how alarming is this install". A receipt needs something else: it has to
// be *surprising*, which is about expectation rather than severity. Three signals matter more than the
// score:
//
//   1. A behavior that appeared or disappeared between two versions of the same package. "lodash 4.17.20
//      did not do this and 4.17.21 does" is a story; "lodash writes to node_modules" is not.
//   2. A behavior that contradicts the package's own registry metadata — no declared install script, yet
//      a process was spawned.
//   3. A behavior in a class a reader would not expect from the package's description.
//
// Only (1) and (2) can be computed here. (3) is the human's part, which is why the queue carries the
// evidence rather than a verdict.
//
// AND WHY COUNT IS THE WRONG WAY TO RANK (1)
//
// The first real backfill ranked by `added.length` and put this at the top:
//
//     yargs@18.1.0 vs 17.7.3 — 1307 new behavior(s)
//       [filesystem] wrote project/node_modules/cliui/build/tsconfig.tsbuildinfo
//
// A dependency bump, not a story. See CLASS_WEIGHT below: ranking is by what kind of behavior appeared,
// and a single new network connection outranks a thousand new node_modules writes.
//
// Usage:
//   node harness/corpus/select-receipts.mjs --merged merged.json [--plan corpus-plan.json]
//     [--diffs diffs/] [--out-json receipts-queue.json] [--out-md RECEIPTS-QUEUE.md] [--top 20]

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const SELECTOR_VERSION = "corpus-select-receipts-0.1.0";

/** Phases.md:15 wants three for the G3 teaser; the queue is longer so a human can reject freely. */
const G3_RECEIPTS_WANTED = 3;

function fail(message) {
  console.error(`select-receipts: FATAL: ${message}`);
  process.exit(2);
}

function log(message) {
  console.error(`select-receipts: ${message}`);
}

const options = {
  merged: "",
  plan: "",
  diffs: "",
  outJson: "receipts-queue.json",
  outMd: "RECEIPTS-QUEUE.md",
  top: 20,
};

for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  switch (arg) {
    case "--merged": options.merged = process.argv[++i]; break;
    case "--plan": options.plan = process.argv[++i]; break;
    case "--diffs": options.diffs = process.argv[++i]; break;
    case "--out-json": options.outJson = process.argv[++i]; break;
    case "--out-md": options.outMd = process.argv[++i]; break;
    case "--top": options.top = Number.parseInt(process.argv[++i], 10); break;
    case "-h":
    case "--help":
      console.log(
        "Usage: select-receipts.mjs --merged FILE [--plan FILE] [--diffs DIR]\n" +
          "                          [--out-json FILE] [--out-md FILE] [--top N]"
      );
      process.exit(0);
      break;
    default: fail(`unknown argument: ${arg}`);
  }
}

if (options.merged === "") fail("--merged is required (output of shard.mjs merge)");
if (!Number.isInteger(options.top) || options.top < 1) {
  fail(`--top must be a positive integer, got: ${options.top}`);
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
const plan = options.plan !== "" && existsSync(options.plan)
  ? readJson(options.plan, "corpus plan")
  : null;

// ---------------------------------------------------------------------------------------------
// What the plan said each version declares, so a recording can be checked against it
// ---------------------------------------------------------------------------------------------

/** `package@version` -> the install hooks its registry metadata declares. */
const declaredScripts = new Map();
if (plan && Array.isArray(plan.packages)) {
  for (const entry of plan.packages) {
    for (const version of entry.versions ?? []) {
      declaredScripts.set(
        `${entry.package}@${version.version}`,
        Array.isArray(version.declares_install_scripts) ? version.declares_install_scripts : []
      );
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Version diffs, when the workflow produced them
// ---------------------------------------------------------------------------------------------

/**
 * Reads `installscope diff --json`-shaped output, if a diffs directory was given.
 *
 * A missing directory is normal: diffs are produced only for packages with two or more recorded
 * versions, and a first backfill of one version each has none. Absence is reported so a reader knows
 * the strongest signal was unavailable rather than empty.
 */
function readDiffs(dir) {
  const found = [];
  const unreadable = [];
  if (dir === "" || !existsSync(dir)) return { found, unreadable, present: false };

  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".json")) {
        try {
          const parsed = JSON.parse(readFileSync(full, "utf8"));
          if (typeof parsed.package === "string" && Array.isArray(parsed.added)) {
            found.push(parsed);
          }
        } catch (error) {
          unreadable.push({ path: full, error: error.message });
        }
      }
    }
  };
  walk(dir);
  return { found, unreadable, present: true };
}

const diffs = readDiffs(options.diffs);

// ---------------------------------------------------------------------------------------------
// Candidate assembly
// ---------------------------------------------------------------------------------------------

const recordings = Array.isArray(merged.recordings) ? merged.recordings : [];

// PARTIAL recordings are excluded from the queue, not just deprioritised. A truncated recording can
// produce a behavior that fuller evidence would explain away, and a receipt built on one would be
// retracted publicly — the worst possible outcome for a launch (PRD.md:58's reasoning, applied to the
// dataset rather than to a single report).
const usable = recordings.filter((r) => r.complete === true);
const excludedPartial = recordings.filter((r) => r.recorded === true && r.complete !== true);
const excludedFailed = recordings.filter((r) => r.recorded !== true);

const candidates = [];

// ---------------------------------------------------------------------------------------------
// Weighting behavior classes
// ---------------------------------------------------------------------------------------------

/**
 * How much a newly-appeared behavior is worth to a human reviewer, by class.
 *
 * WHY THIS TABLE EXISTS, AND WHAT IT REPLACED
 *
 * The first version weighted a version-to-version change as `100 + added.length`. The first real
 * backfill showed exactly why that is wrong. Its top candidate:
 *
 *     yargs@18.1.0 vs 17.7.3 — 1307 new behavior(s)
 *       [filesystem] wrote project/node_modules/cliui/build/tsconfig.tsbuildinfo
 *       [filesystem] created directory project/node_modules/cliui/node_modules
 *       ...
 *
 * That is a dependency tree change, not surprising behavior: yargs bumped its deps, so 1300 new files
 * appeared under `node_modules`. Ranking by count means the packages with the most vendoring churn
 * dominate the queue, and they are the least interesting things in it. A queue of 25 candidates that
 * all read like that is a queue nobody finishes.
 *
 * So the weight is driven by *what kind* of behavior appeared, not how many. One new
 * `resolved telemetry.example` outranks 1300 new `node_modules` writes, because a maintainer's reaction
 * to the first is "wait, what?" and to the second is "yes, that is what a dependency bump does".
 *
 * The numbers are ordinal, not measurements. Their only job is to sort a reading queue, and they are
 * deliberately far apart so that no quantity of filesystem churn can outrank a single network
 * connection. Kept here rather than read from the rule catalog: that catalog scores *severity* for a
 * report, and this ranks *surprise* for a human — related, and not the same question.
 */
const CLASS_WEIGHT = {
  // A write outside every declared zone is the critical class (Architecture.md section 4). Nothing in a
  // normal install does this.
  "writes outside expected directories": 500,
  // Reading ~/.ssh or ~/.aws during an install has no legitimate explanation a reviewer would guess.
  "credential reads": 400,
  // A resolved hostname or a connect is the "phones home" story, and it is what a receipt usually is.
  network: 300,
  // Spawning curl, sh, or a downloaded binary. High, but a build tool spawning gcc is ordinary, so it
  // ranks below network.
  processes: 200,
  // node_modules writes, cache writes, /proc reads. Every install does thousands of these.
  filesystem: 1,
};

/** Weight for a class this script does not know about. */
const UNKNOWN_CLASS_WEIGHT = 50;

/**
 * Scores a set of newly-appeared behaviors.
 *
 * Counts *distinct classes* rather than summing every behavior: 40 new network connections is one story
 * about a package, not 40 stories, and summing would reintroduce the churn problem one level up. The
 * count within a class contributes a small logarithmic nudge so that "resolved 12 new hosts" ranks above
 * "resolved 1 new host" without ever overtaking a higher class.
 */
function scoreAdded(added) {
  const byClass = new Map();
  for (const behavior of added) {
    const cls = typeof behavior === "object" && behavior !== null ? behavior.class : undefined;
    const key = typeof cls === "string" ? cls : "unknown";
    byClass.set(key, (byClass.get(key) ?? 0) + 1);
  }

  let score = 0;
  for (const [cls, count] of byClass) {
    const base = CLASS_WEIGHT[cls] ?? UNKNOWN_CLASS_WEIGHT;
    // log2(count + 1) stays under 11 for a thousand behaviors, so the nudge can never bridge the gap
    // between two class tiers.
    score += base + Math.round(Math.log2(count + 1));
  }
  return { score, byClass };
}

/**
 * Orders evidence so a reviewer reads the interesting lines first.
 *
 * Without this, a candidate whose one new network connection is buried under 1300 `node_modules` writes
 * shows ten filesystem lines and nothing else — the reader sees churn and moves on, which is the same
 * failure as ranking it low.
 */
function orderEvidence(added) {
  return [...added].sort((a, b) => {
    const weightOf = (behavior) => {
      const cls = typeof behavior === "object" && behavior !== null ? behavior.class : undefined;
      return CLASS_WEIGHT[typeof cls === "string" ? cls : "unknown"] ?? UNKNOWN_CLASS_WEIGHT;
    };
    return weightOf(b) - weightOf(a);
  });
}

// ---- signal 1: behavior changed between two versions of one package ---------------------------
//
// The strongest signal, and the one the corpus exists for. A diff that reports added behaviors is a
// story with a before and an after.
for (const diff of diffs.found) {
  // A blocked comparison is not evidence of anything about the package (registry/src/diff.rs), so it
  // cannot become a candidate. Counted separately below.
  if (diff.comparable === false) continue;
  const added = Array.isArray(diff.added) ? diff.added : [];
  if (added.length === 0) continue;

  const { score, byClass } = scoreAdded(added);
  // Classes named in the summary, most interesting first, so the queue is skimmable without opening a
  // single candidate.
  const classSummary = [...byClass.entries()]
    .sort((a, b) => (CLASS_WEIGHT[b[0]] ?? UNKNOWN_CLASS_WEIGHT) - (CLASS_WEIGHT[a[0]] ?? UNKNOWN_CLASS_WEIGHT))
    .map(([cls, count]) => `${count} ${cls}`)
    .join(", ");

  candidates.push({
    kind: "behavior_changed_between_versions",
    package: diff.package,
    version: diff.after_version ?? null,
    compared_with: diff.before_version ?? null,
    // Driven by class, not by count. See CLASS_WEIGHT for why, and for what this replaced.
    weight: 100 + score,
    // Recorded so a reader can see what drove the ranking without reverse-engineering the number.
    classes: Object.fromEntries(byClass),
    summary:
      `${diff.package} behaves differently in ${diff.after_version} than in ${diff.before_version}: ` +
      `${classSummary}`,
    // Rendered as readable lines rather than raw objects, most interesting class first. This file is a
    // reading task for a human, and a wall of JSON — or ten lines of node_modules churn — is exactly the
    // friction that makes a review get skipped.
    evidence: orderEvidence(added)
      .slice(0, 10)
      .map((behavior) =>
        typeof behavior === "string"
          ? behavior
          : `[${behavior.class ?? "?"}] ${behavior.summary ?? JSON.stringify(behavior)}`
      ),
    confirmed: null,
    confirmation_note: null,
  });
}

// ---- signal 2: a recording contradicts the package's own metadata -----------------------------
for (const recording of usable) {
  const key = `${recording.package}@${recording.version}`;
  const declared = declaredScripts.get(key);
  if (declared === undefined) continue;

  // The recording's event count is a weak proxy for "did anything happen", and it is what a merged
  // result carries. A package declaring no install hooks whose recording is nonetheless busy is worth a
  // human look; the events themselves live in the artifact.
  //
  // Deliberately not asserted as a finding: npm itself spawns processes and writes files during any
  // install, so a high event count is not by itself surprising. This is a *sorting* signal.
  if (declared.length === 0 && recording.events > 0) {
    candidates.push({
      kind: "no_declared_install_script",
      package: recording.package,
      version: recording.version,
      compared_with: null,
      // Low weight on purpose. npm's own activity dominates, so this is a hint for review rather than a
      // claim, and it must not outrank a real version-to-version change — even one whose only new
      // behavior is filesystem churn, which scores 100 + 1 + a small nudge.
      weight: 10,
      classes: {},
      summary:
        `${key} declares no install script in its registry metadata, and its recording contains ` +
        `${recording.events} events`,
      evidence: [
        `declared install hooks: none`,
        `events recorded: ${recording.events}`,
        `install exit code: ${recording.recorder_exit_code}`,
      ],
      confirmed: null,
      confirmation_note: null,
    });
  } else if (declared.length > 0) {
    candidates.push({
      kind: "declares_install_script",
      package: recording.package,
      version: recording.version,
      compared_with: null,
      weight: 20,
      classes: {},
      summary: `${key} declares ${declared.join(", ")} and was recorded running it`,
      evidence: [
        `declared install hooks: ${declared.join(", ")}`,
        `events recorded: ${recording.events}`,
      ],
      confirmed: null,
      confirmation_note: null,
    });
  }
}

// Highest weight first, then package name, so two runs over the same inputs produce the same queue.
candidates.sort(
  (a, b) => b.weight - a.weight || a.package.localeCompare(b.package) ||
    String(a.version).localeCompare(String(b.version))
);

const queue = candidates.slice(0, options.top);

const output = {
  schema: "installscope-receipts-queue/1",
  selector_version: SELECTOR_VERSION,
  generated_at: new Date().toISOString(),
  receipts_wanted_for_g3: G3_RECEIPTS_WANTED,

  // The word "candidate" is load-bearing. Nothing in this file is a receipt.
  verdict: {
    decided_by: "human",
    note:
      "This file ranks CANDIDATES for review. A candidate becomes a receipt only when a human reads " +
      "the evidence and confirms the behavior is genuinely surprising (Rules.md rule 7). No script " +
      "decides G3. Record the confirmed count and the verdict in Memory.md.",
  },

  inputs: {
    recordings_total: recordings.length,
    recordings_usable: usable.length,
    excluded_partial: excludedPartial.length,
    excluded_failed: excludedFailed.length,
    version_diffs_available: diffs.present,
    version_diffs_read: diffs.found.length,
    version_diffs_unreadable: diffs.unreadable.length,
    version_diffs_blocked: diffs.found.filter((d) => d.comparable === false).length,
    plan_metadata_available: plan !== null,
  },

  // Stated rather than implied: a queue built without diffs is missing the signal that matters most,
  // and a reader should know that before concluding the corpus is boring.
  caveats: [
    excludedPartial.length > 0
      ? `${excludedPartial.length} incomplete recording(s) are excluded entirely: a receipt built on ` +
        "truncated evidence would be retracted publicly"
      : null,
    !diffs.present
      ? "no version diffs were supplied, so the strongest signal — a behavior that appeared between " +
        "two versions — could not be computed"
      : null,
    plan === null
      ? "no plan was supplied, so recordings could not be checked against their registry metadata"
      : null,
    diffs.found.filter((d) => d.comparable === false).length > 0
      ? `${diffs.found.filter((d) => d.comparable === false).length} version comparison(s) were ` +
        "blocked and contribute nothing: a difference between recordings is not a difference between " +
        "versions"
      : null,
  ].filter((entry) => entry !== null),

  candidates_total: candidates.length,
  queue,
};

writeFileSync(options.outJson, JSON.stringify(output, null, 2) + "\n");

// ---------------------------------------------------------------------------------------------
// Markdown review sheet
// ---------------------------------------------------------------------------------------------

const L = [];
L.push("# Receipt review queue");
L.push("");
L.push(`Generated ${output.generated_at} by \`${SELECTOR_VERSION}\`.`);
L.push("");
L.push("**Nothing here is a receipt yet.** These are candidates ranked for reading. A candidate");
L.push("becomes a receipt when a human confirms the behavior is genuinely surprising — a rule firing");
L.push("means \"this matched a pattern\", a receipt means \"a maintainer would be surprised\", and only");
L.push("the second is a judgement about people (Rules.md rule 7).");
L.push("");
L.push(`Phases.md:15 needs **${G3_RECEIPTS_WANTED}** confirmed receipts to fire G3.`);
L.push("");

L.push("## What went into this queue");
L.push("");
L.push("| | |");
L.push("|---|---|");
L.push(`| Recordings available | ${output.inputs.recordings_total} |`);
L.push(`| Usable (complete) | ${output.inputs.recordings_usable} |`);
L.push(`| Excluded — incomplete | ${output.inputs.excluded_partial} |`);
L.push(`| Excluded — could not record | ${output.inputs.excluded_failed} |`);
L.push(`| Version diffs read | ${output.inputs.version_diffs_read} |`);
L.push(`| Candidates found | ${output.candidates_total} |`);
L.push("");

if (output.caveats.length > 0) {
  L.push("### Caveats");
  L.push("");
  for (const caveat of output.caveats) L.push(`- ${caveat}`);
  L.push("");
}

if (queue.length === 0) {
  L.push("## No candidates");
  L.push("");
  L.push("This is a real result, not an error. Phases.md:41's stop rule applies: if the corpus");
  L.push("produces nothing surprising, the \"postinstall epidemic is boring\" hypothesis is winning, and");
  L.push("a human decides between repositioning and launching as a content piece. Widening the rules to");
  L.push("manufacture candidates is a process failure, not a fix.");
  L.push("");
} else {
  L.push("## Candidates");
  L.push("");
  L.push("Read top to bottom. Mark each `confirmed` in the JSON, or reject it — a rejection is as");
  L.push("informative as a confirmation and belongs in Memory.md either way.");
  L.push("");
  L.push("Ranking is by **what kind** of behavior appeared, not how many. A single new network");
  L.push("connection outranks a thousand new `node_modules` writes, because a dependency bump produces");
  L.push("the second and nothing ordinary produces the first. Evidence within a candidate is ordered the");
  L.push("same way, so the interesting lines are the ones you see.");
  L.push("");
  queue.forEach((candidate, index) => {
    L.push(`### ${index + 1}. \`${candidate.package}@${candidate.version ?? "?"}\``);
    L.push("");
    L.push(`**${candidate.kind}** · weight ${candidate.weight}`);
    L.push("");
    L.push(candidate.summary);
    L.push("");
    if (candidate.evidence.length > 0) {
      L.push("Evidence:");
      L.push("");
      for (const item of candidate.evidence) {
        L.push(`- \`${typeof item === "string" ? item : JSON.stringify(item)}\``);
      }
      const shown = candidate.evidence.length;
      const total = Object.values(candidate.classes ?? {}).reduce((sum, n) => sum + n, 0);
      if (total > shown) {
        // The count, not silence. A reader deciding whether to open the artifact needs to know whether
        // they have seen the interesting part or the first tenth of it.
        L.push(`- …and ${total - shown} more, in the recording artifact`);
      }
      L.push("");
    }
    L.push("- [ ] confirmed as a receipt");
    L.push("- [ ] rejected (say why)");
    L.push("");
  });
}

L.push("## Next step");
L.push("");
L.push("1. Read each candidate's evidence in the uploaded recording artifact.");
L.push("2. Confirm or reject. Rejections are informative.");
L.push(`3. If ≥${G3_RECEIPTS_WANTED} are confirmed, pick the ${G3_RECEIPTS_WANTED} spiciest and fire G3 (Phases.md:40).`);
L.push("4. Record the verdict, the confirmed count, and any rule changes in Memory.md.");
L.push("");

writeFileSync(options.outMd, L.join("\n") + "\n");

log(`wrote ${options.outJson} and ${options.outMd}`);
log(
  `${candidates.length} candidate(s) from ${usable.length} usable recording(s); ` +
    `${queue.length} queued for review`
);
if (excludedPartial.length > 0) {
  log(`${excludedPartial.length} incomplete recording(s) excluded from the queue entirely`);
}
if (!diffs.present) {
  log("no version diffs supplied — the strongest signal was unavailable");
}
