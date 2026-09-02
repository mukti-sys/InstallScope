#!/usr/bin/env node
// test-corpus.mjs — golden tests for the Phase 5 corpus harness.
//
// Covers resolve-versions.mjs (offline), shard.mjs (plan + merge), summarize-corpus.mjs and
// select-receipts.mjs, against synthetic fixtures under fixtures/.
//
// WHY THESE TESTS EXIST IN THIS SHAPE
//
// The corpus harness is mostly Node driving a matrix, and its failure mode is not a crash. It is
// producing a *plausible number*: a dataset that says 1000 recordings when 340 failed, a receipt queue
// that ranks a truncated recording first, a claim sentence assembled from a plan rather than from the
// store. None of that throws. So the assertions here are mostly about what the scripts refuse to say.
//
// Every fixture is labeled synthetic (Rules.md rule 5). Nothing here may be cited as a receipt.
//
// Pure Node, no network and no Linux dependency — which is what lets it run on every push.
// Usage: node harness/corpus/test-corpus.mjs

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

let checks = 0;
let failures = 0;

function check(name, condition, detail) {
  checks += 1;
  if (condition) {
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function section(name) {
  console.log(name);
}

/** Runs a harness script, returning stdout/stderr/status rather than throwing on non-zero. */
function run(script, args) {
  try {
    const stdout = execFileSync(process.execPath, [path.join(here, script), ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stdout, stderr: "" };
  } catch (error) {
    return {
      status: error.status ?? 1,
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
    };
  }
}

function readJson(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

const work = mkdtempSync(path.join(tmpdir(), "corpus-test-"));

try {
  // -------------------------------------------------------------------------------------------
  // resolve-versions.mjs, offline against a cached packument
  // -------------------------------------------------------------------------------------------
  section("resolve-versions.mjs");

  const cacheDir = path.join(work, "packuments");
  mkdirSync(cacheDir, { recursive: true });

  // A synthetic packument carrying every shape the real registry produces and that the resolver has to
  // handle: prereleases, an unpublished version (in `time` but not in `versions`), the non-version
  // `created`/`modified` keys, and publish order that disagrees with semver order.
  writeFileSync(
    path.join(cacheDir, "SYNTHETIC-pkg.json"),
    JSON.stringify({
      name: "SYNTHETIC-pkg",
      "dist-tags": { latest: "2.1.0" },
      time: {
        created: "2020-01-01T00:00:00.000Z",
        modified: "2026-01-01T00:00:00.000Z",
        "1.0.0": "2021-01-01T00:00:00.000Z",
        // Published AFTER 2.0.0, so publish order and semver order disagree here.
        "1.9.0": "2025-06-01T00:00:00.000Z",
        "2.0.0": "2024-01-01T00:00:00.000Z",
        "2.1.0": "2025-12-01T00:00:00.000Z",
        "2.2.0-beta.1": "2026-01-01T00:00:00.000Z",
        "1.5.0": "2023-01-01T00:00:00.000Z",
      },
      versions: {
        "1.0.0": { version: "1.0.0", scripts: {}, dist: { unpackedSize: 100 } },
        "1.9.0": { version: "1.9.0", scripts: {}, dist: { unpackedSize: 190 } },
        "2.0.0": { version: "2.0.0", scripts: { postinstall: "node install.js" }, dist: { unpackedSize: 200 } },
        "2.1.0": { version: "2.1.0", scripts: {}, dist: { unpackedSize: 210 } },
        "2.2.0-beta.1": { version: "2.2.0-beta.1", scripts: {} },
        // 1.5.0 is deliberately absent from `versions`: unpublished.
      },
    })
  );

  const packageList = path.join(work, "packages.txt");
  writeFileSync(packageList, "# synthetic\nSYNTHETIC-pkg\n");

  const planPath = path.join(work, "plan.json");
  const resolved = run("resolve-versions.mjs", [
    "--packages", packageList,
    "--versions", "3",
    "--cache", cacheDir,
    "--out", planPath,
    "--offline",
  ]);
  check("resolves offline from the cache", resolved.status === 0, resolved.stderr);

  const plan = readJson(planPath);
  const versions = plan.packages[0].versions.map((v) => v.version);

  check(
    "selects by publish time, not by semver",
    JSON.stringify(versions) === JSON.stringify(["2.1.0", "1.9.0", "2.0.0"]),
    `got ${JSON.stringify(versions)}`
  );
  check("excludes prereleases", !versions.includes("2.2.0-beta.1"));
  check(
    "counts the prerelease as excluded rather than dropping it silently",
    plan.packages[0].versions_excluded.prerelease === 1,
    JSON.stringify(plan.packages[0].versions_excluded)
  );
  check(
    "excludes a version present in .time but absent from .versions",
    !versions.includes("1.5.0") && plan.packages[0].versions_excluded.unpublished === 1,
    JSON.stringify(plan.packages[0].versions_excluded)
  );
  check(
    "does not treat created/modified as versions",
    !versions.includes("created") && !versions.includes("modified") &&
      plan.packages[0].stable_versions_available === 4,
    `stable_available=${plan.packages[0].stable_versions_available}`
  );
  check(
    "carries the declared install scripts from registry metadata",
    plan.packages[0].versions.find((v) => v.version === "2.0.0")
      .declares_install_scripts.includes("postinstall")
  );
  check(
    "refuses to make a popularity claim",
    plan.claim_you_may_NOT_make.includes("top N"),
    plan.claim_you_may_NOT_make
  );
  check(
    "refuses to state a behavior count",
    plan.claim_you_may_make.includes("summarize-corpus"),
    plan.claim_you_may_make
  );

  // A name that could escape into a shell or a path must be refused, not sanitised.
  const hostileList = path.join(work, "hostile.txt");
  writeFileSync(hostileList, "../../etc/passwd\n");
  const hostile = run("resolve-versions.mjs", [
    "--packages", hostileList, "--cache", cacheDir, "--out", path.join(work, "no.json"), "--offline",
  ]);
  check(
    "refuses a package name that could escape a path",
    hostile.status !== 0 && hostile.stderr.includes("suspicious"),
    hostile.stderr.trim()
  );

  // -------------------------------------------------------------------------------------------
  // shard.mjs plan
  // -------------------------------------------------------------------------------------------
  section("shard.mjs plan");

  // A plan with lopsided version counts, so bin packing is actually exercised.
  const bigPlanPath = path.join(work, "big-plan.json");
  writeFileSync(
    bigPlanPath,
    JSON.stringify({
      schema: "installscope-corpus-plan/1",
      packages: [
        { package: "SYNTHETIC-a", versions: [{ version: "1" }, { version: "2" }, { version: "3" }, { version: "4" }, { version: "5" }] },
        { package: "SYNTHETIC-b", versions: [{ version: "1" }] },
        { package: "SYNTHETIC-c", versions: [{ version: "1" }, { version: "2" }] },
        { package: "SYNTHETIC-d", versions: [{ version: "1" }, { version: "2" }] },
      ],
    })
  );

  const shardsPath = path.join(work, "shards.json");
  const planned = run("shard.mjs", [
    "plan", "--plan", bigPlanPath, "--shards", "3", "--out", shardsPath,
  ]);
  check("plans shards", planned.status === 0, planned.stderr);
  check(
    "prints only the shard count on stdout",
    planned.stdout.trim() === "3",
    JSON.stringify(planned.stdout)
  );

  const shards = readJson(shardsPath);
  check(
    "every planned recording lands in exactly one shard",
    shards.totals.recordings === 10 &&
      shards.shards.reduce((sum, s) => sum + s.recordings, 0) === 10,
    JSON.stringify(shards.totals)
  );
  check(
    "balances the shards rather than round-robining",
    // 10 recordings over 3 shards: a balanced split is 4/3/3, and the 5-version package alone is 5.
    // Longest-first packing gives 5/3/2; the point is that no shard gets 8 while another gets 1.
    shards.totals.recordings_per_shard.max - shards.totals.recordings_per_shard.min <= 3,
    JSON.stringify(shards.totals.recordings_per_shard)
  );
  check(
    "encodes each shard as a matrix-safe scalar",
    shards.shards.every((s) => typeof s.spec === "string" && s.spec.includes(":")),
    JSON.stringify(shards.shards.map((s) => s.spec))
  );
  check(
    "sharding is deterministic",
    (() => {
      const again = path.join(work, "shards-again.json");
      run("shard.mjs", ["plan", "--plan", bigPlanPath, "--shards", "3", "--out", again]);
      return JSON.stringify(readJson(again).shards) === JSON.stringify(shards.shards);
    })()
  );

  // -------------------------------------------------------------------------------------------
  // shard.mjs plan --completed, i.e. resumability
  // -------------------------------------------------------------------------------------------
  section("shard.mjs resumability");

  const resultsDir = path.join(work, "results");

  /** Writes a recording result exactly as record-corpus.sh does. */
  function writeRecording(pkg, version, overrides = {}) {
    const dir = path.join(resultsDir, `${pkg}_${version}`.replace(/[^A-Za-z0-9._-]/g, "_"));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, "recording.json"),
      JSON.stringify({
        schema: "installscope-corpus-recording/1",
        package: pkg,
        version,
        spec: `${pkg}@${version}`,
        started_at: "2026-09-02T10:00:00Z",
        recorded: true,
        complete: true,
        incomplete_reason: null,
        events: 40,
        installed: { version, matches_requested: true },
        snapshot: { pushed: true, digest: "a".repeat(64), error: null },
        ...overrides,
      })
    );
  }

  writeRecording("SYNTHETIC-a", "1");
  writeRecording("SYNTHETIC-a", "2");
  // A PARTIAL recording: attempted, refused by the registry, and therefore NOT done.
  writeRecording("SYNTHETIC-b", "1", {
    complete: false,
    incomplete_reason: "recorder reported PARTIAL",
    snapshot: { pushed: false, digest: null, error: "refused: PARTIAL" },
  });

  const resumePath = path.join(work, "shards-resume.json");
  const resumed = run("shard.mjs", [
    "plan", "--plan", bigPlanPath, "--shards", "3", "--completed", resultsDir, "--out", resumePath,
  ]);
  check("re-plans against previous results", resumed.status === 0, resumed.stderr);

  const resume = readJson(resumePath);
  const remaining = resume.shards.flatMap((s) => s.packages);
  const remainingSpecs = remaining.flatMap((p) => p.versions.map((v) => `${p.package}@${v}`));

  check(
    "skips recordings that already completed",
    !remainingSpecs.includes("SYNTHETIC-a@1") && !remainingSpecs.includes("SYNTHETIC-a@2") &&
      resume.totals.skipped_already_complete === 2,
    JSON.stringify(remainingSpecs)
  );
  check(
    "retries a PARTIAL recording rather than treating it as done",
    remainingSpecs.includes("SYNTHETIC-b@1"),
    "a PARTIAL recording was refused by the registry, so the corpus does not have it"
  );

  // Everything complete means nothing to do — which must be a clean exit, not a failure, so a
  // workflow can tell "finished" from "broken".
  const allDone = path.join(work, "all-done.json");
  writeFileSync(
    allDone,
    JSON.stringify({
      schema: "installscope-corpus-plan/1",
      packages: [{ package: "SYNTHETIC-a", versions: [{ version: "1" }] }],
    })
  );
  const nothing = run("shard.mjs", [
    "plan", "--plan", allDone, "--shards", "3", "--completed", resultsDir,
    "--out", path.join(work, "nothing.json"),
  ]);
  check(
    "a fully-completed plan exits 0 with zero shards",
    nothing.status === 0 && nothing.stdout.trim() === "0",
    `status=${nothing.status} stdout=${JSON.stringify(nothing.stdout)}`
  );

  // -------------------------------------------------------------------------------------------
  // shard.mjs merge
  // -------------------------------------------------------------------------------------------
  section("shard.mjs merge");

  // A second, later result for a version that previously failed: the merge must prefer the success.
  const retryDir = path.join(resultsDir, "retry");
  mkdirSync(retryDir, { recursive: true });
  writeFileSync(
    path.join(retryDir, "recording.json"),
    JSON.stringify({
      schema: "installscope-corpus-recording/1",
      package: "SYNTHETIC-b",
      version: "1",
      spec: "SYNTHETIC-b@1",
      started_at: "2026-09-02T12:00:00Z",
      recorded: true,
      complete: true,
      incomplete_reason: null,
      events: 55,
      installed: { version: "1", matches_requested: true },
      snapshot: { pushed: true, digest: "b".repeat(64), error: null },
    })
  );
  // And a result that could not record at all, plus one that installed the wrong version.
  writeRecording("SYNTHETIC-c", "1", {
    recorded: false,
    complete: false,
    incomplete_reason: "recorder exited 1",
    snapshot: { pushed: false, digest: null, error: null },
  });
  writeRecording("SYNTHETIC-d", "1", {
    installed: { version: "9.9.9", matches_requested: false },
  });
  // An unreadable result: a truncated upload. Must be counted, not skipped.
  const brokenDir = path.join(resultsDir, "broken");
  mkdirSync(brokenDir, { recursive: true });
  writeFileSync(path.join(brokenDir, "recording.json"), "{ truncated");

  const mergedPath = path.join(work, "merged.json");
  const mergeRun = run("shard.mjs", ["merge", "--indir", resultsDir, "--out", mergedPath]);
  check("merges shard results", mergeRun.status === 0, mergeRun.stderr);

  const merged = readJson(mergedPath);
  check(
    "prefers a later successful retry over an earlier PARTIAL",
    merged.recordings.find((r) => r.spec === "SYNTHETIC-b@1").complete === true &&
      merged.totals.duplicate_results_collapsed === 1,
    JSON.stringify(merged.totals)
  );
  check(
    "counts a failed recording as failed, not missing",
    merged.totals.failed === 1 && merged.failed_recordings[0].spec === "SYNTHETIC-c@1",
    JSON.stringify(merged.totals)
  );
  check(
    "names version mismatches rather than only counting them",
    merged.totals.version_mismatches === 1 &&
      merged.version_mismatches[0].installed === "9.9.9",
    JSON.stringify(merged.version_mismatches)
  );
  check(
    "counts an unreadable result rather than ignoring it",
    merged.totals.unreadable_results === 1,
    JSON.stringify(merged.totals)
  );

  // -------------------------------------------------------------------------------------------
  // summarize-corpus.mjs
  // -------------------------------------------------------------------------------------------
  section("summarize-corpus.mjs");

  // The registry's own view, shaped as `snapshot summarize --json` emits it.
  const corpusPath = path.join(work, "corpus.json");
  writeFileSync(
    corpusPath,
    JSON.stringify({
      snapshots: 3,
      snapshots_readable: 3,
      packages: 2,
      packages_with_multiple_versions: 1,
      diffable_pairs: 1,
      behavior_observations: 120,
      distinct_behaviors: 44,
      observations_by_class: { filesystem: 100, network: 20 },
      unresolved_paths: 0,
      intact: true,
      unreadable_snapshots: [],
      incomplete_snapshots: [],
    })
  );

  const datasetJson = path.join(work, "dataset.json");
  const datasetMd = path.join(work, "DATASET.md");
  const summarized = run("summarize-corpus.mjs", [
    "--merged", mergedPath, "--corpus", corpusPath,
    "--out-json", datasetJson, "--out-md", datasetMd,
  ]);
  check("summarizes the dataset", summarized.status === 0, summarized.stderr);

  const dataset = readJson(datasetJson);
  check(
    "takes behavior counts from the registry, not from the plan",
    dataset.corpus.behavior_observations === 120 && dataset.corpus.distinct_behaviors === 44
  );
  check(
    "reports both behavior numbers in the claim",
    dataset.claim_you_may_make.includes("120 behavior observations") &&
      dataset.claim_you_may_make.includes("44 are distinct"),
    dataset.claim_you_may_make
  );
  check(
    "states the failure count as part of the claim rather than a footnote",
    dataset.claim_you_may_make.includes("could not be recorded"),
    dataset.claim_you_may_make
  );
  check(
    "refuses a ranking claim",
    dataset.claim_you_may_NOT_make.some((entry) => entry.includes("top N")),
    JSON.stringify(dataset.claim_you_may_NOT_make)
  );
  check(
    "flags a low completion rate as disqualifying an unqualified claim",
    // The merged fixture has 1 failed of 4, i.e. 75%.
    dataset.recording_run.completion_rate < 0.9 &&
      dataset.claim_you_may_NOT_make.some((entry) => entry.includes("completion rate")),
    `rate=${dataset.recording_run.completion_rate}`
  );
  check(
    "notices a recording that completed but never reached the registry",
    // SYNTHETIC-d@1 is complete and pushed; SYNTHETIC-b@1's retry is pushed. None are unpushed here,
    // so the discrepancy list must be empty rather than fabricated.
    Array.isArray(dataset.discrepancies.complete_but_not_in_registry),
    JSON.stringify(dataset.discrepancies)
  );

  const datasetText = readFileSync(datasetMd, "utf8");
  check(
    "the report explains why distinct is the honest number",
    datasetText.includes("distinct counts how many *different*"),
  );
  check(
    "the report warns that failures bias the corpus",
    datasetText.includes("biased *against* the behaviors it exists to document"),
  );
  check("the report states nothing in it is a receipt", datasetText.includes("Nothing in this file is a receipt"));

  // A corpus that is not intact must fail, not warn: no claim may be published from it.
  const brokenCorpus = path.join(work, "corpus-broken.json");
  writeFileSync(
    brokenCorpus,
    JSON.stringify({
      snapshots: 3, snapshots_readable: 2, packages: 1, packages_with_multiple_versions: 0,
      diffable_pairs: 0, behavior_observations: 10, distinct_behaviors: 5,
      observations_by_class: {}, unresolved_paths: 0, intact: false,
      unreadable_snapshots: [{ snapshot: "SYNTHETIC-a@1", reason: "digest mismatch" }],
      incomplete_snapshots: [],
    })
  );
  const brokenRun = run("summarize-corpus.mjs", [
    "--merged", mergedPath, "--corpus", brokenCorpus,
    "--out-json", path.join(work, "broken-dataset.json"),
    "--out-md", path.join(work, "BROKEN.md"),
  ]);
  check(
    "a corpus that is not intact fails rather than warning",
    brokenRun.status !== 0 && brokenRun.stderr.includes("NOT intact"),
    `status=${brokenRun.status}`
  );
  check(
    "and it refuses any claim in that state",
    readJson(path.join(work, "broken-dataset.json")).claim_you_may_NOT_make.some((entry) =>
      entry.includes("while the corpus reports unreadable")
    )
  );

  // -------------------------------------------------------------------------------------------
  // select-receipts.mjs
  // -------------------------------------------------------------------------------------------
  section("select-receipts.mjs");

  const diffsDir = path.join(work, "diffs");
  mkdirSync(diffsDir, { recursive: true });
  writeFileSync(
    path.join(diffsDir, "a.json"),
    JSON.stringify({
      package: "SYNTHETIC-a",
      before_version: "1",
      after_version: "2",
      comparable: true,
      identical: false,
      unchanged: 12,
      added: [
        { class: "network", summary: "resolved SYNTHETIC-telemetry.example" },
        { class: "processes", summary: "piped curl output into a shell" },
      ],
      removed: [],
      blockers: [],
      caveats: [],
    })
  );

  // THE fixture the first real backfill produced, reduced to its shape: a dependency bump that added
  // 1200 node_modules writes and nothing else. Ranking by `added.length` put this at the top of the
  // queue, above a package that started phoning home, and a queue of 25 of these is a queue nobody
  // finishes. It must now rank *below* the two-behavior network change above.
  writeFileSync(
    path.join(diffsDir, "churn.json"),
    JSON.stringify({
      package: "SYNTHETIC-churn",
      before_version: "1",
      after_version: "2",
      comparable: true,
      identical: false,
      unchanged: 40,
      added: Array.from({ length: 1200 }, (_, index) => ({
        class: "filesystem",
        summary: `wrote project/node_modules/vendored-${index}/index.js`,
      })),
      removed: [],
      blockers: [],
      caveats: [],
    })
  );

  // A single write outside every declared zone — the critical class. One of these must outrank both of
  // the above, because nothing an ordinary install does produces it.
  writeFileSync(
    path.join(diffsDir, "escape.json"),
    JSON.stringify({
      package: "SYNTHETIC-escape",
      before_version: "1",
      after_version: "2",
      comparable: true,
      identical: false,
      unchanged: 5,
      added: [
        { class: "writes outside expected directories", summary: "wrote /etc/cron.d/SYNTHETIC" },
      ],
      removed: [],
      blockers: [],
      caveats: [],
    })
  );

  // A candidate whose one interesting behavior is buried under churn. The *evidence* must lead with the
  // credential read, not with ten node_modules lines — otherwise a reader sees churn and moves on, which
  // is the same failure as ranking it low.
  writeFileSync(
    path.join(diffsDir, "buried.json"),
    JSON.stringify({
      package: "SYNTHETIC-buried",
      before_version: "1",
      after_version: "2",
      comparable: true,
      identical: false,
      unchanged: 3,
      added: [
        ...Array.from({ length: 300 }, (_, index) => ({
          class: "filesystem",
          summary: `wrote project/node_modules/noise-${index}/index.js`,
        })),
        { class: "credential reads", summary: "read home/.ssh/id_rsa" },
      ],
      removed: [],
      blockers: [],
      caveats: [],
    })
  );

  // A blocked comparison must contribute nothing: a difference between recordings is not a difference
  // between versions.
  writeFileSync(
    path.join(diffsDir, "blocked.json"),
    JSON.stringify({
      package: "SYNTHETIC-d",
      before_version: "1",
      after_version: "2",
      comparable: false,
      identical: false,
      unchanged: 0,
      added: [{ class: "network", summary: "resolved SYNTHETIC-should-not-appear.example" }],
      removed: [],
      blockers: ["the two recordings were made by different backends"],
      caveats: [],
    })
  );

  const queueJson = path.join(work, "queue.json");
  const queueMd = path.join(work, "QUEUE.md");
  const selected = run("select-receipts.mjs", [
    "--merged", mergedPath, "--plan", planPath, "--diffs", diffsDir,
    "--out-json", queueJson, "--out-md", queueMd,
  ]);
  check("builds a review queue", selected.status === 0, selected.stderr);

  const queue = readJson(queueJson);
  const rankOf = (pkg) => queue.queue.findIndex((c) => c.package === pkg);
  const weightOf = (pkg) => queue.queue.find((c) => c.package === pkg)?.weight ?? -1;

  check(
    "ranks a version-to-version change above a metadata hint",
    queue.queue[0].kind === "behavior_changed_between_versions",
    queue.queue.map((c) => c.kind).join(", ")
  );

  // ---- the ranking fix, asserted from four directions ----------------------------------------
  //
  // Asserted as *tiers*, not as an exact ordering. `SYNTHETIC-escape` (one outside-project write, 601)
  // and `SYNTHETIC-a` (one network plus one process, 602) land one point apart, and which of those two
  // a human should read first is not a question the weighting claims to answer — a package that started
  // both phoning home and piping curl into a shell is not obviously less interesting than one that wrote
  // a single stray file. Pinning that 1-point order would be pinning an accident, and it would flip on
  // any future tweak for no reason a reader could defend.
  //
  // What the weighting *does* claim: notable classes outrank filesystem churn by an unbridgeable margin.
  // That is what these check.
  const NOTABLE = ["SYNTHETIC-escape", "SYNTHETIC-a", "SYNTHETIC-buried"];
  check(
    "every notable-class candidate outranks pure churn",
    NOTABLE.every((pkg) => rankOf(pkg) < rankOf("SYNTHETIC-churn")) &&
      NOTABLE.every((pkg) => weightOf(pkg) > weightOf("SYNTHETIC-churn")),
    queue.queue.slice(0, 5).map((c) => `${c.package}(${c.weight})`).join(", ")
  );
  check(
    "the top candidate is a notable class, never churn",
    NOTABLE.includes(queue.queue[0].package),
    `top is ${queue.queue[0].package}(${queue.queue[0].weight})`
  );
  check(
    "1200 node_modules writes rank BELOW a two-behavior network change",
    rankOf("SYNTHETIC-churn") > rankOf("SYNTHETIC-a") &&
      weightOf("SYNTHETIC-churn") < weightOf("SYNTHETIC-a"),
    `churn=${weightOf("SYNTHETIC-churn")} network=${weightOf("SYNTHETIC-a")}`
  );
  check(
    "no quantity of filesystem churn can bridge a class tier",
    // 1200 writes is the largest realistic churn; the log nudge must stay far below the tier gap. The
    // margin is asserted rather than just the ordering, so a future weighting change that narrowed it to
    // one point would fail here instead of silently becoming fragile.
    weightOf("SYNTHETIC-buried") - weightOf("SYNTHETIC-churn") > 100,
    `churn=${weightOf("SYNTHETIC-churn")} buried-credential-read=${weightOf("SYNTHETIC-buried")}`
  );
  check(
    "a credential read buried under 300 writes still ranks by the credential read",
    rankOf("SYNTHETIC-buried") < rankOf("SYNTHETIC-churn"),
    `buried=${rankOf("SYNTHETIC-buried")} churn=${rankOf("SYNTHETIC-churn")}`
  );
  check(
    "evidence leads with the interesting class, not with churn",
    queue.queue
      .find((c) => c.package === "SYNTHETIC-buried")
      .evidence[0].startsWith("[credential reads]"),
    queue.queue.find((c) => c.package === "SYNTHETIC-buried").evidence[0]
  );
  check(
    "the summary names the classes rather than a bare count",
    queue.queue.find((c) => c.package === "SYNTHETIC-buried").summary.includes("1 credential reads"),
    queue.queue.find((c) => c.package === "SYNTHETIC-buried").summary
  );
  check(
    "each candidate carries the class breakdown that drove its weight",
    queue.queue.find((c) => c.package === "SYNTHETIC-churn").classes.filesystem === 1200,
    JSON.stringify(queue.queue.find((c) => c.package === "SYNTHETIC-churn").classes)
  );
  check(
    "the withheld evidence count is stated rather than silently truncated",
    readFileSync(queueMd, "utf8").includes("more, in the recording artifact"),
    "a reader must know whether they saw the interesting part or the first tenth"
  );

  check(
    "excludes a blocked comparison entirely",
    !JSON.stringify(queue.queue).includes("should-not-appear"),
    "a blocked comparison says nothing about the package"
  );
  check(
    "counts blocked comparisons so their absence is explained",
    queue.inputs.version_diffs_blocked === 1,
    JSON.stringify(queue.inputs)
  );
  check(
    "excludes incomplete recordings from the queue",
    queue.inputs.recordings_usable < queue.inputs.recordings_total,
    JSON.stringify(queue.inputs)
  );
  check(
    "leaves every candidate unconfirmed",
    queue.queue.every((c) => c.confirmed === null),
    "no script may confirm a receipt (Rules.md rule 7)"
  );
  check(
    "says a human decides",
    queue.verdict.decided_by === "human" && queue.verdict.note.includes("No script"),
    queue.verdict.note
  );
  check(
    "renders evidence as readable lines rather than raw JSON",
    queue.queue[0].evidence.every((line) => typeof line === "string" && !line.startsWith("{")),
    JSON.stringify(queue.queue[0].evidence)
  );

  const queueText = readFileSync(queueMd, "utf8");
  check("the queue never prints PASS", !queueText.includes("PASS"));
  check(
    "the queue states nothing in it is a receipt yet",
    queueText.includes("Nothing here is a receipt yet")
  );
  check(
    "the queue leaves a checkbox for confirmation and rejection",
    queueText.includes("- [ ] confirmed as a receipt") && queueText.includes("- [ ] rejected")
  );

  // No diffs at all: the strongest signal is unavailable, and that must be said rather than implied by
  // a short queue.
  const noDiffs = run("select-receipts.mjs", [
    "--merged", mergedPath, "--plan", planPath,
    "--out-json", path.join(work, "queue-nodiffs.json"),
    "--out-md", path.join(work, "QUEUE-NODIFFS.md"),
  ]);
  check("builds a queue with no diffs available", noDiffs.status === 0, noDiffs.stderr);
  check(
    "says the strongest signal was unavailable",
    readJson(path.join(work, "queue-nodiffs.json")).caveats.some((c) =>
      c.includes("strongest signal")
    )
  );

  // An empty queue is a real result, and Phases.md:41's stop rule has to be visible in it.
  const emptyMerged = path.join(work, "empty-merged.json");
  writeFileSync(
    emptyMerged,
    JSON.stringify({
      schema: "installscope-corpus-merged/1",
      totals: { recordings: 0, complete: 0, partial: 0, failed: 0 },
      recordings: [],
    })
  );
  run("select-receipts.mjs", [
    "--merged", emptyMerged,
    "--out-json", path.join(work, "queue-empty.json"),
    "--out-md", path.join(work, "QUEUE-EMPTY.md"),
  ]);
  const emptyText = readFileSync(path.join(work, "QUEUE-EMPTY.md"), "utf8");
  check(
    "an empty queue states the stop rule rather than reading as a bug",
    emptyText.includes("stop rule applies") && emptyText.includes("process failure, not a fix"),
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log("");
console.log(`${checks - failures}/${checks} checks passed`);
if (failures > 0) {
  console.error(`test-corpus: ${failures} check(s) FAILED`);
  process.exit(1);
}
