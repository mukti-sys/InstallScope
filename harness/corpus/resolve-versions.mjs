#!/usr/bin/env node
// resolve-versions.mjs — turn a package list into a concrete, verifiable recording plan.
//
// Phases.md:38 asks for "top ~200 npm packages x last ~5 versions". Both halves of that are claims,
// and this script's job is to make them checkable rather than plausible.
//
// WHY "LAST 5 VERSIONS" NEEDS DECIDING RATHER THAN ASSUMING
//
// npm's registry offers no "last N versions" concept, and three obvious readings disagree:
//
//   1. Last 5 entries in the `versions` map. Wrong: object key order is insertion order, which for a
//      republished package is not publish order.
//   2. Highest 5 by semver. Wrong for the diff moat: a package maintaining 3.x and 4.x in parallel
//      would yield five 4.x versions and no history of what changed in 3.x.
//   3. Most recent 5 by publish time, prereleases excluded.  <- what this uses.
//
// (3) is what a version-diff wants: consecutive releases a real user would have installed one after
// the other. Prereleases are excluded because `npm install pkg` never resolves to one, so recording
// them would document behavior nobody experiences.
//
// WHY PUBLISH TIME COMES FROM `.time` AND NOT FROM THE VERSION LIST
//
// Verified against the live registry, not assumed: the full packument carries a `time` object mapping
// every version to an ISO publish timestamp, plus `created` and `modified` keys that are NOT versions
// and must be filtered out. The abbreviated packument (`Accept:
// application/vnd.npm.install-v1+json`) omits `time` entirely, so this script must request the full
// document — which is larger, which is why it caches.
//
// A version can appear in `time` but not in `versions`: that is an unpublished version, and its
// tarball is gone. Recording it is impossible, so the intersection is what gets planned.
//
// WHAT THIS SCRIPT REFUSES TO CLAIM
//
// It never writes "the top N packages". The input list is whatever a human put in packages.txt, and
// `rank-packages.mjs` is what attaches verifiable download counts. This script records the *plan*,
// including which versions it could not resolve and why, so a later summary can state the dataset's
// real shape instead of the intended one.
//
// Usage:
//   node harness/corpus/resolve-versions.mjs --packages harness/g2/packages.txt --versions 5 \
//     --out plan.json [--cache .cache/packuments] [--limit 200] [--offline]
//
// Network access required unless --offline (which reads only the cache). Not run in CI's default
// path: a corpus plan must not depend on a third-party API being up for an unrelated push to pass.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const REGISTRY = "https://registry.npmjs.org/";

/** Keys in a packument's `time` object that are not versions. Verified against the live registry. */
const TIME_NON_VERSION_KEYS = new Set(["created", "modified"]);

function fail(message) {
  console.error(`resolve-versions: FATAL: ${message}`);
  process.exit(2);
}

function log(message) {
  console.error(`resolve-versions: ${message}`);
}

// ---------------------------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------------------------

const options = {
  packages: "harness/g2/packages.txt",
  versions: 5,
  out: "corpus-plan.json",
  cache: ".cache/packuments",
  limit: 0,
  offline: false,
};

for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  switch (arg) {
    case "--packages": options.packages = process.argv[++i]; break;
    case "--versions": options.versions = Number.parseInt(process.argv[++i], 10); break;
    case "--out": options.out = process.argv[++i]; break;
    case "--cache": options.cache = process.argv[++i]; break;
    case "--limit": options.limit = Number.parseInt(process.argv[++i], 10); break;
    case "--offline": options.offline = true; break;
    case "-h":
    case "--help":
      console.log(
        "Usage: resolve-versions.mjs [--packages FILE] [--versions N] [--out FILE]\n" +
          "                           [--cache DIR] [--limit N] [--offline]"
      );
      process.exit(0);
      break;
    default: fail(`unknown argument: ${arg}`);
  }
}

if (!Number.isInteger(options.versions) || options.versions < 1 || options.versions > 50) {
  fail(`--versions must be an integer 1-50, got: ${options.versions}`);
}
if (!Number.isInteger(options.limit) || options.limit < 0) {
  fail(`--limit must be a non-negative integer, got: ${options.limit}`);
}

// ---------------------------------------------------------------------------------------------
// Package list
// ---------------------------------------------------------------------------------------------

/**
 * Reads the candidate list.
 *
 * Any pinned version in the list is stripped: this script's whole purpose is to choose versions, and
 * a pin in the input would silently override that for one entry and not others.
 */
function readPackageList(file) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch (error) {
    fail(`cannot read ${file}: ${error.message}`);
  }

  const names = [];
  const seen = new Set();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;

    // A scoped name starts with @ and its separator is the *second* @.
    const at = line.lastIndexOf("@");
    const name = at > 0 ? line.slice(0, at) : line;

    // Same character policy as record-package.sh and the workflow planner: a name reaches a shell
    // and a filesystem path, so anything outside npm's own conservative set is a bug or an attack.
    if (!/^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(name) || name.includes("..")) {
      fail(`refusing suspicious package name in ${file}: ${JSON.stringify(line)}`);
    }
    if (!seen.has(name)) {
      seen.add(name);
      names.push(name);
    }
  }
  if (names.length === 0) fail(`no packages found in ${file}`);
  return names;
}

// ---------------------------------------------------------------------------------------------
// Packuments
// ---------------------------------------------------------------------------------------------

/** Cache filename for a package. Scoped names contain a slash, which cannot be a path component. */
function cachePath(name) {
  return path.join(options.cache, `${name.replace(/[^A-Za-z0-9._-]/g, "_")}.json`);
}

/**
 * Fetches a full packument, cached on disk.
 *
 * Cached because the full document is large (typescript's is tens of megabytes) and because a
 * resumable backfill should not re-fetch on every shard. The cache is keyed by name only: a
 * packument is a moving target, and `fetched_at` in the plan is what records which snapshot was used.
 */
async function packumentOf(name) {
  const file = cachePath(name);
  if (existsSync(file)) {
    try {
      return { document: JSON.parse(readFileSync(file, "utf8")), cached: true };
    } catch (error) {
      // A corrupt cache entry is refetched rather than trusted or silently skipped.
      log(`cache entry for ${name} is unreadable (${error.message}); refetching`);
    }
  }
  if (options.offline) {
    return { document: null, cached: false, error: "not in cache and --offline was given" };
  }

  const url = REGISTRY + encodeURIComponent(name).replace(/^%40/, "@");
  try {
    const response = await fetch(url, { headers: { accept: "application/json" } });
    if (!response.ok) {
      return { document: null, cached: false, error: `HTTP ${response.status} for ${url}` };
    }
    const document = await response.json();
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, JSON.stringify(document));
    return { document, cached: false };
  } catch (error) {
    return { document: null, cached: false, error: String(error.message ?? error) };
  }
}

// ---------------------------------------------------------------------------------------------
// Version selection
// ---------------------------------------------------------------------------------------------

/**
 * True for a version string with a prerelease component.
 *
 * `npm install pkg` never resolves to one, so recording it would document behavior no user
 * experiences. Detected by the semver separator rather than by a keyword list, because prerelease
 * tags are arbitrary text.
 */
function isPrerelease(version) {
  return version.includes("-");
}

/**
 * Selects the most recent stable versions, newest first.
 *
 * Returns the selection plus everything that was excluded and why, because a plan that silently
 * drops candidates cannot be audited.
 */
function selectVersions(document, count) {
  const time = document.time ?? {};
  const published = document.versions ?? {};

  const excluded = { prerelease: 0, unpublished: 0, no_timestamp: 0 };

  const dated = [];
  for (const [version, stamp] of Object.entries(time)) {
    if (TIME_NON_VERSION_KEYS.has(version)) continue;
    if (isPrerelease(version)) { excluded.prerelease += 1; continue; }
    // Present in `time` but absent from `versions` means unpublished: the tarball is gone and the
    // install cannot be recorded.
    if (!Object.prototype.hasOwnProperty.call(published, version)) {
      excluded.unpublished += 1;
      continue;
    }
    const at = Date.parse(stamp);
    if (!Number.isFinite(at)) { excluded.no_timestamp += 1; continue; }
    dated.push({ version, published_at: stamp, at });
  }

  // Newest first, with the version string as a tiebreak so two versions published in the same
  // millisecond order deterministically rather than by object iteration order.
  dated.sort((a, b) => b.at - a.at || (a.version < b.version ? 1 : -1));

  const selected = dated.slice(0, count).map(({ version, published_at }) => {
    const manifest = published[version] ?? {};
    const scripts = manifest.scripts ?? {};
    // Recorded as a *prior* claim from registry metadata, to be compared against what the recording
    // actually observed. Metadata saying "no install script" and a recording showing a spawned
    // process is itself interesting.
    const installScripts = ["preinstall", "install", "postinstall", "prepare"]
      .filter((hook) => typeof scripts[hook] === "string" && scripts[hook].trim() !== "");
    return {
      version,
      published_at,
      declares_install_scripts: installScripts,
      deprecated: typeof manifest.deprecated === "string" ? manifest.deprecated : null,
      unpacked_bytes: manifest.dist?.unpackedSize ?? null,
      integrity: manifest.dist?.integrity ?? null,
    };
  });

  return { selected, excluded, stable_available: dated.length };
}

// ---------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------

const names = readPackageList(options.packages);
const planned = options.limit > 0 ? names.slice(0, options.limit) : names;
log(`${planned.length} package(s) from ${options.packages}, up to ${options.versions} versions each`);

const packages = [];
const failures = [];
let fetched = 0;
let fromCache = 0;

for (const name of planned) {
  const { document, cached, error } = await packumentOf(name);
  if (!document) {
    failures.push({ package: name, error });
    log(`${name}: UNRESOLVED (${error})`);
    continue;
  }
  if (cached) fromCache += 1; else fetched += 1;

  const { selected, excluded, stable_available } = selectVersions(document, options.versions);
  if (selected.length === 0) {
    failures.push({ package: name, error: "no stable published versions with timestamps" });
    log(`${name}: UNRESOLVED (no stable versions)`);
    continue;
  }

  packages.push({
    package: name,
    latest: document["dist-tags"]?.latest ?? null,
    stable_versions_available: stable_available,
    versions_excluded: excluded,
    versions: selected,
  });
}

const recordings = packages.reduce((sum, entry) => sum + entry.versions.length, 0);
const withScripts = packages.reduce(
  (sum, entry) => sum + entry.versions.filter((v) => v.declares_install_scripts.length > 0).length,
  0
);

const plan = {
  schema: "installscope-corpus-plan/1",
  generated_at: new Date().toISOString(),
  source: {
    registry: REGISTRY,
    package_list: options.packages,
    note:
      "npm publishes no ranking endpoint. This plan says which package@version pairs will be " +
      "recorded; it makes no claim about popularity. Run harness/g2/rank-packages.mjs for " +
      "verifiable download counts.",
  },
  selection_rule:
    `most recent ${options.versions} stable versions by registry publish time, newest first; ` +
    "prereleases and unpublished versions excluded",
  totals: {
    packages_requested: planned.length,
    packages_resolved: packages.length,
    packages_unresolved: failures.length,
    recordings_planned: recordings,
    recordings_declaring_install_scripts: withScripts,
    packuments_fetched: fetched,
    packuments_from_cache: fromCache,
  },
  // Stated because Phases.md:39's "~50k version-behaviors" is a different quantity from the number
  // of recordings, and the difference is easy to blur in a launch post. Only a completed backfill
  // can count behaviors; a plan can only count recordings.
  claim_you_may_make:
    `${packages.length} packages x up to ${options.versions} versions = ${recordings} planned ` +
    "recordings. A behavior count can only come from summarize-corpus.mjs after the backfill runs.",
  claim_you_may_NOT_make:
    '"the top N npm packages" (no ranking established here), and no behavior count from this file',
  unresolved: failures,
  packages,
};

writeFileSync(options.out, JSON.stringify(plan, null, 2) + "\n");
log(`wrote ${options.out}`);
log(
  `${packages.length}/${planned.length} packages resolved, ${recordings} recordings planned, ` +
    `${withScripts} declare install scripts`
);
if (failures.length > 0) {
  log(`${failures.length} package(s) unresolved — see .unresolved in the plan`);
}
