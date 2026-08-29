#!/usr/bin/env node
// rank-packages.mjs — attach real download counts to packages.txt.
//
// Why this exists: PRD.md:66 warns against getting fact-checked. Saying "we recorded the top 50 npm
// packages" is a claim about ranking. npm exposes no ranking endpoint, so this script does the
// honest, verifiable thing instead: it queries the documented bulk downloads API and records the
// ACTUAL weekly download count for every package in packages.txt.
//
// That converts an unverifiable claim ("the top 50") into a verifiable one ("50 packages, each with
// at least N weekly downloads, counts recorded on DATE"). Use the second form in public writing.
//
// Network access required. Not run in CI: the gate must not depend on a third-party API being up.
// Usage: node harness/g2/rank-packages.mjs [--out ranking.json]

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const ENDPOINT = "https://api.npmjs.org/downloads/point/last-week/";
const BULK_LIMIT = 100; // API documents 128; stay under it

function fail(msg) { console.error(`rank-packages: FATAL: ${msg}`); process.exit(2); }

let outPath = path.join(here, "ranking.json");
for (let i = 2; i < process.argv.length; i += 1) {
  if (process.argv[i] === "--out") outPath = process.argv[++i];
  else if (process.argv[i] === "-h" || process.argv[i] === "--help") {
    console.log("Usage: rank-packages.mjs [--out ranking.json]");
    process.exit(0);
  } else fail(`unknown argument: ${process.argv[i]}`);
}

const specs = readFileSync(path.join(here, "packages.txt"), "utf8")
  .split("\n")
  .map((l) => l.trim())
  .filter((l) => l !== "" && !l.startsWith("#"));

// Strip any pinned version; the downloads API takes bare names.
const names = [...new Set(specs.map((s) => {
  const at = s.lastIndexOf("@");
  return at > 0 ? s.slice(0, at) : s;
}))];

// Scoped packages cannot be bulk-queried; they must be fetched one at a time.
const scoped = names.filter((n) => n.startsWith("@"));
const plain = names.filter((n) => !n.startsWith("@"));

const counts = new Map();
const errors = [];

async function fetchJson(url) {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

for (let i = 0; i < plain.length; i += BULK_LIMIT) {
  const batch = plain.slice(i, i + BULK_LIMIT);
  try {
    const data = await fetchJson(ENDPOINT + batch.join(","));
    // A single-package batch returns the object directly rather than keyed by name.
    if (batch.length === 1) {
      counts.set(batch[0], data && typeof data.downloads === "number" ? data.downloads : null);
    } else {
      for (const name of batch) {
        const entry = data ? data[name] : null;
        counts.set(name, entry && typeof entry.downloads === "number" ? entry.downloads : null);
      }
    }
  } catch (err) {
    errors.push({ batch, error: String(err.message ?? err) });
    for (const name of batch) counts.set(name, null);
  }
}

for (const name of scoped) {
  try {
    const data = await fetchJson(ENDPOINT + encodeURIComponent(name));
    counts.set(name, data && typeof data.downloads === "number" ? data.downloads : null);
  } catch (err) {
    errors.push({ batch: [name], error: String(err.message ?? err) });
    counts.set(name, null);
  }
}

const ranked = [...counts.entries()]
  .map(([name, downloads]) => ({ name, weekly_downloads: downloads }))
  .sort((a, b) => (b.weekly_downloads ?? -1) - (a.weekly_downloads ?? -1));

const known = ranked.filter((r) => typeof r.weekly_downloads === "number");
const minKnown = known.length > 0 ? known[known.length - 1].weekly_downloads : null;

const out = {
  source: ENDPOINT + "<comma-separated-names>",
  source_note: "npm registry downloads API, last-week point counts. npm publishes no ranking endpoint.",
  fetched_at: new Date().toISOString(),
  packages_in_list: names.length,
  packages_with_counts: known.length,
  packages_without_counts: ranked.length - known.length,
  min_weekly_downloads_observed: minKnown,
  claim_you_may_make: minKnown === null
    ? "no counts retrieved — make no popularity claim"
    : `${known.length} packages, each with at least ${minKnown.toLocaleString("en-US")} weekly downloads as of ${new Date().toISOString().slice(0, 10)}`,
  claim_you_may_NOT_make: "\"the top N npm packages\" — this data does not establish a ranking",
  errors,
  ranked,
};

writeFileSync(outPath, JSON.stringify(out, null, 2) + "\n");
console.error(`rank-packages: wrote ${outPath} (${known.length}/${names.length} counts, ${errors.length} errors)`);
if (minKnown !== null) console.error(`rank-packages: safe claim -> ${out.claim_you_may_make}`);
