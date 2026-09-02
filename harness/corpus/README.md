# harness/corpus — Phase 5 corpus backfill

Phases.md:38 asks for "top ~200 npm packages × last ~5 versions, clean-VM-per-package harness (no cache
contamination)". This directory is that harness.

Unlike `harness/g2/`, which was deliberately disposable, what this produces gets **published**. So it
uses the product recorder rather than a throwaway parser, and the numbers it reports are computed from
stored evidence rather than from a plan.

## Pipeline

```
packages.txt ──▶ resolve-versions ──▶ corpus-plan.json
                                          │
                                     shard plan ──▶ shards.json ──▶ matrix
                                                                      │
                            per shard: record-corpus.sh × N ──▶ recording.json + registry/
                                                                      │
                                     shard merge ──▶ merged.json ◀─────┘
                                          │
        installscope snapshot summarize ──┼──▶ summarize-corpus ──▶ DATASET.md
                installscope diff --json ─┴──▶ select-receipts   ──▶ RECEIPTS-QUEUE.md
                                                                      │
                                                            human confirms ──▶ G3
```

| File | Role |
|---|---|
| `resolve-versions.mjs` | package list → concrete `package@version` plan, from registry publish times |
| `record-corpus.sh` | records ONE `package@version` with `installscope record`, cold cache |
| `shard.mjs` | `plan` splits work for a matrix and is resumable; `merge` collects results |
| `summarize-corpus.mjs` | joins the run log with the store → the dataset description and its claim |
| `select-receipts.mjs` | ranks candidates for human review. Confirms nothing. |
| `test-corpus.mjs` | golden tests over synthetic fixtures for all four |

## Three decisions worth not re-litigating

### "Last 5 versions" means most recent by publish time

Three readings disagree, and this was checked against the live registry rather than assumed:

1. **Last 5 keys in the `versions` map** — wrong. Object key order is insertion order, which for a
   republished package is not publish order.
2. **Highest 5 by semver** — wrong for the diff moat. A package maintaining 3.x and 4.x in parallel
   yields five 4.x versions and no history of what changed in 3.x.
3. **Most recent 5 by publish time, prereleases excluded** — what `resolve-versions.mjs` uses. These are
   consecutive releases a real user would have installed one after the other, which is what a
   version-diff wants. `npm install pkg` never resolves to a prerelease, so recording one would document
   behavior nobody experiences.

Two things verified against real packuments, both of which would silently corrupt the plan:

- The **abbreviated** packument (`Accept: application/vnd.npm.install-v1+json`) has no `time` object at
  all. The resolver must request the full document, which is why it caches.
- `time` contains `created` and `modified` keys that are **not versions**. Filtering them is mandatory,
  or every package gains two phantom entries.

A version can also appear in `time` but be absent from `versions`: that is an unpublished version and its
tarball is gone. `chalk@5.6.1` is exactly this — published 2025-09-08, now a hard 404. The plan records
the intersection and counts the exclusions.

### Cache isolation is per recording, not per package

This is the subtle half of "no cache contamination". Recording `lodash@4.18.1` and then `4.18.0` against
a shared cache means the second install finds its tarball already present, makes no network requests, and
produces a recording with **no DNS and no connects**.

The two recordings would then differ enormously, for a reason that has nothing to do with the package.
And the difference is invisible to the diff engine: zone-relative paths cannot fix an *absent* event.

So every recording gets a cold cache, and the cost is that every install re-downloads. That cost is the
price of two recordings of the same package being comparable at all.

The *VM* is shared across versions of one package, which is what keeps the backfill at ~200 jobs rather
than ~1000. `record-corpus.sh` gives every recording a fresh cache, home, project and tmp, so what a
shared VM can leak between versions is only state outside those zones — a postinstall writing to
`/usr/local`, say. Sharing that risk within one package is acceptable; sharing it across packages is not,
because then one package's behavior could appear as another's.

### PARTIAL recordings are counted, never quietly dropped

The registry refuses incomplete recordings (`registry/src/lib.rs`), because a version-diff drawn against
one reports "this behavior disappeared in 1.2.4" when the recorder actually stopped early. So a PARTIAL
recording never enters the corpus.

It does enter every report. `shard.mjs merge` names them, `summarize-corpus.mjs` puts the failure count
**inside** the claim sentence rather than in a footnote, and a completion rate below 90% disqualifies an
unqualified dataset claim outright. The reason is not just honesty: a package with an elaborate
postinstall is more likely to time out, so a lossy backfill is biased *against* the behaviors the corpus
exists to document.

`shard.mjs plan --completed` also treats a PARTIAL recording as **attempted but not done**, so a resumed
run retries it. Treating it as done would silently shrink the dataset on every resume.

## Two numbers, not one

Phases.md:39 wants to publish "we already recorded ~50k version-behaviors". 200 packages × 5 versions is
1000 **recordings**, which is a different quantity — and only a completed corpus can produce the second
one.

`installscope snapshot summarize` computes both:

- **behavior observations** — every behavior in every recording
- **distinct behaviors** — how many *different* behaviors exist

The second is much smaller, because every install writes to `node_modules`. Publishing only the larger
would be technically true and misleading, so `summarize-corpus.mjs` puts both in the claim sentence and
`DATASET.md` explains the difference. `Rules.md` rule 5 applies to our own headline as much as to the
neighbour table.

## No script decides G3

`select-receipts.mjs` produces a **review queue**. Every candidate carries `confirmed: null`, the
Markdown has checkboxes, and nothing anywhere prints PASS.

That is not ceremony. A rule firing means "this matched a pattern"; a receipt means "a maintainer would
be surprised", and only the second is a judgement about people. A script that auto-confirmed would be
manufacturing the gate's own evidence, which is the failure `Rules.md` rule 7 names.

The queue ranks three signals, weighted:

| Signal | Weight | Why |
|---|---|---|
| Behavior appeared between two versions of one package | 100+ | The only signal carrying its own baseline: the same package, one version earlier, not doing this |
| Package declares an install script and was recorded running it | 20 | Expected, but worth reading |
| Package declares no install script yet its recording is busy | 10 | A hint only — npm's own activity dominates any install |

A **blocked** comparison contributes nothing. Different backends or a PARTIAL recording on either side
means a difference between *recordings*, not between versions (`registry/src/diff.rs`), and ranking one as
a candidate would put a retractable claim at the top of a launch post. Blocked comparisons are counted so
their absence from the queue is explained rather than looking like an empty result.

An **empty queue is a real result**, and the Markdown says so: Phases.md:41's stop rule applies, and a
human chooses between repositioning and launching as a content piece. Widening the rules to manufacture
candidates is a process failure, not a fix.

## Popularity claims

Nothing here establishes a ranking. `harness/g2/packages.txt` is hand-written, and
`harness/g2/rank-packages.mjs` is what attaches verifiable weekly download counts — use its phrasing
("N packages, each with at least X weekly downloads as of DATE") rather than "the top N".
`summarize-corpus.mjs` copies that sentence verbatim when a ranking file is supplied, and refuses the
"top N" phrasing in every case.

## Local run

```sh
# Plan (network: reads the npm registry)
node harness/corpus/resolve-versions.mjs --packages harness/g2/packages.txt \
  --versions 3 --limit 6 --out corpus-plan.json

# Shard
node harness/corpus/shard.mjs plan --plan corpus-plan.json --shards 2 --out shards.json

# Record one version (Linux only; needs strace and a built installscope)
harness/corpus/record-corpus.sh --package ms --version 2.1.3 \
  --outdir out/ms_2.1.3 --registry registry --timeout 600

# Merge, describe, and queue
node harness/corpus/shard.mjs merge --indir out --out merged.json
installscope snapshot summarize --registry registry --json --out corpus-summary.json
node harness/corpus/summarize-corpus.mjs --merged merged.json --corpus corpus-summary.json \
  --out-json dataset.json --out-md DATASET.md
node harness/corpus/select-receipts.mjs --merged merged.json --plan corpus-plan.json \
  --diffs diffs --out-json receipts-queue.json --out-md RECEIPTS-QUEUE.md
```

Recording is Linux-only. Everything else is pure Node and runs anywhere, which is what
`test-corpus.mjs` exercises on every push.
