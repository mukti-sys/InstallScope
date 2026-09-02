# harness/ — gate tooling and the corpus backfill

Nothing here is `core/`, `recorder/`, `cli/`, `report/`, `lockfile/` or `registry/` from
Architecture.md §5. Two different kinds of thing live here:

| Directory | Phase | Question | Disposable? |
|---|---|---|---|
| `g1/` | 0 | Does an aya eBPF program load and record an event on a stock `ubuntu-latest` runner? | yes |
| `g2/` | 0 | Do real npm installs actually do surprising things — ≥10 documented receipts? | yes |
| `corpus/` | 5 | The backfill: top ~200 packages × last ~5 versions, and the receipt queue | **no** |

The Phase 0 directories were written to be abandoned. `g2/`'s parser is a throwaway Node script
deliberately: it answered a gate cheaply and Phase 1 replaced it with the Rust recorder.

`corpus/` is different. What it produces gets **published**, so it drives the product recorder rather
than reimplementing one, and every number it reports is computed from stored evidence rather than from a
plan. See `corpus/README.md`.

## Deviation from Phases.md, stated plainly

Phases.md:7 specifies "fresh VM per package" in a **local** VM. This machine (win32, no WSL) cannot host
that harness, so the same isolation property is obtained differently: **one `ubuntu-latest` job per
package** in a GitHub Actions matrix. Each job is a fresh ephemeral VM with its own kernel, filesystem,
and empty npm cache — equal or better isolation than a locally reused VM image, at the cost of trusting
GitHub's runner image.

This is a change of execution venue, not of scope. No Scope.md IN/OUT entry is affected; Scope.md:25
already names `ubuntu-latest` runners as an in-scope environment.

The Phase 5 backfill goes one step further and isolates the **cache per recording**, not per job. Two
versions of one package sharing a cache would make the second install fetch nothing, and the two
recordings would then differ for a reason that has nothing to do with the package. See
`corpus/README.md`.

## Gate discipline

Rules.md §7: a failed gate stops work. These scripts therefore **do not decide** gate outcomes.

- `g2/aggregate.mjs` reports *candidate* surprises. `G2 PASS` was a human sign-off recorded in Memory.md.
- `corpus/select-receipts.mjs` produces a *review queue*: every candidate carries `confirmed: null`, and
  nothing prints PASS. G3 is fired by a human who reads the evidence.

A candidate becomes a receipt only when a human confirms the behavior is genuinely surprising. A rule
firing means "this matched a pattern"; a receipt means "a maintainer would be surprised", and only the
second is a judgement about people.
