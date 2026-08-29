# harness/ — Phase 0 kill-gate tooling

This directory is **gate tooling, not product code**.

Memory.md records "Product code: NONE yet by design — gates precede code." Nothing here is
`core/`, `recorder/`, `cli/`, or `report/` from Architecture.md §5. These scripts exist only to
answer two questions cheaply:

| Gate | Question | Directory |
|---|---|---|
| **G1** | Does an aya eBPF program load and record an event on a stock `ubuntu-latest` runner? | `g1/` |
| **G2** | Do real npm installs actually do surprising things — ≥10 documented receipts? | `g2/` |

When Phase 1 starts, the product recorder is written fresh in Rust under `recorder/`. The G2
parser here is a throwaway Node script deliberately: it must be cheap to abandon.

## Deviation from Phases.md, stated plainly

Phases.md:7 specifies "fresh VM per package" in a **local** VM. This machine (win32, no WSL, no
Rust toolchain) cannot host that harness, so the same isolation property is obtained differently:
**one `ubuntu-latest` job per package** in a GitHub Actions matrix. Each job is a fresh ephemeral
VM with its own kernel, filesystem, and empty npm cache — equal or better isolation than a
locally reused VM image, at the cost of trusting GitHub's runner image.

This is a change of execution venue, not of scope. No Scope.md IN/OUT entry is affected;
Scope.md:25 already names `ubuntu-latest` runners as an in-scope environment.

## Gate discipline

Rules.md §7: a failed gate stops work. These scripts therefore **do not decide** gate outcomes.
`g2/aggregate.mjs` reports *candidate* surprises; a candidate becomes a **receipt** only after a
human reads the evidence and confirms it. `G2 PASS` is a human sign-off recorded in Memory.md,
never a green checkmark from a script.
