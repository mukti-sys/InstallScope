# Scope.md — InstallScope v1 boundary contract
**Canonical scope authority. If a doc disagrees with this file, this file wins.**

## What this file is
PRD.md says what we build. This file says what we **refuse to build (for now)** and the exact
conditions under which a refused thing gets promoted. It exists because scope creep — not bugs —
is how solo builds die and how tools stay 80% forever.

## Boot order for any AI session
1. `Memory.md` (state snapshot)
2. `Scope.md` (this file — the fence)
3. `Phases.md` → current phase only
4. Only NOW the codebase.

## Decision protocol for any new idea ("can we also…")
1. On the **IN list**? → do it, inside the correct phase.
2. On the **DEFERRED list**? → do nothing; log in Memory.md open threads.
3. In no list? → apply the one-line test:
   *"Does this make the evidence more trustworthy, or the evidence easier to get?"*
   Neither → reject. Add one line here with the reason.
4. Any promotion OUT→IN requires: edit this file + bump a phase in Phases.md + log in Memory.md.
   Three files or it didn't happen. There is no "quick add."

## IN scope — v1 (complete list)
- Linux only (ubuntu-latest GitHub runners + local VM harness)
- npm + pnpm lockfile-diff trigger ONLY
- Recorder backends: strace (v1.0), aya eBPF (v1.1, gated on Gate G1)
- Audit/observe-only mode — everything allowed, everything logged
- Deterministic rules engine (no LLM); score 0–100; max 3 bullets in PR comment
- Reports: PR comment + SARIF 2.1.0 + self-contained HTML artifact
- Snapshot registry v0: content-addressed (sha256/zstd) blobs + version-diff engine
- Corpus backfill: top ~200 npm packages × last ~5 versions, clean-VM-per-package harness
- Receipts teaser as the demand probe (Gate G3)

## OUT of scope — v1 (hard rejections, re-opened only via triggers below)
| Rejected | One-line why |
|---|---|
| Blocking builds by default | FP kills adoption; advisory is the trust path (PRD §5.4) |
| Strict/sandbox mode | Marketing as protection = credibility death; audit mode is the product |
| macOS / Windows | Kernel-evidence surface × 2 more platforms = guaranteed 80% forever |
| Yarn / Poetry / Cargo lockfiles | Four parsers in v1 = four half-finished ones |
| LLM anything | Determinism is a feature; banned in Rules.md |
| GUI/dashboard | Report artifact + HTML is the UX; web app = company, not v1 repo |
| Wrapping arbitrary installs | Lockfile-diff trigger is sacred; habit-change tools die |
| Telemetry on users | "We watch packages, not people" — irony is fatal |

## DEFERRED — v2 candidates with concrete promotion triggers
| Item | Promotion trigger (measurable, not vibes) |
|---|---|
| Strict mode (bubblewrap+seccomp, opt-in) | ≥20 distinct users/issues asking "how do I *stop* this behavior" AND spec written |
| macOS (Endpoint Security backend) | v1 core stable 30 days AND ≥100 reactions on macOS-demand issue |
| Windows (ETW backend) | Same pattern as macOS, measured separately |
| Smoke-profile (run-time recording) | Corpus shows a top-10 attack shape install-time recording would have missed |
| Yarn/Cargo/Poetry lockfiles | Top request issue ≥50 reactions after Phase 6 |
| Hosted registry / org tier | ≥10 inbound org asks (the PRD success metric itself) |
| LLM-assisted summaries | **Permanent rejection** absent a deliberate portfolio decision — revisiting costs determinism trust |

## Pre-authorized scope REDUCTIONS (so gate failure ≠ design debate)
- G1 fails twice → drop aya from v1, ship strace-only. Scope.md already allows this; no rewrite needed.
- G2 fails (<10 surprises on top-200) → v1 pivots to "registry-version-diff viewer" or stops. Human decides; coding stops.
- Phase 4 runner-time >3 min → drop HTML artifact before dropping SARIF. Evidence > polish.
