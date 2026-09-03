# Phases.md — InstallScope build sequence
Rule: each phase ends with **Done =** checkboxes all true + Memory.md updated. Gates G1–G3 are walls,
not suggestions. Stop rules are explicit. Scope changes go through Scope.md, never around it.

## Phase 0 — Kill gates (≤1 week, BEFORE product code)
### G2 first (cheap, informative): strace harness in local VM
- Script: fresh VM per package → `npm install <pkg>` under `strace -f -ff` → JSONL.
- Run top ~50 npm packages. **Done: ≥10 documented behavioral surprises** (README-worthy receipts
  with evidence files in `corpus/`).
- **Stop rule:** <10 surprises on top 200 → the "postinstall epidemic is boring" hypothesis wins.
  Reposition or stop. Log in Memory.md. Do not code product.
### G1 same week (pricing the eBPF bet, ~1 hour)
- aya tracepoint hello-world in an `ubuntu-latest` GitHub Action: load, record 1 event, upload artifact.
- **Done: green run + artifact.** Fallback order: aya → libbpf-rs → strace-only product (pre-authorized in Scope.md).
### G3 prepared but not fired: pick the 3 spiciest G2 receipts; no launch yet.

## Phase 1 — strace recorder CLI (v1.0 core)
- `installscope record -- <cmd>`: spawn under strace, parse to JSONL (schema v1), heartbeat,
  session_end, PARTIAL handling.
- **Done:** records real `npm install` end-to-end; golden tests; zero unwraps; complete→clean / crash→PARTIAL tested.

## Phase 2 — aya backend (v1.1, behind G1)
- eBPF events: fs write, tcp connect, proc spawn. Dedupe, merge into JSONL, parity tests vs strace.
- **Done:** parity on synthetic workload in VM; ubuntu-latest Action runs full record; agent stamps backend.

## Phase 3 — Rules engine + reports
- YAML rule catalog (PRD §4 table), scoring (40/15/5/1), SARIF 2.1.0 emitter (schema-validated),
  self-contained HTML artifact, PR-comment renderer (1 score + 3 bullets + link).
- **Done:** demo corpus reports generated at all three levels (clean / high / critical); score math unit-tested.

## Phase 4 — GitHub Action + snapshot registry v0
- Lockfile-diff trigger (package-lock.json, pnpm-lock.yaml — npm+pnpm ONLY), runs recorder in audit mode,
  posts advisory comment (blocking opt-in), uploads SARIF+HTML, pushes content-addressed snapshot
  (sha256/zstd) to registry, `installscope diff pkg v1 v2`.
- **Done:** fresh repo, 1 dependency PR → comment + artifacts + snapshot, all under ~3 min runner time.

## Phase 5 — Corpus backfill + receipts (the launch ammunition)
- Top ~200 npm packages × last ~5 versions, clean-VM-per-package harness (no cache contamination).
- Publish the "we already recorded ~50k version-behaviors" dataset.
- **Fire G3:** post the 3 best receipts publicly (teaser thread).
- **Stop rule:** zero inbound asks → launch anyway as content piece, consciously, portfolio-grade ≠ star-bait.

## Phase 6 — Launch kit + Show HN
- GIF-first README (≤15s: PR → finding, zero setup), ≤3-command quickstart, neighbor table (incl.
  re-verified Socket CLI status), engineering blog post BEFORE Show HN, signed releases, CHANGELOG,
  3 good-first-issues (one = "write a community rule").
- **Done:** post Show HN. Start the 30-day/300-star + signups clock.

## Phase 7+ — post-launch (each item enters scope only via Scope.md promotion)
Community rule catalog drive → strict mode (opt-in) → smoke-profile → macOS ES / Windows ETW spikes →
org tier when ≥10 inbound org asks, not before.

Sequencing note: G2-before-eBPF is deliberate — if reality is boring, better to learn on strace+harness
in 2 days than after 3 weeks of eBPF.
