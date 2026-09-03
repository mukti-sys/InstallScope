# Rules.md — Boundaries for the AI building InstallScope

You are the AI coding agent on this repo. These rules are hard constraints.

## 1. Libraries
- **Allowed:** aya, libbpf-rs (fallback only), tokio, clap, serde/serde_json/serde_yaml, thiserror,
  anyhow (CLI boundary only), tracing, zstd, minisign/sigstore, reqwest (CLI only, never core).
- **Avoid:** C-dependent stacks unless documented (libbpf-sys acceptable for fallback backend),
  heavyweight web frameworks for reports (single HTML file, inline assets), Docker-in-CI for kernel
  paths (use VM scripts), any ORM/DB (JSONL + files until org tier).
- **Banned:** any LLM/cloud/telemetry SDK inside core or recorder. No exceptions. This product's
  entire moral claim is "we watch packages, not people."

## 2. Error handling
- `thiserror` typed errors in `core/`; `anyhow` only at `cli/main.rs`.
- **No `.unwrap()` / `.expect()` in non-test code.** Clippy denies: `clippy::unwrap_used`.
- Recorder failure philosophy: fail LOUD. A dead recording must surface as `PARTIAL`, never as silence.
  Every session writes `heartbeat` events; missing `session_end{complete:true}` ⇒ report says PARTIAL.
- Never swallow errors in the Action step; a green build with a silently-dead recorder is the worst
  outcome this project can produce. Worse than crashing.

## 3. Scope hard lines
- **Scope.md is the canonical boundary document.** Read it at session start (boot order: Memory.md →
  Scope.md → current phase). Default-OUT rule: anything not on the IN list doesn't get built.
- v1 = Linux, npm+pnpm lockfiles, audit mode (observe-only). Touching strict mode, macOS, Windows,
  smoke-profile, or Yarn without a Scope.md promotion + phase bump = scope violation. Say no.
- No LLM anywhere in v0.x. Deterministic rules only.
- No feature that requires users to change how they install things. The lockfile-diff trigger is sacred.

## 4. Banned language (in code, docs, README, comments)
"protection", "sandbox", "safe", "guaranteed", "security blanket", "blocks malicious packages".
**Use:** "evidence", "records", "observe", "forensic report", "audit". If strict mode ships later,
it is "opt-in enforcement", never "protection". Security reviewers will eat you alive otherwise.

## 5. Truth discipline
- Never fabricate recordings, syscall data, or neighbor-product claims in docs/tests/examples.
  Golden fixtures must be labeled synthetic; real corpus recordings must never be hand-edited.
- Every unverified claim (versions, competitor features, runner capabilities) gets a `// TODO-verify`
  marker, not a confident sentence.
- On kernel/eBPF APIs: **ask, don't guess.** Admitted uncertainty > plausible-looking wrong code.

## 6. Engineering standards
- `cargo fmt` + `clippy -D warnings` clean. Conventional commits. Semver + signed releases from v0.1.
- **Git & Author Discipline:** All commits and pushes belong to GitHub account `mukti-sys`.
  Consolidate work into clean, atomic commits; **never push more than 1 commit in a single day.**
  One commit per day is a hard ceiling, so a day's work is squashed into one coherent commit before
  it leaves the machine. This tightens the previous ≤10/day limit and supersedes it. Practical
  consequence: batch a whole session, verify it, then commit once — and if a commit already went out
  today, the next one waits for tomorrow rather than being amended into the pushed one.
- Every rules-engine change ships with golden test fixtures + SARIF schema validation (2.1.0 schema check in CI).
- Kernel backends get parity tests vs strace on the same synthetic workload, run in the VM harness,
  not in CI.
- Memory.md MUST be updated at the end of every working session (progress, decisions, open threads).

## 7. When stuck
- Kernel behavior unclear → reproduce in the local VM harness; if impossible, stop and ask the human.
- Gate fails → STOP. Log in Memory.md. Never "fix around" a kill gate. Gates exist to spend hours,
  not months.
