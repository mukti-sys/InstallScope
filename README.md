# InstallScope
[![rust](https://github.com/mukti-sys/InstallScope/actions/workflows/rust.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/rust.yml)
[![G2 — strace receipts harness](https://github.com/mukti-sys/InstallScope/actions/workflows/g2-strace-harness.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/g2-strace-harness.yml)
[![Phase 2 — aya backend parity](https://github.com/mukti-sys/InstallScope/actions/workflows/phase2-aya.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/phase2-aya.yml)
> Attestations verify *who signed* it. InstallScope records *what it did*.

The flight recorder for package installs.

> 🚧 **Status:** Preparing for Phase 6 (Public Launch) — recorder, rules engine, reports, snapshot
> registry, GitHub Action, and corpus backfill harness are implemented, audited, and hardened.

---

## What is InstallScope?

When a PR adds or updates a dependency, InstallScope records the **syscall-level ground truth** of what that install actually does — filesystem writes, network connections, and spawned processes — and posts a **one-page forensic report** to the PR.

## Landscape

| | CVE knowledge | Registry heuristics | Runtime behavior evidence |
|---|---|---|---|
| npm / pip audit | ✅ | ❌ | ❌ |
| Socket | partial | ✅ | ❌ |
| Falco / Tracee | ❌ | ❌ | ✅ (production runtime) |
| firejail / bubblewrap | ❌ | ❌ | primitives, no report/CI |
| **InstallScope** | ❌ by design | ❌ by design | ✅ **per-install, per-PR, forensic** |

---

## The CLI

```
installscope record -- npm install        # record an install into a JSONL event stream
installscope verify events.jsonl          # is the recording complete, or PARTIAL?
installscope report events.jsonl          # evaluate against the rule catalog → SARIF + HTML + comment
installscope lockfile-diff --before a --after b   # did this PR introduce code that will run?
installscope snapshot push events.jsonl --package p --version v
installscope snapshot verify              # re-check every stored snapshot against its content address
installscope diff <pkg> <v1> <v2>         # what changed behaviorally between two versions
installscope parity --strace a --aya b    # do the two backends agree about what happened?
```

Recording needs Linux. Everything else runs anywhere, so a recording made on a runner can be
evaluated, diffed and re-rendered on any machine.

## Repository layout

| Crate | What it holds |
|---|---|
| `core/` | schema v1 event model, zones, rule catalog, scoring, coverage |
| `recorder/` | the strace backend (v1.0) and the aya eBPF backend (v1.1), plus parity |
| `lockfile/` | npm and pnpm lockfile parsing and diffing — the trigger |
| `registry/` | content-addressed snapshot store and the behavioral version-diff engine |
| `report/` | SARIF 2.1.0, PR-comment Markdown, self-contained HTML, and the diff surfaces |
| `cli/` | the `installscope` binary |
| `action/` | two composite GitHub Actions: `record` (read-only) and `comment` (write) |
| `rules/` | the public YAML rule catalog |
| `corpus/demo/` | synthetic fixtures, labelled as such |

`action/README.md` explains why recording and commenting are two separate workflows: the recording job
executes untrusted install scripts, so it must never hold a token that can write to the repository.

### Backend architecture & CI execution
- **`strace` (v1.0)**: Primary engine for `installscope record` and GitHub Actions (`action/record`). Traces filesystem writes, credential reads, network connects, DNS queries, and spawned processes with zero root/eBPF privileges required.
- **`aya` eBPF (v1.1)**: Optional in-kernel backend verified against `strace` via the parity suite (`installscope parity`). Standard PR workflows run `strace` because hosted runners do not grant eBPF root privileges by default.
- **Process spawn parity**: `strace` and `aya` hook execution at slightly different boundaries (shebang script execution vs binary interpreter invocation), so cross-backend process spawn parity is classified as best-effort.
- **Unresolved paths**: Relative paths without a determinable parent directory are counted and displayed in reports, but deliberately not scored as outside-zone to avoid manufacturing false criticals.

---

## Phase 0: Kill Gates

Phase 0 validated the core technical assumptions before product code:

1. **Gate G1 — eBPF Runner Probe**: an `aya` tracepoint probe loads, attaches, and captures events on standard `ubuntu-latest` GitHub runners.
2. **Gate G2 — `strace` Receipts Harness**: candidate npm package installs run inside clean ephemeral matrix environments under `strace -f -ff`, and structured syscall telemetry is extracted.

Both passed. See `.github/workflows/` and `harness/`.

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
