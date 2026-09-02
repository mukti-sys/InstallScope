# InstallScope
[![rust](https://github.com/mukti-sys/InstallScope/actions/workflows/rust.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/rust.yml)
[![G2 — strace receipts harness](https://github.com/mukti-sys/InstallScope/actions/workflows/g2-strace-harness.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/g2-strace-harness.yml)
[![Phase 2 — aya backend parity](https://github.com/mukti-sys/InstallScope/actions/workflows/phase2-aya.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/phase2-aya.yml)
> Attestations verify *who signed* it. InstallScope records *what it did*.

The flight recorder for package installs.

> 🚧 **Status:** Phase 4 in progress — recorder, rules engine, reports, snapshot registry and the
> GitHub Action are implemented; the README below is developer-facing until Phase 6 writes the public
> one.

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
