# Changelog

All notable changes to InstallScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-03

Initial public release of InstallScope — the flight recorder for package installs.

### Added

#### Core & Architecture
- **Schema v1 Event Stream:** Structured JSONL telemetry for filesystem writes, reads, network connections, DNS query payloads, and process execution trees.
- **Rules Engine & Scoring:** Deterministic, non-LLM rule evaluation calculating a bounded 0–100 Surprise Index with strict false-positive discipline.
- **Coverage & Observability Tracking:** Comprehensive coverage tables identifying observed, partial, and unobserved syscall categories per backend.
- **Zero-Observation Safety:** Recordings with zero observed syscall events refuse unqualified clean bills of health.

#### Recorders
- **Strace Recorder (v1.0):** Zero-privilege Linux recording engine instrumenting `strace -f -ff -yy -ttt` with canonical path resolution and socket endpoint decoding.
- **Process Group Containment:** Spawns traced commands in dedicated process groups (`process_group(0)`) and enforces multi-stage termination (`SIGTERM` → 2-second grace period → `SIGKILL -<pgid>`) on timeout to prevent zombie process survival.
- **Anti-Debugging & Evasion Detection:** Intercepts `ptrace` and `io_uring` evasion syscalls, distinguishing benign tracer handshakes from anti-analysis probes and forcing incomplete sessions to `PARTIAL`.
- **Aya eBPF Recorder (v1.1):** In-kernel tracepoint backend written in pure Rust, validated against `strace` via automated parity test harnesses.

#### Registry & Version-Diff
- **Content-Addressed Snapshot Store:** SHA-256 addressed event stream store compressed with `zstd`, featuring atomic unique temporary file writes to prevent concurrent writer collisions.
- **Behavioral Version-Diff Engine:** Compares consecutive package versions to pinpoint added or removed network endpoints, credential reads, outside-zone writes, and spawned processes.

#### Reporting & Actions
- **Multi-Format Reports:** Emits PR-comment Markdown (capped at 3 actionable bullets), self-contained standalone HTML evidence dashboards, and SARIF 2.1.0 code scanning artifacts.
- **Dual-Workflow GitHub Action:**
  - `action/record`: Runs untrusted installation commands with a read-only token on standard `ubuntu-latest` runners.
  - `action/comment`: Inspects uploaded evidence artifacts and posts sticky PR reports without executing untrusted PR code.
- **Advisory Default:** Comments provide diagnostic intelligence by default without failing builds; opt-in blocking configurable via `fail-above`.

#### Empirical Dataset & Verification
- **50-Package Backfill Corpus:** 250 complete installations across 200 consecutive version pairs demonstrating 100% completion and zero blocked comparisons.
- **Rigorous Test Suite:** 556 unit and integration tests with zero compiler warnings under strict `-D warnings` deny lints.
