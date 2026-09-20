# Changelog

All notable changes to InstallScope will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-04

Initial public release of InstallScope — the flight recorder for package installs.

### Added

#### Core & Architecture
- **Schema v1 Event Stream:** Structured JSONL telemetry for filesystem writes, reads, network connections, DNS query payloads, and process execution trees.
- **Rules Engine & Scoring:** Deterministic, non-LLM rule evaluation calculating a bounded 0–100 Surprise Index with strict false-positive discipline.
- **Coverage & Observability Tracking:** Comprehensive coverage tables identifying observed, partial, and unobserved syscall categories per backend.
- **Zero-Observation Safety:** Recordings with zero observed syscall events refuse unqualified clean bills of health.

#### Recorders
- **Strace Recorder (v1.0):** Zero-privilege Linux recording engine instrumenting `strace -f -ff -yy -ttt` with canonical path resolution and socket endpoint decoding.
- **Path and Descriptor Forms Both Traced:** `chmod`/`fchmod`, `chown`/`fchown`, and `truncate`/`ftruncate` are traced together. Tracing only the path forms left the top-severity "made a file executable outside the project" rule defeatable by opening the file first, which is one line of Node. A descriptor-based mutation resolves through the same fd table `write` uses; when the descriptor cannot be resolved to a file the event is dropped rather than emitted with a guessed path.
- **Process Group Containment:** Spawns traced commands in dedicated process groups (`process_group(0)`) and enforces multi-stage termination (`SIGTERM` → 2-second grace period → `SIGKILL -<pgid>`) on timeout to prevent zombie process survival.
- **Anti-Debugging Detection:** Traces `ptrace`, distinguishing the benign `PTRACE_TRACEME` handshake a tracee performs so `strace` can attach from an anti-analysis probe or an attempt to interfere with the tracer. A detected attempt forces the session to `PARTIAL` rather than being reported as a finding, because a process fighting the tracer means the recording cannot be trusted to be whole.
- **Aya eBPF Recorder (v1.1):** In-kernel tracepoint backend written in pure Rust — 22 tracepoint programs with in-kernel process-tree filtering — verified against the `strace` backend by an automated parity harness on a live kernel.

#### Known coverage gaps
Stated here rather than left for a reader to discover, because a recorder that implies more coverage than it has is the failure this project exists to detect in other tools.

- **`io_uring` is not traced.** A package that submits opens, writes, or connects through an io_uring ring issues none of the syscalls in the traced set, and the recording will report `complete` while having observed none of it. Tracing `io_uring_enter` was tried and removed (it fires continuously from the Node.js event loop, producing false evasion reports); ring-creation tracing is the intended fix and is not implemented.
- **Inbound sockets are not traced.** `bind`, `listen`, and `accept` produce no events, so a package that opens a listening port is invisible. Closing this needs a new event shape rather than another syscall name.
- **Encrypted DNS is indistinguishable from other traffic.** Questions are decoded from datagrams sent to port 53; DNS-over-HTTPS and DNS-over-TLS appear only as ordinary connections.
- **Byte volumes are a floor, not a measurement.** Volume moved by `sendfile`, `copy_file_range`, or a shared mapping is not counted.

Every one of these is reflected in the per-class coverage table each report carries, so a clean result names what it could not see.

#### Registry & Version-Diff
- **Content-Addressed Snapshot Store:** SHA-256 addressed event stream store compressed with `zstd`, featuring atomic unique temporary file writes to prevent concurrent writer collisions.
- **Behavioral Version-Diff Engine:** Compares consecutive package versions to pinpoint added or removed network endpoints, credential reads, outside-zone writes, and spawned processes.

#### Reporting & Actions
- **Multi-Format Reports:** Emits PR-comment Markdown (capped at 3 actionable bullets), a self-contained standalone HTML evidence artifact, and SARIF 2.1.0 for code scanning.
- **Signal Log Rendered From The Recording:** The HTML artifact's signal log is built by walking the event stream — one row per observation, with the observing pid, the syscall, the outcome, and the path origin the recorder actually determined. Where the schema cannot supply a value the field is absent rather than filled in: there is no raw trace line in the stream, no source location inside a package's JavaScript, and no stream digest available to the renderer, so none of the three is displayed.
- **User-Supplied Rule Catalogs:** `report --rules <path>` evaluates a recording against a catalog on disk instead of the embedded one, so a private registry host or an extra expected build directory does not require a rebuild.
- **Dual-Workflow GitHub Action:**
  - `action/record`: Runs untrusted installation commands with a read-only token on standard `ubuntu-latest` runners.
  - `action/comment`: Inspects uploaded evidence artifacts and posts sticky PR reports without executing untrusted PR code.
- **Advisory Default:** Comments provide diagnostic intelligence by default without failing builds; opt-in blocking configurable via `fail-above`.

#### Empirical Dataset & Verification
- **50-Package Backfill Corpus:** 250 recordings across 200 consecutive version pairs, 100% completion, 0 blocked comparisons. 840,069 behavior observations of which 195,780 are distinct. Every figure is computed from the stored recordings rather than from the plan, by `harness/corpus/summarize-corpus.mjs`; the run is [#33632942704](https://github.com/mukti-sys/InstallScope/actions/runs/33632942704) and `dataset.json` / `DATASET.md` in its `corpus` artifact are the primary source.
- **Rigorous Test Suite:** 581 unit and integration tests with zero compiler warnings under strict `-D warnings` deny lints. Counts per crate, and an explicit list of what a local run cannot cover, are in [TESTS.md](TESTS.md).
