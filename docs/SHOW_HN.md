# Show HN: InstallScope – Syscall flight recorder for package installs in CI

**URL:** https://github.com/mukti-sys/InstallScope

**Title:** Show HN: InstallScope – Syscall flight recorder for package installs in CI

---

### Body text for Hacker News:

Hey HN,

We built InstallScope, an open-source flight recorder that runs during package installation (`npm install`, `pnpm install`) in CI and records the syscall-level ground truth of what install scripts actually do on disk and network.

When a pull request adds or updates a dependency, InstallScope posts a one-page forensic report directly to the PR: a 0–100 Surprise Index, max 3 actionable bullets, and links to full evidence artifacts (HTML dashboard, SARIF, and raw event streams).

### Why we built this

Existing supply chain tools largely fall into three buckets:
1. **Advisory databases (`npm audit`):** Match names and versions against published CVEs. Blind to unannounced or zero-day malicious code.
2. **Provenance attestations (Sigstore, npm provenance):** Prove *who built and signed* the package. But as recent ecosystem attacks have shown, an attacker with a compromised maintainer token can sign malicious code with valid provenance.
3. **Static AST scanners:** Guess intent by inspecting manifests and syntax trees without running the code.

Meanwhile, package install scripts (`postinstall`, `build.rs`) run with full user permissions. If an update quietely connects to an external IP, dumps credentials from `~/.npmrc`, or writes to `/etc/cron.d`, maintainers have no structured evidence before merging.

### What 840,069 syscalls taught us

Before releasing, we ran an automated backfill across 50 top npm packages, recording 250 complete installs across 200 consecutive version transitions on standard GitHub Actions runners.

Two counter-intuitive findings from the data:

1. **Ambient network calls and config reads happen on almost every install, but are static:** Every package in our dataset connected to external IPs (npm querying the registry) and read `~/.npmrc`. Crucially, across 200 version pairs, **0 packages introduced new external endpoints or credential reads.**
2. **What actually changed across versions:** Out of 200 version bumps, only 3 introduced new spawned processes (`bcrypt` introducing `node-gyp-build`, `sqlite3` invoking `prebuild-install`, and `protobufjs` invoking `sh`). All three were legitimate native addon builds.

This confirmed our design choice: the real signal isn't naive absolute alerting, but a **version-to-version behavioral delta**. InstallScope stores recordings in a content-addressed snapshot registry (`zstd` + SHA-256), allowing you to diff `v1.2.3` against `v1.2.4` to see if a minor patch suddenly introduced new outbound network calls or unexpected binaries.

### How it works under the hood

- **Strace Engine (v1.0 - Default):** Uses `strace -f -ff -yy -ttt` in userspace. Resolves file descriptors to absolute paths and network sockets to remote endpoints. On timeouts, it enforces multi-stage process group termination (`SIGTERM` → 2s grace → `SIGKILL -<pgid>`) so orphaned child processes cannot survive in the CI runner.
- **Aya eBPF Engine (v1.1 - Optional):** In-kernel tracepoint backend written in pure Rust (`aya`), hooking 10+ kernel tracepoints with zero overhead.
- **Security Boundary:** The GitHub Action uses two separate workflows: `record.yml` runs the install with a read-only token; `comment.yml` reads the uploaded artifact and posts the comment without ever checking out or executing untrusted PR code.
- **False-Positive Discipline:** Low findings (routine config reads) are excluded from the score sum to prevent alert fatigue. If an install path cannot be resolved to an absolute directory, it is caveated rather than guessed as an outside-zone write. If a recording is truncated, it prints a visible `[PARTIAL]` badge.

Written in Rust (556 unit tests, 0 compiler warnings under `-D warnings`). Dual-licensed under MIT and Apache-2.0.

Code: https://github.com/mukti-sys/InstallScope  
Blog post on the 840k syscall experiment: https://github.com/mukti-sys/InstallScope/blob/main/docs/blog/the-840k-syscall-experiment.md

Would love feedback on the rule catalog, trace parsing, and whether this fits into your PR review workflows.
