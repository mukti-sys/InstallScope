# InstallScope
[![G2 — strace receipts harness](https://github.com/mukti-sys/InstallScope/actions/workflows/g2-strace-harness.yml/badge.svg)](https://github.com/mukti-sys/InstallScope/actions/workflows/g2-strace-harness.yml)
> Attestations verify *who signed* it. InstallScope records *what it did*.

The flight recorder for package installs.

> 🚧 **Status:** Early development (Phase 0/1). Core architecture is being validated — README and full documentation will follow once the recorder pipeline is stable.

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

## Phase 0: Kill Gates

Phase 0 validates the core technical assumptions before product code:

1. **Gate G1 — eBPF Runner Probe**: Validates that an `aya` tracepoint eBPF probe loads, attaches, and captures events on standard `ubuntu-latest` GitHub runners.
2. **Gate G2 — `strace` Receipts Harness**: Runs candidate npm package installs inside clean ephemeral matrix environments under `strace -f -ff` and extracts structured syscall telemetry.

See `.github/workflows/` and `harness/` for test harness workflows.

---

## License

Dual-licensed under either:
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
