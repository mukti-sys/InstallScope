# InstallScope
> Attestations verify *who signed* it. InstallScope records *what it did*.

The flight recorder for package installs.

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
