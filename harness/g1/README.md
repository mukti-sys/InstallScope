# G1 — pricing the eBPF bet

**Gate question (Phases.md:12-14):** does an aya eBPF program load and record an event on a stock
`ubuntu-latest` GitHub runner? Budget ~1 hour. **Done = green run + uploaded artifact.**

Fallback order, pre-authorized in Scope.md:59 so a failure is not a design debate:
`aya` → `libbpf-rs` → strace-only product. A second failure drops eBPF from v1 entirely; the
strace backend (Architecture.md:35) ships regardless, so G1 failing is survivable by design.

## What the program does, and what it deliberately does not do

Attaches to the `syscalls:sys_enter_execve` tracepoint, emits one record per exec through a
`PerfEventArray`, and the loader prints/records them as JSONL. Then it execs `/bin/true` itself so
an event is **certain** to occur — a gate that could pass or fail on whether the runner happened
to be busy would measure nothing.

It is not a recorder. No path resolution, no filtering, no network or file events, no ring buffer
tuning, no CO-RE struct reads. Those are Phase 2 (Architecture.md:71). G1 answers exactly one
question: *can we load and receive an event here at all.*

## What a pass actually proves

Only that a tracepoint program loads and delivers events on this runner image, today. It does
**not** prove kprobes/fentry work, that BTF-dependent CO-RE reads work, that `bpf_probe_read` of
task structs works, or that the runner image will still allow this next month. Phase 2 must
re-verify per program type. Recording `uname -r` and the runner image version in the artifact
exists so a later regression is diagnosable rather than mysterious.

This is the gate's real limitation, and Phase 2 inherits it: `sys_enter_execve` was chosen
*because* it needs no struct access. Reading a file path or a socket address requires exactly the
capabilities this run left untested.

## Toolchain reality (verified by run #33297876067)

- The eBPF crate needs **nightly** plus `rust-src`, because `bpfel-unknown-none` has no prebuilt
  `core`: it is compiled with `-Z build-std=core`.
- `g1-ebpf/` is a **separate cargo workspace** from the loader. This is the standard aya layout —
  the two crates need different targets, panic strategies, and `no_std` settings, and a single
  workspace cannot express that cleanly.
- Loading requires `CAP_BPF`/`CAP_PERFMON` (Architecture.md:97), so the loader runs under `sudo`.
- Versions are pinned **exactly** to what actually built and loaded: `aya 0.13.1`,
  `aya-ebpf 0.1.1` (with `aya-ebpf-bindings 0.1.2`, `aya-ebpf-macros 0.1.2`, `aya-ebpf-cty 0.2.3`),
  on kernel `6.17.0-1022-azure` / `ubuntu24` runner image `20260823.283.1`. The earlier
  `TODO-verify` markers are resolved.
- `aya-ebpf 0.2.1` exists and is deliberately **not** adopted. The proven version is the one that
  loaded; upgrading is a Phase 2 decision that earns its own verification run rather than a
  drive-by bump (Rules.md §5: ask, don't guess, on kernel APIs).

## Observed runner facts worth carrying into Phase 2

From the passing run's `g1-result.json`:

| Fact | Value | Why it matters |
|---|---|---|
| BTF at `/sys/kernel/btf/vmlinux` | present, 6,841,206 bytes | CO-RE is possible in principle |
| `unprivileged_bpf_disabled` | `2` | unprivileged BPF is off; sudo is mandatory, not optional |
| `perf_event_paranoid` | `4` | most restrictive setting; perf buffers worked anyway under root |
| online CPUs | 4 | one perf buffer per CPU |
| events lost | 0 | the perf ring kept up with a trivial workload — says nothing about a real install |
| object size | 2,504 bytes | a tracepoint-only program; real probes will be larger |

## Layout

```
harness/g1/
├── Cargo.toml          # workspace: common + loader
├── g1-common/          # shared #[repr(C)] event struct (no_std)
├── g1-loader/          # userspace: load, attach, receive, write JSONL
└── g1-ebpf/            # separate workspace; nightly + build-std
```

## Run

Via the `G1 — aya eBPF runner probe` workflow (manual dispatch). Locally on Linux:

```sh
cd harness/g1/g1-ebpf && cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release
cd ../ && cargo build --release
sudo ./target/release/g1-loader --out g1-result.json --events g1-events.jsonl --timeout-ms 5000
```
