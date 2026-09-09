# What Happens During `npm install`? We Recorded 840,069 Syscalls to Find Out

When a developer runs `npm install`, or a CI runner checks out a pull request, third-party packages are allowed to execute arbitrary code with the ambient permissions of the host process. `preinstall`, `install`, and `postinstall` hooks can write anywhere in your home directory, initiate TCP connections, read SSH keys, and spawn child interpreters.

The industry has built three layers of defense around this problem:

1. **Advisory databases (`npm audit`, `pip audit`):** Match declared package names and versions against CVEs that have already been discovered, reported, and cataloged.
2. **Provenance attestations (Sigstore, npm provenance):** Mathematically prove *which GitHub Actions workflow built and signed the tarball*.
3. **Static heuristic scanners (Socket, etc.):** Inspect ASTs, manifest fields, and known malicious patterns before the code runs.

Each of these answers an important question: *Has someone reported this? Who signed it? Does the source code look suspicious?*

None of them answer the basic runtime question: **What did the package actually do on disk and wire when it ran?**

To establish an empirical baseline before releasing [InstallScope](https://github.com/mukti-sys/InstallScope), we built an automated, content-addressed recording harness and ran it over 50 widely-used npm packages across 200 consecutive version pairs.

Here is what 840,069 behavior observations taught us about real-world package installations.

---

## The Experiment Setup

We selected 50 widely-used packages spanning pure JavaScript utilities, CLI tools, network clients, and native binary addons (including `bcrypt`, `sqlite3`, `protobufjs`, `sharp`, `esbuild`, `puppeteer`, and `playwright`). For each package, we resolved the five most recent consecutive release versions.

The package list is `harness/g2/packages.txt`, chosen by hand for coverage of install-time behaviors rather than by download rank. Nothing in the pipeline establishes a ranking, so this is not a "top 50 by downloads" dataset and the harness refuses to describe it as one.

Every recording ran in an ephemeral `ubuntu-latest` runner under controlled conditions:

- **Syscall Tracer:** `strace -f -ff -yy -ttt`, capturing filesystem mutations, network connections, DNS questions, and process execution trees.
- **Controlled Environment:** A fresh project, cache, home, and temp directory per recording, so one package's install cannot show up as another's behavior.
- **Integrity Validation:** Every recording was re-parsed by an independent verifier. An interrupted tracer, a truncated event log, or an unparseable buffer marks the session `PARTIAL`, and a `PARTIAL` recording is refused by the snapshot store rather than diffed.

Across 250 recordings, **250 completed cleanly (100% completion, 0 partials)**, producing a content-addressed dataset of 22.21 MB compressed with `zstd`.

One caveat on that completion rate: it was measured on a list of well-behaved, widely-used packages. It does not predict the rate on a list chosen to include awkward ones.

---

## The Raw Telemetry

Across the corpus, the recorder observed **840,069 behavior observations**, of which **195,780 were distinct**:

| Observation Class | Observations |
|---|---|
| Filesystem (`openat`, `creat`, `mkdir`, `unlink`, `rename`, …) | 837,988 |
| External network connections (`connect`) | 1,023 |
| Spawned process invocations (`execve`) | 558 |
| Credential / environment reads (`.npmrc`, SSH paths) | 500 |
| **Total** | **840,069** |

Two things about those numbers are worth stating plainly, because a table like this invites being quoted without them.

**Observations are not distinct behaviors.** 840,069 counts every behavior in every recording; 195,780 counts how many *different* ones exist. The gap is almost entirely `node_modules` and cache writes that every install performs. The second figure is the honest one for a claim about a dataset's size, and it is the one the harness prints first.

**Filesystem dominates by three orders of magnitude.** 99.8% of the observations are writes. Any conclusion drawn from the network, process, or credential rows rests on hundreds of events, not hundreds of thousands, and should be read with that in mind.

---

## Finding #1: Network & Credential Reads are Constant — But Static

Security tooling that alerts whenever a package makes an outbound network connection or reads a configuration file suffers from crippling false-positive rates.

In our dataset, **every single package installation initiated external network connections (1,023 total) and read configuration files in the user profile (500 total).**

Why? Because `npm` itself connects to `registry.npmjs.org` to check package metadata and tarball checksums, and reads the user's `~/.npmrc` to determine registry authentication scopes.

However, when we compared consecutive releases of the same package ($v_1 \to v_2$), we observed a striking result:

| Behavior Class Changed Across 200 Version Pairs | Diffs Detected |
|---|---|
| New / Changed External Network Hosts | **0** |
| New / Changed Credential Reads | **0** |
| Writes Outside Expected Project/Cache Directories | **0** |
| New / Changed Spawned Processes | **3** |
| Filesystem-Only Structural Changes | **197** |

**Zero packages introduced new network endpoints or new credential read paths between releases.**

This means that while ambient network traffic and config reads are ubiquitous during installation, **unexpected changes to that baseline are extremely rare.** An install that phones home to an unpinned IP address or reads `~/.ssh/id_rsa` is not normal background noise; it is an acute, measurable anomaly.

---

## Finding #2: What Actually Changes Across Versions

Out of 200 consecutive version pairs, exactly **3 packages** introduced newly spawned processes:

1. **`bcrypt@6.0.0` vs `5.1.1`:** Started spawning `/bin/sh -c node-gyp-build` as part of its native compilation build pipeline.
2. **`protobufjs@7.6.6` vs `8.8.0`:** Transitioned build steps to invoke `/bin/sh`.
3. **`sqlite3@5.1.7` vs `5.1.6`:** Began executing `prebuild-install` to fetch precompiled C++ binaries before falling back to local `node-gyp` builds.

All three cases represented legitimate build toolchain evolutions in native addon packages. None were malicious, and all three were cleanly surfaced and categorized by the diff engine.

The remaining 197 version pairs produced purely internal filesystem layout changes inside `node_modules`.

---

## Finding #3: The Moat is the Behavioral Diff

The primary failure mode of security scanners in CI is **alert fatigue**. If a tool posts a multi-page comment warning that a native package invoked `gcc` or contacted a CDN, maintainers quickly ignore the output or disable the check entirely.

The empirical data proves that the most actionable signal is not an absolute score, but a **version-to-version behavioral delta**:

> *"Package `foo` updated from `1.4.1` to `1.4.2`. Filesystem writes stayed within `node_modules`. No new network endpoints contacted. No new processes spawned."*

Versus:

> *"Package `foo` updated from `1.4.1` to `1.4.2`. **New behavior detected:** spawned `curl` and initiated outbound TCP connection to `198.51.100.42:4444`."*

By storing verified execution traces in a content-addressed snapshot registry, InstallScope allows maintainers to evaluate pull requests against established historical baselines.

---

## Architecture: Why `strace` for CI?

When building InstallScope, we designed two distinct backends:
1. An in-kernel eBPF backend using pure Rust (`aya`) — 22 tracepoint programs (`sys_enter_execve`, `sys_enter_connect`, and the write/mutation family), filtered to the recorded process tree in-kernel.
2. A userspace recorder instrumenting `strace` with dedicated process group management.

eBPF avoids the per-syscall ptrace stop, which is the reason to want it. But loading a BPF program needs `CAP_BPF`/`CAP_PERFMON`, which means root — and while a GitHub-hosted `ubuntu-latest` runner does grant passwordless sudo, an action that requires it is an action many repositories will not adopt.

Userspace `strace` with `-f -ff -yy -ttt` needs nothing beyond `ptrace`, gets the kernel's own resolved paths from `-yy` rather than reconstructing them, and decodes socket structures reliably. For an install running for fifteen seconds in CI, tracer overhead is not the binding constraint; working out of the box on any runner is. So `strace` is the default and the permanent fallback, and the eBPF backend is optional.

We have not benchmarked either backend against an untraced install. The overhead difference between them is a well-understood property of the two mechanisms, not something this corpus measured, and it is not stated as a number anywhere in the project.

**The two backends do not have equal coverage**, which matters more than overhead. The eBPF probes are scoped to filesystem writes, network connects, and process spawns; they record no credential reads and no DNS queries at all. A zero score from an eBPF recording is therefore a weaker claim than a zero from `strace`, and every report names the backend that produced it alongside a per-class coverage table. Conflating the two would be exactly the false confidence this project exists to avoid.

---

## What This Recorder Cannot See

A tool that implies more coverage than it has is the failure mode we built this to detect in others, so the gaps are documented rather than left to be discovered:

- **`io_uring` is not traced.** A package that submits opens, writes, or connects through an io_uring ring issues none of the syscalls in the traced set. The recording will report `complete` having observed none of it. Nothing in the corpus above used io_uring, which is why the dataset is unaffected — but that is a fact about the packages sampled, not a property of the recorder.
- **Inbound sockets are not traced.** A package that binds and listens produces no event.
- **Encrypted resolution is indistinguishable from other traffic.** DNS questions are decoded from datagrams sent to port 53; DNS-over-HTTPS and DNS-over-TLS appear only as ordinary connections.
- **Byte volumes are a floor.** `sendfile`, `copy_file_range`, and writes through a shared mapping move bytes without a traced `write`, so a total understates rather than measures.

One gap that used to be on this list is closed: `fchmod`, `fchown`, and `ftruncate` are traced alongside their path-based forms, so making a file executable through an open descriptor is no longer invisible. It was worth closing precisely because it was cheap to exploit — `fs.openSync` then `fs.fchmodSync` is two lines.

Each of these appears in the per-class coverage table on every report, so a clean result states what it could not check.

---

## False-Positive Discipline

To ensure reports remain trusted, InstallScope enforces strict false-positive discipline:

- **The Bounded Score (0–100):** Critical, high, and medium findings contribute to the Surprise Index; the sum is capped at 100 and the uncapped raw value is retained so the flattening stays visible.
- **Low Findings are Informational:** Routine reads of `.npmrc` and standard compiler toolchain invocations are reported and ranked, but excluded from the score sum, so an install that merely does a lot of ordinary things cannot reach an alarming number.
- **Unresolved Paths are Caveated:** If an install uses relative directory descriptors the recorder cannot resolve to an absolute path, the report counts them and states they were not checked against the expected directories — rather than guessing and manufacturing a critical finding.
- **Visible PARTIAL Badges:** If a recording is truncated, a tracer killed, or an event log corrupted, the report leads with a `[PARTIAL]` badge and the recorder's own reason for it. Silence is never rendered as a clean install.
- **The Score is Not a Baseline Comparison.** It is a weighted sum of the rules that fired on one recording, which makes it a triage signal rather than a measurement. The version-to-version diff described above is the baseline-relative half of the product, and it is a separate output.

---

## Conclusion & Next Steps

Attestations verify who signed an artifact. Static analysis inspects what an author claims their code does. Recorded syscalls are evidence of what a specific install actually did on a specific machine — bounded by what the recorder was watching, which is why every report says what it could not see.

InstallScope brings flight recording to package installs: deterministic, advisory by default, and built for the pull request review boundary.

- **GitHub Repository:** [mukti-sys/InstallScope](https://github.com/mukti-sys/InstallScope)
- **Rule Catalog:** [rules/catalog.yaml](https://github.com/mukti-sys/InstallScope/blob/main/rules/catalog.yaml)
- **Test Log & Coverage Boundaries:** [TESTS.md](https://github.com/mukti-sys/InstallScope/blob/main/TESTS.md)
- **Dataset:** run [#33632942704](https://github.com/mukti-sys/InstallScope/actions/runs/33632942704) — `dataset.json` and `DATASET.md` in its `corpus` artifact are the source for every figure quoted here.
