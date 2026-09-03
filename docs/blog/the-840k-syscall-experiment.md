# What Happens During `npm install`? We Recorded 840,069 Syscalls to Find Out

When a developer runs `npm install`, or a CI runner checks out a pull request, third-party packages are allowed to execute arbitrary code with the ambient permissions of the host process. `preinstall`, `install`, and `postinstall` hooks can write anywhere in your home directory, initiate TCP connections, read SSH keys, and spawn child interpreters.

The industry has built three layers of defense around this problem:

1. **Advisory databases (`npm audit`, `pip audit`):** Match declared package names and versions against CVEs that have already been discovered, reported, and cataloged.
2. **Provenance attestations (Sigstore, npm provenance):** Mathematically prove *which GitHub Actions workflow built and signed the tarball*.
3. **Static heuristic scanners (Socket, etc.):** Inspect ASTs, manifest fields, and known malicious patterns before the code runs.

Each of these answers an important question: *Has someone reported this? Who signed it? Does the source code look suspicious?*

None of them answer the basic runtime question: **What did the package actually do on disk and wire when it ran?**

To establish an empirical baseline before releasing [InstallScope](https://github.com/mukti-sys/InstallScope), we built an automated, content-addressed recording harness and ran it over 50 top npm packages across 200 consecutive version pairs.

Here is what 840,069 syscall observations taught us about real-world package installations.

---

## The Experiment Setup

We selected 50 widely-used packages spanning pure JavaScript utilities, CLI tools, network clients, and native binary addons (including `bcrypt`, `sqlite3`, `protobufjs`, `sharp`, `esbuild`, `puppeteer`, and `playwright`). For each package, we resolved the five most recent consecutive release versions.

Every recording ran in an ephemeral `ubuntu-latest` runner under strict containment:

- **Syscall Tracer:** Instrumented with `strace -f -ff -yy -ttt` capturing file descriptor mutations, network connections, DNS questions, and process execution trees.
- **Controlled Environment:** Fixed working directories, isolated home and temp zones, and structured logging.
- **Integrity Validation:** Every recording was re-parsed and validated by an independent verifier. If a tracer was interrupted, an event log truncated, or an unparseable binary buffer written, the session was marked `PARTIAL`.

Across 250 recordings, **250 completed cleanly (100% completion, 0 partials)**, generating a content-addressed dataset of 22.21 MB compressed with `zstd`.

---

## The Raw Telemetry

Across the corpus, the recorder observed **840,069 total syscall events**, of which **195,780 were distinct behavioral observations**:

| Observation Class | Total Observed Events |
|---|---|
| Filesystem Writes (`openat`, `creat`, `unlink`, `mkdir`) | 838,016 |
| External Network Connections (`connect`, `socket`) | 1,023 |
| Credential / Environment Reads (`.npmrc`, SSH paths) | 500 |
| Spawned Process Invocations (`execve`, `clone`) | 558 |
| DNS Question Payloads Decoded | 512 |

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
1. An in-kernel eBPF backend using pure Rust (`aya`), hooking 10+ kernel tracepoints (`sys_enter_execve`, `sys_enter_connect`, etc.).
2. A userspace recorder instrumenting `strace` with dedicated process group management.

While eBPF offers near-zero overhead for production runtime daemons, GitHub Actions hosted runners (`ubuntu-latest`) do not grant root eBPF capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`) to standard workflows.

Userspace `strace` with `-f -ff -yy -ttt` requires zero elevated kernel privileges, resolves file descriptors to absolute canonical paths in userspace, and decodes socket structures reliably. For an installation command running in CI for 15 seconds, the microseconds of tracer overhead are negligible, while the ability to run out-of-the-box on any standard runner is paramount.

---

## False-Positive Discipline

To ensure reports remain trusted, InstallScope enforces strict false-positive discipline:

- **The Bounded Score (0–100):** Only high-severity and critical events (writes outside declared project/cache zones, reverse shells, downloads piped directly to interpreters) contribute to the Surprise Index score.
- **Low Findings are Informational:** Routine reads of `.npmrc` or standard compiler toolchain invocations are ranked for inspection, but excluded from score sums so legitimate builds never trigger false alarms.
- **Unresolved Paths are Caveated:** If an install uses relative directory descriptors that cannot be resolved to an absolute path, the report explicitly states that those paths were not scored as outside-zone escapes, rather than guessing and generating false critical alerts.
- **Visible PARTIAL Badges:** If a recording is truncated, a tracer killed, or an event log corrupted, InstallScope prints a visible `[PARTIAL]` badge. Silence is never mistaken for a clean install.

---

## Conclusion & Next Steps

Attestations verify who signed an artifact. Static analysis inspects what an author claims their code does. But runtime syscalls represent the immutable ground truth of what actually executed.

InstallScope brings flight recording to package installs: lightweight, deterministic, and built directly for the pull request review boundary.

- **GitHub Repository:** [mukti-sys/InstallScope](https://github.com/mukti-sys/InstallScope)
- **Rule Catalog:** [rules/catalog.yaml](https://github.com/mukti-sys/InstallScope/blob/main/rules/catalog.yaml)
- **Dataset & Verification:** [TESTS.md](https://github.com/mukti-sys/InstallScope/blob/main/TESTS.md)
