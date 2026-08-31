# harness/parity/ — Phase 2 parity comparison

Phase 2's Done condition is "parity on synthetic workload in VM; ubuntu-latest Action runs full
record; agent stamps backend" (`Phases.md`:24). This directory holds the workload; the comparison
logic lives in `recorder/src/parity.rs` and is exposed as `installscope parity`.

## Why a synthetic workload rather than a real install

A real `npm install` is not reproducible enough to compare two recordings of. It resolves versions,
hits a CDN whose addresses rotate, and spawns a different number of processes depending on cache
state — so two runs differ for reasons unrelated to backend fidelity, and every difference would need
hand-triage before it meant anything.

Phase 1's `phase1-e2e.yml` already records a real install, which covers realism. This covers
*comparability*: the same operations twice, so any difference is attributable to how it was observed.

## Parity is not equality

The two backends observe through different mechanisms. Demanding identical output would either fail
permanently or force the comparison to be loosened until it proved nothing. So every difference is
classified, and only unexplained ones fail:

| Difference | Cause | Verdict |
|---|---|---|
| Relative vs resolved paths | strace's `-yy` gives the kernel's resolved path; the aya probes read the syscall argument | expected, **and only when the pair is present** |
| No `dns_query` from aya | decoding DNS payloads inside a BPF program is a stated non-goal | expected |
| No `fs_read` from aya | **scope decision**: `Phases.md`:23 scopes the aya backend to writes, connects, and spawns | expected, permanently |
| Byte counts differ | strace sees actual bytes, aya sees the requested count | not compared |
| An absolute-path write present on one side only | nothing explains it | **defect** |
| A `mkdir` reported as an `open` | wrong operation | **defect** |

The relative-path allowance is pairwise on purpose. Judging each fact alone would let a genuinely
missed write hide behind it: strace reports `/work/x/real.txt`, aya reports nothing, and a naive
classifier waves the absolute path through as "probably the resolved form of something." The
comparison therefore requires the matching relative counterpart to actually exist, with a component
boundary check so `/work/other.txt` does not pair with `her.txt`.

## `fs_read` is a permanent strace advantage, not pending work

Recording credential reads stays a strace-backend capability. `Phases.md`:23 scopes the aya probes to
"fs write, tcp connect, proc spawn", and the filter that selects interesting reads is a path list in
the strace parser — a place it can be edited without touching kernel code or re-verifying a probe on a
live kernel.

The consequence is worth stating rather than burying: an install that reads `~/.ssh/id_rsa` produces a
`high` finding (Architecture.md §4) under strace and **nothing** under aya. The two backends are not
interchangeable. Phase 3's report must not present an aya recording as equivalent coverage, and the
parity output keeps the asymmetry visible in its per-class counts rather than hiding it behind a pass.

## A PARTIAL input fails regardless of the diff

Two streams can agree perfectly and prove nothing if one stopped early. Same refusal as
`summarize_stream` rejecting a stream with no `session_end`: an incomplete recording is unusable, not
merely weaker.

## What the workload exercises

- **Every `WriteKind` the ABI defines** — create, append, truncate, mkdir, rename, symlink, hardlink,
  unlink, chmod — so a mis-mapped kind surfaces as a difference rather than passing silently.
- **A known byte volume** (256 KiB via `dd`) so write aggregation is comparable.
- **A relative-path write**, present deliberately: it is the documented divergence, and the harness
  must classify it rather than trip over it.
- **Loopback network only.** A public host would resolve to a rotating CDN address and produce a
  spurious difference every run.
- **A shell pipeline**, structurally like the download-piped-to-shell shape that matters most in real
  findings, without doing anything unsafe.
- **A forked child that writes.** The aya backend's pid filter is maintained in-kernel via
  `sched_process_fork`; if that propagation breaks, the child's writes vanish from the aya stream and
  the harness reports it as unexplained.

Deliberately absent: anything reaching the public internet, background processes that outlive the
script, and writes outside the work directory. The last one matters because this must be safe to run
on a developer's machine, not only on a disposable runner.

## Running it

```sh
# Record the same workload under each backend, then compare.
sudo installscope record --backend strace --out /tmp/p/strace -- \
  harness/parity/parity-workload.sh /tmp/p/work-strace
sudo installscope record --backend aya --out /tmp/p/aya -- \
  harness/parity/parity-workload.sh /tmp/p/work-aya

installscope parity --strace /tmp/p/strace/events.jsonl --aya /tmp/p/aya/events.jsonl
```

Note the two runs use *different* work directories. Sharing one would make the second recording
observe the first's leftovers, and cleaning between runs would itself be recorded.

`phase2-aya.yml` does this on `ubuntu-latest` and dumps every tracepoint format file first, so an
argument-offset mismatch in the probes is a five-minute fix rather than a guessing game.
