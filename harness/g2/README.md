# G2 — strace receipts harness

**Gate question (Phases.md:6-11):** do real npm installs do surprising things? Target: **≥10
documented behavioral surprises**, else the "postinstall epidemic is boring" hypothesis wins and
coding stops (Scope.md:60).

## Isolation model

One `ubuntu-latest` matrix job per package. Each job is a fresh ephemeral VM: own kernel, own
filesystem, empty npm cache. Inside the job the install is further isolated with a private
`HOME`, a private `--cache`, and a scratch project dir, so nothing from the runner image's
preinstalled npm state leaks into the recording.

Phases.md:7 says "fresh VM per package". This is that property, obtained on runners because the
dev machine is win32 with no WSL. See `../README.md` for why that is a venue change, not a scope
change.

## Files

| File | Role |
|---|---|
| `packages.txt` | Candidate list, one spec per line. **No behavioral claims attached.** |
| `record-package.sh` | Installs one package under `strace -f -ff`, writes `session.json` |
| `parse-trace.mjs` | strace output → `events.jsonl` (Architecture.md §3 schema, see deviations) |
| `classify.mjs` | events → `findings.json` using Architecture.md §4 severities |
| `aggregate.mjs` | all findings → `g2-summary.json` + `SUMMARY.md` |
| `rank-packages.mjs` | Records real weekly download counts so popularity claims are verifiable |
| `test-parse.mjs` | Runs parser+classifier over `fixtures/synthetic/`, asserts expected output |
| `fixtures/synthetic/` | **Synthetic, hand-written trace.** Not a recording. Never cite as a receipt. |

## Traced syscalls, and what is deliberately not traced

Traced: `openat open creat truncate rename renameat renameat2 unlink unlinkat mkdir mkdirat rmdir
chmod fchmodat chown fchownat link linkat symlink symlinkat connect sendto sendmsg execve execveat`.

Not traced, on purpose:

- `write`/`pwrite64` — an `openat` carrying `O_WRONLY|O_CREAT|O_TRUNC|O_APPEND|O_RDWR` already
  proves write intent, and npm's write volume would dominate the trace. Consequence: **byte
  counts are not available**, so a finding like Design.md:35's "wrote ~13 MB outside project dir"
  cannot be produced by this harness. Phase 1's recorder must re-add write accounting.
- `clone`/`fork` — `execve` is the interesting edge of a spawn; process-tree reconstruction is a
  Phase 1 concern.

## Schema deviations from Architecture.md §3 (harness-only)

These exist because the gate needs them; Phase 1 decides whether any of them enter schema v1.

1. `ts_ns` is **nanoseconds since session start**, not epoch nanoseconds. Epoch ns exceeds
   JSON's safe integer range, and the example events in Architecture.md:47-51 use small values.
   Absolute wall-clock start is recorded once in `session.json`.
2. New op **`dns_query`** carrying `qname`, extracted best-effort from UDP/53 `sendto` payloads.
   Rationale: strace cannot attribute a TCP connect to a hostname, so without this every network
   finding would read as a bare IP address and be useless as a receipt. Best-effort means
   truncated or compressed payloads yield no event, never a guessed name.
3. Events carry `pid` and `syscall` for evidence traceability.

## Severity table

Taken from Architecture.md §4 and implemented as constants in `classify.mjs`. This is **not** the
public YAML rule catalog — that is Phase 3 work (Architecture.md:63). Deliberately kept as
throwaway JS so it is cheap to abandon.

## Verdict is human, not automatic

`aggregate.mjs` counts **candidate** surprises. A candidate becomes a receipt only when a human
reads the evidence and confirms the behavior is genuinely surprising. The script never prints
"G2 PASS"; that verdict is a human sign-off recorded in Memory.md (Rules.md:51-52).

## Local run

```sh
harness/g2/record-package.sh --package lodash --outdir /tmp/g2/lodash --timeout 300
node harness/g2/parse-trace.mjs --indir /tmp/g2/lodash --out /tmp/g2/lodash/events.jsonl
node harness/g2/classify.mjs --indir /tmp/g2/lodash --out /tmp/g2/lodash/findings.json
```

Linux only. The parser, classifier, and aggregator are pure Node and run anywhere — that is what
`test-parse.mjs` exercises.
