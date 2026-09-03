# PRD — InstallScope
**The flight recorder for package installs.**

## 1. Problem
A dependency is added. Nothing about what it *does* is recorded. `npm audit` knows only CVEs;
`--ignore-scripts` breaks builds; Socket checks registry metadata, not your machine. Meanwhile
install scripts run with full user privileges. When a package turns malicious — or just quietly
phones home — nobody has evidence, only vibes after the fact.

## 2. Product statement
When a PR adds a dependency, InstallScope records the **syscall-level ground truth** of what that
install actually does — file writes, network, spawned processes — and posts a **one-page forensic
report** to the PR. That's the whole product.

**Positioning sentence (use verbatim everywhere):**
> Attestations verify *who signed* it. InstallScope records *what it did*.

**Banned framing:** sandbox / protection / safe. See Rules.md §Banned language.

## 3. Target users
| User | Pain | Hook |
|---|---|---|
| OSS maintainer (primary v1) | Merges dependency PRs from strangers; owns the blast radius | Lockfile-diff GitHub Action, zero config |
| Platform/devops team | Needs evidence for supply-chain review, not another CVE feed | Snapshot registry, org corpus (paid) |
| Security engineer | Faces "what did that dependency touch?" post-incident with no data | Recorded evidence + version diffs |

**Not users in v1:** Windows/macOS teams (stated bluntly — see Scope.md), lawyers, non-devs.

## 4. Trigger (the adoption unlock)
GitHub Action fires **only on lockfile diff** that adds/changes dependencies. No habit change,
no wrapping commands, no daemon. Appears exactly at the moment of risk.

## 5. v1 Feature list (must-have)
1. **Repo recorder CLI**: `installscope record -- <install command>` — captures FS writes, sockets
   (connect/send DNS), process spawns into a JSONL event stream. Backends: `strace` (v1.0) and
   `aya eBPF` (v1.1, gated on Phase 0 gate G1).
2. **Behavior rules engine** — deterministic, no LLM. Findings include: network to non-registry
   domains during install; writes outside the project/cache/expected dirs; child process spawning;
   downloads of executables; env-variable harvesting reads.
3. **Report = one page**: a **Single Score (0–100 "Surprise Index")**, **max 3 bullets**, everything
   else in expandable evidence (+SARIF 2.1.0 and standalone HTML artifact).
4. **PR comment bot**: posts score + bullets, links evidence. Advisory by default; "fail build"
   is opt-in per rule. FP paranoia is the religion — see output discipline below.
5. **Snapshot registry v0**: content-addressed (sha256, zstd) recordings per package@version →
   enables the moat: **"This package's behavior changed between 1.2.3 and 1.2.4."**
6. **Demo dataset in-repo**: recordings shipped in the repo so first clone works with zero setup.

## 6. v2+ (explicitly NOT v1 — full boundary contract in Scope.md)
- Strict mode (bubblewrap + seccomp deny-by-default). v1 is **audit/observe-only, everything allowed**.
- macOS (Endpoint Security), Windows (ETW).
- Run-time smoke-profile recording.
- Yarn / Poetry / Cargo lockfiles.
- Hosted registry / org dashboards (the paid tier later, not the product).

## 7. Output discipline (score spec)
- Score = weighted finding sum, capped at 100: critical ×40, high ×15, medium ×5. (Low findings have weight 1 defined for ranking, but are excluded from the score sum as informational evidence to prevent routine installs reaching critical scores — false-positive discipline per §4).
- 3-bullet cap in PR comment. No walls of text. Evidence lives behind a link, not in the comment.
- **Incomplete recording = visible `PARTIAL` badge.** A recorder that dies silently produces false
  confidence — that is the single worst failure mode of this product.
- Deterministic rubric only in v1. No LLM anywhere (same discipline as DarkLint's no-LLM core).

## 8. Landscape (README table — name the neighbors before HN does)
| | CVE knowledge | Registry heuristics | **Runtime behavior evidence** |
|---|---|---|---|
| npm/pip audit | ✅ | ❌ | ❌ |
| Socket | partial | ✅ (verify current CLI state **before** HN — don't get fact-checked) | ❌ |
| Falco/Tracee | ❌ | ❌ | ✅ but **production runtime** — different lane, say so |
| firejail/bubblewrap | ❌ | ❌ | primitives, no report, no CI |
| **InstallScope** | ❌ by design | ❌ by design | ✅ **per-install, per-PR, forensic** |

## 9. Success metrics (this project owns the star gate)
- **≥300 GitHub stars / 30 days** post-Show HN.
- **≥10 org-tier signups / 60 days** for the eventual private-snapshot tier.
- G2 evidence: ≥10 documented behavioral surprises in top-200 npm.
- G3 evidence: ≥1 inbound ask from the receipts teaser.

## 10. Kill gates (run BEFORE product code — see Phases Phase 0)
- **G1** — aya example runs on a standard `ubuntu-latest` GitHub runner, records one event, uploads artifact. ~1 hour.
- **G2** — strace harness in local VM records top-200 npm installs → **≥10 surprises** or reposition.
- **G3** — 3 best receipts posted publicly → inbound demand, or launch as content-only.

*Fail G1 → try libbpf-rs; fail again → strace-only product (still viable, weaker demo). Fail G2 → the
"epidemic is boring" hypothesis is true; narrow the lane or stop. Fail G3 → ship anyway as portfolio
piece with lowered expectations, chosen consciously.*
