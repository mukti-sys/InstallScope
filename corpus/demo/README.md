# corpus/demo — synthetic fixtures for the rules engine and renderers

**Every file here is hand-written and synthetic. None is a recording of a real package.**

`Rules.md` §5 requires golden fixtures to be labelled as such, and the reason is specific to this
product: a fabricated recording presented as real would be exactly the failure InstallScope exists to
detect in other people's tools. Nothing in this directory may be cited as a receipt, quoted in a blog
post, or used as evidence about any npm package.

Real recordings live in `corpus/` proper, produced by `phase1-e2e.yml` and the Phase 5 backfill.

## What each fixture is for

| File | Score | Purpose |
|---|---|---|
| `clean.jsonl` | 0 | An ordinary install. The most important fixture in the set. |
| `high.jsonl` | 35 | Behaviour worth a look, nothing alarming. Exercises the middle of the range. |
| `critical.jsonl` | 100 (raw 110) | Two criticals plus supporting findings, and a raw sum above the cap. |
| `partial.jsonl` | 40 | A recording that stopped early. The score is real; the report must still say PARTIAL. |
| `aya-clean.jsonl` | 0 | A clean result from a backend with blind spots. |
| `diff-before.jsonl` | — | Version 1.4.2 of a fictional package, recorded on a GitHub runner. |
| `diff-after.jsonl` | — | Version 1.4.3 of the same package, recorded elsewhere, behaving worse. |

`clean.jsonl` earns its "most important" label: if an ordinary install scores above zero the product is
unusable regardless of how good its critical detection is (PRD.md:43). It deliberately includes the
things that *look* suspicious and are not — three port-0 resolver probes, an `.npmrc` read, hundreds of
writes into `node_modules` — because those are what a naive rule set fires on.

`aya-clean.jsonl` exists to pin the Option A decision from Phase 2: the aya backend cannot see
credential reads or DNS, so a zero score from it means something weaker than a zero from strace. The
renderers must say so rather than presenting the two as equivalent.

## The diff pair

`diff-before.jsonl` and `diff-after.jsonl` are the version-diff engine's golden fixture, and the two
recordings differ in **everything except the behavior**:

| | before | after |
|---|---|---|
| project directory | `/home/runner/work/repo-4f2a1c/project` | `/tmp/backfill-8b3d/project` |
| cache directory | `/home/runner/.npm` | `/tmp/backfill-8b3d/npm-cache` |
| home | `/home/runner` | `/tmp/backfill-8b3d/home` |
| pids | 7100–7101 | 9200–9203 |
| timestamps | July | August |
| resolver | `127.0.0.53` | `8.8.8.8` |
| registry IP | `104.16.2.34` | `104.16.9.12` |
| kernel | azure | gcp |
| `index.js` bytes written | 4096 | 5120 |

None of that may show up as a behavioral change. If any of it does, the version-diff is worthless — every
pair of recordings would differ and the moat (Architecture.md:90) would be noise. That is precisely what
the fixtures are for: they make "two recordings of the same thing on different machines reduce
identically" a checkable claim rather than an intention.

What genuinely changed in 1.4.3, and must be reported:

- resolves `metrics.SYNTHETIC-vendor.example`
- connects to port 8443
- attempts to read `~/.ssh/id_rsa` (fails with ENOENT — still evidence of intent)
- runs `sh` and `curl`, piping a download into a shell
- writes `/etc/cron.d/SYNTHETIC-vendor-sync`, outside every declared zone
- chmods a file inside `node_modules`

The shared behaviors — the registry lookup, the `node_modules` writes, the cache write, the `.npmrc`
read, the `/dev/null` write, the postinstall `node` spawn — must all report as unchanged.

## Regenerating expectations

The expected findings and scores are asserted in `core/tests/corpus.rs` rather than stored alongside
the fixtures. A stored expectation file would drift silently; a test fails loudly. The diff pair is
asserted in `report/tests/diff_corpus.rs` for the same reason.
