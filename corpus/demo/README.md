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

`clean.jsonl` earns its "most important" label: if an ordinary install scores above zero the product is
unusable regardless of how good its critical detection is (PRD.md:43). It deliberately includes the
things that *look* suspicious and are not — three port-0 resolver probes, an `.npmrc` read, hundreds of
writes into `node_modules` — because those are what a naive rule set fires on.

`aya-clean.jsonl` exists to pin the Option A decision from Phase 2: the aya backend cannot see
credential reads or DNS, so a zero score from it means something weaker than a zero from strace. The
renderers must say so rather than presenting the two as equivalent.

## Regenerating expectations

The expected findings and scores are asserted in `core/tests/corpus.rs` rather than stored alongside
the fixtures. A stored expectation file would drift silently; a test fails loudly.
