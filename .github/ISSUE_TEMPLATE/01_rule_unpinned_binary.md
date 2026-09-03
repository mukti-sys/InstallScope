---
name: "Community Rule: Flag remote binary download from unpinned URLs"
about: "Contribute a new detection rule to rules/catalog.yaml"
title: "rule: flag remote binary downloads from unpinned URLs"
labels: ["good first issue", "enhancement", "rules"]
---

### Problem Description
Currently, `rules/catalog.yaml` detects executable downloads when `curl` or `wget` is spawned or when common binary distribution hosts (`github.com/releases`, etc.) are resolved. However, an install script downloading an executable file (`.exe`, `.so`, `.node`, ELF) from an unknown, non-distribution domain is an acute anomaly that warrants a specific `High` severity finding.

### Scope & Tasks
1. Add a new rule definition in `rules/catalog.yaml` (`unpinned_binary_download`).
2. Implement the evaluation check in `core/src/rules.rs`.
3. Add a synthetic fixture in `corpus/demo/` verifying that the rule fires when expected.
4. Verify zero clippy warnings and add corresponding unit test in `core/tests/`.

### References
- Rule catalog: `rules/catalog.yaml`
- Evaluation logic: `core/src/rules.rs`
- PRD §7: Scoring discipline
