---
name: "Feature: Add support for Yarn Berry (v2+) yarn.lock"
about: "Extend lockfile/ to detect changes in Yarn Berry lockfiles"
title: "feat(lockfile): support Yarn Berry (v2+) yarn.lock"
labels: ["good first issue", "enhancement", "lockfile"]
---

### Problem Description
InstallScope currently parses `package-lock.json` (v1, v2, v3) and `pnpm-lock.yaml` (v5, v6, v9) to determine whether a pull request introduced or modified packages with install scripts (`lockfile/src/lib.rs`). Yarn Berry (`yarn.lock` v2+) uses a YAML-compatible format that is not yet supported.

### Scope & Tasks
1. Extend `lockfile/` with a Yarn parser that extracts package descriptors and detects install scripts (`postinstall`, `build`).
2. Add a `LockfileFormat::YarnBerry` variant in `lockfile/src/types.rs`.
3. Add unit test fixtures covering additions and version updates in `yarn.lock`.
4. Update `action/record/action.yml` trigger paths to include `**/yarn.lock`.

### References
- Lockfile parser: `lockfile/src/lib.rs`
- Type definitions: `lockfile/src/types.rs`
