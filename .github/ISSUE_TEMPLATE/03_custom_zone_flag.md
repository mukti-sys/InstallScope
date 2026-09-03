---
name: "Feature: Add CLI flag for custom build zones (--zone-extra)"
about: "Allow users to specify custom expected directories"
title: "feat(cli): add --zone-extra flag to configure expected directories"
labels: ["good first issue", "enhancement", "cli"]
---

### Problem Description
InstallScope partitions filesystem mutations into expected zones (`project`, `cache`, `home`, `tmp`) and declared `extra` zones (`core/src/zones.rs`). When a repository uses a custom monorepo output directory (e.g. `/opt/build/cache` or `/workspace/dist`), writes there can be flagged as `outside_expected_dirs` unless declared in the zone configuration.

### Scope & Tasks
1. Add repeated CLI option `--zone-extra <PATH>` to `installscope record` and `installscope report` in `cli/src/main.rs`.
2. Pass declared extra zones into `Zones::new(..., extra: Vec<PathBuf>)`.
3. Add a CLI integration test verifying that writes within `--zone-extra` are scored as `Zone::Declared` rather than `Zone::Outside`.

### References
- Zones definition: `core/src/zones.rs`
- CLI argument parsing: `cli/src/main.rs`
