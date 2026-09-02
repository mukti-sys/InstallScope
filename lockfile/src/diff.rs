//! Comparing two lockfiles: what a pull request actually changed.
//!
//! This is the trigger PRD.md:30 calls the adoption unlock. It answers one question — *which packages
//! will now be installed that were not being installed before* — and everything the Action records
//! follows from the answer.
//!
//! # Why a changed integrity hash is its own category
//!
//! Same name, same version, different tarball hash. On a healthy registry this does not happen:
//! npm forbids republishing a version. So it means one of a small number of things, and none of them
//! are routine — a different registry, a mirror that is out of sync, a lockfile edited by hand, or the
//! case that matters. It is reported separately rather than folded into "changed", because
//! `lodash@4.17.21 -> lodash@4.17.21` looks like a no-op in any list that only shows versions.
//!
//! # Why removals are recorded but never trigger a recording
//!
//! A removed dependency cannot run code during the install being reviewed. It appears in the report
//! because a reviewer reading a diff wants the whole picture, and it is excluded from
//! [`LockfileDiff::should_record`] because recording it would spend runner time proving something
//! about code that is no longer there.
//!
//! # Why a version *downgrade* is not treated differently from an upgrade
//!
//! Tempting, and wrong for this product's purpose. Both replace the code that runs at install time,
//! and the recorder has no opinion about which direction is more suspicious. Reporting a downgrade as
//! more alarming would be a heuristic dressed as evidence — the rules engine is deterministic
//! (`Rules.md` §5) and this module holds the same line. The direction is *shown*, because a reviewer
//! can use it; it does not change what gets recorded.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Groups, Identity, Lockfile, Package, Source};

/// What happened to one package between two lockfiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A package that was not installed before, at a version that was not installed before.
    Added {
        /// The package as the new lockfile describes it.
        package: Package,
    },
    /// A package that is no longer installed at this version.
    Removed {
        /// The package as the old lockfile described it.
        package: Package,
    },
    /// The same package name, resolved to a different version.
    ///
    /// Reported as a pair rather than as an add plus a remove, so a report can say "lodash 4.17.20 to
    /// 4.17.21" instead of listing two unrelated-looking lines.
    VersionChanged {
        /// Package name, identical on both sides.
        name: String,
        /// The old entry.
        before: Package,
        /// The new entry.
        after: Package,
    },
    /// Same name, same version, different bytes.
    ///
    /// See the module docs. This is the case a version-only diff cannot see.
    IntegrityChanged {
        /// Package name.
        name: String,
        /// Version, identical on both sides.
        version: String,
        /// The old integrity string, when there was one.
        before: Option<String>,
        /// The new integrity string, when there is one.
        after: Option<String>,
    },
    /// Same name and version, but fetched from somewhere else.
    ///
    /// A registry dependency replaced by a git dependency or a tarball URL, or the reverse. The code
    /// that runs is no longer coming from the same place, which is a change worth recording even
    /// though the version did not move.
    SourceChanged {
        /// Package name.
        name: String,
        /// Version, identical on both sides.
        version: String,
        /// Where it used to come from.
        before: Source,
        /// Where it comes from now.
        after: Source,
    },
    /// Same name and version, moved between dependency groups.
    ///
    /// The weakest category: nothing about the code changed. Reported because a dev dependency
    /// promoted to production now installs in more places, which is a real change in exposure.
    GroupsChanged {
        /// Package name.
        name: String,
        /// Version.
        version: String,
        /// Old groups.
        before: Groups,
        /// New groups.
        after: Groups,
    },
}

impl Change {
    /// The package name this change concerns.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Added { package } | Self::Removed { package } => &package.name,
            Self::VersionChanged { name, .. }
            | Self::IntegrityChanged { name, .. }
            | Self::SourceChanged { name, .. }
            | Self::GroupsChanged { name, .. } => name,
        }
    }

    /// True when this change introduces code that will run during the next install.
    ///
    /// The question that decides whether a recording is worth a runner's time. A removal and a group
    /// move introduce nothing; everything else does.
    #[must_use]
    pub const fn introduces_code(&self) -> bool {
        match self {
            Self::Added { .. }
            | Self::VersionChanged { .. }
            | Self::IntegrityChanged { .. }
            | Self::SourceChanged { .. } => true,
            Self::Removed { .. } | Self::GroupsChanged { .. } => false,
        }
    }

    /// The identity to record, when there is one.
    ///
    /// `None` for a removal: there is nothing to install.
    #[must_use]
    pub fn recordable(&self) -> Option<Identity> {
        match self {
            Self::Added { package } => Some(package.identity()),
            Self::VersionChanged { after, .. } => Some(after.identity()),
            Self::IntegrityChanged { name, version, .. }
            | Self::SourceChanged { name, version, .. } => Some(Identity {
                name: name.clone(),
                version: version.clone(),
            }),
            Self::Removed { .. } | Self::GroupsChanged { .. } => None,
        }
    }

    /// A short label for a report line.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Added { package } => format!("added {}", package.label()),
            Self::Removed { package } => format!("removed {}", package.label()),
            Self::VersionChanged {
                name,
                before,
                after,
            } => format!("{name} {} to {}", before.version, after.version),
            Self::IntegrityChanged { name, version, .. } => {
                format!("{name}@{version} same version, different tarball hash")
            }
            Self::SourceChanged {
                name,
                version,
                before,
                after,
            } => format!(
                "{name}@{version} now comes from {} instead of {}",
                after.kind(),
                before.kind()
            ),
            Self::GroupsChanged {
                name,
                version,
                before,
                after,
            } => format!("{name}@{version} moved from {before} to {after}"),
        }
    }
}

/// The result of comparing two lockfiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileDiff {
    /// Every change, ordered: code-introducing changes first, then by package name.
    pub changes: Vec<Change>,
    /// True when the two files came from different package managers.
    ///
    /// Not an error. A repository migrating from npm to pnpm produces exactly this, and the honest
    /// reading is that every dependency is being reinstalled by a different tool. Surfaced so a report
    /// can say so rather than presenting a hundred changes as if a single PR added them.
    pub ecosystem_changed: bool,
}

impl LockfileDiff {
    /// True when there is anything at all to report.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Changes that introduce code that will run.
    #[must_use]
    pub fn code_introducing(&self) -> Vec<&Change> {
        self.changes
            .iter()
            .filter(|change| change.introduces_code())
            .collect()
    }

    /// True when this diff justifies spending a runner on a recording.
    ///
    /// A lockfile PR that only removes dependencies or shuffles groups gets no recording, because
    /// there is no new code to observe. PRD.md:31 wants the Action to appear "exactly at the moment of
    /// risk", and this is where that judgement lives.
    #[must_use]
    pub fn should_record(&self) -> bool {
        self.changes.iter().any(Change::introduces_code)
    }

    /// The packages a recording should be attributed to, deduplicated and ordered.
    #[must_use]
    pub fn recordable(&self) -> Vec<Identity> {
        let mut seen: BTreeSet<Identity> = BTreeSet::new();
        for change in &self.changes {
            if let Some(identity) = change.recordable() {
                seen.insert(identity);
            }
        }
        seen.into_iter().collect()
    }
}

/// Compares two lockfiles.
///
/// Only external packages are compared: a workspace member is this repository's own code, and
/// reporting every workspace package as a new third-party dependency on the PR that adds one would
/// make the tool cry wolf.
#[must_use]
pub fn diff(before: &Lockfile, after: &Lockfile) -> LockfileDiff {
    let old_entries = index(before);
    let new_entries = index(after);

    let mut changes: Vec<Change> = Vec::new();

    // Same identity on both sides: look for a change the version alone does not show.
    for (identity, new_package) in &new_entries {
        let Some(old_package) = old_entries.get(identity) else {
            continue;
        };
        changes.extend(compare_same_identity(identity, old_package, new_package));
    }

    // Identities on one side only. Grouped by name so a version bump reads as one change rather than
    // an unrelated-looking add and remove.
    let added: Vec<&Package> = new_entries
        .iter()
        .filter(|(identity, _)| !old_entries.contains_key(*identity))
        .map(|(_, package)| *package)
        .collect();
    let removed: Vec<&Package> = old_entries
        .iter()
        .filter(|(identity, _)| !new_entries.contains_key(*identity))
        .map(|(_, package)| *package)
        .collect();

    changes.extend(pair_by_name(&added, &removed));

    // Code-introducing changes first: a reviewer's attention is finite and belongs on the code that
    // will actually run. Then by name, then by the rendered summary, so the order is total and two
    // runs over the same pair of files produce byte-identical output.
    changes.sort_by(|a, b| {
        b.introduces_code()
            .cmp(&a.introduces_code())
            .then_with(|| a.name().cmp(b.name()))
            .then_with(|| a.summary().cmp(&b.summary()))
    });

    LockfileDiff {
        changes,
        ecosystem_changed: before.ecosystem != after.ecosystem,
    }
}

/// Indexes a lockfile's external packages by identity.
///
/// A lockfile can list the same identity at several keys — `ms@2.1.2` hoisted at the root and again
/// nested — and they are the same install. The first key wins, which is deterministic because the
/// package list is sorted by key.
fn index(lockfile: &Lockfile) -> BTreeMap<Identity, &Package> {
    let mut out: BTreeMap<Identity, &Package> = BTreeMap::new();
    for package in lockfile.external() {
        out.entry(package.identity()).or_insert(package);
    }
    out
}

/// Compares two entries with the same name and version.
///
/// Returns every difference found rather than the first: a package can change both its source and its
/// groups in one PR, and reporting only one would understate the change.
fn compare_same_identity(identity: &Identity, before: &Package, after: &Package) -> Vec<Change> {
    let mut changes = Vec::new();

    let old_integrity = before.source.integrity();
    let new_integrity = after.source.integrity();
    // Only compared when both sides recorded one. A hash appearing where there was none is a lockfile
    // format difference (npm v1 has no integrity for some entries), not a change in the bytes, and
    // reporting it as one would produce a finding out of a format upgrade.
    if let (Some(old), Some(new)) = (old_integrity, new_integrity) {
        if old != new {
            changes.push(Change::IntegrityChanged {
                name: identity.name.clone(),
                version: identity.version.clone(),
                before: Some(old.to_string()),
                after: Some(new.to_string()),
            });
        }
    }

    if !same_source_kind(&before.source, &after.source) {
        changes.push(Change::SourceChanged {
            name: identity.name.clone(),
            version: identity.version.clone(),
            before: before.source.clone(),
            after: after.source.clone(),
        });
    }

    if before.groups != after.groups {
        changes.push(Change::GroupsChanged {
            name: identity.name.clone(),
            version: identity.version.clone(),
            before: before.groups,
            after: after.groups,
        });
    }

    changes
}

/// Whether two sources fetch from the same kind of place.
///
/// Compares the *kind* and, for a remote source, the URL — but not the integrity hash, which
/// [`compare_same_identity`] reports separately so the two do not double-count.
///
/// A URL of `None` on either side is not treated as a difference: pnpm records no URL for a registry
/// package and npm v1 records none for some entries, so comparing an absent URL against a present one
/// would report a source change on every npm-to-pnpm read of an unchanged dependency.
fn same_source_kind(before: &Source, after: &Source) -> bool {
    match (before, after) {
        (Source::Remote { url: old, .. }, Source::Remote { url: new, .. }) => {
            match (old.as_deref(), new.as_deref()) {
                (Some(old), Some(new)) => old == new,
                _ => true,
            }
        }
        // The remaining same-kind pairs compare their single text field. Written as one arm because
        // three arms with identical bodies is what it is; the discriminants still have to match, which
        // is what makes a registry-to-git move a difference.
        (Source::Git { url: old }, Source::Git { url: new })
        | (Source::Directory { path: old }, Source::Directory { path: new })
        | (Source::Workspace { path: old }, Source::Workspace { path: new })
        | (Source::Unknown { raw: old }, Source::Unknown { raw: new }) => old == new,
        _ => false,
    }
}

/// Turns added and removed entries into version changes where the names line up.
///
/// A name present on both sides is a version change; a name on one side only is a plain add or
/// remove. When a name appears several times on a side — the same package at three versions — the
/// entries are paired in sorted order so the result is deterministic, and any surplus is reported as a
/// bare add or remove rather than being dropped.
fn pair_by_name(added: &[&Package], removed: &[&Package]) -> Vec<Change> {
    let mut by_name_added: BTreeMap<&str, Vec<&Package>> = BTreeMap::new();
    for package in added {
        by_name_added
            .entry(package.name.as_str())
            .or_default()
            .push(package);
    }
    let mut by_name_removed: BTreeMap<&str, Vec<&Package>> = BTreeMap::new();
    for package in removed {
        by_name_removed
            .entry(package.name.as_str())
            .or_default()
            .push(package);
    }

    let mut changes = Vec::new();
    let names: BTreeSet<&str> = by_name_added
        .keys()
        .chain(by_name_removed.keys())
        .copied()
        .collect();

    for name in names {
        let mut new_side = by_name_added.remove(name).unwrap_or_default();
        let mut old_side = by_name_removed.remove(name).unwrap_or_default();
        new_side.sort_by(|a, b| a.version.cmp(&b.version));
        old_side.sort_by(|a, b| a.version.cmp(&b.version));

        let paired = new_side.len().min(old_side.len());
        for index in 0..paired {
            changes.push(Change::VersionChanged {
                name: name.to_string(),
                before: old_side[index].clone(),
                after: new_side[index].clone(),
            });
        }
        for package in new_side.iter().skip(paired) {
            changes.push(Change::Added {
                package: (*package).clone(),
            });
        }
        for package in old_side.iter().skip(paired) {
            changes.push(Change::Removed {
                package: (*package).clone(),
            });
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Ecosystem;

    fn registry(name: &str, version: &str, integrity: &str) -> Package {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            alias: None,
            source: Source::Remote {
                url: Some(format!(
                    "https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
                )),
                integrity: Some(integrity.to_string()),
            },
            groups: Groups::PROD,
            has_install_script: None,
            key: format!("node_modules/{name}"),
        }
    }

    fn lockfile(packages: Vec<Package>) -> Lockfile {
        Lockfile {
            ecosystem: Ecosystem::Npm,
            declared_version: "3".to_string(),
            packages,
        }
    }

    #[test]
    fn an_unchanged_lockfile_produces_no_changes() {
        // The common case by far. A PR that touches a lockfile without changing the resolved set must
        // not trigger a recording, or the Action becomes noise.
        let before = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let after = before.clone();
        let result = diff(&before, &after);
        assert!(result.is_empty());
        assert!(!result.should_record());
    }

    #[test]
    fn an_added_package_is_recordable() {
        let before = lockfile(vec![]);
        let after = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1);
        assert!(result.should_record());
        assert_eq!(
            result.recordable(),
            vec![Identity {
                name: "ms".to_string(),
                version: "2.1.3".to_string()
            }]
        );
    }

    #[test]
    fn a_version_bump_is_one_change_not_an_add_and_a_remove() {
        // A reviewer reading "added lodash 4.17.21" and "removed lodash 4.17.20" ten lines apart has to
        // reconstruct the bump themselves.
        let before = lockfile(vec![registry("lodash", "4.17.20", "sha512-old")]);
        let after = lockfile(vec![registry("lodash", "4.17.21", "sha512-new")]);
        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
        match &result.changes[0] {
            Change::VersionChanged {
                name,
                before,
                after,
            } => {
                assert_eq!(name, "lodash");
                assert_eq!(before.version, "4.17.20");
                assert_eq!(after.version, "4.17.21");
            }
            other => panic!("expected VersionChanged, got {other:?}"),
        }
        assert_eq!(result.recordable()[0].version, "4.17.21");
    }

    #[test]
    fn a_downgrade_is_reported_the_same_way_as_an_upgrade() {
        // Both replace the code that runs at install time. Treating a downgrade as more suspicious
        // would be a heuristic dressed as evidence.
        let before = lockfile(vec![registry("lodash", "4.17.21", "sha512-new")]);
        let after = lockfile(vec![registry("lodash", "4.17.20", "sha512-old")]);
        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1);
        assert!(result.changes[0].introduces_code());
        assert!(result.changes[0].summary().contains("4.17.21 to 4.17.20"));
    }

    #[test]
    fn a_changed_hash_at_the_same_version_is_its_own_category() {
        // The case a version-only diff cannot see. On a healthy registry it does not happen, which is
        // exactly why it must be visible when it does.
        let before = lockfile(vec![registry("lodash", "4.17.21", "sha512-original")]);
        let after = lockfile(vec![registry("lodash", "4.17.21", "sha512-different")]);
        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
        assert!(matches!(result.changes[0], Change::IntegrityChanged { .. }));
        assert!(result.should_record(), "different bytes must be recorded");
        assert!(result.changes[0]
            .summary()
            .contains("different tarball hash"));
    }

    #[test]
    fn an_absent_hash_on_one_side_is_not_reported_as_a_change() {
        // npm v1 records no integrity for some entries and pnpm records no URL for registry packages.
        // Comparing absent against present would manufacture a finding out of a format difference.
        let mut before = registry("ms", "2.1.3", "sha512-aaa");
        before.source = Source::Remote {
            url: None,
            integrity: None,
        };
        let after = registry("ms", "2.1.3", "sha512-aaa");
        let result = diff(&lockfile(vec![before]), &lockfile(vec![after]));
        assert!(
            result.is_empty(),
            "a format difference is not a change: {:?}",
            result.changes
        );
    }

    #[test]
    fn a_registry_package_replaced_by_a_git_dependency_is_a_source_change() {
        let before = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let mut moved = registry("ms", "2.1.3", "sha512-aaa");
        moved.source = Source::Git {
            url: "git+ssh://git@github.com/attacker/ms.git#abc".to_string(),
        };
        let after = lockfile(vec![moved]);

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
        assert!(matches!(result.changes[0], Change::SourceChanged { .. }));
        assert!(
            result.should_record(),
            "the code now comes from somewhere else"
        );
    }

    #[test]
    fn a_removal_is_reported_but_not_recorded() {
        // Nothing to observe: removed code cannot run during this install.
        let before = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let after = lockfile(vec![]);
        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1);
        assert!(matches!(result.changes[0], Change::Removed { .. }));
        assert!(!result.should_record());
        assert!(result.recordable().is_empty());
    }

    #[test]
    fn a_group_move_is_reported_but_not_recorded() {
        // The code is byte-identical; only where it installs changed.
        let before = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let mut promoted = registry("ms", "2.1.3", "sha512-aaa");
        promoted.groups = Groups {
            dev: true,
            optional: false,
        };
        let after = lockfile(vec![promoted]);

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1);
        assert!(matches!(result.changes[0], Change::GroupsChanged { .. }));
        assert!(
            !result.should_record(),
            "identical bytes need no new recording"
        );
        assert!(result.changes[0].summary().contains("prod to dev"));
    }

    #[test]
    fn a_workspace_package_is_not_reported_as_a_dependency_change() {
        // Otherwise adding one workspace member would report every workspace member as new
        // third-party code, and the tool would be crying wolf on its own repository.
        let before = lockfile(vec![]);
        let mut member = registry("local-a", "0.1.0", "sha512-aaa");
        member.source = Source::Workspace {
            path: "packages/local-a".to_string(),
        };
        let after = lockfile(vec![member]);
        assert!(diff(&before, &after).is_empty());
    }

    #[test]
    fn several_changes_to_one_package_are_all_reported() {
        // A source change and a group change in the same PR. Reporting only the first would understate
        // what happened.
        let before = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let mut changed = registry("ms", "2.1.3", "sha512-aaa");
        changed.source = Source::Git {
            url: "git+ssh://x#abc".to_string(),
        };
        changed.groups = Groups {
            dev: true,
            optional: false,
        };
        let after = lockfile(vec![changed]);

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 2, "{:?}", result.changes);
        assert!(result
            .changes
            .iter()
            .any(|c| matches!(c, Change::SourceChanged { .. })));
        assert!(result
            .changes
            .iter()
            .any(|c| matches!(c, Change::GroupsChanged { .. })));
    }

    #[test]
    fn code_introducing_changes_are_ordered_first() {
        // A reviewer's attention is finite and belongs on the code that will run.
        let before = lockfile(vec![
            registry("zebra", "1.0.0", "sha512-z"),
            registry("alpha", "1.0.0", "sha512-a"),
        ]);
        let after = lockfile(vec![registry("alpha", "2.0.0", "sha512-a2")]);

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 2);
        assert!(
            result.changes[0].introduces_code(),
            "the version bump must lead: {:?}",
            result.changes
        );
        assert!(!result.changes[1].introduces_code());
    }

    #[test]
    fn several_versions_of_one_name_are_paired_deterministically() {
        // Two entries removed and two added under the same name. Pairing must not depend on hash
        // iteration order, or two runs would produce different reports from identical input.
        let before = lockfile(vec![
            Package {
                key: "node_modules/a/node_modules/ms".to_string(),
                ..registry("ms", "1.0.0", "sha512-1")
            },
            Package {
                key: "node_modules/ms".to_string(),
                ..registry("ms", "2.0.0", "sha512-2")
            },
        ]);
        let after = lockfile(vec![
            Package {
                key: "node_modules/a/node_modules/ms".to_string(),
                ..registry("ms", "3.0.0", "sha512-3")
            },
            Package {
                key: "node_modules/ms".to_string(),
                ..registry("ms", "4.0.0", "sha512-4")
            },
        ]);

        let first = diff(&before, &after);
        assert_eq!(first, diff(&before, &after), "diffing must be repeatable");
        assert_eq!(first.changes.len(), 2);
        // Sorted-order pairing: 1.0.0 -> 3.0.0 and 2.0.0 -> 4.0.0.
        let summaries: Vec<String> = first.changes.iter().map(Change::summary).collect();
        assert!(
            summaries.contains(&"ms 1.0.0 to 3.0.0".to_string()),
            "{summaries:?}"
        );
        assert!(
            summaries.contains(&"ms 2.0.0 to 4.0.0".to_string()),
            "{summaries:?}"
        );
    }

    #[test]
    fn a_surplus_entry_is_reported_rather_than_dropped() {
        // Three versions in, one out. The two unpaired additions must still appear.
        let before = lockfile(vec![registry("ms", "1.0.0", "sha512-1")]);
        let after = lockfile(vec![
            Package {
                key: "node_modules/a/node_modules/ms".to_string(),
                ..registry("ms", "2.0.0", "sha512-2")
            },
            Package {
                key: "node_modules/b/node_modules/ms".to_string(),
                ..registry("ms", "3.0.0", "sha512-3")
            },
            Package {
                key: "node_modules/ms".to_string(),
                ..registry("ms", "4.0.0", "sha512-4")
            },
        ]);

        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 3, "{:?}", result.changes);
        assert_eq!(result.recordable().len(), 3);
    }

    #[test]
    fn the_same_identity_at_two_keys_is_one_install() {
        // A hoisted package and its nested duplicate at the same version are the same install, and
        // recording it twice would double the runner time for no new evidence.
        let before = lockfile(vec![]);
        let after = lockfile(vec![
            Package {
                key: "node_modules/ms".to_string(),
                ..registry("ms", "2.1.3", "sha512-aaa")
            },
            Package {
                key: "node_modules/debug/node_modules/ms".to_string(),
                ..registry("ms", "2.1.3", "sha512-aaa")
            },
        ]);
        let result = diff(&before, &after);
        assert_eq!(result.changes.len(), 1, "{:?}", result.changes);
        assert_eq!(result.recordable().len(), 1);
    }

    #[test]
    fn a_package_manager_migration_is_flagged_rather_than_shown_as_a_hundred_changes() {
        let before = lockfile(vec![registry("ms", "2.1.3", "sha512-aaa")]);
        let after = Lockfile {
            ecosystem: Ecosystem::Pnpm,
            declared_version: "9.0".to_string(),
            packages: vec![registry("ms", "2.1.3", "sha512-aaa")],
        };
        let result = diff(&before, &after);
        assert!(result.ecosystem_changed);
    }
}
