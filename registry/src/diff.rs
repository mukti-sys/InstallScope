//! The version-diff engine: "this package's behavior changed between 1.2.3 and 1.2.4."
//!
//! Architecture.md:90 calls this the moat. It is also the claim in this product most easily made
//! dishonest, because a *difference between two recordings* and a *change in a package* are not the same
//! thing, and only the second is news.
//!
//! # Four reasons two recordings differ that have nothing to do with the package
//!
//! 1. **Different backends.** aya records no credential reads and no DNS at all (`Memory.md`, locked
//!    decision). Diffing a strace recording of 1.2.3 against an aya recording of 1.2.4 would report
//!    every credential read as "removed".
//! 2. **A PARTIAL recording.** A recorder that stopped early observed less. Reporting the shortfall as
//!    "behavior removed in 1.2.4" attributes the recorder's failure to the package — permanently, since
//!    this goes in a durable report.
//! 3. **Different recorder versions.** A version of the recorder that gained a syscall probe will see
//!    behaviors its predecessor could not. Not fatal, because the corpus is backfilled over months and
//!    refusing would make the moat unusable — but it is stated in the output.
//! 4. **Unresolvable paths.** A recording where the backend could not place most paths has less to
//!    compare, and a diff that stays quiet about that overstates its own coverage.
//!
//! The first two are refusals: [`Comparison::comparable`] is false and no behavioral claim is made. The
//! second two are caveats carried on the comparison. `Rules.md` §5 asks for admitted uncertainty over
//! plausible-looking output, and a version-diff is exactly where a plausible-looking wrong answer would
//! be quoted in a launch post.
//!
//! # Why "added" and "removed" rather than a similarity score
//!
//! A percentage invites a threshold, a threshold invites tuning, and a tuned threshold is a heuristic —
//! which `Rules.md` §5 and PRD.md:60 both refuse. Set difference is deterministic and a reader can check
//! it by hand against the evidence.

use std::collections::BTreeSet;

use installscope_core::Backend;

use crate::behavior::{Behavior, BehaviorClass, Profile};

/// Why a comparison cannot support a behavioral claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// The two recordings came from different backends.
    BackendMismatch {
        /// Backend that recorded the earlier version.
        before: Backend,
        /// Backend that recorded the later version.
        after: Backend,
    },
    /// One or both recordings are incomplete.
    PartialRecording {
        /// Which side, for the message.
        side: Side,
    },
}

impl Blocker {
    /// The reason, phrased for a report.
    #[must_use]
    pub fn explanation(&self) -> String {
        match self {
            Self::BackendMismatch { before, after } => format!(
                "the two recordings were made by different backends ({before} and {after}), which \
                 observe different things; a difference between them is a difference between recorders, \
                 not between package versions"
            ),
            Self::PartialRecording { side } => format!(
                "the {side} recording is incomplete, so any behavior missing from it may simply not \
                 have been observed"
            ),
        }
    }
}

/// Which recording a statement is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The earlier version.
    Before,
    /// The later version.
    After,
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Before => "earlier",
            Self::After => "later",
        })
    }
}

/// A caveat that weakens a comparison without invalidating it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caveat {
    /// The recordings were made by different recorder versions.
    AgentVersionDiffers {
        /// Recorder that made the earlier recording.
        before: String,
        /// Recorder that made the later recording.
        after: String,
    },
    /// A recording contained paths the backend could not resolve.
    UnresolvedPaths {
        /// Which side.
        side: Side,
        /// How many.
        count: u32,
    },
    /// The backend has classes it cannot observe at all.
    ///
    /// Both recordings share the limitation, so a diff between them is still valid — but the absence of
    /// a credential read in two aya recordings says nothing about the package.
    BackendBlindSpots {
        /// The backend both recordings used.
        backend: Backend,
        /// Which classes it cannot see.
        classes: Vec<String>,
    },
}

impl Caveat {
    /// The caveat, phrased for a report.
    #[must_use]
    pub fn explanation(&self) -> String {
        match self {
            Self::AgentVersionDiffers { before, after } => format!(
                "the recordings were made by different recorder versions ({before} and {after}); a \
                 behavior that appears only in the later one may be newly observable rather than new"
            ),
            Self::UnresolvedPaths { side, count } => format!(
                "{count} path{} in the {side} recording could not be resolved to an absolute location, \
                 so {} not compared against the expected directories",
                if *count == 1 { "" } else { "s" },
                if *count == 1 { "was" } else { "were" }
            ),
            Self::BackendBlindSpots { backend, classes } => format!(
                "the {backend} backend does not observe {}; absence of those behaviors in either \
                 recording is not evidence they did not happen",
                classes.join(" or ")
            ),
        }
    }
}

/// The result of comparing two recordings of the same package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// Package name.
    pub package: String,
    /// The earlier version.
    pub before_version: String,
    /// The later version.
    pub after_version: String,
    /// Behaviors present only in the later recording.
    pub added: Vec<Behavior>,
    /// Behaviors present only in the earlier recording.
    pub removed: Vec<Behavior>,
    /// Behaviors present in both.
    pub unchanged: usize,
    /// Reasons no behavioral claim can be made. Empty when the comparison is sound.
    pub blockers: Vec<Blocker>,
    /// Reasons the comparison is weaker than it looks.
    pub caveats: Vec<Caveat>,
}

impl Comparison {
    /// True when the comparison supports a statement about the package.
    ///
    /// When false, [`Self::added`] and [`Self::removed`] are still populated — a reader debugging their
    /// own pipeline needs to see them — but no report may present them as a change in the package.
    #[must_use]
    pub fn comparable(&self) -> bool {
        self.blockers.is_empty()
    }

    /// True when the two recordings describe identical behavior.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// The headline for a report.
    ///
    /// Phrased as what is known. "Behavior changed" is a claim about two recordings; when the comparison
    /// is blocked, the headline says so instead of hedging a claim it cannot make.
    #[must_use]
    pub fn headline(&self) -> String {
        if !self.comparable() {
            return format!(
                "{}@{} and {}@{} cannot be compared",
                self.package, self.before_version, self.package, self.after_version
            );
        }
        if self.is_identical() {
            return format!(
                "{}@{} and {}@{} behaved identically",
                self.package, self.before_version, self.package, self.after_version
            );
        }
        format!(
            "{}'s behavior changed between {} and {}",
            self.package, self.before_version, self.after_version
        )
    }

    /// Added behaviors in one class.
    #[must_use]
    pub fn added_in(&self, class: BehaviorClass) -> Vec<&Behavior> {
        self.added
            .iter()
            .filter(|behavior| behavior.class() == class)
            .collect()
    }

    /// Removed behaviors in one class.
    #[must_use]
    pub fn removed_in(&self, class: BehaviorClass) -> Vec<&Behavior> {
        self.removed
            .iter()
            .filter(|behavior| behavior.class() == class)
            .collect()
    }

    /// The classes that changed, in [`BehaviorClass::ALL`] order.
    #[must_use]
    pub fn changed_classes(&self) -> Vec<BehaviorClass> {
        BehaviorClass::ALL
            .iter()
            .copied()
            .filter(|class| {
                !self.added_in(*class).is_empty() || !self.removed_in(*class).is_empty()
            })
            .collect()
    }

    /// The most notable additions, for a capped summary.
    ///
    /// Additions rather than removals, because new behavior is the thing a reviewer needs to see;
    /// notable classes first, because a new network connection matters more than a new file in
    /// `node_modules`. Within a class the order is the behaviors' own, which is deterministic.
    #[must_use]
    pub fn highlights(&self, limit: usize) -> Vec<&Behavior> {
        let mut out: Vec<&Behavior> = Vec::new();
        for class in BehaviorClass::ALL {
            for behavior in self.added_in(*class) {
                if out.len() >= limit {
                    return out;
                }
                out.push(behavior);
            }
        }
        out
    }
}

/// One side of a comparison: a profile plus the metadata needed to judge comparability.
#[derive(Debug, Clone)]
pub struct Recording {
    /// The version this recording is of.
    pub version: String,
    /// Recorder version that produced it.
    pub agent_version: String,
    /// The reduced behaviors.
    pub profile: Profile,
}

/// Compares two recordings of the same package.
///
/// Neither argument is trusted to be comparable with the other; the checks are the point.
#[must_use]
pub fn compare(package: &str, before: &Recording, after: &Recording) -> Comparison {
    let mut blockers = Vec::new();
    let mut caveats = Vec::new();

    if before.profile.backend != after.profile.backend {
        blockers.push(Blocker::BackendMismatch {
            before: before.profile.backend,
            after: after.profile.backend,
        });
    }
    if !before.profile.complete {
        blockers.push(Blocker::PartialRecording { side: Side::Before });
    }
    if !after.profile.complete {
        blockers.push(Blocker::PartialRecording { side: Side::After });
    }

    if before.agent_version != after.agent_version {
        caveats.push(Caveat::AgentVersionDiffers {
            before: before.agent_version.clone(),
            after: after.agent_version.clone(),
        });
    }
    for (side, profile) in [
        (Side::Before, &before.profile),
        (Side::After, &after.profile),
    ] {
        if profile.unresolved_paths > 0 {
            caveats.push(Caveat::UnresolvedPaths {
                side,
                count: profile.unresolved_paths,
            });
        }
    }
    // Only when both sides agree on the backend; otherwise the mismatch blocker already says more.
    if before.profile.backend == after.profile.backend {
        let coverage = installscope_core::Coverage::for_backend(before.profile.backend);
        let blind: Vec<String> = coverage
            .blind_spots()
            .into_iter()
            .map(|(class, _)| class.as_str().to_string())
            .collect();
        if !blind.is_empty() {
            caveats.push(Caveat::BackendBlindSpots {
                backend: before.profile.backend,
                classes: blind,
            });
        }
    }

    let old: &BTreeSet<Behavior> = &before.profile.behaviors;
    let new: &BTreeSet<Behavior> = &after.profile.behaviors;

    Comparison {
        package: package.to_string(),
        before_version: before.version.clone(),
        after_version: after.version.clone(),
        added: new.difference(old).cloned().collect(),
        removed: old.difference(new).cloned().collect(),
        unchanged: new.intersection(old).count(),
        blockers,
        caveats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_core::{WriteKind, Zone};

    fn behavior(relative: &str) -> Behavior {
        Behavior::Wrote {
            zone: Zone::Project,
            relative: relative.to_string(),
            kind: WriteKind::Open,
        }
    }

    fn profile(backend: Backend, complete: bool, behaviors: Vec<Behavior>) -> Profile {
        Profile {
            backend,
            complete,
            behaviors: behaviors.into_iter().collect(),
            unresolved_paths: 0,
        }
    }

    fn recording(version: &str, profile: Profile) -> Recording {
        Recording {
            version: version.to_string(),
            agent_version: "0.1.0".to_string(),
            profile,
        }
    }

    #[test]
    fn identical_recordings_report_no_change() {
        // The common case for a patch release, and the one a false positive here would ruin.
        let before = recording(
            "1.2.3",
            profile(Backend::Strace, true, vec![behavior("a.js")]),
        );
        let after = recording(
            "1.2.4",
            profile(Backend::Strace, true, vec![behavior("a.js")]),
        );
        let result = compare("lodash", &before, &after);

        assert!(result.comparable());
        assert!(result.is_identical());
        assert_eq!(result.unchanged, 1);
        assert!(result.headline().contains("behaved identically"));
    }

    #[test]
    fn a_new_behavior_is_reported_as_added() {
        let before = recording(
            "1.2.3",
            profile(Backend::Strace, true, vec![behavior("a.js")]),
        );
        let after = recording(
            "1.2.4",
            profile(
                Backend::Strace,
                true,
                vec![
                    behavior("a.js"),
                    Behavior::Connected {
                        port: 443,
                        loopback: false,
                        private: false,
                    },
                ],
            ),
        );
        let result = compare("lodash", &before, &after);

        assert!(result.comparable());
        assert!(!result.is_identical());
        assert_eq!(result.added.len(), 1);
        assert!(result.removed.is_empty());
        assert_eq!(result.unchanged, 1);
        assert!(result.headline().contains("behavior changed"));
        assert_eq!(result.changed_classes(), vec![BehaviorClass::Network]);
    }

    #[test]
    fn a_backend_mismatch_blocks_any_behavioral_claim() {
        // Diffing strace against aya would report every credential read and every DNS query as
        // "removed", because the aya backend does not record them at all.
        let before = recording(
            "1.2.3",
            profile(
                Backend::Strace,
                true,
                vec![Behavior::ReadCredential {
                    path: "home/.ssh/id_rsa".to_string(),
                }],
            ),
        );
        let after = recording("1.2.4", profile(Backend::Aya, true, vec![]));
        let result = compare("lodash", &before, &after);

        assert!(!result.comparable(), "{:?}", result.blockers);
        assert!(matches!(
            result.blockers[0],
            Blocker::BackendMismatch { .. }
        ));
        // The difference is still visible for debugging, but the headline refuses to call it a change.
        assert_eq!(result.removed.len(), 1);
        assert!(result.headline().contains("cannot be compared"));
        assert!(result.blockers[0]
            .explanation()
            .contains("not between package versions"));
    }

    #[test]
    fn a_partial_recording_on_either_side_blocks_the_comparison() {
        // Reporting a shortfall as "behavior removed in 1.2.4" attributes the recorder's failure to the
        // package, and this output is durable.
        let complete = profile(Backend::Strace, true, vec![behavior("a.js")]);
        let truncated = profile(Backend::Strace, false, vec![]);

        let with_partial_before = compare(
            "x",
            &recording("1.0.0", truncated.clone()),
            &recording("1.0.1", complete.clone()),
        );
        assert!(!with_partial_before.comparable());
        assert!(matches!(
            with_partial_before.blockers[0],
            Blocker::PartialRecording { side: Side::Before }
        ));

        let with_partial_after = compare(
            "x",
            &recording("1.0.0", complete),
            &recording("1.0.1", truncated),
        );
        assert!(!with_partial_after.comparable());
        assert!(matches!(
            with_partial_after.blockers[0],
            Blocker::PartialRecording { side: Side::After }
        ));
    }

    #[test]
    fn both_sides_partial_names_both() {
        let truncated = profile(Backend::Strace, false, vec![]);
        let result = compare(
            "x",
            &recording("1.0.0", truncated.clone()),
            &recording("1.0.1", truncated),
        );
        assert_eq!(result.blockers.len(), 2);
    }

    #[test]
    fn a_recorder_version_difference_is_a_caveat_not_a_blocker() {
        // The corpus is backfilled over months (Phases.md:38). Refusing would make the moat unusable, so
        // it is stated instead.
        let mut before = recording("1.2.3", profile(Backend::Strace, true, vec![]));
        before.agent_version = "0.1.0".to_string();
        let mut after = recording(
            "1.2.4",
            profile(Backend::Strace, true, vec![behavior("a.js")]),
        );
        after.agent_version = "0.2.0".to_string();

        let result = compare("x", &before, &after);
        assert!(result.comparable(), "a version difference must not block");
        assert!(result
            .caveats
            .iter()
            .any(|caveat| matches!(caveat, Caveat::AgentVersionDiffers { .. })));
        let explanation = result
            .caveats
            .iter()
            .map(Caveat::explanation)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            explanation.contains("newly observable rather than new"),
            "{explanation}"
        );
    }

    #[test]
    fn unresolved_paths_are_carried_as_a_caveat() {
        // A recording where most paths could not be placed has less to compare, and staying quiet about
        // it would overstate the comparison's coverage.
        let mut weak = profile(Backend::Strace, true, vec![]);
        weak.unresolved_paths = 400;
        let result = compare(
            "x",
            &recording("1.0.0", weak),
            &recording("1.0.1", profile(Backend::Strace, true, vec![])),
        );
        assert!(result.comparable());
        let caveat = result
            .caveats
            .iter()
            .find(|c| matches!(c, Caveat::UnresolvedPaths { .. }))
            .expect("the caveat must be present");
        assert!(caveat.explanation().contains("400"));
        assert!(caveat.explanation().contains("earlier"));
    }

    #[test]
    fn two_aya_recordings_carry_the_blind_spot_caveat() {
        // Comparable with each other, but silence about credential reads in both says nothing about the
        // package. The same obligation the Phase 3 report carries.
        let result = compare(
            "x",
            &recording("1.0.0", profile(Backend::Aya, true, vec![])),
            &recording("1.0.1", profile(Backend::Aya, true, vec![])),
        );
        assert!(result.comparable());
        let caveat = result
            .caveats
            .iter()
            .find(|c| matches!(c, Caveat::BackendBlindSpots { .. }))
            .expect("aya has blind spots");
        let text = caveat.explanation();
        assert!(text.contains("credential reads"), "{text}");
        assert!(text.contains("DNS queries"), "{text}");
        assert!(text.contains("not evidence"), "{text}");
    }

    #[test]
    fn two_strace_recordings_carry_no_blind_spot_caveat() {
        // The complement: warnings that always appear stop meaning anything.
        let result = compare(
            "x",
            &recording("1.0.0", profile(Backend::Strace, true, vec![])),
            &recording("1.0.1", profile(Backend::Strace, true, vec![])),
        );
        assert!(!result
            .caveats
            .iter()
            .any(|c| matches!(c, Caveat::BackendBlindSpots { .. })));
    }

    #[test]
    fn highlights_lead_with_the_notable_classes() {
        // A new network connection matters more to a reviewer than a new file in node_modules.
        let before = recording("1.0.0", profile(Backend::Strace, true, vec![]));
        let after = recording(
            "1.0.1",
            profile(
                Backend::Strace,
                true,
                vec![
                    behavior("node_modules/a.js"),
                    behavior("node_modules/b.js"),
                    Behavior::SpawnedShellPipeline {
                        tool: "curl".to_string(),
                    },
                    Behavior::WroteOutside {
                        path: "/etc/cron.d/evil".to_string(),
                        kind: WriteKind::Open,
                    },
                ],
            ),
        );
        let result = compare("x", &before, &after);
        let highlights = result.highlights(3);
        assert_eq!(highlights.len(), 3);
        assert_eq!(
            highlights[0].class(),
            BehaviorClass::FilesystemEscape,
            "the escape must lead: {:?}",
            highlights.iter().map(|b| b.summary()).collect::<Vec<_>>()
        );
        assert!(highlights
            .iter()
            .any(|b| b.class() == BehaviorClass::Process));
    }

    #[test]
    fn highlights_respect_the_limit_and_are_deterministic() {
        let before = recording("1.0.0", profile(Backend::Strace, true, vec![]));
        let after = recording(
            "1.0.1",
            profile(
                Backend::Strace,
                true,
                (0..20)
                    .map(|index| behavior(&format!("file-{index}.js")))
                    .collect(),
            ),
        );
        let result = compare("x", &before, &after);
        assert_eq!(result.highlights(3).len(), 3);
        assert_eq!(
            result
                .highlights(3)
                .iter()
                .map(|b| b.summary())
                .collect::<Vec<_>>(),
            result
                .highlights(3)
                .iter()
                .map(|b| b.summary())
                .collect::<Vec<_>>()
        );
        assert!(result.highlights(0).is_empty());
    }

    #[test]
    fn a_removed_behavior_is_reported() {
        let before = recording(
            "1.0.0",
            profile(
                Backend::Strace,
                true,
                vec![Behavior::Resolved {
                    qname: "telemetry.example".to_string(),
                }],
            ),
        );
        let after = recording("1.0.1", profile(Backend::Strace, true, vec![]));
        let result = compare("x", &before, &after);
        assert_eq!(result.removed.len(), 1);
        assert!(result.added.is_empty());
        assert_eq!(result.removed_in(BehaviorClass::Network).len(), 1);
    }

    #[test]
    fn comparing_is_deterministic() {
        let before = recording(
            "1.0.0",
            profile(
                Backend::Strace,
                true,
                vec![behavior("b.js"), behavior("a.js")],
            ),
        );
        let after = recording(
            "1.0.1",
            profile(
                Backend::Strace,
                true,
                vec![behavior("c.js"), behavior("a.js")],
            ),
        );
        assert_eq!(compare("x", &before, &after), compare("x", &before, &after));
    }

    #[test]
    fn no_headline_or_explanation_uses_banned_framing() {
        // Rules.md §4. These strings are the most likely to be screenshotted (Design.md:53).
        let result = compare(
            "x",
            &recording("1.0.0", profile(Backend::Aya, false, vec![])),
            &recording(
                "1.0.1",
                profile(Backend::Strace, true, vec![behavior("a.js")]),
            ),
        );
        let mut texts = vec![result.headline()];
        texts.extend(result.blockers.iter().map(Blocker::explanation));
        texts.extend(result.caveats.iter().map(Caveat::explanation));
        for text in texts {
            let lower = text.to_ascii_lowercase();
            for banned in ["safe", "protect", "guarantee", "sandbox", "secure"] {
                assert!(!lower.contains(banned), "{text:?} contains {banned:?}");
            }
        }
    }
}
