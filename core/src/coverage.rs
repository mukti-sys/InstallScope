//! What each backend was able to observe, so an absent finding is never mistaken for absent behavior.
//!
//! This module exists because of a decision made in Phase 2: recording credential reads is a permanent
//! strace-backend capability (`Phases.md`:23 scopes the aya probes to writes, connects, and spawns). An
//! install that reads `~/.ssh/id_rsa` therefore produces a `high` finding under strace and **nothing**
//! under aya.
//!
//! A report that shows no credential findings is making one of two very different claims:
//!
//! 1. the install did not read any credentials, or
//! 2. this recorder cannot see credential reads at all.
//!
//! Conflating them is exactly the kind of false confidence PRD.md:58 calls the worst failure mode of the
//! product — the same reasoning that makes `PARTIAL` mandatory. So coverage is computed from the
//! recording's own `backend` stamp and travels with the findings, and a renderer that omits it is wrong.

use crate::events::Backend;

/// A class of behavior a rule might report on.
///
/// Deliberately coarser than the event schema: this is about what a *reader* would look for, not about
/// syscall shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationClass {
    /// Filesystem mutations: writes, renames, deletes, permission changes.
    FilesystemWrites,
    /// Reads of credential- and environment-bearing paths.
    CredentialReads,
    /// Outbound connection attempts.
    NetworkConnections,
    /// Resolved hostnames.
    DnsQueries,
    /// Process executions and their argument vectors.
    ProcessSpawns,
    /// Byte volumes attached to writes.
    WriteVolumes,
}

impl ObservationClass {
    /// Every class, for building a full coverage table.
    pub const ALL: &'static [Self] = &[
        Self::FilesystemWrites,
        Self::CredentialReads,
        Self::NetworkConnections,
        Self::DnsQueries,
        Self::ProcessSpawns,
        Self::WriteVolumes,
    ];

    /// Name for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemWrites => "filesystem writes",
            Self::CredentialReads => "credential reads",
            Self::NetworkConnections => "network connections",
            Self::DnsQueries => "DNS queries",
            Self::ProcessSpawns => "process spawns",
            Self::WriteVolumes => "write byte volumes",
        }
    }
}

impl std::fmt::Display for ObservationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How well a backend can see one class of behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observability {
    /// Fully observed. An absent finding means the behavior did not occur.
    Observed,
    /// Observed with a stated caveat. An absent finding is meaningful, but a present one is approximate.
    Partial(&'static str),
    /// Not observed at all. **An absent finding says nothing about the behavior.**
    Unobserved(&'static str),
}

impl Observability {
    /// True when silence in this class is evidence of absence.
    ///
    /// The question a report must answer before implying "this install did not do X". A renderer that
    /// never asks it will eventually claim an aya recording found no credential reads.
    #[must_use]
    pub const fn silence_is_meaningful(self) -> bool {
        matches!(self, Self::Observed | Self::Partial(_))
    }

    /// The caveat or reason, when there is one.
    #[must_use]
    pub const fn note(self) -> Option<&'static str> {
        match self {
            Self::Observed => None,
            Self::Partial(note) | Self::Unobserved(note) => Some(note),
        }
    }
}

/// What a given backend can observe.
///
/// Every entry is a statement about the recorder rather than about any particular install, and each is
/// traceable to a decision recorded in the probe module or in `Memory.md`.
///
/// # No class is [`Observability::Observed`] on the strength of "we trace the obvious syscalls"
///
/// An earlier version of this table marked strace's filesystem and process classes `Observed`, meaning
/// silence in them was evidence of absence. That was too strong. strace sees the syscalls in
/// `recorder::strace::TRACE_SET` and nothing else, and there are documented ways to mutate a file or run
/// a program that are not in that set. A class is `Observed` here only when the backend's view of it has
/// no known gap; where a gap exists it is named, because a caveat a reader can evaluate is worth more
/// than a reassurance they cannot.
///
/// Two of the gaps that produced this note have since been closed rather than caveated: `fchmod`,
/// `fchown`, and `ftruncate` are now traced, so a descriptor-based mutation is no longer invisible. The
/// note below is narrower as a result. `io_uring` remains the substantive hole and is stated plainly,
/// because closing it needs ring-creation tracing rather than another syscall name.
#[must_use]
pub fn observability(backend: Backend, class: ObservationClass) -> Observability {
    match (backend, class) {
        // ---- strace ----------------------------------------------------------------------------
        (Backend::Strace, ObservationClass::FilesystemWrites) => Observability::Partial(
            "mutations are seen through the traced syscall set, which covers both the path and \
             descriptor forms of every operation it traces. Not covered: an `io_uring` submission, \
             which can open and write without issuing a traced syscall at all",
        ),
        (Backend::Strace, ObservationClass::ProcessSpawns) => Observability::Partial(
            "execution is observed at `execve`/`execveat`; argument vectors are captured up to \
             strace's 512-byte string limit and a longer command line is flagged truncated rather \
             than shown in full",
        ),
        (Backend::Strace, ObservationClass::CredentialReads) => Observability::Partial(
            "reads are filtered to a list of credential- and environment-bearing paths; a read of \
             some other sensitive file is not reported",
        ),
        (Backend::Strace, ObservationClass::NetworkConnections) => Observability::Partial(
            "destinations are IP addresses; strace cannot prove which DNS answer a connect used, so \
             no hostname is attached. Inbound sockets are not traced, so a package that binds and \
             listens produces no event",
        ),
        (Backend::Strace, ObservationClass::DnsQueries) => Observability::Partial(
            "questions are decoded from datagram payloads sent to port 53; a payload truncated by \
             strace's buffer yields no event rather than a partial hostname, and resolution over \
             DNS-over-HTTPS or DNS-over-TLS is indistinguishable from ordinary traffic",
        ),
        (Backend::Strace, ObservationClass::WriteVolumes) => Observability::Partial(
            "byte counts come from the write-family syscalls; volume moved by `sendfile`, \
             `copy_file_range`, or a shared mapping is not counted, so a total is a floor rather \
             than a measurement",
        ),

        // ---- aya -------------------------------------------------------------------------------
        (Backend::Aya, ObservationClass::FilesystemWrites) => Observability::Partial(
            "paths come from the syscall argument rather than a dentry walk, so a relative path \
             stays unresolved and cannot be placed inside or outside a directory",
        ),
        // The decision this module was written for.
        (Backend::Aya, ObservationClass::CredentialReads) => Observability::Unobserved(
            "the aya probes are scoped to writes, connects, and spawns (Phases.md:23); recording \
             credential reads is a strace-backend capability",
        ),
        (Backend::Aya, ObservationClass::NetworkConnections) => Observability::Partial(
            "destination addresses are read from the sockaddr argument; no hostname is attached",
        ),
        (Backend::Aya, ObservationClass::DnsQueries) => Observability::Unobserved(
            "decoding DNS payloads inside a BPF program is a deliberate non-goal; the aya backend \
             emits no dns_query events",
        ),
        (Backend::Aya, ObservationClass::ProcessSpawns) => Observability::Partial(
            "argv is captured in fixed-width slots; a long argument or more than the slot count is \
             truncated with a flag rather than silently shortened",
        ),
        (Backend::Aya, ObservationClass::WriteVolumes) => Observability::Partial(
            "byte counts are the requested count from syscall entry, not the number actually \
             written, so a short write overstates the total",
        ),
    }
}

/// The full coverage table for a recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// Which recorder produced the events.
    pub backend: Backend,
    /// Per-class observability, in [`ObservationClass::ALL`] order for stable rendering.
    pub classes: Vec<(ObservationClass, Observability)>,
}

impl Coverage {
    /// Builds the table for a backend.
    #[must_use]
    pub fn for_backend(backend: Backend) -> Self {
        Self {
            backend,
            classes: ObservationClass::ALL
                .iter()
                .map(|class| (*class, observability(backend, *class)))
                .collect(),
        }
    }

    /// Classes this backend cannot see at all.
    ///
    /// A report **must** surface these. Without them, a clean-looking result overstates what was
    /// checked, which is the same failure as rendering a PARTIAL recording as complete.
    #[must_use]
    pub fn blind_spots(&self) -> Vec<(ObservationClass, &'static str)> {
        self.classes
            .iter()
            .filter_map(|(class, observability)| match observability {
                Observability::Unobserved(reason) => Some((*class, *reason)),
                Observability::Observed | Observability::Partial(_) => None,
            })
            .collect()
    }

    /// True when this backend has no class it cannot see at all.
    ///
    /// Deliberately *not* "sees everything". Every class can still carry a [`Observability::Partial`]
    /// caveat — strace has known gaps in each of them, listed in [`observability`] — and this returning
    /// `true` means only that silence in each class is worth something, not that it is conclusive. The
    /// caveats travel with the report either way, and [`Self::qualifications`] enumerates them.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.blind_spots().is_empty()
    }

    /// Classes this backend sees with a stated limitation.
    ///
    /// Separate from [`Self::blind_spots`] because the two support different claims: a blind spot means
    /// an absent finding says nothing at all, while a qualification means it says less than it appears
    /// to. A report that shows neither is overstating its own coverage.
    #[must_use]
    pub fn qualifications(&self) -> Vec<(ObservationClass, &'static str)> {
        self.classes
            .iter()
            .filter_map(|(class, observability)| match observability {
                Observability::Partial(reason) => Some((*class, *reason)),
                Observability::Observed | Observability::Unobserved(_) => None,
            })
            .collect()
    }

    /// One-line caveat for a report footer, or `None` when there is nothing to caveat.
    ///
    /// Phrased as what was *not checked* rather than as a reassurance, because a reader skimming a
    /// zero-score report needs the limitation to land.
    ///
    /// Only blind spots reach this line. Per-class qualifications are numerous and specific, and
    /// collapsing six of them into one sentence would produce a paragraph nobody reads; they are
    /// rendered in the per-class table instead, which every report surface carries.
    #[must_use]
    pub fn caveat_line(&self) -> Option<String> {
        let blind = self.blind_spots();
        if blind.is_empty() {
            return None;
        }
        let names: Vec<&str> = blind.iter().map(|(class, _)| class.as_str()).collect();
        Some(format!(
            "Not checked by the {} backend: {}. Absence of these findings is not evidence they did \
             not happen.",
            self.backend,
            names.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strace_has_no_blind_spot_but_no_unqualified_class_either() {
        // Two claims that are easy to conflate. strace can see something in every class, so silence is
        // never meaningless — but it sees each class through a bounded syscall set, so silence is never
        // conclusive either. The table has to say both.
        let coverage = Coverage::for_backend(Backend::Strace);
        assert!(
            coverage.is_complete(),
            "strace has no blind spots: {:?}",
            coverage.blind_spots()
        );
        assert_eq!(coverage.caveat_line(), None);
        for (class, observability) in &coverage.classes {
            assert!(
                observability.silence_is_meaningful(),
                "{class}: strace silence must carry some weight"
            );
            assert!(
                observability.note().is_some(),
                "{class}: strace's view of every class has a documented gap; claiming an \
                 unqualified Observed would overstate it"
            );
        }
        assert_eq!(
            coverage.qualifications().len(),
            ObservationClass::ALL.len(),
            "every strace class is qualified"
        );
    }

    #[test]
    fn the_strace_gaps_that_matter_are_named() {
        // Each remaining gap is a documented way to mutate a file, run a program, resolve a name, or
        // move bytes without producing an event, and each has to be visible to a reader rather than
        // living only in a commit message.
        let filesystem = observability(Backend::Strace, ObservationClass::FilesystemWrites)
            .note()
            .expect("filesystem writes are qualified");
        assert!(
            filesystem.contains("io_uring"),
            "io_uring can write without a traced syscall: {filesystem}"
        );

        let network = observability(Backend::Strace, ObservationClass::NetworkConnections)
            .note()
            .expect("network connections are qualified");
        assert!(
            network.contains("listen"),
            "inbound sockets are not traced: {network}"
        );

        let dns = observability(Backend::Strace, ObservationClass::DnsQueries)
            .note()
            .expect("DNS is qualified");
        assert!(
            dns.contains("DNS-over-HTTPS"),
            "encrypted resolution is indistinguishable from other traffic: {dns}"
        );

        let volumes = observability(Backend::Strace, ObservationClass::WriteVolumes)
            .note()
            .expect("write volumes are qualified");
        assert!(
            volumes.contains("floor"),
            "a byte total is a floor, not a measurement: {volumes}"
        );
    }

    #[test]
    fn the_descriptor_gap_is_closed_and_no_longer_claimed() {
        // `fchmod`, `fchown`, and `ftruncate` are traced now, so the filesystem caveat must not still
        // name them as blind. A stale caveat is a smaller failure than a missing one, but it is still a
        // false statement about coverage — and it would make a reader distrust the caveats that are real.
        let filesystem = observability(Backend::Strace, ObservationClass::FilesystemWrites)
            .note()
            .expect("filesystem writes are qualified");
        for closed in ["fchmod", "fchown", "ftruncate"] {
            assert!(
                !filesystem.contains(closed),
                "{closed} is traced now; the caveat must not still claim it is invisible: {filesystem}"
            );
        }
        assert!(
            filesystem.contains("descriptor forms"),
            "the caveat should say what it now does cover, not only what it does not: {filesystem}"
        );
    }

    #[test]
    fn aya_cannot_see_credential_reads() {
        // The decision this module exists to make visible. A zero-finding aya report must not be read as
        // "no credentials were touched".
        let observability = observability(Backend::Aya, ObservationClass::CredentialReads);
        assert!(
            matches!(observability, Observability::Unobserved(_)),
            "got {observability:?}"
        );
        assert!(
            !observability.silence_is_meaningful(),
            "silence here says nothing about the install"
        );
        assert!(observability
            .note()
            .is_some_and(|note| note.contains("Phases.md:23")));
    }

    #[test]
    fn aya_blind_spots_are_exactly_reads_and_dns() {
        let coverage = Coverage::for_backend(Backend::Aya);
        let classes: Vec<ObservationClass> = coverage
            .blind_spots()
            .into_iter()
            .map(|(class, _)| class)
            .collect();
        assert_eq!(
            classes,
            vec![
                ObservationClass::CredentialReads,
                ObservationClass::DnsQueries
            ],
            "any change here is a change in what the product claims to check"
        );
        assert!(!coverage.is_complete());
    }

    #[test]
    fn the_caveat_names_the_backend_and_the_gaps() {
        let caveat = Coverage::for_backend(Backend::Aya)
            .caveat_line()
            .expect("aya has blind spots");
        assert!(caveat.contains("aya"));
        assert!(caveat.contains("credential reads"));
        assert!(caveat.contains("DNS queries"));
        // Phrased as a limitation, not a reassurance: a reader skimming a 0/100 report has to notice.
        assert!(caveat.contains("not evidence"));
    }

    #[test]
    fn every_class_has_an_answer_for_every_backend() {
        // A missing arm would default to something, and whatever it defaulted to would be a silent claim
        // about coverage. Exhaustiveness is enforced by the match, and this asserts the table is also
        // complete in the direction a report iterates it.
        for backend in [Backend::Strace, Backend::Aya] {
            let coverage = Coverage::for_backend(backend);
            assert_eq!(coverage.classes.len(), ObservationClass::ALL.len());
            for class in ObservationClass::ALL {
                assert!(
                    coverage.classes.iter().any(|(c, _)| c == class),
                    "{backend} is missing {class}"
                );
            }
        }
    }

    #[test]
    fn partial_observations_carry_a_reason() {
        // "Partial" with no explanation is indistinguishable from a shrug. Every caveat must say what the
        // limitation actually is, so a reader can judge how much weight a finding carries.
        for backend in [Backend::Strace, Backend::Aya] {
            for class in ObservationClass::ALL {
                let observability = observability(backend, *class);
                if let Observability::Partial(note) | Observability::Unobserved(note) =
                    observability
                {
                    assert!(
                        note.len() > 30,
                        "{backend}/{class}: the reason must be substantive, got {note:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn class_order_is_stable() {
        // Reports render this table; a varying order would produce spurious diffs between two recordings
        // of the same install.
        let first = Coverage::for_backend(Backend::Strace);
        let second = Coverage::for_backend(Backend::Strace);
        assert_eq!(first, second);
        assert_eq!(
            first.classes.first().map(|(class, _)| *class),
            Some(ObservationClass::FilesystemWrites)
        );
    }
}
