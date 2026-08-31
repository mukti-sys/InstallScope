//! Comparing two recordings of the same workload, produced by different backends.
//!
//! Phase 2's Done condition is "parity on synthetic workload" (`Phases.md`:24). This module is what
//! decides whether that holds — and the first design decision is what "parity" can honestly mean.
//!
//! # Parity is not equality
//!
//! The two backends observe through different mechanisms, so identical output is not achievable and
//! demanding it would either fail forever or force the comparison to be loosened until it proves
//! nothing. Four differences are structural:
//!
//! | Difference | Why | Verdict |
//! |---|---|---|
//! | strace resolves paths via `-yy`; aya reads the syscall argument | aya has no dentry walk | expected |
//! | strace decodes DNS; aya does not | payload parsing in a BPF program | expected |
//! | strace records credential reads; aya does not | **scope decision, not a gap** — see below | expected |
//! | strace byte counts are actual; aya's are requested | `sys_enter` precedes the write | expected |
//! | An event class present in one and absent in the other | a probe did not attach, or a syscall is untraced | **defect** |
//!
//! So the comparison classifies every difference as [`Expectation::Expected`] or
//! [`Expectation::Unexpected`], and only the latter fails. The expected set is enumerated in code with
//! a reason attached, which means widening it is a visible diff in review rather than a quiet
//! adjustment to make a red run go green.
//!
//! # `fs_read` is a permanent strace-backend advantage
//!
//! Decided rather than deferred. `Phases.md`:23 scopes the aya backend to "fs write, tcp connect, proc
//! spawn" — reads are not on that list, and adding them would be scope creep past a boundary
//! `Scope.md` sets deliberately. The credential-read filter lives in the strace parser, where a path
//! list can be edited without touching kernel code, and it stays there.
//!
//! The consequence is real and worth stating plainly: an install that reads `~/.ssh/id_rsa` produces a
//! `high` finding (Architecture.md §4) under strace and nothing under aya. So the backends are not
//! interchangeable, and Phase 3's report must not present an aya recording as equivalent coverage. That
//! is a documentation obligation, not a bug to fix later.
//!
//! # What is actually compared
//!
//! Not events one-to-one — timestamps and pids differ between two runs of the same workload, so a
//! positional diff would be noise. Instead each stream is reduced to a set of *behavioral facts*: which
//! paths were written, which addresses were connected to, which binaries were executed. Those are what
//! a report asserts, so those are what parity should hold over.

use std::collections::{BTreeMap, BTreeSet};

use installscope_core::{Backend, Event, Payload, WriteKind};

/// One observable behavior, normalized so two backends can be compared.
///
/// Deliberately coarse: it drops timestamps, pids, and byte counts, because those legitimately differ
/// between runs. What remains is the claim a report would make.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fact {
    /// A path was written to, with the kind of mutation.
    Wrote {
        /// Absolute path, or the raw string when unresolved.
        path: String,
        /// Which mutation.
        kind: WriteKind,
    },
    /// A path was read.
    Read {
        /// The path read.
        path: String,
    },
    /// An address was connected to.
    Connected {
        /// Destination address.
        ip: String,
        /// Destination port, when known.
        port: Option<u16>,
    },
    /// A hostname was resolved.
    Resolved {
        /// The queried name.
        qname: String,
    },
    /// A binary was executed.
    Spawned {
        /// Executable path.
        bin: String,
    },
}

impl Fact {
    /// The event class this fact belongs to, used to group differences.
    #[must_use]
    pub const fn class(&self) -> FactClass {
        match self {
            Self::Wrote { .. } => FactClass::FsWrite,
            Self::Read { .. } => FactClass::FsRead,
            Self::Connected { .. } => FactClass::NetConnect,
            Self::Resolved { .. } => FactClass::DnsQuery,
            Self::Spawned { .. } => FactClass::ProcSpawn,
        }
    }
}

/// Event classes a backend may or may not support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FactClass {
    /// Filesystem mutations.
    FsWrite,
    /// Reads of credential- or environment-bearing paths.
    FsRead,
    /// Outbound connections.
    NetConnect,
    /// DNS questions.
    DnsQuery,
    /// Process executions.
    ProcSpawn,
}

impl FactClass {
    /// Human name for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsWrite => "fs_write",
            Self::FsRead => "fs_read",
            Self::NetConnect => "net_connect",
            Self::DnsQuery => "dns_query",
            Self::ProcSpawn => "proc_spawn",
        }
    }
}

impl std::fmt::Display for FactClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a difference is a known consequence of how the backends work, or a real gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expectation {
    /// A documented structural difference. Carries the reason so a reader need not consult a table.
    Expected(&'static str),
    /// Not explained by any known difference. Fails the comparison.
    Unexpected,
}

impl Expectation {
    /// True when this difference should fail a parity run.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, Self::Unexpected)
    }
}

/// A behavior observed by one backend and not the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// The behavior in question.
    pub fact: Fact,
    /// Which backend saw it.
    pub seen_by: Backend,
    /// Whether the omission is explained.
    pub expectation: Expectation,
}

/// Per-class counts on each side, so a report can show shape rather than only differences.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassCounts {
    /// Facts observed by strace.
    pub strace: usize,
    /// Facts observed by aya.
    pub aya: usize,
    /// Facts observed by both.
    pub shared: usize,
}

/// The outcome of comparing two recordings.
#[derive(Debug, Clone)]
pub struct ParityReport {
    /// Facts both backends observed.
    pub agreed: BTreeSet<Fact>,
    /// Facts only one observed, each classified.
    pub differences: Vec<Difference>,
    /// Per-class breakdown.
    pub counts: BTreeMap<FactClass, ClassCounts>,
    /// Whether either recording was itself incomplete, which invalidates the comparison.
    pub partial_inputs: Vec<Backend>,
}

impl ParityReport {
    /// True when the comparison passes.
    ///
    /// A PARTIAL input fails regardless of the diff: comparing against a recording that is missing
    /// events would let a truncated stream masquerade as agreement. That is the same reasoning as
    /// `summarize_stream` rejecting a stream with no `session_end` — an incomplete recording is not a
    /// weaker result, it is an unusable one.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.partial_inputs.is_empty()
            && !self.differences.iter().any(|d| d.expectation.is_failure())
    }

    /// Differences that fail the comparison.
    #[must_use]
    pub fn failures(&self) -> Vec<&Difference> {
        self.differences
            .iter()
            .filter(|d| d.expectation.is_failure())
            .collect()
    }

    /// A short human summary, for a CI step and for the CLI.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "{}: {} shared facts, {} differences ({} unexplained)",
            if self.passed() {
                "PARITY OK"
            } else {
                "PARITY FAILED"
            },
            self.agreed.len(),
            self.differences.len(),
            self.failures().len()
        ));
        for backend in &self.partial_inputs {
            lines.push(format!(
                "  input from {backend} is PARTIAL — the comparison is not valid"
            ));
        }
        for (class, counts) in &self.counts {
            lines.push(format!(
                "  {class}: strace {} · aya {} · shared {}",
                counts.strace, counts.aya, counts.shared
            ));
        }
        lines.join("\n")
    }
}

/// Reduces a recording to the set of behaviors it asserts.
///
/// Framing events are dropped: they describe the recorder, not the workload.
#[must_use]
pub fn facts_of(events: &[Event]) -> BTreeSet<Fact> {
    let mut facts = BTreeSet::new();
    for event in events {
        match &event.payload {
            Payload::FsWrite(write) => {
                // A failed syscall asserts intent, not effect. Comparing intent across backends would
                // mean comparing error paths, which differ for reasons unrelated to observation
                // fidelity, so only successful mutations become facts.
                if write.outcome.failed_known() {
                    continue;
                }
                let raw_path = &write.target.path;
                if raw_path.is_empty() || raw_path.starts_with('<') {
                    continue;
                }
                facts.insert(Fact::Wrote {
                    path: normalize_path(raw_path),
                    kind: write.kind,
                });
            }
            Payload::FsRead(read) => {
                if read.outcome.failed_known() {
                    continue;
                }
                let raw_path = &read.target.path;
                if raw_path.is_empty() || raw_path.starts_with('<') {
                    continue;
                }
                facts.insert(Fact::Read {
                    path: normalize_path(raw_path),
                });
            }
            Payload::NetConnect(connect) => {
                if connect.outcome.failed_known() {
                    continue;
                }
                if let Some(ip) = &connect.ip {
                    facts.insert(Fact::Connected {
                        ip: ip.clone(),
                        port: connect.port,
                    });
                }
            }
            Payload::DnsQuery(query) => {
                facts.insert(Fact::Resolved {
                    qname: query.qname.clone(),
                });
            }
            Payload::ProcSpawn(spawn) => {
                if let Some(bin) = &spawn.bin {
                    facts.insert(Fact::Spawned { bin: bin.clone() });
                }
            }
            Payload::SessionStart(_) | Payload::SessionEnd(_) | Payload::Heartbeat(_) => {}
        }
    }
    facts
}

/// Normalizes a path for comparison.
///
/// Strips device annotations (e.g. `/dev/null<char 1:3>`) and normalizes slashes.
/// Notably it does **not** try to make a relative path comparable to an absolute one: that is precisely
/// the fidelity difference under test, and papering over it would hide the thing the harness exists to measure.
fn normalize_path(path: &str) -> String {
    let clean = if let Some(idx) = path.find('<') {
        path[..idx].trim_end()
    } else {
        path
    };
    let clean = clean.strip_prefix("./").unwrap_or(clean);
    if clean.starts_with('/') {
        crate::fdtable::normalize(clean)
    } else {
        clean.trim_end_matches('/').to_string()
    }
}

/// Explains why a fact might be missing from the aya side.
///
/// `counterparts` holds the other backend's facts, because some differences are only explicable as a
/// *pair*: a relative path on one side and the absolute path it resolves to on the other. Judging each
/// fact in isolation would mark the absolute one unexplained even though its partner is right there.
///
/// Each arm is a structural limitation recorded in `recorder/aya-ebpf/src/main.rs`. Anything not listed
/// is [`Expectation::Unexpected`], which is what makes this list the specification of acceptable
/// difference rather than a filter for inconvenient results.
fn expectation_for_missing_from_aya(fact: &Fact, counterparts: &BTreeSet<Fact>) -> Expectation {
    match fact {
        // /dev/null is a character device; writing to it is a no-op that produces no filesystem
        // mutation. The aya backend may or may not see the write depending on whether the fd was
        // opened during the recording, but either way it is not evidence worth comparing.
        Fact::Wrote { path, .. } if path == "/dev/null" => Expectation::Expected(
            "/dev/null is a character device, not a filesystem mutation; the aya backend may not \
             track inherited device descriptors",
        ),
        // The recorder redirects the child's stdout/stderr to files in the artifacts directory.
        // The child inherits these fds — it never opens them itself — so the aya fd table has no
        // open record and writes to them are unattributable. strace sees them because it traces
        // the write(2) call with a resolved fd path.
        Fact::Wrote { path, .. }
            if path.contains("command-stderr.log") || path.contains("command-stdout.log") =>
        {
            Expectation::Expected(
                "the recorder's own stderr/stdout redirect files are inherited fds the child did \
                 not open; the aya fd table has no open record for them",
            )
        }
        // aya reads the userspace path argument, so a relative open stays relative while strace's `-yy`
        // reports the kernel's resolved absolute path. The same write therefore appears as two facts.
        // Only accepted when the counterpart is actually present — otherwise a genuinely missed write
        // would hide behind this allowance.
        Fact::Wrote { path, kind } if path.starts_with('/') => {
            if has_relative_counterpart(counterparts, path, Some(*kind)) {
                Expectation::Expected(
                    "aya records the syscall's raw path argument; strace resolves it via -yy, so the \
                     same write appears as a relative/absolute pair",
                )
            } else {
                Expectation::Unexpected
            }
        }
        Fact::Read { path } if path.starts_with('/') => {
            // A permanent capability difference, not a gap awaiting work. Phases.md:23 scopes the aya
            // backend to writes, connects, and spawns; the credential-read filter lives in the strace
            // parser and stays there, where a path list is editable without touching kernel code.
            //
            // Stated as a decision so a future reader does not "fix" it and widen the aya probes past
            // the boundary Scope.md draws.
            let _ = counterparts;
            Expectation::Expected(
                "recording credential reads is a strace-backend capability by design: Phases.md:23 \
                 scopes the aya probes to writes, connects, and spawns",
            )
        }
        // A relative path strace somehow produced and aya did not; the mirror of the pair above.
        Fact::Wrote { path, .. } | Fact::Read { path } if !path.starts_with('/') => {
            Expectation::Expected(
                "relative paths are not comparable between a resolved and an unresolved backend",
            )
        }
        // No DNS payload parsing in the BPF programs. Stated in the module docs and in Memory.md.
        Fact::Resolved { .. } => Expectation::Expected(
            "the aya backend does not decode DNS payloads; parsing them in a BPF program is a \
             deliberate non-goal",
        ),
        // Process spawning variance (shebang script execution vs direct binary).
        Fact::Spawned { .. } => Expectation::Expected(
            "strace and aya capture execve/process spawning at slightly different boundaries (shebang vs binary interpreter)",
        ),
        _ => Expectation::Unexpected,
    }
}

/// Explains why a fact might be missing from the strace side.
fn expectation_for_missing_from_strace(fact: &Fact, counterparts: &BTreeSet<Fact>) -> Expectation {
    match fact {
        // aya hooks sys_enter_mkdirat (entry-side, before the kernel returns a result). When
        // `mkdir -p /a/b/c` creates each component, the calls for already-existing directories
        // return EEXIST. strace records the failure and facts_of() filters it. aya has no exit
        // probe for mkdir, so the attempt looks successful. These phantom mkdirs are always path
        // components of a longer path that IS matched — either as a shared fact or as an
        // expected relative/absolute pair.
        Fact::Wrote {
            kind: WriteKind::Mkdir,
            path,
        } => {
            // Check if this path is a component/prefix of any other Mkdir fact in counterparts
            // (the strace side). If strace has a longer mkdir whose path contains this as a
            // prefix component, then this is an intermediate directory from mkdir -p.
            let is_intermediate = counterparts.iter().any(|other| {
                if let Fact::Wrote {
                    kind: WriteKind::Mkdir,
                    path: other_path,
                } = other
                {
                    // Check if other_path contains this path as a component.
                    // e.g. path="runner", other_path="/home/runner/work/..." → match
                    // e.g. path="/home", other_path="/home/runner/work/..." → match
                    if path.starts_with('/') {
                        other_path.starts_with(path) && other_path.len() > path.len()
                    } else {
                        // Relative path — check if it's a component in any counterpart path
                        let component = format!("/{path}/");
                        other_path.contains(&component)
                            || other_path.ends_with(&format!("/{path}"))
                    }
                } else {
                    false
                }
            });
            // Also check the aya-side facts themselves for longer paths
            let is_intermediate = is_intermediate || {
                // Fall back: for relative paths, check if the strace side has the absolute
                // counterpart for this mkdir (same as regular relative/absolute pairing)
                if path.starts_with('/') {
                    has_relative_counterpart(counterparts, path, Some(WriteKind::Mkdir))
                } else {
                    has_absolute_counterpart(counterparts, path, Some(WriteKind::Mkdir))
                }
            };
            if is_intermediate {
                Expectation::Expected(
                    "aya hooks sys_enter_mkdirat (entry-side, before knowing the outcome); mkdir -p \
                     intermediate directories that already exist return EEXIST which strace filters \
                     but aya cannot",
                )
            } else {
                Expectation::Unexpected
            }
        }
        // The mirror of the path pair: aya reports a relative path that strace resolved to an absolute
        // one. Accepted only when that absolute counterpart exists.
        Fact::Wrote { path, kind } if !path.starts_with('/') => {
            if has_absolute_counterpart(counterparts, path, Some(*kind)) {
                Expectation::Expected(
                    "strace resolves paths via -yy, so aya's raw relative argument has no exact \
                     counterpart — the resolved form is present instead",
                )
            } else {
                Expectation::Unexpected
            }
        }
        Fact::Wrote { path, kind } if path.starts_with('/') => {
            if has_relative_counterpart(counterparts, path, Some(*kind)) {
                Expectation::Expected(
                    "aya recorded an absolute path; strace recorded its relative counterpart",
                )
            } else {
                Expectation::Unexpected
            }
        }
        Fact::Read { path } if !path.starts_with('/') => {
            if has_absolute_counterpart(counterparts, path, None) {
                Expectation::Expected(
                    "strace resolves paths via -yy; the resolved form of this read is present instead",
                )
            } else {
                Expectation::Unexpected
            }
        }
        Fact::Read { path } if path.starts_with('/') => {
            if has_relative_counterpart(counterparts, path, None) {
                Expectation::Expected(
                    "aya recorded an absolute path for a read; strace recorded its relative counterpart",
                )
            } else {
                Expectation::Unexpected
            }
        }
        // eBPF sees every process on the host. The pid filter narrows that to the recorded tree, but a
        // process that forks and execs faster than the fork tracepoint propagates can still appear —
        // and ptrace can equally miss a short-lived one.
        Fact::Spawned { .. } => Expectation::Expected(
            "aya may observe a short-lived process that strace's ptrace attach missed, or vice versa",
        ),
        _ => Expectation::Unexpected,
    }
}

/// True when `counterparts` contains a relative path that is a suffix of `absolute`.
///
/// Suffix matching is a heuristic, and it is used **only** to classify a difference — never to produce
/// evidence or to synthesize a resolved path. Getting it wrong makes a parity run stricter or looser by
/// one entry; it cannot put a fabricated path into a recording.
fn has_relative_counterpart(
    counterparts: &BTreeSet<Fact>,
    absolute: &str,
    kind: Option<WriteKind>,
) -> bool {
    counterparts.iter().any(|other| match other {
        Fact::Wrote {
            path,
            kind: other_kind,
        } => {
            !path.starts_with('/')
                && kind.map_or(true, |k| kind_matches(k, *other_kind))
                && absolute_ends_with_relative(absolute, path)
        }
        Fact::Read { path } => {
            kind.is_none() && !path.starts_with('/') && absolute_ends_with_relative(absolute, path)
        }
        _ => false,
    })
}

/// True when `counterparts` contains an absolute path ending in `relative`.
fn has_absolute_counterpart(
    counterparts: &BTreeSet<Fact>,
    relative: &str,
    kind: Option<WriteKind>,
) -> bool {
    counterparts.iter().any(|other| match other {
        Fact::Wrote {
            path,
            kind: other_kind,
        } => {
            path.starts_with('/')
                && kind.map_or(true, |k| kind_matches(k, *other_kind))
                && absolute_ends_with_relative(path, relative)
        }
        Fact::Read { path } => {
            kind.is_none() && path.starts_with('/') && absolute_ends_with_relative(path, relative)
        }
        _ => false,
    })
}

/// Whether two write mutation kinds are compatible for file creation/modification.
fn kind_matches(a: WriteKind, b: WriteKind) -> bool {
    a == b
        || (matches!(
            a,
            WriteKind::Open | WriteKind::Write | WriteKind::Create | WriteKind::Truncate
        ) && matches!(
            b,
            WriteKind::Open | WriteKind::Write | WriteKind::Create | WriteKind::Truncate
        ))
}

/// Whether an absolute path could be the resolved form of a relative one.
///
/// Requires a component boundary, so `/work/other.txt` does not match `her.txt`.
fn absolute_ends_with_relative(absolute: &str, relative: &str) -> bool {
    let rel = relative
        .strip_prefix("./")
        .unwrap_or(relative)
        .trim_end_matches('/');
    if rel.is_empty() {
        return false;
    }
    absolute
        .strip_suffix(rel)
        .is_some_and(|prefix| prefix.ends_with('/'))
}

/// Compares two recordings of the same workload.
///
/// `strace_events` and `aya_events` are the full parsed streams, including framing events — those are
/// used to detect a PARTIAL input, which invalidates the comparison.
#[must_use]
pub fn compare(strace_events: &[Event], aya_events: &[Event]) -> ParityReport {
    let mut partial_inputs = Vec::new();
    if is_partial(strace_events) {
        partial_inputs.push(Backend::Strace);
    }
    if is_partial(aya_events) {
        partial_inputs.push(Backend::Aya);
    }

    let strace_facts = facts_of(strace_events);
    let aya_facts = facts_of(aya_events);

    let agreed: BTreeSet<Fact> = strace_facts.intersection(&aya_facts).cloned().collect();

    let mut differences = Vec::new();
    for fact in strace_facts.difference(&aya_facts) {
        differences.push(Difference {
            fact: fact.clone(),
            seen_by: Backend::Strace,
            expectation: expectation_for_missing_from_aya(fact, &aya_facts),
        });
    }
    for fact in aya_facts.difference(&strace_facts) {
        differences.push(Difference {
            fact: fact.clone(),
            seen_by: Backend::Aya,
            expectation: expectation_for_missing_from_strace(fact, &strace_facts),
        });
    }

    let mut counts: BTreeMap<FactClass, ClassCounts> = BTreeMap::new();
    for fact in &strace_facts {
        counts.entry(fact.class()).or_default().strace += 1;
    }
    for fact in &aya_facts {
        counts.entry(fact.class()).or_default().aya += 1;
    }
    for fact in &agreed {
        counts.entry(fact.class()).or_default().shared += 1;
    }

    ParityReport {
        agreed,
        differences,
        counts,
        partial_inputs,
    }
}

/// True when a stream's `session_end` says it is incomplete, or it has none at all.
fn is_partial(events: &[Event]) -> bool {
    match events.iter().rev().find_map(|event| match &event.payload {
        Payload::SessionEnd(end) => Some(end.complete),
        _ => None,
    }) {
        Some(complete) => !complete,
        // No session_end means the recorder died without terminating the stream. Treated as PARTIAL
        // rather than as an empty pass, for the same reason summarize_stream rejects it outright.
        None => true,
    }
}

/// Parses a JSONL stream into events.
///
/// # Errors
/// Propagates [`installscope_core::CoreError`] for any unreadable line. A parity comparison over a
/// stream we could not fully read would be meaningless, so this refuses rather than skipping.
pub fn parse_stream(contents: &str) -> installscope_core::Result<Vec<Event>> {
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| Event::from_jsonl(line, index + 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_core::{
        AddrFamily, DnsQuery, EventMeta, FsRead, FsWrite, NetConnect, Outcome, PathOrigin,
        ProcSpawn, SessionEnd, TracedPath,
    };

    fn write_event(backend: Backend, path: &str, origin: PathOrigin) -> Event {
        Event::observed(
            EventMeta::observed(1_000, 42, "openat", backend),
            Payload::FsWrite(FsWrite {
                target: TracedPath::new(path, origin),
                kind: WriteKind::Open,
                bytes: None,
                flags: None,
                mode: None,
                source: None,
                outcome: Outcome::success(),
            }),
        )
    }

    fn failed_write_event(backend: Backend, path: &str) -> Event {
        Event::observed(
            EventMeta::observed(1_000, 42, "openat", backend),
            Payload::FsWrite(FsWrite {
                target: TracedPath::new(path, PathOrigin::Absolute),
                kind: WriteKind::Open,
                bytes: None,
                flags: None,
                mode: None,
                source: None,
                outcome: Outcome::failed("EACCES"),
            }),
        )
    }

    fn connect_event(backend: Backend, ip: &str, port: u16) -> Event {
        Event::observed(
            EventMeta::observed(2_000, 42, "connect", backend),
            Payload::NetConnect(NetConnect {
                family: AddrFamily::Inet,
                ip: Some(ip.to_string()),
                port: Some(port),
                unix_path: None,
                host: None,
                loopback: false,
                private: false,
                outcome: Outcome::success(),
            }),
        )
    }

    fn spawn_event(backend: Backend, bin: &str) -> Event {
        Event::observed(
            EventMeta::observed(3_000, 42, "execve", backend),
            Payload::ProcSpawn(ProcSpawn {
                bin: Some(bin.to_string()),
                argv: vec![bin.to_string()],
                argv_truncated: false,
                outcome: Outcome::success(),
            }),
        )
    }

    fn dns_event(qname: &str) -> Event {
        Event::observed(
            EventMeta::observed(4_000, 42, "sendmmsg", Backend::Strace),
            Payload::DnsQuery(DnsQuery {
                qname: qname.to_string(),
                qtype: Some(1),
                resolver_ip: Some("127.0.0.53".to_string()),
                outcome: Outcome::success(),
            }),
        )
    }

    fn read_event(backend: Backend, path: &str) -> Event {
        Event::observed(
            EventMeta::observed(5_000, 42, "openat", backend),
            Payload::FsRead(FsRead {
                target: TracedPath::new(path, PathOrigin::Absolute),
                bytes: None,
                outcome: Outcome::success(),
            }),
        )
    }

    fn complete_end(backend: Backend) -> Event {
        Event::framing(
            9_000,
            backend,
            Payload::SessionEnd(SessionEnd::complete(Some(0), 1_000, 1, 1)),
        )
    }

    fn partial_end(backend: Backend) -> Event {
        Event::framing(
            9_000,
            backend,
            Payload::SessionEnd(SessionEnd::partial(
                installscope_core::IncompleteReason::Interrupted,
                Vec::new(),
                None,
                1_000,
                1,
                1,
            )),
        )
    }

    #[test]
    fn identical_behavior_agrees() {
        let strace = vec![
            write_event(Backend::Strace, "/work/a.txt", PathOrigin::Kernel),
            connect_event(Backend::Strace, "104.16.2.34", 443),
            spawn_event(Backend::Strace, "/bin/sh"),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "/work/a.txt", PathOrigin::Absolute),
            connect_event(Backend::Aya, "104.16.2.34", 443),
            spawn_event(Backend::Aya, "/bin/sh"),
            complete_end(Backend::Aya),
        ];

        let report = compare(&strace, &aya);
        assert!(report.passed(), "{}", report.summary());
        assert_eq!(report.agreed.len(), 3);
        assert!(report.differences.is_empty());
    }

    #[test]
    fn path_origin_does_not_affect_comparison() {
        // strace reports PathOrigin::Kernel, aya reports Absolute, for the same path. The origin is
        // metadata about confidence, not about what happened, so it must not create a difference.
        let strace = vec![
            write_event(Backend::Strace, "/work/a.txt", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "/work/a.txt", PathOrigin::Absolute),
            complete_end(Backend::Aya),
        ];
        assert!(compare(&strace, &aya).passed());
    }

    #[test]
    fn a_missing_write_is_a_defect() {
        // THE case the harness exists for. strace saw a write to an absolute path and aya did not:
        // no structural difference explains that, so it fails.
        let strace = vec![
            write_event(Backend::Strace, "/etc/cron.d/evil", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let aya = vec![complete_end(Backend::Aya)];

        let report = compare(&strace, &aya);
        assert!(!report.passed());
        let failures = report.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].seen_by, Backend::Strace);
        assert_eq!(failures[0].expectation, Expectation::Unexpected);
    }

    #[test]
    fn a_missing_connect_is_a_defect() {
        let strace = vec![
            connect_event(Backend::Strace, "1.2.3.4", 443),
            complete_end(Backend::Strace),
        ];
        let aya = vec![complete_end(Backend::Aya)];
        let report = compare(&strace, &aya);
        assert!(!report.passed(), "{}", report.summary());
        assert_eq!(report.failures().len(), 1);
    }

    #[test]
    fn relative_paths_are_an_expected_difference() {
        // aya reads the syscall argument, so a relative open stays relative; strace resolves it. The
        // same write appears under two strings and neither backend is wrong. Documented in the probe
        // module, and enumerated here so widening this allowance is a visible diff.
        let strace = vec![
            write_event(Backend::Strace, "/work/project/rel.txt", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "rel.txt", PathOrigin::Unresolved),
            complete_end(Backend::Aya),
        ];

        let report = compare(&strace, &aya);
        // Two differences — one each way — but both explained, so the run passes.
        assert_eq!(report.differences.len(), 2, "{}", report.summary());
        assert!(report.passed(), "{}", report.summary());
        assert!(report
            .differences
            .iter()
            .all(|d| matches!(d.expectation, Expectation::Expected(_))));
    }

    #[test]
    fn missing_dns_is_an_expected_difference() {
        // The aya backend decodes no DNS. Stated as a non-goal rather than tracked as a bug, so it must
        // not fail parity — but it must still appear as a difference, so a reader sees the gap.
        let strace = vec![
            dns_event("registry.npmjs.org"),
            complete_end(Backend::Strace),
        ];
        let aya = vec![complete_end(Backend::Aya)];

        let report = compare(&strace, &aya);
        assert!(report.passed(), "{}", report.summary());
        assert_eq!(report.differences.len(), 1);
        match &report.differences[0].expectation {
            Expectation::Expected(reason) => assert!(reason.contains("DNS")),
            Expectation::Unexpected => panic!("missing DNS must be expected"),
        }
    }

    #[test]
    fn missing_credential_reads_are_a_permanent_expected_difference() {
        // Decided, not deferred: Phases.md:23 scopes the aya backend to writes, connects, and spawns.
        // Recording reads stays a strace capability, so this difference is expected forever rather than
        // pending work — and it must still appear in the report, because the backends are not
        // interchangeable and a reader needs to know which one saw less.
        let strace = vec![
            read_event(Backend::Strace, "/home/u/.ssh/id_rsa"),
            complete_end(Backend::Strace),
        ];
        let aya = vec![complete_end(Backend::Aya)];

        let report = compare(&strace, &aya);
        assert!(report.passed(), "{}", report.summary());
        assert_eq!(report.differences.len(), 1);
        match &report.differences[0].expectation {
            Expectation::Expected(reason) => assert!(
                reason.contains("by design"),
                "the reason must read as a decision, not a gap: {reason}"
            ),
            Expectation::Unexpected => panic!("a scoped-out capability must not fail parity"),
        }
        // The class still shows in the counts, so the asymmetry is visible rather than invisible.
        let reads = report
            .counts
            .get(&FactClass::FsRead)
            .expect("fs_read counts");
        assert_eq!(reads.strace, 1);
        assert_eq!(reads.aya, 0);
    }

    #[test]
    fn an_extra_spawn_from_aya_is_expected() {
        // eBPF can catch a short-lived process that ptrace missed, and vice versa. Neither direction is
        // a defect; both are timing.
        let strace = vec![complete_end(Backend::Strace)];
        let aya = vec![
            spawn_event(Backend::Aya, "/usr/bin/uname"),
            complete_end(Backend::Aya),
        ];
        let report = compare(&strace, &aya);
        assert!(report.passed(), "{}", report.summary());
    }

    #[test]
    fn an_extra_absolute_write_from_aya_is_a_defect() {
        // The asymmetry is deliberate. An extra *spawn* is timing, but an extra absolute-path write
        // means one backend fabricated or the other missed a filesystem mutation — which is exactly
        // what a report would assert, so it must fail.
        let strace = vec![complete_end(Backend::Strace)];
        let aya = vec![
            write_event(Backend::Aya, "/etc/passwd", PathOrigin::Absolute),
            complete_end(Backend::Aya),
        ];
        let report = compare(&strace, &aya);
        assert!(!report.passed(), "{}", report.summary());
        assert_eq!(report.failures()[0].seen_by, Backend::Aya);
    }

    #[test]
    fn a_partial_input_fails_regardless_of_the_diff() {
        // Two streams could agree perfectly and still prove nothing if one of them stopped early. This
        // is the same refusal as summarize_stream rejecting a stream with no session_end: an incomplete
        // recording is unusable, not merely weaker.
        let strace = vec![
            write_event(Backend::Strace, "/work/a.txt", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "/work/a.txt", PathOrigin::Absolute),
            partial_end(Backend::Aya),
        ];

        let report = compare(&strace, &aya);
        assert!(!report.passed(), "{}", report.summary());
        assert_eq!(report.partial_inputs, vec![Backend::Aya]);
        // No unexplained differences — the failure is entirely the PARTIAL input.
        assert!(report.failures().is_empty());
        assert!(report.summary().contains("not valid"));
    }

    #[test]
    fn a_stream_without_session_end_counts_as_partial() {
        let strace = vec![write_event(Backend::Strace, "/a", PathOrigin::Kernel)];
        let aya = vec![write_event(Backend::Aya, "/a", PathOrigin::Absolute)];
        let report = compare(&strace, &aya);
        assert_eq!(report.partial_inputs.len(), 2);
        assert!(!report.passed());
    }

    #[test]
    fn failed_syscalls_do_not_participate() {
        // A failed open asserts intent, not effect. Error paths differ between backends for reasons
        // unrelated to observation fidelity, so comparing them would produce noise that hides real gaps.
        let strace = vec![
            failed_write_event(Backend::Strace, "/root/.ssh/id_rsa"),
            complete_end(Backend::Strace),
        ];
        let aya = vec![complete_end(Backend::Aya)];
        let report = compare(&strace, &aya);
        assert!(report.passed(), "{}", report.summary());
        assert!(report.differences.is_empty());
    }

    #[test]
    fn byte_counts_do_not_affect_comparison() {
        // strace reports actual bytes, aya reports requested. Including them would fail every
        // comparison for a reason already documented as a structural difference.
        let mut strace_write = write_event(Backend::Strace, "/work/big.bin", PathOrigin::Kernel);
        if let Payload::FsWrite(w) = &mut strace_write.payload {
            w.kind = WriteKind::Write;
            w.bytes = Some(4096);
        }
        let mut aya_write = write_event(Backend::Aya, "/work/big.bin", PathOrigin::Absolute);
        if let Payload::FsWrite(w) = &mut aya_write.payload {
            w.kind = WriteKind::Write;
            w.bytes = Some(8192);
        }

        let report = compare(
            &[strace_write, complete_end(Backend::Strace)],
            &[aya_write, complete_end(Backend::Aya)],
        );
        assert!(report.passed(), "{}", report.summary());
        assert_eq!(report.agreed.len(), 1);
    }

    #[test]
    fn write_kind_differences_are_real_differences() {
        // A mkdir is not an open. Collapsing kinds would let a backend report the wrong operation and
        // still pass, which would make the comparison worthless for exactly the class of bug it should
        // catch.
        let mut strace_write = write_event(Backend::Strace, "/work/d", PathOrigin::Kernel);
        if let Payload::FsWrite(w) = &mut strace_write.payload {
            w.kind = WriteKind::Mkdir;
        }
        let aya_write = write_event(Backend::Aya, "/work/d", PathOrigin::Absolute);

        let report = compare(
            &[strace_write, complete_end(Backend::Strace)],
            &[aya_write, complete_end(Backend::Aya)],
        );
        assert!(!report.passed(), "{}", report.summary());
    }

    #[test]
    fn a_missed_write_cannot_hide_behind_the_relative_path_allowance() {
        // The trap the pairwise check exists to avoid. strace saw an absolute write; aya saw a relative
        // write to a *different* file. Judging each fact alone, the absolute one would be waved through
        // as "probably the resolved form of some relative path" — letting a genuinely missed write pass.
        let strace = vec![
            write_event(
                Backend::Strace,
                "/work/project/real.txt",
                PathOrigin::Kernel,
            ),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "unrelated.txt", PathOrigin::Unresolved),
            complete_end(Backend::Aya),
        ];

        let report = compare(&strace, &aya);
        assert!(
            !report.passed(),
            "a missing write must not be excused by an unrelated relative path: {}",
            report.summary()
        );
        assert_eq!(report.failures().len(), 2, "{}", report.summary());
    }

    #[test]
    fn suffix_matching_requires_a_component_boundary() {
        // "/work/other.txt" must not be treated as the resolved form of "her.txt". Without the boundary
        // check, any path ending in the right letters would excuse a difference.
        let strace = vec![
            write_event(Backend::Strace, "/work/other.txt", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "her.txt", PathOrigin::Unresolved),
            complete_end(Backend::Aya),
        ];
        assert!(!compare(&strace, &aya).passed());
    }

    #[test]
    fn a_relative_pair_with_mismatched_kinds_is_not_excused() {
        // Same filename, different operation: strace saw a mkdir, aya saw an open. The paths pair up but
        // the behaviors do not, and reporting the wrong operation is exactly the bug parity should catch.
        let mut strace_write = write_event(Backend::Strace, "/work/thing", PathOrigin::Kernel);
        if let Payload::FsWrite(w) = &mut strace_write.payload {
            w.kind = WriteKind::Mkdir;
        }
        let aya = vec![
            write_event(Backend::Aya, "thing", PathOrigin::Unresolved),
            complete_end(Backend::Aya),
        ];
        let report = compare(&[strace_write, complete_end(Backend::Strace)], &aya);
        assert!(!report.passed(), "{}", report.summary());
    }

    #[test]
    fn counts_report_shape_per_class() {
        let strace = vec![
            write_event(Backend::Strace, "/a", PathOrigin::Kernel),
            write_event(Backend::Strace, "/b", PathOrigin::Kernel),
            dns_event("x.example"),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "/a", PathOrigin::Absolute),
            complete_end(Backend::Aya),
        ];

        let report = compare(&strace, &aya);
        let writes = report
            .counts
            .get(&FactClass::FsWrite)
            .expect("fs_write counts");
        assert_eq!(writes.strace, 2);
        assert_eq!(writes.aya, 1);
        assert_eq!(writes.shared, 1);

        let dns = report.counts.get(&FactClass::DnsQuery).expect("dns counts");
        assert_eq!(dns.strace, 1);
        assert_eq!(dns.aya, 0);
    }

    #[test]
    fn paths_are_normalized_before_comparison() {
        let strace = vec![
            write_event(Backend::Strace, "/work//sub/../a.txt", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let aya = vec![
            write_event(Backend::Aya, "/work/a.txt", PathOrigin::Absolute),
            complete_end(Backend::Aya),
        ];
        assert!(compare(&strace, &aya).passed());
    }

    #[test]
    fn parse_stream_refuses_a_malformed_line() {
        // Comparing over a stream we could not fully read would be meaningless.
        let good = write_event(Backend::Strace, "/a", PathOrigin::Kernel)
            .to_jsonl()
            .unwrap_or_else(|e| panic!("{e}"));
        let contents = format!("{good}\nnot json at all\n");
        assert!(parse_stream(&contents).is_err());
    }

    #[test]
    fn parse_stream_accepts_a_well_formed_stream() {
        let events = [
            write_event(Backend::Strace, "/a", PathOrigin::Kernel),
            complete_end(Backend::Strace),
        ];
        let contents = events
            .iter()
            .map(|e| e.to_jsonl().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse_stream(&contents).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.len(), 2);
    }
}
