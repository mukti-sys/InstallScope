//! Schema v1 event model — the JSONL contract between recorder backends and everything downstream.
//!
//! Architecture.md §3 fixes the shape: one JSON object per line, tagged by `op`, carrying
//! `schema_version: 1`. This module is the authority on that schema, and it is deliberately free of
//! I/O so both the strace backend (Phase 1) and the aya backend (Phase 2) serialize identically.
//!
//! # Resolving the Phase 0 harness deviations
//!
//! The G2 harness (harness/g2/README.md) deviated from Architecture.md §3 in three ways and left the
//! decision to Phase 1. Decided here:
//!
//! 1. **`ts_ns` is session-relative** — promoted into the schema. Epoch nanoseconds exceed the
//!    IEEE-754 safe integer range that JSON consumers assume, so a JS reader would silently corrupt
//!    them. Absolute time is preserved once, in [`SessionStart::wall_clock_utc`], which makes every
//!    event's wall-clock time recoverable without putting a lossy integer on every line.
//! 2. **`dns_query`** — promoted. strace cannot attribute a TCP connect to a hostname, so without
//!    this every network finding degrades to a bare IP and is useless in a report. Architecture.md
//!    §4 already scores "DNS to newly-registered/lookalike domain", which presumes such an event.
//! 3. **`pid`/`syscall` on events** — promoted, as [`EventMeta`]. Evidence a reader cannot trace
//!    back to a specific syscall in a specific process is an assertion, not evidence.
//!
//! One harness gap is closed rather than promoted: the harness did not trace `write`, so it could
//! not produce byte volumes, making Design.md:35's "wrote ~13 MB outside project dir" impossible.
//! [`FsWrite::bytes`] exists for that, and the recorder now traces write syscalls.

use serde::{Deserialize, Serialize};

/// The only schema version this build emits or accepts.
pub const SCHEMA_VERSION: u32 = 1;

/// Which recorder produced an event. Stamped on every event so a mixed-backend stream (Phase 2
/// merges aya and strace) stays attributable, and so a parity test can compare like with like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// The v1.0 backend: `strace -f -ff` (Architecture.md:35).
    Strace,
    /// Phase 2, gated on G1 (which passed; see Memory.md).
    Aya,
}

impl Backend {
    /// The wire string, matching the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strace => "strace",
            Self::Aya => "aya",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provenance carried by every event: when, which process, which syscall, which backend.
///
/// `pid` and `syscall` are absent on framing events (`session_start`, `heartbeat`, `session_end`),
/// which are recorder bookkeeping rather than observations of a traced syscall. `ts_ns` and `backend`
/// are always present — Architecture.md:50-51 shows both `heartbeat` and `session_end` carrying
/// `ts_ns`, and knowing which backend wrote a line matters most precisely when a stream is truncated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMeta {
    /// Nanoseconds since [`SessionStart::wall_clock_utc`]. Session-relative on purpose; see the
    /// module docs.
    pub ts_ns: u64,
    /// Observing process id. `None` on framing events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// The syscall this observation came from (`openat`, `connect`, …). Kept as a string because the
    /// set differs per backend and a closed enum would force lossy mapping. `None` on framing events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscall: Option<String>,
    /// Which recorder observed this.
    pub backend: Backend,
}

impl EventMeta {
    /// Provenance for an observed syscall.
    #[must_use]
    pub fn observed(ts_ns: u64, pid: u32, syscall: impl Into<String>, backend: Backend) -> Self {
        Self {
            ts_ns,
            pid: Some(pid),
            syscall: Some(syscall.into()),
            backend,
        }
    }

    /// Provenance for a framing event, which belongs to the recorder rather than to a syscall.
    #[must_use]
    pub const fn framing(ts_ns: u64, backend: Backend) -> Self {
        Self {
            ts_ns,
            pid: None,
            syscall: None,
            backend,
        }
    }
}

/// Whether the observed syscall succeeded.
///
/// A *failed* operation is still evidence — an attempt to read `~/.ssh/id_rsa` that returns ENOENT
/// says something about intent — so failures are recorded, marked, and scored lower rather than
/// dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// `None` when the backend could not determine success (e.g. a detached syscall).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    /// Errno symbol (`ENOENT`, `EACCES`, …) when the syscall failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Outcome {
    /// The syscall succeeded.
    #[must_use]
    pub const fn success() -> Self {
        Self {
            ok: Some(true),
            error: None,
        }
    }

    /// Success could not be determined.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            ok: None,
            error: None,
        }
    }

    /// The syscall failed with `errno`.
    #[must_use]
    pub fn failed(errno: impl Into<String>) -> Self {
        Self {
            ok: Some(false),
            error: Some(errno.into()),
        }
    }

    /// True when the operation is known to have failed. Distinct from `!succeeded()`, which would
    /// also swallow the unknown case.
    #[must_use]
    pub fn failed_known(&self) -> bool {
        self.ok == Some(false)
    }
}

/// How a path was arrived at. The rules engine must not treat a guess as a fact, so provenance
/// travels with the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOrigin {
    /// The kernel's own resolved path (strace `-yy` annotation, or an aya `d_path`). Most reliable.
    Kernel,
    /// Absolute in the syscall arguments.
    Absolute,
    /// Joined from a `dirfd` whose path was known. Reliable only if the fd table was correct.
    ResolvedFromDirfd,
    /// Relative with no known base. **Must not be classified as inside or outside any directory** —
    /// a plausible-looking guess here would fabricate a critical finding.
    Unresolved,
}

/// A filesystem path plus how confident we are in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracedPath {
    /// The path as observed or reconstructed.
    pub path: String,
    /// How the path was arrived at.
    pub origin: PathOrigin,
}

impl TracedPath {
    /// Builds a traced path with explicit provenance.
    #[must_use]
    pub fn new(path: impl Into<String>, origin: PathOrigin) -> Self {
        Self {
            path: path.into(),
            origin,
        }
    }

    /// True when the path can be reasoned about positionally (i.e. is absolute and trustworthy).
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self.origin, PathOrigin::Unresolved) && self.path.starts_with('/')
    }
}

/// The kind of mutation a write-class syscall performed.
///
/// `Ord` is derived so callers can put these in sorted collections — the parity harness needs a total
/// order to compare fact sets deterministically. The ordering itself carries no meaning; do not read
/// severity into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteKind {
    /// Opened with write intent (`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`/`O_APPEND`).
    Open,
    /// Bytes actually written (`write`, `pwrite64`, `writev`). Carries [`FsWrite::bytes`].
    Write,
    /// `creat`.
    Create,
    /// `truncate`.
    Truncate,
    /// `mkdir`, `mkdirat`.
    Mkdir,
    /// `rename`, `renameat`, `renameat2`.
    Rename,
    /// `unlink`, `unlinkat`, `rmdir`.
    Delete,
    /// `symlink`, `symlinkat`.
    Symlink,
    /// `link`, `linkat`.
    Hardlink,
    /// `chmod`, `fchmodat`.
    Chmod,
    /// `chown`, `lchown`, `fchownat`.
    Chown,
}

/// A filesystem mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsWrite {
    /// What was written to.
    pub target: TracedPath,
    /// Which kind of mutation.
    pub kind: WriteKind,
    /// Bytes written, for [`WriteKind::Write`]. Closes the harness gap that made byte-volume
    /// findings impossible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Open flags as reported by the backend, for evidence display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    /// Mode argument for chmod, or creation mode for open/mkdir.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Source path for rename/link/symlink.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<TracedPath>,
    /// Whether the syscall succeeded.
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// A read of a path the rules engine cares about.
///
/// Deliberately *not* every read: recording all of them would bury the evidence under npm's own
/// traffic and inflate artifacts by orders of magnitude. The recorder filters to credential-bearing
/// and environment-bearing paths; the filter list lives in the recorder, not in the schema, so it
/// can tighten without a schema bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsRead {
    /// What was read.
    pub target: TracedPath,
    /// Bytes read, when the backend tracks it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Whether the syscall succeeded. A failed read of a credential path is still evidence.
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// Address family of a socket operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddrFamily {
    /// IPv4.
    Inet,
    /// IPv6.
    Inet6,
    /// Unix domain socket.
    Unix,
    /// Anything else (netlink, packet, …).
    Other,
}

/// An outbound connection attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConnect {
    /// Address family of the destination.
    pub family: AddrFamily,
    /// Destination address, for inet families.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Destination port, for inet families.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Unix socket path, when `family` is [`AddrFamily::Unix`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_path: Option<String>,
    /// Hostname, only when the backend can *prove* the association.
    ///
    /// The strace backend leaves this `None` — it observes DNS queries and TCP connects as separate
    /// syscalls and cannot join them without guessing. Correlating them heuristically would attach a
    /// hostname to the wrong connection, and an evidence tool that does that is worthless.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Loopback destination. Not a finding, but needed so the rules engine can exclude it.
    pub loopback: bool,
    /// RFC1918 / link-local / unique-local destination.
    pub private: bool,
    /// Whether the connect succeeded. `EINPROGRESS` counts as success.
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// A DNS question observed on the wire. Promoted from the harness; see module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Fully-qualified name as it appeared in the question section. Never a partial decode: a
    /// truncated payload produces no event at all rather than a shortened name.
    pub qname: String,
    /// DNS record type from the question section (1 = A, 28 = AAAA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qtype: Option<u16>,
    /// Resolver the query was sent to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolver_ip: Option<String>,
    /// Whether the send succeeded.
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// A process execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcSpawn {
    /// Executable path as passed to the exec syscall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bin: Option<String>,
    /// Argument vector. Empty when the backend could not read it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    /// True when the backend's buffer cut argv short. A rule that pattern-matches a command line
    /// must know whether it saw all of it.
    pub argv_truncated: bool,
    /// Whether the exec succeeded.
    #[serde(flatten)]
    pub outcome: Outcome,
}

impl ProcSpawn {
    /// Best-effort single-line rendering for report bullets. Not used for matching — rules match on
    /// [`Self::argv`], because joining then re-splitting a command line loses quoting.
    #[must_use]
    pub fn command_line(&self) -> String {
        if self.argv.is_empty() {
            return self.bin.clone().unwrap_or_default();
        }
        self.argv.join(" ")
    }
}

/// Opening record of a session. Carries everything needed to interpret the events that follow, and
/// everything needed to reproduce the recording.
///
/// Note there is no `backend` field: [`EventMeta::backend`] already carries it on every line,
/// including this one, and duplicating it would create two places for them to disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStart {
    /// RFC3339 UTC instant that `ts_ns: 0` refers to.
    pub wall_clock_utc: String,
    /// Recorder version, so a later re-analysis knows what produced the stream.
    pub agent_version: String,
    /// The command that was recorded, unjoined.
    pub command: Vec<String>,
    /// Directories that give paths their meaning. The rules engine classifies against these rather
    /// than against hardcoded assumptions, which is what makes a recording portable between a
    /// runner and a laptop.
    pub zones: Zones,
    /// Facts about the recording machine, so runner behavior is never mistaken for package behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostInfo>,
}

/// Expected write locations for a recording.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Zones {
    /// The project being installed into.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Package manager cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<String>,
    /// `HOME` for the recorded process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// `TMPDIR` for the recorded process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmp: Option<String>,
    /// Additional expected prefixes (toolchain dirs, store paths).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
}

/// Facts about the recording machine. Recorded so runner behavior is never mistaken for package
/// behavior when a receipt is disputed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HostInfo {
    /// `uname -r`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Distribution pretty name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// CPU architecture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Version of the tracing backend (e.g. the `strace -V` line).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_version: Option<String>,
}

/// Periodic liveness marker (Rules.md §2). A stream whose heartbeats stop before `session_end`
/// proves the recorder died rather than the install being quiet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Monotonically increasing from 1.
    pub seq: u64,
    /// Events emitted so far, so a truncated stream reveals how much was lost.
    pub events_so_far: u64,
    /// Coarse phase label when the recorder can infer one (`resolve`, `fetch`, `postinstall`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

/// Why a recording is incomplete. Enumerated rather than free text so the report can render a cause
/// instead of a shrug, and so a new failure mode cannot silently reuse an existing message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    /// The backend process never started.
    BackendFailedToStart {
        /// Why it could not start.
        detail: String,
    },
    /// The backend died before the traced command finished.
    BackendDied {
        /// How it died.
        detail: String,
    },
    /// Wall-clock budget exhausted.
    Timeout {
        /// The limit that was hit.
        limit_secs: u64,
    },
    /// The event cap fired; the stream is a prefix of reality.
    EventCapReached {
        /// The cap that was hit.
        cap: u64,
    },
    /// Trace output could not be fully parsed.
    ParseErrors {
        /// How many lines failed to parse.
        count: u64,
    },
    /// Trace output was truncated by the backend itself.
    TraceTruncated {
        /// What was truncated.
        detail: String,
    },
    /// Recorder was interrupted (SIGINT/SIGTERM).
    Interrupted,
    /// Anything not covered above. Carries detail so it is still actionable.
    Other {
        /// What went wrong.
        detail: String,
    },
}

impl std::fmt::Display for IncompleteReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendFailedToStart { detail } => {
                write!(f, "recorder backend failed to start: {detail}")
            }
            Self::BackendDied { detail } => write!(f, "recorder backend died: {detail}"),
            Self::Timeout { limit_secs } => write!(f, "exceeded {limit_secs}s time limit"),
            Self::EventCapReached { cap } => {
                write!(f, "event cap of {cap} reached; stream is truncated")
            }
            Self::ParseErrors { count } => write!(f, "{count} unparseable trace lines"),
            Self::TraceTruncated { detail } => write!(f, "trace output truncated: {detail}"),
            Self::Interrupted => f.write_str("recording interrupted"),
            Self::Other { detail } => f.write_str(detail),
        }
    }
}

/// Closing record. Its absence, or `complete: false`, forces a PARTIAL badge downstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
    /// True only when the recording is whole. Anything else must render as PARTIAL.
    pub complete: bool,
    /// Empty exactly when `complete` is true.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incomplete_reasons: Vec<IncompleteReason>,
    /// Exit status of the recorded command. `None` when it never ran or was killed by a signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_exit_code: Option<i32>,
    /// Signal that killed the recorded command, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_signal: Option<i32>,
    /// Wall-clock duration of the recording.
    pub duration_ns: u64,
    /// Observations written, excluding framing events.
    pub events_emitted: u64,
    /// Heartbeats written.
    pub heartbeats: u64,
}

impl SessionEnd {
    /// A clean end. `complete: true` is only reachable through this constructor plus an explicitly
    /// empty reason list, so "complete with reasons" cannot be constructed by accident.
    #[must_use]
    pub const fn complete(
        command_exit_code: Option<i32>,
        duration_ns: u64,
        events_emitted: u64,
        heartbeats: u64,
    ) -> Self {
        Self {
            complete: true,
            incomplete_reasons: Vec::new(),
            command_exit_code,
            command_signal: None,
            duration_ns,
            events_emitted,
            heartbeats,
        }
    }

    /// An incomplete end. Takes a non-empty reason list by construction: `partial` with no reason
    /// would tell a user their evidence is untrustworthy without saying why.
    #[must_use]
    pub fn partial(
        first_reason: IncompleteReason,
        rest: Vec<IncompleteReason>,
        command_exit_code: Option<i32>,
        duration_ns: u64,
        events_emitted: u64,
        heartbeats: u64,
    ) -> Self {
        let mut incomplete_reasons = Vec::with_capacity(rest.len() + 1);
        incomplete_reasons.push(first_reason);
        incomplete_reasons.extend(rest);
        Self {
            complete: false,
            incomplete_reasons,
            command_exit_code,
            command_signal: None,
            duration_ns,
            events_emitted,
            heartbeats,
        }
    }
}

/// One line of a recording.
///
/// `#[serde(tag = "op")]` matches Architecture.md §3's `{"op":"fs_write",…}` shape. Deserialization
/// of an unknown `op` fails loudly rather than being skipped, because a reader that ignores events
/// it does not understand reports a cleaner install than actually occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Payload {
    /// Opening framing event.
    SessionStart(SessionStart),
    /// A filesystem mutation.
    FsWrite(FsWrite),
    /// A read of a path the rules engine cares about.
    FsRead(FsRead),
    /// An outbound connection attempt.
    NetConnect(NetConnect),
    /// A DNS question observed on the wire.
    DnsQuery(DnsQuery),
    /// A process execution.
    ProcSpawn(ProcSpawn),
    /// Liveness marker.
    Heartbeat(Heartbeat),
    /// Closing framing event; carries the PARTIAL decision.
    SessionEnd(SessionEnd),
}

impl Payload {
    /// The `op` discriminant, for grouping and metrics without a match at every call site.
    #[must_use]
    pub const fn op(&self) -> &'static str {
        match self {
            Self::SessionStart(_) => "session_start",
            Self::FsWrite(_) => "fs_write",
            Self::FsRead(_) => "fs_read",
            Self::NetConnect(_) => "net_connect",
            Self::DnsQuery(_) => "dns_query",
            Self::ProcSpawn(_) => "proc_spawn",
            Self::Heartbeat(_) => "heartbeat",
            Self::SessionEnd(_) => "session_end",
        }
    }

    /// True for the framing events, which are recorder bookkeeping rather than observations of the
    /// traced program.
    #[must_use]
    pub const fn is_framing(&self) -> bool {
        matches!(
            self,
            Self::SessionStart(_) | Self::SessionEnd(_) | Self::Heartbeat(_)
        )
    }
}

/// A complete event: schema version, provenance, payload.
///
/// `schema_version` is on every line, not just the header, so a partial or concatenated stream is
/// still self-describing — which matters because a truncated recording is exactly the case where
/// interpretation must not go wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Always [`SCHEMA_VERSION`] on emit; verified on parse.
    pub schema_version: u32,
    /// When, where, and by which backend this was observed.
    #[serde(flatten)]
    pub meta: EventMeta,
    /// The observation itself.
    #[serde(flatten)]
    pub payload: Payload,
}

impl Event {
    /// An observation, with full syscall provenance.
    #[must_use]
    pub fn observed(meta: EventMeta, payload: Payload) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            meta,
            payload,
        }
    }

    /// A framing event: carries a timestamp and a backend, but no syscall provenance.
    #[must_use]
    pub const fn framing(ts_ns: u64, backend: Backend, payload: Payload) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            meta: EventMeta::framing(ts_ns, backend),
            payload,
        }
    }

    /// Serializes to a single JSONL line, without the trailing newline.
    ///
    /// # Errors
    /// [`crate::CoreError::Serialize`] if the event cannot be represented as JSON.
    pub fn to_jsonl(&self) -> crate::Result<String> {
        serde_json::to_string(self).map_err(crate::CoreError::from)
    }

    /// Parses one JSONL line, rejecting unknown schema versions rather than guessing.
    ///
    /// # Errors
    /// [`crate::CoreError::MalformedEvent`] if the line is not a valid event, including an unknown
    /// `op`; [`crate::CoreError::UnsupportedSchemaVersion`] if it declares a schema this build does
    /// not understand. Both are refusals rather than best-effort interpretations, because a reader
    /// that guesses reports a cleaner install than actually occurred.
    pub fn from_jsonl(line: &str, line_number: usize) -> crate::Result<Self> {
        let event: Self =
            serde_json::from_str(line).map_err(|source| crate::CoreError::MalformedEvent {
                line: line_number,
                source,
            })?;
        if event.schema_version != SCHEMA_VERSION {
            return Err(crate::CoreError::UnsupportedSchemaVersion {
                found: event.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> EventMeta {
        EventMeta::observed(1_719, 4242, "openat", Backend::Strace)
    }

    #[test]
    fn fs_write_matches_architecture_shape() {
        // Architecture.md:47 — {"ts_ns":1719,"op":"fs_write","path":...,"backend":"strace"}
        let event = Event::observed(
            meta(),
            Payload::FsWrite(FsWrite {
                target: TracedPath::new("/home/runner/.ssh/authorized_keys", PathOrigin::Kernel),
                kind: WriteKind::Open,
                bytes: None,
                flags: Some("O_WRONLY|O_CREAT".to_string()),
                mode: None,
                source: None,
                outcome: Outcome::success(),
            }),
        );
        let line = event.to_jsonl().expect("serialize");
        let json: serde_json::Value = serde_json::from_str(&line).expect("valid json");

        assert_eq!(json["op"], "fs_write");
        assert_eq!(json["ts_ns"], 1_719);
        assert_eq!(json["backend"], "strace");
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["target"]["path"], "/home/runner/.ssh/authorized_keys");
    }

    #[test]
    fn round_trips_every_payload_variant() {
        let payloads = vec![
            Payload::SessionStart(SessionStart {
                wall_clock_utc: "2026-08-29T12:00:00Z".to_string(),
                agent_version: "test".to_string(),
                command: vec!["npm".to_string(), "install".to_string()],
                zones: Zones::default(),
                host: None,
            }),
            Payload::FsWrite(FsWrite {
                target: TracedPath::new("/tmp/x", PathOrigin::Absolute),
                kind: WriteKind::Write,
                bytes: Some(13_631_488),
                flags: None,
                mode: None,
                source: None,
                outcome: Outcome::success(),
            }),
            Payload::FsRead(FsRead {
                target: TracedPath::new("/home/u/.aws/credentials", PathOrigin::Absolute),
                bytes: None,
                outcome: Outcome::failed("ENOENT"),
            }),
            Payload::NetConnect(NetConnect {
                family: AddrFamily::Inet,
                ip: Some("1.2.3.4".to_string()),
                port: Some(443),
                unix_path: None,
                host: None,
                loopback: false,
                private: false,
                outcome: Outcome::success(),
            }),
            Payload::DnsQuery(DnsQuery {
                qname: "telemetry.example".to_string(),
                qtype: Some(1),
                resolver_ip: Some("127.0.0.53".to_string()),
                outcome: Outcome::success(),
            }),
            Payload::ProcSpawn(ProcSpawn {
                bin: Some("/bin/sh".to_string()),
                argv: vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "curl x | sh".to_string(),
                ],
                argv_truncated: false,
                outcome: Outcome::success(),
            }),
            Payload::Heartbeat(Heartbeat {
                seq: 3,
                events_so_far: 900,
                phase: Some("postinstall".to_string()),
            }),
            Payload::SessionEnd(SessionEnd::complete(Some(0), 1_000, 900, 3)),
        ];

        for payload in payloads {
            let op = payload.op();
            let event = if payload.is_framing() {
                Event::framing(4_242, Backend::Strace, payload)
            } else {
                Event::observed(meta(), payload)
            };
            let line = event.to_jsonl().expect("serialize");
            let back = Event::from_jsonl(&line, 1).expect("deserialize");
            assert_eq!(event, back, "round trip failed for {op}");
        }
    }

    #[test]
    fn framing_events_omit_syscall_provenance() {
        // A heartbeat did not come from a syscall, so claiming a pid and a syscall name for it would
        // be inventing provenance. ts_ns and backend stay, per Architecture.md:50-51.
        let event = Event::framing(
            99,
            Backend::Strace,
            Payload::Heartbeat(Heartbeat {
                seq: 1,
                events_so_far: 0,
                phase: None,
            }),
        );
        let line = event.to_jsonl().expect("serialize");
        let json: serde_json::Value = serde_json::from_str(&line).expect("valid json");

        assert_eq!(json["ts_ns"], 99);
        assert_eq!(json["backend"], "strace");
        assert!(json.get("pid").is_none(), "framing events have no pid");
        assert!(
            json.get("syscall").is_none(),
            "framing events have no syscall"
        );
    }

    #[test]
    fn rejects_unknown_schema_version() {
        // A future stream must not be silently reinterpreted by an older build.
        let line = r#"{"schema_version":99,"ts_ns":1,"backend":"strace","op":"heartbeat","seq":1,"events_so_far":0}"#;
        let err = Event::from_jsonl(line, 7).expect_err("must reject");
        assert!(
            matches!(
                err,
                crate::CoreError::UnsupportedSchemaVersion {
                    found: 99,
                    supported: 1
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_op_instead_of_skipping() {
        // Silently ignoring an unknown op would under-report behavior, i.e. render a dirtier
        // install as cleaner. That is the failure direction that matters.
        let line = r#"{"schema_version":1,"op":"quantum_teleport","ts_ns":1,"pid":1,"syscall":"x","backend":"strace"}"#;
        let err = Event::from_jsonl(line, 3).expect_err("must reject");
        assert!(matches!(
            err,
            crate::CoreError::MalformedEvent { line: 3, .. }
        ));
    }

    #[test]
    fn complete_session_end_has_no_reasons() {
        let end = SessionEnd::complete(Some(0), 1, 2, 3);
        assert!(end.complete);
        assert!(end.incomplete_reasons.is_empty());
    }

    #[test]
    fn partial_session_end_always_carries_a_reason() {
        let end = SessionEnd::partial(
            IncompleteReason::Timeout { limit_secs: 300 },
            vec![IncompleteReason::ParseErrors { count: 4 }],
            None,
            1,
            2,
            3,
        );
        assert!(!end.complete);
        assert_eq!(end.incomplete_reasons.len(), 2);
        assert_eq!(
            end.incomplete_reasons[0].to_string(),
            "exceeded 300s time limit"
        );
    }

    #[test]
    fn unresolved_paths_are_never_considered_resolved() {
        // The rules engine keys "write outside expected dirs" (critical, x40) off resolvability.
        // A relative path that leaked through as resolved would manufacture critical findings.
        let relative = TracedPath::new("node_modules/x", PathOrigin::Unresolved);
        assert!(!relative.is_resolved());

        // Even an absolute-looking path is untrusted when its origin is Unresolved.
        let lying = TracedPath::new("/etc/passwd", PathOrigin::Unresolved);
        assert!(!lying.is_resolved());

        assert!(TracedPath::new("/etc/passwd", PathOrigin::Kernel).is_resolved());
    }

    #[test]
    fn failed_outcome_is_distinguishable_from_unknown() {
        assert!(Outcome::failed("EACCES").failed_known());
        assert!(!Outcome::unknown().failed_known());
        assert!(!Outcome::success().failed_known());
    }

    #[test]
    fn outcome_omits_absent_fields() {
        let line = serde_json::to_string(&Outcome::unknown()).expect("serialize");
        assert_eq!(line, "{}", "unknown outcome must not emit null noise");
    }
}
