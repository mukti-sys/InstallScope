//! strace line parser — trace text in, schema v1 events out.
//!
//! Deliberately pure: [`Parser::feed_line`] takes a `&str` and returns events. No I/O, no process
//! control, no platform assumptions. That is what lets the parser be tested exhaustively on any
//! host, which matters because the recorder itself only runs on Linux.
//!
//! # Traced syscalls, and why
//!
//! Writes: `openat`, `open`, `creat`, `truncate`, `write`, `pwrite64`, `writev`, `rename*`,
//! `unlink*`, `mkdir*`, `rmdir`, `chmod`, `fchmodat`, `chown*`, `link*`, `symlink*`.
//! Network: `connect`, `sendto`, `sendmsg`.
//! Process: `execve`, `execveat`, `clone`, `clone3`, `fork`, `vfork`.
//! Bookkeeping: `close`, `chdir`, `fchdir`, `dup`, `dup2`, `dup3`.
//!
//! `write` is traced here, unlike in the Phase 0 harness. The harness omitted it to keep traces
//! small, at the documented cost of having no byte counts — which made Design.md:35's "wrote ~13 MB
//! outside project dir" impossible to produce. Byte accounting is a Phase 1 requirement, so writes
//! are traced and aggregated per descriptor.
//!
//! Reads are filtered to credential- and environment-bearing paths. Recording every read would bury
//! the evidence under npm's own traffic; the filter list lives here rather than in the schema so it
//! can tighten without a schema bump.

use std::collections::HashMap;

use installscope_core::{
    AddrFamily, Backend, DnsQuery, Event, EventMeta, FsRead, FsWrite, NetConnect, Outcome,
    PathOrigin, Payload, ProcSpawn, TracedPath, WriteKind,
};

use crate::decode::{
    self, fd_annotation, fd_number, parse_dns_question, parse_ret, parse_sockaddr, quoted_to_path,
    read_quoted, split_args, SockFamily,
};
use crate::fdtable::{FdTable, FdTarget};

/// Counters describing how well parsing went. Feeds the PARTIAL decision: a stream with unparsed
/// lines is not a whole stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Lines read from trace files.
    pub lines_seen: u64,
    /// Lines recognized as a syscall.
    pub lines_parsed: u64,
    /// Lines that could not be interpreted. Non-zero forces PARTIAL.
    pub parse_errors: u64,
    /// `<unfinished ...>` entries that never got a matching `resumed` line, usually because the
    /// process died mid-syscall.
    pub unmatched_unfinished: u64,
    /// Signal-delivery notices.
    pub signals: u64,
    /// Process-exit notices.
    pub exits: u64,
    /// DNS payloads that could not be decoded without guessing. Counted, never guessed at.
    pub dns_undecodable: u64,
    /// strace's own diagnostic lines (`strace: Process N attached`, and similar). Not syscalls and
    /// not errors; counted so the total accounts for every line read.
    pub diagnostics: u64,
    /// Diagnostics that specifically report strace losing data. Unlike ordinary chatter these do
    /// force PARTIAL, because the stream is then genuinely missing events.
    pub diagnostic_data_loss: u64,
    /// Events produced.
    pub events_emitted: u64,
}

/// True for strace's own commentary rather than a traced syscall.
///
/// These are unavoidable in real output: `-f` announces every process it attaches to, so any install
/// that spawns a child produces them. The list is matched conservatively — an unrecognized line still
/// counts as a parse error, because quietly accepting anything would hide a genuine format change.
fn is_strace_diagnostic(line: &str) -> bool {
    let trimmed = line.trim_start();
    // strace's own messages are prefixed with the program name.
    if trimmed.starts_with("strace:") {
        return true;
    }
    // Older builds emit these without the prefix.
    if trimmed.starts_with("Process ")
        && (trimmed.contains(" attached") || trimmed.contains(" detached"))
    {
        return true;
    }
    // `<pid> +++ killed by SIGKILL +++` is handled by the +++ path; this covers the bare form some
    // builds print when the tracee is killed before any syscall is recorded.
    if trimmed.starts_with("killed by SIG") {
        return true;
    }
    false
}

/// True when a diagnostic reports lost trace data rather than routine bookkeeping.
///
/// The distinction matters: `Process 123 attached` is noise, but `... detached` mid-recording or an
/// out-of-memory message means the stream is incomplete, and a recording that lost events must never
/// render as clean (`Rules.md` §2).
fn diagnostic_indicates_data_loss(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "detaching",
        "out of memory",
        "cannot allocate",
        "could not write",
        "write error",
        "umovestr",
        "invalid",
        "unavailable",
        "lost",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Paths whose *reads* are worth recording.
const CREDENTIAL_READ_PATTERNS: &[&str] = &[
    "/.ssh/",
    "/.aws/",
    "/.netrc",
    "/.npmrc",
    "/.yarnrc",
    "/.docker/config.json",
    "/.git-credentials",
    "/.gitconfig",
    "/.kube/",
    "/.config/gcloud/",
    "/etc/shadow",
    "/etc/passwd",
];

/// Filenames whose reads are interesting regardless of directory.
const CREDENTIAL_READ_BASENAMES: &[&str] = &[
    ".env",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    ".npmrc",
];

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// True when a read of `path` should be recorded.
fn is_read_of_interest(path: &str) -> bool {
    if CREDENTIAL_READ_PATTERNS.iter().any(|p| path.contains(p)) {
        return true;
    }
    let base = basename(path);
    if CREDENTIAL_READ_BASENAMES.contains(&base) {
        return true;
    }
    // .env.production, .env.local, …
    if base.starts_with(".env") {
        return true;
    }
    // The process environment of any pid, which is how env-harvesting shows up.
    if path.starts_with("/proc/") && path.ends_with("/environ") {
        return true;
    }
    false
}

/// Open flags that indicate write intent.
fn has_write_intent(flags: &str) -> bool {
    ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]
        .iter()
        .any(|f| flags.contains(f))
}

/// A syscall awaiting its `<... name resumed>` line.
#[derive(Debug, Clone)]
struct Pending {
    ts_ns: u64,
    name: String,
    args_head: String,
}

/// Accumulated write volume for one descriptor.
#[derive(Debug, Clone)]
struct WriteAccumulator {
    target: TracedPath,
    bytes: u64,
    calls: u64,
    /// Last timestamp seen, so the flushed event lands at the end of the write burst.
    last_ts_ns: u64,
    pid: u32,
}

/// Parses `strace -f -ff -ttt -yy` output into schema v1 events.
///
/// One parser instance handles one session. Feed lines in order; call [`Parser::finish`] at the end
/// to flush accumulated byte counts.
#[derive(Debug)]
pub struct Parser {
    /// Epoch seconds the session started, used to make `ts_ns` session-relative.
    start_epoch_secs: f64,
    fds: FdTable,
    /// Pending unfinished syscalls, keyed by (pid, syscall name).
    pending: HashMap<(u32, String), Pending>,
    /// Write byte accumulation, keyed by (pid, fd).
    writes: HashMap<(u32, i32), WriteAccumulator>,
    stats: ParseStats,
    /// Hard cap on emitted events; a pathological install must not produce an unusable artifact.
    event_cap: u64,
    cap_reached: bool,
}

/// Default event cap. Chosen so a normal install (the Phase 0 corpus ran well under this) never
/// trips it, while a runaway one still produces a bounded artifact.
pub const DEFAULT_EVENT_CAP: u64 = 500_000;

impl Parser {
    /// Creates a parser for a session that began at `start_epoch_secs`.
    #[must_use]
    pub fn new(start_epoch_secs: f64) -> Self {
        Self {
            start_epoch_secs,
            fds: FdTable::new(),
            pending: HashMap::new(),
            writes: HashMap::new(),
            stats: ParseStats::default(),
            event_cap: DEFAULT_EVENT_CAP,
            cap_reached: false,
        }
    }

    /// Overrides the event cap.
    #[must_use]
    pub fn with_event_cap(mut self, cap: u64) -> Self {
        self.event_cap = cap;
        self
    }

    /// Seeds the working directory of the root process, so its relative paths resolve.
    pub fn seed_cwd(&mut self, pid: u32, dir: impl Into<String>) {
        self.fds.seed_cwd(pid, dir);
    }

    /// Parse counters, which feed the PARTIAL decision.
    #[must_use]
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// True when the event cap fired, which forces PARTIAL.
    #[must_use]
    pub const fn cap_reached(&self) -> bool {
        self.cap_reached
    }

    fn ts_ns(&self, epoch_secs: f64) -> u64 {
        let delta = epoch_secs - self.start_epoch_secs;
        if delta <= 0.0 {
            return 0;
        }
        // Saturating on purpose: a clock jump must not panic a recorder mid-install. The f64
        // intermediate is fine here — nanosecond precision within an install's duration is far below
        // the mantissa limit, and the value is only ever a relative timestamp.
        let nanos = delta * 1e9;
        if nanos >= 18_446_744_073_709_551_615.0_f64 {
            u64::MAX
        } else {
            // Sign and range are both established above.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                nanos as u64
            }
        }
    }

    fn meta(ts_ns: u64, pid: u32, syscall: &str) -> EventMeta {
        EventMeta::observed(ts_ns, pid, syscall, Backend::Strace)
    }

    /// Feeds one line of strace output, returning any events it produced.
    ///
    /// `default_pid` is the pid implied by the trace file name (`trace.<pid>` under `-ff`); a pid
    /// prefix on the line itself takes precedence.
    pub fn feed_line(&mut self, line: &str, default_pid: u32) -> Vec<Event> {
        self.stats.lines_seen += 1;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Vec::new();
        }

        // strace's own diagnostics, not syscalls. Recognized explicitly and counted separately,
        // because treating them as parse errors would force PARTIAL on essentially every real
        // recording: `strace: Process N attached` appears whenever an install spawns a child, which
        // every npm install does. A recorder that cried wolf on all valid output would make the
        // PARTIAL badge meaningless, which is worse than not having one.
        if is_strace_diagnostic(line) {
            self.stats.diagnostics += 1;
            // A few diagnostics are not merely noise: they say strace lost data. Those must reach
            // the PARTIAL decision rather than being filed as chatter.
            if diagnostic_indicates_data_loss(line) {
                self.stats.diagnostic_data_loss += 1;
                tracing::warn!(line, "strace reported losing trace data");
            }
            return Vec::new();
        }

        let (pid, ts_and_rest) = split_pid_prefix(line, default_pid);
        let Some((ts, rest)) = split_timestamp(ts_and_rest) else {
            // Lines without a timestamp are exit/signal notices in some strace builds.
            if ts_and_rest.contains("+++") {
                self.stats.exits += 1;
                self.fds.process_exited(pid);
            } else if ts_and_rest.contains("---") {
                self.stats.signals += 1;
            } else {
                self.stats.parse_errors += 1;
                tracing::debug!(line, "unparseable trace line");
            }
            return Vec::new();
        };

        let ts_ns = self.ts_ns(ts);

        if rest.starts_with("+++") {
            self.stats.exits += 1;
            let flushed = self.flush_pid_writes(pid);
            self.fds.process_exited(pid);
            return flushed;
        }
        if rest.starts_with("---") {
            self.stats.signals += 1;
            return Vec::new();
        }

        // `<... openat resumed>` completes an earlier `<unfinished ...>`.
        if let Some(resumed) = parse_resumed(rest) {
            let key = (pid, resumed.name.clone());
            let Some(head) = self.pending.remove(&key) else {
                self.stats.unmatched_unfinished += 1;
                return Vec::new();
            };
            let merged_args = format!("{}{}", head.args_head, resumed.args_tail);
            self.stats.lines_parsed += 1;
            return self.handle_call(pid, head.ts_ns, &head.name, &merged_args, &resumed.ret);
        }

        let Some((name, body)) = split_call_name(rest) else {
            self.stats.parse_errors += 1;
            return Vec::new();
        };

        if let Some(head) = body.strip_suffix("<unfinished ...>") {
            self.pending.insert(
                (pid, name.to_string()),
                Pending {
                    ts_ns,
                    name: name.to_string(),
                    args_head: head.trim_end().to_string(),
                },
            );
            return Vec::new();
        }

        let Some((call_args, call_ret)) = split_args_and_ret(body) else {
            self.stats.parse_errors += 1;
            return Vec::new();
        };

        self.stats.lines_parsed += 1;
        self.handle_call(pid, ts_ns, name, call_args, call_ret)
    }

    /// Flushes accumulated write byte counts and reports leftover unfinished syscalls.
    ///
    /// Must be called once at end of stream; the byte totals only exist here.
    pub fn finish(&mut self) -> Vec<Event> {
        self.stats.unmatched_unfinished += self.pending.len() as u64;
        self.pending.clear();

        let mut keys: Vec<(u32, i32)> = self.writes.keys().copied().collect();
        // Deterministic order so golden tests are stable across HashMap iteration order.
        keys.sort_unstable();
        let mut events = Vec::new();
        for key in keys {
            if let Some(acc) = self.writes.remove(&key) {
                if let Some(event) = self.write_event(&acc) {
                    events.push(event);
                }
            }
        }
        events
    }

    fn flush_pid_writes(&mut self, pid: u32) -> Vec<Event> {
        let mut keys: Vec<(u32, i32)> = self
            .writes
            .keys()
            .filter(|(p, _)| *p == pid)
            .copied()
            .collect();
        keys.sort_unstable();
        let mut events = Vec::new();
        for key in keys {
            if let Some(acc) = self.writes.remove(&key) {
                if let Some(event) = self.write_event(&acc) {
                    events.push(event);
                }
            }
        }
        events
    }

    fn write_event(&mut self, acc: &WriteAccumulator) -> Option<Event> {
        if self.at_cap() {
            return None;
        }
        self.stats.events_emitted += 1;
        Some(Event::observed(
            Self::meta(acc.last_ts_ns, acc.pid, "write"),
            Payload::FsWrite(FsWrite {
                target: acc.target.clone(),
                kind: WriteKind::Write,
                bytes: Some(acc.bytes),
                flags: None,
                mode: None,
                source: None,
                outcome: Outcome::success(),
            }),
        ))
    }

    fn at_cap(&mut self) -> bool {
        if self.stats.events_emitted >= self.event_cap {
            self.cap_reached = true;
            return true;
        }
        false
    }

    fn emit(&mut self, event: Event, out: &mut Vec<Event>) {
        if self.at_cap() {
            return;
        }
        self.stats.events_emitted += 1;
        out.push(event);
    }

    #[allow(clippy::too_many_lines)]
    fn handle_call(
        &mut self,
        pid: u32,
        ts_ns: u64,
        name: &str,
        args_text: &str,
        ret_text: &str,
    ) -> Vec<Event> {
        let args = split_args(args_text);
        let ret = parse_ret(ret_text);
        let outcome = Outcome {
            ok: ret.ok,
            error: ret.error.clone(),
        };
        let mut out = Vec::new();

        match name {
            // ---- opens: the source of both write intent and the fd table -----------------------
            "openat" | "openat2" | "open" | "creat" => {
                let (dirfd, path_arg, flags_arg) = if name == "open" || name == "creat" {
                    (None, args.first(), args.get(1))
                } else {
                    (args.first().map(String::as_str), args.get(1), args.get(2))
                };
                let raw = path_arg.and_then(|a| quoted_to_path(a));
                let resolved = crate::fdtable::resolve(
                    &self.fds,
                    pid,
                    dirfd,
                    raw.as_deref(),
                    ret.annotation.as_deref(),
                );
                let Some(target) = resolved else {
                    return out;
                };
                let flags = flags_arg.cloned().unwrap_or_default();

                // Register the descriptor even for reads: a later write() needs it.
                if let (Some(true), Some(fd)) = (ret.ok, ret.value) {
                    if let Ok(fd) = i32::try_from(fd) {
                        self.fds
                            .open_file(pid, fd, target.path.clone(), target.origin);
                    }
                }

                let writing = name == "creat" || has_write_intent(&flags);
                if writing {
                    self.emit(
                        Event::observed(
                            Self::meta(ts_ns, pid, name),
                            Payload::FsWrite(FsWrite {
                                target,
                                kind: if name == "creat" {
                                    WriteKind::Create
                                } else {
                                    WriteKind::Open
                                },
                                bytes: None,
                                flags: Some(flags),
                                mode: args.get(if name == "open" { 2 } else { 3 }).cloned(),
                                source: None,
                                outcome,
                            }),
                        ),
                        &mut out,
                    );
                } else if is_read_of_interest(&target.path) {
                    self.emit(
                        Event::observed(
                            Self::meta(ts_ns, pid, name),
                            Payload::FsRead(FsRead {
                                target,
                                bytes: None,
                                outcome,
                            }),
                        ),
                        &mut out,
                    );
                }
            }

            // ---- actual bytes written ----------------------------------------------------------
            // Accumulated per descriptor rather than emitted per call: a tarball extraction is
            // thousands of writes to one file, and one event carrying the total is both smaller and
            // more useful than thousands carrying fragments.
            "write" | "pwrite64" | "writev" | "pwritev" => {
                if ret.ok != Some(true) {
                    return out;
                }
                let Some(fd) = args.first().and_then(|a| fd_number(a)) else {
                    return out;
                };
                let written = ret.value.and_then(|v| u64::try_from(v).ok()).unwrap_or(0);

                // Prefer the -yy annotation on the fd argument, then the table.
                let target = args
                    .first()
                    .and_then(|a| fd_annotation(a))
                    .filter(|a| a.starts_with('/'))
                    .map(|a| TracedPath::new(a, PathOrigin::Kernel))
                    .or_else(|| match self.fds.get(pid, fd) {
                        Some(FdTarget::File { path, origin }) => {
                            Some(TracedPath::new(path.clone(), *origin))
                        }
                        // A write to a socket is network behavior, not a file write. Deliberately
                        // not recorded as fs_write; the connect event already carries the evidence.
                        Some(FdTarget::Socket { .. }) | None => None,
                    });
                let Some(target) = target else {
                    return out;
                };

                let entry = self
                    .writes
                    .entry((pid, fd))
                    .or_insert_with(|| WriteAccumulator {
                        target: target.clone(),
                        bytes: 0,
                        calls: 0,
                        last_ts_ns: ts_ns,
                        pid,
                    });
                // A reopened descriptor pointing somewhere else must not merge with the old total.
                if entry.target.path == target.path {
                    entry.bytes = entry.bytes.saturating_add(written);
                    entry.calls += 1;
                    entry.last_ts_ns = ts_ns;
                } else {
                    let stale = entry.clone();
                    *entry = WriteAccumulator {
                        target,
                        bytes: written,
                        calls: 1,
                        last_ts_ns: ts_ns,
                        pid,
                    };
                    if let Some(event) = self.write_event(&stale) {
                        out.push(event);
                    }
                }
            }

            "close" => {
                if let Some(fd) = args.first().and_then(|a| fd_number(a)) {
                    // Flush the byte total at close: that is when the file's write volume is final.
                    if let Some(acc) = self.writes.remove(&(pid, fd)) {
                        if let Some(event) = self.write_event(&acc) {
                            out.push(event);
                        }
                    }
                    self.fds.close(pid, fd);
                }
            }

            "dup" | "dup2" | "dup3" => {
                if let (Some(old), Some(new)) = (
                    args.first().and_then(|a| fd_number(a)),
                    ret.value.and_then(|v| i32::try_from(v).ok()),
                ) {
                    if ret.ok == Some(true) {
                        match self.fds.get(pid, old).cloned() {
                            Some(FdTarget::File { path, origin }) => {
                                self.fds.open_file(pid, new, path, origin);
                            }
                            Some(FdTarget::Socket { description }) => {
                                self.fds.open_socket(pid, new, description);
                            }
                            None => {}
                        }
                    }
                }
            }

            "chdir" => {
                if ret.ok == Some(true) {
                    if let Some(dir) = args.first().and_then(|a| quoted_to_path(a)) {
                        let resolved = if dir.starts_with('/') {
                            crate::fdtable::normalize(&dir)
                        } else if let Some(cwd) = self.fds.cwd(pid) {
                            crate::fdtable::join(cwd, &dir)
                        } else {
                            // Unknown base: forget the cwd rather than record a wrong one, so later
                            // relative paths stay Unresolved instead of being mis-anchored.
                            return out;
                        };
                        self.fds.set_cwd(pid, resolved);
                    }
                }
            }

            "fchdir" => {
                if ret.ok == Some(true) {
                    if let Some(fd) = args.first().and_then(|a| fd_number(a)) {
                        if let Some(FdTarget::File { path, .. }) = self.fds.get(pid, fd).cloned() {
                            self.fds.set_cwd(pid, path);
                        }
                    }
                }
            }

            // ---- other filesystem mutations ----------------------------------------------------
            "truncate" | "mkdir" | "rmdir" | "unlink" => {
                let raw = args.first().and_then(|a| quoted_to_path(a));
                let Some(target) =
                    crate::fdtable::resolve(&self.fds, pid, None, raw.as_deref(), None)
                else {
                    return out;
                };
                let kind = match name {
                    "truncate" => WriteKind::Truncate,
                    "mkdir" => WriteKind::Mkdir,
                    _ => WriteKind::Delete,
                };
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::FsWrite(FsWrite {
                            target,
                            kind,
                            bytes: None,
                            flags: None,
                            mode: if name == "mkdir" {
                                args.get(1).cloned()
                            } else {
                                None
                            },
                            source: None,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            "mkdirat" | "unlinkat" => {
                let raw = args.get(1).and_then(|a| quoted_to_path(a));
                let Some(target) = crate::fdtable::resolve(
                    &self.fds,
                    pid,
                    args.first().map(String::as_str),
                    raw.as_deref(),
                    None,
                ) else {
                    return out;
                };
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::FsWrite(FsWrite {
                            target,
                            kind: if name == "mkdirat" {
                                WriteKind::Mkdir
                            } else {
                                WriteKind::Delete
                            },
                            bytes: None,
                            flags: None,
                            mode: None,
                            source: None,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            "rename" | "link" | "symlink" => {
                // symlink(target, linkpath): arg 0 is the link *contents*, not a path to resolve.
                let (source_arg, dest_arg) = (args.first(), args.get(1));
                let dest_raw = dest_arg.and_then(|a| quoted_to_path(a));
                let Some(target) =
                    crate::fdtable::resolve(&self.fds, pid, None, dest_raw.as_deref(), None)
                else {
                    return out;
                };
                let source = source_arg.and_then(|a| quoted_to_path(a)).map(|s| {
                    if name == "symlink" {
                        TracedPath::new(s, PathOrigin::Unresolved)
                    } else if s.starts_with('/') {
                        TracedPath::new(crate::fdtable::normalize(&s), PathOrigin::Absolute)
                    } else {
                        TracedPath::new(s, PathOrigin::Unresolved)
                    }
                });
                let kind = match name {
                    "rename" => WriteKind::Rename,
                    "link" => WriteKind::Hardlink,
                    _ => WriteKind::Symlink,
                };
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::FsWrite(FsWrite {
                            target,
                            kind,
                            bytes: None,
                            flags: None,
                            mode: None,
                            source,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            "renameat" | "renameat2" | "linkat" | "symlinkat" => {
                // symlinkat(target, newdirfd, linkpath) has one fewer leading arg than renameat.
                let (src_dirfd, src_idx, dst_dirfd_idx, dst_idx) = if name == "symlinkat" {
                    (None, 0usize, 1usize, 2usize)
                } else {
                    (args.first().map(String::as_str), 1usize, 2usize, 3usize)
                };
                let dest_raw = args.get(dst_idx).and_then(|a| quoted_to_path(a));
                let Some(target) = crate::fdtable::resolve(
                    &self.fds,
                    pid,
                    args.get(dst_dirfd_idx).map(String::as_str),
                    dest_raw.as_deref(),
                    None,
                ) else {
                    return out;
                };
                let source = if name == "symlinkat" {
                    args.get(src_idx)
                        .and_then(|a| quoted_to_path(a))
                        .map(|s| TracedPath::new(s, PathOrigin::Unresolved))
                } else {
                    let raw = args.get(src_idx).and_then(|a| quoted_to_path(a));
                    crate::fdtable::resolve(&self.fds, pid, src_dirfd, raw.as_deref(), None)
                };
                let kind = match name {
                    "renameat" | "renameat2" => WriteKind::Rename,
                    "linkat" => WriteKind::Hardlink,
                    _ => WriteKind::Symlink,
                };
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::FsWrite(FsWrite {
                            target,
                            kind,
                            bytes: None,
                            flags: None,
                            mode: None,
                            source,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            "chmod" | "chown" | "lchown" => {
                let raw = args.first().and_then(|a| quoted_to_path(a));
                let Some(target) =
                    crate::fdtable::resolve(&self.fds, pid, None, raw.as_deref(), None)
                else {
                    return out;
                };
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::FsWrite(FsWrite {
                            target,
                            kind: if name == "chmod" {
                                WriteKind::Chmod
                            } else {
                                WriteKind::Chown
                            },
                            bytes: None,
                            flags: None,
                            mode: if name == "chmod" {
                                args.get(1).cloned()
                            } else {
                                None
                            },
                            source: None,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            "fchmodat" | "fchownat" => {
                let raw = args.get(1).and_then(|a| quoted_to_path(a));
                let Some(target) = crate::fdtable::resolve(
                    &self.fds,
                    pid,
                    args.first().map(String::as_str),
                    raw.as_deref(),
                    None,
                ) else {
                    return out;
                };
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::FsWrite(FsWrite {
                            target,
                            kind: if name == "fchmodat" {
                                WriteKind::Chmod
                            } else {
                                WriteKind::Chown
                            },
                            bytes: None,
                            flags: None,
                            mode: if name == "fchmodat" {
                                args.get(2).cloned()
                            } else {
                                None
                            },
                            source: None,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            // ---- sockets -----------------------------------------------------------------------
            "socket" => {
                if let (Some(true), Some(fd)) = (ret.ok, ret.value) {
                    if let Ok(fd) = i32::try_from(fd) {
                        self.fds.open_socket(pid, fd, args.join(", "));
                    }
                }
            }

            "connect" => {
                let Some(sa) = args.get(1).and_then(|a| parse_sockaddr(a)) else {
                    return out;
                };
                match sa.family {
                    SockFamily::Unix => {
                        self.emit(
                            Event::observed(
                                Self::meta(ts_ns, pid, name),
                                Payload::NetConnect(NetConnect {
                                    family: AddrFamily::Unix,
                                    ip: None,
                                    port: None,
                                    unix_path: sa.unix_path,
                                    host: None,
                                    loopback: true,
                                    private: true,
                                    outcome,
                                }),
                            ),
                            &mut out,
                        );
                    }
                    SockFamily::Inet | SockFamily::Inet6 => {
                        let ip = sa.ip.clone().unwrap_or_default();
                        self.emit(
                            Event::observed(
                                Self::meta(ts_ns, pid, name),
                                Payload::NetConnect(NetConnect {
                                    family: if sa.family == SockFamily::Inet {
                                        AddrFamily::Inet
                                    } else {
                                        AddrFamily::Inet6
                                    },
                                    loopback: decode::is_loopback(&ip),
                                    private: decode::is_private(&ip),
                                    ip: sa.ip,
                                    port: sa.port,
                                    unix_path: None,
                                    // Left None deliberately: strace cannot prove which DNS answer
                                    // this connect used, and a guessed hostname is fabricated
                                    // evidence (Rules.md §5).
                                    host: None,
                                    outcome,
                                }),
                            ),
                            &mut out,
                        );
                    }
                    SockFamily::Other => {}
                }
            }

            "sendto" | "sendmsg" => {
                // Only DNS is extracted. Recording every datagram would add noise without adding
                // findings; the connect event already establishes that traffic occurred.
                let (sockaddr_text, payload_arg, truncated) = if name == "sendto" {
                    (
                        args.get(4).cloned().unwrap_or_default(),
                        args.get(1).cloned(),
                        false,
                    )
                } else {
                    let name_field = extract_braced(args_text, "msg_name=").unwrap_or_default();
                    let (iov, iov_truncated) = extract_iov(args_text);
                    (name_field, iov, iov_truncated)
                };
                let Some(sa) = parse_sockaddr(&sockaddr_text) else {
                    return out;
                };
                if sa.port != Some(53) {
                    return out;
                }
                let Some(payload_arg) = payload_arg else {
                    return out;
                };
                let Some(quoted) = read_quoted(&payload_arg, 0) else {
                    return out;
                };
                let cut = truncated || quoted.truncated;
                match parse_dns_question(&quoted.bytes) {
                    Some(question) if !cut || question.qtype.is_some() => {
                        self.emit(
                            Event::observed(
                                Self::meta(ts_ns, pid, name),
                                Payload::DnsQuery(DnsQuery {
                                    qname: question.qname,
                                    qtype: question.qtype,
                                    resolver_ip: sa.ip,
                                    outcome,
                                }),
                            ),
                            &mut out,
                        );
                    }
                    _ => {
                        self.stats.dns_undecodable += 1;
                    }
                }
            }

            // ---- processes ---------------------------------------------------------------------
            "execve" | "execveat" => {
                let bin_idx = usize::from(name == "execveat");
                let bin = args.get(bin_idx).and_then(|a| quoted_to_path(a));
                let rendered_vector = args.get(bin_idx + 1).cloned().unwrap_or_default();
                let argv_truncated = rendered_vector.contains("...");
                let command_vector = parse_argv(&rendered_vector);
                self.emit(
                    Event::observed(
                        Self::meta(ts_ns, pid, name),
                        Payload::ProcSpawn(ProcSpawn {
                            bin,
                            argv: command_vector,
                            argv_truncated,
                            outcome,
                        }),
                    ),
                    &mut out,
                );
            }

            "clone" | "clone3" | "fork" | "vfork" => {
                // Propagate the descriptor table to the child so its writes resolve. Not emitted as
                // an event: a spawn is an execve, and reporting clone separately would double-count.
                if let (Some(true), Some(child)) = (ret.ok, ret.value) {
                    if let Ok(child) = u32::try_from(child) {
                        if child != 0 {
                            self.fds.fork(pid, child);
                        }
                    }
                }
            }

            _ => {}
        }

        out
    }
}

/// Splits an optional leading pid from a trace line.
fn split_pid_prefix(line: &str, default_pid: u32) -> (u32, &str) {
    let trimmed = line.trim_start();
    let mut split = trimmed.splitn(2, ' ');
    if let (Some(head), Some(rest)) = (split.next(), split.next()) {
        // A pid prefix is a bare integer; a timestamp contains a '.'.
        if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(pid) = head.parse::<u32>() {
                return (pid, rest.trim_start());
            }
        }
    }
    (default_pid, trimmed)
}

/// Splits the `-ttt` epoch timestamp from the rest of the line.
fn split_timestamp(s: &str) -> Option<(f64, &str)> {
    let (head, rest) = s.split_once(' ')?;
    if !head.contains('.') {
        return None;
    }
    let ts = head.parse::<f64>().ok()?;
    Some((ts, rest.trim_start()))
}

/// A `<... name resumed>` continuation.
struct Resumed {
    name: String,
    args_tail: String,
    ret: String,
}

fn parse_resumed(rest: &str) -> Option<Resumed> {
    let inner = rest.strip_prefix("<... ")?;
    let idx = inner.find(" resumed>")?;
    let name = inner.get(..idx)?.to_string();
    let tail = inner.get(idx + " resumed>".len()..)?.trim_start();
    let close = tail.find(')');
    match close {
        Some(pos) => Some(Resumed {
            name,
            args_tail: tail.get(..pos)?.to_string(),
            ret: tail.get(pos + 1..)?.trim().to_string(),
        }),
        None => Some(Resumed {
            name,
            args_tail: tail.to_string(),
            ret: String::new(),
        }),
    }
}

/// Splits `openat(AT_FDCWD, "x") = 3` into `("openat", "AT_FDCWD, \"x\") = 3")`.
fn split_call_name(rest: &str) -> Option<(&str, &str)> {
    let open = rest.find('(')?;
    let name = rest.get(..open)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    Some((name, rest.get(open + 1..)?))
}

/// Splits a call body into its argument text and its return text, honoring quotes and nesting.
fn split_args_and_ret(body: &str) -> Option<(&str, &str)> {
    let bytes = body.as_bytes();
    let mut depth = 1i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let q = read_quoted(body, i)?;
                i = q.end;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((body.get(..i)?, body.get(i + 1..)?.trim()));
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Parses an strace-rendered argv array into strings.
fn parse_argv(raw: &str) -> Vec<String> {
    let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) else {
        return Vec::new();
    };
    split_args(inner)
        .iter()
        .filter_map(|a| quoted_to_path(a))
        .collect()
}

/// Extracts a `{...}` struct following `key` from a syscall argument list.
fn extract_braced(text: &str, key: &str) -> Option<String> {
    let start = text.find(key)? + key.len();
    let rest = text.get(start..)?;
    if !rest.starts_with('{') {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return rest.get(..=i).map(ToString::to_string);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extracts the first `iov_base="…"` payload from a sendmsg rendering, plus whether it was cut.
fn extract_iov(text: &str) -> (Option<String>, bool) {
    let Some(idx) = text.find("iov_base=") else {
        return (None, false);
    };
    let start = idx + "iov_base=".len();
    let Some(rest) = text.get(start..) else {
        return (None, false);
    };
    match read_quoted(rest, 0) {
        Some(q) => {
            let literal = rest.get(..q.end).map(ToString::to_string);
            (literal, q.truncated)
        }
        None => (None, true),
    }
}
