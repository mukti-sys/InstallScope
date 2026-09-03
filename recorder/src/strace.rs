//! Linux strace backend — the v1.0 recorder (Architecture.md:35).
//!
//! Spawns the install command under `strace -f -ff`, streams the resulting trace files through
//! [`crate::parser`], and writes a schema v1 JSONL session. Linux-only: `#[cfg(target_os = "linux")]`
//! gates the whole module, and [`crate::RecorderError::UnsupportedPlatform`] is what other platforms
//! get. Scope.md:25 makes that a v1 design decision, not an oversight.
//!
//! # Why post-process rather than stream live
//!
//! `-ff` writes one file per pid, and a live tail would have to poll a growing directory while
//! processes come and go. Reading after the command exits is simpler and — critically — cannot lose
//! events to a race between the recorder and a process that forks and dies quickly. The cost is that
//! events are not available until the install finishes, which no consumer needs: the report is
//! produced after the install either way.
//!
//! The recorder still writes `session_start` before the command runs and heartbeats while it runs, so
//! a recorder killed mid-install leaves a stream that is visibly PARTIAL rather than absent.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use installscope_core::{Backend, HostInfo, IncompleteReason, SessionEnd, Zones};

use crate::parser::Parser;
use crate::session::SessionWriter;
use crate::{RecorderError, Result, AGENT_VERSION};

/// Syscalls traced. Each group earns its place:
///
/// - opens and the `*at` variants: write intent, plus the fd table that gives `write` its path;
/// - `write`/`pwrite64`/`writev`: byte volume, which the Phase 0 harness could not produce;
/// - `close`/`dup*`: fd table accuracy;
/// - `chdir`/`fchdir`: so relative paths resolve instead of being discarded as Unresolved;
/// - `socket`/`connect`: network destinations, and the peer needed to attribute a later `send`;
/// - `sendto`/`sendmsg`/`send`/`sendmmsg`: DNS questions. The last two matter most in practice —
///   glibc's resolver connects its UDP socket and then batches the A and AAAA queries through
///   `sendmmsg`, so omitting them means a recording can show a connection to port 53 while producing
///   no DNS evidence at all;
/// - `execve*`: spawns;
/// - `clone*`/`fork`/`vfork`: inherit the fd table into children.
///
/// Deliberately absent: `read`, `stat`, `access`, `mmap`. They are the bulk of an install's syscalls
/// and contribute no finding that the above do not already establish.
const TRACE_SET: &str = concat!(
    "openat,openat2,open,creat,truncate,",
    "write,pwrite64,writev,pwritev,close,dup,dup2,dup3,",
    "chdir,fchdir,",
    "rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,rmdir,",
    "chmod,fchmodat,chown,lchown,fchownat,link,linkat,symlink,symlinkat,",
    "socket,connect,sendto,sendmsg,send,sendmmsg,",
    "execve,execveat,clone,clone3,fork,vfork,",
    "io_uring_setup,io_uring_enter,io_uring_register,ptrace"
);

/// Terminates a traced process and its entire process tree.
///
/// On Unix, the child is placed in its own process group at spawn. When terminating,
/// we signal the entire process group (`-pgid`) with SIGTERM first so processes have a chance
/// to flush logs and exit cleanly, then escalate to SIGKILL after a 2-second grace period.
/// Calling `child.kill()` alone would only terminate the tracer (strace), which cannot forward
/// SIGKILL, leaving child install processes running in the background as unmonitored orphans.
fn kill_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pgid = child.id().to_string();
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(format!("-{pgid}"))
            .status();

        let deadline = Instant::now() + Duration::from_millis(2000);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let _ = Command::new("kill")
            .arg("-KILL")
            .arg(format!("-{pgid}"))
            .status();
        let _ = child.wait();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// How much of each buffer strace prints. 512 bytes covers a DNS question comfortably while keeping
/// trace files manageable; a shorter limit silently truncates hostnames.
const STRING_LIMIT: &str = "512";

/// How often the wait loop checks whether the traced command has exited. Short so a `--timeout` is
/// enforced promptly rather than up to a heartbeat late.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How often a liveness heartbeat is written while the command runs. Decoupled from [`POLL_INTERVAL`]
/// so frequent polling does not flood the stream: at 200 ms polling, one heartbeat per poll would add
/// ~1,500 lines to a five-minute install and tell the reader nothing the timestamps do not.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Configuration for one recording.
#[derive(Debug, Clone)]
pub struct RecordConfig {
    /// The command to record, argv style. Never passed through a shell.
    pub command: Vec<String>,
    /// Directory for the event stream, trace files, and metadata.
    pub out_dir: PathBuf,
    /// Wall-clock budget. `None` means no limit.
    pub timeout: Option<Duration>,
    /// Working directory for the command.
    pub cwd: Option<PathBuf>,
    /// Directories that give paths meaning downstream.
    pub zones: Zones,
    /// Extra environment for the command.
    pub env: BTreeMap<String, String>,
    /// Keep raw trace files after parsing. Off by default: they are large, and the JSONL is the
    /// evidence. On when a human needs to dispute a finding.
    pub keep_raw_traces: bool,
    /// Cap on emitted events.
    pub event_cap: u64,
}

impl RecordConfig {
    /// A configuration with defaults for everything but the command and output directory.
    #[must_use]
    pub fn new(command: Vec<String>, out_dir: PathBuf) -> Self {
        Self {
            command,
            out_dir,
            timeout: None,
            cwd: None,
            zones: Zones::default(),
            env: BTreeMap::new(),
            keep_raw_traces: false,
            event_cap: crate::parser::DEFAULT_EVENT_CAP,
        }
    }
}

/// What a recording produced.
#[derive(Debug, Clone)]
pub struct Recording {
    /// Path to the JSONL event stream.
    pub events_path: PathBuf,
    /// The `session_end` that was written. Its `complete` flag is the PARTIAL decision.
    pub session_end: SessionEnd,
    /// Exit code of the recorded command, if it exited normally.
    pub command_exit_code: Option<i32>,
    /// Parse statistics, for diagnostics.
    pub stats: crate::ParseStats,
}

impl Recording {
    /// True when the report must show PARTIAL (PRD.md:58).
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.session_end.complete
    }
}

/// Verifies `strace` is present before anything else happens.
///
/// Checked up front so the failure is "strace is not installed" rather than a confusing spawn error
/// after the session file has already been created. Returns the version line, which is stamped into
/// the recording so a disputed finding can be traced to a specific backend build.
///
/// # Errors
/// [`RecorderError::BackendMissing`] when `strace` is not on `PATH`, [`RecorderError::Spawn`] for any
/// other failure to execute it.
pub fn check_available() -> Result<String> {
    let output = Command::new("strace")
        .arg("-V")
        .stdin(Stdio::null())
        .output()
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                RecorderError::BackendMissing { tool: "strace" }
            } else {
                RecorderError::Spawn {
                    what: "strace -V".to_string(),
                    source,
                }
            }
        })?;
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string();
    Ok(version)
}

fn read_first_line(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
}

fn os_pretty_name() -> Option<String> {
    let contents = fs::read_to_string("/etc/os-release").ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim_matches('"').to_string())
    })
}

fn host_info(strace_version: &str) -> HostInfo {
    HostInfo {
        kernel: read_first_line("/proc/sys/kernel/osrelease"),
        os: os_pretty_name(),
        arch: Some(std::env::consts::ARCH.to_string()),
        backend_version: Some(strace_version.to_string()),
    }
}

use crate::clock::{epoch_secs_f64, rfc3339_utc};

/// Records `config.command` under strace.
///
/// Always writes a terminated session: on every failure path the stream ends with a `session_end`
/// carrying an explicit [`IncompleteReason`], because a recorder that dies quietly is the worst
/// outcome this project can produce (`Rules.md` §2).
///
/// # Errors
/// [`RecorderError::EmptyCommand`] for an empty command, [`RecorderError::BackendMissing`] when
/// `strace` is absent, and [`RecorderError::Io`] when the output directory or event stream cannot be
/// created. Note what is *not* an error: a failed install, a timeout, or a dead backend all return
/// `Ok` with a PARTIAL [`Recording`], because those are results to report rather than failures to
/// propagate.
#[allow(clippy::too_many_lines)]
pub fn record(config: &RecordConfig) -> Result<Recording> {
    if config.command.is_empty() {
        return Err(RecorderError::EmptyCommand);
    }

    let strace_version = check_available()?;

    // The program is resolved to an absolute path before anything else happens.
    //
    // strace runs with `current_dir(config.cwd)`, so a relative program path like
    // `./harness/parity/parity-workload.sh` is resolved against the *recorded command's* directory, not
    // the recorder's. Left alone it fails with "Cannot stat", produces no trace files, and the recording
    // comes back PARTIAL blaming the backend — the same class of misleading diagnosis as the relative
    // `-o` bug, and equally the recorder's fault rather than the package's.
    let command = crate::resolve_program(&config.command, config.cwd.as_deref())?;

    fs::create_dir_all(&config.out_dir)
        .map_err(|source| RecorderError::io(&config.out_dir, source))?;

    // Everything below uses an ABSOLUTE output directory.
    //
    // strace is spawned with `current_dir(config.cwd)`, so a relative `-o` path would be resolved
    // against the *install's* directory rather than ours — strace would fail with "Can't fopen", write
    // no trace files, and the recording would come back PARTIAL for a reason that has nothing to do
    // with the package. Resolving once here fixes the trace prefix, the event stream, the command log
    // paths, and the zone comparison in one place.
    let out_dir = fs::canonicalize(&config.out_dir)
        .map_err(|source| RecorderError::io(&config.out_dir, source))?;

    let trace_dir = out_dir.join("trace");
    // A stale trace directory would mix a previous recording's events into this one.
    if trace_dir.exists() {
        fs::remove_dir_all(&trace_dir).map_err(|source| RecorderError::io(&trace_dir, source))?;
    }
    fs::create_dir_all(&trace_dir).map_err(|source| RecorderError::io(&trace_dir, source))?;

    let events_path = out_dir.join("events.jsonl");
    let events_file =
        fs::File::create(&events_path).map_err(|source| RecorderError::io(&events_path, source))?;
    let events_writer = std::io::BufWriter::new(events_file);

    // The recorder's own output directory is an expected write location, and it must be declared as
    // one.
    //
    // The traced command inherits stdout and stderr pointing at files inside `out_dir`, so every line
    // npm prints becomes an observed write to that directory. Without this, a first-time user running
    // `installscope record --out ./somewhere` outside their project would get a critical
    // "wrote outside expected dirs" finding caused entirely by the recorder's own plumbing. Blaming
    // the package for the observer's behavior is exactly the kind of false positive PRD.md:43 calls
    // the religion to avoid.
    let mut zones = config.zones.clone();
    if let Some(out) = out_dir.to_str() {
        let already_covered = [
            zones.project.as_deref(),
            zones.cache.as_deref(),
            zones.home.as_deref(),
            zones.tmp.as_deref(),
        ]
        .into_iter()
        .flatten()
        .chain(zones.extra.iter().map(String::as_str))
        .any(|zone| out == zone || out.starts_with(&format!("{}/", zone.trim_end_matches('/'))));
        if !already_covered {
            zones.extra.push(out.to_string());
        }
    }

    let start_time = SystemTime::now();
    let start_epoch = epoch_secs_f64(start_time);

    let mut session = SessionWriter::start(
        events_writer,
        rfc3339_utc(start_time),
        AGENT_VERSION,
        Backend::Strace,
        command.clone(),
        zones,
        Some(host_info(&strace_version)),
    )?;

    // ---- spawn ---------------------------------------------------------------------------------
    let trace_prefix = trace_dir.join("trace");
    let mut cmd = Command::new("strace");
    cmd.arg("-f") // follow children
        .arg("-ff") // one file per pid, so no interleaving to untangle
        .arg("-ttt") // absolute epoch timestamps; the parser makes them session-relative
        .arg("-yy") // annotate fds with paths and socket details
        .arg("-s")
        .arg(STRING_LIMIT)
        .arg("-e")
        .arg(format!("trace={TRACE_SET}"))
        .arg("-o")
        .arg(&trace_prefix)
        .arg("--");
    for part in &command {
        cmd.arg(OsStr::new(part));
    }
    if let Some(dir) = &config.cwd {
        cmd.current_dir(dir);
    }
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // The install's own output is redirected to FILES, not pipes.
    //
    // This matters more than it looks. A piped stdout with nothing draining it fills the ~64 KiB
    // kernel pipe buffer and then blocks the child forever, so a merely verbose install would hang
    // until the timeout and be reported as PARTIAL. Files cannot deadlock, and they keep the install's
    // own narration available next to the evidence — useful when a human is reconciling a finding
    // against what npm claimed it was doing.
    let stdout_path = out_dir.join("command-stdout.log");
    let stderr_path = out_dir.join("command-stderr.log");
    let stdout_file =
        fs::File::create(&stdout_path).map_err(|source| RecorderError::io(&stdout_path, source))?;
    let stderr_file =
        fs::File::create(&stderr_path).map_err(|source| RecorderError::io(&stderr_path, source))?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }

    let spawn_started = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(source) => {
            let detail = source.to_string();
            let end = session.finish_partial(
                IncompleteReason::BackendFailedToStart { detail },
                Vec::new(),
                None,
            )?;
            return Ok(Recording {
                events_path,
                session_end: end,
                command_exit_code: None,
                stats: crate::ParseStats::default(),
            });
        }
    };

    // ---- wait, with heartbeats and an optional timeout -----------------------------------------
    let mut timed_out = false;
    let mut last_heartbeat = Instant::now();
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(source) => {
                let detail = source.to_string();
                let end = session.finish_partial(
                    IncompleteReason::BackendDied { detail },
                    Vec::new(),
                    None,
                )?;
                return Ok(Recording {
                    events_path,
                    session_end: end,
                    command_exit_code: None,
                    stats: crate::ParseStats::default(),
                });
            }
        }

        if let Some(limit) = config.timeout {
            if spawn_started.elapsed() >= limit {
                timed_out = true;
                // Terminate the entire process group so untrusted child processes do not survive.
                kill_process_group(&mut child);
                break None;
            }
        }

        // Proves liveness during a long, quiet install. Rate-limited: polling is frequent so a
        // timeout fires promptly, but a heartbeat per poll would add thousands of lines to a
        // multi-minute recording without adding information.
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            session.heartbeat()?;
            last_heartbeat = Instant::now();
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    let command_exit_code = exit_status.and_then(|s| s.code());

    // ---- parse the trace files -----------------------------------------------------------------
    let trace_files = collect_trace_files(&trace_dir)?;

    let mut parser = Parser::new(start_epoch).with_event_cap(config.event_cap);
    if let Some(dir) = config.cwd.as_deref().and_then(Path::to_str) {
        // Every traced process descends from one launched in `config.cwd`, so that is each process's
        // starting cwd. Seeding all of them is what makes a relative `openat` resolvable at all.
        //
        // `seed_cwd` only fills a gap, and the parser's `chdir`/`clone` handling overwrites it, so a
        // process that moved is still tracked accurately rather than being pinned here. Without this,
        // the root process's own relative paths would all be `Unresolved` — which is honest but
        // throws away evidence we genuinely have.
        for (pid, _) in &trace_files {
            parser.seed_cwd(*pid, dir);
        }
    }

    if trace_files.is_empty() {
        let end = session.finish_partial(
            IncompleteReason::BackendFailedToStart {
                detail: "strace produced no trace files".to_string(),
            },
            if timed_out {
                vec![IncompleteReason::Timeout {
                    limit_secs: config.timeout.map_or(0, |t| t.as_secs()),
                }]
            } else {
                Vec::new()
            },
            command_exit_code,
        )?;
        return Ok(Recording {
            events_path,
            session_end: end,
            command_exit_code,
            stats: parser.stats().clone(),
        });
    }

    let mut reasons = Vec::new();

    for (pid, path) in &trace_files {
        let contents = match fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(source) => {
                // A single unreadable trace file is a partial recording, not a total failure: the
                // other pids' evidence is still real. Recorded as a reason so the gap is visible.
                tracing::warn!(path = %path.display(), error = %source, "could not read trace file");
                reasons.push(IncompleteReason::TraceTruncated {
                    detail: format!(
                        "could not read trace file for pid {pid} ({}): {source}",
                        path.display()
                    ),
                });
                continue;
            }
        };
        for line in contents.lines() {
            let events = parser.feed_line(line, *pid);
            session.write_events(&events)?;
        }
    }
    let trailing = parser.finish();
    session.write_events(&trailing)?;

    let stats = parser.stats().clone();

    if !config.keep_raw_traces {
        let _ = fs::remove_dir_all(&trace_dir);
    }

    // ---- decide complete vs PARTIAL ------------------------------------------------------------
    // Every condition that could make the stream a lie is enumerated. Silence is not an option.
    if timed_out {
        reasons.push(IncompleteReason::Timeout {
            limit_secs: config.timeout.map_or(0, |t| t.as_secs()),
        });
    }
    if stats.evasion_attempts > 0 {
        reasons.push(IncompleteReason::Other {
            detail: format!(
                "process attempted untraced execution or anti-debugging ({} evasion syscall{})",
                stats.evasion_attempts,
                if stats.evasion_attempts == 1 { "" } else { "s" },
            ),
        });
    }
    if parser.cap_reached() {
        reasons.push(IncompleteReason::EventCapReached {
            cap: config.event_cap,
        });
    }
    if stats.parse_errors > 0 {
        reasons.push(IncompleteReason::ParseErrors {
            count: stats.parse_errors,
        });
    }
    if stats.diagnostic_data_loss > 0 {
        // strace said it lost data. Distinct from a parse error: the trace file is well-formed, it is
        // just missing events we know about.
        reasons.push(IncompleteReason::TraceTruncated {
            detail: format!(
                "strace reported losing data {} time(s)",
                stats.diagnostic_data_loss
            ),
        });
    }
    if stats.unmatched_unfinished > 0 {
        reasons.push(IncompleteReason::TraceTruncated {
            detail: format!(
                "{} syscalls never completed in the trace",
                stats.unmatched_unfinished
            ),
        });
    }
    if let Some(status) = exit_status {
        // strace itself failing (as opposed to the install failing) means the recording is suspect.
        // Distinguishing them is not possible from the exit code alone, so this is reported as a
        // reason rather than asserted as either.
        if !status.success() && status.code().is_none() {
            reasons.push(IncompleteReason::BackendDied {
                detail: "strace terminated by a signal".to_string(),
            });
        }
    }

    let session_end = if reasons.is_empty() {
        session.finish_complete(command_exit_code)?
    } else {
        let mut iter = reasons.into_iter();
        // Safe by construction: the branch is only taken when the vector is non-empty, and the
        // fallback is a truthful reason rather than a silent success.
        let first = iter.next().unwrap_or(IncompleteReason::Other {
            detail: "recording incomplete for an unrecorded reason".to_string(),
        });
        session.finish_partial(first, iter.collect(), command_exit_code)?
    };

    Ok(Recording {
        events_path,
        session_end,
        command_exit_code,
        stats,
    })
}

/// Finds `trace.<pid>` files, returning them sorted by pid for deterministic output.
fn collect_trace_files(dir: &Path) -> Result<Vec<(u32, PathBuf)>> {
    let entries = fs::read_dir(dir).map_err(|source| RecorderError::io(dir, source))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| RecorderError::io(dir, source))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        let Some(pid_str) = name.strip_prefix("trace.") else {
            continue;
        };
        if let Ok(pid) = pid_str.parse::<u32>() {
            files.push((pid, path));
        }
    }
    files.sort_unstable();
    Ok(files)
}

/// Writes a human-readable session summary next to the event stream.
///
/// Not part of the schema; a convenience for `installscope record` output and for CI logs.
///
/// # Errors
/// [`RecorderError::Io`] if the summary file cannot be created or written.
pub fn write_summary(out_dir: &Path, recording: &Recording) -> Result<PathBuf> {
    let path = out_dir.join("session-summary.txt");
    let mut file = fs::File::create(&path).map_err(|source| RecorderError::io(&path, source))?;
    let state = if recording.is_partial() {
        "PARTIAL"
    } else {
        "complete"
    };
    writeln!(file, "state: {state}").map_err(|source| RecorderError::io(&path, source))?;
    for reason in &recording.session_end.incomplete_reasons {
        writeln!(file, "reason: {reason}").map_err(|source| RecorderError::io(&path, source))?;
    }
    writeln!(
        file,
        "command_exit_code: {}",
        recording
            .command_exit_code
            .map_or_else(|| "none".to_string(), |c| c.to_string())
    )
    .map_err(|source| RecorderError::io(&path, source))?;
    writeln!(file, "events: {}", recording.session_end.events_emitted)
        .map_err(|source| RecorderError::io(&path, source))?;
    writeln!(file, "heartbeats: {}", recording.session_end.heartbeats)
        .map_err(|source| RecorderError::io(&path, source))?;
    writeln!(file, "lines_seen: {}", recording.stats.lines_seen)
        .map_err(|source| RecorderError::io(&path, source))?;
    writeln!(file, "parse_errors: {}", recording.stats.parse_errors)
        .map_err(|source| RecorderError::io(&path, source))?;
    writeln!(file, "dns_undecodable: {}", recording.stats.dns_undecodable)
        .map_err(|source| RecorderError::io(&path, source))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_command_is_rejected_before_any_file_is_created() {
        let config = RecordConfig::new(Vec::new(), PathBuf::from("/tmp/does-not-matter"));
        let err = record(&config).expect_err("must reject");
        assert!(matches!(err, RecorderError::EmptyCommand));
    }

    #[test]
    fn a_nonexistent_program_is_named_rather_than_blamed_on_the_backend() {
        // Run 33390145890 failed as "strace produced no trace files" because the workflow passed a
        // relative script path that resolved against --cwd instead of the recorder's directory. That
        // message is true and useless: it points at the recorder when the fault is the command line.
        let config = RecordConfig::new(
            vec!["./definitely/not/here.sh".to_string()],
            PathBuf::from("/tmp/does-not-matter"),
        );
        match record(&config) {
            Err(RecorderError::CommandNotExecutable { program, .. }) => {
                assert_eq!(program, "./definitely/not/here.sh");
            }
            Err(RecorderError::BackendMissing { .. }) => {
                // No strace on this host; the resolution check is still exercised by the unit tests in
                // lib.rs, which need no external binary.
            }
            other => panic!("expected CommandNotExecutable, got {other:?}"),
        }
    }

    #[test]
    fn trace_set_covers_the_syscalls_the_parser_handles() {
        // A syscall the parser knows but strace is not asked to trace is silently dead code, and the
        // finding it would have produced simply never appears. Byte accounting is the case that
        // matters most: it is the Phase 0 gap this phase exists to close.
        for required in [
            "openat", "write", "pwrite64", "close", "connect", "sendto", "sendmsg", "send",
            "sendmmsg", "socket", "execve", "clone", "chdir", "rename", "symlink", "chmod",
            "unlink",
        ] {
            assert!(
                TRACE_SET.split(',').any(|s| s == required),
                "{required} is handled by the parser but not traced"
            );
        }
    }
}
