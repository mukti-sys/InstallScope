//! The aya backend: loads the eBPF programs, drains their perf buffers, writes a schema v1 session.
//!
//! Linux-only, and gated behind the `aya-backend` feature because it pulls in `aya` and requires a
//! compiled eBPF object. `installscope record --backend strace` works without any of it.
//!
//! # UNVERIFIED
//!
//! This has never run. G1 (#33297876067) proved a *tracepoint* program loads on `ubuntu-latest` and
//! delivers perf events; it did not prove maps-in-tracepoints, entry/exit correlation, or the argument
//! offsets these programs depend on. Expect the first real run to fail. The workflow dumps every
//! tracepoint format file before loading so a mismatch is a five-minute fix rather than a guessing game.
//!
//! # How this differs structurally from the strace backend
//!
//! strace post-processes trace files after the command exits — `-ff` writes one file per pid and reading
//! them afterwards cannot race a process that forks and dies quickly. eBPF has no such luxury: perf
//! buffers are ring buffers, and anything not drained is overwritten. So this backend drains
//! *concurrently* with the install, on a dedicated thread, and that concurrency is where its failure
//! modes live:
//!
//! - a ring that fills between polls loses records, reported by the kernel's own lost counter and
//!   forcing PARTIAL;
//! - per-CPU delivery arrives out of order, handled by [`crate::merge::Merger`];
//! - the drain thread must outlive the command so late events still land.
//!
//! # Why this module is the crate's only `unsafe`
//!
//! Reading a `#[repr(C)]` record out of a perf buffer requires a pointer cast; there is no safe
//! equivalent, because the bytes arrive as an untyped slice. Every such site is bounds-checked against
//! the struct size first, and the `abi` crate's layout assertions catch a kernel/userspace mismatch at
//! build time. Everything else in the crate stays unsafe-free.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use aya::maps::perf::{PerfBufferError, PerfEventArray};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Ebpf, EbpfLoader};
use bytes::BytesMut;
use installscope_abi::{FsRecord, Header, NetRecord, ProcRecord, MAX_RECORD_SIZE};
use installscope_core::{Backend, HostInfo, IncompleteReason, SessionEnd, Zones};

use crate::merge::{MergeStats, Merger};
use crate::session::SessionWriter;
use crate::{translate, RecorderError, Result, AGENT_VERSION};

/// Map holding the tracked process tree. Must match the name in the eBPF program.
const TRACKED_PIDS_MAP: &str = "TRACKED_PIDS";

/// Perf output maps, one per record type.
///
/// Three rather than one because `PerfEventArray<T>` is a typed channel: `output` sends exactly
/// `size_of::<T>()` bytes. A single map would have to carry the largest record for every event, spending
/// 1,600 bytes to report a 592-byte write — the difference between a ring that keeps up during a tarball
/// extraction and one that drops records, and dropped records force PARTIAL.
///
/// Ordering is unaffected: [`Merger`] sorts by `ktime_ns` across every source, so which map a record
/// arrived on is irrelevant by the time it reaches the stream.
const EVENT_MAPS: &[&str] = &["FS_EVENTS", "NET_EVENTS", "PROC_EVENTS"];

/// Every program in the object, paired with the tracepoint it attaches to.
///
/// Listed as data rather than a sequence of calls so the loader can report exactly which attachment
/// failed. On a kernel missing one of these, that distinction is the difference between "eBPF is
/// unavailable" and "this one tracepoint moved".
const PROGRAMS: &[(&str, &str, &str, bool)] = &[
    (
        "installscope_openat_enter",
        "syscalls",
        "sys_enter_openat",
        true,
    ),
    (
        "installscope_openat_exit",
        "syscalls",
        "sys_exit_openat",
        true,
    ),
    ("installscope_write", "syscalls", "sys_enter_write", true),
    ("installscope_close", "syscalls", "sys_enter_close", true),
    (
        "installscope_mkdirat",
        "syscalls",
        "sys_enter_mkdirat",
        true,
    ),
    ("installscope_mkdir", "syscalls", "sys_enter_mkdir", false),
    (
        "installscope_renameat",
        "syscalls",
        "sys_enter_renameat2",
        true,
    ),
    ("installscope_rename", "syscalls", "sys_enter_rename", false),
    (
        "installscope_unlinkat",
        "syscalls",
        "sys_enter_unlinkat",
        true,
    ),
    ("installscope_unlink", "syscalls", "sys_enter_unlink", false),
    ("installscope_rmdir", "syscalls", "sys_enter_rmdir", false),
    (
        "installscope_symlinkat",
        "syscalls",
        "sys_enter_symlinkat",
        true,
    ),
    (
        "installscope_symlink",
        "syscalls",
        "sys_enter_symlink",
        false,
    ),
    ("installscope_linkat", "syscalls", "sys_enter_linkat", true),
    ("installscope_link", "syscalls", "sys_enter_link", false),
    ("installscope_chmod", "syscalls", "sys_enter_chmod", false),
    (
        "installscope_fchmodat",
        "syscalls",
        "sys_enter_fchmodat",
        true,
    ),
    (
        "installscope_truncate",
        "syscalls",
        "sys_enter_truncate",
        false,
    ),
    (
        "installscope_connect",
        "syscalls",
        "sys_enter_connect",
        true,
    ),
    ("installscope_execve", "syscalls", "sys_enter_execve", true),
    (
        "installscope_sched_fork",
        "sched",
        "sched_process_fork",
        true,
    ),
    (
        "installscope_sched_exit",
        "sched",
        "sched_process_exit",
        true,
    ),
];

/// Per-CPU perf buffer page count.
///
/// 64 pages (256 KiB) per CPU. Chosen because the Phase 1 corpus showed ~2,200 events for a small
/// install arriving in bursts during tarball extraction; a smaller ring would drop records under that
/// burst, and dropped records force PARTIAL. Memory cost is bounded and small next to an install.
const PERF_PAGES: usize = 64;

/// How often the drain thread polls when buffers are empty.
const DRAIN_IDLE_SLEEP: Duration = Duration::from_millis(10);

/// Configuration for one aya recording.
#[derive(Debug, Clone)]
pub struct RecordConfig {
    /// The command to record, argv style. Never passed through a shell.
    pub command: Vec<String>,
    /// Compiled eBPF object.
    pub object: PathBuf,
    /// Directory for the event stream and metadata.
    pub out_dir: PathBuf,
    /// Wall-clock budget. `None` means no limit.
    pub timeout: Option<Duration>,
    /// Working directory for the command.
    pub cwd: Option<PathBuf>,
    /// Directories that give paths meaning downstream.
    pub zones: Zones,
    /// Extra environment for the command.
    pub env: BTreeMap<String, String>,
    /// Cap on emitted events.
    pub event_cap: u64,
}

impl RecordConfig {
    /// A configuration with defaults for everything but the command, object, and output directory.
    #[must_use]
    pub fn new(command: Vec<String>, object: PathBuf, out_dir: PathBuf) -> Self {
        Self {
            command,
            object,
            out_dir,
            timeout: None,
            cwd: None,
            zones: Zones::default(),
            env: BTreeMap::new(),
            event_cap: crate::parser::DEFAULT_EVENT_CAP,
        }
    }
}

/// What an aya recording produced.
#[derive(Debug, Clone)]
pub struct Recording {
    /// Path to the JSONL event stream.
    pub events_path: PathBuf,
    /// The `session_end` that was written. Its `complete` flag is the PARTIAL decision.
    pub session_end: SessionEnd,
    /// Exit code of the recorded command.
    pub command_exit_code: Option<i32>,
    /// Merge diagnostics.
    pub merge_stats: MergeStats,
    /// Which programs attached, for the capability record.
    pub attached: Vec<String>,
}

impl Recording {
    /// True when the report must show PARTIAL.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.session_end.complete
    }
}

/// One record drained from a perf buffer, still in ABI form.
///
/// The size disparity between variants is deliberate: boxing the small ones would add an allocation per
/// event on the hot drain path, and [`ProcRecord`] is boxed already because it is by far the largest.
#[allow(clippy::large_enum_variant)]
enum RawRecord {
    Fs(FsRecord),
    Net(NetRecord),
    Proc(Box<ProcRecord>),
    Close {
        header: Header,
        fd: i32,
    },
    /// The kernel reported dropping `count` records because a ring was full.
    Lost(u64),
}

/// Checks the preconditions eBPF needs, returning why it is unavailable rather than a bare bool.
///
/// Called before anything is created so the failure is actionable. `perf_event_paranoid` and
/// `unprivileged_bpf_disabled` were observed at their most restrictive values on the G1 runner and BPF
/// still worked under root, so they are reported rather than treated as blockers.
///
/// # Errors
/// [`RecorderError::BackendMissing`] when the compiled eBPF object is absent. Note that a non-root euid
/// is *reported*, not rejected: the point is to learn what the host actually permits rather than to
/// assume, which is the same reasoning the G1 gate used.
pub fn check_available(object: &Path) -> Result<AyaCapabilities> {
    let euid = users_euid();
    let btf = Path::new("/sys/kernel/btf/vmlinux");

    if !object.exists() {
        return Err(RecorderError::BackendMissing {
            tool: "installscope-ebpf object (build recorder/aya-ebpf first)",
        });
    }

    Ok(AyaCapabilities {
        euid,
        is_root: euid == 0,
        btf_present: btf.exists(),
        btf_bytes: std::fs::metadata(btf).ok().map(|m| m.len()),
        perf_event_paranoid: read_trimmed("/proc/sys/kernel/perf_event_paranoid"),
        unprivileged_bpf_disabled: read_trimmed("/proc/sys/kernel/unprivileged_bpf_disabled"),
        kernel: read_trimmed("/proc/sys/kernel/osrelease"),
    })
}

/// Facts about the host's eBPF support, recorded so a failure is diagnosable later.
#[derive(Debug, Clone)]
pub struct AyaCapabilities {
    /// Effective uid of the recorder.
    pub euid: u32,
    /// Whether the recorder is root. BPF load needs `CAP_BPF`/`CAP_PERFMON`.
    pub is_root: bool,
    /// Whether kernel BTF is available.
    pub btf_present: bool,
    /// Size of the BTF blob.
    pub btf_bytes: Option<u64>,
    /// `/proc/sys/kernel/perf_event_paranoid`.
    pub perf_event_paranoid: Option<String>,
    /// `/proc/sys/kernel/unprivileged_bpf_disabled`.
    pub unprivileged_bpf_disabled: Option<String>,
    /// `uname -r`.
    pub kernel: Option<String>,
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn users_euid() -> u32 {
    // Safety: geteuid reads process state, takes no arguments, and cannot fail.
    unsafe {
        extern "C" {
            fn geteuid() -> u32;
        }
        geteuid()
    }
}

/// Records `config.command` under the aya backend.
///
/// Always writes a terminated session. Every failure path ends with a `session_end` carrying an explicit
/// [`IncompleteReason`], because a recorder that dies quietly is the worst outcome this project can
/// produce (`Rules.md` §2).
///
/// # Errors
/// [`RecorderError::EmptyCommand`] for an empty command, [`RecorderError::BackendMissing`] when the eBPF
/// object is absent, [`RecorderError::Io`] when the output directory or event stream cannot be created,
/// and [`RecorderError::Spawn`] when the perf map is missing or cannot be opened. Note what is *not* an
/// error: a failed install, a timeout, a partial attach, or lost records all return `Ok` with a PARTIAL
/// [`Recording`], because those are results to report rather than failures to propagate.
#[allow(clippy::too_many_lines)]
pub fn record(config: &RecordConfig) -> Result<Recording> {
    if config.command.is_empty() {
        return Err(RecorderError::EmptyCommand);
    }
    // Same resolution as the strace backend, for the same reason: the child runs with a caller-chosen
    // working directory, so a relative program path would be resolved against the wrong one. Failing here
    // names the command line instead of leaving an empty recording that blames the backend.
    let resolved_command = crate::resolve_program(&config.command, config.cwd.as_deref())?;
    let capabilities = check_available(&config.object)?;

    std::fs::create_dir_all(&config.out_dir)
        .map_err(|source| RecorderError::io(&config.out_dir, source))?;
    // Absolute, for the same reason the strace backend canonicalizes: the child runs with a different
    // cwd, and a relative path would resolve against the wrong directory.
    let out_dir = std::fs::canonicalize(&config.out_dir)
        .map_err(|source| RecorderError::io(&config.out_dir, source))?;

    let events_path = out_dir.join("events.jsonl");
    let events_file = std::fs::File::create(&events_path)
        .map_err(|source| RecorderError::io(&events_path, source))?;

    let mut zones = config.zones.clone();
    if let Some(out) = out_dir.to_str() {
        if !zone_covers(&zones, out) {
            zones.extra.push(out.to_string());
        }
    }

    let wall_clock = SystemTime::now();
    // The anchor: one wall-clock reading paired with one kernel-clock reading. Every event's ktime is
    // expressed relative to this, so the stream needs no per-event clock conversion.
    let session_start_ktime = read_boottime_ns().unwrap_or(0);

    let mut session = SessionWriter::start(
        std::io::BufWriter::new(events_file),
        crate::clock::rfc3339_utc(wall_clock),
        AGENT_VERSION,
        Backend::Aya,
        resolved_command.clone(),
        zones,
        Some(host_info(&capabilities)),
    )?;

    // ---- load and attach -----------------------------------------------------------------------
    let mut ebpf = match EbpfLoader::new().load_file(&config.object) {
        Ok(ebpf) => ebpf,
        Err(err) => {
            let end = session.finish_partial(
                IncompleteReason::BackendFailedToStart {
                    detail: format!("loading {}: {err}", config.object.display()),
                },
                Vec::new(),
                None,
            )?;
            return Ok(Recording {
                events_path,
                session_end: end,
                command_exit_code: None,
                merge_stats: MergeStats::default(),
                attached: Vec::new(),
            });
        }
    };

    let mut attached = Vec::new();
    let mut attach_failures = Vec::new();
    for (program_name, category, event, required) in PROGRAMS {
        match attach_tracepoint(&mut ebpf, program_name, category, event) {
            Ok(()) => attached.push((*program_name).to_string()),
            Err(detail) => {
                if *required {
                    attach_failures.push(detail);
                }
            }
        }
    }

    // A partial attach is a partial recording, not a failure: eight of ten probes still produce real
    // evidence. But the report must say which event classes are missing rather than letting a reader
    // infer their absence means the install did not do those things.
    if attached.is_empty() {
        let end = session.finish_partial(
            IncompleteReason::BackendFailedToStart {
                detail: format!("no programs attached: {}", attach_failures.join("; ")),
            },
            Vec::new(),
            None,
        )?;
        return Ok(Recording {
            events_path,
            session_end: end,
            command_exit_code: None,
            merge_stats: MergeStats::default(),
            attached,
        });
    }

    // ---- open perf buffers before the command starts --------------------------------------------
    // Order matters: buffers must exist before the first event can occur, or the earliest and most
    // interesting behavior is lost.
    //
    // One drain thread per (map, cpu). All of them feed the same channel, and the merger orders by
    // ktime_ns, so the split across maps is invisible downstream.
    let cpus = online_cpus().map_err(|(msg, err)| RecorderError::Spawn {
        what: format!("online_cpus: {msg}"),
        source: err,
    })?;

    let (sender, receiver) = mpsc::channel::<RawRecord>();
    let stop = Arc::new(AtomicBool::new(false));
    let mut drain_threads = Vec::new();

    for map_name in EVENT_MAPS {
        let map = ebpf
            .take_map(map_name)
            .ok_or_else(|| RecorderError::Spawn {
                what: format!("map {map_name} not found in object"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing map"),
            })?;
        let mut perf_array: PerfEventArray<_> =
            PerfEventArray::try_from(map).map_err(|err| RecorderError::Spawn {
                what: format!("{map_name} is not a PerfEventArray: {err}"),
                source: std::io::Error::other("map type mismatch"),
            })?;

        for cpu in &cpus {
            let buffer =
                perf_array
                    .open(*cpu, Some(PERF_PAGES))
                    .map_err(|err| RecorderError::Spawn {
                        what: format!("opening {map_name} perf buffer for cpu {cpu}: {err}"),
                        source: std::io::Error::other("perf open failed"),
                    })?;
            let sender = sender.clone();
            let stop = Arc::clone(&stop);
            drain_threads.push(std::thread::spawn(move || {
                drain_cpu(buffer, &sender, &stop);
            }));
        }
    }
    // The original sender must go, or the receive loop below never sees a disconnect.
    drop(sender);

    // ---- spawn the command ----------------------------------------------------------------------
    let mut command = Command::new(&resolved_command[0]);
    command.args(&resolved_command[1..]);
    if let Some(dir) = &config.cwd {
        command.current_dir(dir);
    }
    for (key, value) in &config.env {
        command.env(key, value);
    }
    // Files, not pipes: an unread pipe fills its buffer and deadlocks a verbose install. Learned in
    // Phase 1 (see strace.rs).
    let stdout_path = out_dir.join("command-stdout.log");
    let stderr_path = out_dir.join("command-stderr.log");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(&stdout_path)
                .map_err(|source| RecorderError::io(&stdout_path, source))?,
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&stderr_path)
                .map_err(|source| RecorderError::io(&stderr_path, source))?,
        ));

    let started = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            stop.store(true, Ordering::Relaxed);
            for handle in drain_threads {
                let _ = handle.join();
            }
            let end = session.finish_partial(
                IncompleteReason::BackendFailedToStart {
                    detail: format!("spawning the command: {source}"),
                },
                Vec::new(),
                None,
            )?;
            return Ok(Recording {
                events_path,
                session_end: end,
                command_exit_code: None,
                merge_stats: MergeStats::default(),
                attached,
            });
        }
    };

    // Seed the tracked set with the child's pid. Everything it forks is added in-kernel, which closes
    // the race a userspace-maintained set cannot: a child can exec and write before we learn it exists.
    let root_pid = child.id();
    if let Some(map) = ebpf.map_mut(TRACKED_PIDS_MAP) {
        if let Ok(mut tracked) = aya::maps::HashMap::<_, u32, u8>::try_from(map) {
            let _ = tracked.insert(root_pid, 1, 0);
        }
    }

    // ---- merge and write while the command runs -------------------------------------------------
    let mut merger = Merger::new();
    let mut newest_ktime = 0u64;
    let mut timed_out = false;
    let mut cap_reached = false;

    let exit_status = loop {
        // Drain whatever the threads have handed over. A short timeout keeps this loop responsive to
        // both new records and the command exiting.
        match receiver.recv_timeout(DRAIN_IDLE_SLEEP) {
            Ok(record) => {
                newest_ktime = newest_ktime.max(feed(&mut merger, record));
                let ready = merger.drain_ready(newest_ktime);
                if write_merged(&mut session, &ready, session_start_ktime, config.event_cap)? {
                    cap_reached = true;
                }
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
        }

        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(source) => {
                stop.store(true, Ordering::Relaxed);
                let end = session.finish_partial(
                    IncompleteReason::BackendDied {
                        detail: format!("waiting for the command: {source}"),
                    },
                    Vec::new(),
                    None,
                )?;
                return Ok(Recording {
                    events_path,
                    session_end: end,
                    command_exit_code: None,
                    merge_stats: merger.stats().clone(),
                    attached,
                });
            }
        }

        if let Some(limit) = config.timeout {
            if started.elapsed() >= limit {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let command_exit_code = exit_status.and_then(|status| status.code());

    // The command has exited, but its last events may still be in a ring. Keep draining briefly rather
    // than cutting the recording at the exact moment of exit — the final writes of a postinstall script
    // are exactly the ones worth having.
    let grace_deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < grace_deadline {
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(record) => {
                newest_ktime = newest_ktime.max(feed(&mut merger, record));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    stop.store(true, Ordering::Relaxed);
    for handle in drain_threads {
        let _ = handle.join();
    }
    // Anything the threads produced before stopping.
    while let Ok(record) = receiver.try_recv() {
        newest_ktime = newest_ktime.max(feed(&mut merger, record));
    }

    let trailing = merger.finish();
    if write_merged(
        &mut session,
        &trailing,
        session_start_ktime,
        config.event_cap,
    )? {
        cap_reached = true;
    }

    let merge_stats = merger.stats().clone();

    // ---- decide complete vs PARTIAL -------------------------------------------------------------
    let mut reasons = Vec::new();
    if timed_out {
        reasons.push(IncompleteReason::Timeout {
            limit_secs: config.timeout.map_or(0, |t| t.as_secs()),
        });
    }
    if cap_reached {
        reasons.push(IncompleteReason::EventCapReached {
            cap: config.event_cap,
        });
    }
    if merge_stats.indicates_data_loss() {
        reasons.push(IncompleteReason::TraceTruncated {
            detail: format!(
                "the kernel dropped {} perf records because a ring buffer filled",
                merge_stats.lost_records
            ),
        });
    }
    if !attach_failures.is_empty() {
        // Some REQUIRED event classes were never observed. Saying so is the difference between "the install did
        // not do X" and "we could not see X".
        reasons.push(IncompleteReason::Other {
            detail: format!(
                "{} required probes failed to attach: {}",
                attach_failures.len(),
                attach_failures.join("; ")
            ),
        });
    }

    let session_end = if reasons.is_empty() {
        session.finish_complete(command_exit_code)?
    } else {
        let mut iter = reasons.into_iter();
        let first = iter.next().unwrap_or(IncompleteReason::Other {
            detail: "recording incomplete for an unrecorded reason".to_string(),
        });
        session.finish_partial(first, iter.collect(), command_exit_code)?
    };

    Ok(Recording {
        events_path,
        session_end,
        command_exit_code,
        merge_stats,
        attached,
    })
}

/// Feeds one raw record into the merger, returning its kernel timestamp.
fn feed(merger: &mut Merger, record: RawRecord) -> u64 {
    match record {
        RawRecord::Fs(fs) => {
            let ktime = fs.header.ktime_ns;
            merger.push_fs(&fs);
            ktime
        }
        RawRecord::Net(net) => {
            let ktime = net.header.ktime_ns;
            merger.push_net(net);
            ktime
        }
        RawRecord::Proc(proc_record) => {
            let ktime = proc_record.header.ktime_ns;
            merger.push_proc(*proc_record);
            ktime
        }
        RawRecord::Close { header, fd } => {
            let ktime = header.ktime_ns;
            merger.push_close(&header, fd);
            ktime
        }
        RawRecord::Lost(count) => {
            merger.note_lost(count);
            0
        }
    }
}

/// Writes merged records as schema v1 events. Returns true if the cap was hit.
fn write_merged<W: std::io::Write>(
    session: &mut SessionWriter<W>,
    merged: &[crate::merge::Merged],
    session_start_ktime: u64,
    event_cap: u64,
) -> Result<bool> {
    for record in merged {
        if session.events_emitted() >= event_cap {
            return Ok(true);
        }
        if let Some(event) = translate::to_event(record, session_start_ktime) {
            session.write_event(&event)?;
        }
    }
    Ok(false)
}

/// Attaches one program, returning a description of the failure rather than an opaque error.
fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> std::result::Result<(), String> {
    let program = ebpf
        .program_mut(program_name)
        .ok_or_else(|| format!("{program_name}: not present in the object"))?;
    let tracepoint: &mut TracePoint = program
        .try_into()
        .map_err(|err| format!("{program_name}: not a tracepoint: {err}"))?;
    tracepoint
        .load()
        .map_err(|err| format!("{program_name}: verifier rejected it: {err}"))?;
    tracepoint
        .attach(category, event)
        .map_err(|err| format!("{program_name}: attaching to {category}:{event}: {err}"))?;
    Ok(())
}

/// Drains one CPU's perf buffer until told to stop.
///
/// Runs on its own thread because a ring buffer that is not drained is overwritten — unlike strace's
/// files, which can be read at leisure after the fact.
///
/// The `BorrowMut<MapData>` bound is what `read_events` requires; it is satisfied by the buffer aya
/// hands back from `PerfEventArray::open`.
fn drain_cpu<T: std::borrow::BorrowMut<aya::maps::MapData>>(
    mut buffer: aya::maps::perf::PerfEventArrayBuffer<T>,
    sender: &mpsc::Sender<RawRecord>,
    stop: &AtomicBool,
) {
    let mut buffers: Vec<BytesMut> = (0..16)
        .map(|_| BytesMut::with_capacity(MAX_RECORD_SIZE))
        .collect();

    while !stop.load(Ordering::Relaxed) {
        match buffer.read_events(&mut buffers) {
            Ok(events) => {
                if events.lost > 0 {
                    // The kernel telling us it discarded records. Forwarded rather than logged and
                    // forgotten: this is the one condition here that forces PARTIAL.
                    let _ = sender.send(RawRecord::Lost(events.lost as u64));
                }
                for item in buffers.iter().take(events.read) {
                    if let Some(record) = decode_record(item) {
                        if sender.send(record).is_err() {
                            return; // receiver gone; the session is finishing
                        }
                    }
                }
                if events.read == 0 {
                    std::thread::sleep(DRAIN_IDLE_SLEEP);
                }
            }
            Err(PerfBufferError::NoBuffers) => std::thread::sleep(DRAIN_IDLE_SLEEP),
            Err(err) => {
                tracing::warn!(error = %err, "perf buffer read failed; stopping this cpu's drain");
                return;
            }
        }
    }
}

/// Interprets a perf record's bytes as the ABI struct its header names.
///
/// Returns `None` for a record shorter than its declared kind requires. That would mean the kernel and
/// userspace disagree about layout, in which case reading it would produce garbage paths — the
/// `abi` crate's size assertions exist to catch this at build time, and this is the runtime backstop.
fn decode_record(bytes: &[u8]) -> Option<RawRecord> {
    if bytes.len() < core::mem::size_of::<Header>() {
        return None;
    }
    // Safety: the kernel wrote a #[repr(C)] struct here. read_unaligned because perf records carry no
    // alignment guarantee.
    let header: Header = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Header>()) };

    match header.kind {
        installscope_abi::KIND_FS_WRITE | installscope_abi::KIND_FS_READ => {
            if bytes.len() < core::mem::size_of::<FsRecord>() {
                return None;
            }
            let record: FsRecord =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<FsRecord>()) };
            Some(RawRecord::Fs(record))
        }
        installscope_abi::KIND_FD_CLOSE => {
            if bytes.len() < core::mem::size_of::<FsRecord>() {
                return None;
            }
            let record: FsRecord =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<FsRecord>()) };
            Some(RawRecord::Close {
                header: record.header,
                fd: record.fd,
            })
        }
        installscope_abi::KIND_NET_CONNECT => {
            if bytes.len() < core::mem::size_of::<NetRecord>() {
                return None;
            }
            let record: NetRecord =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<NetRecord>()) };
            Some(RawRecord::Net(record))
        }
        installscope_abi::KIND_PROC_SPAWN => {
            if bytes.len() < core::mem::size_of::<ProcRecord>() {
                return None;
            }
            let record: ProcRecord =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<ProcRecord>()) };
            Some(RawRecord::Proc(Box::new(record)))
        }
        _ => None,
    }
}

/// Reads `CLOCK_BOOTTIME` in nanoseconds, matching `bpf_ktime_get_ns`.
///
/// Returns `None` if the clock cannot be read, in which case the caller anchors at zero and timestamps
/// become boot-relative rather than session-relative. Ordering still holds; only the origin shifts.
fn read_boottime_ns() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let seconds: f64 = uptime.split_whitespace().next()?.parse().ok()?;
    // Truncation is fine: this is a monotonic anchor, and sub-nanosecond precision is meaningless.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some((seconds * 1e9) as u64)
}

fn host_info(capabilities: &AyaCapabilities) -> HostInfo {
    HostInfo {
        kernel: capabilities.kernel.clone(),
        os: std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|line| {
                    line.strip_prefix("PRETTY_NAME=")
                        .map(|v| v.trim_matches('"').to_string())
                })
            }),
        arch: Some(std::env::consts::ARCH.to_string()),
        backend_version: Some(format!(
            "aya 0.13.1 (btf={}, euid={})",
            capabilities.btf_present, capabilities.euid
        )),
    }
}

fn zone_covers(zones: &Zones, path: &str) -> bool {
    [
        zones.project.as_deref(),
        zones.cache.as_deref(),
        zones.home.as_deref(),
        zones.tmp.as_deref(),
    ]
    .into_iter()
    .flatten()
    .chain(zones.extra.iter().map(String::as_str))
    .any(|zone| path == zone || path.starts_with(&format!("{}/", zone.trim_end_matches('/'))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_program_has_a_distinct_name_and_tracepoint() {
        // A duplicated program name would silently attach one probe twice and leave another unattached,
        // producing double-counted events for one class and none for another.
        let mut names: Vec<&str> = PROGRAMS.iter().map(|(name, _, _, _)| *name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate program name in PROGRAMS");

        let mut targets: Vec<(&str, &str)> = PROGRAMS
            .iter()
            .map(|(_, category, event, _)| (*category, *event))
            .collect();
        targets.sort_unstable();
        let count = targets.len();
        targets.dedup();
        assert_eq!(targets.len(), count, "duplicate tracepoint in PROGRAMS");
    }

    #[test]
    fn the_program_list_covers_every_event_class_phase_2_promises() {
        // Phases.md:23 names fs write, tcp connect, and proc spawn. A missing probe would produce a
        // recording that looks clean because it never watched.
        let events: Vec<&str> = PROGRAMS.iter().map(|(_, _, event, _)| *event).collect();
        for required in [
            "sys_enter_openat",
            "sys_exit_openat",
            "sys_enter_write",
            "sys_enter_close",
            "sys_enter_connect",
            "sys_enter_execve",
        ] {
            assert!(events.contains(&required), "{required} is not attached");
        }
        // Process-tree tracking is what keeps this a recorder rather than a system monitor.
        assert!(events.contains(&"sched_process_fork"));
        assert!(events.contains(&"sched_process_exit"));
    }

    #[test]
    fn a_short_record_is_rejected_rather_than_misread() {
        // A truncated record means the ABI is out of sync. Reading it anyway would produce a plausible
        // but wrong path — the exact failure the abi crate's size assertions guard against at build
        // time. This is the runtime backstop.
        let mut header = Header::zeroed();
        header.kind = installscope_abi::KIND_FS_WRITE;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&header).cast::<u8>(),
                core::mem::size_of::<Header>(),
            )
        };
        assert!(
            decode_record(bytes).is_none(),
            "a header-sized buffer is too short for an FsRecord"
        );
        assert!(decode_record(&[]).is_none());
    }

    #[test]
    fn an_unknown_record_kind_is_ignored_not_guessed() {
        let mut header = Header::zeroed();
        header.kind = 9_999;
        let padded = vec![0u8; core::mem::size_of::<ProcRecord>()];
        let mut bytes = padded;
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&header).cast::<u8>(),
                core::mem::size_of::<Header>(),
            )
        };
        bytes[..header_bytes.len()].copy_from_slice(header_bytes);
        assert!(decode_record(&bytes).is_none());
    }

    #[test]
    fn a_full_fs_record_decodes() {
        let mut record = FsRecord::zeroed();
        record.header.kind = installscope_abi::KIND_FS_WRITE;
        record.header.ktime_ns = 12_345;
        record.write_kind = installscope_abi::WRITE_OPEN;
        record.fd = 7;
        let path = b"/work/file";
        record.path[..path.len()].copy_from_slice(path);
        record.path_len = u32::try_from(path.len()).unwrap_or(0);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&record).cast::<u8>(),
                core::mem::size_of::<FsRecord>(),
            )
        };
        match decode_record(bytes) {
            Some(RawRecord::Fs(decoded)) => {
                assert_eq!(decoded.header.ktime_ns, 12_345);
                assert_eq!(decoded.fd, 7);
                assert_eq!(decoded.path_bytes(), path);
            }
            _ => panic!("expected an Fs record"),
        }
    }

    #[test]
    fn a_close_record_is_routed_to_the_close_path() {
        // KIND_FD_CLOSE shares FsRecord's layout but must not be treated as a write, or every close
        // would appear as a zero-byte write event.
        let mut record = FsRecord::zeroed();
        record.header.kind = installscope_abi::KIND_FD_CLOSE;
        record.fd = 3;
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&record).cast::<u8>(),
                core::mem::size_of::<FsRecord>(),
            )
        };
        match decode_record(bytes) {
            Some(RawRecord::Close { fd, .. }) => assert_eq!(fd, 3),
            _ => panic!("expected a Close record"),
        }
    }

    #[test]
    fn zone_coverage_matches_prefixes_not_substrings() {
        let zones = Zones {
            project: Some("/work/project".to_string()),
            ..Zones::default()
        };
        assert!(zone_covers(&zones, "/work/project"));
        assert!(zone_covers(&zones, "/work/project/sub/file"));
        // "/work/project-evil" must not count as inside "/work/project": a substring match here would
        // silently exempt a sibling directory from outside-zone findings.
        assert!(!zone_covers(&zones, "/work/project-evil"));
        assert!(!zone_covers(&zones, "/etc/passwd"));
    }
}
