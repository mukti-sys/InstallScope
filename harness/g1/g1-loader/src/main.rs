//! G1 loader — load the eBPF probe, attach it, receive at least one event, write receipts.
//!
//! Gate tooling, not product code (harness/README.md). Phase 2 writes the real backend under
//! `recorder/aya/`.
//!
//! The gate question is narrow: *does an aya program load and deliver an event on a stock
//! `ubuntu-latest` runner?* So this binary does four things and stops:
//!   1. record the environment (kernel, BTF presence, capabilities) BEFORE loading
//!   2. load + attach a tracepoint program
//!   3. exec `/bin/true` so an event is certain to occur
//!   4. write `g1-result.json` + `g1-events.jsonl`, and exit non-zero if no event arrived
//!
//! It always writes the result file, including on failure — a gate that fails without leaving
//! diagnostics costs another hour to re-run (Rules.md §2: fail loud).
//!
//! # Unverified API assumptions (Rules.md §5)
//!
//! This was written without a local cargo toolchain, so the aya API surface used below is
//! **unverified**. Each assumption is listed here so the first failing build is a five-minute fix
//! against `Cargo.lock` rather than a guessing game:
//!
//! - `aya::EbpfLoader::new().load_file(path)` returns `Ebpf`. Older releases name the type `Bpf`
//!   and the loader `BpfLoader`; aya 0.13 renamed them.
//! - `Ebpf::program_mut(name)` yields something convertible to `&mut TracePoint` via `try_into`,
//!   and `TracePoint::attach(category, name)` takes two `&str`.
//! - `Ebpf::take_map(name)` returns `Option<Map>`, and `PerfEventArray::try_from(map)` works on it.
//! - `aya::util::online_cpus()` returns `Result<Vec<u32>, _>`.
//! - `PerfEventArray::open(cpu, None)` returns a buffer with
//!   `read_events(&mut [BytesMut]) -> Result<Events, _>` where `Events { read, lost }`.
//!
//! The program name looked up at runtime is `g1_execve`, matching the `#[tracepoint]` function in
//! `g1-ebpf`. aya derives the ELF section name from that function name.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Ebpf, EbpfLoader};
use bytes::BytesMut;
use clap::Parser;
use g1_common::ExecEvent;
use serde::Serialize;

/// Tracepoint category and name. `sys_enter_execve` is chosen because it is stable across kernels
/// and trivially triggerable, unlike anything requiring CO-RE struct access.
const TP_CATEGORY: &str = "syscalls";
const TP_NAME: &str = "sys_enter_execve";
const MAP_NAME: &str = "G1_EVENTS";
const PROGRAM_NAME: &str = "g1_execve";

#[derive(Parser, Debug)]
#[command(name = "g1-loader", about = "Phase 0 gate G1: prove aya loads and delivers on a runner")]
struct Args {
    /// Compiled eBPF object (bpfel-unknown-none ELF).
    #[arg(long, default_value = "g1-ebpf/target/bpfel-unknown-none/release/g1-ebpf")]
    object: PathBuf,

    /// Where to write the machine-readable gate result.
    #[arg(long, default_value = "g1-result.json")]
    out: PathBuf,

    /// Where to write received events as JSONL.
    #[arg(long, default_value = "g1-events.jsonl")]
    events: PathBuf,

    /// How long to wait for at least one event.
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Skip the self-triggered exec. Only useful for observing organic traffic; makes the gate
    /// non-deterministic, so it is off by default.
    #[arg(long, default_value_t = false)]
    no_trigger: bool,
}

#[derive(Serialize, Clone)]
struct EnvInfo {
    kernel_release: String,
    os_pretty_name: String,
    arch: String,
    btf_vmlinux_present: bool,
    btf_vmlinux_bytes: Option<u64>,
    tracepoint_present: bool,
    unprivileged_bpf_disabled: Option<String>,
    perf_event_paranoid: Option<String>,
    euid: u32,
    runner_image_os: Option<String>,
    runner_image_version: Option<String>,
    aya_version: &'static str,
}

#[derive(Serialize)]
struct EventOut {
    ktime_ns: u64,
    tgid: u32,
    pid: u32,
    uid: u32,
    comm: Option<String>,
}

#[derive(Serialize)]
struct Result_ {
    gate: &'static str,
    loader_version: &'static str,
    recorded_at: String,
    passed: bool,
    failure_stage: Option<String>,
    failure_detail: Option<String>,
    program: &'static str,
    tracepoint: String,
    object_path: String,
    object_bytes: Option<u64>,
    load_ok: bool,
    attach_ok: bool,
    events_received: usize,
    events_lost: u64,
    triggered_self_exec: bool,
    wait_ms: u128,
    online_cpus: usize,
    env: EnvInfo,
    first_events: Vec<EventOut>,
    /// Stated so a green run is not over-read. A pass covers tracepoints on this image today,
    /// nothing more.
    proves: &'static str,
    does_not_prove: &'static str,
    fallback_if_failed: &'static str,
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn os_pretty_name() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn uname_field(flag: &str) -> String {
    Command::new("uname")
        .arg(flag)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn collect_env() -> EnvInfo {
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    let tp_path = format!("/sys/kernel/debug/tracing/events/{TP_CATEGORY}/{TP_NAME}");
    // Reading the debugfs path needs root; fall back to the tracefs mount which is often readable.
    let tp_alt = format!("/sys/kernel/tracing/events/{TP_CATEGORY}/{TP_NAME}");

    EnvInfo {
        kernel_release: uname_field("-r"),
        os_pretty_name: os_pretty_name(),
        arch: uname_field("-m"),
        btf_vmlinux_present: btf.exists(),
        btf_vmlinux_bytes: fs::metadata(btf).ok().map(|m| m.len()),
        tracepoint_present: Path::new(&tp_path).exists() || Path::new(&tp_alt).exists(),
        unprivileged_bpf_disabled: read_trim("/proc/sys/kernel/unprivileged_bpf_disabled"),
        perf_event_paranoid: read_trim("/proc/sys/kernel/perf_event_paranoid"),
        // Safety: geteuid is always safe; it reads process state and cannot fail.
        euid: unsafe { libc_geteuid() },
        runner_image_os: std::env::var("ImageOS").ok(),
        runner_image_version: std::env::var("ImageVersion").ok(),
        aya_version: "see Cargo.lock — pins in Cargo.toml are TODO-verify",
    }
}

/// Minimal geteuid without pulling in the `libc` crate for one call.
///
/// Safety: the syscall takes no arguments, touches no memory, and cannot fail.
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

fn now_iso() -> String {
    // Formatted by hand to avoid adding a date crate to a throwaway gate binary. Precision to the
    // second is plenty; the authoritative ordering is ktime_ns inside the events.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Howard Hinnant's days-from-civil, inverted. Public-domain algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let args = Args::parse();
    let env = collect_env();
    let started = Instant::now();

    let object_bytes = fs::metadata(&args.object).ok().map(|m| m.len());

    // Every field is filled in as we go so the result file is meaningful no matter where we fail.
    let mut result = Result_ {
        gate: "G1",
        loader_version: "g1-loader-0.1.0",
        recorded_at: now_iso(),
        passed: false,
        failure_stage: None,
        failure_detail: None,
        program: PROGRAM_NAME,
        tracepoint: format!("{TP_CATEGORY}:{TP_NAME}"),
        object_path: args.object.display().to_string(),
        object_bytes,
        load_ok: false,
        attach_ok: false,
        events_received: 0,
        events_lost: 0,
        triggered_self_exec: false,
        wait_ms: 0,
        online_cpus: 0,
        env: env.clone(),
        first_events: Vec::new(),
        proves: "an aya tracepoint program loads and delivers perf events on this runner image, today",
        does_not_prove: "kprobe/fentry support, CO-RE struct reads, BTF-dependent field access, or that a future runner image will still allow this — Phase 2 must re-verify per program type",
        fallback_if_failed: "Scope.md:59 — aya -> libbpf-rs -> strace-only product; the strace backend ships regardless",
    };

    // Run the whole attempt in a closure so a failure still reaches the writer below.
    let outcome = (|| -> Result<()> {
        if !args.object.exists() {
            result.failure_stage = Some("object_missing".into());
            return Err(anyhow!("eBPF object not found at {}", args.object.display()));
        }
        if env.euid != 0 {
            // Not fatal — recorded, then attempted anyway, because the point is to learn what the
            // runner actually permits rather than to assume.
            eprintln!("g1-loader: WARNING: not running as root (euid={}); BPF load will likely fail", env.euid);
        }
        if !env.tracepoint_present {
            eprintln!("g1-loader: WARNING: {TP_CATEGORY}:{TP_NAME} not visible in tracefs; attach may fail");
        }

        // ---- load -------------------------------------------------------------------------------
        result.failure_stage = Some("load".into());
        let mut ebpf: Ebpf = EbpfLoader::new()
            .load_file(&args.object)
            .with_context(|| format!("loading {}", args.object.display()))?;
        result.load_ok = true;

        // ---- attach -----------------------------------------------------------------------------
        result.failure_stage = Some("attach".into());
        let program: &mut TracePoint = ebpf
            .program_mut(PROGRAM_NAME)
            .ok_or_else(|| anyhow!("program `{PROGRAM_NAME}` not found in object"))?
            .try_into()
            .context("program is not a tracepoint")?;
        program.load().context("program.load() — verifier rejection lands here")?;
        program
            .attach(TP_CATEGORY, TP_NAME)
            .with_context(|| format!("attaching to {TP_CATEGORY}:{TP_NAME}"))?;
        result.attach_ok = true;

        // ---- open the perf buffers --------------------------------------------------------------
        result.failure_stage = Some("open_perf_array".into());
        let map = ebpf
            .take_map(MAP_NAME)
            .ok_or_else(|| anyhow!("map `{MAP_NAME}` not found in object"))?;
        let mut perf_array: PerfEventArray<_> =
            PerfEventArray::try_from(map).context("map is not a PerfEventArray")?;

        let cpus = online_cpus().map_err(|e| anyhow!("online_cpus failed: {e:?}"))?;
        result.online_cpus = cpus.len();

        let mut buffers = Vec::new();
        for cpu in &cpus {
            let buf = perf_array
                .open(*cpu, None)
                .with_context(|| format!("opening perf buffer for cpu {cpu}"))?;
            buffers.push(buf);
        }

        // ---- trigger ----------------------------------------------------------------------------
        // Guarantees an event exists. Without this the gate could fail merely because the runner
        // was idle, which would measure nothing.
        if !args.no_trigger {
            result.failure_stage = Some("trigger".into());
            for _ in 0..3 {
                let _ = Command::new("/bin/true").status();
            }
            result.triggered_self_exec = true;
        }

        // ---- receive ----------------------------------------------------------------------------
        result.failure_stage = Some("receive".into());
        let mut scratch: Vec<BytesMut> = (0..16).map(|_| BytesMut::with_capacity(1024)).collect();
        let mut events_file = fs::File::create(&args.events)
            .with_context(|| format!("creating {}", args.events.display()))?;

        let deadline = Instant::now() + Duration::from_millis(args.timeout_ms);
        let wait_start = Instant::now();
        let mut received = 0usize;
        let mut lost = 0u64;

        while Instant::now() < deadline {
            for buf in &mut buffers {
                let ev = buf.read_events(&mut scratch).context("read_events")?;
                lost += ev.lost as u64;
                for item in scratch.iter().take(ev.read) {
                    // Safety: the kernel side wrote a #[repr(C)] ExecEvent into this buffer.
                    // read_unaligned is used because perf records carry no alignment guarantee.
                    if item.len() < std::mem::size_of::<ExecEvent>() {
                        continue;
                    }
                    let parsed: ExecEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<ExecEvent>()) };
                    let out = EventOut {
                        ktime_ns: parsed.ktime_ns,
                        tgid: parsed.tgid,
                        pid: parsed.pid,
                        uid: parsed.uid,
                        comm: parsed.comm_str().map(str::to_string),
                    };
                    writeln!(events_file, "{}", serde_json::to_string(&out)?)?;
                    if result.first_events.len() < 20 {
                        result.first_events.push(out);
                    }
                    received += 1;
                }
            }
            if received > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        events_file.flush()?;
        result.wait_ms = wait_start.elapsed().as_millis();
        result.events_received = received;
        result.events_lost = lost;

        if received == 0 {
            result.failure_stage = Some("no_events".into());
            return Err(anyhow!(
                "loaded and attached, but received 0 events in {}ms — delivery, not loading, is the problem",
                args.timeout_ms
            ));
        }

        result.failure_stage = None;
        result.passed = true;
        Ok(())
    })();

    if let Err(err) = &outcome {
        result.failure_detail = Some(format!("{err:#}"));
        result.passed = false;
    }

    let json = serde_json::to_string_pretty(&result)?;
    fs::write(&args.out, format!("{json}\n"))
        .with_context(|| format!("writing {}", args.out.display()))?;

    eprintln!(
        "g1-loader: passed={} load_ok={} attach_ok={} events={} lost={} elapsed={}ms",
        result.passed,
        result.load_ok,
        result.attach_ok,
        result.events_received,
        result.events_lost,
        started.elapsed().as_millis()
    );

    match outcome {
        Ok(()) => Ok(()),
        Err(err) => {
            eprintln!("g1-loader: FAILED at stage {:?}: {err:#}", result.failure_stage);
            eprintln!("g1-loader: fallback per Scope.md:59 — aya -> libbpf-rs -> strace-only");
            std::process::exit(1);
        }
    }
}
