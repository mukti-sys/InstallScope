//! End-to-end recorder tests. **Linux only, and `#[ignore]`d by default.**
//!
//! These spawn real processes under real `strace`, so they need a Linux host with `strace` installed
//! and, for the npm test, a working `npm`. Ordinary CI (`.github/workflows/rust.yml`) runs the unit
//! and golden suites only; the E2E workflow runs these with `--ignored`.
//!
//! They exist to satisfy the Phase 1 Done condition (`Phases.md`:20): *records real `npm install`
//! end-to-end; golden tests; zero unwraps; complete→clean / crash→PARTIAL tested.* The golden tests
//! in `parse.rs` cover the parser; these cover the parts a fixture cannot: process orchestration,
//! timeouts, signals, and whether a recording that went wrong actually says so.
//!
//! Run locally on Linux:
//! ```sh
//! cargo test -p installscope-recorder --test e2e_linux -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use installscope_core::{IncompleteReason, Payload, WriteKind, Zones};
use installscope_recorder::strace::{self, RecordConfig, Recording};
use installscope_recorder::summarize_stream;

/// Creates a scratch directory for one test, named after the test so failures are traceable.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("installscope-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    dir
}

/// Reads the recorded stream back and returns its events, verifying the artifact rather than the
/// in-memory result. The artifact is what downstream consumes, so the artifact is what is asserted.
fn read_events(recording: &Recording) -> Vec<installscope_core::Event> {
    let contents = std::fs::read_to_string(&recording.events_path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", recording.events_path.display()));
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            installscope_core::Event::from_jsonl(line, i + 1)
                .unwrap_or_else(|e| panic!("line {} is not a valid event: {e}", i + 1))
        })
        .collect()
}

/// Builds a config that records `command` with `out` as both the working directory and the project
/// zone, so writes land inside a zone the rules engine would consider expected.
fn config_for(_name: &str, command: &[&str], out: &Path) -> RecordConfig {
    let mut config = RecordConfig::new(
        command.iter().map(|s| (*s).to_string()).collect(),
        out.join("recording"),
    );
    config.cwd = Some(out.to_path_buf());
    config.zones = Zones {
        project: out.to_str().map(ToString::to_string),
        cache: out.join("cache").to_str().map(ToString::to_string),
        home: out.join("home").to_str().map(ToString::to_string),
        tmp: out.join("tmp").to_str().map(ToString::to_string),
        extra: Vec::new(),
    };
    config
}

/// Skips rather than fails when the host lacks a tool. A missing `strace` is an environment problem,
/// and dressing it up as a test failure would train people to ignore red.
fn require(tool: &str) -> bool {
    let found = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        eprintln!("SKIP: {tool} is not installed on this host");
    }
    found
}

// =============================================================================================
// complete → clean
// =============================================================================================

#[test]
#[ignore = "needs Linux with strace installed"]
fn a_simple_command_records_cleanly() {
    if !require("strace") {
        return;
    }
    let dir = scratch("simple");
    let config = config_for("simple", &["/bin/sh", "-c", "echo hello > out.txt"], &dir);

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));

    assert!(
        !recording.is_partial(),
        "a command that ran to completion must record as complete, got reasons: {:?}",
        recording.session_end.incomplete_reasons
    );
    assert_eq!(recording.command_exit_code, Some(0));

    let contents = std::fs::read_to_string(&recording.events_path)
        .unwrap_or_else(|e| panic!("reading the stream: {e}"));
    let summary = summarize_stream(&contents).unwrap_or_else(|e| panic!("summarizing: {e}"));
    assert!(
        summary.has_session_start,
        "stream must open with session_start"
    );
    assert!(!summary.is_partial());
    assert!(summary.events > 0, "a shell redirect must produce events");

    // The redirect wrote a file inside the project; that must be visible with a byte count.
    let events = read_events(&recording);
    let wrote_out = events.iter().any(|e| match &e.payload {
        Payload::FsWrite(w) => w.target.path.ends_with("out.txt"),
        _ => false,
    });
    assert!(wrote_out, "the redirect target must appear as an fs_write");
}

#[test]
#[ignore = "needs Linux with strace installed"]
fn byte_volumes_are_recorded_for_real_writes() {
    // Phase 0's harness could not do this at all: it did not trace write(), so Design.md:35's
    // "wrote ~13 MB outside project dir" was unproducible. This asserts the gap is closed against a
    // real process writing a known number of bytes.
    if !require("strace") || !require("dd") {
        return;
    }
    let dir = scratch("bytes");
    let config = config_for(
        "bytes",
        &[
            "/bin/sh",
            "-c",
            "dd if=/dev/zero of=big.bin bs=1024 count=512 2>/dev/null",
        ],
        &dir,
    );

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));
    let events = read_events(&recording);

    let total: u64 = events
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::FsWrite(w)
                if w.kind == WriteKind::Write && w.target.path.ends_with("big.bin") =>
            {
                w.bytes
            }
            _ => None,
        })
        .sum();

    assert_eq!(
        total,
        512 * 1024,
        "dd wrote 512 KiB; the recorder must account for all of it"
    );
}

#[test]
#[ignore = "needs Linux with strace and npm installed"]
fn records_a_real_npm_install_end_to_end() {
    // The Phase 1 Done condition (Phases.md:20). Network access required; the install is a real one.
    if !require("strace") || !require("npm") {
        return;
    }
    let dir = scratch("npm");
    let home = dir.join("home");
    let cache = dir.join("cache");
    for sub in [&home, &cache, &dir.join("tmp")] {
        std::fs::create_dir_all(sub).unwrap_or_else(|e| panic!("mkdir: {e}"));
    }
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"e2e-scratch","version":"0.0.0","private":true}"#,
    )
    .unwrap_or_else(|e| panic!("seeding package.json: {e}"));

    let mut config = config_for(
        "npm",
        &[
            "npm",
            "install",
            "lodash",
            "--no-audit",
            "--no-fund",
            "--loglevel=error",
        ],
        &dir,
    );
    config.timeout = Some(Duration::from_secs(300));
    config.env.insert(
        "HOME".to_string(),
        home.to_str().unwrap_or_default().to_string(),
    );
    config.env.insert(
        "npm_config_cache".to_string(),
        cache.to_str().unwrap_or_default().to_string(),
    );
    config.env.insert("CI".to_string(), "true".to_string());

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));
    let events = read_events(&recording);

    eprintln!(
        "npm install recorded: partial={} exit={:?} events={} stats={:?}",
        recording.is_partial(),
        recording.command_exit_code,
        recording.session_end.events_emitted,
        recording.stats
    );

    // A network hiccup should not be reported as a passing test, but neither should it be reported as
    // a recorder bug. The install's own success is asserted separately from the recording's integrity.
    assert_eq!(
        recording.command_exit_code,
        Some(0),
        "npm install failed; that is an environment problem, not a recorder one"
    );
    assert!(
        !recording.is_partial(),
        "a successful install must record as complete, got: {:?}",
        recording.session_end.incomplete_reasons
    );

    assert!(
        recording.session_end.events_emitted > 50,
        "an npm install touches far more than {} things",
        recording.session_end.events_emitted
    );
    assert!(
        recording.session_end.heartbeats > 0,
        "a multi-second install must emit heartbeats proving liveness"
    );

    // node_modules must appear as writes inside the project.
    let wrote_node_modules = events.iter().any(|e| match &e.payload {
        Payload::FsWrite(w) => w.target.path.contains("node_modules"),
        _ => false,
    });
    assert!(
        wrote_node_modules,
        "the install must write into node_modules"
    );

    // The registry must appear as network activity: either a resolved DNS question or a connect.
    let saw_network = events.iter().any(|e| {
        matches!(&e.payload, Payload::DnsQuery(_))
            || matches!(&e.payload, Payload::NetConnect(c) if !c.private)
    });
    assert!(
        saw_network,
        "fetching from the registry must produce DNS or connect evidence"
    );

    // Byte volumes must be present for at least one written file.
    let has_bytes = events.iter().any(|e| match &e.payload {
        Payload::FsWrite(w) => w.kind == WriteKind::Write && w.bytes.unwrap_or(0) > 0,
        _ => false,
    });
    assert!(
        has_bytes,
        "write byte accounting must produce nonzero volumes"
    );

    // Parse hygiene on real-world output is the point of running this at all: a fixture cannot tell
    // you whether strace's actual formatting is handled.
    assert_eq!(
        recording.stats.parse_errors, 0,
        "real strace output must parse without errors; {:?}",
        recording.stats
    );
}

// =============================================================================================
// crash → PARTIAL
// =============================================================================================

#[test]
#[ignore = "needs Linux with strace installed"]
fn a_timeout_records_as_partial_with_a_timeout_reason() {
    if !require("strace") {
        return;
    }
    let dir = scratch("timeout");
    let mut config = config_for("timeout", &["/bin/sh", "-c", "sleep 30"], &dir);
    config.timeout = Some(Duration::from_secs(2));

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));

    assert!(
        recording.is_partial(),
        "a killed-by-timeout recording must never read as complete"
    );
    assert!(
        recording
            .session_end
            .incomplete_reasons
            .iter()
            .any(|r| matches!(r, IncompleteReason::Timeout { .. })),
        "the reason must name the timeout, got {:?}",
        recording.session_end.incomplete_reasons
    );

    // Even a PARTIAL recording must be a terminated, readable stream — that is what makes the
    // PARTIAL badge possible downstream instead of a parse failure.
    let contents = std::fs::read_to_string(&recording.events_path)
        .unwrap_or_else(|e| panic!("reading the stream: {e}"));
    let summary = summarize_stream(&contents)
        .unwrap_or_else(|e| panic!("a PARTIAL stream must still be readable: {e}"));
    assert!(summary.is_partial());
    assert!(!summary.incomplete_reasons.is_empty());
}

#[test]
#[ignore = "needs Linux with strace installed"]
fn a_command_killed_by_a_signal_still_terminates_the_stream() {
    // The Rules.md §2 nightmare: a recording that stops without saying so. The traced process kills
    // itself, so there is no clean exit code to report.
    if !require("strace") {
        return;
    }
    let dir = scratch("signal");
    let config = config_for(
        "signal",
        &["/bin/sh", "-c", "echo pre > pre.txt; kill -9 $$"],
        &dir,
    );

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));

    let contents = std::fs::read_to_string(&recording.events_path)
        .unwrap_or_else(|e| panic!("reading the stream: {e}"));
    let summary = summarize_stream(&contents).unwrap_or_else(|e| {
        panic!("a signalled command must still leave a terminated stream: {e}")
    });

    // Evidence recorded before the kill must survive: the write happened and is real.
    let events = read_events(&recording);
    assert!(
        events.iter().any(|e| match &e.payload {
            Payload::FsWrite(w) => w.target.path.ends_with("pre.txt"),
            _ => false,
        }),
        "writes observed before the signal must be kept"
    );
    // Whether this is complete or PARTIAL depends on what strace reports; what must hold is that the
    // stream terminated and said which one.
    assert!(
        summary.complete || !summary.incomplete_reasons.is_empty(),
        "a stream must never be incomplete without a stated reason"
    );
}

#[test]
#[ignore = "needs Linux with strace installed"]
fn a_nonexistent_command_is_reported_rather_than_silently_empty() {
    if !require("strace") {
        return;
    }
    let dir = scratch("missing");
    let config = config_for(
        "missing",
        &["/nonexistent/definitely-not-a-real-binary"],
        &dir,
    );

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));

    // strace itself starts fine and then fails to exec, so this is a *recording of a failed command*
    // rather than a recorder failure. Either way the stream must be terminated and readable.
    let contents = std::fs::read_to_string(&recording.events_path)
        .unwrap_or_else(|e| panic!("reading the stream: {e}"));
    let summary = summarize_stream(&contents)
        .unwrap_or_else(|e| panic!("the stream must be terminated even here: {e}"));
    assert!(
        summary.complete || !summary.incomplete_reasons.is_empty(),
        "no silent incompleteness"
    );
    assert_ne!(
        recording.command_exit_code,
        Some(0),
        "a command that could not be executed must not report success"
    );
}

#[test]
#[ignore = "needs Linux with strace installed"]
fn the_event_cap_forces_partial() {
    // A truncated stream that claimed to be complete would be a confident lie about a quiet install.
    if !require("strace") {
        return;
    }
    let dir = scratch("cap");
    let mut config = config_for(
        "cap",
        &[
            "/bin/sh",
            "-c",
            "for i in $(seq 1 200); do echo x > f$i.txt; done",
        ],
        &dir,
    );
    config.event_cap = 5;

    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));

    assert!(
        recording.is_partial(),
        "hitting the cap must mark the recording PARTIAL"
    );
    assert!(
        recording
            .session_end
            .incomplete_reasons
            .iter()
            .any(|r| matches!(r, IncompleteReason::EventCapReached { .. })),
        "the reason must name the cap, got {:?}",
        recording.session_end.incomplete_reasons
    );
}

#[test]
#[ignore = "needs Linux with strace installed"]
fn raw_traces_are_removed_unless_requested() {
    if !require("strace") {
        return;
    }
    let dir = scratch("raw");
    let config = config_for("raw", &["/bin/sh", "-c", "true"], &dir);
    let recording = strace::record(&config).unwrap_or_else(|e| panic!("recording failed: {e}"));
    let trace_dir = recording
        .events_path
        .parent()
        .map(|p| p.join("trace"))
        .unwrap_or_default();
    assert!(
        !trace_dir.exists(),
        "raw traces are large; they must be discarded unless keep_raw_traces is set"
    );

    let dir2 = scratch("raw-kept");
    let mut keep = config_for("raw-kept", &["/bin/sh", "-c", "true"], &dir2);
    keep.keep_raw_traces = true;
    let kept = strace::record(&keep).unwrap_or_else(|e| panic!("recording failed: {e}"));
    let kept_dir = kept
        .events_path
        .parent()
        .map(|p| p.join("trace"))
        .unwrap_or_default();
    assert!(
        kept_dir.exists(),
        "keep_raw_traces must preserve the evidence a human needs to dispute a finding"
    );
}
