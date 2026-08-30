//! `installscope` — the flight recorder for package installs.
//!
//! This binary is the CLI boundary, which is the one place `Rules.md` §2 permits `anyhow`. Everything
//! it calls into uses typed errors.
//!
//! Phase 1 ships two subcommands:
//! - `record -- <command>` — record an install and write a schema v1 JSONL stream;
//! - `verify <events.jsonl>` — re-read a stream and say whether it is trustworthy.
//!
//! `verify` exists because of `Rules.md` §2: the failure mode that matters is a recorder that dies
//! quietly and leaves output that *looks* clean. A separate verification path means CI can assert the
//! evidence is whole rather than trusting the recorder's own exit code.
//!
//! Deliberately absent in Phase 1: `report`, `diff`, and `push`. Those are Phases 3 and 4
//! (`Phases.md`), and stubbing them now would invite scope creep.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, rust_2018_idioms)]

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
#[cfg(target_os = "linux")]
use installscope_core::Zones;
use installscope_recorder::summarize_stream;

/// Exit code used when a recording completed but is PARTIAL.
///
/// Distinct from both success and hard failure so a caller can tell "recorded, but do not trust it as
/// complete" from "did not record at all". A green build over a silently-dead recorder is the worst
/// outcome this project can produce (`Rules.md` §2), so it gets its own code.
const EXIT_PARTIAL: u8 = 3;

/// Exit code for a hard failure.
const EXIT_FAILURE: u8 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "installscope",
    version,
    about = "Records the syscall-level ground truth of what a package install actually does.",
    long_about = "Attestations verify who signed it. InstallScope records what it did.\n\n\
                  v1 is Linux-only and observes without interfering: everything is allowed, \
                  everything is logged."
)]
struct Cli {
    /// Increase log verbosity. Repeat for more.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Record a command's syscall behavior into a JSONL event stream.
    Record(RecordArgs),
    /// Re-read a recording and report whether it is complete or PARTIAL.
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
struct RecordArgs {
    /// Directory for events.jsonl and session metadata.
    #[arg(short, long, default_value = "installscope-out")]
    out: PathBuf,

    /// Abort the recording after this many seconds. Omit for no limit.
    #[arg(long)]
    timeout: Option<u64>,

    /// Working directory for the recorded command.
    #[arg(long)]
    cwd: Option<PathBuf>,

    /// Project directory, used to classify writes downstream. Defaults to `--cwd` or the current
    /// directory.
    #[arg(long)]
    project: Option<PathBuf>,

    /// Package manager cache directory.
    #[arg(long)]
    cache: Option<PathBuf>,

    /// Additional expected-write prefix. Repeatable.
    #[arg(long = "expect", value_name = "PATH")]
    expect: Vec<PathBuf>,

    /// Keep raw strace output alongside the event stream. Large; useful when disputing a finding.
    #[arg(long)]
    keep_raw: bool,

    /// Cap on recorded events. Hitting it marks the recording PARTIAL rather than truncating quietly.
    #[arg(long, default_value_t = installscope_recorder::DEFAULT_EVENT_CAP)]
    event_cap: u64,

    /// Exit non-zero if the recording is PARTIAL. Off by default because a PARTIAL recording is still
    /// a result worth keeping; on in CI, where silence is dangerous.
    #[arg(long)]
    fail_on_partial: bool,

    /// The command to record, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to an events.jsonl produced by `installscope record`.
    events: PathBuf,

    /// Exit non-zero when the recording is PARTIAL.
    #[arg(long)]
    fail_on_partial: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match run(&cli) {
        Ok(code) => code,
        Err(err) => {
            // The full chain, because the leaf ("No such file or directory") is rarely the useful
            // part.
            eprintln!("installscope: error: {err:#}");
            ExitCode::from(EXIT_FAILURE)
        }
    }
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    // Logs go to stderr so stdout stays machine-readable.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

fn run(cli: &Cli) -> Result<ExitCode> {
    match &cli.command {
        Command::Record(args) => run_record(args),
        Command::Verify(args) => run_verify(args),
    }
}

#[cfg(target_os = "linux")]
fn run_record(args: &RecordArgs) -> Result<ExitCode> {
    use installscope_recorder::strace;

    if args.command.is_empty() {
        bail!("no command given; usage: installscope record -- npm install <pkg>");
    }

    let cwd = match &args.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().context("determining the current directory")?,
    };
    let project = args.project.clone().unwrap_or_else(|| cwd.clone());

    let mut zones = Zones {
        project: path_to_string(&project),
        cache: args.cache.as_deref().and_then(path_to_string),
        home: std::env::var("HOME").ok(),
        tmp: std::env::var("TMPDIR")
            .ok()
            .or_else(|| Some("/tmp".to_string())),
        extra: args
            .expect
            .iter()
            .filter_map(|p| path_to_string(p))
            .collect(),
    };
    // An unset cache would make every cache write look like it landed somewhere unexpected. npm's
    // default is derived from HOME, so it is inferred rather than left empty.
    if zones.cache.is_none() {
        zones.cache = zones.home.as_ref().map(|home| format!("{home}/.npm"));
    }

    let mut config = strace::RecordConfig::new(args.command.clone(), args.out.clone());
    config.timeout = args.timeout.map(std::time::Duration::from_secs);
    config.cwd = Some(cwd);
    config.zones = zones;
    config.env = BTreeMap::new();
    config.keep_raw_traces = args.keep_raw;
    config.event_cap = args.event_cap;

    let recording = strace::record(&config).context("recording the install")?;
    let summary_path =
        strace::write_summary(&args.out, &recording).context("writing the session summary")?;

    // Re-read what was just written rather than trusting the in-memory result. If these disagree,
    // the artifact is what downstream consumes, so the artifact wins.
    let contents = std::fs::read_to_string(&recording.events_path)
        .with_context(|| format!("re-reading {}", recording.events_path.display()))?;
    let verified = summarize_stream(&contents).with_context(|| {
        format!(
            "the recording at {} is not a readable event stream",
            recording.events_path.display()
        )
    })?;

    print_recording_report(&recording, &verified, &summary_path);

    if verified.is_partial() {
        if args.fail_on_partial {
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
        return Ok(ExitCode::from(EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn run_record(_args: &RecordArgs) -> Result<ExitCode> {
    // Scope.md:25 makes v1 Linux-only, and Scope.md:51-52 gives macOS and Windows explicit,
    // measurable promotion triggers. Saying so plainly beats a vague "unsupported".
    bail!(
        "recording requires Linux. v1 is Linux-only by design: the evidence comes from ptrace \
         (and later eBPF), which have no equivalent here. macOS (Endpoint Security) and Windows \
         (ETW) backends are deferred with published promotion triggers.\n\
         To record from this machine, run the GitHub Action, which records on an ubuntu-latest \
         runner.\n\
         `installscope verify` works everywhere and can inspect a recording produced elsewhere."
    )
}

fn run_verify(args: &VerifyArgs) -> Result<ExitCode> {
    let contents = std::fs::read_to_string(&args.events)
        .with_context(|| format!("reading {}", args.events.display()))?;
    let summary = summarize_stream(&contents)
        .with_context(|| format!("{} is not a valid event stream", args.events.display()))?;

    if !summary.has_session_start {
        // Without session_start there is no wall-clock anchor and no zone information, so relative
        // timestamps and path classification are both meaningless.
        eprintln!(
            "installscope: warning: no session_start event; timestamps and zones cannot be \
             interpreted"
        );
    }

    println!(
        "{}",
        if summary.is_partial() {
            "PARTIAL"
        } else {
            "complete"
        }
    );
    println!("events:     {}", summary.events);
    println!("heartbeats: {}", summary.heartbeats);
    if let Some(code) = summary.command_exit_code {
        println!("command exit code: {code}");
    }
    for reason in &summary.incomplete_reasons {
        println!("reason: {reason}");
    }

    if summary.is_partial() {
        if args.fail_on_partial {
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
        return Ok(ExitCode::from(EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(target_os = "linux")]
fn print_recording_report(
    recording: &installscope_recorder::strace::Recording,
    verified: &installscope_recorder::StreamSummary,
    summary_path: &std::path::Path,
) {
    // PARTIAL is printed first and unmissably. PRD.md:58 calls a recorder that dies silently the
    // single worst failure mode of this product, so the state leads.
    if verified.is_partial() {
        println!("PARTIAL — this recording is incomplete and must not be read as clean");
        for reason in &verified.incomplete_reasons {
            println!("  reason: {reason}");
        }
    } else {
        println!("complete");
    }

    println!("events:     {}", verified.events);
    println!("heartbeats: {}", verified.heartbeats);
    match recording.command_exit_code {
        Some(0) => println!("command:    exited 0"),
        Some(code) => println!("command:    exited {code} (a failed install is still evidence)"),
        None => println!("command:    did not exit normally"),
    }
    println!("stream:     {}", recording.events_path.display());
    println!("summary:    {}", summary_path.display());

    let stats = &recording.stats;
    if stats.parse_errors > 0 || stats.dns_undecodable > 0 || stats.unmatched_unfinished > 0 {
        println!(
            "diagnostics: parse_errors={} unmatched_syscalls={} undecodable_dns={}",
            stats.parse_errors, stats.unmatched_unfinished, stats.dns_undecodable
        );
    }
}

#[cfg(target_os = "linux")]
fn path_to_string(path: &std::path::Path) -> Option<String> {
    path.to_str().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn record_requires_a_command_after_the_separator() {
        // `installscope record` with nothing to record is a usage error, not an empty recording.
        let parsed = Cli::try_parse_from(["installscope", "record"]);
        assert!(parsed.is_err(), "a bare `record` must not be accepted");
    }

    #[test]
    fn record_captures_the_whole_command_after_the_separator() {
        let cli = Cli::try_parse_from([
            "installscope",
            "record",
            "--out",
            "/tmp/out",
            "--",
            "npm",
            "install",
            "--foreground-scripts",
            "lodash",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));

        match cli.command {
            Command::Record(args) => {
                assert_eq!(
                    args.command,
                    vec!["npm", "install", "--foreground-scripts", "lodash"],
                    "flags belonging to the recorded command must not be consumed by clap"
                );
                assert_eq!(args.out, PathBuf::from("/tmp/out"));
            }
            Command::Verify(_) => panic!("expected the record subcommand"),
        }
    }

    #[test]
    fn verify_accepts_a_path() {
        let cli = Cli::try_parse_from(["installscope", "verify", "events.jsonl"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Verify(args) => assert_eq!(args.events, PathBuf::from("events.jsonl")),
            Command::Record(_) => panic!("expected the verify subcommand"),
        }
    }

    #[test]
    fn partial_has_a_distinct_exit_code() {
        // A caller must be able to distinguish "recorded but incomplete" from "failed to record".
        assert_ne!(EXIT_PARTIAL, EXIT_FAILURE);
        assert_ne!(EXIT_PARTIAL, 0);
    }
}
