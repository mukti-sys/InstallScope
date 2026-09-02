//! `installscope` — the flight recorder for package installs.
//!
//! This binary is the CLI boundary, which is the one place `Rules.md` §2 permits `anyhow`. Everything
//! it calls into uses typed errors.
//!
//! Subcommands:
//! - `record -- <command>` — record an install and write a schema v1 JSONL stream;
//! - `verify <events.jsonl>` — re-read a stream and say whether it is trustworthy;
//! - `report <events.jsonl>` — evaluate a recording against the rule catalog and emit reports;
//! - `lockfile-diff --before <a> --after <b>` — decide whether a lockfile change is worth recording;
//! - `snapshot push|list` — store a recording in the content-addressed registry;
//! - `diff <pkg> <v1> <v2>` — compare two recorded versions behaviorally;
//! - `parity --strace <a> --aya <b>` — compare two recordings of the same workload (Phase 2).
//!
//! `verify` exists because of `Rules.md` §2: the failure mode that matters is a recorder that dies
//! quietly and leaves output that *looks* clean. A separate verification path means CI can assert the
//! evidence is whole rather than trusting the recorder's own exit code.
//!
//! `report` evaluates a recording against the embedded YAML rule catalog and writes SARIF, Markdown,
//! and/or HTML to the output directory. It is the pipeline entry point: `record` produces evidence,
//! `report` produces findings.
//!
//! `lockfile-diff` is the Phase 4 trigger (PRD.md:30). It exists as a subcommand rather than as shell in
//! the Action for the same reason `parity` does: the decision about what counts as a dependency change is
//! unit-tested Rust, and a shell reimplementation would drift from it.
//!
//! `snapshot` and `diff` are the registry (Architecture.md §6). `diff` is the moat — "this package's
//! behavior changed between 1.2.3 and 1.2.4" — and it refuses to make that claim when the two recordings
//! cannot support it.
//!
//! `parity` exists for the same reason at one level up: it decides whether two backends agree about
//! what happened, and it lives here rather than as a CI script so the comparison logic is unit-tested
//! Rust rather than shell that drifts.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::pedantic, rust_2018_idioms)]

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
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

/// Which recorder backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendChoice {
    /// `strace -f -ff`. The v1.0 backend: needs only ptrace, works on any Linux.
    Strace,
    /// eBPF via aya. Needs root, a compiled probe object, and a kernel that loads it.
    Aya,
}

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
    /// Evaluate a recording against the rule catalog and emit reports.
    Report(ReportArgs),
    /// Decide whether a lockfile change introduces code worth recording.
    LockfileDiff(LockfileDiffArgs),
    /// Store and list recordings in the content-addressed snapshot registry.
    #[command(subcommand)]
    Snapshot(SnapshotCommand),
    /// Compare two recorded versions of a package behaviorally.
    Diff(DiffArgs),
    /// Compare two recordings of the same workload, made by different backends.
    Parity(ParityArgs),
}

#[derive(Subcommand, Debug)]
enum SnapshotCommand {
    /// Store a recording under its content address and index it.
    Push(SnapshotPushArgs),
    /// List indexed recordings.
    List(SnapshotListArgs),
    /// Re-verify every stored snapshot against its content address.
    Verify(SnapshotVerifyArgs),
}

#[derive(Args, Debug)]
struct LockfileDiffArgs {
    /// The lockfile as it was before the change.
    #[arg(long)]
    before: PathBuf,

    /// The lockfile as it is after the change.
    #[arg(long)]
    after: PathBuf,

    /// Emit the decision as JSON, for a workflow step to consume.
    #[arg(long)]
    json: bool,

    /// Exit 0 even when nothing needs recording.
    ///
    /// Off by default: the exit code is how a workflow step decides whether to spend a runner on a
    /// recording, and a step that always succeeds cannot express "nothing to do here".
    #[arg(long)]
    always_succeed: bool,
}

#[derive(Args, Debug)]
struct SnapshotPushArgs {
    /// Path to an events.jsonl produced by `installscope record`.
    events: PathBuf,

    /// Registry root. Created if absent.
    #[arg(long, default_value = ".installscope/registry")]
    registry: PathBuf,

    /// Package this recording is of.
    #[arg(long)]
    package: String,

    /// Version this recording is of.
    #[arg(long)]
    version: String,
}

#[derive(Args, Debug)]
struct SnapshotListArgs {
    /// Registry root.
    #[arg(long, default_value = ".installscope/registry")]
    registry: PathBuf,

    /// Only list recordings of this package.
    #[arg(long)]
    package: Option<String>,

    /// Emit JSONL rather than a table.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct SnapshotVerifyArgs {
    /// Registry root.
    #[arg(long, default_value = ".installscope/registry")]
    registry: PathBuf,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Package name.
    package: String,

    /// The earlier version.
    before: String,

    /// The later version.
    after: String,

    /// Registry root.
    #[arg(long, default_value = ".installscope/registry")]
    registry: PathBuf,

    /// Write the Markdown and HTML diff reports into this directory.
    #[arg(short, long)]
    out: Option<PathBuf>,

    /// Exit non-zero when behavior changed.
    ///
    /// Off by default, because a behavioral change is information rather than a verdict — the same
    /// advisory-first discipline as the finding report (PRD.md:43).
    #[arg(long)]
    fail_on_change: bool,
}

#[derive(Args, Debug)]
struct RecordArgs {
    /// Directory for events.jsonl and session metadata.
    #[arg(short, long, default_value = "installscope-out")]
    out: PathBuf,

    /// Which backend to record with.
    ///
    /// strace is the default because it needs only ptrace and works on any Linux. aya needs root, a
    /// compiled probe object, and a kernel that will load it.
    #[arg(long, value_enum, default_value_t = BackendChoice::Strace)]
    backend: BackendChoice,

    /// Compiled eBPF object, for `--backend aya`.
    #[arg(long, default_value = "installscope-ebpf")]
    ebpf_object: PathBuf,

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
struct ParityArgs {
    /// Recording produced by the strace backend.
    #[arg(long)]
    strace: PathBuf,

    /// Recording produced by the aya backend.
    #[arg(long)]
    aya: PathBuf,

    /// Print every difference, including the expected ones.
    ///
    /// Off by default so a passing run stays readable; on in CI, where the expected differences are the
    /// record of what each backend can and cannot see.
    #[arg(long)]
    show_expected: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to an events.jsonl produced by `installscope record`.
    events: PathBuf,

    /// Exit non-zero when the recording is PARTIAL.
    #[arg(long)]
    fail_on_partial: bool,
}

/// Which report formats to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReportFormat {
    /// SARIF 2.1.0 JSON for GitHub code scanning.
    Sarif,
    /// PR-comment Markdown.
    Markdown,
    /// Self-contained HTML artifact.
    Html,
    /// All three formats.
    All,
}

#[derive(Args, Debug)]
struct ReportArgs {
    /// Path to an events.jsonl produced by `installscope record`.
    events: PathBuf,

    /// Output directory for generated reports.
    #[arg(short, long, default_value = "installscope-report")]
    out: PathBuf,

    /// Which format(s) to emit.
    #[arg(long, value_enum, default_value_t = ReportFormat::All)]
    format: ReportFormat,

    /// Package name, for the report header.
    #[arg(long)]
    package: Option<String>,

    /// Package version, for the report header.
    #[arg(long)]
    version: Option<String>,

    /// URL to the full evidence artifact.
    #[arg(long)]
    evidence_link: Option<String>,

    /// URL to the uploaded SARIF file.
    #[arg(long)]
    sarif_link: Option<String>,

    /// Exit non-zero when the score exceeds this threshold (0–100).
    #[arg(long)]
    fail_above: Option<u32>,
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
        Command::Report(args) => run_report(args),
        Command::LockfileDiff(args) => run_lockfile_diff(args),
        Command::Snapshot(SnapshotCommand::Push(args)) => run_snapshot_push(args),
        Command::Snapshot(SnapshotCommand::List(args)) => run_snapshot_list(args),
        Command::Snapshot(SnapshotCommand::Verify(args)) => run_snapshot_verify(args),
        Command::Diff(args) => run_diff(args),
        Command::Parity(args) => run_parity(args),
    }
}

/// Exit code meaning "the lockfile changed, but nothing new will run".
///
/// Distinct from success so a workflow step can branch on it without parsing stdout. Not an error: a PR
/// that only removes a dependency is a perfectly good PR, it just has nothing to record.
const EXIT_NOTHING_TO_RECORD: u8 = 4;

/// Decides whether a lockfile change is worth recording.
///
/// Lives here rather than in the Action's shell for the reason `Rules.md` §6 gives about parity: the
/// decision is unit-tested Rust, and a shell reimplementation would drift from the tests that pin it.
fn run_lockfile_diff(args: &LockfileDiffArgs) -> Result<ExitCode> {
    // The "after" side is parsed first because it is the authoritative one: it is the lockfile as it
    // exists in the working tree, under its real name. The "before" side is a copy pulled out of git and
    // named whatever the caller found convenient, so it borrows this ecosystem when its own name says
    // nothing. See `load_lockfile_side`.
    let after = installscope_lockfile::load(&args.after)
        .with_context(|| format!("reading {}", args.after.display()))?;
    let before = load_lockfile_side(&args.before, after.ecosystem)?;

    // A missing "before" is a lockfile that did not exist yet, which is the first-commit case. Treated as
    // empty rather than as an error: every dependency in the new file is genuinely new.
    let before = before.unwrap_or_else(|| installscope_lockfile::Lockfile {
        ecosystem: after.ecosystem,
        declared_version: after.declared_version.clone(),
        packages: Vec::new(),
    });

    let diff = installscope_lockfile::diff(&before, &after);
    let recordable = diff.recordable();

    if args.json {
        let payload = serde_json::json!({
            "ecosystem": after.ecosystem.to_string(),
            "lockfile": after.ecosystem.lockfile_name(),
            "ecosystem_changed": diff.ecosystem_changed,
            "should_record": diff.should_record(),
            "changes": diff.changes.iter().map(|change| serde_json::json!({
                "name": change.name(),
                "summary": change.summary(),
                "introduces_code": change.introduces_code(),
            })).collect::<Vec<_>>(),
            "record": recordable.iter().map(|identity| serde_json::json!({
                "name": identity.name,
                "version": identity.version,
                "label": identity.to_string(),
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).context("rendering the decision as JSON")?
        );
    } else {
        println!(
            "{}",
            if diff.should_record() {
                "record"
            } else {
                "nothing-to-record"
            }
        );
        println!("ecosystem: {}", after.ecosystem);
        if diff.ecosystem_changed {
            // Named loudly: every dependency is being reinstalled by a different tool, and a reader who
            // misses that would read a hundred changes as if one PR added them.
            println!("note:      the package manager itself changed between these two lockfiles");
        }
        println!("changes:   {}", diff.changes.len());
        for change in &diff.changes {
            println!(
                "  {} {}",
                if change.introduces_code() { "+" } else { " " },
                change.summary()
            );
        }
        if !recordable.is_empty() {
            println!("record:");
            for identity in &recordable {
                println!("  {identity}");
            }
        }
    }

    if diff.should_record() || args.always_succeed {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_NOTHING_TO_RECORD))
    }
}

/// Loads the "before" lockfile, treating absence as "it did not exist yet".
///
/// # Why this side is parsed by ecosystem rather than by filename
///
/// The before-copy never has a lockfile's real name. A workflow obtains it with
/// `git show origin/main:package-lock.json > base-package-lock.json`, because writing it to the real
/// filename would clobber the working tree's copy — the very file being compared against. Requiring the
/// sanctioned name here rejected every caller that did the obvious thing, including this project's own
/// Action and its own CI step. Found by running the extracted workflow scripts locally, not by reading
/// them.
///
/// So the ecosystem comes from the *after* side, which is the file under its real name, and the
/// before-copy is parsed as that same ecosystem. Comparing an npm lockfile against a pnpm one is not a
/// meaningful question anyway: `LockfileDiff::ecosystem_changed` exists for a migration, and a migration
/// changes the file that is actually in the tree.
///
/// A filename that *does* identify an ecosystem still wins, so passing two real lockfile paths keeps
/// working and a genuine mismatch between them stays visible rather than being silently coerced.
fn load_lockfile_side(
    path: &std::path::Path,
    fallback: installscope_lockfile::Ecosystem,
) -> Result<Option<installscope_lockfile::Lockfile>> {
    if !path.exists() {
        return Ok(None);
    }
    // An empty file is what `git show` produces for a path that did not exist at that revision, which is
    // the shape a workflow step will actually hand over. Same reading as an absent file.
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    let name = path.to_str().unwrap_or_default();
    let parsed = if installscope_lockfile::Ecosystem::from_path(name).is_some() {
        installscope_lockfile::parse(name, &text)
    } else {
        installscope_lockfile::parse(fallback.lockfile_name(), &text)
    };
    parsed
        .map(Some)
        .with_context(|| format!("reading {}", path.display()))
}

/// Stores a recording in the registry.
fn run_snapshot_push(args: &SnapshotPushArgs) -> Result<ExitCode> {
    let events = std::fs::read_to_string(&args.events)
        .with_context(|| format!("reading {}", args.events.display()))?;

    let mut registry = installscope_registry::Registry::open(&args.registry)
        .with_context(|| format!("opening the registry at {}", args.registry.display()))?;

    let entry = registry
        .push(&args.package, &args.version, &events)
        .with_context(|| format!("storing the recording of {}@{}", args.package, args.version))?;

    let digest = entry.digest().context("the stored digest is malformed")?;
    let compressed = registry.store().compressed_size(&digest).unwrap_or(0);

    println!("stored {}", entry.label());
    println!("digest:      {}", entry.digest);
    println!("recorded_at: {}", entry.recorded_at);
    println!("backend:     {}", entry.backend);
    println!("events:      {}", entry.events);
    println!(
        "size:        {} bytes compressed from {}",
        compressed, entry.uncompressed_bytes
    );
    println!("registry:    {}", args.registry.display());

    Ok(ExitCode::SUCCESS)
}

/// Lists what the registry holds.
fn run_snapshot_list(args: &SnapshotListArgs) -> Result<ExitCode> {
    let registry = installscope_registry::Registry::open(&args.registry)
        .with_context(|| format!("opening the registry at {}", args.registry.display()))?;
    let index = registry.index();

    let entries: Vec<&installscope_registry::Entry> = index
        .entries()
        .iter()
        .filter(|entry| match args.package.as_deref() {
            Some(package) => entry.package == package,
            None => true,
        })
        .collect();

    if args.json {
        for entry in &entries {
            println!(
                "{}",
                serde_json::to_string(entry).context("rendering an index entry")?
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    if entries.is_empty() {
        println!("no recordings in {}", args.registry.display());
        return Ok(ExitCode::SUCCESS);
    }

    println!(
        "{} recording(s) in {}",
        entries.len(),
        args.registry.display()
    );
    for entry in &entries {
        // The digest is truncated for reading; `--json` gives the full value. A short digest is never
        // used to look anything up.
        let short = entry.digest.get(..12).unwrap_or(&entry.digest);
        println!(
            "  {:<40} {:<8} {:>6} events  {}  {}",
            entry.label(),
            entry.backend,
            entry.events,
            entry.recorded_at,
            short
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Re-verifies every stored snapshot.
///
/// Separate from `list` because they answer different questions: `list` says what the index claims, and
/// `verify` says whether the store can still produce it. Content addressing is only worth having if
/// something checks, and a corpus that backs published receipts is exactly where "it was right when we
/// wrote it" stops being good enough.
fn run_snapshot_verify(args: &SnapshotVerifyArgs) -> Result<ExitCode> {
    let registry = installscope_registry::Registry::open(&args.registry)
        .with_context(|| format!("opening the registry at {}", args.registry.display()))?;

    let results = registry.verify_all();
    if results.is_empty() {
        println!("no recordings in {}", args.registry.display());
        return Ok(ExitCode::SUCCESS);
    }

    let mut failures = 0;
    for result in &results {
        match &result.outcome {
            Ok(events) => println!("ok      {:<40} {events} events", result.label()),
            Err(reason) => {
                failures += 1;
                println!("FAILED  {:<40} {reason}", result.label());
            }
        }
    }

    println!("\n{} verified, {failures} failed", results.len() - failures);

    if failures > 0 {
        // A corrupted corpus is a hard failure, not a warning. Every receipt drawn from it, and every
        // version-diff computed against it, rests on bytes that no longer match their address.
        eprintln!(
            "installscope: error: {failures} snapshot(s) do not match their content address; the \
             affected recordings must not be cited as evidence"
        );
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    Ok(ExitCode::SUCCESS)
}

/// Compares two recorded versions of a package.
fn run_diff(args: &DiffArgs) -> Result<ExitCode> {
    let registry = installscope_registry::Registry::open(&args.registry)
        .with_context(|| format!("opening the registry at {}", args.registry.display()))?;

    let comparison = registry
        .diff_versions(&args.package, &args.before, &args.after)
        .with_context(|| {
            format!(
                "comparing {}@{} with {}@{}",
                args.package, args.before, args.package, args.after
            )
        })?;

    print!("{}", installscope_report::render_diff_markdown(&comparison));

    if let Some(out) = &args.out {
        std::fs::create_dir_all(out)
            .with_context(|| format!("creating output directory {}", out.display()))?;

        let markdown_path = out.join("installscope-diff.md");
        std::fs::write(
            &markdown_path,
            installscope_report::render_diff_markdown(&comparison),
        )
        .with_context(|| format!("writing {}", markdown_path.display()))?;
        eprintln!("wrote {}", markdown_path.display());

        let html_path = out.join("installscope-diff.html");
        std::fs::write(
            &html_path,
            installscope_report::render_diff_html(&comparison),
        )
        .with_context(|| format!("writing {}", html_path.display()))?;
        eprintln!("wrote {}", html_path.display());
    }

    // A blocked comparison exits non-zero regardless of --fail-on-change: the caller asked a question
    // that could not be answered, and reporting success would let a workflow treat "cannot compare" as
    // "nothing changed" — which is the silent-absence failure this project keeps refusing.
    if !comparison.comparable() {
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    if args.fail_on_change && !comparison.is_identical() {
        return Ok(ExitCode::from(EXIT_FAILURE));
    }
    Ok(ExitCode::SUCCESS)
}

/// Compares two recordings of the same workload.
///
/// Lives here rather than in a CI script so the comparison is unit-tested Rust. A shell implementation
/// would drift from the expectations encoded in [`installscope_recorder::parity`], and the point of the
/// harness is that the list of acceptable differences is reviewable.
fn run_parity(args: &ParityArgs) -> Result<ExitCode> {
    use installscope_recorder::parity;

    let strace_text = std::fs::read_to_string(&args.strace)
        .with_context(|| format!("reading {}", args.strace.display()))?;
    let aya_text = std::fs::read_to_string(&args.aya)
        .with_context(|| format!("reading {}", args.aya.display()))?;

    let strace_events = parity::parse_stream(&strace_text)
        .with_context(|| format!("{} is not a valid event stream", args.strace.display()))?;
    let aya_events = parity::parse_stream(&aya_text)
        .with_context(|| format!("{} is not a valid event stream", args.aya.display()))?;

    let report = parity::compare(&strace_events, &aya_events);
    println!("{}", report.summary());

    let failures = report.failures();
    if !failures.is_empty() {
        println!();
        println!("Unexplained differences ({}):", failures.len());
        for difference in &failures {
            println!(
                "  seen only by {}: {:?}",
                difference.seen_by, difference.fact
            );
        }
    }

    if args.show_expected {
        let expected: Vec<_> = report
            .differences
            .iter()
            .filter(|d| !d.expectation.is_failure())
            .collect();
        if !expected.is_empty() {
            println!();
            println!("Expected differences ({}):", expected.len());
            for difference in expected {
                // The reason is printed alongside, because "expected" without a stated cause is
                // indistinguishable from a difference someone chose to ignore.
                if let installscope_recorder::parity::Expectation::Expected(reason) =
                    &difference.expectation
                {
                    println!(
                        "  seen only by {}: {:?}\n    reason: {reason}",
                        difference.seen_by, difference.fact
                    );
                }
            }
        }
    }

    if report.passed() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_FAILURE))
    }
}

#[cfg(target_os = "linux")]
fn run_record(args: &RecordArgs) -> Result<ExitCode> {
    if args.command.is_empty() {
        bail!("no command given; usage: installscope record -- npm install <pkg>");
    }

    let cwd = match &args.cwd {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().context("determining the current directory")?,
    };
    let project = args.project.clone().unwrap_or_else(|| cwd.clone());

    let mut zones = Zones {
        project: absolute_zone(&project),
        cache: args.cache.as_deref().and_then(absolute_zone),
        home: std::env::var("HOME").ok(),
        tmp: std::env::var("TMPDIR")
            .ok()
            .or_else(|| Some("/tmp".to_string())),
        extra: args
            .expect
            .iter()
            .filter_map(|p| absolute_zone(p))
            .collect(),
    };
    // An unset cache would make every cache write look like it landed somewhere unexpected. npm's
    // default is derived from HOME, so it is inferred rather than left empty.
    if zones.cache.is_none() {
        zones.cache = zones.home.as_ref().map(|home| format!("{home}/.npm"));
    }

    match args.backend {
        BackendChoice::Strace => run_record_strace(args, cwd, zones),
        BackendChoice::Aya => run_record_aya(args, cwd, zones),
    }
}

#[cfg(target_os = "linux")]
fn run_record_strace(args: &RecordArgs, cwd: PathBuf, zones: Zones) -> Result<ExitCode> {
    use installscope_recorder::strace;

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

/// Records with the aya backend.
///
/// Only compiled when the `aya-backend` feature is on. Without it the binary still builds and the strace
/// backend still works — a user who does not want an eBPF dependency should not be forced to carry one.
#[cfg(all(target_os = "linux", feature = "aya-backend"))]
fn run_record_aya(args: &RecordArgs, cwd: PathBuf, zones: Zones) -> Result<ExitCode> {
    use installscope_recorder::aya;

    // Reported before recording so a failure names the missing precondition rather than surfacing as an
    // opaque load error. G1 observed the runner's most restrictive sysctl values with BPF still working
    // under root, so these are informational rather than gates.
    let capabilities = aya::check_available(&args.ebpf_object)
        .context("checking whether this host can load the eBPF programs")?;
    if !capabilities.is_root {
        // Not a hard failure: the attempt is what establishes what the host actually permits, which is
        // the same reasoning the G1 gate used.
        eprintln!(
            "installscope: warning: not running as root (euid {}); loading BPF programs will very \
             likely fail. Re-run under sudo.",
            capabilities.euid
        );
    }
    if !capabilities.btf_present {
        eprintln!(
            "installscope: warning: no kernel BTF at /sys/kernel/btf/vmlinux; the probes do not \
             require CO-RE today, but a future one would"
        );
    }

    let mut config = aya::RecordConfig::new(
        args.command.clone(),
        args.ebpf_object.clone(),
        args.out.clone(),
    );
    config.timeout = args.timeout.map(std::time::Duration::from_secs);
    config.cwd = Some(cwd);
    config.zones = zones;
    config.env = BTreeMap::new();
    config.event_cap = args.event_cap;

    let recording = aya::record(&config).context("recording with the aya backend")?;

    let contents = std::fs::read_to_string(&recording.events_path)
        .with_context(|| format!("re-reading {}", recording.events_path.display()))?;
    let verified = summarize_stream(&contents).with_context(|| {
        format!(
            "the recording at {} is not a readable event stream",
            recording.events_path.display()
        )
    })?;

    if verified.is_partial() {
        println!("PARTIAL — this recording is incomplete and must not be read as clean");
        for reason in &verified.incomplete_reasons {
            println!("  reason: {reason}");
        }
    } else {
        println!("complete");
    }
    println!("events:     {}", verified.events);
    println!("backend:    aya");
    println!(
        "probes:     {} of {} attached",
        recording.attached.len(),
        recording.attached.len() + count_attach_failures(&recording)
    );
    match recording.command_exit_code {
        Some(0) => println!("command:    exited 0"),
        Some(code) => println!("command:    exited {code} (a failed install is still evidence)"),
        None => println!("command:    did not exit normally"),
    }
    println!("stream:     {}", recording.events_path.display());

    let stats = &recording.merge_stats;
    println!(
        "merge:      released {} · late {} · lost {} · unattributed writes {} ({} bytes)",
        stats.released,
        stats.late_events,
        stats.lost_records,
        stats.writes_without_path,
        stats.unattributed_bytes
    );

    if verified.is_partial() {
        if args.fail_on_partial {
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
        return Ok(ExitCode::from(EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}

/// How many probes failed to attach, derived from the PARTIAL reasons.
#[cfg(all(target_os = "linux", feature = "aya-backend"))]
fn count_attach_failures(recording: &installscope_recorder::aya::Recording) -> usize {
    recording
        .session_end
        .incomplete_reasons
        .iter()
        .find_map(|reason| match reason {
            installscope_core::IncompleteReason::Other { detail } if detail.contains("attach") => {
                detail
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<usize>().ok())
            }
            _ => None,
        })
        .unwrap_or(0)
}

/// Stands in for the aya backend when the feature is off.
#[cfg(all(target_os = "linux", not(feature = "aya-backend")))]
#[allow(clippy::unnecessary_wraps, clippy::needless_pass_by_value)]
fn run_record_aya(_args: &RecordArgs, _cwd: PathBuf, _zones: Zones) -> Result<ExitCode> {
    // Named explicitly rather than reported as an unknown backend: the difference between "not built in"
    // and "not supported" is the difference between rebuilding and giving up.
    bail!(
        "this binary was built without the aya backend. Rebuild with \
         `cargo build --features aya-backend`, and note that it also needs a compiled eBPF object \
         (see recorder/aya-ebpf) and root privileges."
    )
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

/// Evaluates a recording against the rule catalog and emits reports.
///
/// Cross-platform: unlike `record`, this reads files rather than tracing syscalls, so it runs on
/// any machine. A maintainer on macOS can evaluate a recording produced by a Linux runner.
fn run_report(args: &ReportArgs) -> Result<ExitCode> {
    let contents = std::fs::read_to_string(&args.events)
        .with_context(|| format!("reading {}", args.events.display()))?;

    let events: Vec<installscope_core::Event> = contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            installscope_core::Event::from_jsonl(line, index + 1)
                .with_context(|| format!("{} line {}", args.events.display(), index + 1))
        })
        .collect::<Result<Vec<_>>>()?;

    let catalog =
        installscope_core::Catalog::embedded().context("loading the embedded rule catalog")?;
    let analysis = installscope_core::evaluate(&catalog, &events);

    let context = installscope_report::ReportContext {
        package: args.package.clone(),
        version: args.version.clone(),
        command: Vec::new(),
        evidence_link: args.evidence_link.clone(),
        sarif_link: args.sarif_link.clone(),
    };

    // Create output directory.
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("creating output directory {}", args.out.display()))?;

    let emit_sarif = matches!(args.format, ReportFormat::Sarif | ReportFormat::All);
    let emit_markdown = matches!(args.format, ReportFormat::Markdown | ReportFormat::All);
    let emit_html = matches!(args.format, ReportFormat::Html | ReportFormat::All);

    if emit_sarif {
        let sarif =
            installscope_report::render_sarif(&analysis, &context).context("rendering SARIF")?;
        let path = args.out.join("installscope.sarif.json");
        std::fs::write(&path, &sarif).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    if emit_markdown {
        let md = installscope_report::render_markdown(&analysis, &context);
        let path = args.out.join("installscope-comment.md");
        std::fs::write(&path, &md).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    if emit_html {
        let html = installscope_report::render_html(&analysis, &context);
        let path = args.out.join("installscope-report.html");
        std::fs::write(&path, &html).with_context(|| format!("writing {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    // Summary to stdout, machine-readable.
    println!("score: {}", analysis.score.value);
    println!("raw:   {}", analysis.score.raw);
    println!(
        "partial: {}",
        if analysis.is_partial() {
            "true"
        } else {
            "false"
        }
    );
    println!("findings: {}", analysis.findings.len());

    // Gate on score if requested.
    if let Some(threshold) = args.fail_above {
        if analysis.score.value > threshold {
            eprintln!(
                "installscope: score {} exceeds threshold {threshold}",
                analysis.score.value
            );
            return Ok(ExitCode::from(EXIT_FAILURE));
        }
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

/// Resolves a zone path to an absolute, symlink-free form.
///
/// Zones are compared against paths the kernel reports, which are always absolute and already have
/// symlinks resolved. A relative `--project .` or a path through a symlink would therefore never
/// match, and every write would look like it landed somewhere unexpected — turning a normal install
/// into a page of critical findings. Falls back to lexical absolutization when the directory does not
/// exist yet, which is honest: an approximate zone is better than none, and the failure mode is a
/// missed match rather than a false one.
#[cfg(target_os = "linux")]
fn absolute_zone(path: &std::path::Path) -> Option<String> {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return path_to_string(&canonical);
    }
    if path.is_absolute() {
        return path_to_string(path);
    }
    let cwd = std::env::current_dir().ok()?;
    path_to_string(&cwd.join(path))
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
            other => panic!("expected the record subcommand, got {other:?}"),
        }
    }

    #[test]
    fn verify_accepts_a_path() {
        let cli = Cli::try_parse_from(["installscope", "verify", "events.jsonl"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Verify(args) => assert_eq!(args.events, PathBuf::from("events.jsonl")),
            other => panic!("expected the verify subcommand, got {other:?}"),
        }
    }

    #[test]
    fn the_default_backend_is_strace() {
        // strace needs only ptrace and works on any Linux; aya needs root, a compiled object, and a
        // cooperative kernel. Defaulting to the one with fewer preconditions means `record` works out of
        // the box rather than failing on a machine that cannot load BPF.
        let cli = Cli::try_parse_from(["installscope", "record", "--", "true"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Record(args) => assert_eq!(args.backend, BackendChoice::Strace),
            other => panic!("expected record, got {other:?}"),
        }
    }

    #[test]
    fn the_aya_backend_can_be_selected() {
        let cli = Cli::try_parse_from([
            "installscope",
            "record",
            "--backend",
            "aya",
            "--ebpf-object",
            "/tmp/probe.o",
            "--",
            "true",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Record(args) => {
                assert_eq!(args.backend, BackendChoice::Aya);
                assert_eq!(args.ebpf_object, PathBuf::from("/tmp/probe.o"));
            }
            other => panic!("expected record, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_backend_is_rejected() {
        // A typo must not silently fall back to a backend the user did not ask for: they would get a
        // recording with different fidelity than they believe.
        assert!(
            Cli::try_parse_from(["installscope", "record", "--backend", "ebpf", "--", "true"])
                .is_err(),
            "only the enumerated backends are accepted"
        );
    }

    #[test]
    fn parity_requires_both_recordings() {
        // A one-sided comparison is not a comparison. Requiring both makes that a usage error rather
        // than a run that trivially "passes" against nothing.
        assert!(
            Cli::try_parse_from(["installscope", "parity", "--strace", "a.jsonl"]).is_err(),
            "both streams are required"
        );

        let cli = Cli::try_parse_from([
            "installscope",
            "parity",
            "--strace",
            "a.jsonl",
            "--aya",
            "b.jsonl",
            "--show-expected",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Parity(args) => {
                assert_eq!(args.strace, PathBuf::from("a.jsonl"));
                assert_eq!(args.aya, PathBuf::from("b.jsonl"));
                assert!(args.show_expected);
            }
            other => panic!("expected parity, got {other:?}"),
        }
    }

    #[test]
    fn partial_has_a_distinct_exit_code() {
        // A caller must be able to distinguish "recorded but incomplete" from "failed to record".
        assert_ne!(EXIT_PARTIAL, EXIT_FAILURE);
        assert_ne!(EXIT_PARTIAL, 0);
    }

    #[test]
    fn nothing_to_record_has_its_own_exit_code() {
        // A workflow step branches on this to decide whether to spend a runner. Collapsing it into
        // failure would make a dependency-removal PR look like a broken build; collapsing it into success
        // would record nothing and say nothing.
        assert_ne!(EXIT_NOTHING_TO_RECORD, EXIT_FAILURE);
        assert_ne!(EXIT_NOTHING_TO_RECORD, EXIT_PARTIAL);
        assert_ne!(EXIT_NOTHING_TO_RECORD, 0);
    }

    #[test]
    fn lockfile_diff_requires_both_sides() {
        // A one-sided diff is not a diff. Requiring both makes that a usage error rather than a run that
        // trivially reports "everything is new".
        assert!(
            Cli::try_parse_from(["installscope", "lockfile-diff", "--before", "a.json"]).is_err(),
            "both lockfiles are required"
        );

        let cli = Cli::try_parse_from([
            "installscope",
            "lockfile-diff",
            "--before",
            "old/package-lock.json",
            "--after",
            "new/package-lock.json",
            "--json",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::LockfileDiff(args) => {
                assert_eq!(args.before, PathBuf::from("old/package-lock.json"));
                assert_eq!(args.after, PathBuf::from("new/package-lock.json"));
                assert!(args.json);
                assert!(!args.always_succeed);
            }
            other => panic!("expected lockfile-diff, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_push_requires_the_package_and_version() {
        // A snapshot with no identity cannot be diffed against anything, so it is refused at parse time
        // rather than stored as an orphan.
        assert!(
            Cli::try_parse_from(["installscope", "snapshot", "push", "events.jsonl"]).is_err(),
            "--package and --version are required"
        );

        let cli = Cli::try_parse_from([
            "installscope",
            "snapshot",
            "push",
            "events.jsonl",
            "--package",
            "lodash",
            "--version",
            "4.17.21",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Snapshot(SnapshotCommand::Push(args)) => {
                assert_eq!(args.events, PathBuf::from("events.jsonl"));
                assert_eq!(args.package, "lodash");
                assert_eq!(args.version, "4.17.21");
                assert_eq!(args.registry, PathBuf::from(".installscope/registry"));
            }
            other => panic!("expected snapshot push, got {other:?}"),
        }
    }

    #[test]
    fn diff_takes_a_package_and_two_versions_positionally() {
        // Architecture.md:90 spells it `installscope diff <pkg> 1.2.3 1.2.4`. Matching the documented
        // shape matters: that string is in the README and in the launch post.
        let cli = Cli::try_parse_from(["installscope", "diff", "lodash", "4.17.20", "4.17.21"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Diff(args) => {
                assert_eq!(args.package, "lodash");
                assert_eq!(args.before, "4.17.20");
                assert_eq!(args.after, "4.17.21");
                assert!(!args.fail_on_change, "advisory by default (PRD.md:43)");
            }
            other => panic!("expected diff, got {other:?}"),
        }

        assert!(
            Cli::try_parse_from(["installscope", "diff", "lodash", "4.17.20"]).is_err(),
            "a comparison needs two versions"
        );
    }

    #[test]
    fn snapshot_list_accepts_a_package_filter() {
        let cli = Cli::try_parse_from([
            "installscope",
            "snapshot",
            "list",
            "--package",
            "lodash",
            "--json",
        ])
        .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Snapshot(SnapshotCommand::List(args)) => {
                assert_eq!(args.package.as_deref(), Some("lodash"));
                assert!(args.json);
            }
            other => panic!("expected snapshot list, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_verify_needs_only_a_registry() {
        // Deliberately unfiltered: a partial verification of a corpus is not a verification. Adding a
        // `--package` filter here would invite checking the one snapshot someone was already suspicious
        // of and calling the store sound.
        let cli = Cli::try_parse_from(["installscope", "snapshot", "verify"])
            .unwrap_or_else(|e| panic!("parse: {e}"));
        match cli.command {
            Command::Snapshot(SnapshotCommand::Verify(args)) => {
                assert_eq!(args.registry, PathBuf::from(".installscope/registry"));
            }
            other => panic!("expected snapshot verify, got {other:?}"),
        }
    }
}
