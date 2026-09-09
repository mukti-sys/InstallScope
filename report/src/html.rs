//! Self-contained HTML report — one file, no external assets.
//!
//! The third rendering surface, after the PR comment and SARIF. Architecture.md:18 names it, and
//! Rules.md §1 forbids external CDN links: everything must be inline so the artifact works when
//! downloaded, shared, or opened offline.
//!
//! # Information hierarchy
//!
//! Design.md:28 requires the PR comment and the HTML report to present the same information in the
//! same order. A reader who sees the comment and then opens the artifact is not re-orienting:
//!
//! 1. Score and verdict (with PARTIAL badge when applicable)
//! 2. Top findings (bullets)
//! 3. Coverage caveat (when the backend has blind spots)
//! 4. Full signal log (Row 2)
//! 5. Per-class coverage table
//! 6. Skipped checks & evidence detail
//!
//! # What this renderer refuses to do
//!
//! Same contract as the other two: it does not soften a PARTIAL recording, and it does not present
//! a limited backend's clean result as an unqualified pass. Tests assert both.
//!
//! # Every rendered value comes from the recording
//!
//! The signal log is built by walking the event stream that was passed in. There are no illustrative
//! rows, no placeholder session identifiers, and no invented coverage percentages: a forensic artifact
//! that displays a syscall the recording does not contain is the exact failure this product exists to
//! detect in other tools, and Rules.md §5 forbids it outright. Where the schema cannot supply a value —
//! a raw strace line, a source location inside a package's JavaScript, a stream digest — the field is
//! absent rather than filled in. `renders_only_what_the_recording_contains` and
//! `an_empty_recording_renders_no_signal_rows` are the tests that keep it that way.
//!
//! # Why the per-class coverage table lives here and not in the comment
//!
//! `Memory.md`:194 records it as a Phase 3 obligation: the parity harness keeps the strace/aya
//! asymmetry visible as per-class counts, and the report has to do the same.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use installscope_core::{
    select_bullets, Analysis, Event, Observability, Outcome, PathOrigin, Payload, Severity,
    TracedPath,
};

use crate::{format_bullet, ReportContext, Verdict};

/// Renders the analysis as a self-contained HTML document.
///
/// The output is a complete `<!DOCTYPE html>` page with inline CSS. No external stylesheets, no
/// JavaScript CDN, no images — Rules.md §1 forbids external assets.
///
/// `events` is the recording the analysis came from. It is a separate parameter rather than something
/// reconstructed from [`Analysis`] because the signal log is a log *of the stream*: findings carry only
/// a bounded evidence sample, so an artifact built from findings alone could not show the observations
/// that produced no finding — and "what else did this install do" is the question the artifact exists to
/// answer.
#[must_use]
pub fn render_html(analysis: &Analysis, context: &ReportContext, events: &[Event]) -> String {
    let verdict = Verdict::of(analysis);
    let mut out = String::with_capacity(32768);

    render_head(&mut out, context);
    out.push_str("<div class=\"shell\">\n");
    render_header(&mut out, analysis, context, events);
    render_partial_warning(&mut out, analysis, verdict);
    render_top_row(&mut out, analysis, context, verdict);
    render_caveats(&mut out, analysis);
    render_signal_log(&mut out, analysis, events);
    render_coverage_table(&mut out, analysis);
    render_skipped_rules(&mut out, analysis);
    render_footer(&mut out, analysis, events);
    out.push_str("</div>\n\n");
    render_scripts(&mut out);
    out.push_str("</body>\n</html>\n");
    out
}

/// Emits `<!DOCTYPE html>`, `<head>`, and the opening `<body>` tag.
fn render_head(out: &mut String, context: &ReportContext) {
    let _ = write!(
        out,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>InstallScope — {subject}</title>
{CSS}
</head>
<body>
"#,
        subject = escape(&context.subject_label()),
        CSS = INLINE_CSS,
    );
}

/// Emits the flight recorder header block: beacon, title, subject label, and metadata strip.
///
/// Every field in the metadata strip is read from the recording's own `session_start` and `session_end`.
/// A recording that does not declare its kernel, its capture instant, or its duration renders fewer
/// fields rather than plausible ones: a header that states a kernel version the stream never mentioned
/// is a fabricated provenance claim about evidence, which is worse than an incomplete strip.
fn render_header(out: &mut String, analysis: &Analysis, context: &ReportContext, events: &[Event]) {
    let pkg_name = if let Some(pkg) = &context.package {
        if let Some(ver) = &context.version {
            format!("{pkg}@{ver}")
        } else {
            pkg.clone()
        }
    } else {
        context.subject_label()
    };

    let start = session_start(events);
    let mut fields: Vec<String> = Vec::new();

    // The backend is always known: it is stamped on every event, including the framing ones.
    let mut recorder = format!(
        "RECORDER {}",
        escape(&format!("{}", analysis.coverage.backend))
    );
    if let Some(kernel) = start
        .and_then(|start| start.host.as_ref())
        .and_then(|host| host.kernel.as_deref())
    {
        let _ = write!(recorder, "/{}", escape(kernel));
    }
    fields.push(recorder);

    if let Some(agent) = start.map(|start| start.agent_version.as_str()) {
        fields.push(format!("AGENT {}", escape(agent)));
    }
    if let Some(captured) = start.map(|start| start.wall_clock_utc.as_str()) {
        fields.push(format!("CAPTURED {}", escape(captured)));
    }
    if let Some(duration) = session_end(events).map(|end| end.duration_ns) {
        fields.push(format!("WALL {}", format_duration(duration)));
    }
    fields.push(format!("SIGNALS {}", analysis.observations));

    let _ = write!(
        out,
        r#"<header>
  <div class="header-left">
    <span class="beacon-sq" aria-hidden="true"></span>
    <span class="rec-tag">REC</span>
    <span class="pkg-name">{pkg_name}</span>
  </div>
  <div class="header-right">
    {meta}
  </div>
</header>
"#,
        pkg_name = escape(&pkg_name),
        meta = fields.join("<span class=\"sep\">·</span>"),
    );
}

/// The recording's opening framing event, when it has one.
fn session_start(events: &[Event]) -> Option<&installscope_core::SessionStart> {
    events.iter().find_map(|event| match &event.payload {
        Payload::SessionStart(start) => Some(start),
        _ => None,
    })
}

/// The recording's closing framing event, when it has one.
fn session_end(events: &[Event]) -> Option<&installscope_core::SessionEnd> {
    events.iter().rev().find_map(|event| match &event.payload {
        Payload::SessionEnd(end) => Some(end),
        _ => None,
    })
}

/// Renders a nanosecond duration as seconds with millisecond precision.
fn format_duration(ns: u64) -> String {
    let millis = ns / 1_000_000;
    format!("{}.{:03}s", millis / 1000, millis % 1000)
}

/// Renders a session-relative timestamp as `HH:MM:SS.mmm`.
fn format_timestamp(ns: u64) -> String {
    let millis = ns / 1_000_000;
    let seconds = millis / 1000;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60,
        millis % 1000
    )
}

/// Emits the PARTIAL warning block when the recording was incomplete.
fn render_partial_warning(out: &mut String, analysis: &Analysis, verdict: Verdict) {
    if !verdict.shows_partial_badge() {
        return;
    }
    out.push_str("<div class=\"callout warning\">\n");
    out.push_str(
        "<p><strong>This recording is incomplete.</strong> The findings below are real, but \
         they are not the whole picture — absence of a finding here is not evidence it did \
         not happen.</p>\n",
    );
    if !analysis.partial_reasons.is_empty() {
        out.push_str("<ul>\n");
        for reason in &analysis.partial_reasons {
            let _ = writeln!(out, "<li>{}</li>", escape(reason));
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</div>\n\n");
}

/// Emits Row 1: Score Card (left) and Priority Findings (right).
fn render_top_row(
    out: &mut String,
    analysis: &Analysis,
    _context: &ReportContext,
    verdict: Verdict,
) {
    out.push_str("<section class=\"row-top\" aria-label=\"Risk Score and Priority Findings\">\n");
    render_score_card(out, analysis, verdict);
    render_priority_findings(out, analysis, verdict);
    out.push_str("</section>\n\n");
}

/// Renders the 280px left score card module.
fn render_score_card(out: &mut String, analysis: &Analysis, verdict: Verdict) {
    let score_val = analysis.score.value;
    let (band_name, band_class) = if verdict.shows_partial_badge() {
        ("PARTIAL", "partial")
    } else if score_val == 0 {
        ("NOMINAL", "ok")
    } else if score_val < 25 {
        ("NOTABLE", "med")
    } else if score_val < 60 {
        ("ELEVATED", "high")
    } else {
        ("CRITICAL", "crit")
    };

    let tick_pct = score_val.min(100);
    let crit_count = analysis
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = analysis
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    // The recording's own observation count. No fallback: a stream with zero observations has zero
    // signals, and printing a number for it would assert activity the recording does not contain.
    let total_signals = analysis.observations;
    let unexplained = scorable_count(analysis);

    // Coverage is reported as counts the report can actually derive from the backend's own table: how
    // many classes it cannot see at all, and how many it sees with a documented limitation. The previous
    // fixed "98.2% / 1 GAP" was measured from nothing.
    let blind_spots = analysis.coverage.blind_spots().len();
    let qualified = analysis.coverage.qualifications().len();

    let raw_part = if analysis.score.was_capped() {
        format!(
            " <span class=\"score-raw\">(raw {})</span>",
            analysis.score.raw
        )
    } else {
        String::new()
    };

    let partial_badge = if verdict.shows_partial_badge() {
        " <span class=\"badge partial\">PARTIAL</span>"
    } else {
        ""
    };

    let _ = write!(
        out,
        r#"    <div class="score-card">
      <div class="score-baseline">
        <span class="score-num">{score_val}</span>
        <span class="score-max">/ 100</span>{raw_part}{partial_badge}
        <span class="sr-only">{score_val} / 100</span>
      </div>
      <div class="score-label">SURPRISE INDEX</div>
      <div class="score-band {band_class}">{band_name}</div>
      <p class="score-def">Weighted sum of the findings below, capped at 100. A triage signal, not a measurement: 0 means no rule in the catalog fired on this recording.</p>
      <div class="band-track" aria-hidden="true">
        <div class="track-seg seg-ok"></div>
        <div class="track-seg seg-med"></div>
        <div class="track-seg seg-high"></div>
        <div class="track-seg seg-crit"></div>
        <div class="track-tick" style="left: {tick_pct}%;"></div>
      </div>
      <div class="band-legend">0–9 NOMINAL · 10–24 NOTABLE · 25–59 ELEVATED · 60+ CRITICAL</div>
      <div class="micro-grid">
        <div class="grid-cell"><span class="grid-label">SIGNALS</span><span class="grid-val">{total_signals}</span></div>
        <div class="grid-cell"><span class="grid-label">FINDINGS</span><span class="grid-val">{unexplained}</span></div>
        <div class="grid-cell"><span class="grid-label">CRITICAL</span><span class="grid-val">{crit_count}</span></div>
        <div class="grid-cell"><span class="grid-label">HIGH</span><span class="grid-val">{high_count}</span></div>
        <div class="grid-cell"><span class="grid-label">NOT SEEN</span><span class="grid-val">{blind_spots}</span></div>
        <div class="grid-cell"><span class="grid-label">QUALIFIED</span><span class="grid-val">{qualified}</span></div>
      </div>
    </div>
"#,
    );
}

/// Renders the right flex priority findings module.
fn render_priority_findings(out: &mut String, analysis: &Analysis, verdict: Verdict) {
    let scorable_bullets: Vec<_> = select_bullets(&analysis.findings)
        .into_iter()
        .filter(|f| f.severity.contributes_to_score())
        .collect();

    out.push_str("    <div class=\"findings-panel\">\n");
    out.push_str("      <h2 class=\"panel-title\">PRIORITY FINDINGS</h2>\n");

    if scorable_bullets.is_empty() {
        let _ = writeln!(
            out,
            "      <p class=\"headline\">{}</p>",
            escape(&capitalise(verdict.headline()))
        );
    } else {
        out.push_str("      <div class=\"findings-list\">\n");
        for finding in &scorable_bullets {
            render_priority_item(out, finding);
        }
        let hidden = scorable_count(analysis).saturating_sub(scorable_bullets.len());
        if hidden > 0 {
            let _ = writeln!(
                out,
                "        <p class=\"overflow\">…and {hidden} more finding{} below in signal log</p>",
                if hidden == 1 { "" } else { "s" }
            );
        }
        out.push_str("      </div>\n");
    }
    out.push_str("    </div>\n");
}

/// ATT&CK technique for a rule, when the mapping is defensible.
///
/// Keyed on the rule ids that actually exist in `rules/catalog.yaml` — an earlier version of this
/// function matched on `persistence_cron`, `persistence_shell_init` and `credential_read`, none of which
/// are rules, so every finding fell through to a default technique it had not earned.
///
/// Returns `None` rather than a fallback. A technique id is a claim about attacker behaviour, and
/// attaching `T1059.007` to a finding that is merely an unrecognised binary would be asserting
/// JavaScript execution the recording did not show.
fn attck_technique(rule_id: &str) -> Option<&'static str> {
    match rule_id {
        // Credentials in files.
        "credential_path_read" | "credential_path_read_attempted" | "npmrc_read" => {
            Some("T1552.001")
        }
        // Ingress tool transfer.
        "dns_binary_distribution_host" => Some("T1105"),
        // Application layer protocol: web protocols.
        "spawned_network_tool" => Some("T1071.001"),
        // Command and scripting interpreter: Unix shell.
        "download_piped_to_shell" => Some("T1059.004"),
        // Non-standard port.
        "network_connect_unusual_port" => Some("T1571"),
        // File and directory permissions modification.
        "chmod_exec_outside_project" => Some("T1222.002"),
        // No defensible mapping: a write outside the project, an unfamiliar exec, an unfamiliar
        // hostname, or an ordinary external connect are each consistent with too many techniques to
        // name one.
        _ => None,
    }
}

/// Renders a single finding card inside the priority list.
fn render_priority_item(out: &mut String, finding: &installscope_core::Finding) {
    let sev_str = match finding.severity {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
    };
    let sev_label = match finding.severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    };
    // The rule that fired is shown unconditionally; the technique only when one is mapped. A reader can
    // look the rule up in the catalog, which is more than a guessed technique id gives them.
    let mut tags = format!(
        "<code class=\"rule-id\">{}</code>",
        escape(&finding.rule_id)
    );
    if let Some(technique) = attck_technique(&finding.rule_id) {
        let _ = write!(
            tags,
            " <span class=\"mitre-id\">ATT&amp;CK {technique}</span>"
        );
    }
    if finding.occurrences > 1 {
        let _ = write!(
            tags,
            " <span class=\"finding-count\">&times;{}</span>",
            finding.occurrences
        );
    }

    let prose = match &finding.note {
        Some(note) => format!("{} — {}", escape(&finding.title), escape(note)),
        None => escape(&format_bullet(finding)),
    };

    let _ = write!(
        out,
        r#"        <article class="finding-item {sev_str}">
          <div class="finding-head">
            <span class="sev-tag {sev_str}">{sev_label}</span>
            <span class="finding-tags">{tags}</span>
          </div>
          <p class="finding-prose">{prose}</p>
        </article>
"#,
    );
}

/// Emits coverage caveats and unresolved-path warnings.
fn render_caveats(out: &mut String, analysis: &Analysis) {
    if let Some(caveat) = analysis.coverage.caveat_line() {
        let _ = writeln!(
            out,
            "<div class=\"callout caveat\">\n<p>{}</p>\n</div>\n",
            escape(&caveat)
        );
    }

    if analysis.unresolved_paths > 0 {
        let _ = writeln!(
            out,
            "<div class=\"callout caveat\">\n<p>{} path{} could not be resolved to an absolute \
             location and {} not checked against the expected directories (unresolved paths are not \
             scored as outside-zone to avoid false criticals).</p>\n</div>\n",
            analysis.unresolved_paths,
            if analysis.unresolved_paths == 1 { "" } else { "s" },
            if analysis.unresolved_paths == 1 { "was" } else { "were" },
        );
    }
}

/// Emits Row 2: the Signal Log — one row per observation in the recording.
///
/// Built entirely from `events`. Framing events (`session_start`, `heartbeat`, `session_end`) are
/// excluded because they are recorder bookkeeping rather than observations of the traced program, which is
/// the same split [`Payload::is_framing`] makes and the same one `analysis.observations` counts.
///
/// The severity column is filled by matching an observation against the findings that came out of the
/// same stream. A row with no finding shows `—`, meaning no rule in the catalog fired on it — not that it
/// was judged benign.
fn render_signal_log(out: &mut String, analysis: &Analysis, events: &[Event]) {
    let observations: Vec<&Event> = events
        .iter()
        .filter(|event| !event.payload.is_framing())
        .collect();
    let subjects = finding_subjects(analysis);

    out.push_str(
        r#"  <!-- Row 2: Signal Log -->
  <section class="log-section" aria-label="Syscall Signal Log">
    <div class="log-head">
      <div class="log-head-left">
        <h2 class="panel-title" style="margin-bottom:0;">SIGNAL LOG</h2>
        <div class="log-meta">"#,
    );
    let _ = write!(
        out,
        "{} SIGNALS · {} WITH FINDINGS · {} UNRESOLVED PATH{}",
        observations.len(),
        scorable_count(analysis),
        analysis.unresolved_paths,
        if analysis.unresolved_paths == 1 {
            ""
        } else {
            "S"
        },
    );
    out.push_str(
        r#"</div>
      </div>
      <div class="log-filter-wrap">
        <input type="text" id="signal-filter" placeholder="Filter signals... (/)" aria-label="Filter signals">
        <span id="filter-count" class="filter-count"></span>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <caption class="sr-only">Every observation in this recording, with its timestamp, process, syscall, outcome, and the finding it produced if any</caption>
        <thead>
          <tr>
            <th scope="col" class="r col-ts"><abbr title="Elapsed time since the recording started (HH:MM:SS.mmm)">TIME</abbr></th>
            <th scope="col" class="r col-seq"><abbr title="Position of this observation in the event stream">SEQ #</abbr></th>
            <th scope="col" class="r col-pid"><abbr title="Process id that made the syscall">PID</abbr></th>
            <th scope="col" class="l col-syscall"><abbr title="Syscall the observation came from, as reported by the recorder">SYSCALL</abbr></th>
            <th scope="col" class="l col-op"><abbr title="Event class in the recording's schema">OP</abbr></th>
            <th scope="col" class="l col-args"><abbr title="What was observed: a path, an address, a hostname, a command line">SUBJECT</abbr></th>
            <th scope="col" class="l col-errno"><abbr title="Outcome: ok, the errno when the syscall failed, or unknown when the backend could not tell">OUTCOME</abbr></th>
            <th scope="col" class="r col-delta"><abbr title="Milliseconds elapsed since the preceding observation">Δ MS</abbr></th>
            <th scope="col" class="l col-sev"><abbr title="Severity of the finding this observation produced, or none if no rule fired">FINDING</abbr></th>
            <th scope="col" class="l col-cov"><abbr title="How the recorder arrived at this observation's path">PATH ORIGIN</abbr></th>
          </tr>
        </thead>
        <tbody id="signal-body">
"#,
    );

    if observations.is_empty() {
        out.push_str(
            "          <tr class=\"gap-row\"><td colspan=\"10\">This recording contains no \
             observations. An install that produced no events either failed before executing or was \
             not traced — the score above is a statement about the recording, not about the \
             install.</td></tr>\n",
        );
    } else {
        let mut previous_ts: Option<u64> = None;
        for (index, event) in observations.iter().enumerate() {
            render_signal_row(out, event, index + 1, previous_ts, &subjects);
            previous_ts = Some(event.meta.ts_ns);
        }
    }

    out.push_str("        </tbody>\n      </table>\n    </div>\n");

    // The recorder's own account of why the stream is short, placed after the rows it truncates. This is
    // the honest form of the "coverage gap" row: it names a reason the recording carries rather than
    // inventing a duration and a cause.
    if analysis.is_partial() {
        out.push_str(
            "    <p class=\"log-note\">The stream ends here because the recording is incomplete. \
             Observations after this point were not captured.</p>\n",
        );
    }

    out.push_str("  </section>\n\n");
}

/// Every `(subject, severity)` a finding claimed, most severe first per subject.
///
/// Used to fill the severity column without re-implementing the rules engine in a renderer: an
/// observation is marked with a finding exactly when a finding names its subject. Building the map from
/// `analysis.findings` keeps the report and the score from disagreeing.
fn finding_subjects(analysis: &Analysis) -> BTreeMap<&str, (Severity, &str)> {
    let mut subjects: BTreeMap<&str, (Severity, &str)> = BTreeMap::new();
    for finding in &analysis.findings {
        let entry = (finding.severity, finding.rule_id.as_str());
        subjects
            .entry(finding.subject.as_str())
            .and_modify(|existing| {
                // Severity is ordered most-severe-first, so the smaller value wins.
                if finding.severity < existing.0 {
                    *existing = entry;
                }
            })
            .or_insert(entry);
    }
    subjects
}

/// Emits one row for one observation.
fn render_signal_row(
    out: &mut String,
    event: &Event,
    sequence: usize,
    previous_ts: Option<u64>,
    subjects: &BTreeMap<&str, (Severity, &str)>,
) {
    let subject = signal_subject(&event.payload);
    let detail = signal_detail(&event.payload);
    let outcome = signal_outcome(&event.payload);
    let origin = signal_path_origin(&event.payload);

    // A finding is attached by subject match. `find_finding` also tries the truncated form the rules
    // engine uses for long command lines, so a spawn row is not silently unmarked.
    let finding = find_finding(subjects, &subject);
    let (row_class, severity_cell) = match finding {
        Some((Severity::Critical, _)) => (
            " class=\"row-crit\"",
            "<span class=\"sev-tag crit\">CRITICAL</span>".to_string(),
        ),
        Some((Severity::High, _)) => (
            " class=\"row-high\"",
            "<span class=\"sev-tag high\">HIGH</span>".to_string(),
        ),
        Some((Severity::Medium, _)) => {
            ("", "<span class=\"sev-tag med\">MEDIUM</span>".to_string())
        }
        Some((Severity::Low, _)) => ("", "<span class=\"sev-tag low\">LOW</span>".to_string()),
        None => ("", "&mdash;".to_string()),
    };

    let delta = match previous_ts {
        // Integer arithmetic throughout: the strace backend writes one trace file per pid, so a later
        // row can carry an earlier timestamp. Saturating renders that as +0.0 rather than as a negative
        // interval; the TIME column still shows the real instant. Kept in microseconds and formatted by
        // hand rather than converted to f64, which would silently lose precision on a long recording.
        Some(previous) => {
            let micros = event.meta.ts_ns.saturating_sub(previous) / 1_000;
            format!("+{}.{}", micros / 1_000, (micros % 1_000) / 100)
        }
        None => "&mdash;".to_string(),
    };

    let rule_note = finding.map_or_else(
        || "no rule in the catalog fired on this observation".to_string(),
        |(_, rule_id)| format!("matched rule {rule_id}"),
    );

    let _ = writeln!(
        out,
        "          <tr tabindex=\"0\"{row_class} data-detail=\"{detail}\" data-rule=\"{rule}\">\
         <td class=\"r col-ts\">{ts}</td>\
         <td class=\"r col-seq\">{sequence:04}</td>\
         <td class=\"r col-pid\">{pid}</td>\
         <td class=\"l col-syscall\">{syscall}</td>\
         <td class=\"l col-op\">{op}</td>\
         <td class=\"l col-args\" title=\"{subject_title}\">{subject}</td>\
         <td class=\"l col-errno\">{outcome}</td>\
         <td class=\"r col-delta\">{delta}</td>\
         <td class=\"l col-sev\">{severity_cell}</td>\
         <td class=\"l col-cov {origin_class}\">{origin}</td>\
         </tr>",
        detail = escape(&detail),
        rule = escape(&rule_note),
        ts = format_timestamp(event.meta.ts_ns),
        pid = event
            .meta
            .pid
            .map_or_else(|| "&mdash;".to_string(), |pid| pid.to_string()),
        syscall = event
            .meta
            .syscall
            .as_deref()
            .map_or_else(|| "&mdash;".to_string(), escape),
        op = escape(event.payload.op()),
        subject_title = escape(&subject),
        subject = escape(&elide(&subject, 96)),
        outcome = escape(&outcome),
        origin_class = origin.1,
        origin = origin.0,
    );
}

/// Finds the finding for a subject, allowing for the rules engine's own subject truncation.
fn find_finding<'a>(
    subjects: &BTreeMap<&'a str, (Severity, &'a str)>,
    subject: &str,
) -> Option<(Severity, &'a str)> {
    if let Some(found) = subjects.get(subject) {
        return Some(*found);
    }
    // `core::rules::truncate_subject` caps a subject at 200 chars and appends an ellipsis, and spawn
    // findings key on the basename rather than the full command line. Match on those forms rather than
    // leaving a row that did produce a finding looking as though it did not.
    subjects
        .iter()
        .find(|(key, _)| {
            key.strip_suffix('…')
                .is_some_and(|prefix| subject.starts_with(prefix))
                || subject
                    .split_whitespace()
                    .next()
                    .and_then(|first| first.rsplit('/').next())
                    .is_some_and(|basename| basename == **key)
        })
        .map(|(_, value)| *value)
}

/// The thing an observation is about: a path, an address, a hostname, a command line.
///
/// Mirrors the subject the rules engine keys findings on, so the severity column can be filled by a
/// lookup rather than by a second, quieter copy of the rules.
fn signal_subject(payload: &Payload) -> String {
    match payload {
        Payload::FsWrite(write) => write.target.path.clone(),
        Payload::FsRead(read) => read.target.path.clone(),
        Payload::NetConnect(connect) => match (&connect.ip, connect.port, &connect.unix_path) {
            (Some(ip), Some(port), _) => format!("{ip}:{port}"),
            (Some(ip), None, _) => ip.clone(),
            (None, _, Some(path)) => path.clone(),
            (None, _, None) => format!("{:?} socket", connect.family),
        },
        Payload::DnsQuery(query) => query.qname.clone(),
        Payload::ProcSpawn(spawn) => spawn.command_line(),
        // Framing events are filtered out before this is called.
        Payload::SessionStart(_) | Payload::Heartbeat(_) | Payload::SessionEnd(_) => String::new(),
    }
}

/// Extra facts the schema carries, shown in the expandable inset.
///
/// Deliberately assembled from schema fields only. There is no raw strace line in the event stream and no
/// source location inside the package's JavaScript, so neither is displayed — the previous version of this
/// renderer printed both from literals.
fn signal_detail(payload: &Payload) -> String {
    let mut parts: Vec<String> = Vec::new();
    match payload {
        Payload::FsWrite(write) => {
            parts.push(format!("kind {:?}", write.kind));
            if let Some(bytes) = write.bytes {
                parts.push(format!("{bytes} bytes"));
            }
            if let Some(flags) = &write.flags {
                parts.push(format!("flags {flags}"));
            }
            if let Some(mode) = &write.mode {
                parts.push(format!("mode {mode}"));
            }
            if let Some(source) = &write.source {
                parts.push(format!("source {}", source.path));
            }
        }
        Payload::FsRead(read) => {
            if let Some(bytes) = read.bytes {
                parts.push(format!("{bytes} bytes"));
            }
        }
        Payload::NetConnect(connect) => {
            parts.push(format!("family {:?}", connect.family));
            if connect.loopback {
                parts.push("loopback".to_string());
            }
            if connect.private {
                parts.push("private address".to_string());
            }
            if let Some(host) = &connect.host {
                parts.push(format!("host {host}"));
            }
        }
        Payload::DnsQuery(query) => {
            if let Some(qtype) = query.qtype {
                parts.push(format!("qtype {qtype}"));
            }
            if let Some(resolver) = &query.resolver_ip {
                parts.push(format!("resolver {resolver}"));
            }
        }
        Payload::ProcSpawn(spawn) => {
            if let Some(bin) = &spawn.bin {
                parts.push(format!("bin {bin}"));
            }
            parts.push(format!("{} argv element(s)", spawn.argv.len()));
            if spawn.argv_truncated {
                parts.push("argv truncated by the backend".to_string());
            }
        }
        Payload::SessionStart(_) | Payload::Heartbeat(_) | Payload::SessionEnd(_) => {}
    }
    if parts.is_empty() {
        "no additional detail in the schema".to_string()
    } else {
        parts.join(" · ")
    }
}

/// The outcome cell: `ok`, an errno, or `unknown`.
///
/// `unknown` is rendered as such rather than as success. A backend that could not determine whether a
/// syscall succeeded has not established that it did, and the aya backend's entry-only probes are exactly
/// that case.
fn signal_outcome(payload: &Payload) -> String {
    let outcome: Option<&Outcome> = match payload {
        Payload::FsWrite(write) => Some(&write.outcome),
        Payload::FsRead(read) => Some(&read.outcome),
        Payload::NetConnect(connect) => Some(&connect.outcome),
        Payload::DnsQuery(query) => Some(&query.outcome),
        Payload::ProcSpawn(spawn) => Some(&spawn.outcome),
        Payload::SessionStart(_) | Payload::Heartbeat(_) | Payload::SessionEnd(_) => None,
    };
    match outcome {
        Some(Outcome { ok: Some(true), .. }) => "ok".to_string(),
        Some(Outcome {
            ok: Some(false),
            error: Some(errno),
        }) => errno.clone(),
        Some(Outcome {
            ok: Some(false),
            error: None,
        }) => "failed".to_string(),
        Some(Outcome { ok: None, .. }) | None => "unknown".to_string(),
    }
}

/// How the recorder arrived at this observation's path, and the CSS class for it.
///
/// Surfaced per row because it is what bounds the filesystem rules: an `unresolved` path was deliberately
/// not placed inside or outside any zone, and a reader looking at a quiet log needs to see how many of
/// its rows were unplaceable.
fn signal_path_origin(payload: &Payload) -> (&'static str, &'static str) {
    let traced: Option<&TracedPath> = match payload {
        Payload::FsWrite(write) => Some(&write.target),
        Payload::FsRead(read) => Some(&read.target),
        _ => None,
    };
    match traced.map(|path| path.origin) {
        Some(PathOrigin::Kernel) => ("kernel", "origin-resolved"),
        Some(PathOrigin::Absolute) => ("absolute", "origin-resolved"),
        Some(PathOrigin::ResolvedFromDirfd) => ("from dirfd", "origin-resolved"),
        Some(PathOrigin::Unresolved) => ("unresolved", "origin-unresolved"),
        None => ("&mdash;", ""),
    }
}

/// Shortens a string for a table cell, keeping the full value in the cell's `title`.
fn elide(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let kept: String = text.chars().take(limit.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Emits the per-class coverage table.
fn render_coverage_table(out: &mut String, analysis: &Analysis) {
    out.push_str("<section class=\"coverage\" id=\"coverage-section\" tabindex=\"-1\">\n<div class=\"section-head\"><h2 class=\"panel-title\">What this recording could observe</h2></div>\n");
    let _ = writeln!(
        out,
        "<p class=\"coverage-intro\">Recorded with the <code>{}</code> backend. A class marked \
         <em>not observed</em> means the absence of a finding in that class says nothing about the \
         install.</p>",
        escape(&format!("{}", analysis.coverage.backend))
    );
    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr>\
        <th>Behavior</th><th>Observed</th><th>Qualification</th>\
        </tr></thead>\n<tbody>\n",
    );
    for (class, observability) in &analysis.coverage.classes {
        let (state_class, state_label) = match observability {
            Observability::Observed => ("observed", "yes"),
            Observability::Partial(_) => ("qualified", "with caveat"),
            Observability::Unobserved(_) => ("unobserved", "no"),
        };
        let _ = writeln!(
            out,
            "<tr class=\"coverage-{state_class}\">\
            <td class=\"mono\">{class}</td>\
            <td><span class=\"tag {state_class}\">{state_label}</span></td>\
            <td>{note}</td>\
            </tr>",
            class = escape(class.as_str()),
            note = observability.note().map_or_else(
                || "&mdash;".to_string(),
                |note| capitalise_sentence(&escape(note))
            ),
        );
    }
    out.push_str("</tbody>\n</table></div>\n</section>\n\n");
}

/// Emits the collapsible skipped-rules section.
fn render_skipped_rules(out: &mut String, analysis: &Analysis) {
    if analysis.skipped_rules.is_empty() {
        return;
    }
    out.push_str(
        "<details class=\"skipped\">\n\
        <summary>Checks that did not run on this backend</summary>\n<ul>\n",
    );
    for (rule_id, reason) in &analysis.skipped_rules {
        let _ = writeln!(
            out,
            "<li><code>{}</code> — {}</li>",
            escape(rule_id),
            escape(reason)
        );
    }
    out.push_str("</ul>\n</details>\n\n");
}

/// Emits the footer with keybar and provenance strip.
///
/// The strip states facts the recording carries. It previously printed a fixed `SHA-256 a3f1c9…8e04`
/// and the word `immutable`: the renderer has no digest of the stream (the registry computes one over
/// compressed bytes, and this crate never sees it), so a digest here would be a fabricated integrity
/// claim about evidence — the worst possible place for one.
fn render_footer(out: &mut String, analysis: &Analysis, events: &[Event]) {
    let mut facts: Vec<String> = vec![format!(
        "backend <code>{}</code>",
        escape(&format!("{}", analysis.coverage.backend))
    )];
    if let Some(end) = session_end(events) {
        facts.push(format!(
            "{} observation{} recorded",
            end.events_emitted,
            if end.events_emitted == 1 { "" } else { "s" }
        ));
        facts.push(format!(
            "{} heartbeat{}",
            end.heartbeats,
            if end.heartbeats == 1 { "" } else { "s" }
        ));
        facts.push(
            if end.complete {
                "stream terminated cleanly"
            } else {
                "stream INCOMPLETE"
            }
            .to_string(),
        );
    } else {
        facts.push("no session_end: the stream is unterminated".to_string());
    }
    facts.push(
        "Advisory: this report records what the install did, and does not block the build"
            .to_string(),
    );

    let _ = write!(
        out,
        r#"  <footer>
    <div class="keybar" role="toolbar" aria-label="Keyboard shortcuts and actions">
      <button type="button" class="key-btn" id="btn-move" title="Use j / k or Arrow keys to navigate rows"><kbd>j/k</kbd> move</button>
      <button type="button" class="key-btn" id="btn-expand" title="Press Enter or click row to inspect event details"><kbd>⏎</kbd> expand</button>
      <button type="button" class="key-btn" id="btn-filter" title="Press / to filter signals"><kbd>/</kbd> filter</button>
      <button type="button" class="key-btn" id="btn-coverage" title="Press c to scroll to coverage matrix"><kbd>c</kbd> coverage</button>
      <button type="button" class="key-btn" id="btn-export" title="Press e to export the signal log as JSON"><kbd>e</kbd> export json</button>
      <button type="button" class="key-btn" id="btn-quit" title="Press q or Esc to collapse insets and clear filter"><kbd>q</kbd> quit</button>
    </div>
    <div class="integrity">
      {facts}
    </div>
  </footer>
"#,
        facts = facts.join("<span class=\"sep\">·</span>"),
    );
}

/// Emits the interactive vanilla JS script for row toggling, filter, export, and keyboard navigation.
fn render_scripts(out: &mut String) {
    out.push_str("<script>\n(function() {\n");
    render_scripts_core(out);
    render_scripts_export(out);
    render_scripts_nav(out);
    out.push_str("})();\n</script>\n");
}

/// Emits state initialization, insets expansion, and real-time text filtering.
fn render_scripts_core(out: &mut String) {
    out.push_str(
        r"  const tbody = document.getElementById('signal-body');
  const filterInput = document.getElementById('signal-filter');
  const filterCount = document.getElementById('filter-count');
  const covSection = document.getElementById('coverage-section');
  if (!tbody) return;
  const allRows = Array.from(tbody.querySelectorAll('tr:not(.gap-row)'));
  let visibleRows = allRows.slice();
  let activeIndex = -1;

  function toggleExpand(tr) {
    if (!tr) return;
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('inset-row')) {
      next.remove();
      return;
    }
    const detail = tr.getAttribute('data-detail');
    const rule = tr.getAttribute('data-rule');
    if (!detail && !rule) return;
    const inset = document.createElement('tr');
    inset.className = 'inset-row';
    const td = document.createElement('td');
    td.colSpan = 10;
    // Built with textContent and appendChild rather than by assembling a markup string: these
    // attributes carry paths, hostnames and argv from the recorded install, which is
    // attacker-influenced input. The server-side escaping already covers the attribute, and building
    // the node this way means a second escaping bug cannot become script execution in a report a
    // maintainer opens.
    const wrap = document.createElement('div');
    wrap.className = 'inset-content';
    if (detail) {
      const line = document.createElement('div');
      line.className = 'inset-line mono inset-raw';
      line.textContent = detail;
      wrap.appendChild(line);
    }
    if (rule) {
      const line = document.createElement('div');
      line.className = 'inset-line mono';
      line.textContent = rule;
      wrap.appendChild(line);
    }
    td.appendChild(wrap);
    inset.appendChild(td);
    tr.after(inset);
  }

  function closeAllInsets() {
    tbody.querySelectorAll('.inset-row').forEach(row => row.remove());
  }

  function applyFilter(query) {
    const q = query.toLowerCase().trim();
    closeAllInsets();
    let matches = 0;
    allRows.forEach(tr => {
      const text = (tr.textContent + ' ' + (tr.getAttribute('data-detail') || '') + ' ' + (tr.getAttribute('data-rule') || '')).toLowerCase();
      if (!q || text.includes(q)) {
        tr.style.display = '';
        matches++;
      } else {
        tr.style.display = 'none';
      }
    });
    visibleRows = allRows.filter(tr => tr.style.display !== 'none');
    if (filterCount) {
      filterCount.textContent = q ? matches + ' / ' + allRows.length + ' visible' : '';
    }
    activeIndex = visibleRows.length > 0 ? 0 : -1;
    if (activeIndex >= 0) visibleRows[0].focus();
  }
",
    );
}

/// Emits client-side JSON export and view reset logic.
fn render_scripts_export(out: &mut String) {
    out.push_str(
        r#"  function exportReportJson() {
    const scoreNum = document.querySelector('.score-num')?.textContent?.trim() || "0";
    const scoreBand = document.querySelector('.score-band')?.textContent?.trim() || "";
    const signals = allRows.map((tr) => {
      const cells = tr.querySelectorAll('td');
      return {
        time: cells[0]?.textContent?.trim() || "",
        seq: cells[1]?.textContent?.trim() || "",
        pid: cells[2]?.textContent?.trim() || "",
        syscall: cells[3]?.textContent?.trim() || "",
        op: cells[4]?.textContent?.trim() || "",
        // The full value, not the elided cell text.
        subject: cells[5]?.getAttribute('title') || cells[5]?.textContent?.trim() || "",
        outcome: cells[6]?.textContent?.trim() || "",
        delta_ms: cells[7]?.textContent?.trim() || "",
        finding: cells[8]?.textContent?.trim() || "",
        path_origin: cells[9]?.textContent?.trim() || "",
        detail: tr.getAttribute('data-detail') || "",
        rule: tr.getAttribute('data-rule') || ""
      };
    });
    const reportData = {
      generator: "InstallScope HTML report",
      note: "Rendered from the recording named below. This export is a view of that stream, not a new recording.",
      exported_at: new Date().toISOString(),
      score: { value: parseInt(scoreNum) || 0, band: scoreBand },
      signals_count: signals.length,
      signals: signals
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'installscope-signal-log.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function resetView() {
    closeAllInsets();
    if (filterInput) {
      filterInput.value = '';
      applyFilter('');
      filterInput.blur();
    }
    if (visibleRows.length > 0) {
      activeIndex = 0;
      visibleRows[0].focus();
    }
  }
"#,
    );
}

/// Emits keyboard navigation and keybar button listener registrations.
fn render_scripts_nav(out: &mut String) {
    out.push_str(
        r"  if (filterInput) {
    filterInput.addEventListener('input', (e) => applyFilter(e.target.value));
    filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') resetView();
      else if (e.key === 'Enter') {
        e.preventDefault();
        if (visibleRows.length > 0) visibleRows[0].focus();
      }
    });
  }

  tbody.addEventListener('click', (e) => {
    const tr = e.target.closest('tr');
    if (tr && !tr.classList.contains('gap-row') && !tr.classList.contains('inset-row')) {
      activeIndex = visibleRows.indexOf(tr);
      tr.focus();
      toggleExpand(tr);
    }
  });

  window.addEventListener('keydown', (e) => {
    const isTyping = document.activeElement && (document.activeElement.tagName === 'INPUT' || document.activeElement.tagName === 'TEXTAREA');
    if (isTyping && e.key !== 'Escape') return;

    if (['ArrowDown', 'j', 'J'].includes(e.key)) {
      e.preventDefault();
      if (visibleRows.length > 0) {
        activeIndex = Math.min(activeIndex + 1, visibleRows.length - 1);
        visibleRows[activeIndex].focus();
        visibleRows[activeIndex].scrollIntoView({ block: 'nearest' });
      }
    } else if (['ArrowUp', 'k', 'K'].includes(e.key)) {
      e.preventDefault();
      if (visibleRows.length > 0) {
        activeIndex = Math.max(activeIndex - 1, 0);
        visibleRows[activeIndex].focus();
        visibleRows[activeIndex].scrollIntoView({ block: 'nearest' });
      }
    } else if (e.key === 'Enter' && activeIndex >= 0 && activeIndex < visibleRows.length) {
      e.preventDefault();
      toggleExpand(visibleRows[activeIndex]);
    } else if (e.key === '/' && !isTyping) {
      e.preventDefault();
      if (filterInput) { filterInput.focus(); filterInput.select(); }
    } else if (['c', 'C'].includes(e.key) && !isTyping) {
      e.preventDefault();
      if (covSection) covSection.scrollIntoView({ behavior: 'smooth' });
    } else if (['e', 'E'].includes(e.key) && !isTyping) {
      e.preventDefault();
      exportReportJson();
    } else if (['q', 'Q'].includes(e.key) || e.key === 'Escape') {
      e.preventDefault();
      resetView();
    } else if (e.key === 'g' && !e.shiftKey && !isTyping) {
      e.preventDefault();
      if (visibleRows.length > 0) { activeIndex = 0; visibleRows[0].focus(); }
    } else if ((e.key === 'G' || (e.key === 'g' && e.shiftKey)) && !isTyping) {
      e.preventDefault();
      if (visibleRows.length > 0) { activeIndex = visibleRows.length - 1; visibleRows[activeIndex].focus(); }
    }
  });

  const btnFilter = document.getElementById('btn-filter');
  const btnCoverage = document.getElementById('btn-coverage');
  const btnExport = document.getElementById('btn-export');
  const btnQuit = document.getElementById('btn-quit');
  const btnExpand = document.getElementById('btn-expand');
  if (btnFilter) btnFilter.addEventListener('click', () => { if (filterInput) { filterInput.focus(); filterInput.select(); } });
  if (btnCoverage) btnCoverage.addEventListener('click', () => { if (covSection) covSection.scrollIntoView({ behavior: 'smooth' }); });
  if (btnExport) btnExport.addEventListener('click', exportReportJson);
  if (btnQuit) btnQuit.addEventListener('click', resetView);
  if (btnExpand) btnExpand.addEventListener('click', () => {
    if (activeIndex >= 0 && activeIndex < visibleRows.length) toggleExpand(visibleRows[activeIndex]);
    else if (visibleRows.length > 0) { activeIndex = 0; visibleRows[0].focus(); toggleExpand(visibleRows[0]); }
  });
",
    );
}

/// The full inline `<style>` block.
const INLINE_CSS: &str = r#"<style>
:root {
  --bg: #0B0F14;
  --surface: #131A22;
  --header: #0E141B;
  --rule: #1E2A36;
  --rule-soft: #161F29;
  --row-hover: #161E27;
  --fg: #E6EDF3;
  --fg-dim: #7D8B99;
  --fg-faint: #4A5763;
  --beacon: #FF6A3D;
  --crit: #E5484D;
  --high: #F5A524;
  --med: #3B82C4;
  --ok: #3DD68C;
  --crit-txt: #FF6B70;
  --high-txt: #F5A524;
  --med-txt: #6BA6E0;
  --ok-txt: #3DD68C;
}

*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  background: var(--bg);
  color: var(--fg);
  font-family: Inter, -apple-system, "Segoe UI", system-ui, sans-serif;
  padding: 32px;
  -webkit-font-smoothing: antialiased;
}

.mono {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}

.shell {
  max-width: 1440px;
  margin: 0 auto;
  border: 1px solid var(--rule);
  background: var(--surface);
}

/* 56px Header */
header {
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  background: var(--header);
  border-bottom: 1px solid var(--rule);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.beacon-sq {
  width: 7px;
  height: 7px;
  background: var(--beacon);
  display: inline-block;
  animation: pulse-beacon 1.2s ease-in-out infinite;
}

@keyframes pulse-beacon {
  0% { opacity: 1; }
  50% { opacity: 0.35; }
  100% { opacity: 1; }
}

@media (prefers-reduced-motion: reduce) {
  .beacon-sq {
    animation: none;
    opacity: 1;
  }
}

.rec-tag {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--beacon);
  margin-right: 8px;
}

.pkg-name {
  font-family: Inter, -apple-system, "Segoe UI", system-ui, sans-serif;
  font-size: 15px;
  line-height: 1.3;
  font-weight: 600;
  color: var(--fg);
}

.header-right {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
}

.sep {
  color: var(--fg-faint);
  margin: 0 4px;
}

/* Row 1: Score Card + Top Findings */
.row-top {
  display: flex;
  gap: 16px;
  padding: 24px;
  border-bottom: 1px solid var(--rule);
}

.score-card {
  flex: 0 0 280px;
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: 2px;
  padding: 20px;
  display: flex;
  flex-direction: column;
}

.score-baseline {
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.score-num {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 44px;
  line-height: 1.0;
  font-weight: 500;
  letter-spacing: -0.02em;
  color: var(--fg);
}

.score-max {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 13px;
  line-height: 1.0;
  color: var(--fg-dim);
}

.score-raw {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  color: var(--high-txt);
}

.score-label {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
  margin-top: 8px;
}

.score-band {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  margin-top: 4px;
}

.score-band.ok { color: var(--ok-txt); }
.score-band.med { color: var(--med-txt); }
.score-band.high { color: var(--high-txt); }
.score-band.crit { color: var(--crit-txt); }
.score-band.partial { color: var(--high-txt); }

.score-def {
  font-family: Inter, -apple-system, "Segoe UI", system-ui, sans-serif;
  font-size: 11px;
  line-height: 1.4;
  color: var(--fg-dim);
  margin-top: 8px;
}

.band-track {
  position: relative;
  height: 4px;
  background: var(--header);
  display: flex;
  margin-top: 12px;
}

.track-seg {
  height: 4px;
  border-right: 1px solid var(--rule);
}

.seg-ok { width: 10%; background: rgba(61, 214, 140, 0.18); }
.seg-med { width: 15%; background: rgba(59, 130, 196, 0.18); }
.seg-high { width: 35%; background: rgba(245, 165, 36, 0.18); }
.seg-crit { width: 40%; background: rgba(229, 72, 77, 0.18); border-right: none; }

.track-tick {
  position: absolute;
  top: 0;
  width: 1px;
  height: 4px;
  background: var(--fg);
}

.band-legend {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
  margin-top: 8px;
}

.micro-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  row-gap: 8px;
  column-gap: 12px;
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid var(--rule);
}

.grid-cell {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.grid-label {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
}

.grid-val {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 12px;
  line-height: 1.2;
  font-weight: 400;
  color: var(--fg);
}

.findings-panel {
  flex: 1;
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: 2px;
  padding: 20px;
  display: flex;
  flex-direction: column;
}

.panel-title {
  font-family: Inter, -apple-system, "Segoe UI", system-ui, sans-serif;
  font-size: 11px;
  line-height: 1.4;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--fg-dim);
  margin-bottom: 16px;
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.finding-item {
  padding-left: 12px;
  position: relative;
}

.finding-item.crit { border-left: 2px solid var(--crit); }
.finding-item.high { border-left: 2px solid var(--high); }
.finding-item.med { border-left: 2px solid var(--med); }
.finding-item.low { border-left: 2px solid var(--rule); }

.finding-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
}

.finding-tags {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.rule-id {
  font-size: 10px;
  letter-spacing: 0.04em;
  color: var(--fg-dim);
}

.mitre-id {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  letter-spacing: 0.08em;
  color: var(--fg-dim);
}

.finding-prose {
  font-family: Inter, -apple-system, "Segoe UI", system-ui, sans-serif;
  font-size: 13px;
  line-height: 1.55;
  font-weight: 400;
  max-width: 68ch;
  color: var(--fg);
}

.finding-count {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  color: var(--fg-dim);
  margin-left: 6px;
}

.headline {
  font-size: 1.05rem;
  font-weight: 500;
  color: var(--ok-txt);
  margin: 0;
}

.overflow {
  color: var(--fg-dim);
  font-size: 11px;
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  margin-top: 8px;
}

/* Callouts */
.callout {
  border: 1px solid var(--rule);
  border-left: 3px solid var(--med);
  padding: 12px 16px;
  margin: 20px 24px 0;
  background: var(--header);
  border-radius: 2px;
  font-size: 13px;
  line-height: 1.5;
}

.callout.warning {
  border-left-color: var(--crit);
  background: rgba(229, 72, 77, 0.08);
}

.callout.caveat {
  border-left-color: var(--high);
  background: rgba(245, 165, 36, 0.08);
}

.callout p { margin: 0; }
.callout ul { margin: 8px 0 0; padding-left: 20px; }
.callout li { margin: 4px 0; font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }

/* Row 2: Signal Log */
.log-section {
  padding: 24px;
}

.log-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  gap: 16px;
  flex-wrap: wrap;
}

.log-head-left {
  display: flex;
  align-items: baseline;
  gap: 16px;
  flex-wrap: wrap;
}

.log-meta {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
}

.log-note {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  line-height: 1.5;
  color: var(--high-txt);
  padding: 10px 24px 0;
  max-width: 88ch;
}

.log-filter-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
}

#signal-filter {
  background: var(--header);
  border: 1px solid var(--rule);
  color: var(--fg);
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  padding: 4px 8px;
  border-radius: 2px;
  width: 220px;
  outline: none;
  transition: border-color 0.15s ease;
}

#signal-filter:focus {
  border-color: var(--beacon);
}

.filter-count {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  color: var(--fg-dim);
}

abbr[title] {
  text-decoration: underline dotted var(--fg-faint);
  text-underline-offset: 3px;
  cursor: help;
}

.table-wrap {
  border: 1px solid var(--rule);
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 12px;
  background: var(--surface);
}

thead {
  background: var(--header);
  position: sticky;
  top: 0;
  z-index: 2;
  border-bottom: 1px solid var(--rule);
}

th {
  height: 28px;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
  padding: 0 10px;
  text-align: left;
  white-space: nowrap;
}

th.r, td.r { text-align: right; }
th.l, td.l { text-align: left; }

td {
  padding: 6px 10px;
  border-bottom: 1px solid var(--rule-soft);
  vertical-align: top;
  color: var(--fg);
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--row-hover); }

tr:focus-visible {
  outline: 1px solid var(--beacon);
  outline-offset: -1px;
}

.row-crit { border-left: 2px solid var(--crit); }
.row-high { border-left: 2px solid var(--high); }

.col-ts { width: 96px; color: var(--fg-dim); }
.col-seq { width: 48px; color: var(--fg-faint); }
.col-pid { width: 60px; color: var(--fg-faint); }
.col-syscall { width: 104px; color: var(--fg); font-weight: 500; }
.col-op { width: 96px; color: var(--fg-dim); }
.col-args { max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--fg-dim); }
.col-errno { width: 88px; color: var(--high-txt); }
.col-delta { width: 64px; color: var(--fg-dim); }
.col-sev { width: 80px; }
.col-cov { width: 92px; font-size: 10px; letter-spacing: 0.08em; }

.origin-resolved { color: var(--fg-dim); }
.origin-unresolved { color: var(--high-txt); }

/* Coverage Gap Row */
tr.gap-row, tr.gap-row:hover {
  background: rgba(245, 165, 36, 0.05);
  border-top: 1px dashed var(--high);
  border-bottom: 1px dashed var(--high);
  height: 24px;
}

tr.gap-row td {
  color: var(--high-txt);
  text-align: center;
  padding: 3px 0;
  font-size: 10px;
  letter-spacing: 0.08em;
}

/* Expanded Inset Panel */
tr.inset-row, tr.inset-row:hover {
  background: var(--header);
  border-bottom: 1px solid var(--rule);
  cursor: default;
}

.inset-content {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.inset-line {
  font-size: 11px;
  line-height: 1.4;
  color: var(--fg-dim);
}

.inset-raw {
  color: var(--fg);
  white-space: pre-wrap;
  word-break: break-all;
}

/* Severity & Status Tags */
.sev-tag, .badge, .tag {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  padding: 2px 5px;
  border-radius: 2px;
  background: transparent;
  display: inline-block;
  white-space: nowrap;
}

.sev-tag.crit, .tag.critical, .tag.unobserved {
  border: 1px solid var(--crit);
  color: var(--crit-txt);
  background: rgba(229, 72, 77, 0.12);
}

.sev-tag.high, .tag.high, .badge.partial {
  border: 1px solid var(--high);
  color: var(--high-txt);
  background: rgba(245, 165, 36, 0.12);
}

.sev-tag.med, .tag.medium, .tag.qualified {
  border: 1px solid var(--med);
  color: var(--med-txt);
}

.sev-tag.low, .tag.low {
  border: 1px solid var(--rule);
  color: var(--fg-dim);
}

.tag.observed {
  border: 1px solid var(--ok);
  color: var(--ok-txt);
}

.coverage {
  padding: 0 24px 24px 24px;
}

.section-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.coverage-intro {
  color: var(--fg-dim);
  font-size: 12px;
  margin: 0 0 10px;
}

.coverage-unobserved td { border-left: 2px solid var(--crit); }

/* Collapsible Skipped Checks */
details.skipped {
  margin: 0 24px 24px;
  background: var(--header);
  border: 1px solid var(--rule);
  border-radius: 2px;
  padding: 12px 16px;
}

details.skipped summary {
  cursor: pointer;
  color: var(--fg-dim);
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

details.skipped ul {
  color: var(--fg-dim);
  margin: 10px 0 0;
  padding-left: 20px;
  font-size: 12px;
}

details.skipped li { margin: 4px 0; }

code {
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  background: var(--header);
  border: 1px solid var(--rule);
  padding: 1px 4px;
  border-radius: 2px;
  color: var(--fg);
}

/* Footer & Keybar */
footer {
  min-height: 42px;
  height: auto;
  background: var(--header);
  border-top: 1px solid var(--rule);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px;
  gap: 12px;
  font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-variant-numeric: tabular-nums;
  font-size: 10px;
  line-height: 1.3;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  color: var(--fg-dim);
}

.keybar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.key-btn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--fg-dim);
  font-family: inherit;
  font-size: inherit;
  text-transform: inherit;
  letter-spacing: inherit;
  padding: 2px 6px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  border-radius: 2px;
  transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
}

.key-btn:hover, .key-btn:focus-visible {
  color: var(--fg);
  background: var(--row-hover);
  border-color: var(--rule);
  outline: none;
}

kbd {
  background: var(--surface);
  border: 1px solid var(--rule);
  border-bottom: 2px solid var(--rule);
  color: var(--fg);
  font-family: inherit;
  font-size: 10px;
  padding: 1px 5px;
  border-radius: 3px;
  line-height: 1.1;
}

.integrity {
  color: var(--fg-dim);
}

@media (max-width: 1024px) {
  .col-seq, .col-delta {
    display: none;
  }
}

/* Print Styles */
@media print {
  body {
    background: #FFFFFF !important;
    color: #000000 !important;
    padding: 0 !important;
  }
  .shell, .score-card, .findings-panel, .table-wrap, table, thead, tbody, tr, td, th, header, footer {
    background: #FFFFFF !important;
    color: #000000 !important;
    border-color: #000000 !important;
  }
  .beacon-sq {
    animation: none !important;
    opacity: 1 !important;
    background: #000000 !important;
  }
  footer {
    display: none !important;
  }
  .row-crit, .row-high {
    border-left: 2px solid #000000 !important;
  }
  .sev-tag, .grid-val, .grid-label, .mitre-id, .finding-prose, .score-num, .score-max, .score-band, .pkg-name, .col-syscall, .col-args {
    color: #000000 !important;
    background: transparent !important;
    border-color: #000000 !important;
  }
}
</style>"#;

/// Capitalises the first letter of `s`.
fn capitalise(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |first| {
        format!("{}{}", first.to_uppercase(), chars.as_str())
    })
}

/// Capitalises the first character and appends a full stop when absent.
fn capitalise_sentence(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let trimmed = s.trim();
    let mut result = capitalise(trimmed);
    if !result.ends_with('.') && !result.ends_with('?') && !result.ends_with('!') {
        result.push('.');
    }
    result
}

/// Minimal HTML escaping for untrusted strings.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// How many findings count toward the score.
fn scorable_count(analysis: &Analysis) -> usize {
    analysis
        .findings
        .iter()
        .filter(|f| f.severity.contributes_to_score())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{analyse_fixture, fixture_events};
    use installscope_core::{Backend, WriteKind};

    fn context() -> ReportContext {
        ReportContext {
            package: Some("SYNTHETIC-fixture".to_string()),
            version: Some("1.0.0".to_string()),
            command: vec!["npm".to_string(), "install".to_string()],
            evidence_link: Some("https://example.invalid/artifact".to_string()),
            sarif_link: Some("https://example.invalid/sarif".to_string()),
        }
    }

    /// Renders a fixture through the full pipeline.
    fn render(name: &str) -> String {
        render_html(&analyse_fixture(name), &context(), &fixture_events(name))
    }

    /// Every fixture, so a claim can be asserted across all of them at once.
    const FIXTURES: &[&str] = &[
        "clean.jsonl",
        "high.jsonl",
        "critical.jsonl",
        "partial.jsonl",
        "aya-clean.jsonl",
    ];

    #[test]
    fn a_clean_install_renders_a_valid_html_document() {
        let rendered = render("clean.jsonl");
        assert!(rendered.starts_with("<!DOCTYPE html>"));
        assert!(rendered.contains("</html>"));
        assert!(rendered.contains("0 / 100"));
        assert!(rendered.contains("Nothing outside expected behavior"));
        assert!(
            !rendered.contains("PARTIAL"),
            "a complete recording must not show the badge"
        );
    }

    #[test]
    fn a_partial_recording_shows_the_badge_and_explains_itself() {
        let rendered = render("partial.jsonl");
        assert!(rendered.contains("PARTIAL"), "{rendered}");
        assert!(rendered.contains("incomplete"));
        assert!(
            rendered.contains("not evidence it did not happen"),
            "the reader must be told what the incompleteness means"
        );
    }

    #[test]
    fn a_critical_install_shows_its_score_and_findings() {
        let rendered = render("critical.jsonl");
        assert!(rendered.contains("100 / 100"));
        assert!(rendered.contains("raw"), "the capped excess stays visible");
        assert!(
            rendered.contains("CRITICAL"),
            "critical findings must be labelled"
        );
    }

    // =============================================================================================
    // The signal log reflects the recording
    //
    // These are the tests whose absence let a hand-written signal log ship. Every one of them asks the
    // same question in a different direction: does the artifact display anything the recording does not
    // contain? Rules.md §5 forbids fabricated syscall data, and a forensic report is the worst place in
    // the product for an illustrative row.
    // =============================================================================================

    #[test]
    fn renders_one_signal_row_per_observation() {
        for name in FIXTURES {
            let events = fixture_events(name);
            let analysis = analyse_fixture(name);
            let rendered = render_html(&analysis, &context(), &events);

            let observations = events.iter().filter(|e| !e.payload.is_framing()).count();
            let rows = rendered.matches("<tr tabindex=\"0\"").count();
            assert_eq!(
                rows, observations,
                "{name}: {rows} signal rows for {observations} observations — the log must be the \
                 recording, not an illustration"
            );
            assert_eq!(
                observations as u64, analysis.observations,
                "{name}: the row count and the engine's observation count must agree"
            );
        }
    }

    #[test]
    fn every_rendered_subject_appears_in_the_recording() {
        // The direct form of the fabrication check: pull each row's full subject out of the rendered
        // document and require the recording to contain it. A row for a path, host, or command the
        // stream never mentioned fails here.
        for name in FIXTURES {
            let events = fixture_events(name);
            let known: Vec<String> = events
                .iter()
                .filter(|event| !event.payload.is_framing())
                .map(|event| signal_subject(&event.payload))
                .collect();
            let rendered = render_html(&analyse_fixture(name), &context(), &events);

            for fragment in rendered.split("<td class=\"l col-args\" title=\"").skip(1) {
                let Some((title, _)) = fragment.split_once('"') else {
                    continue;
                };
                let unescaped = unescape(title);
                assert!(
                    known.contains(&unescaped),
                    "{name}: the log shows {unescaped:?}, which is not in the recording"
                );
            }
        }
    }

    #[test]
    fn an_empty_recording_renders_no_signal_rows() {
        // The failure mode that produced the literal `47`: a stream with nothing in it must render an
        // empty log that says so, not a plausible one.
        let events = vec![Event::framing(
            0,
            Backend::Strace,
            Payload::SessionEnd(installscope_core::SessionEnd::complete(Some(0), 0, 0, 0)),
        )];
        let catalog = installscope_core::Catalog::embedded().expect("catalog");
        let analysis = installscope_core::evaluate(&catalog, &events);
        let rendered = render_html(&analysis, &context(), &events);

        assert!(
            !rendered.contains("<tr tabindex=\"0\""),
            "an empty recording must produce no signal rows"
        );
        assert!(
            rendered.contains("contains no observations"),
            "the emptiness must be stated: {rendered}"
        );
        assert!(
            rendered.contains("0 SIGNALS"),
            "the count must be the real one: {rendered}"
        );
        assert!(
            !rendered.contains("47"),
            "no placeholder signal count may survive"
        );
    }

    #[test]
    fn no_report_contains_a_fabricated_observation() {
        // A regression guard naming the specific literals that used to ship. Each was a syscall,
        // hostname, or credential path presented as recorded evidence in reports for streams that
        // contained none of them.
        const FABRICATIONS: &[&str] = &[
            "stats.npm-telemetry-cdn",
            "104.21.38.117",
            "/home/runner/.bashrc",
            "/home/runner/.aws/credentials",
            "/proc/self/environ",
            "_authToken=npm_",
            "postinstall.js:",
            "npm-8f2a",
            "FR-7Q2K",
            "a3f1c9",
            "98.2%",
            "linux-6.8.0-x86_64",
            "ptrace detach during clone",
            "TLS ClientHello",
            "env-parse-lite",
            "0x7f9a1b000000",
            "0x55d8f92a4000",
            "T1059.007",
            "T1546.004",
        ];
        for name in FIXTURES {
            let events = fixture_events(name);
            let raw: String = events
                .iter()
                .filter_map(|event| event.to_jsonl().ok())
                .collect();
            let rendered = render_html(&analyse_fixture(name), &context(), &events);

            for needle in FABRICATIONS {
                if raw.contains(needle) {
                    // If a fixture genuinely contains it, rendering it is correct.
                    continue;
                }
                assert!(
                    !rendered.contains(needle),
                    "{name}: the report contains {needle:?}, which the recording does not"
                );
            }
        }
    }

    #[test]
    fn header_metadata_comes_from_session_start() {
        let events = fixture_events("clean.jsonl");
        let start = session_start(&events).expect("the fixture declares a session_start");
        let rendered = render_html(&analyse_fixture("clean.jsonl"), &context(), &events);

        assert!(
            rendered.contains(&escape(&start.wall_clock_utc)),
            "the capture instant must be the recording's own: {rendered}"
        );
        assert!(
            rendered.contains(&escape(&start.agent_version)),
            "the agent version must be the recording's own"
        );
        if let Some(kernel) = start.host.as_ref().and_then(|host| host.kernel.as_deref()) {
            assert!(
                rendered.contains(&escape(kernel)),
                "the kernel must be the recording's own, not a fixed string"
            );
        }
    }

    #[test]
    fn a_recording_without_host_info_omits_the_kernel_rather_than_inventing_one() {
        let events = vec![
            Event::framing(
                0,
                Backend::Strace,
                Payload::SessionStart(installscope_core::SessionStart {
                    wall_clock_utc: "2026-01-01T00:00:00Z".to_string(),
                    agent_version: "0.0.0-test".to_string(),
                    command: vec!["npm".to_string()],
                    zones: installscope_core::Zones::default(),
                    host: None,
                }),
            ),
            Event::framing(
                1,
                Backend::Strace,
                Payload::SessionEnd(installscope_core::SessionEnd::complete(Some(0), 1, 0, 0)),
            ),
        ];
        let catalog = installscope_core::Catalog::embedded().expect("catalog");
        let analysis = installscope_core::evaluate(&catalog, &events);
        let rendered = render_html(&analysis, &context(), &events);

        assert!(rendered.contains("RECORDER strace"));
        assert!(
            !rendered.contains("RECORDER strace/"),
            "with no host info the kernel must be absent, not guessed: {rendered}"
        );
    }

    #[test]
    fn the_footer_states_no_digest_it_cannot_compute() {
        // The renderer never sees a hash of the stream. Printing one was an integrity claim about
        // evidence with nothing behind it.
        for name in FIXTURES {
            let rendered = render(name);
            assert!(
                !rendered.contains("SHA-256"),
                "{name}: the report claims a digest it did not compute"
            );
            assert!(
                !rendered.contains("immutable"),
                "{name}: the report claims immutability it cannot establish"
            );
        }
    }

    #[test]
    fn a_row_with_no_finding_is_not_labelled_benign() {
        // "VERIFIED" in the old coverage column asserted the recorder had vouched for the row. The
        // honest statement is that no rule fired, which the inset says explicitly.
        let rendered = render("clean.jsonl");
        assert!(
            !rendered.contains("VERIFIED"),
            "an unflagged observation has not been verified as benign: {rendered}"
        );
        assert!(
            rendered.contains("no rule in the catalog fired on this observation"),
            "the absence of a finding must be stated as such"
        );
    }

    #[test]
    fn severity_cells_agree_with_the_findings() {
        // The log's severity column is derived from the same findings the score is, so the two surfaces
        // cannot disagree. A count mismatch means the log invented or dropped a severity.
        for name in FIXTURES {
            let analysis = analyse_fixture(name);
            let rendered = render(name);
            for severity in [Severity::Critical, Severity::High, Severity::Medium] {
                let label = severity.as_str().to_uppercase();
                let tag = format!(
                    "<span class=\"sev-tag {}\">{label}</span>",
                    match severity {
                        Severity::Critical => "crit",
                        Severity::High => "high",
                        Severity::Medium => "med",
                        Severity::Low => "low",
                    }
                );
                let has_finding = analysis.findings.iter().any(|f| f.severity == severity);
                if !has_finding {
                    assert!(
                        !rendered.contains(&tag),
                        "{name}: the log shows a {severity} row but no {severity} finding exists"
                    );
                }
            }
        }
    }

    #[test]
    fn unresolved_paths_are_marked_in_the_log() {
        // The aya fixture's writes arrive unresolved. A reader scanning a quiet log has to be able to
        // see that those rows were never placed inside or outside a zone.
        let analysis = analyse_fixture("aya-clean.jsonl");
        assert!(
            analysis.unresolved_paths > 0,
            "the fixture is supposed to contain unresolved paths"
        );
        let rendered = render("aya-clean.jsonl");
        assert!(
            rendered.contains("unresolved"),
            "unresolved paths must be visible per row: {rendered}"
        );
        assert!(
            rendered.contains(&format!("{} UNRESOLVED PATH", analysis.unresolved_paths)),
            "the count must appear in the log header: {rendered}"
        );
    }

    #[test]
    fn an_unknown_outcome_is_not_rendered_as_success() {
        // The aya backend's entry-only probes cannot tell whether a syscall succeeded. Showing those as
        // "ok" would be the renderer manufacturing the certainty the backend refused to claim.
        let unknown = Payload::NetConnect(installscope_core::NetConnect {
            family: installscope_core::AddrFamily::Inet,
            ip: Some("198.51.100.7".to_string()),
            port: Some(443),
            unix_path: None,
            host: None,
            loopback: false,
            private: false,
            outcome: Outcome::unknown(),
        });
        assert_eq!(signal_outcome(&unknown), "unknown");

        let failed = Payload::FsRead(installscope_core::FsRead {
            target: TracedPath::new("/x", PathOrigin::Absolute),
            bytes: None,
            outcome: Outcome::failed("EACCES"),
        });
        assert_eq!(signal_outcome(&failed), "EACCES");
    }

    #[test]
    fn attck_techniques_are_only_claimed_for_rules_that_exist() {
        // The previous mapping keyed on three rule ids that are not in the catalog and defaulted
        // everything else to T1059.007. Both halves are asserted here: every mapped id must be a real
        // rule, and an unmapped rule must produce no technique rather than a fallback.
        let catalog = installscope_core::Catalog::embedded().expect("catalog");
        let ids: Vec<&str> = catalog.rules.iter().map(|rule| rule.id.as_str()).collect();

        for id in &ids {
            // Not every rule needs a technique; the point is that a claim, when made, is about a real
            // rule and is stable.
            let _ = attck_technique(id);
        }
        assert_eq!(attck_technique("no_such_rule"), None);
        assert_eq!(attck_technique("write_outside_expected_dirs"), None);
        assert_eq!(attck_technique("spawned_unexpected_binary"), None);
        assert_eq!(
            attck_technique("download_piped_to_shell"),
            Some("T1059.004")
        );

        // And nothing mapped may be absent from the catalog.
        for id in [
            "credential_path_read",
            "credential_path_read_attempted",
            "npmrc_read",
            "dns_binary_distribution_host",
            "spawned_network_tool",
            "download_piped_to_shell",
            "network_connect_unusual_port",
            "chmod_exec_outside_project",
        ] {
            assert!(
                ids.contains(&id),
                "{id} has an ATT&CK mapping but is not a rule in the catalog"
            );
            assert!(attck_technique(id).is_some());
        }
    }

    #[test]
    fn the_finding_cards_name_the_rule_that_fired() {
        let analysis = analyse_fixture("critical.jsonl");
        let rendered = render("critical.jsonl");
        for finding in select_bullets(&analysis.findings) {
            assert!(
                rendered.contains(&escape(&finding.rule_id)),
                "the card must name {} so a reader can look it up",
                finding.rule_id
            );
        }
    }

    #[test]
    fn the_row_inset_is_not_built_from_markup() {
        // The inset is built with textContent and appendChild, so a path containing markup cannot become
        // an element. This asserts the script does not reintroduce a markup-assembly path.
        let rendered = render("critical.jsonl");
        let script_start = rendered.find("<script>").expect("a script block");
        let script = &rendered[script_start..];
        assert!(
            !script.contains(".innerHTML"),
            "the inset must not be assigned markup: attacker-influenced paths reach it"
        );
        assert!(
            !script.contains(".outerHTML"),
            "the inset must not be assigned markup: attacker-influenced paths reach it"
        );
        assert!(
            script.contains("textContent"),
            "the inset must set text rather than markup"
        );
    }

    // =============================================================================================
    // Coverage, escaping, and the existing contract
    // =============================================================================================

    #[test]
    fn an_aya_report_carries_its_coverage_caveat() {
        let rendered = render("aya-clean.jsonl");
        assert!(rendered.contains("credential reads"), "{rendered}");
        assert!(rendered.contains("not evidence"));
        assert!(
            rendered.contains("did not run"),
            "the skipped checks must be listed: {rendered}"
        );
    }

    #[test]
    fn a_strace_report_has_no_caveat() {
        let rendered = render("clean.jsonl");
        assert!(!rendered.contains("Not checked by"));
        assert!(!rendered.contains("did not run"));
    }

    #[test]
    fn every_report_carries_the_full_per_class_coverage_table() {
        for name in FIXTURES {
            let analysis = analyse_fixture(name);
            let rendered = render(name);
            assert!(
                rendered.contains("What this recording could observe"),
                "{name}: the coverage table is missing"
            );
            for (class, _) in &analysis.coverage.classes {
                assert!(
                    rendered.contains(class.as_str()),
                    "{name}: the coverage table omits {class}"
                );
            }
        }
    }

    #[test]
    fn the_coverage_table_distinguishes_unobserved_from_qualified() {
        let aya = render("aya-clean.jsonl");
        assert!(
            aya.contains("tag unobserved"),
            "aya has blind spots and must show them as such: {aya}"
        );
        assert!(
            aya.contains("tag qualified"),
            "aya's caveated classes must be marked distinctly: {aya}"
        );

        let strace = render("clean.jsonl");
        assert!(
            !strace.contains("tag unobserved"),
            "strace has no blind spot; marking one unobserved would be a false claim: {strace}"
        );
        assert!(
            strace.contains("tag qualified"),
            "every strace class carries a documented limitation and must be marked as qualified \
             rather than as unconditionally observed: {strace}"
        );
    }

    #[test]
    fn the_coverage_table_states_the_reason_for_every_qualification() {
        for name in ["clean.jsonl", "aya-clean.jsonl"] {
            let analysis = analyse_fixture(name);
            let rendered = render(name);
            for (class, observability) in &analysis.coverage.classes {
                if let Some(note) = observability.note() {
                    let fragment: String = note
                        .split_whitespace()
                        .take(4)
                        .collect::<Vec<_>>()
                        .join(" ");
                    let escaped = escape(&fragment);
                    let expected = capitalise(&escaped);
                    assert!(
                        rendered.contains(&escaped) || rendered.contains(&expected),
                        "{name}: {class} is qualified but its reason is absent: {note}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_coverage_table_names_the_backend_that_produced_the_recording() {
        let aya = render("aya-clean.jsonl");
        assert!(aya.contains("<code>aya</code>"), "{aya}");
        let strace = render("clean.jsonl");
        assert!(strace.contains("<code>strace</code>"), "{strace}");
    }

    #[test]
    fn coverage_notes_are_escaped_like_every_other_string() {
        assert_eq!(
            capitalise_sentence(&escape("<b>reads</b> are filtered")),
            "&lt;b&gt;reads&lt;/b&gt; are filtered."
        );
        assert_eq!(capitalise_sentence("already done."), "Already done.");
        assert_eq!(capitalise_sentence(""), "");
    }

    #[test]
    fn user_supplied_strings_are_html_escaped() {
        assert_eq!(
            escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn a_malicious_path_in_a_recording_cannot_inject_markup() {
        // The whole log is built from strings a package controls. A path chosen to close an attribute
        // and open a script tag must survive as text.
        let hostile = r#"/tmp/"><script>alert(1)</script>"#;
        let events = vec![
            Event::framing(
                0,
                Backend::Strace,
                Payload::SessionStart(installscope_core::SessionStart {
                    wall_clock_utc: "2026-01-01T00:00:00Z".to_string(),
                    agent_version: "0.0.0-test".to_string(),
                    command: vec!["npm".to_string()],
                    zones: installscope_core::Zones::default(),
                    host: None,
                }),
            ),
            Event::observed(
                installscope_core::EventMeta::observed(1, 7, "openat", Backend::Strace),
                Payload::FsWrite(installscope_core::FsWrite {
                    target: TracedPath::new(hostile, PathOrigin::Kernel),
                    kind: WriteKind::Open,
                    bytes: None,
                    flags: Some("O_WRONLY|\"><script>".to_string()),
                    mode: None,
                    source: None,
                    outcome: Outcome::success(),
                }),
            ),
            Event::framing(
                2,
                Backend::Strace,
                Payload::SessionEnd(installscope_core::SessionEnd::complete(Some(0), 2, 1, 0)),
            ),
        ];
        let catalog = installscope_core::Catalog::embedded().expect("catalog");
        let analysis = installscope_core::evaluate(&catalog, &events);
        let rendered = render_html(&analysis, &context(), &events);

        assert!(
            !rendered.contains("<script>alert(1)</script>"),
            "an unescaped path escaped into markup"
        );
        assert!(
            rendered.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "the path must still be shown, escaped: {rendered}"
        );
    }

    #[test]
    fn no_external_assets() {
        for name in FIXTURES {
            let rendered = render(name);
            assert!(!rendered.contains("@import"), "{name}: contains an @import");
            assert!(
                !rendered.contains("fonts.googleapis"),
                "{name}: references external fonts"
            );
            assert!(
                !rendered.contains("src=\"http"),
                "{name}: references an external resource"
            );
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        for name in FIXTURES {
            let analysis = analyse_fixture(name);
            let events = fixture_events(name);
            assert_eq!(
                render_html(&analysis, &context(), &events),
                render_html(&analysis, &context(), &events),
                "{name} rendered differently on a second pass"
            );
        }
    }

    #[test]
    fn the_inline_css_uses_the_beacon_accent() {
        assert!(
            INLINE_CSS.contains("#FF6A3D"),
            "the Beacon brand accent must be present in the CSS"
        );
    }

    #[test]
    fn the_report_says_it_is_advisory() {
        let rendered = render("high.jsonl");
        assert!(rendered.contains("Advisory"));
        assert!(rendered.contains("does not block the build"));
    }

    #[test]
    fn timestamps_and_durations_render_from_the_schema() {
        assert_eq!(format_timestamp(0), "00:00:00.000");
        assert_eq!(format_timestamp(1_234_000_000), "00:00:01.234");
        assert_eq!(format_timestamp(3_661_500_000_000), "01:01:01.500");
        assert_eq!(format_duration(0), "0.000s");
        assert_eq!(format_duration(4_118_000_000), "4.118s");
    }

    #[test]
    fn a_long_subject_is_elided_in_the_cell_and_whole_in_the_title() {
        let long = "/".to_string() + &"a".repeat(200);
        let elided = elide(&long, 96);
        assert_eq!(elided.chars().count(), 96);
        assert!(elided.ends_with('…'));
        assert_eq!(elide("short", 96), "short");
    }

    /// Reverses [`escape`], for asserting a rendered value against the recording.
    fn unescape(text: &str) -> String {
        text.replace("&quot;", "\"")
            .replace("&gt;", ">")
            .replace("&lt;", "<")
            .replace("&amp;", "&")
    }
}
