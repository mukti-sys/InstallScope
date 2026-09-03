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
//! 4. Full findings table
//! 5. Per-class coverage table
//! 6. Evidence detail (expandable per finding)
//!
//! # What this renderer refuses to do
//!
//! Same contract as the other two: it does not soften a PARTIAL recording, and it does not present
//! a limited backend's clean result as an unqualified pass. Tests assert both.
//!
//! # Why the per-class coverage table lives here and not in the comment
//!
//! `Memory.md`:194 records it as a Phase 3 obligation: the parity harness keeps the strace/aya
//! asymmetry visible as per-class counts, and the report has to do the same. The one-line caveat in
//! [`installscope_core::Coverage::caveat_line`] names only the classes a backend cannot see *at all* —
//! it says nothing about the ones it sees with a caveat, and "byte counts are the requested count, not
//! the number actually written" is exactly the sort of qualification that changes how a reader weighs a
//! finding.
//!
//! So the full table belongs in the artifact, which is the surface with room for it. The PR comment
//! keeps the one-liner, because PRD.md:57 caps that surface at a score, three bullets, and a link.

use std::fmt::Write as _;

use installscope_core::{select_bullets, Analysis, Observability, Severity};

use crate::{format_bullet, ReportContext, Verdict};

/// Renders the analysis as a self-contained HTML document.
///
/// The output is a complete `<!DOCTYPE html>` page with inline CSS. No external stylesheets, no
/// JavaScript CDN, no images — Rules.md §1 forbids external assets.
#[must_use]
pub fn render_html(analysis: &Analysis, context: &ReportContext) -> String {
    let verdict = Verdict::of(analysis);
    let mut out = String::with_capacity(16384);

    render_head(&mut out, context);
    out.push_str("<div class=\"shell\">\n");
    render_header(&mut out, analysis, context, verdict);
    render_partial_warning(&mut out, analysis, verdict);
    render_top_row(&mut out, analysis, context, verdict);
    render_caveats(&mut out, analysis);
    render_findings_table(&mut out, analysis);
    render_coverage_table(&mut out, analysis);
    render_skipped_rules(&mut out, analysis);
    render_footer(&mut out, analysis);
    out.push_str("</div>\n\n</body>\n</html>\n");
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
fn render_header(out: &mut String, analysis: &Analysis, context: &ReportContext, verdict: Verdict) {
    let subject = escape(&context.subject_label());
    let backend = escape(&format!("{}", analysis.coverage.backend));
    let verdict_str = if verdict.shows_partial_badge() {
        "PARTIAL"
    } else if analysis.score.value == 0 {
        "NOMINAL"
    } else if analysis.score.value >= 60 {
        "CRITICAL"
    } else {
        "OBSERVED"
    };

    let _ = write!(
        out,
        r#"<header>
  <div class="header-left">
    <span class="beacon-sq" aria-hidden="true"></span>
    <span class="rec-tag">REC</span>
    <span class="pkg-name">InstallScope &middot; {subject}</span>
  </div>
  <div class="header-right">
    ENGINE {backend}<span class="sep">·</span>VERDICT {verdict_str}<span class="sep">·</span>ADVISORY
  </div>
</header>
"#,
    );
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
    let med_count = analysis
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let scorable = scorable_count(analysis);
    let total_findings = analysis.findings.len();

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
        r#"  <div class="score-card">
    <div class="score-baseline">
      <span class="score-num">{score_val} / 100</span>{raw_part}{partial_badge}
    </div>
    <div class="score-label">SURPRISE INDEX</div>
    <div class="score-band {band_class}">{band_name}</div>
    <p class="score-def">Share of recorded syscall activity not attributable to declared install work. 0 = fully accounted for.</p>
    <div class="band-track" aria-hidden="true">
      <div class="track-seg seg-ok"></div>
      <div class="track-seg seg-med"></div>
      <div class="track-seg seg-high"></div>
      <div class="track-seg seg-crit"></div>
      <div class="track-tick" style="left: {tick_pct}%;"></div>
    </div>
    <div class="band-legend">0–9 NOMINAL · 10–24 NOTABLE · 25–59 ELEVATED · 60+ CRITICAL</div>
    <div class="micro-grid">
      <div class="grid-cell"><span class="grid-label">FINDINGS</span><span class="grid-val">{total_findings}</span></div>
      <div class="grid-cell"><span class="grid-label">SCORABLE</span><span class="grid-val">{scorable}</span></div>
      <div class="grid-cell"><span class="grid-label">CRITICAL</span><span class="grid-val">{crit_count}</span></div>
      <div class="grid-cell"><span class="grid-label">HIGH</span><span class="grid-val">{high_count}</span></div>
      <div class="grid-cell"><span class="grid-label">MEDIUM</span><span class="grid-val">{med_count}</span></div>
      <div class="grid-cell"><span class="grid-label">UNRESOLVED</span><span class="grid-val">{unresolved}</span></div>
    </div>
  </div>
"#,
        unresolved = analysis.unresolved_paths,
    );
}

/// Renders the right flex priority findings module.
fn render_priority_findings(out: &mut String, analysis: &Analysis, verdict: Verdict) {
    let scorable_bullets: Vec<_> = select_bullets(&analysis.findings)
        .into_iter()
        .filter(|f| f.severity.contributes_to_score())
        .collect();

    out.push_str("  <div class=\"findings-panel\">\n");
    out.push_str("    <h2 class=\"panel-title\">PRIORITY FINDINGS</h2>\n");

    if scorable_bullets.is_empty() {
        let _ = writeln!(
            out,
            "    <p class=\"headline\">{}</p>",
            escape(&capitalise(verdict.headline()))
        );
    } else {
        out.push_str("    <div class=\"findings-list\">\n");
        for finding in &scorable_bullets {
            render_priority_item(out, finding);
        }
        let hidden = scorable_count(analysis).saturating_sub(scorable_bullets.len());
        if hidden > 0 {
            let _ = writeln!(
                out,
                "      <p class=\"overflow\">…and {hidden} more finding{} below in full table</p>",
                if hidden == 1 { "" } else { "s" }
            );
        }
        out.push_str("    </div>\n");
    }
    out.push_str("  </div>\n");
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
    let note_str = finding
        .note
        .as_deref()
        .map_or_else(String::new, |n| format!(" — {}", escape(n)));
    let count_badge = if finding.occurrences > 1 {
        format!(
            " <span class=\"finding-count\">&times;{}</span>",
            finding.occurrences
        )
    } else {
        String::new()
    };

    let _ = write!(
        out,
        r#"      <article class="finding-item {sev_str}">
        <div class="finding-head">
          <span class="sev-tag {sev_str}">{sev_label}</span>
          <span class="finding-rule"><code>{rule}</code>{count_badge}</span>
        </div>
        <p class="finding-prose">{bullet}{note}</p>
      </article>
"#,
        rule = escape(&finding.rule_id),
        bullet = escape(&format_bullet(finding)),
        note = note_str,
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

/// Emits the full findings table.
fn render_findings_table(out: &mut String, analysis: &Analysis) {
    if analysis.findings.is_empty() {
        return;
    }
    out.push_str("<section class=\"findings\">\n<div class=\"section-head\"><h2 class=\"panel-title\">FINDINGS DETAIL</h2><span class=\"section-meta\">");
    let _ = write!(
        out,
        "{} FINDING{}",
        analysis.findings.len(),
        if analysis.findings.len() == 1 {
            ""
        } else {
            "S"
        }
    );
    out.push_str("</span></div>\n");
    out.push_str(
        "<div class=\"table-wrap\"><table>\n<thead><tr>\
        <th class=\"col-sev\">Severity</th><th class=\"col-rule\">Rule</th><th class=\"col-subj\">Subject</th><th class=\"col-desc\">Description</th><th class=\"col-cnt r\">Count</th>\
        </tr></thead>\n<tbody>\n",
    );
    for finding in &analysis.findings {
        let note_html = finding
            .note
            .as_deref()
            .map(|n| format!("<br><small class=\"note-text\">{}</small>", escape(n)))
            .unwrap_or_default();
        let sev_str = match finding.severity {
            Severity::Critical => "crit",
            Severity::High => "high",
            Severity::Medium => "med",
            Severity::Low => "low",
        };
        let row_class = match finding.severity {
            Severity::Critical => "row-crit",
            Severity::High => "row-high",
            _ => "",
        };
        let _ = writeln!(
            out,
            "<tr class=\"{row_class}\">\
            <td><span class=\"sev-tag {sev_str}\">{sev_label}</span></td>\
            <td><code>{rule}</code></td>\
            <td class=\"subj-cell\">{subject}</td>\
            <td>{title}{note}</td>\
            <td class=\"r\">{count}</td>\
            </tr>",
            sev_label = escape(&format!("{:?}", finding.severity)),
            rule = escape(&finding.rule_id),
            subject = escape(&finding.subject),
            title = escape(&finding.title),
            note = note_html,
            count = finding.occurrences,
        );
    }
    out.push_str("</tbody>\n</table></div>\n</section>\n\n");
}

/// Emits the per-class coverage table.
fn render_coverage_table(out: &mut String, analysis: &Analysis) {
    out.push_str("<section class=\"coverage\">\n<div class=\"section-head\"><h2 class=\"panel-title\">What this recording could observe</h2></div>\n");
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

/// Emits the footer with backend and advisory notice.
fn render_footer(out: &mut String, analysis: &Analysis) {
    let _ = writeln!(
        out,
        "<footer>\n<div class=\"footer-left\">Recorded with the {} backend. Advisory: this report records what the \
         install did, and does not block the build.</div>\n<div class=\"footer-right\">InstallScope &middot; immutable forensic trace</div>\n</footer>",
        escape(&format!("{}", analysis.coverage.backend)),
    );
}

/// The full inline `<style>` block.
///
/// Self-contained: no `@import`, no external fonts, no CDN. Hand-authored CSS tokens adhering to
/// Tactical Minimalism flight-recorder aesthetics.
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

.shell {
    max-width: 1440px;
    margin: 0 auto;
    border: 1px solid var(--rule);
    background: var(--surface);
    border-radius: 2px;
}

/* 56px Flight Recorder Header */
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

/* Row 1: Score Card + Priority Findings */
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

/* Section Headers & Tables */
.findings, .coverage {
    padding: 24px 24px 0 24px;
}

.section-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}

.section-meta {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10px;
    letter-spacing: 0.14em;
    color: var(--fg-dim);
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

td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--rule-soft);
    vertical-align: top;
    color: var(--fg);
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--row-hover); }

.row-crit { border-left: 2px solid var(--crit); }
.row-high { border-left: 2px solid var(--high); }

.col-sev { width: 90px; }
.col-rule { width: 180px; }
.col-subj { width: 180px; }
.col-cnt { width: 60px; }

.subj-cell {
    color: var(--fg);
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.note-text {
    color: var(--fg-dim);
    font-size: 11px;
}

code {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px;
    background: var(--header);
    border: 1px solid var(--rule);
    padding: 1px 4px;
    border-radius: 2px;
    color: var(--fg);
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

.coverage-intro {
    color: var(--fg-dim);
    font-size: 12px;
    margin: 0 0 10px;
}

.coverage-unobserved td { border-left: 2px solid var(--crit); }

/* Collapsible Skipped Checks */
details.skipped {
    margin: 20px 24px 0;
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

/* Footer */
footer {
    height: 36px;
    background: var(--header);
    border-top: 1px solid var(--rule);
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 24px;
    margin-top: 24px;
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10px;
    color: var(--fg-dim);
}

.footer-left { color: var(--fg-dim); }
.footer-right { color: var(--fg-faint); }

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
    .sev-tag, .grid-val, .grid-label, .finding-prose, .score-num, .score-max, .score-band, .pkg-name, code {
        color: #000000 !important;
        background: transparent !important;
        border-color: #000000 !important;
    }
}
</style>"#;

/// How many findings count toward the score.
fn scorable_count(analysis: &Analysis) -> usize {
    analysis
        .findings
        .iter()
        .filter(|finding| finding.severity.contributes_to_score())
        .count()
}

/// Uppercases the first character.
fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Capitalises a note and gives it a full stop.
///
/// The coverage notes are written as sentence fragments so they read correctly inside
/// [`installscope_core::Coverage::caveat_line`]. In a table cell they stand alone, so they get the
/// punctuation a standalone sentence needs. Applied *after* escaping, so it cannot alter an entity.
fn capitalise_sentence(text: &str) -> String {
    let mut sentence = capitalise(text);
    if !sentence.is_empty() && !sentence.ends_with('.') {
        sentence.push('.');
    }
    sentence
}

/// HTML-escapes a string to prevent XSS.
///
/// Every user-supplied value (paths, rule text, command lines) passes through this before being
/// placed in the document. A finding subject like `<script>alert(1)</script>` must render as text,
/// not as executable markup.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::analyse_fixture;

    fn context() -> ReportContext {
        ReportContext {
            package: Some("SYNTHETIC-fixture".to_string()),
            version: Some("1.0.0".to_string()),
            command: vec!["npm".to_string(), "install".to_string()],
            evidence_link: Some("https://example.invalid/artifact".to_string()),
            sarif_link: Some("https://example.invalid/sarif".to_string()),
        }
    }

    #[test]
    fn a_clean_install_renders_a_valid_html_document() {
        let rendered = render_html(&analyse_fixture("clean.jsonl"), &context());
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
        let rendered = render_html(&analyse_fixture("partial.jsonl"), &context());
        assert!(rendered.contains("PARTIAL"), "{rendered}");
        assert!(rendered.contains("incomplete"));
        assert!(
            rendered.contains("not evidence it did not happen"),
            "the reader must be told what the incompleteness means"
        );
    }

    #[test]
    fn a_critical_install_shows_its_score_and_findings() {
        let rendered = render_html(&analyse_fixture("critical.jsonl"), &context());
        assert!(rendered.contains("100 / 100"));
        assert!(rendered.contains("raw"), "the capped excess stays visible");
        assert!(
            rendered.contains("Critical"),
            "critical findings must be labelled"
        );
    }

    #[test]
    fn an_aya_report_carries_its_coverage_caveat() {
        let rendered = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(rendered.contains("credential reads"), "{rendered}");
        assert!(rendered.contains("not evidence"));
        assert!(
            rendered.contains("did not run"),
            "the skipped checks must be listed: {rendered}"
        );
    }

    #[test]
    fn a_strace_report_has_no_caveat() {
        let rendered = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(!rendered.contains("Not checked by"));
        assert!(!rendered.contains("did not run"));
    }

    #[test]
    fn every_report_carries_the_full_per_class_coverage_table() {
        // Memory.md:194 makes this a Phase 3 obligation: the parity harness keeps the strace/aya
        // asymmetry visible in per-class counts, and the report must too. Rendered unconditionally,
        // because a table that appears only on the weaker backend would teach a reader to read its
        // absence as completeness.
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "partial.jsonl",
            "aya-clean.jsonl",
        ] {
            let analysis = analyse_fixture(name);
            let rendered = render_html(&analysis, &context());
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
        // The distinction the table exists for. "Byte counts are approximate" and "credential reads are
        // not recorded at all" must not render identically — the first qualifies a finding, the second
        // means silence proves nothing.
        let aya = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(
            aya.contains("tag unobserved"),
            "aya has blind spots and must show them as such: {aya}"
        );
        assert!(
            aya.contains("tag qualified"),
            "aya's caveated classes must be marked distinctly: {aya}"
        );

        // strace has no blind spots, so nothing may be marked unobserved for it. This is the assertion
        // that stops the table degrading into decoration that always looks the same.
        let strace = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(
            !strace.contains("tag unobserved"),
            "strace sees every class; marking one unobserved would be a false claim: {strace}"
        );
        assert!(
            strace.contains("tag observed"),
            "strace's fully-observed classes must be visible as such"
        );
    }

    #[test]
    fn the_coverage_table_states_the_reason_for_every_qualification() {
        // A "with caveat" cell and no reason is a shrug. Each note comes from
        // installscope_core::observability, so the report cannot phrase its own caveat and drift from
        // what the engine actually did.
        for name in ["clean.jsonl", "aya-clean.jsonl"] {
            let analysis = analyse_fixture(name);
            let rendered = render_html(&analysis, &context());
            for (class, observability) in &analysis.coverage.classes {
                if let Some(note) = observability.note() {
                    // The note is escaped and sentence-cased before rendering, so a distinctive
                    // fragment is compared rather than the whole string.
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
        // The table is a claim about a recorder, not about an install. Which recorder must be on the
        // same screen as the claim.
        let aya = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(aya.contains("<code>aya</code>"), "{aya}");
        let strace = render_html(&analyse_fixture("clean.jsonl"), &context());
        assert!(strace.contains("<code>strace</code>"), "{strace}");
    }

    #[test]
    fn coverage_notes_are_escaped_like_every_other_string() {
        // The notes are static today, so this guards the mechanism rather than current data: a future
        // note containing a `<` must render as text.
        assert_eq!(
            capitalise_sentence(&escape("<b>reads</b> are filtered")),
            "&lt;b&gt;reads&lt;/b&gt; are filtered."
        );
        // An existing full stop is not doubled.
        assert_eq!(capitalise_sentence("already done."), "Already done.");
        assert_eq!(capitalise_sentence(""), "");
    }

    #[test]
    fn user_supplied_strings_are_html_escaped() {
        // A path like <script> must not become executable markup.
        assert_eq!(
            escape("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape("a & b"), "a &amp; b");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn no_external_assets() {
        // Rules.md §1: no CDN, no @import, no external fonts. The report must work offline.
        for name in [
            "clean.jsonl",
            "critical.jsonl",
            "partial.jsonl",
            "aya-clean.jsonl",
        ] {
            let rendered = render_html(&analyse_fixture(name), &context());
            assert!(!rendered.contains("@import"), "{name}: contains an @import");
            assert!(
                !rendered.contains("fonts.googleapis"),
                "{name}: references external fonts"
            );
        }
    }

    #[test]
    fn rendering_is_deterministic() {
        for name in [
            "clean.jsonl",
            "high.jsonl",
            "critical.jsonl",
            "aya-clean.jsonl",
        ] {
            let analysis = analyse_fixture(name);
            assert_eq!(
                render_html(&analysis, &context()),
                render_html(&analysis, &context()),
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
        let rendered = render_html(&analyse_fixture("high.jsonl"), &context());
        assert!(rendered.contains("Advisory"));
        assert!(rendered.contains("does not block the build"));
    }
}
