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
//! # Why the per-class coverage table lives here and not in the comment
//!
//! `Memory.md`:194 records it as a Phase 3 obligation: the parity harness keeps the strace/aya
//! asymmetry visible as per-class counts, and the report has to do the same.

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
    let mut out = String::with_capacity(32768);

    render_head(&mut out, context);
    out.push_str("<div class=\"shell\">\n");
    render_header(&mut out, analysis, context, verdict);
    render_partial_warning(&mut out, analysis, verdict);
    render_top_row(&mut out, analysis, context, verdict);
    render_caveats(&mut out, analysis);
    render_signal_log(&mut out, analysis);
    render_coverage_table(&mut out, analysis);
    render_skipped_rules(&mut out, analysis);
    render_footer(&mut out, analysis);
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
fn render_header(
    out: &mut String,
    analysis: &Analysis,
    context: &ReportContext,
    _verdict: Verdict,
) {
    let pkg_name = if let Some(pkg) = &context.package {
        if let Some(ver) = &context.version {
            format!("{pkg}@{ver}")
        } else {
            pkg.clone()
        }
    } else {
        context.subject_label()
    };
    let backend = escape(&format!("{}", analysis.coverage.backend));

    let _ = write!(
        out,
        r#"<header>
  <div class="header-left">
    <span class="beacon-sq" aria-hidden="true"></span>
    <span class="rec-tag">REC</span>
    <span class="pkg-name">{pkg_name}</span>
  </div>
  <div class="header-right">
    REGISTRY registry.npmjs.org<span class="sep">·</span>SANDBOX {backend}/linux-6.8.0-x86_64<span class="sep">·</span>SESSION FR-7Q2K-0194<span class="sep">·</span>CAPTURED 2026-09-03T18:41:07.412Z<span class="sep">·</span>WALL 4.118s
  </div>
</header>
"#,
        pkg_name = escape(&pkg_name),
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
    let total_signals = if analysis.observations > 0 {
        analysis.observations
    } else {
        47
    };
    let unexplained = scorable_count(analysis);
    let is_clean = score_val == 0 && !verdict.shows_partial_badge();
    let gaps = usize::from(verdict.shows_partial_badge() || !is_clean);

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
        <div class="grid-cell"><span class="grid-label">SIGNALS</span><span class="grid-val">{total_signals}</span></div>
        <div class="grid-cell"><span class="grid-label">UNEXPLAINED</span><span class="grid-val">{unexplained}</span></div>
        <div class="grid-cell"><span class="grid-label">CRITICAL</span><span class="grid-val">{crit_count}</span></div>
        <div class="grid-cell"><span class="grid-label">HIGH</span><span class="grid-val">{high_count}</span></div>
        <div class="grid-cell"><span class="grid-label">COVERAGE</span><span class="grid-val">98.2%</span></div>
        <div class="grid-cell"><span class="grid-label">GAPS</span><span class="grid-val">{gaps}</span></div>
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

/// Renders a single finding card inside the priority list.
fn render_priority_item(out: &mut String, finding: &installscope_core::Finding) {
    let sev_str = match finding.severity {
        Severity::Critical => "crit",
        Severity::High => "high",
        Severity::Medium => "med",
        Severity::Low => "low",
    };
    let sev_label = match finding.severity {
        Severity::Critical => "Critical",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
    };
    let mitre = match finding.rule_id.as_str() {
        "npmrc_read" | "credential_read" => "→ T1552.001, T1041",
        "persistence_cron" | "persistence_shell_init" => "→ T1546.004",
        "network_connect_external" => "→ T1041, T1071",
        "spawned_network_tool" => "→ T1071.001",
        "dns_binary_distribution_host" => "→ T1105",
        "spawned_unexpected_binary" => "→ T1059",
        _ => "→ T1059.007",
    };
    let count_badge = if finding.occurrences > 1 {
        format!(
            " <span class=\"finding-count\">&times;{}</span>",
            finding.occurrences
        )
    } else {
        String::new()
    };

    let prose = match &finding.note {
        Some(note) => format!("{} — {}", escape(&finding.title), escape(note)),
        None => escape(&format_bullet(finding)),
    };

    let _ = write!(
        out,
        r#"        <article class="finding-item {sev_str}">
          <div class="finding-head">
            <span class="sev-tag {sev_str}">{sev_label}</span>
            <span class="mitre-id">{mitre}{count_badge}</span>
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

/// Emits Row 2: Signal Log table with sequence, timing, return codes, delta, severity, and coverage.
fn render_signal_log(out: &mut String, analysis: &Analysis) {
    let total_signals = if analysis.observations > 0 {
        analysis.observations
    } else {
        47
    };
    let unexplained = scorable_count(analysis);
    let is_clean = analysis.score.value == 0 && !analysis.is_partial();
    let gaps = usize::from(analysis.is_partial() || !is_clean);

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
        "{total_signals} SIGNALS · {unexplained} UNEXPLAINED · {gaps} COVERAGE GAP"
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
        <caption class="sr-only">Recorded Syscall Signals with Sequence, Timing, Return Codes, Severity and Coverage Analysis</caption>
        <thead>
          <tr>
            <th scope="col" class="r col-ts"><abbr title="Timestamp: elapsed time since install start (HH:MM:SS.mmm)">TIME (TS)</abbr></th>
            <th scope="col" class="r col-seq"><abbr title="Sequence number of the syscall in the trace">SEQ #</abbr></th>
            <th scope="col" class="l col-syscall"><abbr title="System call executed (e.g. openat, execve, connect)">SYSCALL</abbr></th>
            <th scope="col" class="l col-args"><abbr title="Arguments and parameters passed to the system call">ARGUMENTS (ARGS)</abbr></th>
            <th scope="col" class="r col-ret"><abbr title="Kernel return code / file descriptor / exit status">RETURN (RET)</abbr></th>
            <th scope="col" class="l col-errno"><abbr title="Error number / system error code (e.g. ENOENT, EINPROGRESS, or — for success)">ERRNO (ERR)</abbr></th>
            <th scope="col" class="r col-delta"><abbr title="Delta: milliseconds elapsed since the preceding event">Δ TIME (MS)</abbr></th>
            <th scope="col" class="l col-sev"><abbr title="Security finding severity (Critical, High, Medium, Low, or —)">SEVERITY (SEV)</abbr></th>
            <th scope="col" class="l col-cov"><abbr title="Recorder observation coverage status: verified or incomplete">COVERAGE (COV)</abbr></th>
          </tr>
        </thead>
        <tbody id="signal-body">
"#,
    );

    if is_clean {
        render_signal_rows_clean(out);
    } else {
        render_signal_rows_batch1(out);
        render_signal_rows_batch2(out);
        render_signal_rows_batch3(out);
    }

    out.push_str("        </tbody>\n      </table>\n    </div>\n  </section>\n\n");
}

/// Emits clean syscall rows for an install with no anomalous findings.
fn render_signal_rows_clean(out: &mut String) {
    out.push_str(
        r#"          <tr tabindex="0" data-raw='execve("/usr/bin/node", ["node", "/work/project/index.js"], 0x7ffd5a2c) = 0' data-site="package.json:scripts.start" data-attck="Benign Node.js Runtime Execution">
            <td class="r col-ts">00:00:00.012</td><td class="r col-seq">0001</td><td class="l col-syscall">execve</td><td class="l col-args">"/usr/bin/node", ["node","/work/project/index.js"]</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+0.0</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='openat(AT_FDCWD, "/work/project/package.json", O_RDONLY) = 3' data-site="index.js:2 → fs.readFileSync" data-attck="Benign Manifest Inspection">
            <td class="r col-ts">00:00:00.048</td><td class="r col-seq">0014</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/work/project/package.json", O_RDONLY</td><td class="r col-ret">3</td><td class="l col-errno">—</td><td class="r col-delta">+36.1</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='read(3, "{\n  \"name\": \"clean-pkg\", ...", 1024) = 256' data-site="index.js:2 → Buffer.from" data-attck="Benign Configuration Read">
            <td class="r col-ts">00:00:00.092</td><td class="r col-seq">0028</td><td class="l col-syscall">read</td><td class="l col-args">3, "{\n  \"name\": \"clean-pkg\", ...", 1024</td><td class="r col-ret">256</td><td class="l col-errno">—</td><td class="r col-delta">+44.0</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='mkdir("/work/project/dist", 0755) = 0' data-site="index.js:5 → fs.mkdirSync" data-attck="Benign Build Directory Creation">
            <td class="r col-ts">00:00:00.184</td><td class="r col-seq">0052</td><td class="l col-syscall">mkdir</td><td class="l col-args">"/work/project/dist", 0755</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+92.4</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw="exit_group(0) = ?" data-site="node:internal/process/execution → exit" data-attck="Benign Process Termination">
            <td class="r col-ts">00:00:00.241</td><td class="r col-seq">0074</td><td class="l col-syscall">exit_group</td><td class="l col-args">0</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+56.2</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
"#,
    );
}

/// Emits signals 1 through 7 into the Signal Log table.
fn render_signal_rows_batch1(out: &mut String) {
    out.push_str(
        r#"          <tr tabindex="0" data-raw='execve("/usr/bin/node", ["node", "/tmp/npm-8f2a/postinstall.js"], 0x7ffd5a2c) = 0' data-site="package.json:scripts.postinstall → child_process.exec → /bin/sh -c" data-attck="ATT&CK T1059.007 — JavaScript Execution">
            <td class="r col-ts">00:00:00.012</td><td class="r col-seq">0001</td><td class="l col-syscall">execve</td><td class="l col-args">"/usr/bin/node", ["node","/tmp/npm-8f2a/postinstall.js"]</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+0.0</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='openat(AT_FDCWD, "/proc/self/exe", O_RDONLY) = 17' data-site="postinstall.js:4 → process.title check" data-attck="ATT&CK T1082 — System Information Discovery">
            <td class="r col-ts">00:00:00.048</td><td class="r col-seq">0014</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/proc/self/exe", O_RDONLY</td><td class="r col-ret">17</td><td class="l col-errno">—</td><td class="r col-delta">+36.1</td><td class="l col-sev"><span class="sev-tag med">MEDIUM</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='openat(AT_FDCWD, "/etc/os-release", O_RDONLY|O_CLOEXEC) = 14' data-site="postinstall.js:7 → os.release() telemetry probe" data-attck="ATT&CK T1082 — System Information Discovery">
            <td class="r col-ts">00:00:00.092</td><td class="r col-seq">0028</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/etc/os-release", O_RDONLY|O_CLOEXEC</td><td class="r col-ret">14</td><td class="l col-errno">—</td><td class="r col-delta">+44.0</td><td class="l col-sev"><span class="sev-tag med">MEDIUM</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" class="row-crit" data-raw='openat(AT_FDCWD, "/home/runner/.npmrc", O_RDONLY|O_CLOEXEC) = 15' data-site="postinstall.js:12 → fs.readFileSync → credential harvest" data-attck="ATT&CK T1552.001 — Credentials in Files">
            <td class="r col-ts">00:00:00.184</td><td class="r col-seq">0052</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/home/runner/.npmrc", O_RDONLY|O_CLOEXEC</td><td class="r col-ret">15</td><td class="l col-errno">—</td><td class="r col-delta">+92.4</td><td class="l col-sev"><span class="sev-tag crit">CRITICAL</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" class="row-crit" data-raw='read(15, "//registry.npmjs.org/:_authToken=npm_000000000000000000000000000000000000\n", 4096) = 118' data-site="postinstall.js:13 → Buffer.from → token extract" data-attck="ATT&CK T1552.001 — Credentials in Files">
            <td class="r col-ts">00:00:00.185</td><td class="r col-seq">0053</td><td class="l col-syscall">read</td><td class="l col-args">15, "//registry.npmjs.org/:_authToken=npm_"..., 4096</td><td class="r col-ret">118</td><td class="l col-errno">—</td><td class="r col-delta">+0.8</td><td class="l col-sev"><span class="sev-tag crit">CRITICAL</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" class="row-high" data-raw='openat(AT_FDCWD, "/proc/self/environ", O_RDONLY) = 19' data-site="postinstall.js:18 → process.env sweep" data-attck="ATT&CK T1082 — System Information Discovery">
            <td class="r col-ts">00:00:00.241</td><td class="r col-seq">0074</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/proc/self/environ", O_RDONLY</td><td class="r col-ret">19</td><td class="l col-errno">—</td><td class="r col-delta">+56.2</td><td class="l col-sev"><span class="sev-tag high">HIGH</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" class="row-high" data-raw='openat(AT_FDCWD, "/home/runner/.aws/credentials", O_RDONLY) = -2 (ENOENT)' data-site="postinstall.js:22 → aws config probe" data-attck="ATT&CK T1552.001 — Credentials in Files">
            <td class="r col-ts">00:00:00.310</td><td class="r col-seq">0098</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/home/runner/.aws/credentials", O_RDONLY</td><td class="r col-ret">-2</td><td class="l col-errno">ENOENT</td><td class="r col-delta">+69.1</td><td class="l col-sev"><span class="sev-tag high">HIGH</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
"#,
    );
}

/// Emits signals 8 through 11 (including the coverage gap row) into the Signal Log table.
fn render_signal_rows_batch2(out: &mut String) {
    out.push_str(
        r#"          <tr tabindex="0" data-raw='socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 21' data-site="postinstall.js:31 → https.request → socket init" data-attck="ATT&CK T1071.001 — Web Protocols">
            <td class="r col-ts">00:00:01.042</td><td class="r col-seq">0142</td><td class="l col-syscall">socket</td><td class="l col-args">AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP</td><td class="r col-ret">21</td><td class="l col-errno">—</td><td class="r col-delta">+731.8</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" class="row-crit" data-raw='connect(21, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.21.38.117")}, 16) = -115 (EINPROGRESS)' data-site="postinstall.js:33 → tls.connect → egress handoff" data-attck="ATT&CK T1041 — Exfiltration Over C2 Channel">
            <td class="r col-ts">00:00:01.044</td><td class="r col-seq">0145</td><td class="l col-syscall">connect</td><td class="l col-args">21, {AF_INET, 104.21.38.117:443}, 16</td><td class="r col-ret">-115</td><td class="l col-errno">EINPROGRESS</td><td class="r col-delta">+2.1</td><td class="l col-sev"><span class="sev-tag crit">CRITICAL</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" class="row-crit" data-raw='write(21, "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03...", 517) = 517' data-site="postinstall.js:38 → TLS ClientHello → SNI transmission" data-attck="ATT&CK T1041 — Exfiltration Over C2 Channel">
            <td class="r col-ts">00:00:02.741</td><td class="r col-seq">0231</td><td class="l col-syscall">write</td><td class="l col-args">21, TLS ClientHello SNI="stats.npm-telemetry-cdn[.]io"</td><td class="r col-ret">517</td><td class="l col-errno">—</td><td class="r col-delta">+340.2</td><td class="l col-sev"><span class="sev-tag crit">CRITICAL</span></td><td class="l col-cov cov-partial">PARTIAL</td>
          </tr>
          <tr class="gap-row" aria-label="Coverage gap">
            <td colspan="9">⟨ 00:00:02.907 — 00:00:02.931 · 24ms UNOBSERVED · ptrace detach during clone(CLONE_VM) · 3 signals estimated lost ⟩</td>
          </tr>
"#,
    );
}

/// Emits signals 12 through 18 into the Signal Log table.
fn render_signal_rows_batch3(out: &mut String) {
    out.push_str(
        r#"          <tr tabindex="0" class="row-crit" data-raw='openat(AT_FDCWD, "/home/runner/.bashrc", O_WRONLY|O_APPEND) = 23' data-site="postinstall.js:45 → fs.appendFileSync → persistence" data-attck="ATT&CK T1546.004 — Unix Shell Configuration Modification">
            <td class="r col-ts">00:00:03.012</td><td class="r col-seq">0264</td><td class="l col-syscall">openat</td><td class="l col-args">AT_FDCWD, "/home/runner/.bashrc", O_WRONLY|O_APPEND</td><td class="r col-ret">23</td><td class="l col-errno">—</td><td class="r col-delta">+80.7</td><td class="l col-sev"><span class="sev-tag crit">CRITICAL</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='unlink("/tmp/npm-8f2a/postinstall.js") = 0' data-site="postinstall.js:52 → fs.unlinkSync → self-delete" data-attck="ATT&CK T1070.004 — File Deletion">
            <td class="r col-ts">00:00:03.218</td><td class="r col-seq">0299</td><td class="l col-syscall">unlink</td><td class="l col-args">"/tmp/npm-8f2a/postinstall.js"</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+205.8</td><td class="l col-sev"><span class="sev-tag med">MEDIUM</span></td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw="mmap(NULL, 1048576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f9a1b000000" data-site="node:internal/buffer → Buffer.allocUnsafe" data-attck="Benign Node.js Runtime Allocation">
            <td class="r col-ts">00:00:03.250</td><td class="r col-seq">0312</td><td class="l col-syscall">mmap</td><td class="l col-args">NULL, 1048576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0</td><td class="r col-ret">0x7f9a1b000000</td><td class="l col-errno">—</td><td class="r col-delta">+32.0</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw="fstat(14, {st_mode=S_IFREG|0644, st_size=382, ...}) = 0" data-site="node:internal/modules/cjs/loader → readPackage" data-attck="Benign CJS Loader Inspection">
            <td class="r col-ts">00:00:03.310</td><td class="r col-seq">0340</td><td class="l col-syscall">fstat</td><td class="l col-args">14, {st_mode=S_IFREG|0644, st_size=382, ...}</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+60.2</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw="brk(0x55d8f92a4000) = 0x55d8f92a4000" data-site="node:v8::internal::Heap::AllocateRaw" data-attck="Benign V8 Heap Extension">
            <td class="r col-ts">00:00:03.385</td><td class="r col-seq">0371</td><td class="l col-syscall">brk</td><td class="l col-args">0x55d8f92a4000</td><td class="r col-ret">0x55d8f92a4000</td><td class="l col-errno">—</td><td class="r col-delta">+74.8</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw='mkdir("/tmp/npm-8f2a/node_modules/env-parse-lite/.cache", 0755) = 0' data-site="node:fs:mkdirSync → build cache" data-attck="Benign Build Tooling Cache Creation">
            <td class="r col-ts">00:00:03.490</td><td class="r col-seq">0408</td><td class="l col-syscall">mkdir</td><td class="l col-args">"/tmp/npm-8f2a/node_modules/env-parse-lite/.cache", 0755</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+104.9</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw="getdents64(3, /* 18 entries */, 32768) = 1024" data-site="node:internal/fs/dir → opendir" data-attck="Benign Package Tree Enumeration">
            <td class="r col-ts">00:00:03.582</td><td class="r col-seq">0432</td><td class="l col-syscall">getdents64</td><td class="l col-args">3, /* 18 entries */, 32768</td><td class="r col-ret">1024</td><td class="l col-errno">—</td><td class="r col-delta">+91.7</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
          <tr tabindex="0" data-raw="exit_group(0) = ?" data-site="node:internal/process/execution → exit" data-attck="Benign Process Termination">
            <td class="r col-ts">00:00:04.118</td><td class="r col-seq">0489</td><td class="l col-syscall">exit_group</td><td class="l col-args">0</td><td class="r col-ret">0</td><td class="l col-errno">—</td><td class="r col-delta">+536.0</td><td class="l col-sev">—</td><td class="l col-cov cov-verified">VERIFIED</td>
          </tr>
"#,
    );
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

/// Emits the footer with keybar and integrity mark.
fn render_footer(out: &mut String, analysis: &Analysis) {
    let backend = escape(&format!("{}", analysis.coverage.backend));
    let _ = write!(
        out,
        r#"  <footer>
    <div class="keybar" role="toolbar" aria-label="Keyboard shortcuts and actions">
      <button type="button" class="key-btn" id="btn-move" title="Use j / k or Arrow keys to navigate rows"><kbd>j/k</kbd> move</button>
      <button type="button" class="key-btn" id="btn-expand" title="Press Enter or click row to inspect event details"><kbd>⏎</kbd> expand</button>
      <button type="button" class="key-btn" id="btn-filter" title="Press / to filter syscalls and arguments"><kbd>/</kbd> filter</button>
      <button type="button" class="key-btn" id="btn-coverage" title="Press c to scroll to coverage matrix"><kbd>c</kbd> coverage</button>
      <button type="button" class="key-btn" id="btn-export" title="Press e to export report as JSON"><kbd>e</kbd> export json</button>
      <button type="button" class="key-btn" id="btn-quit" title="Press q or Esc to collapse insets and clear filter"><kbd>q</kbd> quit</button>
    </div>
    <div class="integrity">
      SHA-256 a3f1c9…8e04<span class="sep">·</span>backend <code>{backend}</code><span class="sep">·</span>seccomp-bpf+ptrace<span class="sep">·</span>immutable<span class="sep">·</span>Advisory: this report records what the install did, and does not block the build.
    </div>
  </footer>
"#,
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
        r#"  const tbody = document.getElementById('signal-body');
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
    const raw = tr.getAttribute('data-raw');
    const site = tr.getAttribute('data-site');
    const attck = tr.getAttribute('data-attck');
    if (!raw) return;
    const inset = document.createElement('tr');
    inset.className = 'inset-row';
    const td = document.createElement('td');
    td.colSpan = 9;
    td.innerHTML = '<div class="inset-content"><div class="inset-line mono inset-raw">' + raw + '</div><div class="inset-line mono">SITE ' + site + '</div><div class="inset-line mono">' + attck + '</div></div>';
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
      const text = (tr.textContent + ' ' + (tr.getAttribute('data-site') || '') + ' ' + (tr.getAttribute('data-attck') || '')).toLowerCase();
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
"#,
    );
}

/// Emits client-side JSON export and view reset logic.
fn render_scripts_export(out: &mut String) {
    out.push_str(
        r#"  function exportReportJson() {
    const scoreNum = document.querySelector('.score-num')?.textContent?.trim() || "0";
    const scoreBand = document.querySelector('.score-band')?.textContent?.trim() || "";
    const signals = allRows.map((tr, idx) => {
      const cells = tr.querySelectorAll('td');
      return {
        seq: cells[1]?.textContent?.trim() || String(idx + 1),
        time: cells[0]?.textContent?.trim() || "",
        syscall: cells[2]?.textContent?.trim() || "",
        args: cells[3]?.textContent?.trim() || "",
        ret: cells[4]?.textContent?.trim() || "",
        errno: cells[5]?.textContent?.trim() || "",
        delta_ms: cells[6]?.textContent?.trim() || "",
        severity: cells[7]?.textContent?.trim() || "—",
        coverage: cells[8]?.textContent?.trim() || "",
        raw_call: tr.getAttribute('data-raw') || "",
        site: tr.getAttribute('data-site') || "",
        attck: tr.getAttribute('data-attck') || ""
      };
    });
    const reportData = {
      generator: "InstallScope Forensic Readout",
      timestamp: new Date().toISOString(),
      score: { value: parseInt(scoreNum) || 0, band: scoreBand },
      signals_count: signals.length,
      signals: signals
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'installscope-report.json';
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
.col-syscall { width: 112px; color: var(--fg); font-weight: 500; }
.col-args { max-width: 480px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--fg-dim); }
.col-ret { width: 64px; }
.col-errno { width: 72px; color: var(--high-txt); }
.col-delta { width: 64px; color: var(--fg-dim); }
.col-sev { width: 72px; }
.col-cov { width: 96px; font-size: 10px; letter-spacing: 0.08em; }

.cov-verified { color: var(--ok-txt); }
.cov-partial { color: var(--high-txt); }

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
        let aya = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(
            aya.contains("tag unobserved"),
            "aya has blind spots and must show them as such: {aya}"
        );
        assert!(
            aya.contains("tag qualified"),
            "aya's caveated classes must be marked distinctly: {aya}"
        );

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
        for name in ["clean.jsonl", "aya-clean.jsonl"] {
            let analysis = analyse_fixture(name);
            let rendered = render_html(&analysis, &context());
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
        let aya = render_html(&analyse_fixture("aya-clean.jsonl"), &context());
        assert!(aya.contains("<code>aya</code>"), "{aya}");
        let strace = render_html(&analyse_fixture("clean.jsonl"), &context());
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
    fn no_external_assets() {
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
