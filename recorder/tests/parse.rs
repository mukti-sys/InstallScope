//! Golden tests for the strace parser.
//!
//! Fixtures under `tests/fixtures/` are **synthetic and labeled as such** (`Rules.md` §5); see
//! `fixtures/README.md` for what each line exercises. They are hand-written, never edited real
//! recordings, and must not be cited as receipts.
//!
//! These tests assert two categories of behavior, and the second matters as much as the first:
//!
//! 1. **Extraction** — the events the parser must produce, including the write-byte accounting that
//!    the Phase 0 harness could not do at all.
//! 2. **Refusal** — the events it must *not* produce. A relative path with no known base must stay
//!    `Unresolved`; a truncated DNS payload must yield nothing; a write to a socket must not become a
//!    file write. Each of those, if it went the other way, would put a fabricated claim into a
//!    forensic report.

use std::path::Path;

use installscope_core::{Event, PathOrigin, Payload, WriteKind};
use installscope_recorder::Parser;

/// Epoch second the fixtures start at, matching their first timestamp.
const FIXTURE_START_EPOCH: f64 = 1_719_245_678.0;

/// Parses every `trace.<pid>` file in a fixture directory, in pid order, exactly as the strace
/// backend does.
fn parse_fixture(dir: &str) -> (Vec<Event>, installscope_recorder::ParseStats) {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(dir);

    let mut files: Vec<(u32, std::path::PathBuf)> = std::fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("reading {}: {e}", base.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            let pid = name.strip_prefix("trace.")?.parse::<u32>().ok()?;
            Some((pid, path))
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no trace files in {}", base.display());

    let mut parser = Parser::new(FIXTURE_START_EPOCH);
    // The root process's cwd is established by its own chdir; children inherit. Nothing is seeded,
    // so any resolution seen in these tests came from the trace itself.
    let mut events = Vec::new();
    for (pid, path) in &files {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        for line in contents.lines() {
            events.extend(parser.feed_line(line, *pid));
        }
    }
    events.extend(parser.finish());
    let stats = parser.stats().clone();
    (events, stats)
}

fn writes(events: &[Event]) -> Vec<&installscope_core::FsWrite> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::FsWrite(w) => Some(w),
            _ => None,
        })
        .collect()
}

fn reads(events: &[Event]) -> Vec<&installscope_core::FsRead> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::FsRead(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn connects(events: &[Event]) -> Vec<&installscope_core::NetConnect> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::NetConnect(c) => Some(c),
            _ => None,
        })
        .collect()
}

fn dns(events: &[Event]) -> Vec<&installscope_core::DnsQuery> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::DnsQuery(d) => Some(d),
            _ => None,
        })
        .collect()
}

fn spawns(events: &[Event]) -> Vec<&installscope_core::ProcSpawn> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Payload::ProcSpawn(p) => Some(p),
            _ => None,
        })
        .collect()
}

/// Finds the byte-carrying write event for a path.
fn byte_write<'a>(events: &'a [Event], path: &str) -> Option<&'a installscope_core::FsWrite> {
    writes(events)
        .into_iter()
        .find(|w| w.kind == WriteKind::Write && w.target.path == path)
}

// =============================================================================================
// Extraction
// =============================================================================================

#[test]
fn parses_the_fixture_without_errors() {
    let (events, stats) = parse_fixture("complete");
    assert_eq!(
        stats.parse_errors, 0,
        "the fixture must parse cleanly; {stats:?}"
    );
    assert_eq!(
        stats.unmatched_unfinished, 0,
        "every unfinished syscall in this fixture is resumed; {stats:?}"
    );
    assert!(!events.is_empty());
    // One exit notice per traced process: 4100, 4101, 4103.
    assert_eq!(stats.exits, 3, "one exit per process; {stats:?}");
    assert_eq!(stats.signals, 1, "one signal notice; {stats:?}");
}

#[test]
fn strace_diagnostics_are_not_parse_errors() {
    // The bug this guards against would have forced PARTIAL on every real recording. `-f` prints
    // "strace: Process N attached" for every child, and npm always spawns children, so counting those
    // as parse errors would mean no install could ever record as complete — making the PARTIAL badge
    // meaningless precisely when it needs to be trustworthy.
    let (_, stats) = parse_fixture("complete");
    assert!(
        stats.diagnostics >= 3,
        "the fixture's attach lines must be recognized as diagnostics; {stats:?}"
    );
    assert_eq!(
        stats.parse_errors, 0,
        "diagnostics must not be counted as errors; {stats:?}"
    );
    assert_eq!(
        stats.diagnostic_data_loss, 0,
        "an attach notice is routine, not data loss; {stats:?}"
    );
}

#[test]
fn diagnostics_reporting_data_loss_are_distinguished_from_chatter() {
    // Not every diagnostic is noise. strace detaching mid-recording, or failing to allocate, means the
    // stream is genuinely missing events — and the strace backend turns this counter into an
    // IncompleteReason so the report shows PARTIAL.
    let mut parser = Parser::new(FIXTURE_START_EPOCH);

    parser.feed_line("strace: Process 999 attached", 1);
    assert_eq!(parser.stats().diagnostic_data_loss, 0);

    parser.feed_line("strace: Out of memory", 1);
    parser.feed_line("strace: detaching from 999", 1);
    assert_eq!(
        parser.stats().diagnostic_data_loss,
        2,
        "data-loss diagnostics must be counted separately; {:?}",
        parser.stats()
    );
    assert_eq!(
        parser.stats().parse_errors,
        0,
        "these are still diagnostics, not malformed lines"
    );
}

#[test]
fn timestamps_are_session_relative_and_ordered_within_a_process() {
    let (events, _) = parse_fixture("complete");
    // Epoch nanoseconds would exceed JSON's safe integer range, which is why the schema is relative.
    for event in &events {
        assert!(
            event.meta.ts_ns < 10_000_000_000,
            "ts_ns {} looks like epoch time, not session-relative",
            event.meta.ts_ns
        );
    }
}

#[test]
fn sums_write_bytes_across_calls_to_one_descriptor() {
    // The Phase 0 harness did not trace write() at all, so byte volumes were impossible and
    // Design.md:35's "wrote ~13 MB outside project dir" could not be produced. This is that gap
    // closed: three writes to one cache file, 4 MiB + 2 MiB + 1 MiB, reported as one 7 MiB event.
    let (events, _) = parse_fixture("complete");
    let cache_path = "/work/cache/_cacache/content-v2/sha512/aa/bb/cc";
    let write = byte_write(&events, cache_path).expect("a byte-carrying write for the cache file");
    assert_eq!(
        write.bytes,
        Some(4_194_304 + 2_097_152 + 1_048_576),
        "write, pwrite64, and write must all accumulate"
    );

    // Exactly one aggregated event, not one per syscall.
    let count = writes(&events)
        .iter()
        .filter(|w| w.kind == WriteKind::Write && w.target.path == cache_path)
        .count();
    assert_eq!(count, 1, "byte writes must aggregate into a single event");
}

#[test]
fn flushes_byte_totals_at_close() {
    let (events, _) = parse_fixture("complete");
    let write = byte_write(&events, "/work/project/package.json").expect("package.json byte write");
    // 12 bytes from the root process, 1 more, then the child adds 15 through the inherited fd and 7
    // through a dup. The root's total is flushed at its close(); the child's is flushed at finish().
    assert!(
        write.bytes.unwrap_or(0) >= 13,
        "expected at least the root process's 13 bytes, got {:?}",
        write.bytes
    );
}

#[test]
fn a_reopened_descriptor_does_not_merge_totals() {
    // fd 4 is the cache file, then is reopened as /work/tmp/staging.bin. Merging the two would
    // attribute 7 MiB of cache writes to a temp file — a wrong byte volume in a report.
    let (events, _) = parse_fixture("complete");
    let staging = byte_write(&events, "/work/tmp/staging.bin").expect("staging byte write");
    assert_eq!(
        staging.bytes,
        Some(7),
        "the reopened descriptor starts a fresh total"
    );
}

#[test]
fn tracks_writes_through_inherited_and_duplicated_descriptors() {
    // The child never opened fd 3; it inherited it through clone. dup2 then aliases it to fd 20.
    // Both must resolve to package.json rather than being dropped for an unknown descriptor.
    let (events, _) = parse_fixture("complete");
    let child_writes: Vec<_> = writes(&events)
        .into_iter()
        .filter(|w| w.kind == WriteKind::Write && w.target.path == "/work/project/package.json")
        .collect();
    assert!(
        !child_writes.is_empty(),
        "inherited-descriptor writes must resolve to a path"
    );
    let total: u64 = child_writes.iter().filter_map(|w| w.bytes).sum();
    assert_eq!(
        total, 35,
        "13 root bytes + 15 inherited + 7 through dup2 = 35; got {total}"
    );
}

#[test]
fn records_the_write_outside_every_expected_directory() {
    let (events, _) = parse_fixture("complete");
    let cron = writes(&events)
        .into_iter()
        .find(|w| w.target.path == "/etc/cron.d/synthetic-fixture")
        .expect("the /etc/cron.d write");
    assert!(
        cron.target.is_resolved(),
        "an absolute path from the kernel annotation must be resolved"
    );
    assert_eq!(cron.target.origin, PathOrigin::Kernel);
}

#[test]
fn resolves_relative_paths_against_a_chdir() {
    // The root process chdir'd to /work/project, so `node_modules/.bin` must resolve rather than
    // being discarded. Without cwd tracking this evidence would be unusable.
    let (events, _) = parse_fixture("complete");
    let mkdir = writes(&events)
        .into_iter()
        .find(|w| w.kind == WriteKind::Mkdir)
        .expect("the mkdirat event");
    assert_eq!(mkdir.target.path, "/work/project/node_modules/.bin");
    assert_eq!(mkdir.target.origin, PathOrigin::ResolvedFromDirfd);
}

#[test]
fn records_rename_symlink_delete_and_chmod_with_their_details() {
    let (events, _) = parse_fixture("complete");
    let all = writes(&events);

    let rename = all
        .iter()
        .find(|w| w.kind == WriteKind::Rename)
        .expect("rename");
    assert_eq!(
        rename.target.path,
        "/work/project/node_modules/pkg/bin.node"
    );
    assert_eq!(
        rename.source.as_ref().map(|s| s.path.as_str()),
        Some("/work/tmp/staging.bin")
    );

    let symlink = all
        .iter()
        .find(|w| w.kind == WriteKind::Symlink)
        .expect("symlink");
    assert_eq!(symlink.target.path, "/work/project/node_modules/.bin/pkg");
    // The link contents are not a path on this filesystem, so they stay Unresolved by construction.
    assert_eq!(
        symlink.source.as_ref().map(|s| s.origin),
        Some(PathOrigin::Unresolved),
        "a symlink's target string must not be presented as a resolved path"
    );

    let chmod = all
        .iter()
        .find(|w| w.kind == WriteKind::Chmod)
        .expect("chmod");
    assert_eq!(chmod.target.path, "/usr/local/bin/synthetic-tool");
    assert!(
        chmod.mode.as_deref().unwrap_or_default().contains("755"),
        "the mode must survive for evidence display, got {:?}",
        chmod.mode
    );

    assert!(
        all.iter().any(|w| w.kind == WriteKind::Delete),
        "unlink must be recorded"
    );
}

#[test]
fn records_credential_reads_including_failed_attempts() {
    let (events, _) = parse_fixture("complete");
    let all = reads(&events);

    let ssh = all
        .iter()
        .find(|r| r.target.path.ends_with("id_rsa"))
        .expect("the SSH key read");
    assert_eq!(ssh.outcome.ok, Some(true));

    // A failed read is still evidence of intent, so it is recorded and marked rather than dropped.
    let aws = all
        .iter()
        .find(|r| r.target.path.ends_with("/.aws/credentials"))
        .expect("the failed AWS credentials read");
    assert!(aws.outcome.failed_known());
    assert_eq!(aws.outcome.error.as_deref(), Some("ENOENT"));

    assert!(
        all.iter().any(|r| r.target.path.ends_with("/environ")),
        "reading a process environment is how env harvesting appears"
    );
}

#[test]
fn classifies_connect_destinations() {
    let (events, _) = parse_fixture("complete");
    let all = connects(&events);

    let public = all
        .iter()
        .find(|c| c.ip.as_deref() == Some("104.16.0.1"))
        .expect("the public connect");
    assert!(!public.loopback && !public.private);
    assert_eq!(public.port, Some(443));
    // EINPROGRESS on a non-blocking connect is a real attempt, not a failure.
    assert_eq!(public.outcome.ok, Some(true));

    let resolver = all
        .iter()
        .find(|c| c.ip.as_deref() == Some("127.0.0.53"))
        .expect("the resolver connect");
    assert!(resolver.loopback && resolver.private);

    let metadata = all
        .iter()
        .find(|c| c.ip.as_deref() == Some("169.254.169.254"))
        .expect("the link-local connect");
    assert!(
        metadata.private,
        "link-local must be private so runner metadata traffic is not a finding"
    );
}

#[test]
fn decodes_dns_questions_from_sendto() {
    let (events, _) = parse_fixture("complete");
    let names: Vec<&str> = dns(&events).iter().map(|d| d.qname.as_str()).collect();
    assert!(
        names.contains(&"registry.npmjs.org"),
        "expected registry.npmjs.org, got {names:?}"
    );
}

#[test]
fn decodes_dns_questions_sent_on_a_connected_socket() {
    // Regression test for a real gap found in run 33296408610: the recording showed a connect to
    // 127.0.0.53:53 and zero dns_query events. glibc's resolver connects its UDP socket to the
    // nameserver and then calls `send`, which carries no destination address — so a parser that only
    // reads `sendto`/`sendmsg` destinations sees an anonymous datagram and discards it. The peer must
    // come from the fd table instead.
    let (events, _) = parse_fixture("complete");
    let query = dns(&events)
        .into_iter()
        .find(|d| d.qname == "resolvers.example.net")
        .expect("a DNS question sent via send() on a connected socket");
    assert_eq!(
        query.resolver_ip.as_deref(),
        Some("127.0.0.53"),
        "the resolver address must come from the connect recorded against that descriptor"
    );
}

#[test]
fn decodes_every_question_in_a_batched_sendmmsg() {
    // Run 33297018475 still produced zero DNS events after `send` was handled: glibc actually batches
    // the A and AAAA lookups for one hostname into a single `sendmmsg`. Reading only the first
    // iov_base would halve the recorded questions; missing the syscall entirely records none.
    let (events, _) = parse_fixture("complete");
    let batched: Vec<&installscope_core::DnsQuery> = dns(&events)
        .into_iter()
        .filter(|d| d.qname == "batch.example.org")
        .collect();
    assert_eq!(
        batched.len(),
        2,
        "both messages in the batch must be decoded, got {:?}",
        batched.iter().map(|d| d.qtype).collect::<Vec<_>>()
    );
    // A (1) and AAAA (28) — the pair a resolver sends for one name.
    let mut types: Vec<Option<u16>> = batched.iter().map(|d| d.qtype).collect();
    types.sort();
    assert_eq!(types, vec![Some(1), Some(28)]);
    assert!(
        batched
            .iter()
            .all(|d| d.resolver_ip.as_deref() == Some("127.0.0.53")),
        "a NULL msg_name must fall back to the connected peer"
    );
}

#[test]
fn preserves_argv_for_spawns() {
    let (events, _) = parse_fixture("complete");
    let all = spawns(&events);

    let shell = all
        .iter()
        .find(|s| s.argv.iter().any(|a| a == "-c"))
        .expect("the sh -c spawn");
    // Rules match on argv, so the script text must survive intact — including the pipe, which is
    // what makes "download piped to a shell" detectable at all.
    assert!(
        shell
            .argv
            .last()
            .is_some_and(|a| a.contains("curl") && a.contains("| sh")),
        "the shell script text must survive: {:?}",
        shell.argv
    );
    assert!(!shell.argv_truncated);

    assert!(
        all.iter()
            .any(|s| s.bin.as_deref() == Some("/usr/bin/curl")),
        "curl must be recorded as a spawn"
    );
    assert_eq!(
        all.len(),
        3,
        "npm, sh, and curl; got {:?}",
        all.iter().map(|s| s.bin.as_deref()).collect::<Vec<_>>()
    );
}

// =============================================================================================
// Refusal — the parser must not invent
// =============================================================================================

#[test]
fn a_relative_path_with_no_known_base_stays_unresolved() {
    // THE critical negative case. The rules engine keys "write outside expected dirs" (critical, x40)
    // off resolvability. Process 4103 was never seen to chdir and did not inherit a cwd, so
    // `no-cwd-known.txt` has no trustworthy base. Anchoring it anywhere would manufacture a critical
    // finding out of nothing.
    let (events, _) = parse_fixture("complete");
    let relative = writes(&events)
        .into_iter()
        .find(|w| w.target.path == "no-cwd-known.txt")
        .expect("the relative openat must still be recorded, just not resolved");
    assert_eq!(relative.target.origin, PathOrigin::Unresolved);
    assert!(
        !relative.target.is_resolved(),
        "an unresolved path must not be treated as placeable"
    );

    // Same for a bare mkdir with no dirfd argument at all.
    let mkdir = writes(&events)
        .into_iter()
        .find(|w| w.target.path == "also-relative")
        .expect("the relative mkdir");
    assert_eq!(mkdir.target.origin, PathOrigin::Unresolved);
}

#[test]
fn a_child_inherits_its_parents_cwd_for_path_resolution() {
    // The counterpart to the test above: process 4101 was cloned from a parent that had chdir'd, so
    // its relative paths DO resolve. Discarding these would throw away real evidence.
    let (events, _) = parse_fixture("complete");
    let inherited = writes(&events)
        .into_iter()
        .find(|w| w.target.path == "/work/project/inherited-cwd.txt")
        .expect("a cloned child must inherit its parent's cwd");
    assert_eq!(inherited.target.origin, PathOrigin::ResolvedFromDirfd);
}

#[test]
fn a_truncated_dns_payload_produces_no_event() {
    // The sendmsg payload is cut mid-label ("registry.npm"...). Emitting a shortened hostname would
    // put a name that was never queried into a report.
    let (events, stats) = parse_fixture("complete");
    let names: Vec<&str> = dns(&events).iter().map(|d| d.qname.as_str()).collect();
    assert!(
        !names
            .iter()
            .any(|n| n.starts_with("registry.npm") && *n != "registry.npmjs.org"),
        "a partially decoded name must never appear, got {names:?}"
    );
    assert!(
        stats.dns_undecodable >= 1,
        "the truncated payload must be counted, not silently dropped; {stats:?}"
    );
}

#[test]
fn a_write_to_a_socket_is_not_reported_as_a_file_write() {
    // fd 8 is a TCP socket. Reporting its 517-byte TLS handshake as a filesystem write would be
    // both wrong and alarming — a phantom file with binary contents.
    let (events, _) = parse_fixture("complete");
    for write in writes(&events) {
        assert!(
            !write.target.path.contains("TCP:") && !write.target.path.contains("UDP:"),
            "socket write leaked into fs_write: {:?}",
            write.target
        );
    }
}

#[test]
fn uninteresting_reads_produce_no_events() {
    // Recording every read would bury the evidence. /usr/lib/... is npm reading its own files.
    let (events, _) = parse_fixture("complete");
    assert!(
        !reads(&events)
            .iter()
            .any(|r| r.target.path.starts_with("/usr/lib/")),
        "ordinary library reads must not be recorded"
    );
}

#[test]
fn clone_and_close_do_not_emit_events() {
    // Bookkeeping syscalls maintain parser state; emitting them would double-count a spawn (already
    // covered by execve) and pad the artifact.
    let (events, _) = parse_fixture("complete");
    for event in &events {
        let syscall = event.meta.syscall.as_deref().unwrap_or("");
        assert!(
            !matches!(
                syscall,
                "clone" | "clone3" | "close" | "dup" | "dup2" | "socket" | "chdir"
            ),
            "bookkeeping syscall {syscall} must not produce an event"
        );
    }
}

// =============================================================================================
// PARTIAL propagation
// =============================================================================================

#[test]
fn an_unmatched_unfinished_syscall_is_counted() {
    // The process died mid-openat. Rules.md §2: a recording that lost data must be visibly
    // incomplete. The strace backend turns this count into an IncompleteReason, so the report shows
    // PARTIAL rather than a clean score built on truncated evidence.
    let (events, stats) = parse_fixture("truncated");
    assert_eq!(
        stats.unmatched_unfinished, 1,
        "the dangling openat must be counted; {stats:?}"
    );
    // Everything before the truncation is still real evidence and is kept.
    assert!(
        byte_write(&events, "/work/project/half-written.txt").is_some(),
        "evidence recorded before the truncation must survive"
    );
}

#[test]
fn the_event_cap_is_reported_rather_than_silently_truncating() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("complete")
        .join("trace.4100");
    let contents = std::fs::read_to_string(&base).unwrap_or_else(|e| panic!("{e}"));

    let mut parser = Parser::new(FIXTURE_START_EPOCH).with_event_cap(3);
    let mut produced = 0;
    for line in contents.lines() {
        produced += parser.feed_line(line, 4100).len();
    }
    produced += parser.finish().len();

    assert!(produced <= 3, "the cap must bound output, got {produced}");
    assert!(
        parser.cap_reached(),
        "hitting the cap must be observable so the session can be marked PARTIAL"
    );
}

#[test]
fn malformed_lines_are_counted_not_ignored() {
    let mut parser = Parser::new(FIXTURE_START_EPOCH);
    let events = parser.feed_line("this is not strace output at all", 1);
    assert!(events.is_empty());
    assert_eq!(
        parser.stats().parse_errors,
        1,
        "an unparseable line must be counted so it can force PARTIAL"
    );
}

#[test]
fn every_emitted_event_carries_full_provenance() {
    // Evidence a reader cannot trace back to a specific syscall in a specific process is an
    // assertion, not evidence.
    let (events, _) = parse_fixture("complete");
    for event in &events {
        assert_eq!(event.schema_version, installscope_core::SCHEMA_VERSION);
        assert_eq!(event.meta.backend, installscope_core::Backend::Strace);
        assert!(event.meta.pid.is_some(), "observation without a pid");
        assert!(
            event.meta.syscall.as_deref().is_some_and(|s| !s.is_empty()),
            "observation without a syscall name"
        );
        // Every event must survive a round trip, since the artifact is what downstream reads.
        let line = event
            .to_jsonl()
            .unwrap_or_else(|e| panic!("serialize: {e}"));
        let back = Event::from_jsonl(&line, 1).unwrap_or_else(|e| panic!("deserialize: {e}"));
        assert_eq!(*event, back);
    }
}

#[test]
fn ptrace_anti_debugging_and_attach_are_counted_as_evasion() {
    let mut parser = Parser::new(FIXTURE_START_EPOCH);
    // Anti-debugging probe: fails with EPERM when strace is already attached
    parser.feed_line(
        "1700000000.000100 ptrace(PTRACE_TRACEME, 0, 0, 0) = -1 EPERM",
        1,
    );
    // Process hijacking / tracing interference
    parser.feed_line("1700000000.000200 ptrace(PTRACE_ATTACH, 1337, 0, 0) = 0", 1);

    assert_eq!(
        parser.stats().evasion_attempts,
        2,
        "anti-debugging probe and attach attempts must be counted to force PARTIAL"
    );
}

#[test]
fn benign_ptrace_traceme_handshake_is_not_evasion() {
    let mut parser = Parser::new(FIXTURE_START_EPOCH);
    parser.feed_line("1700000000.000100 ptrace(PTRACE_TRACEME, 0, 0, 0) = 0", 1);
    assert_eq!(
        parser.stats().evasion_attempts,
        0,
        "benign tracer handshake must not be flagged as evasion"
    );
}
