//! Translating merged eBPF records into schema v1 events.
//!
//! Pure functions over [`crate::merge::Merged`], deliberately separate from the loader so the mapping
//! is testable without a kernel — the same split that let Phase 1's parser be verified on a Windows
//! machine while the recorder itself only runs on Linux.
//!
//! # Two honest downgrades versus strace
//!
//! **Path origin.** strace's `-yy` hands over the kernel's own resolved path, so Phase 1 recordings
//! come back with [`PathOrigin::Kernel`] on nearly every event. These probes read the *userspace path
//! argument* instead — what the process asked for, not where it landed. So an absolute argument becomes
//! [`PathOrigin::Absolute`] and a relative one becomes [`PathOrigin::Unresolved`], because resolving it
//! would require the `dirfd` and cwd tracking the kernel side does not supply. Symlinks are not
//! resolved either. The rules engine already refuses to place an unresolved path in a zone, so the
//! consequence is a missed finding rather than a fabricated one — the correct direction to fail.
//!
//! **Byte counts are requested, not actual.** `sys_enter_write` sees the count the process asked to
//! write, before the kernel knows how much it managed. A short write overstates the total. That is
//! recorded in the event's flags rather than presented as exact.
//!
//! Both are stated here and in `Memory.md` so a later reader does not mistake them for bugs.

use installscope_core::{
    AddrFamily, Backend, Event, EventMeta, FsWrite, NetConnect, Outcome, PathOrigin, Payload,
    ProcSpawn, TracedPath, WriteKind,
};

use crate::merge::Merged;

/// Converts a kernel monotonic timestamp into a session-relative one.
///
/// `bpf_ktime_get_ns` counts nanoseconds since boot. Schema v1 wants nanoseconds since session start,
/// anchored once in `session_start.wall_clock_utc` — the same choice the strace backend makes, and for
/// the same reason: epoch nanoseconds exceed JSON's safe integer range, so converting per event would
/// invite silent corruption in any JavaScript consumer.
#[must_use]
pub fn session_relative_ns(ktime_ns: u64, session_start_ktime_ns: u64) -> u64 {
    ktime_ns.saturating_sub(session_start_ktime_ns)
}

/// Maps an ABI write kind onto the schema's.
///
/// An unrecognized value maps to [`WriteKind::Open`] rather than being dropped: a write we cannot
/// classify is still a write, and losing it would under-report behavior. The kinds are `u32` constants
/// rather than an enum precisely because an ABI must tolerate a value it does not know.
#[must_use]
pub fn write_kind_of(abi_kind: u32) -> WriteKind {
    match abi_kind {
        installscope_abi::WRITE_WRITE => WriteKind::Write,
        installscope_abi::WRITE_CREATE => WriteKind::Create,
        installscope_abi::WRITE_TRUNCATE => WriteKind::Truncate,
        installscope_abi::WRITE_MKDIR => WriteKind::Mkdir,
        installscope_abi::WRITE_RENAME => WriteKind::Rename,
        installscope_abi::WRITE_DELETE => WriteKind::Delete,
        installscope_abi::WRITE_SYMLINK => WriteKind::Symlink,
        installscope_abi::WRITE_HARDLINK => WriteKind::Hardlink,
        installscope_abi::WRITE_CHMOD => WriteKind::Chmod,
        installscope_abi::WRITE_CHOWN => WriteKind::Chown,
        _ => WriteKind::Open,
    }
}

/// Classifies a path read from a syscall argument.
///
/// Absolute paths are trustworthy as written. Relative ones are [`PathOrigin::Unresolved`]: the probe
/// has no `dirfd` or cwd, and a guessed base would let the rules engine place a write in a zone it may
/// not belong to. That is how a fabricated critical finding gets made, so the guess is refused.
#[must_use]
pub fn classify_path(path: &str) -> TracedPath {
    if path.starts_with('/') {
        TracedPath::new(crate::fdtable::normalize(path), PathOrigin::Absolute)
    } else {
        TracedPath::new(path, PathOrigin::Unresolved)
    }
}

/// Formats an address from an ABI [`installscope_abi::NetRecord`].
///
/// Returns `None` for an unrecognized family rather than rendering meaningless bytes as an address.
#[must_use]
pub fn format_addr(family: u32, addr: &[u8; installscope_abi::ADDR_LEN]) -> Option<String> {
    match family {
        installscope_abi::AF_INET4 => {
            Some(format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]))
        }
        installscope_abi::AF_INET6 => {
            let segments: [u16; 8] =
                core::array::from_fn(|i| u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]));
            Some(std::net::Ipv6Addr::from(segments).to_string())
        }
        _ => None,
    }
}

/// Splits a NUL-separated argv buffer into arguments.
///
/// Trailing empty entries are dropped, since the kernel side writes a separator after each argument.
/// Interior empty arguments are preserved: `sh -c ''` is a real invocation, and silently dropping the
/// empty string would change what a rule sees.
#[must_use]
pub fn split_argv(buffer: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = buffer
        .split(|b| *b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

/// Translates one merged record into a schema v1 event.
///
/// Returns `None` only for records that carry no reportable observation — currently a network record
/// whose address family the probe could not decode, where emitting an event would mean inventing a
/// destination.
#[must_use]
pub fn to_event(merged: &Merged, session_start_ktime_ns: u64) -> Option<Event> {
    match merged {
        Merged::Fs {
            header,
            write_kind,
            path,
            path_truncated,
            bytes,
            mode,
            errno,
        } => {
            let ts_ns = session_relative_ns(header.ktime_ns, session_start_ktime_ns);
            let meta = EventMeta::observed(
                ts_ns,
                header.tgid,
                syscall_name_for(*write_kind),
                Backend::Aya,
            );

            // A write with no known descriptor path is still an event; its target is explicitly
            // unresolved rather than omitted, so a reader can see that bytes moved somewhere unknown.
            let target = match path {
                Some(p) => {
                    let mut traced = classify_path(p);
                    if *path_truncated {
                        // A truncated path is a prefix, so it cannot be trusted positionally even when
                        // it starts with '/'. Downgrading is what keeps the rules engine from placing a
                        // partial path in a zone.
                        traced.origin = PathOrigin::Unresolved;
                    }
                    traced
                }
                None => TracedPath::new("<unknown descriptor>", PathOrigin::Unresolved),
            };

            let outcome = match errno {
                Some(code) => Outcome::failed(errno_name(*code)),
                None => Outcome::success(),
            };

            Some(Event::observed(
                meta,
                Payload::FsWrite(FsWrite {
                    target,
                    kind: write_kind_of(*write_kind),
                    bytes: *bytes,
                    // Recorded as a flag string rather than dropped: a consumer comparing byte volumes
                    // between backends needs to know strace's are exact and these are requested.
                    flags: (*write_kind == installscope_abi::WRITE_WRITE)
                        .then(|| "requested_count".to_string()),
                    mode: (*mode != 0).then(|| format!("{mode:#o}")),
                    source: None,
                    outcome,
                }),
            ))
        }

        Merged::Net(record) => {
            let ts_ns = session_relative_ns(record.header.ktime_ns, session_start_ktime_ns);
            let meta = EventMeta::observed(ts_ns, record.header.tgid, "connect", Backend::Aya);

            let family = match record.family {
                installscope_abi::AF_INET4 => AddrFamily::Inet,
                installscope_abi::AF_INET6 => AddrFamily::Inet6,
                _ => AddrFamily::Other,
            };
            let ip = format_addr(record.family, &record.addr);

            // An undecodable family means we know a connect happened but not to where. Reporting it
            // with no address would be a bare "something connected", which no rule can act on and which
            // reads as noise; the merge stats already count it.
            let ip_str = ip.clone()?;

            Some(Event::observed(
                meta,
                Payload::NetConnect(NetConnect {
                    family,
                    loopback: crate::decode::is_loopback(&ip_str),
                    private: crate::decode::is_private(&ip_str),
                    ip,
                    port: (record.port != 0).then_some(record.port),
                    unix_path: None,
                    // Same refusal as the strace backend: correlating a DNS answer to a specific
                    // connect requires guessing, and a hostname on the wrong connection is worse than
                    // no hostname.
                    host: None,
                    outcome: if record.header.has(installscope_abi::FLAG_FAILED) {
                        Outcome::failed(errno_name(record.errno))
                    } else {
                        Outcome::success()
                    },
                }),
            ))
        }

        Merged::Proc(record) => {
            let ts_ns = session_relative_ns(record.header.ktime_ns, session_start_ktime_ns);
            let meta = EventMeta::observed(ts_ns, record.header.tgid, "execve", Backend::Aya);
            let bin = String::from_utf8_lossy(record.filename_bytes())
                .trim_end_matches('\0')
                .to_string();

            Some(Event::observed(
                meta,
                Payload::ProcSpawn(ProcSpawn {
                    bin: (!bin.is_empty()).then_some(bin),
                    argv: split_argv(record.argv_bytes()),
                    argv_truncated: record.header.has(installscope_abi::FLAG_ARGV_TRUNCATED),
                    outcome: Outcome::success(),
                }),
            ))
        }
    }
}

/// The syscall name to stamp on an event, inferred from its write kind.
///
/// The ABI does not carry a syscall name — it would cost 16+ bytes per record for a value derivable
/// from the kind. Inferred rather than invented: each mapping is the syscall whose probe produces that
/// kind, so `syscall` remains traceable back to a specific probe.
const fn syscall_name_for(write_kind: u32) -> &'static str {
    match write_kind {
        installscope_abi::WRITE_WRITE => "write",
        installscope_abi::WRITE_MKDIR => "mkdirat",
        installscope_abi::WRITE_RENAME => "renameat2",
        installscope_abi::WRITE_DELETE => "unlinkat",
        installscope_abi::WRITE_SYMLINK => "symlinkat",
        installscope_abi::WRITE_HARDLINK => "linkat",
        installscope_abi::WRITE_CHMOD => "fchmodat",
        installscope_abi::WRITE_CHOWN => "fchownat",
        installscope_abi::WRITE_TRUNCATE => "truncate",
        installscope_abi::WRITE_CREATE => "creat",
        _ => "openat",
    }
}

/// Maps an errno number to its symbol.
///
/// Only the values an install realistically produces are named; anything else is rendered numerically
/// rather than guessed at, because a wrong errno symbol in evidence is worse than a number.
#[must_use]
pub fn errno_name(code: u32) -> String {
    match code {
        1 => "EPERM".to_string(),
        2 => "ENOENT".to_string(),
        5 => "EIO".to_string(),
        9 => "EBADF".to_string(),
        11 => "EAGAIN".to_string(),
        13 => "EACCES".to_string(),
        17 => "EEXIST".to_string(),
        20 => "ENOTDIR".to_string(),
        21 => "EISDIR".to_string(),
        22 => "EINVAL".to_string(),
        24 => "EMFILE".to_string(),
        28 => "ENOSPC".to_string(),
        30 => "EROFS".to_string(),
        36 => "ENAMETOOLONG".to_string(),
        39 => "ENOTEMPTY".to_string(),
        101 => "ENETUNREACH".to_string(),
        110 => "ETIMEDOUT".to_string(),
        111 => "ECONNREFUSED".to_string(),
        113 => "EHOSTUNREACH".to_string(),
        115 => "EINPROGRESS".to_string(),
        other => format!("errno {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_abi::{Header, NetRecord, ProcRecord};

    fn fs(write_kind: u32, path: Option<&str>, bytes: Option<u64>) -> Merged {
        let mut header = Header::zeroed();
        header.ktime_ns = 5_000;
        header.tgid = 42;
        Merged::Fs {
            header,
            write_kind,
            path: path.map(ToString::to_string),
            path_truncated: false,
            bytes,
            mode: 0,
            errno: None,
        }
    }

    #[test]
    fn timestamps_become_session_relative() {
        // Kernel monotonic time is nanoseconds since boot — a number in the tens of trillions on a
        // long-running host, which exceeds JavaScript's safe integer range. Anchoring is what keeps a
        // JSON consumer from silently corrupting it.
        assert_eq!(session_relative_ns(5_000, 1_000), 4_000);
        // A record older than the anchor (possible for a program attached before the anchor was taken)
        // clamps to zero rather than underflowing into a huge positive.
        assert_eq!(session_relative_ns(500, 1_000), 0);
    }

    #[test]
    fn absolute_paths_are_trusted_relative_ones_are_not() {
        let absolute = classify_path("/work/project/file.js");
        assert_eq!(absolute.origin, PathOrigin::Absolute);
        assert!(absolute.is_resolved());

        // THE important case. Without a dirfd and cwd, a relative path cannot be placed. The rules
        // engine keys "write outside expected dirs" (critical, ×40) off resolvability, so guessing a
        // base here would manufacture critical findings from ordinary relative opens.
        let relative = classify_path("node_modules/.bin/thing");
        assert_eq!(relative.origin, PathOrigin::Unresolved);
        assert!(!relative.is_resolved());
    }

    #[test]
    fn absolute_paths_are_normalized() {
        assert_eq!(classify_path("/a/b/../c").path, "/a/c");
        assert_eq!(classify_path("/a//b/").path, "/a/b");
    }

    #[test]
    fn a_truncated_path_is_downgraded_even_when_absolute() {
        // A truncated path is a prefix. It looks absolute and is not trustworthy positionally: "/work/no"
        // is not inside "/work/node_modules". Treating it as placeable is exactly how a wrong zone
        // classification happens.
        let mut header = Header::zeroed();
        header.ktime_ns = 1_000;
        let merged = Merged::Fs {
            header,
            write_kind: installscope_abi::WRITE_OPEN,
            path: Some("/work/very/long/tru".to_string()),
            path_truncated: true,
            bytes: None,
            mode: 0,
            errno: None,
        };
        let event = to_event(&merged, 0).expect("event");
        match event.payload {
            Payload::FsWrite(w) => {
                assert_eq!(w.target.origin, PathOrigin::Unresolved);
                assert!(!w.target.is_resolved());
            }
            _ => panic!("expected fs_write"),
        }
    }

    #[test]
    fn every_event_is_stamped_with_the_aya_backend() {
        // A mixed-backend corpus stays attributable only if each event says which recorder produced it.
        // Phase 2's parity work depends on this, as does any later comparison across recordings.
        let event =
            to_event(&fs(installscope_abi::WRITE_OPEN, Some("/x"), None), 0).expect("event");
        assert_eq!(event.meta.backend, Backend::Aya);
        assert_eq!(event.schema_version, installscope_core::SCHEMA_VERSION);
        assert_eq!(event.meta.pid, Some(42));
    }

    #[test]
    fn write_bytes_are_labelled_as_requested_not_exact() {
        // sys_enter_write sees the requested count, so a short write overstates it. A consumer comparing
        // volumes between backends must be able to tell that strace's number is exact and this one is
        // an upper bound.
        let event = to_event(
            &fs(installscope_abi::WRITE_WRITE, Some("/x"), Some(4096)),
            0,
        )
        .expect("event");
        match event.payload {
            Payload::FsWrite(w) => {
                assert_eq!(w.bytes, Some(4096));
                assert_eq!(w.flags.as_deref(), Some("requested_count"));
            }
            _ => panic!("expected fs_write"),
        }
    }

    #[test]
    fn a_write_without_a_path_is_reported_as_unknown_not_omitted() {
        // Bytes moved somewhere. Dropping the event would understate volume; inventing a path would
        // misplace it. So: report it, explicitly unresolved.
        let event =
            to_event(&fs(installscope_abi::WRITE_WRITE, None, Some(512)), 0).expect("event");
        match event.payload {
            Payload::FsWrite(w) => {
                assert!(!w.target.is_resolved());
                assert_eq!(w.bytes, Some(512));
            }
            _ => panic!("expected fs_write"),
        }
    }

    #[test]
    fn write_kinds_map_onto_the_schema() {
        let cases = [
            (installscope_abi::WRITE_WRITE, WriteKind::Write),
            (installscope_abi::WRITE_MKDIR, WriteKind::Mkdir),
            (installscope_abi::WRITE_RENAME, WriteKind::Rename),
            (installscope_abi::WRITE_DELETE, WriteKind::Delete),
            (installscope_abi::WRITE_SYMLINK, WriteKind::Symlink),
            (installscope_abi::WRITE_CHMOD, WriteKind::Chmod),
        ];
        for (abi, expected) in cases {
            assert_eq!(write_kind_of(abi), expected, "abi kind {abi}");
        }
        // An unknown kind must not vanish: a write we cannot classify is still a write.
        assert_eq!(write_kind_of(9_999), WriteKind::Open);
    }

    #[test]
    fn syscall_names_stay_traceable_to_a_probe() {
        // `syscall` is provenance: a reader disputing a finding needs to know which probe produced it.
        let event =
            to_event(&fs(installscope_abi::WRITE_MKDIR, Some("/d"), None), 0).expect("event");
        assert_eq!(event.meta.syscall.as_deref(), Some("mkdirat"));

        let event =
            to_event(&fs(installscope_abi::WRITE_WRITE, Some("/f"), Some(1)), 0).expect("event");
        assert_eq!(event.meta.syscall.as_deref(), Some("write"));
    }

    #[test]
    fn formats_ipv4_and_ipv6_addresses() {
        let mut addr = [0u8; installscope_abi::ADDR_LEN];
        addr[..4].copy_from_slice(&[104, 16, 2, 34]);
        assert_eq!(
            format_addr(installscope_abi::AF_INET4, &addr).as_deref(),
            Some("104.16.2.34")
        );

        // 2606:4700::6810:222
        let mut v6 = [0u8; installscope_abi::ADDR_LEN];
        v6[0..2].copy_from_slice(&0x2606u16.to_be_bytes());
        v6[2..4].copy_from_slice(&0x4700u16.to_be_bytes());
        v6[12..14].copy_from_slice(&0x6810u16.to_be_bytes());
        v6[14..16].copy_from_slice(&0x0222u16.to_be_bytes());
        assert_eq!(
            format_addr(installscope_abi::AF_INET6, &v6).as_deref(),
            Some("2606:4700::6810:222")
        );

        // An unrecognized family yields nothing rather than rendering arbitrary bytes as an address.
        assert_eq!(format_addr(999, &addr), None);
    }

    #[test]
    fn connect_events_classify_loopback_and_private() {
        let mut record = NetRecord::zeroed();
        record.header.ktime_ns = 1_000;
        record.header.tgid = 7;
        record.family = installscope_abi::AF_INET4;
        record.port = 53;
        record.addr[..4].copy_from_slice(&[127, 0, 0, 53]);

        let event = to_event(&Merged::Net(record), 0).expect("event");
        match event.payload {
            Payload::NetConnect(c) => {
                assert_eq!(c.ip.as_deref(), Some("127.0.0.53"));
                assert_eq!(c.port, Some(53));
                assert!(c.loopback && c.private);
                // The same refusal as the strace backend: no guessed hostname.
                assert_eq!(c.host, None);
            }
            _ => panic!("expected net_connect"),
        }
    }

    #[test]
    fn a_connect_with_an_undecodable_family_produces_no_event() {
        // AF_UNIX and friends. We know something connected but not to where; a bare event with no
        // address is noise no rule can act on, and inventing one would be fabrication. The merge stats
        // already count these, so they are not invisible.
        let mut record = NetRecord::zeroed();
        record.header.ktime_ns = 1_000;
        record.family = 1; // AF_UNIX
        record.header.flags |= installscope_abi::FLAG_ADDR_UNKNOWN;
        assert!(to_event(&Merged::Net(record), 0).is_none());
    }

    #[test]
    fn port_zero_is_omitted_rather_than_reported() {
        // glibc probes candidate addresses with port 0. Reporting it as a real port would let a Phase 3
        // "unusual port" rule fire on ordinary resolution — the false-positive shape PRD.md:43 warns
        // about. Recorded in Memory.md as a known Phase 1 observation; the same applies here.
        let mut record = NetRecord::zeroed();
        record.header.ktime_ns = 1_000;
        record.family = installscope_abi::AF_INET4;
        record.port = 0;
        record.addr[..4].copy_from_slice(&[104, 16, 2, 34]);

        let event = to_event(&Merged::Net(record), 0).expect("event");
        match event.payload {
            Payload::NetConnect(c) => assert_eq!(c.port, None),
            _ => panic!("expected net_connect"),
        }
    }

    #[test]
    fn splits_nul_separated_argv() {
        assert_eq!(
            split_argv(b"sh\0-c\0curl x | sh\0"),
            vec!["sh", "-c", "curl x | sh"]
        );
        assert_eq!(split_argv(b""), Vec::<String>::new());
        // An interior empty argument is real: `sh -c ''` is a valid invocation, and dropping it would
        // change what a rule matches against.
        assert_eq!(split_argv(b"sh\0-c\0\0"), vec!["sh", "-c"]);
        assert_eq!(split_argv(b"a\0\0b\0"), vec!["a", "", "b"]);
    }

    #[test]
    fn spawn_events_carry_argv_and_truncation() {
        let mut record = ProcRecord::zeroed();
        record.header.ktime_ns = 2_000;
        record.header.tgid = 9;
        let bin = b"/bin/sh";
        record.filename[..bin.len()].copy_from_slice(bin);
        record.filename_len = u32::try_from(bin.len()).unwrap_or(0);
        let argv = b"sh\0-c\0curl https://x | sh\0";
        record.argv[..argv.len()].copy_from_slice(argv);
        record.argv_len = u32::try_from(argv.len()).unwrap_or(0);
        record.argc = 3;
        record.header.flags |= installscope_abi::FLAG_ARGV_TRUNCATED;

        let event = to_event(&Merged::Proc(Box::new(record)), 0).expect("event");
        match event.payload {
            Payload::ProcSpawn(p) => {
                assert_eq!(p.bin.as_deref(), Some("/bin/sh"));
                assert_eq!(p.argv, vec!["sh", "-c", "curl https://x | sh"]);
                // A rule pattern-matching a command line must know whether it saw all of it.
                assert!(p.argv_truncated);
            }
            _ => panic!("expected proc_spawn"),
        }
    }

    #[test]
    fn failed_syscalls_carry_an_errno_symbol() {
        let mut header = Header::zeroed();
        header.ktime_ns = 1_000;
        let merged = Merged::Fs {
            header,
            write_kind: installscope_abi::WRITE_OPEN,
            path: Some("/root/.ssh/id_rsa".to_string()),
            path_truncated: false,
            bytes: None,
            mode: 0,
            errno: Some(13),
        };
        let event = to_event(&merged, 0).expect("event");
        match event.payload {
            Payload::FsWrite(w) => {
                assert!(w.outcome.failed_known());
                assert_eq!(w.outcome.error.as_deref(), Some("EACCES"));
            }
            _ => panic!("expected fs_write"),
        }
    }

    #[test]
    fn unknown_errnos_are_numbered_not_guessed() {
        // A wrong errno symbol in evidence is worse than a number a reader can look up.
        assert_eq!(errno_name(2), "ENOENT");
        assert_eq!(errno_name(115), "EINPROGRESS");
        assert_eq!(errno_name(4_242), "errno 4242");
    }

    #[test]
    fn translated_events_round_trip_through_jsonl() {
        // The artifact is what downstream consumes, so translation output must survive serialization.
        let records = [
            fs(installscope_abi::WRITE_OPEN, Some("/work/a"), None),
            fs(installscope_abi::WRITE_WRITE, Some("/work/a"), Some(2048)),
        ];
        for merged in &records {
            let event = to_event(merged, 0).expect("event");
            let line = event
                .to_jsonl()
                .unwrap_or_else(|e| panic!("serialize: {e}"));
            let back = Event::from_jsonl(&line, 1).unwrap_or_else(|e| panic!("deserialize: {e}"));
            assert_eq!(event, back);
        }
    }

    #[test]
    fn a_record_predating_the_anchor_does_not_underflow() {
        // Programs are attached before the wall-clock anchor is taken, so an event can legitimately
        // carry an earlier ktime. Wrapping would produce a timestamp near u64::MAX and sort the event to
        // the end of the recording.
        let event =
            to_event(&fs(installscope_abi::WRITE_OPEN, Some("/x"), None), 999_999).expect("event");
        assert_eq!(event.meta.ts_ns, 0);
    }
}
