//! Merging and deduplicating events from a perf-buffer backend.
//!
//! Two problems the strace backend never had, both created by eBPF's delivery model:
//!
//! # 1. Per-CPU buffers arrive out of order
//!
//! A `PerfEventArray` has one ring per CPU, and the loader drains them in whatever order it polls. Two
//! events a microsecond apart on different CPUs can arrive in either order. Emitting them as they
//! arrive would produce a stream whose timestamps go backwards — which breaks the one thing a forensic
//! reader relies on: that the order they read is the order things happened.
//!
//! Handled with a bounded reorder window. Records are buffered and only released once they are older
//! than [`REORDER_WINDOW_NS`], by which point any straggler from another CPU has arrived. That trades a
//! small delay for a correctly ordered stream. A record arriving *after* its slot has been released is
//! counted as [`MergeStats::late_events`] and emitted anyway, out of order — dropping it would be worse,
//! and a visible count is better than a silent lie about ordering.
//!
//! # 2. Write bytes need a path, and the path came from a different event
//!
//! The kernel side reports `write(fd, count)` without a path, because resolving one inside a BPF program
//! means walking a dentry chain. So the fd table lives here: an open supplies `fd -> path`, subsequent
//! writes accumulate against it, and a close flushes the total. That is deliberately the same shape as
//! the strace backend's accounting, so both backends produce comparable byte volumes rather than
//! coincidentally similar ones.
//!
//! # What this module does NOT do
//!
//! It does not merge two *backends* into one stream. Running aya and strace simultaneously would double
//! every event, and deciding which copy to trust is a judgment a recorder should not make silently —
//! the same reason [`installscope_core::NetConnect::host`] stays `None`. `installscope record` picks one
//! backend per session and stamps it on every event. Cross-backend comparison happens in the parity
//! harness, which compares two separate recordings and reports differences rather than hiding them.

use std::collections::{BTreeMap, HashMap};

use installscope_abi::{FsRecord, Header, NO_FD};

/// How long to hold a record before releasing it, in nanoseconds.
///
/// 50 ms is generous for cross-CPU delivery skew on the same host, while keeping the memory held by the
/// window small. The cost of being wrong in the safe direction is latency; the cost of being wrong the
/// other way is a misordered stream.
pub const REORDER_WINDOW_NS: u64 = 50_000_000;

/// Cap on records held in the reorder window.
///
/// A burst that outruns the window releases early rather than growing without bound. Preferring a
/// possibly-misordered event over an OOM-killed recorder is the right trade: the recorder dying loses
/// everything, whereas early release loses only strict ordering, and [`MergeStats::forced_releases`]
/// records that it happened.
pub const MAX_PENDING: usize = 16_384;

/// Diagnostics from the merge stage. Feeds the PARTIAL decision, so nothing here is cosmetic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// Records accepted into the window.
    pub accepted: u64,
    /// Records released in order.
    pub released: u64,
    /// Records that arrived older than the last released timestamp. Emitted anyway, out of order.
    pub late_events: u64,
    /// Times the pending cap forced an early release.
    pub forced_releases: u64,
    /// Writes against a descriptor with no known path. Each one is a byte volume that cannot be
    /// attributed — usually an inherited or pre-existing descriptor.
    pub writes_without_path: u64,
    /// Bytes written that could not be attributed to a path.
    pub unattributed_bytes: u64,
    /// Descriptors closed that were never opened in this recording.
    pub closes_without_open: u64,
    /// Perf-buffer records the kernel reported losing. Non-zero forces PARTIAL: the stream is provably
    /// missing events.
    pub lost_records: u64,
}

impl MergeStats {
    /// True when the merge stage observed anything that makes the stream not provably whole.
    ///
    /// Deliberately narrow. Late events and forced releases affect *ordering*, not completeness, and
    /// unattributed writes are an expected consequence of inherited descriptors rather than data loss.
    /// Only genuinely missing records qualify — inflating this would make PARTIAL meaningless, which is
    /// the failure Phase 1 already had to fix once.
    #[must_use]
    pub const fn indicates_data_loss(&self) -> bool {
        self.lost_records > 0
    }
}

/// What a descriptor points at, and how much has been written to it.
#[derive(Debug, Clone)]
struct OpenFile {
    path: String,
    /// True when the recorded path was cut short by the kernel-side buffer.
    truncated: bool,
    bytes: u64,
    writes: u64,
    /// Timestamp of the most recent write, so the flushed event lands at the end of the burst rather
    /// than at the open.
    last_ktime_ns: u64,
}

/// One merged, ordered observation ready for translation into schema v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merged {
    /// A filesystem event carrying a resolved path where one is known.
    Fs {
        /// Provenance from the kernel side.
        header: Header,
        /// One of the `WRITE_*` constants from the ABI.
        write_kind: u32,
        /// Path, when known. `None` for a write against an unknown descriptor.
        path: Option<String>,
        /// True when the path was cut short.
        path_truncated: bool,
        /// Bytes, for an aggregated write.
        bytes: Option<u64>,
        /// Open flags or mode.
        mode: u32,
        /// Errno when the syscall failed.
        errno: Option<u32>,
    },
    /// A network connection attempt, passed through unchanged.
    Net(installscope_abi::NetRecord),
    /// A process spawn, passed through unchanged.
    Proc(Box<installscope_abi::ProcRecord>),
}

impl Merged {
    /// The kernel timestamp this observation carries, for ordering.
    #[must_use]
    pub const fn ktime_ns(&self) -> u64 {
        match self {
            Self::Fs { header, .. } => header.ktime_ns,
            Self::Net(r) => r.header.ktime_ns,
            Self::Proc(r) => r.header.ktime_ns,
        }
    }
}

/// A record waiting in the reorder window, still unprocessed.
///
/// Buffered *before* any fd-table work, which is the whole point: per-CPU rings deliver out of order, so
/// a write frequently arrives before the open that gives it a path. Run 33398685709 showed the cost of
/// getting this wrong — 83 writes and 262 KB unattributable because the open had not been seen yet.
#[derive(Debug, Clone)]
enum Buffered {
    Fs(Box<FsRecord>),
    Close { header: Header, fd: i32 },
    Net(installscope_abi::NetRecord),
    Proc(Box<installscope_abi::ProcRecord>),
}

impl Buffered {
    const fn ktime_ns(&self) -> u64 {
        match self {
            Self::Fs(record) => record.header.ktime_ns,
            Self::Close { header, .. } => header.ktime_ns,
            Self::Net(record) => record.header.ktime_ns,
            Self::Proc(record) => record.header.ktime_ns,
        }
    }
}

/// Buffers, orders, and aggregates records from a perf-buffer backend.
///
/// Feed records in arrival order; drain with [`Self::drain_ready`] periodically and [`Self::finish`]
/// once at the end.
///
/// # Why the fd table is updated on drain, not on push
///
/// Descriptor state is inherently ordered: an open establishes `fd -> path`, later writes accumulate
/// against it, a close finalizes the total. Applying those in arrival order gives wrong answers whenever
/// the ring buffers hand them over out of order, which they routinely do. So records are buffered raw,
/// released in timestamp order, and only *then* interpreted.
#[derive(Debug, Default)]
pub struct Merger {
    /// Pending records keyed by `(ktime_ns, sequence)`. The sequence disambiguates identical timestamps,
    /// which are common because `bpf_ktime_get_ns` has coarse resolution on some kernels — without it,
    /// a `BTreeMap` would silently drop the second event of a pair.
    pending: BTreeMap<(u64, u64), Buffered>,
    sequence: u64,
    /// Open descriptors per pid. Keyed by tgid because that is the process userspace means.
    files: HashMap<(u32, i32), OpenFile>,
    /// Highest timestamp released so far, for detecting late arrivals.
    last_released_ns: u64,
    stats: MergeStats,
}

impl Merger {
    /// A merger with the default window.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge diagnostics.
    #[must_use]
    pub const fn stats(&self) -> &MergeStats {
        &self.stats
    }

    /// Records that the kernel dropped `count` perf records because a ring was full.
    ///
    /// Reported by the loader from the perf buffer's own lost counter. Forces PARTIAL: unlike a
    /// reordering hiccup, this is provable data loss.
    pub fn note_lost(&mut self, count: u64) {
        self.stats.lost_records = self.stats.lost_records.saturating_add(count);
    }

    /// Accepts a filesystem record.
    pub fn push_fs(&mut self, record: &FsRecord) {
        self.stats.accepted += 1;
        self.enqueue(Buffered::Fs(Box::new(*record)));
    }

    /// Accepts a descriptor close.
    pub fn push_close(&mut self, header: &Header, fd: i32) {
        self.stats.accepted += 1;
        self.enqueue(Buffered::Close {
            header: *header,
            fd,
        });
    }

    /// Accepts a network record.
    pub fn push_net(&mut self, record: installscope_abi::NetRecord) {
        self.stats.accepted += 1;
        self.enqueue(Buffered::Net(record));
    }

    /// Accepts a process spawn.
    pub fn push_proc(&mut self, record: installscope_abi::ProcRecord) {
        self.stats.accepted += 1;
        self.enqueue(Buffered::Proc(Box::new(record)));
    }

    fn enqueue(&mut self, buffered: Buffered) {
        let ktime = buffered.ktime_ns();
        if ktime < self.last_released_ns {
            self.stats.late_events += 1;
        }
        self.sequence += 1;
        self.pending.insert((ktime, self.sequence), buffered);
    }

    /// Interprets one released record, updating descriptor state and producing events.
    fn process(&mut self, buffered: Buffered, out: &mut Vec<Merged>) {
        match buffered {
            Buffered::Fs(record) => self.process_fs(&record, out),
            Buffered::Close { header, fd } => match self.files.remove(&(header.tgid, fd)) {
                Some(file) => Self::flush_file(header.tgid, &file, out),
                None => self.stats.closes_without_open += 1,
            },
            Buffered::Net(record) => out.push(Merged::Net(record)),
            Buffered::Proc(record) => out.push(Merged::Proc(record)),
        }
    }

    fn process_fs(&mut self, record: &FsRecord, out: &mut Vec<Merged>) {
        let tgid = record.header.tgid;

        match record.write_kind {
            installscope_abi::WRITE_WRITE => self.accumulate_write(record, tgid, out),
            installscope_abi::WRITE_OPEN => {
                let path = String::from_utf8_lossy(record.path_bytes())
                    .trim_end_matches('\0')
                    .to_string();
                let truncated = record.header.has(installscope_abi::FLAG_PATH_TRUNCATED);

                // A successful open registers the descriptor so later writes resolve. A failed one does
                // not — there is no descriptor — but the attempt is still emitted below.
                if record.fd != NO_FD && !record.header.has(installscope_abi::FLAG_FAILED) {
                    // Reusing a descriptor without an intervening close (dup2, or a close we missed)
                    // must flush the old total rather than merge two files' bytes.
                    if let Some(previous) = self.files.remove(&(tgid, record.fd)) {
                        Self::flush_file(tgid, &previous, out);
                    }
                    self.files.insert(
                        (tgid, record.fd),
                        OpenFile {
                            path: path.clone(),
                            truncated,
                            bytes: 0,
                            writes: 0,
                            last_ktime_ns: record.header.ktime_ns,
                        },
                    );
                }

                out.push(Merged::Fs {
                    header: record.header,
                    write_kind: installscope_abi::WRITE_OPEN,
                    path: Some(path),
                    path_truncated: truncated,
                    bytes: None,
                    mode: record.mode,
                    errno: errno_of(record),
                });
            }
            _ => {
                // mkdir, rename, and friends: a path with no descriptor.
                let path = String::from_utf8_lossy(record.path_bytes())
                    .trim_end_matches('\0')
                    .to_string();
                out.push(Merged::Fs {
                    header: record.header,
                    write_kind: record.write_kind,
                    path: (!path.is_empty()).then_some(path),
                    path_truncated: record.header.has(installscope_abi::FLAG_PATH_TRUNCATED),
                    bytes: None,
                    mode: record.mode,
                    errno: errno_of(record),
                });
            }
        }
    }

    fn accumulate_write(&mut self, record: &FsRecord, tgid: u32, out: &mut Vec<Merged>) {
        if let Some(file) = self.files.get_mut(&(tgid, record.fd)) {
            file.bytes = file.bytes.saturating_add(record.bytes);
            file.writes += 1;
            file.last_ktime_ns = record.header.ktime_ns;
            return;
        }
        // No known path. Expected for descriptors inherited across fork or opened before the recording
        // started — stdout and stderr are the common case. Counted so the total is honest about what
        // could not be attributed, and emitted with `path: None` rather than guessed at.
        self.stats.writes_without_path += 1;
        self.stats.unattributed_bytes = self.stats.unattributed_bytes.saturating_add(record.bytes);
        out.push(Merged::Fs {
            header: record.header,
            write_kind: installscope_abi::WRITE_WRITE,
            path: None,
            path_truncated: false,
            bytes: Some(record.bytes),
            mode: 0,
            errno: None,
        });
    }

    /// Emits the aggregated byte total for a closed descriptor.
    fn flush_file(tgid: u32, file: &OpenFile, out: &mut Vec<Merged>) {
        if file.writes == 0 {
            return; // opened but never written; the open event already recorded it
        }
        let mut header = Header::zeroed();
        header.kind = installscope_abi::KIND_FS_WRITE;
        header.ktime_ns = file.last_ktime_ns;
        header.tgid = tgid;
        header.pid = tgid;
        out.push(Merged::Fs {
            header,
            write_kind: installscope_abi::WRITE_WRITE,
            path: Some(file.path.clone()),
            path_truncated: file.truncated,
            bytes: Some(file.bytes),
            mode: 0,
            errno: None,
        });
    }

    /// Releases every buffered record older than the reorder window.
    ///
    /// `now_ktime_ns` is the newest timestamp seen from any CPU; records more than
    /// [`REORDER_WINDOW_NS`] older than it are safe to interpret.
    pub fn drain_ready(&mut self, now_ktime_ns: u64) -> Vec<Merged> {
        let cutoff = now_ktime_ns.saturating_sub(REORDER_WINDOW_NS);
        let mut out = Vec::new();

        // Split off everything at or below the cutoff. BTreeMap keeps this ordered by construction.
        let ready: Vec<(u64, u64)> = self
            .pending
            .range(..=(cutoff, u64::MAX))
            .map(|(key, _)| *key)
            .collect();
        for key in ready {
            if let Some(buffered) = self.pending.remove(&key) {
                self.last_released_ns = self.last_released_ns.max(key.0);
                self.stats.released += 1;
                self.process(buffered, &mut out);
            }
        }

        // Over the cap: release the oldest regardless of the window rather than growing unbounded.
        while self.pending.len() > MAX_PENDING {
            let Some(key) = self.pending.keys().next().copied() else {
                break;
            };
            if let Some(buffered) = self.pending.remove(&key) {
                self.stats.forced_releases += 1;
                self.last_released_ns = self.last_released_ns.max(key.0);
                self.stats.released += 1;
                self.process(buffered, &mut out);
            }
        }

        // An aggregated write carries the timestamp of its last write, which can predate a plain event
        // released alongside it. Sorting the batch keeps the stream monotonic; a stable sort preserves
        // the relative order of events that share a timestamp.
        out.sort_by_key(Merged::ktime_ns);
        out
    }

    /// Flushes every descriptor still open and every buffered record, in order.
    ///
    /// Must be called once at end of session: the accumulated byte totals for files never explicitly
    /// closed exist only here, and losing them would silently understate write volume.
    pub fn finish(&mut self) -> Vec<Merged> {
        let mut out = Vec::new();

        let keys: Vec<(u64, u64)> = self.pending.keys().copied().collect();
        for key in keys {
            if let Some(buffered) = self.pending.remove(&key) {
                self.stats.released += 1;
                self.process(buffered, &mut out);
            }
        }

        let mut open: Vec<((u32, i32), OpenFile)> = self.files.drain().collect();
        // Deterministic order so a parity comparison is stable across runs.
        open.sort_by_key(|((tgid, fd), _)| (*tgid, *fd));
        for ((tgid, _), file) in open {
            Self::flush_file(tgid, &file, &mut out);
        }

        out.sort_by_key(Merged::ktime_ns);
        out
    }

    /// Descriptors currently tracked. Diagnostics only.
    #[must_use]
    pub fn tracked_files(&self) -> usize {
        self.files.len()
    }
}

fn errno_of(record: &FsRecord) -> Option<u32> {
    record
        .header
        .has(installscope_abi::FLAG_FAILED)
        .then_some(record.errno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use installscope_abi::{
        FLAG_FAILED, FLAG_PATH_TRUNCATED, KIND_FS_WRITE, WRITE_MKDIR, WRITE_OPEN, WRITE_WRITE,
    };

    fn fs_record(ktime: u64, tgid: u32, kind: u32, fd: i32, path: &str, bytes: u64) -> FsRecord {
        let mut record = FsRecord::zeroed();
        record.header.kind = KIND_FS_WRITE;
        record.header.ktime_ns = ktime;
        record.header.tgid = tgid;
        record.header.pid = tgid;
        record.write_kind = kind;
        record.fd = fd;
        record.bytes = bytes;
        let bytes_of_path = path.as_bytes();
        let len = bytes_of_path.len().min(installscope_abi::PATH_BUF_LEN);
        record.path[..len].copy_from_slice(&bytes_of_path[..len]);
        record.path_len = u32::try_from(len).unwrap_or(u32::MAX);
        record
    }

    fn net_record(ktime: u64) -> installscope_abi::NetRecord {
        let mut record = installscope_abi::NetRecord::zeroed();
        record.header.kind = installscope_abi::KIND_NET_CONNECT;
        record.header.ktime_ns = ktime;
        record
    }

    fn paths_of(events: &[Merged]) -> Vec<Option<&str>> {
        events
            .iter()
            .map(|e| match e {
                Merged::Fs { path, .. } => path.as_deref(),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn releases_in_timestamp_order_regardless_of_arrival_order() {
        // The core reordering case. Two CPUs deliver out of order; the stream must still read in the
        // order things happened, because that is the one guarantee a forensic reader depends on.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(3_000, 1, WRITE_MKDIR, NO_FD, "/third", 0));
        merger.push_fs(&fs_record(1_000, 1, WRITE_MKDIR, NO_FD, "/first", 0));
        merger.push_fs(&fs_record(2_000, 1, WRITE_MKDIR, NO_FD, "/second", 0));

        let released = merger.drain_ready(3_000 + REORDER_WINDOW_NS);
        assert_eq!(
            paths_of(&released),
            vec![Some("/first"), Some("/second"), Some("/third")],
            "events must be released in timestamp order"
        );
    }

    #[test]
    fn identical_timestamps_do_not_collide() {
        // bpf_ktime_get_ns has coarse resolution on some kernels, so simultaneous events are common. A
        // plain timestamp key would silently drop all but one — losing evidence with no error.
        let mut merger = Merger::new();
        for i in 0..5 {
            merger.push_fs(&fs_record(
                1_000,
                1,
                WRITE_MKDIR,
                NO_FD,
                &format!("/same-{i}"),
                0,
            ));
        }
        let released = merger.drain_ready(1_000 + REORDER_WINDOW_NS);
        assert_eq!(
            released.len(),
            5,
            "every event with an identical timestamp must survive"
        );
    }

    #[test]
    fn holds_events_inside_the_reorder_window() {
        // Releasing immediately would defeat the purpose: a straggler from another CPU would arrive
        // after its slot had passed.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(10_000, 1, WRITE_MKDIR, NO_FD, "/recent", 0));

        let released = merger.drain_ready(10_500);
        assert!(
            released.is_empty(),
            "an event newer than the window must not be released yet"
        );

        let released = merger.drain_ready(10_000 + REORDER_WINDOW_NS + 1);
        assert_eq!(released.len(), 1);
    }

    #[test]
    fn accumulates_write_bytes_against_the_open_path() {
        // The Phase 0 gap, closed on this backend too. The kernel side reports write(fd, count) with no
        // path; the fd table is what turns that into an attributable byte volume.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 7, WRITE_OPEN, 3, "/work/big.bin", 0));
        merger.push_fs(&fs_record(1_100, 7, WRITE_WRITE, 3, "", 4096));
        merger.push_fs(&fs_record(1_200, 7, WRITE_WRITE, 3, "", 2048));
        merger.push_fs(&fs_record(1_300, 7, WRITE_WRITE, 3, "", 1024));

        let mut header = Header::zeroed();
        header.tgid = 7;
        header.ktime_ns = 1_400;
        merger.push_close(&header, 3);

        let released = merger.drain_ready(2_000 + REORDER_WINDOW_NS);
        let byte_event = released
            .iter()
            .find(|e| matches!(e, Merged::Fs { bytes: Some(_), .. }))
            .expect("an aggregated byte event");

        match byte_event {
            Merged::Fs { path, bytes, .. } => {
                assert_eq!(path.as_deref(), Some("/work/big.bin"));
                assert_eq!(*bytes, Some(4096 + 2048 + 1024));
            }
            _ => panic!("expected an fs event"),
        }

        // One aggregate, not one per write.
        assert_eq!(
            released
                .iter()
                .filter(|e| matches!(e, Merged::Fs { bytes: Some(_), .. }))
                .count(),
            1,
            "writes must aggregate into a single event"
        );
    }

    #[test]
    fn a_reused_descriptor_does_not_merge_two_files() {
        // fd 3 is reopened without an intervening close. Merging the totals would attribute one file's
        // volume to another — a wrong number in a report, which is worse than no number.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 7, WRITE_OPEN, 3, "/work/first", 0));
        merger.push_fs(&fs_record(1_100, 7, WRITE_WRITE, 3, "", 500));
        merger.push_fs(&fs_record(1_200, 7, WRITE_OPEN, 3, "/work/second", 0));
        merger.push_fs(&fs_record(1_300, 7, WRITE_WRITE, 3, "", 700));

        let released = merger.finish();
        let totals: Vec<(Option<&str>, Option<u64>)> = released
            .iter()
            .filter_map(|e| match e {
                Merged::Fs {
                    path,
                    bytes: Some(b),
                    ..
                } => Some((path.as_deref(), Some(*b))),
                _ => None,
            })
            .collect();

        assert!(
            totals.contains(&(Some("/work/first"), Some(500))),
            "the first file's total must be flushed on reuse, got {totals:?}"
        );
        assert!(
            totals.contains(&(Some("/work/second"), Some(700))),
            "the second file starts a fresh total, got {totals:?}"
        );
    }

    #[test]
    fn descriptors_are_per_process() {
        // fd 3 in one process is unrelated to fd 3 in another. Sharing the table would cross-attribute
        // writes between processes.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 100, WRITE_OPEN, 3, "/a.txt", 0));
        merger.push_fs(&fs_record(1_100, 200, WRITE_OPEN, 3, "/b.txt", 0));
        merger.push_fs(&fs_record(1_200, 100, WRITE_WRITE, 3, "", 111));
        merger.push_fs(&fs_record(1_300, 200, WRITE_WRITE, 3, "", 222));

        let released = merger.finish();
        let totals: Vec<(Option<&str>, Option<u64>)> = released
            .iter()
            .filter_map(|e| match e {
                Merged::Fs {
                    path,
                    bytes: Some(b),
                    ..
                } => Some((path.as_deref(), Some(*b))),
                _ => None,
            })
            .collect();
        assert!(totals.contains(&(Some("/a.txt"), Some(111))), "{totals:?}");
        assert!(totals.contains(&(Some("/b.txt"), Some(222))), "{totals:?}");
    }

    #[test]
    fn an_unattributable_write_is_counted_not_guessed() {
        // A descriptor we never saw opened — inherited across fork, or predating the recording. The
        // bytes are real, so the event is emitted; the path is unknown, so it stays None. Inventing one
        // would place the write in a zone it may not belong to, which is how a fabricated critical
        // finding gets made.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 7, WRITE_WRITE, 99, "", 4096));

        let released = merger.drain_ready(1_000 + REORDER_WINDOW_NS);
        assert_eq!(released.len(), 1);
        match &released[0] {
            Merged::Fs { path, bytes, .. } => {
                assert_eq!(
                    *path, None,
                    "an unknown descriptor must not get a guessed path"
                );
                assert_eq!(*bytes, Some(4096));
            }
            _ => panic!("expected an fs event"),
        }
        assert_eq!(merger.stats().writes_without_path, 1);
        assert_eq!(merger.stats().unattributed_bytes, 4096);
    }

    #[test]
    fn a_failed_open_registers_no_descriptor_but_is_still_reported() {
        // An attempt to open a credential file that fails is evidence of intent. But it produces no
        // descriptor, so a later write to that number must not resolve to this path.
        let mut merger = Merger::new();
        let mut record = fs_record(1_000, 7, WRITE_OPEN, NO_FD, "/root/.ssh/id_rsa", 0);
        record.header.flags |= FLAG_FAILED;
        record.errno = 13; // EACCES
        merger.push_fs(&record);

        merger.push_fs(&fs_record(1_100, 7, WRITE_WRITE, 3, "", 128));

        let released = merger.drain_ready(2_000 + REORDER_WINDOW_NS);
        let open = released
            .iter()
            .find(|e| matches!(e, Merged::Fs { write_kind, .. } if *write_kind == WRITE_OPEN))
            .expect("the failed open must still be reported");
        match open {
            Merged::Fs { errno, path, .. } => {
                assert_eq!(*errno, Some(13));
                assert_eq!(path.as_deref(), Some("/root/.ssh/id_rsa"));
            }
            _ => unreachable!(),
        }
        assert_eq!(
            merger.stats().writes_without_path,
            1,
            "the write must not have resolved against a failed open"
        );
    }

    #[test]
    fn path_truncation_survives_aggregation() {
        // A truncated path must stay marked through the fd table, or the flushed byte event would
        // present a shortened path as complete.
        let mut merger = Merger::new();
        let mut open = fs_record(1_000, 7, WRITE_OPEN, 3, "/very/long/path", 0);
        open.header.flags |= FLAG_PATH_TRUNCATED;
        merger.push_fs(&open);
        merger.push_fs(&fs_record(1_100, 7, WRITE_WRITE, 3, "", 64));

        let released = merger.finish();
        let flushed = released
            .iter()
            .find(|e| matches!(e, Merged::Fs { bytes: Some(_), .. }))
            .expect("aggregated write");
        match flushed {
            Merged::Fs { path_truncated, .. } => assert!(
                *path_truncated,
                "truncation must survive into the aggregated event"
            ),
            _ => unreachable!(),
        }
    }

    #[test]
    fn finish_flushes_files_never_closed() {
        // An install killed mid-write, or a process that simply exits without closing. The bytes were
        // real; dropping them would understate volume silently.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 7, WRITE_OPEN, 3, "/work/unclosed", 0));
        merger.push_fs(&fs_record(1_100, 7, WRITE_WRITE, 3, "", 999));
        // Nothing is in the fd table yet: records are buffered raw and only interpreted on release, so
        // that out-of-order arrivals can be reordered before descriptor state is applied.
        assert_eq!(merger.tracked_files(), 0);

        let released = merger.finish();
        assert_eq!(merger.tracked_files(), 0);
        assert!(
            released.iter().any(|e| matches!(
                e,
                Merged::Fs { path: Some(p), bytes: Some(999), .. } if p == "/work/unclosed"
            )),
            "an unclosed file's total must still be emitted"
        );
    }

    #[test]
    fn a_write_arriving_before_its_open_still_resolves() {
        // THE case this design exists for. Per-CPU rings deliver out of order, so a write frequently
        // arrives before the open that names its descriptor. Run 33398685709 interpreted records on
        // arrival and lost 262 KB across 83 writes to "<unknown descriptor>" for exactly this reason.
        let mut merger = Merger::new();
        // Write first, open second — reversed arrival, correct timestamps.
        merger.push_fs(&fs_record(2_000, 7, WRITE_WRITE, 3, "", 4096));
        merger.push_fs(&fs_record(
            1_000,
            7,
            WRITE_OPEN,
            3,
            "/work/reordered.bin",
            0,
        ));

        let released = merger.finish();
        let attributed = released.iter().find_map(|e| match e {
            Merged::Fs {
                path: Some(path),
                bytes: Some(bytes),
                ..
            } => Some((path.clone(), *bytes)),
            _ => None,
        });
        assert_eq!(
            attributed,
            Some(("/work/reordered.bin".to_string(), 4096)),
            "the write must resolve against an open that arrived later"
        );
        assert_eq!(
            merger.stats().writes_without_path,
            0,
            "nothing should be unattributable once ordering is applied"
        );
    }

    #[test]
    fn released_batches_are_monotonic_in_time() {
        // An aggregated write carries the timestamp of its last write, which can predate a plain event
        // released in the same batch. Without the sort the stream would step backwards, breaking the one
        // guarantee a forensic reader relies on.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 7, WRITE_OPEN, 3, "/work/a", 0));
        merger.push_fs(&fs_record(1_100, 7, WRITE_WRITE, 3, "", 10));
        merger.push_fs(&fs_record(1_500, 7, WRITE_MKDIR, NO_FD, "/work/dir", 0));
        let mut header = Header::zeroed();
        header.tgid = 7;
        header.ktime_ns = 1_600;
        merger.push_close(&header, 3);

        let released = merger.drain_ready(2_000 + REORDER_WINDOW_NS);
        let times: Vec<u64> = released.iter().map(Merged::ktime_ns).collect();
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_eq!(times, sorted, "a released batch must be ordered: {times:?}");
    }

    #[test]
    fn late_arrivals_are_counted_and_still_emitted() {
        // A record older than what has already been released. Dropping it would lose evidence; emitting
        // it silently would misrepresent ordering. So: emit, and count.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(100_000, 1, WRITE_MKDIR, NO_FD, "/on-time", 0));
        let _ = merger.drain_ready(100_000 + REORDER_WINDOW_NS);

        merger.push_fs(&fs_record(1_000, 1, WRITE_MKDIR, NO_FD, "/very-late", 0));
        assert_eq!(merger.stats().late_events, 1);

        let released = merger.finish();
        assert_eq!(
            paths_of(&released),
            vec![Some("/very-late")],
            "a late event is still emitted rather than dropped"
        );
    }

    #[test]
    fn lost_records_force_partial_but_reordering_does_not() {
        // The PARTIAL signal must mean something. Reordering and unattributed writes are normal
        // consequences of how eBPF delivers events; only records the kernel says it dropped are
        // genuine data loss. Phase 1 already had to fix a case where PARTIAL fired on every recording.
        let mut merger = Merger::new();
        merger.push_fs(&fs_record(1_000, 7, WRITE_WRITE, 99, "", 10));
        merger.push_fs(&fs_record(500, 7, WRITE_MKDIR, NO_FD, "/late", 0));
        let _ = merger.drain_ready(1_000 + REORDER_WINDOW_NS);
        assert!(
            !merger.stats().indicates_data_loss(),
            "reordering and unattributed writes are not data loss"
        );

        merger.note_lost(3);
        assert!(
            merger.stats().indicates_data_loss(),
            "records the kernel dropped are data loss"
        );
        assert_eq!(merger.stats().lost_records, 3);
    }

    #[test]
    fn net_and_proc_records_participate_in_ordering() {
        // All three record kinds share one perf buffer, so they must order against each other rather
        // than each maintaining its own sequence.
        let mut merger = Merger::new();
        merger.push_net(net_record(2_000));
        merger.push_fs(&fs_record(1_000, 1, WRITE_MKDIR, NO_FD, "/first", 0));
        merger.push_net(net_record(3_000));

        let released = merger.drain_ready(3_000 + REORDER_WINDOW_NS);
        let times: Vec<u64> = released.iter().map(Merged::ktime_ns).collect();
        assert_eq!(times, vec![1_000, 2_000, 3_000]);
    }

    #[test]
    fn the_pending_cap_forces_release_rather_than_growing() {
        // A burst that outruns the window must not grow memory without bound: an OOM-killed recorder
        // loses everything, whereas early release loses only strict ordering — and says so.
        let mut merger = Merger::new();
        for i in 0..(MAX_PENDING as u64 + 10) {
            // All timestamps recent, so the window alone would release nothing.
            merger.push_fs(&fs_record(
                1_000_000_000 + i,
                1,
                WRITE_MKDIR,
                NO_FD,
                "/burst",
                0,
            ));
        }
        let released = merger.drain_ready(1_000_000_000);
        assert!(
            !released.is_empty(),
            "the cap must force release even inside the window"
        );
        assert!(merger.stats().forced_releases > 0);
    }
}
