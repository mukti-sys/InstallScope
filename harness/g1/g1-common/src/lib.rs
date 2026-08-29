//! Event struct shared between the G1 eBPF program and its loader.
//!
//! Gate tooling, not product code (see harness/README.md). Phase 2 defines the real event model in
//! `core/src/events.rs` per Architecture.md §3; this exists only to prove one event can cross the
//! kernel/userspace boundary on a GitHub runner.
#![no_std]

/// Fixed-size comm buffer. `TASK_COMM_LEN` in the kernel is 16.
pub const COMM_LEN: usize = 16;

/// One observed `execve` entry.
///
/// `#[repr(C)]` because the kernel side writes it and userspace reads it byte-for-byte. Every field
/// is a fixed-width integer or a fixed-size array, so there is no padding ambiguity between the
/// bpfel-unknown-none and host builds.
///
/// Deliberately omits the executable path: reading a userspace string pointer safely is CO-RE work
/// that belongs in Phase 2. `comm` comes from a single helper call and is enough to prove delivery.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Nanoseconds since boot, from `bpf_ktime_get_ns`. Not epoch time; the loader records a
    /// wall-clock anchor separately rather than converting and risking a fabricated timestamp.
    pub ktime_ns: u64,
    /// Thread group ID (upper 32 bits of `bpf_get_current_pid_tgid`).
    pub tgid: u32,
    /// Thread ID (lower 32 bits).
    pub pid: u32,
    /// Real UID (lower 32 bits of `bpf_get_current_uid_gid`).
    pub uid: u32,
    /// Length of the valid prefix of `comm`.
    pub comm_len: u32,
    /// Process name, NUL-padded.
    pub comm: [u8; COMM_LEN],
}

impl ExecEvent {
    pub const fn zeroed() -> Self {
        Self {
            ktime_ns: 0,
            tgid: 0,
            pid: 0,
            uid: 0,
            comm_len: 0,
            comm: [0u8; COMM_LEN],
        }
    }

    /// `comm` as a &str, truncated at the first NUL. Returns `None` on non-UTF-8 rather than
    /// lossily substituting characters — a mangled process name in evidence output would be a
    /// small fabrication (Rules.md §5).
    pub fn comm_str(&self) -> Option<&str> {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMM_LEN)
            .min(COMM_LEN);
        core::str::from_utf8(&self.comm[..end]).ok()
    }
}

// No aya dependency here on purpose: this crate must compile for bpfel-unknown-none, and the
// loader reads events out of the perf buffer with `read_unaligned` rather than via `aya::Pod`, so
// no trait impl is needed on either side.
