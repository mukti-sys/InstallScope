//! Fixed-layout structs shared between the eBPF programs and the userspace loader.
//!
//! This crate is the kernel/userspace ABI. It is `no_std` and dependency-free because it must compile
//! for `bpfel-unknown-none`, where nothing else is available — and that constraint is deliberate:
//! anything that cannot cross this boundary has no business being in the wire format.
//!
//! # Why not reuse `installscope-core`?
//!
//! [`installscope_core::Event`](../installscope_core/events/struct.Event.html) is the *output* schema:
//! `String`, `Vec`, `Option`, serde. None of that exists in a BPF program, where every buffer is
//! fixed-size and every allocation is impossible. So the kernel side emits these flat records, and the
//! loader translates them into schema v1. The translation is the only place the two representations
//! meet, which keeps the ABI free to change without touching the artifact format that reports and the
//! registry depend on.
//!
//! # Layout rules, and why each matters
//!
//! Every struct here is `#[repr(C)]` with fixed-width fields and explicit padding, because the kernel
//! writes bytes that userspace reads back by pointer cast. Three specific hazards:
//!
//! 1. **No `usize`/`isize`.** They differ between a BPF target and the host. Always `u32`/`u64`.
//! 2. **No implicit padding.** The BPF verifier rejects programs that leak uninitialized stack bytes
//!    into a map, so every struct is padded explicitly and zero-initialized.
//! 3. **No enums with data.** A niche-optimized layout is not something to rely on across an ABI;
//!    discriminants are plain `u32` constants.
//!
//! # Truncation is recorded, never hidden
//!
//! Paths can exceed [`PATH_BUF_LEN`] and argv can exceed [`ARGV_BUF_LEN`]. When that happens the
//! record carries a truncation flag rather than a silently shortened value. A rule that pattern-matches
//! a command line must know whether it saw all of it — `Rules.md` §5 forbids presenting a partial
//! decode as a whole one.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Bytes reserved for a path. Linux's `PATH_MAX` is 4096, but a BPF program has a 512-byte stack, so
/// a full-size buffer must live in a per-CPU map rather than on the stack.
///
/// 512 is chosen against observed data rather than taste: in the Phase 1 corpus the longest path in a
/// real `npm install` recording was well under 300 bytes (deep `node_modules` nesting is the driver).
/// Paths longer than this are recorded with [`FLAG_PATH_TRUNCATED`] set.
pub const PATH_BUF_LEN: usize = 512;

/// Arguments captured per spawn.
///
/// Eight is enough for the shapes that matter: `sh -c '<script>'` is three, and a package manager
/// invocation is rarely more than six. Overruns set [`FLAG_ARGV_TRUNCATED`].
pub const ARGV_MAX_ARGS: usize = 8;

/// Bytes reserved per argument, including its NUL terminator.
///
/// Fixed-width slots rather than a packed buffer, and the reason is the BPF verifier rather than
/// taste. A packed layout needs a running cursor, which makes each write a variable-offset,
/// variable-size access into a map value — and the verifier rejects those outright:
///
/// ```text
/// invalid access to map value, value_size=1600 off=595 size=1023
/// R1 min value is outside of the allowed memory range
/// ```
///
/// With fixed slots the offset is `i * ARGV_ARG_LEN` for a constant `i` after loop unrolling, and the
/// size is a constant, so the check is trivial.
///
/// 256 bytes because the highest-value finding shape in the corpus is a shell command piping a
/// download into an interpreter, and those are typically well under 200 characters. A longer argument
/// is truncated with [`FLAG_ARGV_TRUNCATED`] set — never silently shortened.
pub const ARGV_ARG_LEN: usize = 256;

/// Total argv buffer: [`ARGV_MAX_ARGS`] slots of [`ARGV_ARG_LEN`] bytes.
pub const ARGV_BUF_LEN: usize = ARGV_MAX_ARGS * ARGV_ARG_LEN;

/// `TASK_COMM_LEN` in the kernel.
pub const COMM_LEN: usize = 16;

/// Maximum IPv6 address bytes; IPv4 uses the first four.
pub const ADDR_LEN: usize = 16;

// ---------------------------------------------------------------------------------------------
// Record kinds
// ---------------------------------------------------------------------------------------------

/// A filesystem write.
pub const KIND_FS_WRITE: u32 = 1;
/// An outbound connection attempt.
pub const KIND_NET_CONNECT: u32 = 2;
/// A process execution.
pub const KIND_PROC_SPAWN: u32 = 3;
/// A read of a path the loader's filter considers interesting.
///
/// **Reserved, not emitted.** `Phases.md`:23 scopes the aya backend to writes, connects, and spawns, and
/// recording credential reads is a permanent strace-backend capability — the filter that selects them is
/// a path list in the strace parser, editable without touching kernel code. The discriminant stays
/// defined so the loader's decode path handles it if a future phase promotes reads through `Scope.md`,
/// rather than leaving a hole in the numbering.
pub const KIND_FS_READ: u32 = 4;
/// A descriptor was closed. Carries no path; lets the loader retire an fd-table entry and flush that
/// descriptor's accumulated write volume at the right moment.
pub const KIND_FD_CLOSE: u32 = 5;

// ---------------------------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------------------------

/// The path did not fit in [`PATH_BUF_LEN`] and is a prefix of the real one.
pub const FLAG_PATH_TRUNCATED: u32 = 1 << 0;
/// The argv did not fit in [`ARGV_BUF_LEN`].
pub const FLAG_ARGV_TRUNCATED: u32 = 1 << 1;
/// The syscall returned an error. The kernel side records the attempt anyway: an attempt to read
/// `~/.ssh/id_rsa` that fails still says something about intent.
pub const FLAG_FAILED: u32 = 1 << 2;
/// The path was reconstructed from a dentry walk that hit its iteration limit, so it may be missing
/// leading components. Distinct from [`FLAG_PATH_TRUNCATED`], which loses the *tail*.
pub const FLAG_PATH_INCOMPLETE: u32 = 1 << 3;
/// The address family was neither IPv4 nor IPv6.
pub const FLAG_ADDR_UNKNOWN: u32 = 1 << 4;

// ---------------------------------------------------------------------------------------------
// Write kinds, mirroring installscope_core::WriteKind
// ---------------------------------------------------------------------------------------------

/// Opened with write intent.
pub const WRITE_OPEN: u32 = 1;
/// Bytes actually written.
pub const WRITE_WRITE: u32 = 2;
/// Created.
pub const WRITE_CREATE: u32 = 3;
/// Truncated.
pub const WRITE_TRUNCATE: u32 = 4;
/// Directory created.
pub const WRITE_MKDIR: u32 = 5;
/// Renamed.
pub const WRITE_RENAME: u32 = 6;
/// Deleted.
pub const WRITE_DELETE: u32 = 7;
/// Symlinked.
pub const WRITE_SYMLINK: u32 = 8;
/// Hard-linked.
pub const WRITE_HARDLINK: u32 = 9;
/// Mode changed.
pub const WRITE_CHMOD: u32 = 10;
/// Ownership changed.
pub const WRITE_CHOWN: u32 = 11;

/// Address family: IPv4.
pub const AF_INET4: u32 = 2;
/// Address family: IPv6.
pub const AF_INET6: u32 = 10;

/// Header common to every record.
///
/// Sits first in each struct so the loader can read the kind before deciding how to interpret the
/// rest, which is what allows one perf buffer to carry mixed record types.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// One of the `KIND_*` constants.
    pub kind: u32,
    /// Bitwise OR of the `FLAG_*` constants.
    pub flags: u32,
    /// `bpf_ktime_get_ns()`: nanoseconds since boot, monotonic.
    ///
    /// Not epoch time. The loader anchors this against a single wall-clock reading taken at session
    /// start, exactly as the strace backend does — converting per event would invite clock skew into
    /// evidence.
    pub ktime_ns: u64,
    /// Thread group id, i.e. what userspace calls the pid.
    pub tgid: u32,
    /// Thread id.
    pub pid: u32,
    /// Parent thread group id, for reconstructing the process tree.
    pub ppid: u32,
    /// Real uid.
    pub uid: u32,
    /// Process name, NUL-padded.
    pub comm: [u8; COMM_LEN],
}

impl Header {
    /// An all-zero header.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            flags: 0,
            ktime_ns: 0,
            tgid: 0,
            pid: 0,
            ppid: 0,
            uid: 0,
            comm: [0; COMM_LEN],
        }
    }

    /// True when `flag` is set.
    #[must_use]
    pub const fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// `comm` up to its first NUL, as UTF-8.
    ///
    /// Returns `None` on invalid UTF-8 rather than substituting replacement characters: a mangled
    /// process name in a forensic report is a small fabrication.
    #[must_use]
    pub fn comm_str(&self) -> Option<&str> {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMM_LEN)
            .min(COMM_LEN);
        core::str::from_utf8(self.comm.get(..end)?).ok()
    }
}

/// A filesystem write or read.
///
/// Field order is chosen so the struct has no implicit padding: the `u64` sits immediately after the
/// 48-byte header (both 8-aligned), then the `u32`s, then an explicit pad, then the buffer. The
/// verifier rejects programs that copy uninitialized stack bytes into a map, so every byte must belong
/// to a named field.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FsRecord {
    /// Common header. `kind` is [`KIND_FS_WRITE`] or [`KIND_FS_READ`].
    pub header: Header,
    /// Bytes transferred, for [`WRITE_WRITE`]. Zero otherwise.
    ///
    /// This is the *requested* count from syscall entry, not the returned one: a short write would
    /// overstate it. The loader records the distinction rather than presenting it as exact.
    pub bytes: u64,
    /// One of the `WRITE_*` constants. Zero for reads.
    pub write_kind: u32,
    /// Valid bytes in [`Self::path`].
    pub path_len: u32,
    /// Open flags or mode, as the kernel saw them.
    pub mode: u32,
    /// Errno when [`FLAG_FAILED`] is set.
    pub errno: u32,
    /// File descriptor this record concerns.
    ///
    /// For an open, the descriptor returned — which is what lets userspace build the fd table that
    /// gives a later `write` its path. For a write, the descriptor written to. [`NO_FD`] when the
    /// record has no descriptor.
    pub fd: i32,
    /// Explicit padding to an 8-byte boundary.
    pub _pad: u32,
    /// The path, not NUL-terminated; use [`Self::path_len`].
    pub path: [u8; PATH_BUF_LEN],
}

/// Sentinel for [`FsRecord::fd`] when no descriptor applies.
pub const NO_FD: i32 = -1;

impl FsRecord {
    /// An all-zero record with no descriptor.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            header: Header::zeroed(),
            bytes: 0,
            write_kind: 0,
            path_len: 0,
            mode: 0,
            errno: 0,
            fd: NO_FD,
            _pad: 0,
            path: [0; PATH_BUF_LEN],
        }
    }

    /// The recorded path bytes, bounded by [`Self::path_len`].
    #[must_use]
    pub fn path_bytes(&self) -> &[u8] {
        let len = (self.path_len as usize).min(PATH_BUF_LEN);
        self.path.get(..len).unwrap_or(&[])
    }
}

/// An outbound connection attempt.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NetRecord {
    /// Common header. `kind` is [`KIND_NET_CONNECT`].
    pub header: Header,
    /// [`AF_INET4`] or [`AF_INET6`].
    pub family: u32,
    /// Destination port, host byte order. The kernel side converts from network order.
    pub port: u16,
    /// Explicit padding so the struct has no implicit holes.
    pub _pad: u16,
    /// Destination address. IPv4 occupies the first four bytes.
    pub addr: [u8; ADDR_LEN],
    /// Errno when [`FLAG_FAILED`] is set.
    pub errno: u32,
    /// Padding to an 8-byte boundary.
    pub _pad2: u32,
}

impl NetRecord {
    /// An all-zero record.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            header: Header::zeroed(),
            family: 0,
            port: 0,
            _pad: 0,
            addr: [0; ADDR_LEN],
            errno: 0,
            _pad2: 0,
        }
    }
}

/// A process execution.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProcRecord {
    /// Common header. `kind` is [`KIND_PROC_SPAWN`].
    pub header: Header,
    /// Valid bytes in [`Self::filename`].
    pub filename_len: u32,
    /// Valid bytes in [`Self::argv`].
    pub argv_len: u32,
    /// Number of argv entries the kernel side managed to copy.
    pub argc: u32,
    /// Padding to an 8-byte boundary.
    pub _pad: u32,
    /// Executable path.
    pub filename: [u8; PATH_BUF_LEN],
    /// Arguments in fixed-width slots of [`ARGV_ARG_LEN`] bytes, each NUL-terminated.
    ///
    /// Slot `i` starts at `i * ARGV_ARG_LEN`. Fixed slots rather than a packed buffer because the BPF
    /// verifier rejects variable-offset writes into a map value; see [`ARGV_ARG_LEN`].
    pub argv: [u8; ARGV_BUF_LEN],
}

impl ProcRecord {
    /// An all-zero record.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            header: Header::zeroed(),
            filename_len: 0,
            argv_len: 0,
            argc: 0,
            _pad: 0,
            filename: [0; PATH_BUF_LEN],
            argv: [0; ARGV_BUF_LEN],
        }
    }

    /// The recorded executable path bytes.
    #[must_use]
    pub fn filename_bytes(&self) -> &[u8] {
        let len = (self.filename_len as usize).min(PATH_BUF_LEN);
        self.filename.get(..len).unwrap_or(&[])
    }

    /// The recorded argv bytes, still NUL-separated.
    #[must_use]
    pub fn argv_bytes(&self) -> &[u8] {
        let len = (self.argv_len as usize).min(ARGV_BUF_LEN);
        self.argv.get(..len).unwrap_or(&[])
    }

    /// Argument `index`, up to its NUL terminator.
    ///
    /// Returns `None` past [`Self::argc`], so a slot that was never written is never read as an empty
    /// argument — `sh -c ''` and `sh -c` are different invocations and a rule may treat them differently.
    #[must_use]
    pub fn arg(&self, index: usize) -> Option<&[u8]> {
        if index >= self.argc as usize || index >= ARGV_MAX_ARGS {
            return None;
        }
        let start = index * ARGV_ARG_LEN;
        let slot = self.argv.get(start..start + ARGV_ARG_LEN)?;
        let end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
        slot.get(..end)
    }
}

/// The largest record, which sizes the loader's read buffer.
///
/// A perf buffer read must be able to hold whichever record arrives, and the loader has no way to know
/// in advance which that will be.
pub const MAX_RECORD_SIZE: usize = core::mem::size_of::<ProcRecord>();

// ---------------------------------------------------------------------------------------------
// Debug impls
//
// Hand-written rather than derived: the buffers are 512 and 1024 bytes, and a derived Debug would print
// every byte — turning one log line into a screenful and burying whatever was being diagnosed. These
// print the fields a human actually needs, with paths as text.
// ---------------------------------------------------------------------------------------------

impl core::fmt::Debug for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Header")
            .field("kind", &self.kind)
            .field("flags", &self.flags)
            .field("ktime_ns", &self.ktime_ns)
            .field("tgid", &self.tgid)
            .field("pid", &self.pid)
            .field("comm", &self.comm_str().unwrap_or("<non-utf8>"))
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for FsRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FsRecord")
            .field("header", &self.header)
            .field("write_kind", &self.write_kind)
            .field("fd", &self.fd)
            .field("bytes", &self.bytes)
            .field("path_len", &self.path_len)
            .field(
                "path",
                &core::str::from_utf8(self.path_bytes()).unwrap_or("<non-utf8>"),
            )
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for NetRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NetRecord")
            .field("header", &self.header)
            .field("family", &self.family)
            .field("port", &self.port)
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ProcRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProcRecord")
            .field("header", &self.header)
            .field(
                "filename",
                &core::str::from_utf8(self.filename_bytes()).unwrap_or("<non-utf8>"),
            )
            .field("argc", &self.argc)
            .field("argv_len", &self.argv_len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one property that silently corrupts evidence if it breaks: the kernel and userspace must
    /// agree byte-for-byte. A layout change on either side turns a path into garbage without any
    /// error surfacing, so the sizes are asserted rather than assumed.
    #[test]
    fn layouts_are_stable() {
        assert_eq!(core::mem::size_of::<Header>(), 48, "Header layout changed");
        assert_eq!(core::mem::align_of::<Header>(), 8);

        // Header 48 + bytes 8 + write_kind 4 + path_len 4 + mode 4 + errno 4 + fd 4 + pad 4 + 512
        assert_eq!(
            core::mem::size_of::<FsRecord>(),
            592,
            "FsRecord layout changed"
        );
        assert_eq!(
            core::mem::size_of::<NetRecord>(),
            80,
            "NetRecord layout changed"
        );
        assert_eq!(
            core::mem::size_of::<ProcRecord>(),
            2624,
            "ProcRecord layout changed"
        );
        assert_eq!(MAX_RECORD_SIZE, core::mem::size_of::<ProcRecord>());
    }

    #[test]
    fn no_implicit_padding_in_records() {
        // The BPF verifier rejects programs that copy uninitialized stack bytes into a map, so every
        // byte of these structs must be accounted for by a named field.
        assert_eq!(
            core::mem::size_of::<Header>(),
            4 + 4 + 8 + 4 + 4 + 4 + 4 + COMM_LEN
        );
        assert_eq!(
            core::mem::size_of::<FsRecord>(),
            core::mem::size_of::<Header>() + 8 + 4 + 4 + 4 + 4 + 4 + 4 + PATH_BUF_LEN
        );
        assert_eq!(
            core::mem::size_of::<NetRecord>(),
            core::mem::size_of::<Header>() + 4 + 2 + 2 + ADDR_LEN + 4 + 4
        );
        assert_eq!(
            core::mem::size_of::<ProcRecord>(),
            core::mem::size_of::<Header>() + 4 + 4 + 4 + 4 + PATH_BUF_LEN + ARGV_BUF_LEN
        );
    }

    #[test]
    fn a_record_with_no_descriptor_is_distinguishable_from_fd_zero() {
        // fd 0 is stdin, a perfectly valid write target. Defaulting to 0 would make "no descriptor"
        // indistinguishable from "wrote to stdin", so the sentinel is negative — asserted at compile
        // time below, and checked here on a real value.
        const _: () = assert!(
            NO_FD < 0,
            "the no-descriptor sentinel must not be a valid fd"
        );
        let record = FsRecord::zeroed();
        assert_eq!(record.fd, NO_FD);
    }

    #[test]
    fn comm_reads_up_to_the_nul() {
        let mut header = Header::zeroed();
        header.comm[..4].copy_from_slice(b"node");
        assert_eq!(header.comm_str(), Some("node"));

        // A full-width comm with no NUL must not read past the buffer.
        let mut full = Header::zeroed();
        full.comm = [b'x'; COMM_LEN];
        assert_eq!(full.comm_str(), Some("xxxxxxxxxxxxxxxx"));

        // Invalid UTF-8 yields None rather than a lossy substitution.
        let mut bad = Header::zeroed();
        bad.comm[0] = 0xff;
        assert_eq!(bad.comm_str(), None);
    }

    #[test]
    fn length_fields_bound_the_buffers() {
        // A kernel bug or a hostile value must not let a length field read past the array. These
        // accessors are the only sanctioned way in, precisely so that clamp lives in one place.
        let mut record = FsRecord::zeroed();
        record.path[..5].copy_from_slice(b"/tmp/");
        record.path_len = u32::MAX;
        assert_eq!(record.path_bytes().len(), PATH_BUF_LEN);

        record.path_len = 5;
        assert_eq!(record.path_bytes(), b"/tmp/");

        let mut proc_record = ProcRecord::zeroed();
        proc_record.argv_len = u32::MAX;
        assert_eq!(proc_record.argv_bytes().len(), ARGV_BUF_LEN);
        proc_record.filename_len = u32::MAX;
        assert_eq!(proc_record.filename_bytes().len(), PATH_BUF_LEN);
    }

    #[test]
    fn arguments_read_from_fixed_slots() {
        // Fixed-width slots exist because the verifier rejects variable-offset map writes. The accessor
        // is the only sanctioned way in, so the slot arithmetic lives in one place.
        let mut record = ProcRecord::zeroed();
        record.argc = 3;
        for (index, text) in [b"sh".as_slice(), b"-c", b"curl x | sh"].iter().enumerate() {
            let start = index * ARGV_ARG_LEN;
            record.argv[start..start + text.len()].copy_from_slice(text);
        }

        assert_eq!(record.arg(0), Some(b"sh".as_slice()));
        assert_eq!(record.arg(1), Some(b"-c".as_slice()));
        assert_eq!(record.arg(2), Some(b"curl x | sh".as_slice()));
        // Past argc is None, not an empty argument: `sh -c ''` and `sh -c` are different invocations.
        assert_eq!(record.arg(3), None);
        assert_eq!(record.arg(ARGV_MAX_ARGS), None);
        assert_eq!(record.arg(usize::MAX), None);
    }

    #[test]
    fn an_empty_argument_is_preserved() {
        // An interior empty argument is real. Reading it as absent would change what a rule matches.
        let mut record = ProcRecord::zeroed();
        record.argc = 2;
        record.argv[..2].copy_from_slice(b"sh");
        // Slot 1 left zeroed: an empty string.
        assert_eq!(record.arg(0), Some(b"sh".as_slice()));
        assert_eq!(record.arg(1), Some(b"".as_slice()));
    }

    #[test]
    fn a_full_slot_reads_to_its_end() {
        // A maximal argument has no NUL inside its slot, so the reader must stop at the slot boundary
        // rather than running into the next argument.
        let mut record = ProcRecord::zeroed();
        record.argc = 2;
        record.argv[..ARGV_ARG_LEN].fill(b'x');
        record.argv[ARGV_ARG_LEN..ARGV_ARG_LEN + 3].copy_from_slice(b"end");
        assert_eq!(record.arg(0).map(<[u8]>::len), Some(ARGV_ARG_LEN));
        assert_eq!(record.arg(1), Some(b"end".as_slice()));
    }

    #[test]
    fn flags_are_distinct_bits() {
        let all = [
            FLAG_PATH_TRUNCATED,
            FLAG_ARGV_TRUNCATED,
            FLAG_FAILED,
            FLAG_PATH_INCOMPLETE,
            FLAG_ADDR_UNKNOWN,
        ];
        let mut seen = 0u32;
        for flag in all {
            assert_eq!(flag.count_ones(), 1, "{flag} is not a single bit");
            assert_eq!(seen & flag, 0, "{flag} collides with an earlier flag");
            seen |= flag;
        }
    }

    #[test]
    fn header_flag_test_works() {
        let mut header = Header::zeroed();
        assert!(!header.has(FLAG_FAILED));
        header.flags = FLAG_FAILED | FLAG_PATH_TRUNCATED;
        assert!(header.has(FLAG_FAILED));
        assert!(header.has(FLAG_PATH_TRUNCATED));
        assert!(!header.has(FLAG_ARGV_TRUNCATED));
    }
}
