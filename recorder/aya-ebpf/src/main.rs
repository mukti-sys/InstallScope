//! eBPF programs for the InstallScope aya backend (Phase 2, `Phases.md`:22).
//!
//! Records the three event classes Phase 2 calls for — filesystem writes, TCP connects, and process
//! spawns — and pushes them to userspace as [`installscope_abi`] records.
//!
//! # UNVERIFIED CODE
//!
//! **None of this has been compiled or loaded.** It was written on a Windows machine with no Linux
//! kernel and no ability to build for `bpfel-unknown-none`. G1 (run #33297876067) proved only that a
//! *tracepoint* program using `bpf_get_current_comm` loads on `ubuntu-latest`; it explicitly did not
//! prove the capabilities this file needs. `Rules.md` §5 says admitted uncertainty beats
//! plausible-looking wrong code, so the specific assumptions are listed below rather than buried:
//!
//! 1. **Syscall tracepoint argument offsets.** `TracePointContext::read_at` needs a byte offset into
//!    the tracepoint's format record. The offsets used here are the conventional layout for
//!    `syscalls/sys_enter_*` on x86-64 (8-byte header, then 8 bytes per argument), but the authoritative
//!    source is `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format` on the target kernel.
//!    The workflow dumps those files, so a mismatch is diagnosable rather than mysterious.
//! 2. **`bpf_probe_read_user_str_bytes` semantics.** Assumed to return the byte slice including the
//!    NUL terminator, which is why lengths are adjusted below. Verify against the aya 0.1.1 docs.
//! 3. **Per-CPU scratch maps.** Records exceed the 512-byte BPF stack, so they are built in a
//!    `PerCpuArray` and copied out. This is the standard workaround; the verifier's exact tolerance for
//!    it on this kernel is unproven.
//! 4. **Entry/exit correlation through a `HashMap`.** Standard practice, but map-in-tracepoint on this
//!    kernel is unproven, and a dropped entry silently loses one open.
//! 5. **Verifier acceptance overall.** Loop bounds, bounds checks, and program size all have to satisfy
//!    the verifier, and no amount of local reasoning substitutes for loading it.
//!
//! Expect the first real build to fail. The point of writing it now is that the *shape* — which
//! syscalls, which fields, which truncation semantics — is a design decision that can be reviewed
//! independently of whether it compiles.
//!
//! # What is deliberately absent
//!
//! - **Credential and environment reads.** `Phases.md`:23 scopes this backend to "fs write, tcp
//!   connect, proc spawn". Reads are not on that list, and the filter that selects interesting ones is a
//!   path list living in the strace parser — a place it can be edited without touching kernel code.
//!   Decided as a **permanent strace-backend advantage** rather than deferred work, so a future reader
//!   does not widen these probes past the boundary `Scope.md` draws.
//!
//!   The consequence is real: an install reading `~/.ssh/id_rsa` produces a `high` finding
//!   (Architecture.md §4) under strace and nothing here. The two backends are therefore *not*
//!   interchangeable, and Phase 3's report must not present an aya recording as equivalent coverage.
//!   [`installscope_recorder::parity`] encodes this as an expected difference and keeps it visible in the
//!   per-class counts.
//! - **Path resolution from dentries.** Reading a full path from a `struct file` requires walking the
//!   dentry chain with CO-RE, which is the single hardest part of a file probe. These programs read the
//!   *userspace path argument* instead, which is what the process asked for rather than where it landed.
//!   Consequence: paths are relative when the process passed a relative path, so the loader marks them
//!   `Unresolved` exactly as the strace backend does. Symlinks are not resolved either. This is the main
//!   fidelity gap versus strace's `-yy`, and it is stated rather than papered over.
//! - **DNS payload parsing.** Reading a datagram payload and decoding a DNS question inside a BPF
//!   program is materially harder than doing it in userspace, and the Phase 1 experience — two rounds to
//!   find that glibc batches queries through `sendmmsg` — suggests it would be worse here. The aya
//!   backend therefore produces no `dns_query` events, and full parity with strace is not achievable on
//!   that event class. Recorded as a known gap in `Memory.md`, not a bug to fix later.
//! - **Byte-accurate write volume.** `sys_enter_write` sees the *requested* count, not the returned
//!   one. A short write would overstate the volume, so these programs record the request and the loader
//!   labels it accordingly.
//!
//! # System-wide by nature, scoped by policy
//!
//! strace traces one process; these programs fire for every process on the host. Every probe therefore
//! checks [`TRACKED_PIDS`] first, and the tree is maintained in-kernel through the `sched_process_fork`
//! tracepoint. Without that filter a CI recording of `npm install` would also contain the runner agent
//! and every daemon that happened to tick — attributing unrelated behavior to the package under test,
//! which is a correctness failure rather than noise.

#![no_std]
#![no_main]
// See the module docs: which aya helpers are safe wrappers versus raw unsafe bindings has moved
// between versions. Helper calls are wrapped in `unsafe` blocks; if a wrapper turns out to be safe the
// cost is a warning that this silences, whereas guessing the other way is a hard compile error.
#![allow(unused_unsafe)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::TracePointContext,
};
use installscope_abi::{
    FsRecord, Header, NetRecord, ProcRecord, AF_INET4, AF_INET6, ARGV_BUF_LEN, FLAG_ADDR_UNKNOWN,
    FLAG_ARGV_TRUNCATED, FLAG_FAILED, FLAG_PATH_TRUNCATED, KIND_FD_CLOSE, KIND_FS_WRITE,
    KIND_NET_CONNECT, KIND_PROC_SPAWN, NO_FD, PATH_BUF_LEN, WRITE_MKDIR, WRITE_OPEN, WRITE_RENAME,
    WRITE_WRITE,
};

/// Output channel to userspace. One perf buffer per CPU; the loader opens all of them.
#[map(name = "INSTALLSCOPE_EVENTS")]
static mut EVENTS: PerfEventArray<u8> = PerfEventArray::new(0);

/// Scratch space for building an [`FsRecord`], which is far larger than the 512-byte BPF stack.
#[map(name = "FS_SCRATCH")]
static mut FS_SCRATCH: PerCpuArray<FsRecord> = PerCpuArray::with_max_entries(1, 0);

/// Scratch space for a [`ProcRecord`].
#[map(name = "PROC_SCRATCH")]
static mut PROC_SCRATCH: PerCpuArray<ProcRecord> = PerCpuArray::with_max_entries(1, 0);

/// In-flight `openat` calls, keyed by `pid_tgid`.
///
/// An open must be reported *with its descriptor*, because that descriptor is what lets userspace give
/// a later `write` a path. But syscall entry knows the path and not the result, and syscall exit knows
/// the result and not the path — so the path is parked here between the two.
///
/// Keyed by `pid_tgid` rather than pid: two threads of one process can have an open in flight
/// simultaneously, and collapsing them would attribute one thread's path to the other's descriptor.
///
/// A dropped entry (exit never fires, e.g. the task is killed mid-syscall) leaks one slot until the map
/// fills, at which point new inserts fail and the open goes unreported. Bounded at 4096 to make that
/// bounded rather than unbounded; the loader counts how many writes arrive for unknown descriptors, so
/// the gap is visible instead of silent.
#[map(name = "OPEN_INFLIGHT")]
static mut OPEN_INFLIGHT: HashMap<u64, PendingOpen> = HashMap::with_max_entries(4096, 0);

/// Process ids whose behavior belongs to this recording.
///
/// **This map is what makes the aya backend a recorder rather than a system-wide monitor.** strace only
/// ever sees the process it traces; eBPF programs fire for *every* process on the host. Without this
/// filter, a recording of `npm install` on a CI runner would also contain the runner's own agent, the
/// journal daemon, and whatever else happened to run — attributing unrelated behavior to the package
/// under test. That is not a noise problem, it is a correctness problem: a report is meant to say what
/// this install did.
///
/// Userspace seeds the root pid. From there the filter maintains itself in-kernel via
/// [`installscope_sched_fork`], which avoids a race that a userspace-maintained set cannot: a child can
/// exec and write files before the loader has drained the fork event and learned the child exists.
///
/// Values are a placeholder `u8`; only key presence matters.
#[map(name = "TRACKED_PIDS")]
static mut TRACKED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(8192, 0);

/// Path and flags parked between `sys_enter_openat` and `sys_exit_openat`.
#[repr(C)]
#[derive(Clone, Copy)]
struct PendingOpen {
    mode: u32,
    path_len: u32,
    flags: u32,
    _pad: u32,
    path: [u8; PATH_BUF_LEN],
}

impl PendingOpen {
    const fn zeroed() -> Self {
        Self {
            mode: 0,
            path_len: 0,
            flags: 0,
            _pad: 0,
            path: [0; PATH_BUF_LEN],
        }
    }
}

/// True when the current process belongs to the recorded process tree.
///
/// Every probe calls this first. Returning early for untracked processes also keeps the perf buffer
/// free for events that matter — on a busy host the untracked traffic would otherwise dominate and
/// cause real losses.
fn tracked(tgid: u32) -> bool {
    let map = unsafe { &*core::ptr::addr_of!(TRACKED_PIDS) };
    unsafe { map.get(&tgid) }.is_some()
}

/// Byte offset of the first syscall argument in a `syscalls/sys_enter_*` tracepoint record.
///
/// The record begins with a `common_*` header followed by `__syscall_nr`, and arguments start after
/// that. ASSUMPTION — see the module docs; verify against
/// `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format`.
const ARG0: usize = 16;
/// Each subsequent argument is one 64-bit word further in.
const ARG_STRIDE: usize = 8;

/// Byte offset of a `sys_exit_*` tracepoint's return value.
///
/// Same 8-byte common header plus `__syscall_nr`, then `ret`. ASSUMPTION — verify against
/// `/sys/kernel/tracing/events/syscalls/sys_exit_openat/format`.
const EXIT_RET: usize = 16;

/// Byte offset of syscall argument `n`.
const fn arg_offset(n: usize) -> usize {
    ARG0 + n * ARG_STRIDE
}

/// Open flags that indicate write intent, from `asm-generic/fcntl.h`.
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

/// Builds the header every record shares.
///
/// Callers must have already confirmed the process is tracked; this does not re-check.
fn header(kind: u32) -> Header {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let mut h = Header::zeroed();
    h.kind = kind;
    h.ktime_ns = unsafe { bpf_ktime_get_ns() };
    h.tgid = (pid_tgid >> 32) as u32;
    h.pid = (pid_tgid & 0xffff_ffff) as u32;
    h.uid = (uid_gid & 0xffff_ffff) as u32;
    // ppid needs a CO-RE read of task_struct->real_parent->tgid, which G1 did not verify. Left zero
    // rather than guessed; the loader treats zero as unknown instead of claiming pid 0 is the parent.
    h.ppid = 0;
    if let Ok(comm) = unsafe { bpf_get_current_comm() } {
        h.comm = comm;
    }
    h
}

/// Emits a record's bytes to userspace.
///
/// Safety: `EVENTS` is a static map, and aya requires a raw reference to hand it to the helper. The
/// slice is derived from a `#[repr(C)]` value with no padding holes, so every byte is initialized —
/// which matters because the verifier rejects programs that leak uninitialized stack memory into a map.
unsafe fn emit<T>(ctx: &TracePointContext, record: &T) {
    let bytes = core::slice::from_raw_parts(
        core::ptr::from_ref::<T>(record).cast::<u8>(),
        core::mem::size_of::<T>(),
    );
    let events = &mut *core::ptr::addr_of_mut!(EVENTS);
    events.output(ctx, bytes, 0);
}

/// Copies a userspace string into `buf`, returning its length and whether it was truncated.
fn read_user_path(buf: &mut [u8; PATH_BUF_LEN], addr: u64) -> (u32, bool) {
    if addr == 0 {
        return (0, false);
    }
    // Reserve the final byte so a maximal string is still distinguishable from an overrun.
    let Some(target) = buf.get_mut(..PATH_BUF_LEN - 1) else {
        return (0, true);
    };
    match unsafe { bpf_probe_read_user_str_bytes(addr as *const u8, target) } {
        Ok(read) => {
            let len = read.len();
            // A string filling the buffer was probably cut; the flag makes that visible rather than
            // presenting a prefix as the whole path.
            (len as u32, len >= PATH_BUF_LEN - 1)
        }
        Err(_) => (0, true),
    }
}

// ---------------------------------------------------------------------------------------------
// Filesystem writes
// ---------------------------------------------------------------------------------------------

/// `openat(dirfd, pathname, flags, mode)` — entry.
///
/// Parks the path for the matching exit rather than emitting here. The descriptor is the whole point:
/// without it a later `write` has no path, and byte volume — the Phase 0 gap Phase 1 closed — would be
/// lost again on this backend.
///
/// Only write-intent opens are tracked. Recording every open would bury the evidence under an install's
/// own library loading, exactly as it would with strace.
#[tracepoint]
pub fn installscope_openat_enter(ctx: TracePointContext) -> u32 {
    let _ = try_openat_enter(&ctx);
    0
}

fn try_openat_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    if !tracked((pid_tgid >> 32) as u32) {
        return Ok(());
    }
    let flags: u64 = unsafe { ctx.read_at(arg_offset(2)) }?;
    let writing = flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND) != 0;
    if !writing {
        return Ok(());
    }
    let path_addr: u64 = unsafe { ctx.read_at(arg_offset(1)) }?;
    let mode: u64 = unsafe { ctx.read_at(arg_offset(3)) }.unwrap_or(0);

    let mut pending = PendingOpen::zeroed();
    pending.flags = flags as u32;
    pending.mode = mode as u32;
    let (len, truncated) = read_user_path(&mut pending.path, path_addr);
    pending.path_len = len;
    // Truncation is carried through the map so the exit-side record reports it. Reusing the flags field
    // would be cheaper but would conflate an open flag with a recorder condition.
    if truncated {
        pending.flags |= TRUNCATED_MARKER;
    }

    let map = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_INFLIGHT) };
    // Failure here means the map is full — the entry is dropped and this open goes unreported. Not
    // silently: the loader sees a write against an unknown descriptor and counts it.
    let _ = map.insert(&pid_tgid, &pending, 0);
    Ok(())
}

/// Bit borrowed in [`PendingOpen::flags`] to carry path truncation from entry to exit.
///
/// Chosen above every real `O_*` constant so it cannot collide with a genuine open flag.
const TRUNCATED_MARKER: u32 = 1 << 31;

/// `openat` — exit. Emits the record now that the descriptor is known.
#[tracepoint]
pub fn installscope_openat_exit(ctx: TracePointContext) -> u32 {
    let _ = try_openat_exit(&ctx);
    0
}

fn try_openat_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let key = unsafe { bpf_get_current_pid_tgid() };
    let map = unsafe { &mut *core::ptr::addr_of_mut!(OPEN_INFLIGHT) };
    let Some(pending) = unsafe { map.get(&key) }.copied() else {
        return Ok(()); // not a write-intent open, or the entry was dropped
    };
    let _ = map.remove(&key);

    let ret: i64 = unsafe { ctx.read_at(EXIT_RET) }?;

    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(FS_SCRATCH) };
    let record = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    // Safety: a per-CPU array slot is exclusively ours for the duration of this program.
    let record = unsafe { &mut *record };
    *record = FsRecord::zeroed();
    record.header = header(KIND_FS_WRITE);
    record.write_kind = WRITE_OPEN;
    record.mode = pending.mode;
    record.path_len = pending.path_len.min(PATH_BUF_LEN as u32);
    record.path = pending.path;

    if pending.flags & TRUNCATED_MARKER != 0 {
        record.header.flags |= FLAG_PATH_TRUNCATED;
    }

    if ret < 0 {
        // A failed open is still evidence of intent, so it is recorded and marked rather than dropped.
        record.header.flags |= FLAG_FAILED;
        record.errno = (-ret) as u32;
        record.fd = NO_FD;
    } else {
        record.fd = ret as i32;
    }

    unsafe { emit(ctx, record) };
    Ok(())
}

/// `write(fd, buf, count)`.
///
/// Records the *requested* count, because `sys_enter` runs before the kernel knows how many bytes were
/// actually written. A short write therefore overstates volume; the loader labels this rather than
/// presenting it as exact. The path comes from the loader's fd table, keyed on [`FsRecord::fd`].
#[tracepoint]
pub fn installscope_write(ctx: TracePointContext) -> u32 {
    let _ = try_write(&ctx);
    0
}

fn try_write(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    if !tracked((pid_tgid >> 32) as u32) {
        return Ok(());
    }
    let fd: u64 = unsafe { ctx.read_at(arg_offset(0)) }?;
    let count: u64 = unsafe { ctx.read_at(arg_offset(2)) }?;
    if count == 0 {
        return Ok(());
    }

    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(FS_SCRATCH) };
    let record = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let record = unsafe { &mut *record };
    *record = FsRecord::zeroed();
    record.header = header(KIND_FS_WRITE);
    record.write_kind = WRITE_WRITE;
    record.bytes = count;
    record.fd = fd as i32;
    record.path_len = 0;

    unsafe { emit(ctx, record) };
    Ok(())
}

/// `close(fd)`.
///
/// Emitted so the loader can retire its fd-table entry and flush that descriptor's accumulated write
/// volume at the moment the file's total is final — the same point the strace backend flushes. Without
/// it, a descriptor reused for a different file would merge two files' byte counts.
#[tracepoint]
pub fn installscope_close(ctx: TracePointContext) -> u32 {
    let _ = try_close(&ctx);
    0
}

fn try_close(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    if !tracked((pid_tgid >> 32) as u32) {
        return Ok(());
    }
    let fd: u64 = unsafe { ctx.read_at(arg_offset(0)) }?;

    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(FS_SCRATCH) };
    let record = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let record = unsafe { &mut *record };
    *record = FsRecord::zeroed();
    record.header = header(KIND_FD_CLOSE);
    record.fd = fd as i32;

    unsafe { emit(ctx, record) };
    Ok(())
}

/// `mkdirat(dirfd, pathname, mode)`.
#[tracepoint]
pub fn installscope_mkdirat(ctx: TracePointContext) -> u32 {
    let _ = try_path_only(&ctx, WRITE_MKDIR, 1);
    0
}

/// `renameat2(olddirfd, oldpath, newdirfd, newpath, flags)` — the destination is what matters.
#[tracepoint]
pub fn installscope_renameat(ctx: TracePointContext) -> u32 {
    let _ = try_path_only(&ctx, WRITE_RENAME, 3);
    0
}

/// Shared body for write-class syscalls whose only interesting argument is a path.
fn try_path_only(ctx: &TracePointContext, write_kind: u32, path_arg: usize) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    if !tracked((pid_tgid >> 32) as u32) {
        return Ok(());
    }
    let path_addr: u64 = unsafe { ctx.read_at(arg_offset(path_arg)) }?;

    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(FS_SCRATCH) };
    let record = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let record = unsafe { &mut *record };
    *record = FsRecord::zeroed();
    record.header = header(KIND_FS_WRITE);
    record.write_kind = write_kind;

    let (len, truncated) = read_user_path(&mut record.path, path_addr);
    record.path_len = len;
    if truncated {
        record.header.flags |= FLAG_PATH_TRUNCATED;
    }

    unsafe { emit(ctx, record) };
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------------------------

/// `connect(sockfd, addr, addrlen)`.
///
/// Reads the `sockaddr` from userspace rather than from kernel structures, which keeps this free of
/// CO-RE — the capability G1 left unproven.
#[tracepoint]
pub fn installscope_connect(ctx: TracePointContext) -> u32 {
    let _ = try_connect(&ctx);
    0
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    if !tracked((pid_tgid >> 32) as u32) {
        return Ok(());
    }
    let addr_ptr: u64 = unsafe { ctx.read_at(arg_offset(1)) }?;
    if addr_ptr == 0 {
        return Ok(());
    }

    // sa_family is the first two bytes of every sockaddr.
    let family: u16 = unsafe { bpf_probe_read_user(addr_ptr as *const u16) }.map_err(|e| e as i64)?;

    let mut record = NetRecord::zeroed();
    record.header = header(KIND_NET_CONNECT);

    match u32::from(family) {
        AF_INET4 => {
            record.family = AF_INET4;
            // struct sockaddr_in { u16 family; u16 port; u32 addr; }
            let port_be: u16 =
                unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16) }.map_err(|e| e as i64)?;
            let addr_be: [u8; 4] =
                unsafe { bpf_probe_read_user((addr_ptr + 4) as *const [u8; 4]) }
                    .map_err(|e| e as i64)?;
            record.port = u16::from_be(port_be);
            record.addr[..4].copy_from_slice(&addr_be);
        }
        AF_INET6 => {
            record.family = AF_INET6;
            // struct sockaddr_in6 { u16 family; u16 port; u32 flowinfo; u8 addr[16]; ... }
            let port_be: u16 =
                unsafe { bpf_probe_read_user((addr_ptr + 2) as *const u16) }.map_err(|e| e as i64)?;
            let addr_be: [u8; 16] =
                unsafe { bpf_probe_read_user((addr_ptr + 8) as *const [u8; 16]) }
                    .map_err(|e| e as i64)?;
            record.port = u16::from_be(port_be);
            record.addr = addr_be;
        }
        _ => {
            // AF_UNIX and friends. Recorded with a flag rather than dropped, so the loader can report
            // that *something* connected without inventing an address.
            record.header.flags |= FLAG_ADDR_UNKNOWN;
            record.family = u32::from(family);
        }
    }

    unsafe { emit(ctx, &record) };
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Process spawns
// ---------------------------------------------------------------------------------------------

/// Maximum argv entries copied. Bounded because the verifier requires a compile-time loop bound, and
/// because an unbounded copy would let one pathological process fill the perf buffer.
const MAX_ARGV: usize = 20;

/// `execve(filename, argv, envp)`.
///
/// envp is deliberately not read. Environment variables routinely contain tokens and credentials, and
/// this product's claim is that it watches packages, not people (`Rules.md` §1). A *read* of an
/// environment file is evidence; copying the environment's contents into an artifact is a liability.
#[tracepoint]
pub fn installscope_execve(ctx: TracePointContext) -> u32 {
    let _ = try_execve(&ctx);
    0
}

#[allow(clippy::cast_possible_truncation)]
fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    if !tracked((pid_tgid >> 32) as u32) {
        return Ok(());
    }
    let filename_addr: u64 = unsafe { ctx.read_at(arg_offset(0)) }?;
    let argv_addr: u64 = unsafe { ctx.read_at(arg_offset(1)) }?;

    let scratch = unsafe { &mut *core::ptr::addr_of_mut!(PROC_SCRATCH) };
    let record = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let record = unsafe { &mut *record };
    *record = ProcRecord::zeroed();
    record.header = header(KIND_PROC_SPAWN);

    let (len, truncated) = read_user_path(&mut record.filename, filename_addr);
    record.filename_len = len;
    if truncated {
        record.header.flags |= FLAG_PATH_TRUNCATED;
    }

    // argv is a NULL-terminated array of pointers; each string is copied into one flat buffer,
    // NUL-separated, which is what the ABI documents.
    let mut cursor = 0usize;
    let mut argc = 0u32;
    let mut argv_truncated = false;

    for i in 0..MAX_ARGV {
        if argv_addr == 0 {
            break;
        }
        let slot = argv_addr + (i * core::mem::size_of::<u64>()) as u64;
        let Ok(str_ptr) = unsafe { bpf_probe_read_user(slot as *const u64) } else {
            argv_truncated = true;
            break;
        };
        if str_ptr == 0 {
            break; // end of argv
        }
        // Leave room for the separator; bail rather than write a partial argument.
        if cursor + 2 >= ARGV_BUF_LEN {
            argv_truncated = true;
            break;
        }
        let Some(dest) = record.argv.get_mut(cursor..ARGV_BUF_LEN - 1) else {
            argv_truncated = true;
            break;
        };
        match unsafe { bpf_probe_read_user_str_bytes(str_ptr as *const u8, dest) } {
            Ok(read) => {
                let n = read.len();
                cursor += n;
                if let Some(slot) = record.argv.get_mut(cursor) {
                    *slot = 0; // explicit separator
                    cursor += 1;
                }
                argc += 1;
            }
            Err(_) => {
                argv_truncated = true;
                break;
            }
        }
        if i == MAX_ARGV - 1 {
            // Hit the entry cap; there may be more arguments we did not see.
            argv_truncated = true;
        }
    }

    record.argv_len = cursor as u32;
    record.argc = argc;
    if argv_truncated {
        record.header.flags |= FLAG_ARGV_TRUNCATED;
    }

    unsafe { emit(ctx, record) };
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Process tree tracking
// ---------------------------------------------------------------------------------------------

/// `sched:sched_process_fork` — adds new children to the tracked set.
///
/// Maintained in-kernel rather than from userspace to close a race that matters: a forked child can
/// exec and write files within microseconds, long before the loader has drained a fork notification and
/// added the pid itself. Those early writes are often the interesting ones — a postinstall script's
/// first act — so losing them would lose exactly the evidence worth having.
///
/// ASSUMPTION: the `sched_process_fork` tracepoint's format places `parent_pid` and `child_pid` at the
/// offsets used below. Unlike syscall tracepoints these are named fields in a struct, so the offsets
/// differ; the authoritative source is
/// `/sys/kernel/tracing/events/sched/sched_process_fork/format`, which the workflow dumps.
#[tracepoint]
pub fn installscope_sched_fork(ctx: TracePointContext) -> u32 {
    let _ = try_sched_fork(&ctx);
    0
}

/// Offset of `parent_pid` in the `sched_process_fork` record: 8-byte common header, then
/// `parent_comm[16]`.
const FORK_PARENT_PID: usize = 24;
/// Offset of `child_pid`: after `parent_pid` (4 bytes) and `child_comm[16]`.
const FORK_CHILD_PID: usize = 44;

fn try_sched_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let parent: u32 = unsafe { ctx.read_at(FORK_PARENT_PID) }?;
    if !tracked(parent) {
        return Ok(());
    }
    let child: u32 = unsafe { ctx.read_at(FORK_CHILD_PID) }?;
    let map = unsafe { &mut *core::ptr::addr_of_mut!(TRACKED_PIDS) };
    // A full map means the tree grew past 8192 concurrent processes and later children go untracked.
    // The loader reports the map's occupancy so that ceiling is visible rather than a silent gap.
    let _ = map.insert(&child, &1, 0);
    Ok(())
}

/// `sched:sched_process_exit` — retires pids from the tracked set.
///
/// Without this, a long recording accumulates dead pids until the map fills, and — worse — a recycled
/// pid would be treated as tracked, attributing an unrelated process's behavior to this recording.
#[tracepoint]
pub fn installscope_sched_exit(ctx: TracePointContext) -> u32 {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & 0xffff_ffff) as u32;
    // Only the thread group leader's exit retires the process; a thread exiting leaves it running.
    if tgid == pid {
        let map = unsafe { &mut *core::ptr::addr_of_mut!(TRACKED_PIDS) };
        let _ = map.remove(&tgid);
    }
    0
}

/// Required by `no_std`. `panic = "abort"` is set in Cargo.toml, so this is unreachable in practice;
/// `unreachable_unchecked` keeps the verifier from analyzing a loop it cannot bound.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
/// The kernel refuses to load programs using GPL-only helpers without a compatible license.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
