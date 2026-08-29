//! G1 eBPF probe — the smallest program that answers the gate question.
//!
//! Attaches to `syscalls:sys_enter_execve` and pushes one [`ExecEvent`] per exec into a
//! `PerfEventArray`. Gate tooling only (harness/README.md): Phase 2 writes the real backend under
//! `recorder/aya/` per Architecture.md:71.
//!
//! Deliberately minimal: no argv/path reads (userspace pointer chasing is CO-RE work), no
//! filtering, no maps beyond the output channel. The question is only "does a program load and
//! deliver an event on a stock ubuntu-latest runner".
#![no_std]
#![no_main]
// TODO-verify: aya-ebpf exposes safe wrappers for some helpers and raw unsafe bindings for others,
// and which is which has moved between versions. Helper calls below are wrapped in `unsafe` blocks
// deliberately: if a wrapper turns out to be safe, the cost is an `unused_unsafe` warning (silenced
// here), whereas guessing the other way is a hard compile error. Resolve against the version in
// Cargo.lock after the first real build rather than guessing (Rules.md §5).
#![allow(unused_unsafe)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use g1_common::{ExecEvent, COMM_LEN};

#[map(name = "G1_EVENTS")]
static mut EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn g1_execve(ctx: TracePointContext) -> u32 {
    match try_g1_execve(&ctx) {
        Ok(()) => 0,
        // A dropped event must never look like "nothing happened". The loader distinguishes zero
        // events from failed emits by checking the perf buffer's own lost-event counter, so
        // returning non-zero here is enough; there is no error map to maintain in a gate probe.
        Err(_) => 1,
    }
}

fn try_g1_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let mut event = ExecEvent::zeroed();
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };
    event.tgid = (pid_tgid >> 32) as u32;
    event.pid = (pid_tgid & 0xffff_ffff) as u32;
    event.uid = (uid_gid & 0xffff_ffff) as u32;

    // bpf_get_current_comm returns a NUL-padded TASK_COMM_LEN buffer. The loop bound is a
    // compile-time constant so the verifier can unroll it.
    let comm = unsafe { bpf_get_current_comm() }.map_err(|e| e as i64)?;
    let mut len = 0u32;
    let mut i = 0usize;
    while i < COMM_LEN {
        event.comm[i] = comm[i];
        i += 1;
    }
    while (len as usize) < COMM_LEN && event.comm[len as usize] != 0 {
        len += 1;
    }
    event.comm_len = len;

    // Safety: `EVENTS` is a static map; aya requires a raw reference to pass it to the helper. The
    // program is single-threaded per invocation and the map is only ever appended to.
    unsafe {
        let events = &mut *core::ptr::addr_of_mut!(EVENTS);
        events.output(ctx, &event, 0);
    }

    Ok(())
}

/// Required by the verifier. `panic = "abort"` is set in Cargo.toml, so this is unreachable in
/// practice; it exists because `no_std` demands a handler.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // `unreachable_unchecked` keeps the verifier from seeing a loop it must analyze.
    unsafe { core::hint::unreachable_unchecked() }
}

/// The kernel refuses to load programs that use GPL-only helpers without a compatible license.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
