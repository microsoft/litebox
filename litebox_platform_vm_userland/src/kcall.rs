// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Calls into the kernel. `gate` must be the process's only `syscall`
//! instruction outside guest code: the kernel accepts calls only from
//! [`GATE_SECTION`](litebox_common_vm_abi::GATE_SECTION).

use core::sync::atomic::AtomicU32;
use litebox_common_vm_abi::{
    CallSet, DeriveKeyReply, DeriveKeyRequest, ExitRequest, FutexRequest, KernelCall, LogLevel,
    LogRequest, MapRequest, Message, Placement, Populate, Prot, ProtSet, ProtectRequest,
    ReadyRequest, RestrictRequest, SetTimerRequest, Status, UnmapRequest, UserRange,
};
use zerocopy::{FromZeros as _, IntoBytes as _};

#[unsafe(naked)]
#[unsafe(link_section = ".kabi_gate")]
unsafe extern "C" fn gate(
    id: u64,
    request: *const u8,
    request_len: usize,
    reply: *mut u8,
    reply_len: usize,
) -> u64 {
    core::arch::naked_asm!(
        "mov rax, rdi",
        "mov rdi, rsi",
        "mov rsi, rdx",
        "mov rdx, rcx",
        "mov r10, r8",
        "syscall",
        "ret",
    );
}

/// # Errors
///
/// The kernel's [`Status`].
///
/// # Panics
///
/// If the kernel returns a status the ABI does not define.
pub fn call<C: KernelCall>(request: &C) -> Result<C::Reply, Status> {
    let mut reply = C::Reply::new_zeroed();
    // Safety: the request and reply buffers are valid for their sizes; the
    // kernel only writes the reply buffer.
    let raw = unsafe {
        gate(
            C::ID as u64,
            core::ptr::from_ref(request).cast(),
            size_of::<C>(),
            reply.as_mut_bytes().as_mut_ptr(),
            size_of::<C::Reply>(),
        )
    };
    match Status::from_raw(raw) {
        Some(result) => result.map(|()| reply),
        None => panic!("the kernel returned an unknown status {raw:#x}"),
    }
}

fn user_bytes(bytes: &[u8]) -> UserRange {
    UserRange {
        start: bytes.as_ptr() as u64,
        len: bytes.len() as u64,
    }
}

fn range(addr: usize, len: usize) -> UserRange {
    UserRange {
        start: addr as u64,
        len: len as u64,
    }
}

pub fn exit(code: u32) -> ! {
    let _ = call(&ExitRequest { code });
    // The kernel never resumes an exited process.
    loop {
        core::hint::spin_loop();
    }
}

/// Best effort.
pub fn log(level: LogLevel, message: &str) {
    let _ = call(&LogRequest::new(level, user_bytes(message.as_bytes())));
}

/// # Errors
///
/// See [`call`].
pub fn ready(upcall_entry: usize) -> Result<Message, Status> {
    call(&ReadyRequest::new(upcall_entry as u64))
}

/// # Errors
///
/// See [`call`].
pub fn reply_and_wait(reply: &Message) -> Result<Message, Status> {
    call(reply)
}

/// Blocks while `word` is `expected`, until a [`futex_wake`] on it,
/// `deadline`, or an interrupt ([`Status::Interrupted`]).
///
/// # Errors
///
/// See [`call`].
pub fn futex_wait(
    word: &AtomicU32,
    expected: u32,
    deadline: Option<crate::Instant>,
) -> Result<(), Status> {
    call(&FutexRequest::wait(
        word.as_ptr() as u64,
        expected,
        // Zero means none, so the (theoretical) instant zero waits from 1 ns.
        deadline.map_or(0, |deadline| deadline.as_nanos().max(1)),
    ))
    .map(|_| ())
}

/// Wakes up to `count` threads waiting on `word`; returns how many.
///
/// # Errors
///
/// See [`call`].
pub fn futex_wake(word: &AtomicU32, count: u64) -> Result<u64, Status> {
    call(&FutexRequest::wake(word.as_ptr() as u64, count)).map(|reply| reply.woken)
}

/// # Errors
///
/// See [`call`].
pub fn map(
    addr: usize,
    len: usize,
    prot: Prot,
    placement: Placement,
    populate: Populate,
) -> Result<usize, Status> {
    call(&MapRequest::new(
        range(addr, len),
        prot,
        placement,
        populate,
    ))
    .map(|reply| usize::try_from(reply.addr).unwrap_or(usize::MAX))
}

/// # Errors
///
/// See [`call`].
pub fn unmap(addr: usize, len: usize) -> Result<(), Status> {
    call(&UnmapRequest {
        range: range(addr, len),
    })
}

/// # Errors
///
/// See [`call`].
pub fn protect(addr: usize, len: usize, prot: Prot) -> Result<(), Status> {
    call(&ProtectRequest::new(range(addr, len), prot))
}

/// Irrevocable.
///
/// # Errors
///
/// See [`call`].
pub fn restrict(calls: CallSet, prots: ProtSet) -> Result<(), Status> {
    call(&RestrictRequest::new(calls, prots))
}

/// Sets the process's one-shot timer: at `deadline`, the kernel
/// delivers [`litebox_common_vm_abi::UpcallKind::Interrupt`] if the process
/// still runs then; `None` cancels.
///
/// # Errors
///
/// See [`call`].
pub fn set_timer(deadline: Option<crate::Instant>) -> Result<(), Status> {
    call(&SetTimerRequest {
        // Zero means none, so the (theoretical) instant zero fires at 1 ns.
        deadline: deadline.map_or(0, |deadline| deadline.as_nanos().max(1)),
    })
}

/// # Errors
///
/// See [`call`].
pub fn derive_key(context: &[u8]) -> Result<DeriveKeyReply, Status> {
    call(&DeriveKeyRequest {
        context: user_bytes(context),
    })
}
