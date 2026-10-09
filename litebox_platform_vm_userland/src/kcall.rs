// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Calls into the kernel. `gate` must be the process's only `syscall`
//! instruction outside guest code: the kernel accepts calls only from
//! [`GATE_SECTION`](litebox_common_vm_abi::GATE_SECTION).

use litebox_common_vm_abi::{
    CallSet, DeriveKeyReply, DeriveKeyRequest, ExitRequest, KernelCall, LogLevel, LogRequest,
    MapRequest, Message, NO_TIMEOUT, Placement, Populate, Prot, ProtSet, ProtectRequest,
    ReadyRequest, RestrictRequest, RunRequest, Status, UnmapRequest, UserRange, WaitRequest,
    WakeRequest,
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

/// For a runner that serves no requests; instead of [`ready`].
///
/// # Errors
///
/// See [`call`].
pub fn run(upcall_entry: usize) -> Result<(), Status> {
    call(&RunRequest::new(upcall_entry as u64))
}

/// # Errors
///
/// See [`call`].
pub fn reply_and_wait(reply: &Message) -> Result<Message, Status> {
    call(reply)
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

/// Blocks while `word` holds `expected`, until a [`wake`] on it or the
/// `timeout`. Success: woken, or `word` did not hold `expected`.
///
/// # Errors
///
/// [`Status::TimedOut`], [`Status::Stalled`] if nothing could end the wait,
/// or see [`call`].
pub fn wait(
    word: &core::sync::atomic::AtomicU32,
    expected: u32,
    timeout: Option<core::time::Duration>,
) -> Result<(), Status> {
    let timeout_ns = timeout.map_or(NO_TIMEOUT, |timeout| {
        u64::try_from(timeout.as_nanos()).map_or(NO_TIMEOUT - 1, |ns| ns.min(NO_TIMEOUT - 1))
    });
    call(&WaitRequest::new(
        word.as_ptr() as u64,
        expected,
        timeout_ns,
    ))
}

/// Wakes up to `count` threads waiting on `word`; returns how many.
///
/// # Errors
///
/// See [`call`].
pub fn wake(word: &core::sync::atomic::AtomicU32, count: u32) -> Result<u32, Status> {
    call(&WakeRequest::new(word.as_ptr() as u64, count)).map(|reply| reply.woken)
}

/// Irrevocable.
///
/// # Errors
///
/// See [`call`].
pub fn restrict(calls: CallSet, prots: ProtSet) -> Result<(), Status> {
    call(&RestrictRequest::new(calls, prots))
}

/// # Errors
///
/// See [`call`].
pub fn derive_key(context: &[u8]) -> Result<DeriveKeyReply, Status> {
    call(&DeriveKeyRequest {
        context: user_bytes(context),
    })
}
