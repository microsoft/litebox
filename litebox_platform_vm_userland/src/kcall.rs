// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Calls into the kernel. `gate` must be the process's only `syscall`
//! instruction outside guest code: the kernel accepts calls only from
//! [`GATE_SECTION`](litebox_common_vm_abi::GATE_SECTION).

use litebox_common_vm_abi::{
    DeriveKeyReply, DeriveKeyRequest, ExitRequest, KernelCall, LogLevel, LogRequest, MapRequest,
    Message, Placement, Populate, Prot, ProtectRequest, ReadyRequest, Status, UnmapRequest,
    UserBytes,
};
use zerocopy::TryFromBytes;

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
/// The kernel's [`Status`]; [`Status::InvalidArgument`] for an undecodable
/// status or reply.
pub fn call<C: KernelCall>(request: &C) -> Result<C::Reply, Status> {
    let mut reply = core::mem::MaybeUninit::<C::Reply>::zeroed();
    // Safety: the request and reply buffers are valid for their sizes; the
    // kernel only writes the reply buffer.
    let raw = unsafe {
        gate(
            C::ID as u64,
            core::ptr::from_ref(request).cast(),
            size_of::<C>(),
            reply.as_mut_ptr().cast(),
            size_of::<C::Reply>(),
        )
    };
    match Status::from_raw(raw) {
        Some(Status::Ok) => {
            // Safety: every byte was zeroed and possibly overwritten by the
            // kernel, so all are initialized.
            let bytes = unsafe {
                core::slice::from_raw_parts(reply.as_ptr().cast::<u8>(), size_of::<C::Reply>())
            };
            C::Reply::try_read_from_bytes(bytes).map_err(|_| Status::InvalidArgument)
        }
        Some(status) => Err(status),
        None => Err(Status::InvalidArgument),
    }
}

fn user_bytes(bytes: &[u8]) -> UserBytes {
    UserBytes {
        addr: bytes.as_ptr() as u64,
        len: bytes.len() as u64,
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
    let _ = call(&LogRequest {
        level,
        reserved: 0,
        message: user_bytes(message.as_bytes()),
    });
}

/// # Errors
///
/// See [`call`].
pub fn ready(upcall_entry: usize) -> Result<Message, Status> {
    call(&ReadyRequest {
        abi_version: litebox_common_vm_abi::ABI_VERSION,
        reserved: 0,
        upcall_entry: upcall_entry as u64,
    })
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
    call(&MapRequest {
        addr: addr as u64,
        len: len as u64,
        prot,
        placement,
        populate,
        reserved: 0,
    })
    .map(|reply| usize::try_from(reply.addr).unwrap_or(usize::MAX))
}

/// # Errors
///
/// See [`call`].
pub fn unmap(addr: usize, len: usize) -> Result<(), Status> {
    call(&UnmapRequest {
        addr: addr as u64,
        len: len as u64,
    })
}

/// # Errors
///
/// See [`call`].
pub fn protect(addr: usize, len: usize, prot: Prot) -> Result<(), Status> {
    call(&ProtectRequest {
        addr: addr as u64,
        len: len as u64,
        prot,
        reserved: 0,
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
