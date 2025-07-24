//! A shim that provides an OP-TEE-compatible ABI via LiteBox

#![no_std]

extern crate alloc;

// TODO(jayb) Replace out all uses of once_cell and such with our own implementation that uses
// platform-specific things within it.
use once_cell::race::OnceBox;

use alloc::vec;
use litebox::{
    LiteBox,
    platform::{RawConstPointer as _, RawMutPointer as _},
};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::SyscallRequest;
use litebox_platform_multiplex::Platform;

pub(crate) mod syscalls;

const MAX_KERNEL_BUF_SIZE: usize = 0x80_000;

/// Get the global litebox object
pub fn litebox<'a>() -> &'a LiteBox<Platform> {
    static LITEBOX: OnceBox<LiteBox<Platform>> = OnceBox::new();
    LITEBOX.get_or_init(|| {
        alloc::boxed::Box::new(LiteBox::new(litebox_platform_multiplex::platform()))
    })
}

/// Handle OP-TEE syscalls
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development purposes.
pub fn handle_syscall_request(request: SyscallRequest<Platform>) -> isize {
    let res: Result<usize, Errno> = match request {
        SyscallRequest::Return { ret } => syscalls::tee::sys_return(ret),
        SyscallRequest::Log { buf, len } => match unsafe { buf.to_cow_slice(len) } {
            Some(buf) => syscalls::tee::sys_log(&buf),
            None => Err(Errno::EFAULT),
        },
        SyscallRequest::Panic { code } => syscalls::tee::sys_panic(code),
        SyscallRequest::CrypRandomNumberGenerate { buf, blen } => {
            let mut kernel_buf = vec![0u8; blen.min(MAX_KERNEL_BUF_SIZE)];
            syscalls::cryp::sys_cryp_random_number_generate(&mut kernel_buf).and_then(|()| {
                buf.copy_from_slice(0, &kernel_buf)
                    .map(|()| 0)
                    .ok_or(Errno::EFAULT)
            })
        }
        _ => todo!(),
    };

    res.map_or_else(
        |e| {
            let e: i32 = e.as_neg();
            let Ok(e) = isize::try_from(e) else {
                // On both 32-bit and 64-bit, this should never be triggered
                unreachable!()
            };
            e
        },
        |val: usize| {
            let Ok(v) = isize::try_from(val) else {
                // Note in case where val is an address (e.g., returned from `mmap`), we currently
                // assume user space address does not exceed isize::MAX. On 64-bit, the max user
                // address is 0x7FFF_FFFF_F000, which is below this; for 32-bit, this may not hold,
                // and we might need to de-restrict this if ever seen in practice. For now, we are
                // keeping the stricter version.
                unreachable!("invalid user pointer");
            };
            v
        },
    )
}
