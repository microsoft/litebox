// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Serves one OP-TEE TA instance in ring 3 on the LiteBox VM kernel.
//!
//! - One instance per process; a second is refused.
//! - The TA and `ldelf` may be syscall-rewritten (syscalls are calls into the
//!   shim) or unmodified (each `syscall` costs one kernel round trip).
//! - Static PIE linked at 0 (`x86_64_vm_userland.ld`): the kernel loads it at
//!   the top of the user address space and applies its relocations.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod heap;
mod optee;

use core::panic::PanicInfo;
use litebox_common_vm_abi::{ABI_VERSION, LogLevel, StartupInfo};
use litebox_platform_vm_userland::{KernelLogger, kcall};

/// TA failures go in entry replies; this is for the runner's own.
const EXIT_FAILURE: u32 = 1;

/// `rdi`: the [`StartupInfo`] page; `rsp`: the top of the stack.
///
/// # Safety
///
/// Only the kernel may enter here, once.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text._start")]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "and rsp, -16",
        "xor ebp, ebp",
        "call {main}",
        "ud2",
        main = sym runner_main,
    );
}

extern "C" fn runner_main(info: *const StartupInfo) -> ! {
    // Safety: mapped read-only for the process's lifetime.
    let info = unsafe { info.read() };
    if info.abi_version != ABI_VERSION {
        kcall::log(LogLevel::Error, "kernel ABI version mismatch");
        kcall::exit(EXIT_FAILURE);
    }
    // Safety: mapped writable for the process's lifetime; used only here.
    unsafe { heap::init(info.heap) };
    let _ = log::set_logger(&KernelLogger);
    // Each message costs a kernel call; send only what the kernel keeps.
    log::set_max_level(match info.max_log_level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    });

    optee::serve(&info)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write as _;
    let mut message = arrayvec_string::Message::new();
    let _ = write!(message, "runner panic: {info}");
    kcall::log(LogLevel::Error, message.as_str());
    kcall::exit(EXIT_FAILURE)
}

/// Truncating and allocation-free, for the panic handler.
mod arrayvec_string {
    pub struct Message {
        buf: [u8; 512],
        len: usize,
    }

    impl Message {
        pub const fn new() -> Self {
            Self {
                buf: [0; 512],
                len: 0,
            }
        }

        pub fn as_str(&self) -> &str {
            match core::str::from_utf8(&self.buf[..self.len]) {
                Ok(s) => s,
                Err(e) => core::str::from_utf8(&self.buf[..e.valid_up_to()]).unwrap_or(""),
            }
        }
    }

    impl core::fmt::Write for Message {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
}
