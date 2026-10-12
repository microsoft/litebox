// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A runner's process entry, heap, and panic handler, so that a runner is
//! only its service: the kernel enters [`_start`], which checks the ABI,
//! fills the heap, routes `log` to the kernel log, and calls the runner's main
//! function, given with [`entry!`](crate::entry). Runners link with this
//! crate's `x86_64_vm_userland.ld`, from `DEP_LITEBOX_PLATFORM_VM_USERLAND_LINKER_SCRIPT`.

use crate::{KernelLogger, kcall};
use litebox_common_vm_abi::{ABI_VERSION, LogLevel, StartupInfo, UserRange};

/// A runner's exit code for its own failures; the service's go in its
/// replies.
pub const EXIT_FAILURE: u32 = 1;

/// Defines the runner's main function, `fn(&StartupInfo) -> !`, which serves
/// once the process is set up (see [`crate::start`]).
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        fn __litebox_runner_main(info: &::litebox_common_vm_abi::StartupInfo) -> ! {
            $main(info)
        }
    };
}

unsafe extern "Rust" {
    safe fn __litebox_runner_main(info: &StartupInfo) -> !;
}

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
    unsafe { init_heap(info.heap) };
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
    __litebox_runner_main(&info)
}

/// Largest single allocation: `1 << (HEAP_ORDER - 1)` bytes (16 MiB).
const HEAP_ORDER: usize = 25;

/// [`StartupInfo::heap`], and nothing else.
#[global_allocator]
static ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<'static, HEAP_ORDER, NoHost> =
    litebox::mm::allocator::SafeZoneAllocator::new();

struct NoHost;

impl litebox::mm::allocator::MemoryProvider for NoHost {
    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        None
    }

    unsafe fn free(_addr: usize) {
        unreachable!("the heap never obtains memory from a host");
    }
}

/// # Safety
///
/// `region` must be mapped writable, stay mapped, and be otherwise unused.
unsafe fn init_heap(region: UserRange) {
    let start = usize::try_from(region.start).expect("heap address fits usize");
    let len = usize::try_from(region.len).expect("heap length fits usize");
    // Safety: forwarded to the caller.
    unsafe { ALLOCATOR.fill_pages(start, len) };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write as _;
    let mut message = Message::new();
    let _ = write!(message, "runner panic: {info}");
    kcall::log(LogLevel::Error, message.as_str());
    kcall::exit(EXIT_FAILURE)
}

/// Truncating and allocation-free, for the panic handler.
struct Message {
    buf: [u8; 512],
    len: usize,
}

impl Message {
    const fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
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
