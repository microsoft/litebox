// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs one Linux program in ring 3 on the LiteBox VM kernel, as
//! `litebox_common_linux::vm_userland` describes: the program and its
//! environment come from the startup images, its files from the kernel's
//! broker, and its wait status goes back as the exit code.
//!
//! - Serves no requests ([`kcall::run`]): the process runs the program to its
//!   end, then exits.
//! - Single-threaded, with no timers or signals. The kernel time-slices it
//!   with other processes, and its waits with a timeout (e.g., `nanosleep`)
//!   block in the kernel; one without a timeout is a deadlock, as no other
//!   thread could end it, and the runner fails. Reading the real-time clock
//!   (`time`, `gettimeofday`, `CLOCK_REALTIME`) panics: `VmUserland` has no
//!   wall clock.
//! - The program may be syscall-rewritten, or patched by the shim as it loads;
//!   any `syscall` left costs one kernel round trip (an upcall).
//! - Static PIE linked at 0 (`litebox_platform_vm_userland`'s
//!   `x86_64_vm_userland.ld`): the kernel loads it at the top of the user
//!   address space and applies its relocations.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod heap;

use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::vm_userland::{
    ARGV_IMAGE, ENVP_IMAGE, RUNNER_FAILURE, decode_strings, exit_code,
};
use litebox_common_vm_abi::{ABI_VERSION, CallId, CallSet, Image, LogLevel, ProtSet, StartupInfo};
use litebox_platform_vm_userland::{KernelLogger, VmUserland, kcall};

/// The guest's credentials, as on the other Linux runners.
const GUEST_UID: u32 = 1000;
const GUEST_GID: u32 = 1000;

/// Besides [`CallId::Exit`], which is always allowed: no new broker
/// association, requests, or derived keys. Executable memory stays allowed, as
/// the shim maps the program and its libraries, and patches syscalls, as the
/// program runs.
const RUNNING_CALLS: CallSet = CallSet::EMPTY
    .with(CallId::Map)
    .with(CallId::Unmap)
    .with(CallId::Protect)
    .with(CallId::BrokerEnter)
    .with(CallId::Log)
    .with(CallId::Wait)
    .with(CallId::Wake);

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
        kcall::exit(RUNNER_FAILURE);
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

    kcall::exit(run(&info))
}

/// Runs the program; returns the process's exit code.
fn run(info: &StartupInfo) -> u32 {
    let platform: &'static VmUserland = Box::leak(Box::new(VmUserland::new(info)));
    let local = litebox_broker_local_vm_userland::connect(info)
        .unwrap_or_else(|e| panic!("broker association: {e:?}"));
    kcall::run(VmUserland::upcall_entry_address())
        .unwrap_or_else(|status| panic!("run: {status:?}"));
    kcall::restrict(RUNNING_CALLS, ProtSet::ALL)
        .unwrap_or_else(|status| panic!("lockdown: {status:?}"));

    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, local);
    let pid = i32::try_from(process_id.0).expect("broker process IDs fit pid_t");
    let shim =
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox, pid).build();

    let argv = strings(info.images[ARGV_IMAGE]);
    let envp = strings(info.images[ENVP_IMAGE]);
    let path = String::from(
        argv.first()
            .and_then(|path| path.to_str().ok())
            .expect("argv[0] is the program's path"),
    );
    litebox_util_log::info!(path:% = path; "loading the program");
    let task = litebox_common_linux::TaskParams {
        pid,
        ppid: 0,
        uid: GUEST_UID,
        euid: GUEST_UID,
        gid: GUEST_GID,
        egid: GUEST_GID,
        blocked_signals: litebox_common_linux::signal::SigSet::empty(),
        ignored_signals: litebox_common_linux::signal::SigSet::empty(),
        inherited_fds: None,
        cwd: None,
        umask: None,
    };
    let litebox_shim_linux::LoadedProgram {
        entrypoints,
        process,
    } = match shim.load_program(task, initial_thread, &path, argv, envp) {
        Ok(program) => program,
        Err(error) => {
            litebox_util_log::error!(error:% = error; "failed to load the program");
            return RUNNER_FAILURE;
        }
    };
    // Safety: no other guest thread runs.
    unsafe {
        litebox_platform_vm_userland::thread::run_thread_ref(
            &entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    // Detaches the only thread, ending the process; until then, waiting for
    // it would block forever.
    drop(entrypoints);
    let status = process.wait_for_exit_status();
    litebox_util_log::info!(status:? = status; "the program ended");
    exit_code(status)
}

/// The NUL-terminated strings in `image`.
fn strings(image: Image) -> Vec<CString> {
    assert!(
        image.len <= image.region.len,
        "image length exceeds its region"
    );
    let start: usize = image.region.start.trunc();
    // Safety: images are mapped read-only for the process's lifetime, and
    // nothing writes them.
    let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, image.len.trunc()) };
    decode_strings(bytes)
        .expect("NUL-terminated strings")
        .into_iter()
        .map(|s| CString::new(s).expect("no interior NULs"))
        .collect()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    use core::fmt::Write as _;
    let mut message = Message::new();
    let _ = write!(message, "runner panic: {info}");
    kcall::log(LogLevel::Error, message.as_str());
    kcall::exit(RUNNER_FAILURE)
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
