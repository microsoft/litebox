// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs init, the guest's process 1, until it exits.

use alloc::ffi::CString;
use core::time::Duration;
use litebox_broker_vm_kernel::BrokerHandle;
use litebox_common_vm_abi::program::{self, ExitStatus, Program};
use litebox_hal::serial_println;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::{VmKernel, cpu};
use litebox_shim_vm_kernel::sched::Scheduler;
use litebox_shim_vm_kernel::{Dead, MAX_MESSAGE_LEN, Process, ProcessConfig};

/// The command line's key for init's path.
pub const PATH_KEY: &str = "litebox.init";

/// Init's path without [`PATH_KEY`]: the guest service.
pub const DEFAULT_PATH: &str = "/.litebox/guest-service";

/// The command line's key that, set to `0`, runs init as an ordinary process, which other
/// processes can kill.
#[cfg(debug_assertions)]
pub const AS_INIT_KEY: &str = "litebox.root_process_as_init";

/// The command line's key that, set to `1`, sets [`ProcessConfig::give_up_once`].
#[cfg(debug_assertions)]
pub const REPLAY_KEY: &str = "litebox.replay";

/// The payload's file with the runner of init and its descendants.
pub const RUNNER: &str = "linux-runner.elf";

/// The payload's `policy` (see `litebox_broker_vm_kernel`'s docs); without
/// it, sockets reach only the guest network.
pub const POLICY: &str = "policy";

/// Why init did not run to completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    /// The request does not encode or does not fit the message window.
    BadProgram,
    Dead(Dead),
}

/// Runs the program at `path` as init until it exits, and reports its outcome. Debug builds
/// give it `hooks`' arguments and hooks, then run the other processes until idle, and check that
/// the hooks acted and the processes left nothing behind.
///
/// # Panics
///
/// If init's runner process cannot be spawned, or, in debug builds, if a check fails.
pub fn run(
    scheduler: &Scheduler,
    platform: &'static VmKernel,
    broker: &BrokerHandle,
    config: &ProcessConfig<'_>,
    path: &str,
    #[cfg(debug_assertions)] hooks: &crate::test_hooks::Boot,
) -> Result<ExitStatus, RunError> {
    let mut process = Process::spawn(scheduler, platform, broker, config)
        .unwrap_or_else(|error| panic!("failed to spawn init's runner: {error}"));
    let status = run_program(
        &mut process,
        path,
        #[cfg(debug_assertions)]
        hooks,
    );
    process.finish();
    // Before the debug checks, which a descendant that never ends blocks.
    report(status);
    if cfg!(debug_assertions) {
        scheduler.run_until_idle();
        #[cfg(debug_assertions)]
        hooks.check();
        drop(process);
        check_released(scheduler, platform);
    }
    status
}

/// Prints init's outcome for the test scripts.
fn report(status: Result<ExitStatus, RunError>) {
    match status {
        Ok(ExitStatus::Exited { code }) => {
            serial_println!("[litebox] init exit status: exited {code}");
        }
        Ok(ExitStatus::Signaled { signal }) => {
            serial_println!("[litebox] init exit status: signaled {signal}");
        }
        Ok(ExitStatus::Unknown) => serial_println!("[litebox] init exit status: unknown"),
        Err(RunError::BadProgram) => {
            serial_println!("[litebox] init exit status: not run (bad program)");
        }
        Err(RunError::Dead(dead)) => {
            serial_println!("[litebox] init exit status: its runner died ({dead:?})");
        }
    }
}

fn run_program(
    process: &mut Process,
    path: &str,
    #[cfg(debug_assertions)] hooks: &crate::test_hooks::Boot,
) -> Result<ExitStatus, RunError> {
    let argv0 = CString::new(path).map_err(|_| RunError::BadProgram)?;
    #[cfg(debug_assertions)]
    let argv = core::iter::once(Ok(argv0))
        .chain(hooks.args.iter().map(|&arg| CString::new(arg)))
        .collect::<Result<_, _>>()
        .map_err(|_| RunError::BadProgram)?;
    #[cfg(not(debug_assertions))]
    let argv = alloc::vec![argv0];
    let request = program::encode_request(&Program {
        path: path.into(),
        argv,
        envp: alloc::vec![],
    })
    .filter(|request| request.len() as u64 <= MAX_MESSAGE_LEN)
    .ok_or(RunError::BadProgram)?;
    process.start().map_err(RunError::Dead)?;
    let reply = process.call(&request).map_err(RunError::Dead)?;
    program::decode_reply(&reply)
        .ok_or_else(|| RunError::Dead(process.kill("malformed program reply")))
}

/// Checks that the ended processes left no address space, shared frame or
/// broker stack behind: the one stack left is the source thread's.
///
/// # Panics
///
/// If they did.
fn check_released(scheduler: &Scheduler, platform: &VmKernel) {
    const TIMEOUT: Duration = Duration::from_secs(5);
    /// Between looks, which take the locks that releases take.
    const BACKOFF: Duration = Duration::from_micros(100);
    let released = || {
        scheduler.reap();
        platform.address_space_count() == 0 && platform.shared_frame_count() == 0
    };
    let after = |duration| {
        platform
            .now()
            .checked_add(duration)
            .expect("the clock is far from overflowing")
    };
    let deadline = after(TIMEOUT);
    while !released() && platform.now() < deadline {
        let next = after(BACKOFF);
        while platform.now() < next {
            cpu::relax();
        }
    }
    assert_eq!(
        platform.address_space_count(),
        0,
        "ended processes left address spaces, after waiting {TIMEOUT:?} for the other CPUs"
    );
    assert_eq!(
        platform.shared_frame_count(),
        0,
        "ended processes left shared frames, after waiting {TIMEOUT:?} for the other CPUs"
    );
    assert_eq!(
        litebox_platform_vm_kernel::kthread::stacks(),
        1,
        "ended processes left broker stacks"
    );
}
