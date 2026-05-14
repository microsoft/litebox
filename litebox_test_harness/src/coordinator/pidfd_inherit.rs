// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Handler-native pidfd inheritance smoke tests.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::os::pidfd::Pidfd;
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

#[derive(Debug, Serialize, Deserialize)]
struct PidfdSpawnOut {
    child_pid: u32,
    pidfd_raw: i32,
    fired: bool,
}

const PIDFD_SPAWN_AND_OPEN: HandlerToken<(), PidfdSpawnOut> =
    HandlerToken::new("pidfd_inherit.spawn_and_open");

async fn handle_pidfd_spawn_and_open(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<PidfdSpawnOut, HandlerError> {
    // SAFETY: fork creates a child process. The child performs only async-signal-safe
    // libc sleep followed by _exit; the parent continues Rust execution.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        // SAFETY: child process terminates directly after sleeping.
        unsafe {
            libc::sleep(1);
            libc::_exit(0);
        }
    }

    let child_pid = u32::try_from(child).map_err(|e| HandlerError(e.to_string()))?;
    let pidfd = Pidfd::open(child_pid).map_err(|e| HandlerError(format!("pidfd_open: {e}")))?;
    let fired = pidfd
        .poll_exit_in(5000)
        .map_err(|e| HandlerError(format!("pidfd poll: {e}")))?;
    let mut status = 0;
    // SAFETY: waiting for the child pid returned by fork.
    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
    if waited != child {
        return Err(HandlerError(format!(
            "waitpid({child}) returned {waited}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(PidfdSpawnOut {
        child_pid,
        pidfd_raw: std::os::fd::AsRawFd::as_raw_fd(&pidfd),
        fired,
    })
}

pub(crate) fn register_pidfd_inherit_tests(reg: &mut Registry<'_>) {
    register_handler!(PIDFD_SPAWN_AND_OPEN, handle_pidfd_spawn_and_open);

    reg.test("vscode", "pidfd_inherit", "PIFH.basic")
        .timeout(20)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    match run
                        .send_named_typed(&agent, &PIDFD_SPAWN_AND_OPEN, ())
                        .await
                    {
                        Ok(out) if out.fired => TestOutcome::new(
                            "Dpg1",
                            true,
                            format!(
                                "pidfd fd={} fired for child {}",
                                out.pidfd_raw, out.child_pid
                            ),
                        ),
                        Ok(out) => TestOutcome::new(
                            "Dpg1",
                            false,
                            format!(
                                "pidfd fd={} did not fire for child {}",
                                out.pidfd_raw, out.child_pid
                            ),
                        ),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler error: {e}")),
                    }
                })
            })
        });
}
