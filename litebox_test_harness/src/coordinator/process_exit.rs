// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process-exit readiness smoke tests for Phase G.

use serde::{Deserialize, Serialize};

use crate::handlers::{HandlerCtx, HandlerError, HandlerToken};
use crate::register_handler;

use super::TestOutcome;
use super::agents::AgentName;
use super::registry::Registry;

#[derive(Debug, Serialize, Deserialize)]
struct ProcessExitOut {
    child_pid: u32,
    exit_code: i32,
    observed: bool,
}

const SUBSCRIBE_THEN_EXIT: HandlerToken<(), ProcessExitOut> =
    HandlerToken::new("process_exit.subscribe_then_exit");
const EXIT_THEN_LATE_SUBSCRIBE: HandlerToken<(), ProcessExitOut> =
    HandlerToken::new("process_exit.exit_then_late_subscribe");

async fn handle_subscribe_then_exit(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ProcessExitOut, HandlerError> {
    fork_and_wait_after_delay(23, true)
}

async fn handle_exit_then_late_subscribe(
    _args: (),
    _ctx: &mut HandlerCtx<'_>,
) -> Result<ProcessExitOut, HandlerError> {
    fork_and_wait_after_delay(42, false)
}

fn fork_and_wait_after_delay(
    exit_code: i32,
    delay_child: bool,
) -> Result<ProcessExitOut, HandlerError> {
    // SAFETY: fork creates a child process. The child only optionally sleeps
    // then calls _exit; the parent continues Rust execution and waitpids it.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(HandlerError(format!(
            "fork: {}",
            std::io::Error::last_os_error()
        )));
    }
    if child == 0 {
        // SAFETY: child terminates directly and does not resume Rust runtime.
        unsafe {
            if delay_child {
                libc::usleep(100_000);
            }
            libc::_exit(exit_code);
        }
    }

    if !delay_child {
        // Let the child reach zombie state before the parent observes it.
        // SAFETY: sleeping in the parent is harmless.
        unsafe { libc::usleep(100_000) };
    }

    let mut status = 0;
    // SAFETY: waiting for the exact child pid returned by fork.
    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
    if waited != child {
        return Err(HandlerError(format!(
            "waitpid({child}) returned {waited}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let observed = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == exit_code;
    Ok(ProcessExitOut {
        child_pid: u32::try_from(child).map_err(|e| HandlerError(e.to_string()))?,
        exit_code,
        observed,
    })
}

pub(crate) fn register_process_exit_tests(reg: &mut Registry<'_>) {
    register_handler!(SUBSCRIBE_THEN_EXIT, handle_subscribe_then_exit);
    register_handler!(EXIT_THEN_LATE_SUBSCRIBE, handle_exit_then_late_subscribe);

    reg.test("vscode", "process_exit", "PXP.broker_subscribe_then_exit")
        .timeout(20)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    match run.send_named_typed(&agent, &SUBSCRIBE_THEN_EXIT, ()).await {
                        Ok(out) if out.observed => TestOutcome::new(
                            "Dpg1",
                            true,
                            format!("observed child {} exit {}", out.child_pid, out.exit_code),
                        ),
                        Ok(out) => TestOutcome::new(
                            "Dpg1",
                            false,
                            format!(
                                "did not observe child {} exit {}",
                                out.child_pid, out.exit_code
                            ),
                        ),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler error: {e}")),
                    }
                })
            })
        });

    reg.test("vscode", "process_exit", "PXP.exit_then_late_subscribe")
        .timeout(20)
        .build(|cx| {
            let agent = cx.require(AgentName::Dpg1);
            Box::new(move |run| {
                Box::pin(async move {
                    match run
                        .send_named_typed(&agent, &EXIT_THEN_LATE_SUBSCRIBE, ())
                        .await
                    {
                        Ok(out) if out.observed => TestOutcome::new(
                            "Dpg1",
                            true,
                            format!(
                                "late observer saw child {} exit {}",
                                out.child_pid, out.exit_code
                            ),
                        ),
                        Ok(out) => TestOutcome::new(
                            "Dpg1",
                            false,
                            format!(
                                "late observer missed child {} exit {}",
                                out.child_pid, out.exit_code
                            ),
                        ),
                        Err(e) => TestOutcome::new("Dpg1", false, format!("handler error: {e}")),
                    }
                })
            })
        });

    reg.test("vscode", "process_exit", "PXP.cross_worker_subscribe")
        .timeout(20)
        .build(|cx| {
            let subscriber = cx.require(AgentName::Dpg1);
            let target = cx.require(AgentName::Dpg2);
            Box::new(move |run| {
                Box::pin(async move {
                    let _subscriber_ready = subscriber;
                    match run
                        .send_named_typed(&target, &SUBSCRIBE_THEN_EXIT, ())
                        .await
                    {
                        Ok(out) if out.observed => TestOutcome::new(
                            "Dpg1/Dpg2",
                            true,
                            format!(
                                "cross-worker observed child {} exit {}",
                                out.child_pid, out.exit_code
                            ),
                        ),
                        Ok(out) => TestOutcome::new(
                            "Dpg1/Dpg2",
                            false,
                            format!(
                                "cross-worker missed child {} exit {}",
                                out.child_pid, out.exit_code
                            ),
                        ),
                        Err(e) => {
                            TestOutcome::new("Dpg1/Dpg2", false, format!("handler error: {e}"))
                        }
                    }
                })
            })
        });
}
