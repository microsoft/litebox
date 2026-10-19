// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Program service on a [`Process`], in the message format of
//! [`litebox_common_vm_abi::program`]: a process runs one program, on
//! whichever guest OS its runner provides, then replies with its exit status.

use crate::sched::Scheduler;
use crate::{Dead, Process};
use alloc::vec::Vec;
use litebox_common_vm_abi::program::{self, ExitStatus, Program};

/// Why a program did not run to completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    /// The request does not encode or does not fit the message window.
    BadProgram,
    Dead(Dead),
}

/// Runs each program in its process, all at once, in `scheduler`, and returns
/// their exit statuses, in order. A malformed reply kills the process.
///
/// # Panics
///
/// If a process was not started.
pub fn run_all(
    scheduler: &Scheduler,
    runs: &mut [(&mut Process, &Program)],
) -> Vec<Result<ExitStatus, RunError>> {
    let mut replies: Vec<Option<Result<ExitStatus, RunError>>> = runs
        .iter_mut()
        .map(|(process, program)| submit(process, program).err().map(Err))
        .collect();
    let mut collect = || {
        for ((process, _), reply) in runs.iter_mut().zip(&mut replies) {
            if reply.is_none() && process.is_stopped() {
                *reply = Some(self::reply(process));
            }
        }
        replies.iter().all(Option::is_some)
    };
    scheduler.run_until(&mut collect);
    // The last step may have stopped some (e.g., killed them).
    collect();
    replies
        .into_iter()
        .map(|reply| reply.expect("a submitted process ran to a wait"))
        .collect()
}

fn submit(process: &mut Process, program: &Program) -> Result<(), RunError> {
    let request = program::encode_request(program)
        .filter(|request| request.len() as u64 <= crate::MAX_MESSAGE_LEN)
        .ok_or(RunError::BadProgram)?;
    process.submit(&request).map_err(RunError::Dead)
}

fn reply(process: &mut Process) -> Result<ExitStatus, RunError> {
    let reply = process.reply().map_err(RunError::Dead)?;
    program::decode_reply(&reply)
        .ok_or_else(|| RunError::Dead(process.kill("malformed program reply")))
}
