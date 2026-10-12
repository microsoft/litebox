// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Program service on a [`Process`], in the message format of
//! [`litebox_common_vm_abi::program`]: a process runs one program, on
//! whichever guest OS its runner provides, then replies with its exit status.

use crate::{Dead, Process};
use litebox_common_vm_abi::program::{self, ExitStatus, Program};

/// Why a program did not run to completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    /// The request does not encode or does not fit the message window.
    BadProgram,
    Dead(Dead),
}

/// Runs `program` in `process` and returns its exit status. A malformed reply
/// kills the process.
///
/// # Errors
///
/// See [`RunError`].
///
/// # Panics
///
/// If the process was not started.
pub fn run(process: &mut Process, program: &Program) -> Result<ExitStatus, RunError> {
    let request = program::encode_request(program)
        .filter(|request| request.len() as u64 <= crate::MAX_MESSAGE_LEN)
        .ok_or(RunError::BadProgram)?;
    let reply = process.call(&request).map_err(RunError::Dead)?;
    program::decode_reply(&reply)
        .ok_or_else(|| RunError::Dead(process.kill("malformed program reply")))
}
