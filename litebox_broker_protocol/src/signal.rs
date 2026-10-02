// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signals sent between broker processes.
//!
//! Signals are numbered from one to [`MAX_SIGNAL`]. The broker keeps at most
//! one pending instance of each signal per process, so repeated signals
//! coalesce until the process takes them.

use crate::{ObjectHandle, ProcessId};

/// Largest signal number the broker delivers.
pub const MAX_SIGNAL: u32 = 64;

/// Request to send a signal to a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSignalRequest {
    /// Target process.
    ///
    /// The broker returns `UnknownObject` if no such process exists.
    pub process_id: ProcessId,
    /// Signal number, or zero to only check that the target exists.
    ///
    /// The broker returns `UnsupportedOperation` for a number above
    /// [`MAX_SIGNAL`].
    pub signal: u32,
}

/// Response to a request opening the caller's signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenSignalsResponse {
    /// Handle that becomes readable while signals are pending.
    pub handle: ObjectHandle,
}

/// Request to take one of the caller's pending signals.
///
/// The broker returns `WouldBlock` when no signal is pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSignalRequest {
    /// Handle returned by the open request.
    pub handle: ObjectHandle,
}

/// A signal taken from the caller's pending signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSignal {
    /// Signal number, from one to [`MAX_SIGNAL`].
    pub signal: u32,
    /// Process that first sent the signal while it was pending.
    pub sender: ProcessId,
}
