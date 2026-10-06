// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signals sent between broker processes, and changes to their children
//! reported to parents.
//!
//! Signals are numbered from one to [`MAX_SIGNAL`]. The broker keeps at most
//! one pending instance of each signal per process, so repeated signals
//! coalesce until the process takes them. Child events coalesce the same way:
//! a parent has at most one pending child exit, the earliest since it last
//! took one, and at most one pending child removal.

use crate::process::ChildExit;
use crate::{ObjectHandle, ProcessId};

/// Largest signal number the broker delivers.
pub const MAX_SIGNAL: u32 = 64;

/// Process or processes a signal is sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalTarget {
    /// One process.
    Process(ProcessId),
    /// Every process in a process group.
    ProcessGroup(ProcessId),
    /// Every process except the caller and the root processes, which have no
    /// creator.
    All,
}

/// Request to send a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSignalRequest {
    /// Target processes.
    ///
    /// The broker returns `UnknownObject` if no process is targeted.
    pub target: SignalTarget,
    /// Signal number, or zero to only check that a target exists.
    ///
    /// The broker returns `UnsupportedOperation` for a number above
    /// [`MAX_SIGNAL`].
    pub signal: u32,
}

/// Response to a request opening the caller's signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenSignalsResponse {
    /// Handle that becomes readable while signals or child events are pending.
    pub handle: ObjectHandle,
}

/// Request to take one of the caller's pending signals or its pending child
/// exit.
///
/// The broker returns `WouldBlock` when neither is pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSignalRequest {
    /// Handle returned by the open request.
    pub handle: ObjectHandle,
}

/// One event taken from the caller's signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalEvent {
    /// A signal another process sent.
    Signal(PendingSignal),
    /// The earliest child exit since the caller last took one.
    ChildExited(ChildExit),
    /// One or more children left the caller without exiting since it last
    /// took this event, such as a child whose startup failed.
    ///
    /// A reap that found only such children live no longer finds them.
    ChildRemoved,
}

/// A signal taken from the caller's pending signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSignal {
    /// Signal number, from one to [`MAX_SIGNAL`].
    pub signal: u32,
    /// Process that first sent the signal while it was pending.
    pub sender: ProcessId,
}
