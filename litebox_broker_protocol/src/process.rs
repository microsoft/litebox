// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::shared_buffer::SharedBufferSequence;
use crate::{ObjectHandle, ProcessId, ThreadId};

/// Maximum size of one process bootstrap carried through the broker.
pub const MAX_PROCESS_BOOTSTRAP_SIZE: u32 = 64 * 1024;

/// Child startup descriptor transported through the broker protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStartupDescriptor {
    /// Operation-scoped shared-buffer sequence containing the bootstrap bytes.
    pub buffer: SharedBufferSequence,
}

/// Owned child startup data delivered during broker negotiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStartupData {
    /// Opaque runner-defined bytes whose schema follows the broker protocol version.
    pub payload: Vec<u8>,
}

/// Broker-assigned process and initial-thread identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Broker-assigned process ID.
    pub process_id: ProcessId,
    /// Broker-assigned initial thread ID.
    pub initial_thread_id: ThreadId,
}

/// Portable process termination status retained until the process is reaped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessExitStatus {
    /// The process exited normally with the supplied status code.
    Exited { code: u32 },
    /// The process was terminated by a signal.
    Signaled {
        /// Signal number reported by the runner platform.
        signal: u32,
    },
    /// The runner terminated without an observable platform status.
    Unknown,
}

/// One newly created process and the creator's handle to it.
///
/// The handle reports [`ReadinessFlags::READ`](crate::readiness::ReadinessFlags::READ)
/// once the process terminates. Closing it releases the process's retained
/// exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedProcess {
    /// Broker-assigned process ID.
    pub process_id: ProcessId,
    /// Handle used to observe process termination.
    pub handle: ObjectHandle,
}

/// Result of starting one child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartedProcess {
    /// Started process identity.
    pub identity: ProcessIdentity,
    /// Handle to the process when this start request created it.
    ///
    /// Starting a pending child returns `None` because allocation already
    /// returned its handle.
    pub handle: Option<ObjectHandle>,
}

/// Selects whether thread creation extends the current process or creates a child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateThreadRequest {
    /// Creates another thread in the requesting process.
    Thread,
    /// Creates a pending child process and its initial thread.
    Process,
}

/// Successful thread or process creation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateThreadResponse {
    /// A thread was created in the requesting process.
    Thread(ThreadId),
    /// A pending child process was created.
    Process(CreatedProcess),
}

/// Source used to start one child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartChildProcessSource {
    /// Starts a child from an opaque platform bootstrap.
    Bootstrap(ProcessStartupDescriptor),
    /// Starts a child by duplicating the calling process from an encoded,
    /// input-only image whose exact length is the buffer sequence length.
    Duplicate(SharedBufferSequence),
}

/// Starts either a newly allocated child or a pending child created earlier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartChildProcessRequest {
    /// Existing pending child to start, or `None` to allocate a new child.
    pub child_process_id: Option<ProcessId>,
    /// Process startup source.
    pub source: StartChildProcessSource,
}
