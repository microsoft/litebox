// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence,
};
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

/// A terminated process's status as its handle observes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessTermination {
    /// Termination status.
    pub exit_status: ProcessExitStatus,
    /// Whether the process was reaped when it terminated, so no wait reports
    /// it.
    pub reaped: bool,
}

/// One newly created process and the creator's handle to it.
///
/// The handle reports [`ReadinessFlags::READ`](crate::readiness::ReadinessFlags::READ)
/// once the process terminates. Closing it releases the process's retained
/// exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedProcess {
    /// Broker-assigned process identity.
    pub identity: ProcessIdentity,
    /// Handle used to observe process termination.
    pub handle: ObjectHandle,
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
    ///
    /// The child's runner also receives the memory image written by
    /// [`WriteChildMemoryRequest`]s, if any.
    Bootstrap(ProcessStartupDescriptor),
}

/// Starts a pending child created earlier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartChildProcessRequest {
    /// Pending child to start.
    pub child_process_id: ProcessId,
    /// Process startup source.
    pub source: StartChildProcessSource,
}

/// Maximum number of object references one [`DuplicateObjectsToChildRequest`]
/// duplicates, which fill one shared-buffer slot.
pub const MAX_CHILD_OBJECT_DUPLICATES: u32 = SHARED_BUFFER_SLOT_SIZE / 8;

/// Duplicates the caller's object references into its pending child, as a
/// Linux child inherits its parent's descriptors.
///
/// `handles` holds the caller's handles as consecutive little-endian `u64`
/// values. On success, the broker overwrites them in place with the child's
/// handles in the same order. Either every reference is duplicated or none is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuplicateObjectsToChildRequest {
    /// Pending child that receives the duplicates.
    pub child_process_id: ProcessId,
    /// Operation-scoped shared-buffer sequence holding between one and
    /// [`MAX_CHILD_OBJECT_DUPLICATES`] handles.
    pub handles: SharedBufferSequence,
}

/// Number of shared-buffer slots one [`WriteChildMemoryRequest`] fills at most.
const MAX_CHILD_MEMORY_WRITE_SLOT_COUNT: u32 = 8;

const _: () =
    assert!(MAX_CHILD_MEMORY_WRITE_SLOT_COUNT as usize <= MAX_SHARED_BUFFER_SEQUENCE_SLOTS);

/// Maximum number of bytes one [`WriteChildMemoryRequest`] writes.
pub const MAX_CHILD_MEMORY_WRITE_SIZE: u32 =
    SHARED_BUFFER_SLOT_SIZE * MAX_CHILD_MEMORY_WRITE_SLOT_COUNT;

/// Writes bytes into the memory image of the caller's pending child, as a
/// Linux `fork` child starts from a copy of its parent's memory.
///
/// The image is a byte array, zero wherever it was not written, that the
/// child's runner receives when the child starts. Its layout is opaque to the
/// broker. A pending child has no image until it is first written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteChildMemoryRequest {
    /// Pending child whose image receives the bytes.
    pub child_process_id: ProcessId,
    /// Image offset of the first byte.
    pub offset: u64,
    /// Operation-scoped shared-buffer sequence holding between one and
    /// [`MAX_CHILD_MEMORY_WRITE_SIZE`] bytes.
    pub data: SharedBufferSequence,
}

/// Records the exit of a pending child that ran without starting its own
/// runner, as a Linux `vfork` child does before `execve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitChildProcessRequest {
    /// Pending child that exited.
    pub child_process_id: ProcessId,
    /// Termination status retained until the child is reaped.
    pub exit_status: ProcessExitStatus,
}
