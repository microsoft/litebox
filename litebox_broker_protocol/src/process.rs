// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::process_group::ProcessGroupMembership;
use crate::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SHARED_BUFFER_SLOT_SIZE, SharedBufferSequence,
};
use crate::{ProcessGroupId, ProcessId, ThreadId};

/// Maximum size of one process bootstrap carried through the broker.
pub const MAX_PROCESS_BOOTSTRAP_SIZE: u32 = 64 * 1024;

/// Maximum size of opaque platform data used to adopt an already-created runner.
pub const MAX_PROCESS_LAUNCH_DESCRIPTOR_SIZE: u32 = 4 * 1024;

/// Maximum combined launch descriptor and process bootstrap size.
pub const MAX_EXISTING_RUNNER_START_SIZE: u32 =
    MAX_PROCESS_LAUNCH_DESCRIPTOR_SIZE + MAX_PROCESS_BOOTSTRAP_SIZE;

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

/// Portable process termination status retained until it is collected.
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

/// A child process's exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildExit {
    /// Child that exited.
    pub process_id: ProcessId,
    /// Child's termination status.
    pub exit_status: ProcessExitStatus,
}

/// Selects which of the caller's children an exit collection considers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildSelector {
    /// Any child.
    Any,
    /// One child.
    Process(ProcessId),
    /// Any child in a process group.
    ProcessGroup(ProcessGroupId),
}

/// A process's place in the process tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process that created this one, absent for a root process.
    ///
    /// The creator never changes, even after it exits.
    pub creator: Option<ProcessId>,
    /// Process that collects this one's exit.
    ///
    /// The parent starts as the creator. When it exits, the nearest running
    /// ancestor that adopts orphans becomes the parent, or none does and the
    /// process's exit is discarded.
    pub parent: Option<ProcessId>,
    /// Process group and session.
    pub membership: ProcessGroupMembership,
}

/// The process a thread belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadInfo {
    /// Process the thread belongs to.
    pub process_id: ProcessId,
    /// Whether the thread is the process's initial thread.
    pub initial: bool,
}

/// Starts a pending child created earlier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartChildProcessRequest {
    /// Pending child to start.
    pub child_process_id: ProcessId,
    /// Opaque platform bootstrap for the child.
    ///
    /// The child's runner also receives the memory image written by
    /// [`WriteChildMemoryRequest`]s, if any.
    pub startup: ProcessStartupDescriptor,
}

/// Starts a pending child in an already-created platform runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartChildWithExistingRunnerRequest {
    /// Pending child to start.
    pub child_process_id: ProcessId,
    /// Number of bytes at the beginning of `data` containing the opaque platform descriptor.
    pub launch_descriptor_length: u32,
    /// Operation-scoped sequence containing the platform descriptor followed by startup bytes.
    pub data: SharedBufferSequence,
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
const MAX_CHILD_MEMORY_WRITE_SLOT_COUNT: u32 = 16;

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
    /// Termination status retained until it is collected.
    pub exit_status: ProcessExitStatus,
}
