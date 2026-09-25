// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use crate::shared_buffer::SharedBufferSequence;
use crate::{ObjectHandle, ProcessId, ThreadId};

/// Maximum size of one versioned process bootstrap carried through the broker.
pub const MAX_PROCESS_BOOTSTRAP_SIZE: u32 = 64 * 1024;

/// Maximum number of broker objects inherited by the bounded initial contract.
pub const MAX_INHERITED_PROCESS_OBJECTS: usize = 4;

/// Platform-defined process-bootstrap format.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessBootstrapFormat(pub u32);

/// Version of a platform-defined process-bootstrap format.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessBootstrapVersion(pub u16);

/// Ordered broker-object handles inherited by a child.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InheritedProcessObjects {
    handles: [ObjectHandle; MAX_INHERITED_PROCESS_OBJECTS],
    count: u8,
}

impl InheritedProcessObjects {
    /// Empty inherited-object list.
    pub const EMPTY: Self = Self {
        handles: [ObjectHandle(0); MAX_INHERITED_PROCESS_OBJECTS],
        count: 0,
    };

    /// Creates a bounded ordered inherited-object list.
    pub fn new(handles: &[ObjectHandle]) -> Option<Self> {
        if handles.len() > MAX_INHERITED_PROCESS_OBJECTS {
            return None;
        }
        let Ok(count) = u8::try_from(handles.len()) else {
            return None;
        };
        let mut stored = [ObjectHandle(0); MAX_INHERITED_PROCESS_OBJECTS];
        stored[..handles.len()].copy_from_slice(handles);
        Some(Self {
            handles: stored,
            count,
        })
    }

    /// Returns inherited handles in manifest order.
    #[must_use]
    pub fn as_slice(&self) -> &[ObjectHandle] {
        &self.handles[..usize::from(self.count)]
    }
}

/// Child startup descriptor transported through the broker protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStartupDescriptor {
    /// Platform-defined format.
    pub format: ProcessBootstrapFormat,
    /// Version within the platform-defined format.
    pub version: ProcessBootstrapVersion,
    /// Operation-scoped shared-buffer sequence containing the bootstrap bytes.
    pub buffer: SharedBufferSequence,
    /// Broker handles inherited in manifest order.
    pub inherited_objects: InheritedProcessObjects,
}

/// Owned child startup data delivered during broker negotiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStartupData {
    /// Platform-defined format.
    pub format: ProcessBootstrapFormat,
    /// Version within the platform-defined format.
    pub version: ProcessBootstrapVersion,
    /// Opaque platform bytes.
    pub payload: Vec<u8>,
    /// Child-owned broker handles in the parent's inheritance-manifest order.
    pub inherited_objects: InheritedProcessObjects,
}

/// Broker-assigned process and initial-thread identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// Broker-assigned process ID.
    pub process_id: ProcessId,
    /// Broker-assigned initial thread ID.
    pub initial_thread_id: ThreadId,
}

/// Selects how the broker starts one child process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartChildProcessRequest {
    /// Starts a child from an opaque platform bootstrap.
    Bootstrap(ProcessStartupDescriptor),
    /// Starts a child by duplicating the calling process from an encoded,
    /// input-only image whose exact length is the buffer sequence length.
    Duplicate(SharedBufferSequence),
}

/// One constrained shared-address-space `vfork` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VforkRequest {
    /// Allocates one pending child process and its initial thread identity.
    Create,
    /// Transfers a pending child into a fresh runner using a Program startup.
    Start {
        /// Pending child process allocated by [`Self::Create`].
        child_process_id: ProcessId,
        /// Program startup delivered to the fresh child runner.
        startup: ProcessStartupDescriptor,
    },
}

/// Successful result of a constrained `vfork` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VforkResponse {
    /// The pending child identity allocated for the shared execution window.
    Created(ProcessIdentity),
    /// The pending child established its fresh runner association.
    Started,
}
