// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

/// Association-scoped token for acknowledging a child process start.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessStartToken(pub u64);

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

/// Opaque bootstrap descriptor supplied when starting a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessBootstrap {
    /// Platform-defined format.
    pub format: ProcessBootstrapFormat,
    /// Version within the platform-defined format.
    pub version: ProcessBootstrapVersion,
    /// Operation-scoped shared-buffer sequence containing the bootstrap bytes.
    pub buffer: SharedBufferSequence,
}

/// Child startup data delivered during broker negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStartup {
    /// Opaque platform bootstrap staged in the child's shared-buffer pool.
    pub bootstrap: ProcessBootstrap,
    /// Child-owned broker handles in the parent's inheritance-manifest order.
    pub inherited_objects: InheritedProcessObjects,
}

/// Starts one child process from an opaque platform bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartProcessRequest {
    /// Opaque bootstrap staged in the parent's shared-buffer pool.
    pub bootstrap: ProcessBootstrap,
    /// Parent-owned broker handles inherited in manifest order.
    pub inherited_objects: InheritedProcessObjects,
}

/// Reports a materialized child that is ready for parent acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartedProcess {
    /// Token that must be acknowledged before the child may begin guest execution.
    pub token: ProcessStartToken,
    /// Broker-assigned child process ID.
    pub process_id: ProcessId,
    /// Broker-assigned initial thread ID when it differs from the process ID.
    pub initial_thread_id: Option<ThreadId>,
}

/// Reports that a child finished restoring its initial state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessReadyRequest {
    /// Broker-assigned initial thread ID when it differs from the process ID.
    pub initial_thread_id: Option<ThreadId>,
}
