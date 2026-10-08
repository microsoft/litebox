// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's broker association: control frames in kernel calls, payloads
//! in the process's broker shared memory.

use alloc::sync::Arc;
use core::cell::{Cell, RefCell};
use core::convert::Infallible;
use litebox_broker_core::BrokerCore;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_host::BrokerHostAssociation;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_LAYOUT;
use litebox_broker_protocol::wire;
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError};
use litebox_common_vm_abi::{BrokerOp, Status, UserRange, WireFrame};

/// Accessed through the process's user mapping: valid only while that
/// process's address space is current, which holds because the broker host
/// touches it only during that process's kernel calls.
pub(crate) struct UserSharedMemory {
    region: UserRange,
}

impl UserSharedMemory {
    fn checked(&self, offset: usize, len: usize) -> Result<u64, SharedMemoryError> {
        let end = offset
            .checked_add(len)
            .ok_or(SharedMemoryError::InvalidRange)?;
        if end > self.len() {
            return Err(SharedMemoryError::InvalidRange);
        }
        Ok(self.region.start + offset as u64)
    }
}

impl SharedMemory for UserSharedMemory {
    fn len(&self) -> usize {
        usize::try_from(self.region.len).unwrap_or(0)
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let addr = self.checked(offset, destination.len())?;
        let bytes = crate::memory::copy_from_user(addr, destination.len())
            .map_err(|_| SharedMemoryError::AccessFailed)?;
        destination.copy_from_slice(&bytes);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let addr = self.checked(offset, source.len())?;
        crate::memory::copy_to_user(addr, source).map_err(|_| SharedMemoryError::AccessFailed)
    }
}

/// Assumes no broker object a process can create needs readiness.
struct NoReadiness;

impl ReadinessSink for NoReadiness {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(
        &self,
        _handle: ObjectHandle,
        _readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        Ok(())
    }

    fn republish(
        &self,
        _handle: ObjectHandle,
        _readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

/// One handshake request in, one response out.
struct KernelHostSetup {
    request: Option<BrokerHandshakeRequest>,
    response: Option<BrokerHandshakeResponse>,
}

impl HostSetupChannel for KernelHostSetup {
    type Error = Infallible;

    /// The kernel created the process, so it vouches for it.
    fn peer_credential(&self) -> Result<PeerCredential, Infallible> {
        Ok(PeerCredential::HostGuaranteed)
    }

    fn recv_handshake_request(
        &mut self,
    ) -> Result<HostReceive<BrokerHandshakeRequest>, Infallible> {
        Ok(self
            .request
            .take()
            .map_or(HostReceive::PeerClosed, HostReceive::Message))
    }

    fn send_handshake_response(
        &mut self,
        response: &BrokerHandshakeResponse,
    ) -> Result<(), Infallible> {
        self.response = Some(response.clone());
        Ok(())
    }
}

pub(crate) struct Broker {
    core: BrokerCore,
    shared_memory: UserRange,
    association: RefCell<Option<BrokerHostAssociation<UserSharedMemory>>>,
    handshake_attempted: Cell<bool>,
}

/// [`Status::Unsupported`] if the response does not fit a [`WireFrame`].
fn frame(bytes: &[u8]) -> Result<WireFrame, Status> {
    WireFrame::new(bytes).ok_or(Status::Unsupported)
}

impl Broker {
    pub(crate) fn new(core: BrokerCore, shared_memory: UserRange) -> Self {
        Self {
            core,
            shared_memory,
            association: RefCell::new(None),
            handshake_attempted: Cell::new(false),
        }
    }

    /// One attempt, successful or not.
    pub(crate) fn handshake(&self, request: &WireFrame) -> Result<WireFrame, Status> {
        if self.handshake_attempted.replace(true) {
            return Err(Status::Denied);
        }
        let request =
            wire::decode_handshake_request(request.as_slice().ok_or(Status::InvalidArgument)?)
                .map_err(|_| Status::InvalidArgument)?;
        let shared_buffers = SharedBufferPool::new(
            UserSharedMemory {
                region: self.shared_memory,
            },
            SHARED_BUFFER_LAYOUT,
        )
        .map_err(|_| Status::Unsupported)?;
        let mut setup = KernelHostSetup {
            request: Some(request),
            response: None,
        };
        let readiness: Arc<dyn ReadinessSink> = Arc::new(NoReadiness);
        let result = litebox_broker_host::setup_connection(
            &self.core,
            None,
            None,
            &mut setup,
            Arc::new(shared_buffers),
            readiness,
            |_| false,
            |_| Ok(()),
        );
        if let Ok(Ok(association)) = result {
            if association.activate_process().is_err() {
                // Releases its broker process ID.
                association.finish();
                return Err(Status::Denied);
            }
            *self.association.borrow_mut() = Some(association);
        }
        let response = setup.response.ok_or(Status::Denied)?;
        frame(&wire::encode_handshake_response(response))
    }

    /// # Errors
    ///
    /// [`CallError::NotPermitted`] before execution if `permits` rejects the
    /// operation.
    pub(crate) fn call(
        &self,
        request: &WireFrame,
        permits: impl FnOnce(BrokerOp) -> bool,
    ) -> Result<WireFrame, CallError> {
        let association = self.association.borrow();
        let association = association.as_ref().ok_or(Status::Denied)?;
        let request = wire::decode_request(request.as_slice().ok_or(Status::InvalidArgument)?)
            .map_err(|_| Status::InvalidArgument)?;
        let op = op_kind(&request.operation);
        if !permits(op) {
            return Err(CallError::NotPermitted(op));
        }
        let mut response = None;
        association
            .execute_request(request, |r| {
                response = Some(r.clone());
                Ok::<(), Infallible>(())
            })
            .map_err(|_| Status::Denied)?;
        Ok(frame(&wire::encode_response(
            response.ok_or(Status::Denied)?,
        ))?)
    }
}

pub(crate) enum CallError {
    Status(Status),
    NotPermitted(BrokerOp),
}

impl From<Status> for CallError {
    fn from(status: Status) -> Self {
        Self::Status(status)
    }
}

/// Exhaustive: a new broker operation must be classified.
fn op_kind(operation: &BrokerOperation) -> BrokerOp {
    match operation {
        BrokerOperation::CreateThread(_) => BrokerOp::CreateThread,
        BrokerOperation::ExitThread(_) => BrokerOp::ExitThread,
        BrokerOperation::CloseObject(_) => BrokerOp::CloseObject,
        BrokerOperation::CheckReadiness(_) => BrokerOp::CheckReadiness,
        BrokerOperation::GetStatusFlags(_) => BrokerOp::GetStatusFlags,
        BrokerOperation::SetStatusFlags(_) => BrokerOp::SetStatusFlags,
        BrokerOperation::Event(_) => BrokerOp::Event,
        BrokerOperation::Pipe(_) => BrokerOp::Pipe,
        BrokerOperation::Socket(_) => BrokerOp::Socket,
        BrokerOperation::FillRandom(_) => BrokerOp::FillRandom,
        BrokerOperation::File(_) => BrokerOp::File,
        BrokerOperation::StartChildProcess(_) => BrokerOp::StartChildProcess,
        BrokerOperation::GetProcessExitStatus(_) => BrokerOp::GetProcessExitStatus,
        BrokerOperation::ExitChildProcess(_) => BrokerOp::ExitChildProcess,
        BrokerOperation::ReportExitStatus(_) => BrokerOp::ReportExitStatus,
        BrokerOperation::SetChildReaping(_) => BrokerOp::SetChildReaping,
        BrokerOperation::DuplicateObjectsToChild(_) => BrokerOp::DuplicateObjectsToChild,
        BrokerOperation::WriteChildMemory(_) => BrokerOp::WriteChildMemory,
        BrokerOperation::Timer(_) => BrokerOp::Timer,
        BrokerOperation::Signal(_) => BrokerOp::Signal,
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        if let Some(association) = self.association.get_mut().take() {
            association.finish();
        }
    }
}
