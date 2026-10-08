// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LiteBox VM kernel's broker, like `litebox_broker_userland` for hosted
//! runners: [`Broker`] is the kernel's, and each runner process has an
//! [`Association`] with it (see `litebox_common_vm_abi`, Broker). Requests and
//! responses are in the control ring, pinned and accessed through the
//! kernel's mapping; payloads are in the process's lazily populated shared
//! buffers.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod memory;
pub mod providers;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::Infallible;
use litebox_broker_core::BrokerCore;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_host::BrokerHostAssociation;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_protocol::wire;
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::control_ring::{
    BrokerControlRingEndpoints, CONTROL_RING_MEMORY_SIZE, ControlRing, ControlRingConsumer,
    ControlRingProducer, ControlRingReadStatus, ControlRingWriteStatus, MemoryAccessPolicy,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedBufferPool};
use litebox_common_vm_abi::{BrokerEnterOp, BrokerEnterRequest, Status, UserRange, WireFrame};
use litebox_platform_vm_kernel::PinnedUserPages;

use memory::{PinnedControlRing, UserSharedMemory};

/// Size of a process's broker shared memory.
pub const SHARED_MEMORY_SIZE: usize = SHARED_BUFFER_POOL_SIZE;

/// Size of a process's broker control ring.
pub const CONTROL_RING_SIZE: usize = CONTROL_RING_MEMORY_SIZE;

/// The kernel's broker; clones share it.
#[derive(Clone)]
pub struct Broker {
    core: BrokerCore,
}

impl Broker {
    /// Randomness only. At most once: only one broker core may exist.
    ///
    /// # Panics
    ///
    /// Without a hardware CSPRNG, or on a second call.
    #[expect(
        clippy::new_without_default,
        reason = "not `Default`: a second call panics"
    )]
    pub fn new() -> Self {
        Self::with_file_service(
            Arc::new(litebox_broker_core::fs::UnsupportedFileService),
            litebox_broker_core::ObjectRights::empty(),
        )
    }

    /// Randomness and `fs`, whose objects processes get `rights` to. At most
    /// once, as [`Self::new`].
    ///
    /// # Panics
    ///
    /// As [`Self::new`].
    pub fn with_file_service(
        fs: Arc<dyn litebox_broker_core::fs::FileService>,
        rights: litebox_broker_core::ObjectRights,
    ) -> Self {
        Self {
            core: providers::core(fs, rights),
        }
    }

    /// A process's association, before its handshake. `shared_memory` is in
    /// the process's user mapping; `control_ring` is at the start of
    /// `control_ring_pages`.
    ///
    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    pub fn associate(
        &self,
        shared_memory: UserRange,
        control_ring_pages: PinnedUserPages,
    ) -> Association {
        let memory =
            PinnedControlRing::new(control_ring_pages).expect("the pages hold the control ring");
        let ring = ControlRing::new(memory).expect("a pinned control ring has the exact size");
        Association {
            broker: self.clone(),
            shared_memory,
            state: RefCell::new(State::New(ring)),
        }
    }
}

/// Discards readiness: the broker provides only randomness, and files and
/// standard streams that are always ready. A provider with readiness (e.g.,
/// timers) needs a sink that publishes to the notification ring.
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

enum State {
    /// Before the handshake, with the ring it would activate.
    New(ControlRing<PinnedControlRing>),
    Active(Box<Active>),
    /// The handshake did not activate one, or it failed.
    Ended,
}

/// The broker's ends of the request and response rings. Its notification
/// producer awaits a provider with readiness (see `NoReadiness`).
struct Active {
    association: BrokerHostAssociation<UserSharedMemory>,
    requests: ControlRingConsumer<PinnedControlRing>,
    responses: ControlRingProducer<PinnedControlRing>,
    /// For [`BrokerEnterOp::Wait`].
    words: PinnedControlRing,
    /// A response the full ring could not take; no request is consumed while
    /// it waits.
    overflow: Option<Vec<u8>>,
}

/// A process's broker association. Accessed only during the process's
/// kernel calls, while its address space is current.
pub struct Association {
    broker: Broker,
    shared_memory: UserRange,
    state: RefCell<State>,
}

/// [`Status::Unsupported`] if the response does not fit a [`WireFrame`].
fn frame(bytes: &[u8]) -> Result<WireFrame, Status> {
    WireFrame::new(bytes).ok_or(Status::Unsupported)
}

impl Association {
    /// [`BrokerHandshake`](litebox_common_vm_abi::CallId::BrokerHandshake):
    /// one attempt, successful or not; success activates the control ring.
    ///
    /// # Errors
    ///
    /// The status for the runner.
    pub fn handshake(&self, request: &WireFrame) -> Result<WireFrame, Status> {
        let mut state = self.state.borrow_mut();
        let State::New(ring) = core::mem::replace(&mut *state, State::Ended) else {
            return Err(Status::Denied);
        };
        let request =
            wire::decode_handshake_request(request.as_slice().ok_or(Status::InvalidArgument)?)
                .map_err(|_| Status::InvalidArgument)?;
        let shared_buffers = SharedBufferPool::new(
            UserSharedMemory::new(self.shared_memory),
            SHARED_BUFFER_LAYOUT,
        )
        .map_err(|_| Status::Unsupported)?;
        let mut setup = KernelHostSetup {
            request: Some(request),
            response: None,
        };
        let readiness: Arc<dyn ReadinessSink> = Arc::new(NoReadiness);
        let result = litebox_broker_host::setup_connection(
            &self.broker.core,
            None,
            None,
            &mut setup,
            Arc::new(shared_buffers),
            readiness,
            |_| false,
            |_| Ok(()),
        );
        if let Ok(Ok(host)) = result {
            if host.activate_process().is_err() {
                // Releases its broker process ID.
                host.finish();
                return Err(Status::Denied);
            }
            let words = ring.memory().clone();
            let BrokerControlRingEndpoints {
                request_consumer,
                response_producer,
                // Unused until a provider has readiness.
                notification_producer: _,
            } = ring.into_broker();
            *state = State::Active(Box::new(Active {
                association: host,
                requests: request_consumer,
                responses: response_producer,
                words,
                overflow: None,
            }));
        }
        let response = setup.response.ok_or(Status::Denied)?;
        frame(&wire::encode_handshake_response(response))
    }

    /// [`BrokerEnter`](litebox_common_vm_abi::CallId::BrokerEnter): serves
    /// every published request, unless the response ring fills up, then
    /// performs `request`'s operation. An invalid request has no effect.
    /// Before the handshake, any request is [`Status::Denied`].
    ///
    /// # Errors
    ///
    /// See [`EnterError`].
    pub fn enter(&self, request: &BrokerEnterRequest) -> Result<(), EnterError> {
        let mut state = self.state.borrow_mut();
        let State::Active(active) = &mut *state else {
            return Err(EnterError::Status(Status::Denied));
        };
        let invalid = || EnterError::Status(Status::InvalidArgument);
        let wait_offset = match request.op {
            BrokerEnterOp::Wake => {
                if (request.expected, request.offset, request.deadline) != (0, 0, 0) {
                    return Err(invalid());
                }
                None
            }
            BrokerEnterOp::Wait => {
                if request.deadline != 0 {
                    return Err(EnterError::Status(Status::Unsupported));
                }
                let offset = usize::try_from(request.offset).map_err(|_| invalid())?;
                if !MemoryAccessPolicy::ControlRing.permits_u32(offset) {
                    return Err(invalid());
                }
                Some(offset)
            }
        };
        if active.serve().is_err() {
            if let State::Active(active) = core::mem::replace(&mut *state, State::Ended) {
                end(active.association);
            }
            return Err(EnterError::Failed);
        }
        // Nothing else changes ring words, so a word unchanged after serving
        // stays so.
        match wait_offset.map(|offset| active.words.load_u32_acquire(offset)) {
            None => Ok(()),
            Some(Ok(word)) if word != request.expected => Ok(()),
            Some(Ok(_)) => Err(EnterError::Status(Status::Stalled)),
            Some(Err(_)) => Err(invalid()),
        }
    }
}

impl Active {
    fn serve(&mut self) -> Result<(), Failed> {
        if let Some(response) = self.overflow.take()
            && !self.publish(response)?
        {
            return Ok(());
        }
        let mut served = 0u64;
        while let ControlRingReadStatus::Message(request) = self
            .requests
            .try_read(wire::decode_request)
            .map_err(failure("request ring"))?
        {
            let mut response = None;
            self.association
                .execute_request(request, |r| {
                    response = Some(wire::encode_response(r.clone()));
                    Ok::<(), Infallible>(())
                })
                .map_err(failure("request execution"))?;
            served += 1;
            let response = response
                .ok_or("no response")
                .map_err(failure("request execution"))?;
            if !self.publish(response)? {
                break;
            }
        }
        self.requests
            .publish_head()
            .map_err(failure("request ring"))?;
        log::trace!("broker served {served} requests");
        Ok(())
    }

    /// Whether the response ring took `response`; if not, it overflows.
    fn publish(&mut self, response: Vec<u8>) -> Result<bool, Failed> {
        match self
            .responses
            .try_write(&response)
            .map_err(failure("response ring"))?
        {
            ControlRingWriteStatus::Written => Ok(true),
            ControlRingWriteStatus::Full { .. } => {
                self.overflow = Some(response);
                Ok(false)
            }
        }
    }
}

/// Serving failed; the cause is logged.
struct Failed;

/// Logs why `what` failed the association.
fn failure<E: core::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> Failed {
    move |error| {
        log::warn!("broker {what} failed: {error:?}");
        Failed
    }
}

/// Why [`Association::enter`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterError {
    /// A status for the runner; the association is unaffected.
    Status(Status),
    /// Serving failed, which ended the association.
    Failed,
}

/// Ends an active association as the userland broker does when its runner
/// goes away.
fn end(association: BrokerHostAssociation<UserSharedMemory>) {
    association.request_cancellation();
    association.association_ending();
    association.finish();
}

impl Drop for Association {
    fn drop(&mut self) {
        if let State::Active(active) = core::mem::replace(self.state.get_mut(), State::Ended) {
            end(active.association);
        }
    }
}

#[cfg(test)]
mod tests {
    use litebox_broker_transport::control_ring::CONTROL_RING_READY;

    /// `ABI_VERSION` stands in for the userland broker's ring-layout token;
    /// change both together.
    #[test]
    fn ring_layout_change_needs_an_abi_version_change() {
        assert_eq!(
            (CONTROL_RING_READY, litebox_common_vm_abi::ABI_VERSION),
            (&b"litebox-control-ring-ready-v1"[..], 1)
        );
    }
}
