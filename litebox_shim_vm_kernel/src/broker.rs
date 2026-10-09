// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's broker association (see `litebox_common_vm_abi`, Broker):
//! handshake in a kernel call, then requests and responses in the control
//! ring, pinned and accessed through the kernel's mapping
//! ([`PinnedControlRing`]), and payloads in the process's lazily populated
//! shared buffers ([`UserSharedMemory`]).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::Infallible;
use core::ops::Range;
use litebox_broker_core::BrokerCore;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_host::BrokerHostAssociation;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_LAYOUT;
use litebox_broker_protocol::wire;
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::control_ring::{
    BrokerControlRingEndpoints, CONTROL_RING_MEMORY_SIZE, ControlRing, ControlRingConsumer,
    ControlRingProducer, ControlRingReadStatus, ControlRingWriteStatus, MemoryAccessPolicy,
};
use litebox_broker_transport::peer_memory;
use litebox_broker_transport::shared_memory::{
    ControlRingMemory, SharedBufferPool, SharedMemory, SharedMemoryError,
};
use litebox_common_vm_abi::{Status, UserRange, WireFrame};
use litebox_platform_vm_kernel::PinnedUserPages;

use crate::memory::{copy_from_user, copy_to_user};

/// The shared buffers, through the process's mapping: valid only while its
/// address space is current.
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
        let bytes =
            copy_from_user(addr, destination.len()).map_err(|_| SharedMemoryError::AccessFailed)?;
        destination.copy_from_slice(&bytes);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let addr = self.checked(offset, source.len())?;
        copy_to_user(addr, source).map_err(|_| SharedMemoryError::AccessFailed)
    }
}

/// The control ring at the start of pinned pages, through the kernel's
/// mapping. Accesses keep to [`MemoryAccessPolicy::ControlRing`].
pub(crate) struct PinnedControlRing(PinnedUserPages);

impl PinnedControlRing {
    /// `None` if `pages` cannot hold the ring.
    pub(crate) fn new(pages: PinnedUserPages) -> Option<Self> {
        (pages.len() >= CONTROL_RING_MEMORY_SIZE).then_some(Self(pages))
    }

    fn word<T>(&self, offset: usize, permitted: bool) -> Result<*mut T, SharedMemoryError> {
        if !permitted {
            return Err(SharedMemoryError::InvalidRange);
        }
        if !offset.is_multiple_of(size_of::<T>()) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        // An aligned word never crosses a page.
        let (address, _) = self
            .0
            .kernel_address(offset)
            .ok_or(SharedMemoryError::InvalidRange)?;
        Ok(address.cast())
    }

    fn u32_at(&self, offset: usize) -> Result<*mut u32, SharedMemoryError> {
        self.word(offset, MemoryAccessPolicy::ControlRing.permits_u32(offset))
    }

    fn u64_at(&self, offset: usize) -> Result<*mut u64, SharedMemoryError> {
        self.word(offset, MemoryAccessPolicy::ControlRing.permits_u64(offset))
    }

    /// Calls `copy` for each page's part of `offset..offset + len`, with that
    /// part's range within `0..len`.
    fn for_each_part(
        &self,
        offset: usize,
        len: usize,
        mut copy: impl FnMut(*mut u8, Range<usize>),
    ) -> Result<(), SharedMemoryError> {
        if !MemoryAccessPolicy::ControlRing.permits_byte_range(offset, len) {
            return Err(SharedMemoryError::InvalidRange);
        }
        let mut done = 0;
        while done < len {
            let (address, available) = self
                .0
                .kernel_address(offset + done)
                .ok_or(SharedMemoryError::InvalidRange)?;
            let part = available.min(len - done);
            copy(address, done..done + part);
            done += part;
        }
        Ok(())
    }
}

// Safety (below): pinned for `self`'s lifetime, in bounds and aligned
// (checked), and disjoint from private memory.
impl SharedMemory for PinnedControlRing {
    fn len(&self) -> usize {
        CONTROL_RING_MEMORY_SIZE
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        self.for_each_part(offset, destination.len(), |source, part| {
            // Safety: see above.
            unsafe { peer_memory::copy_from_peer(source, &mut destination[part]) };
        })
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        self.for_each_part(offset, source.len(), |destination, part| {
            // Safety: see above.
            unsafe { peer_memory::copy_to_peer(&source[part], destination) };
        })
    }
}

impl ControlRingMemory for PinnedControlRing {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        let address = self.u32_at(offset)?;
        // Safety: see above.
        Ok(unsafe { peer_memory::load_u32_acquire(address) })
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = self.u32_at(offset)?;
        // Safety: see above.
        unsafe { peer_memory::increment_u32_release(address) };
        Ok(())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        let address = self.u64_at(offset)?;
        // Safety: see above.
        Ok(unsafe { peer_memory::load_u64_acquire(address) })
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        let address = self.u64_at(offset)?;
        // Safety: see above.
        unsafe { peer_memory::store_u64_release(address, value) };
        Ok(())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        let store = self.u64_at(store_offset)?;
        let increment = self.u32_at(increment_offset)?;
        // Safety: see above.
        unsafe {
            peer_memory::store_u64_release(store, value);
            peer_memory::increment_u32_release(increment);
        }
        Ok(())
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

enum Association {
    /// Before the handshake, with the ring it would activate.
    New(ControlRing<PinnedControlRing>),
    Active(Box<Active>),
    /// The handshake did not activate one, or it failed.
    Ended,
}

/// The broker's ends of the rings: requests in, responses out.
struct Active {
    association: BrokerHostAssociation<UserSharedMemory>,
    requests: ControlRingConsumer<PinnedControlRing>,
    responses: ControlRingProducer<PinnedControlRing>,
    /// A response the full ring could not take; no request is consumed while
    /// it waits.
    overflow: Option<Vec<u8>>,
}

pub(crate) struct Broker {
    core: BrokerCore,
    shared_memory: UserRange,
    association: RefCell<Association>,
}

/// [`Status::Unsupported`] if the response does not fit a [`WireFrame`].
fn frame(bytes: &[u8]) -> Result<WireFrame, Status> {
    WireFrame::new(bytes).ok_or(Status::Unsupported)
}

impl Broker {
    pub(crate) fn new(
        core: BrokerCore,
        shared_memory: UserRange,
        control_ring: ControlRing<PinnedControlRing>,
    ) -> Self {
        Self {
            core,
            shared_memory,
            association: RefCell::new(Association::New(control_ring)),
        }
    }

    /// One attempt, successful or not; success activates the control ring.
    pub(crate) fn handshake(&self, request: &WireFrame) -> Result<WireFrame, Status> {
        let mut association = self.association.borrow_mut();
        let Association::New(ring) = core::mem::replace(&mut *association, Association::Ended)
        else {
            return Err(Status::Denied);
        };
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
        if let Ok(Ok(host)) = result {
            if host.activate_process().is_err() {
                // Releases its broker process ID.
                host.finish();
                return Err(Status::Denied);
            }
            let BrokerControlRingEndpoints {
                request_consumer,
                response_producer,
                notification_producer: _,
            } = ring.into_broker();
            *association = Association::Active(Box::new(Active {
                association: host,
                requests: request_consumer,
                responses: response_producer,
                overflow: None,
            }));
        }
        let response = setup.response.ok_or(Status::Denied)?;
        frame(&wire::encode_handshake_response(response))
    }

    /// Serves every published request, unless the response ring fills up.
    ///
    /// # Errors
    ///
    /// See [`EnterError`].
    pub(crate) fn enter(&self) -> Result<(), EnterError> {
        let mut association = self.association.borrow_mut();
        let Association::Active(active) = &mut *association else {
            return Err(EnterError::NoAssociation);
        };
        active.serve().map_err(|Failed| {
            if let Association::Active(active) =
                core::mem::replace(&mut *association, Association::Ended)
            {
                end(active.association);
            }
            EnterError::Failed
        })
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

pub(crate) enum EnterError {
    /// Before a successful handshake.
    NoAssociation,
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

impl Drop for Broker {
    fn drop(&mut self) {
        if let Association::Active(active) =
            core::mem::replace(self.association.get_mut(), Association::Ended)
        {
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
