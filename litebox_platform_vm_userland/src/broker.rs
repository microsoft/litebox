// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker association with the kernel (see `litebox_common_vm_abi`, Broker):
//! handshake in a kernel call, then requests and responses in the control
//! ring and payloads in the shared buffers.
//!
//! Where the userland transport waits or wakes with futexes, this one enters
//! the kernel ([`kcall::broker_enter`]), which serves the ring before
//! returning; a call takes one entry. Shared memory is accessed only through
//! `peer_memory`.

use alloc::sync::Arc;
use litebox::utils::TruncateExt as _;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
};
use litebox_broker_protocol::wire::{self, WireError};
use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_SIZE, ControlRing, ControlRingConsumer, ControlRingDirection,
    ControlRingError, ControlRingProducer, ControlRingReadError, ControlRingReadStatus,
    ControlRingWriteStatus, LocalControlRingEndpoints, MemoryAccessPolicy, WaitableSharedMemory,
};
use litebox_broker_transport::peer_memory;
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use litebox_common_vm_abi::{BrokerHandshakeFrame, StartupInfo, Status, UserRange, WireFrame};

use crate::kcall;

#[derive(Debug)]
pub enum ChannelError {
    Kernel(Status),
    Wire(WireError),
    Ring(ControlRingError),
    Memory(SharedMemoryError),
    Oversized,
    NoRequest,
    /// The kernel made no progress on what the call waits for.
    Stalled,
    /// A response for another request.
    UnexpectedResponse,
    /// A reentrant call.
    Busy,
    /// An earlier call failed the association.
    Failed,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Kernel(status) => write!(f, "kernel rejected the broker call: {status:?}"),
            Self::Wire(error) => write!(f, "malformed broker frame: {error}"),
            Self::Ring(error) => write!(f, "broker control ring: {error:?}"),
            Self::Memory(error) => write!(f, "broker shared memory: {error}"),
            Self::Oversized => f.write_str("broker frame too large"),
            Self::NoRequest => f.write_str("no handshake request was sent"),
            Self::Stalled => f.write_str("the broker made no progress"),
            Self::UnexpectedResponse => f.write_str("broker response for another request"),
            Self::Busy => f.write_str("reentrant broker call"),
            Self::Failed => f.write_str("the broker association failed"),
        }
    }
}

impl core::error::Error for ChannelError {}

#[derive(Default)]
pub struct KernelBrokerSetup {
    request: Option<WireFrame>,
}

impl LocalSetupChannel for KernelBrokerSetup {
    type Error = ChannelError;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> Result<(), ChannelError> {
        let frame = wire::encode_handshake_request(request.clone());
        self.request = Some(WireFrame::new(&frame).ok_or(ChannelError::Oversized)?);
        Ok(())
    }

    fn recv_handshake_response(&mut self) -> Result<Option<BrokerHandshakeResponse>, ChannelError> {
        let request = self.request.take().ok_or(ChannelError::NoRequest)?;
        let response = kcall::call(&BrokerHandshakeFrame(request)).map_err(ChannelError::Kernel)?;
        let response = response.as_slice().ok_or(ChannelError::Oversized)?;
        wire::decode_handshake_response(response)
            .map(Some)
            .map_err(ChannelError::Wire)
    }
}

/// The local ends of the rings: requests out, responses in.
struct Rings {
    requests: ControlRingProducer<KernelControlRing>,
    responses: ControlRingConsumer<KernelControlRing>,
}

impl Rings {
    /// One call in flight, so responses arrive in order.
    fn call(&mut self, request: BrokerRequest) -> Result<BrokerResponse, ChannelError> {
        let request_id = request.request_id;
        let frame = wire::encode_request(request);
        loop {
            match self
                .requests
                .try_write(&frame)
                .map_err(ChannelError::Ring)?
            {
                ControlRingWriteStatus::Written => break,
                ControlRingWriteStatus::Full { wait_epoch } => {
                    self.requests.wait_for_capacity(wait_epoch)?;
                }
            }
        }
        // The doorbell.
        self.requests.wake_consumer()?;
        let response = loop {
            match self.responses.try_read(wire::decode_response) {
                Ok(ControlRingReadStatus::Message(response)) => break response,
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    self.responses.wait_for_message(wait_epoch)?;
                }
                Err(ControlRingReadError::Ring(error)) => return Err(ChannelError::Ring(error)),
                Err(ControlRingReadError::Decode(error)) => return Err(ChannelError::Wire(error)),
            }
        };
        self.responses.publish_head().map_err(ChannelError::Ring)?;
        self.responses.wake_producer()?;
        if response.request_id != request_id {
            return Err(ChannelError::UnexpectedResponse);
        }
        Ok(response)
    }
}

pub struct KernelBrokerChannel {
    /// `None` once a call has failed the association.
    rings: spin::Mutex<Option<Rings>>,
}

impl LocalCallChannel for KernelBrokerChannel {
    type Error = ChannelError;

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, ChannelError> {
        let mut rings = self.rings.try_lock().ok_or(ChannelError::Busy)?;
        let result = rings.as_mut().ok_or(ChannelError::Failed)?.call(request);
        if result.is_err() {
            *rings = None;
        }
        result
    }
}

/// Bounds-checks `offset..offset + len` against `size`; returns the address.
fn checked(
    start: usize,
    size: usize,
    offset: usize,
    len: usize,
) -> Result<usize, SharedMemoryError> {
    let end = offset
        .checked_add(len)
        .ok_or(SharedMemoryError::InvalidRange)?;
    if end > size {
        return Err(SharedMemoryError::InvalidRange);
    }
    Ok(start + offset)
}

/// The broker's shared buffers.
struct KernelSharedMemory {
    region: UserRange,
}

impl SharedMemory for KernelSharedMemory {
    fn len(&self) -> usize {
        self.region.len.trunc()
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let source = checked(
            self.region.start.trunc(),
            self.len(),
            offset,
            destination.len(),
        )?;
        // Safety: in bounds of a region mapped for the process's lifetime,
        // disjoint from private memory.
        unsafe { peer_memory::copy_from_peer(source as *const u8, destination) };
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let destination = checked(self.region.start.trunc(), self.len(), offset, source.len())?;
        // Safety: as in `read`.
        unsafe { peer_memory::copy_to_peer(source, destination as *mut u8) };
        Ok(())
    }
}

/// The control ring at the start of its region. Accesses keep to
/// [`MemoryAccessPolicy::ControlRing`].
struct KernelControlRing {
    start: usize,
}

impl KernelControlRing {
    /// `None` if `region` cannot hold the ring.
    fn new(region: UserRange) -> Option<Self> {
        let start: usize = region.start.trunc();
        (region.len >= CONTROL_RING_MEMORY_SIZE as u64 && start.is_multiple_of(size_of::<u64>()))
            .then_some(Self { start })
    }

    fn word<T>(&self, offset: usize, permitted: bool) -> Result<*mut T, SharedMemoryError> {
        if !permitted {
            return Err(SharedMemoryError::InvalidRange);
        }
        if !offset.is_multiple_of(size_of::<T>()) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        Ok((self.start + offset) as *mut T)
    }

    fn u32_at(&self, offset: usize) -> Result<*mut u32, SharedMemoryError> {
        self.word(offset, MemoryAccessPolicy::ControlRing.permits_u32(offset))
    }

    fn u64_at(&self, offset: usize) -> Result<*mut u64, SharedMemoryError> {
        self.word(offset, MemoryAccessPolicy::ControlRing.permits_u64(offset))
    }

    fn bytes_at(&self, offset: usize, len: usize) -> Result<usize, SharedMemoryError> {
        if !MemoryAccessPolicy::ControlRing.permits_byte_range(offset, len) {
            return Err(SharedMemoryError::InvalidRange);
        }
        checked(self.start, CONTROL_RING_MEMORY_SIZE, offset, len)
    }
}

// Safety (below): in bounds and aligned (checked), in a region mapped for the
// process's lifetime and disjoint from private memory.
impl SharedMemory for KernelControlRing {
    fn len(&self) -> usize {
        CONTROL_RING_MEMORY_SIZE
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let source = self.bytes_at(offset, destination.len())?;
        // Safety: see above.
        unsafe { peer_memory::copy_from_peer(source as *const u8, destination) };
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let destination = self.bytes_at(offset, source.len())?;
        // Safety: see above.
        unsafe { peer_memory::copy_to_peer(source, destination as *mut u8) };
        Ok(())
    }
}

impl ControlRingMemory for KernelControlRing {
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

/// Waits and wakes enter the kernel, which serves the ring synchronously.
impl WaitableSharedMemory for KernelControlRing {
    type Error = ChannelError;

    fn wait_access_error(error: SharedMemoryError) -> ChannelError {
        ChannelError::Memory(error)
    }

    /// One entry is all the progress the kernel can make, so an unchanged
    /// epoch is [`ChannelError::Stalled`].
    fn wait_while_equal(&self, offset: usize, expected: u32) -> Result<(), ChannelError> {
        if self
            .load_u32_acquire(offset)
            .map_err(ChannelError::Memory)?
            != expected
        {
            return Ok(());
        }
        kcall::broker_enter().map_err(ChannelError::Kernel)?;
        if self
            .load_u32_acquire(offset)
            .map_err(ChannelError::Memory)?
            == expected
        {
            return Err(ChannelError::Stalled);
        }
        Ok(())
    }

    /// Only the request ring's consumer, the kernel, needs waking.
    fn wake_one(&self, offset: usize) -> Result<(), ChannelError> {
        if offset == ControlRingDirection::Requests.producer_epoch_offset() {
            kcall::broker_enter().map_err(ChannelError::Kernel)?;
        }
        Ok(())
    }
}

/// Call at most once per process.
///
/// # Errors
///
/// The kernel rejects the association or negotiation fails.
pub fn connect(
    info: &StartupInfo,
) -> litebox_broker_local::Result<BrokerLocal<KernelBrokerChannel>, ChannelError> {
    let (local, _startup, ()) = BrokerLocal::negotiate(KernelBrokerSetup::default(), |_setup| {
        let memory = KernelControlRing::new(info.broker_control_ring)
            .ok_or(ChannelError::Memory(SharedMemoryError::InvalidRange))?;
        let LocalControlRingEndpoints {
            request_producer,
            response_consumer,
            notification_consumer: _,
        } = ControlRing::new(memory)
            .map_err(ChannelError::Ring)?
            .into_local();
        let channel = KernelBrokerChannel {
            rings: spin::Mutex::new(Some(Rings {
                requests: request_producer,
                responses: response_consumer,
            })),
        };
        let shared_memory: Arc<dyn SharedMemory> = Arc::new(KernelSharedMemory {
            region: info.broker_shared_memory,
        });
        Ok((channel, shared_memory, ()))
    })?;
    Ok(local)
}
