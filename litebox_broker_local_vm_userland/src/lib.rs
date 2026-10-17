// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker's local endpoint for a runner on the LiteBox VM kernel, like
//! `litebox_broker_local_userland` for hosted runners: handshake in a kernel
//! call, then requests and responses in the control ring and payloads in the
//! shared buffers (see `litebox_common_vm_abi`, Broker).
//!
//! Where the userland transport uses the host's futex, this one uses the
//! kernel's (`Futex`), on the same ring words. The kernel serves the ring
//! apart from it, so a call takes a Wake (on the requests' producer epoch)
//! and, unless the response is already there, a Wait. Shared memory is
//! accessed only through `peer_memory`.
//!
//! Notifications (readiness of broker objects, e.g., standard input) have no
//! receiver thread: the runner receives them with [`Notifications::receive`],
//! which also waits for them, or, as the platform's waits and interrupts
//! need, with a [`Receiver`] (in place of the userland receiver thread).
//!
//! Calls from several threads take turns: one call is in flight at a time.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use litebox::utils::TruncateExt as _;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};
use litebox_broker_protocol::wire::{self, WireError};
use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_SIZE, CONTROL_RING_NOTIFICATION_SLOT_COUNT, ControlRing,
    ControlRingConsumer, ControlRingDirection, ControlRingError, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWriteStatus, LocalControlRingEndpoints,
    MemoryAccessPolicy, WaitableSharedMemory,
};
use litebox_broker_transport::peer_memory;
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use litebox_common_vm_abi::{
    BrokerHandshakeFrame, FutexRequest, StartupInfo, Status, UserRange, WireFrame,
};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_userland::{Instant, NotificationReceiver, VmUserland, kcall};

#[derive(Debug)]
pub enum ChannelError {
    Kernel(Status),
    Wire(WireError),
    Ring(ControlRingError),
    Memory(SharedMemoryError),
    Oversized,
    NoRequest,
    /// A response for another request.
    UnexpectedResponse,
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
            Self::UnexpectedResponse => f.write_str("broker response for another request"),
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

/// The local ends of the request and response rings.
struct Rings {
    requests: ControlRingProducer<KernelControlRing>,
    responses: ControlRingConsumer<KernelControlRing>,
    /// For the Wake that has the kernel serve requests.
    words: KernelControlRing,
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
        // The kernel announces no waits, so `wake_consumer` would skip this.
        broker_wake(self.words.start).map_err(ChannelError::Kernel)?;
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
    /// `None` once a call has failed the association. A thread may be
    /// preempted, or wait in the kernel, holding it.
    rings: litebox_platform::sync::Mutex<VmUserland, Option<Rings>>,
}

impl LocalCallChannel for KernelBrokerChannel {
    type Error = ChannelError;

    fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, ChannelError> {
        let mut rings = self.rings.lock();
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

    fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
        let address = self.u32_at(offset)?;
        // Safety: see above.
        unsafe { peer_memory::store_u32_release(address, value) };
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

/// The kernel's futex operations on ring words.
impl WaitableSharedMemory for KernelControlRing {
    type Error = ChannelError;

    fn wait_access_error(error: SharedMemoryError) -> ChannelError {
        ChannelError::Memory(error)
    }

    fn wait_while_equal(&self, offset: usize, expected: u32) -> Result<(), ChannelError> {
        broker_wait(self.start, offset, expected, None).map_err(ChannelError::Kernel)
    }

    /// The kernel waits on no ring word, so it announces no waits for this
    /// to wake; [`broker_wake`] has it serve new requests.
    fn wake_one(&self, _offset: usize) -> Result<(), ChannelError> {
        Ok(())
    }
}

/// The notification ring's local end.
pub struct Notifications {
    consumer: ControlRingConsumer<KernelControlRing>,
    /// For [`self_check`].
    words: KernelControlRing,
}

/// Call at most once per process.
///
/// # Errors
///
/// The kernel rejects the association or negotiation fails.
pub fn connect(
    info: &StartupInfo,
) -> litebox_broker_local::Result<(BrokerLocal<KernelBrokerChannel>, Notifications), ChannelError> {
    let (local, _startup, notifications) =
        BrokerLocal::negotiate(KernelBrokerSetup::default(), |_setup| {
            let ring = || {
                KernelControlRing::new(info.broker_control_ring)
                    .ok_or(ChannelError::Memory(SharedMemoryError::InvalidRange))
            };
            let LocalControlRingEndpoints {
                request_producer,
                response_consumer,
                notification_consumer,
            } = ControlRing::new(ring()?)
                .map_err(ChannelError::Ring)?
                .into_local();
            let notifications = Notifications {
                consumer: notification_consumer,
                words: ring()?,
            };
            let channel = KernelBrokerChannel {
                rings: litebox_platform::sync::Mutex::new(Some(Rings {
                    requests: request_producer,
                    responses: response_consumer,
                    words: ring()?,
                })),
            };
            let shared_memory: Arc<dyn SharedMemory> = Arc::new(KernelSharedMemory {
                region: info.broker_shared_memory,
            });
            Ok((channel, shared_memory, notifications))
        })?;
    Ok((local, notifications))
}

impl Notifications {
    /// Passes every published notification to `dispatch` (e.g.,
    /// `LiteBox::broker_notification_dispatcher`); if there is none, first
    /// waits for one until `deadline`, if any. Returns how many it passed:
    /// zero at the deadline.
    ///
    /// # Errors
    ///
    /// A malformed ring, or a wait the kernel rejects ([`Status::Stalled`]
    /// if nothing could publish).
    pub fn receive(
        &mut self,
        deadline: Option<Instant>,
        mut dispatch: impl FnMut(BrokerNotification),
    ) -> Result<usize, ChannelError> {
        loop {
            let start = self.words.start;
            let (received, wait_epoch) =
                self.read_published(&mut dispatch, || broker_wake(start))?;
            if received != 0 {
                return Ok(received);
            }
            let epoch = ControlRingDirection::Notifications.producer_epoch_offset();
            match broker_wait(self.words.start, epoch, wait_epoch, deadline) {
                Ok(()) => {}
                Err(Status::TimedOut) => return Ok(0),
                Err(status) => return Err(ChannelError::Kernel(status)),
            }
        }
    }

    /// Passes the notifications already published to `dispatch`, without
    /// waiting. Enters the kernel only after reading a full ring, for it to
    /// publish what did not fit. Returns how many it passed.
    ///
    /// # Errors
    ///
    /// A malformed ring, or a kernel call the kernel rejects.
    pub fn try_receive(
        &mut self,
        mut dispatch: impl FnMut(BrokerNotification),
    ) -> Result<usize, ChannelError> {
        let start = self.words.start;
        Ok(self.read_published(&mut dispatch, || broker_wake(start))?.0)
    }

    /// As [`Self::try_receive`], also returning the producer epoch to wait on
    /// while the ring stays empty; `publish_rest` (e.g., [`broker_wake`]) has
    /// the kernel publish what did not fit in a full ring.
    ///
    /// Reads what is published, publishes its progress, and only then
    /// dispatches it, until a read finds nothing: dispatching may take long
    /// (e.g., waiting for a lock, or preempted), and meanwhile the kernel
    /// sees the ring consumed, so it does not end other threads' waits for
    /// what this one dispatches (see `litebox_common_vm_abi`, Threads).
    fn read_published(
        &mut self,
        dispatch: &mut impl FnMut(BrokerNotification),
        mut publish_rest: impl FnMut() -> Result<(), Status>,
    ) -> Result<(usize, u32), ChannelError> {
        let mut received = 0;
        loop {
            let mut batch = Vec::new();
            let wait_epoch = loop {
                match self.consumer.try_read(wire::decode_notification) {
                    Ok(ControlRingReadStatus::Message(notification)) => batch.push(notification),
                    Ok(ControlRingReadStatus::Empty { wait_epoch }) => break wait_epoch,
                    Err(error) => return Err(read_error(error)),
                }
            };
            if batch.is_empty() {
                return Ok((received, wait_epoch));
            }
            // The kernel sees the freed slots when it next publishes.
            self.consumer.publish_head().map_err(ChannelError::Ring)?;
            let full = batch.len() as u64 == CONTROL_RING_NOTIFICATION_SLOT_COUNT;
            received += batch.len();
            batch.into_iter().for_each(&mut *dispatch);
            if full {
                // A full ring: the kernel may hold more. This publishes them,
                // and so leaves the kernel to interrupt the process for them
                // once more, with nothing left to receive by then.
                publish_rest().map_err(ChannelError::Kernel)?;
            }
        }
    }
}

impl Notifications {
    /// For the platform's waits and interrupts
    /// (`VmUserland::set_notification_receiver`).
    pub fn into_receiver<Dispatch, Failure>(
        self,
        dispatch: Dispatch,
        dispatch_failure: Failure,
    ) -> Receiver<Dispatch, Failure>
    where
        Dispatch: Fn(BrokerNotification) + Sync,
        Failure: Fn() + Sync,
    {
        Receiver {
            reading: spin::Mutex::new(Reading {
                notifications: Some(self),
                queue: VecDeque::new(),
            }),
            dispatching: AtomicBool::new(false),
            requested: AtomicBool::new(false),
            dispatch,
            dispatch_failure,
        }
    }
}

/// Receives the association's notifications as the userland receiver thread
/// does: each goes to `dispatch` (e.g.,
/// `LiteBox::broker_notification_dispatcher`); a failure to receive (e.g., a
/// malformed ring) fails the association's objects, once, with
/// `dispatch_failure` (e.g., `LiteBox::broker_failure_dispatcher`), and then
/// nothing more is received.
///
/// Threads may drain at once: each reads what is published, so that the
/// kernel sees the ring consumed at once, and one at a time dispatches what
/// was read, in order. Dispatching may take long (e.g., waiting for a lock,
/// or preempted): meanwhile, the others' waits do not end for notifications
/// that are only left to dispatch (see `litebox_common_vm_abi`, Threads).
pub struct Receiver<Dispatch, Failure> {
    /// Held only to read the ring or take from the queue.
    reading: spin::Mutex<Reading>,
    /// A thread dispatches the queue.
    dispatching: AtomicBool,
    /// A drain found `dispatching` set: its dispatcher dispatches again.
    requested: AtomicBool,
    dispatch: Dispatch,
    dispatch_failure: Failure,
}

struct Reading {
    /// `None` once receiving failed.
    notifications: Option<Notifications>,
    /// Read but not yet dispatched, in order.
    queue: VecDeque<BrokerNotification>,
}

impl<Dispatch, Failure> Receiver<Dispatch, Failure>
where
    Dispatch: Fn(BrokerNotification) + Sync,
    Failure: Fn() + Sync,
{
    /// Reads what is published into the queue, unless receiving failed;
    /// fails the association's objects if this fails it.
    fn read(&self) {
        let mut reading = self.reading.lock();
        if !reading.read() {
            drop(reading);
            (self.dispatch_failure)();
        }
    }

    /// The queue's first, reading what is published if it is empty. Only
    /// the dispatcher takes from the queue, so that it keeps the order.
    fn next(&self) -> Option<BrokerNotification> {
        let mut reading = self.reading.lock();
        if let Some(notification) = reading.queue.pop_front() {
            return Some(notification);
        }
        if !reading.read() {
            drop(reading);
            (self.dispatch_failure)();
            reading = self.reading.lock();
        }
        reading.queue.pop_front()
    }
}

impl Reading {
    /// Reads what is published into the queue, unless receiving failed;
    /// false if this fails it.
    fn read(&mut self) -> bool {
        let Self {
            notifications,
            queue,
        } = self;
        let Some(Err(error)) = notifications.as_mut().map(|notifications| {
            notifications.try_receive(|notification| queue.push_back(notification))
        }) else {
            return true;
        };
        log::error!("failed to receive broker notifications: {error}");
        *notifications = None;
        false
    }
}

impl<Dispatch, Failure> NotificationReceiver for Receiver<Dispatch, Failure>
where
    Dispatch: Fn(BrokerNotification) + Sync,
    Failure: Fn() + Sync,
{
    /// Reads what is published (nothing once receiving failed), then
    /// dispatches it, unless another thread dispatches: that one then
    /// dispatches it too, once it is done (it may have found the queue empty
    /// just before). Dispatching may wait (e.g., for a lock), and
    /// interrupted, drain again: nested, it so has the outer drain dispatch
    /// what it read.
    fn drain(&self) {
        self.read();
        self.requested.store(true, Ordering::SeqCst);
        // Checked once no longer dispatching: a request since then, which
        // this does not see, found dispatching free.
        while self.requested.load(Ordering::SeqCst) {
            if self.dispatching.swap(true, Ordering::SeqCst) {
                return;
            }
            self.requested.store(false, Ordering::SeqCst);
            while let Some(notification) = self.next() {
                (self.dispatch)(notification);
            }
            self.dispatching.store(false, Ordering::SeqCst);
        }
    }
}

fn read_error(error: ControlRingReadError<WireError>) -> ChannelError {
    match error {
        ControlRingReadError::Ring(error) => ChannelError::Ring(error),
        ControlRingReadError::Decode(error) => ChannelError::Wire(error),
    }
}

/// The kernel's futex on the control ring at `start`, at `offset`.
fn futex(
    start: usize,
    request: impl FnOnce(u64) -> FutexRequest,
    offset: usize,
) -> Result<(), Status> {
    kcall::call(&request((start + offset) as u64)).map(|_| ())
}

/// Has the kernel serve published broker requests: a wake on the requests'
/// producer epoch of the control ring at `start`.
fn broker_wake(start: usize) -> Result<(), Status> {
    let offset = ControlRingDirection::Requests.producer_epoch_offset();
    futex(start, |addr| FutexRequest::wake(addr, 1), offset)
}

/// Has the kernel serve published broker requests, and waits while the word
/// at `offset` into the control ring at `start` equals `expected`, until
/// `deadline`, if any.
fn broker_wait(
    start: usize,
    offset: usize,
    expected: u32,
    deadline: Option<Instant>,
) -> Result<(), Status> {
    // Zero means none, so the (theoretical) instant zero waits from 1 ns.
    let deadline = deadline.map_or(0, |deadline| deadline.as_nanos().max(1));
    futex(
        start,
        |addr| FutexRequest::wait(addr, expected, deadline),
        offset,
    )
}

/// Self-check (debug builds): the broker's futex operations, on the
/// notification ring's producer epoch and on the request ring's consumer
/// epoch, which only the kernel's serving changes.
///
/// # Panics
///
/// On a failed check.
pub fn self_check(notifications: &Notifications, platform: &VmUserland) {
    let epoch = ControlRingDirection::Notifications.producer_epoch_offset();
    let served = ControlRingDirection::Requests.consumer_epoch_offset();
    let now = || platform.now();
    let current = |offset| {
        notifications
            .words
            .load_u32_acquire(offset)
            .expect("a ring word")
    };
    let start = notifications.words.start;
    broker_wake(start).expect("waking an idle broker");
    // The broker waits on no other word.
    assert_eq!(
        futex(start, |addr| FutexRequest::wake(addr, 1), epoch),
        Ok(())
    );
    let notified = current(epoch);
    assert_eq!(
        broker_wait(start, epoch, notified.wrapping_add(1), None),
        Ok(()),
        "word differs"
    );
    let soon = now()
        .checked_add(core::time::Duration::from_millis(1))
        .expect("the clock is far from overflowing");
    assert_eq!(
        broker_wait(start, served, current(served), None),
        Err(Status::Stalled)
    );
    assert_eq!(
        broker_wait(start, served, current(served), Some(soon)),
        Err(Status::TimedOut)
    );
    assert!(now() >= soon, "a timed wait returned early");
    assert_eq!(broker_wait(start, 0, 0, None), Err(Status::InvalidArgument));
    let mut wake = FutexRequest::wake((start + served) as u64, 1);
    wake.expected = 1;
    assert_eq!(kcall::call(&wake), Err(Status::InvalidArgument));
    broker_wake(start).expect("the association survives");
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::message::ReadinessNotification;
    use litebox_broker_protocol::readiness::ReadinessFlags;

    /// A control ring in `memory`: the runner's notifications, and the
    /// kernel's notification producer.
    fn ring(memory: &mut [u64]) -> (Notifications, ControlRingProducer<KernelControlRing>) {
        let region = UserRange {
            start: memory.as_mut_ptr() as u64,
            len: CONTROL_RING_MEMORY_SIZE as u64,
        };
        let ring = || KernelControlRing::new(region).expect("room for the ring");
        let notifications = Notifications {
            consumer: ControlRing::new(ring())
                .expect("ring")
                .into_local()
                .notification_consumer,
            words: ring(),
        };
        let producer = ControlRing::new(ring())
            .expect("ring")
            .into_broker()
            .notification_producer;
        (notifications, producer)
    }

    fn readiness(handle: u64) -> Vec<u8> {
        wire::encode_notification(BrokerNotification::Readiness(ReadinessNotification {
            handle: ObjectHandle(handle),
            readiness: ReadinessFlags::READ,
        }))
    }

    fn ring_memory() -> Vec<u64> {
        alloc::vec![0u64; CONTROL_RING_MEMORY_SIZE / size_of::<u64>()]
    }

    #[test]
    fn receiving_one_at_a_time_frees_every_slot() {
        let mut memory = ring_memory();
        let (mut notifications, mut producer) = ring(&mut memory);
        let slots = usize::try_from(CONTROL_RING_NOTIFICATION_SLOT_COUNT).unwrap();
        for round in 0..2 * slots {
            assert_eq!(
                producer.try_write(&readiness(7)),
                Ok(ControlRingWriteStatus::Written),
                "full at round {round}: received slots never freed"
            );
            assert_eq!(notifications.receive(None, |_| {}).expect("received"), 1);
        }
    }

    #[test]
    fn receiving_a_full_ring_has_the_kernel_publish_the_rest() {
        let mut memory = ring_memory();
        let (mut notifications, mut producer) = ring(&mut memory);
        for handle in 0..CONTROL_RING_NOTIFICATION_SLOT_COUNT {
            producer.try_write(&readiness(handle)).expect("written");
        }
        assert!(matches!(
            producer.try_write(&readiness(99)),
            Ok(ControlRingWriteStatus::Full { .. })
        ));
        // As `receive` and `try_receive` read, with the kernel call counted.
        let mut publish_rest_calls = 0;
        let (received, _) = notifications
            .read_published(&mut |_| {}, || {
                publish_rest_calls += 1;
                Ok(())
            })
            .expect("received");
        assert_eq!(
            received,
            usize::try_from(CONTROL_RING_NOTIFICATION_SLOT_COUNT).unwrap()
        );
        assert_eq!(publish_rest_calls, 1);
        // The kernel's next write finds room again.
        assert_eq!(
            producer.try_write(&readiness(99)),
            Ok(ControlRingWriteStatus::Written)
        );
    }

    #[test]
    fn notifications_are_consumed_before_their_dispatch() {
        let mut memory = ring_memory();
        let (notifications, producer) = ring(&mut memory);
        let producer = spin::Mutex::new(producer);
        producer.lock().try_write(&readiness(7)).expect("written");
        let dispatched = AtomicUsize::new(0);
        let receiver = notifications.into_receiver(
            |_| {
                let mut producer = producer.lock();
                // Other threads' waits do not end for what this dispatches.
                assert!(!producer.has_unconsumed().expect("ring"));
                if dispatched.fetch_add(1, Ordering::Relaxed) == 0 {
                    // Published while dispatching: received in the same drain.
                    producer.try_write(&readiness(8)).expect("written");
                }
            },
            || panic!("receiving failed"),
        );
        receiver.drain();
        assert_eq!(dispatched.load(Ordering::Relaxed), 2);
        assert!(!producer.lock().has_unconsumed().expect("ring"));
    }

    #[test]
    fn a_drain_while_another_dispatches_leaves_it_to_that_one_in_order() {
        let mut memory = ring_memory();
        let (notifications, mut producer) = ring(&mut memory);
        let dispatched = spin::Mutex::new(Vec::new());
        let receiver = notifications.into_receiver(
            |notification| {
                let BrokerNotification::Readiness(readiness) = notification;
                dispatched.lock().push(readiness.handle.0);
            },
            || panic!("receiving failed"),
        );
        // As if another thread dispatched.
        receiver.dispatching.store(true, Ordering::SeqCst);
        producer.try_write(&readiness(1)).expect("written");
        producer.try_write(&readiness(2)).expect("written");
        receiver.drain();
        assert!(dispatched.lock().is_empty());
        assert!(
            !producer.has_unconsumed().expect("ring"),
            "read, for other threads' waits"
        );
        producer.try_write(&readiness(3)).expect("written");
        // That thread, done, finds the request, and dispatches all, in order.
        receiver.dispatching.store(false, Ordering::SeqCst);
        assert!(receiver.requested.load(Ordering::SeqCst));
        receiver.drain();
        assert_eq!(*dispatched.lock(), [1, 2, 3]);
    }

    #[test]
    fn a_receive_failure_fails_the_association_once_and_stops_receiving() {
        let mut memory = ring_memory();
        let (notifications, mut producer) = ring(&mut memory);
        let dispatched = AtomicUsize::new(0);
        let failures = AtomicUsize::new(0);
        let receiver = notifications.into_receiver(
            |_| {
                dispatched.fetch_add(1, Ordering::Relaxed);
            },
            || {
                failures.fetch_add(1, Ordering::Relaxed);
            },
        );

        producer.try_write(&readiness(7)).expect("written");
        receiver.drain();
        assert_eq!(dispatched.load(Ordering::Relaxed), 1);
        assert_eq!(failures.load(Ordering::Relaxed), 0);

        // Not a notification: as the userland receiver, fail rather than
        // panic, and receive nothing more.
        producer.try_write(&[0xff; 4]).expect("written");
        producer.try_write(&readiness(8)).expect("written");
        receiver.drain();
        assert_eq!(failures.load(Ordering::Relaxed), 1);
        receiver.drain();
        assert_eq!(dispatched.load(Ordering::Relaxed), 1);
        assert_eq!(failures.load(Ordering::Relaxed), 1);
    }
}
