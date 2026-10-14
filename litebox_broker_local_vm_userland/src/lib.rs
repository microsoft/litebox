// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker's local endpoint for a runner on the LiteBox VM kernel, like
//! `litebox_broker_local_userland` for hosted runners: handshake in a kernel
//! call, then requests and responses in the control ring and payloads in the
//! shared buffers (see `litebox_common_vm_abi`, Broker).
//!
//! Where the userland transport uses futexes, this one uses the kernel's
//! (`BrokerEnter`'s Wake and Wait). The kernel serves the ring apart from
//! them, so a call takes a Wake and, unless the response is already there, a
//! Wait. Shared memory is accessed only through
//! `peer_memory`.
//!
//! Notifications (readiness of broker objects, e.g., standard input) have no
//! receiver thread: the runner receives them with [`Notifications::receive`],
//! which also waits for them, or, as the platform's waits and interrupts
//! need, with a [`Receiver`] (in place of the userland receiver thread).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

use alloc::sync::Arc;
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
    BrokerEnterRequest, BrokerHandshakeFrame, StartupInfo, Status, UserRange, WireFrame,
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

/// The local ends of the request and response rings.
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

/// The kernel's futex operations on ring words.
impl WaitableSharedMemory for KernelControlRing {
    type Error = ChannelError;

    fn wait_access_error(error: SharedMemoryError) -> ChannelError {
        ChannelError::Memory(error)
    }

    fn wait_while_equal(&self, offset: usize, expected: u32) -> Result<(), ChannelError> {
        broker_wait(offset, expected, None).map_err(ChannelError::Kernel)
    }

    /// The kernel waits on no ring word: only new requests need it.
    fn wake_one(&self, offset: usize) -> Result<(), ChannelError> {
        if offset == ControlRingDirection::Requests.producer_epoch_offset() {
            broker_wake().map_err(ChannelError::Kernel)?;
        }
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
                rings: spin::Mutex::new(Some(Rings {
                    requests: request_producer,
                    responses: response_consumer,
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
            let (received, wait_epoch) = self.read_published(&mut dispatch, broker_wake)?;
            if received != 0 {
                return Ok(received);
            }
            let epoch = ControlRingDirection::Notifications.producer_epoch_offset();
            match broker_wait(epoch, wait_epoch, deadline) {
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
        Ok(self.read_published(&mut dispatch, broker_wake)?.0)
    }

    /// As [`Self::try_receive`], also returning the producer epoch to wait on
    /// while the ring stays empty; `publish_rest` (e.g., [`broker_wake`]) has
    /// the kernel publish what did not fit in a full ring.
    fn read_published(
        &mut self,
        dispatch: &mut impl FnMut(BrokerNotification),
        mut publish_rest: impl FnMut() -> Result<(), Status>,
    ) -> Result<(usize, u32), ChannelError> {
        let mut received = 0;
        loop {
            let mut batch = 0;
            let wait_epoch = loop {
                match self.consumer.try_read(wire::decode_notification) {
                    Ok(ControlRingReadStatus::Message(notification)) => {
                        dispatch(notification);
                        batch += 1;
                    }
                    Ok(ControlRingReadStatus::Empty { wait_epoch }) => break wait_epoch,
                    Err(error) => return Err(read_error(error)),
                }
            };
            received += batch;
            if batch != 0 {
                // The kernel sees the freed slots when it next publishes.
                self.consumer.publish_head().map_err(ChannelError::Ring)?;
            }
            if (batch as u64) < CONTROL_RING_NOTIFICATION_SLOT_COUNT {
                return Ok((received, wait_epoch));
            }
            // A full ring: the kernel may hold more. This publishes them, and
            // so leaves the kernel to interrupt the process for them once
            // more, with nothing left to receive by then.
            publish_rest().map_err(ChannelError::Kernel)?;
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
            notifications: spin::Mutex::new(Some(self)),
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
pub struct Receiver<Dispatch, Failure> {
    /// `None` once receiving failed.
    notifications: spin::Mutex<Option<Notifications>>,
    dispatch: Dispatch,
    dispatch_failure: Failure,
}

impl<Dispatch, Failure> Receiver<Dispatch, Failure>
where
    Dispatch: Fn(BrokerNotification) + Sync,
    Failure: Fn() + Sync,
{
    /// `receive` on the notifications, unless receiving failed (`None`);
    /// fails them on an error.
    fn with_notifications<T>(
        &self,
        receive: impl FnOnce(&mut Notifications, &Dispatch) -> Result<T, ChannelError>,
    ) -> Option<Result<T, ChannelError>> {
        let mut notifications = self
            .notifications
            .try_lock()
            .expect("one thread receives at a time");
        let result = receive(notifications.as_mut()?, &self.dispatch);
        match &result {
            Err(ChannelError::Kernel(Status::Stalled)) | Ok(_) => {}
            Err(error) => {
                log::error!("failed to receive broker notifications: {error}");
                *notifications = None;
                drop(notifications);
                (self.dispatch_failure)();
            }
        }
        Some(result)
    }
}

impl<Dispatch, Failure> NotificationReceiver for Receiver<Dispatch, Failure>
where
    Dispatch: Fn(BrokerNotification) + Sync,
    Failure: Fn() + Sync,
{
    /// After a failure, nothing could publish (`None`). The failure itself
    /// counts as one dispatched notification, so waiters recheck (and see
    /// their objects failed).
    fn receive(&self, deadline: Option<Instant>) -> Option<usize> {
        match self.with_notifications(|notifications, dispatch| {
            notifications.receive(deadline, dispatch)
        })? {
            Ok(received) => Some(received),
            // Nothing could publish: no input to come, and no timer armed.
            Err(ChannelError::Kernel(Status::Stalled)) => None,
            Err(_) => Some(1),
        }
    }

    fn drain(&self) {
        self.with_notifications(|notifications, dispatch| notifications.try_receive(dispatch));
    }
}

fn read_error(error: ControlRingReadError<WireError>) -> ChannelError {
    match error {
        ControlRingReadError::Ring(error) => ChannelError::Ring(error),
        ControlRingReadError::Decode(error) => ChannelError::Wire(error),
    }
}

/// Has the kernel serve published broker requests.
fn broker_wake() -> Result<(), Status> {
    kcall::call(&BrokerEnterRequest::wake())
}

/// Has the kernel serve published broker requests, and waits while the
/// control-ring word at `offset` equals `expected`, until `deadline`, if any.
fn broker_wait(offset: usize, expected: u32, deadline: Option<Instant>) -> Result<(), Status> {
    // Zero means none, so the (theoretical) instant zero waits from 1 ns.
    let deadline = deadline.map_or(0, |deadline| deadline.as_nanos().max(1));
    kcall::call(&BrokerEnterRequest::wait(offset as u64, expected, deadline))
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
    broker_wake().expect("waking an idle broker");
    let notified = current(epoch);
    assert_eq!(
        broker_wait(epoch, notified.wrapping_add(1), None),
        Ok(()),
        "word differs"
    );
    let soon = now()
        .checked_add(core::time::Duration::from_millis(1))
        .expect("the clock is far from overflowing");
    assert_eq!(
        broker_wait(served, current(served), None),
        Err(Status::Stalled)
    );
    assert_eq!(
        broker_wait(served, current(served), Some(soon)),
        Err(Status::TimedOut)
    );
    assert!(now() >= soon, "a timed wait returned early");
    assert_eq!(broker_wait(0, 0, None), Err(Status::InvalidArgument));
    let mut wake = BrokerEnterRequest::wake();
    wake.expected = 1;
    assert_eq!(kcall::call(&wake), Err(Status::InvalidArgument));
    broker_wake().expect("the association survives");
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
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
        assert_eq!(
            receiver.receive(Some(Instant::from_nanos(1))),
            None,
            "nothing could publish, so no wait"
        );
        assert_eq!(dispatched.load(Ordering::Relaxed), 1);
        assert_eq!(failures.load(Ordering::Relaxed), 1);
    }
}
