// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LiteBox VM kernel's broker, like `litebox_broker_userland` for hosted
//! runners: [`Broker`] is the kernel's, and each runner process has an
//! [`Association`] with it (see `litebox_common_vm_abi`, Broker). Requests and
//! responses are in the control ring, pinned and accessed through the
//! kernel's mapping; payloads are in the process's lazily populated shared
//! buffers.
//!
//! Files are the devices under `/dev`, with standard streams on the
//! runner's [`stdio::Console`], and those of an optional read-only root
//! ([`Config::root`]). Timers are on the kernel clock. IPv4 TCP and UDP
//! sockets are on smoltcp (`litebox_broker_smoltcp`): between runner
//! processes, and, with the runner's [`Link`] ([`Config::network`]), to the
//! outside. Readiness (e.g., of standard input, a timer's expiry, or
//! sockets) goes to the association's notification ring. Waiting
//! ([`BrokerEnterOp::Wait`]) halts until the runner's [`Events`] report
//! something, e.g., an interrupt, or until a timer's or the network stack's
//! deadline.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod memory;
mod providers;
mod readiness;
pub mod stdio;
mod timers;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::convert::Infallible;
use litebox_broker_core::BrokerCore;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_host::BrokerHostAssociation;
use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_protocol::wire;
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::control_ring::{
    BrokerControlRingEndpoints, CONTROL_RING_MEMORY_SIZE, ControlRing, ControlRingConsumer,
    ControlRingDirection, ControlRingProducer, ControlRingReadStatus, ControlRingWriteStatus,
    MemoryAccessPolicy,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedBufferPool};
use litebox_common_vm_abi::{BrokerEnterOp, BrokerEnterRequest, Status, UserRange, WireFrame};
use litebox_platform::time::TimeProvider as _;
use litebox_platform_vm_kernel::{Instant, PinnedUserPages, VmKernel};

pub use litebox_broker_smoltcp::Link;

use memory::{PinnedControlRing, UserSharedMemory};
use readiness::KernelReadiness;
use stdio::ConsoleStdio;
use timers::KernelTimers;

/// Size of a process's broker shared memory.
pub const SHARED_MEMORY_SIZE: usize = SHARED_BUFFER_POOL_SIZE;

/// Size of a process's broker control ring.
pub const CONTROL_RING_SIZE: usize = CONTROL_RING_MEMORY_SIZE;

/// What the broker waits for: the runner's event sources (e.g., device
/// interrupts and a timer).
pub trait Events: Sync {
    /// Halts until an event may have happened, or until `deadline` passes.
    /// Without a deadline, false if no event could ever end the halt (and it
    /// does not halt).
    fn wait(&self, deadline: Option<Instant>) -> bool;

    /// Whether a device interrupted since [`Self::clear_interrupted`]: it may
    /// have something for the broker (e.g., received network frames), which
    /// [`Association::next_timer_deadline`] then makes due at once.
    fn interrupted(&self) -> bool {
        false
    }

    /// The broker is about to look at every device.
    fn clear_interrupted(&self) {}
}

/// The runner's sources for a [`Broker`].
pub struct Config {
    /// For its clock, which timers are on.
    pub platform: &'static VmKernel,
    /// Behind `/dev/stdin`, `/dev/stdout`, and `/dev/stderr`.
    pub console: &'static dyn stdio::Console,
    pub events: &'static dyn Events,
    /// A tar, read-only at `/`, e.g., a Linux program's files.
    pub root: Option<&'static [u8]>,
    /// The network sockets reach beyond the guest, if any.
    pub network: Option<&'static dyn Link>,
}

/// The kernel's broker; clones share it.
#[derive(Clone)]
pub struct Broker {
    core: BrokerCore,
    platform: &'static VmKernel,
    events: &'static dyn Events,
    stdio: Arc<ConsoleStdio>,
    timers: Arc<KernelTimers>,
    network: litebox_broker_smoltcp::Network,
}

impl Broker {
    /// At most once: only one broker core may exist.
    ///
    /// # Panics
    ///
    /// Without a hardware CSPRNG, or on a second call.
    pub fn new(config: Config) -> Self {
        let stdio = Arc::new(ConsoleStdio::new(config.console));
        let timers = Arc::new(KernelTimers::new(config.platform));
        let clock: &'static KernelClock =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(KernelClock(config.platform)));
        let network = litebox_broker_smoltcp::Network::new(
            clock,
            config.network,
            providers::seed(),
            &providers::LIMITS,
        );
        Self {
            core: providers::core(
                config.root,
                stdio.clone(),
                timers.clone(),
                network.provider(),
                config.network.is_some(),
            ),
            platform: config.platform,
            events: config.events,
            stdio,
            timers,
            network,
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
            readiness: Arc::new(KernelReadiness::default()),
            state: RefCell::new(State::New(ring)),
        }
    }

    /// Looks at what changes outside requests: standard input, timers, and
    /// the network.
    fn poll_sources(&self) {
        // First: a device interrupting meanwhile is looked at next time.
        self.events.clear_interrupted();
        self.stdio.poll();
        self.timers.fire();
        self.network.poll();
    }

    /// When the network stack must next run, if ever.
    fn next_network_poll(&self) -> Option<Instant> {
        self.network.next_poll().map(instant)
    }
}

/// `time` on the [`KernelClock`], as an instant.
fn instant(time: core::time::Duration) -> Instant {
    Instant::from_nanos(u64::try_from(time.as_nanos()).unwrap_or(u64::MAX))
}

/// The kernel clock, for the network stack.
struct KernelClock(&'static VmKernel);

impl litebox_broker_smoltcp::Clock for KernelClock {
    fn now(&self) -> core::time::Duration {
        core::time::Duration::from_nanos(self.0.now().as_nanos())
    }
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

/// The broker's ends of the request and response rings; the notification
/// ring's is in [`Association::readiness`].
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
    readiness: Arc<KernelReadiness>,
    state: RefCell<State>,
}

/// [`Status::Unsupported`] if the response does not fit a [`WireFrame`].
fn frame(bytes: &[u8]) -> Result<WireFrame, Status> {
    WireFrame::new(bytes).ok_or(Status::Unsupported)
}

impl Association {
    /// When, on the kernel clock, [`Self::fire_timers`] must next run while
    /// the process runs: the earliest armed broker timer's deadline, the
    /// network stack's (e.g., to retransmit), or soon after a device
    /// interrupt (e.g., frames received): as soon as the network stack may
    /// run again, so a flood of interrupts cannot keep the CPU.
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        let devices = self
            .broker
            .events
            .interrupted()
            .then(|| instant(self.broker.network.earliest_run()));
        timers::earliest(
            timers::earliest(self.broker.timers.next_deadline(), devices),
            self.broker.next_network_poll(),
        )
    }

    /// Does what is due outside requests (fires the broker timers, runs the
    /// network stack, looks at standard input) and publishes the readiness
    /// that changes, as [`BrokerEnterOp::Wait`] would; for a process that is
    /// running instead. Whether anything was published: see
    /// [`Self::take_published`]. A notification ring this corrupts fails the
    /// association, which its next [`Self::enter`] reports.
    pub fn fire_timers(&self) {
        self.broker.poll_sources();
        let _ = self.flush_readiness();
    }

    /// Whether a notification was published since the last call (e.g., a
    /// timer fired, or standard input arrived, as the broker served a
    /// request): the process then has something to receive, even while it
    /// runs.
    pub fn take_published(&self) -> bool {
        self.readiness.take_published()
    }

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
        let readiness: Arc<dyn ReadinessSink> = self.readiness.clone();
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
                notification_producer,
            } = ring.into_broker();
            self.readiness.activate(notification_producer);
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
    /// Waiting halts the kernel (single CPU, no scheduler) until the word
    /// changes or the deadline passes, running the network stack at its
    /// deadlines meanwhile. Only notifications change ring words
    /// asynchronously; a wait on another word without a deadline, or on the
    /// notification epoch when no event or armed timer could publish, is
    /// [`Status::Stalled`]. A corrupted notification ring fails the
    /// association, as a corrupted request ring does.
    ///
    /// # Errors
    ///
    /// See [`EnterError`].
    pub fn enter(&self, request: &BrokerEnterRequest) -> Result<(), EnterError> {
        let mut state = self.state.borrow_mut();
        let State::Active(active) = &mut *state else {
            return Err(EnterError::Status(Status::Denied));
        };
        let result = self.enter_active(active, request);
        if result == Err(EnterError::Failed)
            && let State::Active(active) = core::mem::replace(&mut *state, State::Ended)
        {
            end(active.association, &self.readiness);
        }
        result
    }

    fn enter_active(
        &self,
        active: &mut Active,
        request: &BrokerEnterRequest,
    ) -> Result<(), EnterError> {
        let invalid = || EnterError::Status(Status::InvalidArgument);
        let wait_offset = match request.op {
            BrokerEnterOp::Wake => {
                if (request.expected, request.offset, request.deadline) != (0, 0, 0) {
                    return Err(invalid());
                }
                None
            }
            BrokerEnterOp::Wait => {
                let offset = usize::try_from(request.offset).map_err(|_| invalid())?;
                if !MemoryAccessPolicy::ControlRing.permits_u32(offset) {
                    return Err(invalid());
                }
                Some(offset)
            }
        };
        self.broker.poll_sources();
        active.serve().map_err(|Failed| EnterError::Failed)?;
        self.flush_readiness()?;
        let Some(offset) = wait_offset else {
            return Ok(());
        };
        let deadline = (request.deadline != 0).then(|| Instant::from_nanos(request.deadline));
        let asynchronous = offset == ControlRingDirection::Notifications.producer_epoch_offset();
        loop {
            match active.words.load_u32_acquire(offset) {
                Ok(word) if word != request.expected => {
                    if asynchronous {
                        // The runner receives the notifications next, so
                        // need not also be interrupted for them.
                        self.readiness.take_published();
                    }
                    return Ok(());
                }
                Ok(_) => {}
                Err(_) => return Err(invalid()),
            }
            if deadline.is_some_and(|deadline| self.broker.platform.now() >= deadline) {
                return Err(EnterError::Status(Status::TimedOut));
            }
            if deadline.is_none() && !asynchronous {
                return Err(EnterError::Status(Status::Stalled));
            }
            // Only notifications see timers, which fire as the broker runs.
            let wake = if asynchronous {
                timers::earliest(deadline, self.broker.timers.next_deadline())
            } else {
                deadline
            };
            let wake = timers::earliest(wake, self.broker.next_network_poll());
            if !self.broker.events.wait(wake) {
                return Err(EnterError::Status(Status::Stalled));
            }
            self.broker.poll_sources();
            self.flush_readiness()?;
        }
    }

    /// Publishes pending readiness; a corrupted notification ring fails the
    /// association.
    fn flush_readiness(&self) -> Result<(), EnterError> {
        self.readiness.flush();
        if self.readiness.failed() {
            return Err(EnterError::Failed);
        }
        Ok(())
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
fn end(association: BrokerHostAssociation<UserSharedMemory>, readiness: &KernelReadiness) {
    readiness.close();
    association.request_cancellation();
    association.association_ending();
    association.finish();
}

impl Drop for Association {
    fn drop(&mut self) {
        if let State::Active(active) = core::mem::replace(self.state.get_mut(), State::Ended) {
            end(active.association, &self.readiness);
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
