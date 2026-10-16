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
//! runner's [`stdio::Console`], those of an optional read-only root
//! ([`Config::root`]), and read-only host directories ([`Config::shares`]).
//! Timers are on the kernel clock. IPv4 TCP and UDP
//! sockets are `litebox_broker_smoltcp`'s, which mediates their traffic:
//! between runner processes directly, and, with the runner's [`Network`]
//! device ([`Config::network`]), to the outside on smoltcp. Readiness (e.g., of
//! standard input, a timer's expiry, or sockets) goes to the association's
//! notification ring.
//!
//! As in the userland broker, requests are served apart from the runner's
//! calls ([`Association::serve`]), and a wait blocks only its process: the
//! kernel's scheduler polls it ([`Association::poll_wait`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod memory;
mod providers;
mod readiness;
pub mod share;
pub mod stdio;
mod timers;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, Ordering};
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

use litebox_broker_smoltcp::{Network, SmoltcpSocketProvider};

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

    /// Whether a device interrupted since the last call.
    fn take_device_interrupt(&self) -> bool;
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
    /// Host directories, each mounted read-only at its path.
    pub shares: Vec<share::Share>,
    /// The network sockets reach beyond the guest, if any.
    pub network: Option<&'static dyn Network>,
}

/// The kernel's broker; clones share it.
#[derive(Clone)]
pub struct Broker {
    core: BrokerCore,
    platform: &'static VmKernel,
    events: &'static dyn Events,
    stdio: Arc<ConsoleStdio>,
    timers: Arc<KernelTimers>,
    /// See [`Association::take_woken`].
    woken: Arc<AtomicBool>,
    sockets: Arc<SmoltcpSocketProvider>,
}

impl Broker {
    /// At most once: only one broker core may exist.
    ///
    /// # Panics
    ///
    /// Without a hardware CSPRNG, on a second call, or if a share cannot be
    /// mounted.
    pub fn new(config: Config) -> Self {
        let stdio = Arc::new(ConsoleStdio::new(config.console));
        let timers = Arc::new(KernelTimers::new(config.platform));
        let sockets = Arc::new(SmoltcpSocketProvider::new(
            providers::LIMITS.max_sockets,
            providers::LIMITS.max_sockets_per_process,
            timers.clone(),
            config.network,
            providers::seed(),
        ));
        Self {
            core: providers::core(
                config.root,
                config.shares,
                stdio.clone(),
                timers.clone(),
                sockets.clone(),
                config.network.is_some(),
            ),
            platform: config.platform,
            events: config.events,
            stdio,
            timers,
            woken: Arc::new(AtomicBool::new(false)),
            sockets,
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
            readiness: Arc::new(KernelReadiness::new(self.woken.clone())),
            state: RefCell::new(State::New(ring)),
            submitted: Cell::new(false),
        }
    }

    /// Looks at what changes outside requests: standard input, timers, and
    /// the network.
    fn poll_sources(&self) {
        self.stdio.poll();
        self.timers.fire();
        self.sockets.poll();
    }

    /// When the network stack must next run, if ever.
    fn next_network_deadline(&self) -> Option<Instant> {
        self.sockets.next_deadline().map(timers::instant)
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

/// A process's broker association. Only [`Association::serve`] and the
/// handshake touch the shared buffers.
pub struct Association {
    broker: Broker,
    shared_memory: UserRange,
    readiness: Arc<KernelReadiness>,
    state: RefCell<State>,
    /// See [`Association::has_submitted`].
    submitted: Cell<bool>,
}

/// A [`BrokerEnterOp::Wait`] that did not end at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    offset: usize,
    expected: u32,
    deadline: Option<Instant>,
    /// On the notification epoch, which the broker changes on its own.
    notifications: bool,
}

/// What [`Association::enter`] leaves to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entered {
    Done,
    /// [`BrokerEnterOp::Wake`]: serve before the call returns.
    Woke,
    /// Poll it with [`Association::poll_wait`].
    Wait(Wait),
}

/// See [`Association::poll_wait`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitState {
    Ended(Result<(), EnterError>),
    /// Until an event, or `wake`, if any (see [`Association::halt`]).
    Blocked {
        wake: Option<Instant>,
    },
}

/// [`Status::Unsupported`] if the response does not fit a [`WireFrame`].
fn frame(bytes: &[u8]) -> Result<WireFrame, Status> {
    WireFrame::new(bytes).ok_or(Status::Unsupported)
}

impl Association {
    /// When, on the kernel clock, [`Self::poll_events`] next has something
    /// to do: the earliest armed broker timer's deadline, or the network
    /// stack's (e.g., to retransmit).
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        timers::earliest(
            self.broker.timers.next_deadline(),
            self.broker.next_network_deadline(),
        )
    }

    /// Looks at the devices (standard input, the network) and fires the
    /// broker timers that are due, publishing readiness, as
    /// [`BrokerEnterOp::Wait`] would; for a process that is running instead
    /// (e.g., an interrupt stopped it). A notification ring this corrupts
    /// fails the association, which its next [`Self::enter`] reports.
    pub fn poll_events(&self) {
        self.broker.poll_sources();
        let _ = self.flush_readiness();
    }

    /// Whether a notification was published since the last call (e.g., a
    /// timer fired, or standard input arrived, as the broker served a request
    /// or [`Self::poll_events`]): the process then has something to receive,
    /// even while it runs.
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

    /// [`BrokerEnter`](litebox_common_vm_abi::CallId::BrokerEnter): leaves
    /// published requests to [`Self::serve`], and a wait that does not end at
    /// once to the caller. An invalid request has no effect. Before the
    /// handshake, any request is [`Status::Denied`]. A corrupted notification
    /// ring fails the association, as a corrupted request ring does.
    ///
    /// # Errors
    ///
    /// See [`EnterError`].
    pub fn enter(&self, request: &BrokerEnterRequest) -> Result<Entered, EnterError> {
        if !matches!(*self.state.borrow(), State::Active(_)) {
            return Err(EnterError::Status(Status::Denied));
        }
        let invalid = || EnterError::Status(Status::InvalidArgument);
        let wait = match request.op {
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
                Some(Wait {
                    offset,
                    expected: request.expected,
                    deadline: (request.deadline != 0)
                        .then(|| Instant::from_nanos(request.deadline)),
                    notifications: offset
                        == ControlRingDirection::Notifications.producer_epoch_offset(),
                })
            }
        };
        self.submitted.set(true);
        let Some(wait) = wait else {
            self.with_active(|_| self.poll())?;
            return Ok(Entered::Woke);
        };
        match self.poll_wait(&wait) {
            WaitState::Ended(result) => result.map(|()| Entered::Done),
            WaitState::Blocked { .. } => Ok(Entered::Wait(wait)),
        }
    }

    /// Whether a call since the last [`Self::serve`] may have published
    /// requests.
    pub fn has_submitted(&self) -> bool {
        self.submitted.get()
    }

    /// Serves the published requests, unless the response ring fills up.
    /// Needs the process's address space, for the shared buffers.
    ///
    /// # Errors
    ///
    /// [`EnterError::Failed`], which ended the association.
    pub fn serve(&self) -> Result<(), EnterError> {
        self.submitted.set(false);
        self.with_active(|active| {
            active.serve().map_err(|Failed| EnterError::Failed)?;
            self.flush_readiness()
        })
    }

    /// Where `wait` stands, after firing due timers and publishing readiness.
    /// Without a deadline, a wait on a word other than the notification epoch
    /// is [`Status::Stalled`] once [`Self::serve`] has nothing left to serve.
    pub fn poll_wait(&self, wait: &Wait) -> WaitState {
        let state = self
            .with_active(|active| {
                self.poll()?;
                match active.words.load_u32_acquire(wait.offset) {
                    Ok(word) if word != wait.expected => {
                        if wait.notifications {
                            // The runner receives them next, so need not also
                            // be interrupted for them.
                            self.readiness.take_published();
                        }
                        return Ok(WaitState::Ended(Ok(())));
                    }
                    Ok(_) => {}
                    Err(_) => return Err(EnterError::Status(Status::InvalidArgument)),
                }
                let now = self.broker.platform.now();
                if wait.deadline.is_some_and(|deadline| now >= deadline) {
                    return Err(EnterError::Status(Status::TimedOut));
                }
                if wait.deadline.is_none() && !wait.notifications && !self.submitted.get() {
                    return Err(EnterError::Status(Status::Stalled));
                }
                // Only notifications see timers; the network stack runs at
                // its deadlines, whatever the wait.
                let wake = if wait.notifications {
                    timers::earliest(wait.deadline, self.broker.timers.next_deadline())
                } else {
                    wait.deadline
                };
                let wake = timers::earliest(wake, self.broker.next_network_deadline());
                Ok(WaitState::Blocked { wake })
            })
            .unwrap_or_else(|error| WaitState::Ended(Err(error)));
        self.readiness
            .set_waiting(wait.notifications && matches!(state, WaitState::Blocked { .. }));
        state
    }

    /// See [`Events::take_device_interrupt`].
    pub fn take_device_interrupt(&self) -> bool {
        self.broker.events.take_device_interrupt()
    }

    /// For a blocked wait that the caller ends itself (e.g., stalled, or the
    /// process killed).
    pub fn abandon_wait(&self) {
        self.readiness.set_waiting(false);
    }

    /// Whether a notification reached a process blocked on its notification
    /// epoch since the last call (any process's): poll the waits again.
    pub fn take_woken(&self) -> bool {
        self.broker.woken.swap(false, Ordering::Relaxed)
    }

    /// [`Events::wait`]: for when no process can run.
    pub fn halt(&self, wake: Option<Instant>) -> bool {
        self.broker.events.wait(wake)
    }

    /// Runs `f` on the active association, ending it if `f` fails it.
    fn with_active<T>(
        &self,
        f: impl FnOnce(&mut Active) -> Result<T, EnterError>,
    ) -> Result<T, EnterError> {
        let mut state = self.state.borrow_mut();
        let State::Active(active) = &mut *state else {
            return Err(EnterError::Status(Status::Denied));
        };
        let result = f(active);
        if let Err(EnterError::Failed) = result
            && let State::Active(active) = core::mem::replace(&mut *state, State::Ended)
        {
            end(active.association, &self.readiness);
        }
        result
    }

    /// Catches up with what changed outside requests (devices, timers),
    /// publishing readiness.
    fn poll(&self) -> Result<(), EnterError> {
        self.broker.poll_sources();
        self.flush_readiness()
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
