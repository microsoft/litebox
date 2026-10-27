// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LiteBox VM kernel's broker, like `litebox_broker_userland` for hosted
//! runners: [`Broker`] is the kernel's, and each runner process has an
//! [`Association`] with it (see `litebox_common_vm_abi`, Broker). Requests and
//! responses are in the control ring, payloads in the shared buffers: both
//! pinned (the shared buffers populated as they are accessed), and accessed
//! through the kernel's mapping, from any CPU, in any address space.
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
//! calls ([`Association::run`], a batch at a time, on the process's broker
//! task: see [`litebox_platform_vm_kernel::worker`]), and a wait blocks only
//! its process: the kernel's scheduler polls it ([`Association::poll_wait`]).
//!
//! A process can start a child process (`StartChild`). Its association queues a
//! [`PendingRunnerAssociation`] ([`Association::take_pending_associations`]),
//! for which the kernel creates a runner process and associates it
//! ([`Broker::associate`]); the child's handshake returns its startup data.
//! It can also start one with an existing runner
//! (`StartChildWithExistingRunner`): a process clone it made (see
//! `litebox_common_vm_abi`, `CloneKind::Process`), which the kernel associated
//! as it made it ([`Broker::associate_clone`]). The child's queued association
//! names the clone ([`PendingRunnerAssociation::clone_to_adopt`]), which the
//! kernel adopts as the child's runner ([`Association::adopt`]), making the
//! clone's handshake before it runs, so that the parent's task, suspended in
//! the start, never waits for the clone. Memory images (`WriteChildMemory`) are
//! not supported.
//!
//! When a process ends ([`Association::exited`]), its association ends on its
//! task ([`Association::run`]), and its broker process exits, releasing what
//! it holds (e.g., pipe ends).
//!
//! Releasing what a process holds may wait for a provider (e.g., closing a
//! share's file, for the 9P client's lock, which a task holds across its round
//! trips, suspended), so it runs on tasks only: an association ends on its
//! process's task, and a child's start that fails elsewhere (e.g., as its
//! handshake fails, in a thread's entry) is failed by its parent's task, which
//! waits for it (see [`PendingRunnerAssociation`]). What runs elsewhere (the
//! handshake, an adoption, and a root's failed start) takes spin locks only,
//! with this broker's providers (see [`Association::handshake`]), and the
//! core's lifecycle notifications only wake tasks (see `TaskWake`).
//!
//! With child processes enabled ([`Config::allow_process_duplication`]), the
//! broker has a virtual init: process 1, a broker process with no runner
//! process, that never exits. Each process the kernel starts on its own (a
//! root) is init's child and leads its own session and process group. Init
//! adopts orphans, as on Linux, and keeps no exit statuses, so its children
//! are reaped as they exit, as `tini` does. Otherwise, a root's handshake
//! creates its broker process with no parent, as the userland broker does for
//! its root runner.

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
use core::cell::{Cell, OnceCell, RefCell};
use core::convert::Infallible;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{
    BrokerCore, BrokerError, BrokerProcess, CallerCredential, ChildImage, ProcessImage,
    ProcessLifecycleSink, process_group,
};
use litebox_broker_host::{BrokerHostAssociation, ProcessLauncher, handle_process_operation};
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_protocol::wire;
use litebox_broker_transport::channel::{HostReceive, HostSetupChannel, PeerCredential};
use litebox_broker_transport::control_ring::{
    ControlRing, ControlRingConsumer, ControlRingLayout, ControlRingProducer,
    ControlRingReadStatus, ControlRingWriteStatus, HostControlRingEndpoints,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedBufferPool};
use litebox_common_vm_abi::{Status, WireFrame};
use litebox_platform::time::TimeProvider as _;
use litebox_platform_vm_kernel::{Instant, PinnedUserPages, VmKernel, cpu, worker};

use litebox_broker_smoltcp::{Network, SmoltcpSocketProvider};

use memory::{PinnedControlRing, UserSharedMemory};
use readiness::KernelReadiness;
use stdio::ConsoleStdio;
use timers::KernelTimers;

/// Size of a process's broker shared memory.
pub const SHARED_MEMORY_SIZE: usize = SHARED_BUFFER_POOL_SIZE;

/// Layout of a process's broker control ring: the kernel serves one call at a
/// time, so a single lane.
pub const CONTROL_RING_LAYOUT: ControlRingLayout = ControlRingLayout::SINGLE_LANE;

/// Size of a process's broker control ring.
pub const CONTROL_RING_SIZE: usize = CONTROL_RING_LAYOUT.memory_size();

/// What the kernel's scheduler halts with: the runner's event sources (e.g.,
/// device interrupts and a timer), for the processes' waits (see
/// [`Association::poll_wait`]).
pub trait Events: Sync {
    /// Halts the calling CPU until an event may have happened, another CPU
    /// wakes it (see [`cpu::halt`]), or `deadline` passes. Without a
    /// deadline, false if no device could ever end the halt (and it does not
    /// halt).
    fn wait(&self, deadline: Option<Instant>) -> bool;
}

/// The runner's sources for a [`Broker`].
pub struct Config {
    /// For its clock, which timers are on.
    pub platform: &'static VmKernel,
    /// Behind `/dev/stdin`, `/dev/stdout`, and `/dev/stderr`.
    pub console: &'static dyn stdio::Console,
    /// A tar, read-only at `/`, e.g., a Linux program's files.
    pub root: Option<&'static [u8]>,
    /// Host directories, each mounted read-only at its path.
    pub shares: Vec<share::Share>,
    /// The network sockets reach beyond the guest, if any.
    pub network: Option<&'static dyn Network>,
    /// Whether processes may start child processes (process duplication), as
    /// the userland broker's `allow_process_duplication`; the kernel then
    /// creates their runner processes (see [`PendingRunnerAssociation`]). Roots
    /// then run under a virtual init (see the [crate] docs).
    pub allow_process_duplication: bool,
}

/// The kernel's broker; clones share it.
#[derive(Clone)]
pub struct Broker {
    core: BrokerCore,
    platform: &'static VmKernel,
    stdio: Arc<ConsoleStdio>,
    timers: Arc<KernelTimers>,
    sockets: Arc<SmoltcpSocketProvider>,
    /// The virtual init, with [`Config::allow_process_duplication`].
    init: Option<Arc<BrokerProcess>>,
}

impl Broker {
    /// At most once: only one broker core may exist.
    ///
    /// # Panics
    ///
    /// Without a hardware CSPRNG, on a second call, if a share cannot be
    /// mounted, or if the virtual init cannot be created as process 1.
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
        let core = providers::core(
            config.root,
            config.shares,
            stdio.clone(),
            timers.clone(),
            sockets.clone(),
            config.network.is_some(),
            config.allow_process_duplication,
        );
        let init = config.allow_process_duplication.then(|| {
            let init = core
                .create_process(CallerCredential::HostGuaranteed, None)
                .expect("the first process can be created");
            assert_eq!(
                init.id(),
                ProcessId(1),
                "the virtual init is the first process"
            );
            init.complete_start().expect("a new process can start");
            init.set_orphan_adoption(true)
                .and_then(|()| init.set_child_exit_retention(false))
                .expect("a running process can change its place in the tree");
            init
        });
        Self {
            core,
            platform: config.platform,
            stdio,
            timers,
            sockets,
            init,
        }
    }

    /// A process's association, before its handshake. The shared buffers are
    /// `shared_memory` (see [`SHARED_MEMORY_SIZE`]), which may be pinned
    /// lazily; the control ring is at the start of `control_ring_pages`. With
    /// `launch`, the process is a launched one, and its handshake attaches it
    /// to `launch`'s broker process. Otherwise, it is a root; under the
    /// virtual init, its broker process is created here (see the [crate]
    /// docs).
    ///
    /// # Errors
    ///
    /// If the root's broker process cannot be created (e.g., too many
    /// processes).
    ///
    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    pub fn associate(
        &self,
        shared_memory: PinnedUserPages,
        control_ring_pages: PinnedUserPages,
        launch: Option<PendingRunnerAssociation>,
    ) -> Result<Association, BrokerError> {
        let launched = launch.is_some();
        let launch = match (launch, &self.init) {
            (None, Some(init)) => {
                let id = init.allocate_child_process()?.process_id;
                // Its own session, as without init, so that, e.g., a root's
                // `kill(0, ..)` reaches no other root.
                let process = process_group::create_session(init, id)
                    .and_then(|()| init.take_child_process(id))
                    .inspect_err(|_| {
                        let _ = init.cancel_child_process(id);
                    })?;
                Some(PendingRunnerAssociation::root(process))
            }
            (launch, _) => launch,
        };
        Ok(self.association(shared_memory, control_ring_pages, launched, launch))
    }

    /// A process clone's association (see `litebox_common_vm_abi`,
    /// `CloneKind::Process`), before its handshake: as a launched process's
    /// (see [`Self::associate`]), but with no process until
    /// [`Association::adopt`] gives it one. `control_ring_pages` must be
    /// zeroed, as a new process's are.
    ///
    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    pub fn associate_clone(
        &self,
        shared_memory: PinnedUserPages,
        control_ring_pages: PinnedUserPages,
    ) -> Association {
        self.association(shared_memory, control_ring_pages, true, None)
    }

    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    fn association(
        &self,
        shared_memory: PinnedUserPages,
        control_ring_pages: PinnedUserPages,
        launched: bool,
        launch: Option<PendingRunnerAssociation>,
    ) -> Association {
        let memory =
            PinnedControlRing::new(control_ring_pages).expect("the pages hold the control ring");
        let ring = ControlRing::new(memory, CONTROL_RING_LAYOUT)
            .expect("a pinned control ring has the exact size");
        Association {
            broker: self.clone(),
            readiness: Arc::new(KernelReadiness::new()),
            launched,
            process: launch
                .as_ref()
                .map(|launch| OnceCell::from(launch.process.clone()))
                .unwrap_or_default(),
            exit_status: Cell::new(None),
            torn_down: Cell::new(false),
            launcher: Arc::new(KernelProcessLauncher::default()),
            state: RefCell::new(State::New(
                ring,
                UserSharedMemory::new(shared_memory),
                launch,
            )),
            adoption_response: Cell::new(None),
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

/// The handshake request a runner makes, which the kernel makes for a
/// process clone (see [`Association::adopt`]).
const RUNNER_HANDSHAKE: BrokerHandshakeRequest = BrokerHandshakeRequest {
    protocol_version: litebox_broker_protocol::BROKER_PROTOCOL_VERSION,
};

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
    /// Before the handshake, with the ring and shared buffers it would
    /// activate, and the pending association, if the broker process already
    /// exists (see [`Broker::associate`]).
    New(
        ControlRing<PinnedControlRing>,
        UserSharedMemory,
        Option<PendingRunnerAssociation>,
    ),
    Active(Box<Active>),
    /// Serving failed it; it ends once the process ended (see
    /// [`Association::run`]).
    Ending(Box<Active>),
    /// The handshake did not activate one, or it ended.
    Ended,
}

/// The broker's ends of the request and response rings; the notification
/// ring's is in [`Association::readiness`].
struct Active {
    association: BrokerHostAssociation<UserSharedMemory>,
    requests: ControlRingConsumer<PinnedControlRing>,
    responses: ControlRingProducer<PinnedControlRing>,
    /// For [`RingFutex::Wait`].
    words: PinnedControlRing,
    /// A response the full ring could not take; no request is consumed while
    /// it waits.
    overflow: Option<Vec<u8>>,
}

/// A process's broker association. Only [`Association::run`] and the
/// handshake touch the shared buffers.
pub struct Association {
    broker: Broker,
    readiness: Arc<KernelReadiness>,
    /// See [`Broker::associate`].
    launched: bool,
    /// The broker process: from the start, or once the handshake creates it
    /// (see [`Broker::associate`]). The process's end completes its exit.
    process: OnceCell<Arc<BrokerProcess>>,
    /// Once the process ended (see [`Self::exited`]): its task then ends the
    /// association.
    exit_status: Cell<Option<ProcessExitStatus>>,
    /// Its task ended it (see [`Self::run`]).
    torn_down: Cell<bool>,
    /// Queues the child processes the process starts, for the kernel.
    launcher: Arc<KernelProcessLauncher>,
    state: RefCell<State>,
    /// The response of a process clone's handshake, which [`Self::adopt`]
    /// made, until the clone's own [`Self::handshake`] takes it.
    adoption_response: Cell<Option<WireFrame>>,
    /// See [`Association::has_submitted`].
    submitted: Cell<bool>,
}

/// A [`RingFutex::Wait`] that did not end at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait {
    offset: usize,
    expected: u32,
    deadline: Option<Instant>,
    /// On the notification wake counter, which the broker changes on its own.
    notifications: bool,
}

impl Wait {
    /// Whether it is on the notification wake counter, which a notification
    /// ends.
    pub fn is_for_notifications(&self) -> bool {
        self.notifications
    }
}

/// A futex operation on a word of the control ring (see
/// `litebox_common_vm_abi`, Broker).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingFutex {
    /// On the requests' producer wake counter, has the broker serve them; on
    /// other words, nothing.
    Wake,
    /// Until the word differs from `expected`, or `deadline` passes.
    Wait {
        expected: u32,
        deadline: Option<Instant>,
    },
}

/// What [`Association::futex`] leaves to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entered {
    Done,
    /// [`RingFutex::Wake`] on the requests' producer wake counter: serve
    /// before the call returns.
    Woke,
    /// Poll it with [`Association::poll_wait`].
    Wait(Wait),
}

/// See [`Association::poll_wait`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitState {
    Ended(Result<(), EnterError>),
    /// Until an event, or `wake`, if any (see [`Events::wait`]).
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
    /// [`RingFutex::Wait`] would; for a process that is running instead
    /// (e.g., an interrupt stopped it). A notification ring this corrupts
    /// fails the association, which its next [`Self::futex`] reports.
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

    /// Whether the notification ring holds notifications the process has not
    /// consumed (published its progress past): unlike
    /// [`Self::take_published`], what it still has to receive.
    pub fn has_notifications(&self) -> bool {
        self.readiness.unconsumed()
    }

    /// [`BrokerHandshake`](litebox_common_vm_abi::CallId::BrokerHandshake):
    /// one attempt, successful or not; success activates the control ring.
    /// For an adopted process clone, it returns the response of the handshake
    /// that [`Self::adopt`] made, if `request` is the one runners make.
    ///
    /// Made in a thread's entry, off any task (as an adoption is, in a
    /// scheduler's step), so it never suspends, and takes spin locks only, with
    /// this broker's providers: it registers the readiness of what a parent
    /// passed the process, whose sources are standard input's, timers', pipes',
    /// events', readiness queues', sockets', and pseudo-terminals' (a share's
    /// or the root's files have none), all behind spin locks; activating the
    /// process notifies the core's lifecycle sink, which only wakes tasks (see
    /// `TaskWake`); and a failed start's pending association leaves releasing
    /// what the process holds to the parent's task (see
    /// [`PendingRunnerAssociation`]). A source whose registration could wait
    /// would need the handshake on a task.
    ///
    /// # Errors
    ///
    /// The status for the runner.
    pub fn handshake(&self, request: &WireFrame) -> Result<WireFrame, Status> {
        let request = request
            .as_slice()
            .and_then(|request| wire::decode_handshake_request(request).ok())
            .ok_or(Status::InvalidArgument);
        if let Some(response) = self.adoption_response.take() {
            return match request {
                Ok(request) if request == RUNNER_HANDSHAKE => Ok(response),
                _ => Err(Status::InvalidArgument),
            };
        }
        self.connect(request)
    }

    /// Whether the association holds the response of the handshake that
    /// [`Self::adopt`] made, which the process clone's [`Self::handshake`]
    /// takes.
    pub fn holds_adoption_response(&self) -> bool {
        self.adoption_response.get().is_some()
    }

    /// Makes the association's one handshake, with `request` (or fails with
    /// its error), as [`Self::handshake`] does.
    fn connect(
        &self,
        request: Result<BrokerHandshakeRequest, Status>,
    ) -> Result<WireFrame, Status> {
        let mut state = self.state.borrow_mut();
        let (ring, shared_memory, mut launch) = match core::mem::replace(&mut *state, State::Ended)
        {
            State::New(ring, shared_memory, launch) => (ring, shared_memory, launch),
            // Left as it was (e.g., active, on a repeated handshake).
            other => {
                *state = other;
                return Err(Status::Denied);
            }
        };
        let (process, startup) = match &mut launch {
            Some(launch) => (Some(launch.process.clone()), launch.startup.take()),
            None => (None, None),
        };
        // `launch` lives until the end, so a failed handshake fails the start
        // (see `PendingRunnerAssociation`'s `Drop`).
        let request = request?;
        let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)
            .map_err(|_| Status::Unsupported)?;
        let mut setup = KernelHostSetup {
            request: Some(request),
            response: None,
        };
        let readiness: Arc<dyn ReadinessSink> = self.readiness.clone();
        let result = litebox_broker_host::setup_connection(
            &self.broker.core,
            process,
            startup,
            &mut setup,
            Arc::new(shared_buffers),
            readiness,
            |process| {
                let _ = self.process.set(process.clone());
                false
            },
            |_| Ok(()),
        );
        if let Ok(Ok(host)) = result {
            if host.activate_process().is_err() {
                // Releases its broker process ID.
                host.finish();
                return Err(Status::Denied);
            }
            let words = ring.memory().clone();
            let HostControlRingEndpoints {
                lanes,
                lane_demand: _,
                notification_producer,
            } = ring.into_host();
            let [lane] = <[_; 1]>::try_from(lanes)
                .unwrap_or_else(|_| unreachable!("a single-lane layout has one lane"));
            self.readiness.activate(notification_producer);
            *state = State::Active(Box::new(Active {
                association: host,
                requests: lane.request_consumer,
                responses: lane.response_producer,
                words,
                overflow: None,
            }));
        }
        let response = setup.response.ok_or(Status::Denied)?;
        frame(&wire::encode_handshake_response(response))
    }

    /// [`Futex`](litebox_common_vm_abi::CallId::Futex) on the `u32` at
    /// `offset` into the control ring: leaves published requests to
    /// [`Self::run`], and a wait that does not end at once to the caller.
    /// An invalid request has no effect. Before the handshake, any request is
    /// [`Status::Denied`]. A corrupted notification ring fails the
    /// association, as a corrupted request ring does.
    ///
    /// # Errors
    ///
    /// See [`EnterError`].
    pub fn futex(&self, offset: usize, op: RingFutex) -> Result<Entered, EnterError> {
        if !matches!(*self.state.borrow(), State::Active(_)) {
            return Err(EnterError::Status(Status::Denied));
        }
        if !CONTROL_RING_LAYOUT.permits_u32(offset) {
            return Err(EnterError::Status(Status::InvalidArgument));
        }
        let wait = match op {
            RingFutex::Wake => {
                if offset != CONTROL_RING_LAYOUT.requests(0).producer_wake_offset() {
                    // The broker waits on no other word.
                    return Ok(Entered::Done);
                }
                None
            }
            RingFutex::Wait { expected, deadline } => Some(Wait {
                offset,
                expected,
                deadline,
                notifications: offset == CONTROL_RING_LAYOUT.notifications().producer_wake_offset(),
            }),
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

    /// Whether a call since the last batch (see [`Self::run`]) may have
    /// published requests, or that left some.
    pub fn has_submitted(&self) -> bool {
        self.submitted.get()
    }

    /// Whether the process's task has work (see [`Self::run`]): requests to
    /// serve (see [`Self::has_submitted`]), or, once the process ended, the
    /// association to end. Looks at no state a suspended batch may borrow.
    pub fn has_work(&self) -> bool {
        !self.torn_down.get() && (self.exit_status.get().is_some() || self.submitted.get())
    }

    /// A batch, on the process's task ([`litebox_platform_vm_kernel::worker`]):
    /// serves at most `max` of the published requests, unless the response
    /// ring fills up, or the process ends meanwhile; once it served `max`,
    /// more may be left (see [`Self::has_submitted`]). Then, if the process
    /// ended (see [`Self::exited`]), ends the association, as the userland
    /// broker does when its runner goes away, and completes the broker
    /// process's exit, or, if it never started, fails its start (see
    /// [`PendingRunnerAssociation`]): releasing what it holds, which may wait
    /// for a provider.
    ///
    /// A request may suspend the task, as may the end: one waiting for a
    /// device or a lock, or one starting a child process, which waits until
    /// the child's start completes (see `Start`). While the task is
    /// suspended, the caller must keep creating what
    /// [`Self::take_pending_associations`] returns, running the processes, and
    /// resuming the task once due, or the batch never completes.
    ///
    /// # Errors
    ///
    /// [`EnterError::Failed`], which ends the association once the process
    /// ended, in a later batch.
    pub fn run(&self, max: usize) -> Result<(), EnterError> {
        if self.exit_status.get().is_none() {
            self.serve(max)?;
        }
        if self.exit_status.get().is_some() {
            self.tear_down();
        }
        Ok(())
    }

    /// See [`Self::run`].
    fn serve(&self, max: usize) -> Result<(), EnterError> {
        self.submitted.set(false);
        self.with_active(|active| {
            let more = active
                .serve(&self.launcher, max, || self.exit_status.get().is_some())
                .map_err(|Failed| EnterError::Failed)?;
            self.submitted.set(more);
            self.flush_readiness()
        })
    }

    /// Ends the association, whose process ended, on the process's task (see
    /// [`Self::run`]).
    fn tear_down(&self) {
        let status = self.exit_status.get().expect("the process ended");
        // Not borrowed across what may suspend the task.
        let state = core::mem::replace(&mut *self.state.borrow_mut(), State::Ended);
        match state {
            State::Active(active) | State::Ending(active) => {
                end(active.association, &self.readiness);
            }
            // A pending association that never started fails (see
            // `PendingRunnerAssociation`'s `Drop`).
            State::New(_, _, launch) => drop(launch),
            State::Ended => {}
        }
        if let Some(process) = self.process.get() {
            // Only the first completion counts; a process that never started
            // has none.
            let _ = process.complete_exit(status);
        }
        self.torn_down.set(true);
    }

    /// The child processes the process started since the last call, in order,
    /// for the caller to create a runner process for each (see
    /// [`Broker::associate`]), or adopt the process clone it names as its
    /// runner ([`PendingRunnerAssociation::clone_to_adopt`]), or fail it
    /// ([`PendingRunnerAssociation::fail`]). The request that started one
    /// keeps the process's task suspended until the child's start completes
    /// (see [`Self::run`]); dropping a pending association fails it too.
    pub fn take_pending_associations(&self) -> Vec<PendingRunnerAssociation> {
        core::mem::take(&mut *self.launcher.pending.lock())
    }

    /// The broker, e.g., to associate the process's children.
    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    /// Whether the process is a launched one (see [`Broker::associate`]).
    pub fn is_launched(&self) -> bool {
        self.launched
    }

    /// Adopts the process clone this association is for (see
    /// [`Broker::associate_clone`]) as the runner of `launch`'s process
    /// (`StartChildWithExistingRunner`): makes the clone's handshake as its
    /// runner would, which completes the start before the clone runs; the
    /// clone's own [`Self::handshake`] then returns the response.
    ///
    /// # Errors
    ///
    /// [`BrokerError::PolicyDenied`] unless the association is a clone's that
    /// no start adopted and that has not ended, or [`BrokerError::PeerClosed`]
    /// if the handshake fails; either fails `launch` (see
    /// [`PendingRunnerAssociation`]).
    pub fn adopt(&self, launch: PendingRunnerAssociation) -> Result<(), BrokerError> {
        let adoptable =
            self.launched && self.process.get().is_none() && self.exit_status.get().is_none();
        if adoptable
            && let Ok(mut state) = self.state.try_borrow_mut()
            && let State::New(_, _, pending @ None) = &mut *state
        {
            let _ = self.process.set(launch.process.clone());
            *pending = Some(launch);
        } else {
            launch.fail(BrokerError::PolicyDenied);
            return Err(BrokerError::PolicyDenied);
        }
        match self.connect(Ok(RUNNER_HANDSHAKE)) {
            Ok(response) if matches!(*self.state.borrow(), State::Active(_)) => {
                self.adoption_response.set(Some(response));
                Ok(())
            }
            // Dropping `launch` failed the start.
            _ => Err(BrokerError::PeerClosed),
        }
    }

    /// The process ended (e.g., it exited, or the kernel killed it) with
    /// `status`, unless it reported its own: its task then ends the
    /// association (see [`Self::has_work`] and [`Self::run`]), after the
    /// request it may be suspended in. Only the first call counts.
    pub fn exited(&self, status: ProcessExitStatus) {
        if self.exit_status.get().is_none() {
            self.exit_status.set(Some(status));
        }
    }

    /// Where `wait` stands, after firing due timers and publishing readiness.
    /// Without a deadline, a wait on a word other than the notification wake
    /// counter is [`Status::Stalled`] once [`Self::run`] has nothing left to
    /// serve.
    pub fn poll_wait(&self, wait: &Wait) -> WaitState {
        self.with_active(|active| {
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
            // Only notifications see timers; the network stack runs at its
            // deadlines, whatever the wait.
            let wake = if wait.notifications {
                timers::earliest(wait.deadline, self.broker.timers.next_deadline())
            } else {
                wait.deadline
            };
            let wake = timers::earliest(wake, self.broker.next_network_deadline());
            Ok(WaitState::Blocked { wake })
        })
        .unwrap_or_else(|error| WaitState::Ended(Err(error)))
    }

    /// For a blocked wait that the caller ends itself (e.g., stalled, or the
    /// process killed).
    pub fn abandon_wait(&self) {
        self.readiness.set_waiting(false);
    }

    /// Whether a thread of the process blocks in a wait that a notification
    /// would end (on the notification wake counter, or another the caller ends
    /// for them, e.g., a futex wait), for a notification to notify every CPU
    /// ([`cpu::notify_all`], see [`cpu::take_notified`]): poll the waits
    /// again. The caller's to keep current: before polling waits, since
    /// polling may publish; ordered before the polls' reads, so that a
    /// notification another CPU publishes meanwhile is either seen by the
    /// poll or notified.
    pub fn set_notification_waiter(&self, waiting: bool) {
        self.readiness.set_waiting(waiting);
    }

    /// Runs `f` on the active association; if `f` fails it, leaves it ending
    /// (see [`State::Ending`]): wherever this runs, the process's task ends it,
    /// once the process ended.
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
            *state = State::Ending(active);
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
    /// Serves at most `max` requests, unless the response ring fills up, or
    /// the process ended (`ended`): whether it served `max`, so that more may
    /// be left.
    fn serve(
        &mut self,
        launcher: &Arc<KernelProcessLauncher>,
        max: usize,
        ended: impl Fn() -> bool,
    ) -> Result<bool, Failed> {
        if let Some(response) = self.overflow.take()
            && !self.publish(response)?
        {
            return Ok(false);
        }
        let mut served = 0;
        let more = loop {
            if served == max {
                break true;
            }
            if ended() {
                break false;
            }
            let ControlRingReadStatus::Message(request) = self
                .requests
                .try_read(wire::decode_request)
                .map_err(failure("request ring"))?
            else {
                break false;
            };
            let mut response = None;
            self.association
                .execute_request_with(
                    request,
                    |parent, operation, shared_buffers| {
                        handle_process_operation(launcher, parent, operation, shared_buffers)
                    },
                    |r| {
                        response = Some(wire::encode_response(r.clone()));
                        Ok::<(), Infallible>(())
                    },
                )
                .map_err(failure("request execution"))?;
            served += 1;
            let response = response
                .ok_or("no response")
                .map_err(failure("request execution"))?;
            if !self.publish(response)? {
                break false;
            }
        };
        self.requests
            .publish_head()
            .map_err(failure("request ring"))?;
        log::trace!("broker served {served} requests");
        Ok(more)
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

/// Why [`Association::futex`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnterError {
    /// A status for the runner; the association is unaffected.
    Status(Status),
    /// Serving failed the association, which ends once the process ended
    /// (see [`Association::run`]).
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
    /// Only once its task ended it (see [`Association::has_work`]): ending it
    /// here, maybe off any task, could wait for what a suspended task holds.
    /// Dropped before, it is not ended: a bug, logged (and asserted in debug
    /// builds).
    fn drop(&mut self) {
        let torn_down = self.torn_down.get();
        if !torn_down {
            log::error!(
                "BUG: an association dropped before its task ended it (process {:?})",
                self.process.get().map(|process| process.id())
            );
        }
        debug_assert!(torn_down, "an association dropped before its task ended it");
    }
}

/// A child process to start (`StartChild`), for which the kernel creates a
/// runner process (see [`Association::take_pending_associations`]), or adopts a
/// process clone as its runner (`StartChildWithExistingRunner`), or a root
/// under the virtual init (see [`Broker::associate`]). Dropping it before the
/// process's handshake fails the start ([`Self::fail`]), wherever it drops
/// (e.g., as the handshake fails, in a thread's entry): a launched child's on
/// its parent's task, which waits until it dropped (see `Start`), as releasing
/// what the parent passed the child may wait for a provider; a root's at once,
/// as its broker process holds nothing yet but its socket account, whose
/// release takes spin locks only.
pub struct PendingRunnerAssociation {
    process: Arc<BrokerProcess>,
    /// Until the handshake takes it; a root has none.
    startup: Option<ProcessStartupData>,
    /// See [`Self::clone_to_adopt`].
    clone: Option<u64>,
    /// The start the parent's task waits for; a root's has none.
    start: Option<Arc<Start>>,
    /// What the start fails with, if it does (see [`Self::fail`]).
    error: BrokerError,
}

impl PendingRunnerAssociation {
    /// A root's, under the virtual init (see [`Broker::associate`]).
    fn root(process: Arc<BrokerProcess>) -> Self {
        Self {
            process,
            startup: None,
            clone: None,
            start: None,
            error: BrokerError::PeerClosed,
        }
    }

    /// For a start with an existing runner (`StartChildWithExistingRunner`),
    /// the process clone it names, which the kernel adopts as its runner
    /// ([`Association::adopt`]) only if the starting process made the clone.
    /// `None` for a runner process to create.
    pub fn clone_to_adopt(&self) -> Option<u64> {
        self.clone
    }

    /// Fails to start the process with `error`, e.g., if its runner process
    /// cannot be created, as dropping it does with [`BrokerError::PeerClosed`].
    pub fn fail(mut self, error: BrokerError) {
        self.error = error;
    }
}

impl Drop for PendingRunnerAssociation {
    /// Fails the start unless the process started (`fail_start` keeps an
    /// earlier failure's error): a launched child's by handing it to the
    /// parent's task, which this then wakes, on whichever CPU; a root's at
    /// once (see the type's docs).
    fn drop(&mut self) {
        let started = matches!(self.process.startup_result(), Some(Ok(())));
        match &self.start {
            Some(start) => {
                start.hand_off((!started).then_some(self.error));
                wake_tasks();
            }
            None if !started => {
                let _ = self.process.fail_start(self.error, false, true);
                self.process.retire(true);
            }
            None => {}
        }
    }
}

/// A launched child's start, which the parent's task waits for
/// ([`Self::wait`]), until the child's pending association dropped, wherever
/// it was (queued, being spawned or adopted, or in the child's association,
/// before its handshake), and the start completed: so the task, and the
/// launcher it runs, outlive the pending association, and fail the start if
/// that handed the failure over, which then waits for nothing else (e.g.,
/// another start).
struct Start(spin::Mutex<Handoff>);

/// Where a [`Start`] stands.
#[derive(Clone, Copy)]
enum Handoff {
    /// The pending association is out there.
    Pending,
    /// It dropped: the start is the process's own (see
    /// [`BrokerProcess::startup_result`]).
    Done,
    /// It dropped, the process not started: the parent's task is to fail the
    /// start with this.
    Failed(BrokerError),
}

impl Start {
    /// A start that failed with `error` before it had a pending association.
    fn failed(error: BrokerError) -> Self {
        Self(spin::Mutex::new(Handoff::Failed(error)))
    }

    /// As the pending association drops: the parent's task is to fail the
    /// start with `failure`, if any.
    fn hand_off(&self, failure: Option<BrokerError>) {
        *self.0.lock() = failure.map_or(Handoff::Done, Handoff::Failed);
    }

    /// On the parent's task: once the pending association dropped, fails the
    /// start if that handed the failure over, releasing what the process holds
    /// (which may wait for a provider); then whether the process started, once
    /// its start completed: a failure only once what the process held is
    /// released, maybe by another (e.g., its parent's owner death), whose
    /// notification then wakes the tasks (see `TaskWake`). `None` until then.
    fn poll(&self, process: &BrokerProcess) -> Option<Result<(), BrokerError>> {
        let failure = {
            let mut handoff = self.0.lock();
            match *handoff {
                Handoff::Pending => return None,
                Handoff::Done => None,
                Handoff::Failed(error) => {
                    *handoff = Handoff::Done;
                    Some(error)
                }
            }
        };
        if let Some(error) = failure {
            let _ = process.fail_start(error, false, true);
            process.retire(true);
        }
        process.startup_result()
    }

    /// On the parent's task: suspends it until [`Self::poll`] has the start's
    /// outcome, which every change it looks at wakes it for (see
    /// `PendingRunnerAssociation`'s `Drop`, and `TaskWake`).
    fn wait(&self, process: &BrokerProcess) -> Result<(), BrokerError> {
        loop {
            // Before looking (see `worker::Wait`).
            let seen = worker::wakes();
            if let Some(result) = self.poll(process) {
                return result;
            }
            assert!(
                worker::suspend(worker::Wait::event(seen, None)),
                "requests are served on a task"
            );
        }
    }
}

/// Makes the tasks due that may wait for what the caller published (see
/// [`worker::Wait`]), e.g., a start's outcome: no locks.
fn wake_tasks() {
    // Tasks run in the VM kernel only: a host build (e.g., any crate's tests)
    // has no per-CPU data.
    if cfg!(target_os = "none") {
        worker::wake_blocked(cpu::current());
    }
}

/// The broker core's lifecycle sink, which it notifies once a broker
/// process's state changed (e.g., its start completed, see [`Start::poll`]):
/// wakes the tasks. Notified holding no lock but, maybe, the process tree's
/// spin lock (e.g., by a process's final drop), so it takes none.
pub(crate) struct TaskWake;

impl ProcessLifecycleSink for TaskWake {
    fn changed(&self) {
        wake_tasks();
    }
}

/// An association's [`ProcessLauncher`]: queues each child process for the
/// kernel, and suspends the process's task until the child's start completes
/// (see [`Start`]).
#[derive(Default)]
struct KernelProcessLauncher {
    pending: spin::Mutex<Vec<PendingRunnerAssociation>>,
}

impl KernelProcessLauncher {
    /// Queues a pending association for `process`, for the kernel to create
    /// its runner process, or adopt the process clone `clone` names as its
    /// runner: its start, for the task to wait for.
    fn queue(
        &self,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        clone: Option<u64>,
    ) -> Arc<Start> {
        let start = Arc::new(Start(spin::Mutex::new(Handoff::Pending)));
        self.pending.lock().push(PendingRunnerAssociation {
            process,
            startup: Some(startup),
            clone,
            start: Some(start.clone()),
            error: BrokerError::PeerClosed,
        });
        start
    }
}

impl ProcessLauncher for KernelProcessLauncher {
    fn launch(
        self: Arc<Self>,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        image: Option<ChildImage>,
    ) -> Result<(), BrokerError> {
        if image.is_some() {
            // Only from `create_image`, which creates none.
            return Start::failed(BrokerError::UnsupportedOperation).wait(&process);
        }
        self.queue(process.clone(), startup, None).wait(&process)
    }

    /// The runner must be a process clone that the parent made, which
    /// `runner_descriptor` names (see
    /// [`PendingRunnerAssociation::clone_to_adopt`]).
    fn launch_existing(
        self: Arc<Self>,
        _parent_process_id: ProcessId,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        runner_descriptor: Vec<u8>,
    ) -> Result<(), BrokerError> {
        let clone = litebox_common_vm_abi::decode_clone_descriptor(&runner_descriptor);
        if clone.is_none() {
            log::warn!("rejected a runner descriptor that names no process clone");
            return Start::failed(BrokerError::PolicyDenied).wait(&process);
        }
        self.queue(process.clone(), startup, clone).wait(&process)
    }

    fn create_image(&self, _capacity: u64) -> Result<Box<dyn ProcessImage>, BrokerError> {
        Err(BrokerError::UnsupportedOperation)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{CONTROL_RING_LAYOUT, KernelProcessLauncher, PendingRunnerAssociation};
    use alloc::boxed::Box;
    use alloc::sync::{Arc, Weak};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::time::Duration;
    use litebox_broker_core::readiness::{ReadinessSink, SharedReadinessWatchers};
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::timer::{Alarm, TimerProvider};
    use litebox_broker_core::{
        BrokerCore, BrokerCoreLimits, BrokerError, BrokerProcess, CallerCredential, ObjectRights,
        PolicyEngine, ProcessLifecycleSink,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::fs::FileOpenFlags;
    use litebox_broker_protocol::process::ProcessStartupData;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use std::sync::{Mutex, OnceLock, mpsc};

    /// `ABI_VERSION` stands in for the userland broker's ring-layout token;
    /// change both together.
    #[test]
    fn ring_layout_change_needs_an_abi_version_change() {
        assert_eq!(
            (
                CONTROL_RING_LAYOUT.ready_token(),
                litebox_common_vm_abi::ABI_VERSION
            ),
            (&b"litebox-control-ring-ready-v1"[..], 1)
        );
    }

    /// Runs as each alarm drops, once set, as a provider's destructor would,
    /// which may block.
    type DropHook = Arc<OnceLock<Box<dyn Fn() + Send + Sync>>>;

    /// Timers whose alarms, which drop with their timers' last references,
    /// run a hook.
    struct HookedTimers(DropHook);

    impl TimerProvider for HookedTimers {
        fn now(&self) -> Duration {
            Duration::ZERO
        }

        fn create_alarm(
            &self,
            _watchers: SharedReadinessWatchers,
        ) -> litebox_broker_core::Result<Box<dyn Alarm>> {
            Ok(Box::new(HookedAlarm(self.0.clone())))
        }
    }

    struct HookedAlarm(DropHook);

    impl Alarm for HookedAlarm {
        fn set(&self, _deadline: Option<Duration>) {}
    }

    impl Drop for HookedAlarm {
        fn drop(&mut self) {
            if let Some(hook) = self.0.get() {
                hook();
            }
        }
    }

    struct NoReadiness;

    impl ReadinessSink for NoReadiness {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(&self, _: ObjectHandle, _: ReadinessFlags) -> litebox_broker_core::Result<()> {
            Ok(())
        }

        fn republish(&self, _: ObjectHandle, _: ReadinessFlags) -> litebox_broker_core::Result<()> {
            Ok(())
        }

        fn retire(&self, _: ObjectHandle) {}
    }

    /// Records the start of the process it watches, if any, at each
    /// lifecycle notification: what a task woken for it would see.
    #[derive(Default)]
    struct Recorder {
        watched: Mutex<Weak<BrokerProcess>>,
        seen: Mutex<Vec<Option<Result<(), BrokerError>>>>,
    }

    impl ProcessLifecycleSink for Recorder {
        fn changed(&self) {
            let watched = self.watched.lock().unwrap().upgrade();
            if let Some(process) = watched {
                self.seen.lock().unwrap().push(process.startup_result());
            }
        }
    }

    /// A broker with room for `threads` threads, whose timers' alarms run the
    /// returned hook as they drop, and whose lifecycle notifications the
    /// returned recorder records.
    fn broker(threads: usize) -> (BrokerCore, DropHook, Arc<Recorder>) {
        let hook = DropHook::default();
        let recorder = Arc::new(Recorder::default());
        let mut limits = BrokerCoreLimits::DEFAULT;
        limits.max_threads = threads;
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_limits(limits)
        .with_timer_provider(Arc::new(HookedTimers(hook.clone())))
        .build()
        .unwrap()
        .with_process_lifecycle_sink(recorder.clone());
        (broker, hook, recorder)
    }

    /// A running root process.
    fn root(broker: &BrokerCore) -> Arc<BrokerProcess> {
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        root
    }

    /// A child of `parent`, taken for its start, which holds the only
    /// references to two timers it inherited, so that their alarms drop as
    /// it releases what it holds.
    fn child(parent: &BrokerProcess) -> Arc<BrokerProcess> {
        let sink: Arc<dyn ReadinessSink> = Arc::new(NoReadiness);
        let timers = [(); 2].map(|()| {
            litebox_broker_core::timer::create(parent, &sink, FileOpenFlags::NONE).unwrap()
        });
        let id = parent.allocate_child_process().unwrap().process_id;
        parent
            .duplicate_object_references_to_child(id, &timers, &sink)
            .unwrap();
        for timer in timers {
            parent.close_object_reference(timer).unwrap();
        }
        parent.take_child_process(id).unwrap()
    }

    fn startup() -> ProcessStartupData {
        ProcessStartupData {
            payload: Vec::new(),
        }
    }

    /// Makes the alarms count their drops.
    fn count_drops(hook: &DropHook) -> Arc<AtomicUsize> {
        let drops = Arc::new(AtomicUsize::new(0));
        let counted = drops.clone();
        let count = move || {
            counted.fetch_add(1, Ordering::Relaxed);
        };
        assert!(hook.set(Box::new(count)).is_ok());
        drops
    }

    /// Makes the first alarm to drop report to the returned receiver, then
    /// block until the returned sender sends.
    fn block_first_drop(hook: &DropHook) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entered_receiver) = mpsc::channel();
        let (release_sender, release) = mpsc::channel::<()>();
        let first = Mutex::new(Some((entered, release)));
        let block = move || {
            let first = first.lock().unwrap().take();
            if let Some((entered, release)) = first {
                entered.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
        };
        assert!(hook.set(Box::new(block)).is_ok());
        (entered_receiver, release_sender)
    }

    #[test]
    fn a_pending_association_that_drops_leaves_failing_the_start_to_its_task() {
        // The parent, its child, and one more once the child is retired.
        let (broker, hook, _) = broker(2);
        let drops = count_drops(&hook);
        let parent = root(&broker);
        let launcher = KernelProcessLauncher::default();
        let child = child(&parent);
        let start = launcher.queue(child.clone(), startup(), None);

        // Off the parent's task, e.g., as the kernel fails to create the
        // child's runner process: nothing is released there.
        let launch = launcher.pending.lock().pop().unwrap();
        launch.fail(BrokerError::OutOfMemory);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(child.startup_result(), None);

        // The parent's task fails it, though no other start follows.
        assert_eq!(start.poll(&child), Some(Err(BrokerError::OutOfMemory)));
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(start.poll(&child), Some(Err(BrokerError::OutOfMemory)));
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        // Retired, it released its thread's ID as it dropped.
        drop((child, start));
        broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
    }

    #[test]
    fn a_start_waits_for_its_pending_association_whatever_failed_it_before() {
        // The parent, its two children, and two more once they are retired.
        let (broker, hook, _) = broker(3);
        let drops = count_drops(&hook);
        let parent = root(&broker);
        let launcher = KernelProcessLauncher::default();
        let queued = child(&parent);
        let queued_start = launcher.queue(queued.clone(), startup(), None);
        let transferred = child(&parent);
        let transferred_start = launcher.queue(transferred.clone(), startup(), None);
        // As the kernel takes it, e.g., into the association of the runner
        // process it creates for the child.
        let transferred_launch = launcher.pending.lock().pop().unwrap();

        // Owner death fails both starts, releasing what the children
        // inherited, but their pending associations are still out there.
        parent.handle_owner_death();
        assert_eq!(drops.load(Ordering::Relaxed), 4);
        for (start, child) in [(&queued_start, &queued), (&transferred_start, &transferred)] {
            assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
            assert_eq!(start.poll(child), None);
        }

        // Each start completes as its pending association drops, whether the
        // launcher still queues it or is gone.
        drop(launcher);
        assert_eq!(
            queued_start.poll(&queued),
            Some(Err(BrokerError::PeerClosed))
        );
        assert_eq!(transferred_start.poll(&transferred), None);
        drop(transferred_launch);
        assert_eq!(
            transferred_start.poll(&transferred),
            Some(Err(BrokerError::PeerClosed))
        );
        assert_eq!(drops.load(Ordering::Relaxed), 4);
        // Retired, they released their threads' IDs as they dropped.
        drop((queued, queued_start, transferred, transferred_start));
        let _more: Vec<_> = (0..2)
            .map(|_| {
                broker
                    .create_process(CallerCredential::Unauthenticated, None)
                    .unwrap()
            })
            .collect();
    }

    #[test]
    fn a_start_another_fails_completes_once_what_the_child_held_is_released() {
        let (broker, hook, recorder) = broker(2);
        let parent = root(&broker);
        let launcher = KernelProcessLauncher::default();
        let child = child(&parent);
        *recorder.watched.lock().unwrap() = Arc::downgrade(&child);
        let start = launcher.queue(child.clone(), startup(), None);
        let (entered, release) = block_first_drop(&hook);
        let dying = {
            let parent = parent.clone();
            std::thread::spawn(move || parent.handle_owner_death())
        };
        entered.recv_timeout(Duration::from_secs(5)).unwrap();

        // Owner death fails the start, blocked in a provider as it releases
        // what the child inherited: the pending association drops meanwhile,
        // and the parent's task, failing the start too, sees it pending.
        drop(launcher.pending.lock().pop());
        assert_eq!(start.poll(&child), None);
        assert!(recorder.seen.lock().unwrap().is_empty());

        // Then the failure is published, and notified, which wakes the task.
        release.send(()).unwrap();
        dying.join().unwrap();
        assert_eq!(
            *recorder.seen.lock().unwrap(),
            [Some(Err(BrokerError::PeerClosed))]
        );
        assert_eq!(start.poll(&child), Some(Err(BrokerError::PeerClosed)));
    }

    #[test]
    fn a_started_child_is_left_running() {
        let (broker, _, _) = broker(2);
        let parent = root(&broker);
        let launcher = KernelProcessLauncher::default();
        let child = child(&parent);
        let start = launcher.queue(child.clone(), startup(), None);
        let launch = launcher.pending.lock().pop().unwrap();
        // As the child's handshake activates it.
        child.complete_start().unwrap();
        assert_eq!(start.poll(&child), None);
        drop(launch);
        assert_eq!(start.poll(&child), Some(Ok(())));
        assert!(child.is_running());
    }

    #[test]
    fn a_roots_start_fails_as_its_pending_association_drops() {
        // The root, and one more once it is retired.
        let (broker, _, _) = broker(1);
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        drop(PendingRunnerAssociation::root(root.clone()));
        assert_eq!(root.startup_result(), Some(Err(BrokerError::PeerClosed)));
        drop(root);
        broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
    }
}
