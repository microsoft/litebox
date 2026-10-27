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
//! runner's [`stdio::Console`], those of an optional root, writable as the
//! userland broker's ([`Config::root`]), and read-only host directories
//! ([`Config::shares`]).
//! Timers are on the kernel clock. IPv4 TCP and UDP
//! sockets are `litebox_broker_smoltcp`'s, which mediates their traffic:
//! between runner processes directly, and, with the runner's [`Network`]
//! device ([`Config::network`]), to the outside on smoltcp, as
//! [`Config::socket_policy`] allows.
//! With the runner's socket device ([`Config::vsock`]), vsock sockets are
//! [`litebox_broker_core::vsock_socket::transport`]'s; without it, they
//! cannot be created. Readiness (e.g., of standard input, a timer's expiry,
//! or sockets) goes to the association's notification ring.
//!
//! As in the userland broker, requests are served apart from the runner's
//! calls, on preemptible kernel threads, which may block (e.g., for a lock, a
//! share's server, or a child process's start): an association thread drains
//! an association's inbox (see `inbox`), and the source thread looks at what
//! changes outside requests. The kernel's scheduler runs them ([`ThreadWork`]).
//!
//! The kernel never takes the broker's locks, nor runs or drops broker state.
//!
//! A process can start a child process (`StartChild`). Its association queues a
//! [`PendingRunnerAssociation`] ([`Association::take_pending_associations`]),
//! for which the kernel creates a runner process and associates it
//! ([`BrokerHandle::associate`]); the child's handshake returns its startup
//! data. It can also start one with an existing runner
//! (`StartChildWithExistingRunner`): a process clone it made (see
//! `litebox_common_vm_abi`, `CloneKind::Process`), which the kernel associated
//! as it made it ([`BrokerHandle::associate_clone`]). The child's queued
//! association names the clone ([`PendingRunnerAssociation::clone_to_adopt`]),
//! which the kernel adopts as the child's runner ([`Association::adopt`]).
//! Memory images (`WriteChildMemory`) are not supported.
//!
//! When a process ends ([`Association::exited`]), its association ends and
//! its broker process exits, releasing what it holds (e.g., pipe ends).
//!
//! A process the kernel starts on its own (a root) has no parent, as in the
//! userland broker. A root's handshake creates its broker process, and a root
//! whose broker process cannot be created (e.g., too many processes) gets an
//! error response.
//!
//! # `policy`
//!
//! The socket policy ([`policy::parse`]), a rule a line:
//!
//! ```text
//! egress tcp 10.0.2.100/32:7
//! egress udp 10.0.2.3/32:53
//! ```
//!
//! `egress tcp|udp CIDR:PORT[-PORT]`, as the userland broker's
//! `--allow-tcp-destination` and `--allow-udp-destination`, allows a
//! destination beyond the guest network; at most
//! [`litebox_broker_core::MAX_DESTINATION_RULES`] a protocol. Empty lines are
//! ignored; others are rejected.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod inbox;
mod memory;
pub mod policy;
mod providers;
mod readiness;
mod serving;
pub mod share;
pub mod stdio;
mod timers;

/// A binding of an association's inbox (see [`Association::has_ended`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding(u64);

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, OnceCell};
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use inbox::{Bindings, Inbox, Op, Posted};
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{
    BrokerCore, BrokerError, BrokerProcess, CallerCredential, ChildImage, ProcessImage,
    SocketPolicy, fs::FileService, job::Job, pid_namespace::PidNamespace,
};
use litebox_broker_host::{
    BrokerHostAssociation, ProcessLauncher, default_host_names, handle_process_operation,
};
use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
use litebox_broker_protocol::process::ProcessStartupData;
use litebox_broker_protocol::process::{CpuTime, PidNamespaceOptions, ProcessExitStatus};
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
use litebox_platform_vm_kernel::kthread::{self, Kthread, Stack, WaitQueue};
use litebox_platform_vm_kernel::preempt::KernelMutex;
use litebox_platform_vm_kernel::{Instant, PinnedUserPages, VmKernel, cpu};

use litebox_broker_core::vsock_socket::transport::{VsockTransport, VsockTransportProvider};
use litebox_broker_smoltcp::{Network, SmoltcpSocketProvider};

use memory::{PinnedControlRing, UserSharedMemory};
use readiness::KernelReadiness;
use stdio::ConsoleStdio;
use timers::{KernelTimers, PublishedDeadline};

/// Size of a process's broker shared memory.
pub const SHARED_MEMORY_SIZE: usize = SHARED_BUFFER_POOL_SIZE;

/// Layout of a process's broker control ring: the kernel serves one call at a
/// time, so a single lane.
pub const CONTROL_RING_LAYOUT: ControlRingLayout = ControlRingLayout::SINGLE_LANE;

/// Size of a process's broker control ring.
pub const CONTROL_RING_SIZE: usize = CONTROL_RING_LAYOUT.memory_size();

/// What the kernel waits for: the runner's event sources (e.g., device
/// interrupts and a timer).
pub trait Events: Sync {
    /// Halts the calling CPU until an event may have happened, another CPU
    /// wakes it (see [`cpu::halt`]), or `deadline` passes. Without a
    /// deadline, false if no device could ever end the halt (and it does not
    /// halt).
    fn wait(&self, deadline: Option<Instant>) -> bool;

    /// Whether a device interrupted since the last call, on any CPU; if so,
    /// wakes the kernel threads that wait for a device. Lock-free if not.
    fn poll(&self) -> bool;
}

/// The runner's sources for a [`Broker`].
pub struct Config {
    /// For its clock, which timers are on.
    pub platform: &'static VmKernel,
    /// Behind `/dev/stdin`, `/dev/stdout`, and `/dev/stderr`.
    pub console: &'static dyn stdio::Console,
    /// A tar, the root's read-only lower layer, e.g., a Linux program's files.
    pub root: Option<&'static [u8]>,
    /// Host directories, each mounted read-only at its path.
    pub shares: Vec<share::Share>,
    /// The network sockets reach beyond the guest, if any.
    pub network: Option<&'static dyn Network>,
    /// What sockets may reach: the guest network, and the destinations it
    /// allows beyond, through [`Self::network`] (see [`policy`]).
    pub socket_policy: SocketPolicy,
    /// The socket device vsock sockets connect with the host on, if any.
    pub vsock: Option<Arc<dyn VsockTransport>>,
    /// Whether processes may start child processes (process duplication), as
    /// the userland broker's `allow_process_duplication`; the kernel then
    /// creates their runner processes (see [`PendingRunnerAssociation`]).
    pub allow_process_duplication: bool,
    /// The options of the roots' PID namespace.
    pub pid_namespace: PidNamespaceOptions,
    /// The wall clock, which runners also get.
    pub wall_clock: litebox_common_vm_abi::WallClock,
    /// The devices, whose interrupts the source thread looks at.
    pub events: &'static dyn Events,
}

/// The kernel's broker, whose state only broker threads use.
pub struct Broker(Arc<BrokerState>);

struct BrokerState {
    core: Arc<BrokerCore>,
    /// The PID namespace of the processes the kernel starts.
    pid_namespace: Arc<PidNamespace>,
    /// Their file service.
    fs: Arc<dyn FileService>,
    /// Their job.
    job: Arc<Job>,
    platform: &'static VmKernel,
    stdio: Arc<ConsoleStdio>,
    timers: Arc<KernelTimers>,
    sockets: Arc<SmoltcpSocketProvider>,
    /// With [`Config::vsock`].
    vsock: Option<Arc<VsockTransportProvider<Instant>>>,
    runtime: Arc<Runtime>,
}

/// What the kernel and broker threads share: lock-free, or kernel-grade.
pub(crate) struct Runtime {
    /// The inboxes bound with no thread yet.
    queued: KernelMutex<Vec<Arc<Inbox<Runtime, Side>>>>,
    bound: AtomicUsize,
    sides: AtomicUsize,
    /// When the source thread next has something to do; lowering it wakes it.
    deadline: Arc<PublishedDeadline>,
    events: &'static dyn Events,
    platform: &'static VmKernel,
    stopping: AtomicBool,
}

impl Runtime {
    fn queue(&self, inbox: Arc<Inbox<Runtime, Side>>) {
        self.queued.lock().push(inbox);
        cpu::wake_idle_or_resched();
    }
}

impl Bindings for Runtime {
    fn bind(&self) {
        self.bound.fetch_add(1, Ordering::SeqCst);
    }

    fn unbind(&self) {
        self.bound.fetch_sub(1, Ordering::SeqCst);
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

/// The kernel's side of the [`Broker`]: it holds no broker state, so the
/// kernel may hold and drop it anywhere. Clones share it.
#[derive(Clone)]
pub struct BrokerHandle {
    runtime: Arc<Runtime>,
    /// Gone once the broker is shut down.
    state: Weak<BrokerState>,
}

impl Broker {
    /// At most once: only one broker core may exist. Before any broker
    /// thread exists, as it may block (e.g., mounting a share over FUSE).
    ///
    /// # Panics
    ///
    /// Without a hardware CSPRNG, on a second call, or if a share cannot be
    /// mounted.
    pub fn new(config: Config) -> Self {
        let deadline = Arc::new(PublishedDeadline::new());
        let stdio = Arc::new(ConsoleStdio::new(config.console));
        let timers = Arc::new(KernelTimers::new(
            config.platform,
            config.wall_clock,
            deadline.clone(),
        ));
        let sockets = Arc::new(SmoltcpSocketProvider::new(
            providers::LIMITS.max_sockets,
            providers::LIMITS.max_sockets_per_process,
            timers.clone(),
            config.network,
            providers::seed(),
        ));
        let platform = config.platform;
        let vsock = config.vsock.map(|transport| {
            Arc::new(VsockTransportProvider::new(
                transport,
                Box::new(move || platform.now()),
                providers::seed(),
            ))
        });
        let (core, pid_namespace, fs) = providers::core(
            config.root,
            config.shares,
            stdio.clone(),
            timers.clone(),
            sockets.clone(),
            &config.socket_policy,
            vsock
                .clone()
                .map(|vsock| vsock as Arc<dyn litebox_broker_core::vsock_socket::VsockProvider>),
            config.allow_process_duplication,
            config.pid_namespace,
        );
        let job = Job::new(None);
        Self(Arc::new(BrokerState {
            core,
            pid_namespace,
            fs,
            job,
            platform: config.platform,
            stdio,
            timers,
            sockets,
            vsock,
            runtime: Arc::new(Runtime {
                queued: KernelMutex::new(Vec::new()),
                bound: AtomicUsize::new(0),
                sides: AtomicUsize::new(0),
                deadline,
                events: config.events,
                platform: config.platform,
                stopping: AtomicBool::new(false),
            }),
        }))
    }

    /// The kernel's side.
    pub fn handle(&self) -> BrokerHandle {
        BrokerHandle {
            runtime: self.0.runtime.clone(),
            state: Arc::downgrade(&self.0),
        }
    }

    /// The source thread's work, on `stack`, to start once.
    pub fn source(&self, stack: Stack) -> ThreadWork {
        ThreadWork {
            state: self.0.clone(),
            kind: Kind::Source(stack),
        }
    }

    /// Has the source thread finish, at its next look.
    pub fn stop_source(&self) {
        self.0.runtime.stopping.store(true, Ordering::SeqCst);
        self.0.runtime.deadline.wake_source();
    }

    /// How many associations' broker sides are alive: none, with no broker
    /// thread left, before the broker drops.
    pub fn sides(&self) -> usize {
        self.0.runtime.sides.load(Ordering::SeqCst)
    }

    /// Whether no thread's work holds the broker's state.
    pub fn is_unshared(&self) -> bool {
        Arc::strong_count(&self.0) == 1
    }
}

impl BrokerHandle {
    /// A process's association, before its handshake. The shared buffers are
    /// `shared_memory` (see [`SHARED_MEMORY_SIZE`]), which may be pinned
    /// lazily; the control ring is at the start of `control_ring_pages`. With
    /// `launch`, the process is a launched one, and its handshake attaches it
    /// to `launch`'s broker process. Otherwise, it is a root, whose handshake
    /// creates its broker process (see the [crate] docs).
    ///
    /// # Errors
    ///
    /// [`Status::NoMemory`] if no stack is left; `launch`, if any, then fails.
    ///
    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    pub fn associate(
        &self,
        shared_memory: PinnedUserPages,
        control_ring_pages: PinnedUserPages,
        launch: Option<PendingRunnerAssociation>,
    ) -> Result<Association, Status> {
        let Some(stack) = Stack::allocate() else {
            if let Some(launch) = launch {
                launch.fail(BrokerError::OutOfMemory);
            }
            return Err(Status::NoMemory);
        };
        let launched = launch.is_some();
        Ok(self.association(stack, shared_memory, control_ring_pages, launched, launch))
    }

    /// A process clone's association (see `litebox_common_vm_abi`,
    /// `CloneKind::Process`), before its handshake: as a launched process's
    /// (see [`Self::associate`]), but with no process until
    /// [`Association::adopt`] gives it one. `control_ring_pages` must be
    /// zeroed, as a new process's are.
    ///
    /// # Errors
    ///
    /// [`Status::NoMemory`] if no stack is left.
    ///
    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    pub fn associate_clone(
        &self,
        shared_memory: PinnedUserPages,
        control_ring_pages: PinnedUserPages,
    ) -> Result<Association, Status> {
        let stack = Stack::allocate().ok_or(Status::NoMemory)?;
        Ok(self.association(stack, shared_memory, control_ring_pages, true, None))
    }

    /// # Panics
    ///
    /// If `control_ring_pages` cannot hold [`CONTROL_RING_SIZE`].
    fn association(
        &self,
        stack: Stack,
        shared_memory: PinnedUserPages,
        control_ring_pages: PinnedUserPages,
        launched: bool,
        launch: Option<PendingRunnerAssociation>,
    ) -> Association {
        let memory =
            PinnedControlRing::new(control_ring_pages).expect("the pages hold the control ring");
        let words = memory.clone();
        let ring = ControlRing::new(memory, CONTROL_RING_LAYOUT)
            .expect("a pinned control ring has the exact size");
        let readiness = Arc::new(KernelReadiness::new());
        let children = Arc::new(KernelProcessLauncher::default());
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let process = launch
            .as_ref()
            .map_or_default(|launch| OnceCell::from(launch.process().clone()));
        let side = Side {
            state: State::New(ring, UserSharedMemory::new(shared_memory), launch),
            process,
            launched,
            launcher: children.clone(),
            readiness: readiness.clone(),
            shutdown_requested: shutdown_requested.clone(),
            adoption_response: None,
        };
        let inbox = Arc::new(Inbox::new(self.runtime.clone(), side, stack));
        self.runtime.sides.fetch_add(1, Ordering::SeqCst);
        Association {
            inbox,
            words,
            readiness,
            launcher: children,
            broker: self.clone(),
            launched,
            unthreaded: Cell::new(false),
            adoption_pending: Cell::new(false),
            shutdown_requested,
        }
    }

    /// The inboxes bound with no thread, to start a thread for each.
    ///
    /// # Panics
    ///
    /// Once the broker is shut down.
    pub fn take_queued(&self) -> Vec<ThreadWork> {
        let queued = core::mem::take(&mut *self.runtime.queued.lock());
        queued
            .into_iter()
            .map(|inbox| ThreadWork {
                state: self.state.upgrade().expect("the broker runs"),
                kind: Kind::Association(inbox),
            })
            .collect()
    }

    /// Looks at the devices (see [`Events::poll`]), waking the source thread
    /// if one interrupted: whether one did.
    pub fn poll_devices(&self) -> bool {
        let interrupted = self.runtime.events.poll();
        if interrupted {
            self.runtime.deadline.wake_source();
        }
        interrupted
    }

    /// Whether no inbox is bound or queued.
    pub fn is_idle(&self) -> bool {
        self.runtime.bound.load(Ordering::SeqCst) == 0
    }

    /// When the source thread next has something to do.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.runtime.deadline.get()
    }
}

/// Broker work for a kernel thread: an association's, or the source's.
pub struct ThreadWork {
    state: Arc<BrokerState>,
    kind: Kind,
}

enum Kind {
    Association(Arc<Inbox<Runtime, Side>>),
    Source(Stack),
}

/// What the kernel keeps of a started [`ThreadWork`] until its thread
/// finished ([`Self::finish`]).
pub struct Started(Whose);

enum Whose {
    /// The kernel may then be the inbox's last owner.
    Association(Arc<Inbox<Runtime, Side>>),
    Source,
}

impl ThreadWork {
    /// Starts its thread, on its inbox's stack or its own.
    pub fn start(self) -> (Kthread, Started) {
        let state = self.state;
        let (stack, inbox) = match self.kind {
            Kind::Association(inbox) => (inbox.take_stack(), Some(inbox)),
            Kind::Source(stack) => (stack, None),
        };
        let drained = inbox.clone();
        let work: Box<dyn FnOnce() + Send> = Box::new(move || {
            debug_assert!(kthread::in_kthread(), "kernel code reached broker code");
            match drained {
                Some(inbox) => state.drain(&inbox),
                None => state.run_source(),
            }
        });
        let whose = inbox.map_or(Whose::Source, Whose::Association);
        (Kthread::new(stack, work), Started(whose))
    }
}

impl Started {
    /// Its thread finished, with `stack`, which the kernel, off that stack,
    /// gives back to its inbox, or frees.
    pub fn finish(self, stack: Stack) {
        match self.0 {
            Whose::Association(inbox) => {
                if inbox.finished(stack) {
                    inbox.runtime.clone().queue(inbox);
                }
            }
            Whose::Source => drop(stack),
        }
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
    /// exists (see [`BrokerHandle::associate`]): a launched process's, or none
    /// for a root, or for a process clone until adopted.
    New(
        ControlRing<PinnedControlRing>,
        UserSharedMemory,
        Option<PendingRunnerAssociation>,
    ),
    Active(Box<Active>),
    /// The handshake did not activate one, or it failed.
    Ended,
}

/// The broker's ends of the request and response rings; the notification
/// ring's is in [`Side::readiness`].
struct Active {
    association: BrokerHostAssociation<UserSharedMemory>,
    requests: ControlRingConsumer<PinnedControlRing>,
    responses: ControlRingProducer<PinnedControlRing>,
    /// A response the full ring could not take; no request is consumed while
    /// it waits.
    overflow: Option<Vec<u8>>,
}

/// An association's broker side, which its inbox's bound thread holds.
pub(crate) struct Side {
    state: State,
    /// The broker process: a launched process's from the start, a root's once
    /// its handshake creates it (see [`BrokerHandle::associate`]), and a
    /// process clone's once [`Association::adopt`] gives it one.
    process: OnceCell<Arc<BrokerProcess>>,
    launched: bool,
    /// Queues the child processes the process starts, for the kernel.
    launcher: Arc<KernelProcessLauncher>,
    readiness: Arc<KernelReadiness>,
    /// [`Association::shutdown_requested`]'s.
    shutdown_requested: Arc<AtomicBool>,
    /// The response of a process clone's handshake, which [`Self::adopt`]
    /// made, until the clone's own handshake takes it.
    adoption_response: Option<WireFrame>,
}

/// A process's broker association's kernel side, which the process holds,
/// under its claim; its drop ends the association, unless its end did.
pub struct Association {
    inbox: Arc<Inbox<Runtime, Side>>,
    /// The control ring's words, for [`RingFutex::Wait`].
    words: PinnedControlRing,
    readiness: Arc<KernelReadiness>,
    /// Its queues only (kernel-grade).
    launcher: Arc<KernelProcessLauncher>,
    broker: BrokerHandle,
    launched: bool,
    /// A call bound the inbox, which has no thread yet (see [`Self::thread`]).
    unthreaded: Cell<bool>,
    adoption_pending: Cell<bool>,
    /// Set by the broker process's shutdown (see [`Side::install_shutdown`]).
    shutdown_requested: Arc<AtomicBool>,
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
    /// Until the word differs from `expected`, or `deadline` passes; has the
    /// broker serve the requests too.
    Wait {
        expected: u32,
        deadline: Option<Instant>,
    },
}

/// What [`Association::futex`] leaves to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entered {
    /// The call returns.
    Done,
    /// The call waits: poll it with [`Association::poll_wait`].
    Wait(Wait),
    /// The call bound the inbox, for a thread to serve its requests. A Wake
    /// (no `then`) waits until `binding` ended; a Wait, `then`, only for
    /// itself, polled from the call's handoff on (see the kernel's scheduler)
    /// as the binding's thread works on.
    InBroker {
        binding: Binding,
        then: Option<Wait>,
    },
    /// A wait that ended at once, with this; its inbox's thread is queued.
    Queued(Result<(), Status>),
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
    /// See [`BrokerHandle::next_deadline`].
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        self.broker.next_deadline()
    }

    /// For a process that is running instead: looks at the devices, and
    /// publishes the readiness pending for the process.
    pub fn poll_events(&self) {
        self.broker.poll_devices();
        self.readiness.flush();
    }

    /// Whether a notification was published since the last call (e.g., a
    /// timer fired, or standard input arrived): the process then has
    /// something to receive, even while it runs.
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
    /// posts the process's one handshake, with `request`, for its thread to
    /// make: the call waits for the response ([`Self::take_handshake_reply`]).
    /// An adopted process clone's gets its adoption's response.
    ///
    /// # Errors
    ///
    /// [`Status::Denied`] for a second handshake, or once the process ended.
    pub fn handshake(&self, request: &WireFrame) -> Result<(), Status> {
        if self.inbox.is_handshaken() {
            return Err(Status::Denied);
        }
        match self.inbox.post_handshake(*request) {
            Posted::Bound(_) => self.unthreaded.set(true),
            Posted::Pending => {}
            Posted::Refused => return Err(Status::Denied),
        }
        Ok(())
    }

    /// The handshake's response, once its thread made it.
    pub fn take_handshake_reply(&self) -> Option<Result<WireFrame, Status>> {
        self.inbox.take_reply()
    }

    /// Whether the handshake's response is made.
    pub fn has_handshake_reply(&self) -> bool {
        self.inbox.has_reply()
    }

    /// Whether a process clone's adoption was posted, and the clone has not made
    /// its handshake yet, which it may then make whatever its lockdown.
    pub fn adoption_pending(&self) -> bool {
        self.adoption_pending.get() && !self.inbox.is_handshaken()
    }

    /// [`Futex`](litebox_common_vm_abi::CallId::Futex) on the `u32` at
    /// `offset` into the control ring (see [`RingFutex`] and [`Entered`]).
    /// An invalid request has no effect. Before the handshake, any request is
    /// [`Status::Denied`]. A corrupted notification ring fails the
    /// association, as a corrupted request ring does. Once the process ended,
    /// any request is denied too.
    ///
    /// # Errors
    ///
    /// See [`EnterError`].
    pub fn futex(&self, offset: usize, op: RingFutex) -> Result<Entered, EnterError> {
        if !self.inbox.is_active() {
            return Err(EnterError::Status(Status::Denied));
        }
        if self.inbox.has_failed() {
            return Err(EnterError::Failed);
        }
        if !CONTROL_RING_LAYOUT.permits_u32(offset) {
            return Err(EnterError::Status(Status::InvalidArgument));
        }
        let then = match op {
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
        let binding = match self.inbox.post(Op::Submitted) {
            Posted::Bound(binding) => binding,
            Posted::Pending => {
                return match then {
                    None => Ok(Entered::Done),
                    Some(wait) => match self.poll_wait(&wait) {
                        WaitState::Ended(result) => result.map(|()| Entered::Done),
                        WaitState::Blocked { .. } => Ok(Entered::Wait(wait)),
                    },
                };
            }
            Posted::Refused => return Err(EnterError::Status(Status::Denied)),
        };
        let Some(wait) = then else {
            self.unthreaded.set(true);
            return Ok(Entered::InBroker {
                binding,
                then: None,
            });
        };
        match self.poll_wait(&wait) {
            WaitState::Blocked { .. } => {
                self.unthreaded.set(true);
                Ok(Entered::InBroker {
                    binding,
                    then: Some(wait),
                })
            }
            WaitState::Ended(result) => {
                self.queue();
                match result {
                    Ok(()) => Ok(Entered::Queued(Ok(()))),
                    Err(EnterError::Status(status)) => Ok(Entered::Queued(Err(status))),
                    Err(EnterError::Failed) => Err(EnterError::Failed),
                }
            }
        }
    }

    /// The thread to start for the inbox that a call of the process bound, if
    /// it has none yet.
    ///
    /// # Panics
    ///
    /// Once the broker is shut down.
    pub fn thread(&self) -> Option<ThreadWork> {
        self.unthreaded.take().then(|| ThreadWork {
            state: self.broker.state.upgrade().expect("the broker runs"),
            kind: Kind::Association(self.inbox.clone()),
        })
    }

    /// Debug builds: whether a call bound the inbox and no thread was started
    /// for it yet.
    #[cfg(debug_assertions)]
    pub fn is_unthreaded(&self) -> bool {
        self.unthreaded.get()
    }

    /// For a call that bound the inbox but returns instead of stopping for its
    /// handoff (e.g., its reply could not be written): queues the inbox for a
    /// thread.
    pub fn queue_unthreaded(&self) {
        if self.unthreaded.get() {
            self.queue();
        }
    }

    /// Whether `binding` (see [`Entered::InBroker`]) ended.
    pub fn has_ended(&self, binding: Binding) -> bool {
        self.inbox.has_ended(binding)
    }

    /// The child processes the process started since the last call, in order,
    /// for the caller to create a runner process for each (see
    /// [`BrokerHandle::associate`]), or adopt the process clone it names as its
    /// runner ([`PendingRunnerAssociation::clone_to_adopt`]), or fail it
    /// ([`PendingRunnerAssociation::fail`]).
    pub fn take_pending_associations(&self) -> Vec<PendingRunnerAssociation> {
        self.launcher.take_pending()
    }

    /// The broker's kernel side, e.g., to associate the process's children.
    pub fn broker(&self) -> &BrokerHandle {
        &self.broker
    }

    /// Whether the process is a launched one (see [`BrokerHandle::associate`]).
    pub fn is_launched(&self) -> bool {
        self.launched
    }

    /// Posts the adoption of the process clone this association is for as the
    /// runner of `launch`'s process: its thread makes the clone's handshake,
    /// whose failure fails the start and the association.
    pub fn adopt(&self, launch: PendingRunnerAssociation) {
        match self.inbox.post_adopt(launch) {
            Posted::Bound(_) => self.queue(),
            Posted::Pending => {}
            Posted::Refused => return,
        }
        self.adoption_pending.set(true);
    }

    /// The process ended (e.g., it exited, or the kernel killed it) with
    /// `status`: posts the end, for its thread. Only the first call counts.
    pub fn exited(&self, status: ProcessExitStatus) {
        if self.inbox.is_ending() {
            return;
        }
        if let Posted::Bound(_) = self.inbox.post_end(status) {
            self.queue();
        } else {
            // A binding that no thread was started for: its call's handoff
            // (see [`Self::thread`]) will not come once the process ended
            // (e.g., dying clears its threads' suspensions).
            self.queue_unthreaded();
        }
    }

    /// Whether serving, or the adoption, failed the association.
    pub fn has_failed(&self) -> bool {
        self.inbox.has_failed()
    }

    /// Whether the broker asked to shut the process down (e.g., its PID
    /// namespace ended), which the kernel does by killing it. Lock-free.
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Whether no broker work is in flight for the process. Lock-free.
    pub fn is_idle(&self) -> bool {
        self.inbox.is_idle()
    }

    /// Mirrors whether the process stopped, for the inbox's thread, which wakes
    /// the boot CPU once done with a stopped process's work.
    pub fn set_stopped(&self, stopped: bool) {
        self.inbox.set_stopped(stopped);
    }

    /// Where `wait` stands, after publishing readiness. Without a deadline, a
    /// wait on a word other than the notification wake counter is
    /// [`Status::Stalled`] once the inbox is idle.
    pub fn poll_wait(&self, wait: &Wait) -> WaitState {
        self.wait_state(wait)
            .unwrap_or_else(|error| WaitState::Ended(Err(error)))
    }

    fn wait_state(&self, wait: &Wait) -> Result<WaitState, EnterError> {
        if !self.inbox.is_active() {
            return Err(EnterError::Status(Status::Denied));
        }
        self.readiness.flush();
        if self.readiness.failed() || self.inbox.has_failed() {
            return Err(EnterError::Failed);
        }
        // Before the word: the thread writes its responses before the kernel
        // unbinds the inbox.
        let idle = self.inbox.is_idle();
        match self.words.load_u32_acquire(wait.offset) {
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
        let now = self.broker.runtime.platform.now();
        if wait.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(EnterError::Status(Status::TimedOut));
        }
        if wait.deadline.is_none() && !wait.notifications && idle {
            return Err(EnterError::Status(Status::Stalled));
        }
        Ok(WaitState::Blocked {
            wake: wait.deadline,
        })
    }

    /// For a blocked wait that the caller ends itself.
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

    fn queue(&self) {
        self.unthreaded.set(false);
        self.broker.runtime.queue(self.inbox.clone());
    }
}

impl Drop for Association {
    /// Ends the association if the process's end did not.
    fn drop(&mut self) {
        self.exited(ProcessExitStatus::Unknown);
    }
}

impl BrokerState {
    /// An association thread's work: takes `inbox`'s operations, with safe
    /// points between them, until none is left.
    fn drain(&self, inbox: &Arc<Inbox<Runtime, Side>>) {
        let mut side = inbox.take_side();
        let mut first = true;
        while let Some(op) = inbox.take() {
            // After the take, so that an operation posted as the last one ran
            // has one before it too; none after the last.
            if !core::mem::take(&mut first) {
                kthread::safe_point();
            }
            match op {
                Op::End => {
                    // The operations not started: a pending start fails.
                    let (exit, adopt) = inbox.take_end();
                    drop(adopt);
                    if let Some(side) = side.take() {
                        side.end(exit.unwrap_or(ProcessExitStatus::Unknown));
                        // Releasing the process's objects may have changed
                        // the deadlines (e.g., a closed socket's connection
                        // lingers).
                        self.publish_deadline(true);
                        self.runtime.sides.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Op::Adopt => {
                    let launch = inbox.take_adopt();
                    if let (Some(side), Some(launch)) = (&mut side, launch) {
                        if side.adopt(self, launch).is_err() {
                            inbox.fail();
                        }
                        side.activate_inbox(inbox);
                    }
                }
                Op::Handshake => {
                    let request = inbox.take_handshake();
                    let reply = match (&mut side, request) {
                        (Some(side), Some(request)) => {
                            let reply = side.handshake(self, &request);
                            side.activate_inbox(inbox);
                            reply
                        }
                        _ => Err(Status::Denied),
                    };
                    inbox.reply(reply);
                }
                Op::Submitted => {
                    if let Some(side) = &mut side
                        && side.serve().is_err()
                    {
                        inbox.fail();
                    }
                    // What changed outside requests reaches the process soon.
                    self.poll_sources(true);
                    if let Some(side) = &side {
                        side.readiness.flush();
                    }
                }
            }
        }
        inbox.put_side(side);
    }

    fn run_source(&self) {
        let runtime = &self.runtime;
        while !runtime.stopping.load(Ordering::SeqCst) {
            let prepared = runtime.deadline.prepare_source();
            self.poll_sources(false);
            if runtime.stopping.load(Ordering::SeqCst) {
                break;
            }
            prepared.sleep(runtime.deadline.get());
        }
    }

    /// Looks at what changes outside requests, then publishes the next
    /// deadline, waking the source thread for an earlier one if `wake`.
    fn poll_sources(&self, wake: bool) {
        self.stdio.poll();
        self.timers.fire();
        self.sockets.poll();
        if let Some(vsock) = &self.vsock {
            vsock.poll();
        }
        self.publish_deadline(wake);
    }

    /// Publishes when [`Self::poll_sources`] next has something to do; one
    /// earlier than before wakes the source thread, if `wake`.
    fn publish_deadline(&self, wake: bool) {
        let earlier = self.runtime.deadline.publish(|| {
            [
                self.timers.next_deadline(),
                self.next_sources_deadline(),
                self.stdio.next_deadline(self.platform.now()),
            ]
            .into_iter()
            .flatten()
            .min()
        });
        if earlier && wake {
            self.runtime.deadline.wake_source();
        }
    }

    /// When the network stack, or the vsock sockets, must next run, if ever.
    fn next_sources_deadline(&self) -> Option<Instant> {
        timers::earliest(
            self.sockets.next_deadline().map(timers::instant),
            self.vsock.as_ref().and_then(|vsock| vsock.next_deadline()),
        )
    }

    /// Creates a new root's broker process, with no parent, at its handshake:
    /// creating one allocates and takes the broker core's locks (e.g., its PID
    /// namespace's), which is broker work, not the kernel's.
    fn create_root(&self) -> Result<Arc<BrokerProcess>, BrokerError> {
        self.core.create_process(
            CallerCredential::HostGuaranteed,
            &self.pid_namespace,
            &self.fs,
            &self.job,
            default_host_names(),
            None,
        )
    }
}

impl Side {
    fn activate_inbox(&self, inbox: &Inbox<Runtime, Side>) {
        if matches!(self.state, State::Active(_)) {
            inbox.activate();
        }
    }

    /// Has `process`'s shutdown (e.g., as its PID namespace ends) set
    /// [`Association::shutdown_requested`] and notify the CPUs, for the kernel
    /// to kill the process. On the association's thread, as installing takes
    /// the broker core's locks; a shutdown requested before then runs now.
    fn install_shutdown(&self, process: &BrokerProcess) {
        debug_assert!(kthread::in_kthread(), "kernel code reached broker code");
        let requested = self.shutdown_requested.clone();
        process.install_shutdown(Arc::new(move || {
            requested.store(true, Ordering::SeqCst);
            cpu::notify_all();
        }));
    }

    fn handshake(&mut self, state: &BrokerState, request: &WireFrame) -> Result<WireFrame, Status> {
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
        self.connect(state, request)
    }

    /// Makes the association's one handshake, with `request` (or fails with
    /// its error), as [`Self::handshake`] does.
    fn connect(
        &mut self,
        broker: &BrokerState,
        request: Result<BrokerHandshakeRequest, Status>,
    ) -> Result<WireFrame, Status> {
        let (ring, shared_memory, launch) = match core::mem::replace(&mut self.state, State::Ended)
        {
            State::New(ring, shared_memory, launch) if launch.is_some() || !self.launched => {
                (ring, shared_memory, launch)
            }
            // Left as it was (e.g., active, on a repeated handshake, or a
            // process clone's that no start adopted).
            other => {
                self.state = other;
                return Err(Status::Denied);
            }
        };
        // Before the request's errors: dropping a launched child's start fails
        // it, which requests the child's shutdown.
        if let Some(launch) = &launch {
            self.install_shutdown(launch.process());
        }
        let request = request?;
        let mut launch = match launch {
            Some(launch) => launch,
            // A root's.
            None => match broker.create_root() {
                Ok(process) => {
                    self.install_shutdown(&process);
                    let _ = self.process.set(process.clone());
                    PendingRunnerAssociation {
                        process: Some(process),
                        startup: None,
                        clone: None,
                        launcher: Weak::new(),
                    }
                }
                Err(error) => {
                    let response = BrokerHandshakeResponse::Error(error.into());
                    return frame(&wire::encode_handshake_response(&response));
                }
            },
        };
        let startup = launch.startup.take();
        // `launch` lives until the end, so a failed handshake fails the start
        // (see `PendingRunnerAssociation`'s `Drop`).
        let shared_buffers = SharedBufferPool::new(shared_memory, SHARED_BUFFER_LAYOUT)
            .map_err(|_| Status::Unsupported)?;
        let mut setup = KernelHostSetup {
            request: Some(request),
            response: None,
        };
        let readiness: Arc<dyn ReadinessSink> = self.readiness.clone();
        let result = litebox_broker_host::setup_connection(
            launch.process(),
            startup,
            &mut setup,
            Arc::new(shared_buffers),
            readiness,
            |_| Ok(()),
        );
        if let Ok(Ok(host)) = result {
            if host.activate_process().is_err() {
                // Releases its broker process ID.
                host.finish();
                return Err(Status::Denied);
            }
            let HostControlRingEndpoints {
                lanes,
                lane_demand: _,
                notification_producer,
            } = ring.into_host();
            let [lane] = <[_; 1]>::try_from(lanes)
                .unwrap_or_else(|_| unreachable!("a single-lane layout has one lane"));
            self.readiness.activate(notification_producer);
            self.state = State::Active(Box::new(Active {
                association: host,
                requests: lane.request_consumer,
                responses: lane.response_producer,
                overflow: None,
            }));
        }
        let response = setup.response.ok_or(Status::Denied)?;
        frame(&wire::encode_handshake_response(&response))
    }

    /// See [`Association::adopt`]: fails `launch`, with
    /// [`BrokerError::PolicyDenied`] unless the association is a clone's that
    /// no start adopted, or [`BrokerError::PeerClosed`] if the handshake fails.
    fn adopt(
        &mut self,
        broker: &BrokerState,
        launch: PendingRunnerAssociation,
    ) -> Result<(), BrokerError> {
        if self.launched
            && self.process.get().is_none()
            && let State::New(_, _, pending @ None) = &mut self.state
        {
            let _ = self.process.set(launch.process().clone());
            *pending = Some(launch);
        } else {
            launch.fail(BrokerError::PolicyDenied);
            return Err(BrokerError::PolicyDenied);
        }
        match self.connect(broker, Ok(RUNNER_HANDSHAKE)) {
            Ok(response) if matches!(self.state, State::Active(_)) => {
                self.adoption_response = Some(response);
                Ok(())
            }
            // Dropping `launch` failed the start.
            _ => Err(BrokerError::PeerClosed),
        }
    }

    /// Serves the published requests, unless the response ring fills up, and
    /// publishes the readiness pending; [`Failed`] ended the association.
    fn serve(&mut self) -> Result<(), Failed> {
        let State::Active(active) = &mut self.state else {
            return Ok(());
        };
        let served = serving::serve(&self.readiness, || active.serve(&self.launcher));
        let served = served.and_then(|()| {
            self.readiness.flush();
            if self.readiness.failed() {
                Err(Failed)
            } else {
                Ok(())
            }
        });
        if served.is_err()
            && let State::Active(active) = core::mem::replace(&mut self.state, State::Ended)
        {
            end(active.association, &self.readiness);
        }
        served
    }

    /// Ends the association, and completes the broker process's exit, or fails
    /// its start if it never started.
    fn end(mut self, status: ProcessExitStatus) {
        if let State::Active(active) = core::mem::replace(&mut self.state, State::Ended) {
            end(active.association, &self.readiness);
        }
        if let Some(process) = self.process.get() {
            // Only the first completion counts; a process that never started
            // has none. This kernel does not measure its processes' CPU time.
            let _ = process.complete_exit(status, CpuTime::default());
        }
    }
}

impl Drop for Side {
    fn drop(&mut self) {
        debug_assert!(
            kthread::in_kthread(),
            "an association's broker side drops on a broker thread"
        );
    }
}

impl Active {
    fn serve(&mut self, launcher: &Arc<KernelProcessLauncher>) -> Result<(), Failed> {
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
                .execute_request_with(
                    request,
                    |parent, operation, shared_buffers| {
                        handle_process_operation(launcher, parent, operation, shared_buffers)
                    },
                    |r| {
                        response = Some(wire::encode_response(r));
                        Ok::<(), Infallible>(())
                    },
                )
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

/// Why [`Association::futex`] failed.
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

/// A child process to start (`StartChild`), for which the kernel creates a
/// runner process (see [`Association::take_pending_associations`]), or adopts a
/// process clone as its runner (`StartChildWithExistingRunner`), or a root
/// (see [`BrokerHandle::associate`]). Dropping it before the process's
/// handshake fails the start (in the kernel, through the request that waits
/// for it, as failing it is broker work).
pub struct PendingRunnerAssociation {
    /// Until [`Self::hand_back`] moves it to broker work: the kernel drops no
    /// reference to a broker process, as the last one's cleanup takes broker
    /// locks.
    process: Option<Arc<BrokerProcess>>,
    /// Until the handshake takes it; a root has none.
    startup: Option<ProcessStartupData>,
    /// See [`Self::clone_to_adopt`].
    clone: Option<u64>,
    /// The launcher of the request that waits for the start; a root has none.
    launcher: Weak<KernelProcessLauncher>,
}

impl PendingRunnerAssociation {
    /// For a start with an existing runner (`StartChildWithExistingRunner`),
    /// the process clone it names, which the kernel adopts as its runner
    /// ([`Association::adopt`]) only if the starting process made the clone.
    /// `None` for a runner process to create.
    pub fn clone_to_adopt(&self) -> Option<u64> {
        self.clone
    }

    /// Fails to start the process with `error`, e.g., if its runner process
    /// cannot be created.
    pub fn fail(mut self, error: BrokerError) {
        if !self.hand_back(error) {
            let _ = self.process().fail_start(error, false, true);
        }
    }

    /// Its process, until handed back (see [`Self::hand_back`]).
    fn process(&self) -> &Arc<BrokerProcess> {
        self.process
            .as_ref()
            .expect("a start not handed back has its process")
    }

    /// In the kernel, hands the start back to the request that waits for it,
    /// to fail with `error`: whether it did.
    fn hand_back(&mut self, error: BrokerError) -> bool {
        if kthread::in_kthread() {
            return false;
        }
        let launcher = core::mem::take(&mut self.launcher)
            .upgrade()
            .expect("the request that started a child waits for its start");
        // Its process too, moved, not cloned: the request may drop every other
        // reference first, and the kernel must drop none.
        let start = Self {
            process: self.process.take(),
            startup: self.startup.take(),
            clone: self.clone,
            launcher: Weak::new(),
        };
        launcher.failed.lock().push((start, error));
        launcher.started.wake(1);
        true
    }
}

impl Drop for PendingRunnerAssociation {
    /// Retires the process unless it started; `fail_start` keeps an earlier
    /// failure's error. In the kernel, hands it back instead (see
    /// [`Self::fail`]), unless handed back already, with its process.
    fn drop(&mut self) {
        if self.launcher.strong_count() != 0 {
            self.hand_back(BrokerError::PeerClosed);
        }
        let Some(process) = &self.process else {
            return;
        };
        debug_assert!(
            kthread::in_kthread(),
            "the kernel drops a broker process's reference, not handing its start back"
        );
        if kthread::in_kthread() && !matches!(process.startup_result(), Some(Ok(()))) {
            let _ = process.fail_start(BrokerError::PeerClosed, false, true);
            process.retire(true);
        }
        if let Some(launcher) = self.launcher.upgrade() {
            launcher.started.wake(1);
        }
    }
}

/// An association's [`ProcessLauncher`]: queues each child process for the
/// kernel, and sleeps until the child starts or fails.
#[derive(Default)]
struct KernelProcessLauncher {
    /// Kernel-grade: broker work queues, and the kernel takes.
    pending: KernelMutex<Vec<PendingRunnerAssociation>>,
    /// The starts the kernel handed back, with why.
    failed: KernelMutex<Vec<(PendingRunnerAssociation, BrokerError)>>,
    /// The request that waits for a start: one thread serves the process.
    started: WaitQueue,
}

impl KernelProcessLauncher {
    /// The starts queued since the last call, in order.
    fn take_pending(&self) -> Vec<PendingRunnerAssociation> {
        core::mem::take(&mut *self.pending.lock())
    }

    /// Queues `launch`, and sleeps until its process started or failed, or
    /// the kernel handed it back, which this fails.
    fn start(self: &Arc<Self>, mut launch: PendingRunnerAssociation) -> Result<(), BrokerError> {
        let process = launch.process().clone();
        launch.launcher = Arc::downgrade(self);
        self.pending.lock().push(launch);
        loop {
            // Before the registration: failing a start is broker work, which
            // may sleep itself.
            let failed = core::mem::take(&mut *self.failed.lock());
            for (launch, error) in failed {
                launch.fail(error);
            }
            let prepared = self.started.prepare();
            if let Some(result) = process.startup_result() {
                return result;
            }
            if self.failed.lock().is_empty() {
                prepared.sleep(None);
            }
        }
    }
}

impl Drop for KernelProcessLauncher {
    fn drop(&mut self) {
        debug_assert!(
            self.pending.lock().is_empty() && self.failed.lock().is_empty(),
            "a launcher dropped with starts left"
        );
    }
}

impl ProcessLauncher for KernelProcessLauncher {
    /// Never created: the kernel associates clones itself (see [`Self::launch_existing`]).
    type ChildConnection = Infallible;

    fn launch(
        self: Arc<Self>,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        image: Option<ChildImage>,
    ) -> Result<(), BrokerError> {
        if image.is_some() {
            // Only from `create_image`, which creates none.
            PendingRunnerAssociation {
                process: Some(process),
                startup: Some(startup),
                clone: None,
                launcher: Weak::new(),
            }
            .fail(BrokerError::UnsupportedOperation);
            return Err(BrokerError::UnsupportedOperation);
        }
        self.start(PendingRunnerAssociation {
            process: Some(process),
            startup: Some(startup),
            clone: None,
            launcher: Weak::new(),
        })
    }

    /// The runner must be a process clone that the parent made, which
    /// `runner_descriptor` names (see
    /// [`PendingRunnerAssociation::clone_to_adopt`]).
    fn launch_existing(
        self: Arc<Self>,
        _parent: litebox_broker_core::ProcessKey,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        runner_descriptor: Vec<u8>,
        _connection: Option<Infallible>,
    ) -> Result<(), BrokerError> {
        let clone = litebox_common_vm_abi::decode_clone_descriptor(&runner_descriptor);
        let launch = PendingRunnerAssociation {
            process: Some(process),
            startup: Some(startup),
            clone,
            launcher: Weak::new(),
        };
        if clone.is_none() {
            log::warn!("rejected a runner descriptor that names no process clone");
            launch.fail(BrokerError::PolicyDenied);
            return Err(BrokerError::PolicyDenied);
        }
        self.start(launch)
    }

    fn create_image(&self, _capacity: u64) -> Result<Box<dyn ProcessImage>, BrokerError> {
        Err(BrokerError::UnsupportedOperation)
    }
}

#[cfg(test)]
mod tests {
    use super::CONTROL_RING_LAYOUT;

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
}
