// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kernel side of `litebox_common_vm_abi`: ring-3 runner processes on
//! [`VmKernel`].
//!
//! Assumptions:
//! - Processes run only inside a [`sched::Scheduler`]'s calls: on the boot
//!   CPU, a service's (e.g., from [`Process::start`] or [`Process::call`]);
//!   on the others, [`sched::Scheduler::run`]. A process's threads run in
//!   parallel, on different CPUs, in ring 3 without its claim, which each of
//!   their kernel entries takes (see `claim`).
//! - A process's address space is current on a CPU only while the CPU runs
//!   one of its threads, or briefly as the kernel creates the process or a
//!   clone of it (see `fork`). Any other CPU that kept it current would take
//!   its TLB shootdowns needlessly, and keep its page table and frames alive
//!   until switching away (see `litebox_platform_vm_kernel`).
//! - The kernel does not use FS; user state across switches is the address
//!   space, and, per thread (see `thread`), the FS base and
//!   [`UserThreadState`].
//!
//! Contract: runners are untrusted. Every call is validated and scoped to its
//! process; identity-bound results use the identity fixed at
//! [`Process::spawn`].
//!
//! Generic over the service a runner provides: standalone [`program`]s, and
//! `optee` (feature `optee`, on by default).
//!
//! When a process starts a child process (`StartChild`), the scheduler
//! creates a launched process for it (see `litebox_common_vm_abi`, Messages)
//! with [`ProcessConfig::started_runner`], and runs it with the others (see
//! [`sched::Scheduler`]). A process that may start children can also clone
//! itself, as Linux's `fork` (see `fork`); the clone runs only once the
//! process starts a child with it (`StartChildWithExistingRunner`).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

/// The longest request [`Process::call`] accepts, and the longest reply.
pub const MAX_MESSAGE_LEN: u64 = layout::MESSAGE_WINDOW.len;

mod claim;
mod fork;
mod layout;
pub mod loader;
mod lockdown;
mod memory;
#[cfg(feature = "optee")]
pub mod optee;
pub mod program;
pub mod sched;
mod thread;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ops::Range;
use core::time::Duration;
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox::utils::TruncateExt as _;
use litebox_broker_core::BrokerError;
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_broker_vm_kernel::{Association, Broker, PendingRunnerAssociation, Wait};
use litebox_common_linux::PtRegs;
use litebox_common_vm_abi::envelope::Envelope;
use litebox_common_vm_abi::{
    ABI_VERSION, CallId, CloneKind, DERIVED_KEY_LEN, DeriveKeyReply, DeriveKeyRequest, FutexReply,
    IDENTITY_LEN, Image, KernelCall, LogLevel, LogRequest, MAX_IMAGES, MAX_KDF_CONTEXT_LEN,
    MAX_LOG_LEN, MapReply, MapRequest, Message, PAGE_SIZE, Placement, Populate, Prot,
    ProtectRequest, RUNNER_MANAGED_MAX, RUNNER_MANAGED_MIN, Registers, Request, RestrictRequest,
    SetTimerRequest, Sharing, StartupInfo, Status, UnmapRequest, UpcallFrame, UpcallKind,
    UserRange, WallClock,
};
use litebox_platform::time::{Instant as _, TimeProvider as _};
#[cfg(doc)]
use litebox_platform_vm_kernel::UserThreadState;
use litebox_platform_vm_kernel::cpu::{self, CpuId};
use litebox_platform_vm_kernel::{AddressSpaceId, Instant, PinnedUserPages, RunEnd, VmKernel};
use zerocopy::IntoBytes;

use claim::{Claim, Owned};
use memory::{Mappings, checked_range, copy_from_user, copy_to_user};
use sched::Scheduler;
use thread::{FutexFlow, FutexWait, Thread};

#[derive(Clone)]
pub struct ProcessConfig<'a> {
    /// Static-PIE ELF (see `loader`).
    pub runner: &'a [u8],
    /// At most [`MAX_IMAGES`]; see [`StartupInfo::images`].
    pub images: &'a [&'a [u8]],
    /// Binds derived keys; the caller is responsible for what it names.
    pub identity: [u8; IDENTITY_LEN],
    /// [`StartupInfo::clock_khz`]: the frequency of the counter behind the
    /// platform's installed clock source, which must be the same clock.
    pub clock_khz: u64,
    pub wall_clock: WallClock,
    /// For the process's [`CallId::SetTimer`] deadline.
    pub timer: &'static dyn ProcessTimer,
    /// The runner for the process's children and their descendants, which get
    /// no images and otherwise this configuration. Without one, the process
    /// cannot start children.
    pub started_runner: Option<&'static [u8]>,
    /// Debug builds, for tests of replays: the process's first kernel entry of
    /// each kind (a kernel call, a guest's syscall, a page fault, another
    /// exception, and an interrupt) gives up on its claim, as if another CPU
    /// held it (see `Running::entry`), so that its thread replays it once it
    /// runs again; [`Process::replay_counts`] then tells how often each was
    /// handled. Not passed on to its children.
    #[cfg(debug_assertions)]
    pub give_up_once: bool,
}

/// Each CPU's one-shot hardware timer, which processes' [`CallId::SetTimer`]
/// deadlines and the [scheduler](sched)'s time slices share, one at a time:
/// the runner owns it (e.g., a local APIC's).
pub trait ProcessTimer: Sync {
    /// Arms the calling CPU's timer, or with `None` disarms it, for a one-shot
    /// interrupt at `deadline`, which interrupts a process running then there
    /// (see [`EnterShim::interrupt`]). Arming replaces an earlier deadline.
    fn arm(&self, deadline: Option<Instant>);
}

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("loading the runner: {0}")]
    Load(loader::LoadError),
    #[error("too many images")]
    TooManyImages,
    #[error("images too large")]
    ImagesTooLarge,
    #[error("mapping failed: {0:?}")]
    Map(Status),
    #[error("pinning the broker's memory failed: {0:?}")]
    Pin(litebox_common_linux::errno::Errno),
    #[error("creating the broker process failed: {0:?}")]
    Broker(BrokerError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dead {
    Exited(u32),
    Killed(&'static str),
    /// See [`Process::finish`].
    Finished,
}

/// Fixed by [`CallId::Ready`], except for the reply slot, which each
/// `ReplyAndWait` names anew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Waiter {
    /// Where the next request's [`Message`] goes.
    reply_slot: u64,
    upcall_entry: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    New,
    /// A process clone not adopted yet (see `fork`), which runs nothing until
    /// then: it then serves, with its parent's `upcall_entry`.
    Cloned {
        upcall_entry: Option<u64>,
    },
    /// Before [`CallId::Ready`].
    Starting,
    /// In `Ready` or `ReplyAndWait`; `reply` is the last request's.
    Waiting {
        waiter: Waiter,
        reply: Option<Vec<u8>>,
    },
    /// `request` is delivered when the process next runs.
    Delivering {
        waiter: Waiter,
        request: Vec<u8>,
    },
    Serving {
        upcall_entry: Option<u64>,
    },
    Dead(Dead),
}

/// A runner process, shared by its [`Scheduler`], its [`Process`] handle, if
/// any, and, while one serves the process, a CPU's broker worker, behind its
/// claim (see `claim`); a process clone not adopted yet, weakly, by its parent
/// (see `fork`). Its address space is released once the last of them drops
/// it.
struct Inner {
    platform: &'static VmKernel,
    address_space: AddressSpaceId,
    identity: [u8; IDENTITY_LEN],
    entry: u64,
    gate: Range<u64>,
    /// See [`loader::LoadedRunner::executable`].
    executable: Vec<Range<u64>>,
    mappings: Mappings,
    broker: Association,
    timer: &'static dyn ProcessTimer,
    /// The configuration of its children's runner processes (see
    /// [`ProcessConfig::started_runner`]).
    started_runner_config: Option<ProcessConfig<'static>>,
    /// Borrowed briefly: killing the process replaces it.
    state: RefCell<State>,
    lockdown: Cell<lockdown::Lockdown>,
    /// Statistics for the current request.
    entries: Cell<u64>,
    reflected: Cell<u64>,
    /// [`CallId::SetTimer`]'s deadline. Armed to the platform's timer just
    /// before every resume to ring 3, and cleared once delivered.
    armed_deadline: Cell<Option<Instant>>,
    /// The broker published notifications (e.g., as it served a request)
    /// that the process has not been interrupted for yet.
    notified: Cell<bool>,
    /// See [`Self::share`].
    shared: Cell<bool>,
    /// The main thread first; exited threads until `sched` reaps them.
    threads: RefCell<Vec<Arc<Thread>>>,
    /// The next [`Thread::id`].
    next_thread: Cell<u64>,
    /// See [`Inner::broker_requester`].
    broker_requester: Cell<u64>,
    /// The CPU whose broker worker is suspended serving the process, set and
    /// cleared by that CPU: the association is in use, so broker calls wait
    /// ([`Self::broker_busy`]); only that CPU resumes the worker, while any
    /// may run the process's threads (see `sched`). The one record of it,
    /// mirrored in [`Owned::worker`] at each release.
    worker: Cell<Option<CpuId>>,
    /// The process clone the process made that is not adopted yet, if any, with
    /// its ID (see `fork`), reached only through the clone's claim. Weak: the
    /// scheduler owns it, and forgets it once dead (see `sched`).
    pending_clone: RefCell<Option<(u64, Weak<Owned>)>>,
    /// The next process clone's ID: the process never reuses one.
    next_clone: Cell<u64>,
    /// Debug builds: by [`EntryKind`], see [`ProcessConfig::give_up_once`].
    #[cfg(debug_assertions)]
    give_ups: [Cell<GiveUp>; EntryKind::COUNT],
}

/// Why a thread stopped mid-run, to resume where it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Suspended {
    No,
    /// Its slice ended, anywhere in ring 3; or, new, it has yet to run.
    Preempted,
    /// In `Futex`'s Wake on the broker's requests, for the broker's worker;
    /// it keeps its slice.
    Yielded,
    /// In `Futex`'s Wait on the broker's control ring: the scheduler polls
    /// the wait.
    Waiting(Wait),
    /// In `Futex`'s Wait elsewhere: the scheduler polls the wait.
    Futex(FutexWait),
    /// Its broker call is to be made again, once the worker is done with
    /// the process: it resumes at the call.
    Retry,
    /// `Futex`, or a failed `Clone` of a process clone, returns this once
    /// the thread resumes.
    Woken(Result<(), Status>),
    /// In `Clone` of a process clone, which the scheduler makes once its run
    /// ends (see `fork`); `slot` is the call's reply.
    Forking {
        slot: u64,
    },
    /// Back from `Clone` of a process clone, in the process and in the clone:
    /// once it resumes, the call returns its reply, `thread`, at `slot`.
    Cloned {
        slot: u64,
        thread: u64,
    },
    /// An entry that gave up on the process's claim (see `Running::entry`),
    /// handled once the thread resumes.
    Replay(Entry),
}

/// A kernel entry of a running thread, from the context the thread saved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Syscall,
    /// In user mode, as [`ExceptionInfo`] says; a trap (e.g., a single step's
    /// debug exception) would not recur if the thread just resumed.
    Exception {
        exception: Exception,
        error_code: u32,
        cr2: usize,
    },
    Interrupt,
}

/// Debug builds: a kind of [`Entry`], for tests that have the first entry of
/// each kind give up on the claim (see [`ProcessConfig::give_up_once`]).
#[cfg(debug_assertions)]
#[derive(Clone, Copy)]
enum EntryKind {
    /// A `syscall` of the runner's gate.
    KernelCall,
    /// Another `syscall`, a guest's, which the kernel reflects.
    Reflected,
    PageFault,
    /// Another exception.
    Exception,
    Interrupt,
}

#[cfg(debug_assertions)]
impl EntryKind {
    const COUNT: usize = 5;
}

/// Debug builds: whether the next entry of a kind gives up on the claim, and
/// then how often it is handled (see [`ProcessConfig::give_up_once`]).
#[cfg(debug_assertions)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum GiveUp {
    #[default]
    Off,
    /// It does.
    Armed,
    /// That of the thread with this ID did, which has handled it this many
    /// times since (see `Running::handle`), until it replays it.
    GaveUp(u64, u32),
    /// The thread replayed it, having handled it this many times in all.
    Replayed(u32),
}

/// A service's runner process, which runs in its scheduler until it dies.
/// Dropping it [finishes](Self::finish) it.
///
/// Its methods, but [`Self::is_stopped`] and [`Self::identity`], take the
/// process's claim (see `claim`), waiting while another CPU holds it (e.g.,
/// serving its broker requests): call them between the scheduler's steps,
/// holding nothing the processes' broker work may take (see
/// `sched::Scheduler::claim`).
pub struct Process {
    owned: Arc<Owned>,
    scheduler: Scheduler,
    identity: [u8; IDENTITY_LEN],
    /// [`Self::start`] was called (another CPU may have started it before).
    started: bool,
}

impl Process {
    /// Adds the process to `scheduler`. Runs nothing, but the other CPUs may
    /// start it at once.
    ///
    /// # Errors
    ///
    /// An invalid runner image, oversized images, or memory exhaustion.
    ///
    /// # Panics
    ///
    /// If the new address space cannot be activated.
    pub fn spawn(
        scheduler: &Scheduler,
        platform: &'static VmKernel,
        broker: &Broker,
        config: &ProcessConfig<'_>,
    ) -> Result<Self, SpawnError> {
        // Frees the memory of those that died (e.g., dropped ones) first.
        scheduler.reap();
        let inner = Inner::spawn(platform, broker, config, None)?;
        let identity = inner.identity;
        Ok(Self {
            owned: scheduler.add(inner),
            scheduler: scheduler.clone(),
            identity,
            started: false,
        })
    }

    /// Runs the scheduler until the runner waits for its first request.
    ///
    /// # Errors
    ///
    /// The process died.
    ///
    /// # Panics
    ///
    /// If called twice.
    pub fn start(&mut self) -> Result<(), Dead> {
        assert!(!self.started, "process already started");
        self.started = true;
        self.scheduler.run_until(|| self.owned.is_stopped());
        self.claim().settle()?;
        Ok(())
    }

    /// Delivers `request` and returns the reply, both envelopes; the reply's
    /// framing is checked. Runs the scheduler until the process replies, so
    /// the other processes run meanwhile too.
    ///
    /// # Errors
    ///
    /// The process is dead or died serving the request.
    ///
    /// # Panics
    ///
    /// As for [`Self::submit`].
    pub fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, Dead> {
        self.submit(request)?;
        self.scheduler.run_until(|| self.owned.is_stopped());
        self.reply()
    }

    /// Gives `request` to the process, to serve when it next runs;
    /// [`Self::reply`] then takes the reply.
    ///
    /// # Errors
    ///
    /// The process is dead.
    ///
    /// # Panics
    ///
    /// If the process is not waiting for a request (e.g., not started), or
    /// `request` is longer than [`MAX_MESSAGE_LEN`].
    pub fn submit(&mut self, request: &[u8]) -> Result<(), Dead> {
        let process = self.claim();
        if let Some(dead) = process.dead() {
            return Err(dead);
        }
        let State::Waiting { waiter, .. } = *process.state.borrow() else {
            panic!("process is not waiting for a request");
        };
        assert!(
            request.len() as u64 <= MAX_MESSAGE_LEN,
            "request exceeds the message window"
        );
        *process.state.borrow_mut() = State::Delivering {
            waiter,
            request: request.into(),
        };
        process.entries.set(0);
        process.reflected.set(0);
        // For any CPU to run.
        process.share();
        Ok(())
    }

    /// The reply to the request from [`Self::submit`], once the process
    /// stopped (see [`Self::is_stopped`]).
    ///
    /// # Errors
    ///
    /// The process died serving the request.
    ///
    /// # Panics
    ///
    /// If there is no reply: no request was submitted, or it was not run.
    pub fn reply(&mut self) -> Result<Vec<u8>, Dead> {
        let process = self.claim();
        let reply = process.settle()?;
        log::debug!(
            "request served with {} kernel entries ({} reflected syscalls)",
            process.entries.get(),
            process.reflected.get()
        );
        Ok(reply.expect("a waiting process has completed its request"))
    }

    /// Whether the process waits for a request (e.g., with its reply), or is
    /// dead. Lock-free, as of the last release of its claim.
    pub fn is_stopped(&self) -> bool {
        self.owned.is_stopped()
    }

    /// Guest syscalls the kernel reflected to the runner (`syscall`s outside
    /// its gate) while serving the last request.
    pub fn reflected_syscalls(&self) -> u64 {
        self.claim().reflected.get()
    }

    /// Debug builds: per kind, in [`ProcessConfig::give_up_once`]'s order, how
    /// many times the entry that gave up was handled, from its give-up through
    /// its replay, or 0 if it was not replayed: once, if its replay handled it,
    /// and nothing else.
    #[cfg(debug_assertions)]
    pub fn replay_counts(&self) -> [u32; EntryKind::COUNT] {
        self.claim()
            .give_ups
            .each_ref()
            .map(|give_up| match give_up.get() {
                GiveUp::Replayed(handled) => handled,
                GiveUp::Off | GiveUp::Armed | GiveUp::GaveUp(..) => 0,
            })
    }

    pub fn identity(&self) -> &[u8; IDENTITY_LEN] {
        &self.identity
    }

    /// For services: ends a process that has served all it will (e.g., its one
    /// program) at once, as its runner's exit would. Its broker process exits,
    /// releasing what it holds (e.g., pipe ends its children may wait on). A
    /// dead process keeps its cause of death.
    pub fn finish(&mut self) {
        let process = self.claim();
        if process.dead().is_none() {
            process.die(Dead::Finished);
        }
        // E.g., for the worker suspended serving it.
        process.share();
    }

    /// For services: ends a process that broke their protocol. A dead process
    /// keeps its cause of death.
    pub fn kill(&mut self, reason: &'static str) -> Dead {
        let process = self.claim();
        if let Some(dead) = process.dead() {
            return dead;
        }
        process.kill(reason);
        process.share();
        Dead::Killed(reason)
    }

    /// See [`Scheduler::claim`].
    fn claim(&self) -> Claim<'_> {
        self.scheduler.claim(&self.owned)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Inner {
    /// With `launch`, the process is a launched one (see
    /// [`Broker::associate`]). Leaves the kernel's address space current (see
    /// the crate docs).
    fn spawn(
        platform: &'static VmKernel,
        broker: &Broker,
        config: &ProcessConfig<'_>,
        launch: Option<PendingRunnerAssociation>,
    ) -> Result<Self, SpawnError> {
        let address_space = platform.create_address_space();
        // Safety: the kernel holds no references into user memory.
        unsafe { platform.switch_address_space(address_space) }
            .expect("a freshly created address space is registered");
        let inner =
            Self::populate(platform, address_space, broker, config, launch).inspect_err(|_| {
                // Safety: nothing references the half-built process's memory,
                // and it never ran, so its frames are exclusively owned.
                unsafe { release_address_space(platform, address_space) };
            })?;
        // Safety: as above.
        unsafe { platform.switch_address_space(AddressSpaceId::KERNEL) }
            .expect("the kernel address space always exists");
        Ok(inner)
    }

    fn populate(
        platform: &'static VmKernel,
        address_space: AddressSpaceId,
        broker: &Broker,
        config: &ProcessConfig<'_>,
        launch: Option<PendingRunnerAssociation>,
    ) -> Result<Self, SpawnError> {
        let mappings = Mappings::new(platform);
        let runner = loader::load(config.runner, &mappings).map_err(SpawnError::Load)?;

        let lazy = |region: UserRange| {
            mappings
                .map(
                    region_range(region),
                    Prot::ReadWrite,
                    Placement::NoReplace,
                    Populate::Lazy,
                    Sharing::Private,
                )
                .map_err(SpawnError::Map)
        };
        lazy(layout::UPCALL_STACK)?;
        lazy(layout::STACK)?;
        lazy(layout::MESSAGE_WINDOW)?;
        lazy(layout::HEAP)?;
        let (shared_memory, control_ring) =
            pin_broker_memory(platform, address_space, &mappings, Placement::NoReplace)?;
        let broker = broker
            .associate(shared_memory, control_ring, launch)
            .map_err(SpawnError::Broker)?;
        let images = map_images(&mappings, config.images)?;

        let info = StartupInfo {
            abi_version: ABI_VERSION,
            max_log_level: log::max_level() as u32,
            clock_khz: config.clock_khz,
            wall_clock: config.wall_clock,
            identity: config.identity,
            images,
            heap: layout::HEAP,
            stack: layout::STACK,
            upcall_stack: layout::UPCALL_STACK,
            message_window: layout::MESSAGE_WINDOW,
            broker_shared_memory: layout::BROKER_SHARED_MEMORY,
            broker_control_ring: layout::BROKER_CONTROL_RING,
        };
        map_read_only(&mappings, layout::STARTUP_INFO, info.as_bytes())?;
        // Armed so before any CPU may run the process.
        #[cfg(debug_assertions)]
        let give_up = if config.give_up_once {
            GiveUp::Armed
        } else {
            GiveUp::Off
        };

        Ok(Self {
            platform,
            address_space,
            identity: config.identity,
            entry: runner.entry,
            gate: runner.gate,
            executable: runner.executable,
            mappings,
            broker,
            timer: config.timer,
            started_runner_config: config.started_runner.map(|runner| ProcessConfig {
                runner,
                images: &[],
                identity: config.identity,
                clock_khz: config.clock_khz,
                wall_clock: config.wall_clock,
                timer: config.timer,
                started_runner: Some(runner),
                #[cfg(debug_assertions)]
                give_up_once: false,
            }),
            state: RefCell::new(State::New),
            lockdown: Cell::new(lockdown::Lockdown::OPEN),
            entries: Cell::new(0),
            reflected: Cell::new(0),
            armed_deadline: Cell::new(None),
            notified: Cell::new(false),
            shared: Cell::new(false),
            threads: RefCell::new(alloc::vec![new_thread(Thread::main(layout::UPCALL_STACK))]),
            next_thread: Cell::new(thread::MAIN + 1),
            broker_requester: Cell::new(thread::MAIN),
            worker: Cell::new(None),
            pending_clone: RefCell::new(None),
            next_clone: Cell::new(1),
            #[cfg(debug_assertions)]
            give_ups: [give_up; EntryKind::COUNT].map(Cell::new),
        })
    }

    /// Makes the process's address space current, and `thread`'s FS base, to
    /// run the thread, until the result ends.
    fn activate_thread(&self, thread: &Thread) -> Activated {
        use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
        // Safety: the kernel holds no references into user memory.
        unsafe { self.platform.switch_address_space(self.address_space) }
            .expect("the process's address space stays registered");
        self.platform
            .set_arch_specific_register(&ArchSpecificRegister::FsBase, thread.fs_base.get())
            .expect("a saved FS base is valid");
        Activated {
            platform: self.platform,
            timer: self.timer,
            _cpu: core::marker::PhantomData,
        }
    }

    /// Not running, so its deadline is not to interrupt anything (e.g., the
    /// kernel's halts, or the next process); re-armed as it resumes.
    fn deactivate(&self) {
        self.timer.arm(None);
    }

    /// Ring 3 can set any FS base (FSGSBASE is enabled); one that
    /// `activate_thread` could not restore kills a live process.
    fn save_fs_base(&self, thread: &Thread, fs_base: usize) {
        if litebox::arch::x86_64::is_valid_user_fs_base(fs_base) {
            thread.fs_base.set(fs_base);
        } else {
            thread.fs_base.set(0);
            self.kill("invalid FS base");
        }
    }

    fn dead(&self) -> Option<Dead> {
        match *self.state.borrow() {
            State::Dead(dead) => Some(dead),
            _ => None,
        }
    }

    /// Creates a runner process for each child this process started since the
    /// last call (see [`Association::take_pending_associations`]), adding it to
    /// `spawned`, or adopts the process clone it was started with as its runner
    /// (see `fork`), and fails the start of those it cannot. Returns whether
    /// there were any: either way, the requests that started them can complete.
    /// Leaves the kernel's address space current if it creates a process.
    pub(crate) fn spawn_launched(&self, spawned: &mut Vec<Self>) -> bool {
        let broker = self.broker.broker();
        let launches = self.broker.take_pending_associations();
        let started = !launches.is_empty();
        for launch in launches {
            if let Some(clone) = launch.clone_to_adopt() {
                self.adopt(clone, launch);
                continue;
            }
            let Some(config) = &self.started_runner_config else {
                log::warn!("a process without a child runner started a child process");
                launch.fail(BrokerError::UnsupportedOperation);
                continue;
            };
            // `spawn` fails it if it cannot create the process.
            match Self::spawn(self.platform, broker, config, Some(launch)) {
                Ok(process) => spawned.push(process),
                Err(error) => log::warn!("failed to spawn a launched process: {error}"),
            }
        }
        started
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Safety: the kernel holds no references into user memory, and the
        // process never runs again.
        unsafe { release_address_space(self.platform, self.address_space) };
    }
}

/// A process's address space, current on the calling CPU (see
/// [`Inner::activate_thread`]) until this drops: then the kernel's is again.
#[must_use = "dropping it makes the kernel's address space current at once"]
struct Activated {
    platform: &'static VmKernel,
    timer: &'static dyn ProcessTimer,
    /// Not `Send`: the calling CPU's.
    _cpu: core::marker::PhantomData<*const ()>,
}

impl Activated {
    /// Ends the thread's run on the calling CPU, needing no claim: the
    /// kernel's address space is current again, and the timer disarmed (see
    /// [`Inner::deactivate`]). Returns the FS base the thread left, unchecked
    /// (see [`Inner::save_fs_base`]).
    fn end(self) -> usize {
        use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
        self.timer.arm(None);
        self.platform
            .get_arch_specific_register(&ArchSpecificRegister::FsBase)
            .expect("the platform supports FS")
    }
}

impl Drop for Activated {
    fn drop(&mut self) {
        // Freeing a process can have left it already (see
        // `release_address_space`).
        if self.platform.current_address_space() != AddressSpaceId::KERNEL {
            // Safety: the kernel holds no references into user memory.
            unsafe { self.platform.switch_address_space(AddressSpaceId::KERNEL) }
                .expect("the kernel address space always exists");
        }
    }
}

/// Releases `address_space`; other processes keep the frames they share with
/// it copy-on-write (see `fork`).
///
/// # Safety
///
/// Nothing may reference the address space's user memory, and it must never
/// run again.
unsafe fn release_address_space(platform: &VmKernel, address_space: AddressSpaceId) {
    // Safety: forwarded to the caller.
    unsafe {
        platform
            .switch_address_space(AddressSpaceId::KERNEL)
            .expect("the kernel address space always exists");
        let _ = platform.unregister_address_space(address_space);
    }
}

/// Shared across CPUs only inside its process (see `claim`), whose claim
/// serializes what it touches, but, as it runs, its context, which only its
/// CPU touches (see [`Thread::running`]); `Arc` for references held past a
/// claim (e.g., by `sched`).
#[expect(
    clippy::arc_with_non_send_sync,
    reason = "a thread is touched only under its process's claim, or by the CPU it runs on"
)]
fn new_thread(thread: Thread) -> Arc<Thread> {
    Arc::new(thread)
}

fn region_range(region: UserRange) -> Range<usize> {
    usize::try_from(region.start).unwrap()..usize::try_from(region.end()).unwrap()
}

/// The broker's memory, pinned at creation, a process clone's too, as the
/// clone does not map its parent's: the shared buffers, populated as the
/// broker accesses them, and the control ring, populated now. Nothing unmaps,
/// remaps, or protects either: the runner's calls are confined to the
/// runner-managed area, the kernel maps both only here, and a fork leaves
/// pinned leaves as they are.
fn pin_broker_memory(
    platform: &VmKernel,
    address_space: AddressSpaceId,
    mappings: &Mappings,
    placement: Placement,
) -> Result<(PinnedUserPages, PinnedUserPages), SpawnError> {
    let shared_memory = region_range(layout::BROKER_SHARED_MEMORY);
    let control_ring = region_range(layout::BROKER_CONTROL_RING);
    mappings
        .map(
            shared_memory.clone(),
            Prot::ReadWrite,
            placement,
            Populate::Lazy,
            Sharing::Private,
        )
        .map_err(SpawnError::Map)?;
    mappings
        .map(
            control_ring.clone(),
            Prot::ReadWrite,
            placement,
            Populate::Now,
            Sharing::Private,
        )
        .map_err(SpawnError::Map)?;
    // Safety: see above, and it is mapped read-write; unregistering the
    // address space frees nothing while pinned.
    let shared_memory = unsafe { platform.pin_user_pages_lazily(address_space, shared_memory) }
        .map_err(SpawnError::Pin)?;
    // Safety: as for the shared buffers.
    let control_ring =
        unsafe { platform.pin_user_pages(address_space, control_ring) }.map_err(SpawnError::Pin)?;
    Ok((shared_memory, control_ring))
}

/// Read-only, packed in [`layout::IMAGES`] with a guard page after each.
fn map_images(mappings: &Mappings, images: &[&[u8]]) -> Result<[Image; MAX_IMAGES], SpawnError> {
    if images.len() > MAX_IMAGES {
        return Err(SpawnError::TooManyImages);
    }
    let mut mapped = [Image::default(); MAX_IMAGES];
    let mut next = layout::IMAGES.start;
    for (image, bytes) in mapped.iter_mut().zip(images) {
        let region = UserRange {
            start: next,
            len: (bytes.len() as u64).max(1).next_multiple_of(PAGE_SIZE),
        };
        if region.end() > layout::IMAGES.end() {
            return Err(SpawnError::ImagesTooLarge);
        }
        map_read_only(mappings, region, bytes)?;
        *image = Image {
            region,
            len: bytes.len() as u64,
        };
        next = region.end() + PAGE_SIZE;
    }
    Ok(mapped)
}

fn map_read_only(mappings: &Mappings, region: UserRange, bytes: &[u8]) -> Result<(), SpawnError> {
    let range = region_range(region);
    mappings
        .map(
            range.clone(),
            Prot::ReadWrite,
            Placement::NoReplace,
            Populate::Now,
            Sharing::Private,
        )
        .map_err(SpawnError::Map)?;
    copy_to_user(region.start, bytes).map_err(SpawnError::Map)?;
    mappings.protect(range, Prot::Read).map_err(SpawnError::Map)
}

fn registers(ctx: &PtRegs) -> Registers {
    Registers {
        r15: ctx.r15 as u64,
        r14: ctx.r14 as u64,
        r13: ctx.r13 as u64,
        r12: ctx.r12 as u64,
        rbp: ctx.rbp as u64,
        rbx: ctx.rbx as u64,
        r11: ctx.r11 as u64,
        r10: ctx.r10 as u64,
        r9: ctx.r9 as u64,
        r8: ctx.r8 as u64,
        rax: ctx.rax as u64,
        rcx: ctx.rcx as u64,
        rdx: ctx.rdx as u64,
        rsi: ctx.rsi as u64,
        rdi: ctx.rdi as u64,
        orig_rax: ctx.orig_rax as u64,
        rip: ctx.rip as u64,
        cs: ctx.cs as u64,
        rflags: ctx.eflags as u64,
        rsp: ctx.rsp as u64,
        ss: ctx.ss as u64,
    }
}

enum Flow {
    /// Resume with this result in `rax`.
    Return(Result<(), Status>),
    /// The process now waits or is dead.
    Stop,
}

/// HMAC-SHA256 keyed with the platform root key; at most 32 bytes.
fn hmac_kdf(prk: &[u8], params: litebox::platform::KDFParams) -> Result<(), Status> {
    use hmac::Mac as _;
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(prk).map_err(|_| Status::Unsupported)?;
    mac.update(params.context);
    let tag = mac.finalize().into_bytes();
    let output = params.output;
    if output.len() > tag.len() {
        return Err(Status::Unsupported);
    }
    output.copy_from_slice(&tag[..output.len()]);
    Ok(())
}

/// Domain separation for [`CallId::DeriveKey`]; changing it changes every
/// derived key.
const KDF_LABEL: &[u8] = b"litebox-vm-userland-key-v1\0";

impl Inner {
    /// A dead process keeps its cause of death.
    fn kill(&self, reason: &'static str) {
        if self.is_dead() {
            return;
        }
        log::warn!("killing runner process: {reason}");
        self.die(Dead::Killed(reason));
    }

    /// Ends every thread, wherever it stopped (e.g., in a wait), so none is
    /// left for the scheduler, interrupting those that run on other CPUs,
    /// whose entries then end their runs (see `Running`); and the process
    /// clone it has not started a child with, if any, which may leave the
    /// kernel's address space current (see [`fork::end_pending`]): the caller
    /// must not resume a thread afterward.
    fn die(&self, dead: Dead) {
        *self.state.borrow_mut() = State::Dead(dead);
        self.broker.exited(match dead {
            Dead::Exited(code) => ProcessExitStatus::Exited { code },
            // As a host kills a runner process.
            Dead::Killed(_) => ProcessExitStatus::Signaled {
                signal: litebox_common_linux::signal::Signal::SIGKILL
                    .as_i32()
                    .cast_unsigned(),
            },
            // Its runner reported the guest's (see `Process::finish`).
            Dead::Finished => ProcessExitStatus::Unknown,
        });
        for thread in self.threads.borrow().iter() {
            thread.suspended.set(Suspended::No);
        }
        self.interrupt_running();
        self.broker.abandon_wait();
        fork::end_pending(self.pending_clone.take());
    }

    fn is_dead(&self) -> bool {
        matches!(*self.state.borrow(), State::Dead(_))
    }

    fn is_new(&self) -> bool {
        *self.state.borrow() == State::New
    }

    /// Interrupts the CPUs that run the process's threads, but the calling
    /// one (whose thread, if any, is the caller): their entries look at the
    /// process again (see `Running`).
    fn interrupt_running(&self) {
        let current = cpu::current();
        cpu::interrupt(
            self.threads
                .borrow()
                .iter()
                .filter_map(|thread| thread.cpu_to_interrupt())
                .filter(|&cpu| cpu != current),
        );
    }

    /// See [`Self::worker`].
    fn broker_busy(&self) -> bool {
        self.worker.get().is_some()
    }

    /// The process has work another CPU may take (e.g., a runnable thread):
    /// the claim's release wakes the other idle CPUs.
    pub(crate) fn share(&self) {
        self.shared.set(true);
    }

    /// The waiting process's reply, if it has one.
    ///
    /// # Panics
    ///
    /// If the process still has to run.
    fn settle(&self) -> Result<Option<Vec<u8>>, Dead> {
        match &mut *self.state.borrow_mut() {
            State::Waiting { reply, .. } => Ok(reply.take()),
            State::Dead(dead) => Err(*dead),
            _ => panic!("the process has not run to a wait"),
        }
    }

    /// Waiting for a request, or dead.
    fn is_stopped(&self) -> bool {
        matches!(*self.state.borrow(), State::Waiting { .. } | State::Dead(_))
    }

    fn kill_and_stop(&self, reason: &'static str) -> ContinueOperation {
        self.kill(reason);
        ContinueOperation::Terminate
    }

    /// Resumes where `thread` was suspended.
    fn resume(&self, thread: &Thread) -> ContinueOperation {
        // Others may have published to it (e.g., fired its timers).
        self.broker.poll_events();
        // That, or an interrupt during a halt in the kernel, may have made
        // another due to run: a blocked thread, which it runs soon after
        // (see `sched`), or this CPU's worker, which it stops for at once
        // (see `Running::leave`).
        self.take_notified(thread);
        self.rearm_timer(thread);
        ContinueOperation::Resume
    }

    /// Resumes a thread suspended in a call, which returns `result`.
    fn resume_call(
        &self,
        thread: &Thread,
        ctx: &mut PtRegs,
        result: Result<(), Status>,
    ) -> ContinueOperation {
        ctx.rax = Status::to_raw(result).trunc();
        self.resume(thread)
    }

    /// Suspends `thread` to make its call again (the gate's `syscall`) once
    /// it resumes, as Linux restarts a call (`ERESTARTNOINTR`).
    fn retry(thread: &Thread, ctx: &mut PtRegs) -> Flow {
        ctx.rip -= 2;
        ctx.rax = ctx.orig_rax;
        thread.suspended.set(Suspended::Retry);
        Flow::Stop
    }

    fn dispatch(&self, thread: &Thread, ctx: &mut PtRegs) -> Flow {
        let Some(id) = CallId::from_raw(ctx.orig_rax as u64) else {
            return Flow::Return(Err(Status::UnknownCall));
        };
        // A process clone may make the handshake its inherited lockdown
        // refuses while its association holds the response of the one the
        // kernel made at adoption, which `Association::handshake` takes.
        let exempt = id == CallId::BrokerHandshake && self.broker.holds_adoption_response();
        if !self.lockdown.get().permits_call(id) && !exempt {
            return self.violation("call not allowed by the lockdown", id);
        }
        if ctx.rsi != id.request_size() || ctx.r10 != id.reply_size() {
            return Flow::Return(Err(Status::BadSize));
        }
        let request = match copy_from_user(ctx.rdi as u64, id.request_size())
            .and_then(|bytes| Request::decode(id, &bytes))
        {
            Ok(request) => request,
            Err(status) => return Flow::Return(Err(status)),
        };
        let slot = ctx.rdx as u64;
        match request {
            // The worker is using the association (see `sched`).
            Request::BrokerHandshake(_) if self.broker_busy() => Self::retry(thread, ctx),
            Request::Ready(_) | Request::ReplyAndWait(_)
                if !thread.is_main() || self.live_threads() > 1 =>
            {
                Flow::Return(Err(Status::Denied))
            }
            Request::Ready(ready) => {
                if *self.state.borrow() != State::Starting {
                    return Flow::Return(Err(Status::Denied));
                }
                if ready.abi_version != ABI_VERSION {
                    return Flow::Return(Err(Status::Unsupported));
                }
                let entry = ready.upcall_entry;
                if entry != 0 && !self.executable.iter().any(|seg| seg.contains(&entry)) {
                    return Flow::Return(Err(Status::InvalidArgument));
                }
                let upcall_entry = (entry != 0).then_some(entry);
                if self.broker.is_launched() {
                    // It has no request: it serves until it exits.
                    *self.state.borrow_mut() = State::Serving { upcall_entry };
                    return respond(&ready, slot, Ok(Message { len: 0 }));
                }
                *self.state.borrow_mut() = State::Waiting {
                    waiter: Waiter {
                        reply_slot: slot,
                        upcall_entry,
                    },
                    reply: None,
                };
                Flow::Stop
            }
            Request::ReplyAndWait(reply) => {
                let State::Serving { upcall_entry } = *self.state.borrow() else {
                    return Flow::Return(Err(Status::Denied));
                };
                if self.broker.is_launched() {
                    // It has no request to reply to.
                    return Flow::Return(Err(Status::Denied));
                }
                match Self::complete(reply) {
                    Ok(reply) => {
                        *self.state.borrow_mut() = State::Waiting {
                            waiter: Waiter {
                                reply_slot: slot,
                                upcall_entry,
                            },
                            reply: Some(reply),
                        };
                        Flow::Stop
                    }
                    Err(status) => Flow::Return(Err(status)),
                }
            }
            Request::Map(MapRequest { prot, .. })
            | Request::Protect(ProtectRequest { prot, .. })
                if !self.lockdown.get().permits_prot(prot) =>
            {
                self.violation("page permissions not allowed by the lockdown", prot)
            }
            Request::Map(r) => respond(&r, slot, self.map(&r)),
            Request::Unmap(r) => respond(&r, slot, self.unmap(&r)),
            Request::Protect(r) => respond(&r, slot, self.protect(&r)),
            Request::BrokerHandshake(r) => respond(&r, slot, self.broker.handshake(&r.0)),
            Request::DeriveKey(r) => respond(&r, slot, self.derive_key(&r)),
            Request::Log(r) => respond(&r, slot, Self::log(&r)),
            Request::Exit(r) => {
                self.die(Dead::Exited(r.code));
                Flow::Stop
            }
            Request::Restrict(r) => respond(&r, slot, self.restrict(&r)),
            Request::SetTimer(r) => respond(&r, slot, self.set_timer(r)),
            Request::Clone(r) => match r.kind {
                CloneKind::Thread => respond(&r, slot, self.clone_thread(&r)),
                // The scheduler makes it once the run ends.
                CloneKind::Process => match self.check_fork(&r) {
                    Ok(()) => {
                        thread.suspended.set(Suspended::Forking { slot });
                        Flow::Stop
                    }
                    Err(status) => Flow::Return(Err(status)),
                },
            },
            Request::ExitThread(_) if thread.is_main() => Flow::Return(Err(Status::Denied)),
            Request::ExitThread(r) => {
                self.exit_thread(thread, r.clear);
                Flow::Stop
            }
            Request::Futex(r) => match self.futex(thread, &r) {
                Ok(FutexFlow::Done(woken)) => respond(&r, slot, Ok(FutexReply { woken })),
                // Its reply is ready, for a successful return.
                Ok(FutexFlow::Block(suspended)) => {
                    match copy_to_user(slot, FutexReply { woken: 0 }.as_bytes()) {
                        Ok(()) => {
                            thread.suspended.set(suspended);
                            Flow::Stop
                        }
                        Err(status) => Flow::Return(Err(status)),
                    }
                }
                Ok(FutexFlow::Retry) => Self::retry(thread, ctx),
                Ok(FutexFlow::Failed) => {
                    self.kill("broker association failed");
                    Flow::Stop
                }
                Err(status) => Flow::Return(Err(status)),
            },
            Request::InterruptThread(r) => respond(&r, slot, self.interrupt_thread(r)),
        }
    }

    /// Kills the process for a lockdown violation; `what` was refused.
    fn violation(&self, reason: &'static str, what: impl core::fmt::Debug) -> Flow {
        log::warn!("killing runner process: {reason}: {what:?}");
        self.die(Dead::Killed(reason));
        Flow::Stop
    }

    fn restrict(&self, r: &RestrictRequest) -> Result<(), Status> {
        self.lockdown.set(self.lockdown.get().narrowed(r)?);
        log::debug!("lockdown: {}", self.lockdown.get());
        Ok(())
    }

    /// [`CallId::SetTimer`]: stores the deadline; [`Self::rearm_timer`]
    /// gives it to the platform just before the process next resumes, on the
    /// calling CPU and on those that run its other threads, which an earlier
    /// deadline interrupts for it (a later one fires their timers early, and
    /// they re-arm then).
    #[expect(
        clippy::unnecessary_wraps,
        reason = "matches `respond`'s signature, which fallible handlers need"
    )]
    fn set_timer(&self, r: SetTimerRequest) -> Result<(), Status> {
        let deadline = (r.deadline != 0).then(|| Instant::from_nanos(r.deadline));
        let earlier = deadline.is_some_and(|deadline| {
            self.armed_deadline
                .get()
                .is_none_or(|armed| deadline < armed)
        });
        self.armed_deadline.set(deadline);
        if earlier {
            self.interrupt_running();
        }
        Ok(())
    }

    /// Gives the platform's one-shot timer the process's armed deadline (or
    /// disarms it), so a running process sees it even without a kernel call
    /// of its own. Call before every resume to ring 3.
    ///
    /// Not before the process registers an upcall entry, as nothing could be
    /// delivered: the deadline is kept, and armed once there is one.
    ///
    /// Shares the timer with the broker's bounded waits (see
    /// [`ProcessTimer::arm`]), which always disarm it afterward, so nothing
    /// is lost by calling this unconditionally. Also arms the end of the time
    /// slice, if earlier.
    ///
    /// Also at once for `thread` if it was kicked
    /// ([`CallId::InterruptThread`]).
    fn rearm_timer(&self, thread: &Thread) {
        if self.broker.take_published() {
            self.notified.set(true);
        }
        self.arm_timer(
            thread,
            self.upcall_entry().and(timer_deadline(
                self.notified.get() || thread.kicked.get(),
                self.armed_deadline.get(),
                self.broker.next_timer_deadline(),
            )),
        );
    }

    /// Arms the platform's timer for `deadline` or the end of `thread`'s time
    /// slice, whichever is first. Only as ring 3 resumes, in the process's
    /// address space (e.g., not after [`Self::die`]).
    fn arm_timer(&self, thread: &Thread, deadline: Option<Instant>) {
        debug_assert_eq!(
            self.platform.current_address_space(),
            self.address_space,
            "ring 3 resumes in its process's address space"
        );
        let first = match (deadline, thread.slice_end.get()) {
            (Some(deadline), Some(slice_end)) => Some(deadline.min(slice_end)),
            (deadline, slice_end) => deadline.or(slice_end),
        };
        self.timer.arm(first);
    }

    /// The registered upcall entry, once the process is serving.
    fn upcall_entry(&self) -> Option<u64> {
        match *self.state.borrow() {
            State::Serving { upcall_entry } => upcall_entry,
            _ => None,
        }
    }

    fn managed(addr: u64, len: u64) -> Result<Range<usize>, Status> {
        checked_range(addr, len, RUNNER_MANAGED_MIN..RUNNER_MANAGED_MAX)
    }

    /// W^X, regardless of lockdown. Defense in depth only: the guest can reach
    /// the gate anyway.
    fn check_wx(prot: Prot) -> Result<(), Status> {
        if prot.write() && prot.exec() {
            Err(Status::Denied)
        } else {
            Ok(())
        }
    }

    // No per-process quota: a process can exhaust the kernel heap, which also
    // backs page tables.
    fn map(&self, r: &MapRequest) -> Result<MapReply, Status> {
        Self::check_wx(r.prot)?;
        self.mappings.map(
            Self::managed(r.range.start, r.range.len)?,
            r.prot,
            r.placement,
            r.populate,
            r.sharing,
        )?;
        Ok(MapReply {
            addr: r.range.start,
        })
    }

    fn unmap(&self, r: &UnmapRequest) -> Result<(), Status> {
        self.mappings
            .unmap(Self::managed(r.range.start, r.range.len)?)
    }

    fn protect(&self, r: &ProtectRequest) -> Result<(), Status> {
        Self::check_wx(r.prot)?;
        self.mappings
            .protect(Self::managed(r.range.start, r.range.len)?, r.prot)
    }

    fn derive_key(&self, r: &DeriveKeyRequest) -> Result<DeriveKeyReply, Status> {
        use litebox::platform::DerivedKeyProvider as _;
        if r.context.len > MAX_KDF_CONTEXT_LEN {
            return Err(Status::InvalidArgument);
        }
        let context = copy_from_user(r.context.start, r.context.len.trunc())?;
        let mut input = Vec::with_capacity(KDF_LABEL.len() + IDENTITY_LEN + context.len());
        input.extend_from_slice(KDF_LABEL);
        input.extend_from_slice(&self.identity);
        input.extend_from_slice(&context);
        let mut key = [0u8; DERIVED_KEY_LEN];
        self.platform
            .derive_key(
                Some(hmac_kdf),
                litebox::platform::KDFParams {
                    context: &input,
                    output: &mut key,
                },
            )
            .map_err(|_| Status::Unsupported)?;
        log::debug!("derived a key for a {}-byte context", context.len());
        Ok(DeriveKeyReply { key })
    }

    fn log(r: &LogRequest) -> Result<(), Status> {
        if r.message.len > MAX_LOG_LEN {
            return Err(Status::InvalidArgument);
        }
        let message = copy_from_user(r.message.start, r.message.len.trunc())?;
        let message = Untrusted(&String::from_utf8_lossy(&message));
        let level = match r.level {
            LogLevel::Error => log::Level::Error,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Info => log::Level::Info,
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Trace => log::Level::Trace,
        };
        log::log!(target: "runner", level, "runner: {message}");
        Ok(())
    }

    fn deliver(reply_slot: u64, request: &[u8]) -> Result<(), Status> {
        copy_to_user(layout::MESSAGE_WINDOW.start, request)?;
        let message = Message {
            len: request.len() as u64,
        };
        copy_to_user(reply_slot, message.as_bytes())
    }

    /// The reply, once its framing is checked.
    fn complete(reply: Message) -> Result<Vec<u8>, Status> {
        if reply.len > layout::MESSAGE_WINDOW.len {
            return Err(Status::InvalidArgument);
        }
        let bytes = copy_from_user(layout::MESSAGE_WINDOW.start, reply.len.trunc())?;
        Envelope::parse(&bytes).map_err(|_| Status::InvalidArgument)?;
        Ok(bytes.into_vec())
    }

    fn deliver_exception(
        &self,
        thread: &Thread,
        ctx: &mut PtRegs,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        log::debug!(
            "user exception {} error {:#x} at {:#x} address {:#x}",
            info.exception.0,
            info.error_code,
            ctx.rip,
            info.cr2
        );
        let fault_address = if info.exception == Exception::PAGE_FAULT {
            info.cr2 as u64
        } else {
            0
        };
        self.upcall(
            thread,
            ctx,
            UpcallKind::Exception,
            u64::from(info.exception.0),
            u64::from(info.error_code),
            fault_address,
        )
    }

    /// Kills the process without an upcall entry, on a nested upcall, or if
    /// the frame cannot be written. On `thread`'s upcall stack.
    fn upcall(
        &self,
        thread: &Thread,
        ctx: &mut PtRegs,
        kind: UpcallKind,
        vector: u64,
        error_code: u64,
        fault_address: u64,
    ) -> ContinueOperation {
        let Some(entry) = self.upcall_entry() else {
            // An interrupt before the process registered an entry (or with
            // none registered at all) is not a protocol violation.
            return if kind == UpcallKind::Interrupt {
                self.rearm_timer(thread);
                ContinueOperation::Resume
            } else {
                self.kill_and_stop(match kind {
                    UpcallKind::Exception => "unhandled exception",
                    UpcallKind::Syscall => "syscall outside the gate without an upcall entry",
                    UpcallKind::Interrupt => unreachable!("handled above"),
                })
            };
        };
        let stack = thread.upcall_stack;
        if stack.contains(ctx.rsp as u64) {
            return self.kill_and_stop("upcall during upcall delivery");
        }
        let frame = UpcallFrame::new(kind, registers(ctx), vector, error_code, fault_address);
        let frame_addr = (stack.end() - size_of::<UpcallFrame>() as u64) & !0xf;
        if copy_to_user(frame_addr, frame.as_bytes()).is_err() {
            return self.kill_and_stop("cannot write the upcall frame");
        }
        ctx.rip = entry.trunc();
        ctx.rsp = frame_addr.trunc();
        ctx.rdi = frame_addr.trunc();
        self.rearm_timer(thread);
        ContinueOperation::Resume
    }
}

/// When to interrupt the process: at once if the broker published
/// notifications it has not been interrupted for (`notified`), else at its
/// own `armed` deadline, or the broker's next timer's, whose readiness it
/// should see without a kernel call.
fn timer_deadline(
    notified: bool,
    armed: Option<Instant>,
    broker_timer: Option<Instant>,
) -> Option<Instant> {
    /// Already passed.
    const NOW: Instant = Instant::from_nanos(0);
    if notified {
        return Some(NOW);
    }
    match (armed, broker_timer) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// What [`Inner::on_interrupt`] does, given the deadline it would deliver at.
#[derive(Debug, PartialEq, Eq)]
enum InterruptAction {
    /// No deadline is armed: another interrupt (e.g., a device's, with
    /// nothing published), or a spurious or left-over timer fire.
    Ignore,
    /// Before the deadline: another interrupt, or the timer fired early
    /// (e.g., a one-shot count capped short of it). Arm it again.
    Rearm,
    /// Due, but the runner is still taking an earlier upcall, which a nested
    /// one would overwrite: fire again then. The deadline stays (past), so a
    /// re-arm in the meantime (a kernel call from the upcall stack) fires at
    /// once and retries again; runners rarely make one there.
    Retry(Instant),
    /// Due: deliver [`UpcallKind::Interrupt`].
    Deliver,
}

impl InterruptAction {
    /// Ample for the runner to leave the upcall stack, without spinning on
    /// retries.
    const UPCALL_STACK_RETRY: Duration = Duration::from_micros(100);

    /// `deadline` is the armed one, if any.
    fn decide(deadline: Option<Instant>, now: Instant, on_upcall_stack: bool) -> Self {
        match deadline {
            None => Self::Ignore,
            Some(deadline) if now < deadline => Self::Rearm,
            Some(_) if on_upcall_stack => Self::Retry(
                now.checked_add(Self::UPCALL_STACK_RETRY)
                    .unwrap_or(Instant::from_nanos(u64::MAX)),
            ),
            Some(_) => Self::Deliver,
        }
    }
}

/// Escapes control characters so a process cannot forge or garble log lines.
struct Untrusted<'a>(&'a str);

impl core::fmt::Display for Untrusted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write as _;
        for c in self.0.chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                f.write_char(c)?;
            }
        }
        Ok(())
    }
}

/// `request` fixes the reply type.
fn respond<C: KernelCall>(_request: &C, slot: u64, result: Result<C::Reply, Status>) -> Flow {
    Flow::Return(result.and_then(|value| copy_to_user(slot, value.as_bytes())))
}

impl Inner {
    /// Whether the `syscall` that left the thread at `ctx` is a kernel call:
    /// the runner's gate's.
    fn is_kernel_call(&self, ctx: &PtRegs) -> bool {
        let syscall_at = (ctx.rip as u64).wrapping_sub(2);
        self.gate.start <= syscall_at && ctx.rip as u64 <= self.gate.end
    }

    /// A `syscall` of `thread`: a kernel call from the runner's gate, or a
    /// guest's, which is reflected.
    fn on_syscall(&self, thread: &Thread, ctx: &mut PtRegs) -> ContinueOperation {
        self.entries.set(self.entries.get() + 1);
        if !self.is_kernel_call(ctx) {
            // A guest syscall: reflect it.
            self.reflected.set(self.reflected.get() + 1);
            return self.upcall(thread, ctx, UpcallKind::Syscall, 0, 0, 0);
        }
        match self.dispatch(thread, ctx) {
            Flow::Return(result) => {
                if let Err(status) = result {
                    log::debug!("kernel call {:#x} failed: {status:?}", ctx.orig_rax);
                }
                ctx.rax = Status::to_raw(result).trunc();
                self.rearm_timer(thread);
                ContinueOperation::Resume
            }
            Flow::Stop => ContinueOperation::Terminate,
        }
    }

    /// A user-mode exception of `thread`: demand paging, or an upcall.
    fn on_exception(
        &self,
        thread: &Thread,
        ctx: &mut PtRegs,
        info: &ExceptionInfo,
    ) -> ContinueOperation {
        self.entries.set(self.entries.get() + 1);
        if info.exception == Exception::PAGE_FAULT
            && self
                .mappings
                .demand_page(info.cr2, u64::from(info.error_code))
        {
            self.rearm_timer(thread);
            return ContinueOperation::Resume;
        }
        self.deliver_exception(thread, ctx, info)
    }

    /// An interrupt (e.g., the timer's, or a device's) stopped `thread`.
    /// First has the broker look at the devices and fire its due timers, as
    /// a kernel call would. Past its slice end, or once another may be due
    /// to run (see `sched`), then preempts it; what is due is delivered
    /// once it resumes. Otherwise delivers
    /// [`UpcallKind::Interrupt`] (quietly ignored before [`CallId::Ready`],
    /// like any upcall with no entry registered yet) if that published a
    /// notification, the thread was kicked ([`CallId::InterruptThread`]), or
    /// once the armed deadline has passed. Otherwise resumes:
    /// - with no deadline armed, there is nothing to deliver;
    /// - before the deadline, this re-arms it (e.g., the timer fired early,
    ///   as a one-shot count capped short of it);
    /// - on the upcall stack, the runner is still taking an earlier upcall
    ///   (which a nested one would overwrite), so this retries shortly.
    fn on_interrupt(&self, thread: &Thread, ctx: &mut PtRegs) -> ContinueOperation {
        self.broker.poll_events();
        if self.broker.take_published() {
            self.notified.set(true);
        }
        // Another may be due to run (see `sched`).
        self.take_notified(thread);
        let now = self.platform.now();
        if self.worker_due()
            || thread
                .slice_end
                .get()
                .is_some_and(|slice_end| now >= slice_end)
        {
            thread.suspended.set(Suspended::Preempted);
            return ContinueOperation::Terminate;
        }
        let on_upcall_stack = thread.upcall_stack.contains(ctx.rsp as u64);
        let deadline = timer_deadline(
            self.notified.get() || thread.kicked.get(),
            self.armed_deadline.get(),
            self.broker.next_timer_deadline(),
        );
        match InterruptAction::decide(deadline, now, on_upcall_stack) {
            // The slice end, if any, may still be armed.
            InterruptAction::Ignore | InterruptAction::Rearm => {
                self.rearm_timer(thread);
                ContinueOperation::Resume
            }
            InterruptAction::Retry(at) => {
                // Takes the pending interrupts (e.g., the last retry's
                // timer). Otherwise, if handling outlasts a retry,
                // the thread never runs. The retry polls for them.
                cpu::relax();
                self.arm_timer(thread, Some(at));
                ContinueOperation::Resume
            }
            // Kept until there is an upcall entry to deliver it to.
            InterruptAction::Deliver if self.upcall_entry().is_none() => {
                self.arm_timer(thread, None);
                ContinueOperation::Resume
            }
            InterruptAction::Deliver => {
                // For the other threads too.
                self.expire_deadline();
                // The upcall is for everything published so far.
                self.notified.set(false);
                thread.kicked.set(false);
                self.upcall(thread, ctx, UpcallKind::Interrupt, 0, 0, 0)
            }
        }
    }
}

#[cfg(debug_assertions)]
impl Inner {
    /// The kind of `entry`, which left the thread at `ctx`.
    fn entry_kind(&self, ctx: &PtRegs, entry: Entry) -> EntryKind {
        match entry {
            Entry::Syscall if self.is_kernel_call(ctx) => EntryKind::KernelCall,
            Entry::Syscall => EntryKind::Reflected,
            Entry::Exception { exception, .. } if exception == Exception::PAGE_FAULT => {
                EntryKind::PageFault
            }
            Entry::Exception { .. } => EntryKind::Exception,
            Entry::Interrupt => EntryKind::Interrupt,
        }
    }

    /// Whether `thread`'s `entry`, which left it at `ctx`, gives up on the
    /// claim (see [`ProcessConfig::give_up_once`]).
    fn gives_up(&self, thread: &Thread, ctx: &PtRegs, entry: Entry) -> bool {
        let give_up = &self.give_ups[self.entry_kind(ctx, entry) as usize];
        let armed = give_up.get() == GiveUp::Armed;
        if armed {
            give_up.set(GiveUp::GaveUp(thread.id, 0));
        }
        armed
    }

    /// `thread` handles an entry (see `Running::handle`): if one of its gave
    /// up, that one, as the thread stays parked until it replays it.
    fn handling(&self, thread: &Thread) {
        for give_up in &self.give_ups {
            if let GiveUp::GaveUp(id, handled) = give_up.get()
                && id == thread.id
            {
                give_up.set(GiveUp::GaveUp(id, handled + 1));
            }
        }
    }

    /// `thread` replayed an entry of `kind` (see `Running::resume_suspended`):
    /// if its entry of that kind gave up, that one, whose handling then stops
    /// counting.
    fn replayed(&self, thread: &Thread, kind: EntryKind) {
        let give_up = &self.give_ups[kind as usize];
        if let GiveUp::GaveUp(id, handled) = give_up.get()
            && id == thread.id
        {
            give_up.set(GiveUp::Replayed(handled));
        }
    }
}

/// A thread of a process, as the platform runs it on a CPU (see `sched`): in
/// ring 3 without the process's claim, which each kernel entry takes
/// ([`Self::entry`]) and releases as the thread resumes. A run that ends
/// without the claim ([`Unclaimed`]) has its CPU park the thread rather than
/// wait for the claim.
pub(crate) struct Running<'a, 't> {
    process: &'a Arc<Owned>,
    thread: &'t Thread,
    /// How the run ends, if it ends now: under the scheduler's claim until the
    /// first entry takes it; else as the entry that ended it recorded, or
    /// `None` between entries, when only the platform can end it (see
    /// [`Self::end`]).
    ending: Cell<Option<Ended<'a>>>,
}

/// How a thread's run ended (see [`Running::end`]).
pub(crate) enum Ended<'a> {
    /// Under the process's claim, which its last entry kept.
    Claimed(Claim<'a>),
    /// Without it: the CPU parks the thread.
    Unclaimed(Unclaimed),
}

/// Why a thread's run ended without its process's claim, for the claim's next
/// holder to act on (see `sched`).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Unclaimed {
    /// This entry gave up on the claim (see [`Running::entry`]), to replay
    /// once the thread resumes.
    GaveUp(Entry),
    /// The platform cannot return to the thread's context (see
    /// [`RunEnd::InvalidContext`]): at a `syscall`, which it then does not
    /// pass to the shim, or as an entry resumed the thread. That ends the
    /// process.
    InvalidContext,
}

impl<'a, 't> Running<'a, 't> {
    /// A run of `thread`, which starts under `claim`.
    pub(crate) fn new(claim: Claim<'a>, thread: &'t Thread) -> Self {
        Self {
            process: claim.process(),
            thread,
            ending: Cell::new(Some(Ended::Claimed(claim))),
        }
    }

    /// How the run ended, given how the platform ended it (`run_end`): an
    /// entry that ends the run records how, and otherwise releases the claim
    /// as it resumes the thread, which the platform may then fail to do.
    pub(crate) fn end(self, run_end: RunEnd) -> Ended<'a> {
        match (self.ending.into_inner(), run_end) {
            (Some(ended), RunEnd::Terminated) => ended,
            (None, RunEnd::InvalidContext) => Ended::Unclaimed(Unclaimed::InvalidContext),
            (Some(_), RunEnd::InvalidContext) | (None, RunEnd::Terminated) => {
                unreachable!("an entry records how it ends the run, and resumes otherwise")
            }
        }
    }

    /// The claim the run starts under.
    fn start(&self) -> Claim<'a> {
        match self.ending.take() {
            Some(Ended::Claimed(claim)) => claim,
            _ => unreachable!("the scheduler hands its claim to the run"),
        }
    }

    /// Ends an entry: the thread resumes ring 3 without the claim, or the run
    /// ends, keeping it for the scheduler. Preempts the thread instead if this
    /// CPU's suspended worker is due ([`Inner::worker_due`]), which only this
    /// CPU resumes, between runs: the entry may have taken a device's
    /// interrupt in kernel mode (e.g., spinning for the claim or a TLB
    /// shootdown), and the thread may not enter the kernel again before its
    /// slice ends.
    fn leave(&self, claim: Claim<'a>, op: ContinueOperation) -> ContinueOperation {
        let op = if op == ContinueOperation::Resume && claim.worker_due() {
            self.thread.suspended.set(Suspended::Preempted);
            ContinueOperation::Terminate
        } else {
            op
        };
        if op == ContinueOperation::Terminate {
            self.ending.set(Some(Ended::Claimed(claim)));
        }
        op
    }

    /// An entry from ring 3, under the claim, unless another CPU holds it past
    /// a brief spin ([`Owned::claim_briefly`]): then the run ends without it,
    /// to replay the entry once the thread resumes. The run also ends if the
    /// process stopped meanwhile (e.g., another thread ended it).
    fn entry(&self, ctx: &mut PtRegs, entry: Entry) -> ContinueOperation {
        let give_up = || {
            self.ending
                .set(Some(Ended::Unclaimed(Unclaimed::GaveUp(entry))));
            ContinueOperation::Terminate
        };
        let Some(claim) = self.process.claim_briefly() else {
            return give_up();
        };
        if claim.is_stopped() {
            return self.leave(claim, ContinueOperation::Terminate);
        }
        // Debug builds: also, as if the spin failed, if a test has it give up
        // (see `ProcessConfig::give_up_once`).
        #[cfg(debug_assertions)]
        if claim.gives_up(self.thread, ctx, entry) {
            drop(claim);
            return give_up();
        }
        let op = self.handle(&claim, ctx, entry);
        self.leave(claim, op)
    }

    /// Handles `entry`, which the thread made at `ctx`.
    fn handle(&self, inner: &Inner, ctx: &mut PtRegs, entry: Entry) -> ContinueOperation {
        #[cfg(debug_assertions)]
        inner.handling(self.thread);
        let thread = self.thread;
        match entry {
            Entry::Syscall => inner.on_syscall(thread, ctx),
            Entry::Exception {
                exception,
                error_code,
                cr2,
            } => {
                let info = ExceptionInfo {
                    exception,
                    error_code,
                    cr2,
                    kernel_mode: false,
                };
                inner.on_exception(thread, ctx, &info)
            }
            Entry::Interrupt => inner.on_interrupt(thread, ctx),
        }
    }

    /// Resumes the thread where it was suspended, or delivers its request.
    fn resume_suspended(&self, inner: &Inner, ctx: &mut PtRegs) -> ContinueOperation {
        let thread = self.thread;
        // Debug builds: a thread whose entry gave up (see
        // `ProcessConfig::give_up_once`) resumes by replaying it, or else a
        // later replay of that kind would take its place. Not if the process
        // stopped, which drops replays: e.g., killed as a step polled the
        // threads, after it found this one runnable.
        #[cfg(debug_assertions)]
        assert!(
            inner.is_stopped()
                || matches!(thread.suspended.get(), Suspended::Replay(_))
                || !inner.give_ups.iter().any(|give_up| {
                    matches!(give_up.get(), GiveUp::GaveUp(id, _) if id == thread.id)
                }),
            "thread {} resumed without replaying its entry that gave up",
            thread.id
        );
        match thread.suspended.replace(Suspended::No) {
            Suspended::No => {}
            Suspended::Waiting(_) | Suspended::Futex(_) => {
                return inner.kill_and_stop("resumed while waiting");
            }
            Suspended::Forking { .. } => return inner.kill_and_stop("resumed while forking"),
            Suspended::Preempted | Suspended::Retry => return inner.resume(thread),
            Suspended::Yielded => return inner.resume_call(thread, ctx, Ok(())),
            Suspended::Woken(result) => return inner.resume_call(thread, ctx, result),
            Suspended::Cloned { slot, thread: id } => {
                return inner.resume_cloned(thread, ctx, slot, id);
            }
            Suspended::Replay(entry) => {
                // As the entry left the thread: `handle` may move `rip`.
                #[cfg(debug_assertions)]
                let kind = inner.entry_kind(ctx, entry);
                let op = self.handle(inner, ctx, entry);
                #[cfg(debug_assertions)]
                inner.replayed(thread, kind);
                return op;
            }
        }
        let (waiter, request) = match &mut *inner.state.borrow_mut() {
            State::Delivering { waiter, request } => (*waiter, core::mem::take(request)),
            _ => return ContinueOperation::Terminate,
        };
        if Inner::deliver(waiter.reply_slot, &request).is_err() {
            return inner.kill_and_stop("cannot deliver the request");
        }
        *inner.state.borrow_mut() = State::Serving {
            upcall_entry: waiter.upcall_entry,
        };
        ctx.rax = Status::to_raw(Ok(())).trunc();
        inner.rearm_timer(thread);
        ContinueOperation::Resume
    }
}

impl EnterShim for Running<'_, '_> {
    type ExecutionContext = PtRegs;

    /// The main thread's start.
    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let claim = self.start();
        *ctx = PtRegs {
            rip: claim.entry.trunc(),
            rsp: layout::STACK.end().trunc(),
            rdi: layout::STARTUP_INFO.start.trunc(),
            ..PtRegs::default()
        };
        *claim.state.borrow_mut() = State::Starting;
        claim.rearm_timer(self.thread);
        self.leave(claim, ContinueOperation::Resume)
    }

    /// Resumes a suspended thread where it was, or delivers its request.
    fn reenter(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let claim = self.start();
        let op = self.resume_suspended(&claim, ctx);
        self.leave(claim, op)
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.entry(ctx, Entry::Syscall)
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        if info.kernel_mode {
            // Safety: the fault interrupted this CPU, which, if it holds the
            // claim (e.g., in a thread's entry, where alone the kernel
            // touches user memory: the broker's worker reaches it through
            // pinned pages), holds it until the fault returns.
            let inner = unsafe { self.process.claimed() };
            return if let Some(inner) = inner
                && info.exception == Exception::PAGE_FAULT
                && inner
                    .mappings
                    .demand_page(info.cr2, u64::from(info.error_code))
            {
                ContinueOperation::Resume
            } else {
                // Recovered by the faulting access's exception-table fixup,
                // else a panic.
                ContinueOperation::Terminate
            };
        }
        self.entry(
            ctx,
            Entry::Exception {
                exception: info.exception,
                error_code: info.error_code,
                cr2: info.cr2,
            },
        )
    }

    /// See [`Inner::on_interrupt`].
    fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.entry(ctx, Entry::Interrupt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupts_wait_out_early_fires_and_upcall_delivery() {
        let at = Instant::from_nanos;
        assert_eq!(
            InterruptAction::decide(None, at(100), false),
            InterruptAction::Ignore
        );
        // Early (e.g., a capped one-shot count): keep the deadline.
        assert_eq!(
            InterruptAction::decide(Some(at(200)), at(100), false),
            InterruptAction::Rearm
        );
        assert_eq!(
            InterruptAction::decide(Some(at(200)), at(100), true),
            InterruptAction::Rearm
        );
        // Due while the runner takes another upcall: retry, not kill.
        assert_eq!(
            InterruptAction::decide(Some(at(100)), at(150), true),
            InterruptAction::Retry(at(150 + 100_000))
        );
        assert_eq!(
            InterruptAction::decide(Some(at(100)), at(100), false),
            InterruptAction::Deliver
        );
    }

    #[test]
    fn timer_deadline_is_the_earliest_and_at_once_for_notifications() {
        let at = |nanos| Some(Instant::from_nanos(nanos));
        assert_eq!(timer_deadline(false, None, None), None);
        assert_eq!(timer_deadline(false, at(300), None), at(300));
        assert_eq!(timer_deadline(false, None, at(200)), at(200));
        assert_eq!(timer_deadline(false, at(300), at(200)), at(200));
        // Published while serving a request (e.g., a timer fired as the
        // broker was entered): interrupt as soon as the process resumes.
        assert_eq!(timer_deadline(true, None, None), at(0));
        assert_eq!(timer_deadline(true, at(300), at(200)), at(0));
        assert!(matches!(
            InterruptAction::decide(
                timer_deadline(true, None, None),
                Instant::from_nanos(100),
                false
            ),
            InterruptAction::Deliver
        ));
    }

    #[test]
    fn untrusted_text_is_escaped() {
        assert_eq!(
            alloc::format!("{}", Untrusted("a\nb\x1b[31mc\u{7f}é")),
            "a\\nb\\u{1b}[31mc\\u{7f}é"
        );
    }

    #[test]
    fn managed_ranges_are_checked() {
        let page = PAGE_SIZE;
        assert!(Inner::managed(RUNNER_MANAGED_MIN, page).is_ok());
        assert_eq!(
            Inner::managed(RUNNER_MANAGED_MIN - page, page),
            Err(Status::Denied)
        );
        assert_eq!(
            Inner::managed(RUNNER_MANAGED_MAX - page, 2 * page),
            Err(Status::Denied)
        );
        assert_eq!(
            Inner::managed(RUNNER_MANAGED_MIN + 1, page),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            Inner::managed(RUNNER_MANAGED_MIN, 0),
            Err(Status::InvalidArgument)
        );
        assert_eq!(
            Inner::managed(!(page - 1), page),
            Err(Status::InvalidArgument)
        );
        assert_eq!(Inner::check_wx(Prot::ReadWriteExec), Err(Status::Denied));
        assert_eq!(Inner::check_wx(Prot::ReadExec), Ok(()));
    }
}
