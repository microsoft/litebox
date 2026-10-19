// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kernel side of `litebox_common_vm_abi`: ring-3 runner processes on
//! [`VmKernel`].
//!
//! Assumptions:
//! - Single CPU: processes run only inside a [`sched::Scheduler`]'s calls
//!   (e.g., from [`Process::start`] or [`Process::call`]).
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
//! [`sched::Scheduler`]).

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

/// The longest request [`Process::call`] accepts, and the longest reply.
pub const MAX_MESSAGE_LEN: u64 = layout::MESSAGE_WINDOW.len;

mod layout;
pub mod loader;
mod lockdown;
mod memory;
#[cfg(feature = "optee")]
pub mod optee;
pub mod program;
pub mod sched;
mod thread;

use alloc::rc::Rc;
use alloc::string::String;
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
    ABI_VERSION, CallId, DERIVED_KEY_LEN, DeriveKeyReply, DeriveKeyRequest, FutexReply,
    IDENTITY_LEN, Image, KernelCall, LogLevel, LogRequest, MAX_IMAGES, MAX_KDF_CONTEXT_LEN,
    MAX_LOG_LEN, MapReply, MapRequest, Message, PAGE_SIZE, Placement, Populate, Prot,
    ProtectRequest, RUNNER_MANAGED_MAX, RUNNER_MANAGED_MIN, Registers, Request, RestrictRequest,
    SetTimerRequest, StartupInfo, Status, UnmapRequest, UpcallFrame, UpcallKind, UserRange,
    WallClock,
};
use litebox_platform::time::{Instant as _, TimeProvider as _};
#[cfg(doc)]
use litebox_platform_vm_kernel::UserThreadState;
use litebox_platform_vm_kernel::{AddressSpaceId, Instant, PinnedUserPages, VmKernel};
use zerocopy::IntoBytes;

use memory::{Mappings, checked_range, copy_from_user, copy_to_user};
use sched::Scheduler;
use thread::{FutexFlow, FutexWait, Thread};

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
}

/// The kernel's one-shot hardware timer, which processes' [`CallId::SetTimer`]
/// deadlines and the [scheduler](sched)'s time slices share, one at a time:
/// the runner owns it (e.g., a local APIC's).
pub trait ProcessTimer: Sync {
    /// Arms, or with `None` disarms, a one-shot interrupt at `deadline`,
    /// which interrupts a process running then (see
    /// [`EnterShim::interrupt`]). Arming replaces an earlier deadline.
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
    #[error("pinning the broker control ring failed: {0:?}")]
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
/// any, and, while it serves the process, the broker's worker. Its address
/// space is released once the last of them drops it.
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
    /// For the running thread; `None` if nothing else needs the CPU.
    slice_end: Cell<Option<Instant>>,
    /// The main thread first; exited threads until `sched` reaps them.
    threads: RefCell<Vec<Rc<Thread>>>,
    /// The next [`Thread::id`].
    next_thread: Cell<u64>,
    /// See [`Inner::broker_requester`].
    broker_requester: Cell<u64>,
    /// The broker's worker is suspended serving the process: its
    /// association is in use, so broker calls wait (see `sched`).
    broker_busy: Cell<bool>,
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
    /// `Futex` returns this once the thread resumes.
    Woken(Result<(), Status>),
}

/// A service's runner process, which runs in its scheduler until it dies.
/// Dropping it [finishes](Self::finish) it.
pub struct Process {
    inner: Rc<Inner>,
    scheduler: Scheduler,
}

impl Process {
    /// Adds the process to `scheduler`, and leaves its new address space
    /// current. Runs nothing.
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
        let inner = Rc::new(Inner::spawn(platform, broker, config, None)?);
        scheduler.add(inner.clone());
        Ok(Self {
            inner,
            scheduler: scheduler.clone(),
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
        assert!(self.inner.is_new(), "process already started");
        self.scheduler.run_until(|| self.inner.is_stopped());
        self.settle()?;
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
        self.scheduler.run_until(|| self.inner.is_stopped());
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
        if let Some(dead) = self.inner.dead() {
            return Err(dead);
        }
        let State::Waiting { waiter, .. } = *self.inner.state.borrow() else {
            panic!("process is not waiting for a request");
        };
        assert!(
            request.len() as u64 <= MAX_MESSAGE_LEN,
            "request exceeds the message window"
        );
        *self.inner.state.borrow_mut() = State::Delivering {
            waiter,
            request: request.into(),
        };
        self.inner.entries.set(0);
        self.inner.reflected.set(0);
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
        let reply = self.settle()?;
        log::debug!(
            "request served with {} kernel entries ({} reflected syscalls)",
            self.inner.entries.get(),
            self.inner.reflected.get()
        );
        Ok(reply.expect("a waiting process has completed its request"))
    }

    /// Whether the process waits for a request (e.g., with its reply), or is
    /// dead.
    pub fn is_stopped(&self) -> bool {
        self.inner.is_stopped()
    }

    /// Guest syscalls the kernel reflected to the runner (`syscall`s outside
    /// its gate) while serving the last request.
    pub fn reflected_syscalls(&self) -> u64 {
        self.inner.reflected.get()
    }

    pub fn identity(&self) -> &[u8; IDENTITY_LEN] {
        &self.inner.identity
    }

    /// For services: ends a process that has served all it will (e.g., its one
    /// program) at once, as its runner's exit would. Its broker process exits,
    /// releasing what it holds (e.g., pipe ends its children may wait on). A
    /// dead process keeps its cause of death.
    pub fn finish(&mut self) {
        if self.inner.dead().is_none() {
            self.inner.die(Dead::Finished);
        }
    }

    /// For services: ends a process that broke their protocol. A dead process
    /// keeps its cause of death.
    pub fn kill(&mut self, reason: &'static str) -> Dead {
        if let Some(dead) = self.inner.dead() {
            return dead;
        }
        self.inner.kill(reason);
        Dead::Killed(reason)
    }

    /// The waiting process's reply, if it has one.
    ///
    /// # Panics
    ///
    /// If the process still has to run.
    fn settle(&self) -> Result<Option<Vec<u8>>, Dead> {
        match &mut *self.inner.state.borrow_mut() {
            State::Waiting { reply, .. } => Ok(reply.take()),
            State::Dead(dead) => Err(*dead),
            _ => panic!("the process has not run to a wait"),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Inner {
    /// With `launch`, the process is a launched one (see
    /// [`Broker::associate`]).
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
        Self::populate(platform, address_space, broker, config, launch).inspect_err(|_| {
            // Safety: nothing references the half-built process's memory, and
            // it never ran, so its frames are exclusively owned.
            unsafe { release_address_space(platform, address_space) };
        })
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
                )
                .map_err(SpawnError::Map)
        };
        lazy(layout::UPCALL_STACK)?;
        lazy(layout::STACK)?;
        lazy(layout::MESSAGE_WINDOW)?;
        lazy(layout::BROKER_SHARED_MEMORY)?;
        lazy(layout::HEAP)?;
        let control_ring = pin_control_ring(platform, address_space, &mappings)?;
        let broker = broker
            .associate(layout::BROKER_SHARED_MEMORY, control_ring, launch)
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
            }),
            state: RefCell::new(State::New),
            lockdown: Cell::new(lockdown::Lockdown::OPEN),
            entries: Cell::new(0),
            reflected: Cell::new(0),
            armed_deadline: Cell::new(None),
            notified: Cell::new(false),
            slice_end: Cell::new(None),
            threads: RefCell::new(alloc::vec![Rc::new(Thread::main(layout::UPCALL_STACK))]),
            next_thread: Cell::new(thread::MAIN + 1),
            broker_requester: Cell::new(thread::MAIN),
            broker_busy: Cell::new(false),
        })
    }

    /// Makes the process's address space current, e.g., for the worker.
    fn activate(&self) {
        // Safety: the kernel holds no references into user memory.
        unsafe { self.platform.switch_address_space(self.address_space) }
            .expect("the process's address space stays registered");
    }

    /// Not running, so its deadline is not to interrupt anything (e.g., the
    /// kernel's halts, or the next process); re-armed as it resumes.
    fn deactivate(&self) {
        self.timer.arm(None);
    }

    /// [`Self::activate`], and `thread`'s FS base.
    fn activate_thread(&self, thread: &Thread) {
        use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
        self.activate();
        self.platform
            .set_arch_specific_register(&ArchSpecificRegister::FsBase, thread.fs_base.get())
            .expect("a saved FS base is valid");
    }

    /// Ring 3 can set any FS base (FSGSBASE is enabled); one that
    /// `activate_thread` could not restore kills a live process.
    fn deactivate_thread(&self, thread: &Thread) {
        use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
        self.deactivate();
        let fs_base = self
            .platform
            .get_arch_specific_register(&ArchSpecificRegister::FsBase)
            .expect("the platform supports FS");
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
    /// `spawned`, and fails the start of those it cannot create. Returns
    /// whether there were any: either way, the requests that started them can
    /// complete. Leaves another address space current.
    pub(crate) fn spawn_launched(&self, spawned: &mut Vec<Rc<Self>>) -> bool {
        let broker = self.broker.broker();
        let launches = self.broker.take_pending_associations();
        let started = !launches.is_empty();
        for launch in launches {
            let Some(config) = &self.started_runner_config else {
                log::warn!("a process without a child runner started a child process");
                launch.fail(BrokerError::UnsupportedOperation);
                continue;
            };
            // `spawn` fails it if it cannot create the process.
            match Self::spawn(self.platform, broker, config, Some(launch)) {
                Ok(process) => spawned.push(Rc::new(process)),
                Err(error) => log::warn!("failed to spawn a launched process: {error}"),
            }
        }
        started
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Safety: the kernel holds no references into user memory, and the
        // process never runs again, so its frames are exclusively owned.
        unsafe { release_address_space(self.platform, self.address_space) };
    }
}

/// # Safety
///
/// Nothing may reference the address space's user memory, and its frames must
/// be exclusively owned.
unsafe fn release_address_space(platform: &VmKernel, address_space: AddressSpaceId) {
    // Safety: forwarded to the caller.
    unsafe {
        platform
            .switch_address_space(AddressSpaceId::KERNEL)
            .expect("the kernel address space always exists");
        let _ = platform.unregister_address_space(address_space);
    }
}

fn region_range(region: UserRange) -> Range<usize> {
    usize::try_from(region.start).unwrap()..usize::try_from(region.end()).unwrap()
}

/// Populated and pinned at creation. Nothing unmaps or remaps it: the
/// runner's calls are confined to the runner-managed area.
fn pin_control_ring(
    platform: &VmKernel,
    address_space: AddressSpaceId,
    mappings: &Mappings,
) -> Result<PinnedUserPages, SpawnError> {
    let range = region_range(layout::BROKER_CONTROL_RING);
    mappings
        .map(
            range.clone(),
            Prot::ReadWrite,
            Placement::NoReplace,
            Populate::Now,
        )
        .map_err(SpawnError::Map)?;
    // Safety: see above; unregistering the address space frees nothing while
    // pinned.
    unsafe { platform.pin_user_pages(address_space, range) }.map_err(SpawnError::Pin)
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
    /// left for the scheduler.
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
        self.broker.abandon_wait();
    }

    fn is_dead(&self) -> bool {
        matches!(*self.state.borrow(), State::Dead(_))
    }

    fn is_new(&self) -> bool {
        *self.state.borrow() == State::New
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
        // another due to run: stop, for the scheduler to see.
        if self.others_due() {
            thread.suspended.set(Suspended::Preempted);
            return ContinueOperation::Terminate;
        }
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
        if !self.lockdown.get().permits_call(id) {
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
            Request::BrokerHandshake(_) if self.broker_busy.get() => Self::retry(thread, ctx),
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
            Request::Clone(r) => respond(&r, slot, self.clone_thread(&r)),
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
    /// gives it to the platform just before the process next resumes.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "matches `respond`'s signature, which fallible handlers need"
    )]
    fn set_timer(&self, r: SetTimerRequest) -> Result<(), Status> {
        self.armed_deadline
            .set((r.deadline != 0).then(|| Instant::from_nanos(r.deadline)));
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
        self.arm_timer(self.upcall_entry().and(timer_deadline(
            self.notified.get() || thread.kicked.get(),
            self.armed_deadline.get(),
            self.broker.next_timer_deadline(),
        )));
    }

    /// Arms the platform's timer for `deadline` or the end of the time slice,
    /// whichever is first.
    fn arm_timer(&self, deadline: Option<Instant>) {
        let first = match (deadline, self.slice_end.get()) {
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

/// What [`Running::interrupt`] does, given the deadline it would deliver at.
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

/// A thread of a process, as the platform enters it.
pub(crate) struct Running<'a> {
    inner: &'a Inner,
    thread: &'a Thread,
}

impl EnterShim for Running<'_> {
    type ExecutionContext = PtRegs;

    /// The main thread's start.
    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let Self { inner, thread } = *self;
        *ctx = PtRegs {
            rip: inner.entry.trunc(),
            rsp: layout::STACK.end().trunc(),
            rdi: layout::STARTUP_INFO.start.trunc(),
            ..PtRegs::default()
        };
        *inner.state.borrow_mut() = State::Starting;
        inner.rearm_timer(thread);
        ContinueOperation::Resume
    }

    /// Resumes a suspended thread where it was, or delivers its request.
    fn reenter(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let Self { inner, thread } = *self;
        match thread.suspended.replace(Suspended::No) {
            Suspended::No => {}
            Suspended::Waiting(_) | Suspended::Futex(_) => {
                return inner.kill_and_stop("resumed while waiting");
            }
            Suspended::Preempted | Suspended::Retry => return inner.resume(thread),
            Suspended::Yielded => return inner.resume_call(thread, ctx, Ok(())),
            Suspended::Woken(result) => return inner.resume_call(thread, ctx, result),
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

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let Self { inner, thread } = *self;
        inner.entries.set(inner.entries.get() + 1);
        let syscall_at = (ctx.rip as u64).wrapping_sub(2);
        if !(inner.gate.start <= syscall_at && ctx.rip as u64 <= inner.gate.end) {
            // A guest syscall: reflect it.
            inner.reflected.set(inner.reflected.get() + 1);
            return inner.upcall(thread, ctx, UpcallKind::Syscall, 0, 0, 0);
        }
        match inner.dispatch(thread, ctx) {
            Flow::Return(result) => {
                if let Err(status) = result {
                    log::debug!("kernel call {:#x} failed: {status:?}", ctx.orig_rax);
                }
                ctx.rax = Status::to_raw(result).trunc();
                inner.rearm_timer(thread);
                ContinueOperation::Resume
            }
            Flow::Stop => ContinueOperation::Terminate,
        }
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        let Self { inner, thread } = *self;
        if !info.kernel_mode {
            inner.entries.set(inner.entries.get() + 1);
        }
        if info.exception == Exception::PAGE_FAULT
            && inner
                .mappings
                .demand_page(info.cr2, u64::from(info.error_code))
        {
            // Kernel code (e.g., the worker serving the process) does not
            // resume ring 3.
            if !info.kernel_mode {
                inner.rearm_timer(thread);
            }
            return ContinueOperation::Resume;
        }
        if info.kernel_mode {
            // Recovered by the faulting access's exception-table fixup.
            return ContinueOperation::Terminate;
        }
        inner.deliver_exception(thread, ctx, info)
    }

    /// An interrupt (e.g., the timer's, or a device's) stopped the thread.
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
    fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let Self { inner, thread } = *self;
        inner.broker.poll_events();
        if inner.broker.take_published() {
            inner.notified.set(true);
        }
        let now = inner.platform.now();
        // Another may be due to run (see `sched`).
        if inner.others_due()
            || inner
                .slice_end
                .get()
                .is_some_and(|slice_end| now >= slice_end)
        {
            thread.suspended.set(Suspended::Preempted);
            return ContinueOperation::Terminate;
        }
        let on_upcall_stack = thread.upcall_stack.contains(ctx.rsp as u64);
        let deadline = timer_deadline(
            inner.notified.get() || thread.kicked.get(),
            inner.armed_deadline.get(),
            inner.broker.next_timer_deadline(),
        );
        match InterruptAction::decide(deadline, now, on_upcall_stack) {
            // The slice end, if any, may still be armed.
            InterruptAction::Ignore | InterruptAction::Rearm => {
                inner.rearm_timer(thread);
                ContinueOperation::Resume
            }
            InterruptAction::Retry(at) => {
                inner.arm_timer(Some(at));
                ContinueOperation::Resume
            }
            // Kept until there is an upcall entry to deliver it to.
            InterruptAction::Deliver if inner.upcall_entry().is_none() => {
                inner.arm_timer(None);
                ContinueOperation::Resume
            }
            InterruptAction::Deliver => {
                // For the other threads too.
                inner.expire_deadline();
                // The upcall is for everything published so far.
                inner.notified.set(false);
                thread.kicked.set(false);
                inner.upcall(thread, ctx, UpcallKind::Interrupt, 0, 0, 0)
            }
        }
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
