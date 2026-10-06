// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kernel side of `litebox_common_vm_abi`: ring-3 runner processes on
//! [`VmKernel`].
//!
//! Assumptions:
//! - Single CPU, no scheduler: a process runs only inside [`Process::start`]
//!   or [`Process::call`], until it waits, exits, or is killed.
//! - The kernel does not use FS; user state across switches is the address
//!   space and the FS base.
//!
//! Contract: runners are untrusted. Every call is validated and scoped to its
//! process; identity-bound results use the identity fixed at
//! [`Process::spawn`].
//!
//! Generic over the service a runner provides; `optee` (feature `optee`, on
//! by default) is one.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

/// The longest request [`Process::call`] accepts, and the longest reply.
pub const MAX_MESSAGE_LEN: u64 = layout::MESSAGE_WINDOW.len;

mod broker;
mod layout;
pub mod loader;
mod memory;
#[cfg(feature = "optee")]
pub mod optee;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ops::Range;
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox::utils::TruncateExt as _;
use litebox_broker_core::BrokerCore;
use litebox_common_linux::PtRegs;
use litebox_common_vm_abi::envelope::Envelope;
use litebox_common_vm_abi::{
    ABI_VERSION, CallId, DERIVED_KEY_LEN, DeriveKeyReply, DeriveKeyRequest, IDENTITY_LEN, Image,
    KernelCall, LogLevel, LogRequest, MAX_IMAGES, MAX_KDF_CONTEXT_LEN, MAX_LOG_LEN, MapReply,
    MapRequest, Message, PAGE_SIZE, Placement, Populate, Prot, ProtectRequest, RUNNER_MANAGED_MAX,
    RUNNER_MANAGED_MIN, Registers, Request, StartupInfo, Status, UnmapRequest, UpcallFrame,
    UpcallKind, UserRange,
};
use litebox_platform_vm_kernel::{AddressSpaceId, VmKernel};
use zerocopy::IntoBytes;

use memory::{Mappings, checked_range, copy_from_user, copy_to_user};

pub struct ProcessConfig<'a> {
    /// Static-PIE ELF (see `loader`).
    pub runner: &'a [u8],
    /// At most [`MAX_IMAGES`]; see [`StartupInfo::images`].
    pub images: &'a [&'a [u8]],
    /// Binds derived keys; the caller is responsible for what it names.
    pub identity: [u8; IDENTITY_LEN],
    pub tsc_khz: u64,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dead {
    Exited(u32),
    Killed(&'static str),
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

/// Separate from [`Process`] so that the platform can borrow it alongside the
/// register context.
struct Inner {
    platform: &'static VmKernel,
    address_space: AddressSpaceId,
    identity: [u8; IDENTITY_LEN],
    entry: u64,
    gate: Range<u64>,
    /// See [`loader::LoadedRunner::executable`].
    executable: Vec<Range<u64>>,
    mappings: Mappings,
    broker: broker::Broker,
    /// Borrowed briefly: killing the process replaces it.
    state: RefCell<State>,
    /// Statistics for the current request.
    entries: Cell<u64>,
}

pub struct Process {
    inner: Inner,
    ctx: PtRegs,
    /// Saved while another process runs.
    fs_base: usize,
}

impl Process {
    /// Leaves the new address space current. Runs nothing.
    ///
    /// # Errors
    ///
    /// An invalid runner image, oversized images, or memory exhaustion.
    ///
    /// # Panics
    ///
    /// If the new address space cannot be activated.
    pub fn spawn(
        platform: &'static VmKernel,
        broker_core: BrokerCore,
        config: &ProcessConfig<'_>,
    ) -> Result<Self, SpawnError> {
        let address_space = platform.create_address_space();
        // Safety: the kernel holds no references into user memory.
        unsafe { platform.switch_address_space(address_space) }
            .expect("a freshly created address space is registered");
        Self::populate(platform, address_space, broker_core, config).inspect_err(|_| {
            // Safety: nothing references the half-built process's memory, and
            // it never ran, so its frames are exclusively owned.
            unsafe { release_address_space(platform, address_space) };
        })
    }

    fn populate(
        platform: &'static VmKernel,
        address_space: AddressSpaceId,
        broker_core: BrokerCore,
        config: &ProcessConfig<'_>,
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
        let images = map_images(&mappings, config.images)?;

        let info = StartupInfo {
            abi_version: ABI_VERSION,
            max_log_level: log::max_level() as u32,
            tsc_khz: config.tsc_khz,
            identity: config.identity,
            images,
            heap: layout::HEAP,
            stack: layout::STACK,
            upcall_stack: layout::UPCALL_STACK,
            message_window: layout::MESSAGE_WINDOW,
            broker_shared_memory: layout::BROKER_SHARED_MEMORY,
        };
        map_read_only(&mappings, layout::STARTUP_INFO, info.as_bytes())?;

        Ok(Self {
            inner: Inner {
                platform,
                address_space,
                identity: config.identity,
                entry: runner.entry,
                gate: runner.gate,
                executable: runner.executable,
                mappings,
                broker: broker::Broker::new(broker_core, layout::BROKER_SHARED_MEMORY),
                state: RefCell::new(State::New),
                entries: Cell::new(0),
            },
            ctx: PtRegs::default(),
            fs_base: 0,
        })
    }

    fn activate(&self) {
        use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
        // Safety: the kernel holds no references into user memory.
        unsafe {
            self.inner
                .platform
                .switch_address_space(self.inner.address_space)
        }
        .expect("the process's address space stays registered");
        self.inner
            .platform
            .set_arch_specific_register(&ArchSpecificRegister::FsBase, self.fs_base)
            .expect("a saved FS base is valid");
    }

    /// Ring 3 can set any FS base (FSGSBASE is enabled); one that `activate`
    /// could not restore kills a live process.
    fn deactivate(&mut self) {
        use litebox::platform::{ArchSpecificProvider as _, ArchSpecificRegister};
        let fs_base = self
            .inner
            .platform
            .get_arch_specific_register(&ArchSpecificRegister::FsBase)
            .expect("the platform supports FS");
        if litebox_common_linux::arch::is_valid_user_fs_base(fs_base) {
            self.fs_base = fs_base;
        } else {
            self.fs_base = 0;
            let _ = self.kill("invalid FS base");
        }
    }

    fn dead(&self) -> Option<Dead> {
        match *self.inner.state.borrow() {
            State::Dead(dead) => Some(dead),
            _ => None,
        }
    }

    /// Runs the runner until it waits for its first request.
    ///
    /// # Errors
    ///
    /// The process died.
    ///
    /// # Panics
    ///
    /// If called twice.
    pub fn start(&mut self) -> Result<(), Dead> {
        assert_eq!(
            *self.inner.state.borrow(),
            State::New,
            "process already started"
        );
        self.activate();
        // Safety: single CPU, and no other thread runs; `ctx` is this
        // process's context.
        unsafe { litebox_platform_vm_kernel::run_thread_ref(&self.inner, &mut self.ctx) };
        self.deactivate();
        self.settle()?;
        Ok(())
    }

    /// Delivers `request` and returns the reply, both envelopes; the reply's
    /// framing is checked.
    ///
    /// # Errors
    ///
    /// The process is dead or died serving the request.
    ///
    /// # Panics
    ///
    /// If the process was not started, or `request` is longer than
    /// [`MAX_MESSAGE_LEN`].
    pub fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, Dead> {
        if let Some(dead) = self.dead() {
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
        self.activate();
        // Safety: as in `start`.
        unsafe { litebox_platform_vm_kernel::reenter_thread_ref(&self.inner, &mut self.ctx) };
        self.deactivate();
        let reply = self.settle()?;
        log::debug!(
            "request served with {} kernel entries",
            self.inner.entries.get()
        );
        Ok(reply.expect("a waiting process has completed its request"))
    }

    pub fn identity(&self) -> &[u8; IDENTITY_LEN] {
        &self.inner.identity
    }

    /// For services: ends a process that broke their protocol. A dead process
    /// keeps its cause of death.
    pub fn kill(&mut self, reason: &'static str) -> Dead {
        if let Some(dead) = self.dead() {
            return dead;
        }
        self.inner.kill(reason);
        Dead::Killed(reason)
    }

    /// The waiting process's reply, if it has one.
    fn settle(&self) -> Result<Option<Vec<u8>>, Dead> {
        match &mut *self.inner.state.borrow_mut() {
            State::Waiting { reply, .. } => return Ok(reply.take()),
            State::Dead(dead) => return Err(*dead),
            _ => {}
        }
        self.inner.kill("returned to the kernel without waiting");
        Err(self.dead().expect("just killed"))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Safety: the kernel holds no references into user memory, and the
        // process never runs again, so its frames are exclusively owned.
        unsafe { release_address_space(self.inner.platform, self.inner.address_space) };
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
    fn kill(&self, reason: &'static str) {
        log::warn!("killing runner process: {reason}");
        *self.state.borrow_mut() = State::Dead(Dead::Killed(reason));
    }

    fn kill_and_stop(&self, reason: &'static str) -> ContinueOperation {
        self.kill(reason);
        ContinueOperation::Terminate
    }

    fn dispatch(&self, ctx: &PtRegs) -> Flow {
        let Some(id) = CallId::from_raw(ctx.orig_rax as u64) else {
            return Flow::Return(Err(Status::UnknownCall));
        };
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
                *self.state.borrow_mut() = State::Waiting {
                    waiter: Waiter {
                        reply_slot: slot,
                        upcall_entry: (entry != 0).then_some(entry),
                    },
                    reply: None,
                };
                Flow::Stop
            }
            Request::ReplyAndWait(reply) => {
                let State::Serving { upcall_entry } = *self.state.borrow() else {
                    return Flow::Return(Err(Status::Denied));
                };
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
            Request::Map(r) => respond(&r, slot, self.map(&r)),
            Request::Unmap(r) => respond(&r, slot, self.unmap(&r)),
            Request::Protect(r) => respond(&r, slot, self.protect(&r)),
            Request::BrokerHandshake(r) => respond(&r, slot, self.broker.handshake(&r.0)),
            Request::BrokerCall(r) => respond(&r, slot, self.broker.call(&r.0)),
            Request::DeriveKey(r) => respond(&r, slot, self.derive_key(&r)),
            Request::Log(r) => respond(&r, slot, Self::log(&r)),
            Request::Exit(r) => {
                *self.state.borrow_mut() = State::Dead(Dead::Exited(r.code));
                Flow::Stop
            }
        }
    }

    fn managed(addr: u64, len: u64) -> Result<Range<usize>, Status> {
        checked_range(addr, len, RUNNER_MANAGED_MIN..RUNNER_MANAGED_MAX)
    }

    /// W^X. Defense in depth only: the guest can reach the gate anyway.
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

    fn deliver_exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
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
            ctx,
            UpcallKind::Exception,
            u64::from(info.exception.0),
            u64::from(info.error_code),
            fault_address,
        )
    }

    /// Kills the process without an upcall entry, on a nested upcall, or if
    /// the frame cannot be written.
    fn upcall(
        &self,
        ctx: &mut PtRegs,
        kind: UpcallKind,
        vector: u64,
        error_code: u64,
        fault_address: u64,
    ) -> ContinueOperation {
        let entry = match *self.state.borrow() {
            State::Serving { upcall_entry } => upcall_entry,
            _ => None,
        };
        let Some(entry) = entry else {
            return self.kill_and_stop("unhandled exception");
        };
        let stack = layout::UPCALL_STACK;
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
        ContinueOperation::Resume
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

impl EnterShim for Inner {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        *ctx = PtRegs {
            rip: self.entry.trunc(),
            rsp: layout::STACK.end().trunc(),
            rdi: layout::STARTUP_INFO.start.trunc(),
            ..PtRegs::default()
        };
        *self.state.borrow_mut() = State::Starting;
        ContinueOperation::Resume
    }

    fn reenter(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let (waiter, request) = match &mut *self.state.borrow_mut() {
            State::Delivering { waiter, request } => (*waiter, core::mem::take(request)),
            _ => return ContinueOperation::Terminate,
        };
        if Self::deliver(waiter.reply_slot, &request).is_err() {
            return self.kill_and_stop("cannot deliver the request");
        }
        *self.state.borrow_mut() = State::Serving {
            upcall_entry: waiter.upcall_entry,
        };
        ctx.rax = Status::to_raw(Ok(())).trunc();
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.entries.set(self.entries.get() + 1);
        let syscall_at = (ctx.rip as u64).wrapping_sub(2);
        if !(self.gate.start <= syscall_at && ctx.rip as u64 <= self.gate.end) {
            return self.kill_and_stop("syscall outside the gate");
        }
        match self.dispatch(ctx) {
            Flow::Return(result) => {
                if let Err(status) = result {
                    log::debug!("kernel call {:#x} failed: {status:?}", ctx.orig_rax);
                }
                ctx.rax = Status::to_raw(result).trunc();
                ContinueOperation::Resume
            }
            Flow::Stop => ContinueOperation::Terminate,
        }
    }

    fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
        if !info.kernel_mode {
            self.entries.set(self.entries.get() + 1);
        }
        if info.exception == Exception::PAGE_FAULT
            && self
                .mappings
                .demand_page(info.cr2, u64::from(info.error_code))
        {
            return ContinueOperation::Resume;
        }
        if info.kernel_mode {
            // Recovered by the faulting access's exception-table fixup.
            return ContinueOperation::Terminate;
        }
        self.deliver_exception(ctx, info)
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Resume
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
