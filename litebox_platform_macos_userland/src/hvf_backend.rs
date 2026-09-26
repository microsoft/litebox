// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The Hypervisor.framework guest backend: unchanged stock AArch64 Linux code
//! executed at EL0 on real vCPUs, dispatched into the existing Linux shim.
//!
//! Shape:
//!
//! * One process-global, permission-mirrored [`HvfAddressSpace`].  The Linux
//!   shim already runs every guest process's threads in one flat address
//!   space at guest VA == host VA (pre-`exec` fork families take turns by
//!   parking their private memory), and it dereferences guest pointers
//!   directly, so the backend mirrors every guest mapping into the host view
//!   with host permissions = guest permissions minus EXECUTE.
//! * A bounded pool of owner lanes (see [`crate::hvf_vcpu`]).  vCPUs are
//!   interchangeable execution engines: a guest thread's complete
//!   architectural state lives in its `PtRegs` plus a per-thread FP/TLS
//!   context, so any lane can run any thread.  A thread acquires a lane per
//!   run, runs until the next exit (syscall, fault, kick, or time-slice
//!   timer), and releases it, so more guest threads than vCPUs are fine and no
//!   compute-bound thread can starve the others.
//! * Interrupts: [`HvfThreadSlot`] records a pending interrupt and kicks the
//!   lane the thread is currently running on, under one lock, so a kick can
//!   never be lost between "checked for pending" and "entered the guest" (the
//!   lane latches kicks that land while it is still entering).
//! * Every EL0 exception is vectored by the EL1 monitor into one `HVC` exit;
//!   `ESR_EL1` says what happened: `SVC` becomes `EnterShim::syscall`, `WFx`
//!   a yield, everything else `EnterShim::exception`.  A kick becomes
//!   `EnterShim::interrupt`; a timer slice simply re-queues the thread.

use core::cell::RefCell;
use core::fmt;
use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, FixedAddressBehavior, MemoryRegionPermissions,
    PermissionUpdateError, RemapError, SharedPageIoError,
};
use litebox::shim::{ContinueOperation, EnterShim, Exception, ExceptionInfo};
use litebox_common_linux::PtRegs;

use crate::hvf::{
    HvfArchitecturalState, HvfEl1State, HvfError, HvfSimd128, HvfVcpuExit, process_hvf_vm,
};
use crate::hvf_memory::{
    HvfAddressSpace, HvfGuestPermissions, HvfMemory, HvfMemoryError, HvfRangeMutation,
    HvfSharedBackingKey, HvfVcpuMemorySnapshot, HvfVcpuParticipant, process_hvf_memory,
};
use crate::hvf_vcpu::{
    HvfVcpuExitState, HvfVcpuLane, HvfVcpuLaneCancellation, HvfVcpuLaneError, HvfVcpuLaneHandle,
    HvfVcpuRegistry, HvfVcpuRunReservation, HvfVcpuRunResult,
};

const PAGE_SIZE: usize = 16 * 1024;
/// Guest range the shim may use, mirrored from `lib.rs`'s `GUEST_ADDR_MIN/MAX`.
const GUEST_ADDR_MIN: usize = 0x0100_0000_0000;
const GUEST_ADDR_MAX: usize = 0x0000_4000_0000_0000;
/// One guest-executable page holding the `rt_sigreturn` trampoline.  Reported
/// to the shim as reserved so its own allocator never places anything there.
const SIGRETURN_TRAMPOLINE_GVA: usize = GUEST_ADDR_MAX - PAGE_SIZE;
/// `movz x8, #139` (`__NR_rt_sigreturn`); `svc #0`.
const SIGRETURN_TRAMPOLINE: [u32; 2] = [0xd280_1168, 0xd400_0001];
const LANE_QUEUE_CAPACITY: usize = 16;
/// Base GVA and per-worker stride for [`hvf_scheduler_scaling_probe`]'s
/// disjoint per-thread compute pages. Placed well clear of both
/// `GUEST_ADDR_MIN` and the trampoline/lane-starvation scratch page near
/// `GUEST_ADDR_MAX`, with a 1 MiB stride so up to eight single-page workers
/// never share a page.
const SCALING_PROBE_BASE_GVA: usize = GUEST_ADDR_MIN + 0x1000_0000;
const SCALING_PROBE_STRIDE: usize = 0x0010_0000;
const LANE_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
/// Apple Silicon's generic timer runs at 24 MHz and `mach_absolute_time`
/// reads the same counter the guest sees as `CNTVCT_EL0` (offset zero).
const TIMER_TICKS_PER_SECOND: u64 = 24_000_000;
/// One guest time slice before a running thread is re-queued for fairness.
const TIME_SLICE: Duration = Duration::from_millis(10);
/// Bound on one synchronous shootdown (kick running lanes, synchronize idle
/// ones, pump acknowledgements) after a mapping mutation.  Expiry is logged,
/// never fatal: the retirement simply stays deferred.
const SHOOTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const SHOOTDOWN_POLL: Duration = Duration::from_micros(50);
const LANE_REPLACEMENT_POLL: Duration = Duration::from_millis(10);
/// Bound on consecutive attach/run races a single `run_thread` iteration will
/// retry before treating it as a genuine, non-recoverable failure instead of
/// expected concurrent-mutation contention.
const ATTACHMENT_RACE_RETRY_LIMIT: u32 = 1000;
/// Bound on consecutive memory-abort reruns attributed to a stale view before
/// the fault is delivered to the guest regardless.
const STALE_VIEW_RERUN_LIMIT: u32 = 64;
const EC_SHIFT: u64 = 26;
const EC_MASK: u64 = 0x3f;
const EC_WFX: u64 = 0x01;
const EC_SVC64: u64 = 0x15;
const EC_HVC64: u64 = 0x16;
const EC_BRK64: u64 = 0x3c;
/// ESR_EL1 exception classes for a stage-1 abort taken from a lower EL: an
/// instruction fetch and a data access respectively. `dispatch_monitor_exit`
/// already tests both together via its `is_abort` match; `try_resolve_wx_fault`
/// needs to distinguish them (a fetch always wants EXECUTE; a data access's
/// direction depends on the ESR `WnR` bit below).
const EC_INSTRUCTION_ABORT_LOWER_EL: u64 = 0x20;
const EC_DATA_ABORT_LOWER_EL: u64 = 0x24;
/// ESR_EL1\[5:0\]: the Data/Instruction Fault Status Code. The permission-fault
/// codes are `0b0011LL` for translation level `LL` (ARM DDI 0487, ESR_EL1.DFSC/IFSC);
/// masking off the level bits leaves this fixed pattern.
const ESR_FSC_PERMISSION_FAULT: u64 = 0x0c;
const ESR_FSC_PERMISSION_FAULT_MASK: u64 = 0x3c;
/// ESR_EL1\[6\]: Write-not-Read, valid for a Data Abort. Set means the guest's
/// faulting access was a write.
const ESR_WNR: u64 = 1 << 6;
const HVC_IMMEDIATE_MASK: u64 = 0xffff;
const MONITOR_HVC_IMMEDIATE: u64 = 0x4c42;
/// Entry PC of the lower-EL AArch64 synchronous vector. The monitor's first
/// instruction there is its HVC to the host; an authenticated kick can stop the
/// vCPU immediately before that instruction executes.
const MONITOR_LOWER_EL_SYNC_OFFSET: u64 = 0x400;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaneReplacementFailure {
    index: usize,
    generation: u64,
    stage: &'static str,
}

struct LaneMaintenanceFailure {
    failure: LaneReplacementFailure,
    source: HvfBackendError,
}

#[derive(Debug)]
pub enum HvfBackendError {
    Hvf(HvfError),
    Memory(HvfMemoryError),
    // Boxed to keep this error small (`clippy::result_large_err`).
    Lane(Box<HvfVcpuLaneError>),
    AlreadyInstalled,
    NotInstalled,
    LaneAcquisitionTimeout,
    LaneTicketExhausted,
    LanePoolCorrupt {
        index: usize,
    },
    LaneNotReusable {
        index: usize,
    },
    LaneReplacementFailed {
        index: usize,
        generation: u64,
        stage: &'static str,
    },
    LaneMaintenanceThread(std::io::Error),
    Trampoline(&'static str),
    /// An exit the dispatch loop cannot classify (a malformed/unknown HVF
    /// SDK exit, or an exception taken outside the EL1 monitor / not the
    /// monitor's own `HVC`). `source_pc` is the guest architectural PC at
    /// the moment of that exit when the caller has one available (the main
    /// dispatch loop always does, via `HvfArchitecturalState::pc`), so the
    /// resulting fatal-failure message names both the exit's own syndrome
    /// (already inside `HvfVcpuExit`'s `Debug` output) and where in the
    /// guest it happened, rather than only the former.
    UnexpectedExit {
        exit: Box<HvfVcpuExit>,
        source_pc: Option<u64>,
    },
}

impl fmt::Display for HvfBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::Memory(error) => write!(f, "{error}"),
            Self::Lane(error) => write!(f, "{error}"),
            Self::AlreadyInstalled => write!(f, "the HVF guest backend is already installed"),
            Self::NotInstalled => write!(f, "the HVF guest backend is not installed"),
            Self::LaneAcquisitionTimeout => {
                write!(f, "timed out waiting for a free HVF vCPU lane")
            }
            Self::LaneTicketExhausted => {
                write!(f, "the HVF vCPU lane ticket sequence is exhausted")
            }
            Self::LanePoolCorrupt { index } => {
                write!(
                    f,
                    "the HVF vCPU lane pool rejected duplicate or invalid lane {index}"
                )
            }
            Self::LaneNotReusable { index } => {
                write!(
                    f,
                    "HVF vCPU lane {index} left checkout without reaching reusable idle state"
                )
            }
            Self::LaneReplacementFailed {
                index,
                generation,
                stage,
            } => write!(
                f,
                "HVF vCPU lane {index} generation {generation} failed replacement while {stage}"
            ),
            Self::LaneMaintenanceThread(error) => {
                write!(
                    f,
                    "failed to start the HVF lane-maintenance thread: {error}"
                )
            }
            Self::Trampoline(message) => {
                write!(
                    f,
                    "failed to install the guest sigreturn trampoline: {message}"
                )
            }
            Self::UnexpectedExit { exit, source_pc } => match source_pc {
                Some(pc) => write!(
                    f,
                    "the HVF vCPU returned an exit the backend cannot classify at guest PC {pc:#x}: {exit:?}"
                ),
                None => write!(
                    f,
                    "the HVF vCPU returned an exit the backend cannot classify: {exit:?}"
                ),
            },
        }
    }
}

impl std::error::Error for HvfBackendError {}

impl From<HvfError> for HvfBackendError {
    fn from(value: HvfError) -> Self {
        Self::Hvf(value)
    }
}

impl From<HvfMemoryError> for HvfBackendError {
    fn from(value: HvfMemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<HvfVcpuLaneError> for HvfBackendError {
    fn from(value: HvfVcpuLaneError) -> Self {
        Self::Lane(Box::new(value))
    }
}

// ---------------------------------------------------------------------------
// Per-thread guest context.
// ---------------------------------------------------------------------------

/// The parts of a guest thread's architectural state that do not live in its
/// `PtRegs`: the vector file and the thread pointer.  Zero is the correct
/// initial value for a fresh thread (cleared vector file, default rounding
/// mode, no TLS), matching the native backend.
struct HvfThreadContext {
    fp: litebox::platform::FpSimdState64,
    tpidr_el0: u64,
}

impl HvfThreadContext {
    const fn new() -> Self {
        Self {
            fp: litebox::platform::FpSimdState64 {
                v: [0; 32],
                fpsr: 0,
                fpcr: 0,
            },
            tpidr_el0: 0,
        }
    }
}

thread_local! {
    static HVF_THREAD: RefCell<HvfThreadContext> = const { RefCell::new(HvfThreadContext::new()) };
}

pub(crate) fn thread_fp_state() -> litebox::platform::FpSimdState64 {
    HVF_THREAD.with(|context| context.borrow().fp)
}

pub(crate) fn set_thread_fp_state(state: &litebox::platform::FpSimdState64) {
    HVF_THREAD.with(|context| context.borrow_mut().fp = *state);
}

pub(crate) fn thread_tpidr_el0() -> usize {
    HVF_THREAD.with(|context| usize::try_from(context.borrow().tpidr_el0).unwrap_or(0))
}

pub(crate) fn set_thread_tpidr_el0(value: usize) {
    HVF_THREAD.with(|context| context.borrow_mut().tpidr_el0 = value as u64);
}

/// Per-thread interrupt state shared with [`crate::ThreadHandle`], so an
/// interrupt aimed at a thread from any other thread reaches the vCPU it is
/// running on (or is delivered before its next entry).
pub(crate) struct HvfThreadSlot {
    pending: AtomicBool,
    current: Mutex<Option<HvfVcpuLaneCancellation>>,
}

impl HvfThreadSlot {
    pub(crate) const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            current: Mutex::new(None),
        }
    }

    /// Records an interrupt and kicks the lane this thread is currently
    /// running on, if any.  Holding `current` across the kick is what makes
    /// the kick target exactly this thread's run: the run loop only clears
    /// `current` (under the same lock) after its run has returned.
    pub(crate) fn kick(&self) {
        self.pending.store(true, Ordering::Release);
        if let Some(backend) = active() {
            backend.available.notify_all();
        }
        let current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cancellation) = current.as_ref() {
            let _ = cancellation.request();
        }
    }

    fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }
}

// ---------------------------------------------------------------------------
// Backend.
// ---------------------------------------------------------------------------

struct LaneGeneration {
    lane: Mutex<Option<HvfVcpuLane>>,
    handle: HvfVcpuLaneHandle,
    participant: HvfVcpuParticipant,
}

enum LaneSlotState {
    Ready(Arc<LaneGeneration>),
    Retiring(Arc<LaneGeneration>),
    Replacing { old_generation: u64 },
    Failed(LaneReplacementFailure),
}

struct PooledLane {
    state: Mutex<LaneSlotState>,
}

struct LaneMaintenance {
    requested: Mutex<bool>,
    wake: Condvar,
    owner: Mutex<Option<std::thread::JoinHandle<()>>>,
}

struct SharedInitialization {
    initialized: HashMap<usize, Vec<Range<usize>>>,
    in_progress: HashMap<usize, Vec<Range<usize>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationKind {
    /// A new mapping: nothing can be stale, no shootdown.
    Map,
    /// Permissions changed on existing pages.
    Protect,
    /// Existing pages removed.
    Unmap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreeLane {
    index: usize,
    generation: u64,
}

/// Ticket-ordered free-list state: a lane index is served to whichever
/// waiter's own ticket equals `next_serving`, so an acquire admitted after a
/// longer-waiting one can never barge ahead of it, regardless of `Condvar`
/// wakeup order.
struct LanePool {
    free: VecDeque<FreeLane>,
    checked_out: usize,
    retiring: usize,
    failure: Option<LaneReplacementFailure>,
    canceled_tickets: BTreeSet<u64>,
    next_ticket: u64,
    next_serving: u64,
}

pub(crate) struct HvfBackend {
    memory: &'static HvfMemory,
    space: HvfAddressSpace,
    registry: HvfVcpuRegistry,
    el1: HvfEl1State,
    lanes: Vec<PooledLane>,
    free: Mutex<LanePool>,
    available: Condvar,
    lane_maintenance: LaneMaintenance,
    participant_recovery: Mutex<()>,
    trampoline: Range<usize>,
    shared_initialization: Mutex<SharedInitialization>,
    shared_initialization_changed: Condvar,
    /// Running count of settled mutations, for the periodic debug counters.
    mutations: std::sync::atomic::AtomicU64,
    /// Lazy write-xor-execute emulation for a guest `mprotect(RWX)`; see
    /// [`WxToggle`]'s own doc comment.
    wx_toggle: WxToggle,
}

/// Affine custody of one index removed from [`LanePool::free`]. A checkout can
/// move to a worker thread, but it cannot be copied or forgotten accidentally;
/// every return is also checked against the lane owner's quiescent state.
struct LaneLease<'backend> {
    backend: &'backend HvfBackend,
    index: usize,
    generation: Arc<LaneGeneration>,
    return_to_pool: bool,
}

impl LaneLease<'_> {
    const fn index(&self) -> usize {
        self.index
    }

    fn lane(&self) -> &LaneGeneration {
        &self.generation
    }

    fn retire(mut self) {
        let generation = self.generation.handle.generation();
        let requested = self
            .generation
            .lane
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|lane| {
                lane.request_retirement();
                true
            });
        let mut pool = self
            .backend
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut slot = self.backend.lanes[self.index]
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retiring = pool.retiring.checked_add(1);
        let valid = requested
            && pool.failure.is_none()
            && !pool.free.iter().any(|free| free.index == self.index)
            && pool.checked_out != 0
            && retiring.is_some()
            && matches!(
                &*slot,
                LaneSlotState::Ready(current)
                    if current.handle.generation() == generation
                        && Arc::ptr_eq(current, &self.generation)
            );
        if valid {
            let Some(retiring) = retiring else {
                unreachable!();
            };
            *slot = LaneSlotState::Retiring(Arc::clone(&self.generation));
            pool.checked_out -= 1;
            pool.retiring = retiring;
            self.return_to_pool = false;
        }
        drop(slot);
        drop(pool);
        if !valid {
            fatal(
                "retiring a vCPU lane generation",
                &HvfBackendError::LanePoolCorrupt { index: self.index },
            );
        }
        let backend = self.backend;
        drop(self);
        backend.request_lane_maintenance();
    }
}

impl Drop for LaneLease<'_> {
    fn drop(&mut self) {
        if !self.return_to_pool {
            return;
        }
        if !self.generation.handle.is_reusable() {
            fatal(
                "returning a non-quiescent vCPU lane to the pool",
                &HvfBackendError::LaneNotReusable { index: self.index },
            );
        }
        self.backend.release_lane(self.index, &self.generation);
    }
}

/// Extends a lane checkout with the exact cancellation capability and run
/// reservation installed for this thread. Its destructor clears thread
/// authority, settles any unsubmitted reservation, and only then returns a
/// reusable lane to the pool or retires a non-reusable generation.
struct ActiveThreadLaneLease<'backend, 'slot> {
    lease: Option<LaneLease<'backend>>,
    slot: &'slot HvfThreadSlot,
    cancellation: Option<HvfVcpuLaneCancellation>,
    reservation: Option<HvfVcpuRunReservation>,
}

impl<'backend, 'slot> ActiveThreadLaneLease<'backend, 'slot> {
    const fn new(lease: LaneLease<'backend>, slot: &'slot HvfThreadSlot) -> Self {
        Self {
            lease: Some(lease),
            slot,
            cancellation: None,
            reservation: None,
        }
    }

    fn index(&self) -> usize {
        self.lease.as_ref().map_or(usize::MAX, LaneLease::index)
    }

    fn lane(&self) -> &LaneGeneration {
        self.lease.as_ref().map_or_else(
            || {
                fatal(
                    "accessing a released vCPU lane checkout",
                    &HvfBackendError::LanePoolCorrupt { index: usize::MAX },
                )
            },
            LaneLease::lane,
        )
    }

    fn install(
        &mut self,
        reservation: HvfVcpuRunReservation,
        cancellation: HvfVcpuLaneCancellation,
    ) {
        if self.cancellation.is_some() || self.reservation.is_some() {
            fatal(
                "installing duplicate vCPU run authority",
                &HvfBackendError::LanePoolCorrupt {
                    index: self.index(),
                },
            );
        }
        self.cancellation = Some(cancellation);
        self.reservation = Some(reservation);
    }

    fn take_reservation(&mut self) -> HvfVcpuRunReservation {
        self.reservation.take().unwrap_or_else(|| {
            fatal(
                "submitting a missing vCPU run reservation",
                &HvfBackendError::LanePoolCorrupt {
                    index: self.index(),
                },
            )
        })
    }
}

impl Drop for ActiveThreadLaneLease<'_, '_> {
    fn drop(&mut self) {
        if let Some(expected) = self.cancellation.take() {
            let mut current = self
                .slot
                .current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !current
                .as_ref()
                .is_some_and(|installed| installed.is_same_run(&expected))
            {
                drop(current);
                fatal(
                    "clearing a vCPU run cancellation capability",
                    &HvfBackendError::LanePoolCorrupt {
                        index: self.index(),
                    },
                );
            }
            *current = None;
        }

        // Dropping an unsubmitted reservation settles its exact epoch. This is
        // deliberately after clearing `slot.current`, so no new interrupt can
        // acquire stale authority while the reservation is being canceled.
        drop(self.reservation.take());

        let Some(lease) = self.lease.take() else {
            return;
        };
        if lease.generation.handle.is_reusable() {
            drop(lease);
        } else {
            lease.retire();
        }
    }
}

struct OwnedGuestRange<'backend> {
    backend: &'backend HvfBackend,
    range: Range<usize>,
    armed: bool,
}

impl<'backend> OwnedGuestRange<'backend> {
    fn new(backend: &'backend HvfBackend, range: Range<usize>) -> Self {
        Self {
            backend,
            range,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for OwnedGuestRange<'_> {
    fn drop(&mut self) {
        if self.armed {
            let cleaned = self.backend.mutate_with_retry(MutationKind::Unmap, || {
                self.backend.space.unmap_range(self.range.clone())
            });
            if !matches!(cleaned, Ok(true)) {
                fatal(
                    "cleaning up an owned HVF guest range",
                    &HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting),
                );
            }
        }
    }
}

struct ProbeWorker<T> {
    index: usize,
    stop: std::sync::Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<T, HvfVcpuLaneError>>>,
}

impl<T> ProbeWorker<T> {
    fn join(mut self) -> std::thread::Result<Result<T, HvfVcpuLaneError>> {
        match self.thread.take() {
            Some(thread) => thread.join(),
            None => Err(Box::new("HVF probe worker was already joined")),
        }
    }
}

impl<T> Drop for ProbeWorker<T> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl fmt::Debug for HvfBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfBackend")
            .field("address_space", &self.space.id())
            .field("lanes", &self.lanes.len())
            .field("registry", &self.registry)
            .field("trampoline", &self.trampoline)
            .finish_non_exhaustive()
    }
}

static HVF_BACKEND: OnceLock<HvfBackend> = OnceLock::new();
static HVF_BACKEND_INSTALL: Mutex<()> = Mutex::new(());

/// The installed backend, if the runner selected HVF execution.
pub(crate) fn active() -> Option<&'static HvfBackend> {
    HVF_BACKEND.get()
}

/// Live witness that the already-installed HVF backend keeps working with the
/// Seatbelt sandbox up: acquires a pooled lane, runs one real
/// `hv_vcpu_run` round-trip through the EL1 monitor (the same `HVC`-dispatch
/// path every guest syscall uses), and confirms the exit is the expected
/// monitor `HVC`. `hv_vcpu_run`/`hv_vm_map`/etc. are not syscalls, so Seatbelt
/// (which mediates named *operations*, not arbitrary Mach traps) has no
/// policy rule that could deny them either way -- this proves that
/// empirically rather than assuming it, matching how the rest of this module
/// treats every other host-boundary interaction.
///
/// # Errors
///
/// Returns the backend's typed error if no lane is available, the vCPU
/// cannot be attached, or the run does not return the expected monitor exit.
pub fn hvf_sandbox_probe() -> Result<(), HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lease = backend.acquire_lane()?;
    let outcome = (|| {
        let lane = lease.lane();
        let attachment = backend.space.attach_vcpu(&lane.participant)?;
        let state = spin_probe_state(backend.trampoline_address());
        let run = lane.handle.run(attachment, &state)?;
        let hvc = matches!(run.state, HvfVcpuExitState::LowerElMonitor(_))
            && matches!(
                run.exit,
                HvfVcpuExit::Exception(exception)
                    if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_HVC64
                        && exception.syndrome & HVC_IMMEDIATE_MASK == MONITOR_HVC_IMMEDIATE
            );
        if hvc {
            Ok(())
        } else {
            let state = match &run.state {
                HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => {
                    state
                }
            };
            Err(HvfBackendError::UnexpectedExit {
                exit: Box::new(run.exit),
                source_pc: Some(state.pc),
            })
        }
    })();
    drop(lease);
    outcome
}

/// Live, process-terminal-scale witness (it runs for slightly over
/// `LANE_ACQUIRE_TIMEOUT`) that `HvfBackend::acquire_lane`'s 60-second
/// deadline is a genuine bound under real starvation, not dead code: every
/// pooled lane is occupied with a real spinning guest run on its own thread,
/// a fresh acquire is issued against the exhausted pool, and the call must
/// block for approximately the full deadline before returning the typed
/// [`HvfBackendError::LaneAcquisitionTimeout`] -- neither hanging forever nor
/// returning early. Every occupying run is then stopped through authenticated
/// cancellation or the cooperative VTimer fallback, and the pool is proven to
/// return to exactly its baseline free count.
///
/// # Errors
///
/// Returns the backend's typed error if the spin page cannot be mapped, a
/// lane cannot be occupied, the timeout does not fire within a bounded
/// margin past the deadline, or the pool fails to drain back to baseline.
pub fn hvf_lane_starvation_probe() -> Result<HvfLaneStarvationReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let spin_range = backend.trampoline.end..backend.trampoline.end + PAGE_SIZE;
    let mapped = backend.space.map_range(
        spin_range.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        false,
    )?;
    let _spin_mapping = OwnedGuestRange::new(backend, spin_range.clone());
    backend.space.defer_retirement(mapped.retirement)?;
    // `b .`: spins in place until canceled.
    let spin_instruction: u32 = 0x1400_0000;
    // SAFETY: `spin_range` was just mapped read/write in the mirrored host
    // view and nothing else references it yet.
    unsafe {
        core::ptr::copy_nonoverlapping(
            spin_instruction.to_le_bytes().as_ptr(),
            spin_range.start as *mut u8,
            4,
        );
    }
    let executable = backend.space.protect_range(
        spin_range.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
    )?;
    backend.space.defer_retirement(executable.retirement)?;
    backend.space.pump_retirements()?;

    let lane_count = backend.lanes.len();

    (|| {
        let mut occupied: Vec<ProbeWorker<HvfVcpuRunResult>> = Vec::new();
        occupied
            .try_reserve_exact(lane_count)
            .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
        for _ in 0..lane_count {
            let lease = backend.acquire_lane()?;
            let index = lease.index();
            let lane = lease.lane();
            let attachment = backend.space.attach_vcpu(&lane.participant)?;
            let state = spin_probe_state(spin_range.start);
            let handle = lane.handle.clone();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let worker_stop = std::sync::Arc::clone(&stop);
            let thread = std::thread::Builder::new()
                .name("litebox-hvf-lane-starvation-occupier".to_owned())
                .spawn(move || {
                    let lane = lease.lane();
                    // time-slicing: no single `hv_vcpu_run`/command round trip
                    // is held open anywhere near `COMMAND_WAIT_TIMEOUT` (30s),
                    // so the lane can genuinely stay occupied for the full 60s
                    // `LANE_ACQUIRE_TIMEOUT` this witness needs, exactly as a
                    // real long-running compute-bound guest thread would.
                    // `backend` is `&'static`, so re-attaching across time
                    // slices from inside this thread needs no extra lifetime
                    // plumbing.
                    let mut attachment = attachment;
                    let mut state = state;
                    loop {
                        let deadline = time_slice_deadline();
                        let run = handle.run_with_deadline(attachment, &state, deadline)?;
                        match (run.exit, run.state) {
                            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(next)) => {
                                if worker_stop.load(Ordering::Acquire) {
                                    return Ok(run);
                                }
                                state = next;
                                attachment = backend.space.attach_vcpu(&lane.participant)?;
                            }
                            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_)) => {
                                return Ok(run);
                            }
                            _ => return Err(invalid_run_state(&run)),
                        }
                    }
                })
                .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
            occupied.push(ProbeWorker {
                index,
                stop,
                thread: Some(thread),
            });
        }
        // Every lane is now genuinely held (popped from the free list, with a
        // real run in progress on it) rather than merely marked busy, so this
        // acquire has no lane to receive even if scheduling is adversarial.
        let started = Instant::now();
        let acquisition = backend.acquire_lane();
        let elapsed = started.elapsed();
        let timed_out = matches!(acquisition, Err(HvfBackendError::LaneAcquisitionTimeout));
        // Bounded margin (not exact equality) for scheduling jitter around a
        // real wall-clock deadline; still tight enough to prove the const is
        // honored rather than, say, a near-zero or unbounded wait.
        let timing_bounded = elapsed >= LANE_ACQUIRE_TIMEOUT
            && elapsed < LANE_ACQUIRE_TIMEOUT.saturating_add(Duration::from_secs(10));
        if let Ok(lease) = acquisition {
            // Should not happen given every lane is genuinely held, but leave
            // no lane silently checked out if it somehow does.
            drop(lease);
        }

        let mut cancel_errors: Vec<String> = Vec::new();
        let mut cancellations = Vec::new();
        for worker in &occupied {
            let cancellation = backend.current_lane_handle(worker.index)?.cancellation();
            let cancellation_stop = std::sync::Arc::clone(&worker.stop);
            match std::thread::Builder::new()
                .name("litebox-hvf-lane-starvation-canceller".to_owned())
                .spawn(move || {
                    let result = cancellation.cancel();
                    if result.is_err() {
                        cancellation_stop.store(true, Ordering::Release);
                    }
                    result
                }) {
                Ok(thread) => {
                    cancellations.push((std::sync::Arc::clone(&worker.stop), thread));
                }
                Err(error) => {
                    worker.stop.store(true, Ordering::Release);
                    cancel_errors.push(format!("failed to spawn cancellation thread: {error}"));
                }
            }
        }
        for (stop, cancellation) in cancellations {
            match cancellation.join() {
                Ok(
                    Ok(_)
                    | Err(
                        HvfVcpuLaneError::CancellationTooLate { .. }
                        | HvfVcpuLaneError::VcpuNotRunning,
                    ),
                ) => {}
                Ok(Err(error)) => cancel_errors.push(format!("{error}")),
                Err(_) => {
                    stop.store(true, Ordering::Release);
                    cancel_errors.push("cancellation thread panicked".to_owned());
                }
            }
        }
        let mut run_errors: Vec<String> = Vec::new();
        for worker in occupied {
            let stop = std::sync::Arc::clone(&worker.stop);
            match worker.join() {
                Ok(Ok(run)) => {
                    let clean = matches!(
                        (run.exit, run.state),
                        (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
                    ) || stop.load(Ordering::Acquire)
                        && matches!(
                            (run.exit, run.state),
                            (
                                HvfVcpuExit::VtimerActivated,
                                HvfVcpuExitState::DirectGuest(_)
                            )
                        );
                    if !clean {
                        run_errors.push(format!("unexpected exit: {:?}", run.exit));
                    }
                }
                Ok(Err(error)) => run_errors.push(format!("{error}")),
                Err(_) => run_errors.push("occupier thread panicked".to_owned()),
            }
        }
        let pool_at_baseline = {
            let pool = backend
                .free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            lane_pool_at_baseline(&pool, lane_count)
        };
        Ok(HvfLaneStarvationReport {
            lane_count,
            timed_out,
            timing_bounded,
            elapsed_millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            occupying_runs_stopped_cleanly: cancel_errors.is_empty() && run_errors.is_empty(),
            cancel_errors,
            run_errors,
            pool_at_baseline,
        })
    })()
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfLaneStarvationReport {
    pub lane_count: usize,
    pub timed_out: bool,
    pub timing_bounded: bool,
    pub elapsed_millis: u64,
    /// Every occupying run stopped through either an authenticated cancellation
    /// or the cooperative VTimer fallback, without an owner-lane error.
    pub occupying_runs_stopped_cleanly: bool,
    pub cancel_errors: Vec<String>,
    pub run_errors: Vec<String>,
    pub pool_at_baseline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfLaneReplacementReport {
    pub lane_count: usize,
    pub lane_index: usize,
    pub retired_generation: u64,
    pub replacement_generation: u64,
    pub old_generation_non_reusable: bool,
    pub cancellation_authority_cleared: bool,
    pub owner_reaped_and_slot_replaced: bool,
    pub replacement_hvc_verified: bool,
    pub pool_at_baseline: bool,
}

/// Deterministically exercises the installed backend's complete generational
/// lane-replacement path. Every pooled generation is checked out so that, once
/// one target is made non-reusable and retired through
/// `ActiveThreadLaneLease`, the next ordinary acquisition can only receive a
/// newer generation published into that exact slot.
///
/// # Errors
///
/// Returns the backend's typed error if the pool does not begin or end at its
/// exact baseline, run authority is not cleared, retirement or replacement does
/// not preserve the target slot's identity, or the replacement cannot execute
/// the normal monitor-HVC path.
pub fn hvf_lane_replacement_probe() -> Result<HvfLaneReplacementReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lane_count = backend.lanes.len();
    {
        let pool = backend
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !lane_pool_at_baseline(&pool, lane_count) {
            return Err(HvfBackendError::LanePoolCorrupt { index: usize::MAX });
        }
    }

    let mut held = Vec::new();
    held.try_reserve_exact(lane_count)
        .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
    for _ in 0..lane_count {
        held.push(backend.acquire_lane()?);
    }
    let target = held
        .pop()
        .ok_or(HvfBackendError::LanePoolCorrupt { index: usize::MAX })?;
    let lane_index = target.index();
    let retired_generation = target.lane().handle.generation();

    let slot = HvfThreadSlot::new();
    let mut active = ActiveThreadLaneLease::new(target, &slot);
    {
        let mut current = slot
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_some() {
            return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
        }
        let reservation = active.lane().handle.reserve_run()?;
        let cancellation = reservation.cancellation();
        active.install(reservation, cancellation.clone());
        *current = Some(cancellation);
    }

    let retirement_requested = active
        .lane()
        .lane
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_some_and(|lane| {
            lane.request_retirement();
            true
        });
    let old_generation_non_reusable = retirement_requested && !active.lane().handle.is_reusable();

    // This is the behavior under witness: clear the exact thread authority,
    // settle the still-unsubmitted reservation, and select retirement rather
    // than the ordinary reusable-lane return path.
    drop(active);
    let cancellation_authority_cleared = slot
        .current
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_none();
    if !old_generation_non_reusable || !cancellation_authority_cleared {
        return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
    }

    // Every other slot remains checked out in `held`; successful acquisition
    // therefore requires maintenance to reap and replace this exact slot.
    let replacement = backend.acquire_lane()?;
    let replacement_generation = replacement.lane().handle.generation();
    let owner_reaped_and_slot_replaced =
        replacement.index() == lane_index && replacement_generation > retired_generation;
    if !owner_reaped_and_slot_replaced {
        return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
    }

    let run = {
        let lane = replacement.lane();
        let attachment = backend.space.attach_vcpu(&lane.participant)?;
        let state = spin_probe_state(backend.trampoline_address());
        lane.handle.run(attachment, &state)?
    };
    let replacement_hvc_verified = matches!(run.state, HvfVcpuExitState::LowerElMonitor(_))
        && matches!(
            run.exit,
            HvfVcpuExit::Exception(exception)
                if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_HVC64
                    && exception.syndrome & HVC_IMMEDIATE_MASK == MONITOR_HVC_IMMEDIATE
        );
    if !replacement_hvc_verified {
        let state = match &run.state {
            HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => state,
        };
        return Err(HvfBackendError::UnexpectedExit {
            exit: Box::new(run.exit),
            source_pc: Some(state.pc),
        });
    }

    drop(replacement);
    drop(held);
    let pool_at_baseline = {
        let pool = backend
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lane_pool_at_baseline(&pool, lane_count)
    };
    if !pool_at_baseline {
        return Err(HvfBackendError::LanePoolCorrupt { index: lane_index });
    }

    Ok(HvfLaneReplacementReport {
        lane_count,
        lane_index,
        retired_generation,
        replacement_generation,
        old_generation_non_reusable,
        cancellation_authority_cleared,
        owner_reaped_and_slot_replaced,
        replacement_hvc_verified,
        pool_at_baseline,
    })
}

/// Number of queue-to-wake trials [`hvf_scheduler_latency_probe`] measures.
const SCHEDULER_LATENCY_TRIALS: usize = 2000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSchedulerLatencyReport {
    pub lane_count: usize,
    pub trials: usize,
    pub p50_nanos: u64,
    pub p99_nanos: u64,
    pub max_nanos: u64,
    pub min_nanos: u64,
    pub mean_nanos: u64,
    /// Whether the trailing half of the sample is not systematically slower
    /// than the leading half (a coarse, cheap growth check: unbounded
    /// wakeup latency would show up as a rising trend across trials).
    pub no_growth_trend: bool,
    pub pool_at_baseline: bool,
}

/// Live witness measuring the real wall-clock latency from "a lane is handed
/// back to the pool" (`release_lane`, the moment `acquire_lane`'s `Condvar`
/// is notified) to "a concurrently blocked waiter wakes and observes it"
/// (`acquire_lane` returning), across many trials. This is the queue/wakeup
/// path `HvfBackend::run_thread` depends on for every guest syscall return
/// and every VTimer re-queue, so its latency distribution bounds how quickly
/// an idle lane picks up newly queued guest work.
///
/// One lane is held out of the pool as a dedicated "server": each trial
/// spawns a fresh waiter thread that blocks in `acquire_lane` (the pool is
/// otherwise fully free, so the waiter always contends on the `Condvar`
/// rather than an already-idle fast path), the main thread times a short
/// settle, releases the held-out lane, and the waiter reports the elapsed
/// time from just before `release_lane` to its own `acquire_lane` return.
/// p50/p99/max/min/mean are reported in nanoseconds; a monotonic bound is
/// not asserted (real OS scheduling jitter varies by load) but growth across
/// the trial sequence would indicate an unbounded/leaking wakeup path, which
/// this checks for directly.
///
/// # Errors
///
/// Returns the backend's typed error if no lane is available or a waiter
/// thread cannot be spawned or joined.
pub fn hvf_scheduler_latency_probe() -> Result<HvfSchedulerLatencyReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lane_count = backend.lanes.len();
    // Hold every lane but one out of the pool for the duration of the probe,
    // so each trial's waiter genuinely blocks on the `Condvar` (a free lane
    // elsewhere in the pool would let `acquire_lane` return immediately
    // without ever reaching the wait path this probe measures).
    let mut held = Vec::new();
    for _ in 0..lane_count.saturating_sub(1) {
        held.push(backend.acquire_lane()?);
    }
    let mut samples = Vec::with_capacity(SCHEDULER_LATENCY_TRIALS);
    let outcome: Result<(), HvfBackendError> = (|| {
        for _ in 0..SCHEDULER_LATENCY_TRIALS {
            let served = backend.acquire_lane()?;
            let start_barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let waiter_barrier = std::sync::Arc::clone(&start_barrier);
            let thread = std::thread::Builder::new()
                .name("litebox-hvf-scheduler-latency-waiter".to_owned())
                .spawn(move || {
                    waiter_barrier.wait();
                    let started = Instant::now();
                    let index = backend.acquire_lane();
                    let elapsed = started.elapsed();
                    (index, elapsed)
                })
                .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
            start_barrier.wait();
            // A short, fixed settle so the waiter thread has genuinely
            // reached `acquire_lane`'s wait before the lane is released;
            // this is scheduling slack for the waiter to start, not part of
            // the measured interval (the waiter's own `Instant::now()` is
            // taken after the barrier, immediately before it calls
            // `acquire_lane`).
            std::thread::sleep(Duration::from_micros(200));
            drop(served);
            let (lease, elapsed) = thread
                .join()
                .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
            drop(lease?);
            samples.push(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        }
        Ok(())
    })();
    drop(held);
    outcome?;

    // Trend check first, over trial order (the sequence as collected, before
    // sorting destroys that order): compare the mean of the first half of
    // the run to the mean of the second half. A genuinely bounded wakeup
    // path shows no systematic rise as the process keeps running; this
    // rejects only a clear rise (second half more than 50% above the
    // first), tolerant of ordinary jitter.
    let no_growth_trend = if samples.len() < 20 {
        true
    } else {
        let half = samples.len() / 2;
        let mean_of = |slice: &[u64]| -> u128 {
            slice.iter().map(|&value| u128::from(value)).sum::<u128>() / slice.len() as u128
        };
        let first_half_mean = mean_of(&samples[..half]);
        let second_half_mean = mean_of(&samples[half..]);
        second_half_mean <= first_half_mean.saturating_mul(3) / 2 + 1
    };

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let n = sorted.len().max(1);
    let percentile = |p: usize| sorted[(n.saturating_mul(p) / 100).min(n - 1)];
    let min_nanos = *sorted.first().unwrap_or(&0);
    let max_nanos = *sorted.last().unwrap_or(&0);
    let mean_nanos = if sorted.is_empty() {
        0
    } else {
        u64::try_from(sorted.iter().map(|&value| u128::from(value)).sum::<u128>() / n as u128)
            .unwrap_or(u64::MAX)
    };
    let pool = backend
        .free
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pool_at_baseline = lane_pool_at_baseline(&pool, lane_count);
    drop(pool);
    Ok(HvfSchedulerLatencyReport {
        lane_count,
        trials: sorted.len(),
        p50_nanos: percentile(50),
        p99_nanos: percentile(99),
        max_nanos,
        min_nanos,
        mean_nanos,
        no_growth_trend,
        pool_at_baseline,
    })
}

/// Wall-clock budget each concurrency level runs for in
/// [`hvf_scheduler_scaling_probe`].
const SCALING_RUN_DURATION: Duration = Duration::from_millis(1500);
/// `add x0, x0, #1` ; `b <self>` : an unbounded ALU loop that genuinely
/// retires instructions each pass (unlike `hvf_lane_starvation_probe`'s
/// `b .`, which never advances architectural state), so time-sliced re-entry
/// counts below are real compute progress, not mere occupancy.
const COMPUTE_LOOP: [u32; 2] = [0x9100_0000, 0x1400_0000];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSchedulerScalingLevel {
    pub concurrency: usize,
    /// Total VTimer time-slice re-entries observed across all threads at
    /// this concurrency, summed -- the scheduler's own unit of guest compute
    /// progress, independent of host clock-source quirks.
    pub total_slices: u64,
    pub elapsed_millis: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HvfSchedulerScalingReport {
    pub lane_count: usize,
    pub levels: Vec<HvfSchedulerScalingLevel>,
    /// `levels[i].total_slices` throughput relative to the N=1 level, i.e.
    /// the measured speedup at each concurrency (near-`N` up to the lane
    /// count would indicate concurrent, non-serialized progress).
    pub speedup: Vec<f64>,
    pub pool_at_baseline: bool,
}

/// Live witness measuring real wall-clock scaling of independent,
/// non-yielding compute-bound guest threads: for each concurrency level in
/// `1, 2, 4, ..` up to the lane pool's own size, `concurrency` guest threads
/// each spin an unbounded ALU loop (`COMPUTE_LOOP`) on their own disjoint
/// mapped page for a fixed wall-clock budget, re-attaching after each VTimer
/// slice exit exactly as `HvfBackend::run_thread` does in production. The
/// summed slice count at each level is the scheduler's own throughput unit;
/// near-linear growth with `concurrency` (up to the real core/lane count) is
/// the direct live proof that independent vCPUs make concurrent progress on
/// real cores rather than serializing behind a shared lock -- the clearest
/// evidence for the "no global lock across `hv_vcpu_run`" invariant, since a
/// held lock would flatten this curve regardless of core count.
///
/// # Errors
///
/// Returns the backend's typed error if a scratch page cannot be mapped, a
/// lane cannot be occupied, or an occupier thread cannot be spawned/joined.
pub fn hvf_scheduler_scaling_probe() -> Result<HvfSchedulerScalingReport, HvfBackendError> {
    let backend = active().ok_or(HvfBackendError::NotInstalled)?;
    let lane_count = backend.lanes.len();
    let mut levels_to_run: Vec<usize> = [1usize, 2, 4, 8]
        .into_iter()
        .filter(|&n| n <= lane_count)
        .collect();
    if levels_to_run.is_empty() {
        levels_to_run.push(lane_count.max(1));
    }

    let mut levels = Vec::with_capacity(levels_to_run.len());
    for &concurrency in &levels_to_run {
        let mut ranges = Vec::with_capacity(concurrency);
        let mut owned_ranges = Vec::with_capacity(concurrency);
        for slot in 0..concurrency {
            let base = SCALING_PROBE_BASE_GVA + slot * SCALING_PROBE_STRIDE;
            let range = base..base + PAGE_SIZE;
            let mapped = backend.space.map_range(
                range.clone(),
                HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                false,
            )?;
            let owned = OwnedGuestRange::new(backend, range.clone());
            backend.space.defer_retirement(mapped.retirement)?;
            let mut bytes = [0u8; COMPUTE_LOOP.len() * 4];
            for (index, instruction) in COMPUTE_LOOP.iter().enumerate() {
                bytes[index * 4..index * 4 + 4].copy_from_slice(&instruction.to_le_bytes());
            }
            // SAFETY: `range` was just mapped read/write in the mirrored
            // host view and nothing else references it yet.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), range.start as *mut u8, bytes.len());
            }
            let executable = backend.space.protect_range(
                range.clone(),
                HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            )?;
            backend.space.defer_retirement(executable.retirement)?;
            ranges.push(range);
            owned_ranges.push(owned);
        }
        backend.space.pump_retirements()?;

        let mut occupied: Vec<ProbeWorker<u64>> = Vec::with_capacity(concurrency);
        for range in &ranges {
            let lease = backend.acquire_lane()?;
            let index = lease.index();
            let lane = lease.lane();
            let attachment = backend.space.attach_vcpu(&lane.participant)?;
            let state = spin_probe_state(range.start);
            let handle = lane.handle.clone();
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let worker_stop = std::sync::Arc::clone(&stop);
            let thread = std::thread::Builder::new()
                .name("litebox-hvf-scheduler-scaling-worker".to_owned())
                .spawn(move || -> Result<u64, HvfVcpuLaneError> {
                    let lane = lease.lane();
                    let mut attachment = attachment;
                    let mut state = state;
                    let deadline = Instant::now() + SCALING_RUN_DURATION;
                    let mut slices = 0u64;
                    loop {
                        let vtimer_deadline = time_slice_deadline();
                        let run = handle.run_with_deadline(attachment, &state, vtimer_deadline)?;
                        match (run.exit, run.state) {
                            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(next)) => {
                                slices += 1;
                                if worker_stop.load(Ordering::Acquire) || Instant::now() >= deadline
                                {
                                    // Cooperative stop: the loop simply
                                    // declines to re-enter after this slice
                                    // rather than needing a cross-thread
                                    // cancel, which keeps every worker's
                                    // timing symmetric across concurrency
                                    // levels.
                                    return Ok(slices);
                                }
                                state = next;
                                attachment = backend.space.attach_vcpu(&lane.participant)?;
                            }
                            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_)) => {
                                return Ok(slices);
                            }
                            _ => return Err(invalid_run_state(&run)),
                        }
                    }
                })
                .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
            occupied.push(ProbeWorker {
                index,
                stop,
                thread: Some(thread),
            });
        }

        let started = Instant::now();
        let mut total_slices = 0u64;
        let mut join_errors: Vec<String> = Vec::new();
        for worker in occupied {
            match worker.join() {
                Ok(Ok(slices)) => total_slices += slices,
                Ok(Err(error)) => join_errors.push(format!("{error}")),
                Err(_) => join_errors.push("scaling worker thread panicked".to_owned()),
            }
        }
        let elapsed = started.elapsed();
        drop(owned_ranges);
        if !join_errors.is_empty() {
            litebox_util_log::warn!(
                concurrency:? = concurrency, errors:? = join_errors;
                "HVF scheduler scaling probe worker error"
            );
        }
        levels.push(HvfSchedulerScalingLevel {
            concurrency,
            total_slices,
            elapsed_millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        });
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "a throughput ratio for a diagnostic report; counts beyond 2^53 are not a concern"
    )]
    let baseline_throughput = levels.first().map_or(0.0, |level| {
        if level.elapsed_millis == 0 {
            0.0
        } else {
            level.total_slices as f64 / level.elapsed_millis as f64
        }
    });
    #[expect(
        clippy::cast_precision_loss,
        reason = "a throughput ratio for a diagnostic report; counts beyond 2^53 are not a concern"
    )]
    let speedup = levels
        .iter()
        .map(|level| {
            if level.elapsed_millis == 0 || baseline_throughput == 0.0 {
                0.0
            } else {
                (level.total_slices as f64 / level.elapsed_millis as f64) / baseline_throughput
            }
        })
        .collect();

    let pool = backend
        .free
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pool_at_baseline = lane_pool_at_baseline(&pool, lane_count);
    drop(pool);

    Ok(HvfSchedulerScalingReport {
        lane_count,
        levels,
        speedup,
        pool_at_baseline,
    })
}

fn advance_canceled_tickets(pool: &mut LanePool) -> Result<(), HvfBackendError> {
    pool.canceled_tickets
        .retain(|ticket| *ticket >= pool.next_serving);
    while pool.canceled_tickets.remove(&pool.next_serving) {
        pool.next_serving = pool
            .next_serving
            .checked_add(1)
            .ok_or(HvfBackendError::LaneTicketExhausted)?;
    }
    Ok(())
}

fn lane_pool_at_baseline(pool: &LanePool, lane_count: usize) -> bool {
    pool.failure.is_none()
        && pool.canceled_tickets.is_empty()
        && pool.checked_out == 0
        && pool.retiring == 0
        && pool.next_serving == pool.next_ticket
        && pool.free.len() == lane_count
        && (0..lane_count)
            .all(|index| pool.free.iter().filter(|free| free.index == index).count() == 1)
}

fn lane_replacement_error(failure: LaneReplacementFailure) -> HvfBackendError {
    HvfBackendError::LaneReplacementFailed {
        index: failure.index,
        generation: failure.generation,
        stage: failure.stage,
    }
}

fn invalid_run_state(run: &HvfVcpuRunResult) -> HvfVcpuLaneError {
    let state = match &run.state {
        HvfVcpuExitState::DirectGuest(state) | HvfVcpuExitState::LowerElMonitor(state) => state,
    };
    HvfVcpuLaneError::InvalidExecutionState {
        exit: Box::new(run.exit),
        state: Box::new(state.into()),
    }
}

/// A minimal architectural state whose PC is the guest-executable sigreturn
/// trampoline (`svc #0`), the one guest page every HVF backend installation
/// already guarantees is mapped RX -- so this witness needs no address space
/// of its own and cannot race any real guest thread's own mappings.
fn spin_probe_state(pc: usize) -> HvfArchitecturalState {
    let mut state = HvfArchitecturalState::default();
    state.pc = pc as u64;
    state.cpsr = 0xa000_0000;
    state.sp_el0 = 0;
    state.sp_el1 = 0;
    state
}

/// Installs the process-global HVF backend.  Must run before the shim maps
/// anything: every later page-management call is routed through it.
pub(crate) fn install() -> Result<&'static HvfBackend, HvfBackendError> {
    let _installation = HVF_BACKEND_INSTALL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if HVF_BACKEND.get().is_some() {
        return Err(HvfBackendError::AlreadyInstalled);
    }
    let backend = HvfBackend::create()?;
    litebox_util_log::info!(
        lanes:? = backend.lanes.len(),
        capacity:? = backend.registry.capacity(),
        trampoline:? = backend.trampoline.start;
        "HVF guest backend installed: unchanged stock code will execute on real vCPUs"
    );
    match HVF_BACKEND.set(backend) {
        Ok(()) => {}
        Err(_backend) => fatal(
            "publishing the process-global HVF backend",
            &HvfBackendError::AlreadyInstalled,
        ),
    }
    let backend = HVF_BACKEND.get().unwrap_or_else(|| {
        fatal(
            "recovering the process-global HVF backend after publication",
            &HvfBackendError::NotInstalled,
        )
    });
    if let Err(error) = backend.start_lane_maintenance() {
        // Publication is a process-global one-way transition: `active()` may
        // already have handed this backend to another thread, so a maintenance
        // owner that cannot be established is not a recoverable installation
        // error.  Abort instead of returning an error that could invite a
        // native fallback while `HVF_BACKEND` remains permanently installed.
        fatal(
            "starting lane maintenance after publishing the HVF backend",
            &error,
        );
    }
    Ok(backend)
}

impl HvfBackend {
    fn create() -> Result<Self, HvfBackendError> {
        let memory = process_hvf_memory()?;
        let space = memory.create_mirrored_address_space()?;
        let registry = HvfVcpuRegistry::process()?;
        let snapshot = space.vcpu_snapshot()?;
        let el1 = HvfEl1State::linux_user(
            snapshot.synchronization_ttbr0_el1,
            snapshot.regime.tcr_el1,
            u64::from(snapshot.regime.mair_attr0),
        );
        let parallelism = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        // `LITEBOX_HVF_LANES=<n>` caps the vCPU lane pool below the host's
        // parallelism. A diagnostic knob, not a tuning one: a single lane
        // serializes all guest execution, which is the cleanest way to tell
        // a genuine multi-core race (vanishes at 1) from a timing-independent
        // bug (persists at 1) without touching any other code path. Values
        // outside [1, parallelism] are clamped; unparsable values are ignored
        // with a warning rather than refusing to start.
        let requested_lanes = std::env::var("LITEBOX_HVF_LANES")
            .ok()
            .and_then(|raw| if let Ok(n) = raw.trim().parse::<usize>() { Some(n) } else {
                litebox_util_log::warn!(raw:? = raw; "LITEBOX_HVF_LANES is not a number; ignoring");
                None
            })
            .map(|n| n.clamp(1, parallelism.max(1)));
        let lane_count = requested_lanes
            .unwrap_or(parallelism)
            .max(1)
            .min(usize::try_from(registry.capacity()).unwrap_or(1));
        if requested_lanes.is_some() {
            litebox_util_log::warn!(lane_count, parallelism; "LITEBOX_HVF_LANES override in effect");
        }
        let mut lanes = Vec::new();
        lanes
            .try_reserve_exact(lane_count)
            .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
        let mut free = Vec::new();
        free.try_reserve_exact(lane_count)
            .map_err(|_| HvfBackendError::from(HvfVcpuLaneError::RegistryAccounting))?;
        for index in 0..lane_count {
            let generation = Self::create_lane_generation(&registry, &space, el1)?;
            free.push(FreeLane {
                index,
                generation: generation.handle.generation(),
            });
            lanes.push(PooledLane {
                state: Mutex::new(LaneSlotState::Ready(generation)),
            });
        }
        let backend = Self {
            memory,
            space,
            registry,
            el1,
            lanes,
            free: Mutex::new(LanePool {
                free: VecDeque::from(free),
                checked_out: 0,
                retiring: 0,
                failure: None,
                canceled_tickets: BTreeSet::new(),
                next_ticket: 0,
                next_serving: 0,
            }),
            available: Condvar::new(),
            lane_maintenance: LaneMaintenance {
                requested: Mutex::new(false),
                wake: Condvar::new(),
                owner: Mutex::new(None),
            },
            participant_recovery: Mutex::new(()),
            trampoline: SIGRETURN_TRAMPOLINE_GVA..SIGRETURN_TRAMPOLINE_GVA + PAGE_SIZE,
            shared_initialization: Mutex::new(SharedInitialization {
                initialized: HashMap::new(),
                in_progress: HashMap::new(),
            }),
            shared_initialization_changed: Condvar::new(),
            mutations: std::sync::atomic::AtomicU64::new(0),
            wx_toggle: WxToggle::default(),
        };
        backend.install_trampoline()?;
        Ok(backend)
    }

    fn create_lane_generation(
        registry: &HvfVcpuRegistry,
        space: &HvfAddressSpace,
        el1: HvfEl1State,
    ) -> Result<Arc<LaneGeneration>, HvfBackendError> {
        let lane = registry.create_lane(LANE_QUEUE_CAPACITY)?;
        let handle = lane.handle();
        handle.initialize_el1(el1)?;
        handle.set_vtimer(true, 0)?;
        let participant = space.register_vcpu_participant(handle.participant_capability()?)?;
        Ok(Arc::new(LaneGeneration {
            lane: Mutex::new(Some(lane)),
            handle,
            participant,
        }))
    }

    fn start_lane_maintenance(&'static self) -> Result<(), HvfBackendError> {
        let mut owner = self
            .lane_maintenance
            .owner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if owner.is_some() {
            return Err(HvfBackendError::LanePoolCorrupt { index: usize::MAX });
        }
        match std::thread::Builder::new()
            .name("litebox-hvf-lane-maintenance".to_owned())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.lane_maintenance_loop();
                }));
                if outcome.is_err() {
                    self.fail_lane_pool(LaneReplacementFailure {
                        index: usize::MAX,
                        generation: 0,
                        stage: "running lane maintenance",
                    });
                }
            }) {
            Ok(thread) => {
                *owner = Some(thread);
                Ok(())
            }
            Err(error) => {
                drop(owner);
                self.fail_lane_pool(LaneReplacementFailure {
                    index: usize::MAX,
                    generation: 0,
                    stage: "starting lane maintenance",
                });
                Err(HvfBackendError::LaneMaintenanceThread(error))
            }
        }
    }

    fn request_lane_maintenance(&self) {
        let mut requested = self
            .lane_maintenance
            .requested
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *requested = true;
        drop(requested);
        self.lane_maintenance.wake.notify_one();
    }

    fn retiring_lane_count(&self) -> usize {
        self.free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retiring
    }

    fn lane_maintenance_loop(&'static self) {
        loop {
            let mut requested = self
                .lane_maintenance
                .requested
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*requested {
                requested = self
                    .lane_maintenance
                    .wake
                    .wait(requested)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            *requested = false;
            drop(requested);
            while self.retiring_lane_count() != 0 {
                let mut progressed = false;
                for index in 0..self.lanes.len() {
                    match self.repair_retired_lane(index) {
                        Ok(repaired) => progressed |= repaired,
                        Err(error) => {
                            litebox_util_log::error!(
                                index:? = error.failure.index,
                                generation:? = error.failure.generation,
                                stage:? = error.failure.stage,
                                error:% = error.source;
                                "HVF lane replacement failed"
                            );
                            self.fail_lane_pool(error.failure);
                            return;
                        }
                    }
                }
                if !progressed && self.retiring_lane_count() != 0 {
                    let requested = self
                        .lane_maintenance
                        .requested
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (mut requested, _) = self
                        .lane_maintenance
                        .wake
                        .wait_timeout(requested, LANE_REPLACEMENT_POLL)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *requested = false;
                }
            }
        }
    }

    fn repair_retired_lane(&self, index: usize) -> Result<bool, Box<LaneMaintenanceFailure>> {
        let generation = {
            let slot = self.lanes[index]
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match &*slot {
                LaneSlotState::Retiring(generation) => Arc::clone(generation),
                _ => return Ok(false),
            }
        };
        let old_generation = generation.handle.generation();
        if Arc::strong_count(&generation) != 2 {
            return Ok(false);
        }
        let reaped = {
            let mut lane = generation
                .lane
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lane = lane.as_mut().ok_or(LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "finding retired lane ownership",
                },
                source: HvfBackendError::LanePoolCorrupt { index },
            })?;
            lane.try_reaped().map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "waiting for owner reaping",
                },
                source: error.into(),
            })?
        };
        if !reaped {
            return Ok(false);
        }
        let old = {
            let pool = self
                .free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut slot = self.lanes[index]
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pool.failure.is_some() || pool.retiring == 0 {
                return Err(LaneMaintenanceFailure {
                    failure: LaneReplacementFailure {
                        index,
                        generation: old_generation,
                        stage: "claiming retired lane ownership",
                    },
                    source: HvfBackendError::LanePoolCorrupt { index },
                }
                .into());
            }
            let old =
                match core::mem::replace(&mut *slot, LaneSlotState::Replacing { old_generation }) {
                    LaneSlotState::Retiring(current) if Arc::ptr_eq(&current, &generation) => {
                        current
                    }
                    other => {
                        *slot = other;
                        return Err(LaneMaintenanceFailure {
                            failure: LaneReplacementFailure {
                                index,
                                generation: old_generation,
                                stage: "claiming retired lane ownership",
                            },
                            source: HvfBackendError::LanePoolCorrupt { index },
                        }
                        .into());
                    }
                };
            drop(slot);
            drop(pool);
            old
        };
        drop(generation);
        let LaneGeneration {
            lane,
            handle,
            participant,
        } = Arc::try_unwrap(old).map_err(|_| LaneMaintenanceFailure {
            failure: LaneReplacementFailure {
                index,
                generation: old_generation,
                stage: "isolating retired lane ownership",
            },
            source: HvfBackendError::LanePoolCorrupt { index },
        })?;
        drop(
            lane.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        drop(handle);
        let participant_id = participant.id();
        let mut participant = Some(participant);
        let deregistration = self
            .space
            .deregister_vcpu_participant(participant.as_mut().ok_or({
                LaneMaintenanceFailure {
                    failure: LaneReplacementFailure {
                        index,
                        generation: old_generation,
                        stage: "finding retired participant ownership",
                    },
                    source: HvfBackendError::LanePoolCorrupt { index },
                }
            })?);
        match deregistration {
            Ok(()) => {}
            Err(HvfMemoryError::ParticipantBusy(_)) => {
                let _recovery = self
                    .participant_recovery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(participant.take());
                let receipts = self
                    .space
                    .recover_stopped_vcpu_participants()
                    .map_err(|error| LaneMaintenanceFailure {
                        failure: LaneReplacementFailure {
                            index,
                            generation: old_generation,
                            stage: "recovering retired participant",
                        },
                        source: error.into(),
                    })?;
                if !receipts
                    .iter()
                    .any(|receipt| receipt.participant == participant_id && receipt.removed)
                {
                    return Err(LaneMaintenanceFailure {
                        failure: LaneReplacementFailure {
                            index,
                            generation: old_generation,
                            stage: "verifying retired participant recovery",
                        },
                        source: HvfBackendError::LanePoolCorrupt { index },
                    }
                    .into());
                }
            }
            Err(error) => {
                return Err(LaneMaintenanceFailure {
                    failure: LaneReplacementFailure {
                        index,
                        generation: old_generation,
                        stage: "deregistering retired participant",
                    },
                    source: error.into(),
                }
                .into());
            }
        }
        drop(participant);
        self.space
            .pump_retirements()
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "settling retired participant",
                },
                source: error.into(),
            })?;
        if process_hvf_vm()
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "checking replacement VM state",
                },
                source: error.into(),
            })?
            .is_poisoned()
        {
            return Err(LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "checking replacement VM state",
                },
                source: HvfError::Poisoned.into(),
            }
            .into());
        }
        let replacement = Self::create_lane_generation(&self.registry, &self.space, self.el1)
            .map_err(|error| LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "creating replacement generation",
                },
                source: error,
            })?;
        let replacement_generation = replacement.handle.generation();
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut slot = self.lanes[index]
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = pool.failure.is_none()
            && pool.retiring != 0
            && replacement_generation > old_generation
            && !pool.free.iter().any(|free| free.index == index)
            && matches!(
                &*slot,
                LaneSlotState::Replacing {
                    old_generation: current
                } if *current == old_generation
            );
        if !valid {
            drop(slot);
            drop(pool);
            return Err(LaneMaintenanceFailure {
                failure: LaneReplacementFailure {
                    index,
                    generation: old_generation,
                    stage: "publishing replacement generation",
                },
                source: HvfBackendError::LanePoolCorrupt { index },
            }
            .into());
        }
        *slot = LaneSlotState::Ready(replacement);
        pool.retiring -= 1;
        pool.free.push_back(FreeLane {
            index,
            generation: replacement_generation,
        });
        drop(slot);
        drop(pool);
        self.available.notify_all();
        Ok(true)
    }

    fn fail_lane_pool(&self, failure: LaneReplacementFailure) {
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.index < self.lanes.len() {
            let mut slot = self.lanes[failure.index]
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if matches!(
                &*slot,
                LaneSlotState::Retiring(current)
                    if current.handle.generation() == failure.generation
            ) || matches!(
                &*slot,
                LaneSlotState::Replacing { old_generation }
                    if *old_generation == failure.generation
            ) {
                pool.retiring = pool.retiring.saturating_sub(1);
            }
            *slot = LaneSlotState::Failed(failure);
        }
        pool.failure.get_or_insert(failure);
        drop(pool);
        self.available.notify_all();
        self.kick_running_lanes();
    }

    fn current_lane_handle(&self, index: usize) -> Result<HvfVcpuLaneHandle, HvfBackendError> {
        let slot = self
            .lanes
            .get(index)
            .ok_or(HvfBackendError::LanePoolCorrupt { index })?
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*slot {
            LaneSlotState::Ready(generation) | LaneSlotState::Retiring(generation) => {
                Ok(generation.handle.clone())
            }
            LaneSlotState::Replacing { .. } => Err(HvfBackendError::LanePoolCorrupt { index }),
            LaneSlotState::Failed(failure) => Err(lane_replacement_error(*failure)),
        }
    }

    fn install_trampoline(&self) -> Result<(), HvfBackendError> {
        let range = self.trampoline.clone();
        let mapped = self.space.map_range(
            range.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
            false,
        )?;
        let mapping = OwnedGuestRange::new(self, range.clone());
        self.space.defer_retirement(mapped.retirement)?;
        // The host view is mirrored, so the page is writable at its own GVA.
        let mut bytes = [0u8; SIGRETURN_TRAMPOLINE.len() * 4];
        for (index, instruction) in SIGRETURN_TRAMPOLINE.iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&instruction.to_le_bytes());
        }
        // SAFETY: `range` was just mapped read/write in the mirrored host
        // view and nothing else references it yet.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), range.start as *mut u8, bytes.len());
        }
        let executable = self.space.protect_range(
            range.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        )?;
        self.space.defer_retirement(executable.retirement)?;
        self.space.pump_retirements()?;
        // SAFETY: the page is readable in the mirrored host view.
        let readback = unsafe { core::ptr::read_unaligned(range.start as *const [u8; 8]) };
        if readback != bytes {
            return Err(HvfBackendError::Trampoline(
                "trampoline bytes did not read back through the mirrored view",
            ));
        }
        mapping.disarm();
        Ok(())
    }

    pub(crate) fn trampoline_address(&self) -> usize {
        self.trampoline.start
    }

    pub(crate) fn reserved_ranges(&self) -> Vec<Range<usize>> {
        vec![self.trampoline.clone()]
    }

    // -- lane pool ---------------------------------------------------------

    /// Acquires any idle lane in strict arrival order: a waiter is served
    /// only once every waiter that started waiting before it has already been
    /// served, so a thread that repeatedly releases and reacquires a lane can
    /// never barge ahead of one that has been waiting longer. This is what
    /// makes `LANE_ACQUIRE_TIMEOUT` a bound on genuine sustained
    /// oversubscription rather than on adversarial scheduling luck.
    fn acquire_lane(&self) -> Result<LaneLease<'_>, HvfBackendError> {
        self.acquire_lane_inner(None)?
            .ok_or(HvfBackendError::LaneAcquisitionTimeout)
    }

    fn acquire_lane_for_thread(
        &self,
        slot: &HvfThreadSlot,
    ) -> Result<Option<LaneLease<'_>>, HvfBackendError> {
        self.acquire_lane_inner(Some(slot))
    }

    fn acquire_lane_inner(
        &self,
        interrupt: Option<&HvfThreadSlot>,
    ) -> Result<Option<LaneLease<'_>>, HvfBackendError> {
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(failure) = pool.failure {
            return Err(lane_replacement_error(failure));
        }
        let deadline = Instant::now()
            .checked_add(LANE_ACQUIRE_TIMEOUT)
            .ok_or(HvfBackendError::LaneAcquisitionTimeout)?;
        let ticket = pool.next_ticket;
        let successor = ticket
            .checked_add(1)
            .ok_or(HvfBackendError::LaneTicketExhausted)?;
        pool.next_ticket = successor;
        loop {
            if let Some(failure) = pool.failure {
                pool.next_serving = pool.next_serving.max(successor);
                advance_canceled_tickets(&mut pool)?;
                drop(pool);
                self.available.notify_all();
                return Err(lane_replacement_error(failure));
            }
            if interrupt.is_some_and(HvfThreadSlot::has_pending) {
                if !pool.canceled_tickets.insert(ticket) {
                    return Err(HvfBackendError::LanePoolCorrupt { index: usize::MAX });
                }
                advance_canceled_tickets(&mut pool)?;
                drop(pool);
                self.available.notify_all();
                return Ok(None);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                pool.next_serving = pool.next_serving.max(successor);
                advance_canceled_tickets(&mut pool)?;
                drop(pool);
                self.available.notify_all();
                return Err(HvfBackendError::LaneAcquisitionTimeout);
            }
            if ticket == pool.next_serving
                && let Some(free) = pool.free.front().copied()
            {
                let Some(pooled) = self.lanes.get(free.index) else {
                    return Err(HvfBackendError::LanePoolCorrupt { index: free.index });
                };
                let slot = pooled
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let generation = match &*slot {
                    LaneSlotState::Ready(generation)
                        if generation.handle.generation() == free.generation =>
                    {
                        Arc::clone(generation)
                    }
                    _ => {
                        return Err(HvfBackendError::LanePoolCorrupt { index: free.index });
                    }
                };
                let checked_out = pool
                    .checked_out
                    .checked_add(1)
                    .ok_or(HvfBackendError::LanePoolCorrupt { index: free.index })?;
                if pool.free.pop_front() != Some(free) {
                    return Err(HvfBackendError::LanePoolCorrupt { index: free.index });
                }
                pool.checked_out = checked_out;
                pool.next_serving = successor;
                advance_canceled_tickets(&mut pool)?;
                drop(slot);
                drop(pool);
                self.available.notify_all();
                return Ok(Some(LaneLease {
                    backend: self,
                    index: free.index,
                    generation,
                    return_to_pool: true,
                }));
            }
            let wait = interrupt.map_or(remaining, |_| remaining.min(Duration::from_millis(10)));
            let (next, _) = self
                .available
                .wait_timeout(pool, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pool = next;
        }
    }

    fn release_lane(&self, index: usize, generation: &Arc<LaneGeneration>) {
        let generation_id = generation.handle.generation();
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(pooled) = self.lanes.get(index) else {
            drop(pool);
            fatal(
                "returning a vCPU lane to the pool",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        };
        let slot = pooled
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = pool.checked_out != 0
            && !pool.free.iter().any(|free| free.index == index)
            && matches!(
                &*slot,
                LaneSlotState::Ready(current)
                    if current.handle.generation() == generation_id
                        && Arc::ptr_eq(current, generation)
            );
        if valid {
            pool.checked_out -= 1;
            if pool.failure.is_none() {
                pool.free.push_back(FreeLane {
                    index,
                    generation: generation_id,
                });
            }
        }
        drop(slot);
        drop(pool);
        if !valid {
            fatal(
                "returning a vCPU lane to the pool",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        }
        self.available.notify_all();
    }

    /// Takes a specific lane out of the pool only if it is idle right now.
    /// Deliberately bypasses ticket ordering: the shootdown loop targets one
    /// exact lane it already knows is retired-root-affected, not "the next
    /// fair turn," so admitting it out of order here does not defeat
    /// `acquire_lane`'s fairness guarantee for ordinary guest threads.
    fn try_acquire_lane(&self, index: usize) -> Option<LaneLease<'_>> {
        let mut pool = self
            .free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pool.failure.is_some() {
            return None;
        }
        let position = pool.free.iter().position(|free| free.index == index)?;
        let free = pool.free[position];
        let Some(pooled) = self.lanes.get(index) else {
            drop(pool);
            fatal(
                "checking out a targeted vCPU lane",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        };
        let slot = pooled
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = match &*slot {
            LaneSlotState::Ready(generation)
                if generation.handle.generation() == free.generation =>
            {
                Arc::clone(generation)
            }
            _ => {
                drop(slot);
                drop(pool);
                fatal(
                    "checking out a targeted vCPU lane",
                    &HvfBackendError::LanePoolCorrupt { index },
                );
            }
        };
        let Some(checked_out) = pool.checked_out.checked_add(1) else {
            drop(slot);
            drop(pool);
            fatal(
                "checking out a targeted vCPU lane",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        };
        if pool.free.remove(position) != Some(free) {
            drop(slot);
            drop(pool);
            fatal(
                "checking out a targeted vCPU lane",
                &HvfBackendError::LanePoolCorrupt { index },
            );
        }
        pool.checked_out = checked_out;
        drop(slot);
        Some(LaneLease {
            backend: self,
            index,
            generation,
            return_to_pool: true,
        })
    }

    /// The Linux TLB-shootdown equivalent after a mapping mutation: every
    /// lane still running the retired root is kicked out of the guest, idle
    /// lanes that owe an acknowledgement are synchronized here directly, and
    /// deferred retirements are pumped until none remain (or the bound
    /// expires, in which case they stay deferred and are pumped later).
    fn shootdown(&self) {
        let deadline = Instant::now()
            .checked_add(SHOOTDOWN_TIMEOUT)
            .unwrap_or_else(Instant::now);
        self.kick_running_lanes();
        loop {
            let _ = self.space.pump_retirements();
            if self.space.pending_retirements() == 0 {
                return;
            }
            for index in 0..self.lanes.len() {
                // Enforced per lane, not only once per outer loop iteration:
                // a single stalled lane's own command timeout must not be
                // able to consume the whole shootdown budget on its own.
                if Instant::now() >= deadline {
                    litebox_util_log::warn!(
                        pending:? = self.space.pending_retirements();
                        "HVF shootdown did not drain every retirement within its bound"
                    );
                    return;
                }
                let Some(lease) = self.try_acquire_lane(index) else {
                    continue;
                };
                let mut retire = false;
                {
                    let lane = lease.lane();
                    match self.space.attach_vcpu(&lane.participant) {
                        Ok(attachment) if attachment.requires_synchronization() => {
                            if let Err(error) = lane.handle.synchronize_before(attachment, deadline)
                                && !lane.handle.is_reusable()
                            {
                                litebox_util_log::warn!(index:? = index, error:% = error;
                                    "retiring an HVF lane that exceeded the shootdown bound");
                                retire = true;
                            }
                        }
                        Ok(attachment) => drop(attachment),
                        Err(_) => {}
                    }
                }
                if retire {
                    lease.retire();
                } else {
                    drop(lease);
                }
            }
            let _ = self.space.pump_retirements();
            if self.space.pending_retirements() == 0 {
                return;
            }
            if Instant::now() >= deadline {
                litebox_util_log::warn!(
                    pending:? = self.space.pending_retirements();
                    "HVF shootdown did not drain every retirement within its bound"
                );
                return;
            }
            std::thread::sleep(SHOOTDOWN_POLL);
        }
    }

    /// Kicks every lane that is currently running guest code so it exits,
    /// re-attaches (synchronizing onto the newest root) and acknowledges
    /// pending retirements.  Best effort: a lane that is not running simply
    /// reports so.
    fn kick_running_lanes(&self) {
        for lane in &self.lanes {
            let handle = {
                let slot = lane
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match &*slot {
                    LaneSlotState::Ready(generation) | LaneSlotState::Retiring(generation) => {
                        Some(generation.handle.clone())
                    }
                    LaneSlotState::Replacing { .. } | LaneSlotState::Failed(_) => None,
                }
            };
            if let Some(handle) = handle {
                let _ = handle.cancellation().request();
            }
        }
    }

    /// Settles one mutation the way Linux settles a page-table change:
    ///
    /// * A new mapping needs no shootdown at all -- no vCPU can hold a
    ///   translation for a range that was unmapped, so nothing is stale.
    /// * Narrowing (protect, unmap) kicks every running lane once, without
    ///   waiting: each kicked lane re-attaches and synchronizes before it
    ///   runs again, and any access it makes through a stale entry in the
    ///   meantime either still hits its own (retired, not yet reused) memory
    ///   or faults -- and a fault on a stale view is rerun after
    ///   synchronization rather than delivered (see `dispatch_monitor_exit`).
    ///   Retired resources are released as acknowledgements arrive; they are
    ///   never reused before every in-flight participant has acknowledged.
    /// * Only resource pressure (a `ResourceLimit`) triggers the bounded,
    ///   synchronous drain, after which the caller retries once.
    fn settle_mutation(
        &self,
        kind: MutationKind,
        mutation: Result<HvfRangeMutation, HvfMemoryError>,
    ) -> Result<bool, HvfMemoryError> {
        match mutation {
            Ok(mutation) => {
                let changed = mutation.changed;
                self.space
                    .defer_retirement(mutation.retirement)
                    .map_err(|error| {
                        HvfMemoryError::after_publication("retirement deferral", error)
                    })?;
                if kind != MutationKind::Map {
                    self.kick_running_lanes();
                }
                let _ = self.space.pump_retirements();
                let count = self
                    .mutations
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_add(1);
                if count.is_multiple_of(256) {
                    let usage = self.memory.usage();
                    litebox_util_log::debug!(
                        mutations:? = count,
                        pending_retirements:? = self.space.pending_retirements(),
                        retired_generations:? = usage.retired_generations,
                        claimed_pages:? = usage.claimed_pages,
                        table_pages:? = usage.table_pages,
                        host_slots:? = usage.host_slots,
                        ipa_owned_pages:? = usage.ipa_owned_pages;
                        "HVF mutation counters"
                    );
                }
                Ok(changed)
            }
            Err(HvfMemoryError::ResourceLimit {
                resource,
                requested,
                limit,
            }) => {
                self.shootdown();
                Err(HvfMemoryError::ResourceLimit {
                    resource,
                    requested,
                    limit,
                })
            }
            Err(error) => Err(error),
        }
    }

    fn mutate_with_retry(
        &self,
        kind: MutationKind,
        mut operation: impl FnMut() -> Result<HvfRangeMutation, HvfMemoryError>,
    ) -> Result<bool, HvfMemoryError> {
        let result = match self.settle_mutation(kind, operation()) {
            Err(HvfMemoryError::ResourceLimit { .. }) => self.settle_mutation(kind, operation()),
            result => result,
        };
        match result {
            Err(error) if error.published_before_failure() => {
                let error = HvfBackendError::Memory(error);
                fatal(
                    match kind {
                        MutationKind::Map => "completing a published guest map",
                        MutationKind::Protect => "completing a published guest protection change",
                        MutationKind::Unmap => "completing a published guest unmap",
                    },
                    &error,
                )
            }
            result => result,
        }
    }

    /// Whether the address space has moved past the generations a run was
    /// attached with, i.e. whether that run may have executed on a stale
    /// translation.  Only consulted on memory-abort exits, which are rare.
    fn view_was_stale(&self, snapshot: &HvfVcpuMemorySnapshot) -> bool {
        self.space.vcpu_snapshot().is_ok_and(|current| {
            current.root_generation > snapshot.root_generation
                || current.executable_generation > snapshot.executable_generation
                || current.pending_tlbi_generation > snapshot.pending_tlbi_generation
        })
    }

    // -- page management ---------------------------------------------------

    pub(crate) fn allocate_pages(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<usize, AllocationError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(AllocationError::Unaligned);
        }
        if range.start < GUEST_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > GUEST_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if overlaps(&range, &self.trampoline) {
            return Err(AllocationError::AddressInUseByPlatform);
        }
        let replace = fixed_address_behavior == FixedAddressBehavior::Replace;
        // MAP_FIXED over live pages is an unmap as far as stale views go.
        let kind = if replace {
            MutationKind::Unmap
        } else {
            MutationKind::Map
        };
        let Some(guest) = guest_permissions(permissions) else {
            // Combined write+execute, same as `update_permissions`: never
            // hand `HvfAddressSpace` a combined request (its own refusal
            // stays exactly as strict), register the range for
            // `try_resolve_wx_fault` instead, and materialize it read+write.
            // This path is reached not only for a guest `mmap(..., RWX,
            // ...)` directly, but also whenever `Vmem::reset_pages`
            // (`MADV_DONTNEED`/`MADV_FREE` on part of an already-registered
            // WX-toggle region) re-creates a mapping from its stored,
            // guest-visible `VmArea` flags -- which are legitimately RWX
            // once `update_permissions` above started accepting that. Both
            // cases need the same accommodation, or the second one panics
            // (`reset_pages`'s `.expect` treats re-establishing a
            // previously-successful mapping as infallible).
            self.wx_toggle.register(range.clone());
            self.mutate_with_retry(kind, || {
                self.space.map_range(
                    range.clone(),
                    HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                    replace,
                )
            })
            .map_err(allocation_error)?;
            return Ok(range.start);
        };
        self.mutate_with_retry(kind, || self.space.map_range(range.clone(), guest, replace))
            .map_err(allocation_error)?;
        Ok(range.start)
    }

    pub(crate) fn allocate_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<usize, AllocationError> {
        if !range.start.is_multiple_of(PAGE_SIZE)
            || !range.len().is_multiple_of(PAGE_SIZE)
            || !backing_offset.is_multiple_of(PAGE_SIZE)
        {
            return Err(AllocationError::Unaligned);
        }
        if range.start < GUEST_ADDR_MIN {
            return Err(AllocationError::BelowMinAddress);
        }
        if range.end > GUEST_ADDR_MAX {
            return Err(AllocationError::AboveMaxAddress);
        }
        if overlaps(&range, &self.trampoline) {
            return Err(AllocationError::AddressInUseByPlatform);
        }
        let guest = guest_permissions(permissions).ok_or(AllocationError::OutOfMemory)?;
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        self.space
            .preflight_map_range(&range, guest)
            .map_err(allocation_error)?;
        let replaced = if fixed_address_behavior == FixedAddressBehavior::Replace {
            self.mutate_with_retry(MutationKind::Unmap, || {
                self.space.unmap_range(range.clone())
            })
            .map_err(allocation_error)?
        } else {
            false
        };
        match self.mutate_with_retry(MutationKind::Map, || {
            self.space.map_shared_range(range.clone(), guest, key)
        }) {
            Ok(_) => Ok(range.start),
            // Same pre-publish guarantee `map_range`/`map_shared_range` already exempt on
            // (`claim_with`'s `ensure_claim_gap` always runs before any lock/mutation of *this*
            // range, so this error can never be `map_shared_range`'s own claim half-applied): an
            // already-published unmap from `replaced` above does not make a subsequent
            // AddressOverlap/MonitorOverlap on the re-claim a torn host state -- it is an
            // ordinary "another actor claimed this range first" race, and `allocation_error`
            // already has the recoverable `AddressInUse` arm for exactly these two variants.
            // Forcing them through `fatal()` here turned that ordinary race into a host abort.
            Err(
                error @ (HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_)),
            ) => Err(allocation_error(error)),
            Err(error) if replaced => {
                let error = HvfBackendError::Memory(HvfMemoryError::after_publication(
                    "shared MAP_FIXED replacement",
                    error,
                ));
                fatal("completing a published shared guest map", &error)
            }
            Err(error) => Err(allocation_error(error)),
        }
    }

    pub(crate) fn deallocate_pages(&self, range: Range<usize>) -> Result<(), DeallocationError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(DeallocationError::Unaligned);
        }
        if overlaps(&range, &self.trampoline) {
            return Err(DeallocationError::AlreadyUnallocated);
        }
        let unmapped = self
            .mutate_with_retry(MutationKind::Unmap, || self.space.unmap_range(range.clone()))
            .map(|_| ())
            .map_err(|error| {
                litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF unmap failed");
                DeallocationError::AlreadyUnallocated
            });
        if unmapped.is_ok() {
            self.wx_toggle.release(&range);
        }
        unmapped
    }

    pub(crate) fn update_permissions(
        &self,
        range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<(), PermissionUpdateError> {
        if !range.start.is_multiple_of(PAGE_SIZE) || !range.len().is_multiple_of(PAGE_SIZE) {
            return Err(PermissionUpdateError::Unaligned);
        }
        if overlaps(&range, &self.trampoline) {
            return Err(PermissionUpdateError::Unallocated);
        }
        let Some(guest) = guest_permissions(permissions) else {
            // Combined write+execute: `guest_permissions` only ever refuses
            // this exact combination (see its own body), so reaching here
            // unambiguously means the guest wants RWX. Never ask
            // `HvfAddressSpace` for that -- `refuse_write_execute` inside it
            // (and every one of its own callers) refuses it too, and that
            // invariant is not weakened by any of this. Instead grant the
            // guest's logical view as RWX (real Linux's own promise) while
            // registering the range for `try_resolve_wx_fault` to enforce a
            // real, single-direction stage-2 permission on each page,
            // flipping it lazily on demand. See `WxToggle`'s doc comment.
            self.wx_toggle.register(range.clone());
            return self
                .mutate_with_retry(MutationKind::Protect, || {
                    self.space.protect_range(
                        range.clone(),
                        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                    )
                })
                .map(|_| ())
                .map_err(|error| {
                    litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF WX-toggle registration protect failed");
                    PermissionUpdateError::Unallocated
                });
        };
        // An ordinary, non-combined permission change means the guest is
        // deliberately leaving whatever regime it had (including a prior
        // WX-toggle registration) -- release it so a later fault here is
        // never misattributed to this mechanism.
        self.wx_toggle.release(&range);
        self.mutate_with_retry(MutationKind::Protect, || {
            self.space.protect_range(range.clone(), guest)
        })
        .map(|_| ())
        .map_err(|error| {
            litebox_util_log::warn!(start:? = range.start, end:? = range.end, error:% = error; "HVF protect failed");
            PermissionUpdateError::Unallocated
        })
    }

    pub(crate) fn remap_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        old_range: Range<usize>,
        new_range: Range<usize>,
        permissions: MemoryRegionPermissions,
    ) -> Result<usize, RemapError> {
        if !old_range.start.is_multiple_of(PAGE_SIZE)
            || !old_range.len().is_multiple_of(PAGE_SIZE)
            || !new_range.start.is_multiple_of(PAGE_SIZE)
            || !new_range.len().is_multiple_of(PAGE_SIZE)
            || !backing_offset.is_multiple_of(PAGE_SIZE)
        {
            return Err(RemapError::Unaligned);
        }
        if overlaps(&old_range, &new_range) {
            return Err(RemapError::Overlapping);
        }
        if new_range.len() < old_range.len() {
            return Err(RemapError::OutOfMemory);
        }
        let Some(guest) = guest_permissions(permissions) else {
            return Err(RemapError::OutOfMemory);
        };
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        let transaction = process_hvf_vm()
            .map_err(HvfMemoryError::from)
            .and_then(|vm| {
                vm.with_operation(|_| {
                    self.space.preflight_mapped_range(&old_range)?;
                    self.space.preflight_map_range(&new_range, guest)?;
                    self.mutate_with_retry(MutationKind::Map, || {
                        self.space.map_shared_range(new_range.clone(), guest, key)
                    })?;
                    match self.mutate_with_retry(MutationKind::Unmap, || {
                        self.space.unmap_range(old_range.clone())
                    }) {
                        Ok(true) => Ok(new_range.start),
                        Ok(false) => Err(HvfMemoryError::RangeUnmapped(old_range.clone())),
                        Err(error) => Err(error),
                    }
                })
            });
        match transaction {
            Ok(start) => Ok(start),
            Err(error) if error.published_before_failure() => {
                let error = HvfBackendError::Memory(error);
                fatal("completing a published shared guest remap", &error)
            }
            Err(HvfMemoryError::RangeUnmapped(_)) => Err(RemapError::AlreadyUnallocated),
            Err(HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_)) => {
                Err(RemapError::AlreadyAllocated)
            }
            Err(error) => {
                litebox_util_log::warn!(error:% = error; "HVF shared remap failed before publication");
                Err(RemapError::OutOfMemory)
            }
        }
    }

    pub(crate) fn initialize_shared_pages<E>(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        length: usize,
        mut initialize: impl FnMut(Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(end) = backing_offset.checked_add(length) else {
            return Ok(());
        };
        let requested = backing_offset..end;
        loop {
            let mut registry = self
                .shared_initialization
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let initialized = registry
                .initialized
                .get(&backing_identity)
                .cloned()
                .unwrap_or_default();
            let missing = subtract_ranges(&requested, &initialized);
            if missing.is_empty() {
                return Ok(());
            }
            let in_progress = registry
                .in_progress
                .get(&backing_identity)
                .cloned()
                .unwrap_or_default();
            let claimable = missing
                .iter()
                .flat_map(|range| subtract_ranges(range, &in_progress))
                .next();
            let Some(claim) = claimable else {
                registry = self
                    .shared_initialization_changed
                    .wait(registry)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(registry);
                continue;
            };
            registry
                .in_progress
                .entry(backing_identity)
                .or_default()
                .push(claim.clone());
            drop(registry);

            let relative = (claim.start - backing_offset)..(claim.end - backing_offset);
            let result = initialize(relative);

            let mut registry = self
                .shared_initialization
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(list) = registry.in_progress.get_mut(&backing_identity) {
                list.retain(|range| *range != claim);
            }
            if result.is_ok() {
                let list = registry.initialized.entry(backing_identity).or_default();
                list.push(claim);
                normalize_ranges(list);
            }
            self.shared_initialization_changed.notify_all();
            drop(registry);
            result?;
        }
    }

    fn wait_shared_initialization(&self, backing_identity: usize, requested: &Range<usize>) {
        let mut registry = self
            .shared_initialization
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let busy = registry
                .in_progress
                .get(&backing_identity)
                .is_some_and(|list| list.iter().any(|range| overlaps(range, requested)));
            if !busy {
                return;
            }
            registry = self
                .shared_initialization_changed
                .wait(registry)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    pub(crate) fn read_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &mut [u8],
    ) -> Result<(), SharedPageIoError> {
        let end = backing_offset
            .checked_add(data.len())
            .ok_or(SharedPageIoError::OutOfRange)?;
        self.wait_shared_initialization(backing_identity, &(backing_offset..end));
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        self.memory
            .with_shared_backing(key, data.len(), |bytes| data.copy_from_slice(bytes))
            .map_err(|_| SharedPageIoError::Io)
    }

    pub(crate) fn write_shared_pages(
        &self,
        backing_identity: usize,
        backing_offset: usize,
        data: &[u8],
    ) -> Result<(), SharedPageIoError> {
        let end = backing_offset
            .checked_add(data.len())
            .ok_or(SharedPageIoError::OutOfRange)?;
        self.wait_shared_initialization(backing_identity, &(backing_offset..end));
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_offset,
        };
        self.memory
            .with_shared_backing(key, data.len(), |bytes| bytes.copy_from_slice(data))
            .map_err(|_| SharedPageIoError::Io)?;
        self.mark_initialized(backing_identity, backing_offset..end);
        Ok(())
    }

    pub(crate) fn zero_shared_pages(
        &self,
        backing_identity: usize,
        backing_range: Range<usize>,
    ) -> Result<(), SharedPageIoError> {
        if backing_range.is_empty() {
            return Ok(());
        }
        self.wait_shared_initialization(backing_identity, &backing_range);
        let key = HvfSharedBackingKey {
            identity: backing_identity,
            offset: backing_range.start,
        };
        self.memory
            .with_shared_backing(key, backing_range.len(), |bytes| bytes.fill(0))
            .map_err(|_| SharedPageIoError::Io)?;
        self.mark_initialized(backing_identity, backing_range);
        Ok(())
    }

    fn mark_initialized(&self, backing_identity: usize, range: Range<usize>) {
        let mut registry = self
            .shared_initialization
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = registry.initialized.entry(backing_identity).or_default();
        list.push(range);
        normalize_ranges(list);
        self.shared_initialization_changed.notify_all();
    }

    // -- execution ---------------------------------------------------------

    /// Runs one guest thread to completion: the HVF counterpart of
    /// `guest::run_thread`.  `ctx` is the thread's authoritative integer
    /// context; the vector file and thread pointer live in [`HVF_THREAD`].
    pub(crate) fn run_thread(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
    ) {
        if shim.init(ctx) == ContinueOperation::Terminate {
            return;
        }
        let thread = crate::ThreadHandle::current();
        let slot = thread.hvf_slot();
        let mut consecutive_attachment_races = 0u32;
        let mut stale_view_reruns = 0u32;
        loop {
            if slot.take_pending() && shim.interrupt(ctx) == ContinueOperation::Terminate {
                return;
            }
            let lease = match self.acquire_lane_for_thread(slot) {
                Ok(Some(lease)) => lease,
                Ok(None) => {
                    if slot.take_pending() && shim.interrupt(ctx) == ContinueOperation::Terminate {
                        return;
                    }
                    continue;
                }
                Err(error) => fatal("acquiring a vCPU lane", &error),
            };
            let mut active = ActiveThreadLaneLease::new(lease, slot);
            {
                let mut current = slot
                    .current
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if slot.take_pending() {
                    drop(current);
                    drop(active);
                    if shim.interrupt(ctx) == ContinueOperation::Terminate {
                        return;
                    }
                    continue;
                }
                if current.is_some() {
                    drop(current);
                    drop(active);
                    fatal(
                        "reserving a vCPU lane with stale thread authority",
                        &HvfBackendError::LanePoolCorrupt { index: usize::MAX },
                    );
                }
                let reservation = match active.lane().handle.reserve_run() {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        drop(current);
                        drop(active);
                        fatal("reserving a vCPU run epoch", &error.into());
                    }
                };
                let cancellation = reservation.cancellation();
                active.install(reservation, cancellation.clone());
                *current = Some(cancellation);
            }
            let state = HVF_THREAD.with(|context| architectural_state(ctx, &context.borrow()));
            let deadline = time_slice_deadline();
            let outcome = self
                .space
                .attach_vcpu(&active.lane().participant)
                .map_err(HvfBackendError::from)
                .and_then(|attachment| {
                    let snapshot = attachment.snapshot().clone();
                    let reservation = active.take_reservation();
                    active
                        .lane()
                        .handle
                        .run_with_deadline_reserved(reservation, attachment, &state, deadline)
                        .map(|run| (run, snapshot))
                        .map_err(HvfBackendError::from)
                });
            drop(active);
            let (run, snapshot) = match outcome {
                Ok(run) => run,
                // `attach_vcpu` snapshots the address space's generations at
                // the moment it is called, but this thread's `submit`/
                // `begin_running` only reach the lane's own serialized
                // command queue afterwards; a concurrent mutation landing in
                // that window is expected and recoverable, not a genuine
                // failure -- retry with a fresh attachment against whatever
                // generation is now current instead of aborting the process.
                Err(error) if is_recoverable_attachment_race(&error) => {
                    consecutive_attachment_races += 1;
                    if consecutive_attachment_races >= ATTACHMENT_RACE_RETRY_LIMIT {
                        fatal("retrying past a stale HVF vCPU attachment", &error);
                    }
                    continue;
                }
                Err(error) => fatal("running the guest on a vCPU lane", &error),
            };
            consecutive_attachment_races = 0;
            // Opportunistic acknowledgement work: keeps retired resources
            // flowing back without any mutator having to wait for it.
            if self.space.pending_retirements() != 0 {
                let _ = self.space.pump_retirements();
            }
            let disposition =
                self.dispatch(shim, ctx, slot, &run, &snapshot, &mut stale_view_reruns);
            if disposition == ContinueOperation::Terminate {
                return;
            }
        }
    }

    fn dispatch(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
        slot: &HvfThreadSlot,
        run: &HvfVcpuRunResult,
        snapshot: &HvfVcpuMemorySnapshot,
        stale_view_reruns: &mut u32,
    ) -> ContinueOperation {
        match (run.exit, &run.state) {
            (HvfVcpuExit::Exception(exception), HvfVcpuExitState::LowerElMonitor(state))
                if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_HVC64
                    && exception.syndrome & HVC_IMMEDIATE_MASK == MONITOR_HVC_IMMEDIATE =>
            {
                HVF_THREAD.with(|context| {
                    capture_thread_state(&mut context.borrow_mut(), state);
                });
                self.dispatch_monitor_exit(shim, ctx, state, snapshot, stale_view_reruns)
            }
            (HvfVcpuExit::Exception(exception), HvfVcpuExitState::DirectGuest(state))
                if (exception.syndrome >> EC_SHIFT) & EC_MASK == EC_BRK64 =>
            {
                // Hypervisor.framework intercepts an EL0 BRK before the guest's
                // EL1 vector even though ordinary synchronous exceptions are
                // delivered through the monitor. The direct EL0 state and SDK
                // syndrome are authoritative, so surface the same exception to
                // the shim instead of requiring a monitor HVC that cannot occur.
                HVF_THREAD.with(|context| {
                    capture_thread_state(&mut context.borrow_mut(), state);
                });
                write_direct_exit(ctx, state);
                *stale_view_reruns = 0;
                ctx.syscallno = -1;
                let info = ExceptionInfo {
                    exception: Exception(u8::try_from(EC_BRK64).expect("BRK EC fits in u8")),
                    fault_address: usize::try_from(exception.virtual_address).unwrap_or(usize::MAX),
                    esr: exception.syndrome,
                    kernel_mode: false,
                };
                shim.exception(ctx, &info)
            }
            (HvfVcpuExit::Canceled, HvfVcpuExitState::LowerElMonitor(state))
                if state.pc == MONITOR_LOWER_EL_SYNC_OFFSET =>
            {
                // The authenticated kick won immediately after EL0 exception
                // entry but before the monitor's HVC ran. The original exception
                // is already complete in ELR_EL1/SPSR_EL1/ESR_EL1; dispatch it
                // exactly once instead of dropping a syscall or treating valid
                // EL1h state as a corrupt guest exit. A real thread interrupt
                // remains latched in `slot` and is delivered on the next loop.
                HVF_THREAD.with(|context| {
                    capture_thread_state(&mut context.borrow_mut(), state);
                });
                self.dispatch_monitor_exit(shim, ctx, state, snapshot, stale_view_reruns)
            }
            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(state)) => {
                HVF_THREAD.with(|context| {
                    capture_thread_state(&mut context.borrow_mut(), state);
                });
                let interrupted = slot.take_pending();
                write_direct_exit(ctx, state);
                if interrupted {
                    shim.interrupt(ctx)
                } else {
                    // Mapping shootdowns use the same authenticated lane
                    // cancellation but do not create a thread-interrupt
                    // obligation. Reattach on the current root without
                    // spuriously entering the shim's signal path.
                    ContinueOperation::Resume
                }
            }
            (HvfVcpuExit::VtimerActivated, HvfVcpuExitState::DirectGuest(state)) => {
                HVF_THREAD.with(|context| {
                    capture_thread_state(&mut context.borrow_mut(), state);
                });
                // End of a time slice: the thread simply re-queues for a lane,
                // which is what gives other guest threads a turn.
                write_direct_exit(ctx, state);
                ContinueOperation::Resume
            }
            _ => {
                let state = match &run.state {
                    HvfVcpuExitState::DirectGuest(state)
                    | HvfVcpuExitState::LowerElMonitor(state) => state,
                };
                fatal(
                    "classifying a vCPU exit",
                    &HvfBackendError::UnexpectedExit {
                        exit: Box::new(run.exit),
                        source_pc: Some(state.pc),
                    },
                )
            }
        }
    }

    fn dispatch_monitor_exit(
        &self,
        shim: &dyn EnterShim<ExecutionContext = PtRegs>,
        ctx: &mut PtRegs,
        state: &HvfArchitecturalState,
        snapshot: &HvfVcpuMemorySnapshot,
        stale_view_reruns: &mut u32,
    ) -> ContinueOperation {
        write_monitor_exit(ctx, state);
        let class = (state.esr_el1 >> EC_SHIFT) & EC_MASK;
        match class {
            EC_SVC64 => {
                *stale_view_reruns = 0;
                ctx.syscallno =
                    u32::try_from(state.x[8] & 0xffff_ffff).map_or(-1, u32::cast_signed);
                ctx.orig_x0 = ctx.regs[0];
                shim.syscall(ctx)
            }
            EC_WFX => {
                // `WFI`/`WFE` at EL0: skip the instruction and give up the
                // lane for a moment instead of halting a real core.
                *stale_view_reruns = 0;
                ctx.pc = ctx.pc.wrapping_add(4);
                ctx.syscallno = -1;
                std::thread::yield_now();
                ContinueOperation::Resume
            }
            _ => {
                ctx.syscallno = -1;
                // A memory abort taken through a translation this vCPU may
                // have cached before a concurrent mapping change is not yet a
                // guest fault: the faulting PC is unchanged, so resuming
                // re-attaches (which synchronizes onto the current root) and
                // re-executes exactly that instruction.  Only a fault that
                // recurs on a current view is delivered.  Bounded so a real
                // fault under continuous unrelated mutation still surfaces.
                let is_abort = matches!(class, 0x20 | 0x21 | 0x24 | 0x25);
                if is_abort
                    && *stale_view_reruns < STALE_VIEW_RERUN_LIMIT
                    && self.view_was_stale(snapshot)
                {
                    *stale_view_reruns += 1;
                    litebox_util_log::debug!(
                        class:? = class, far:? = state.far_el1, pc:? = ctx.pc,
                        reruns:? = *stale_view_reruns;
                        "HVF memory abort on a stale view: rerunning after synchronization"
                    );
                    return ContinueOperation::Resume;
                }
                if is_abort
                    && let Some(op) = self.try_resolve_wx_fault(class, state.far_el1, state.esr_el1)
                {
                    *stale_view_reruns = 0;
                    return op;
                }
                *stale_view_reruns = 0;
                let info = ExceptionInfo {
                    exception: Exception(u8::try_from(class).unwrap_or(0)),
                    fault_address: usize::try_from(state.far_el1).unwrap_or(usize::MAX),
                    esr: state.esr_el1,
                    kernel_mode: false,
                };
                // Permanent diagnostic aid: every non-SVC/non-WFx monitor
                // exception is rare enough in practice (aborts, undefined
                // instructions, BRK) that a debug-level trace here costs
                // nothing when logging is off and saves a debugger session
                // when a genuine guest fault needs to be diagnosed later.
                litebox_util_log::debug!(
                    class:? = class, esr:? = state.esr_el1, far:? = state.far_el1,
                    pc:? = ctx.pc;
                    "HVF monitor exception dispatched to shim.exception"
                );
                shim.exception(ctx, &info)
            }
        }
    }

    /// Resolves a guest stage-2 permission fault against a WX-toggle-eligible
    /// region (see [`WxToggle`]), flipping exactly the faulting page's real
    /// permission and letting the guest resume at the same instruction with
    /// no guest-visible signal. Returns `None` for every fault this
    /// mechanism does not own -- including a permission fault whose
    /// direction already matches the page's current real state, which means
    /// something other than this toggle caused it -- so the caller falls
    /// through to ordinary guest-signal delivery exactly as before this
    /// mechanism existed.
    fn try_resolve_wx_fault(
        &self,
        class: u64,
        far_el1: u64,
        esr_el1: u64,
    ) -> Option<ContinueOperation> {
        if esr_el1 & ESR_FSC_PERMISSION_FAULT_MASK != ESR_FSC_PERMISSION_FAULT {
            return None;
        }
        let want_execute = match class {
            EC_INSTRUCTION_ABORT_LOWER_EL => true,
            EC_DATA_ABORT_LOWER_EL if esr_el1 & ESR_WNR != 0 => false,
            _ => return None,
        };
        let page = usize::try_from(far_el1).ok()? & !(PAGE_SIZE - 1);
        let mut state = self
            .wx_toggle
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let in_region = state
            .regions
            .range(..=page)
            .next_back()
            .is_some_and(|(_, &end)| page < end);
        if !in_region || state.executable_pages.contains(&page) == want_execute {
            // Not a toggle-eligible page, or its real permission already
            // matches what the guest wants -- this fault is not this
            // mechanism's doing.
            return None;
        }
        let want = if want_execute {
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE
        } else {
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE
        };
        let flip = self.mutate_with_retry(MutationKind::Protect, || {
            self.space.protect_range(page..page + PAGE_SIZE, want)
        });
        match flip {
            Ok(_) => {
                if want_execute {
                    state.executable_pages.insert(page);
                } else {
                    state.executable_pages.remove(&page);
                }
                Some(ContinueOperation::Resume)
            }
            Err(error) => {
                litebox_util_log::warn!(page:? = page, error:% = error; "HVF WX-toggle flip failed");
                None
            }
        }
    }
}

/// Guest-transparent write-xor-execute emulation for a guest `mprotect`
/// requesting simultaneous WRITE and EXECUTE (e.g. V8/JIT CodeRange setup).
/// `guest_permissions` below refuses that combination outright, and every
/// path through `HvfAddressSpace` still refuses it too (`refuse_write_execute`
/// in `hvf_memory.rs`) -- no guest page is ever granted real, simultaneous
/// write+execute stage-2 permission by this mechanism or any other. Instead,
/// a registered region is granted the guest's *logical* view as RWX (so
/// `mprotect`/`/proc/self/maps` see exactly what real Linux would show, via
/// the ordinary `VmArea`/`VmFlags` bookkeeping in `litebox/src/mm/vmem.rs`,
/// which is populated from whatever `MemoryRegionPermissions` this platform's
/// `update_permissions` returns `Ok` for) while the *real* stage-2 permission
/// on each page is either read+write or read+execute, flipping a single page
/// on demand -- see [`HvfBackend::try_resolve_wx_fault`] -- the instant a
/// stage-2 permission fault proves the guest actually needs the other one. A
/// page absent from `executable_pages` is the default, read+write, matching
/// the state every registration (re-)establishes.
#[derive(Default)]
struct WxToggle {
    state: Mutex<WxToggleState>,
}

#[derive(Default)]
struct WxToggleState {
    /// Disjoint address ranges currently granted combined RWX, start -> end.
    regions: BTreeMap<usize, usize>,
    /// Pages inside a region above whose real permission has been flipped to
    /// read+execute. Absent means read+write, the default a region starts at.
    executable_pages: BTreeSet<usize>,
}

impl WxToggle {
    /// Grants `range` combined RWX from the guest's point of view. The real
    /// permission for every page in `range` starts (or resets to) read+write
    /// -- matching real Linux's own `mprotect(RWX)`, which does not preserve
    /// whatever a page happened to contain permission-wise beforehand.
    /// Overlapping/adjacent existing registrations are merged so `contains`
    /// sees one continuous region rather than fragments.
    fn register(&self, range: Range<usize>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.executable_pages.retain(|page| !range.contains(page));
        let mut start = range.start;
        let mut end = range.end;
        let overlapping: Vec<(usize, usize)> = state
            .regions
            .iter()
            .filter(|&(&s, &e)| s <= end && start <= e)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            state.regions.remove(&s);
            start = start.min(s);
            end = end.max(e);
        }
        state.regions.insert(start, end);
    }

    /// Releases `range` from toggle tracking: a guest `mprotect` to a
    /// non-combined permission, or an `munmap`, means this address range is
    /// no longer under this emulation, and any later fault there must be
    /// treated as a genuine guest fault rather than a toggle-eligible one.
    fn release(&self, range: &Range<usize>) {
        if range.start >= range.end {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.executable_pages.retain(|page| !range.contains(page));
        let overlapping: Vec<(usize, usize)> = state
            .regions
            .iter()
            .filter(|&(&s, &e)| s < range.end && range.start < e)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            state.regions.remove(&s);
            if s < range.start {
                state.regions.insert(s, range.start);
            }
            if range.end < e {
                state.regions.insert(range.end, e);
            }
        }
    }
}

/// Whether `error` is the expected, recoverable "the address space moved
/// between attachment and submission" race.
fn is_recoverable_attachment_race(error: &HvfBackendError) -> bool {
    fn memory_is_race(error: &HvfMemoryError) -> bool {
        matches!(error, HvfMemoryError::AttachmentGenerationChanged)
    }
    fn lane_is_race(error: &HvfVcpuLaneError) -> bool {
        match error {
            HvfVcpuLaneError::Memory(inner) => memory_is_race(inner),
            HvfVcpuLaneError::Cleanup { primary, cleanup } => {
                lane_is_race(primary) && lane_is_race(cleanup)
            }
            _ => false,
        }
    }
    match error {
        HvfBackendError::Memory(inner) => memory_is_race(inner),
        HvfBackendError::Lane(inner) => lane_is_race(inner),
        _ => false,
    }
}

fn fatal(what: &str, error: &HvfBackendError) -> ! {
    litebox_util_log::error!(error:% = error; "fatal HVF backend failure while {what}");
    eprintln!("litebox_platform_macos_userland: fatal HVF backend failure while {what}: {error}");
    std::process::abort()
}

fn time_slice_deadline() -> u64 {
    let now: u64;
    // SAFETY: EL0 reads of `CNTVCT_EL0` are permitted on Apple Silicon (it is
    // what `mach_absolute_time` itself reads); the guest sees the same counter
    // because the backend never programs a virtual-timer offset.
    unsafe {
        core::arch::asm!("isb", "mrs {counter}, cntvct_el0", counter = out(reg) now, options(nomem, nostack));
    }
    let ticks = TIME_SLICE
        .as_nanos()
        .saturating_mul(u128::from(TIMER_TICKS_PER_SECOND))
        / 1_000_000_000;
    now.saturating_add(u64::try_from(ticks).unwrap_or(u64::MAX))
}

fn architectural_state(ctx: &PtRegs, thread: &HvfThreadContext) -> HvfArchitecturalState {
    let mut state = HvfArchitecturalState::default();
    for (destination, source) in state.x.iter_mut().zip(ctx.regs.iter()) {
        *destination = *source as u64;
    }
    state.sp_el0 = ctx.sp as u64;
    state.sp_el1 = 0;
    state.pc = ctx.pc as u64;
    state.cpsr = ctx.pstate;
    for (destination, source) in state.q.iter_mut().zip(thread.fp.v.iter()) {
        *destination = HvfSimd128 {
            bytes: source.to_le_bytes(),
        };
    }
    state.fpcr = u64::from(thread.fp.fpcr);
    state.fpsr = u64::from(thread.fp.fpsr);
    state.tpidr_el0 = thread.tpidr_el0;
    state
}

fn capture_thread_state(thread: &mut HvfThreadContext, state: &HvfArchitecturalState) {
    for (destination, source) in thread.fp.v.iter_mut().zip(state.q.iter()) {
        *destination = u128::from_le_bytes(source.bytes);
    }
    thread.fp.fpcr = u32::try_from(state.fpcr & 0xffff_ffff).unwrap_or(0);
    thread.fp.fpsr = u32::try_from(state.fpsr & 0xffff_ffff).unwrap_or(0);
    thread.tpidr_el0 = state.tpidr_el0;
}

fn write_registers(ctx: &mut PtRegs, state: &HvfArchitecturalState, pc: u64, pstate: u64) {
    for (destination, source) in ctx.regs.iter_mut().zip(state.x.iter()) {
        *destination = usize::try_from(*source).unwrap_or(usize::MAX);
    }
    ctx.sp = usize::try_from(state.sp_el0).unwrap_or(usize::MAX);
    ctx.pc = usize::try_from(pc).unwrap_or(usize::MAX);
    ctx.pstate = pstate;
    ctx.orig_x0 = ctx.regs[0];
    ctx.syscallno = -1;
}

/// The guest was interrupted at EL0: its own PC and PSTATE are authoritative.
fn write_direct_exit(ctx: &mut PtRegs, state: &HvfArchitecturalState) {
    write_registers(ctx, state, state.pc, state.cpsr);
}

/// The guest took an EL0 exception into the monitor: the interrupted PC and
/// PSTATE are what the exception entry saved.
fn write_monitor_exit(ctx: &mut PtRegs, state: &HvfArchitecturalState) {
    write_registers(ctx, state, state.elr_el1, state.spsr_el1);
}

fn guest_permissions(permissions: MemoryRegionPermissions) -> Option<HvfGuestPermissions> {
    let mut guest = HvfGuestPermissions::NONE;
    if permissions.contains(MemoryRegionPermissions::READ) {
        guest |= HvfGuestPermissions::READ;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE) {
        // Linux grants read with write; the compact manager requires it.
        guest = guest | HvfGuestPermissions::READ | HvfGuestPermissions::WRITE;
    }
    if permissions.contains(MemoryRegionPermissions::EXEC) {
        guest = guest | HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE;
    }
    if permissions.contains(MemoryRegionPermissions::WRITE)
        && permissions.contains(MemoryRegionPermissions::EXEC)
    {
        return None;
    }
    Some(guest)
}

fn allocation_error(error: HvfMemoryError) -> AllocationError {
    match error {
        HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_) => {
            AllocationError::AddressInUse
        }
        HvfMemoryError::ResourceLimit { .. } | HvfMemoryError::IpaExhausted(_) => {
            AllocationError::OutOfMemory
        }
        other => {
            litebox_util_log::warn!(error:% = other; "HVF mapping failed");
            AllocationError::OutOfMemory
        }
    }
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end
}

/// `range` minus every range in `subtrahends`, as sorted disjoint pieces.
fn subtract_ranges(range: &Range<usize>, subtrahends: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut pieces = vec![range.clone()];
    for subtrahend in subtrahends {
        let mut next = Vec::new();
        for piece in pieces {
            if !overlaps(&piece, subtrahend) {
                next.push(piece);
                continue;
            }
            if piece.start < subtrahend.start {
                next.push(piece.start..subtrahend.start);
            }
            if subtrahend.end < piece.end {
                next.push(subtrahend.end..piece.end);
            }
        }
        pieces = next;
    }
    pieces
}

/// Sorts and merges adjacent/overlapping ranges in place.
fn normalize_ranges(ranges: &mut Vec<Range<usize>>) {
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    *ranges = merged;
}
