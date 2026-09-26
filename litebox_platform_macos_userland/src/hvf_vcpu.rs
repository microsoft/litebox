// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Owner-thread-affine HVF vCPU lanes.
//!
//! Every Hypervisor.framework vCPU is created, driven, and destroyed on one
//! dedicated owner thread (the SDK is owner-affine for everything except
//! `hv_vcpus_exit`).  Other threads talk to a lane through a bounded command
//! queue; the only cross-thread operation is a cancellation kick, which is a
//! request to the owner rather than a mutation of vCPU state.
//!
//! Ownership rules this module enforces:
//!
//! * A lane's registry slot and reaper slot are reserved before the owner
//!   thread is spawned and are released only by the process reaper after the
//!   owner thread has been joined, so capacity accounting is exact.
//! * A vCPU that could not be destroyed is quarantined under its creator
//!   thread identity by the SDK; the owner thread therefore stays alive as a
//!   cleanup custodian, retrying in bounded waves, until nothing owner-keyed
//!   remains.  Retry exhaustion never orphans a resource.
//! * Cancellation attempts are linear, epoch-bound records; a kick that lands
//!   after the run it targeted has already exited is remembered so that the
//!   spurious `Canceled` exit it may produce on the next run is consumed
//!   instead of misattributed.
//! * The command queue owns the closed/drain transition under its own lock, so
//!   a sender that passed its liveness check can never enqueue after the
//!   owner's final drain: the push itself is refused and the sender finishes
//!   its own attachment.

use core::fmt;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::hvf::{
    HvfArchitecturalState, HvfEl1State, HvfError, HvfPstateContext, HvfVcpu, HvfVcpuCancellation,
    HvfVcpuExit, process_hvf_vm,
};
use crate::hvf_memory::{HvfMemoryError, HvfVcpuRunAttachment};

const COMMAND_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_COMMAND_QUEUE_CAPACITY: usize = 64;
const MAX_SHUTDOWN_CANCELLATION_ATTEMPTS: usize = 3;
const OWNER_CLEANUP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Owner-affine destroy retries per custody wave before the lane reports
/// residual vCPUs and settles into cleanup custody.
pub(crate) const OWNER_CLEANUP_WAVE_ATTEMPTS: usize = 8;
const CONTROL_WAIT_POLL: Duration = Duration::from_millis(10);
const STAGE_ONE_TABLE_ALIGNMENT: u64 = 16 * 1024;
const STAGE_ONE_TTBR_BASE_MASK: u64 = 0x0000_ffff_ffff_c000;
const LANE_LIVE: u8 = 0;
const LANE_CLOSING: u8 = 1;
const LANE_ABANDONED: u8 = 2;
const LANE_CLOSED: u8 = 3;

/// Failure injection for the owner-panic-containment witness.  While the
/// counter is nonzero, the next command an owner thread pops consumes one
/// unit and panics synthetically instead of executing it, so the diagnostic
/// can prove `catch_unwind` in [`owner_thread`] contains the unwind: the
/// panic must not escape past this module, must not abort the process, and
/// the lane's own cleanup (vCPU destroy/quarantine, registry release, reaper
/// join) must still run to completion afterwards. Pure Rust, consumed inside
/// the owner thread itself, so no FFI/SDK boundary is touched by the
/// injection.
static OWNER_PANIC_INJECTION: AtomicU8 = AtomicU8::new(0);

struct SynchronizationBarrierState {
    generation: u64,
    armed: Option<u64>,
    reached: Option<u64>,
}

struct SynchronizationBarrier {
    state: Mutex<SynchronizationBarrierState>,
    changed: Condvar,
}

static SYNCHRONIZATION_BARRIER: OnceLock<SynchronizationBarrier> = OnceLock::new();

fn synchronization_barrier() -> &'static SynchronizationBarrier {
    SYNCHRONIZATION_BARRIER.get_or_init(|| SynchronizationBarrier {
        state: Mutex::new(SynchronizationBarrierState {
            generation: 0,
            armed: None,
            reached: None,
        }),
        changed: Condvar::new(),
    })
}

#[must_use]
pub(crate) struct HvfVcpuSynchronizationBarrier {
    generation: u64,
    active: bool,
}

pub(crate) fn arm_vcpu_synchronization_barrier()
-> Result<HvfVcpuSynchronizationBarrier, HvfVcpuLaneError> {
    let barrier = synchronization_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.armed.is_some() {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
    state.generation = generation;
    state.armed = Some(generation);
    state.reached = None;
    barrier.changed.notify_all();
    Ok(HvfVcpuSynchronizationBarrier {
        generation,
        active: true,
    })
}

impl HvfVcpuSynchronizationBarrier {
    pub(crate) fn wait_until_reached(&self) -> Result<(), HvfVcpuLaneError> {
        if !self.active {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let deadline = operation_deadline()?;
        let barrier = synchronization_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.reached == Some(self.generation) {
                return Ok(());
            }
            if state.armed != Some(self.generation) {
                return Err(HvfVcpuLaneError::LaneClosed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HvfVcpuLaneError::OperationTimeout);
            }
            let (next, _) = barrier
                .changed
                .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }

    pub(crate) fn release(mut self) {
        self.disarm();
    }

    fn disarm(&mut self) {
        if !self.active {
            return;
        }
        let barrier = synchronization_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.armed == Some(self.generation) {
            state.armed = None;
        }
        self.active = false;
        barrier.changed.notify_all();
    }
}

impl Drop for HvfVcpuSynchronizationBarrier {
    fn drop(&mut self) {
        self.disarm();
    }
}

fn hold_vcpu_synchronization_barrier() {
    let barrier = synchronization_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(generation) = state.armed else {
        return;
    };
    state.reached = Some(generation);
    barrier.changed.notify_all();
    while state.armed == Some(generation) {
        state = barrier
            .changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    if state.reached == Some(generation) {
        state.reached = None;
    }
    barrier.changed.notify_all();
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RunCompletionBarrierTarget {
    generation: u64,
    lane_generation: u64,
    run_epoch: u64,
}

struct RunCompletionBarrierState {
    generation: u64,
    armed: Option<RunCompletionBarrierTarget>,
    reached: Option<u64>,
}

struct RunCompletionBarrier {
    state: Mutex<RunCompletionBarrierState>,
    changed: Condvar,
}

static RUN_COMPLETION_BARRIER: OnceLock<RunCompletionBarrier> = OnceLock::new();
/// Keeps the ordinary multi-lane exit path free of a process-global mutex when
/// the deterministic completion witness is not armed.
static RUN_COMPLETION_BARRIER_ARMED: AtomicBool = AtomicBool::new(false);

fn run_completion_barrier() -> &'static RunCompletionBarrier {
    RUN_COMPLETION_BARRIER.get_or_init(|| RunCompletionBarrier {
        state: Mutex::new(RunCompletionBarrierState {
            generation: 0,
            armed: None,
            reached: None,
        }),
        changed: Condvar::new(),
    })
}

#[must_use]
pub(crate) struct HvfVcpuRunCompletionBarrier {
    target: RunCompletionBarrierTarget,
    active: bool,
}

pub(crate) fn arm_vcpu_run_completion_barrier(
    lane_generation: u64,
    run_epoch: u64,
) -> Result<HvfVcpuRunCompletionBarrier, HvfVcpuLaneError> {
    if lane_generation == 0 || run_epoch == 0 {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let barrier = run_completion_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.armed.is_some() {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let generation = state
        .generation
        .checked_add(1)
        .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
    let target = RunCompletionBarrierTarget {
        generation,
        lane_generation,
        run_epoch,
    };
    state.generation = generation;
    state.armed = Some(target);
    state.reached = None;
    RUN_COMPLETION_BARRIER_ARMED.store(true, Ordering::Release);
    barrier.changed.notify_all();
    Ok(HvfVcpuRunCompletionBarrier {
        target,
        active: true,
    })
}

impl HvfVcpuRunCompletionBarrier {
    pub(crate) fn wait_until_reached(&self) -> Result<(), HvfVcpuLaneError> {
        if !self.active {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let deadline = operation_deadline()?;
        let barrier = run_completion_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.reached == Some(self.target.generation) {
                return Ok(());
            }
            if state.armed != Some(self.target) {
                return Err(HvfVcpuLaneError::LaneClosed);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HvfVcpuLaneError::OperationTimeout);
            }
            let (next, _) = barrier
                .changed
                .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }

    pub(crate) fn release(mut self) {
        self.disarm();
    }

    fn disarm(&mut self) {
        if !self.active {
            return;
        }
        let barrier = run_completion_barrier();
        let mut state = barrier
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.armed == Some(self.target) {
            state.armed = None;
            RUN_COMPLETION_BARRIER_ARMED.store(false, Ordering::Release);
        }
        self.active = false;
        barrier.changed.notify_all();
    }
}

impl Drop for HvfVcpuRunCompletionBarrier {
    fn drop(&mut self) {
        self.disarm();
    }
}

fn hold_vcpu_run_completion_barrier(lane_generation: u64, run_epoch: u64) {
    if !RUN_COMPLETION_BARRIER_ARMED.load(Ordering::Acquire) {
        return;
    }
    let barrier = run_completion_barrier();
    let mut state = barrier
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(target) = state.armed else {
        return;
    };
    if target.lane_generation != lane_generation || target.run_epoch != run_epoch {
        return;
    }
    state.reached = Some(target.generation);
    barrier.changed.notify_all();
    while state.armed == Some(target) {
        state = barrier
            .changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    if state.reached == Some(target.generation) {
        state.reached = None;
    }
    barrier.changed.notify_all();
}

/// Arms (or disarms with `0`) the owner-panic injection; returns the
/// previously armed count.  Diagnostic-only, crate-private.
pub(crate) fn inject_owner_panic(count: u8) -> u8 {
    OWNER_PANIC_INJECTION.swap(count, Ordering::AcqRel)
}

fn raise_lane_lifecycle(lifecycle: &AtomicU8, target: u8) {
    let mut current = lifecycle.load(Ordering::Acquire);
    while current < target {
        match lifecycle.compare_exchange_weak(current, target, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn hvf_vcpu_lane_is_live(lifecycle: &AtomicU8, owner_stopped: &AtomicBool) -> bool {
    lifecycle.load(Ordering::Acquire) == LANE_LIVE && !owner_stopped.load(Ordering::Acquire)
}

#[derive(Debug)]
pub enum HvfVcpuLaneError {
    Hvf(HvfError),
    Memory(HvfMemoryError),
    Capacity {
        active: u32,
        limit: u32,
    },
    QueueCapacity(usize),
    QueueOverloaded,
    LaneClosed,
    LaneTerminal,
    /// Internal: a cancellation latched while the lane was still entering the
    /// guest, so the run completes as `Canceled` without ever entering it.
    LatchedCancellation,
    VcpuNotRunning,
    CancellationInFlight {
        sequence: u64,
        run_epoch: u64,
    },
    CancellationTooLate {
        sequence: u64,
        run_epoch: u64,
    },
    UnexpectedCancellation {
        run_epoch: u64,
    },
    OperationTimeout,
    ThreadSpawn(std::io::Error),
    OwnerPanicked,
    // The exit record and state snapshot are boxed so that this error, returned from nearly
    // every lane operation, stays small (`clippy::result_large_err`).
    RejectedExit(Box<HvfVcpuExit>),
    InvalidExecutionState {
        exit: Box<HvfVcpuExit>,
        state: Box<HvfSynchronizationExitState>,
    },
    InvalidContinuation {
        pc: u64,
        cpsr: u64,
        esr_el1: u64,
    },
    InvalidSynchronizationExit {
        exit: Box<HvfVcpuExit>,
        lane_generation: u64,
        request: Box<HvfSynchronizationRequest>,
        state: Box<HvfSynchronizationExitState>,
    },
    Cleanup {
        primary: Box<HvfVcpuLaneError>,
        cleanup: Box<HvfVcpuLaneError>,
    },
    RegistryAccounting,
    ResidualVcpus {
        current_thread: usize,
        process: usize,
    },
}

impl fmt::Display for HvfVcpuLaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::Memory(error) => write!(f, "{error}"),
            Self::Capacity { active, limit } => {
                write!(f, "HVF vCPU lane capacity {active}/{limit} is exhausted")
            }
            Self::QueueCapacity(capacity) => write!(
                f,
                "HVF vCPU command queue capacity {capacity} is outside 1..={MAX_COMMAND_QUEUE_CAPACITY}"
            ),
            Self::QueueOverloaded => write!(f, "the bounded HVF vCPU command queue is full"),
            Self::LaneClosed => write!(f, "the HVF vCPU owner lane is closed"),
            Self::LaneTerminal => write!(
                f,
                "the HVF vCPU owner lane reached a terminal execution state"
            ),
            Self::LatchedCancellation => write!(
                f,
                "a cancellation latched before the HVF vCPU entered the guest"
            ),
            Self::VcpuNotRunning => write!(f, "the HVF vCPU owner lane has no active run"),
            Self::CancellationInFlight {
                sequence,
                run_epoch,
            } => write!(
                f,
                "HVF vCPU cancellation {sequence} is already pending for run epoch {run_epoch}"
            ),
            Self::CancellationTooLate {
                sequence,
                run_epoch,
            } => write!(
                f,
                "HVF vCPU cancellation {sequence} arrived too late for run epoch {run_epoch}"
            ),
            Self::UnexpectedCancellation { run_epoch } => write!(
                f,
                "HVF vCPU run epoch {run_epoch} returned an unauthenticated cancellation"
            ),
            Self::OperationTimeout => write!(
                f,
                "timed out waiting for the HVF vCPU owner lane after 30 seconds"
            ),
            Self::ThreadSpawn(error) => write!(f, "failed to spawn HVF vCPU owner lane: {error}"),
            Self::OwnerPanicked => write!(f, "the HVF vCPU owner lane panicked"),
            Self::RejectedExit(exit) => {
                write!(f, "the HVF vCPU returned rejected exit {exit:?}")
            }
            Self::InvalidExecutionState { exit, state } => write!(
                f,
                "the HVF vCPU returned {exit:?} with phase-invalid architectural state {state:?}"
            ),
            Self::InvalidContinuation { pc, cpsr, esr_el1 } => write!(
                f,
                "the HVF vCPU continuation has pc={pc:#x}, cpsr={cpsr:#x}, esr_el1={esr_el1:#x}"
            ),
            Self::InvalidSynchronizationExit {
                exit,
                lane_generation,
                request,
                state,
            } => write!(
                f,
                "HVF synchronization monitor returned {exit:?} on lane {lane_generation} for {request:?}; architectural state={state:?}"
            ),
            Self::Cleanup { primary, cleanup } => {
                write!(f, "{primary}; cleanup also failed: {cleanup}")
            }
            Self::RegistryAccounting => write!(f, "HVF vCPU lane registry accounting failed"),
            Self::ResidualVcpus {
                current_thread,
                process,
            } => write!(
                f,
                "HVF vCPU cleanup retained {current_thread} owner-thread and {process} process-wide quarantined vCPUs; the owner lane stays alive as cleanup custodian"
            ),
        }
    }
}

impl HvfVcpuLaneError {
    fn with_cleanup(self, cleanup: impl Into<Self>) -> Self {
        Self::Cleanup {
            primary: Box::new(self),
            cleanup: Box::new(cleanup.into()),
        }
    }

    /// Errors after which the vCPU's architectural state can no longer be
    /// trusted and the vCPU must be retired rather than resumed.
    fn terminalizes_vcpu(&self) -> bool {
        match self {
            Self::RejectedExit(_)
            | Self::InvalidExecutionState { .. }
            | Self::InvalidSynchronizationExit { .. }
            | Self::UnexpectedCancellation { .. } => true,
            Self::Cleanup { primary, cleanup } => {
                primary.terminalizes_vcpu() || cleanup.terminalizes_vcpu()
            }
            _ => false,
        }
    }

    fn terminalizes_execution_vcpu(&self) -> bool {
        match self {
            Self::Hvf(_) => true,
            Self::Cleanup { primary, cleanup } => {
                primary.terminalizes_execution_vcpu() || cleanup.terminalizes_execution_vcpu()
            }
            _ => self.terminalizes_vcpu(),
        }
    }
}

impl std::error::Error for HvfVcpuLaneError {}

impl From<HvfError> for HvfVcpuLaneError {
    fn from(value: HvfError) -> Self {
        Self::Hvf(value)
    }
}

impl From<HvfMemoryError> for HvfVcpuLaneError {
    fn from(value: HvfMemoryError) -> Self {
        Self::Memory(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfSynchronizationRequest {
    pub address_space_id: u64,
    pub participant_id: u64,
    pub asid: u8,
    pub asid_epoch: u64,
    pub synchronization_ttbr0_el1: u64,
    pub ttbr0_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub root_generation: u64,
    pub executable_generation: u64,
    pub tlbi_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfSynchronizationExitState {
    pub pc: u64,
    pub cpsr: u64,
    pub spsr_el1: u64,
    pub elr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
}

impl From<&HvfArchitecturalState> for HvfSynchronizationExitState {
    fn from(state: &HvfArchitecturalState) -> Self {
        Self {
            pc: state.pc,
            cpsr: state.cpsr,
            spsr_el1: state.spsr_el1,
            elr_el1: state.elr_el1,
            esr_el1: state.esr_el1,
            far_el1: state.far_el1,
        }
    }
}

/// Proof, minted only by an owner thread that actually ran the EL1
/// synchronization monitor under the immutable ASID-zero bootstrap root, that
/// the requested nonzero ASID was invalidated, and that the requested target
/// root was installed afterwards. Deliberately not `Clone`/`Copy`: one monitor
/// trip yields exactly one acknowledgement.
#[derive(Debug, Eq, PartialEq)]
pub struct HvfOwnerSynchronizationProof {
    lane_generation: u64,
    request: HvfSynchronizationRequest,
    synchronization_epoch: u64,
    execution_time: u64,
}

impl HvfOwnerSynchronizationProof {
    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    pub const fn request(&self) -> HvfSynchronizationRequest {
        self.request
    }

    pub const fn synchronization_epoch(&self) -> u64 {
        self.synchronization_epoch
    }

    pub const fn execution_time(&self) -> u64 {
        self.execution_time
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfVcpuExitState {
    DirectGuest(HvfArchitecturalState),
    LowerElMonitor(HvfArchitecturalState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVcpuRunResult {
    pub exit: HvfVcpuExit,
    pub state: HvfVcpuExitState,
    pub run_epoch: u64,
    pub execution_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVtimerState {
    pub masked: bool,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVcpuLaneCloseReport {
    pub lane_generation: u64,
    pub cleanup_attempts: usize,
    pub residual_vcpus: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfVcpuCancellationReceipt {
    pub lane_generation: u64,
    pub sequence: u64,
    pub observed_run_epoch: u64,
}

impl HvfVcpuCancellationReceipt {
    const fn from_key(key: CancellationAttemptKey) -> Self {
        Self {
            lane_generation: key.lane_generation,
            sequence: key.sequence,
            observed_run_epoch: key.target.epoch(),
        }
    }
}

// ---------------------------------------------------------------------------
// Run control: the owner's execution phase plus linear cancellation attempts.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionPhase {
    Idle,
    Reserved {
        run_epoch: u64,
    },
    Synchronizing {
        synchronization_epoch: u64,
        run_epoch: Option<u64>,
    },
    Entering {
        run_epoch: u64,
    },
    Running {
        run_epoch: u64,
    },
    /// The run outcome is fixed: either `hv_vcpu_run` returned or a pre-entry
    /// cancellation was already applied. Owner-side exit/state validation and
    /// reservation settlement are not complete, but another public cancellation
    /// is too late and must not be mistaken for pre-entry.
    Completing {
        run_epoch: u64,
    },
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationTarget {
    Synchronization { synchronization_epoch: u64 },
    Run { run_epoch: u64 },
}

impl CancellationTarget {
    const fn epoch(self) -> u64 {
        match self {
            Self::Synchronization {
                synchronization_epoch,
            } => synchronization_epoch,
            Self::Run { run_epoch } => run_epoch,
        }
    }
}

#[derive(Clone, Debug)]
enum CancellationCompletion {
    /// The targeted run exited with `Canceled` because of this attempt.
    Applied,
    /// The targeted run had already exited when the kick landed.
    TooLate,
    /// The kick itself could not be issued.
    Failed(HvfError),
    /// The requester stopped waiting before the owner observed the outcome.
    Expired,
    Terminalized,
}

#[derive(Clone, Debug)]
enum CancellationProgress {
    Issuing,
    Issued,
    Completed(CancellationCompletion),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CancellationAttemptKey {
    lane_generation: u64,
    sdk_generation: u64,
    sequence: u64,
    target: CancellationTarget,
}

struct CancellationAttempt {
    key: CancellationAttemptKey,
    progress: Mutex<CancellationProgress>,
    changed: Condvar,
}

impl CancellationAttempt {
    fn new(key: CancellationAttemptKey) -> Self {
        Self {
            key,
            progress: Mutex::new(CancellationProgress::Issuing),
            changed: Condvar::new(),
        }
    }

    const fn key(&self) -> CancellationAttemptKey {
        self.key
    }

    fn progress(&self) -> CancellationProgress {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn mark_issued(&self) -> Result<(), HvfVcpuLaneError> {
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*progress, CancellationProgress::Issuing) {
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        *progress = CancellationProgress::Issued;
        self.changed.notify_all();
        Ok(())
    }

    /// Records the outcome exactly once; returns `false` if it was already
    /// completed by the other side.
    fn complete(&self, completion: CancellationCompletion) -> bool {
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(
            *progress,
            CancellationProgress::Issuing | CancellationProgress::Issued
        ) {
            return false;
        }
        *progress = CancellationProgress::Completed(completion);
        self.changed.notify_all();
        true
    }

    fn wait_until(&self, deadline: Instant) -> Option<CancellationCompletion> {
        let mut progress = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let CancellationProgress::Completed(completion) = &*progress {
                return Some(completion.clone());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (next, _) = self
                .changed
                .wait_timeout(progress, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            progress = next;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunDisposition {
    /// Deliver the exit to the requester.
    Deliver,
    /// The exit was a spurious `Canceled` produced by a stale kick; run again.
    Rerun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SynchronizationDisposition {
    Completed,
    Rerun,
    Canceled(HvfVcpuCancellationReceipt),
}

struct RunControlState {
    phase: ExecutionPhase,
    synchronization_epoch: u64,
    run_epoch: u64,
    cancellation_sequence: u64,
    cancellation: Option<Arc<CancellationAttempt>>,
    /// A public cancellation that arrived while the owner was between
    /// admitting a run and entering the guest (synchronizing or entering).
    /// No SDK kick is issued for it; `begin_running` consumes it and the run
    /// completes as `Canceled` without entering the guest.  This closes the
    /// window in which an interrupt aimed at a run in progress would otherwise
    /// be reported as "not running" and lost until the guest's next exit.
    latched: Option<Arc<CancellationAttempt>>,
    shutdown_requested: bool,
    /// A kick was issued after its target run had already exited; the SDK may
    /// deliver it as an immediate `Canceled` on the next `hv_vcpu_run`.
    stale_kick_possible: bool,
    /// The terminal phase was reached because the vCPU's state can no longer
    /// be trusted (inconsistent phase, unauthenticated exit, lost kick), as
    /// opposed to an orderly shutdown.  Only an untrusted vCPU is quarantined;
    /// a shut-down one is destroyed normally.
    untrusted: bool,
}

struct RunControl {
    state: Mutex<RunControlState>,
    changed: Condvar,
}

impl RunControl {
    fn new() -> Self {
        Self {
            state: Mutex::new(RunControlState {
                phase: ExecutionPhase::Idle,
                synchronization_epoch: 0,
                run_epoch: 0,
                cancellation_sequence: 0,
                cancellation: None,
                latched: None,
                shutdown_requested: false,
                stale_kick_possible: false,
                untrusted: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RunControlState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn phase(&self) -> ExecutionPhase {
        self.lock().phase
    }

    fn is_running(&self) -> bool {
        matches!(self.phase(), ExecutionPhase::Running { .. })
    }

    fn is_terminal(&self) -> bool {
        self.phase() == ExecutionPhase::Terminal
    }

    fn is_untrusted(&self) -> bool {
        self.lock().untrusted
    }

    fn is_reusable(&self) -> bool {
        let state = self.lock();
        state.phase == ExecutionPhase::Idle
            && state.cancellation.is_none()
            && state.latched.is_none()
            && !state.shutdown_requested
            && !state.untrusted
    }

    fn run_epoch(&self) -> u64 {
        self.lock().run_epoch
    }

    fn complete_attempt(
        slot: &mut Option<Arc<CancellationAttempt>>,
        completion: CancellationCompletion,
    ) {
        if let Some(attempt) = slot.take() {
            let _ = attempt.complete(completion);
        }
    }

    fn terminalize(
        &self,
        state: &mut RunControlState,
        untrusted: bool,
        latched_completion: CancellationCompletion,
    ) {
        Self::complete_attempt(
            &mut state.cancellation,
            CancellationCompletion::Terminalized,
        );
        Self::complete_attempt(&mut state.latched, latched_completion);
        state.phase = ExecutionPhase::Terminal;
        state.stale_kick_possible = false;
        state.untrusted |= untrusted;
        self.changed.notify_all();
    }

    fn set_terminal(&self, state: &mut RunControlState) {
        self.terminalize(state, true, CancellationCompletion::Terminalized);
    }

    fn set_orderly_terminal(&self, state: &mut RunControlState) {
        self.terminalize(state, false, CancellationCompletion::Applied);
    }

    fn settle_synchronization(
        &self,
        state: &mut RunControlState,
        run_epoch: Option<u64>,
        failed: bool,
    ) {
        if failed {
            self.set_terminal(state);
        } else if state.shutdown_requested {
            self.set_orderly_terminal(state);
        } else {
            state.phase = match run_epoch {
                Some(run_epoch) => ExecutionPhase::Reserved { run_epoch },
                None => ExecutionPhase::Idle,
            };
            self.changed.notify_all();
        }
    }

    fn settle_run(&self, state: &mut RunControlState, run_epoch: u64, failed: bool) {
        if failed {
            self.set_terminal(state);
        } else if state.shutdown_requested {
            self.set_orderly_terminal(state);
        } else {
            state.phase = ExecutionPhase::Completing { run_epoch };
            self.changed.notify_all();
        }
    }

    fn next_cancellation_attempt(
        state: &mut RunControlState,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
        target: CancellationTarget,
    ) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        if let Some(attempt) = state.cancellation.as_ref() {
            return Err(HvfVcpuLaneError::CancellationInFlight {
                sequence: attempt.key().sequence,
                run_epoch: attempt.key().target.epoch(),
            });
        }
        let sequence = state
            .cancellation_sequence
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        let attempt = Arc::new(CancellationAttempt::new(CancellationAttemptKey {
            lane_generation,
            sdk_generation: cancellation.generation(),
            sequence,
            target,
        }));
        state.cancellation_sequence = sequence;
        state.cancellation = Some(Arc::clone(&attempt));
        Ok(attempt)
    }

    /// Issues the SDK kick while the control lock is held, so the owner's
    /// `finish_*` (which needs the same lock) observes the attempt either
    /// fully issued or fully withdrawn, never half-way.
    fn issue_cancellation(
        &self,
        state: &mut RunControlState,
        attempt: &Arc<CancellationAttempt>,
        cancellation: &HvfVcpuCancellation,
    ) -> Result<(), HvfVcpuLaneError> {
        match cancellation.cancel() {
            Ok(()) => match attempt.mark_issued() {
                Ok(()) => Ok(()),
                Err(error) => {
                    let _ = attempt.complete(CancellationCompletion::Terminalized);
                    state.shutdown_requested = true;
                    state.stale_kick_possible = true;
                    state.untrusted = true;
                    self.changed.notify_all();
                    Err(error)
                }
            },
            Err(error) => {
                if !attempt.complete(CancellationCompletion::Failed(error.clone())) {
                    state.shutdown_requested = true;
                    state.stale_kick_possible = true;
                    state.untrusted = true;
                    self.changed.notify_all();
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                state.shutdown_requested = true;
                state.stale_kick_possible = true;
                state.untrusted = true;
                self.changed.notify_all();
                Err(error.into())
            }
        }
    }

    fn abandon_timed_out_attempt(&self, attempt: &CancellationAttempt) {
        let _ = attempt.complete(CancellationCompletion::Expired);
        let mut state = self.lock();
        state.shutdown_requested = true;
        state.untrusted = true;
        self.changed.notify_all();
    }

    fn await_attempt(
        &self,
        attempt: &CancellationAttempt,
        deadline: Instant,
    ) -> Result<HvfVcpuCancellationReceipt, HvfVcpuLaneError> {
        let key = attempt.key();
        let completion = if let Some(completion) = attempt.wait_until(deadline) {
            completion
        } else if attempt.complete(CancellationCompletion::Expired) {
            self.abandon_timed_out_attempt(attempt);
            return Err(HvfVcpuLaneError::OperationTimeout);
        } else {
            match attempt.progress() {
                CancellationProgress::Completed(completion) => completion,
                CancellationProgress::Issuing | CancellationProgress::Issued => {
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
            }
        };
        match completion {
            CancellationCompletion::Applied => Ok(HvfVcpuCancellationReceipt::from_key(key)),
            CancellationCompletion::TooLate => Err(HvfVcpuLaneError::CancellationTooLate {
                sequence: key.sequence,
                run_epoch: key.target.epoch(),
            }),
            CancellationCompletion::Failed(error) => Err(error.into()),
            CancellationCompletion::Expired => {
                self.abandon_timed_out_attempt(attempt);
                Err(HvfVcpuLaneError::OperationTimeout)
            }
            CancellationCompletion::Terminalized => Err(HvfVcpuLaneError::LaneClosed),
        }
    }

    fn reserve_run(&self) -> Result<u64, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        match state.phase {
            ExecutionPhase::Idle => {}
            ExecutionPhase::Terminal => return Err(HvfVcpuLaneError::LaneTerminal),
            _ => return Err(HvfVcpuLaneError::RegistryAccounting),
        }
        if state.cancellation.is_some() || state.latched.is_some() || state.untrusted {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let run_epoch = state
            .run_epoch
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        state.run_epoch = run_epoch;
        state.phase = ExecutionPhase::Reserved { run_epoch };
        self.changed.notify_all();
        Ok(run_epoch)
    }

    fn begin_synchronizing(&self, run_epoch: Option<u64>) -> Result<u64, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        match (state.phase, run_epoch) {
            (ExecutionPhase::Idle, None) => {}
            (
                ExecutionPhase::Reserved {
                    run_epoch: reserved,
                },
                Some(run_epoch),
            ) if reserved == run_epoch => {}
            (ExecutionPhase::Terminal, _) => return Err(HvfVcpuLaneError::LaneTerminal),
            _ => return Err(HvfVcpuLaneError::RegistryAccounting),
        }
        if state.cancellation.is_some() || (run_epoch.is_none() && state.latched.is_some()) {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let synchronization_epoch = state
            .synchronization_epoch
            .checked_add(1)
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        state.synchronization_epoch = synchronization_epoch;
        state.phase = ExecutionPhase::Synchronizing {
            synchronization_epoch,
            run_epoch,
        };
        self.changed.notify_all();
        Ok(synchronization_epoch)
    }

    fn finish_synchronizing(
        &self,
        synchronization_epoch: u64,
        exit: &Result<HvfVcpuExit, HvfError>,
    ) -> Result<SynchronizationDisposition, HvfVcpuLaneError> {
        let mut state = self.lock();
        let run_epoch = match state.phase {
            ExecutionPhase::Synchronizing {
                synchronization_epoch: active_epoch,
                run_epoch,
            } if active_epoch == synchronization_epoch => run_epoch,
            _ => {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
        };
        let target = CancellationTarget::Synchronization {
            synchronization_epoch,
        };
        let canceled = matches!(exit, Ok(HvfVcpuExit::Canceled));
        let attempt = state
            .cancellation
            .as_ref()
            .filter(|attempt| attempt.key().target == target)
            .cloned();
        match (canceled, attempt) {
            (true, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::Applied) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::UnexpectedCancellation {
                            run_epoch: synchronization_epoch,
                        });
                    }
                }
                state.cancellation = None;
                self.set_orderly_terminal(&mut state);
                Ok(SynchronizationDisposition::Canceled(
                    HvfVcpuCancellationReceipt::from_key(attempt.key()),
                ))
            }
            (true, None) => {
                if state.stale_kick_possible {
                    state.stale_kick_possible = false;
                    self.settle_synchronization(&mut state, run_epoch, false);
                    Ok(SynchronizationDisposition::Rerun)
                } else {
                    self.set_terminal(&mut state);
                    Err(HvfVcpuLaneError::UnexpectedCancellation {
                        run_epoch: synchronization_epoch,
                    })
                }
            }
            (false, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::TooLate) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                        state.stale_kick_possible = true;
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {
                        state.stale_kick_possible = true;
                    }
                    CancellationProgress::Completed(CancellationCompletion::Failed(_)) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                }
                state.cancellation = None;
                self.settle_synchronization(&mut state, run_epoch, exit.is_err());
                Ok(SynchronizationDisposition::Completed)
            }
            (false, None) => {
                state.stale_kick_possible = false;
                self.settle_synchronization(&mut state, run_epoch, exit.is_err());
                Ok(SynchronizationDisposition::Completed)
            }
        }
    }

    fn begin_run(&self, run_epoch: u64) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            self.set_orderly_terminal(&mut state);
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        match state.phase {
            ExecutionPhase::Reserved {
                run_epoch: reserved,
            } if reserved == run_epoch => {}
            ExecutionPhase::Terminal => return Err(HvfVcpuLaneError::LaneTerminal),
            _ => {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
        }
        if state.cancellation.is_some() {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        state.phase = ExecutionPhase::Entering { run_epoch };
        self.changed.notify_all();
        Ok(())
    }

    fn consume_latched(
        &self,
        state: &mut RunControlState,
        run_epoch: u64,
    ) -> Result<bool, HvfVcpuLaneError> {
        let Some(attempt) = state.latched.take() else {
            return Ok(false);
        };
        if attempt.key().target != (CancellationTarget::Run { run_epoch }) {
            let _ = attempt.complete(CancellationCompletion::Terminalized);
            self.set_terminal(state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        match attempt.progress() {
            CancellationProgress::Issued => {
                if !attempt.complete(CancellationCompletion::Applied) {
                    self.set_terminal(state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
            }
            CancellationProgress::Completed(CancellationCompletion::Expired) => {}
            _ => {
                self.set_terminal(state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
        }
        Ok(true)
    }

    fn begin_running(&self, run_epoch: u64) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            self.set_orderly_terminal(&mut state);
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        if state.phase != (ExecutionPhase::Entering { run_epoch }) {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        if self.consume_latched(&mut state, run_epoch)? {
            self.settle_run(&mut state, run_epoch, false);
            return Err(HvfVcpuLaneError::LatchedCancellation);
        }
        state.phase = ExecutionPhase::Running { run_epoch };
        self.changed.notify_all();
        Ok(())
    }

    fn settle_reservation(
        &self,
        run_epoch: u64,
        lane_live: bool,
        untrusted: bool,
    ) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        match state.phase {
            ExecutionPhase::Reserved {
                run_epoch: reserved,
            }
            | ExecutionPhase::Entering {
                run_epoch: reserved,
            }
            | ExecutionPhase::Completing {
                run_epoch: reserved,
            } if reserved == run_epoch => {
                let preentry = !matches!(state.phase, ExecutionPhase::Completing { .. });
                if untrusted {
                    self.set_terminal(&mut state);
                    return Ok(());
                }
                if state.cancellation.is_some() {
                    self.set_terminal(&mut state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                if let Some(attempt) = state.latched.take() {
                    if !preentry {
                        let _ = attempt.complete(CancellationCompletion::Terminalized);
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                    if attempt.key().target != (CancellationTarget::Run { run_epoch }) {
                        let _ = attempt.complete(CancellationCompletion::Terminalized);
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                    match attempt.progress() {
                        CancellationProgress::Issued => {
                            if !attempt.complete(CancellationCompletion::Applied) {
                                self.set_terminal(&mut state);
                                return Err(HvfVcpuLaneError::RegistryAccounting);
                            }
                        }
                        CancellationProgress::Completed(CancellationCompletion::Expired) => {}
                        _ => {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                    }
                }
                if lane_live && !state.shutdown_requested {
                    state.phase = ExecutionPhase::Idle;
                    self.changed.notify_all();
                } else {
                    self.set_orderly_terminal(&mut state);
                }
                Ok(())
            }
            ExecutionPhase::Terminal => {
                let was_untrusted = state.untrusted;
                self.terminalize(
                    &mut state,
                    was_untrusted,
                    CancellationCompletion::Terminalized,
                );
                Ok(())
            }
            ExecutionPhase::Synchronizing {
                run_epoch: Some(active),
                ..
            }
            | ExecutionPhase::Running { run_epoch: active }
                if active == run_epoch =>
            {
                self.set_terminal(&mut state);
                Err(HvfVcpuLaneError::RegistryAccounting)
            }
            _ => {
                self.set_terminal(&mut state);
                Err(HvfVcpuLaneError::RegistryAccounting)
            }
        }
    }

    fn finish_run(
        &self,
        run_epoch: u64,
        exit: &Result<HvfVcpuExit, HvfError>,
    ) -> Result<RunDisposition, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.phase != (ExecutionPhase::Running { run_epoch }) {
            self.set_terminal(&mut state);
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let target = CancellationTarget::Run { run_epoch };
        let canceled = matches!(exit, Ok(HvfVcpuExit::Canceled));
        let attempt = state
            .cancellation
            .as_ref()
            .filter(|attempt| attempt.key().target == target)
            .cloned();
        match (canceled, attempt) {
            (true, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::Applied) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::UnexpectedCancellation { run_epoch });
                    }
                }
                state.cancellation = None;
                self.settle_run(&mut state, run_epoch, false);
                Ok(RunDisposition::Deliver)
            }
            (true, None) => {
                if state.stale_kick_possible {
                    state.stale_kick_possible = false;
                    if state.shutdown_requested {
                        self.set_orderly_terminal(&mut state);
                        Ok(RunDisposition::Deliver)
                    } else {
                        state.phase = ExecutionPhase::Reserved { run_epoch };
                        self.changed.notify_all();
                        Ok(RunDisposition::Rerun)
                    }
                } else {
                    self.set_terminal(&mut state);
                    Err(HvfVcpuLaneError::UnexpectedCancellation { run_epoch })
                }
            }
            (false, Some(attempt)) => {
                match attempt.progress() {
                    CancellationProgress::Issued => {
                        if !attempt.complete(CancellationCompletion::TooLate) {
                            self.set_terminal(&mut state);
                            return Err(HvfVcpuLaneError::RegistryAccounting);
                        }
                        state.stale_kick_possible = true;
                    }
                    CancellationProgress::Completed(CancellationCompletion::Expired) => {
                        state.stale_kick_possible = true;
                    }
                    CancellationProgress::Completed(CancellationCompletion::Failed(_)) => {}
                    _ => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                }
                state.cancellation = None;
                self.settle_run(&mut state, run_epoch, exit.is_err());
                Ok(RunDisposition::Deliver)
            }
            (false, None) => {
                state.stale_kick_possible = false;
                self.settle_run(&mut state, run_epoch, exit.is_err());
                Ok(RunDisposition::Deliver)
            }
        }
    }

    fn request_public(
        &self,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
        requested_run_epoch: Option<u64>,
    ) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        let mut state = self.lock();
        if state.shutdown_requested {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let (run_epoch, running) = match state.phase {
            ExecutionPhase::Reserved { run_epoch } | ExecutionPhase::Entering { run_epoch } => {
                (run_epoch, false)
            }
            ExecutionPhase::Synchronizing {
                run_epoch: Some(run_epoch),
                ..
            } => (run_epoch, false),
            ExecutionPhase::Running { run_epoch } => (run_epoch, true),
            ExecutionPhase::Idle
            | ExecutionPhase::Synchronizing {
                run_epoch: None, ..
            }
            | ExecutionPhase::Completing { .. }
            | ExecutionPhase::Terminal => return Err(HvfVcpuLaneError::VcpuNotRunning),
        };
        if requested_run_epoch.is_some_and(|requested| requested != run_epoch) {
            return Err(HvfVcpuLaneError::VcpuNotRunning);
        }
        let target = CancellationTarget::Run { run_epoch };
        if running {
            if state.latched.is_some() {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
            let attempt =
                Self::next_cancellation_attempt(&mut state, lane_generation, cancellation, target)?;
            self.issue_cancellation(&mut state, &attempt, cancellation)?;
            Ok(attempt)
        } else {
            Self::latch_cancellation(&mut state, lane_generation, cancellation, target)
        }
    }

    fn latch_cancellation(
        state: &mut RunControlState,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
        target: CancellationTarget,
    ) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        if let Some(latched) = state.latched.as_ref() {
            return Err(HvfVcpuLaneError::CancellationInFlight {
                sequence: latched.key().sequence,
                run_epoch: latched.key().target.epoch(),
            });
        }
        let attempt =
            Self::next_cancellation_attempt(state, lane_generation, cancellation, target)?;
        // Not an SDK kick: move it out of the kick slot into the latch.
        state.cancellation = None;
        attempt.mark_issued()?;
        state.latched = Some(Arc::clone(&attempt));
        Ok(attempt)
    }

    fn request_shutdown(
        &self,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
    ) -> Result<(), HvfVcpuLaneError> {
        let mut state = self.lock();
        state.shutdown_requested = true;
        self.changed.notify_all();
        let target = match state.phase {
            ExecutionPhase::Synchronizing {
                synchronization_epoch,
                ..
            } => CancellationTarget::Synchronization {
                synchronization_epoch,
            },
            ExecutionPhase::Running { run_epoch } => CancellationTarget::Run { run_epoch },
            ExecutionPhase::Idle
            | ExecutionPhase::Reserved { .. }
            | ExecutionPhase::Entering { .. }
            | ExecutionPhase::Completing { .. } => {
                self.set_orderly_terminal(&mut state);
                return Ok(());
            }
            ExecutionPhase::Terminal => {
                let was_untrusted = state.untrusted;
                self.terminalize(
                    &mut state,
                    was_untrusted,
                    CancellationCompletion::Terminalized,
                );
                return Ok(());
            }
        };
        if let Some(attempt) = state.cancellation.clone() {
            if attempt.key().target != target {
                self.set_terminal(&mut state);
                return Err(HvfVcpuLaneError::RegistryAccounting);
            }
            match attempt.progress() {
                CancellationProgress::Issuing | CancellationProgress::Issued => {
                    let _ = attempt.complete(CancellationCompletion::Terminalized);
                    state.cancellation = None;
                    state.stale_kick_possible = true;
                }
                CancellationProgress::Completed(
                    CancellationCompletion::Expired
                    | CancellationCompletion::Failed(_)
                    | CancellationCompletion::Terminalized,
                ) => {
                    state.cancellation = None;
                }
                CancellationProgress::Completed(
                    CancellationCompletion::Applied | CancellationCompletion::TooLate,
                ) => {
                    self.set_terminal(&mut state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
            }
        }
        let attempt =
            Self::next_cancellation_attempt(&mut state, lane_generation, cancellation, target)?;
        self.issue_cancellation(&mut state, &attempt, cancellation)
    }

    fn cancel_for_shutdown(
        &self,
        lane_generation: u64,
        cancellation: &HvfVcpuCancellation,
    ) -> Result<(), HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        let mut issued = 0usize;
        let mut state = self.lock();
        state.shutdown_requested = true;
        self.changed.notify_all();
        loop {
            let target = match state.phase {
                ExecutionPhase::Idle
                | ExecutionPhase::Reserved { .. }
                | ExecutionPhase::Entering { .. }
                | ExecutionPhase::Completing { .. } => {
                    self.set_orderly_terminal(&mut state);
                    return Ok(());
                }
                ExecutionPhase::Terminal => return Ok(()),
                ExecutionPhase::Synchronizing {
                    synchronization_epoch,
                    ..
                } => CancellationTarget::Synchronization {
                    synchronization_epoch,
                },
                ExecutionPhase::Running { run_epoch } => CancellationTarget::Run { run_epoch },
            };
            let pending = if let Some(attempt) = state.cancellation.clone() {
                if attempt.key().target != target {
                    self.set_terminal(&mut state);
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                match attempt.progress() {
                    CancellationProgress::Issuing | CancellationProgress::Issued => Some(attempt),
                    CancellationProgress::Completed(
                        CancellationCompletion::Expired
                        | CancellationCompletion::Failed(_)
                        | CancellationCompletion::Terminalized,
                    ) => {
                        state.cancellation = None;
                        None
                    }
                    CancellationProgress::Completed(
                        CancellationCompletion::Applied | CancellationCompletion::TooLate,
                    ) => {
                        self.set_terminal(&mut state);
                        return Err(HvfVcpuLaneError::RegistryAccounting);
                    }
                }
            } else {
                None
            };
            let attempt = if let Some(attempt) = pending {
                attempt
            } else {
                if issued >= MAX_SHUTDOWN_CANCELLATION_ATTEMPTS {
                    state.untrusted = true;
                    self.changed.notify_all();
                    return Err(HvfVcpuLaneError::OperationTimeout);
                }
                issued += 1;
                let attempt = Self::next_cancellation_attempt(
                    &mut state,
                    lane_generation,
                    cancellation,
                    target,
                )?;
                self.issue_cancellation(&mut state, &attempt, cancellation)?;
                attempt
            };
            drop(state);
            let completion = attempt.wait_until(deadline);
            state = self.lock();
            match completion {
                None => {
                    let _ = attempt.complete(CancellationCompletion::Expired);
                    state.untrusted = true;
                    self.changed.notify_all();
                    return Err(HvfVcpuLaneError::OperationTimeout);
                }
                Some(CancellationCompletion::Failed(error)) => return Err(error.into()),
                Some(
                    CancellationCompletion::Applied
                    | CancellationCompletion::TooLate
                    | CancellationCompletion::Expired
                    | CancellationCompletion::Terminalized,
                ) => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.untrusted = true;
                self.changed.notify_all();
                return Err(HvfVcpuLaneError::OperationTimeout);
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining.min(CONTROL_WAIT_POLL))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }
}

// ---------------------------------------------------------------------------
// Capabilities handed to the memory manager.
// ---------------------------------------------------------------------------

/// Opaque, single-use proof that a lane is live, minted only by a live lane
/// handle.  The memory manager consumes it to register a vCPU participant; no
/// numeric generation is ever accepted in its place.
#[must_use = "an HVF vCPU participant capability must be registered or explicitly discarded"]
pub struct HvfVcpuLaneParticipantCapability {
    generation: u64,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    admission: Arc<Mutex<()>>,
}

pub(crate) struct HvfVcpuLaneRegistration {
    pub(crate) generation: u64,
    pub(crate) lifecycle: Arc<AtomicU8>,
    pub(crate) owner_stopped: Arc<AtomicBool>,
}

impl HvfVcpuLaneRegistration {
    pub(crate) fn is_live(&self) -> bool {
        hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped)
    }
}

impl fmt::Debug for HvfVcpuLaneParticipantCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLaneParticipantCapability")
            .field("generation", &self.generation)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("owner_stopped", &self.owner_stopped.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLaneParticipantCapability {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn with_live_registration<R>(
        self,
        register: impl FnOnce(HvfVcpuLaneRegistration) -> R,
    ) -> Result<R, HvfVcpuLaneError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped) {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        Ok(register(HvfVcpuLaneRegistration {
            generation: self.generation,
            lifecycle: Arc::clone(&self.lifecycle),
            owner_stopped: Arc::clone(&self.owner_stopped),
        }))
    }
}

#[must_use]
pub struct HvfVcpuRunReservation {
    lane_generation: u64,
    run_epoch: u64,
    cancellation: HvfVcpuLaneCancellation,
    active: bool,
}

impl fmt::Debug for HvfVcpuRunReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuRunReservation")
            .field("lane_generation", &self.lane_generation)
            .field("run_epoch", &self.run_epoch)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl HvfVcpuRunReservation {
    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    pub const fn run_epoch(&self) -> u64 {
        self.run_epoch
    }

    pub fn cancellation(&self) -> HvfVcpuLaneCancellation {
        self.cancellation.clone()
    }

    fn belongs_to(&self, handle: &HvfVcpuLaneHandle) -> bool {
        self.active
            && self.lane_generation == handle.generation
            && Arc::ptr_eq(&self.cancellation.control, &handle.control)
            && Arc::ptr_eq(&self.cancellation.lifecycle, &handle.lifecycle)
    }

    fn settle(&mut self, untrusted: bool) -> Result<(), HvfVcpuLaneError> {
        if !self.active {
            return Ok(());
        }
        let lane_live = self.cancellation.lifecycle.load(Ordering::Acquire) == LANE_LIVE;
        let result =
            self.cancellation
                .control
                .settle_reservation(self.run_epoch, lane_live, untrusted);
        self.active = false;
        if result.is_err() || self.cancellation.control.is_untrusted() {
            raise_lane_lifecycle(&self.cancellation.lifecycle, LANE_ABANDONED);
            self.cancellation.command_queue.wake();
            self.cancellation.reaper.unpark();
        }
        result
    }
}

impl Drop for HvfVcpuRunReservation {
    fn drop(&mut self) {
        let _ = self.settle(false);
    }
}

#[derive(Clone)]
pub struct HvfVcpuLaneCancellation {
    lane_generation: u64,
    run_epoch: Option<u64>,
    cancellation: HvfVcpuCancellation,
    attempt: Arc<Mutex<Option<Arc<CancellationAttempt>>>>,
    lifecycle: Arc<AtomicU8>,
    control: Arc<RunControl>,
    command_queue: Arc<CommandQueue>,
    reaper: std::thread::Thread,
}

impl fmt::Debug for HvfVcpuLaneCancellation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLaneCancellation")
            .field("lane_generation", &self.lane_generation)
            .field("run_epoch", &self.run_epoch)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("running", &self.control.is_running())
            .field("run_epoch", &self.control.run_epoch())
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLaneCancellation {
    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    pub(crate) fn is_same_run(&self, other: &Self) -> bool {
        self.run_epoch.is_some()
            && self.lane_generation == other.lane_generation
            && self.run_epoch == other.run_epoch
            && self.cancellation.generation() == other.cancellation.generation()
            && Arc::ptr_eq(&self.attempt, &other.attempt)
            && Arc::ptr_eq(&self.lifecycle, &other.lifecycle)
            && Arc::ptr_eq(&self.control, &other.control)
    }

    fn request_attempt(&self) -> Result<Arc<CancellationAttempt>, HvfVcpuLaneError> {
        let mut requested = self
            .attempt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(attempt) = requested.as_ref() {
            return Ok(Arc::clone(attempt));
        }
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let result =
            self.control
                .request_public(self.lane_generation, &self.cancellation, self.run_epoch);
        if let Ok(attempt) = &result {
            *requested = Some(Arc::clone(attempt));
        }
        if result.is_err() && self.control.is_untrusted() {
            raise_lane_lifecycle(&self.lifecycle, LANE_ABANDONED);
            self.command_queue.wake();
            self.reaper.unpark();
        }
        result
    }

    pub fn request(&self) -> Result<(), HvfVcpuLaneError> {
        self.request_attempt().map(|_| ())
    }

    pub fn cancel(&self) -> Result<HvfVcpuCancellationReceipt, HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        let attempt = self.request_attempt()?;
        let result = self.control.await_attempt(&attempt, deadline);
        if result.is_err() && self.control.is_untrusted() {
            raise_lane_lifecycle(&self.lifecycle, LANE_ABANDONED);
            self.command_queue.wake();
            self.reaper.unpark();
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Bounded command queue with an owner-driven closed/drain transition.
// ---------------------------------------------------------------------------

struct CommandQueueState {
    commands: VecDeque<Command>,
    closed: bool,
}

struct CommandQueue {
    capacity: usize,
    state: Mutex<CommandQueueState>,
    owner: OnceLock<std::thread::Thread>,
}

enum PushRejection {
    Closed(Command),
    Full(Command),
}

impl CommandQueue {
    fn new(capacity: usize) -> Result<Self, HvfVcpuLaneError> {
        let mut commands = VecDeque::new();
        commands
            .try_reserve_exact(capacity)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
        Ok(Self {
            capacity,
            state: Mutex::new(CommandQueueState {
                commands,
                closed: false,
            }),
            owner: OnceLock::new(),
        })
    }

    fn register_owner(&self) -> Result<(), HvfVcpuLaneError> {
        self.owner
            .set(std::thread::current())
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the rejected command is handed back so the sender can finish its own attachment; boxing would put an allocation on the syscall path"
    )]
    fn try_push(&self, command: Command) -> Result<(), PushRejection> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(PushRejection::Closed(command));
        }
        if state.commands.len() >= self.capacity {
            return Err(PushRejection::Full(command));
        }
        state.commands.push_back(command);
        drop(state);
        self.wake();
        Ok(())
    }

    fn pop(&self) -> Option<Command> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commands
            .pop_front()
    }

    /// Refuses every future push and returns everything still queued.  The
    /// closed flag and the drain are one critical section, so no sender that
    /// already passed its liveness check can slip a command in afterwards.
    fn close_and_drain(&self) -> VecDeque<Command> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        core::mem::take(&mut state.commands)
    }

    fn wake(&self) {
        if let Some(owner) = self.owner.get() {
            owner.unpark();
        }
    }
}

// ---------------------------------------------------------------------------
// Process registry and reaper.
// ---------------------------------------------------------------------------

struct RegistryState {
    next_generation: u64,
    active: u32,
    custodial: u32,
}

struct RegistryShared {
    limit: u32,
    state: Mutex<RegistryState>,
}

fn release_registry_lane(shared: &RegistryShared) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match state.active.checked_sub(1) {
        Some(active) => {
            state.active = active;
            true
        }
        None => false,
    }
}

fn adjust_registry_custodial(shared: &RegistryShared, delta: i32) -> bool {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let next = if delta >= 0 {
        state.custodial.checked_add(delta.unsigned_abs())
    } else {
        state.custodial.checked_sub(delta.unsigned_abs())
    };
    match next {
        Some(custodial) => {
            state.custodial = custodial;
            true
        }
        None => false,
    }
}

struct VcpuReapEntry {
    lane_generation: u64,
    owner: JoinHandle<()>,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    registry_reaped: Arc<AtomicBool>,
    custody: Arc<AtomicBool>,
    queue: Arc<CommandQueue>,
    control: Arc<RunControl>,
    cancellation: Arc<Mutex<Option<HvfVcpuCancellation>>>,
    registry: Arc<RegistryShared>,
    reaped: mpsc::SyncSender<Result<(), HvfVcpuLaneError>>,
}

enum ReapSlot {
    Vacant,
    Reserved,
    Occupied(VcpuReapEntry),
}

struct ReaperSlots {
    slots: Mutex<Vec<ReapSlot>>,
}

/// A reaper slot reserved for a lane whose owner thread is about to be
/// spawned.  Filling it cannot fail; that is the whole point.
struct ReapSlotReservation {
    index: usize,
}

struct VcpuReaper {
    limit: u32,
    slots: Arc<ReaperSlots>,
    owner: JoinHandle<()>,
    thread: std::thread::Thread,
}

impl VcpuReaper {
    fn start(limit: u32) -> Result<Self, HvfVcpuLaneError> {
        let capacity = limit as usize;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
        for _ in 0..capacity {
            slots.push(ReapSlot::Vacant);
        }
        let mut finished = Vec::new();
        finished
            .try_reserve_exact(capacity)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
        let slots = Arc::new(ReaperSlots {
            slots: Mutex::new(slots),
        });
        let loop_slots = Arc::clone(&slots);
        let owner = std::thread::Builder::new()
            .name("litebox-hvf-vcpu-reaper".to_owned())
            .spawn(move || vcpu_reaper_loop(&loop_slots, finished))
            .map_err(HvfVcpuLaneError::ThreadSpawn)?;
        let thread = owner.thread().clone();
        Ok(Self {
            limit,
            slots,
            owner,
            thread,
        })
    }

    fn reserve_slot(&self) -> Result<ReapSlotReservation, HvfVcpuLaneError> {
        let mut slots = self
            .slots
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = slots
            .iter()
            .position(|slot| matches!(slot, ReapSlot::Vacant))
            .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
        slots[index] = ReapSlot::Reserved;
        Ok(ReapSlotReservation { index })
    }

    fn fill_slot(&self, reservation: ReapSlotReservation, entry: VcpuReapEntry) {
        {
            let mut slots = self
                .slots
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slots[reservation.index] = ReapSlot::Occupied(entry);
        }
        self.thread.unpark();
    }

    fn release_slot(&self, reservation: ReapSlotReservation) {
        let mut slots = self
            .slots
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(slots[reservation.index], ReapSlot::Reserved) {
            slots[reservation.index] = ReapSlot::Vacant;
        }
    }
}

static PROCESS_VCPU_REAPER: OnceLock<VcpuReaper> = OnceLock::new();
static PROCESS_VCPU_REAPER_INIT: Mutex<()> = Mutex::new(());

fn process_vcpu_reaper(limit: u32) -> Result<&'static VcpuReaper, HvfVcpuLaneError> {
    let _initialization = PROCESS_VCPU_REAPER_INIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if PROCESS_VCPU_REAPER.get().is_none() {
        let reaper = VcpuReaper::start(limit)?;
        PROCESS_VCPU_REAPER
            .set(reaper)
            .map_err(|_| HvfVcpuLaneError::RegistryAccounting)?;
    }
    let reaper = PROCESS_VCPU_REAPER
        .get()
        .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
    if reaper.limit != limit || reaper.owner.is_finished() {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    Ok(reaper)
}

fn vcpu_reaper_loop(slots: &ReaperSlots, mut finished: Vec<VcpuReapEntry>) {
    loop {
        let mut custodial = false;
        let mut shutting_down = false;
        {
            let mut guard = slots
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for slot in guard.iter_mut() {
                let ReapSlot::Occupied(entry) = slot else {
                    continue;
                };
                if entry.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
                    shutting_down = true;
                    entry.queue.wake();
                    let cancellation = entry
                        .cancellation
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    if let Some(cancellation) = cancellation {
                        let _ = entry
                            .control
                            .request_shutdown(entry.lane_generation, &cancellation);
                    }
                }
                if entry.custody.load(Ordering::Acquire) {
                    custodial = true;
                    entry.owner.thread().unpark();
                }
                // `owner_stopped` is published with Release immediately before
                // the owner returns, so it is sufficient to join; `is_finished`
                // covers an owner that unwound before publishing it.
                let stopped =
                    entry.owner_stopped.load(Ordering::Acquire) || entry.owner.is_finished();
                if stopped
                    && finished.len() < finished.capacity()
                    && let ReapSlot::Occupied(entry) = core::mem::replace(slot, ReapSlot::Vacant)
                {
                    finished.push(entry);
                }
            }
        }
        for entry in finished.drain(..) {
            let joined = entry.owner.join();
            entry.owner_stopped.store(true, Ordering::Release);
            if joined.is_err() {
                raise_lane_lifecycle(&entry.lifecycle, LANE_ABANDONED);
            }
            let released = release_registry_lane(&entry.registry);
            if released {
                entry.registry_reaped.store(true, Ordering::Release);
            }
            let _ = entry.reaped.send(match (joined, released) {
                (Ok(()), true) => Ok(()),
                (Err(_), _) => Err(HvfVcpuLaneError::OwnerPanicked),
                (Ok(()), false) => Err(HvfVcpuLaneError::RegistryAccounting),
            });
        }
        if custodial || shutting_down {
            std::thread::park_timeout(OWNER_CLEANUP_RETRY_INTERVAL);
        } else {
            std::thread::park();
        }
    }
}

#[derive(Clone)]
pub struct HvfVcpuRegistry {
    shared: Arc<RegistryShared>,
}

static PROCESS_VCPU_REGISTRY: OnceLock<Arc<RegistryShared>> = OnceLock::new();

impl fmt::Debug for HvfVcpuRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f.debug_struct("HvfVcpuRegistry")
            .field("limit", &self.shared.limit)
            .field("active", &state.active)
            .field("custodial", &state.custodial)
            .finish()
    }
}

impl HvfVcpuRegistry {
    pub fn process() -> Result<Self, HvfVcpuLaneError> {
        let vm = process_hvf_vm()?;
        let limit = vm.report().max_vcpu_count;
        process_vcpu_reaper(limit)?;
        let shared = PROCESS_VCPU_REGISTRY.get_or_init(|| {
            Arc::new(RegistryShared {
                limit,
                state: Mutex::new(RegistryState {
                    next_generation: 1,
                    active: 0,
                    custodial: 0,
                }),
            })
        });
        if shared.limit != limit {
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        Ok(Self {
            shared: Arc::clone(shared),
        })
    }

    pub fn capacity(&self) -> u32 {
        self.shared.limit
    }

    pub fn active(&self) -> u32 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    /// Lanes whose owner thread is alive only to retry owner-keyed vCPU
    /// cleanup.  They still hold registry capacity.
    pub fn custodial(&self) -> u32 {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .custodial
    }

    /// Triggers an immediate custodial retry wave instead of waiting for the
    /// reaper's next tick.
    pub fn wake_custodians(&self) {
        if let Some(reaper) = PROCESS_VCPU_REAPER.get() {
            reaper.thread.unpark();
        }
    }

    pub fn create_lane(&self, queue_capacity: usize) -> Result<HvfVcpuLane, HvfVcpuLaneError> {
        if !(1..=MAX_COMMAND_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(HvfVcpuLaneError::QueueCapacity(queue_capacity));
        }
        let generation = {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.active >= self.shared.limit {
                return Err(HvfVcpuLaneError::Capacity {
                    active: state.active,
                    limit: self.shared.limit,
                });
            }
            let generation = state.next_generation;
            state.next_generation = generation
                .checked_add(1)
                .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
            state.active = state
                .active
                .checked_add(1)
                .ok_or(HvfVcpuLaneError::RegistryAccounting)?;
            generation
        };
        let release_registry = |error: HvfVcpuLaneError| {
            if release_registry_lane(&self.shared) {
                error
            } else {
                HvfVcpuLaneError::RegistryAccounting
            }
        };

        let reaper = match process_vcpu_reaper(self.shared.limit) {
            Ok(reaper) => reaper,
            Err(error) => return Err(release_registry(error)),
        };
        // Durable reaper ownership is reserved before anything is spawned, so
        // the owner thread is never left without a reaper.
        let reservation = match reaper.reserve_slot() {
            Ok(reservation) => reservation,
            Err(error) => return Err(release_registry(error)),
        };

        let lifecycle = Arc::new(AtomicU8::new(LANE_LIVE));
        let owner_stopped = Arc::new(AtomicBool::new(false));
        let registry_reaped = Arc::new(AtomicBool::new(false));
        let custody = Arc::new(AtomicBool::new(false));
        let admission = Arc::new(Mutex::new(()));
        let control = Arc::new(RunControl::new());
        let cancellation_slot = Arc::new(Mutex::new(None));
        let command_queue = match CommandQueue::new(queue_capacity) {
            Ok(queue) => Arc::new(queue),
            Err(error) => {
                reaper.release_slot(reservation);
                return Err(release_registry(error));
            }
        };
        let reaper_thread = reaper.thread.clone();
        let (created, creation) = mpsc::sync_channel(1);
        let (completed, completion) = mpsc::sync_channel(1);
        let (reaped_sender, reaping) = mpsc::sync_channel(1);
        let thread_registry = Arc::clone(&self.shared);
        let thread_lifecycle = Arc::clone(&lifecycle);
        let thread_owner_stopped = Arc::clone(&owner_stopped);
        let thread_custody = Arc::clone(&custody);
        let thread_reaper = reaper_thread.clone();
        let thread_control = Arc::clone(&control);
        let thread_command_queue = Arc::clone(&command_queue);
        let thread_cancellation_slot = Arc::clone(&cancellation_slot);
        let thread = match std::thread::Builder::new()
            .name(format!("litebox-hvf-vcpu-{generation}"))
            .spawn(move || {
                owner_thread(OwnerThreadContext {
                    lane_generation: generation,
                    registry: thread_registry,
                    lifecycle: thread_lifecycle,
                    owner_stopped: thread_owner_stopped,
                    custody: thread_custody,
                    reaper: thread_reaper,
                    control: thread_control,
                    cancellation_slot: thread_cancellation_slot,
                    command_queue: thread_command_queue,
                    created,
                    completed,
                });
            }) {
            Ok(thread) => thread,
            Err(error) => {
                reaper.release_slot(reservation);
                return Err(release_registry(HvfVcpuLaneError::ThreadSpawn(error)));
            }
        };
        reaper.fill_slot(
            reservation,
            VcpuReapEntry {
                lane_generation: generation,
                owner: thread,
                lifecycle: Arc::clone(&lifecycle),
                owner_stopped: Arc::clone(&owner_stopped),
                registry_reaped: Arc::clone(&registry_reaped),
                custody: Arc::clone(&custody),
                queue: Arc::clone(&command_queue),
                control: Arc::clone(&control),
                cancellation: Arc::clone(&cancellation_slot),
                registry: Arc::clone(&self.shared),
                reaped: reaped_sender,
            },
        );
        // From here on the reaper owns the thread and the registry slot;
        // every failure path just abandons the lane and lets it reap.
        let abandon = |error: HvfVcpuLaneError| {
            raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
            command_queue.wake();
            reaper_thread.unpark();
            error
        };
        let deadline = match operation_deadline() {
            Ok(deadline) => deadline,
            Err(error) => return Err(abandon(error)),
        };
        let cancellation = match receive_until(creation, deadline) {
            Ok(Ok(cancellation)) => cancellation,
            Ok(Err(error)) | Err(error) => return Err(abandon(error)),
        };
        let handle = HvfVcpuLaneHandle {
            generation,
            command_queue,
            cancellation,
            lifecycle,
            owner_stopped,
            custody,
            reaper: reaper_thread,
            admission,
            control,
        };
        Ok(HvfVcpuLane {
            handle,
            completion: Some(completion),
            reaping: Some(reaping),
            registry_reaped,
        })
    }
}

// ---------------------------------------------------------------------------
// Lane handles.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HvfVcpuLaneHandle {
    generation: u64,
    command_queue: Arc<CommandQueue>,
    cancellation: HvfVcpuCancellation,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    custody: Arc<AtomicBool>,
    reaper: std::thread::Thread,
    admission: Arc<Mutex<()>>,
    control: Arc<RunControl>,
}

impl fmt::Debug for HvfVcpuLaneHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLaneHandle")
            .field("generation", &self.generation)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .field("running", &self.is_running())
            .field("custodial", &self.custody.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLaneHandle {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_live(&self) -> bool {
        hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped)
    }

    pub fn is_custodial(&self) -> bool {
        self.custody.load(Ordering::Acquire)
    }

    pub fn participant_capability(
        &self,
    ) -> Result<HvfVcpuLaneParticipantCapability, HvfVcpuLaneError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hvf_vcpu_lane_is_live(&self.lifecycle, &self.owner_stopped) {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        Ok(HvfVcpuLaneParticipantCapability {
            generation: self.generation,
            lifecycle: Arc::clone(&self.lifecycle),
            owner_stopped: Arc::clone(&self.owner_stopped),
            admission: Arc::clone(&self.admission),
        })
    }

    pub fn is_running(&self) -> bool {
        self.control.is_running()
    }

    /// Whether no command owns this lane and its architectural state remains
    /// eligible for another pooled checkout.
    pub(crate) fn is_reusable(&self) -> bool {
        self.is_live() && self.control.is_reusable()
    }

    pub fn run_epoch(&self) -> u64 {
        self.control.run_epoch()
    }

    /// The raw SDK kick, bypassing the lane's epoch binding.  Crate-private:
    /// only the failure witness uses it, to prove that an unauthenticated
    /// `Canceled` exit retires the vCPU instead of being resumed.
    pub(crate) fn sdk_cancellation(&self) -> HvfVcpuCancellation {
        self.cancellation.clone()
    }

    pub fn cancellation(&self) -> HvfVcpuLaneCancellation {
        HvfVcpuLaneCancellation {
            lane_generation: self.generation,
            run_epoch: None,
            cancellation: self.cancellation.clone(),
            attempt: Arc::new(Mutex::new(None)),
            lifecycle: Arc::clone(&self.lifecycle),
            control: Arc::clone(&self.control),
            command_queue: Arc::clone(&self.command_queue),
            reaper: self.reaper.clone(),
        }
    }

    pub fn reserve_run(&self) -> Result<HvfVcpuRunReservation, HvfVcpuLaneError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err(HvfVcpuLaneError::LaneClosed);
        }
        let run_epoch = self.control.reserve_run()?;
        Ok(HvfVcpuRunReservation {
            lane_generation: self.generation,
            run_epoch,
            cancellation: HvfVcpuLaneCancellation {
                lane_generation: self.generation,
                run_epoch: Some(run_epoch),
                cancellation: self.cancellation.clone(),
                attempt: Arc::new(Mutex::new(None)),
                lifecycle: Arc::clone(&self.lifecycle),
                control: Arc::clone(&self.control),
                command_queue: Arc::clone(&self.command_queue),
                reaper: self.reaper.clone(),
            },
            active: true,
        })
    }

    pub fn initialize_el1(
        &self,
        configuration: HvfEl1State,
    ) -> Result<HvfEl1State, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::InitializeEl1 {
            configuration,
            reply,
        })
    }

    pub fn el1_state(&self) -> Result<HvfEl1State, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::ReadEl1 { reply })
    }

    pub fn run(
        &self,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let reservation = self.reserve_run()?;
        self.execute(ExecutionKind::Start, reservation, attachment, state, None)
    }

    /// [`Self::run`] with the virtual timer armed to `vtimer_deadline` (a
    /// guest `CNTVCT_EL0` value) so the run exits with `VtimerActivated` no
    /// later than that, bounding one time slice.
    pub fn run_with_deadline(
        &self,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        vtimer_deadline: u64,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let reservation = self.reserve_run()?;
        self.run_with_deadline_reserved(reservation, attachment, state, vtimer_deadline)
    }

    pub fn run_with_deadline_reserved(
        &self,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        vtimer_deadline: u64,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        self.execute(
            ExecutionKind::Start,
            reservation,
            attachment,
            state,
            Some(vtimer_deadline),
        )
    }

    pub fn resume(
        &self,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        let reservation = self.reserve_run()?;
        self.execute(ExecutionKind::Resume, reservation, attachment, state, None)
    }

    /// Brings this lane's vCPU onto the attachment's current root and
    /// generations (the same monitor TLBI trip a run would perform first) and
    /// acknowledges them, without executing guest code.  Used by the backend
    /// to complete a shootdown promptly on idle pooled lanes.
    pub fn synchronize(&self, attachment: HvfVcpuRunAttachment) -> Result<(), HvfVcpuLaneError> {
        self.synchronize_before(attachment, operation_deadline()?)
    }

    /// [`Self::synchronize`], bounded by an externally supplied deadline
    /// rather than the lane's own default operation timeout, so a caller
    /// iterating many lanes under its own overall time budget (the backend's
    /// shootdown loop) cannot have a single stalled lane consume the whole
    /// budget on its own.
    pub fn synchronize_before(
        &self,
        attachment: HvfVcpuRunAttachment,
        deadline: Instant,
    ) -> Result<(), HvfVcpuLaneError> {
        attachment.submit(self.generation)?;
        let (reply, response) = mpsc::sync_channel(1);
        let command = Command::Synchronize { attachment, reply };
        if let Err(rejection) = self.admit(command) {
            let (command, primary) = *rejection;
            return Err(match command {
                Command::Synchronize { attachment, .. } => {
                    finish_attachment_with_error(attachment, primary)
                }
                _ => HvfVcpuLaneError::RegistryAccounting,
            });
        }
        match receive_until(response, deadline) {
            Err(error @ (HvfVcpuLaneError::OperationTimeout | HvfVcpuLaneError::LaneClosed)) => {
                self.abandon_after_wait_failure();
                Err(error)
            }
            result => result?,
        }
    }

    fn execute(
        &self,
        kind: ExecutionKind,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        state: &HvfArchitecturalState,
        vtimer_deadline: Option<u64>,
    ) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
        if !reservation.belongs_to(self) {
            return Err(HvfVcpuLaneError::RegistryAccounting);
        }
        let deadline = operation_deadline()?;
        attachment.submit(self.generation)?;
        let (reply, response) = mpsc::sync_channel(1);
        let command = Command::Execute {
            kind,
            reservation,
            attachment,
            state: Box::new(*state),
            vtimer_deadline,
            reply,
        };
        if let Err(rejection) = self.admit(command) {
            let (command, primary) = *rejection;
            return Err(match command {
                Command::Execute {
                    mut reservation,
                    attachment,
                    ..
                } => {
                    let primary = finish_attachment_with_error(attachment, primary);
                    match reservation.settle(false) {
                        Ok(()) => primary,
                        Err(cleanup) => primary.with_cleanup(cleanup),
                    }
                }
                _ => HvfVcpuLaneError::RegistryAccounting,
            });
        }
        match receive_until(response, deadline) {
            Err(error @ (HvfVcpuLaneError::OperationTimeout | HvfVcpuLaneError::LaneClosed)) => {
                self.abandon_after_wait_failure();
                Err(error)
            }
            result => result?,
        }
    }

    pub fn set_pending_interrupt(&self, fiq: bool, pending: bool) -> Result<(), HvfVcpuLaneError> {
        self.dispatch(|reply| Command::SetPendingInterrupt {
            fiq,
            pending,
            reply,
        })
    }

    pub fn pending_interrupt(&self, fiq: bool) -> Result<bool, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::ReadPendingInterrupt { fiq, reply })
    }

    pub fn set_vtimer(
        &self,
        masked: bool,
        offset: u64,
    ) -> Result<HvfVtimerState, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::SetVtimer {
            masked,
            offset,
            reply,
        })
    }

    pub fn vtimer(&self) -> Result<HvfVtimerState, HvfVcpuLaneError> {
        self.dispatch(|reply| Command::ReadVtimer { reply })
    }

    fn dispatch<T: Send + 'static>(
        &self,
        command: impl FnOnce(mpsc::SyncSender<Result<T, HvfVcpuLaneError>>) -> Command,
    ) -> Result<T, HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        let (reply, response) = mpsc::sync_channel(1);
        if let Err(rejection) = self.admit(command(reply)) {
            let (command, error) = *rejection;
            command.reject(HvfVcpuLaneError::LaneClosed);
            return Err(error);
        }
        match receive_until(response, deadline) {
            Err(error @ (HvfVcpuLaneError::OperationTimeout | HvfVcpuLaneError::LaneClosed)) => {
                self.abandon_after_wait_failure();
                Err(error)
            }
            result => result?,
        }
    }

    /// Liveness check plus enqueue.  The queue's own closed flag is what makes
    /// this safe against a concurrent final drain; the admission lock only
    /// orders it against capability minting and close.
    fn admit(&self, command: Command) -> Result<(), Box<(Command, HvfVcpuLaneError)>> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Err(Box::new((command, HvfVcpuLaneError::LaneClosed)));
        }
        match self.command_queue.try_push(command) {
            Ok(()) => Ok(()),
            Err(PushRejection::Closed(command)) => {
                Err(Box::new((command, HvfVcpuLaneError::LaneClosed)))
            }
            Err(PushRejection::Full(command)) => {
                Err(Box::new((command, HvfVcpuLaneError::QueueOverloaded)))
            }
        }
    }

    fn cancel_for_shutdown(&self) -> Result<(), HvfVcpuLaneError> {
        self.control
            .cancel_for_shutdown(self.generation, &self.cancellation)
    }

    fn abandon_after_wait_failure(&self) {
        raise_lane_lifecycle(&self.lifecycle, LANE_ABANDONED);
        self.command_queue.wake();
        self.reaper.unpark();
        let _ = self
            .control
            .request_shutdown(self.generation, &self.cancellation);
    }
}

pub struct HvfVcpuLane {
    handle: HvfVcpuLaneHandle,
    completion: Option<mpsc::Receiver<Result<HvfVcpuLaneCloseReport, HvfVcpuLaneError>>>,
    reaping: Option<mpsc::Receiver<Result<(), HvfVcpuLaneError>>>,
    registry_reaped: Arc<AtomicBool>,
}

impl fmt::Debug for HvfVcpuLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuLane")
            .field("handle", &self.handle)
            .field("completion_pending", &self.completion.is_some())
            .field("reaping_pending", &self.reaping.is_some())
            .finish_non_exhaustive()
    }
}

impl HvfVcpuLane {
    pub fn handle(&self) -> HvfVcpuLaneHandle {
        self.handle.clone()
    }

    pub(crate) fn request_retirement(&self) {
        self.handle.abandon_after_wait_failure();
    }

    pub(crate) fn try_reaped(&mut self) -> Result<bool, HvfVcpuLaneError> {
        let Some(reaping) = self.reaping.as_ref() else {
            return if self.registry_reaped.load(Ordering::Acquire) {
                Ok(true)
            } else {
                Err(HvfVcpuLaneError::RegistryAccounting)
            };
        };
        match reaping.try_recv() {
            Ok(Ok(())) => {
                if !self.registry_reaped.load(Ordering::Acquire) {
                    return Err(HvfVcpuLaneError::RegistryAccounting);
                }
                self.reaping = None;
                Ok(true)
            }
            Ok(Err(error)) => Err(error),
            Err(mpsc::TryRecvError::Empty) => Ok(false),
            Err(mpsc::TryRecvError::Disconnected) => Err(HvfVcpuLaneError::LaneClosed),
        }
    }

    pub fn close(mut self) -> Result<HvfVcpuLaneCloseReport, HvfVcpuLaneError> {
        let deadline = operation_deadline()?;
        {
            let _admission = self
                .handle
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.handle
                .lifecycle
                .compare_exchange(LANE_LIVE, LANE_CLOSING, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| HvfVcpuLaneError::LaneClosed)?;
        }
        self.handle.command_queue.wake();
        self.handle.reaper.unpark();

        let mut failures = None;
        if let Err(error) = self.handle.cancel_for_shutdown() {
            append_lane_error(&mut failures, error);
            self.handle.abandon_after_wait_failure();
        }
        let completion = self.completion.take().ok_or(HvfVcpuLaneError::LaneClosed)?;
        let reaping = self.reaping.take().ok_or(HvfVcpuLaneError::LaneClosed)?;
        let mut report = None;
        let mut custodial = false;
        match receive_until(completion, deadline) {
            Ok(Ok(completed)) => report = Some(completed),
            Ok(Err(error)) => {
                custodial = matches!(error, HvfVcpuLaneError::ResidualVcpus { .. });
                append_lane_error(&mut failures, error);
            }
            Err(error) => {
                append_lane_error(&mut failures, error);
                self.handle.abandon_after_wait_failure();
            }
        }
        // A custodial owner deliberately stays alive; nothing to reap yet.
        if !custodial {
            match receive_until(reaping, deadline) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => append_lane_error(&mut failures, error),
                Err(error) => {
                    append_lane_error(&mut failures, error);
                    self.handle.abandon_after_wait_failure();
                }
            }
        }
        match (report, failures) {
            (Some(report), None) => Ok(report),
            (_, Some(error)) => Err(error),
            (None, None) => Err(HvfVcpuLaneError::RegistryAccounting),
        }
    }
}

impl Drop for HvfVcpuLane {
    fn drop(&mut self) {
        if self.handle.lifecycle.load(Ordering::Acquire) != LANE_CLOSED {
            self.request_retirement();
        }
    }
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

type Reply<T> = mpsc::SyncSender<Result<T, HvfVcpuLaneError>>;

#[derive(Clone, Copy)]
enum ExecutionKind {
    Start,
    Resume,
}

enum Command {
    InitializeEl1 {
        configuration: HvfEl1State,
        reply: Reply<HvfEl1State>,
    },
    ReadEl1 {
        reply: Reply<HvfEl1State>,
    },
    Execute {
        kind: ExecutionKind,
        reservation: HvfVcpuRunReservation,
        attachment: HvfVcpuRunAttachment,
        // Boxed: the full register file would otherwise make this variant dwarf the others
        // (`clippy::large_enum_variant`).
        state: Box<HvfArchitecturalState>,
        vtimer_deadline: Option<u64>,
        reply: Reply<HvfVcpuRunResult>,
    },
    /// Synchronize this lane onto the attachment's root/generations (monitor
    /// TLBI trip plus acknowledgement) without running guest code.
    Synchronize {
        attachment: HvfVcpuRunAttachment,
        reply: Reply<()>,
    },
    SetPendingInterrupt {
        fiq: bool,
        pending: bool,
        reply: Reply<()>,
    },
    ReadPendingInterrupt {
        fiq: bool,
        reply: Reply<bool>,
    },
    SetVtimer {
        masked: bool,
        offset: u64,
        reply: Reply<HvfVtimerState>,
    },
    ReadVtimer {
        reply: Reply<HvfVtimerState>,
    },
}

impl Command {
    fn reject(self, error: HvfVcpuLaneError) {
        match self {
            Self::InitializeEl1 { reply, .. } | Self::ReadEl1 { reply } => {
                reply_result(reply, Err(error));
            }
            Self::Execute {
                mut reservation,
                attachment,
                reply,
                ..
            } => {
                let error = finish_attachment_with_error(attachment, error);
                let error = match reservation.settle(false) {
                    Ok(()) => error,
                    Err(cleanup) => error.with_cleanup(cleanup),
                };
                reply_result(reply, Err(error));
            }
            Self::Synchronize { attachment, reply } => {
                reply_result(reply, Err(finish_attachment_with_error(attachment, error)));
            }
            Self::SetPendingInterrupt { reply, .. } => reply_result(reply, Err(error)),
            Self::ReadPendingInterrupt { reply, .. } => reply_result(reply, Err(error)),
            Self::SetVtimer { reply, .. } | Self::ReadVtimer { reply } => {
                reply_result(reply, Err(error));
            }
        }
    }
}

fn append_lane_error(failures: &mut Option<HvfVcpuLaneError>, error: HvfVcpuLaneError) {
    *failures = Some(match failures.take() {
        Some(primary) => primary.with_cleanup(error),
        None => error,
    });
}

fn operation_deadline() -> Result<Instant, HvfVcpuLaneError> {
    Instant::now()
        .checked_add(COMMAND_WAIT_TIMEOUT)
        .ok_or(HvfVcpuLaneError::OperationTimeout)
}

fn receive_until<T>(receiver: mpsc::Receiver<T>, deadline: Instant) -> Result<T, HvfVcpuLaneError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return match receiver.try_recv() {
            Ok(value) => Ok(value),
            Err(mpsc::TryRecvError::Empty) => Err(HvfVcpuLaneError::OperationTimeout),
            Err(mpsc::TryRecvError::Disconnected) => Err(HvfVcpuLaneError::LaneClosed),
        };
    }
    match receiver.recv_timeout(remaining) {
        Ok(value) => Ok(value),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(HvfVcpuLaneError::OperationTimeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(HvfVcpuLaneError::LaneClosed),
    }
}

// ---------------------------------------------------------------------------
// Owner thread.
// ---------------------------------------------------------------------------

struct OwnerThreadContext {
    lane_generation: u64,
    registry: Arc<RegistryShared>,
    lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    custody: Arc<AtomicBool>,
    reaper: std::thread::Thread,
    control: Arc<RunControl>,
    cancellation_slot: Arc<Mutex<Option<HvfVcpuCancellation>>>,
    command_queue: Arc<CommandQueue>,
    created: mpsc::SyncSender<Result<HvfVcpuCancellation, HvfVcpuLaneError>>,
    completed: mpsc::SyncSender<Result<HvfVcpuLaneCloseReport, HvfVcpuLaneError>>,
}

fn owner_thread(context: OwnerThreadContext) {
    let OwnerThreadContext {
        lane_generation,
        registry,
        lifecycle,
        owner_stopped,
        custody,
        reaper,
        control,
        cancellation_slot,
        command_queue,
        created,
        completed,
    } = context;
    let mut vcpu = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let setup = (|| {
            command_queue.register_owner()?;
            let vm = process_hvf_vm()?;
            let raw = vm.create_vcpu()?;
            let cancellation = raw.cancellation()?;
            vcpu = Some(raw);
            Ok::<_, HvfVcpuLaneError>(cancellation)
        })();
        let cancellation = match setup {
            Ok(cancellation) => cancellation,
            Err(error) => {
                if created.send(Err(error)).is_err() {
                    raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
                }
                return Ok(());
            }
        };
        *cancellation_slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cancellation.clone());
        if created.send(Ok(cancellation)).is_err() {
            raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
        }
        owner_loop(
            lane_generation,
            &lifecycle,
            &control,
            &command_queue,
            &mut vcpu,
        )
    }));
    if outcome.is_err() || lifecycle.load(Ordering::Acquire) == LANE_LIVE {
        raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
    }

    // Final drain: from here no sender can enqueue, and every command that
    // made it in is answered.
    for command in command_queue.close_and_drain() {
        command.reject(HvfVcpuLaneError::LaneClosed);
    }

    let mut cleanup_attempts = 0usize;
    let mut cleanup_error: Option<HvfVcpuLaneError> = None;
    if let Some(raw) = vcpu.take()
        && raw.is_live()
    {
        cleanup_attempts = 1;
        if let Err(error) = raw.destroy() {
            cleanup_error = Some(error.into());
        }
    }
    let vm = match process_hvf_vm() {
        Ok(vm) => Some(vm),
        Err(error) => {
            if cleanup_error.is_none() {
                cleanup_error = Some(error.into());
            }
            None
        }
    };

    // Owner-affine cleanup custody: the SDK quarantines a vCPU under its
    // creator thread, so this thread is the only one that can ever retire it.
    let mut report_sent = false;
    let mut custodial = false;
    if let Some(vm) = vm {
        loop {
            for _ in 0..OWNER_CLEANUP_WAVE_ATTEMPTS {
                if vm.quarantined_vcpu_count_for_current_thread() == 0 {
                    break;
                }
                cleanup_attempts = cleanup_attempts.saturating_add(1);
                if let Err(error) = vm.retry_quarantined_vcpus_for_current_thread()
                    && cleanup_error.is_none()
                {
                    cleanup_error = Some(error.into());
                }
                if vm.quarantined_vcpu_count_for_current_thread() == 0 {
                    break;
                }
                std::thread::park_timeout(OWNER_CLEANUP_RETRY_INTERVAL);
            }
            let residual = vm.quarantined_vcpu_count_for_current_thread();
            if residual == 0 {
                break;
            }
            if !custodial {
                custodial = true;
                custody.store(true, Ordering::Release);
                raise_lane_lifecycle(&lifecycle, LANE_ABANDONED);
                if !adjust_registry_custodial(&registry, 1) && cleanup_error.is_none() {
                    cleanup_error = Some(HvfVcpuLaneError::RegistryAccounting);
                }
                let _ = completed.send(Err(HvfVcpuLaneError::ResidualVcpus {
                    current_thread: residual,
                    process: vm.quarantined_vcpu_count(),
                }));
                report_sent = true;
                reaper.unpark();
            }
            // The reaper unparks custodians every retry interval; this bound
            // only guards against a missed wake.
            std::thread::park_timeout(OWNER_CLEANUP_RETRY_INTERVAL);
        }
    }
    if custodial {
        custody.store(false, Ordering::Release);
        if !adjust_registry_custodial(&registry, -1) && cleanup_error.is_none() {
            cleanup_error = Some(HvfVcpuLaneError::RegistryAccounting);
        }
    }

    *cancellation_slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let mut final_error = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some(HvfVcpuLaneError::OwnerPanicked),
    };
    if let Some(cleanup) = cleanup_error {
        final_error = Some(match final_error.take() {
            Some(primary) => primary.with_cleanup(cleanup),
            None => cleanup,
        });
    }
    let residual_vcpus = match vm {
        Some(vm) => vm.quarantined_vcpu_count(),
        None => 0,
    };
    let report = HvfVcpuLaneCloseReport {
        lane_generation,
        cleanup_attempts,
        residual_vcpus,
    };
    if lifecycle.load(Ordering::Acquire) == LANE_ABANDONED && final_error.is_none() {
        final_error = Some(HvfVcpuLaneError::LaneClosed);
    }
    if let Some(error) = final_error {
        lifecycle.store(LANE_ABANDONED, Ordering::Release);
        if !report_sent {
            let _ = completed.send(Err(error));
        }
    } else {
        lifecycle.store(LANE_CLOSED, Ordering::Release);
        if !report_sent {
            let _ = completed.send(Ok(report));
        }
    }
    // Published with Release before returning: the reaper joins on this.
    owner_stopped.store(true, Ordering::Release);
    reaper.unpark();
}

fn owner_loop(
    lane_generation: u64,
    lifecycle: &AtomicU8,
    control: &RunControl,
    command_queue: &CommandQueue,
    vcpu: &mut Option<HvfVcpu>,
) -> Result<(), HvfVcpuLaneError> {
    loop {
        if lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            return Ok(());
        }
        let Some(command) = command_queue.pop() else {
            if vcpu.as_ref().is_some_and(|raw| !raw.is_live()) {
                vcpu.take();
                raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                return Ok(());
            }
            std::thread::park();
            continue;
        };
        if lifecycle.load(Ordering::Acquire) != LANE_LIVE {
            command.reject(HvfVcpuLaneError::LaneClosed);
            return Ok(());
        }
        if OWNER_PANIC_INJECTION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            panic!("injected HVF owner-lane panic for the containment witness");
        }
        let Some(raw) = vcpu.as_mut() else {
            command.reject(HvfVcpuLaneError::LaneClosed);
            return Err(HvfVcpuLaneError::LaneClosed);
        };
        if !raw.is_live() || control.is_terminal() {
            command.reject(HvfVcpuLaneError::LaneTerminal);
            raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
            return Ok(());
        }
        match command {
            Command::InitializeEl1 {
                configuration,
                reply,
            } => {
                let result = raw.initialize_el1(&configuration).map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::ReadEl1 { reply } => {
                let result = raw.el1_state().map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::Execute {
                kind,
                reservation,
                attachment,
                state,
                vtimer_deadline,
                reply,
            } => {
                let mut result = execute_attached(
                    raw,
                    control,
                    lane_generation,
                    kind,
                    reservation,
                    attachment,
                    &state,
                    vtimer_deadline,
                );
                let untrusted = result
                    .as_ref()
                    .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
                    || control.is_untrusted();
                if untrusted {
                    // The architectural state can no longer be trusted: retire
                    // the vCPU now, on its owner thread, unless the SDK already
                    // did so while reporting the failure.
                    if let Some(raw) = vcpu.take()
                        && raw.is_live()
                        && let Err(cleanup) = raw.quarantine_rejected_exit()
                    {
                        result = Err(match result {
                            Ok(_) => cleanup.into(),
                            Err(primary) => primary.with_cleanup(cleanup),
                        });
                    }
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if vcpu.as_ref().is_some_and(|raw| !raw.is_live()) {
                    // The SDK quarantined the vCPU inside the run; the lane is
                    // finished even though the error itself is not terminal.
                    vcpu.take();
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if control.is_terminal() {
                    // Orderly shutdown reached during this run: the vCPU is
                    // still trustworthy and is destroyed normally by cleanup.
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                }
                reply_result(reply, result);
            }
            Command::Synchronize { attachment, reply } => {
                let mut result = synchronize_attached(raw, control, lane_generation, attachment);
                let untrusted = result
                    .as_ref()
                    .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
                    || control.is_untrusted();
                if untrusted {
                    if let Some(raw) = vcpu.take()
                        && raw.is_live()
                        && let Err(cleanup) = raw.quarantine_rejected_exit()
                    {
                        result = Err(match result {
                            Ok(()) => cleanup.into(),
                            Err(primary) => primary.with_cleanup(cleanup),
                        });
                    }
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if vcpu.as_ref().is_some_and(|raw| !raw.is_live()) {
                    vcpu.take();
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                } else if control.is_terminal() {
                    raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
                }
                reply_result(reply, result);
            }
            Command::SetPendingInterrupt {
                fiq,
                pending,
                reply,
            } => {
                let result = raw.set_pending_interrupt(fiq, pending).map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::ReadPendingInterrupt { fiq, reply } => {
                let result = raw.pending_interrupt(fiq).map_err(Into::into);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::SetVtimer {
                masked,
                offset,
                reply,
            } => {
                let result = set_vtimer(raw, masked, offset);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
            Command::ReadVtimer { reply } => {
                let result = read_vtimer(raw);
                reply_simple_command(vcpu, lifecycle, reply, result);
            }
        }
    }
}

fn finish_attachment_with_error(
    attachment: HvfVcpuRunAttachment,
    primary: HvfVcpuLaneError,
) -> HvfVcpuLaneError {
    match attachment.finish() {
        Ok(()) => primary,
        Err(cleanup) => primary.with_cleanup(cleanup),
    }
}

fn reply_simple_command<T>(
    vcpu: &mut Option<HvfVcpu>,
    lifecycle: &AtomicU8,
    reply: Reply<T>,
    result: Result<T, HvfVcpuLaneError>,
) {
    let raw_died = vcpu.as_ref().is_some_and(|raw| !raw.is_live());
    let result = if raw_died {
        vcpu.take();
        raise_lane_lifecycle(lifecycle, LANE_ABANDONED);
        match result {
            Ok(_) => Err(HvfVcpuLaneError::LaneTerminal),
            Err(error) => Err(error),
        }
    } else {
        result
    };
    reply_result(reply, result);
}

fn reply_result<T>(reply: Reply<T>, result: Result<T, HvfVcpuLaneError>) {
    let _ = reply.send(result);
}

// ---------------------------------------------------------------------------
// Execution on the owner thread.
// ---------------------------------------------------------------------------

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is an independent part of one queued execute command"
)]
fn execute_attached(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    kind: ExecutionKind,
    mut reservation: HvfVcpuRunReservation,
    attachment: HvfVcpuRunAttachment,
    state: &HvfArchitecturalState,
    vtimer_deadline: Option<u64>,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    let run_epoch = reservation.run_epoch();
    let result = (|| {
        if attachment.requires_synchronization() {
            attachment.begin_synchronizing(lane_generation)?;
            let proof = synchronize_once(
                vcpu,
                control,
                lane_generation,
                Some(run_epoch),
                attachment.synchronization_request(),
            )?;
            attachment.acknowledge_owner_synchronization(proof)?;
        }
        attachment.begin_running(lane_generation)?;
        if let Some(cval) = vtimer_deadline {
            vcpu.arm_vtimer(cval)?;
        }
        match kind {
            ExecutionKind::Start => run_once(
                vcpu,
                control,
                lane_generation,
                run_epoch,
                state,
                HvfPstateContext::UserEl0t,
            ),
            ExecutionKind::Resume => resume_once(vcpu, control, lane_generation, run_epoch, state),
        }
    })();
    let untrusted = result
        .as_ref()
        .is_err_and(HvfVcpuLaneError::terminalizes_execution_vcpu)
        || control.is_untrusted();
    let mut cleanup_error = reservation.settle(untrusted).err();
    if let Err(error) = attachment.finish().map_err(HvfVcpuLaneError::from) {
        append_lane_error(&mut cleanup_error, error);
    }
    match (result, cleanup_error) {
        (Ok(result), None) => Ok(result),
        (Err(primary), None) => Err(primary),
        (Err(primary), Some(cleanup)) => Err(primary.with_cleanup(cleanup)),
        (Ok(_), Some(cleanup)) => Err(cleanup),
    }
}

fn synchronize_attached(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    attachment: HvfVcpuRunAttachment,
) -> Result<(), HvfVcpuLaneError> {
    let result = (|| {
        if attachment.requires_synchronization() {
            attachment.begin_synchronizing(lane_generation)?;
            let proof = synchronize_once(
                vcpu,
                control,
                lane_generation,
                None,
                attachment.synchronization_request(),
            )?;
            attachment.acknowledge_owner_synchronization(proof)?;
        }
        Ok(())
    })();
    let cleanup = attachment.finish().map_err(HvfVcpuLaneError::from);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(primary.with_cleanup(cleanup)),
        (Ok(()), Err(cleanup)) => Err(cleanup),
    }
}

fn execute_once(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
) -> Result<(HvfVcpuExit, u64, u64), HvfVcpuLaneError> {
    loop {
        control.begin_run(run_epoch)?;
        match control.begin_running(run_epoch) {
            Ok(()) => {}
            Err(HvfVcpuLaneError::LatchedCancellation) => {
                return Ok((HvfVcpuExit::Canceled, vcpu.execution_time()?, run_epoch));
            }
            Err(error) => return Err(error),
        }
        let run = vcpu.run();
        let disposition = control.finish_run(run_epoch, &run);
        let exit = match (run, disposition) {
            (Ok(exit), Ok(RunDisposition::Deliver)) => exit,
            (Ok(_), Ok(RunDisposition::Rerun)) => continue,
            (Err(primary), Ok(_)) => return Err(primary.into()),
            (Ok(_), Err(error)) => return Err(error),
            (Err(primary), Err(cleanup)) => {
                return Err(HvfVcpuLaneError::from(primary).with_cleanup(cleanup));
            }
        };
        hold_vcpu_run_completion_barrier(lane_generation, run_epoch);
        return Ok((exit, vcpu.execution_time()?, run_epoch));
    }
}

fn run_once(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
    state: &HvfArchitecturalState,
    context: HvfPstateContext,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    vcpu.set_architectural_state(state, context)?;
    let (exit, execution_time, run_epoch) =
        execute_once(vcpu, control, lane_generation, run_epoch)?;
    if matches!(exit, HvfVcpuExit::Unknown | HvfVcpuExit::Malformed { .. }) {
        return Err(HvfVcpuLaneError::RejectedExit(Box::new(exit)));
    }
    let raw_state = vcpu.architectural_state_unclassified()?;
    let state = match raw_state.cpsr_context() {
        Ok(HvfPstateContext::UserEl0t) => HvfVcpuExitState::DirectGuest(raw_state),
        Ok(HvfPstateContext::MonitorEl1h)
            if raw_state
                .require_spsr_el1(HvfPstateContext::UserEl0t)
                .is_ok() =>
        {
            HvfVcpuExitState::LowerElMonitor(raw_state)
        }
        _ => {
            return Err(HvfVcpuLaneError::InvalidExecutionState {
                exit: Box::new(exit),
                state: Box::new((&raw_state).into()),
            });
        }
    };
    Ok(HvfVcpuRunResult {
        exit,
        state,
        run_epoch,
        execution_time,
    })
}

fn resume_once(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: u64,
    state: &HvfArchitecturalState,
) -> Result<HvfVcpuRunResult, HvfVcpuLaneError> {
    if state.pc != process_hvf_vm()?.monitor().resume_offset() as u64
        || state.esr_el1 != 0x5600_0000
    {
        return Err(HvfVcpuLaneError::InvalidContinuation {
            pc: state.pc,
            cpsr: state.cpsr,
            esr_el1: state.esr_el1,
        });
    }
    state.require_cpsr(HvfPstateContext::MonitorEl1h)?;
    state.require_spsr_el1(HvfPstateContext::UserEl0t)?;
    run_once(
        vcpu,
        control,
        lane_generation,
        run_epoch,
        state,
        HvfPstateContext::MonitorEl1h,
    )
}

#[derive(Clone, Copy)]
struct HvfInternalSideState {
    irq: bool,
    fiq: bool,
    vtimer: HvfVtimerState,
}

fn capture_internal_side_state(
    vcpu: &mut HvfVcpu,
) -> Result<HvfInternalSideState, HvfVcpuLaneError> {
    Ok(HvfInternalSideState {
        irq: vcpu.pending_interrupt(false)?,
        fiq: vcpu.pending_interrupt(true)?,
        vtimer: read_vtimer(vcpu)?,
    })
}

fn suppress_internal_interrupts(vcpu: &mut HvfVcpu) -> Result<(), HvfVcpuLaneError> {
    vcpu.set_pending_interrupt(false, false)?;
    vcpu.set_pending_interrupt(true, false)?;
    vcpu.set_vtimer_mask(true)?;
    Ok(())
}

fn append_cleanup(failures: &mut Option<HvfVcpuLaneError>, result: Result<(), HvfError>) {
    if let Err(error) = result {
        let cleanup = HvfVcpuLaneError::from(error);
        *failures = Some(match failures.take() {
            Some(primary) => primary.with_cleanup(cleanup),
            None => cleanup,
        });
    }
}

fn restore_internal_side_state(
    vcpu: &mut HvfVcpu,
    side: HvfInternalSideState,
) -> Result<(), HvfVcpuLaneError> {
    let mut failures = None;
    append_cleanup(&mut failures, vcpu.set_vtimer_offset(side.vtimer.offset));
    append_cleanup(&mut failures, vcpu.set_vtimer_mask(side.vtimer.masked));
    append_cleanup(&mut failures, vcpu.set_pending_interrupt(true, side.fiq));
    append_cleanup(&mut failures, vcpu.set_pending_interrupt(false, side.irq));
    match failures {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Runs the EL1 synchronization monitor once from the immutable ASID-zero
/// bootstrap root, invalidates the requested nonzero ASID, installs its target
/// stage-one root with an architectural context synchronization event, and then
/// returns through `HVC`. The trip uses canonical scratch architectural state
/// and restores only interrupt/timer side state; every subsequent guest run
/// installs its caller-owned architectural state first.
fn synchronize_once(
    vcpu: &mut HvfVcpu,
    control: &RunControl,
    lane_generation: u64,
    run_epoch: Option<u64>,
    request: HvfSynchronizationRequest,
) -> Result<HvfOwnerSynchronizationProof, HvfVcpuLaneError> {
    if request.address_space_id == 0
        || request.participant_id == 0
        || request.asid == 0
        || request.synchronization_ttbr0_el1 == 0
        || request.synchronization_ttbr0_el1 >> 48 != 0
        || request.synchronization_ttbr0_el1 & STAGE_ONE_TTBR_BASE_MASK == 0
        || request.synchronization_ttbr0_el1 & (STAGE_ONE_TABLE_ALIGNMENT - 1) != 0
        || request.ttbr0_el1 & STAGE_ONE_TTBR_BASE_MASK == 0
        || request.ttbr0_el1 & (STAGE_ONE_TABLE_ALIGNMENT - 1) != 0
        || request.ttbr0_el1 >> 48 != u64::from(request.asid)
        || request.tcr_el1 == 0
        || request.mair_el1 == 0
        || request.root_generation == 0
        || request.tlbi_generation == 0
    {
        return Err(HvfVcpuLaneError::RegistryAccounting);
    }
    let side = capture_internal_side_state(vcpu)?;
    let synchronize_offset = process_hvf_vm()?.monitor().synchronize_offset() as u64;
    let outcome = (|| {
        vcpu.program_stage_one(
            request.synchronization_ttbr0_el1,
            request.tcr_el1,
            request.mair_el1,
        )?;
        loop {
            let mut monitor = HvfArchitecturalState::default();
            monitor.x[0] = u64::from(request.asid) << 48;
            monitor.x[1] = request.ttbr0_el1;
            monitor.pc = synchronize_offset;
            monitor.cpsr = 0x3c5;
            monitor.spsr_el1 = 0;
            vcpu.set_architectural_state(&monitor, HvfPstateContext::MonitorEl1h)?;
            suppress_internal_interrupts(vcpu)?;
            let synchronization_epoch = control.begin_synchronizing(run_epoch)?;
            hold_vcpu_synchronization_barrier();
            let run = vcpu.run();
            let disposition = control.finish_synchronizing(synchronization_epoch, &run);
            let exit = match (run, disposition) {
                (Ok(exit), Ok(SynchronizationDisposition::Completed)) => exit,
                (Ok(_), Ok(SynchronizationDisposition::Rerun)) => continue,
                (Ok(_), Ok(SynchronizationDisposition::Canceled(_))) => {
                    return Err(HvfVcpuLaneError::LaneClosed);
                }
                (Err(primary), Ok(_)) => return Err(primary.into()),
                (Ok(_), Err(error)) => return Err(error),
                (Err(primary), Err(cleanup)) => {
                    return Err(HvfVcpuLaneError::from(primary).with_cleanup(cleanup));
                }
            };
            let execution_time = vcpu.execution_time()?;
            let exited = vcpu.architectural_state_unclassified()?;
            let valid = matches!(
                exit,
                HvfVcpuExit::Exception(exception)
                    if exception.syndrome == 0x5a00_4c43
                        && exception.virtual_address == 0
                        && exception.physical_address == 0
            ) && exited.pc == synchronize_offset + 32
                && exited.cpsr == 0x3c5;
            if !valid {
                return Err(HvfVcpuLaneError::InvalidSynchronizationExit {
                    exit: Box::new(exit),
                    lane_generation,
                    request: Box::new(request),
                    state: Box::new((&exited).into()),
                });
            }
            vcpu.verify_stage_one(request.ttbr0_el1, request.tcr_el1, request.mair_el1)?;
            return Ok((synchronization_epoch, execution_time));
        }
    })();
    let restore = restore_internal_side_state(vcpu, side);
    let (synchronization_epoch, execution_time) = match (outcome, restore) {
        (Ok(outcome), Ok(())) => outcome,
        (Err(primary), Ok(())) => return Err(primary),
        (Err(primary), Err(cleanup)) => return Err(primary.with_cleanup(cleanup)),
        (Ok(_), Err(cleanup)) => return Err(cleanup),
    };
    Ok(HvfOwnerSynchronizationProof {
        lane_generation,
        request,
        synchronization_epoch,
        execution_time,
    })
}

fn set_vtimer(
    vcpu: &mut HvfVcpu,
    masked: bool,
    offset: u64,
) -> Result<HvfVtimerState, HvfVcpuLaneError> {
    vcpu.set_vtimer_offset(offset)?;
    vcpu.set_vtimer_mask(masked)?;
    read_vtimer(vcpu)
}

fn read_vtimer(vcpu: &mut HvfVcpu) -> Result<HvfVtimerState, HvfVcpuLaneError> {
    Ok(HvfVtimerState {
        masked: vcpu.vtimer_mask()?,
        offset: vcpu.vtimer_offset()?,
    })
}
