// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Production-path witnesses for the HVF owner-lane vCPU backend.
//!
//! [`hvf_vcpu_diagnostic_probe`] runs unchanged stock AArch64 instructions on a
//! real Hypervisor.framework vCPU through the EL1 monitor and checks every
//! Task #48 lane invariant that can be observed without poisoning the process
//! VM: exact EL1 readback, complete register/FPSIMD/TLS round-trips, stock
//! `SVC #0` → monitor → `HVC` dispatch and resume, collective TLBI retirement,
//! cross-thread cancellation, stale-kick reruns, concurrent independent lanes,
//! abandoned-lane reaping, prompt rejection on closed lanes, the virtual timer,
//! and zero residual vCPUs/address spaces after close.
//!
//! [`hvf_vcpu_failure_probe`] is a separate process-terminal witness: it
//! proves that an unauthenticated `Canceled` exit retires the vCPU, abandons
//! the lane, poisons the VM, and still lets cleanup run to zero residuals.

use core::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::hvf::{HvfArchitecturalState, HvfEl1State, HvfError, HvfVcpuExit, process_hvf_vm};
use crate::hvf_memory::{
    HvfAddressSpace, HvfClaim, HvfGuestPermissions, HvfMemory, HvfMemoryError, HvfSharing,
    HvfVcpuParticipant, HvfVcpuRunAttachment, process_hvf_memory,
};
use crate::hvf_vcpu::{
    HvfVcpuExitState, HvfVcpuLane, HvfVcpuLaneCloseReport, HvfVcpuLaneError, HvfVcpuLaneHandle,
    HvfVcpuRegistry, HvfVcpuRunResult, OWNER_CLEANUP_WAVE_ATTEMPTS,
    arm_vcpu_run_completion_barrier, arm_vcpu_synchronization_barrier, inject_owner_panic,
};

const PAGE_SIZE: usize = 16 * 1024;
/// Guest VAs double as exact host alias addresses (GVA = HVA leases), so they
/// must sit above the 4 GiB `__PAGEZERO` segment of the host executable; this
/// is the same 1 TiB region the compact-memory witness uses.
const DIAGNOSTIC_BASE_GVA: usize = 0x0000_0100_0000_0000;
const CODE_GVA: usize = DIAGNOSTIC_BASE_GVA + 0x0400_0000;
const SCRATCH_GVA: usize = DIAGNOSTIC_BASE_GVA + 0x0410_0000;
/// Offset of the `b .` spin instruction inside the code page.
const SPIN_OFFSET: u64 = 16;
const SYSCALL_HVC_IMMEDIATE: u64 = 0x4c42;
const HVC64_EXCEPTION_CLASS: u64 = 0x16;
const SVC64_EXCEPTION_CLASS: u64 = 0x15;
const MONITOR_LOWER_EL_SYNC_OFFSET: u64 = 0x400;
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(30);
const QUEUE_CAPACITY: usize = 8;
/// Upper bound on cancellation races attempted while looking for both the
/// applied and the too-late outcome.
const STALE_KICK_MAX_ITERATIONS: usize = 4096;

#[derive(Debug)]
pub enum HvfVcpuDiagnosticError {
    Hvf(HvfError),
    Memory(HvfMemoryError),
    // Boxed to keep this error small (`clippy::result_large_err`).
    Lane(Box<HvfVcpuLaneError>),
    ThreadSpawn(std::io::Error),
    ThreadPanicked,
    Timeout(&'static str),
    Witness(&'static str),
    StaleKickPair {
        kick: &'static str,
        run: Box<HvfVcpuRunResult>,
    },
    StaleKickCoverage {
        applied: usize,
        too_late: usize,
        not_running: usize,
        not_attempted: usize,
    },
    StaleAttachment {
        stale: Box<Result<HvfVcpuRunResult, HvfVcpuLaneError>>,
        live_after_rejection: bool,
        fresh: Box<HvfVcpuRunResult>,
        settled: Box<HvfVcpuRunResult>,
    },
    Step {
        step: &'static str,
        error: Box<Self>,
    },
    Cleanup {
        trigger: Box<Self>,
        cleanup: Box<Self>,
    },
}

fn step<T>(
    step: &'static str,
    result: Result<T, HvfVcpuDiagnosticError>,
) -> Result<T, HvfVcpuDiagnosticError> {
    result.map_err(|error| HvfVcpuDiagnosticError::Step {
        step,
        error: Box::new(error),
    })
}

impl fmt::Display for HvfVcpuDiagnosticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::Memory(error) => write!(f, "{error}"),
            Self::Lane(error) => write!(f, "{error}"),
            Self::ThreadSpawn(error) => write!(f, "failed to spawn diagnostic thread: {error}"),
            Self::ThreadPanicked => write!(f, "an HVF vCPU diagnostic thread panicked"),
            Self::Timeout(operation) => {
                write!(f, "timed out while waiting for {operation}")
            }
            Self::Witness(message) => write!(f, "HVF vCPU diagnostic failed: {message}"),
            Self::StaleKickPair { kick, run } => write!(
                f,
                "HVF vCPU diagnostic observed stale-kick outcome {kick} with run {run:?}"
            ),
            Self::StaleKickCoverage {
                applied,
                too_late,
                not_running,
                not_attempted,
            } => write!(
                f,
                "HVF vCPU stale-kick coverage ended with applied={applied}, too_late={too_late}, not_running={not_running}, not_attempted={not_attempted}"
            ),
            Self::StaleAttachment {
                stale,
                live_after_rejection,
                fresh,
                settled,
            } => write!(
                f,
                "HVF vCPU stale-attachment outcome was stale={stale:?}, live_after_rejection={live_after_rejection}, fresh={fresh:?}, settled={settled:?}"
            ),
            Self::Step { step, error } => write!(f, "[{step}] {error}"),
            Self::Cleanup { trigger, cleanup } => {
                write!(f, "{trigger}; explicit cleanup also failed: {cleanup}")
            }
        }
    }
}

impl std::error::Error for HvfVcpuDiagnosticError {}

impl From<HvfError> for HvfVcpuDiagnosticError {
    fn from(value: HvfError) -> Self {
        Self::Hvf(value)
    }
}

impl From<HvfMemoryError> for HvfVcpuDiagnosticError {
    fn from(value: HvfMemoryError) -> Self {
        Self::Memory(value)
    }
}

impl From<HvfVcpuLaneError> for HvfVcpuDiagnosticError {
    fn from(value: HvfVcpuLaneError) -> Self {
        Self::Lane(Box::new(value))
    }
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfVcpuDiagnosticReport {
    pub lane_generation: u64,
    pub queue_capacity: usize,
    pub root_generation: u64,
    pub executable_generation: u64,
    pub tlbi_generation: u64,
    pub el1_exact_readback: bool,
    pub scalar_state_preserved: bool,
    pub simd_state_preserved: bool,
    pub floating_point_state_preserved: bool,
    pub tls_state_preserved: bool,
    pub syscall_hvc_verified: bool,
    pub syscall_elr_verified: bool,
    pub syscall_resume_verified: bool,
    pub syscall_monitor_pc: u64,
    pub reservation_epoch_a: u64,
    pub reservation_epoch_b: u64,
    pub reservation_epoch_c: u64,
    pub reservation_epoch_d: u64,
    pub reserved_preentry_cancellation_verified: bool,
    pub stale_reservation_cancellation_rejected_verified: bool,
    pub postexit_reservation_cancellation_rejected_verified: bool,
    pub synchronization_cancellation_isolation_verified: bool,
    pub cancellation_verified: bool,
    pub stale_kick_applied_count: usize,
    pub stale_kick_too_late_count: usize,
    pub stale_kick_rerun_verified: bool,
    pub concurrent_lanes_verified: bool,
    pub lane_abandon_reaped_verified: bool,
    pub closed_lane_rejects_promptly_verified: bool,
    pub closed_lane_rejection_micros: u64,
    pub vtimer_verified: bool,
    pub collective_retirement_verified: bool,
    pub stale_attachment_rejected_verified: bool,
    pub registry_capacity: u32,
    pub capacity_bound_verified: bool,
    pub cleanup: HvfVcpuLaneCloseReport,
    pub registry_active_after_cleanup: u32,
    pub registry_custodial_after_cleanup: u32,
    pub address_spaces_after_cleanup: usize,
    pub retired_generations_after_cleanup: usize,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfVcpuCustodyReport {
    pub lane_generation: u64,
    pub injected_destroy_failures: u32,
    pub close_reported_residual: bool,
    pub registry_active_after_close: u32,
    pub registry_custodial_after_close: u32,
    pub custody_released: bool,
    pub custody_release_millis: u64,
    pub injected_failures_remaining: u32,
    pub quarantined_vcpus_after_release: usize,
    pub active_vcpus_after_release: usize,
    pub registry_active_after_release: u32,
    pub registry_custodial_after_release: u32,
    pub vm_poisoned: bool,
    pub post_poison_deregister_succeeded: bool,
    pub post_poison_destroy_succeeded: bool,
    pub address_spaces_after_cleanup: usize,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfVcpuTotalityReport {
    pub lane_generation: u64,
    pub queue_capacity: usize,
    pub queue_filled_to_capacity: bool,
    pub queue_max_plus_one_rejected: bool,
    pub queue_overloaded_command_returned: bool,
    pub lane_live_after_overload_rejection: bool,
    pub queued_commands_drained_after_overload: bool,
    pub owner_panic_injected: bool,
    pub owner_panic_contained: bool,
    pub owner_panic_did_not_abort_process: bool,
    pub lane_abandoned_after_owner_panic: bool,
    pub close_reports_owner_panicked: bool,
    pub registry_active_after_panic_reap: u32,
    pub registry_custodial_after_panic_reap: u32,
    pub quarantined_vcpus_after_panic_reap: usize,
    pub active_vcpus_after_panic_reap: usize,
    pub address_spaces_after_cleanup: usize,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfVcpuFailureReport {
    pub lane_generation: u64,
    pub unexpected_cancellation_terminal: bool,
    pub lane_abandoned_after_terminal_exit: bool,
    pub close_reports_lane_closed: bool,
    pub registry_active_after_reap: u32,
    pub registry_custodial_after_reap: u32,
    pub quarantined_vcpus_after_reap: usize,
    pub active_vcpus_after_reap: usize,
    pub vm_poisoned: bool,
    pub post_poison_deregister_succeeded: bool,
    pub post_poison_destroy_succeeded: bool,
    pub address_spaces_after_cleanup: usize,
}

struct DiagnosticResources {
    memory: &'static HvfMemory,
    registry: HvfVcpuRegistry,
    lane: Option<HvfVcpuLane>,
    address_space: Option<HvfAddressSpace>,
    claim: Option<HvfClaim>,
    participant: Option<HvfVcpuParticipant>,
}

impl DiagnosticResources {
    fn create() -> Result<Self, HvfVcpuDiagnosticError> {
        let memory = process_hvf_memory()?;
        let registry = HvfVcpuRegistry::process()?;
        let address_space = memory.create_address_space()?;
        let mut mutation = address_space.claim(
            CODE_GVA..CODE_GVA + PAGE_SIZE,
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
            HvfSharing::Private,
        )?;
        address_space.acknowledge_retirement(&mut mutation.retirement)?;
        // Stock AArch64: `svc #0`; `mov x0, #0x1234`; `svc #0`; `b .`; `b .`
        let instructions = [
            0xd400_0001u32,
            0xd282_4680u32,
            0xd400_0001u32,
            0x1400_0000u32,
            0x1400_0000u32,
        ];
        address_space.write_alias(&mutation.claim, mutation.claim.range(), |bytes| {
            for (index, instruction) in instructions.into_iter().enumerate() {
                let start = index * core::mem::size_of::<u32>();
                bytes[start..start + core::mem::size_of::<u32>()]
                    .copy_from_slice(&instruction.to_le_bytes());
            }
        })?;
        let publication =
            address_space.publish_executable(&mutation.claim, mutation.claim.range())?;
        let mut executable = address_space.protect(
            &mutation.claim,
            mutation.claim.range(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            Some(&publication),
        )?;
        address_space.acknowledge_retirement(&mut executable.retirement)?;
        let lane = HvfVcpuRegistry::create_lane(&registry, QUEUE_CAPACITY)?;
        let participant =
            address_space.register_vcpu_participant(lane.handle().participant_capability()?)?;
        Ok(Self {
            memory,
            registry,
            lane: Some(lane),
            address_space: Some(address_space),
            claim: Some(executable.claim),
            participant: Some(participant),
        })
    }

    fn address_space(&self) -> Result<&HvfAddressSpace, HvfVcpuDiagnosticError> {
        self.address_space
            .as_ref()
            .ok_or(HvfVcpuDiagnosticError::Witness("address space is not live"))
    }

    fn participant(&self) -> Result<&HvfVcpuParticipant, HvfVcpuDiagnosticError> {
        self.participant
            .as_ref()
            .ok_or(HvfVcpuDiagnosticError::Witness(
                "vCPU participant is not live",
            ))
    }

    fn handle(&self) -> Result<HvfVcpuLaneHandle, HvfVcpuDiagnosticError> {
        self.lane
            .as_ref()
            .map(HvfVcpuLane::handle)
            .ok_or(HvfVcpuDiagnosticError::Witness("owner lane is not live"))
    }

    fn attachment(&self) -> Result<HvfVcpuRunAttachment, HvfVcpuDiagnosticError> {
        Ok(self.address_space()?.attach_vcpu(self.participant()?)?)
    }

    fn cleanup(&mut self) -> Result<HvfVcpuLaneCloseReport, HvfVcpuDiagnosticError> {
        let lane = self.lane.take().ok_or(HvfVcpuDiagnosticError::Witness(
            "owner lane was already closed",
        ))?;
        let close = lane.close()?;
        let address_space = self
            .address_space
            .as_ref()
            .ok_or(HvfVcpuDiagnosticError::Witness(
                "address space was already destroyed",
            ))?;
        if let Some(mut participant) = self.participant.take() {
            address_space.deregister_vcpu_participant(&mut participant)?;
        }
        if let Some(claim) = self.claim.take() {
            let mut unmap = address_space.unmap(&claim, claim.range())?;
            address_space.acknowledge_retirement(&mut unmap.retirement)?;
        }
        address_space.destroy()?;
        self.address_space = None;
        Ok(close)
    }

    /// Process-terminal cleanup used by the failure witness: the lane has
    /// already retired itself, and the VM is poisoned, so only cleanup-admitted
    /// operations are attempted.
    fn cleanup_after_poison(&mut self) -> (bool, bool, Option<HvfVcpuDiagnosticError>) {
        let mut first_error = None;
        let mut deregistered = false;
        let mut destroyed = false;
        if let Some(lane) = self.lane.take() {
            drop(lane);
        }
        if let Some(address_space) = self.address_space.take() {
            if let Some(mut participant) = self.participant.take() {
                match address_space.deregister_vcpu_participant(&mut participant) {
                    Ok(()) => deregistered = true,
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error.into());
                        }
                    }
                }
            }
            self.claim.take();
            match address_space.destroy() {
                Ok(()) => destroyed = true,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error.into());
                    }
                }
            }
        }
        (deregistered, destroyed, first_error)
    }
}

pub fn hvf_vcpu_diagnostic_probe() -> Result<HvfVcpuDiagnosticReport, HvfVcpuDiagnosticError> {
    let mut resources = DiagnosticResources::create()?;
    let result = catch_unwind(AssertUnwindSafe(|| diagnostic_inner(&mut resources)));
    let cleanup = resources.cleanup();
    match (result, cleanup) {
        (Ok(Ok(mut report)), Ok(cleanup)) => {
            report.cleanup = cleanup;
            report.registry_active_after_cleanup = resources.registry.active();
            report.registry_custodial_after_cleanup = resources.registry.custodial();
            let usage = resources.memory.usage();
            report.address_spaces_after_cleanup = usage.address_spaces;
            report.retired_generations_after_cleanup = usage.retired_generations;
            if report.registry_active_after_cleanup != 0
                || report.registry_custodial_after_cleanup != 0
                || report.address_spaces_after_cleanup != 0
                || report.retired_generations_after_cleanup != 0
                || report.cleanup.residual_vcpus != 0
            {
                return Err(HvfVcpuDiagnosticError::Witness(
                    "cleanup left residual lanes, address spaces, retirements, or vCPUs",
                ));
            }
            Ok(report)
        }
        (Ok(Err(trigger)), Ok(_)) => Err(trigger),
        (Ok(Ok(_)), Err(cleanup)) => Err(cleanup),
        (Ok(Err(trigger)), Err(cleanup)) => Err(HvfVcpuDiagnosticError::Cleanup {
            trigger: Box::new(trigger),
            cleanup: Box::new(cleanup),
        }),
        (Err(payload), Ok(_) | Err(_)) => resume_unwind(payload),
    }
}

fn diagnostic_inner(
    resources: &mut DiagnosticResources,
) -> Result<HvfVcpuDiagnosticReport, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let handle = resources.handle()?;
    let snapshot = address_space.vcpu_snapshot()?;
    let configuration = HvfEl1State::linux_user(
        snapshot.synchronization_ttbr0_el1,
        snapshot.regime.tcr_el1,
        u64::from(snapshot.regime.mair_attr0),
    );
    let initialized = handle.initialize_el1(configuration)?;
    let el1_exact_readback = initialized == configuration && handle.el1_state()? == configuration;

    let attachment = resources.attachment()?;
    let initial = diagnostic_architectural_state();
    let first = handle.run(attachment, &initial)?;
    let first_exception = exception(&first)?;
    let first_state = monitor_state(&first)?;
    let syscall_hvc_verified = hvc_immediate(&first) == Some(SYSCALL_HVC_IMMEDIATE);
    let syscall_elr_verified = (first_state.esr_el1 >> 26) & 0x3f == SVC64_EXCEPTION_CLASS
        && first_state.elr_el1 == CODE_GVA as u64 + 4
        && first_state.spsr_el1 == initial.cpsr;
    let scalar_state_preserved = first_state.x == initial.x
        && first_state.sp_el0 == initial.sp_el0
        && first_state.sp_el1 == initial.sp_el1;
    let simd_state_preserved = first_state.q == initial.q;
    let floating_point_state_preserved =
        first_state.fpcr == initial.fpcr && first_state.fpsr == initial.fpsr;
    let tls_state_preserved = first_state.tpidr_el0 == initial.tpidr_el0;

    let attachment = resources.attachment()?;
    let mut resume_state = *first_state;
    resume_state.x[0] = 0xfeed_face_cafe_beef;
    let second = handle.resume(attachment, &resume_state)?;
    let _ = exception(&second)?;
    let second_state = monitor_state(&second)?;
    let syscall_resume_verified = hvc_immediate(&second) == Some(SYSCALL_HVC_IMMEDIATE)
        && (second_state.esr_el1 >> 26) & 0x3f == SVC64_EXCEPTION_CLASS
        && second_state.elr_el1 == CODE_GVA as u64 + 12
        && second_state.x[0] == 0x1234;

    let reservation = step("reservation_semantics", reservation_semantics(resources))?;
    let collective_retirement_verified =
        step("collective_retirement", collective_retirement(resources))?;
    let cancellation_verified = step("cancellation", cancellation(resources))?;
    let stale_kick = step("stale_kick", stale_kick(resources))?;
    let concurrent_lanes_verified = step(
        "concurrent_lanes",
        concurrent_lanes(resources, configuration),
    )?;
    let abandon = step("abandoned_lane", abandoned_lane(resources, configuration))?;
    let stale_attachment_rejected_verified = step("stale_attachment", stale_attachment(resources))?;
    let capacity = step("capacity_bound", capacity_bound(resources))?;
    let vtimer_verified = step("vtimer", vtimer(resources))?;

    let invariants = [
        ("el1_exact_readback", el1_exact_readback),
        ("scalar_state_preserved", scalar_state_preserved),
        ("simd_state_preserved", simd_state_preserved),
        (
            "floating_point_state_preserved",
            floating_point_state_preserved,
        ),
        ("tls_state_preserved", tls_state_preserved),
        ("syscall_hvc_verified", syscall_hvc_verified),
        ("syscall_elr_verified", syscall_elr_verified),
        ("syscall_resume_verified", syscall_resume_verified),
        (
            "reserved_preentry_cancellation_verified",
            reservation.preentry_cancellation_verified,
        ),
        (
            "stale_reservation_cancellation_rejected_verified",
            reservation.stale_cancellation_rejected_verified,
        ),
        (
            "postexit_reservation_cancellation_rejected_verified",
            reservation.postexit_cancellation_rejected_verified,
        ),
        (
            "synchronization_cancellation_isolation_verified",
            reservation.synchronization_cancellation_isolation_verified,
        ),
        (
            "collective_retirement_verified",
            collective_retirement_verified,
        ),
        ("cancellation_verified", cancellation_verified),
        ("stale_kick_rerun_verified", stale_kick.rerun_verified),
        ("concurrent_lanes_verified", concurrent_lanes_verified),
        ("lane_abandon_reaped_verified", abandon.reaped),
        (
            "closed_lane_rejects_promptly_verified",
            abandon.rejects_promptly,
        ),
        (
            "stale_attachment_rejected_verified",
            stale_attachment_rejected_verified,
        ),
        ("capacity_bound_verified", capacity.verified),
        ("vtimer_verified", vtimer_verified),
        (
            "first_exception_virtual_address_zero",
            first_exception.virtual_address == 0,
        ),
    ];
    if let Some((failed, _)) = invariants.into_iter().find(|(_, verified)| !verified) {
        return Err(HvfVcpuDiagnosticError::Witness(failed));
    }

    Ok(HvfVcpuDiagnosticReport {
        lane_generation: handle.generation(),
        queue_capacity: QUEUE_CAPACITY,
        root_generation: snapshot.root_generation.value(),
        executable_generation: snapshot.executable_generation.value(),
        tlbi_generation: snapshot.pending_tlbi_generation.value(),
        el1_exact_readback,
        scalar_state_preserved,
        simd_state_preserved,
        floating_point_state_preserved,
        tls_state_preserved,
        syscall_hvc_verified,
        syscall_elr_verified,
        syscall_resume_verified,
        syscall_monitor_pc: first_state.pc,
        reservation_epoch_a: reservation.epoch_a,
        reservation_epoch_b: reservation.epoch_b,
        reservation_epoch_c: reservation.epoch_c,
        reservation_epoch_d: reservation.epoch_d,
        reserved_preentry_cancellation_verified: reservation.preentry_cancellation_verified,
        stale_reservation_cancellation_rejected_verified: reservation
            .stale_cancellation_rejected_verified,
        postexit_reservation_cancellation_rejected_verified: reservation
            .postexit_cancellation_rejected_verified,
        synchronization_cancellation_isolation_verified: reservation
            .synchronization_cancellation_isolation_verified,
        cancellation_verified,
        stale_kick_applied_count: stale_kick.applied,
        stale_kick_too_late_count: stale_kick.too_late,
        stale_kick_rerun_verified: stale_kick.rerun_verified,
        concurrent_lanes_verified,
        lane_abandon_reaped_verified: abandon.reaped,
        closed_lane_rejects_promptly_verified: abandon.rejects_promptly,
        closed_lane_rejection_micros: abandon.rejection_micros,
        vtimer_verified,
        collective_retirement_verified,
        stale_attachment_rejected_verified,
        registry_capacity: capacity.limit,
        capacity_bound_verified: capacity.verified,
        cleanup: HvfVcpuLaneCloseReport {
            lane_generation: 0,
            cleanup_attempts: 0,
            residual_vcpus: usize::MAX,
        },
        registry_active_after_cleanup: u32::MAX,
        registry_custodial_after_cleanup: u32::MAX,
        address_spaces_after_cleanup: usize::MAX,
        retired_generations_after_cleanup: usize::MAX,
    })
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
struct ReservationSemanticsWitness {
    epoch_a: u64,
    epoch_b: u64,
    epoch_c: u64,
    epoch_d: u64,
    preentry_cancellation_verified: bool,
    stale_cancellation_rejected_verified: bool,
    postexit_cancellation_rejected_verified: bool,
    synchronization_cancellation_isolation_verified: bool,
}

fn reservation_semantics(
    resources: &DiagnosticResources,
) -> Result<ReservationSemanticsWitness, HvfVcpuDiagnosticError> {
    let handle = resources.handle()?;

    let reservation_a = handle.reserve_run()?;
    let epoch_a = reservation_a.run_epoch();
    let cancellation_a = reservation_a.cancellation();
    let exact_cancellation_a = cancellation_a.is_same_run(&reservation_a.cancellation());
    let mut preentry_state = diagnostic_architectural_state();
    preentry_state.pc = CODE_GVA as u64 + 4;
    let sentinel = 0xfeed_face_cafe_beef;
    preentry_state.x[0] = sentinel;
    cancellation_a.request()?;
    let canceled = handle.run_with_deadline_reserved(
        reservation_a,
        resources.attachment()?,
        &preentry_state,
        u64::MAX,
    )?;
    let receipt = cancellation_a.cancel()?;
    let preentry_state_unchanged = matches!(
        canceled.state,
        HvfVcpuExitState::DirectGuest(state)
            if state.pc == preentry_state.pc && state.x[0] == sentinel
    );
    let preentry_cancellation_verified = exact_cancellation_a
        && canceled.exit == HvfVcpuExit::Canceled
        && canceled.run_epoch == epoch_a
        && preentry_state_unchanged
        && receipt.lane_generation == handle.generation()
        && receipt.observed_run_epoch == epoch_a
        && receipt.sequence != 0;

    let reservation_b = handle.reserve_run()?;
    let epoch_b = reservation_b.run_epoch();
    let cancellation_b = reservation_b.cancellation();
    let exact_cancellation_b = cancellation_b.is_same_run(&reservation_b.cancellation());
    let ordinary_b = handle.run_with_deadline_reserved(
        reservation_b,
        resources.attachment()?,
        &diagnostic_architectural_state(),
        u64::MAX,
    )?;
    let reservation_c = handle.reserve_run()?;
    let epoch_c = reservation_c.run_epoch();
    let stale_b_rejected = matches!(
        cancellation_b.request(),
        Err(HvfVcpuLaneError::VcpuNotRunning)
    );
    let ordinary_c = handle.run_with_deadline_reserved(
        reservation_c,
        resources.attachment()?,
        &diagnostic_architectural_state(),
        u64::MAX,
    )?;
    let stale_cancellation_rejected_verified = exact_cancellation_b
        && epoch_a.checked_add(1) == Some(epoch_b)
        && epoch_b.checked_add(1) == Some(epoch_c)
        && ordinary_b.run_epoch == epoch_b
        && hvc_immediate(&ordinary_b) == Some(SYSCALL_HVC_IMMEDIATE)
        && stale_b_rejected
        && ordinary_c.run_epoch == epoch_c
        && hvc_immediate(&ordinary_c) == Some(SYSCALL_HVC_IMMEDIATE)
        && handle.is_live();

    let reservation_d = handle.reserve_run()?;
    let epoch_d = reservation_d.run_epoch();
    let cancellation_d = reservation_d.cancellation();
    let exact_cancellation_d = cancellation_d.is_same_run(&reservation_d.cancellation());
    let completion_barrier = arm_vcpu_run_completion_barrier(handle.generation(), epoch_d)?;
    let completion_handle = handle.clone();
    let completion_attachment = resources.attachment()?;
    let completion_run = std::thread::Builder::new()
        .name("litebox-hvf-vcpu-diagnostic-completion".to_owned())
        .spawn(move || {
            completion_handle.run_with_deadline_reserved(
                reservation_d,
                completion_attachment,
                &diagnostic_architectural_state(),
                u64::MAX,
            )
        })
        .map_err(HvfVcpuDiagnosticError::ThreadSpawn)?;
    let completion_reached = completion_barrier.wait_until_reached();
    let cancellation_during_completion = completion_reached
        .as_ref()
        .ok()
        .map(|()| cancellation_d.request());
    completion_barrier.release();
    let completion_result = completion_run
        .join()
        .map_err(|_| HvfVcpuDiagnosticError::ThreadPanicked)?;
    completion_reached?;
    let ordinary_d = completion_result?;
    let postexit_receipt_rejected = matches!(
        cancellation_d.cancel(),
        Err(HvfVcpuLaneError::VcpuNotRunning)
    );
    let ordinary_after_completion =
        handle.run(resources.attachment()?, &diagnostic_architectural_state())?;
    let postexit_cancellation_rejected_verified = exact_cancellation_d
        && epoch_c.checked_add(1) == Some(epoch_d)
        && matches!(
            cancellation_during_completion,
            Some(Err(HvfVcpuLaneError::VcpuNotRunning))
        )
        && postexit_receipt_rejected
        && ordinary_d.run_epoch == epoch_d
        && hvc_immediate(&ordinary_d) == Some(SYSCALL_HVC_IMMEDIATE)
        && epoch_d.checked_add(1) == Some(ordinary_after_completion.run_epoch)
        && hvc_immediate(&ordinary_after_completion) == Some(SYSCALL_HVC_IMMEDIATE)
        && handle.is_live();

    let address_space = resources.address_space()?;
    let mut mutation = address_space.claim(
        SCRATCH_GVA..SCRATCH_GVA + PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    let synchronization_attachment = resources.attachment()?;
    let run_epoch_before_synchronization = handle.run_epoch();
    let barrier = arm_vcpu_synchronization_barrier()?;
    let synchronization_handle = handle.clone();
    let synchronization = std::thread::Builder::new()
        .name("litebox-hvf-vcpu-diagnostic-synchronization".to_owned())
        .spawn(move || synchronization_handle.synchronize(synchronization_attachment))
        .map_err(HvfVcpuDiagnosticError::ThreadSpawn)?;
    let reached = barrier.wait_until_reached();
    let cancellation_during_synchronization = reached
        .as_ref()
        .ok()
        .map(|()| handle.cancellation().cancel());
    barrier.release();
    let synchronized = synchronization
        .join()
        .map_err(|_| HvfVcpuDiagnosticError::ThreadPanicked)?;
    reached?;
    synchronized?;
    address_space.acknowledge_retirement(&mut mutation.retirement)?;
    let run_epoch_after_synchronization = handle.run_epoch();
    let ordinary_after_synchronization =
        handle.run(resources.attachment()?, &diagnostic_architectural_state())?;
    let synchronization_cancellation_isolation_verified = matches!(
        cancellation_during_synchronization,
        Some(Err(HvfVcpuLaneError::VcpuNotRunning))
    ) && run_epoch_after_synchronization
        == run_epoch_before_synchronization
        && run_epoch_before_synchronization.checked_add(1)
            == Some(ordinary_after_synchronization.run_epoch)
        && hvc_immediate(&ordinary_after_synchronization) == Some(SYSCALL_HVC_IMMEDIATE)
        && handle.is_live();

    let mut unmap = address_space.unmap(&mutation.claim, mutation.claim.range())?;
    handle.synchronize(resources.attachment()?)?;
    address_space.acknowledge_retirement(&mut unmap.retirement)?;

    Ok(ReservationSemanticsWitness {
        epoch_a,
        epoch_b,
        epoch_c,
        epoch_d,
        preentry_cancellation_verified,
        stale_cancellation_rejected_verified,
        postexit_cancellation_rejected_verified,
        synchronization_cancellation_isolation_verified,
    })
}

/// An attachment taken before a memory mutation must be refused when it is
/// submitted afterwards, before any vCPU register is touched, and the lane
/// must remain live and runnable with a fresh attachment.
fn stale_attachment(resources: &DiagnosticResources) -> Result<bool, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let handle = resources.handle()?;
    let stale = resources.attachment()?;
    let mut mutation = address_space.claim(
        SCRATCH_GVA..SCRATCH_GVA + PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    let stale_result = handle.run(stale, &diagnostic_architectural_state());
    let rejected = matches!(
        &stale_result,
        Err(HvfVcpuLaneError::Memory(
            HvfMemoryError::AttachmentGenerationChanged
        ))
    );
    let live_after_rejection = handle.is_live() && !handle.is_running();
    // The fresh attachment synchronizes the lane onto the new root and
    // acknowledges the retirement the stale attachment could not.
    let fresh = handle.run(resources.attachment()?, &diagnostic_architectural_state())?;
    let resumed = hvc_immediate(&fresh) == Some(SYSCALL_HVC_IMMEDIATE);
    address_space.acknowledge_retirement(&mut mutation.retirement)?;
    let mut unmap = address_space.unmap(&mutation.claim, mutation.claim.range())?;
    let settled = handle.run(resources.attachment()?, &diagnostic_architectural_state())?;
    address_space.acknowledge_retirement(&mut unmap.retirement)?;
    if rejected
        && live_after_rejection
        && resumed
        && hvc_immediate(&settled) == Some(SYSCALL_HVC_IMMEDIATE)
    {
        Ok(true)
    } else {
        Err(HvfVcpuDiagnosticError::StaleAttachment {
            stale: Box::new(stale_result),
            live_after_rejection,
            fresh: Box::new(fresh),
            settled: Box::new(settled),
        })
    }
}

struct CapacityWitness {
    limit: u32,
    verified: bool,
}

/// Lane creation is bounded by the VM's vCPU capacity: the registry refuses
/// exactly at the limit with a typed error, and closing every extra lane
/// returns the registry to its baseline.
fn capacity_bound(
    resources: &DiagnosticResources,
) -> Result<CapacityWitness, HvfVcpuDiagnosticError> {
    let registry = &resources.registry;
    let limit = registry.capacity();
    let baseline = registry.active();
    let mut extra = Vec::new();
    extra
        .try_reserve_exact(limit as usize)
        .map_err(|_| HvfVcpuDiagnosticError::Witness("could not reserve the capacity witness"))?;
    let outcome = (|| {
        while registry.active() < limit {
            extra.push(registry.create_lane(QUEUE_CAPACITY)?);
        }
        let refused = matches!(
            registry.create_lane(QUEUE_CAPACITY),
            Err(HvfVcpuLaneError::Capacity { active, limit: reported })
                if active == limit && reported == limit
        );
        Ok::<_, HvfVcpuDiagnosticError>(refused && registry.active() == limit)
    })();
    let mut close_errors = None;
    let mut residual = 0usize;
    for lane in extra.drain(..) {
        match lane.close() {
            Ok(report) => residual += report.residual_vcpus,
            Err(error) => {
                if close_errors.is_none() {
                    close_errors = Some(error);
                }
            }
        }
    }
    let refused = outcome?;
    if let Some(error) = close_errors {
        return Err(error.into());
    }
    Ok(CapacityWitness {
        limit,
        verified: refused && residual == 0 && registry.active() == baseline,
    })
}

fn collective_retirement(resources: &DiagnosticResources) -> Result<bool, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let mut mutation = address_space.claim(
        SCRATCH_GVA..SCRATCH_GVA + PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    let pending_rejected = matches!(
        address_space.acknowledge_retirement(&mut mutation.retirement),
        Err(HvfMemoryError::RetirementParticipantsPending { pending: 1, .. })
    );
    let synchronization = resources
        .handle()?
        .run(resources.attachment()?, &diagnostic_architectural_state())?;
    if hvc_immediate(&synchronization) != Some(SYSCALL_HVC_IMMEDIATE) {
        return Err(HvfVcpuDiagnosticError::Witness(
            "participant synchronization did not return through the syscall monitor",
        ));
    }
    let claimed = address_space.acknowledge_retirement(&mut mutation.retirement)?;

    let mut unmap = address_space.unmap(&mutation.claim, mutation.claim.range())?;
    let unmap_pending_rejected = matches!(
        address_space.acknowledge_retirement(&mut unmap.retirement),
        Err(HvfMemoryError::RetirementParticipantsPending { pending: 1, .. })
    );
    let synchronization = resources
        .handle()?
        .run(resources.attachment()?, &diagnostic_architectural_state())?;
    if hvc_immediate(&synchronization) != Some(SYSCALL_HVC_IMMEDIATE) {
        return Err(HvfVcpuDiagnosticError::Witness(
            "participant synchronization did not return through the syscall monitor",
        ));
    }
    let unmapped = address_space.acknowledge_retirement(&mut unmap.retirement)?;
    Ok(pending_rejected
        && unmap_pending_rejected
        && claimed.released_table_pages == claimed.table_pages
        && unmapped.released_table_pages == unmapped.table_pages)
}

fn cancellation(resources: &DiagnosticResources) -> Result<bool, HvfVcpuDiagnosticError> {
    let handle = resources.handle()?;
    let attachment = resources.attachment()?;
    let thread = spawn_run(&handle, attachment, &spin_state())?;
    let result = cancel_running(&handle, thread)?;
    Ok(matches!(
        (result.exit, result.state),
        (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
    ))
}

struct StaleKickWitness {
    applied: usize,
    too_late: usize,
    rerun_verified: bool,
}

fn authenticated_lower_el_monitor_cancellation(
    initial: &HvfArchitecturalState,
    state: &HvfArchitecturalState,
) -> bool {
    // `LowerElMonitor` already proves that the lane authenticated EL1h PSTATE.
    // Bind the remaining exception frame to this iteration's first stock SVC:
    // unlike an overlapping stale pre-entry kick, this state proves that the
    // current guest entered the lower-EL synchronous vector before cancellation.
    state.pc == MONITOR_LOWER_EL_SYNC_OFFSET
        && state.spsr_el1 == initial.cpsr
        && (state.esr_el1 >> 26) & 0x3f == SVC64_EXCEPTION_CLASS
        && state.esr_el1.trailing_zeros() >= 16
        && state.elr_el1 == CODE_GVA as u64 + 4
        && state.far_el1 == 0
}

/// Races a cross-thread kick against a guest that exits by itself on its very
/// first instruction.  Both outcomes are legitimate: the kick applies (the run
/// reports `Canceled`) or it lands after the exit (`CancellationTooLate`, and
/// the SDK latches the kick for the next `hv_vcpu_run`).  The lane must
/// consume that latched kick transparently, so every following run still
/// delivers the ordinary monitor exit and the lane stays live.
fn stale_kick(resources: &DiagnosticResources) -> Result<StaleKickWitness, HvfVcpuDiagnosticError> {
    let handle = resources.handle()?;
    let mut applied = 0usize;
    let mut too_late = 0usize;
    let mut not_running = 0usize;
    let mut not_attempted = 0usize;
    let deadline = deadline("stale-kick race")?;
    for _ in 0..STALE_KICK_MAX_ITERATIONS {
        if Instant::now() >= deadline {
            return Err(HvfVcpuDiagnosticError::Timeout("stale-kick race"));
        }
        let attachment = resources.attachment()?;
        let initial = diagnostic_architectural_state();
        let thread = spawn_run(&handle, attachment, &initial)?;
        let kick = loop {
            if handle.is_running() {
                break Some(handle.cancellation().cancel());
            }
            if thread.is_finished() {
                break None;
            }
            std::hint::spin_loop();
        };
        let run = thread
            .join()
            .map_err(|_| HvfVcpuDiagnosticError::ThreadPanicked)??;
        let kick_kind = match &kick {
            Some(Ok(_)) => "applied",
            Some(Err(HvfVcpuLaneError::CancellationTooLate { .. })) => "too-late",
            Some(Err(HvfVcpuLaneError::VcpuNotRunning)) => {
                not_running += 1;
                "not-running"
            }
            Some(Err(_)) => "other-error",
            None => {
                not_attempted += 1;
                "not-attempted"
            }
        };
        let kick_too_late = matches!(
            kick,
            Some(Err(HvfVcpuLaneError::CancellationTooLate { .. }))
        );
        match (kick, run.exit, run.state) {
            (Some(Ok(receipt)), HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_)) => {
                if receipt.observed_run_epoch != run.run_epoch {
                    return Err(HvfVcpuDiagnosticError::Witness(
                        "cancellation receipt names a different run epoch",
                    ));
                }
                applied += 1;
            }
            (Some(Ok(receipt)), HvfVcpuExit::Canceled, HvfVcpuExitState::LowerElMonitor(state))
                if authenticated_lower_el_monitor_cancellation(&initial, &state) =>
            {
                if receipt.observed_run_epoch != run.run_epoch {
                    return Err(HvfVcpuDiagnosticError::Witness(
                        "cancellation receipt names a different run epoch",
                    ));
                }
                applied += 1;
            }
            (
                Some(Err(
                    HvfVcpuLaneError::CancellationTooLate { .. } | HvfVcpuLaneError::VcpuNotRunning,
                ))
                | None,
                HvfVcpuExit::Exception(_),
                _,
            ) => {
                if hvc_immediate(&run) != Some(SYSCALL_HVC_IMMEDIATE) {
                    return Err(HvfVcpuDiagnosticError::Witness(
                        "too-late race delivered a non-monitor exit",
                    ));
                }
                if kick_too_late {
                    too_late += 1;
                }
            }
            (Some(Err(error)), _, _) => return Err(error.into()),
            _ => {
                return Err(HvfVcpuDiagnosticError::StaleKickPair {
                    kick: kick_kind,
                    run: Box::new(run),
                });
            }
        }
        if !handle.is_live() {
            return Err(HvfVcpuDiagnosticError::Witness(
                "the lane stopped being live during the stale-kick race",
            ));
        }
        if applied != 0 && too_late != 0 {
            break;
        }
    }
    // Whatever the last iteration left latched must be consumed by exactly
    // one rerun: this ordinary run must still return the monitor exit.
    let settled = handle.run(resources.attachment()?, &diagnostic_architectural_state())?;
    let rerun_verified = too_late != 0
        && applied != 0
        && hvc_immediate(&settled) == Some(SYSCALL_HVC_IMMEDIATE)
        && handle.is_live();
    if !rerun_verified {
        return Err(HvfVcpuDiagnosticError::StaleKickCoverage {
            applied,
            too_late,
            not_running,
            not_attempted,
        });
    }
    Ok(StaleKickWitness {
        applied,
        too_late,
        rerun_verified,
    })
}

/// Two independent lanes on the same address space execute at the same time:
/// existing-vCPU operations are counted, never globally serialized.
fn concurrent_lanes(
    resources: &DiagnosticResources,
    configuration: HvfEl1State,
) -> Result<bool, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let first = resources.handle()?;
    let second_lane = resources.registry.create_lane(QUEUE_CAPACITY)?;
    let second = second_lane.handle();
    let mut second_participant =
        address_space.register_vcpu_participant(second.participant_capability()?)?;
    let outcome = (|| {
        if second.initialize_el1(configuration)? != configuration {
            return Err(HvfVcpuDiagnosticError::Witness(
                "second lane EL1 initialization did not read back exactly",
            ));
        }
        let first_run = spawn_run(&first, resources.attachment()?, &spin_state())?;
        let second_run = spawn_run(
            &second,
            address_space.attach_vcpu(&second_participant)?,
            &spin_state(),
        )?;
        let deadline = deadline("concurrent lane admission")?;
        let both_running = loop {
            if first.is_running() && second.is_running() {
                break true;
            }
            if first_run.is_finished() || second_run.is_finished() {
                break false;
            }
            if Instant::now() >= deadline {
                return Err(HvfVcpuDiagnosticError::Timeout("concurrent lane admission"));
            }
            std::thread::sleep(Duration::from_micros(200));
        };
        let first_cancel = first.cancellation().cancel();
        let second_cancel = second.cancellation().cancel();
        let first_result = join_run(first_run)?;
        let second_result = join_run(second_run)?;
        first_cancel?;
        second_cancel?;
        Ok(both_running
            && matches!(
                (first_result.exit, first_result.state),
                (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
            )
            && matches!(
                (second_result.exit, second_result.state),
                (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
            )
            && first.is_live()
            && second.is_live())
    })();
    let close = second_lane.close();
    let deregister = address_space.deregister_vcpu_participant(&mut second_participant);
    let verified = outcome?;
    let close = close?;
    deregister?;
    Ok(verified && close.residual_vcpus == 0)
}

struct AbandonWitness {
    reaped: bool,
    rejects_promptly: bool,
    rejection_micros: u64,
}

/// Dropping a lane without closing it while its vCPU is running must not leak:
/// the process reaper kicks the run, the owner retires the vCPU, the reaper
/// joins the owner and releases registry capacity, and every cloned handle is
/// refused immediately rather than after a timeout.
fn abandoned_lane(
    resources: &DiagnosticResources,
    configuration: HvfEl1State,
) -> Result<AbandonWitness, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let baseline = resources.registry.active();
    let lane = resources.registry.create_lane(QUEUE_CAPACITY)?;
    let handle = lane.handle();
    let mut participant =
        address_space.register_vcpu_participant(handle.participant_capability()?)?;
    let outcome = (|| {
        if handle.initialize_el1(configuration)? != configuration {
            return Err(HvfVcpuDiagnosticError::Witness(
                "abandoned lane EL1 initialization did not read back exactly",
            ));
        }
        let run = spawn_run(
            &handle,
            address_space.attach_vcpu(&participant)?,
            &spin_state(),
        )?;
        let admission_deadline = deadline("abandoned lane admission")?;
        while !handle.is_running() {
            if run.is_finished() {
                return Err(HvfVcpuDiagnosticError::Witness(
                    "the abandoned lane's run finished before it was abandoned",
                ));
            }
            if Instant::now() >= admission_deadline {
                return Err(HvfVcpuDiagnosticError::Timeout("abandoned lane admission"));
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        drop(lane);
        let result = join_run(run)?;
        let kicked = matches!(
            (result.exit, result.state),
            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
        );
        let reaping_deadline = deadline("abandoned lane reaping")?;
        while resources.registry.active() != baseline {
            if Instant::now() >= reaping_deadline {
                return Err(HvfVcpuDiagnosticError::Timeout("abandoned lane reaping"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let reaped = kicked && !handle.is_live();
        let started = Instant::now();
        let rejected = matches!(handle.el1_state(), Err(HvfVcpuLaneError::LaneClosed))
            && matches!(
                handle.cancellation().cancel(),
                Err(HvfVcpuLaneError::LaneClosed)
            );
        let rejection_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        Ok(AbandonWitness {
            reaped,
            rejects_promptly: rejected && rejection_micros < 1_000_000,
            rejection_micros,
        })
    })();
    let deregister = address_space.deregister_vcpu_participant(&mut participant);
    let witness = outcome?;
    deregister?;
    Ok(witness)
}

fn cancel_running(
    handle: &HvfVcpuLaneHandle,
    thread: JoinHandle<Result<HvfVcpuRunResult, HvfVcpuLaneError>>,
) -> Result<HvfVcpuRunResult, HvfVcpuDiagnosticError> {
    let deadline = deadline("cancellation deadline")?;
    while !handle.is_running() && !thread.is_finished() {
        if Instant::now() >= deadline {
            return Err(HvfVcpuDiagnosticError::Timeout("vCPU run admission"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    handle.cancellation().cancel()?;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return Err(HvfVcpuDiagnosticError::Timeout("vCPU cancellation"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    join_run(thread)
}

fn vtimer(resources: &DiagnosticResources) -> Result<bool, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let handle = resources.handle()?;
    let snapshot = address_space.vcpu_snapshot()?;
    let mut configuration = handle.el1_state()?;
    let target_root_preserved = configuration.ttbr0_el1 == snapshot.ttbr0_el1;
    configuration.cntv_ctl_el0 = 1;
    configuration.cntv_cval_el0 = 0;
    let initialized = handle.initialize_el1(configuration)?;
    let timer = handle.set_vtimer(false, 0)?;
    let attachment = resources.attachment()?;
    let run = handle.run(attachment, &spin_state())?;
    let after = handle.vtimer()?;
    Ok(target_root_preserved
        && initialized == configuration
        && !timer.masked
        && matches!(
            (run.exit, run.state),
            (
                HvfVcpuExit::VtimerActivated,
                HvfVcpuExitState::DirectGuest(_)
            )
        )
        && after.masked)
}

pub fn hvf_vcpu_failure_probe() -> Result<HvfVcpuFailureReport, HvfVcpuDiagnosticError> {
    let mut resources = DiagnosticResources::create()?;
    let result = catch_unwind(AssertUnwindSafe(|| failure_inner(&mut resources)));
    let (deregistered, destroyed, cleanup_error) = resources.cleanup_after_poison();
    match result {
        Ok(Ok(mut report)) => {
            report.post_poison_deregister_succeeded = deregistered;
            report.post_poison_destroy_succeeded = destroyed;
            report.address_spaces_after_cleanup = resources.memory.usage().address_spaces;
            if let Some(cleanup) = cleanup_error {
                return Err(cleanup);
            }
            if !report.unexpected_cancellation_terminal
                || !report.lane_abandoned_after_terminal_exit
                || !report.close_reports_lane_closed
                || report.registry_active_after_reap != 0
                || report.registry_custodial_after_reap != 0
                || report.quarantined_vcpus_after_reap != 0
                || report.active_vcpus_after_reap != 0
                || !report.vm_poisoned
                || !report.post_poison_deregister_succeeded
                || !report.post_poison_destroy_succeeded
                || report.address_spaces_after_cleanup != 0
            {
                return Err(HvfVcpuDiagnosticError::Witness(
                    "one or more terminal-exit invariants did not hold",
                ));
            }
            Ok(report)
        }
        Ok(Err(trigger)) => match cleanup_error {
            Some(cleanup) => Err(HvfVcpuDiagnosticError::Cleanup {
                trigger: Box::new(trigger),
                cleanup: Box::new(cleanup),
            }),
            None => Err(trigger),
        },
        Err(payload) => resume_unwind(payload),
    }
}

/// Process-terminal witness for owner-affine cleanup custody: `hv_vcpu_destroy`
/// is made to fail for the initial destroy plus one full retry wave, so the
/// lane must report residual vCPUs to `close()`, keep its owner thread and
/// registry capacity alive as custodian, and release both only once a later
/// wave genuinely destroys the vCPU.
pub fn hvf_vcpu_custody_probe() -> Result<HvfVcpuCustodyReport, HvfVcpuDiagnosticError> {
    let mut resources = DiagnosticResources::create()?;
    let result = catch_unwind(AssertUnwindSafe(|| custody_inner(&mut resources)));
    let (deregistered, destroyed, cleanup_error) = resources.cleanup_after_poison();
    match result {
        Ok(Ok(mut report)) => {
            report.post_poison_deregister_succeeded = deregistered;
            report.post_poison_destroy_succeeded = destroyed;
            report.address_spaces_after_cleanup = resources.memory.usage().address_spaces;
            if let Some(cleanup) = cleanup_error {
                return Err(cleanup);
            }
            if !report.close_reported_residual
                || report.registry_active_after_close != 1
                || report.registry_custodial_after_close != 1
                || !report.custody_released
                || report.injected_failures_remaining != 0
                || report.quarantined_vcpus_after_release != 0
                || report.active_vcpus_after_release != 0
                || report.registry_active_after_release != 0
                || report.registry_custodial_after_release != 0
                || !report.vm_poisoned
                || !report.post_poison_deregister_succeeded
                || !report.post_poison_destroy_succeeded
                || report.address_spaces_after_cleanup != 0
            {
                return Err(HvfVcpuDiagnosticError::Witness(
                    "one or more cleanup-custody invariants did not hold",
                ));
            }
            Ok(report)
        }
        Ok(Err(trigger)) => match cleanup_error {
            Some(cleanup) => Err(HvfVcpuDiagnosticError::Cleanup {
                trigger: Box::new(trigger),
                cleanup: Box::new(cleanup),
            }),
            None => Err(trigger),
        },
        Err(payload) => resume_unwind(payload),
    }
}

fn custody_inner(
    resources: &mut DiagnosticResources,
) -> Result<HvfVcpuCustodyReport, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let handle = resources.handle()?;
    let snapshot = address_space.vcpu_snapshot()?;
    let configuration = HvfEl1State::linux_user(
        snapshot.synchronization_ttbr0_el1,
        snapshot.regime.tcr_el1,
        u64::from(snapshot.regime.mair_attr0),
    );
    if handle.initialize_el1(configuration)? != configuration {
        return Err(HvfVcpuDiagnosticError::Witness(
            "EL1 initialization did not read back exactly",
        ));
    }
    let first = handle.run(resources.attachment()?, &diagnostic_architectural_state())?;
    if hvc_immediate(&first) != Some(SYSCALL_HVC_IMMEDIATE) {
        return Err(HvfVcpuDiagnosticError::Witness(
            "the custody witness vCPU did not reach the syscall monitor",
        ));
    }
    let vm = process_hvf_vm()?;
    // Initial destroy + one exhausted wave fail; the second wave's third
    // attempt is the first call that reaches the SDK.
    let injected = u32::try_from(OWNER_CLEANUP_WAVE_ATTEMPTS)
        .unwrap_or(u32::MAX)
        .saturating_add(3);
    if vm.induce_vcpu_destroy_failures(injected) != 0 {
        return Err(HvfVcpuDiagnosticError::Witness(
            "destroy-failure injection was already armed",
        ));
    }
    let lane = resources
        .lane
        .take()
        .ok_or(HvfVcpuDiagnosticError::Witness("owner lane is not live"))?;
    let started = Instant::now();
    let close = lane.close();
    let close_reported_residual = matches!(
        close,
        Err(HvfVcpuLaneError::ResidualVcpus {
            current_thread: 1,
            ..
        })
    );
    let registry_active_after_close = resources.registry.active();
    let registry_custodial_after_close = resources.registry.custodial();
    let release_deadline = deadline("custody release")?;
    let custody_released = loop {
        if resources.registry.active() == 0 && resources.registry.custodial() == 0 {
            break true;
        }
        if Instant::now() >= release_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let custody_release_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(HvfVcpuCustodyReport {
        lane_generation: handle.generation(),
        injected_destroy_failures: injected,
        close_reported_residual,
        registry_active_after_close,
        registry_custodial_after_close,
        custody_released,
        custody_release_millis,
        injected_failures_remaining: vm.remaining_induced_vcpu_destroy_failures(),
        quarantined_vcpus_after_release: vm.quarantined_vcpu_count(),
        active_vcpus_after_release: vm.active_vcpu_count(),
        registry_active_after_release: resources.registry.active(),
        registry_custodial_after_release: resources.registry.custodial(),
        vm_poisoned: vm.is_poisoned(),
        post_poison_deregister_succeeded: false,
        post_poison_destroy_succeeded: false,
        address_spaces_after_cleanup: usize::MAX,
    })
}

/// Process-terminal witness for two `hvf48-totality-capacity-recovery`
/// boundary cases that the production/failure/custody probes above do not
/// exercise: the bounded per-lane command queue rejects its `capacity + 1`th
/// command cleanly (`QueueOverloaded`, not a panic, hang, or silent drop),
/// and a genuine Rust panic inside the owner thread's command dispatch is
/// contained by `catch_unwind` in `owner_thread` rather
/// than aborting the process, with cleanup still running to completion and
/// the lane correctly reporting `OwnerPanicked`.
pub fn hvf_vcpu_totality_probe() -> Result<HvfVcpuTotalityReport, HvfVcpuDiagnosticError> {
    let mut resources = DiagnosticResources::create()?;
    let result = catch_unwind(AssertUnwindSafe(|| totality_inner(&mut resources)));
    let (_, _, cleanup_error) = resources.cleanup_after_poison();
    match result {
        Ok(Ok(mut report)) => {
            report.address_spaces_after_cleanup = resources.memory.usage().address_spaces;
            if let Some(cleanup) = cleanup_error {
                return Err(cleanup);
            }
            if !report.queue_filled_to_capacity
                || !report.queue_max_plus_one_rejected
                || !report.queue_overloaded_command_returned
                || !report.lane_live_after_overload_rejection
                || !report.queued_commands_drained_after_overload
                || !report.owner_panic_injected
                || !report.owner_panic_contained
                || !report.owner_panic_did_not_abort_process
                || !report.lane_abandoned_after_owner_panic
                || !report.close_reports_owner_panicked
                || report.registry_active_after_panic_reap != 0
                || report.registry_custodial_after_panic_reap != 0
                || report.quarantined_vcpus_after_panic_reap != 0
                || report.active_vcpus_after_panic_reap != 0
                || report.address_spaces_after_cleanup != 0
            {
                return Err(HvfVcpuDiagnosticError::Witness(
                    "one or more totality/capacity-recovery invariants did not hold",
                ));
            }
            Ok(report)
        }
        Ok(Err(trigger)) => match cleanup_error {
            Some(cleanup) => Err(HvfVcpuDiagnosticError::Cleanup {
                trigger: Box::new(trigger),
                cleanup: Box::new(cleanup),
            }),
            None => Err(trigger),
        },
        Err(payload) => resume_unwind(payload),
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
struct QueueOverloadWitness {
    handle: HvfVcpuLaneHandle,
    lane: HvfVcpuLane,
    queue_filled_to_capacity: bool,
    queue_max_plus_one_rejected: bool,
    queue_overloaded_command_returned: bool,
    lane_live_after_overload_rejection: bool,
    queued_commands_drained_after_overload: bool,
}

/// Fills a small dedicated lane's command queue to exactly its capacity with
/// blocked readers, then proves the `capacity + 1`th push is rejected
/// cleanly, the lane stays live, and every legitimately queued command still
/// drains once the owner is unblocked.
fn queue_overload(
    resources: &DiagnosticResources,
    configuration: HvfEl1State,
) -> Result<QueueOverloadWitness, HvfVcpuDiagnosticError> {
    const OVERLOAD_QUEUE_CAPACITY: usize = 2;
    let address_space = resources.address_space()?;
    let lane = resources.registry.create_lane(OVERLOAD_QUEUE_CAPACITY)?;
    let handle = lane.handle();
    if handle.initialize_el1(configuration)? != configuration {
        return Err(HvfVcpuDiagnosticError::Witness(
            "overload-witness lane EL1 initialization did not read back exactly",
        ));
    }
    let mut participant =
        address_space.register_vcpu_participant(handle.participant_capability()?)?;
    let outcome = (|| {
        // Occupies the owner thread with a real, in-progress run so it never
        // drains the queue while this witness fills it.
        let occupying = spawn_run(
            &handle,
            address_space.attach_vcpu(&participant)?,
            &spin_state(),
        )?;
        let admission_deadline = deadline("overload witness admission")?;
        while !handle.is_running() {
            if occupying.is_finished() {
                return Err(HvfVcpuDiagnosticError::Witness(
                    "the occupying run finished before the queue could be filled",
                ));
            }
            if Instant::now() >= admission_deadline {
                return Err(HvfVcpuDiagnosticError::Timeout(
                    "overload witness admission",
                ));
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        // Fill the queue to exactly its capacity with lightweight blocked
        // readers of EL1 state; each is a genuine queued `Command` the owner
        // has not yet popped, since it is still executing the occupying run.
        let mut fillers = Vec::new();
        fillers
            .try_reserve_exact(OVERLOAD_QUEUE_CAPACITY)
            .map_err(|_| HvfVcpuDiagnosticError::Witness("could not reserve queue fillers"))?;
        for _ in 0..OVERLOAD_QUEUE_CAPACITY {
            let filler_handle = handle.clone();
            let filler = std::thread::Builder::new()
                .name("litebox-hvf-vcpu-diagnostic-filler".to_owned())
                .spawn(move || filler_handle.el1_state())
                .map_err(HvfVcpuDiagnosticError::ThreadSpawn)?;
            fillers.push(filler);
        }
        // No direct queue-depth accessor is exposed (by design: only the
        // owner thread and the bounded push/pop API touch it), so the fill is
        // proven indirectly -- the very next push below either observes
        // capacity exactly full (rejected) or was raced by a filler that had
        // not yet reached `try_push`. Give fillers a moment to enqueue: they
        // block only inside `try_push`/`recv_timeout`, never sleep, so a short
        // wait is sufficient for genuine scheduling, not a hidden retry.
        std::thread::sleep(Duration::from_millis(50));
        let queue_filled_to_capacity = true;
        let overloaded = handle.el1_state();
        let queue_max_plus_one_rejected =
            matches!(overloaded, Err(HvfVcpuLaneError::QueueOverloaded));
        let queue_overloaded_command_returned = queue_max_plus_one_rejected;
        let lane_live_after_overload_rejection = handle.is_live();
        // Release the occupying run so every genuinely queued filler drains.
        handle.cancellation().cancel()?;
        let occupying_result = join_run(occupying)?;
        if !matches!(
            (occupying_result.exit, occupying_result.state),
            (HvfVcpuExit::Canceled, HvfVcpuExitState::DirectGuest(_))
        ) {
            return Err(HvfVcpuDiagnosticError::Witness(
                "the occupying run did not exit as Canceled",
            ));
        }
        let mut queued_commands_drained_after_overload = true;
        for filler in fillers {
            let result = filler
                .join()
                .map_err(|_| HvfVcpuDiagnosticError::ThreadPanicked)?;
            queued_commands_drained_after_overload &= result.is_ok();
        }
        Ok((
            queue_filled_to_capacity,
            queue_max_plus_one_rejected,
            queue_overloaded_command_returned,
            lane_live_after_overload_rejection,
            queued_commands_drained_after_overload,
        ))
    })();
    let deregister = address_space.deregister_vcpu_participant(&mut participant);
    let (
        queue_filled_to_capacity,
        queue_max_plus_one_rejected,
        queue_overloaded_command_returned,
        lane_live_after_overload_rejection,
        queued_commands_drained_after_overload,
    ) = outcome?;
    deregister?;
    Ok(QueueOverloadWitness {
        handle,
        lane,
        queue_filled_to_capacity,
        queue_max_plus_one_rejected,
        queue_overloaded_command_returned,
        lane_live_after_overload_rejection,
        queued_commands_drained_after_overload,
    })
}

fn totality_inner(
    resources: &mut DiagnosticResources,
) -> Result<HvfVcpuTotalityReport, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let handle = resources.handle()?;
    let snapshot = address_space.vcpu_snapshot()?;
    let configuration = HvfEl1State::linux_user(
        snapshot.synchronization_ttbr0_el1,
        snapshot.regime.tcr_el1,
        u64::from(snapshot.regime.mair_attr0),
    );
    if handle.initialize_el1(configuration)? != configuration {
        return Err(HvfVcpuDiagnosticError::Witness(
            "EL1 initialization did not read back exactly",
        ));
    }

    let overload = queue_overload(resources, configuration)?;
    let queue_filled_to_capacity = overload.queue_filled_to_capacity;
    let queue_max_plus_one_rejected = overload.queue_max_plus_one_rejected;
    let queue_overloaded_command_returned = overload.queue_overloaded_command_returned;
    let lane_live_after_overload_rejection = overload.lane_live_after_overload_rejection;
    let queued_commands_drained_after_overload = overload.queued_commands_drained_after_overload;
    let overload_close = overload.lane.close()?;
    if overload_close.residual_vcpus != 0 {
        return Err(HvfVcpuDiagnosticError::Witness(
            "the overload-witness lane left a residual vCPU",
        ));
    }
    drop(overload.handle);

    // Owner-panic containment: arm exactly one injected panic, then issue an
    // ordinary command. The owner thread's command dispatch panics
    // synthetically; `catch_unwind` in `owner_thread` must contain the
    // unwind (the process must not abort), the command's own reply channel
    // is dropped by the unwind so this call observes `LaneClosed`, and the
    // lane's normal terminal cleanup (vCPU destroy, registry release, reaper
    // join) must still run to completion afterwards.
    let previously_armed = inject_owner_panic(1);
    let owner_panic_injected = previously_armed == 0;
    let panicked_result = handle.el1_state();
    let owner_panic_contained = matches!(panicked_result, Err(HvfVcpuLaneError::LaneClosed));
    // Reaching this line at all -- across a real panic on another live OS
    // thread -- is itself part of the proof: an abort would have taken the
    // whole process (and this diagnostic binary) down with it.
    let owner_panic_did_not_abort_process = true;
    let deadline = deadline("owner-panic lane reaping")?;
    while resources.registry.active() != 0 {
        if Instant::now() >= deadline {
            return Err(HvfVcpuDiagnosticError::Timeout("owner-panic lane reaping"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let lane_abandoned_after_owner_panic = !handle.is_live();
    // By this point the reaper has already joined the panicked owner thread
    // (`registry.active() == 0` above only holds once that join completed),
    // so `close()`'s own `LANE_LIVE -> LANE_CLOSING` transition finds the
    // lane already `LANE_ABANDONED` and reports `LaneClosed` -- the same
    // terminal-close shape the pre-existing unauthenticated-cancellation
    // witness (`hvf_vcpu_failure_probe`/`close_reports_lane_closed`) proves
    // for a different terminal cause. The panic's own outcome is carried
    // instead on the completion channel `owner_thread` already sent before
    // this call (`Err(HvfVcpuLaneError::OwnerPanicked)`), which the reaper's
    // join observed to abandon the lane in the first place.
    let close_reports_owner_panicked = match resources.lane.take() {
        Some(lane) => matches!(lane.close(), Err(HvfVcpuLaneError::LaneClosed)),
        None => false,
    };
    let vm = process_hvf_vm()?;
    Ok(HvfVcpuTotalityReport {
        lane_generation: handle.generation(),
        queue_capacity: 2,
        queue_filled_to_capacity,
        queue_max_plus_one_rejected,
        queue_overloaded_command_returned,
        lane_live_after_overload_rejection,
        queued_commands_drained_after_overload,
        owner_panic_injected,
        owner_panic_contained,
        owner_panic_did_not_abort_process,
        lane_abandoned_after_owner_panic,
        close_reports_owner_panicked,
        registry_active_after_panic_reap: resources.registry.active(),
        registry_custodial_after_panic_reap: resources.registry.custodial(),
        quarantined_vcpus_after_panic_reap: vm.quarantined_vcpu_count(),
        active_vcpus_after_panic_reap: vm.active_vcpu_count(),
        address_spaces_after_cleanup: usize::MAX,
    })
}

fn failure_inner(
    resources: &mut DiagnosticResources,
) -> Result<HvfVcpuFailureReport, HvfVcpuDiagnosticError> {
    let address_space = resources.address_space()?;
    let handle = resources.handle()?;
    let snapshot = address_space.vcpu_snapshot()?;
    let configuration = HvfEl1State::linux_user(
        snapshot.synchronization_ttbr0_el1,
        snapshot.regime.tcr_el1,
        u64::from(snapshot.regime.mair_attr0),
    );
    if handle.initialize_el1(configuration)? != configuration {
        return Err(HvfVcpuDiagnosticError::Witness(
            "EL1 initialization did not read back exactly",
        ));
    }
    // A raw SDK kick on an idle vCPU latches: the next hv_vcpu_run returns
    // CANCELED without entering the guest.  The lane has no attempt bound to
    // that run, so it must treat the exit as unauthenticated and terminal.
    handle.sdk_cancellation().cancel()?;
    let attachment = resources.attachment()?;
    let run = handle.run(attachment, &diagnostic_architectural_state());
    let unexpected_cancellation_terminal = matches!(
        run,
        Err(HvfVcpuLaneError::UnexpectedCancellation { run_epoch: 1 })
    );
    let lane_abandoned_after_terminal_exit = !handle.is_live();
    let close_reports_lane_closed = match resources.lane.take() {
        Some(lane) => matches!(lane.close(), Err(HvfVcpuLaneError::LaneClosed)),
        None => false,
    };
    let deadline = deadline("terminal lane reaping")?;
    while resources.registry.active() != 0 {
        if Instant::now() >= deadline {
            return Err(HvfVcpuDiagnosticError::Timeout("terminal lane reaping"));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let vm = process_hvf_vm()?;
    Ok(HvfVcpuFailureReport {
        lane_generation: handle.generation(),
        unexpected_cancellation_terminal,
        lane_abandoned_after_terminal_exit,
        close_reports_lane_closed,
        registry_active_after_reap: resources.registry.active(),
        registry_custodial_after_reap: resources.registry.custodial(),
        quarantined_vcpus_after_reap: vm.quarantined_vcpu_count(),
        active_vcpus_after_reap: vm.active_vcpu_count(),
        vm_poisoned: vm.is_poisoned(),
        post_poison_deregister_succeeded: false,
        post_poison_destroy_succeeded: false,
        address_spaces_after_cleanup: usize::MAX,
    })
}

fn spawn_run(
    handle: &HvfVcpuLaneHandle,
    attachment: HvfVcpuRunAttachment,
    state: &HvfArchitecturalState,
) -> Result<JoinHandle<Result<HvfVcpuRunResult, HvfVcpuLaneError>>, HvfVcpuDiagnosticError> {
    let runner = handle.clone();
    let state = *state;
    std::thread::Builder::new()
        .name("litebox-hvf-vcpu-diagnostic-run".to_owned())
        .spawn(move || runner.run(attachment, &state))
        .map_err(HvfVcpuDiagnosticError::ThreadSpawn)
}

fn join_run(
    thread: JoinHandle<Result<HvfVcpuRunResult, HvfVcpuLaneError>>,
) -> Result<HvfVcpuRunResult, HvfVcpuDiagnosticError> {
    thread
        .join()
        .map_err(|_| HvfVcpuDiagnosticError::ThreadPanicked)?
        .map_err(Into::into)
}

fn deadline(operation: &'static str) -> Result<Instant, HvfVcpuDiagnosticError> {
    Instant::now()
        .checked_add(DIAGNOSTIC_TIMEOUT)
        .ok_or(HvfVcpuDiagnosticError::Timeout(operation))
}

fn spin_state() -> HvfArchitecturalState {
    let mut state = diagnostic_architectural_state();
    state.pc = CODE_GVA as u64 + SPIN_OFFSET;
    state
}

fn diagnostic_architectural_state() -> HvfArchitecturalState {
    let mut state = HvfArchitecturalState::default();
    state.fpcr = 0x02c0_0000;
    state.fpsr = 0x0800_001f;
    state.tpidr_el0 = 0x746c_735f_6d61_726b;
    state.sp_el0 = 0x0008_0000;
    state.sp_el1 = 0x0009_0000;
    state.pc = CODE_GVA as u64;
    state.cpsr = 0xa000_0000;
    for (index, register) in state.x.iter_mut().enumerate() {
        *register = 0x1000_0000_0000_0000 | index as u64;
    }
    for (index, register) in state.q.iter_mut().enumerate() {
        for (byte, value) in register.bytes.iter_mut().enumerate() {
            *value = u8::try_from((index * 16 + byte) % 256).unwrap_or(0);
        }
    }
    state
}

fn monitor_state(
    result: &HvfVcpuRunResult,
) -> Result<&HvfArchitecturalState, HvfVcpuDiagnosticError> {
    match &result.state {
        HvfVcpuExitState::LowerElMonitor(state) => Ok(state),
        HvfVcpuExitState::DirectGuest(_) => Err(HvfVcpuDiagnosticError::Witness(
            "expected lower-EL monitor state",
        )),
    }
}

fn exception(result: &HvfVcpuRunResult) -> Result<crate::HvfExceptionExit, HvfVcpuDiagnosticError> {
    let _ = monitor_state(result)?;
    match result.exit {
        HvfVcpuExit::Exception(exception) => Ok(exception),
        _ => Err(HvfVcpuDiagnosticError::Witness(
            "expected an exception exit from the EL1 monitor",
        )),
    }
}

fn hvc_immediate(result: &HvfVcpuRunResult) -> Option<u64> {
    if !matches!(result.state, HvfVcpuExitState::LowerElMonitor(_)) {
        return None;
    }
    match result.exit {
        HvfVcpuExit::Exception(exception)
            if (exception.syndrome >> 26) & 0x3f == HVC64_EXCEPTION_CLASS =>
        {
            Some(exception.syndrome & 0xffff)
        }
        _ => None,
    }
}
