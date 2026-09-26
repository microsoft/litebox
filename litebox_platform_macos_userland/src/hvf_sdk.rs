// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::cell::Cell;
use core::ffi::c_void;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{BitOr, BitOrAssign, Bound, Range};
use core::ptr::NonNull;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use crate::HvfCompletionCapability;
use litebox::utils::TruncateExt;

const HVF_PAGE_SIZE: usize = 16 * 1024;

unsafe extern "C" {
    /// `mach_vm_region` from `<mach/mach_vm.h>`, declared here so the
    /// host-range fragment walk in [`HvfVm::map_host_range`] can start at the
    /// range being mapped instead of at address zero of the task.
    fn mach_vm_region(
        target: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: libc::c_int,
        info: *mut libc::c_int,
        info_count: *mut u32,
        object_name: *mut u32,
    ) -> libc::c_int;
    fn mach_port_deallocate(task: u32, name: u32) -> libc::c_int;
}

/// `VM_REGION_BASIC_INFO_64` from `<mach/vm_region.h>`, with its `int`-unit
/// count.
const VM_REGION_BASIC_INFO_64: libc::c_int = 9;
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;

/// The task's VM regions at or above `start`, in address order. Mach answers
/// a query inside a region with that region and a query in a gap with the
/// next region above, so a walk over a host range costs one call per region
/// the range touches rather than one per region in the task (which grows
/// with every host slot and backing page the guest owns).
fn host_regions_from(start: usize) -> impl Iterator<Item = Range<usize>> {
    let mut address = start as u64;
    core::iter::from_fn(move || {
        loop {
            let mut size: u64 = 0;
            let mut info = [0 as libc::c_int; VM_REGION_BASIC_INFO_COUNT_64 as usize];
            let mut info_count = VM_REGION_BASIC_INFO_COUNT_64;
            let mut object_name: u32 = 0;
            // SAFETY: every out-parameter points at a live local of the right
            // type, and `info_count` bounds the writes into `info`.
            let kr = unsafe {
                mach_vm_region(
                    crate::darwin::mach_task_self(),
                    &raw mut address,
                    &raw mut size,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &raw mut info_count,
                    &raw mut object_name,
                )
            };
            if kr != crate::darwin::KERN_SUCCESS {
                return None;
            }
            if object_name != 0 {
                // SAFETY: the send right was just produced by the call above.
                unsafe { mach_port_deallocate(crate::darwin::mach_task_self(), object_name) };
            }
            let region_start = usize::try_from(address).ok()?;
            let len = usize::try_from(size).ok()?;
            address = address.checked_add(size)?;
            if len == 0 {
                continue;
            }
            return Some(region_start..region_start + len);
        }
    })
}

const MIN_IPA_BITS: u32 = 14;
const MAX_IPA_BITS: u32 = 40;
const MACOS_26_SDK_VERSION: u32 = 260_000;
const FEATURE_REGISTER_COUNT: usize = 14;
const MONITOR_SYSCALL_OFFSET: usize = 0x400;
const MONITOR_RESUME_OFFSET: usize = 0x404;
const MONITOR_SYNCHRONIZE_OFFSET: usize = 0x800;
const HVF_ABI_VERSION: u32 = 1;
const HVF_EXIT_CANCELED: u32 = 1;
const HVF_EXIT_EXCEPTION: u32 = 2;
const HVF_EXIT_VTIMER: u32 = 3;
const HVF_EXIT_UNKNOWN: u32 = 4;
const HVF_RAW_EXIT_CANCELED: u32 = 0;
const HVF_RAW_EXIT_EXCEPTION: u32 = 1;
const HVF_RAW_EXIT_VTIMER: u32 = 2;
const HVF_RAW_EXIT_UNKNOWN: u32 = 3;
const OPERATION_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const OPERATION_WAIT_POLL: Duration = Duration::from_millis(10);
const MAX_OPERATION_WAITERS: usize = 4096;
const MAX_SECONDARY_PANIC_DISPOSALS: usize = 16;

type HvReturn = i32;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HvfSimd128 {
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfArchitecturalState {
    abi_version: u32,
    byte_size: u32,
    pub x: [u64; 31],
    pub q: [HvfSimd128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
    pub tpidr_el0: u64,
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub pc: u64,
    pub cpsr: u64,
    pub spsr_el1: u64,
    pub elr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
}

impl Default for HvfArchitecturalState {
    fn default() -> Self {
        Self {
            abi_version: HVF_ABI_VERSION,
            byte_size: core::mem::size_of::<Self>().trunc(),
            x: [0; 31],
            q: [HvfSimd128::default(); 32],
            fpcr: 0,
            fpsr: 0,
            tpidr_el0: 0,
            sp_el0: 0,
            sp_el1: 0,
            pc: 0,
            cpsr: 0,
            spsr_el1: 0,
            elr_el1: 0,
            esr_el1: 0,
            far_el1: 0,
        }
    }
}

impl HvfArchitecturalState {
    fn has_valid_header(&self) -> bool {
        self.abi_version == HVF_ABI_VERSION
            && self.byte_size as usize == core::mem::size_of::<Self>()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HvfPstateContext {
    UserEl0t,
    MonitorEl1h,
}

impl HvfPstateContext {
    const MODE_MASK: u64 = 0x1f;
    const NZCV: u64 = 0xf000_0000;
    const DIT: u64 = 1 << 24;
    const SSBS: u64 = 1 << 12;
    const BTYPE: u64 = 0b11 << 10;
    const DAIF: u64 = 0xf << 6;

    fn validate(self, pstate: u64) -> bool {
        let (mode, flags) = match self {
            Self::UserEl0t => (0, Self::NZCV | Self::DIT | Self::SSBS | Self::BTYPE),
            Self::MonitorEl1h => (
                5,
                Self::NZCV | Self::DIT | Self::SSBS | Self::BTYPE | Self::DAIF,
            ),
        };
        pstate & Self::MODE_MASK == mode && pstate & !(Self::MODE_MASK | flags) == 0
    }

    fn from_cpsr(cpsr: u64) -> Result<Self, HvfError> {
        let unsupported = || HvfError::UnsupportedPstate {
            register: HvfArchitecturalState::CPSR,
            value: cpsr,
        };
        let context = match cpsr & Self::MODE_MASK {
            0 => Self::UserEl0t,
            5 => Self::MonitorEl1h,
            _ => return Err(unsupported()),
        };
        context
            .validate(cpsr)
            .then_some(context)
            .ok_or_else(unsupported)
    }
}

impl HvfArchitecturalState {
    const CPSR: &'static str = "CPSR";
    const SPSR_EL1: &'static str = "SPSR_EL1";

    pub(crate) fn cpsr_context(&self) -> Result<HvfPstateContext, HvfError> {
        HvfPstateContext::from_cpsr(self.cpsr)
    }

    fn validate_install(&self, context: HvfPstateContext) -> Result<(), HvfError> {
        self.require_cpsr(context)?;
        self.require_spsr_el1(HvfPstateContext::UserEl0t)
    }

    pub(crate) fn require_cpsr(&self, context: HvfPstateContext) -> Result<(), HvfError> {
        context
            .validate(self.cpsr)
            .then_some(())
            .ok_or(HvfError::UnsupportedPstate {
                register: Self::CPSR,
                value: self.cpsr,
            })
    }

    pub(crate) fn require_spsr_el1(&self, context: HvfPstateContext) -> Result<(), HvfError> {
        context
            .validate(self.spsr_el1)
            .then_some(())
            .ok_or(HvfError::UnsupportedPstate {
                register: Self::SPSR_EL1,
                value: self.spsr_el1,
            })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfEl1State {
    abi_version: u32,
    byte_size: u32,
    pub sctlr_el1: u64,
    pub cpacr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
    pub cntkctl_el1: u64,
    pub cntv_ctl_el0: u64,
    pub cntv_cval_el0: u64,
    pub tpidr_el1: u64,
    pub contextidr_el1: u64,
    pub mdscr_el1: u64,
}

impl Default for HvfEl1State {
    fn default() -> Self {
        Self {
            abi_version: HVF_ABI_VERSION,
            byte_size: core::mem::size_of::<Self>().trunc(),
            sctlr_el1: 0,
            cpacr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            mair_el1: 0,
            vbar_el1: 0,
            cntkctl_el1: 0,
            cntv_ctl_el0: 0,
            cntv_cval_el0: 0,
            tpidr_el1: 0,
            contextidr_el1: 0,
            mdscr_el1: 0,
        }
    }
}

impl HvfEl1State {
    pub fn linux_user(ttbr0_el1: u64, tcr_el1: u64, mair_el1: u64) -> Self {
        const SCTLR_EL1_RES1: u64 =
            (1 << 29) | (1 << 28) | (1 << 23) | (1 << 22) | (1 << 20) | (1 << 11);
        // M, C, SA, SA0, I, DZE (EL0 `DC ZVA`), UCT (EL0 `CTR_EL0` reads),
        // WXN, and UCI (EL0 cache maintenance: `DC CVAU`/`IC IVAU`, which
        // every JIT's `__clear_cache` issues and which must not trap).
        const SCTLR_MMU_CACHE_WXN: u64 = (1 << 0)
            | (1 << 2)
            | (1 << 3)
            | (1 << 4)
            | (1 << 12)
            | (1 << 14)
            | (1 << 15)
            | (1 << 19)
            | (1 << 26);
        const CPACR_FPEN_FULL: u64 = 0b11 << 20;
        const CNTKCTL_EL0VCTEN: u64 = 1 << 1;
        Self {
            sctlr_el1: SCTLR_EL1_RES1 | SCTLR_MMU_CACHE_WXN,
            cpacr_el1: CPACR_FPEN_FULL,
            ttbr0_el1,
            ttbr1_el1: 0,
            tcr_el1,
            mair_el1,
            vbar_el1: 0,
            cntkctl_el1: CNTKCTL_EL0VCTEN,
            ..Self::default()
        }
    }

    fn has_valid_header(&self) -> bool {
        self.abi_version == HVF_ABI_VERSION
            && self.byte_size as usize == core::mem::size_of::<Self>()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HvfExitPayload {
    abi_version: u32,
    byte_size: u32,
    kind: u32,
    raw_reason: u32,
    syndrome: u64,
    virtual_address: u64,
    physical_address: u64,
}

const _: () = {
    assert!(core::mem::size_of::<HvfSimd128>() == 16);
    assert!(core::mem::size_of::<HvfArchitecturalState>() == 856);
    assert!(core::mem::offset_of!(HvfArchitecturalState, x) == 8);
    assert!(core::mem::offset_of!(HvfArchitecturalState, q) == 256);
    assert!(core::mem::offset_of!(HvfArchitecturalState, fpcr) == 768);
    assert!(core::mem::size_of::<HvfEl1State>() == 112);
    assert!(core::mem::size_of::<HvfExitPayload>() == 40);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfExceptionExit {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfVcpuExit {
    Canceled,
    Exception(HvfExceptionExit),
    VtimerActivated,
    Unknown,
    Malformed {
        kind: u32,
        raw_reason: u32,
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    },
}

impl HvfExitPayload {
    fn decode(self) -> HvfVcpuExit {
        let header_valid = self.abi_version == HVF_ABI_VERSION
            && self.byte_size as usize == core::mem::size_of::<Self>();
        let reason_valid = matches!(
            (self.kind, self.raw_reason),
            (HVF_EXIT_CANCELED, HVF_RAW_EXIT_CANCELED)
                | (HVF_EXIT_EXCEPTION, HVF_RAW_EXIT_EXCEPTION)
                | (HVF_EXIT_VTIMER, HVF_RAW_EXIT_VTIMER)
                | (HVF_EXIT_UNKNOWN, HVF_RAW_EXIT_UNKNOWN)
        );
        let empty_exception =
            self.syndrome == 0 && self.virtual_address == 0 && self.physical_address == 0;
        let exception_valid = self.syndrome != 0 && self.syndrome >> 32 == 0;
        if !header_valid || !reason_valid {
            return self.malformed();
        }
        match self.kind {
            HVF_EXIT_CANCELED if empty_exception => HvfVcpuExit::Canceled,
            HVF_EXIT_EXCEPTION if exception_valid => HvfVcpuExit::Exception(HvfExceptionExit {
                syndrome: self.syndrome,
                virtual_address: self.virtual_address,
                physical_address: self.physical_address,
            }),
            HVF_EXIT_VTIMER if empty_exception => HvfVcpuExit::VtimerActivated,
            HVF_EXIT_UNKNOWN if empty_exception => HvfVcpuExit::Unknown,
            _ => self.malformed(),
        }
    }

    fn malformed(self) -> HvfVcpuExit {
        HvfVcpuExit::Malformed {
            kind: self.kind,
            raw_reason: self.raw_reason,
            syndrome: self.syndrome,
            virtual_address: self.virtual_address,
            physical_address: self.physical_address,
        }
    }
}

unsafe extern "C" {
    fn litebox_hvf_sdk_max_allowed() -> u32;
    fn litebox_hvf_runtime_is_macos_26_or_newer() -> u8;
    fn litebox_hvf_return_is_success(result: HvReturn) -> u8;
    fn litebox_hvf_return_is_denied(result: HvReturn) -> u8;
    fn litebox_hvf_monitor_layout(
        start: *mut *const u8,
        length: *mut usize,
        syscall_offset: *mut usize,
        resume_offset: *mut usize,
        synchronize_offset: *mut usize,
    );
    fn litebox_hvf_vm_config_create() -> *mut c_void;
    fn litebox_hvf_vcpu_config_create() -> *mut c_void;
    fn litebox_hvf_vm_config_release(object: *mut c_void);
    fn litebox_hvf_vcpu_config_release(object: *mut c_void);
    fn litebox_hvf_vm_config_get_max_ipa_size(bits: *mut u32) -> HvReturn;
    fn litebox_hvf_vm_config_set_ipa_size(config: *mut c_void, bits: u32) -> HvReturn;
    fn litebox_hvf_vm_config_get_ipa_size(config: *mut c_void, bits: *mut u32) -> HvReturn;
    fn litebox_hvf_vm_config_set_ipa_granule_16k(config: *mut c_void) -> HvReturn;
    fn litebox_hvf_vm_config_get_ipa_granule(
        config: *mut c_void,
        raw: *mut u32,
        is_16k: *mut u8,
    ) -> HvReturn;
    fn litebox_hvf_vm_config_get_el2_supported(supported: *mut u8) -> HvReturn;
    fn litebox_hvf_vm_config_set_el2_disabled(config: *mut c_void) -> HvReturn;
    fn litebox_hvf_vm_config_get_el2_enabled(config: *mut c_void, enabled: *mut u8) -> HvReturn;
    fn litebox_hvf_vm_get_max_vcpu_count(count: *mut u32) -> HvReturn;
    fn litebox_hvf_vm_create(config: *mut c_void) -> HvReturn;
    fn litebox_hvf_vm_map(address: *mut c_void, ipa: u64, size: usize, permissions: u8)
    -> HvReturn;
    fn litebox_hvf_vm_protect(ipa: u64, size: usize, permissions: u8) -> HvReturn;
    fn litebox_hvf_vm_unmap(ipa: u64, size: usize) -> HvReturn;
    fn litebox_hvf_feature_reg_count() -> usize;
    fn litebox_hvf_vcpu_config_get_feature_regs(
        config: *mut c_void,
        values: *mut u64,
        count: usize,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_create(
        identifier: *mut u64,
        exit_area: *mut *mut c_void,
        config: *mut c_void,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_destroy(identifier: u64) -> HvReturn;
    fn litebox_hvf_inject_vcpu_destroy_failures(count: u32) -> u32;
    fn litebox_hvf_remaining_vcpu_destroy_failures() -> u32;
    fn litebox_hvf_vcpu_program_stage_one(
        identifier: u64,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
        ttbr0_readback: *mut u64,
        tcr_readback: *mut u64,
        mair_readback: *mut u64,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_verify_feature_regs(
        identifier: u64,
        config: *mut c_void,
        expected: *const u64,
        count: usize,
        mismatch_index: *mut usize,
        actual_value: *mut u64,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_get_arch_state(
        identifier: u64,
        state: *mut HvfArchitecturalState,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_set_arch_state(
        identifier: u64,
        state: *const HvfArchitecturalState,
        readback: *mut HvfArchitecturalState,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_initialize_el1(
        identifier: u64,
        configuration: *const HvfEl1State,
        readback: *mut HvfEl1State,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_get_el1_state(identifier: u64, state: *mut HvfEl1State) -> HvReturn;
    fn litebox_hvf_vcpu_get_debug_traps(
        identifier: u64,
        exceptions: *mut u8,
        register_accesses: *mut u8,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_run(
        identifier: u64,
        exit_area: *const c_void,
        exit: *mut HvfExitPayload,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_exit(identifier: u64) -> HvReturn;
    fn litebox_hvf_vcpu_set_pending_interrupt(identifier: u64, fiq: u8, pending: u8) -> HvReturn;
    fn litebox_hvf_vcpu_get_pending_interrupt(
        identifier: u64,
        fiq: u8,
        pending: *mut u8,
    ) -> HvReturn;
    fn litebox_hvf_vcpu_set_vtimer_mask(identifier: u64, masked: u8) -> HvReturn;
    fn litebox_hvf_vcpu_arm_vtimer(identifier: u64, cval: u64) -> HvReturn;
    fn litebox_hvf_vcpu_get_vtimer_mask(identifier: u64, masked: *mut u8) -> HvReturn;
    fn litebox_hvf_vcpu_set_vtimer_offset(identifier: u64, offset: u64) -> HvReturn;
    fn litebox_hvf_vcpu_get_vtimer_offset(identifier: u64, offset: *mut u64) -> HvReturn;
    fn litebox_hvf_vcpu_get_exec_time(identifier: u64, time: *mut u64) -> HvReturn;
}

#[derive(Clone, Debug)]
pub enum HvfError {
    SdkTooOld(u32),
    HostTooOld,
    HostPageSize(i64),
    NullVmConfiguration,
    NullVcpuConfiguration,
    NullVcpuExitArea,
    VcpuNotLive,
    HypervisorEntitlementMissing,
    Call {
        operation: &'static str,
        code: HvReturn,
    },
    IpaSizeOutOfRange(u32),
    IpaSizeReadback {
        requested: u32,
        configured: u32,
    },
    IpaGranuleReadback(u32),
    El2StillEnabled,
    NoVcpus,
    InvalidMonitor {
        length: usize,
        alignment: usize,
        syscall_offset: usize,
        resume_offset: usize,
        synchronize_offset: usize,
    },
    InvalidArchitectureState,
    ArchitectureStateReadback,
    InvalidEl1State,
    El1RegisterReadback {
        register: &'static str,
        expected: u64,
        actual: u64,
    },
    DebugTrapReadback,
    UnsupportedPstate {
        register: &'static str,
        value: u64,
    },
    RejectedVcpuExit,
    FeatureRegisterCount(usize),
    FeatureConfigurationChanged {
        register: HvfFeatureRegister,
        admitted: u64,
        configured: u64,
    },
    FeatureRegisterMismatch {
        register: HvfFeatureRegister,
        expected: u64,
        actual: u64,
    },
    StageOneRegisterReadback {
        register: &'static str,
        expected: u64,
        actual: u64,
    },
    PublishedOperationFailure {
        trigger: Box<HvfError>,
    },
    Poisoned,
    EmptyMapping,
    MappingNotLive,
    MappingUnaligned {
        host_address: usize,
        ipa: u64,
        length: usize,
    },
    MappingOutOfRange {
        ipa: u64,
        length: usize,
        ipa_bits: u32,
    },
    HostRangeGap(usize),
    MappingRollback {
        token: u64,
        trigger: &'static str,
        trigger_code: Option<HvReturn>,
        rollback_code: HvReturn,
    },
    MappingFinalization {
        token: u64,
        trigger: Box<HvfError>,
        cleanup: Box<HvfError>,
    },
    MappingCleanup {
        token: u64,
        trigger: Box<HvfError>,
    },
    VcpuCleanup {
        trigger: Box<HvfError>,
        cleanup_code: HvReturn,
        accounting: Option<Box<HvfError>>,
    },
    VcpuQuarantine {
        trigger: Box<HvfError>,
        failure: Box<HvfError>,
    },
    VcpuOwnershipCollision(u64),
    VcpuWrongOwner {
        identifier: u64,
    },
    VcpuCancellationStale {
        identifier: u64,
        generation: u64,
    },
    ResourceReservation(&'static str),
    MappingTokenExhausted,
    MappingTokenMissing(u64),
    WriteExecuteMapping,
    ResidualAccounting,
    SmokeResidualOwnership,
    ZeroVcpuAdmission,
    OperationAbandoned,
    OperationWaitTimeout,
    PublishedPanicWitness(Box<HvfPublishedPanicReport>),
    ResidualOwnership(HvfSdkResidualReport),
}

impl HvfError {
    fn after_publication(trigger: Self) -> Self {
        match trigger {
            Self::PublishedOperationFailure { .. } => trigger,
            trigger => Self::PublishedOperationFailure {
                trigger: Box::new(trigger),
            },
        }
    }

    pub(crate) fn published_before_failure(&self) -> bool {
        match self {
            Self::PublishedOperationFailure { .. } => true,
            Self::MappingCleanup { trigger, .. } | Self::VcpuCleanup { trigger, .. } => {
                trigger.published_before_failure()
            }
            Self::MappingFinalization {
                trigger, cleanup, ..
            } => trigger.published_before_failure() || cleanup.published_before_failure(),
            Self::VcpuQuarantine { trigger, failure } => {
                trigger.published_before_failure() || failure.published_before_failure()
            }
            _ => false,
        }
    }

    pub(crate) fn residual_mapping_token(&self) -> Option<u64> {
        match self {
            Self::PublishedOperationFailure { trigger } => trigger.residual_mapping_token(),
            Self::MappingRollback { token, .. }
            | Self::MappingFinalization { token, .. }
            | Self::MappingCleanup { token, .. } => Some(*token),
            _ => None,
        }
    }

    fn mapping_cleanup(token: u64, trigger: Self) -> Self {
        match trigger {
            Self::MappingCleanup {
                token: existing, ..
            } if existing == token => trigger,
            trigger => Self::MappingCleanup {
                token,
                trigger: Box::new(trigger),
            },
        }
    }

    fn vcpu_cleanup(trigger: Self, cleanup_code: HvReturn, accounting: Option<Self>) -> Self {
        Self::VcpuCleanup {
            trigger: Box::new(trigger),
            cleanup_code,
            accounting: accounting.map(Box::new),
        }
    }

    fn vcpu_quarantine(trigger: Self, failure: Self) -> Self {
        Self::VcpuQuarantine {
            trigger: Box::new(trigger),
            failure: Box::new(failure),
        }
    }

    pub(crate) fn stage_one_mismatch(&self) -> bool {
        match self {
            Self::PublishedOperationFailure { trigger }
            | Self::MappingCleanup { trigger, .. }
            | Self::VcpuCleanup { trigger, .. }
            | Self::VcpuQuarantine { trigger, .. }
            | Self::MappingFinalization { trigger, .. } => trigger.stage_one_mismatch(),
            Self::StageOneRegisterReadback { .. } => true,
            _ => false,
        }
    }
}

pub(crate) trait HvfOperationError: From<HvfError> {
    fn after_hvf_publication(self) -> Self;
}

impl HvfOperationError for HvfError {
    fn after_hvf_publication(self) -> Self {
        Self::after_publication(self)
    }
}

impl HvfOperationError for crate::hvf_memory::HvfMemoryError {
    fn after_hvf_publication(self) -> Self {
        Self::after_publication("SDK operation completion", self)
    }
}

impl fmt::Display for HvfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SdkTooOld(version) => write!(
                f,
                "the active SDK is {version}, but the HVF backend requires the macOS 26 SDK or newer"
            ),
            Self::HostTooOld => write!(f, "the HVF backend requires macOS 26 or newer"),
            Self::HostPageSize(size) => write!(
                f,
                "the host page size is {size}, but the HVF backend requires 16384 bytes"
            ),
            Self::NullVmConfiguration => write!(f, "hv_vm_config_create returned null"),
            Self::NullVcpuConfiguration => write!(f, "hv_vcpu_config_create returned null"),
            Self::NullVcpuExitArea => write!(f, "hv_vcpu_create returned a null exit area"),
            Self::VcpuNotLive => write!(f, "the HVF vCPU has been destroyed or quarantined"),
            Self::HypervisorEntitlementMissing => write!(
                f,
                "Hypervisor.framework denied VM creation; sign the final executable with com.apple.security.hypervisor=true (com.apple.vm.hypervisor is only for deployment targets through macOS 10.15)"
            ),
            Self::Call { operation, code } => {
                write!(
                    f,
                    "{operation} failed with Hypervisor.framework code {:#x}",
                    code.cast_unsigned()
                )
            }
            Self::IpaSizeOutOfRange(bits) => write!(
                f,
                "Hypervisor.framework reported {bits} maximum IPA bits, outside the supported 14..=40 range"
            ),
            Self::IpaSizeReadback {
                requested,
                configured,
            } => write!(
                f,
                "Hypervisor.framework configured {configured} IPA bits after {requested} were requested"
            ),
            Self::IpaGranuleReadback(raw) => write!(
                f,
                "Hypervisor.framework did not retain the requested 16 KiB IPA granule (active-SDK value {raw})"
            ),
            Self::El2StillEnabled => write!(
                f,
                "Hypervisor.framework reports EL2 enabled after the backend explicitly disabled it"
            ),
            Self::NoVcpus => write!(f, "Hypervisor.framework reports no available vCPUs"),
            Self::InvalidMonitor {
                length,
                alignment,
                syscall_offset,
                resume_offset,
                synchronize_offset,
            } => write!(
                f,
                "linked EL1 monitor has length {length}, alignment {alignment}, syscall offset {syscall_offset:#x}, resume offset {resume_offset:#x}, and synchronization offset {synchronize_offset:#x}"
            ),
            Self::InvalidArchitectureState => {
                write!(f, "the HVF architectural-state ABI header is invalid")
            }
            Self::ArchitectureStateReadback => {
                write!(f, "the HVF architectural state did not read back exactly")
            }
            Self::InvalidEl1State => write!(f, "the HVF EL1-state ABI header is invalid"),
            Self::El1RegisterReadback {
                register,
                expected,
                actual,
            } => write!(
                f,
                "{register} read back as {actual:#x} after EL1 initialization programmed {expected:#x}"
            ),
            Self::DebugTrapReadback => write!(
                f,
                "HVF did not retain fail-closed debug exception and register-access traps"
            ),
            Self::UnsupportedPstate { register, value } => write!(
                f,
                "guest {register} {value:#x} requests unsupported execution, mask, or single-step state"
            ),
            Self::RejectedVcpuExit => {
                write!(f, "the HVF vCPU returned a malformed or unknown exit")
            }
            Self::FeatureRegisterCount(count) => write!(
                f,
                "active-SDK feature register table has {count} entries instead of {FEATURE_REGISTER_COUNT}"
            ),
            Self::FeatureConfigurationChanged {
                register,
                admitted,
                configured,
            } => write!(
                f,
                "{} changed from admitted value {admitted:#x} to vCPU configuration value {configured:#x}",
                register.name()
            ),
            Self::FeatureRegisterMismatch {
                register,
                expected,
                actual,
            } => write!(
                f,
                "{} reads {actual:#x} from the vCPU after its configuration admitted {expected:#x}",
                register.name()
            ),
            Self::StageOneRegisterReadback {
                register,
                expected,
                actual,
            } => write!(
                f,
                "{register} read back as {actual:#x} after the HVF backend programmed {expected:#x}"
            ),
            Self::Poisoned => write!(f, "the process-global Hypervisor.framework VM is poisoned"),
            Self::PublishedOperationFailure { trigger } => write!(
                f,
                "an HVF operation published state before admission completion failed: {trigger}"
            ),
            Self::EmptyMapping => write!(f, "an HVF mapping cannot be empty"),
            Self::MappingNotLive => {
                write!(
                    f,
                    "the HVF mapping is quarantined or has already been unmapped"
                )
            }
            Self::MappingUnaligned {
                host_address,
                ipa,
                length,
            } => write!(
                f,
                "HVF mapping host={host_address:#x} ipa={ipa:#x} length={length:#x} is not 16 KiB aligned"
            ),
            Self::MappingOutOfRange {
                ipa,
                length,
                ipa_bits,
            } => write!(
                f,
                "HVF mapping ipa={ipa:#x} length={length:#x} exceeds the configured {ipa_bits}-bit IPA space"
            ),
            Self::HostRangeGap(address) => write!(
                f,
                "host virtual range for an HVF mapping has no Mach VM region at {address:#x}"
            ),
            Self::MappingRollback {
                token,
                trigger,
                trigger_code,
                rollback_code,
            } => write!(
                f,
                "HVF mapping token {token} rollback after {trigger} (trigger code {trigger_code:?}) failed with {:#x}; the VM is poisoned",
                rollback_code.cast_unsigned()
            ),
            Self::MappingFinalization {
                token,
                trigger,
                cleanup,
            } => write!(
                f,
                "HVF mapping token {token} failed with {trigger}; its rollback then failed with {cleanup}; the VM is poisoned"
            ),
            Self::MappingCleanup { token, trigger } => write!(
                f,
                "HVF mapping token {token} cleanup failed with {trigger}; exact retry custody is retained"
            ),
            Self::VcpuCleanup {
                trigger,
                cleanup_code,
                accounting,
            } => {
                write!(
                    f,
                    "{trigger}; destroying the rejected vCPU then failed with {:#x}",
                    cleanup_code.cast_unsigned()
                )?;
                if let Some(accounting) = accounting {
                    write!(
                        f,
                        "; retaining its cleanup record then failed: {accounting}"
                    )?;
                }
                write!(f, "; the VM is poisoned")
            }
            Self::VcpuQuarantine { trigger, failure } => write!(
                f,
                "{trigger}; quarantining the undestroyed vCPU then failed: {failure}"
            ),
            Self::VcpuOwnershipCollision(identifier) => write!(
                f,
                "HVF vCPU identifier {identifier:#x} already has live or quarantined ownership"
            ),
            Self::VcpuWrongOwner { identifier } => write!(
                f,
                "HVF vCPU {identifier:#x} cleanup was attempted from a thread other than its creator"
            ),
            Self::VcpuCancellationStale {
                identifier,
                generation,
            } => write!(
                f,
                "HVF vCPU cancellation capability {identifier:#x}/{generation} is stale"
            ),
            Self::ResourceReservation(resource) => {
                write!(
                    f,
                    "failed to reserve {resource} ownership before HVF mutation"
                )
            }
            Self::MappingTokenExhausted => write!(f, "HVF mapping token space is exhausted"),
            Self::MappingTokenMissing(token) => {
                write!(
                    f,
                    "HVF mapping token {token} has no authoritative registry record"
                )
            }
            Self::WriteExecuteMapping => {
                write!(
                    f,
                    "an HVF stage-two mapping cannot be writable and executable"
                )
            }
            Self::ResidualAccounting => write!(
                f,
                "the HVF SDK residual ledger is internally inconsistent or overflowed"
            ),
            Self::SmokeResidualOwnership => write!(
                f,
                "the bounded HVF smoke retains process-owned resources; production VM admission is blocked"
            ),
            Self::ZeroVcpuAdmission => {
                write!(f, "the operation requires exclusive zero-vCPU admission")
            }
            Self::OperationAbandoned => write!(
                f,
                "an HVF operation capability was abandoned without explicit finish"
            ),
            Self::OperationWaitTimeout => {
                write!(f, "timed out waiting for HVF operation ownership")
            }
            Self::PublishedPanicWitness(report) => {
                write!(f, "published-panic admission witness failed: {report:?}")
            }
            Self::ResidualOwnership(report) => {
                write!(
                    f,
                    "the HVF SDK retained exact residual ownership: {report:?}"
                )
            }
        }
    }
}

impl std::error::Error for HvfError {}

fn succeeded(code: HvReturn) -> bool {
    unsafe { litebox_hvf_return_is_success(code) != 0 }
}

fn denied(code: HvReturn) -> bool {
    unsafe { litebox_hvf_return_is_denied(code) != 0 }
}

fn check(operation: &'static str, code: HvReturn) -> Result<(), HvfError> {
    if succeeded(code) {
        Ok(())
    } else {
        Err(HvfError::Call { operation, code })
    }
}

fn checked_residual_add(value: &mut usize, amount: usize) -> Result<(), HvfError> {
    *value = value
        .checked_add(amount)
        .ok_or(HvfError::ResidualAccounting)?;
    Ok(())
}

fn contain_panic_observer(
    observer: impl FnOnce(),
    invoke: bool,
) -> Option<Box<dyn std::any::Any + Send>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if invoke {
            observer();
        } else {
            drop(observer);
        }
    }))
    .err()
}

fn dispose_secondary_panic(payload: Option<Box<dyn std::any::Any + Send>>) -> bool {
    let Some(payload) = payload else {
        return false;
    };
    // A diagnostic observer must never replace the body failure that was
    // already caught. Dispose each resulting panic payload while no VM lock is
    // held, but bound pathological destructors that recursively produce another
    // panicking payload so the selected primary failure always makes progress.
    let mut payload = Some(payload);
    for _ in 0..MAX_SECONDARY_PANIC_DISPOSALS {
        let Some(current) = payload.take() else {
            return true;
        };
        payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(current))).err();
    }
    if let Some(payload) = payload {
        std::mem::forget(payload);
    }
    true
}

fn dispose_rejected_value<T>(value: T) {
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value))).err();
    dispose_secondary_panic(panic);
}

fn with_hvf_configuration<T>(
    create: unsafe extern "C" fn() -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    null_error: HvfError,
    body: impl FnOnce(NonNull<c_void>) -> Result<T, HvfError>,
) -> Result<T, HvfError> {
    let object = NonNull::new(unsafe { create() }).ok_or(null_error)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(object)));
    // SAFETY: creation returned one retained object and no ownership left this
    // function. Release is explicit while control remains in this frame.
    unsafe { release(object.as_ptr()) };
    match result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn with_vm_configuration<T>(
    body: impl FnOnce(NonNull<c_void>) -> Result<T, HvfError>,
) -> Result<T, HvfError> {
    with_hvf_configuration(
        litebox_hvf_vm_config_create,
        litebox_hvf_vm_config_release,
        HvfError::NullVmConfiguration,
        body,
    )
}

fn with_vcpu_configuration<T>(
    body: impl FnOnce(NonNull<c_void>) -> Result<T, HvfError>,
) -> Result<T, HvfError> {
    with_hvf_configuration(
        litebox_hvf_vcpu_config_create,
        litebox_hvf_vcpu_config_release,
        HvfError::NullVcpuConfiguration,
        body,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum HvfFeatureRegister {
    IdAa64Dfr0El1,
    IdAa64Dfr1El1,
    IdAa64Isar0El1,
    IdAa64Isar1El1,
    IdAa64Mmfr0El1,
    IdAa64Mmfr1El1,
    IdAa64Mmfr2El1,
    IdAa64Pfr0El1,
    IdAa64Pfr1El1,
    CtrEl0,
    ClidrEl1,
    DczidEl0,
    IdAa64Smfr0El1,
    IdAa64Zfr0El1,
}

impl HvfFeatureRegister {
    pub const ALL: [Self; FEATURE_REGISTER_COUNT] = [
        Self::IdAa64Dfr0El1,
        Self::IdAa64Dfr1El1,
        Self::IdAa64Isar0El1,
        Self::IdAa64Isar1El1,
        Self::IdAa64Mmfr0El1,
        Self::IdAa64Mmfr1El1,
        Self::IdAa64Mmfr2El1,
        Self::IdAa64Pfr0El1,
        Self::IdAa64Pfr1El1,
        Self::CtrEl0,
        Self::ClidrEl1,
        Self::DczidEl0,
        Self::IdAa64Smfr0El1,
        Self::IdAa64Zfr0El1,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::IdAa64Dfr0El1 => "ID_AA64DFR0_EL1",
            Self::IdAa64Dfr1El1 => "ID_AA64DFR1_EL1",
            Self::IdAa64Isar0El1 => "ID_AA64ISAR0_EL1",
            Self::IdAa64Isar1El1 => "ID_AA64ISAR1_EL1",
            Self::IdAa64Mmfr0El1 => "ID_AA64MMFR0_EL1",
            Self::IdAa64Mmfr1El1 => "ID_AA64MMFR1_EL1",
            Self::IdAa64Mmfr2El1 => "ID_AA64MMFR2_EL1",
            Self::IdAa64Pfr0El1 => "ID_AA64PFR0_EL1",
            Self::IdAa64Pfr1El1 => "ID_AA64PFR1_EL1",
            Self::IdAa64Zfr0El1 => "ID_AA64ZFR0_EL1",
            Self::IdAa64Smfr0El1 => "ID_AA64SMFR0_EL1",
            Self::CtrEl0 => "CTR_EL0",
            Self::ClidrEl1 => "CLIDR_EL1",
            Self::DczidEl0 => "DCZID_EL0",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct HvfFeatureRegisters {
    values: [u64; FEATURE_REGISTER_COUNT],
}

impl fmt::Debug for HvfFeatureRegisters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut registers = f.debug_struct("HvfFeatureRegisters");
        for (register, value) in self.iter() {
            registers.field(register.name(), &format_args!("{value:#018x}"));
        }
        registers.finish()
    }
}

impl HvfFeatureRegisters {
    pub fn get(&self, register: HvfFeatureRegister) -> u64 {
        self.values[register as usize]
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (HvfFeatureRegister, u64)> + '_ {
        HvfFeatureRegister::ALL
            .into_iter()
            .map(|register| (register, self.get(register)))
    }

    fn from_vcpu_configuration(config: NonNull<c_void>) -> Result<Self, HvfError> {
        let count = unsafe { litebox_hvf_feature_reg_count() };
        if count != FEATURE_REGISTER_COUNT {
            return Err(HvfError::FeatureRegisterCount(count));
        }
        let mut values = [0; FEATURE_REGISTER_COUNT];
        check("hv_vcpu_config_get_feature_reg", unsafe {
            litebox_hvf_vcpu_config_get_feature_regs(
                config.as_ptr(),
                values.as_mut_ptr(),
                values.len(),
            )
        })?;
        Ok(Self { values })
    }

    fn changed_from(&self, admitted: &Self) -> Option<HvfError> {
        HvfFeatureRegister::ALL.into_iter().find_map(|register| {
            let configured = self.get(register);
            let admitted_value = admitted.get(register);
            (configured != admitted_value).then_some(HvfError::FeatureConfigurationChanged {
                register,
                admitted: admitted_value,
                configured,
            })
        })
    }

    fn verify_after_vcpu_create(
        &self,
        identifier: u64,
        config: NonNull<c_void>,
    ) -> Result<(), HvfError> {
        let mut mismatch_index = usize::MAX;
        let mut actual_value = 0;
        check("HVF vCPU feature readback", unsafe {
            litebox_hvf_vcpu_verify_feature_regs(
                identifier,
                config.as_ptr(),
                self.values.as_ptr(),
                self.values.len(),
                &raw mut mismatch_index,
                &raw mut actual_value,
            )
        })?;
        if mismatch_index == usize::MAX {
            return Ok(());
        }
        let Some(&register) = HvfFeatureRegister::ALL.get(mismatch_index) else {
            return Err(HvfError::FeatureRegisterCount(mismatch_index));
        };
        Err(HvfError::FeatureRegisterMismatch {
            register,
            expected: self.get(register),
            actual: actual_value,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfMapPermissions(u8);

impl HvfMapPermissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for HvfMapPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for HvfMapPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[repr(align(16384))]
struct HvfMonitorPage([u8; HVF_PAGE_SIZE]);

const _: () = {
    assert!(core::mem::size_of::<HvfMonitorPage>() == HVF_PAGE_SIZE);
    assert!(core::mem::align_of::<HvfMonitorPage>() == HVF_PAGE_SIZE);
};

pub struct HvfMonitor {
    page: Box<HvfMonitorPage>,
    syscall_offset: usize,
    resume_offset: usize,
    synchronize_offset: usize,
}

impl fmt::Debug for HvfMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfMonitor")
            .field("bytes", &self.page.0.len())
            .field("syscall_offset", &self.syscall_offset)
            .field("resume_offset", &self.resume_offset)
            .field("synchronize_offset", &self.synchronize_offset)
            .finish()
    }
}

impl HvfMonitor {
    fn linked() -> Result<Self, HvfError> {
        let mut start = core::ptr::null();
        let mut length = 0;
        let mut syscall_offset = 0;
        let mut resume_offset = 0;
        let mut synchronize_offset = 0;
        unsafe {
            litebox_hvf_monitor_layout(
                &raw mut start,
                &raw mut length,
                &raw mut syscall_offset,
                &raw mut resume_offset,
                &raw mut synchronize_offset,
            );
        }
        let alignment = (start as usize) % HVF_PAGE_SIZE;
        if start.is_null()
            || length != HVF_PAGE_SIZE
            || alignment != 0
            || syscall_offset != MONITOR_SYSCALL_OFFSET
            || resume_offset != MONITOR_RESUME_OFFSET
            || synchronize_offset != MONITOR_SYNCHRONIZE_OFFSET
        {
            return Err(HvfError::InvalidMonitor {
                length,
                alignment,
                syscall_offset,
                resume_offset,
                synchronize_offset,
            });
        }
        let linked_bytes = unsafe { core::slice::from_raw_parts(start, length) };
        // HVF rejects file-backed Mach-O __TEXT pages as stage-two backing.
        // Keep linkage as the source of truth, then publish an aligned,
        // allocator-backed copy that it can map.
        let mut page = Box::new(HvfMonitorPage([0; HVF_PAGE_SIZE]));
        page.0.copy_from_slice(linked_bytes);
        Ok(Self {
            page,
            syscall_offset,
            resume_offset,
            synchronize_offset,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.page.0
    }

    pub const fn syscall_offset(&self) -> usize {
        self.syscall_offset
    }

    pub const fn resume_offset(&self) -> usize {
        self.resume_offset
    }

    pub const fn synchronize_offset(&self) -> usize {
        self.synchronize_offset
    }
}

#[derive(Clone, Debug)]
pub struct HvfVmReport {
    pub sdk_max_allowed: u32,
    pub max_ipa_bits: u32,
    pub configured_ipa_bits: u32,
    pub ipa_granule_bytes: usize,
    pub el2_supported: bool,
    pub el2_enabled: bool,
    pub max_vcpu_count: u32,
    pub monitor_bytes: usize,
    pub monitor_syscall_offset: usize,
    pub monitor_resume_offset: usize,
    pub monitor_synchronize_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfStageOneRegisterReport {
    pub ttbr0_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HvfSdkResidualReport {
    pub logical_mapping_tokens: usize,
    pub logical_mapping_fragments: usize,
    pub logical_mapping_pages: usize,
    pub logical_mapping_bytes: usize,
    pub known_present_fragments: usize,
    pub known_present_pages: usize,
    pub known_present_bytes: usize,
    pub unknown_fragments: usize,
    pub unknown_pages: usize,
    pub unknown_bytes: usize,
    pub permissions_unknown_mapping_tokens: usize,
    pub logical_vcpu_tokens: usize,
    pub active_vcpus: usize,
    pub quarantined_vcpus: usize,
    pub zero_vcpu_operation_active: bool,
    pub zero_vcpu_owned_by_current_thread: bool,
}

impl HvfSdkResidualReport {
    pub const fn has_mapping_residuals(&self) -> bool {
        self.logical_mapping_tokens != 0
            || self.logical_mapping_fragments != 0
            || self.logical_mapping_pages != 0
            || self.logical_mapping_bytes != 0
            || self.known_present_fragments != 0
            || self.known_present_pages != 0
            || self.known_present_bytes != 0
            || self.unknown_fragments != 0
            || self.unknown_pages != 0
            || self.unknown_bytes != 0
            || self.permissions_unknown_mapping_tokens != 0
    }

    pub const fn is_empty(&self) -> bool {
        !self.has_mapping_residuals()
            && self.logical_vcpu_tokens == 0
            && self.active_vcpus == 0
            && self.quarantined_vcpus == 0
            && !self.zero_vcpu_operation_active
            && !self.zero_vcpu_owned_by_current_thread
    }
}

#[derive(Clone, Debug)]
pub struct HvfBoundaryReport {
    pub vm: HvfVmReport,
    pub monitor_mapping_fragments: usize,
    pub feature_registers: HvfFeatureRegisters,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfPublishedPanicOperation {
    Exclusive,
    Shared,
    ExistingVcpu,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfPublishedPanicReport {
    pub operation: HvfPublishedPanicOperation,
    pub original_payload_preserved: bool,
    pub poison_latched_before_release: bool,
    pub contender_attempted: bool,
    pub normal_admission_rejected: bool,
    pub cleanup_admitted_after_poison: bool,
    pub vcpu_destroyed_without_residual: bool,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

struct HvfOperationWaiter {
    ticket: u64,
    owner: std::thread::ThreadId,
}

struct HvfVmOperationState {
    owner: Option<std::thread::ThreadId>,
    depth: usize,
    cleanup_depth: usize,
    active_vcpu_owners: Vec<std::thread::ThreadId>,
    poison_requested: bool,
    poisoned: bool,
    zero_vcpu_owner: Option<std::thread::ThreadId>,
    zero_vcpu_depth: usize,
    /// Live shared (counting) operations: vCPU attach/submit/acknowledge
    /// paths that only touch state guarded by their own finer-grained locks
    /// and therefore need the gate solely for poison quiescence, never for
    /// mutual exclusion against each other or against the exclusive owner.
    shared: usize,
    next_waiter_ticket: u64,
    waiters: Vec<HvfOperationWaiter>,
}

#[derive(Clone, Copy)]
struct HvfOperationThreadState {
    vm: usize,
    total_depth: usize,
    shared_depth: usize,
    current_descendant_published: bool,
    admission_published: bool,
}

impl HvfOperationThreadState {
    const EMPTY: Self = Self {
        vm: 0,
        total_depth: 0,
        shared_depth: 0,
        current_descendant_published: false,
        admission_published: false,
    };
}

thread_local! {
    static HVF_OPERATION_STATE: Cell<HvfOperationThreadState> = const {
        Cell::new(HvfOperationThreadState::EMPTY)
    };
}

#[derive(Clone, Copy)]
struct HvfOperationPublicationFold {
    frame_published: bool,
    admission_published: bool,
    next_thread: HvfOperationThreadState,
}

struct HvfOperationFrame<'vm> {
    vm: &'vm HvfVm,
    frame_depth: usize,
    saved_parent_descendant_published: bool,
    direct_published: Cell<bool>,
    direct_capability_returned: Cell<bool>,
    finished: bool,
    not_send: PhantomData<Rc<()>>,
}

impl<'vm> HvfOperationFrame<'vm> {
    fn enter(
        vm: &'vm HvfVm,
        state: &mut HvfVmOperationState,
        shared: bool,
    ) -> Result<Self, HvfError> {
        let key = std::ptr::from_ref::<HvfVm>(vm) as usize;
        let entered = HVF_OPERATION_STATE.with(|cell| {
            let mut thread = cell.get();
            let empty_is_canonical = thread.total_depth != 0
                || (thread.vm == 0
                    && thread.shared_depth == 0
                    && !thread.current_descendant_published
                    && !thread.admission_published);
            let live_is_valid = thread.total_depth == 0
                || (thread.vm == key && thread.shared_depth <= thread.total_depth);
            if !empty_is_canonical || !live_is_valid {
                return None;
            }

            let frame_depth = thread.total_depth.checked_add(1)?;
            let shared_depth = if shared {
                thread.shared_depth.checked_add(1)?
            } else {
                thread.shared_depth
            };
            if shared_depth > frame_depth {
                return None;
            }

            let saved_parent_descendant_published =
                thread.total_depth != 0 && thread.current_descendant_published;
            thread.vm = key;
            thread.total_depth = frame_depth;
            thread.shared_depth = shared_depth;
            thread.current_descendant_published = false;
            if frame_depth == 1 {
                thread.admission_published = false;
            }
            cell.set(thread);
            Some((frame_depth, saved_parent_descendant_published))
        });

        let Some((frame_depth, saved_parent_descendant_published)) = entered else {
            vm.abandon_operation_locked(state);
            return Err(HvfError::OperationAbandoned);
        };
        Ok(Self {
            vm,
            frame_depth,
            saved_parent_descendant_published,
            direct_published: Cell::new(false),
            direct_capability_returned: Cell::new(false),
            finished: false,
            not_send: PhantomData,
        })
    }

    fn top_thread_state(&self, shared: bool) -> Option<HvfOperationThreadState> {
        let key = std::ptr::from_ref::<HvfVm>(self.vm) as usize;
        HVF_OPERATION_STATE.with(|cell| {
            let thread = cell.get();
            (thread.vm == key
                && thread.total_depth != 0
                && thread.total_depth == self.frame_depth
                && thread.shared_depth <= thread.total_depth
                && (!shared || thread.shared_depth != 0))
                .then_some(thread)
        })
    }

    fn mark_published(
        &self,
        shared: bool,
        cleanup: bool,
        class_live: impl FnOnce(&HvfVmOperationState) -> bool,
    ) -> Result<(), HvfError> {
        let mut state = self
            .vm
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(mut thread) = self.top_thread_state(shared) else {
            self.vm.abandon_operation_locked(&mut state);
            return Err(HvfError::OperationAbandoned);
        };
        if (self.vm.operation_gate.abandoned.load(Ordering::Acquire) && !cleanup)
            || !class_live(&state)
        {
            self.vm.abandon_operation_locked(&mut state);
            return Err(HvfError::OperationAbandoned);
        }
        self.direct_published.set(true);
        thread.admission_published = true;
        HVF_OPERATION_STATE.with(|cell| cell.set(thread));
        Ok(())
    }

    fn mark_capability_returned(&self, shared: bool) -> Result<(), HvfError> {
        let key = std::ptr::from_ref::<HvfVm>(self.vm) as usize;
        let marked = HVF_OPERATION_STATE.with(|cell| {
            let thread = cell.get();
            if thread.vm == key
                && thread.total_depth == self.frame_depth
                && thread.shared_depth <= thread.total_depth
                && (!shared || thread.shared_depth != 0)
            {
                self.direct_capability_returned.set(true);
                true
            } else {
                false
            }
        });
        if marked {
            Ok(())
        } else {
            self.vm.cleanup_required.store(true, Ordering::Release);
            self.vm
                .operation_gate
                .abandoned
                .store(true, Ordering::Release);
            self.vm.operation_gate.idle.notify_all();
            Err(HvfError::OperationAbandoned)
        }
    }

    fn prepare_leave(&self, shared: bool) -> Option<HvfOperationPublicationFold> {
        let thread = self.top_thread_state(shared)?;
        let next_total = thread.total_depth.checked_sub(1)?;
        let next_shared = if shared {
            thread.shared_depth.checked_sub(1)?
        } else {
            thread.shared_depth
        };
        if next_shared > next_total {
            return None;
        }

        let frame_published = self.direct_published.get() || thread.current_descendant_published;
        let admission_published = thread.admission_published || frame_published;
        let next_thread = if next_total == 0 {
            if next_shared != 0 || frame_published != admission_published {
                return None;
            }
            HvfOperationThreadState::EMPTY
        } else {
            HvfOperationThreadState {
                total_depth: next_total,
                shared_depth: next_shared,
                current_descendant_published: self.saved_parent_descendant_published
                    || frame_published,
                admission_published,
                ..thread
            }
        };
        Some(HvfOperationPublicationFold {
            frame_published,
            admission_published,
            next_thread,
        })
    }

    fn conservative_admission_published(&self) -> bool {
        if self.direct_published.get() || self.saved_parent_descendant_published {
            return true;
        }
        let key = std::ptr::from_ref::<HvfVm>(self.vm) as usize;
        HVF_OPERATION_STATE.with(|cell| {
            let thread = cell.get();
            thread.vm == key && (thread.admission_published || thread.current_descendant_published)
        })
    }

    fn commit_leave(&mut self, fold: HvfOperationPublicationFold) {
        HVF_OPERATION_STATE.with(|cell| cell.set(fold.next_thread));
        self.finished = true;
    }

    fn disarm_abandoned(&mut self) {
        self.finished = true;
    }
}

impl Drop for HvfOperationFrame<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.vm
                .operation_gate
                .abandoned
                .store(true, Ordering::Release);
            self.vm.cleanup_required.store(true, Ordering::Release);
            self.vm.operation_gate.idle.notify_all();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvfOperationFinish {
    Complete {
        frame_published: bool,
        admission_published: bool,
    },
    PoisonRequested {
        admission_published: bool,
    },
}

struct HvfVmOperationGate {
    state: Mutex<HvfVmOperationState>,
    idle: Condvar,
    abandoned: AtomicBool,
}

pub(crate) struct HvfVmOperation<'vm> {
    frame: HvfOperationFrame<'vm>,
    owner: std::thread::ThreadId,
    cleanup: bool,
}

impl HvfVmOperation<'_> {
    pub(crate) fn mark_published(&self) -> Result<(), HvfError> {
        let current = std::thread::current().id();
        self.frame.mark_published(false, self.cleanup, |state| {
            current == self.owner
                && state.owner.as_ref() == Some(&self.owner)
                && state.depth != 0
                && if self.cleanup {
                    state.cleanup_depth != 0
                } else {
                    state.depth > state.cleanup_depth
                }
        })
    }

    pub(crate) fn require_live(&self) -> Result<(), HvfError> {
        if self
            .frame
            .vm
            .operation_gate
            .abandoned
            .load(Ordering::Acquire)
            && !self.cleanup
        {
            return Err(HvfError::OperationAbandoned);
        }
        let current = std::thread::current().id();
        let mut state = self
            .frame
            .vm
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let class_live = current == self.owner
            && state.owner.as_ref() == Some(&self.owner)
            && state.depth != 0
            && self.frame.top_thread_state(false).is_some()
            && if self.cleanup {
                state.cleanup_depth != 0
            } else {
                state.depth > state.cleanup_depth
            };
        if !class_live {
            self.frame.vm.abandon_operation_locked(&mut state);
            return Err(HvfError::OperationAbandoned);
        }
        if !self.cleanup
            && (self.frame.vm.cleanup_required.load(Ordering::Acquire)
                || state.poison_requested
                || state.poisoned)
        {
            return Err(HvfError::Poisoned);
        }
        Ok(())
    }

    fn finish(self, body_panicked: bool) -> Result<HvfOperationFinish, HvfError> {
        self.finish_observed(body_panicked, || {})
    }

    fn finish_observed(
        mut self,
        body_panicked: bool,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<HvfOperationFinish, HvfError> {
        let vm = self.frame.vm;
        let current = std::thread::current().id();
        let mut state = vm
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.cleanup && !state.poisoned && vm.cleanup_required.load(Ordering::Acquire) {
            state.poison_requested = true;
        }

        let fold = self.frame.prepare_leave(false);
        let failure_published = fold.map_or_else(
            || self.frame.conservative_admission_published(),
            |fold| fold.admission_published,
        );
        let class_live = current == self.owner
            && state.owner.as_ref() == Some(&self.owner)
            && state.depth != 0
            && if self.cleanup {
                state.cleanup_depth != 0
            } else {
                state.depth > state.cleanup_depth
            };
        let Some(fold) = fold.filter(|_| class_live) else {
            vm.abandon_operation_locked(&mut state);
            self.frame.disarm_abandoned();
            let observer_panic = contain_panic_observer(on_published_panic_latched, false);
            drop(state);
            dispose_secondary_panic(observer_panic);
            let error = HvfError::OperationAbandoned;
            return Err(if failure_published {
                HvfError::after_publication(error)
            } else {
                error
            });
        };

        let invoke_observer = body_panicked && fold.admission_published;
        if invoke_observer && !state.poisoned {
            state.poison_requested = true;
        }
        let observer_panic = contain_panic_observer(on_published_panic_latched, invoke_observer);
        let poison_requested = state.poison_requested;
        state.depth -= 1;
        if self.cleanup {
            state.cleanup_depth -= 1;
        }
        let outermost = state.depth == 0;
        if outermost {
            state.owner = None;
            if state.cleanup_depth != 0 {
                vm.abandon_operation_locked(&mut state);
            }
        }
        self.frame.commit_leave(fold);
        let observer_panicked = observer_panic.is_some();
        if observer_panicked {
            state.poison_requested = false;
            state.poisoned = true;
            vm.operation_gate.abandoned.store(true, Ordering::Release);
            vm.cleanup_required.store(true, Ordering::Release);
        }
        if outermost {
            HvfVm::promote_poison_if_quiescent(&mut state);
            vm.operation_gate.idle.notify_all();
        }
        let finish = if poison_requested && !self.cleanup {
            HvfOperationFinish::PoisonRequested {
                admission_published: fold.admission_published,
            }
        } else {
            HvfOperationFinish::Complete {
                frame_published: fold.frame_published,
                admission_published: fold.admission_published,
            }
        };
        drop(state);
        dispose_secondary_panic(observer_panic);
        if self.cleanup && poison_requested && !body_panicked {
            vm.poison();
        }
        if vm.operation_gate.abandoned.load(Ordering::Acquire) && !self.cleanup {
            let error = HvfError::OperationAbandoned;
            Err(if fold.admission_published {
                HvfError::after_publication(error)
            } else {
                error
            })
        } else {
            Ok(finish)
        }
    }
}

struct HvfExistingVcpuOperation<'vm> {
    frame: HvfOperationFrame<'vm>,
    owner: std::thread::ThreadId,
}

impl HvfExistingVcpuOperation<'_> {
    fn mark_published(&self) -> Result<(), HvfError> {
        let current = std::thread::current().id();
        self.frame.mark_published(false, false, |state| {
            current == self.owner
                && state
                    .active_vcpu_owners
                    .iter()
                    .filter(|owner| **owner == self.owner)
                    .count()
                    == 1
        })
    }

    fn finish(self, body_panicked: bool) -> Result<HvfOperationFinish, HvfError> {
        self.finish_observed(body_panicked, || {})
    }

    fn finish_observed(
        mut self,
        body_panicked: bool,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<HvfOperationFinish, HvfError> {
        let vm = self.frame.vm;
        vm.finish_existing_vcpu_operation(
            self.owner,
            &mut self.frame,
            body_panicked,
            on_published_panic_latched,
        )
    }
}

pub(crate) struct HvfVmSharedOperation<'vm> {
    frame: HvfOperationFrame<'vm>,
}

impl HvfVmSharedOperation<'_> {
    pub(crate) fn mark_published(&self) -> Result<(), HvfError> {
        self.frame
            .mark_published(true, false, |state| state.shared != 0)
    }

    pub(crate) fn require_live(&self) -> Result<(), HvfError> {
        if self
            .frame
            .vm
            .operation_gate
            .abandoned
            .load(Ordering::Acquire)
        {
            return Err(HvfError::OperationAbandoned);
        }
        let mut state = self
            .frame
            .vm
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.frame.vm.cleanup_required.load(Ordering::Acquire)
            || state.poison_requested
            || state.poisoned
        {
            return Err(HvfError::Poisoned);
        }
        if state.shared == 0 || self.frame.top_thread_state(true).is_none() {
            self.frame.vm.abandon_operation_locked(&mut state);
            return Err(HvfError::OperationAbandoned);
        }
        Ok(())
    }

    fn finish(self, body_panicked: bool) -> Result<HvfOperationFinish, HvfError> {
        self.finish_observed(body_panicked, || {})
    }

    fn finish_observed(
        mut self,
        body_panicked: bool,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<HvfOperationFinish, HvfError> {
        let vm = self.frame.vm;
        vm.finish_shared_operation(&mut self.frame, body_panicked, on_published_panic_latched)
    }
}

trait HvfPublicationCapability {
    fn mark_hvf_published(&self) -> Result<(), HvfError>;
}

impl HvfPublicationCapability for HvfVmOperation<'_> {
    fn mark_hvf_published(&self) -> Result<(), HvfError> {
        HvfVmOperation::mark_published(self)
    }
}

impl HvfPublicationCapability for HvfVmSharedOperation<'_> {
    fn mark_hvf_published(&self) -> Result<(), HvfError> {
        HvfVmSharedOperation::mark_published(self)
    }
}

impl HvfPublicationCapability for HvfExistingVcpuOperation<'_> {
    fn mark_hvf_published(&self) -> Result<(), HvfError> {
        HvfExistingVcpuOperation::mark_published(self)
    }
}

pub(crate) struct HvfVm {
    report: HvfVmReport,
    monitor: HvfMonitor,
    admitted_features: HvfFeatureRegisters,
    operation_gate: HvfVmOperationGate,
    mapping_registry: Mutex<HvfMappingRegistry>,
    cleanup_required: AtomicBool,
    vcpu_ownership: Mutex<HvfVcpuOwnership>,
}

impl fmt::Debug for HvfVm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVm")
            .field("report", &self.report)
            .field("admitted_features", &self.admitted_features)
            .field("poisoned", &self.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl HvfVm {
    /// Promotes a published poison request only when no admission remains.
    /// Called while `operation_gate.state` is locked by every finish path, so
    /// the final departing admission performs one allocation-free state
    /// transition without waiting behind a result-carried fine-grained guard.
    fn promote_poison_if_quiescent(state: &mut HvfVmOperationState) {
        if state.poison_requested
            && state.owner.is_none()
            && state.active_vcpu_owners.is_empty()
            && state.shared == 0
        {
            state.poison_requested = false;
            state.poisoned = true;
        }
    }

    fn abandoned_cleanup_ready(
        &self,
        state: &HvfVmOperationState,
        current: std::thread::ThreadId,
    ) -> bool {
        let canonical = state.owner.is_none()
            && state.depth == 0
            && state.cleanup_depth == 0
            && state.active_vcpu_owners.is_empty()
            && state.shared == 0
            && state.zero_vcpu_owner.is_none()
            && state.zero_vcpu_depth == 0
            && !state.poison_requested
            && state.poisoned;
        if canonical {
            return true;
        }
        if state.owner.as_ref() != Some(&current)
            || state.depth == 0
            || state.cleanup_depth != state.depth
        {
            return false;
        }
        let key = std::ptr::from_ref::<HvfVm>(self) as usize;
        HVF_OPERATION_STATE.with(|cell| {
            let thread = cell.get();
            thread.vm == key && thread.total_depth != 0
        })
    }

    fn abandon_operation_locked(&self, state: &mut HvfVmOperationState) {
        state.poison_requested = false;
        state.poisoned = true;
        self.operation_gate.abandoned.store(true, Ordering::Release);
        self.cleanup_required.store(true, Ordering::Release);
        self.operation_gate.idle.notify_all();
    }

    fn create() -> Result<Self, HvfError> {
        let sdk_max_allowed = unsafe { litebox_hvf_sdk_max_allowed() };
        if sdk_max_allowed < MACOS_26_SDK_VERSION {
            return Err(HvfError::SdkTooOld(sdk_max_allowed));
        }
        if unsafe { litebox_hvf_runtime_is_macos_26_or_newer() } == 0 {
            return Err(HvfError::HostTooOld);
        }
        let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if usize::try_from(host_page_size) != Ok(HVF_PAGE_SIZE) {
            return Err(HvfError::HostPageSize(host_page_size));
        }

        let monitor = HvfMonitor::linked()?;
        with_vm_configuration(move |vm_config| {
            let mut max_ipa_bits = 0;
            check("hv_vm_config_get_max_ipa_size", unsafe {
                litebox_hvf_vm_config_get_max_ipa_size(&raw mut max_ipa_bits)
            })?;
            if max_ipa_bits < MIN_IPA_BITS {
                return Err(HvfError::IpaSizeOutOfRange(max_ipa_bits));
            }
            let requested_ipa_bits = max_ipa_bits.min(MAX_IPA_BITS);
            check("hv_vm_config_set_ipa_size", unsafe {
                litebox_hvf_vm_config_set_ipa_size(vm_config.as_ptr(), requested_ipa_bits)
            })?;
            check("hv_vm_config_set_ipa_granule", unsafe {
                litebox_hvf_vm_config_set_ipa_granule_16k(vm_config.as_ptr())
            })?;
            check("hv_vm_config_set_el2_enabled(false)", unsafe {
                litebox_hvf_vm_config_set_el2_disabled(vm_config.as_ptr())
            })?;

            let mut configured_ipa_bits = 0;
            check("hv_vm_config_get_ipa_size", unsafe {
                litebox_hvf_vm_config_get_ipa_size(vm_config.as_ptr(), &raw mut configured_ipa_bits)
            })?;
            if configured_ipa_bits != requested_ipa_bits {
                return Err(HvfError::IpaSizeReadback {
                    requested: requested_ipa_bits,
                    configured: configured_ipa_bits,
                });
            }

            let mut raw_granule = 0;
            let mut is_16k = 0;
            check("hv_vm_config_get_ipa_granule", unsafe {
                litebox_hvf_vm_config_get_ipa_granule(
                    vm_config.as_ptr(),
                    &raw mut raw_granule,
                    &raw mut is_16k,
                )
            })?;
            if is_16k == 0 {
                return Err(HvfError::IpaGranuleReadback(raw_granule));
            }

            let mut el2_supported = 0;
            check("hv_vm_config_get_el2_supported", unsafe {
                litebox_hvf_vm_config_get_el2_supported(&raw mut el2_supported)
            })?;
            let mut el2_enabled = 0;
            check("hv_vm_config_get_el2_enabled", unsafe {
                litebox_hvf_vm_config_get_el2_enabled(vm_config.as_ptr(), &raw mut el2_enabled)
            })?;
            if el2_enabled != 0 {
                return Err(HvfError::El2StillEnabled);
            }

            let mut max_vcpu_count = 0;
            check("hv_vm_get_max_vcpu_count", unsafe {
                litebox_hvf_vm_get_max_vcpu_count(&raw mut max_vcpu_count)
            })?;
            if max_vcpu_count == 0 {
                return Err(HvfError::NoVcpus);
            }
            let mut active_vcpu_owners = Vec::new();
            active_vcpu_owners
                .try_reserve_exact(max_vcpu_count as usize)
                .map_err(|_| HvfError::ResourceReservation("active vCPU operations"))?;
            let mut waiters = Vec::new();
            waiters
                .try_reserve_exact(MAX_OPERATION_WAITERS)
                .map_err(|_| HvfError::ResourceReservation("operation waiters"))?;
            let vcpu_ownership = HvfVcpuOwnership::with_capacity(max_vcpu_count as usize)?;

            let admitted_features = with_vcpu_configuration(|config| {
                HvfFeatureRegisters::from_vcpu_configuration(config)
            })?;
            let create_result = unsafe { litebox_hvf_vm_create(vm_config.as_ptr()) };
            if denied(create_result) {
                return Err(HvfError::HypervisorEntitlementMissing);
            }
            check("hv_vm_create", create_result)?;

            Ok(Self {
                report: HvfVmReport {
                    sdk_max_allowed,
                    max_ipa_bits,
                    configured_ipa_bits,
                    ipa_granule_bytes: HVF_PAGE_SIZE,
                    el2_supported: el2_supported != 0,
                    el2_enabled: false,
                    max_vcpu_count,
                    monitor_bytes: monitor.bytes().len(),
                    monitor_syscall_offset: monitor.syscall_offset,
                    monitor_resume_offset: monitor.resume_offset,
                    monitor_synchronize_offset: monitor.synchronize_offset,
                },
                monitor,
                admitted_features,
                operation_gate: HvfVmOperationGate {
                    state: Mutex::new(HvfVmOperationState {
                        owner: None,
                        depth: 0,
                        cleanup_depth: 0,
                        active_vcpu_owners,
                        poison_requested: false,
                        poisoned: false,
                        zero_vcpu_owner: None,
                        zero_vcpu_depth: 0,
                        shared: 0,
                        next_waiter_ticket: 1,
                        waiters,
                    }),
                    idle: Condvar::new(),
                    abandoned: AtomicBool::new(false),
                },
                mapping_registry: Mutex::new(HvfMappingRegistry::default()),
                cleanup_required: AtomicBool::new(false),
                vcpu_ownership: Mutex::new(vcpu_ownership),
            })
        })
    }

    pub(crate) fn report(&self) -> &HvfVmReport {
        &self.report
    }

    pub(crate) fn monitor(&self) -> &HvfMonitor {
        &self.monitor
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.operation_gate.abandoned.load(Ordering::Acquire)
            || self
                .operation_gate
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .poisoned
            || self.cleanup_required.load(Ordering::Acquire)
    }

    pub(crate) fn is_terminally_poisoned(&self) -> bool {
        self.operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poisoned
    }

    pub(crate) fn poison_requested(&self) -> bool {
        self.operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poison_requested
    }

    fn wait_for_operation_state<'a>(
        &self,
        state: MutexGuard<'a, HvfVmOperationState>,
        deadline: Instant,
    ) -> (MutexGuard<'a, HvfVmOperationState>, bool) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return (state, true);
        }
        let (state, result) = self
            .operation_gate
            .idle
            .wait_timeout(state, remaining.min(OPERATION_WAIT_POLL))
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let timed_out =
            result.timed_out() && deadline.saturating_duration_since(Instant::now()).is_zero();
        (state, timed_out)
    }

    pub(crate) fn wait_for_poison_request(&self) -> Result<(), HvfError> {
        let deadline = Instant::now()
            .checked_add(OPERATION_WAIT_TIMEOUT)
            .ok_or(HvfError::OperationWaitTimeout)?;
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.poison_requested && !state.poisoned {
            if self.operation_gate.abandoned.load(Ordering::Acquire) {
                return Err(HvfError::OperationAbandoned);
            }
            let (next, timed_out) = self.wait_for_operation_state(state, deadline);
            state = next;
            if timed_out {
                if state.poison_requested || state.poisoned {
                    return Ok(());
                }
                if self.operation_gate.abandoned.load(Ordering::Acquire) {
                    return Err(HvfError::OperationAbandoned);
                }
                return Err(HvfError::OperationWaitTimeout);
            }
        }
        Ok(())
    }

    fn begin_existing_vcpu_operation(&self) -> Result<HvfExistingVcpuOperation<'_>, HvfError> {
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            return Err(HvfError::OperationAbandoned);
        }
        if self.cleanup_required.load(Ordering::Acquire) {
            return Err(HvfError::Poisoned);
        }
        let owner = std::thread::current().id();
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            return Err(HvfError::OperationAbandoned);
        }
        if self.cleanup_required.load(Ordering::Acquire) || state.poison_requested || state.poisoned
        {
            return Err(HvfError::Poisoned);
        }
        if state.active_vcpu_owners.len() >= self.report.max_vcpu_count as usize
            || state.active_vcpu_owners.contains(&owner)
        {
            self.abandon_operation_locked(&mut state);
            return Err(HvfError::ResidualAccounting);
        }
        let frame = HvfOperationFrame::enter(self, &mut state, false)?;
        state.active_vcpu_owners.push(owner);
        Ok(HvfExistingVcpuOperation { frame, owner })
    }

    fn finish_existing_vcpu_operation(
        &self,
        owner: std::thread::ThreadId,
        frame: &mut HvfOperationFrame<'_>,
        body_panicked: bool,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<HvfOperationFinish, HvfError> {
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.poisoned && self.cleanup_required.load(Ordering::Acquire) {
            state.poison_requested = true;
        }

        let fold = frame.prepare_leave(false);
        let mut index = None;
        let mut duplicate = false;
        for (candidate, active) in state.active_vcpu_owners.iter().enumerate() {
            if *active == owner && index.replace(candidate).is_some() {
                duplicate = true;
                break;
            }
        }
        let index = if std::thread::current().id() == owner && !duplicate {
            index
        } else {
            None
        };
        let failure_published = fold.map_or_else(
            || frame.conservative_admission_published(),
            |fold| fold.admission_published,
        );
        let (Some(fold), Some(index)) = (fold, index) else {
            self.abandon_operation_locked(&mut state);
            frame.disarm_abandoned();
            let observer_panic = contain_panic_observer(on_published_panic_latched, false);
            drop(state);
            dispose_secondary_panic(observer_panic);
            let error = HvfError::OperationAbandoned;
            return Err(if failure_published {
                HvfError::after_publication(error)
            } else {
                error
            });
        };

        let invoke_observer = body_panicked && fold.admission_published;
        if invoke_observer && !state.poisoned {
            state.poison_requested = true;
        }
        let observer_panic = contain_panic_observer(on_published_panic_latched, invoke_observer);
        let poison_requested = state.poison_requested;
        state.active_vcpu_owners.swap_remove(index);
        frame.commit_leave(fold);
        let observer_panicked = observer_panic.is_some();
        if observer_panicked {
            state.poison_requested = false;
            state.poisoned = true;
            self.operation_gate.abandoned.store(true, Ordering::Release);
            self.cleanup_required.store(true, Ordering::Release);
        }
        Self::promote_poison_if_quiescent(&mut state);
        self.operation_gate.idle.notify_all();
        let finish = if poison_requested {
            HvfOperationFinish::PoisonRequested {
                admission_published: fold.admission_published,
            }
        } else {
            HvfOperationFinish::Complete {
                frame_published: fold.frame_published,
                admission_published: fold.admission_published,
            }
        };
        drop(state);
        dispose_secondary_panic(observer_panic);
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            let error = HvfError::OperationAbandoned;
            Err(if fold.admission_published {
                HvfError::after_publication(error)
            } else {
                error
            })
        } else {
            Ok(finish)
        }
    }

    fn begin_operation_inner(
        &self,
        cleanup: bool,
        wait_timeout: Duration,
    ) -> Result<HvfVmOperation<'_>, HvfError> {
        if self.operation_gate.abandoned.load(Ordering::Acquire) && !cleanup {
            return Err(HvfError::OperationAbandoned);
        }
        if self.cleanup_required.load(Ordering::Acquire) && !cleanup {
            return Err(HvfError::Poisoned);
        }
        let deadline = Instant::now()
            .checked_add(wait_timeout)
            .ok_or(HvfError::OperationWaitTimeout)?;
        let current = std::thread::current().id();
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut waiter_ticket = None;
        if state.owner.as_ref() != Some(&current) {
            if state.waiters.len() >= MAX_OPERATION_WAITERS {
                return Err(HvfError::ResourceReservation("operation waiters"));
            }
            let ticket = state.next_waiter_ticket;
            let Some(next) = ticket.checked_add(1) else {
                self.abandon_operation_locked(&mut state);
                return Err(HvfError::OperationAbandoned);
            };
            state.next_waiter_ticket = next;
            state.waiters.push(HvfOperationWaiter {
                ticket,
                owner: current,
            });
            waiter_ticket = Some(ticket);
        }

        macro_rules! reject_operation {
            ($error:expr) => {{
                let mut error = $error;
                if let Some(ticket) = waiter_ticket.take() {
                    let index = state
                        .waiters
                        .iter()
                        .position(|waiter| waiter.ticket == ticket && waiter.owner == current);
                    match index {
                        Some(index) => {
                            state.waiters.remove(index);
                            self.operation_gate.idle.notify_all();
                        }
                        None => {
                            self.abandon_operation_locked(&mut state);
                            error = HvfError::OperationAbandoned;
                        }
                    }
                }
                return Err(error);
            }};
        }

        loop {
            let owner_state_valid = state.owner.is_none() == (state.depth == 0)
                && state.cleanup_depth <= state.depth
                && (state.owner.is_some() || state.cleanup_depth == 0);
            let queue_valid = state.waiters.len() <= MAX_OPERATION_WAITERS
                && state
                    .waiters
                    .windows(2)
                    .all(|pair| pair[0].ticket < pair[1].ticket);
            let waiter_index = match waiter_ticket {
                None => None,
                Some(ticket) => {
                    let mut found = None;
                    let mut duplicate = false;
                    for (index, waiter) in state.waiters.iter().enumerate() {
                        if waiter.ticket == ticket && waiter.owner == current {
                            duplicate |= found.replace(index).is_some();
                        }
                    }
                    if duplicate {
                        self.abandon_operation_locked(&mut state);
                        reject_operation!(HvfError::OperationAbandoned);
                    }
                    if let Some(index) = found {
                        Some(index)
                    } else {
                        self.abandon_operation_locked(&mut state);
                        reject_operation!(HvfError::OperationAbandoned);
                    }
                }
            };
            if !owner_state_valid || !queue_valid {
                self.abandon_operation_locked(&mut state);
                reject_operation!(HvfError::OperationAbandoned);
            }
            if self.operation_gate.abandoned.load(Ordering::Acquire) && !cleanup {
                reject_operation!(HvfError::OperationAbandoned);
            }
            if self.cleanup_required.load(Ordering::Acquire) && !cleanup {
                reject_operation!(HvfError::Poisoned);
            }
            if state.poisoned {
                if !cleanup {
                    reject_operation!(HvfError::Poisoned);
                }
            } else if state.poison_requested && !cleanup {
                reject_operation!(HvfError::Poisoned);
            }
            if cleanup
                && self.operation_gate.abandoned.load(Ordering::Acquire)
                && !self.abandoned_cleanup_ready(&state, current)
            {
                let (next, timed_out) = self.wait_for_operation_state(state, deadline);
                state = next;
                if timed_out {
                    let ready = self.abandoned_cleanup_ready(&state, current);
                    if ready {
                        continue;
                    }
                    reject_operation!(HvfError::OperationWaitTimeout);
                }
                continue;
            }

            match state.owner {
                None if waiter_index == Some(0) => {
                    let Some(ticket) = waiter_ticket.take() else {
                        self.abandon_operation_locked(&mut state);
                        return Err(HvfError::OperationAbandoned);
                    };
                    let waiter = state.waiters.remove(0);
                    if waiter.ticket != ticket || waiter.owner != current {
                        self.abandon_operation_locked(&mut state);
                        return Err(HvfError::OperationAbandoned);
                    }
                    let frame = HvfOperationFrame::enter(self, &mut state, false)?;
                    state.owner = Some(current);
                    state.depth = 1;
                    state.cleanup_depth = usize::from(cleanup);
                    self.operation_gate.idle.notify_all();
                    return Ok(HvfVmOperation {
                        frame,
                        owner: current,
                        cleanup,
                    });
                }
                Some(owner) if owner == current && waiter_ticket.is_none() => {
                    let Some(depth) = state.depth.checked_add(1) else {
                        self.abandon_operation_locked(&mut state);
                        return Err(HvfError::OperationAbandoned);
                    };
                    let cleanup_depth = if cleanup {
                        state.cleanup_depth.checked_add(1)
                    } else {
                        Some(state.cleanup_depth)
                    };
                    let Some(cleanup_depth) =
                        cleanup_depth.filter(|cleanup_depth| *cleanup_depth <= depth)
                    else {
                        self.abandon_operation_locked(&mut state);
                        return Err(HvfError::OperationAbandoned);
                    };
                    let frame = HvfOperationFrame::enter(self, &mut state, false)?;
                    state.depth = depth;
                    state.cleanup_depth = cleanup_depth;
                    return Ok(HvfVmOperation {
                        frame,
                        owner: current,
                        cleanup,
                    });
                }
                None | Some(_) => {
                    let (next, timed_out) = self.wait_for_operation_state(state, deadline);
                    state = next;
                    if timed_out {
                        let owner_state_invalid = state.owner.is_none() != (state.depth == 0)
                            || state.cleanup_depth > state.depth
                            || (state.owner.is_none() && state.cleanup_depth != 0);
                        let waiter_ready = waiter_ticket.is_some_and(|ticket| {
                            state.owner.is_none()
                                && state.waiters.first().is_some_and(|waiter| {
                                    waiter.ticket == ticket && waiter.owner == current
                                })
                        });
                        let class_changed = owner_state_invalid
                            || (!cleanup
                                && (self.operation_gate.abandoned.load(Ordering::Acquire)
                                    || self.cleanup_required.load(Ordering::Acquire)
                                    || state.poison_requested
                                    || state.poisoned));
                        if waiter_ready || class_changed {
                            continue;
                        }
                        reject_operation!(HvfError::OperationWaitTimeout);
                    }
                }
            }
        }
    }

    fn finish_operation<T, E>(
        &self,
        result: Result<T, E>,
        finish: Result<HvfOperationFinish, HvfError>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        match finish {
            Ok(HvfOperationFinish::Complete {
                frame_published, ..
            }) => match result {
                Ok(value) => Ok(value),
                Err(trigger) if frame_published => Err(trigger.after_hvf_publication()),
                Err(trigger) => Err(trigger),
            },
            Ok(HvfOperationFinish::PoisonRequested {
                admission_published,
            }) => match result {
                Ok(value) => {
                    self.poison();
                    let trigger = if self.operation_gate.abandoned.load(Ordering::Acquire) {
                        HvfError::OperationAbandoned
                    } else {
                        HvfError::Poisoned
                    };
                    let error = E::from(trigger);
                    let error = if admission_published {
                        error.after_hvf_publication()
                    } else {
                        error
                    };
                    dispose_rejected_value(value);
                    Err(error)
                }
                Err(trigger) => {
                    self.poison();
                    Err(if admission_published {
                        trigger.after_hvf_publication()
                    } else {
                        trigger
                    })
                }
            },
            Err(error) => match result {
                Err(trigger) if error.published_before_failure() => {
                    Err(trigger.after_hvf_publication())
                }
                Err(trigger) => Err(trigger),
                Ok(value) => {
                    let error = E::from(error);
                    dispose_rejected_value(value);
                    Err(error)
                }
            },
        }
    }

    fn finish_capability_operation<T, E>(
        &self,
        result: Result<T, E>,
        finish: Result<HvfOperationFinish, HvfError>,
        exact_capability_returned: bool,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        match finish {
            Ok(HvfOperationFinish::Complete {
                frame_published, ..
            }) => match result {
                Ok(value) => Ok(value),
                Err(trigger) if frame_published => Err(trigger.after_hvf_publication()),
                Err(trigger) => Err(trigger),
            },
            Ok(HvfOperationFinish::PoisonRequested {
                admission_published,
            }) => {
                self.poison();
                match result {
                    Ok(value) if exact_capability_returned => Ok(value),
                    Ok(value) => {
                        let trigger = if self.operation_gate.abandoned.load(Ordering::Acquire) {
                            HvfError::OperationAbandoned
                        } else {
                            HvfError::Poisoned
                        };
                        let error = E::from(trigger);
                        let error = if admission_published {
                            error.after_hvf_publication()
                        } else {
                            error
                        };
                        dispose_rejected_value(value);
                        Err(error)
                    }
                    Err(trigger) if admission_published => Err(trigger.after_hvf_publication()),
                    Err(trigger) => Err(trigger),
                }
            }
            Err(error) => match result {
                Ok(value) if exact_capability_returned => Ok(value),
                Ok(value) => {
                    let error = E::from(error);
                    dispose_rejected_value(value);
                    Err(error)
                }
                Err(trigger) if error.published_before_failure() => {
                    Err(trigger.after_hvf_publication())
                }
                Err(trigger) => Err(trigger),
            },
        }
    }

    fn request_poison_nonblocking(&self) {
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.poisoned {
            state.poison_requested = true;
            Self::promote_poison_if_quiescent(&mut state);
            self.operation_gate.idle.notify_all();
        }
    }

    fn resume_operation_panic(
        &self,
        payload: Box<dyn std::any::Any + Send>,
        finish: Result<HvfOperationFinish, HvfError>,
    ) -> ! {
        match finish {
            Ok(HvfOperationFinish::Complete {
                admission_published: true,
                ..
            }) => {
                self.request_poison_nonblocking();
                std::panic::resume_unwind(payload)
            }
            Ok(
                HvfOperationFinish::Complete {
                    admission_published: false,
                    ..
                }
                | HvfOperationFinish::PoisonRequested { .. },
            ) => std::panic::resume_unwind(payload),
            Err(_) => {
                self.operation_gate.abandoned.store(true, Ordering::Release);
                self.cleanup_required.store(true, Ordering::Release);
                self.operation_gate.idle.notify_all();
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Runs `body` under a counting (shared) admission: refused while the VM
    /// is poisoned, poison-requested, or abandoned; otherwise concurrent with
    /// other shared operations and with the exclusive owner.  Used by the
    /// per-run vCPU attach/submit/acknowledge paths so guest syscalls on many
    /// vCPUs never serialize on the exclusive gate.
    pub(crate) fn with_shared_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmSharedOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        let operation = self.begin_shared_operation().map_err(E::from)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&operation)));
        let body_panicked = result.is_err();
        let finish = operation.finish(body_panicked);
        match result {
            Ok(result) => self.finish_operation(result, finish),
            Err(payload) => self.resume_operation_panic(payload, finish),
        }
    }

    fn with_shared_operation_observed<T, E>(
        &self,
        body: impl FnOnce(&HvfVmSharedOperation<'_>) -> Result<T, E>,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        let operation = self.begin_shared_operation().map_err(E::from)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&operation)));
        let body_panicked = result.is_err();
        let finish = operation.finish_observed(body_panicked, on_published_panic_latched);
        match result {
            Ok(result) => self.finish_operation(result, finish),
            Err(payload) => self.resume_operation_panic(payload, finish),
        }
    }

    fn begin_shared_operation(&self) -> Result<HvfVmSharedOperation<'_>, HvfError> {
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            return Err(HvfError::OperationAbandoned);
        }
        if self.cleanup_required.load(Ordering::Acquire) {
            return Err(HvfError::Poisoned);
        }
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            return Err(HvfError::OperationAbandoned);
        }
        if self.cleanup_required.load(Ordering::Acquire) || state.poison_requested || state.poisoned
        {
            return Err(HvfError::Poisoned);
        }
        let Some(shared) = state.shared.checked_add(1) else {
            self.abandon_operation_locked(&mut state);
            return Err(HvfError::OperationAbandoned);
        };
        let frame = HvfOperationFrame::enter(self, &mut state, true)?;
        state.shared = shared;
        Ok(HvfVmSharedOperation { frame })
    }

    fn finish_shared_operation(
        &self,
        frame: &mut HvfOperationFrame<'_>,
        body_panicked: bool,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<HvfOperationFinish, HvfError> {
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.poisoned && self.cleanup_required.load(Ordering::Acquire) {
            state.poison_requested = true;
        }

        let fold = frame.prepare_leave(true);
        let shared = state.shared.checked_sub(1);
        let failure_published = fold.map_or_else(
            || frame.conservative_admission_published(),
            |fold| fold.admission_published,
        );
        let (Some(fold), Some(shared)) = (fold, shared) else {
            self.abandon_operation_locked(&mut state);
            frame.disarm_abandoned();
            let observer_panic = contain_panic_observer(on_published_panic_latched, false);
            drop(state);
            dispose_secondary_panic(observer_panic);
            let error = HvfError::OperationAbandoned;
            return Err(if failure_published {
                HvfError::after_publication(error)
            } else {
                error
            });
        };

        let invoke_observer = body_panicked && fold.admission_published;
        if invoke_observer && !state.poisoned {
            state.poison_requested = true;
        }
        let observer_panic = contain_panic_observer(on_published_panic_latched, invoke_observer);
        let poison_requested = state.poison_requested;
        state.shared = shared;
        frame.commit_leave(fold);
        let observer_panicked = observer_panic.is_some();
        if observer_panicked {
            state.poison_requested = false;
            state.poisoned = true;
            self.operation_gate.abandoned.store(true, Ordering::Release);
            self.cleanup_required.store(true, Ordering::Release);
        }
        Self::promote_poison_if_quiescent(&mut state);
        self.operation_gate.idle.notify_all();
        let finish = if poison_requested {
            HvfOperationFinish::PoisonRequested {
                admission_published: fold.admission_published,
            }
        } else {
            HvfOperationFinish::Complete {
                frame_published: fold.frame_published,
                admission_published: fold.admission_published,
            }
        };
        drop(state);
        dispose_secondary_panic(observer_panic);
        if self.operation_gate.abandoned.load(Ordering::Acquire) {
            let error = HvfError::OperationAbandoned;
            Err(if fold.admission_published {
                HvfError::after_publication(error)
            } else {
                error
            })
        } else {
            Ok(finish)
        }
    }

    pub(crate) fn with_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        self.with_operation_inner(false, OPERATION_WAIT_TIMEOUT, body)
    }

    pub(crate) fn with_operation_timeout<T, E>(
        &self,
        wait_timeout: Duration,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        self.with_operation_inner(false, wait_timeout, body)
    }

    pub(crate) fn with_cleanup_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        self.with_operation_inner(true, OPERATION_WAIT_TIMEOUT, body)
    }

    pub(crate) fn with_capability_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        T: HvfCompletionCapability,
        E: HvfOperationError,
    {
        let operation = self
            .begin_operation_inner(false, OPERATION_WAIT_TIMEOUT)
            .map_err(E::from)?;
        // Validation and capability-return marking run inside the same
        // catch_unwind as `body`: either can panic (an invariant check in
        // `validate_hvf_completion`, or `mark_capability_returned`'s own
        // bookkeeping), and a panic anywhere in this closure must still reach
        // `operation.finish` below rather than unwinding past it and leaving
        // the operation gate's owner/depth/TLS state stale.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match body(&operation) {
                Ok(value) => {
                    let completion = value
                        .validate_hvf_completion(self)
                        .and_then(|()| operation.frame.mark_capability_returned(false));
                    match completion {
                        Ok(()) => Ok(value),
                        Err(error) => {
                            dispose_rejected_value(value);
                            Err(E::from(error))
                        }
                    }
                }
                Err(error) => Err(error),
            }));
        let body_panicked = result.is_err();
        let exact_capability_returned = operation.frame.direct_capability_returned.get();
        let finish = operation.finish(body_panicked);
        match result {
            Ok(result) => {
                self.finish_capability_operation(result, finish, exact_capability_returned)
            }
            Err(payload) => self.resume_operation_panic(payload, finish),
        }
    }

    fn with_operation_inner<T, E>(
        &self,
        cleanup: bool,
        wait_timeout: Duration,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        let operation = self
            .begin_operation_inner(cleanup, wait_timeout)
            .map_err(E::from)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&operation)));
        let body_panicked = result.is_err();
        let finish = operation.finish(body_panicked);
        match result {
            Ok(result) => self.finish_operation(result, finish),
            Err(payload) => self.resume_operation_panic(payload, finish),
        }
    }

    fn with_operation_inner_observed<T, E>(
        &self,
        cleanup: bool,
        wait_timeout: Duration,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        let operation = self
            .begin_operation_inner(cleanup, wait_timeout)
            .map_err(E::from)?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&operation)));
        let body_panicked = result.is_err();
        let finish = operation.finish_observed(body_panicked, on_published_panic_latched);
        match result {
            Ok(result) => self.finish_operation(result, finish),
            Err(payload) => self.resume_operation_panic(payload, finish),
        }
    }

    pub(crate) fn with_zero_vcpu_operation<T, E>(
        &self,
        body: impl FnOnce(&HvfVmOperation<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: HvfOperationError,
    {
        self.with_operation(|operation| {
            {
                let ownership = self
                    .vcpu_ownership
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !ownership.pending.is_empty()
                    || !ownership.active.is_empty()
                    || !ownership.quarantined.is_empty()
                {
                    return Err(E::from(HvfError::ZeroVcpuAdmission));
                }
            }
            let current = std::thread::current().id();
            {
                let mut state = self
                    .operation_gate
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.zero_vcpu_owner.is_some() || state.zero_vcpu_depth != 0 {
                    return Err(E::from(HvfError::ZeroVcpuAdmission));
                }
                state.zero_vcpu_owner = Some(current);
                state.zero_vcpu_depth = 1;
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(operation)));
            let finish = self.finish_zero_vcpu_operation(current);
            match result {
                Ok(result) => match (result, finish) {
                    (result, Ok(())) => result,
                    (Ok(value), Err(error)) => {
                        let error = E::from(error);
                        dispose_rejected_value(value);
                        Err(error)
                    }
                    (Err(trigger), Err(_)) => Err(trigger),
                },
                Err(payload) => {
                    if finish.is_err() {
                        self.operation_gate.abandoned.store(true, Ordering::Release);
                        self.cleanup_required.store(true, Ordering::Release);
                    }
                    std::panic::resume_unwind(payload)
                }
            }
        })
    }

    fn finish_zero_vcpu_operation(&self, owner: std::thread::ThreadId) -> Result<(), HvfError> {
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.zero_vcpu_owner.as_ref() != Some(&owner) || state.zero_vcpu_depth != 1 {
            state.zero_vcpu_owner = None;
            state.zero_vcpu_depth = 0;
            state.poison_requested = false;
            state.poisoned = true;
            self.operation_gate.abandoned.store(true, Ordering::Release);
            self.cleanup_required.store(true, Ordering::Release);
            self.operation_gate.idle.notify_all();
            return Err(HvfError::OperationAbandoned);
        }
        state.zero_vcpu_owner = None;
        state.zero_vcpu_depth = 0;
        self.operation_gate.idle.notify_all();
        Ok(())
    }

    fn require_vcpu_creation_admitted(&self) -> Result<(), HvfError> {
        let state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (state.zero_vcpu_owner.as_ref(), state.zero_vcpu_depth) {
            (None, 0) => Ok(()),
            (Some(_), 1) => Err(HvfError::ZeroVcpuAdmission),
            _ => Err(HvfError::OperationAbandoned),
        }
    }

    fn cancel_vcpu(
        &self,
        identifier: u64,
        generation: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<HvfVcpuControl>,
    ) -> Result<(), HvfError> {
        {
            let ownership = self
                .vcpu_ownership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let live = ownership.active.iter().any(|record| {
                record.identifier == identifier
                    && record.generation == generation
                    && record.owner == owner
                    && Arc::ptr_eq(&record.handle_state, handle_state)
                    && record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_LIVE
            });
            if !live {
                return Err(HvfError::VcpuCancellationStale {
                    identifier,
                    generation,
                });
            }
            if !ownership.identifier_is_unambiguous(identifier) {
                return Err(HvfError::VcpuOwnershipCollision(identifier));
            }
        }
        let _sdk_call = handle_state
            .sdk_call
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let ownership = self
                .vcpu_ownership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let live = ownership.active.iter().any(|record| {
                record.identifier == identifier
                    && record.generation == generation
                    && record.owner == owner
                    && Arc::ptr_eq(&record.handle_state, handle_state)
                    && record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_LIVE
            });
            if !live {
                return Err(HvfError::VcpuCancellationStale {
                    identifier,
                    generation,
                });
            }
            if !ownership.identifier_is_unambiguous(identifier) {
                return Err(HvfError::VcpuOwnershipCollision(identifier));
            }
        }
        check("hv_vcpus_exit", unsafe {
            litebox_hvf_vcpu_exit(identifier)
        })
    }

    fn destroy_registered_vcpu(
        &self,
        operation: &impl HvfPublicationCapability,
        identifier: u64,
        generation: u64,
        handle_state: &Arc<HvfVcpuControl>,
    ) -> Result<HvReturn, HvfError> {
        let current = std::thread::current().id();
        {
            let ownership = self
                .vcpu_ownership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = ownership
                .active
                .iter()
                .find(|record| {
                    record.identifier == identifier
                        && record.generation == generation
                        && Arc::ptr_eq(&record.handle_state, handle_state)
                })
                .ok_or(HvfError::VcpuNotLive)?;
            if record.owner != current {
                return Err(HvfError::VcpuWrongOwner { identifier });
            }
            if record.handle_state.load(Ordering::Acquire) != VCPU_HANDLE_LIVE {
                return Err(HvfError::VcpuNotLive);
            }
            if !ownership.identifier_is_unambiguous(identifier) {
                return Err(HvfError::VcpuOwnershipCollision(identifier));
            }
        }
        let _sdk_call = handle_state
            .sdk_call
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = ownership
            .active
            .iter()
            .find(|record| {
                record.identifier == identifier
                    && record.generation == generation
                    && Arc::ptr_eq(&record.handle_state, handle_state)
            })
            .ok_or(HvfError::VcpuNotLive)?;
        if record.owner != current {
            return Err(HvfError::VcpuWrongOwner { identifier });
        }
        if record.handle_state.load(Ordering::Acquire) != VCPU_HANDLE_LIVE {
            return Err(HvfError::VcpuNotLive);
        }
        if !ownership.identifier_is_unambiguous(identifier) {
            return Err(HvfError::VcpuOwnershipCollision(identifier));
        }
        operation.mark_hvf_published()?;
        handle_state.store(VCPU_HANDLE_CLOSING, Ordering::Release);
        drop(ownership);
        Ok(unsafe { litebox_hvf_vcpu_destroy(identifier) })
    }

    pub(crate) fn poison(&self) {
        let deadline = Instant::now().checked_add(OPERATION_WAIT_TIMEOUT);
        let current = std::thread::current().id();
        let mut state = self
            .operation_gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.poisoned {
            return;
        }
        // An exclusive/cleanup or shared operation may call this while its
        // body still owns finer-grained memory locks. Publishing the request
        // closes normal admission immediately, but waiting here could deadlock
        // with a shared operation that was admitted earlier and is blocked on
        // one of those locks. The outermost admission finish performs the
        // bounded drain after the body and its guards have gone out of scope.
        let vm = std::ptr::from_ref::<HvfVm>(self) as usize;
        let (operation_depth, shared_depth) = HVF_OPERATION_STATE.with(|cell| {
            let thread = cell.get();
            if thread.vm == vm {
                (thread.total_depth, thread.shared_depth)
            } else {
                (0, 0)
            }
        });
        let owns_active_vcpu = state.active_vcpu_owners.contains(&current);
        if operation_depth != 0 || owns_active_vcpu {
            state.poison_requested = true;
            self.operation_gate.idle.notify_all();
            return;
        }
        state.poison_requested = true;
        self.operation_gate.idle.notify_all();
        while !state.poisoned
            && (state.owner.as_ref().is_some_and(|owner| *owner != current)
                || state
                    .active_vcpu_owners
                    .iter()
                    .any(|owner| *owner != current)
                || state.shared > shared_depth)
        {
            let Some(deadline) = deadline else {
                state.poison_requested = false;
                state.poisoned = true;
                self.operation_gate.abandoned.store(true, Ordering::Release);
                self.cleanup_required.store(true, Ordering::Release);
                self.operation_gate.idle.notify_all();
                return;
            };
            let (next, timed_out) = self.wait_for_operation_state(state, deadline);
            state = next;
            // Another poison caller may have terminalized cleanly while this
            // caller slept. That terminal state wins even when this caller's
            // own deadline expired at the same wakeup; post-poison cleanup is
            // allowed to acquire the exclusive owner and must not be mistaken
            // for a still-undrained pre-poison operation.
            if state.poisoned {
                return;
            }
            if timed_out {
                state.poison_requested = false;
                state.poisoned = true;
                self.operation_gate.abandoned.store(true, Ordering::Release);
                self.cleanup_required.store(true, Ordering::Release);
                self.operation_gate.idle.notify_all();
                return;
            }
        }
        if state.poisoned {
            return;
        }
        state.poison_requested = false;
        state.poisoned = true;
        self.operation_gate.idle.notify_all();
    }

    pub(crate) fn create_vcpu(&'static self) -> Result<HvfVcpu, HvfError> {
        self.with_capability_operation(|operation| {
            self.require_vcpu_creation_admitted()?;
            let reservation = self.begin_vcpu_creation()?;
            let creation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                with_vcpu_configuration(|config| {
                    let configured_features = HvfFeatureRegisters::from_vcpu_configuration(config)?;
                    if let Some(error) = configured_features.changed_from(&self.admitted_features) {
                        return Err(error);
                    }
                    let (identifier, exit_area, mut creation_guard) =
                        self.create_registered_vcpu(operation, &reservation, config)?;
                    let validation = NonNull::new(exit_area)
                        .ok_or(HvfError::NullVcpuExitArea)
                        .and_then(|exit_area| {
                            configured_features
                                .verify_after_vcpu_create(identifier, config)
                                .map(|()| exit_area)
                        });
                    let exit_area = match validation {
                        Ok(exit_area) => exit_area,
                        Err(trigger) => {
                            creation_guard.disarm();
                            return self.reject_vcpu(
                                operation,
                                identifier,
                                reservation.token,
                                reservation.owner,
                                &reservation.handle_state,
                                trigger,
                            );
                        }
                    };
                    let vcpu = HvfVcpu {
                        identifier,
                        generation: reservation.token,
                        exit_area,
                        features: configured_features,
                        vm: self,
                        owner: reservation.owner,
                        handle_state: Arc::clone(&reservation.handle_state),
                        live: true,
                        not_send: PhantomData,
                    };
                    creation_guard.disarm();
                    Ok(vcpu)
                })
            }));
            match creation {
                Ok(result) => {
                    self.cancel_unbound_vcpu_creation(&reservation);
                    result
                }
                Err(payload) => {
                    self.cancel_unbound_vcpu_creation(&reservation);
                    std::panic::resume_unwind(payload);
                }
            }
        })
    }

    fn begin_vcpu_creation(&self) -> Result<HvfVcpuCreationReservation, HvfError> {
        let owner = std::thread::current().id();
        let handle_state = Arc::new(HvfVcpuControl::new());
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let admitted = ownership
            .pending
            .len()
            .checked_add(ownership.active.len())
            .and_then(|count| count.checked_add(ownership.quarantined.len()))
            .ok_or(HvfError::ResidualAccounting)?;
        if admitted >= self.report.max_vcpu_count as usize
            || ownership.pending.len() == ownership.pending.capacity()
            || ownership.active.len() == ownership.active.capacity()
            || ownership.quarantined.len() == ownership.quarantined.capacity()
        {
            return Err(HvfError::ResourceReservation("vCPU admission"));
        }
        let token = ownership.next_token;
        ownership.next_token = token
            .checked_add(1)
            .ok_or(HvfError::ResourceReservation("vCPU creation token"))?;
        ownership.pending.push(HvfPendingVcpu {
            token,
            owner,
            identifier: None,
            cleanup_code: None,
            handle_state: Arc::clone(&handle_state),
        });
        Ok(HvfVcpuCreationReservation {
            token,
            owner,
            handle_state,
        })
    }

    fn create_registered_vcpu<'vm>(
        &'vm self,
        operation: &HvfVmOperation<'_>,
        reservation: &HvfVcpuCreationReservation,
        config: NonNull<c_void>,
    ) -> Result<(u64, *mut c_void, HvfVcpuCreationGuard<'vm>), HvfError> {
        operation.mark_published()?;
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = ownership.pending.iter().position(|pending| {
            pending.token == reservation.token
                && pending.owner == reservation.owner
                && Arc::ptr_eq(&pending.handle_state, &reservation.handle_state)
        }) else {
            return Err(HvfError::ResidualAccounting);
        };
        if ownership.pending[index].identifier.is_some()
            || ownership.pending[index].cleanup_code.is_some()
            || ownership.pending[index]
                .handle_state
                .load(Ordering::Acquire)
                != VCPU_HANDLE_LIVE
        {
            return Err(HvfError::ResidualAccounting);
        }

        let mut identifier = 0;
        let mut exit_area = core::ptr::null_mut();
        let create = unsafe {
            litebox_hvf_vcpu_create(&raw mut identifier, &raw mut exit_area, config.as_ptr())
        };
        if !succeeded(create) {
            return Err(HvfError::Call {
                operation: "hv_vcpu_create",
                code: create,
            });
        }

        // Publish the SDK identifier into its preallocated exact-identity row
        // before releasing the registry lock. Every identifier-only mutation
        // takes this same lock and treats any still-unbound row as ambiguous.
        ownership.pending[index].identifier = Some(identifier);
        let guard = HvfVcpuCreationGuard::new(self, reservation, identifier);
        if !ownership.identifier_is_unambiguous(identifier) {
            ownership.pending[index]
                .handle_state
                .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            drop(ownership);
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
            return Err(HvfError::VcpuOwnershipCollision(identifier));
        }
        if ownership.active.len() == ownership.active.capacity() {
            ownership.pending[index]
                .handle_state
                .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            drop(ownership);
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
            return Err(HvfError::ResourceReservation("active vCPU registry"));
        }
        let pending = ownership.pending.remove(index);
        ownership.active.push(HvfOwnedVcpu {
            identifier,
            generation: pending.token,
            owner: pending.owner,
            handle_state: pending.handle_state,
        });
        drop(ownership);
        Ok((identifier, exit_area, guard))
    }

    fn cancel_unbound_vcpu_creation(&self, reservation: &HvfVcpuCreationReservation) {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(index) = ownership.pending.iter().position(|pending| {
            pending.token == reservation.token
                && pending.owner == reservation.owner
                && Arc::ptr_eq(&pending.handle_state, &reservation.handle_state)
        }) else {
            return;
        };
        if ownership.pending[index].identifier.is_some() {
            return;
        }
        ownership.pending.remove(index);
        reservation
            .handle_state
            .store(VCPU_HANDLE_CLOSED, Ordering::Release);
    }

    fn settle_abandoned_vcpu_creation(
        &self,
        token: u64,
        owner: std::thread::ThreadId,
        identifier: u64,
        handle_state: &Arc<HvfVcpuControl>,
    ) {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending_index = ownership.pending.iter().position(|pending| {
            pending.token == token
                && pending.owner == owner
                && Arc::ptr_eq(&pending.handle_state, handle_state)
        });
        let active_index = ownership.active.iter().position(|record| {
            record.identifier == identifier
                && record.generation == token
                && record.owner == owner
                && Arc::ptr_eq(&record.handle_state, handle_state)
        });
        if pending_index.is_some() == active_index.is_some() {
            handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            drop(ownership);
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
            return;
        }
        if let Some(index) = pending_index {
            match ownership.pending[index].identifier {
                None => ownership.pending[index].identifier = Some(identifier),
                Some(bound) if bound == identifier => {}
                Some(_) => {
                    ownership.pending[index]
                        .handle_state
                        .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                    drop(ownership);
                    self.cleanup_required.store(true, Ordering::Release);
                    self.request_poison_nonblocking();
                    return;
                }
            }
        }
        if !ownership.identifier_is_unambiguous(identifier) {
            handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            drop(ownership);
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
            return;
        }

        handle_state.store(VCPU_HANDLE_CLOSING, Ordering::Release);
        let cleanup = unsafe { litebox_hvf_vcpu_destroy(identifier) };
        if succeeded(cleanup) {
            if let Some(index) = pending_index {
                let record = ownership.pending.remove(index);
                record
                    .handle_state
                    .store(VCPU_HANDLE_CLOSED, Ordering::Release);
            } else if let Some(index) = active_index {
                let record = ownership.active.remove(index);
                record
                    .handle_state
                    .store(VCPU_HANDLE_CLOSED, Ordering::Release);
            }
            return;
        }
        if let Some(index) = pending_index {
            ownership.pending[index].cleanup_code = Some(cleanup);
        }
        handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
        drop(ownership);
        self.cleanup_required.store(true, Ordering::Release);
        self.request_poison_nonblocking();
    }

    fn record_vcpu_cleanup(
        &self,
        identifier: u64,
        generation: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<HvfVcpuControl>,
        cleanup_code: Option<HvReturn>,
    ) -> Result<(), HvfError> {
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let matches_capability = |record: &HvfQuarantinedVcpu| {
            record.identifier == identifier
                && record.generation == generation
                && record.owner == owner
                && Arc::ptr_eq(&record.handle_state, handle_state)
        };
        let quarantine_index = ownership.quarantined.iter().position(matches_capability);
        if cleanup_code.is_some()
            && quarantine_index.is_none()
            && ownership.quarantined.len() == ownership.quarantined.capacity()
        {
            handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            self.cleanup_required.store(true, Ordering::Release);
            return Err(HvfError::ResourceReservation("vCPU quarantine migration"));
        }
        ownership.active.retain(|record| {
            !(record.identifier == identifier
                && record.generation == generation
                && record.owner == owner
                && Arc::ptr_eq(&record.handle_state, handle_state))
        });
        ownership.pending.retain(|record| {
            !(record.token == generation
                && record.owner == owner
                && Arc::ptr_eq(&record.handle_state, handle_state))
        });
        if let Some(cleanup_code) = cleanup_code {
            handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            if let Some(index) = quarantine_index {
                ownership.quarantined[index].cleanup_code = Some(cleanup_code);
            } else {
                ownership.quarantined.push(HvfQuarantinedVcpu {
                    identifier,
                    generation,
                    owner,
                    cleanup_code: Some(cleanup_code),
                    handle_state: Arc::clone(handle_state),
                });
            }
        } else {
            handle_state.store(VCPU_HANDLE_CLOSED, Ordering::Release);
            ownership
                .quarantined
                .retain(|record| !matches_capability(record));
        }
        Ok(())
    }

    fn quarantine_vcpu_without_cleanup(
        &self,
        identifier: u64,
        generation: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<HvfVcpuControl>,
    ) -> Result<(), HvfError> {
        if std::thread::current().id() != owner {
            return Err(HvfError::VcpuWrongOwner { identifier });
        }
        let mut ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let already_quarantined = ownership.quarantined.iter().any(|record| {
            record.identifier == identifier
                && record.generation == generation
                && record.owner == owner
                && Arc::ptr_eq(&record.handle_state, handle_state)
        });
        if !already_quarantined && ownership.quarantined.len() == ownership.quarantined.capacity() {
            handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
            self.cleanup_required.store(true, Ordering::Release);
            return Err(HvfError::ResourceReservation("vCPU quarantine migration"));
        }
        ownership.active.retain(|record| {
            !(record.identifier == identifier
                && record.generation == generation
                && record.owner == owner
                && Arc::ptr_eq(&record.handle_state, handle_state))
        });
        handle_state.store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
        if !already_quarantined {
            ownership.quarantined.push(HvfQuarantinedVcpu {
                identifier,
                generation,
                owner,
                cleanup_code: None,
                handle_state: Arc::clone(handle_state),
            });
        }
        drop(ownership);
        self.cleanup_required.store(true, Ordering::Release);
        self.request_poison_nonblocking();
        Ok(())
    }

    fn reject_vcpu<T>(
        &self,
        operation: &HvfVmOperation<'_>,
        identifier: u64,
        generation: u64,
        owner: std::thread::ThreadId,
        handle_state: &Arc<HvfVcpuControl>,
        trigger: HvfError,
    ) -> Result<T, HvfError> {
        let cleanup =
            match self.destroy_registered_vcpu(operation, identifier, generation, handle_state) {
                Ok(cleanup) => cleanup,
                Err(failure) => {
                    let failure = match self.quarantine_vcpu_without_cleanup(
                        identifier,
                        generation,
                        owner,
                        handle_state,
                    ) {
                        Ok(()) => failure,
                        Err(quarantine) => HvfError::vcpu_quarantine(failure, quarantine),
                    };
                    self.request_poison_nonblocking();
                    return Err(HvfError::vcpu_quarantine(trigger, failure));
                }
            };
        if succeeded(cleanup) {
            match self.record_vcpu_cleanup(identifier, generation, owner, handle_state, None) {
                Ok(()) => Err(trigger),
                Err(accounting) => Err(HvfError::vcpu_quarantine(trigger, accounting)),
            }
        } else {
            let accounting = self
                .record_vcpu_cleanup(identifier, generation, owner, handle_state, Some(cleanup))
                .err();
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
            Err(HvfError::vcpu_cleanup(trigger, cleanup, accounting))
        }
    }

    pub(crate) fn active_vcpu_count(&self) -> usize {
        self.vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .iter()
            .filter(|record| {
                matches!(
                    record.handle_state.load(Ordering::Acquire),
                    VCPU_HANDLE_LIVE | VCPU_HANDLE_CLOSING
                )
            })
            .count()
    }

    pub(crate) fn active_vcpu_count_for_current_thread(&self) -> usize {
        let current = std::thread::current().id();
        self.vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .iter()
            .filter(|record| {
                record.owner == current
                    && matches!(
                        record.handle_state.load(Ordering::Acquire),
                        VCPU_HANDLE_LIVE | VCPU_HANDLE_CLOSING
                    )
            })
            .count()
    }

    pub(crate) fn quarantined_vcpu_count(&self) -> usize {
        let ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ownership.quarantined.len()
            + ownership
                .pending
                .iter()
                .filter(|record| {
                    record.identifier.is_some()
                        && record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_RETRY_QUEUED
                })
                .count()
            + ownership
                .active
                .iter()
                .filter(|record| {
                    record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_RETRY_QUEUED
                })
                .count()
    }

    pub(crate) fn quarantined_vcpu_count_for_current_thread(&self) -> usize {
        let current = std::thread::current().id();
        let ownership = self
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ownership
            .quarantined
            .iter()
            .filter(|record| record.owner == current)
            .count()
            + ownership
                .pending
                .iter()
                .filter(|record| {
                    record.owner == current
                        && record.identifier.is_some()
                        && record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_RETRY_QUEUED
                })
                .count()
            + ownership
                .active
                .iter()
                .filter(|record| {
                    record.owner == current
                        && record.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_RETRY_QUEUED
                })
                .count()
    }

    pub(crate) fn retry_quarantined_vcpus_for_current_thread(&self) -> Result<usize, HvfError> {
        self.with_cleanup_operation(|operation| {
            let current = std::thread::current().id();
            let mut ownership = self
                .vcpu_ownership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut released = 0;
            let mut first_failure = None;

            let mut index = ownership.pending.len();
            while index != 0 {
                index -= 1;
                let Some(identifier) = ownership.pending[index].identifier else {
                    continue;
                };
                if ownership.pending[index].owner != current
                    || ownership.pending[index]
                        .handle_state
                        .load(Ordering::Acquire)
                        != VCPU_HANDLE_RETRY_QUEUED
                {
                    continue;
                }
                if !ownership.identifier_is_unambiguous(identifier) {
                    first_failure.get_or_insert(HvfError::VcpuOwnershipCollision(identifier));
                    continue;
                }
                if let Err(error) = operation.mark_published() {
                    first_failure.get_or_insert(error);
                    break;
                }
                ownership.pending[index].cleanup_code = None;
                ownership.pending[index]
                    .handle_state
                    .store(VCPU_HANDLE_CLOSING, Ordering::Release);
                let result = unsafe { litebox_hvf_vcpu_destroy(identifier) };
                if succeeded(result) {
                    let record = ownership.pending.remove(index);
                    record
                        .handle_state
                        .store(VCPU_HANDLE_CLOSED, Ordering::Release);
                    checked_residual_add(&mut released, 1)?;
                } else {
                    first_failure.get_or_insert(HvfError::Call {
                        operation: "hv_vcpu_destroy",
                        code: result,
                    });
                    ownership.pending[index].cleanup_code = Some(result);
                    ownership.pending[index]
                        .handle_state
                        .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                }
            }

            let mut index = ownership.quarantined.len();
            while index != 0 {
                index -= 1;
                if ownership.quarantined[index].owner != current {
                    continue;
                }
                let identifier = ownership.quarantined[index].identifier;
                if !ownership.identifier_is_unambiguous(identifier) {
                    first_failure.get_or_insert(HvfError::VcpuOwnershipCollision(identifier));
                    continue;
                }
                if let Err(error) = operation.mark_published() {
                    first_failure.get_or_insert(error);
                    break;
                }
                ownership.quarantined[index].cleanup_code = None;
                ownership.quarantined[index]
                    .handle_state
                    .store(VCPU_HANDLE_CLOSING, Ordering::Release);
                let result =
                    unsafe { litebox_hvf_vcpu_destroy(ownership.quarantined[index].identifier) };
                if succeeded(result) {
                    let record = ownership.quarantined.remove(index);
                    record
                        .handle_state
                        .store(VCPU_HANDLE_CLOSED, Ordering::Release);
                    checked_residual_add(&mut released, 1)?;
                } else {
                    first_failure.get_or_insert(HvfError::Call {
                        operation: "hv_vcpu_destroy",
                        code: result,
                    });
                    ownership.quarantined[index].cleanup_code = Some(result);
                    ownership.quarantined[index]
                        .handle_state
                        .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                }
            }

            let mut index = ownership.active.len();
            while index != 0 {
                index -= 1;
                if ownership.active[index].owner != current
                    || ownership.active[index].handle_state.load(Ordering::Acquire)
                        != VCPU_HANDLE_RETRY_QUEUED
                {
                    continue;
                }
                let identifier = ownership.active[index].identifier;
                if !ownership.identifier_is_unambiguous(identifier) {
                    first_failure.get_or_insert(HvfError::VcpuOwnershipCollision(identifier));
                    continue;
                }
                if let Err(error) = operation.mark_published() {
                    first_failure.get_or_insert(error);
                    break;
                }
                ownership.active[index]
                    .handle_state
                    .store(VCPU_HANDLE_CLOSING, Ordering::Release);
                let result =
                    unsafe { litebox_hvf_vcpu_destroy(ownership.active[index].identifier) };
                if succeeded(result) {
                    let record = ownership.active.remove(index);
                    record
                        .handle_state
                        .store(VCPU_HANDLE_CLOSED, Ordering::Release);
                    checked_residual_add(&mut released, 1)?;
                } else {
                    first_failure.get_or_insert(HvfError::Call {
                        operation: "hv_vcpu_destroy",
                        code: result,
                    });
                    ownership.active[index]
                        .handle_state
                        .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                }
            }
            match first_failure {
                Some(error) => Err(error),
                None => Ok(released),
            }
        })
    }

    /// Maps a host virtual range into the process-global VM.
    ///
    /// # Safety
    ///
    /// The caller must keep every byte in `host_range` allocated at the same
    /// virtual address until this mapping token is explicitly closed or its
    /// exact per-resource quarantine record reports every fragment absent.
    pub(crate) unsafe fn map_host_range(
        &self,
        host_range: Range<usize>,
        ipa: u64,
        permissions: HvfMapPermissions,
    ) -> Result<HvfMapping<'_>, HvfError> {
        self.with_capability_operation(|operation| {
            let length = host_range
                .end
                .checked_sub(host_range.start)
                .ok_or(HvfError::EmptyMapping)?;
            if length == 0 {
                return Err(HvfError::EmptyMapping);
            }
            if permissions.contains(HvfMapPermissions::WRITE)
                && permissions.contains(HvfMapPermissions::EXECUTE)
            {
                return Err(HvfError::WriteExecuteMapping);
            }
            if !host_range.start.is_multiple_of(HVF_PAGE_SIZE)
                || !length.is_multiple_of(HVF_PAGE_SIZE)
                || !ipa.is_multiple_of(HVF_PAGE_SIZE as u64)
            {
                return Err(HvfError::MappingUnaligned {
                    host_address: host_range.start,
                    ipa,
                    length,
                });
            }
            let ipa_limit = 1u64 << self.report.configured_ipa_bits;
            let ipa_end = ipa
                .checked_add(length as u64)
                .ok_or(HvfError::MappingOutOfRange {
                    ipa,
                    length,
                    ipa_bits: self.report.configured_ipa_bits,
                })?;
            if ipa_end > ipa_limit {
                return Err(HvfError::MappingOutOfRange {
                    ipa,
                    length,
                    ipa_bits: self.report.configured_ipa_bits,
                });
            }

            let mut fragments = Vec::new();
            let mut cursor = host_range.start;
            for region in host_regions_from(host_range.start) {
                if region.end <= cursor {
                    continue;
                }
                if region.start > cursor {
                    break;
                }
                let fragment_end = region.end.min(host_range.end);
                fragments
                    .try_reserve(1)
                    .map_err(|_| HvfError::ResourceReservation("mapping fragments"))?;
                fragments.push(HvfMappingFragment {
                    ipa: ipa + (cursor - host_range.start) as u64,
                    length: fragment_end - cursor,
                    state: HvfMappingFragmentState::NotMapped,
                    last_unmap_error: None,
                });
                cursor = fragment_end;
                if cursor == host_range.end {
                    break;
                }
            }
            if cursor != host_range.end {
                return Err(HvfError::HostRangeGap(cursor));
            }

            let mut registry = self
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let token = registry.next_token;
            registry.next_token = token
                .checked_add(1)
                .ok_or(HvfError::MappingTokenExhausted)?;
            let handle_state = Arc::new(AtomicU8::new(MAPPING_HANDLE_LIVE));
            let previous = registry.records.insert(
                token,
                HvfMappingRecord {
                    token,
                    host_range: host_range.clone(),
                    ipa,
                    permissions,
                    permissions_unknown: false,
                    fragments,
                    lifecycle: HvfMappingLifecycle::Provisioning,
                    handle_state: Arc::clone(&handle_state),
                },
            );
            debug_assert!(previous.is_none(), "mapping tokens are never reused");

            let mut mapping_error = None;
            {
                let Some(record) = registry.records.get_mut(&token) else {
                    return Err(HvfError::ResidualAccounting);
                };
                for fragment in &mut record.fragments {
                    let host_address =
                        host_range.start + TruncateExt::<usize>::trunc(fragment.ipa - ipa);
                    if let Err(error) = operation.mark_published() {
                        mapping_error = Some(error);
                        break;
                    }
                    let result = unsafe {
                        litebox_hvf_vm_map(
                            host_address as *mut c_void,
                            fragment.ipa,
                            fragment.length,
                            permissions.0,
                        )
                    };
                    if !succeeded(result) {
                        mapping_error = Some(HvfError::Call {
                            operation: "hv_vm_map",
                            code: result,
                        });
                        break;
                    }
                    fragment.state = HvfMappingFragmentState::KnownPresent;
                }
            }

            if let Some(trigger) = mapping_error {
                let cleanup = match registry.records.get_mut(&token) {
                    Some(record) => {
                        Self::unmap_mapping_record(operation, record).and_then(|failure| {
                            match failure {
                                Some(code) => Err(HvfError::Call {
                                    operation: "hv_vm_unmap",
                                    code,
                                }),
                                None => Ok(()),
                            }
                        })
                    }
                    None => Err(HvfError::ResidualAccounting),
                };
                let residual =
                    Self::finalize_failed_mapping_record(&mut registry, token, &handle_state);
                drop(registry);
                if residual {
                    self.cleanup_required.store(true, Ordering::Release);
                    self.poison();
                }
                return match cleanup {
                    Ok(()) => Err(trigger),
                    Err(cleanup) => Err(HvfError::MappingFinalization {
                        token,
                        trigger: Box::new(trigger),
                        cleanup: Box::new(cleanup),
                    }),
                };
            }

            let fragment_count = {
                let Some(record) = registry.records.get_mut(&token) else {
                    return Err(HvfError::ResidualAccounting);
                };
                record.lifecycle = HvfMappingLifecycle::Live;
                record.fragments.len()
            };
            drop(registry);
            Ok(HvfMapping {
                vm: self,
                token,
                host_range,
                ipa,
                permissions,
                fragment_count,
                handle_state,
                live: true,
            })
        })
    }

    fn finalize_failed_mapping_record(
        registry: &mut HvfMappingRegistry,
        token: u64,
        handle_state: &Arc<AtomicU8>,
    ) -> bool {
        // A record that cannot be found cannot be proven absent, so the
        // conservative answer retains residual custody and lets the caller
        // poison, exactly as a still-present dirty record would.
        let residual = match registry.records.get_mut(&token) {
            Some(record) => {
                let residual = record.fragments.iter().any(|fragment| {
                    matches!(
                        fragment.state,
                        HvfMappingFragmentState::KnownPresent
                            | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
                    )
                });
                if residual {
                    record.lifecycle = HvfMappingLifecycle::Quarantined;
                    handle_state.store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
                }
                residual
            }
            None => true,
        };
        if !residual && let Some(record) = registry.records.remove(&token) {
            record
                .handle_state
                .store(MAPPING_HANDLE_CLOSED, Ordering::Release);
        }
        residual
    }

    fn unmap_mapping_record(
        operation: &HvfVmOperation<'_>,
        record: &mut HvfMappingRecord,
    ) -> Result<Option<HvReturn>, HvfError> {
        let mut first_failure = None;
        for fragment in record.fragments.iter_mut().rev() {
            if !matches!(
                fragment.state,
                HvfMappingFragmentState::KnownPresent
                    | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
            ) {
                continue;
            }
            if let Err(error) = operation.mark_published() {
                return Err(match first_failure {
                    Some(code) => HvfError::MappingFinalization {
                        token: record.token,
                        trigger: Box::new(HvfError::Call {
                            operation: "hv_vm_unmap",
                            code,
                        }),
                        cleanup: Box::new(error),
                    },
                    None => error,
                });
            }
            let result = unsafe { litebox_hvf_vm_unmap(fragment.ipa, fragment.length) };
            if succeeded(result) {
                fragment.state = HvfMappingFragmentState::Absent;
                fragment.last_unmap_error = None;
            } else {
                fragment.state = HvfMappingFragmentState::UnknownAfterFailedExactUnmap;
                fragment.last_unmap_error = Some(result);
                if first_failure.is_none() {
                    first_failure = Some(result);
                }
            }
        }
        Ok(first_failure)
    }

    /// Marks the record for `token` quarantined and retry-queued. Every
    /// caller proves the record's presence under the same lock first, so a
    /// missing record is unreachable; if it ever happened, the caller's
    /// `cleanup_required` + poison path remains the fail-safe.
    fn quarantine_mapping_record_locked(registry: &mut HvfMappingRegistry, token: u64) {
        if let Some(record) = registry.records.get_mut(&token) {
            record.lifecycle = HvfMappingLifecycle::Quarantined;
            record
                .handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
        }
    }

    fn cleanup_mapping_token(
        &self,
        operation: &HvfVmOperation<'_>,
        token: u64,
    ) -> Result<usize, HvfError> {
        let mut registry = self
            .mapping_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(record) = registry.records.get(&token) else {
            return Err(HvfError::MappingTokenMissing(token));
        };
        if record.lifecycle == HvfMappingLifecycle::Provisioning
            || !matches!(
                record.handle_state.load(Ordering::Acquire),
                MAPPING_HANDLE_CLOSING | MAPPING_HANDLE_RETRY_QUEUED
            )
        {
            return Err(HvfError::MappingNotLive);
        }
        let before = record
            .fragments
            .iter()
            .filter(|fragment| {
                matches!(
                    fragment.state,
                    HvfMappingFragmentState::KnownPresent
                        | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
                )
            })
            .count();
        let Some(record) = registry.records.get_mut(&token) else {
            return Err(HvfError::ResidualAccounting);
        };
        let failure = match Self::unmap_mapping_record(operation, record) {
            Ok(failure) => failure,
            Err(trigger) => {
                Self::quarantine_mapping_record_locked(&mut registry, token);
                drop(registry);
                self.cleanup_required.store(true, Ordering::Release);
                self.request_poison_nonblocking();
                return Err(HvfError::mapping_cleanup(token, trigger));
            }
        };
        let Some(record) = registry.records.get(&token) else {
            return Err(HvfError::ResidualAccounting);
        };
        let after = record
            .fragments
            .iter()
            .filter(|fragment| {
                matches!(
                    fragment.state,
                    HvfMappingFragmentState::KnownPresent
                        | HvfMappingFragmentState::UnknownAfterFailedExactUnmap
                )
            })
            .count();
        let Some(released) = before.checked_sub(after) else {
            Self::quarantine_mapping_record_locked(&mut registry, token);
            drop(registry);
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
            return Err(HvfError::mapping_cleanup(
                token,
                HvfError::ResidualAccounting,
            ));
        };
        if after == 0 {
            if let Err(trigger) = operation.mark_published() {
                Self::quarantine_mapping_record_locked(&mut registry, token);
                drop(registry);
                self.cleanup_required.store(true, Ordering::Release);
                self.request_poison_nonblocking();
                return Err(HvfError::mapping_cleanup(token, trigger));
            }
            if let Some(record) = registry.records.remove(&token) {
                record
                    .handle_state
                    .store(MAPPING_HANDLE_CLOSED, Ordering::Release);
            }
        } else {
            Self::quarantine_mapping_record_locked(&mut registry, token);
        }
        drop(registry);
        if after != 0 {
            self.cleanup_required.store(true, Ordering::Release);
            self.request_poison_nonblocking();
        }
        if let Some(code) = failure {
            Err(HvfError::mapping_cleanup(
                token,
                HvfError::Call {
                    operation: "hv_vm_unmap",
                    code,
                },
            ))
        } else {
            Ok(released)
        }
    }

    pub(crate) fn residual_report(&self) -> Result<HvfSdkResidualReport, HvfError> {
        self.with_cleanup_operation(|_| {
            let current = std::thread::current().id();
            let (zero_vcpu_operation_active, zero_vcpu_owned_by_current_thread) = {
                let state = self
                    .operation_gate
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match (state.zero_vcpu_owner.as_ref(), state.zero_vcpu_depth) {
                    (None, 0) => (false, false),
                    (Some(owner), 1) => (true, *owner == current),
                    _ => return Err(HvfError::ResidualAccounting),
                }
            };
            let mut report = HvfSdkResidualReport {
                zero_vcpu_operation_active,
                zero_vcpu_owned_by_current_thread,
                ..HvfSdkResidualReport::default()
            };
            {
                let registry = self
                    .mapping_registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for record in registry.records.values() {
                    match (
                        record.lifecycle,
                        record.handle_state.load(Ordering::Acquire),
                    ) {
                        (
                            HvfMappingLifecycle::Provisioning | HvfMappingLifecycle::Live,
                            MAPPING_HANDLE_LIVE,
                        )
                        | (
                            HvfMappingLifecycle::Quarantined,
                            MAPPING_HANDLE_CLOSING | MAPPING_HANDLE_RETRY_QUEUED,
                        ) => {}
                        _ => return Err(HvfError::ResidualAccounting),
                    }
                    let bytes = record
                        .host_range
                        .end
                        .checked_sub(record.host_range.start)
                        .ok_or(HvfError::ResidualAccounting)?;
                    if bytes == 0
                        || !record.host_range.start.is_multiple_of(HVF_PAGE_SIZE)
                        || !bytes.is_multiple_of(HVF_PAGE_SIZE)
                        || !record.ipa.is_multiple_of(HVF_PAGE_SIZE as u64)
                    {
                        return Err(HvfError::ResidualAccounting);
                    }
                    let ipa_end = record
                        .ipa
                        .checked_add(
                            u64::try_from(bytes).map_err(|_| HvfError::ResidualAccounting)?,
                        )
                        .ok_or(HvfError::ResidualAccounting)?;
                    checked_residual_add(&mut report.logical_mapping_tokens, 1)?;
                    checked_residual_add(
                        &mut report.logical_mapping_fragments,
                        record.fragments.len(),
                    )?;
                    checked_residual_add(&mut report.logical_mapping_pages, bytes / HVF_PAGE_SIZE)?;
                    checked_residual_add(&mut report.logical_mapping_bytes, bytes)?;
                    if record.permissions_unknown {
                        checked_residual_add(&mut report.permissions_unknown_mapping_tokens, 1)?;
                    }
                    let mut fragment_cursor = record.ipa;
                    for fragment in &record.fragments {
                        if fragment.length == 0
                            || fragment.ipa != fragment_cursor
                            || !fragment.ipa.is_multiple_of(HVF_PAGE_SIZE as u64)
                            || !fragment.length.is_multiple_of(HVF_PAGE_SIZE)
                        {
                            return Err(HvfError::ResidualAccounting);
                        }
                        let fragment_end = fragment
                            .ipa
                            .checked_add(
                                u64::try_from(fragment.length)
                                    .map_err(|_| HvfError::ResidualAccounting)?,
                            )
                            .ok_or(HvfError::ResidualAccounting)?;
                        if fragment.ipa < record.ipa || fragment_end > ipa_end {
                            return Err(HvfError::ResidualAccounting);
                        }
                        fragment_cursor = fragment_end;
                        let (fragments, pages, bytes) = match fragment.state {
                            HvfMappingFragmentState::KnownPresent => (
                                &mut report.known_present_fragments,
                                &mut report.known_present_pages,
                                &mut report.known_present_bytes,
                            ),
                            HvfMappingFragmentState::UnknownAfterFailedExactUnmap => (
                                &mut report.unknown_fragments,
                                &mut report.unknown_pages,
                                &mut report.unknown_bytes,
                            ),
                            HvfMappingFragmentState::NotMapped
                            | HvfMappingFragmentState::Absent => continue,
                        };
                        checked_residual_add(fragments, 1)?;
                        checked_residual_add(pages, fragment.length / HVF_PAGE_SIZE)?;
                        checked_residual_add(bytes, fragment.length)?;
                    }
                    if fragment_cursor != ipa_end {
                        return Err(HvfError::ResidualAccounting);
                    }
                }
            }
            {
                let ownership = self
                    .vcpu_ownership
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for record in &ownership.pending {
                    checked_residual_add(&mut report.logical_vcpu_tokens, 1)?;
                    match (
                        record.identifier,
                        record.handle_state.load(Ordering::Acquire),
                        record.cleanup_code,
                    ) {
                        (None | Some(_), VCPU_HANDLE_LIVE, None) => {
                            checked_residual_add(&mut report.active_vcpus, 1)?;
                        }
                        (Some(_), VCPU_HANDLE_CLOSING | VCPU_HANDLE_RETRY_QUEUED, _) => {
                            checked_residual_add(&mut report.quarantined_vcpus, 1)?;
                        }
                        _ => return Err(HvfError::ResidualAccounting),
                    }
                }
                for record in &ownership.active {
                    checked_residual_add(&mut report.logical_vcpu_tokens, 1)?;
                    match record.handle_state.load(Ordering::Acquire) {
                        VCPU_HANDLE_LIVE | VCPU_HANDLE_CLOSING => {
                            checked_residual_add(&mut report.active_vcpus, 1)?;
                        }
                        VCPU_HANDLE_RETRY_QUEUED => {
                            checked_residual_add(&mut report.quarantined_vcpus, 1)?;
                        }
                        _ => return Err(HvfError::ResidualAccounting),
                    }
                }
                for record in &ownership.quarantined {
                    if ownership
                        .active
                        .iter()
                        .any(|active| active.identifier == record.identifier)
                    {
                        return Err(HvfError::ResidualAccounting);
                    }
                    checked_residual_add(&mut report.logical_vcpu_tokens, 1)?;
                    match record.handle_state.load(Ordering::Acquire) {
                        VCPU_HANDLE_CLOSING | VCPU_HANDLE_RETRY_QUEUED => {
                            checked_residual_add(&mut report.quarantined_vcpus, 1)?;
                        }
                        _ => return Err(HvfError::ResidualAccounting),
                    }
                }
            }
            Ok(report)
        })
    }

    pub(crate) fn mapping_token_has_residual(&self, token: u64) -> bool {
        self.mapping_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .contains_key(&token)
    }

    pub(crate) fn retry_quarantined_mapping(&self, token: u64) -> Result<usize, HvfError> {
        self.with_cleanup_operation(|operation| {
            let registry = self
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = registry.records.get(&token) else {
                return Ok(0);
            };
            if record.lifecycle != HvfMappingLifecycle::Quarantined
                && record.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_RETRY_QUEUED
            {
                return Err(HvfError::MappingNotLive);
            }
            drop(registry);
            self.cleanup_mapping_token(operation, token)
        })
    }

    pub(crate) fn retry_quarantined_mappings(&self) -> Result<usize, HvfError> {
        self.with_cleanup_operation(|operation| {
            let mut released = 0;
            let mut first_error = None;
            let mut after_token = None;
            loop {
                let token = {
                    let registry = self
                        .mapping_registry
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    // Tokens start at 1 and only ever increase, so excluding
                    // `after_token.unwrap_or(0)` reproduces the previous
                    // full-scan minimum exactly: the first match in ascending
                    // key order is the minimum token above `after_token`.
                    registry
                        .records
                        .range((Bound::Excluded(after_token.unwrap_or(0)), Bound::Unbounded))
                        .filter(|(_, record)| {
                            record.lifecycle == HvfMappingLifecycle::Quarantined
                                || record.handle_state.load(Ordering::Acquire)
                                    == MAPPING_HANDLE_RETRY_QUEUED
                        })
                        .map(|(token, _)| *token)
                        .next()
                };
                let Some(token) = token else {
                    break;
                };
                after_token = Some(token);
                match self.cleanup_mapping_token(operation, token) {
                    Ok(count) => checked_residual_add(&mut released, count)?,
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                }
            }
            if let Some(error) = first_error {
                Err(error)
            } else {
                Ok(released)
            }
        })
    }

    /// Failure injection for the owner-lane custody witness: the next `count`
    /// `hv_vcpu_destroy` calls fail with `HV_ERROR` before reaching the SDK,
    /// so the vCPU stays alive and a later owner-thread retry genuinely
    /// destroys it.  Returns the previously armed count.
    #[expect(
        clippy::unused_self,
        reason = "the injected-failure counter is process-global, but arming it is scoped to a VM handle"
    )]
    pub(crate) fn induce_vcpu_destroy_failures(&self, count: u32) -> u32 {
        // SAFETY: a process-global atomic counter with no preconditions.
        unsafe { litebox_hvf_inject_vcpu_destroy_failures(count) }
    }

    #[expect(
        clippy::unused_self,
        reason = "the injected-failure counter is process-global, but reading it is scoped to a VM handle"
    )]
    pub(crate) fn remaining_induced_vcpu_destroy_failures(&self) -> u32 {
        // SAFETY: a process-global atomic counter with no preconditions.
        unsafe { litebox_hvf_remaining_vcpu_destroy_failures() }
    }

    pub(crate) fn publish_executable_bytes(&self, bytes: &[u8]) -> Result<(), HvfError> {
        self.with_operation(|operation| {
            if !bytes.is_empty() {
                operation.mark_published()?;
            }
            publish_hvf_executable_bytes(bytes);
            Ok(())
        })
    }
}

static PROCESS_HVF_VM: OnceLock<Result<HvfVm, HvfError>> = OnceLock::new();
static PRODUCTION_VM_LIVE: AtomicBool = AtomicBool::new(false);

pub(crate) fn process_hvf_vm() -> Result<&'static HvfVm, HvfError> {
    let result = PROCESS_HVF_VM.get_or_init(|| {
        let _exclusive = super::HVF_SMOKE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if super::smoke_residual_is_live() {
            return Err(HvfError::SmokeResidualOwnership);
        }
        let vm = HvfVm::create();
        if vm.is_ok() {
            PRODUCTION_VM_LIVE.store(true, Ordering::Release);
        }
        vm
    });
    result.as_ref().map_err(Clone::clone)
}

pub fn hvf_boundary_probe() -> Result<HvfBoundaryReport, HvfError> {
    let vm = process_hvf_vm()?;
    vm.publish_executable_bytes(vm.monitor().bytes())?;
    let monitor_start = vm.monitor().bytes().as_ptr() as usize;
    let monitor_end = monitor_start + vm.monitor().bytes().len();
    let mapping = unsafe {
        vm.map_host_range(
            monitor_start..monitor_end,
            0,
            HvfMapPermissions::READ | HvfMapPermissions::EXECUTE,
        )
    }?;
    let monitor_mapping_fragments = mapping.fragment_count();
    mapping.unmap()?;

    let vcpu = vm.create_vcpu()?;
    let feature_registers = vcpu.features().clone();
    if let Err(trigger) = vcpu.destroy() {
        return match vm.retry_quarantined_vcpus_for_current_thread() {
            Ok(_) => Err(trigger),
            Err(cleanup) => Err(HvfError::vcpu_quarantine(trigger, cleanup)),
        };
    }
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "`HvfVmOperation::require_live` is not general enough over the operation's lifetime"
    )]
    vm.with_operation(|operation| operation.require_live())?;
    let sdk_residuals = vm.residual_report()?;
    if !sdk_residuals.is_empty() {
        return Err(HvfError::ResidualOwnership(sdk_residuals));
    }
    Ok(HvfBoundaryReport {
        vm: vm.report().clone(),
        monitor_mapping_fragments,
        feature_registers,
        sdk_residuals,
        vm_poisoned: vm.is_poisoned(),
    })
}

struct HvfPublishedPanicPayload;

/// Process-terminal witness for one admission class. Each class is selected by
/// a separate runner invocation because a correctly observed published panic
/// irreversibly poisons the process-global VM.
pub fn hvf_published_panic_probe(
    operation: HvfPublishedPanicOperation,
) -> Result<HvfPublishedPanicReport, HvfError> {
    let vm = process_hvf_vm()?;
    if vm.is_poisoned() || vm.active_vcpu_count() != 0 || vm.quarantined_vcpu_count() != 0 {
        return Err(HvfError::ResidualAccounting);
    }
    let mut vcpu = match operation {
        HvfPublishedPanicOperation::ExistingVcpu => Some(vm.create_vcpu()?),
        HvfPublishedPanicOperation::Exclusive | HvfPublishedPanicOperation::Shared => None,
    };

    let poison_latched = Arc::new(AtomicBool::new(false));
    let contender_attempted = Arc::new(AtomicBool::new(false));
    let owner_done = Arc::new(AtomicBool::new(false));
    let (owner_result, normal_admission_rejected) = std::thread::scope(|scope| {
        let contender_latched = Arc::clone(&poison_latched);
        let contender_attempt = Arc::clone(&contender_attempted);
        let contender_owner_done = Arc::clone(&owner_done);
        let contender = std::thread::Builder::new()
            .spawn_scoped(scope, move || {
                let deadline = Instant::now().checked_add(OPERATION_WAIT_TIMEOUT);
                while !contender_latched.load(Ordering::Acquire) {
                    if contender_owner_done.load(Ordering::Acquire)
                        || deadline.is_none_or(|deadline| Instant::now() >= deadline)
                    {
                        return false;
                    }
                    std::thread::yield_now();
                }
                contender_attempt.store(true, Ordering::Release);
                matches!(
                    vm.with_operation_timeout(Duration::ZERO, |_| Ok::<_, HvfError>(())),
                    Err(HvfError::Poisoned)
                )
            })
            .map_err(|_| HvfError::ResourceReservation("published-panic witness thread"))?;

        let observer_latched = Arc::clone(&poison_latched);
        let observer_attempt = Arc::clone(&contender_attempted);
        let observe_latch = move || {
            observer_latched.store(true, Ordering::Release);
            let deadline = Instant::now().checked_add(OPERATION_WAIT_TIMEOUT);
            while !observer_attempt.load(Ordering::Acquire) {
                if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
                    break;
                }
                std::thread::yield_now();
            }
        };
        let owner_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), HvfError> {
                match operation {
                    HvfPublishedPanicOperation::Exclusive => vm.with_operation_inner_observed(
                        false,
                        OPERATION_WAIT_TIMEOUT,
                        |operation| {
                            operation.mark_published()?;
                            publish_hvf_executable_bytes(vm.monitor().bytes());
                            std::panic::resume_unwind(Box::new(HvfPublishedPanicPayload));
                        },
                        observe_latch,
                    ),
                    HvfPublishedPanicOperation::Shared => vm.with_shared_operation_observed(
                        |operation| {
                            operation.mark_published()?;
                            publish_hvf_executable_bytes(vm.monitor().bytes());
                            std::panic::resume_unwind(Box::new(HvfPublishedPanicPayload));
                        },
                        observe_latch,
                    ),
                    HvfPublishedPanicOperation::ExistingVcpu => {
                        let vcpu = vcpu.as_mut().ok_or(HvfError::VcpuNotLive)?;
                        vcpu.with_existing_operation_observed(
                            |vcpu, operation| {
                                operation.mark_published()?;
                                check(
                                    "published-panic witness hv_vcpu_set_vtimer_offset",
                                    unsafe {
                                        litebox_hvf_vcpu_set_vtimer_offset(vcpu.identifier, 0)
                                    },
                                )?;
                                std::panic::resume_unwind(Box::new(HvfPublishedPanicPayload));
                            },
                            observe_latch,
                        )
                    }
                }
            }));
        owner_done.store(true, Ordering::Release);
        let normal_admission_rejected =
            contender.join().map_err(|_| HvfError::OperationAbandoned)?;
        Ok::<_, HvfError>((owner_result, normal_admission_rejected))
    })?;

    let original_payload_preserved = owner_result
        .as_ref()
        .err()
        .is_some_and(|payload| payload.is::<HvfPublishedPanicPayload>());
    let poison_latched_before_release = poison_latched.load(Ordering::Acquire);
    let contender_attempted = contender_attempted.load(Ordering::Acquire);
    let vcpu_destroyed_without_residual = match vcpu {
        Some(vcpu) => vcpu.destroy().is_ok(),
        None => true,
    };
    let cleanup_admitted_after_poison =
        vm.with_cleanup_operation(|_| Ok::<_, HvfError>(())).is_ok();
    let sdk_residuals = vm.residual_report()?;
    let report = HvfPublishedPanicReport {
        operation,
        original_payload_preserved,
        poison_latched_before_release,
        contender_attempted,
        normal_admission_rejected,
        cleanup_admitted_after_poison,
        vcpu_destroyed_without_residual,
        sdk_residuals,
        vm_poisoned: vm.is_poisoned(),
    };
    if !report.original_payload_preserved
        || !report.poison_latched_before_release
        || !report.contender_attempted
        || !report.normal_admission_rejected
        || !report.cleanup_admitted_after_poison
        || !report.vcpu_destroyed_without_residual
        || !report.sdk_residuals.is_empty()
        || !report.vm_poisoned
    {
        return Err(HvfError::PublishedPanicWitness(Box::new(report)));
    }
    Ok(report)
}

pub(super) fn production_vm_is_live() -> bool {
    PRODUCTION_VM_LIVE.load(Ordering::Acquire)
}

pub fn publish_hvf_executable_bytes(bytes: &[u8]) {
    if !bytes.is_empty() {
        unsafe {
            crate::darwin::sys_icache_invalidate(bytes.as_ptr().cast_mut().cast(), bytes.len());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvfMappingFragmentState {
    NotMapped,
    KnownPresent,
    Absent,
    UnknownAfterFailedExactUnmap,
}

#[derive(Clone, Copy, Debug)]
struct HvfMappingFragment {
    ipa: u64,
    length: usize,
    state: HvfMappingFragmentState,
    last_unmap_error: Option<HvReturn>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvfMappingLifecycle {
    Provisioning,
    Live,
    Quarantined,
}

const MAPPING_HANDLE_LIVE: u8 = 0;
const MAPPING_HANDLE_CLOSING: u8 = 1;
const MAPPING_HANDLE_CLOSED: u8 = 2;
const MAPPING_HANDLE_RETRY_QUEUED: u8 = 3;

struct HvfMappingRecord {
    token: u64,
    host_range: Range<usize>,
    ipa: u64,
    permissions: HvfMapPermissions,
    permissions_unknown: bool,
    fragments: Vec<HvfMappingFragment>,
    lifecycle: HvfMappingLifecycle,
    handle_state: Arc<std::sync::atomic::AtomicU8>,
}

/// The authoritative mapping ledger, keyed by each record's own token.
///
/// A `BTreeMap` keyed on the monotonically allocated token keeps every
/// per-mutation lookup, insertion, and removal at O(log N) in the number of
/// live records -- the `Vec` it replaces turned every `unmap`/`protect`/
/// completion-validation into an O(N) scan plus an O(N) removal shift, which
/// dominated guest spawn latency once idle processes held many mappings.
///
/// Iteration order is ascending token, which is exactly the insertion order
/// the replaced `Vec` always had: tokens are handed out only by
/// `next_token` increments at `map_host_range` and `split_pages`, are never
/// reused, and removals never reorder survivors. `residual_report`'s
/// traversal and `retry_quarantined_mappings`' minimum-token selection
/// therefore observe the same sequence as before.
struct HvfMappingRegistry {
    next_token: u64,
    records: BTreeMap<u64, HvfMappingRecord>,
}

impl Default for HvfMappingRegistry {
    fn default() -> Self {
        Self {
            next_token: 1,
            records: BTreeMap::new(),
        }
    }
}

const VCPU_HANDLE_LIVE: u8 = 0;
const VCPU_HANDLE_CLOSING: u8 = 1;
const VCPU_HANDLE_CLOSED: u8 = 2;
const VCPU_HANDLE_RETRY_QUEUED: u8 = 3;

struct HvfVcpuControl {
    state: AtomicU8,
    sdk_call: Mutex<()>,
}

impl HvfVcpuControl {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(VCPU_HANDLE_LIVE),
            sdk_call: Mutex::new(()),
        }
    }

    fn load(&self, order: Ordering) -> u8 {
        self.state.load(order)
    }

    fn store(&self, state: u8, order: Ordering) {
        self.state.store(state, order);
    }
}

struct HvfVcpuCreationReservation {
    token: u64,
    owner: std::thread::ThreadId,
    handle_state: Arc<HvfVcpuControl>,
}

struct HvfPendingVcpu {
    token: u64,
    owner: std::thread::ThreadId,
    identifier: Option<u64>,
    cleanup_code: Option<HvReturn>,
    handle_state: Arc<HvfVcpuControl>,
}

struct HvfVcpuCreationGuard<'vm> {
    vm: &'vm HvfVm,
    token: u64,
    owner: std::thread::ThreadId,
    identifier: u64,
    handle_state: Arc<HvfVcpuControl>,
    armed: bool,
    not_send: PhantomData<Rc<()>>,
}

impl<'vm> HvfVcpuCreationGuard<'vm> {
    fn new(vm: &'vm HvfVm, reservation: &HvfVcpuCreationReservation, identifier: u64) -> Self {
        Self {
            vm,
            token: reservation.token,
            owner: reservation.owner,
            identifier,
            handle_state: Arc::clone(&reservation.handle_state),
            armed: true,
            not_send: PhantomData,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HvfVcpuCreationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.vm.settle_abandoned_vcpu_creation(
                self.token,
                self.owner,
                self.identifier,
                &self.handle_state,
            );
            self.armed = false;
        }
    }
}

#[derive(Clone)]
struct HvfOwnedVcpu {
    identifier: u64,
    generation: u64,
    owner: std::thread::ThreadId,
    handle_state: Arc<HvfVcpuControl>,
}

struct HvfQuarantinedVcpu {
    identifier: u64,
    generation: u64,
    owner: std::thread::ThreadId,
    cleanup_code: Option<HvReturn>,
    handle_state: Arc<HvfVcpuControl>,
}

struct HvfVcpuOwnership {
    next_token: u64,
    pending: Vec<HvfPendingVcpu>,
    active: Vec<HvfOwnedVcpu>,
    quarantined: Vec<HvfQuarantinedVcpu>,
}

impl HvfVcpuOwnership {
    fn with_capacity(capacity: usize) -> Result<Self, HvfError> {
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(capacity)
            .map_err(|_| HvfError::ResourceReservation("pending vCPU registry"))?;
        let mut active = Vec::new();
        active
            .try_reserve_exact(capacity)
            .map_err(|_| HvfError::ResourceReservation("active vCPU registry"))?;
        let mut quarantined = Vec::new();
        quarantined
            .try_reserve_exact(capacity)
            .map_err(|_| HvfError::ResourceReservation("vCPU quarantine registry"))?;
        Ok(Self {
            next_token: 1,
            pending,
            active,
            quarantined,
        })
    }

    fn identifier_is_unambiguous(&self, identifier: u64) -> bool {
        let mut found = false;
        for matches in self
            .pending
            .iter()
            .map(|record| record.identifier == Some(identifier))
            .chain(
                self.active
                    .iter()
                    .map(|record| record.identifier == identifier),
            )
            .chain(
                self.quarantined
                    .iter()
                    .map(|record| record.identifier == identifier),
            )
        {
            if matches {
                if found {
                    return false;
                }
                found = true;
            }
        }
        found
    }
}

#[derive(Clone)]
pub struct HvfVcpuCancellation {
    identifier: u64,
    generation: u64,
    owner: std::thread::ThreadId,
    handle_state: Arc<HvfVcpuControl>,
    vm: &'static HvfVm,
}

impl fmt::Debug for HvfVcpuCancellation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuCancellation")
            .field("identifier", &self.identifier)
            .field("generation", &self.generation)
            .field(
                "live",
                &(self.handle_state.load(Ordering::Acquire) == VCPU_HANDLE_LIVE),
            )
            .finish_non_exhaustive()
    }
}

impl HvfVcpuCancellation {
    pub fn cancel(&self) -> Result<(), HvfError> {
        self.vm.cancel_vcpu(
            self.identifier,
            self.generation,
            self.owner,
            &self.handle_state,
        )
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

pub(crate) struct HvfMapping<'vm> {
    vm: &'vm HvfVm,
    token: u64,
    host_range: Range<usize>,
    ipa: u64,
    permissions: HvfMapPermissions,
    fragment_count: usize,
    handle_state: Arc<AtomicU8>,
    live: bool,
}

impl HvfCompletionCapability for HvfMapping<'_> {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        if !std::ptr::eq(self.vm, vm)
            || !self.live
            || self.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE
        {
            return Err(HvfError::MappingNotLive);
        }
        let registry = vm
            .mapping_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = registry
            .records
            .get(&self.token)
            .filter(|record| Arc::ptr_eq(&record.handle_state, &self.handle_state))
            .ok_or(HvfError::MappingTokenMissing(self.token))?;
        if record.lifecycle != HvfMappingLifecycle::Live
            || record.host_range != self.host_range
            || record.ipa != self.ipa
            || record.permissions != self.permissions
            || record.permissions_unknown
            || record.fragments.len() != self.fragment_count
            || record
                .fragments
                .iter()
                .any(|fragment| fragment.state != HvfMappingFragmentState::KnownPresent)
        {
            return Err(HvfError::MappingNotLive);
        }
        Ok(())
    }
}

impl HvfCompletionCapability for Vec<HvfMapping<'_>> {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        if self.is_empty() {
            return Err(HvfError::ResidualAccounting);
        }
        for (index, mapping) in self.iter().enumerate() {
            mapping.validate_hvf_completion(vm)?;
            if self[..index].iter().any(|previous| {
                previous.token == mapping.token
                    || Arc::ptr_eq(&previous.handle_state, &mapping.handle_state)
            }) {
                return Err(HvfError::ResidualAccounting);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for HvfMapping<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfMapping")
            .field("token", &self.token)
            .field("host_range", &self.host_range)
            .field("ipa", &self.ipa)
            .field("permissions", &self.permissions)
            .field("fragment_count", &self.fragment_count)
            .finish()
    }
}

impl HvfMapping<'_> {
    pub(crate) const fn token(&self) -> u64 {
        self.token
    }

    pub(crate) const fn ipa(&self) -> u64 {
        self.ipa
    }

    pub(crate) fn protect(&mut self, permissions: HvfMapPermissions) -> Result<(), HvfError> {
        if !self.live || self.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE {
            self.live = false;
            return Err(HvfError::MappingNotLive);
        }
        if permissions.contains(HvfMapPermissions::WRITE)
            && permissions.contains(HvfMapPermissions::EXECUTE)
        {
            return Err(HvfError::WriteExecuteMapping);
        }
        let vm = self.vm;
        vm.with_operation(|operation| {
            let mut registry = vm
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = registry.records.get_mut(&self.token) else {
                return Err(HvfError::MappingTokenMissing(self.token));
            };
            if record.lifecycle != HvfMappingLifecycle::Live
                || record.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE
                || !Arc::ptr_eq(&record.handle_state, &self.handle_state)
            {
                return Err(HvfError::MappingNotLive);
            }
            operation.mark_published()?;
            let result =
                unsafe { litebox_hvf_vm_protect(self.ipa, self.host_range.len(), permissions.0) };
            if !succeeded(result) {
                record.lifecycle = HvfMappingLifecycle::Quarantined;
                record.permissions_unknown = true;
                record
                    .handle_state
                    .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
                drop(registry);
                self.live = false;
                vm.cleanup_required.store(true, Ordering::Release);
                vm.request_poison_nonblocking();
                return Err(HvfError::mapping_cleanup(
                    self.token,
                    HvfError::Call {
                        operation: "hv_vm_protect",
                        code: result,
                    },
                ));
            }
            record.permissions = permissions;
            record.permissions_unknown = false;
            self.permissions = permissions;
            Ok(())
        })
    }

    pub(crate) fn induce_protect_failure(&mut self) -> Result<(), HvfError> {
        self.protect(HvfMapPermissions(1 << 7))
    }

    pub(crate) fn induce_unmap_failure(mut self) -> Result<(), HvfError> {
        if !self.live || self.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE {
            // A handle that is already dead before this call attempts nothing
            // and establishes no new retry custody, so it must report the
            // same bare `MappingNotLive` that `protect()`'s identical
            // precheck reports below -- not a `MappingCleanup` wrapper, which
            // is reserved for a cleanup attempt that this call actually made
            // and that failed.
            self.live = false;
            return Err(HvfError::MappingNotLive);
        }
        let vm = self.vm;
        vm.with_cleanup_operation(|operation| {
            let mut registry = vm
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = registry.records.get_mut(&self.token) else {
                return Err(HvfError::MappingTokenMissing(self.token));
            };
            if !self.live
                || record.lifecycle != HvfMappingLifecycle::Live
                || record.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE
                || !Arc::ptr_eq(&record.handle_state, &self.handle_state)
            {
                return Err(HvfError::MappingNotLive);
            }
            operation.mark_published()?;
            let result = unsafe { litebox_hvf_vm_unmap(self.ipa + 1, self.host_range.len()) };
            record.lifecycle = HvfMappingLifecycle::Quarantined;
            record
                .handle_state
                .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
            self.live = false;
            vm.cleanup_required.store(true, Ordering::Release);
            vm.request_poison_nonblocking();
            if succeeded(result) {
                return Err(HvfError::mapping_cleanup(
                    self.token,
                    HvfError::ResidualAccounting,
                ));
            }
            for fragment in record
                .fragments
                .iter_mut()
                .filter(|fragment| fragment.state == HvfMappingFragmentState::KnownPresent)
            {
                fragment.state = HvfMappingFragmentState::UnknownAfterFailedExactUnmap;
                fragment.last_unmap_error = Some(result);
            }
            Err(HvfError::mapping_cleanup(
                self.token,
                HvfError::Call {
                    operation: "hv_vm_unmap",
                    code: result,
                },
            ))
        })
    }

    pub(crate) const fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    pub(crate) fn unmap(mut self) -> Result<(), HvfError> {
        if !self.live || self.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE {
            // Same precheck as `protect()` above and for the same reason:
            // a handle that was already quarantined/closed before this call
            // (e.g. by an earlier failed `protect()`) must keep reporting
            // bare `MappingNotLive` so a quarantined handle stays rejected
            // under further mutation attempts, rather than being wrapped in
            // `MappingCleanup` -- which would misreport this no-op call as
            // the operation that just now put the token into retry custody.
            self.live = false;
            return Err(HvfError::MappingNotLive);
        }
        let vm = self.vm;
        let mut closing_started = false;
        let result = vm.with_cleanup_operation(|operation| {
            let registry = vm
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = registry.records.get(&self.token) else {
                return Err(HvfError::MappingTokenMissing(self.token));
            };
            if record.lifecycle != HvfMappingLifecycle::Live
                || record.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE
                || !Arc::ptr_eq(&record.handle_state, &self.handle_state)
            {
                return Err(HvfError::MappingNotLive);
            }
            operation.mark_published()?;
            self.handle_state
                .compare_exchange(
                    MAPPING_HANDLE_LIVE,
                    MAPPING_HANDLE_CLOSING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| HvfError::MappingNotLive)?;
            closing_started = true;
            drop(registry);
            vm.cleanup_mapping_token(operation, self.token).map(|_| ())
        });
        if closing_started {
            self.live = false;
        }
        match result {
            Err(error) => {
                if closing_started {
                    let _ = self.handle_state.compare_exchange(
                        MAPPING_HANDLE_CLOSING,
                        MAPPING_HANDLE_RETRY_QUEUED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    vm.cleanup_required.store(true, Ordering::Release);
                    vm.request_poison_nonblocking();
                }
                Err(HvfError::mapping_cleanup(self.token, error))
            }
            Ok(()) => Ok(()),
        }
    }
}

impl<'vm> HvfMapping<'vm> {
    /// Splits a live multi-page mapping into one live handle per page without
    /// touching the hypervisor: the stage-2 pages stay exactly as mapped, and
    /// the registry now tracks them under per-page tokens so every page can be
    /// unmapped or re-protected on its own. On success this handle is dead
    /// (its pages live on in the returned handles); on failure it is
    /// untouched and still owns the whole mapping.
    pub(crate) fn split_pages(&mut self) -> Result<Vec<HvfMapping<'vm>>, HvfError> {
        if !self.live || self.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE {
            self.live = false;
            return Err(HvfError::MappingNotLive);
        }
        let pages = self.host_range.len() / HVF_PAGE_SIZE;
        let vm = self.vm;
        if pages <= 1 {
            return vm.with_capability_operation(|_| {
                let mut handles = Vec::new();
                handles
                    .try_reserve_exact(1)
                    .map_err(|_| HvfError::ResourceReservation("mapping split"))?;
                handles.push(HvfMapping {
                    vm,
                    token: self.token,
                    host_range: self.host_range.clone(),
                    ipa: self.ipa,
                    permissions: self.permissions,
                    fragment_count: self.fragment_count,
                    handle_state: Arc::clone(&self.handle_state),
                    live: true,
                });
                self.live = false;
                Ok(handles)
            });
        }
        let token = self.token;
        let host_start = self.host_range.start;
        let ipa = self.ipa;
        let permissions = self.permissions;

        vm.with_capability_operation(|operation| {
            let mut registry = vm
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(record) = registry.records.get(&token) else {
                return Err(HvfError::MappingTokenMissing(token));
            };
            if record.lifecycle != HvfMappingLifecycle::Live
                || record.handle_state.load(Ordering::Acquire) != MAPPING_HANDLE_LIVE
                || !Arc::ptr_eq(&record.handle_state, &self.handle_state)
                || record
                    .fragments
                    .iter()
                    .any(|fragment| fragment.state != HvfMappingFragmentState::KnownPresent)
            {
                return Err(HvfError::MappingNotLive);
            }
            let mut handles = Vec::new();
            handles
                .try_reserve_exact(pages)
                .map_err(|_| HvfError::ResourceReservation("mapping split"))?;
            let mut records = Vec::new();
            records
                .try_reserve_exact(pages)
                .map_err(|_| HvfError::ResourceReservation("mapping split"))?;
            let mut next_token = registry.next_token;
            for page in 0..pages {
                let page_token = next_token;
                next_token = next_token
                    .checked_add(1)
                    .ok_or(HvfError::MappingTokenExhausted)?;
                let page_start = host_start + page * HVF_PAGE_SIZE;
                let page_ipa = ipa + (page * HVF_PAGE_SIZE) as u64;
                let mut fragments = Vec::new();
                fragments
                    .try_reserve_exact(1)
                    .map_err(|_| HvfError::ResourceReservation("mapping fragments"))?;
                fragments.push(HvfMappingFragment {
                    ipa: page_ipa,
                    length: HVF_PAGE_SIZE,
                    state: HvfMappingFragmentState::KnownPresent,
                    last_unmap_error: None,
                });
                let handle_state = Arc::new(AtomicU8::new(MAPPING_HANDLE_LIVE));
                records.push(HvfMappingRecord {
                    token: page_token,
                    host_range: page_start..page_start + HVF_PAGE_SIZE,
                    ipa: page_ipa,
                    permissions,
                    permissions_unknown: false,
                    fragments,
                    lifecycle: HvfMappingLifecycle::Live,
                    handle_state: Arc::clone(&handle_state),
                });
                handles.push(HvfMapping {
                    vm,
                    token: page_token,
                    host_range: page_start..page_start + HVF_PAGE_SIZE,
                    ipa: page_ipa,
                    permissions,
                    fragment_count: 1,
                    handle_state,
                    live: false,
                });
            }
            operation.mark_published()?;
            let Some(original) = registry.records.remove(&token) else {
                return Err(HvfError::ResidualAccounting);
            };
            registry.next_token = next_token;
            for record in records {
                let previous = registry.records.insert(record.token, record);
                debug_assert!(previous.is_none(), "mapping tokens are never reused");
            }
            original
                .handle_state
                .store(MAPPING_HANDLE_CLOSED, Ordering::Release);
            self.live = false;
            for handle in &mut handles {
                handle.live = true;
            }
            Ok(handles)
        })
    }
}

impl Drop for HvfMapping<'_> {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        let retained = {
            let mut registry = self
                .vm
                .mapping_registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(record) = registry
                .records
                .get_mut(&self.token)
                .filter(|record| Arc::ptr_eq(&record.handle_state, &self.handle_state))
            {
                record.lifecycle = HvfMappingLifecycle::Quarantined;
                record
                    .handle_state
                    .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
                true
            } else {
                self.handle_state
                    .store(MAPPING_HANDLE_RETRY_QUEUED, Ordering::Release);
                false
            }
        };
        if !retained {
            self.vm
                .operation_gate
                .abandoned
                .store(true, Ordering::Release);
            self.vm.operation_gate.idle.notify_all();
        }
        self.vm.cleanup_required.store(true, Ordering::Release);
        self.vm.request_poison_nonblocking();
        self.live = false;
    }
}

pub(crate) struct HvfVcpu {
    identifier: u64,
    generation: u64,
    exit_area: NonNull<c_void>,
    features: HvfFeatureRegisters,
    vm: &'static HvfVm,
    owner: std::thread::ThreadId,
    handle_state: Arc<HvfVcpuControl>,
    live: bool,
    not_send: PhantomData<Rc<()>>,
}

impl HvfCompletionCapability for HvfVcpu {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        if !std::ptr::eq(self.vm, vm)
            || !self.live
            || self.owner != std::thread::current().id()
            || self.handle_state.load(Ordering::Acquire) != VCPU_HANDLE_LIVE
        {
            return Err(HvfError::VcpuNotLive);
        }
        let ownership = vm
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exact = ownership.active.iter().filter(|record| {
            record.identifier == self.identifier
                && record.generation == self.generation
                && record.owner == self.owner
                && Arc::ptr_eq(&record.handle_state, &self.handle_state)
        });
        if exact.count() != 1 || !ownership.identifier_is_unambiguous(self.identifier) {
            return Err(HvfError::VcpuOwnershipCollision(self.identifier));
        }
        Ok(())
    }
}

impl fmt::Debug for HvfVcpu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpu")
            .field("identifier", &self.identifier)
            .field("generation", &self.generation)
            .field("exit_area", &self.exit_area)
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

impl HvfVcpu {
    fn require_owner_live(&self) -> Result<(), HvfError> {
        if !self.live || self.handle_state.load(Ordering::Acquire) != VCPU_HANDLE_LIVE {
            return Err(HvfError::VcpuNotLive);
        }
        if std::thread::current().id() != self.owner {
            return Err(HvfError::VcpuWrongOwner {
                identifier: self.identifier,
            });
        }
        let ownership = self
            .vm
            .vcpu_ownership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if ownership.active.iter().any(|record| {
            record.identifier == self.identifier
                && record.generation == self.generation
                && record.owner == self.owner
                && Arc::ptr_eq(&record.handle_state, &self.handle_state)
        }) {
            Ok(())
        } else {
            Err(HvfError::VcpuNotLive)
        }
    }

    fn with_existing_operation<T>(
        &mut self,
        body: impl FnOnce(&mut Self, &HvfExistingVcpuOperation<'_>) -> Result<T, HvfError>,
    ) -> Result<T, HvfError> {
        let vm = self.vm;
        let operation = vm.begin_existing_vcpu_operation()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.require_owner_live()?;
            body(self, &operation)
        }));
        let body_panicked = result.is_err();
        let finish = operation.finish(body_panicked);
        match result {
            Ok(result) => vm.finish_operation(result, finish),
            Err(payload) => vm.resume_operation_panic(payload, finish),
        }
    }

    fn with_existing_operation_observed<T>(
        &mut self,
        body: impl FnOnce(&mut Self, &HvfExistingVcpuOperation<'_>) -> Result<T, HvfError>,
        on_published_panic_latched: impl FnOnce(),
    ) -> Result<T, HvfError> {
        let vm = self.vm;
        let operation = vm.begin_existing_vcpu_operation()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.require_owner_live()?;
            body(self, &operation)
        }));
        let body_panicked = result.is_err();
        let finish = operation.finish_observed(body_panicked, on_published_panic_latched);
        match result {
            Ok(result) => vm.finish_operation(result, finish),
            Err(payload) => vm.resume_operation_panic(payload, finish),
        }
    }

    fn quarantine(
        &mut self,
        operation: &impl HvfPublicationCapability,
        trigger: HvfError,
    ) -> HvfError {
        self.vm.request_poison_nonblocking();
        let cleanup = match self.vm.destroy_registered_vcpu(
            operation,
            self.identifier,
            self.generation,
            &self.handle_state,
        ) {
            Ok(code) => code,
            Err(error) => {
                let failure = match self.vm.quarantine_vcpu_without_cleanup(
                    self.identifier,
                    self.generation,
                    self.owner,
                    &self.handle_state,
                ) {
                    Ok(()) => error,
                    Err(quarantine) => HvfError::vcpu_quarantine(error, quarantine),
                };
                self.live = false;
                return HvfError::vcpu_quarantine(trigger, failure);
            }
        };
        self.live = false;
        if succeeded(cleanup) {
            match self.vm.record_vcpu_cleanup(
                self.identifier,
                self.generation,
                self.owner,
                &self.handle_state,
                None,
            ) {
                Ok(()) => trigger,
                Err(accounting) => HvfError::vcpu_quarantine(trigger, accounting),
            }
        } else {
            let accounting = self
                .vm
                .record_vcpu_cleanup(
                    self.identifier,
                    self.generation,
                    self.owner,
                    &self.handle_state,
                    Some(cleanup),
                )
                .err();
            HvfError::vcpu_cleanup(trigger, cleanup, accounting)
        }
    }

    pub(crate) fn features(&self) -> &HvfFeatureRegisters {
        &self.features
    }

    pub(crate) const fn is_live(&self) -> bool {
        self.live
    }

    pub(crate) fn cancellation(&self) -> Result<HvfVcpuCancellation, HvfError> {
        let vm = self.vm;
        let operation = vm.begin_existing_vcpu_operation()?;
        let result = self.require_owner_live().map(|()| HvfVcpuCancellation {
            identifier: self.identifier,
            generation: self.generation,
            owner: self.owner,
            handle_state: Arc::clone(&self.handle_state),
            vm,
        });
        vm.finish_operation(result, operation.finish(false))
    }

    pub(crate) fn architectural_state_unclassified(
        &mut self,
    ) -> Result<HvfArchitecturalState, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut state = HvfArchitecturalState::default();
            let result =
                unsafe { litebox_hvf_vcpu_get_arch_state(vcpu.identifier, &raw mut state) };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_reg/FP/sys_reg",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            if !state.has_valid_header() {
                return Err(vcpu.quarantine(operation, HvfError::InvalidArchitectureState));
            }
            Ok(state)
        })
    }

    pub(crate) fn set_architectural_state(
        &mut self,
        state: &HvfArchitecturalState,
        context: HvfPstateContext,
    ) -> Result<(), HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            if !state.has_valid_header() {
                return Err(HvfError::InvalidArchitectureState);
            }
            state.validate_install(context)?;
            let mut readback = HvfArchitecturalState::default();
            operation.mark_published()?;
            let result = unsafe {
                litebox_hvf_vcpu_set_arch_state(vcpu.identifier, state, &raw mut readback)
            };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_set_reg/FP/sys_reg",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            if readback != *state {
                return Err(vcpu.quarantine(operation, HvfError::ArchitectureStateReadback));
            }
            Ok(())
        })
    }

    pub(crate) fn initialize_el1(
        &mut self,
        configuration: &HvfEl1State,
    ) -> Result<HvfEl1State, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            if !configuration.has_valid_header() {
                return Err(HvfError::InvalidEl1State);
            }
            let mut readback = HvfEl1State::default();
            operation.mark_published()?;
            let result = unsafe {
                litebox_hvf_vcpu_initialize_el1(vcpu.identifier, configuration, &raw mut readback)
            };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "HVF EL1 initialization",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            if !readback.has_valid_header() {
                return Err(vcpu.quarantine(operation, HvfError::InvalidEl1State));
            }
            for (register, expected, actual) in [
                ("SCTLR_EL1", configuration.sctlr_el1, readback.sctlr_el1),
                ("CPACR_EL1", configuration.cpacr_el1, readback.cpacr_el1),
                ("TTBR0_EL1", configuration.ttbr0_el1, readback.ttbr0_el1),
                ("TTBR1_EL1", configuration.ttbr1_el1, readback.ttbr1_el1),
                ("TCR_EL1", configuration.tcr_el1, readback.tcr_el1),
                ("MAIR_EL1", configuration.mair_el1, readback.mair_el1),
                ("VBAR_EL1", configuration.vbar_el1, readback.vbar_el1),
                (
                    "CNTKCTL_EL1",
                    configuration.cntkctl_el1,
                    readback.cntkctl_el1,
                ),
                (
                    "CNTV_CTL_EL0",
                    configuration.cntv_ctl_el0,
                    readback.cntv_ctl_el0,
                ),
                (
                    "CNTV_CVAL_EL0",
                    configuration.cntv_cval_el0,
                    readback.cntv_cval_el0,
                ),
                ("TPIDR_EL1", configuration.tpidr_el1, readback.tpidr_el1),
                (
                    "CONTEXTIDR_EL1",
                    configuration.contextidr_el1,
                    readback.contextidr_el1,
                ),
                ("MDSCR_EL1", configuration.mdscr_el1, readback.mdscr_el1),
            ] {
                if expected != actual {
                    return Err(vcpu.quarantine(
                        operation,
                        HvfError::El1RegisterReadback {
                            register,
                            expected,
                            actual,
                        },
                    ));
                }
            }
            let mut exceptions = 0;
            let mut register_accesses = 0;
            let result = unsafe {
                litebox_hvf_vcpu_get_debug_traps(
                    vcpu.identifier,
                    &raw mut exceptions,
                    &raw mut register_accesses,
                )
            };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_trap_debug_*",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            if exceptions != 1 || register_accesses != 1 {
                return Err(vcpu.quarantine(operation, HvfError::DebugTrapReadback));
            }
            Ok(readback)
        })
    }

    pub(crate) fn el1_state(&mut self) -> Result<HvfEl1State, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut state = HvfEl1State::default();
            let result = unsafe { litebox_hvf_vcpu_get_el1_state(vcpu.identifier, &raw mut state) };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_sys_reg(EL1 state)",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            if !state.has_valid_header() {
                return Err(vcpu.quarantine(operation, HvfError::InvalidEl1State));
            }
            Ok(state)
        })
    }

    pub(crate) fn run(&mut self) -> Result<HvfVcpuExit, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut exit = HvfExitPayload::default();
            operation.mark_published()?;
            let result = unsafe {
                litebox_hvf_vcpu_run(vcpu.identifier, vcpu.exit_area.as_ptr(), &raw mut exit)
            };
            if succeeded(result) {
                Ok(exit.decode())
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_run",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    pub(crate) fn quarantine_rejected_exit(mut self) -> Result<(), HvfError> {
        let vm = self.vm;
        vm.with_cleanup_operation(|operation| {
            self.require_owner_live()?;
            match self.quarantine(operation, HvfError::RejectedVcpuExit) {
                HvfError::RejectedVcpuExit => Ok(()),
                cleanup => Err(HvfError::after_publication(cleanup)),
            }
        })
    }

    pub(crate) fn set_pending_interrupt(
        &mut self,
        fiq: bool,
        pending: bool,
    ) -> Result<(), HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            operation.mark_published()?;
            let result = unsafe {
                litebox_hvf_vcpu_set_pending_interrupt(
                    vcpu.identifier,
                    u8::from(fiq),
                    u8::from(pending),
                )
            };
            if succeeded(result) {
                Ok(())
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_set_pending_interrupt",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    pub(crate) fn pending_interrupt(&mut self, fiq: bool) -> Result<bool, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut pending = 0;
            let result = unsafe {
                litebox_hvf_vcpu_get_pending_interrupt(
                    vcpu.identifier,
                    u8::from(fiq),
                    &raw mut pending,
                )
            };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_pending_interrupt",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            match pending {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(vcpu.quarantine(operation, HvfError::ResidualAccounting)),
            }
        })
    }

    pub(crate) fn set_vtimer_mask(&mut self, masked: bool) -> Result<(), HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            operation.mark_published()?;
            let result =
                unsafe { litebox_hvf_vcpu_set_vtimer_mask(vcpu.identifier, u8::from(masked)) };
            if succeeded(result) {
                Ok(())
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_set_vtimer_mask",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    /// Arms the virtual timer as a one-shot deadline (`CNTV_CVAL_EL0 = cval`,
    /// `CNTV_CTL_EL0.ENABLE`, SDK mask cleared) so the next run exits with
    /// `VtimerActivated` no later than `cval` on the guest's counter.
    pub(crate) fn arm_vtimer(&mut self, cval: u64) -> Result<(), HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            operation.mark_published()?;
            let result = unsafe { litebox_hvf_vcpu_arm_vtimer(vcpu.identifier, cval) };
            if succeeded(result) {
                Ok(())
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_arm_vtimer",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    pub(crate) fn vtimer_mask(&mut self) -> Result<bool, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut masked = 0;
            let result =
                unsafe { litebox_hvf_vcpu_get_vtimer_mask(vcpu.identifier, &raw mut masked) };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_vtimer_mask",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            match masked {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(vcpu.quarantine(operation, HvfError::ResidualAccounting)),
            }
        })
    }

    pub(crate) fn set_vtimer_offset(&mut self, offset: u64) -> Result<(), HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            operation.mark_published()?;
            let result = unsafe { litebox_hvf_vcpu_set_vtimer_offset(vcpu.identifier, offset) };
            if succeeded(result) {
                Ok(())
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_set_vtimer_offset",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    pub(crate) fn vtimer_offset(&mut self) -> Result<u64, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut offset = 0;
            let result =
                unsafe { litebox_hvf_vcpu_get_vtimer_offset(vcpu.identifier, &raw mut offset) };
            if succeeded(result) {
                Ok(offset)
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_vtimer_offset",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    pub(crate) fn execution_time(&mut self) -> Result<u64, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut time = 0;
            let result = unsafe { litebox_hvf_vcpu_get_exec_time(vcpu.identifier, &raw mut time) };
            if succeeded(result) {
                Ok(time)
            } else {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_exec_time",
                    code: result,
                };
                Err(vcpu.quarantine(operation, trigger))
            }
        })
    }

    pub(crate) fn program_stage_one(
        &mut self,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        self.program_stage_one_expected(ttbr0_el1, ttbr0_el1, tcr_el1, tcr_el1, mair_el1, mair_el1)
    }

    pub(crate) fn verify_stage_one(
        &mut self,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut state = HvfEl1State::default();
            let result = unsafe { litebox_hvf_vcpu_get_el1_state(vcpu.identifier, &raw mut state) };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_get_sys_reg(stage-one)",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            if !state.has_valid_header() {
                return Err(vcpu.quarantine(operation, HvfError::InvalidEl1State));
            }
            for (register, expected, actual) in [
                ("TTBR0_EL1", ttbr0_el1, state.ttbr0_el1),
                ("TCR_EL1", tcr_el1, state.tcr_el1),
                ("MAIR_EL1", mair_el1, state.mair_el1),
            ] {
                if actual != expected {
                    let trigger = HvfError::StageOneRegisterReadback {
                        register,
                        expected,
                        actual,
                    };
                    return Err(vcpu.quarantine(operation, trigger));
                }
            }
            Ok(HvfStageOneRegisterReport {
                ttbr0_el1: state.ttbr0_el1,
                tcr_el1: state.tcr_el1,
                mair_el1: state.mair_el1,
            })
        })
    }

    pub(crate) fn induce_stage_one_readback_mismatch(
        &mut self,
        ttbr0_el1: u64,
        tcr_el1: u64,
        mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        self.program_stage_one_expected(
            ttbr0_el1,
            ttbr0_el1,
            tcr_el1,
            tcr_el1,
            mair_el1,
            mair_el1 ^ 1,
        )
    }

    fn program_stage_one_expected(
        &mut self,
        ttbr0_el1: u64,
        expected_ttbr0_el1: u64,
        tcr_el1: u64,
        expected_tcr_el1: u64,
        mair_el1: u64,
        expected_mair_el1: u64,
    ) -> Result<HvfStageOneRegisterReport, HvfError> {
        self.with_existing_operation(|vcpu, operation| {
            let mut ttbr0_readback = 0;
            let mut tcr_readback = 0;
            let mut mair_readback = 0;
            operation.mark_published()?;
            let result = unsafe {
                litebox_hvf_vcpu_program_stage_one(
                    vcpu.identifier,
                    ttbr0_el1,
                    tcr_el1,
                    mair_el1,
                    &raw mut ttbr0_readback,
                    &raw mut tcr_readback,
                    &raw mut mair_readback,
                )
            };
            if !succeeded(result) {
                let trigger = HvfError::Call {
                    operation: "hv_vcpu_set/get_sys_reg(stage-one)",
                    code: result,
                };
                return Err(vcpu.quarantine(operation, trigger));
            }
            for (register, expected, actual) in [
                ("TTBR0_EL1", expected_ttbr0_el1, ttbr0_readback),
                ("TCR_EL1", expected_tcr_el1, tcr_readback),
                ("MAIR_EL1", expected_mair_el1, mair_readback),
            ] {
                if actual != expected {
                    let trigger = HvfError::StageOneRegisterReadback {
                        register,
                        expected,
                        actual,
                    };
                    return Err(vcpu.quarantine(operation, trigger));
                }
            }
            Ok(HvfStageOneRegisterReport {
                ttbr0_el1: ttbr0_readback,
                tcr_el1: tcr_readback,
                mair_el1: mair_readback,
            })
        })
    }

    pub(crate) fn destroy(mut self) -> Result<(), HvfError> {
        let vm = self.vm;
        // The whole teardown runs as a cleanup operation so `poison()`'s
        // quiesce waits for an in-flight destroy on another thread, and so
        // destroy is refused only once the operation gate is `abandoned`
        // (the same gate `retry_quarantined_vcpus_for_current_thread` takes).
        // No `vcpu_ownership` lock is held here: every helper below takes and
        // releases it on its own, and the operation gate is acquired before
        // the body runs.
        let result = vm.with_cleanup_operation(|operation| -> Result<(), HvfError> {
            self.require_owner_live()?;
            let result = vm.destroy_registered_vcpu(
                operation,
                self.identifier,
                self.generation,
                &self.handle_state,
            );
            match result {
                Ok(code) => {
                    self.live = false;
                    if succeeded(code) {
                        vm.record_vcpu_cleanup(
                            self.identifier,
                            self.generation,
                            self.owner,
                            &self.handle_state,
                            None,
                        )
                    } else {
                        let primary = HvfError::Call {
                            operation: "hv_vcpu_destroy",
                            code,
                        };
                        let accounting = vm
                            .record_vcpu_cleanup(
                                self.identifier,
                                self.generation,
                                self.owner,
                                &self.handle_state,
                                Some(code),
                            )
                            .err();
                        vm.cleanup_required.store(true, Ordering::Release);
                        vm.request_poison_nonblocking();
                        match accounting {
                            Some(accounting) => Err(HvfError::vcpu_quarantine(primary, accounting)),
                            None => Err(primary),
                        }
                    }
                }
                Err(error) => {
                    // The vCPU was never handed to hv_vcpu_destroy: record a
                    // durable quarantine so a later retry pass still owns it.
                    match vm.quarantine_vcpu_without_cleanup(
                        self.identifier,
                        self.generation,
                        self.owner,
                        &self.handle_state,
                    ) {
                        Ok(()) => Err(error),
                        Err(failure) => Err(HvfError::vcpu_quarantine(error, failure)),
                    }
                }
            }
        });
        match result {
            Err(trigger) if self.live => {
                let failure = vm
                    .quarantine_vcpu_without_cleanup(
                        self.identifier,
                        self.generation,
                        self.owner,
                        &self.handle_state,
                    )
                    .err();
                self.live = false;
                vm.cleanup_required.store(true, Ordering::Release);
                vm.request_poison_nonblocking();
                match failure {
                    Some(failure) => Err(HvfError::vcpu_quarantine(trigger, failure)),
                    None => Err(trigger),
                }
            }
            result => result,
        }
    }
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        let retained = {
            let mut ownership = self
                .vm
                .vcpu_ownership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(record) = ownership.active.iter_mut().find(|record| {
                record.identifier == self.identifier
                    && record.generation == self.generation
                    && record.owner == self.owner
                    && Arc::ptr_eq(&record.handle_state, &self.handle_state)
            }) {
                record
                    .handle_state
                    .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                true
            } else if let Some(record) = ownership.quarantined.iter_mut().find(|record| {
                record.identifier == self.identifier
                    && record.generation == self.generation
                    && record.owner == self.owner
                    && Arc::ptr_eq(&record.handle_state, &self.handle_state)
            }) {
                record
                    .handle_state
                    .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                true
            } else {
                self.handle_state
                    .store(VCPU_HANDLE_RETRY_QUEUED, Ordering::Release);
                false
            }
        };
        if !retained {
            self.vm
                .operation_gate
                .abandoned
                .store(true, Ordering::Release);
            self.vm.operation_gate.idle.notify_all();
        }
        self.vm.cleanup_required.store(true, Ordering::Release);
        self.vm.request_poison_nonblocking();
        self.live = false;
    }
}
