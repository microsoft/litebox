// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded Hypervisor.framework execution probe.
//!
//! This is deliberately not yet the production guest backend. It exercises the
//! irreducible architecture the backend needs: a 16 KiB EL1 translation regime
//! that keeps LiteBox's guest virtual addresses equal to host-visible pointers,
//! translates them to compact IPAs, enters unchanged EL0 code, receives stock
//! `SVC` in an EL1 vector, and exits to the host through `HVC` without losing
//! x18. The probe is opt-in and leaves the existing native backend untouched.

use core::ffi::{CStr, c_void};
use core::fmt;
use core::ptr;
use std::sync::{Mutex, mpsc};
use std::time::Duration;

#[path = "hvf_sdk.rs"]
mod sdk;

pub use sdk::{
    HvfArchitecturalState, HvfBoundaryReport, HvfEl1State, HvfError, HvfExceptionExit,
    HvfFeatureRegister, HvfFeatureRegisters, HvfMonitor, HvfPublishedPanicOperation,
    HvfPublishedPanicReport, HvfSdkResidualReport, HvfSimd128, HvfStageOneRegisterReport,
    HvfVcpuCancellation, HvfVcpuExit, HvfVmReport, hvf_boundary_probe, hvf_published_panic_probe,
    publish_hvf_executable_bytes,
};
pub(crate) use sdk::{
    HvfMapPermissions, HvfMapping, HvfPstateContext, HvfVcpu, HvfVm, process_hvf_vm,
};

const PAGE_SIZE: usize = 16 * 1024;
const MAX_BACKING_PAGES: usize = 10;
const CODE_PAGE: usize = 0;
const ROOT_TABLE_PAGE: usize = 1;
const COMPACT_IPA_BASE: u64 = 0x1000_0000;
const BOOT_OFFSET: usize = 0x1000;
const EL0_OFFSET: usize = 0x1100;
const LOWER_EL_AARCH64_SYNC_OFFSET: usize = 0x400;
const HOST_EXIT_IMMEDIATE: u16 = 0x4c42;
const SVC_IMMEDIATE: u16 = 0x37;
const X0_SENTINEL: u16 = 0x4c42;
const X18_SENTINEL: u64 = 0xcafe_babe_dead_1818;
const RUN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SMOKE_TEARDOWN_ATTEMPTS: u32 = 8;

const HV_SUCCESS: HvReturn = 0;
const HV_EXIT_REASON_EXCEPTION: u32 = 1;
const HV_MEMORY_READ: u64 = 1 << 0;
const HV_MEMORY_WRITE: u64 = 1 << 1;
const HV_MEMORY_EXEC: u64 = 1 << 2;
const HV_REG_X0: u32 = 0;
const HV_REG_X18: u32 = 18;
const HV_REG_PC: u32 = 31;
const HV_REG_CPSR: u32 = 34;
const HV_SYS_REG_SCTLR_EL1: u16 = 0xc080;
const HV_SYS_REG_TTBR0_EL1: u16 = 0xc100;
const HV_SYS_REG_TCR_EL1: u16 = 0xc102;
const HV_SYS_REG_SPSR_EL1: u16 = 0xc200;
const HV_SYS_REG_ELR_EL1: u16 = 0xc201;
const HV_SYS_REG_SP_EL0: u16 = 0xc208;
const HV_SYS_REG_ESR_EL1: u16 = 0xc290;
const HV_SYS_REG_MAIR_EL1: u16 = 0xc510;
const HV_SYS_REG_VBAR_EL1: u16 = 0xc600;
const HV_SYS_REG_SP_EL1: u16 = 0xe208;
const HV_IPA_GRANULE_16KB: u32 = 1;
const TABLE_DESCRIPTOR: u64 = 0b11;
// Valid page, AttrIdx 0, EL0/EL1 read-only, Inner Shareable, AF set.
const EXECUTABLE_LEAF_DESCRIPTOR: u64 = 0x7c3;
const OUTPUT_ADDRESS_MASK_16K: u64 = 0x0000_ffff_ffff_c000;
const SCTLR_EL1_MMU_CACHES_ON: u64 = 0x30d0_1805;
const MAIR_EL1_NORMAL_WBWA: u64 = 0xff;

// Hypervisor.framework's public arm64 ABI uses a Mach error code.
type HvReturn = i32;
type HvVcpu = u64;
type HvVmConfig = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HvExitException {
    syndrome: u64,
    virtual_address: u64,
    physical_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HvVcpuExit {
    reason: u32,
    _padding: u32,
    exception: HvExitException,
}

#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    fn hv_vm_get_max_vcpu_count(max_vcpu_count: *mut u32) -> HvReturn;
    fn hv_vm_create(config: HvVmConfig) -> HvReturn;
    fn hv_vm_destroy() -> HvReturn;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> HvReturn;
    fn hv_vm_unmap(ipa: u64, size: usize) -> HvReturn;

    fn hv_vcpu_create(
        vcpu: *mut HvVcpu,
        exit: *mut *mut HvVcpuExit,
        config: *mut c_void,
    ) -> HvReturn;
    fn hv_vcpu_destroy(vcpu: HvVcpu) -> HvReturn;
    fn hv_vcpu_get_reg(vcpu: HvVcpu, reg: u32, value: *mut u64) -> HvReturn;
    fn hv_vcpu_set_reg(vcpu: HvVcpu, reg: u32, value: u64) -> HvReturn;
    fn hv_vcpu_get_sys_reg(vcpu: HvVcpu, reg: u16, value: *mut u64) -> HvReturn;
    fn hv_vcpu_set_sys_reg(vcpu: HvVcpu, reg: u16, value: u64) -> HvReturn;
    fn hv_vcpu_run(vcpu: HvVcpu) -> HvReturn;
    fn hv_vcpus_exit(vcpus: *mut HvVcpu, vcpu_count: u32) -> HvReturn;
}

unsafe extern "C" {
    fn os_release(object: *mut c_void);
}

type VmConfigCreate = unsafe extern "C" fn() -> HvVmConfig;
type VmConfigGetMaxIpaSize = unsafe extern "C" fn(*mut u32) -> HvReturn;
type VmConfigSetIpaSize = unsafe extern "C" fn(HvVmConfig, u32) -> HvReturn;
type VmConfigGetIpaSize = unsafe extern "C" fn(HvVmConfig, *mut u32) -> HvReturn;
type VmConfigSetIpaGranule = unsafe extern "C" fn(HvVmConfig, u32) -> HvReturn;
type VmConfigGetIpaGranule = unsafe extern "C" fn(HvVmConfig, *mut u32) -> HvReturn;

#[derive(Clone, Copy)]
struct ConfigApi {
    create: VmConfigCreate,
    get_max_ipa_size: VmConfigGetMaxIpaSize,
    set_ipa_size: VmConfigSetIpaSize,
    get_ipa_size: VmConfigGetIpaSize,
    set_ipa_granule: VmConfigSetIpaGranule,
    get_ipa_granule: VmConfigGetIpaGranule,
}

impl ConfigApi {
    fn load() -> Result<Self, HvfSmokeError> {
        // Configuration and explicit 16 KiB granule selection are resolved at
        // runtime so merely linking this crate does not make the native backend
        // unloadable on an older macOS release. The bounded smoke itself
        // requires all of them and reports the missing symbol precisely.
        macro_rules! load {
            ($symbol:literal, $ty:ty) => {{
                let name: &CStr = cstr($symbol);
                // SAFETY: `RTLD_DEFAULT` searches already-loaded images and
                // `name` is NUL terminated. A non-null result names the public
                // function with the exact type declared in Apple's active SDK.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
                if address.is_null() {
                    return Err(HvfSmokeError::ApiUnavailable($symbol));
                }
                // SAFETY: justified by the public SDK signature above. This
                // macro expands with a concrete function-pointer type, so the
                // pointer sizes are statically equal.
                unsafe { core::mem::transmute::<*mut c_void, $ty>(address) }
            }};
        }

        Ok(Self {
            create: load!("hv_vm_config_create", VmConfigCreate),
            get_max_ipa_size: load!("hv_vm_config_get_max_ipa_size", VmConfigGetMaxIpaSize),
            set_ipa_size: load!("hv_vm_config_set_ipa_size", VmConfigSetIpaSize),
            get_ipa_size: load!("hv_vm_config_get_ipa_size", VmConfigGetIpaSize),
            set_ipa_granule: load!("hv_vm_config_set_ipa_granule", VmConfigSetIpaGranule),
            get_ipa_granule: load!("hv_vm_config_get_ipa_granule", VmConfigGetIpaGranule),
        })
    }
}

fn cstr(symbol: &'static str) -> &'static CStr {
    // Every caller supplies a literal with one explicit trailing NUL appended
    // here and no embedded NUL. Keeping this helper local prevents an FFI
    // symbol typo from leaking into the rest of the backend.
    let bytes: &[u8] = match symbol {
        "hv_vm_config_create" => b"hv_vm_config_create\0",
        "hv_vm_config_get_max_ipa_size" => b"hv_vm_config_get_max_ipa_size\0",
        "hv_vm_config_set_ipa_size" => b"hv_vm_config_set_ipa_size\0",
        "hv_vm_config_get_ipa_size" => b"hv_vm_config_get_ipa_size\0",
        "hv_vm_config_set_ipa_granule" => b"hv_vm_config_set_ipa_granule\0",
        "hv_vm_config_get_ipa_granule" => b"hv_vm_config_get_ipa_granule\0",
        _ => unreachable!("all HVF symbols are listed above"),
    };
    // SAFETY: every match arm is explicitly NUL-terminated and contains no
    // earlier NUL byte.
    unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
}

/// Architectural observations made by [`hvf_smoke_probe`].
#[derive(Clone, Debug)]
pub struct HvfSmokeReport {
    pub max_ipa_bits: u32,
    pub configured_ipa_bits: u32,
    pub max_vcpu_count: u32,
    pub ipa_granule_bytes: usize,
    pub guest_virtual_address: u64,
    pub host_virtual_address: usize,
    pub compact_ipa: u64,
    pub page_table_pages: usize,
    pub exit_reason: u32,
    pub host_exit_syndrome: u64,
    pub host_exit_pc: u64,
    pub source_esr_el1: u64,
    pub source_elr_el1: u64,
    pub source_spsr_el1: u64,
    pub x0: u64,
    pub x18: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfSmokeResourceState {
    Vacant,
    Live,
    Closing,
    Closed,
    Quarantined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSmokeResourceReport {
    pub state: HvfSmokeResourceState,
    pub teardown_attempts: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSmokeResidualReport {
    pub configuration: HvfSmokeResourceReport,
    pub vcpu: HvfSmokeResourceReport,
    pub table_mapping: HvfSmokeResourceReport,
    pub code_mapping: HvfSmokeResourceReport,
    pub vm: HvfSmokeResourceReport,
    pub host_pages: HvfSmokeResourceReport,
}

impl HvfSmokeResidualReport {
    pub fn has_residual(&self) -> bool {
        [
            &self.configuration,
            &self.vcpu,
            &self.table_mapping,
            &self.code_mapping,
            &self.vm,
            &self.host_pages,
        ]
        .into_iter()
        .any(|resource| {
            matches!(
                resource.state,
                HvfSmokeResourceState::Live
                    | HvfSmokeResourceState::Closing
                    | HvfSmokeResourceState::Quarantined
            )
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfSmokeCleanupReport {
    pub before: HvfSmokeResidualReport,
    pub after: HvfSmokeResidualReport,
    pub failures: Vec<HvfSmokeCleanupFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HvfSmokeCleanupFailure {
    Hypervisor {
        operation: &'static str,
        code: HvReturn,
    },
    HostMemory {
        operation: &'static str,
        errno: i32,
    },
    WrongVcpuOwner,
    Blocked {
        resource: &'static str,
        blocker: &'static str,
    },
    AttemptLimit {
        resource: &'static str,
        attempts: u32,
        limit: u32,
    },
}

/// Failure from the bounded HVF smoke path.
#[derive(Debug)]
pub enum HvfSmokeError {
    ApiUnavailable(&'static str),
    Call {
        operation: &'static str,
        code: HvReturn,
    },
    NullConfiguration,
    NullExitArea,
    ProductionVmActive,
    HostPageSize(i64),
    HostMemory(std::io::Error),
    UnexpectedIpaGranule(u32),
    IpaTooSmall(u32),
    GuestAddressOutOfRange(usize),
    PageTableCapacity,
    PageTableConflict(u64),
    InvalidPageTableDescriptor(u64),
    Watchdog(std::io::Error),
    WatchdogPanicked,
    TimedOut,
    UnexpectedExit(Box<HvfSmokeReport>),
    ResidualOwnership(Box<HvfSmokeResidualReport>),
    Cleanup(HvfSmokeCleanupFailure),
    Teardown {
        primary: Option<Box<HvfSmokeError>>,
        failures: Vec<HvfSmokeCleanupFailure>,
        residual: Box<HvfSmokeResidualReport>,
    },
}

impl fmt::Display for HvfSmokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiUnavailable(symbol) => write!(
                f,
                "Hypervisor.framework symbol {symbol} is unavailable; the compact-IPA smoke requires macOS 26 or newer"
            ),
            Self::Call { operation, code } => {
                write!(
                    f,
                    "{operation} failed: {} ({:#x})",
                    hv_error_name(*code),
                    (*code).cast_unsigned()
                )?;
                if (*code).cast_unsigned() == 0xfae9_4007 {
                    write!(
                        f,
                        "; the executable must be signed with com.apple.security.hypervisor=true"
                    )?;
                }
                Ok(())
            }
            Self::NullConfiguration => write!(f, "hv_vm_config_create returned null"),
            Self::NullExitArea => write!(f, "hv_vcpu_create returned a null exit area"),
            Self::ProductionVmActive => write!(
                f,
                "the process-global HVF backend is already active; its VM cannot be replaced by the bounded smoke probe"
            ),
            Self::HostPageSize(size) => {
                write!(f, "host page size is {size}, but this smoke requires 16384")
            }
            Self::HostMemory(error) => write!(f, "host memory operation failed: {error}"),
            Self::UnexpectedIpaGranule(granule) => write!(
                f,
                "Hypervisor.framework configured unexpected IPA granule {granule}"
            ),
            Self::IpaTooSmall(bits) => write!(
                f,
                "Hypervisor.framework reports only {bits} IPA bits, too few for the compact probe arena"
            ),
            Self::GuestAddressOutOfRange(address) => write!(
                f,
                "host-visible guest address {address:#x} is not a 48-bit, 16 KiB-aligned AArch64 VA"
            ),
            Self::PageTableCapacity => write!(f, "compact smoke exhausted its page-table arena"),
            Self::PageTableConflict(gva) => {
                write!(f, "conflicting stage-one mapping for guest VA {gva:#x}")
            }
            Self::InvalidPageTableDescriptor(descriptor) => write!(
                f,
                "stage-one table contains an invalid descriptor {descriptor:#x}"
            ),
            Self::Watchdog(error) => write!(f, "failed to spawn HVF smoke watchdog: {error}"),
            Self::WatchdogPanicked => write!(f, "HVF smoke watchdog panicked"),
            Self::TimedOut => write!(f, "HVF vCPU did not reach its HVC exit within two seconds"),
            Self::UnexpectedExit(report) => write!(f, "unexpected HVF smoke state: {report:?}"),
            Self::ResidualOwnership(report) => write!(
                f,
                "the bounded HVF smoke retains exact process-owned resources: {report:?}"
            ),
            Self::Cleanup(failure) => {
                write!(f, "HVF smoke cleanup failed: {failure:?}")
            }
            Self::Teardown {
                primary,
                failures,
                residual,
            } => write!(
                f,
                "HVF smoke teardown retained resources after primary={primary:?}, failures={failures:?}, residual={residual:?}"
            ),
        }
    }
}

impl std::error::Error for HvfSmokeError {}

fn hv_error_name(code: HvReturn) -> &'static str {
    match code.cast_unsigned() {
        0 => "HV_SUCCESS",
        0xfae9_4001 => "HV_ERROR",
        0xfae9_4002 => "HV_BUSY",
        0xfae9_4003 => "HV_BAD_ARGUMENT",
        0xfae9_4004 => "HV_ILLEGAL_GUEST_STATE",
        0xfae9_4005 => "HV_NO_RESOURCES",
        0xfae9_4006 => "HV_NO_DEVICE",
        0xfae9_4007 => "HV_DENIED",
        0xfae9_4008 => "HV_EXISTS",
        0xfae9_400f => "HV_UNSUPPORTED",
        _ => "unknown HVF error",
    }
}

fn check(operation: &'static str, code: HvReturn) -> Result<(), HvfSmokeError> {
    if code == HV_SUCCESS {
        Ok(())
    } else {
        Err(HvfSmokeError::Call { operation, code })
    }
}

struct Vm;

impl Vm {
    fn create(resources: &mut SmokeResources, config: HvVmConfig) -> Result<(), HvfSmokeError> {
        if resources.vm.state != HvfSmokeResourceState::Vacant {
            return Err(HvfSmokeError::ResidualOwnership(Box::new(
                resources.report(),
            )));
        }
        // SAFETY: `config` remains owned by the process record for this call.
        let result = unsafe { hv_vm_create(config) };
        check("hv_vm_create", result)?;
        resources.vm.state = HvfSmokeResourceState::Live;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct HostPages {
    start: *mut u8,
    len: usize,
}

impl HostPages {
    fn allocate(resources: &mut SmokeResources) -> Result<Self, HvfSmokeError> {
        if resources.pages.resource.state != HvfSmokeResourceState::Vacant {
            return Err(HvfSmokeError::ResidualOwnership(Box::new(
                resources.report(),
            )));
        }
        let len = MAX_BACKING_PAGES * PAGE_SIZE;
        // SAFETY: anonymous private mapping at a kernel-selected address.
        let start = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if start == libc::MAP_FAILED {
            return Err(HvfSmokeError::HostMemory(std::io::Error::last_os_error()));
        }
        let pages = Self {
            start: start.cast(),
            len,
        };
        resources.pages.start = pages.start;
        resources.pages.len = pages.len;
        resources.pages.resource.state = HvfSmokeResourceState::Live;
        Ok(pages)
    }

    fn page(&self, index: usize) -> *mut u8 {
        debug_assert!(index < MAX_BACKING_PAGES);
        // SAFETY: callers use one of the fixed in-range page indices.
        unsafe { self.start.add(index * PAGE_SIZE) }
    }
}

#[derive(Clone, Copy)]
enum SmokeMappingSlot {
    Code,
    Tables,
}

struct VmMapping;

impl VmMapping {
    fn map(
        resources: &mut SmokeResources,
        slot: SmokeMappingSlot,
        addr: *mut u8,
        ipa: u64,
        len: usize,
        flags: u64,
    ) -> Result<(), HvfSmokeError> {
        if resources.mapping(slot).resource.state != HvfSmokeResourceState::Vacant {
            return Err(HvfSmokeError::ResidualOwnership(Box::new(
                resources.report(),
            )));
        }
        // SAFETY: the host allocation covers `len`; address and IPA are aligned.
        let result = unsafe { hv_vm_map(addr.cast(), ipa, len, flags) };
        check("hv_vm_map", result)?;
        let mapping = resources.mapping_mut(slot);
        mapping.ipa = ipa;
        mapping.len = len;
        mapping.resource.state = HvfSmokeResourceState::Live;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Vcpu {
    id: HvVcpu,
    exit: *mut HvVcpuExit,
}

impl Vcpu {
    fn create(resources: &mut SmokeResources) -> Result<Self, HvfSmokeError> {
        if resources.vcpu.resource.state != HvfSmokeResourceState::Vacant {
            return Err(HvfSmokeError::ResidualOwnership(Box::new(
                resources.report(),
            )));
        }
        let mut id = 0;
        let mut exit = ptr::null_mut();
        // SAFETY: both out-pointers are live; the current thread becomes owner.
        let result = unsafe { hv_vcpu_create(&raw mut id, &raw mut exit, ptr::null_mut()) };
        check("hv_vcpu_create", result)?;
        resources.vcpu.id = id;
        resources.vcpu.exit = exit;
        resources.vcpu.owner = Some(std::thread::current().id());
        resources.vcpu.resource.state = HvfSmokeResourceState::Live;
        if exit.is_null() {
            return Err(HvfSmokeError::NullExitArea);
        }
        Ok(Self { id, exit })
    }

    fn set_reg(&self, reg: u32, value: u64, operation: &'static str) -> Result<(), HvfSmokeError> {
        // SAFETY: called on the owner thread for the live recorded vCPU.
        check(operation, unsafe { hv_vcpu_set_reg(self.id, reg, value) })
    }

    fn reg(&self, reg: u32, operation: &'static str) -> Result<u64, HvfSmokeError> {
        let mut value = 0;
        // SAFETY: called on the owner thread; `value` is a live out-parameter.
        check(operation, unsafe {
            hv_vcpu_get_reg(self.id, reg, &raw mut value)
        })?;
        Ok(value)
    }

    fn set_sys_reg(
        &self,
        reg: u16,
        value: u64,
        operation: &'static str,
    ) -> Result<(), HvfSmokeError> {
        // SAFETY: called on the owner thread for the live recorded vCPU.
        check(operation, unsafe {
            hv_vcpu_set_sys_reg(self.id, reg, value)
        })
    }

    fn sys_reg(&self, reg: u16, operation: &'static str) -> Result<u64, HvfSmokeError> {
        let mut value = 0;
        // SAFETY: called on the owner thread; `value` is a live out-parameter.
        check(operation, unsafe {
            hv_vcpu_get_sys_reg(self.id, reg, &raw mut value)
        })?;
        Ok(value)
    }
}

struct PageTables<'a> {
    pages: &'a HostPages,
    next_free_page: usize,
}

impl<'a> PageTables<'a> {
    fn new(pages: &'a HostPages) -> Self {
        Self {
            pages,
            next_free_page: ROOT_TABLE_PAGE + 1,
        }
    }

    fn map_executable_page(&mut self, gva: u64, ipa: u64) -> Result<(), HvfSmokeError> {
        let indices = [
            ((gva >> 47) & 0x7ff) as usize,
            ((gva >> 36) & 0x7ff) as usize,
            ((gva >> 25) & 0x7ff) as usize,
            ((gva >> 14) & 0x7ff) as usize,
        ];
        let mut table_page = ROOT_TABLE_PAGE;
        for index in indices[..3].iter().copied() {
            let entry = self.entry(table_page, index);
            table_page = if entry == 0 {
                let next = self.allocate_table()?;
                self.set_entry(table_page, index, ipa_for_page(next) | TABLE_DESCRIPTOR);
                next
            } else {
                if entry & 0b11 != TABLE_DESCRIPTOR {
                    return Err(HvfSmokeError::InvalidPageTableDescriptor(entry));
                }
                let next_ipa = entry & OUTPUT_ADDRESS_MASK_16K;
                let Some(delta) = next_ipa.checked_sub(COMPACT_IPA_BASE) else {
                    return Err(HvfSmokeError::InvalidPageTableDescriptor(entry));
                };
                let next = usize::try_from(delta / PAGE_SIZE as u64)
                    .map_err(|_| HvfSmokeError::InvalidPageTableDescriptor(entry))?;
                if next < ROOT_TABLE_PAGE || next >= self.next_free_page {
                    return Err(HvfSmokeError::InvalidPageTableDescriptor(entry));
                }
                next
            };
        }

        let leaf = ipa | EXECUTABLE_LEAF_DESCRIPTOR;
        let old = self.entry(table_page, indices[3]);
        if old != 0 && old != leaf {
            return Err(HvfSmokeError::PageTableConflict(gva));
        }
        self.set_entry(table_page, indices[3], leaf);
        Ok(())
    }

    fn allocate_table(&mut self) -> Result<usize, HvfSmokeError> {
        if self.next_free_page >= MAX_BACKING_PAGES {
            return Err(HvfSmokeError::PageTableCapacity);
        }
        let page = self.next_free_page;
        self.next_free_page += 1;
        Ok(page)
    }

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "mmap and the 16 KiB page offsets provide u64 alignment"
    )]
    fn entry(&self, page: usize, index: usize) -> u64 {
        // SAFETY: every table page is a zero-initialized 16 KiB host mapping,
        // and `index < 2048` by construction.
        unsafe { self.pages.page(page).cast::<u64>().add(index).read() }
    }

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "mmap and the 16 KiB page offsets provide u64 alignment"
    )]
    fn set_entry(&self, page: usize, index: usize, value: u64) {
        // SAFETY: same bounds as `entry`, with unique construction-time access.
        unsafe {
            self.pages.page(page).cast::<u64>().add(index).write(value);
        }
    }

    fn table_page_count(&self) -> usize {
        self.next_free_page - ROOT_TABLE_PAGE
    }
}

fn ipa_for_page(page: usize) -> u64 {
    COMPACT_IPA_BASE + page as u64 * PAGE_SIZE as u64
}

fn movz(register: u32, immediate: u16) -> u32 {
    0xd280_0000 | (u32::from(immediate) << 5) | register
}

fn movk(register: u32, immediate: u16, halfword: u32) -> u32 {
    0xf280_0000 | (halfword << 21) | (u32::from(immediate) << 5) | register
}

#[expect(
    clippy::cast_ptr_alignment,
    reason = "mmap and the instruction offsets provide u32 alignment"
)]
fn write_instruction(pages: &HostPages, offset: usize, instruction: u32) {
    // SAFETY: every call uses an aligned offset within the code page, before
    // guest execution begins.
    unsafe {
        pages
            .page(CODE_PAGE)
            .add(offset)
            .cast::<u32>()
            .write(instruction);
    }
}

fn tcr_el1(ipa_bits: u32) -> u64 {
    let ips: u32 = match ipa_bits {
        0..=32 => 0,
        33..=36 => 1,
        37..=40 => 2,
        41..=42 => 3,
        43..=44 => 4,
        45..=48 => 5,
        _ => 6,
    };
    // T0SZ=16 (48-bit TTBR0), WBWA Inner Shareable, TG0=16 KiB,
    // EPD1=1, and the runtime-configured stage-two IPA size.
    0x0080_b510 | (u64::from(ips) << 32)
}

fn run_with_watchdog(vcpu: &Vcpu) -> Result<(), HvfSmokeError> {
    let (finished_tx, finished_rx) = mpsc::channel();
    let id = vcpu.id;
    let watchdog = std::thread::Builder::new()
        .name("litebox-hvf-smoke-watchdog".into())
        .spawn(move || match finished_rx.recv_timeout(RUN_TIMEOUT) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => None,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let mut target = id;
                // SAFETY: cross-thread cancellation is the documented purpose
                // of `hv_vcpus_exit`; the owner joins this thread before destroy.
                Some(unsafe { hv_vcpus_exit(&raw mut target, 1) })
            }
        })
        .map_err(HvfSmokeError::Watchdog)?;

    // SAFETY: this is the vCPU owner thread and all state was initialized.
    let run_result = unsafe { hv_vcpu_run(vcpu.id) };
    let _ = finished_tx.send(());
    let timed_out = watchdog
        .join()
        .map_err(|_| HvfSmokeError::WatchdogPanicked)?;
    if let Some(cancel_result) = timed_out {
        check("hv_vcpus_exit", cancel_result)?;
        return Err(HvfSmokeError::TimedOut);
    }
    check("hv_vcpu_run", run_result)
}

static HVF_SMOKE_LOCK: Mutex<()> = Mutex::new(());
static HVF_SMOKE_RESOURCES: Mutex<SmokeResources> = Mutex::new(SmokeResources::EMPTY);
static HVF_SMOKE_RESIDUAL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[derive(Clone, Copy)]
struct SmokeResourceRecord {
    state: HvfSmokeResourceState,
    teardown_attempts: u32,
}

impl SmokeResourceRecord {
    const EMPTY: Self = Self {
        state: HvfSmokeResourceState::Vacant,
        teardown_attempts: 0,
    };

    fn report(self) -> HvfSmokeResourceReport {
        HvfSmokeResourceReport {
            state: self.state,
            teardown_attempts: self.teardown_attempts,
        }
    }

    fn is_absent(self) -> bool {
        matches!(
            self.state,
            HvfSmokeResourceState::Vacant | HvfSmokeResourceState::Closed
        )
    }

    fn needs_teardown(self) -> bool {
        matches!(
            self.state,
            HvfSmokeResourceState::Live | HvfSmokeResourceState::Quarantined
        )
    }

    fn begin_teardown(&mut self, resource: &'static str) -> Result<(), HvfSmokeCleanupFailure> {
        let attempts =
            self.teardown_attempts
                .checked_add(1)
                .ok_or(HvfSmokeCleanupFailure::AttemptLimit {
                    resource,
                    attempts: self.teardown_attempts,
                    limit: MAX_SMOKE_TEARDOWN_ATTEMPTS,
                })?;
        if attempts > MAX_SMOKE_TEARDOWN_ATTEMPTS {
            self.state = HvfSmokeResourceState::Quarantined;
            return Err(HvfSmokeCleanupFailure::AttemptLimit {
                resource,
                attempts: self.teardown_attempts,
                limit: MAX_SMOKE_TEARDOWN_ATTEMPTS,
            });
        }
        self.teardown_attempts = attempts;
        self.state = HvfSmokeResourceState::Closing;
        Ok(())
    }
}

struct SmokeConfigurationRecord {
    resource: SmokeResourceRecord,
    object: HvVmConfig,
}

struct SmokePagesRecord {
    resource: SmokeResourceRecord,
    start: *mut u8,
    len: usize,
}

#[derive(Clone, Copy)]
struct SmokeMappingRecord {
    resource: SmokeResourceRecord,
    ipa: u64,
    len: usize,
}

struct SmokeVcpuRecord {
    resource: SmokeResourceRecord,
    id: HvVcpu,
    exit: *mut HvVcpuExit,
    owner: Option<std::thread::ThreadId>,
}

struct SmokeResources {
    configuration: SmokeConfigurationRecord,
    vcpu: SmokeVcpuRecord,
    mappings: [SmokeMappingRecord; 2],
    vm: SmokeResourceRecord,
    pages: SmokePagesRecord,
}

// The process locks serialize all raw access. The vCPU record additionally
// retains its creator identity for owner-thread-affine destruction.
unsafe impl Send for SmokeResources {}

impl SmokeResources {
    const EMPTY: Self = Self {
        configuration: SmokeConfigurationRecord {
            resource: SmokeResourceRecord::EMPTY,
            object: ptr::null_mut(),
        },
        vcpu: SmokeVcpuRecord {
            resource: SmokeResourceRecord::EMPTY,
            id: 0,
            exit: ptr::null_mut(),
            owner: None,
        },
        mappings: [
            SmokeMappingRecord {
                resource: SmokeResourceRecord::EMPTY,
                ipa: 0,
                len: 0,
            },
            SmokeMappingRecord {
                resource: SmokeResourceRecord::EMPTY,
                ipa: 0,
                len: 0,
            },
        ],
        vm: SmokeResourceRecord::EMPTY,
        pages: SmokePagesRecord {
            resource: SmokeResourceRecord::EMPTY,
            start: ptr::null_mut(),
            len: 0,
        },
    };

    fn mapping(&self, slot: SmokeMappingSlot) -> &SmokeMappingRecord {
        &self.mappings[match slot {
            SmokeMappingSlot::Code => 0,
            SmokeMappingSlot::Tables => 1,
        }]
    }

    fn mapping_mut(&mut self, slot: SmokeMappingSlot) -> &mut SmokeMappingRecord {
        &mut self.mappings[match slot {
            SmokeMappingSlot::Code => 0,
            SmokeMappingSlot::Tables => 1,
        }]
    }

    fn report(&self) -> HvfSmokeResidualReport {
        HvfSmokeResidualReport {
            configuration: self.configuration.resource.report(),
            vcpu: self.vcpu.resource.report(),
            table_mapping: self.mapping(SmokeMappingSlot::Tables).resource.report(),
            code_mapping: self.mapping(SmokeMappingSlot::Code).resource.report(),
            vm: self.vm.report(),
            host_pages: self.pages.resource.report(),
        }
    }

    fn has_residual(&self) -> bool {
        self.report().has_residual()
    }

    fn record_configuration(&mut self, object: HvVmConfig) {
        self.configuration.object = object;
        self.configuration.resource.state = HvfSmokeResourceState::Live;
    }

    fn release_configuration(&mut self) -> Result<(), HvfSmokeCleanupFailure> {
        if !self.configuration.resource.needs_teardown() {
            return Ok(());
        }
        self.configuration
            .resource
            .begin_teardown("configuration")?;
        unsafe { os_release(self.configuration.object) };
        self.configuration.resource.state = HvfSmokeResourceState::Closed;
        Ok(())
    }

    fn teardown(&mut self) -> Vec<HvfSmokeCleanupFailure> {
        let mut failures = Vec::with_capacity(8);
        if let Err(failure) = self.release_configuration() {
            failures.push(failure);
        }

        if self.vcpu.resource.needs_teardown() {
            if self.vcpu.owner.as_ref() != Some(&std::thread::current().id()) {
                self.vcpu.resource.state = HvfSmokeResourceState::Quarantined;
                failures.push(HvfSmokeCleanupFailure::WrongVcpuOwner);
            } else if let Err(failure) = self.vcpu.resource.begin_teardown("vCPU") {
                failures.push(failure);
            } else {
                let result = unsafe { hv_vcpu_destroy(self.vcpu.id) };
                if result == HV_SUCCESS {
                    self.vcpu.resource.state = HvfSmokeResourceState::Closed;
                } else {
                    self.vcpu.resource.state = HvfSmokeResourceState::Quarantined;
                    failures.push(HvfSmokeCleanupFailure::Hypervisor {
                        operation: "hv_vcpu_destroy",
                        code: result,
                    });
                }
            }
        }

        if self.vcpu.resource.is_absent() {
            for slot in [SmokeMappingSlot::Tables, SmokeMappingSlot::Code] {
                let mapping = self.mapping_mut(slot);
                if !mapping.resource.needs_teardown() {
                    continue;
                }
                if let Err(failure) = mapping.resource.begin_teardown(match slot {
                    SmokeMappingSlot::Code => "code mapping",
                    SmokeMappingSlot::Tables => "table mapping",
                }) {
                    failures.push(failure);
                    continue;
                }
                let result = unsafe { hv_vm_unmap(mapping.ipa, mapping.len) };
                if result == HV_SUCCESS {
                    mapping.resource.state = HvfSmokeResourceState::Closed;
                } else {
                    mapping.resource.state = HvfSmokeResourceState::Quarantined;
                    failures.push(HvfSmokeCleanupFailure::Hypervisor {
                        operation: "hv_vm_unmap",
                        code: result,
                    });
                }
            }
        } else {
            for (resource, mapping) in [
                ("table mapping", self.mapping(SmokeMappingSlot::Tables)),
                ("code mapping", self.mapping(SmokeMappingSlot::Code)),
            ] {
                if !mapping.resource.is_absent() {
                    failures.push(HvfSmokeCleanupFailure::Blocked {
                        resource,
                        blocker: "vCPU",
                    });
                }
            }
        }

        let mappings_absent = self
            .mappings
            .iter()
            .all(|mapping| mapping.resource.is_absent());
        if self.vcpu.resource.is_absent() && mappings_absent {
            if self.vm.needs_teardown() {
                if let Err(failure) = self.vm.begin_teardown("VM") {
                    failures.push(failure);
                } else {
                    let result = unsafe { hv_vm_destroy() };
                    if result == HV_SUCCESS {
                        self.vm.state = HvfSmokeResourceState::Closed;
                    } else {
                        self.vm.state = HvfSmokeResourceState::Quarantined;
                        failures.push(HvfSmokeCleanupFailure::Hypervisor {
                            operation: "hv_vm_destroy",
                            code: result,
                        });
                    }
                }
            }
        } else if !self.vm.is_absent() {
            failures.push(HvfSmokeCleanupFailure::Blocked {
                resource: "VM",
                blocker: if self.vcpu.resource.is_absent() {
                    "mapping"
                } else {
                    "vCPU"
                },
            });
        }

        if self.vcpu.resource.is_absent() && mappings_absent && self.vm.is_absent() {
            if self.pages.resource.needs_teardown() {
                if let Err(failure) = self.pages.resource.begin_teardown("host pages") {
                    failures.push(failure);
                } else {
                    let result = unsafe { libc::munmap(self.pages.start.cast(), self.pages.len) };
                    if result == 0 {
                        self.pages.resource.state = HvfSmokeResourceState::Closed;
                    } else {
                        self.pages.resource.state = HvfSmokeResourceState::Quarantined;
                        failures.push(HvfSmokeCleanupFailure::HostMemory {
                            operation: "munmap",
                            errno: std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                        });
                    }
                }
            }
        } else if !self.pages.resource.is_absent() {
            let blocker = if !self.vcpu.resource.is_absent() {
                "vCPU"
            } else if !mappings_absent {
                "mapping"
            } else {
                "VM"
            };
            failures.push(HvfSmokeCleanupFailure::Blocked {
                resource: "host pages",
                blocker,
            });
        }

        if self.has_residual() {
            HVF_SMOKE_RESIDUAL.store(true, std::sync::atomic::Ordering::Release);
        } else {
            *self = Self::EMPTY;
            HVF_SMOKE_RESIDUAL.store(false, std::sync::atomic::Ordering::Release);
        }
        failures
    }
}

pub(super) fn smoke_residual_is_live() -> bool {
    HVF_SMOKE_RESIDUAL.load(std::sync::atomic::Ordering::Acquire)
}

pub fn hvf_smoke_retry_residual() -> Result<HvfSmokeCleanupReport, HvfSmokeError> {
    let _exclusive = HVF_SMOKE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if sdk::production_vm_is_live() {
        return Err(HvfSmokeError::ProductionVmActive);
    }
    let mut resources = HVF_SMOKE_RESOURCES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = resources.report();
    if !before.has_residual() {
        return Ok(HvfSmokeCleanupReport {
            before: before.clone(),
            after: before,
            failures: Vec::new(),
        });
    }
    let failures = resources.teardown();
    let after = resources.report();
    if failures.is_empty() && !after.has_residual() {
        Ok(HvfSmokeCleanupReport {
            before,
            after,
            failures,
        })
    } else {
        Err(HvfSmokeError::Teardown {
            primary: None,
            failures,
            residual: Box::new(after),
        })
    }
}

/// Run a bounded, real Hypervisor.framework EL0 execution probe.
///
/// The calling executable must carry the `com.apple.security.hypervisor`
/// entitlement. The function creates the process's one HVF VM, destroys every
/// vCPU and mapping in reverse order, and returns only after the VM is gone.
/// It must therefore run before any future long-lived HVF backend is created.
///
/// # Errors
///
/// Returns a precise Hypervisor.framework error, an unavailable-API error on a
/// pre-macOS-26 host, a two-second timeout, or the complete unexpected register
/// snapshot when the architectural invariants do not hold.
pub fn hvf_smoke_probe() -> Result<HvfSmokeReport, HvfSmokeError> {
    let _exclusive = HVF_SMOKE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if sdk::production_vm_is_live() {
        return Err(HvfSmokeError::ProductionVmActive);
    }
    let mut resources = HVF_SMOKE_RESOURCES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if resources.has_residual() {
        HVF_SMOKE_RESIDUAL.store(true, std::sync::atomic::Ordering::Release);
        return Err(HvfSmokeError::ResidualOwnership(Box::new(
            resources.report(),
        )));
    }

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        hvf_smoke_probe_body(&mut resources)
    }));
    let cleanup = resources.teardown();
    let residual = resources.report();
    match outcome {
        Ok(result) if cleanup.is_empty() && !residual.has_residual() => result,
        Ok(result) => Err(HvfSmokeError::Teardown {
            primary: result.err().map(Box::new),
            failures: cleanup,
            residual: Box::new(residual),
        }),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn hvf_smoke_probe_body(resources: &mut SmokeResources) -> Result<HvfSmokeReport, HvfSmokeError> {
    // SAFETY: `_SC_PAGESIZE` has no pointer arguments or side effects.
    let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if host_page_size != 16_384 {
        return Err(HvfSmokeError::HostPageSize(host_page_size));
    }

    let api = ConfigApi::load()?;
    let mut max_ipa_bits = 0;
    // SAFETY: `max_ipa_bits` is a live out-parameter.
    check("hv_vm_config_get_max_ipa_size", unsafe {
        (api.get_max_ipa_size)(&raw mut max_ipa_bits)
    })?;
    if max_ipa_bits < 36 {
        return Err(HvfSmokeError::IpaTooSmall(max_ipa_bits));
    }

    // SAFETY: public constructor with no arguments.
    let raw_config = unsafe { (api.create)() };
    if raw_config.is_null() {
        return Err(HvfSmokeError::NullConfiguration);
    }
    resources.record_configuration(raw_config);
    // SAFETY: `raw_config` stays live in the process record through VM creation.
    check("hv_vm_config_set_ipa_size", unsafe {
        (api.set_ipa_size)(raw_config, max_ipa_bits)
    })?;
    check("hv_vm_config_set_ipa_granule", unsafe {
        (api.set_ipa_granule)(raw_config, HV_IPA_GRANULE_16KB)
    })?;
    let mut configured_ipa_bits = 0;
    let mut configured_granule = 0;
    // SAFETY: both outputs and the configuration object are live.
    check("hv_vm_config_get_ipa_size", unsafe {
        (api.get_ipa_size)(raw_config, &raw mut configured_ipa_bits)
    })?;
    check("hv_vm_config_get_ipa_granule", unsafe {
        (api.get_ipa_granule)(raw_config, &raw mut configured_granule)
    })?;
    if configured_granule != HV_IPA_GRANULE_16KB {
        return Err(HvfSmokeError::UnexpectedIpaGranule(configured_granule));
    }

    let mut max_vcpu_count = 0;
    // SAFETY: `max_vcpu_count` is a live out-parameter.
    check("hv_vm_get_max_vcpu_count", unsafe {
        hv_vm_get_max_vcpu_count(&raw mut max_vcpu_count)
    })?;

    let pages = HostPages::allocate(resources)?;
    let host_virtual_address = pages.page(CODE_PAGE) as usize;
    if !host_virtual_address.is_multiple_of(PAGE_SIZE) || host_virtual_address >= 1usize << 48 {
        return Err(HvfSmokeError::GuestAddressOutOfRange(host_virtual_address));
    }
    let guest_virtual_address = host_virtual_address as u64;
    let vector_virtual_address = ipa_for_page(CODE_PAGE);

    // Every synchronous vector exits with a distinct HVC immediate. The lower
    // AArch64 vector carries the expected marker; the others turn a wrong EL or
    // bootstrap fault into a diagnosable host exit instead of recursion.
    for vector in 0..4u16 {
        let offset = usize::from(vector) * 0x200;
        let immediate = if offset == LOWER_EL_AARCH64_SYNC_OFFSET {
            HOST_EXIT_IMMEDIATE
        } else {
            0x4c00 + vector
        };
        write_instruction(&pages, offset, 0xd400_0002 | (u32::from(immediate) << 5));
        write_instruction(&pages, offset + 4, 0x1400_0000);
    }
    write_instruction(&pages, BOOT_OFFSET, 0xd69f_03e0); // eret
    for (index, instruction) in [
        movz(HV_REG_X0, X0_SENTINEL),
        movz(HV_REG_X18, 0x1818),
        movk(HV_REG_X18, 0xdead, 1),
        movk(HV_REG_X18, 0xbabe, 2),
        movk(HV_REG_X18, 0xcafe, 3),
        0xd400_0001 | (u32::from(SVC_IMMEDIATE) << 5),
        0xd420_0000,
    ]
    .into_iter()
    .enumerate()
    {
        write_instruction(&pages, EL0_OFFSET + index * 4, instruction);
    }

    let mut tables = PageTables::new(&pages);
    tables.map_executable_page(guest_virtual_address, ipa_for_page(CODE_PAGE))?;
    tables.map_executable_page(vector_virtual_address, ipa_for_page(CODE_PAGE))?;
    let page_table_pages = tables.table_page_count();

    // SAFETY: the page contains all code written above and remains mapped.
    let executable_bytes =
        unsafe { core::slice::from_raw_parts(pages.page(CODE_PAGE).cast_const(), PAGE_SIZE) };
    sdk::publish_hvf_executable_bytes(executable_bytes);
    if unsafe { libc::mprotect(pages.page(CODE_PAGE).cast(), PAGE_SIZE, libc::PROT_READ) } != 0 {
        return Err(HvfSmokeError::HostMemory(std::io::Error::last_os_error()));
    }

    Vm::create(resources, raw_config)?;
    resources
        .release_configuration()
        .map_err(HvfSmokeError::Cleanup)?;
    VmMapping::map(
        resources,
        SmokeMappingSlot::Code,
        pages.page(CODE_PAGE),
        ipa_for_page(CODE_PAGE),
        PAGE_SIZE,
        HV_MEMORY_READ | HV_MEMORY_EXEC,
    )?;
    VmMapping::map(
        resources,
        SmokeMappingSlot::Tables,
        pages.page(ROOT_TABLE_PAGE),
        ipa_for_page(ROOT_TABLE_PAGE),
        page_table_pages * PAGE_SIZE,
        HV_MEMORY_READ | HV_MEMORY_WRITE,
    )?;

    let vcpu = Vcpu::create(resources)?;
    let tcr = tcr_el1(configured_ipa_bits);
    vcpu.set_sys_reg(HV_SYS_REG_MAIR_EL1, MAIR_EL1_NORMAL_WBWA, "set MAIR_EL1")?;
    vcpu.set_sys_reg(HV_SYS_REG_TCR_EL1, tcr, "set TCR_EL1")?;
    vcpu.set_sys_reg(
        HV_SYS_REG_TTBR0_EL1,
        ipa_for_page(ROOT_TABLE_PAGE),
        "set TTBR0_EL1",
    )?;
    vcpu.set_reg(
        HV_REG_PC,
        vector_virtual_address + BOOT_OFFSET as u64,
        "set PC",
    )?;
    vcpu.set_reg(HV_REG_CPSR, 0x3c5, "set CPSR")?;
    vcpu.set_sys_reg(HV_SYS_REG_VBAR_EL1, vector_virtual_address, "set VBAR_EL1")?;
    vcpu.set_sys_reg(
        HV_SYS_REG_ELR_EL1,
        guest_virtual_address + EL0_OFFSET as u64,
        "set ELR_EL1",
    )?;
    vcpu.set_sys_reg(HV_SYS_REG_SPSR_EL1, 0, "set SPSR_EL1")?;
    vcpu.set_sys_reg(
        HV_SYS_REG_SP_EL0,
        guest_virtual_address + 0x3800,
        "set SP_EL0",
    )?;
    vcpu.set_sys_reg(
        HV_SYS_REG_SP_EL1,
        vector_virtual_address + 0x3ff0,
        "set SP_EL1",
    )?;
    vcpu.set_sys_reg(
        HV_SYS_REG_SCTLR_EL1,
        SCTLR_EL1_MMU_CACHES_ON,
        "set SCTLR_EL1",
    )?;

    run_with_watchdog(&vcpu)?;

    // SAFETY: the exit pointer is owned by the live vCPU and remains valid
    // until `hv_vcpu_destroy` below.
    let exit = unsafe { *vcpu.exit };
    let report = HvfSmokeReport {
        max_ipa_bits,
        configured_ipa_bits,
        max_vcpu_count,
        ipa_granule_bytes: PAGE_SIZE,
        guest_virtual_address,
        host_virtual_address,
        compact_ipa: ipa_for_page(CODE_PAGE),
        page_table_pages,
        exit_reason: exit.reason,
        host_exit_syndrome: exit.exception.syndrome,
        host_exit_pc: vcpu.reg(HV_REG_PC, "get PC")?,
        source_esr_el1: vcpu.sys_reg(HV_SYS_REG_ESR_EL1, "get ESR_EL1")?,
        source_elr_el1: vcpu.sys_reg(HV_SYS_REG_ELR_EL1, "get ELR_EL1")?,
        source_spsr_el1: vcpu.sys_reg(HV_SYS_REG_SPSR_EL1, "get SPSR_EL1")?,
        x0: vcpu.reg(HV_REG_X0, "get X0")?,
        x18: vcpu.reg(HV_REG_X18, "get X18")?,
    };

    let expected_elr = guest_virtual_address + EL0_OFFSET as u64 + 6 * 4;
    let expected_host_pc = vector_virtual_address + LOWER_EL_AARCH64_SYNC_OFFSET as u64 + 4;
    let valid = report.exit_reason == HV_EXIT_REASON_EXCEPTION
        && (report.host_exit_syndrome >> 26) & 0x3f == 0x16
        && report.host_exit_syndrome & 0xffff == u64::from(HOST_EXIT_IMMEDIATE)
        && report.host_exit_pc == expected_host_pc
        && report.x0 == u64::from(X0_SENTINEL)
        && report.x18 == X18_SENTINEL
        && (report.source_esr_el1 >> 26) & 0x3f == 0x15
        && report.source_esr_el1 & 0xffff == u64::from(SVC_IMMEDIATE)
        && report.source_elr_el1 == expected_elr
        && report.source_spsr_el1.is_multiple_of(16);
    if !valid {
        return Err(HvfSmokeError::UnexpectedExit(Box::new(report)));
    }

    Ok(report)
}
