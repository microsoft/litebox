// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::cell::Cell;
use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{BitOr, BitOrAssign, Deref, DerefMut, Range};
use litebox::utils::TruncateExt;
use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crate::HvfCompletionCapability;
use crate::hvf_vcpu::{
    HvfOwnerSynchronizationProof, HvfSynchronizationRequest, HvfVcpuLaneParticipantCapability,
    HvfVcpuLaneRegistration, hvf_vcpu_lane_is_live,
};

use crate::hvf::{
    HvfError, HvfMapPermissions, HvfMapping, HvfSdkResidualReport, HvfStageOneRegisterReport,
    HvfVm, process_hvf_vm,
};
use crate::hvf_backing::{
    CallbackOutcome, HVF_HOST_PAGE_SIZE, HvfHostBacking, HvfHostBackingError, HvfHostBackingReport,
    HvfHostPermissions, HvfHostSlot, hvf_host_backing_probe, hvf_host_retry_residual,
    with_contiguous_alias,
};

unsafe extern "C" {
    /// `mach_vm_region` from `<mach/mach_vm.h>`, declared here for the
    /// mirrored-view witness so it can read back the live host protection of a
    /// guest page without going through any of this crate's own bookkeeping.
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

/// `VM_REGION_BASIC_INFO_64` and its `int`-unit count, from
/// `<mach/vm_region.h>`.
const VM_REGION_BASIC_INFO_64: libc::c_int = 9;
const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;

const PAGE_SIZE: usize = HVF_HOST_PAGE_SIZE;
const TABLE_ENTRIES: usize = PAGE_SIZE / core::mem::size_of::<u64>();
const VA_BITS: u8 = 48;
const VA_LIMIT: usize = 1usize << VA_BITS;
const ASID_BITS: u8 = 8;
const MAX_ASIDS: u16 = 1 << ASID_BITS;
const MAX_PARTICIPANTS_PER_ADDRESS_SPACE: usize = 256;
const ATTACHMENT_ALLOCATED: u8 = 0;
const ATTACHMENT_SUBMITTED: u8 = 1;
const ATTACHMENT_SYNCHRONIZING: u8 = 2;
const ATTACHMENT_RUNNING: u8 = 3;
const ATTACHMENT_CLOSED: u8 = 4;
const ATTACHMENT_ABANDONED: u8 = 5;
const PARTICIPANT_LIVE: u8 = 0;
const PARTICIPANT_RELEASED: u8 = 2;
const PARTICIPANT_RECOVERED: u8 = 3;
const PARTICIPANT_ABANDONED: u8 = 4;
const DESTROY_TICKET_LIVE: u8 = 0;
const DESTROY_TICKET_FINISHED: u8 = 1;
const DESTROY_TICKET_ABANDONED: u8 = 2;
const MAIR_ATTR0_NORMAL_WB: u64 = 0xff;
const DESCRIPTOR_VALID_TABLE_OR_PAGE: u64 = 0b11;
const DESCRIPTOR_AP_EL0_RW: u64 = 0b01 << 6;
const DESCRIPTOR_AP_EL0_NONE_EL1_RO: u64 = 0b10 << 6;
const DESCRIPTOR_AP_EL0_RO: u64 = 0b11 << 6;
const DESCRIPTOR_INNER_SHAREABLE: u64 = 0b11 << 8;
const DESCRIPTOR_ACCESS_FLAG: u64 = 1 << 10;
const DESCRIPTOR_NOT_GLOBAL: u64 = 1 << 11;
const DESCRIPTOR_PXN: u64 = 1 << 53;
const DESCRIPTOR_UXN: u64 = 1 << 54;
const DESCRIPTOR_OUTPUT_MASK: u64 = 0x0000_ffff_ffff_c000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HvfAddressSpaceId(u64);

impl HvfAddressSpaceId {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HvfVcpuParticipantId(u64);

impl HvfVcpuParticipantId {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfTlbiGeneration(u64);

impl HvfTlbiGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfAsid {
    pub value: u8,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfRootGeneration(u64);

impl HvfRootGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfWriteEpoch(u64);

impl HvfWriteEpoch {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfPublicationEpoch(u64);

impl HvfPublicationEpoch {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvfExecutableGeneration(u64);

impl HvfExecutableGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HvfBackingIdentity(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HvfSharing {
    Private,
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfTranslationRegime {
    pub va_bits: u8,
    pub tbi0: bool,
    pub asid_bits: u8,
    pub ipa_bits: u32,
    pub tcr_el1: u64,
    pub mair_attr0: u8,
}

impl HvfTranslationRegime {
    fn for_ipa_bits(ipa_bits: u32) -> Result<Self, HvfMemoryError> {
        if !(32..=52).contains(&ipa_bits) {
            return Err(HvfMemoryError::UnsupportedIpaWidth(ipa_bits));
        }
        Ok(Self {
            va_bits: VA_BITS,
            tbi0: false,
            asid_bits: ASID_BITS,
            ipa_bits,
            tcr_el1: tcr_el1(ipa_bits),
            mair_attr0: TruncateExt::<u8>::trunc(MAIR_ATTR0_NORMAL_WB),
        })
    }

    fn validate_address(self, gva: usize) -> Result<(), HvfMemoryError> {
        if self.tbi0 || self.va_bits != VA_BITS || gva >= VA_LIMIT {
            return Err(HvfMemoryError::NoncanonicalAddress {
                address: gva,
                va_bits: self.va_bits,
                tbi0: self.tbi0,
            });
        }
        Ok(())
    }

    fn validate_range(self, range: &Range<usize>) -> Result<usize, HvfMemoryError> {
        if range.is_empty() {
            return Err(HvfMemoryError::EmptyRange);
        }
        self.validate_address(range.start)?;
        if range.end > VA_LIMIT {
            return Err(HvfMemoryError::NoncanonicalRange {
                range: range.clone(),
                va_bits: self.va_bits,
                tbi0: self.tbi0,
            });
        }
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or(HvfMemoryError::EmptyRange)?;
        if !range.start.is_multiple_of(PAGE_SIZE) || !length.is_multiple_of(PAGE_SIZE) {
            return Err(HvfMemoryError::Unaligned {
                start: range.start,
                length,
            });
        }
        if range.start < PAGE_SIZE {
            return Err(HvfMemoryError::MonitorOverlap(range.clone()));
        }
        Ok(length / PAGE_SIZE)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfGuestPermissions(u8);

impl HvfGuestPermissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn validate(self) -> Result<(), HvfMemoryError> {
        if self.contains(Self::WRITE) && !self.contains(Self::READ) {
            return Err(HvfMemoryError::WriteWithoutRead);
        }
        if self.contains(Self::WRITE) && self.contains(Self::EXECUTE) {
            return Err(HvfMemoryError::WriteExecute);
        }
        if self.0 & !(Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0) != 0 {
            return Err(HvfMemoryError::InvalidPermissions(self.0));
        }
        Ok(())
    }

    fn stage_two(self) -> HvfMapPermissions {
        let mut permissions = HvfMapPermissions::NONE;
        if self.contains(Self::READ) || self.contains(Self::EXECUTE) {
            permissions |= HvfMapPermissions::READ;
        }
        if self.contains(Self::WRITE) {
            permissions |= HvfMapPermissions::WRITE;
        }
        if self.contains(Self::EXECUTE) {
            permissions |= HvfMapPermissions::EXECUTE;
        }
        permissions
    }

    fn stage_one_descriptor(self, ipa: u64) -> u64 {
        let access = if self.contains(Self::WRITE) {
            DESCRIPTOR_AP_EL0_RW
        } else if self.contains(Self::READ) {
            DESCRIPTOR_AP_EL0_RO
        } else {
            DESCRIPTOR_AP_EL0_NONE_EL1_RO
        };
        let execute_never = if self.contains(Self::EXECUTE) {
            0
        } else {
            DESCRIPTOR_UXN
        };
        (ipa & DESCRIPTOR_OUTPUT_MASK)
            | DESCRIPTOR_VALID_TABLE_OR_PAGE
            | access
            | DESCRIPTOR_INNER_SHAREABLE
            | DESCRIPTOR_ACCESS_FLAG
            | DESCRIPTOR_NOT_GLOBAL
            | DESCRIPTOR_PXN
            | execute_never
    }
}

impl BitOr for HvfGuestPermissions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for HvfGuestPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfMemoryLimits {
    pub max_address_spaces: usize,
    pub max_claimed_pages: usize,
    pub max_live_data_pages: usize,
    pub max_table_pages: usize,
    pub max_host_slots: usize,
    pub max_retired_generations: usize,
    pub max_retired_pages: usize,
    pub max_retired_bytes: usize,
    pub max_mutation_pages: usize,
}

impl Default for HvfMemoryLimits {
    fn default() -> Self {
        Self {
            max_address_spaces: 254,
            max_claimed_pages: 1 << 20,
            max_live_data_pages: 1 << 19,
            max_table_pages: 1 << 18,
            max_host_slots: 1 << 20,
            max_retired_generations: 1 << 14,
            max_retired_pages: 1 << 20,
            max_retired_bytes: 16 * 1024 * 1024 * 1024,
            // A single mutation's own DoS ceiling, independent of `max_claimed_pages`'
            // cumulative budget: large enough for a legitimate single-reservation caller
            // (V8's pointer-compression cage is a well-known, documented 4 GiB PROT_NONE
            // speculative reservation -- https://v8.dev/blog/pointer-compression -- which
            // the previous 1 GiB value rejected outright, observed live as Chromium's
            // renderer immediately hitting "V8 process OOM (Failed to reserve virtual
            // memory for CodeRange)" before painting anything), while staying well inside
            // `max_claimed_pages`' 16 GiB cumulative ceiling so one oversized mutation still
            // cannot alone exhaust an address space's whole budget.
            max_mutation_pages: 1 << 19,
        }
    }
}

#[derive(Clone, Debug)]
pub enum HvfMemoryError {
    Hvf(HvfError),
    HostBacking(HvfHostBackingError),
    UnsupportedIpaWidth(u32),
    EmptyRange,
    Unaligned {
        start: usize,
        length: usize,
    },
    NoncanonicalAddress {
        address: usize,
        va_bits: u8,
        tbi0: bool,
    },
    NoncanonicalRange {
        range: Range<usize>,
        va_bits: u8,
        tbi0: bool,
    },
    MonitorOverlap(Range<usize>),
    InvalidPermissions(u8),
    WriteWithoutRead,
    WriteExecute,
    InitialExecute(Range<usize>),
    BackingWriteExecute {
        backing: HvfBackingIdentity,
        offset: usize,
    },
    WrongMemoryManager,
    AddressSpaceDestroyed(HvfAddressSpaceId),
    AddressOverlap(Range<usize>),
    ClaimStale,
    RangeOutsideClaim(Range<usize>),
    SparseAlias(Range<usize>),
    AliasBusy(Range<usize>),
    AliasReentrant(Range<usize>),
    AliasRestore(Range<usize>),
    PublicationRequired(Range<usize>),
    PublicationStale(Range<usize>),
    RetirementStale,
    RetirementParticipantsPending {
        retirement: u64,
        pending: usize,
    },
    ParticipantStale(HvfVcpuParticipantId),
    ParticipantLaneUnavailable(u64),
    ParticipantLaneMismatch {
        participant: HvfVcpuParticipantId,
        expected: u64,
        actual: u64,
    },
    ParticipantBusy(HvfVcpuParticipantId),
    ParticipantRetirementPending(HvfVcpuParticipantId),
    AttachmentGenerationChanged,
    AttachmentStale,
    AttachmentAbandoned(HvfAddressSpaceId),
    SynchronizationStale,
    DestroyTicketStale,
    DestroyTicketAbandoned(HvfAddressSpaceId),
    AddressSpaceBusy(HvfAddressSpaceId),
    RetirementsPending(HvfAddressSpaceId),
    ResourceLimit {
        resource: &'static str,
        requested: usize,
        limit: usize,
    },
    PublishedMutation {
        operation: &'static str,
        trigger: Box<HvfMemoryError>,
    },
    Finalization {
        trigger: Box<HvfMemoryError>,
        cleanup: Box<HvfMemoryError>,
    },
    IpaExhausted(usize),
    IpaOwnership,
    TableOwnership,
    StageOneWalkFailed(usize),
    AsidExhausted,
    AsidOwnership,
    MetadataAllocation(&'static str),
    CallbackOutputOccupied,
    CallbackOutputMissing,
    InjectedFailure(&'static str),
    Witness(&'static str),
    WitnessReport(Box<HvfMemoryReport>),
    FailureWitnessReport(Box<HvfMemoryFailureReport>),
    AliasPanicFailureWitnessReport(Box<HvfAliasPanicFailureReport>),
    UnmapWitnessReport(Box<HvfUnmapFailureReport>),
    /// A range operation asked for WRITE and EXECUTE on the same pages.
    WriteExecuteRefused(Range<usize>),
    /// A protect-shaped range operation touched a page that is not mapped.
    RangeUnmapped(Range<usize>),
    /// A host slot at this GVA is already owned by (or would be shared with) a
    /// mirrored address space, whose permanent alias cannot be shared.
    MirrorSlotShared(Range<usize>),
    /// `fork_private` is not available on a mirrored address space: two
    /// spaces cannot both mirror the same GVA on the host.
    MirrorForkUnsupported(HvfAddressSpaceId),
    /// The requested window does not fit the shared backing object even after
    /// growth, or the identity is unknown when it had to exist.
    SharedBackingRange {
        identity: usize,
        offset: usize,
        length: usize,
    },
    MirroredWitnessReport(Box<HvfMirroredViewReport>),
    AliasRaceWitnessReport(Box<HvfAliasRaceReport>),
}

impl HvfMemoryError {
    pub(crate) fn after_publication(operation: &'static str, trigger: Self) -> Self {
        match trigger {
            Self::PublishedMutation { .. } => trigger,
            trigger => Self::PublishedMutation {
                operation,
                trigger: Box::new(trigger),
            },
        }
    }

    fn finalization(trigger: Self, cleanup: Self) -> Self {
        Self::Finalization {
            trigger: Box::new(trigger),
            cleanup: Box::new(cleanup),
        }
    }

    fn with_cleanup(trigger: Self, cleanup: Result<(), Self>) -> Self {
        match cleanup {
            Ok(()) => trigger,
            Err(cleanup) => Self::finalization(trigger, cleanup),
        }
    }

    pub(crate) fn published_before_failure(&self) -> bool {
        match self {
            Self::PublishedMutation { .. } => true,
            Self::Finalization { trigger, cleanup } => {
                trigger.published_before_failure() || cleanup.published_before_failure()
            }
            Self::Hvf(error) => error.published_before_failure(),
            _ => false,
        }
    }
}

impl fmt::Display for HvfMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hvf(error) => write!(f, "{error}"),
            Self::HostBacking(error) => write!(f, "{error}"),
            Self::UnsupportedIpaWidth(bits) => write!(f, "unsupported HVF IPA width {bits}"),
            Self::EmptyRange => write!(f, "a compact HVF range cannot be empty"),
            Self::Unaligned { start, length } => write!(
                f,
                "compact HVF range start={start:#x} length={length:#x} is not 16 KiB aligned"
            ),
            Self::NoncanonicalAddress {
                address,
                va_bits,
                tbi0,
            } => write!(
                f,
                "GVA {address:#x} is outside the admitted {va_bits}-bit TBI0={tbi0} TTBR0 regime"
            ),
            Self::NoncanonicalRange {
                range,
                va_bits,
                tbi0,
            } => write!(
                f,
                "GVA range {:#x}..{:#x} crosses the admitted {va_bits}-bit TBI0={tbi0} TTBR0 limit",
                range.start, range.end
            ),
            Self::MonitorOverlap(range) => write!(
                f,
                "guest range {:#x}..{:#x} overlaps the EL1 monitor page",
                range.start, range.end
            ),
            Self::InvalidPermissions(bits) => write!(f, "invalid guest permission bits {bits:#x}"),
            Self::WriteWithoutRead => write!(f, "a writable guest mapping must include read"),
            Self::WriteExecute => write!(f, "compact HVF guest mappings enforce W^X"),
            Self::InitialExecute(range) => write!(
                f,
                "initial executable claim {:#x}..{:#x} must be non-executable and published first",
                range.start, range.end
            ),
            Self::BackingWriteExecute { backing, offset } => write!(
                f,
                "backing page {backing:?}+{offset:#x} has conflicting write and execute authority"
            ),
            Self::WrongMemoryManager => {
                write!(f, "the capability belongs to another HVF memory manager")
            }
            Self::AddressSpaceDestroyed(id) => write!(f, "HVF address space {id:?} is destroyed"),
            Self::AddressOverlap(range) => write!(
                f,
                "guest range {:#x}..{:#x} overlaps an existing logical claim",
                range.start, range.end
            ),
            Self::ClaimStale => write!(f, "the logical GVA claim is stale or foreign"),
            Self::RangeOutsideClaim(range) => write!(
                f,
                "range {:#x}..{:#x} is outside the logical GVA claim",
                range.start, range.end
            ),
            Self::SparseAlias(range) => write!(
                f,
                "range {:#x}..{:#x} contains a deferred PROT_NONE page",
                range.start, range.end
            ),
            Self::AliasBusy(range) => write!(
                f,
                "host slot {:#x}..{:#x} already has an active alias",
                range.start, range.end
            ),
            Self::AliasReentrant(range) => write!(
                f,
                "thread already owns a host alias while requesting {:#x}..{:#x}",
                range.start, range.end
            ),
            Self::AliasRestore(range) => write!(
                f,
                "host slot {:#x}..{:#x} could not return to PROT_NONE ownership",
                range.start, range.end
            ),
            Self::PublicationRequired(range) => write!(
                f,
                "executable range {:#x}..{:#x} needs an explicit cache-publication ticket",
                range.start, range.end
            ),
            Self::PublicationStale(range) => write!(
                f,
                "cache-publication ticket for {:#x}..{:#x} predates a backing write",
                range.start, range.end
            ),
            Self::RetirementStale => write!(f, "the retirement ticket is stale or foreign"),
            Self::RetirementParticipantsPending {
                retirement,
                pending,
            } => write!(
                f,
                "retirement {retirement} still needs {pending} owner-minted participant acknowledgements"
            ),
            Self::ParticipantStale(participant) => {
                write!(
                    f,
                    "HVF vCPU participant {participant:?} is stale or foreign"
                )
            }
            Self::ParticipantLaneUnavailable(generation) => write!(
                f,
                "HVF vCPU lane generation {generation} is no longer live for participant registration"
            ),
            Self::ParticipantLaneMismatch {
                participant,
                expected,
                actual,
            } => write!(
                f,
                "HVF participant {participant:?} belongs to lane generation {expected}, not {actual}"
            ),
            Self::ParticipantBusy(participant) => write!(
                f,
                "HVF participant {participant:?} still owns an in-flight run attachment"
            ),
            Self::ParticipantRetirementPending(participant) => write!(
                f,
                "HVF participant {participant:?} still owes a retirement acknowledgement"
            ),
            Self::AttachmentGenerationChanged => write!(
                f,
                "the HVF address space changed between vCPU attachment and submission"
            ),
            Self::AttachmentStale => write!(f, "the HVF vCPU run attachment is stale or foreign"),
            Self::AttachmentAbandoned(id) => write!(
                f,
                "address space {id:?} has an abandoned in-flight vCPU attachment"
            ),
            Self::SynchronizationStale => write!(
                f,
                "the owner-minted HVF cache/TLBI synchronization proof is stale or foreign"
            ),
            Self::DestroyTicketStale => {
                write!(
                    f,
                    "the HVF address-space destroy ticket is stale or foreign"
                )
            }
            Self::DestroyTicketAbandoned(id) => {
                write!(f, "address space {id:?} has an abandoned destroy ticket")
            }
            Self::AddressSpaceBusy(id) => {
                write!(
                    f,
                    "address space {id:?} still has vCPU participants or attachments"
                )
            }
            Self::RetirementsPending(id) => {
                write!(f, "address space {id:?} still has retirement tickets")
            }
            Self::ResourceLimit {
                resource,
                requested,
                limit,
            } => write!(
                f,
                "compact HVF {resource} request {requested} exceeds bound {limit}"
            ),
            Self::PublishedMutation { operation, trigger } => write!(
                f,
                "compact HVF {operation} published guest memory state before failing: {trigger}"
            ),
            Self::Finalization { trigger, cleanup } => write!(
                f,
                "compact HVF operation failed ({trigger}); cleanup also failed ({cleanup})"
            ),
            Self::IpaExhausted(pages) => {
                write!(f, "compact IPA aperture cannot allocate {pages} pages")
            }
            Self::IpaOwnership => write!(f, "compact IPA token ownership is inconsistent"),
            Self::TableOwnership => write!(f, "stage-one table ownership is inconsistent"),
            Self::StageOneWalkFailed(gva) => {
                write!(f, "software stage-one walk failed for GVA {gva:#x}")
            }
            Self::AsidExhausted => write!(f, "all admitted 8-bit ASIDs are in use"),
            Self::AsidOwnership => write!(f, "8-bit ASID ownership is inconsistent"),
            Self::MetadataAllocation(resource) => {
                write!(f, "failed to reserve compact HVF {resource} metadata")
            }
            Self::CallbackOutputOccupied => {
                write!(f, "the caller-owned HVF callback output is already filled")
            }
            Self::CallbackOutputMissing => {
                write!(
                    f,
                    "the HVF callback returned without filling its caller-owned output"
                )
            }
            Self::InjectedFailure(point) => write!(f, "injected compact-memory failure at {point}"),
            Self::Witness(message) => write!(f, "compact HVF memory witness failed: {message}"),
            Self::WitnessReport(report) => {
                write!(f, "compact HVF memory witness report:\n{report:#?}")
            }
            Self::FailureWitnessReport(report) => {
                write!(f, "compact HVF memory failure witness report:\n{report:#?}")
            }
            Self::AliasPanicFailureWitnessReport(report) => {
                write!(
                    f,
                    "compact HVF alias-panic failure witness report:\n{report:#?}"
                )
            }
            Self::UnmapWitnessReport(report) => {
                write!(f, "compact HVF unmap-failure witness report:\n{report:#?}")
            }
            Self::WriteExecuteRefused(range) => write!(
                f,
                "range {:#x}..{:#x} asked for write and execute together; W^X is enforced",
                range.start, range.end
            ),
            Self::RangeUnmapped(range) => write!(
                f,
                "range {:#x}..{:#x} contains a page that is not mapped",
                range.start, range.end
            ),
            Self::MirrorSlotShared(range) => write!(
                f,
                "host slot {:#x}..{:#x} cannot be shared with a mirrored address space",
                range.start, range.end
            ),
            Self::MirrorForkUnsupported(id) => {
                write!(f, "mirrored HVF address space {id:?} cannot be forked")
            }
            Self::SharedBackingRange {
                identity,
                offset,
                length,
            } => write!(
                f,
                "shared backing {identity} window offset={offset:#x} length={length:#x} is unavailable"
            ),
            Self::MirroredWitnessReport(report) => {
                write!(f, "compact HVF mirrored-view witness report:\n{report:#?}")
            }
            Self::AliasRaceWitnessReport(report) => {
                write!(f, "compact HVF alias-race witness report:\n{report:#?}")
            }
        }
    }
}

impl std::error::Error for HvfMemoryError {}

impl From<HvfError> for HvfMemoryError {
    fn from(value: HvfError) -> Self {
        let published = value.published_before_failure();
        let error = Self::Hvf(value);
        if published {
            Self::after_publication("SDK operation completion", error)
        } else {
            error
        }
    }
}

impl From<HvfHostBackingError> for HvfMemoryError {
    fn from(value: HvfHostBackingError) -> Self {
        Self::HostBacking(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct TableToken(u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct HostSlotToken(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IpaToken {
    id: u64,
    start: u64,
    pages: usize,
}

impl IpaToken {
    fn range(self) -> Range<u64> {
        self.start..self.start + (self.pages * PAGE_SIZE) as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackingPage {
    identity: HvfBackingIdentity,
    offset: usize,
}

#[derive(Clone, Debug)]
pub struct HvfClaim {
    manager: u64,
    address_space: HvfAddressSpaceId,
    id: u64,
    version: u64,
    range: Range<usize>,
}

impl HvfClaim {
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }
}

#[derive(Clone, Debug)]
pub struct HvfPublicationTicket {
    manager: u64,
    address_space: HvfAddressSpaceId,
    claim_id: u64,
    claim_version: u64,
    range: Range<usize>,
    pages: Vec<PublishedPage>,
}

#[derive(Clone, Debug)]
struct PublishedPage {
    backing: BackingPage,
    write_epoch: HvfWriteEpoch,
    publication_epoch: HvfPublicationEpoch,
}

#[must_use = "an HVF retirement ticket must be explicitly acknowledged"]
#[derive(Debug)]
pub struct HvfRetirementTicket {
    manager: u64,
    address_space: HvfAddressSpaceId,
    id: u64,
    generation: HvfRootGeneration,
    live: bool,
}

impl HvfRetirementTicket {
    /// Mints the live ticket for a retirement that is already recorded in
    /// `Acknowledgements::retirements` under `id`; the sole constructor, so a
    /// ticket can never name a retirement the ledger does not hold.
    const fn mint(
        manager: u64,
        address_space: HvfAddressSpaceId,
        id: u64,
        generation: HvfRootGeneration,
    ) -> Self {
        Self {
            manager,
            address_space,
            id,
            generation,
            live: true,
        }
    }

    pub const fn generation(&self) -> HvfRootGeneration {
        self.generation
    }

    pub const fn is_live(&self) -> bool {
        self.live
    }
}

#[derive(Debug)]
pub struct HvfMutation {
    pub claim: HvfClaim,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub retirement: HvfRetirementTicket,
}

#[derive(Debug)]
pub struct HvfUnmapResult {
    pub surviving_claims: Vec<HvfClaim>,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub retirement: HvfRetirementTicket,
}

/// Names a window of a process-global shared backing object: `identity` is
/// the caller's own object id (created on first use, grown on demand) and
/// `offset` is a byte offset into it. Mapping requires a page-aligned offset;
/// [`HvfMemory::with_shared_backing`] accepts any byte window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HvfSharedBackingKey {
    pub identity: usize,
    pub offset: usize,
}

#[must_use]
pub struct HvfCallbackOutput<R> {
    value: Option<R>,
}

impl<R> Default for HvfCallbackOutput<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R> HvfCallbackOutput<R> {
    pub const fn new() -> Self {
        Self { value: None }
    }

    pub fn as_ref(&self) -> Option<&R> {
        self.value.as_ref()
    }

    pub fn take(&mut self) -> Option<R> {
        self.value.take()
    }

    pub fn into_inner(self) -> Option<R> {
        self.value
    }

    fn vacant(&mut self) -> Result<HvfCallbackVacant<'_, R>, HvfMemoryError> {
        if self.value.is_some() {
            Err(HvfMemoryError::CallbackOutputOccupied)
        } else {
            Ok(HvfCallbackVacant { output: self })
        }
    }

    fn into_filled(self) -> Result<R, HvfMemoryError> {
        self.into_inner()
            .ok_or(HvfMemoryError::CallbackOutputMissing)
    }
}

struct HvfCallbackVacant<'a, R> {
    output: &'a mut HvfCallbackOutput<R>,
}

impl<R> HvfCallbackVacant<'_, R> {
    fn fill(&mut self, value: R) {
        self.output.value = Some(value);
    }
}

/// The outcome of one range-shaped mutation. Exactly one retirement ticket is
/// handed back per call; any inner retirements the call had to make (a
/// MAP_FIXED replacement, the claim beneath an executable map, per-claim
/// pieces of a multi-claim range) are acknowledged in place when nobody owes
/// a synchronization, and otherwise parked on the address space's deferred
/// list for [`HvfAddressSpace::pump_retirements`].
#[must_use = "an HVF range mutation carries a retirement ticket that must be acknowledged or deferred"]
#[derive(Debug)]
pub struct HvfRangeMutation {
    pub retirement: HvfRetirementTicket,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub changed: bool,
}

/// Report for [`hvf_alias_race_probe`]: a raw `memcpy_fallible` reader/writer
/// thread (standing in for a Linux shim syscall's `UserPtr`/`UserPtrMut`
/// dereference, which holds no lease and runs with no vCPU `in_flight` --
/// see the type's doc comment) races the owner thread's repeated
/// `unmap_range`/`map_range(replace=false)` on the exact same GVA, with no
/// synchronization between the two beyond what the mirrored address space
/// itself provides.
#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfAliasRaceReport {
    /// The racer thread never observed a byte pattern other than one the
    /// owner thread actually stamped in the epoch window the racer's own
    /// before/after snapshot bounds, or `0` (a freshly (re)claimed anonymous
    /// page reads as zero) -- i.e. it never read a torn word or another
    /// cycle's stale/foreign content.
    pub no_wrong_value_observed: bool,
    /// Every racer-thread fault (`memcpy_fallible` returning `Err`) landed
    /// while the owner thread's own `in_transition` flag (set for the
    /// `unmap_range`..`map_range` window, cleared once the page is mapped
    /// and re-stamped again) was observed set by the racer -- i.e. faults
    /// correlate with a real unmap window, not spurious host state such as
    /// a stray SIGBUS on an otherwise-mapped page.
    pub faults_only_during_transitions: bool,
    /// The racer thread's process (the same OS process, same address space)
    /// never crashed (SIGSEGV/SIGBUS escaping the exception-table recovery,
    /// or a Rust panic unwinding across the raw asm) for the whole race
    /// window -- checked by the probe simply completing and returning.
    pub racer_thread_survived: bool,
    /// At least one fault and at least one successful round-trip were each
    /// observed by the racer, so the race actually exercised both the
    /// "caught the page mapped" and "caught the page unmapped" windows
    /// instead of one side winning the whole run by scheduling luck.
    pub both_outcomes_observed: bool,
    /// Total racer iterations attempted.
    pub racer_iterations: u64,
    /// Racer iterations that faulted (recoverably).
    pub racer_faults: u64,
    /// Racer faults observed with the owner's `in_transition` flag clear --
    /// a fault outside any known unmap window. This is a best-effort,
    /// scheduler-sensitive heuristic, not a proof about the system under
    /// test: the racer reads `in_transition` with its own two atomic loads
    /// bracketing the faulting access, and under heavy host CPU
    /// oversubscription (many more runnable threads than cores) the racer
    /// can be preempted between them for long enough that the owner
    /// completes several further cycles, producing a false positive with
    /// [`no_wrong_value_observed`](Self::no_wrong_value_observed) still `true`.
    /// [`no_wrong_value_observed`](Self::no_wrong_value_observed)
    /// is the property that actually matters (no UAF/torn/foreign data);
    /// this field is corroborating evidence, expected to be zero at normal
    /// scheduling load and tolerated as a rare nonzero count only under
    /// genuine oversubscription -- see [`hvf_alias_race_probe`]'s doc
    /// comment.
    pub racer_faults_outside_transition: u64,
    /// Owner-thread unmap/remap cycles completed.
    pub owner_cycles: u64,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfMirroredViewReport {
    pub mirrored_space_flagged: bool,
    pub plain_space_not_mirrored: bool,
    pub host_write_visible_to_guest_alias: bool,
    pub host_view_permission_mirrored: bool,
    pub executable_view_read_only: bool,
    pub executable_host_write_faults_recoverably: bool,
    pub executable_host_read_still_works: bool,
    pub write_execute_refused: bool,
    pub writable_again_after_executable: bool,
    pub none_keeps_contents: bool,
    pub shared_execute_refused_while_host_writable: bool,
    pub unmapped_view_inaccessible: bool,
    pub partial_unmap_hole_refused: bool,
    pub replace_map_zeroed: bool,
    pub shared_backing_aliased: bool,
    pub shared_backing_initialized_before_map: bool,
    pub shared_backing_byte_window_verified: bool,
    pub rollback_restored_reservation: bool,
    pub fork_refused: bool,
    pub deferred_retirements_pumped: bool,
    pub usage_returned_to_baseline: bool,
    pub zero_vcpus_verified: bool,
    pub final_usage: HvfMemoryUsage,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

pub struct HvfForkResult {
    pub address_space: HvfAddressSpace,
    pub claims: Vec<HvfClaim>,
}

impl core::ops::Deref for HvfForkResult {
    type Target = HvfAddressSpace;

    fn deref(&self) -> &Self::Target {
        &self.address_space
    }
}

impl fmt::Debug for HvfForkResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfForkResult")
            .field("address_space", &self.address_space)
            .field("claims", &self.claims)
            .finish()
    }
}

impl HvfCompletionCapability for HvfForkResult {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        self.address_space.validate_hvf_completion(vm)?;
        let state = self
            .address_space
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.claims.len() != self.claims.len() {
            return Err(HvfError::ResidualAccounting);
        }
        for claim in &self.claims {
            if claim.manager != self.address_space.memory.manager
                || claim.address_space != self.address_space.cell.id
                || !state.claims.get(&claim.range.start).is_some_and(|record| {
                    record.id == claim.id
                        && record.version == claim.version
                        && record.range == claim.range
                })
            {
                return Err(HvfError::ResidualAccounting);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HvfRetirementReport {
    pub generation: HvfRootGeneration,
    pub charged_pages: usize,
    pub charged_bytes: usize,
    pub data_pages: usize,
    pub slot_pages: usize,
    pub backing_pages: usize,
    pub table_pages: usize,
    pub released_data_pages: usize,
    pub released_table_pages: usize,
    pub released_host_slots: usize,
    pub released_backing_references: usize,
    pub quarantined_resources: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfLedgerEntry {
    pub gva: Range<usize>,
    pub permissions: HvfGuestPermissions,
    pub sharing: HvfSharing,
    pub backing_identity: Option<HvfBackingIdentity>,
    pub backing_offset: usize,
    pub ipa: Vec<Range<u64>>,
    pub write_epoch: HvfWriteEpoch,
    pub publication_epoch: HvfPublicationEpoch,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HvfMemoryUsage {
    pub address_spaces: usize,
    pub claimed_pages: usize,
    pub live_data_pages: usize,
    pub table_pages: usize,
    /// Lifetime-pinned table pages owned by the ASID-zero synchronization root.
    pub synchronization_table_pages: usize,
    pub host_slots: usize,
    pub backing_objects: usize,
    pub physical_backing_pages: usize,
    pub physical_backing_bytes: usize,
    pub ipa_owned_pages: usize,
    /// IPA pages permanently owned by the ASID-zero synchronization root.
    pub synchronization_ipa_pages: usize,
    pub ipa_capacity_pages: usize,
    pub asids_owned: usize,
    pub active_alias_pages: usize,
    pub alias_quarantine_reservations: usize,
    pub data_quarantine_reservations: usize,
    pub retired_generations: usize,
    pub retired_pages: usize,
    pub retired_bytes: usize,
    pub quarantined_resources: usize,
    /// Host slots whose permanent permission-mirrored alias is installed.
    pub mirrored_alias_pages: usize,
    /// Process-global shared backing objects still pinned by their key.
    pub pinned_shared_backings: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfAddressSpaceReport {
    pub id: HvfAddressSpaceId,
    pub asid: HvfAsid,
    pub regime: HvfTranslationRegime,
    pub root_ipa: u64,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub pending_tlbi_generation: HvfTlbiGeneration,
    pub participant_count: usize,
    pub in_flight_attachments: usize,
    pub attachment_abandoned: bool,
    pub stage_one_table_pages: usize,
    pub monitor_leaf_ipa: u64,
    pub mappings: Vec<HvfLedgerEntry>,
    pub usage: HvfMemoryUsage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HvfVcpuMemorySnapshot {
    pub address_space_id: HvfAddressSpaceId,
    pub asid: HvfAsid,
    pub regime: HvfTranslationRegime,
    pub synchronization_ttbr0_el1: u64,
    pub ttbr0_el1: u64,
    pub root_generation: HvfRootGeneration,
    pub executable_generation: HvfExecutableGeneration,
    pub pending_tlbi_generation: HvfTlbiGeneration,
}

/// One participant record repaired by
/// [`HvfAddressSpace::recover_stopped_vcpu_participants`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HvfParticipantRecoveryReceipt {
    pub participant: HvfVcpuParticipantId,
    /// In-flight attachments this recovery released back to the address space
    /// after unlinking the abandoned lease from the record.
    pub released_in_flight: usize,
    /// `true` when the record itself was removed because its participant handle
    /// was abandoned on a stopped lane; `false` when only the abandoned
    /// attachment was cleared and the participant stays registered.
    pub removed: bool,
}

#[must_use = "an HVF vCPU participant must be explicitly deregistered"]
pub struct HvfVcpuParticipant {
    manager: u64,
    address_space: HvfAddressSpaceId,
    id: HvfVcpuParticipantId,
    lane_generation: u64,
    lane_lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    capability_state: Arc<AtomicU8>,
}

impl fmt::Debug for HvfVcpuParticipant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuParticipant")
            .field("address_space", &self.address_space)
            .field("id", &self.id)
            .field("lane_generation", &self.lane_generation)
            .field(
                "capability_state",
                &self.capability_state.load(Ordering::Acquire),
            )
            .finish_non_exhaustive()
    }
}

impl HvfVcpuParticipant {
    pub const fn id(&self) -> HvfVcpuParticipantId {
        self.id
    }

    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }
}

impl Drop for HvfVcpuParticipant {
    fn drop(&mut self) {
        let _ = self.capability_state.compare_exchange(
            PARTICIPANT_LIVE,
            PARTICIPANT_ABANDONED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

pub struct HvfVcpuRunAttachment {
    memory: &'static HvfMemory,
    cell: Arc<AddressSpaceCell>,
    participant: HvfVcpuParticipantId,
    lane_generation: u64,
    snapshot: HvfVcpuMemorySnapshot,
    requires_synchronization: bool,
    lease_state: Arc<AtomicU8>,
}

impl fmt::Debug for HvfVcpuRunAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfVcpuRunAttachment")
            .field("address_space", &self.snapshot.address_space_id)
            .field("participant", &self.participant)
            .field("lane_generation", &self.lane_generation)
            .field("snapshot", &self.snapshot)
            .field("requires_synchronization", &self.requires_synchronization)
            .finish_non_exhaustive()
    }
}

impl HvfVcpuRunAttachment {
    pub const fn participant_id(&self) -> HvfVcpuParticipantId {
        self.participant
    }

    pub const fn lane_generation(&self) -> u64 {
        self.lane_generation
    }

    pub const fn snapshot(&self) -> &HvfVcpuMemorySnapshot {
        &self.snapshot
    }

    pub const fn requires_synchronization(&self) -> bool {
        self.requires_synchronization
    }

    pub fn synchronization_request(&self) -> HvfSynchronizationRequest {
        HvfSynchronizationRequest {
            address_space_id: self.snapshot.address_space_id.value(),
            participant_id: self.participant.value(),
            asid: self.snapshot.asid.value,
            asid_epoch: self.snapshot.asid.epoch,
            synchronization_ttbr0_el1: self.snapshot.synchronization_ttbr0_el1,
            ttbr0_el1: self.snapshot.ttbr0_el1,
            tcr_el1: self.snapshot.regime.tcr_el1,
            mair_el1: u64::from(self.snapshot.regime.mair_attr0),
            root_generation: self.snapshot.root_generation.value(),
            executable_generation: self.snapshot.executable_generation.value(),
            tlbi_generation: self.snapshot.pending_tlbi_generation.value(),
        }
    }

    pub(crate) fn submit(&self, lane_generation: u64) -> Result<(), HvfMemoryError> {
        if lane_generation != self.lane_generation {
            return Err(HvfMemoryError::ParticipantLaneMismatch {
                participant: self.participant,
                expected: self.lane_generation,
                actual: lane_generation,
            });
        }
        if self.lease_state.load(Ordering::Acquire) != ATTACHMENT_ALLOCATED {
            return Err(HvfMemoryError::AttachmentStale);
        }
        self.memory.vm.with_shared_operation(|operation| {
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            if state.root_generation != self.snapshot.root_generation
                || state.executable_generation != self.snapshot.executable_generation
                || state.pending_tlbi_generation != self.snapshot.pending_tlbi_generation
            {
                return Err(HvfMemoryError::AttachmentGenerationChanged);
            }
            let participant = state
                .participants
                .get(&self.participant)
                .ok_or(HvfMemoryError::ParticipantStale(self.participant))?;
            if participant.lane_generation != lane_generation {
                return Err(HvfMemoryError::ParticipantLaneMismatch {
                    participant: self.participant,
                    expected: participant.lane_generation,
                    actual: lane_generation,
                });
            }
            if participant.capability_state.load(Ordering::Acquire) != PARTICIPANT_LIVE {
                return Err(HvfMemoryError::ParticipantStale(self.participant));
            }
            if !hvf_vcpu_lane_is_live(&participant.lane_lifecycle, &participant.owner_stopped) {
                return Err(HvfMemoryError::ParticipantLaneUnavailable(
                    participant.lane_generation,
                ));
            }
            if participant.in_flight != 0 || participant.attachment_state.is_some() {
                return Err(HvfMemoryError::ParticipantBusy(self.participant));
            }
            let in_flight = state
                .in_flight
                .checked_add(1)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let synchronization_ttbr0 =
                arenas.tables.ipa(self.memory.synchronization_root.token)?;
            if synchronization_ttbr0 != self.memory.synchronization_root.ipa {
                return Err(HvfMemoryError::TableOwnership);
            }
            let expected_ttbr0 =
                (u64::from(self.cell.asid.value) << 48) | arenas.tables.ipa(state.root)?;
            if self.snapshot.address_space_id != self.cell.id
                || self.snapshot.asid != self.cell.asid
                || self.snapshot.regime != self.cell.regime
                || self.snapshot.synchronization_ttbr0_el1 != synchronization_ttbr0
                || self.snapshot.ttbr0_el1 != expected_ttbr0
            {
                return Err(HvfMemoryError::AttachmentStale);
            }
            operation.require_live()?;
            // Re-look the record up mutably before the lease CAS: every fallible
            // step precedes the first mutation, so a failed lookup can never
            // strand a lease in SUBMITTED with no ledger row behind it.
            let participant = state
                .participants
                .get_mut(&self.participant)
                .ok_or(HvfMemoryError::ParticipantStale(self.participant))?;
            self.lease_state
                .compare_exchange(
                    ATTACHMENT_ALLOCATED,
                    ATTACHMENT_SUBMITTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| HvfMemoryError::AttachmentStale)?;
            operation.mark_published()?;
            participant.in_flight = 1;
            participant.attachment_state = Some(Arc::clone(&self.lease_state));
            state.in_flight = in_flight;
            Ok(())
        })
    }

    pub(crate) fn begin_synchronizing(&self, lane_generation: u64) -> Result<(), HvfMemoryError> {
        if !self.requires_synchronization || lane_generation != self.lane_generation {
            return Err(HvfMemoryError::AttachmentStale);
        }
        self.lease_state
            .compare_exchange(
                ATTACHMENT_SUBMITTED,
                ATTACHMENT_SYNCHRONIZING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| HvfMemoryError::AttachmentStale)
    }

    pub(crate) fn begin_running(&self, lane_generation: u64) -> Result<(), HvfMemoryError> {
        if lane_generation != self.lane_generation {
            return Err(HvfMemoryError::ParticipantLaneMismatch {
                participant: self.participant,
                expected: self.lane_generation,
                actual: lane_generation,
            });
        }
        let expected = if self.requires_synchronization {
            ATTACHMENT_SYNCHRONIZING
        } else {
            ATTACHMENT_SUBMITTED
        };
        self.lease_state
            .compare_exchange(
                expected,
                ATTACHMENT_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| HvfMemoryError::AttachmentStale)?;
        HvfAddressSpace {
            memory: self.memory,
            cell: Arc::clone(&self.cell),
        }
        .validate_attachment_for_run(self)
    }

    pub(crate) fn acknowledge_owner_synchronization(
        &self,
        proof: HvfOwnerSynchronizationProof,
    ) -> Result<(), HvfMemoryError> {
        if self.lease_state.load(Ordering::Acquire) != ATTACHMENT_SYNCHRONIZING {
            return Err(HvfMemoryError::AttachmentStale);
        }
        HvfAddressSpace {
            memory: self.memory,
            cell: Arc::clone(&self.cell),
        }
        .acknowledge_synchronization(self, proof)
    }

    /// Marks the lease abandoned and flags the owning cell so mutators stay
    /// refused until recovery runs; idempotent, and the same transition `Drop`
    /// applies to a lease that was never retired.
    fn abandon(&self) {
        self.lease_state
            .store(ATTACHMENT_ABANDONED, Ordering::Release);
        self.cell
            .attachment_abandoned
            .store(true, Ordering::Release);
    }

    pub(crate) fn finish(self) -> Result<(), HvfMemoryError> {
        let address_space = HvfAddressSpace {
            memory: self.memory,
            cell: Arc::clone(&self.cell),
        };
        address_space.finish_vcpu_attachment(self)
    }
}

impl Drop for HvfVcpuRunAttachment {
    fn drop(&mut self) {
        match self.lease_state.load(Ordering::Acquire) {
            ATTACHMENT_ALLOCATED => {
                self.lease_state.store(ATTACHMENT_CLOSED, Ordering::Release);
            }
            ATTACHMENT_CLOSED | ATTACHMENT_ABANDONED => {}
            _ => self.abandon(),
        }
    }
}

#[must_use = "an HVF address-space destroy ticket must be explicitly finished"]
pub struct HvfAddressSpaceDestroyTicket {
    memory: &'static HvfMemory,
    cell: Arc<AddressSpaceCell>,
    manager: u64,
    address_space: HvfAddressSpaceId,
    asid: HvfAsid,
    root: TableToken,
    root_generation: HvfRootGeneration,
    lifecycle: Arc<AtomicU8>,
}

impl fmt::Debug for HvfAddressSpaceDestroyTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfAddressSpaceDestroyTicket")
            .field("address_space", &self.address_space)
            .field("asid", &self.asid)
            .field("root_generation", &self.root_generation)
            .field("lifecycle", &self.lifecycle.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Drop for HvfAddressSpaceDestroyTicket {
    fn drop(&mut self) {
        if self.lifecycle.load(Ordering::Acquire) == DESTROY_TICKET_LIVE {
            self.lifecycle
                .store(DESTROY_TICKET_ABANDONED, Ordering::Release);
            self.cell.destroy_abandoned.store(true, Ordering::Release);
        }
    }
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfPoisonConcurrencyReport {
    pub poison_requested_while_owner_live: bool,
    pub normal_rejected_while_owner_live: bool,
    pub contender_timed_out_while_owner_live: bool,
    pub poison_waited_for_owner_release: bool,
    pub cleanup_admitted_after_poison: bool,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfRegisterFailureReport {
    pub programmed_stage_one: HvfStageOneRegisterReport,
    pub stage_one_programming_verified: bool,
    pub mismatch_rejected: bool,
    pub vcpu_registered_to_current_thread: bool,
    pub vcpu_destroyed_without_residual: bool,
    pub cleanup_retry_released_vcpus: usize,
    pub active_vcpu_count: usize,
    pub quarantined_vcpu_count: usize,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfUnmapFailureReport {
    pub poison_observed_before_capability_finish: bool,
    pub committed_capability_returned_after_poison: bool,
    pub returned_capability_token: u64,
    pub normal_operation_rejected_after_capability_finish: bool,
    pub returned_capability_cleanup_succeeded: bool,
    pub capability_cleanup_residuals: HvfSdkResidualReport,
    pub explicit_unmap_succeeded: bool,
    pub protect_failure_observed: bool,
    pub protect_failure_quarantined: bool,
    pub quarantined_handle_rejected_cleanup: bool,
    pub unmap_failure_observed: bool,
    pub unmap_failure_quarantined: bool,
    pub sdk_residuals_before_retry: HvfSdkResidualReport,
    pub cleanup_retry_cleared_fragments: usize,
    pub sdk_residuals_after_retry: HvfSdkResidualReport,
    pub final_sdk_residuals: HvfSdkResidualReport,
    pub post_poison_cleanup_succeeded: bool,
    pub vm_poisoned: bool,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent outcome of finishing the unmap capability"
)]
struct HvfUnmapCapabilityCompletion<'vm> {
    capability: HvfMapping<'vm>,
    poison_observed_before_capability_finish: bool,
    protect_failure_observed: bool,
    protect_failure_quarantined: bool,
    quarantined_handle_rejected_cleanup: bool,
    unmap_failure_observed: bool,
    unmap_failure_quarantined: bool,
    sdk_residuals_before_retry: HvfSdkResidualReport,
    cleanup_retry_cleared_fragments: usize,
    sdk_residuals_after_retry: HvfSdkResidualReport,
}

impl HvfCompletionCapability for HvfUnmapCapabilityCompletion<'_> {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        self.capability.validate_hvf_completion(vm)
    }
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfMemoryReport {
    pub configured_ipa_bits: u32,
    pub monitor_ipa: u64,
    pub regime: HvfTranslationRegime,
    pub monitor_leaf_verified: bool,
    pub dynamic_tcr_ips_verified: bool,
    pub sparse_claim_verified: bool,
    pub split_verified: bool,
    pub coalesce_verified: bool,
    pub all_stage_one_boundaries_verified: bool,
    pub nonzero_offsets_verified: bool,
    pub compact_nonidentity_ipa_verified: bool,
    pub exact_ipa_reuse_verified: bool,
    pub retired_ipa_held_until_ack_verified: bool,
    pub overlap_rejection_verified: bool,
    pub adjacent_claims_verified: bool,
    pub independent_roots_verified: bool,
    pub competitor_isolation_verified: bool,
    pub asid_reuse_verified: bool,
    pub alias_reservation_verified: bool,
    pub alias_preflight_verified: bool,
    pub alias_reentry_verified: bool,
    pub alias_concurrency_verified: bool,
    pub private_fork_verified: bool,
    pub fork_capability_order_verified: bool,
    pub shared_coherence_verified: bool,
    pub global_wx_fork_retirement_verified: bool,
    pub initial_execute_rejected: bool,
    pub publication_epoch_verified: bool,
    pub stale_publication_rejected: bool,
    pub all_resource_limits_verified: bool,
    pub rollback_verified: bool,
    pub retirement_verified: bool,
    pub retirement_checkpoints_verified: bool,
    pub physical_accounting_verified: bool,
    pub allocator_conservation_verified: bool,
    pub zero_vcpus_verified: bool,
    pub final_usage: HvfMemoryUsage,
    pub sdk_residuals: HvfSdkResidualReport,
    pub host_backing: HvfHostBackingReport,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
pub struct HvfQuarantineRetryReport {
    pub sdk_mapping_fragments_released: usize,
    pub host_resources_released: usize,
    pub aliases_restored: usize,
    pub data_pages_released: usize,
    pub table_pages_released: usize,
    pub host_slots_released: usize,
    pub backings_released: usize,
    pub sdk_residuals: HvfSdkResidualReport,
    pub remaining: HvfMemoryUsage,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfMemoryFailureReport {
    pub rollback_preserved_root: bool,
    pub alias_restore_failure_observed: bool,
    pub data_unmap_failure_observed: bool,
    pub table_unmap_failure_observed: bool,
    pub quarantine_count_before_retry: usize,
    pub quarantine_retry: HvfQuarantineRetryReport,
    pub final_quarantine_count: usize,
    pub post_poison_destroy_succeeded: bool,
    pub zero_vcpus_verified: bool,
    pub final_usage: HvfMemoryUsage,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

#[derive(Clone, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field records an independent property the diagnostic verified"
)]
pub struct HvfAliasPanicFailureReport {
    pub original_payload_preserved: bool,
    pub restore_failure_quarantined: bool,
    pub cleanup_retry_restored_alias: bool,
    pub post_poison_destroy_succeeded: bool,
    pub final_usage: HvfMemoryUsage,
    pub sdk_residuals: HvfSdkResidualReport,
    pub vm_poisoned: bool,
}

#[repr(align(16384))]
struct StageOneTable([u64; TABLE_ENTRIES]);

struct IpaAllocator {
    base: u64,
    owners: Vec<u64>,
    next_id: u64,
    /// Pages with a non-zero owner, kept exact so usage accounting never
    /// rescans the ownership vector.
    owned: usize,
    /// No page below this index is free: first-fit resumes here instead of
    /// at zero, and every release lowers it.
    search_hint: usize,
}

impl IpaAllocator {
    fn new(range: Range<u64>, max_pages: usize) -> Result<Self, HvfMemoryError> {
        let length = range
            .end
            .checked_sub(range.start)
            .ok_or(HvfMemoryError::IpaExhausted(max_pages))?;
        if !range.start.is_multiple_of(PAGE_SIZE as u64) || !length.is_multiple_of(PAGE_SIZE as u64)
        {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let available_pages = usize::try_from(length / PAGE_SIZE as u64)
            .map_err(|_| HvfMemoryError::IpaExhausted(max_pages))?;
        let capacity = available_pages.min(max_pages);
        if capacity == 0 {
            return Err(HvfMemoryError::IpaExhausted(max_pages));
        }
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(capacity)
            .map_err(|_| HvfMemoryError::MetadataAllocation("IPA ownership"))?;
        owners.resize(capacity, 0);
        Ok(Self {
            base: range.start,
            owners,
            next_id: 1,
            owned: 0,
            search_hint: 0,
        })
    }

    /// First-fit over the ownership vector: the lowest run of `pages` free
    /// pages, exactly as a scan from zero would find it, but resumed from
    /// [`Self::search_hint`] (below which nothing is free).
    fn allocate(&mut self, pages: usize) -> Result<IpaToken, HvfMemoryError> {
        let len = self.owners.len();
        if pages == 0 || pages > len {
            return Err(HvfMemoryError::IpaExhausted(pages));
        }
        let mut index = self.search_hint.min(len);
        let mut first_free = None;
        let mut found = None;
        while index < len {
            if self.owners[index] != 0 {
                index += 1;
                continue;
            }
            if first_free.is_none() {
                first_free = Some(index);
            }
            let mut end = index;
            while end < len && end - index < pages && self.owners[end] == 0 {
                end += 1;
            }
            if end - index == pages {
                found = Some(index);
                break;
            }
            index = end;
        }
        let index = found.ok_or(HvfMemoryError::IpaExhausted(pages))?;
        let id = self.next_id;
        let next_id = id.checked_add(1).ok_or(HvfMemoryError::IpaOwnership)?;
        let start = self
            .base
            .checked_add((index * PAGE_SIZE) as u64)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let owned = self
            .owned
            .checked_add(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        self.owners[index..index + pages].fill(id);
        self.next_id = next_id;
        self.owned = owned;
        // Everything below the first free page seen is still owned; when that
        // page was the one just taken, the run behind it is now owned too.
        self.search_hint = match first_free {
            Some(first) if first == index => index + pages,
            Some(first) => first,
            None => index + pages,
        };
        Ok(IpaToken { id, start, pages })
    }

    fn release(&mut self, token: IpaToken) -> Result<(), HvfMemoryError> {
        let offset = token
            .start
            .checked_sub(self.base)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if token.id == 0 || token.pages == 0 || !offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let index =
            usize::try_from(offset / PAGE_SIZE as u64).map_err(|_| HvfMemoryError::IpaOwnership)?;
        let end = index
            .checked_add(token.pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let owners = self
            .owners
            .get_mut(index..end)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if owners.iter().any(|owner| *owner != token.id) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let owned = self
            .owned
            .checked_sub(token.pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        owners.fill(0);
        self.owned = owned;
        self.search_hint = self.search_hint.min(index);
        Ok(())
    }

    fn owned_pages(&self) -> usize {
        self.owned
    }

    fn capacity_pages(&self) -> usize {
        self.owners.len()
    }

    fn owns(&self, token: IpaToken) -> bool {
        let Some(offset) = token.start.checked_sub(self.base) else {
            return false;
        };
        if token.id == 0 || token.pages == 0 || !offset.is_multiple_of(PAGE_SIZE as u64) {
            return false;
        }
        let Ok(index) = usize::try_from(offset / PAGE_SIZE as u64) else {
            return false;
        };
        let Some(end) = index.checked_add(token.pages) else {
            return false;
        };
        self.owners
            .get(index..end)
            .is_some_and(|owners| owners.iter().all(|owner| *owner == token.id))
    }
}

struct AsidAllocator {
    free: [bool; MAX_ASIDS as usize],
    epochs: [u64; MAX_ASIDS as usize],
}

impl AsidAllocator {
    fn new() -> Self {
        let mut free = [true; MAX_ASIDS as usize];
        free[0] = false;
        Self {
            free,
            epochs: [0; MAX_ASIDS as usize],
        }
    }

    fn allocate(&mut self) -> Result<HvfAsid, HvfMemoryError> {
        let index = self
            .free
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(index, free)| free.then_some(index))
            .ok_or(HvfMemoryError::AsidExhausted)?;
        self.free[index] = false;
        Ok(HvfAsid {
            value: index.trunc(),
            epoch: self.epochs[index],
        })
    }

    fn release(&mut self, asid: HvfAsid) -> Result<(), HvfMemoryError> {
        let index = usize::from(asid.value);
        if asid.value == 0 || self.free[index] || self.epochs[index] != asid.epoch {
            return Err(HvfMemoryError::AsidOwnership);
        }
        let epoch = self.epochs[index]
            .checked_add(1)
            .ok_or(HvfMemoryError::AsidOwnership)?;
        self.epochs[index] = epoch;
        self.free[index] = true;
        Ok(())
    }

    fn owned(&self) -> usize {
        self.free.iter().skip(1).filter(|free| !**free).count()
    }
}

struct StageOneTableBacking {
    bytes: ManuallyDrop<Box<StageOneTable>>,
    mapping_may_remain: bool,
}

impl StageOneTableBacking {
    fn new(bytes: Box<StageOneTable>) -> Self {
        Self {
            bytes: ManuallyDrop::new(bytes),
            mapping_may_remain: false,
        }
    }

    fn arm_before_mapping(&mut self) {
        self.mapping_may_remain = true;
    }

    fn disarm_after_exact_absence(&mut self) {
        self.mapping_may_remain = false;
    }

    fn mapping_may_remain(&self) -> bool {
        self.mapping_may_remain
    }
}

impl Deref for StageOneTableBacking {
    type Target = StageOneTable;

    fn deref(&self) -> &Self::Target {
        self.bytes.as_ref()
    }
}

impl DerefMut for StageOneTableBacking {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.bytes.as_mut()
    }
}

impl Drop for StageOneTableBacking {
    fn drop(&mut self) {
        if !self.mapping_may_remain {
            unsafe { ManuallyDrop::drop(&mut self.bytes) };
        }
    }
}

struct TableRecord {
    level: u8,
    ipa: IpaToken,
    bytes: StageOneTableBacking,
    children: HashMap<usize, TableToken>,
    references: usize,
    mapping: Option<HvfMapping<'static>>,
}

struct TableQuarantine {
    ipa: Option<IpaToken>,
    bytes: StageOneTableBacking,
    sdk_token: Option<u64>,
    retryable: bool,
}

/// A released table page kept ready for reuse: still stage-2 mapped at its
/// IPA, contents zeroed, owned by nobody. Reusing it costs a 16 KiB copy
/// instead of an `hv_vm_unmap` now and an `hv_vm_map` later.
struct PooledTable {
    ipa: IpaToken,
    bytes: StageOneTableBacking,
    mapping: HvfMapping<'static>,
}

/// Upper bound on pooled table pages regardless of the table-page limit.
const TABLE_POOL_MAX_PAGES: usize = 1024;

struct TableArena {
    records: HashMap<TableToken, TableRecord>,
    next_token: u64,
    quarantined: Vec<TableQuarantine>,
    /// Outstanding failed-release obligations, keyed by root with an
    /// explicit multiplicity count. A token can gain more than one
    /// obligation when independent retains on the *same* table each fail to
    /// release (e.g. two nested candidate-root cleanups on one token during
    /// sustained allocation pressure): each occurrence is one distinct
    /// `release` call still owed, so the count -- never a plain dedup by
    /// token identity -- is what must be discharged before the token is
    /// dropped from this list.
    abandoned_roots: Vec<(TableToken, usize)>,
    /// Released pages awaiting reuse; never longer than `pool_limit`, and
    /// drained (really unmapped) once the last address space is gone.
    pool: Vec<PooledTable>,
    pool_limit: usize,
    /// Sum of every record's `children.len()`, kept exact at record insert
    /// and removal (children maps are never edited in place), so release
    /// planning sizes its work list without walking every table.
    edges: usize,
}

impl TableArena {
    fn new(limit: usize) -> Result<Self, HvfMemoryError> {
        let mut records = HashMap::new();
        records
            .try_reserve(limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table ownership"))?;
        let mut quarantined = Vec::new();
        quarantined
            .try_reserve_exact(limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
        let mut abandoned_roots = Vec::new();
        abandoned_roots
            .try_reserve_exact(limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table root quarantine"))?;
        let pool_limit = (limit / 4).min(TABLE_POOL_MAX_PAGES);
        let mut pool = Vec::new();
        pool.try_reserve_exact(pool_limit)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table pool"))?;
        Ok(Self {
            records,
            next_token: 1,
            quarantined,
            abandoned_roots,
            pool,
            pool_limit,
            edges: 0,
        })
    }

    /// Total parent-to-child edges over every record, from the running
    /// counter (cross-checked against a full walk in debug builds).
    fn edge_count(&self) -> Result<usize, HvfMemoryError> {
        if cfg!(debug_assertions) {
            let recounted = self.records.values().try_fold(0usize, |count, record| {
                count
                    .checked_add(record.children.len())
                    .ok_or(HvfMemoryError::TableOwnership)
            })?;
            debug_assert_eq!(self.edges, recounted);
        }
        Ok(self.edges)
    }

    /// Pooled pages plus everything owned or quarantined: what the table-page
    /// limit is charged against.
    fn charged_pages(&self) -> Result<usize, HvfMemoryError> {
        self.records
            .len()
            .checked_add(self.quarantined.len())
            .and_then(|owned| owned.checked_add(self.pool.len()))
            .ok_or(HvfMemoryError::TableOwnership)
    }

    /// Returns a detached, still-mapped page to the pool when there is room;
    /// hands it back otherwise so the caller unmaps it.
    fn pool_page(
        &mut self,
        ipa: IpaToken,
        mut bytes: StageOneTableBacking,
        mapping: HvfMapping<'static>,
    ) -> Option<(IpaToken, StageOneTableBacking, HvfMapping<'static>)> {
        if self.pool.len() >= self.pool_limit {
            return Some((ipa, bytes, mapping));
        }
        bytes.0.fill(0);
        // Capacity for `pool_limit` entries was reserved up front.
        self.pool.push(PooledTable {
            ipa,
            bytes,
            mapping,
        });
        None
    }

    /// Really unmaps every pooled page. Failures quarantine the page exactly
    /// like a failed release of an owned table and poison the VM.
    fn drain_pool(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
    ) -> Result<(), HvfMemoryError> {
        self.quarantined
            .try_reserve(self.pool.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
        let mut first_error = None;
        while let Some(pooled) = self.pool.pop() {
            let PooledTable {
                ipa,
                mut bytes,
                mapping,
            } = pooled;
            let sdk_token = mapping.token();
            if let Err(error) = mapping.unmap() {
                self.quarantined.push(TableQuarantine {
                    ipa: Some(ipa),
                    bytes,
                    sdk_token: Some(sdk_token),
                    retryable: true,
                });
                vm.poison();
                first_error.get_or_insert(error.into());
                continue;
            }
            bytes.disarm_after_exact_absence();
            if let Err(error) = allocator.release(ipa) {
                self.quarantined.push(TableQuarantine {
                    ipa: Some(ipa),
                    bytes,
                    sdk_token: None,
                    retryable: true,
                });
                vm.poison();
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn allocate(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
        level: u8,
        bytes: Box<StageOneTable>,
        children: HashMap<usize, TableToken>,
        limit: usize,
    ) -> Result<TableToken, HvfMemoryError> {
        let charged = self.charged_pages()?;
        if self.pool.is_empty() {
            // A pooled page is already charged; only a fresh page adds one.
            admit_resource("stage-one table pages", charged, 1, limit)?;
        }
        self.records
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table ownership"))?;
        self.quarantined
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
        let token = TableToken(self.next_token);
        let next_token = self
            .next_token
            .checked_add(1)
            .ok_or(HvfMemoryError::TableOwnership)?;
        if self.records.contains_key(&token) {
            return Err(HvfMemoryError::TableOwnership);
        }

        let mut child_increments = HashMap::<TableToken, usize>::new();
        child_increments
            .try_reserve(children.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table child ownership"))?;
        for child in children.values() {
            let increment = child_increments.entry(*child).or_default();
            *increment = increment
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
        }
        let mut child_references = Vec::new();
        child_references
            .try_reserve_exact(child_increments.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table child ownership"))?;
        for (child, increment) in child_increments {
            let references = self
                .records
                .get(&child)
                .ok_or(HvfMemoryError::TableOwnership)?
                .references;
            let updated = references
                .checked_add(increment)
                .ok_or(HvfMemoryError::TableOwnership)?;
            child_references.push((child, references, updated));
        }
        let mut bytes = StageOneTableBacking::new(bytes);
        let (ipa, mut bytes, mapping) = if let Some(pooled) = self.pool.pop() {
            // The pooled page is still stage-2 mapped at its IPA; only its
            // contents change, and nothing references it until the new
            // root that carries it is published.
            let PooledTable {
                ipa,
                bytes: mut pooled_bytes,
                mapping,
            } = pooled;
            pooled_bytes.0.copy_from_slice(&bytes.0);
            drop(bytes);
            (ipa, pooled_bytes, mapping)
        } else {
            let ipa = allocator.allocate(1)?;
            bytes.arm_before_mapping();
            let start = bytes.0.as_ptr() as usize;
            let mapping = unsafe {
                vm.map_host_range(start..start + PAGE_SIZE, ipa.start, HvfMapPermissions::READ)
            };
            match mapping {
                Ok(mapping) => (ipa, bytes, mapping),
                Err(error) => {
                    let sdk_token = error.residual_mapping_token();
                    if sdk_token.is_some() {
                        self.quarantined.push(TableQuarantine {
                            ipa: Some(ipa),
                            bytes,
                            sdk_token,
                            retryable: true,
                        });
                    } else {
                        bytes.disarm_after_exact_absence();
                        if allocator.release(ipa).is_err() {
                            self.quarantined.push(TableQuarantine {
                                ipa: Some(ipa),
                                bytes,
                                sdk_token: None,
                                retryable: true,
                            });
                            vm.poison();
                        }
                    }
                    return Err(error.into());
                }
            }
        };
        for (child, _, updated) in &child_references {
            self.records
                .get_mut(child)
                .ok_or(HvfMemoryError::TableOwnership)?
                .references = *updated;
        }
        let child_edges = children.len();
        match self.records.entry(token) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(TableRecord {
                    level,
                    ipa,
                    bytes,
                    children,
                    references: 0,
                    mapping: Some(mapping),
                });
                self.edges = self.edges.saturating_add(child_edges);
                self.next_token = next_token;
                Ok(token)
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                let mut cleanup_error = None;
                for (child, original, _) in &child_references {
                    if let Some(record) = self.records.get_mut(child) {
                        record.references = *original;
                    } else {
                        vm.poison();
                        cleanup_error.get_or_insert(HvfMemoryError::TableOwnership);
                    }
                }
                let sdk_token = mapping.token();
                if let Err(error) = mapping.unmap() {
                    self.quarantined.push(TableQuarantine {
                        ipa: Some(ipa),
                        bytes,
                        sdk_token: Some(sdk_token),
                        retryable: true,
                    });
                    vm.poison();
                    cleanup_error.get_or_insert(error.into());
                } else {
                    bytes.disarm_after_exact_absence();
                    if let Err(error) = allocator.release(ipa) {
                        self.quarantined.push(TableQuarantine {
                            ipa: Some(ipa),
                            bytes,
                            sdk_token: None,
                            retryable: true,
                        });
                        vm.poison();
                        cleanup_error.get_or_insert(error);
                    }
                }
                vm.poison();
                Err(cleanup_error.unwrap_or(HvfMemoryError::TableOwnership))
            }
        }
    }

    fn abandon_root(&mut self, token: TableToken) -> Result<(), HvfMemoryError> {
        if !self.records.contains_key(&token) {
            return Err(HvfMemoryError::TableOwnership);
        }
        Self::record_abandoned(&mut self.abandoned_roots, token)
    }

    fn abandon_unreferenced(&mut self, created: &[TableToken]) -> Result<(), HvfMemoryError> {
        for token in created {
            if !self.records.contains_key(token) {
                return Err(HvfMemoryError::TableOwnership);
            }
        }
        for token in created {
            if self
                .records
                .get(token)
                .is_some_and(|record| record.references == 0)
            {
                Self::record_abandoned(&mut self.abandoned_roots, *token)?;
            }
        }
        Ok(())
    }

    /// Adds one release obligation for `token`. An existing entry for the
    /// same token has its multiplicity incremented in place -- no new `Vec`
    /// slot, so the up-front `try_reserve_exact(limit)` capacity (one slot
    /// per *distinct* token) still covers it -- rather than being silently
    /// treated as already satisfied: a repeat call means a second, distinct
    /// obligation on that root, not a duplicate report of the same one.
    fn record_abandoned(
        abandoned_roots: &mut Vec<(TableToken, usize)>,
        token: TableToken,
    ) -> Result<(), HvfMemoryError> {
        if let Some((_, count)) = abandoned_roots.iter_mut().find(|(t, _)| *t == token) {
            *count = count.checked_add(1).ok_or(HvfMemoryError::TableOwnership)?;
        } else {
            // Capacity for every possible distinct table token was reserved
            // before any SDK mapping.
            abandoned_roots.push((token, 1));
        }
        Ok(())
    }

    fn ipa(&self, token: TableToken) -> Result<u64, HvfMemoryError> {
        self.records
            .get(&token)
            .map(|record| record.ipa.start)
            .ok_or(HvfMemoryError::TableOwnership)
    }

    fn retain(&mut self, token: TableToken) -> Result<(), HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::TableOwnership)?;
        record.references = record
            .references
            .checked_add(1)
            .ok_or(HvfMemoryError::TableOwnership)?;
        Ok(())
    }

    fn release(&mut self, token: TableToken) -> Result<Vec<TableRecord>, HvfMemoryError> {
        if self
            .records
            .get(&token)
            .ok_or(HvfMemoryError::TableOwnership)?
            .references
            == 0
        {
            return Err(HvfMemoryError::TableOwnership);
        }
        let edge_count = self.edge_count()?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(edge_count.saturating_add(1))
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release plan"))?;
        let mut decrements = HashMap::<TableToken, usize>::new();
        decrements
            .try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release plan"))?;
        let mut free = HashSet::<TableToken>::new();
        free.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release plan"))?;
        pending.push(token);
        while let Some(current) = pending.pop() {
            let decrement = decrements.entry(current).or_default();
            *decrement = decrement
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
            let record = self
                .records
                .get(&current)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
            if *decrement == record.references && free.insert(current) {
                pending.extend(record.children.values().copied());
            }
        }
        self.detach_planned(decrements, free)
    }

    fn release_count(&self, token: TableToken) -> Result<usize, HvfMemoryError> {
        if self
            .records
            .get(&token)
            .ok_or(HvfMemoryError::TableOwnership)?
            .references
            == 0
        {
            return Err(HvfMemoryError::TableOwnership);
        }
        let edge_count = self.edge_count()?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(edge_count.saturating_add(1))
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release count"))?;
        let mut decrements = HashMap::<TableToken, usize>::new();
        decrements
            .try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release count"))?;
        let mut free = HashSet::<TableToken>::new();
        free.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table release count"))?;
        pending.push(token);
        while let Some(current) = pending.pop() {
            let decrement = decrements.entry(current).or_default();
            *decrement = decrement
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
            let record = self
                .records
                .get(&current)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
            if *decrement == record.references && free.insert(current) {
                pending.extend(record.children.values().copied());
            }
        }
        Ok(free.len())
    }

    fn discard_unreferenced(
        &mut self,
        created: &mut Vec<TableToken>,
    ) -> Result<Vec<TableRecord>, HvfMemoryError> {
        let edge_count = self.edge_count()?;
        let mut created_set = HashSet::<TableToken>::new();
        created_set
            .try_reserve(created.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        let mut free = HashSet::<TableToken>::new();
        free.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(edge_count)
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        for token in created.iter().copied() {
            if !created_set.insert(token) {
                return Err(HvfMemoryError::TableOwnership);
            }
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if record.references == 0 && free.insert(token) {
                pending.extend(record.children.values().copied());
            }
        }
        let mut decrements = HashMap::<TableToken, usize>::new();
        decrements
            .try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table rollback plan"))?;
        while let Some(current) = pending.pop() {
            let decrement = decrements.entry(current).or_default();
            *decrement = decrement
                .checked_add(1)
                .ok_or(HvfMemoryError::TableOwnership)?;
            let record = self
                .records
                .get(&current)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
            if *decrement == record.references && free.insert(current) {
                pending.extend(record.children.values().copied());
            }
        }
        if created_set.iter().any(|token| !free.contains(token)) {
            return Err(HvfMemoryError::TableOwnership);
        }
        let released = self.detach_planned(decrements, free)?;
        created.clear();
        Ok(released)
    }

    fn detach_planned(
        &mut self,
        decrements: HashMap<TableToken, usize>,
        free: HashSet<TableToken>,
    ) -> Result<Vec<TableRecord>, HvfMemoryError> {
        let mut removed_tokens = Vec::new();
        removed_tokens
            .try_reserve_exact(free.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("detached table ownership"))?;
        removed_tokens.extend(free.iter().copied());
        removed_tokens.sort_unstable();
        let mut released = Vec::new();
        released
            .try_reserve_exact(removed_tokens.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("detached table ownership"))?;
        for (token, decrement) in &decrements {
            if free.contains(token) {
                continue;
            }
            let record = self
                .records
                .get(token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if *decrement > record.references {
                return Err(HvfMemoryError::TableOwnership);
            }
        }
        for token in &removed_tokens {
            if !self.records.contains_key(token) {
                return Err(HvfMemoryError::TableOwnership);
            }
        }
        for (token, decrement) in decrements {
            if !free.contains(&token) {
                let record = self
                    .records
                    .get_mut(&token)
                    .ok_or(HvfMemoryError::TableOwnership)?;
                record.references -= decrement;
            }
        }
        for token in removed_tokens {
            let record = self
                .records
                .remove(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            self.edges = self.edges.saturating_sub(record.children.len());
            released.push(record);
        }
        Ok(released)
    }

    /// Copy-on-write of every leaf in `updates` (any order, later entries win
    /// for a repeated address) into one new root: each table on a touched
    /// path is copied once for the whole batch, not once per page.
    fn cow_leaves(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
        root: TableToken,
        updates: &[(usize, u64)],
        limit: usize,
    ) -> Result<(TableToken, Vec<TableToken>), HvfMemoryError> {
        let mut sorted = Vec::new();
        sorted
            .try_reserve_exact(updates.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("stage-one COW updates"))?;
        sorted.extend_from_slice(updates);
        // Stable, so a repeated address keeps its last descriptor; address
        // order is index order at every level, so each level groups its
        // updates by scanning runs.
        sorted.sort_by_key(|(gva, _)| *gva);
        let mut created = Vec::new();
        created
            .try_reserve_exact(4)
            .map_err(|_| HvfMemoryError::MetadataAllocation("stage-one COW ownership"))?;
        let result = self.cow_level(vm, allocator, Some(root), 0, &sorted, limit, &mut created);
        match result {
            Ok(Some(root)) => Ok((root, created)),
            Ok(None) => Err(HvfMemoryError::TableOwnership),
            Err(error) => {
                let records = match self.discard_unreferenced(&mut created) {
                    Ok(records) => records,
                    Err(cleanup) => {
                        let quarantine = self.abandon_unreferenced(&created);
                        vm.poison();
                        let cleanup = HvfMemoryError::with_cleanup(cleanup, quarantine);
                        return Err(HvfMemoryError::finalization(error, cleanup));
                    }
                };
                let cleanup = cleanup_detached_table_records(vm, self, allocator, records, false);
                Err(HvfMemoryError::with_cleanup(error, cleanup))
            }
        }
    }

    /// One level of [`Self::cow_leaves`]: `updates` is sorted by address and
    /// every entry shares the path above `level`.
    #[allow(clippy::too_many_arguments)]
    fn cow_level(
        &mut self,
        vm: &'static HvfVm,
        allocator: &mut IpaAllocator,
        current: Option<TableToken>,
        level: u8,
        updates: &[(usize, u64)],
        limit: usize,
        created: &mut Vec<TableToken>,
    ) -> Result<Option<TableToken>, HvfMemoryError> {
        let level_index = usize::from(level);
        // Distinct child slots this batch touches at this level.
        let mut groups = 0usize;
        let mut previous = None;
        for &(gva, _) in updates {
            let index = stage_one_indexes(gva)[level_index];
            if previous != Some(index) {
                groups += 1;
                previous = Some(index);
            }
        }
        let (mut bytes, mut children) = if let Some(token) = current {
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            if record.level != level {
                return Err(HvfMemoryError::TableOwnership);
            }
            let mut children = HashMap::new();
            children
                .try_reserve(record.children.len().saturating_add(groups))
                .map_err(|_| HvfMemoryError::MetadataAllocation("table child copy"))?;
            children.extend(
                record
                    .children
                    .iter()
                    .map(|(&index, &child)| (index, child)),
            );
            (Box::new(StageOneTable(record.bytes.0)), children)
        } else {
            let mut children = HashMap::new();
            children
                .try_reserve(groups)
                .map_err(|_| HvfMemoryError::MetadataAllocation("table children"))?;
            (Box::new(StageOneTable([0; TABLE_ENTRIES])), children)
        };
        if level == 3 {
            for &(gva, descriptor) in updates {
                bytes.0[stage_one_indexes(gva)[3]] = descriptor;
            }
        } else {
            let mut start = 0;
            while start < updates.len() {
                let index = stage_one_indexes(updates[start].0)[level_index];
                let mut end = start + 1;
                while end < updates.len() && stage_one_indexes(updates[end].0)[level_index] == index
                {
                    end += 1;
                }
                let old_child = children.get(&index).copied();
                let new_child = self.cow_level(
                    vm,
                    allocator,
                    old_child,
                    level + 1,
                    &updates[start..end],
                    limit,
                    created,
                )?;
                if let Some(child) = new_child {
                    bytes.0[index] = table_descriptor(self.ipa(child)?);
                    children.insert(index, child);
                } else {
                    bytes.0[index] = 0;
                    children.remove(&index);
                }
                start = end;
            }
        }
        if level != 0 && bytes.0.iter().all(|entry| *entry == 0) {
            return Ok(None);
        }
        created
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("stage-one COW ownership"))?;
        let token = self.allocate(vm, allocator, level, bytes, children, limit)?;
        created.push(token);
        Ok(Some(token))
    }

    fn walk(&self, root: TableToken, gva: usize) -> Result<(u64, u64), HvfMemoryError> {
        let indexes = stage_one_indexes(gva);
        let mut token = root;
        for (level, index) in indexes.into_iter().enumerate() {
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::StageOneWalkFailed(gva))?;
            let descriptor = record.bytes.0[index];
            if descriptor & 0b11 != DESCRIPTOR_VALID_TABLE_OR_PAGE {
                return Err(HvfMemoryError::StageOneWalkFailed(gva));
            }
            if level == 3 {
                let ipa =
                    (descriptor & DESCRIPTOR_OUTPUT_MASK) | (gva as u64 & (PAGE_SIZE as u64 - 1));
                return Ok((ipa, descriptor));
            }
            token = *record
                .children
                .get(&index)
                .ok_or(HvfMemoryError::StageOneWalkFailed(gva))?;
        }
        Err(HvfMemoryError::StageOneWalkFailed(gva))
    }

    fn reachable_count(&self, root: TableToken) -> Result<usize, HvfMemoryError> {
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table walk"))?;
        let mut seen = HashSet::new();
        seen.try_reserve(self.records.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("table walk"))?;
        pending.push(root);
        while let Some(token) = pending.pop() {
            if !seen.insert(token) {
                continue;
            }
            let record = self
                .records
                .get(&token)
                .ok_or(HvfMemoryError::TableOwnership)?;
            pending.extend(record.children.values().copied());
        }
        Ok(seen.len())
    }
}

/// The permanent host alias a mirrored address space keeps installed in a
/// slot: which backing page it exposes at the GVA, and whether the host view
/// is writable (guest WRITE) or read-only (guest READ or EXECUTE).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MirrorState {
    backing: BackingPage,
    write: bool,
}

impl MirrorState {
    fn host_permissions(self) -> HvfHostPermissions {
        if self.write {
            HvfHostPermissions::READ_WRITE
        } else {
            HvfHostPermissions::READ
        }
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent per-slot state flags"
)]
struct HostSlotRecord {
    gva: usize,
    slot: Option<HvfHostSlot>,
    references: usize,
    active: bool,
    /// A physical alias is still installed or its exact restoration is
    /// uncertain. Logical references may retire while this is set; only the
    /// physical slot reservation is deferred.
    alias_quarantined: bool,
    /// Releasing the now-unreferenced slot reservation itself failed.
    release_quarantined: bool,
    /// Owned by a mirrored address space; such a slot is never shared with a
    /// second space.
    mirrored: bool,
    /// The permanent alias currently installed, if any.
    mirror: Option<MirrorState>,
    /// Exact registry reference owned by `mirror`.
    mirror_backing_pin: bool,
}

/// One record's contribution to [`HostSlotArena::tally`]. Every mutation of
/// a record goes through [`HostSlotArena::update`], which re-tallies the
/// record around the mutation, so the running totals cannot drift from the
/// fields whatever the mutation changed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct HostSlotTally {
    /// Records with a temporary alias installed.
    active: usize,
    /// Records with a permanent mirror installed.
    mirrored: usize,
    /// Records that are release-quarantined and not alias-quarantined: the
    /// slot term of `HvfMemoryUsage::quarantined_resources` (an alias-
    /// quarantined slot is already counted through its
    /// `Acknowledgements::alias_quarantine` entry, which is what sets and
    /// clears `alias_quarantined`).
    release_quarantined: usize,
}

impl HostSlotTally {
    fn add(self, other: Self) -> Self {
        Self {
            active: self.active + other.active,
            mirrored: self.mirrored + other.mirrored,
            release_quarantined: self.release_quarantined + other.release_quarantined,
        }
    }

    fn sub(self, other: Self) -> Self {
        Self {
            active: self.active - other.active,
            mirrored: self.mirrored - other.mirrored,
            release_quarantined: self.release_quarantined - other.release_quarantined,
        }
    }
}

impl HostSlotRecord {
    fn tally(&self) -> HostSlotTally {
        HostSlotTally {
            active: usize::from(self.active),
            mirrored: usize::from(self.mirror.is_some()),
            release_quarantined: usize::from(self.release_quarantined && !self.alias_quarantined),
        }
    }
}

struct HostSlotArena {
    records: HashMap<HostSlotToken, HostSlotRecord>,
    by_gva: HashMap<usize, HostSlotToken>,
    next_token: u64,
    /// The sum of every record's [`HostSlotRecord::tally`], kept exact at
    /// each insert, removal and [`Self::update`] so usage reports never
    /// rescan the arena.
    tally: HostSlotTally,
}

impl HostSlotArena {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            by_gva: HashMap::new(),
            next_token: 1,
            tally: HostSlotTally::default(),
        }
    }

    /// Mutates `token`'s record through `f`, folding whatever `f` changed
    /// into [`Self::tally`].
    fn update<R>(
        &mut self,
        token: HostSlotToken,
        f: impl FnOnce(&mut HostSlotRecord) -> R,
    ) -> Result<R, HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let before = record.tally();
        let result = f(record);
        let after = record.tally();
        self.tally = self.tally.add(after).sub(before);
        Ok(result)
    }

    fn remove_record(&mut self, token: HostSlotToken) -> Result<HostSlotRecord, HvfMemoryError> {
        let record = self
            .records
            .remove(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        self.by_gva.remove(&record.gva);
        self.tally = self.tally.sub(record.tally());
        Ok(record)
    }

    /// [`Self::tally`] recomputed from every record: the debug cross-check.
    fn recount(&self) -> HostSlotTally {
        self.records
            .values()
            .fold(HostSlotTally::default(), |sum, record| {
                sum.add(record.tally())
            })
    }

    fn claim(
        &mut self,
        gva: usize,
        limit: usize,
        mirrored: bool,
    ) -> Result<HostSlotToken, HvfMemoryError> {
        if let Some(token) = self.by_gva.get(&gva).copied() {
            let record = self
                .records
                .get_mut(&token)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if record.mirror.is_some() != record.mirror_backing_pin {
                return Err(HvfMemoryError::IpaOwnership);
            }
            if record.alias_quarantined || record.release_quarantined {
                return Err(HvfMemoryError::AliasRestore(gva..gva + PAGE_SIZE));
            }
            // A slot keeps the kind it was born with, and a mirrored slot can
            // be re-claimed only while no permanent alias is installed (its
            // previous page unmapped, the retirement not yet acknowledged).
            if record.mirrored != mirrored
                || (mirrored && (record.mirror.is_some() || record.active))
            {
                return Err(HvfMemoryError::MirrorSlotShared(gva..gva + PAGE_SIZE));
            }
            record.references = record
                .references
                .checked_add(1)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            return Ok(token);
        }
        admit_resource("host slots", self.records.len(), 1, limit)?;
        self.records
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("host slot ownership"))?;
        self.by_gva
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("host slot address index"))?;
        let token = HostSlotToken(self.next_token);
        let next_token = self
            .next_token
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let record_entry = match self.records.entry(token) {
            std::collections::hash_map::Entry::Vacant(entry) => entry,
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(HvfMemoryError::IpaOwnership);
            }
        };
        let address_entry = match self.by_gva.entry(gva) {
            std::collections::hash_map::Entry::Vacant(entry) => entry,
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(HvfMemoryError::IpaOwnership);
            }
        };
        let slot = HvfHostSlot::reserve_exact(gva..gva + PAGE_SIZE)?;
        let record = HostSlotRecord {
            gva,
            slot: Some(slot),
            references: 1,
            active: false,
            alias_quarantined: false,
            release_quarantined: false,
            mirrored,
            mirror: None,
            mirror_backing_pin: false,
        };
        let added = record.tally();
        record_entry.insert(record);
        address_entry.insert(token);
        self.tally = self.tally.add(added);
        self.next_token = next_token;
        Ok(token)
    }

    fn retain(&mut self, token: HostSlotToken) -> Result<(), HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        record.references = record
            .references
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release(&mut self, token: HostSlotToken) -> Result<bool, HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.mirror.is_some() != record.mirror_backing_pin {
            return Err(HvfMemoryError::IpaOwnership);
        }
        if record.references == 0
            || record.release_quarantined
            || (record.active && !record.alias_quarantined)
        {
            return Err(HvfMemoryError::IpaOwnership);
        }
        if record.references == 1 && record.mirror.is_some() {
            // A permanent alias must be torn down through `transition_mirror`
            // (which also returns its host-writer authority) before the slot
            // can leave the arena.
            return Err(HvfMemoryError::AliasBusy(
                record.gva..record.gva + PAGE_SIZE,
            ));
        }
        record.references -= 1;
        if record.references != 0 || record.alias_quarantined {
            return Ok(false);
        }
        self.reap_if_unowned(token)
    }

    fn reap_if_unowned(&mut self, token: HostSlotToken) -> Result<bool, HvfMemoryError> {
        let record = self
            .records
            .get_mut(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.mirror.is_some() != record.mirror_backing_pin {
            return Err(HvfMemoryError::IpaOwnership);
        }
        if record.references != 0 || record.active || record.alias_quarantined {
            return Ok(false);
        }
        if record.mirror.is_some() {
            return Err(HvfMemoryError::AliasBusy(
                record.gva..record.gva + PAGE_SIZE,
            ));
        }
        let slot = record.slot.as_mut().ok_or(HvfMemoryError::IpaOwnership)?;
        let release = slot.release();
        if let Err(error) = release {
            self.update(token, |record| record.release_quarantined = true)?;
            return Err(error.into());
        }
        self.remove_record(token)?;
        Ok(true)
    }

    fn retry_quarantined_releases(&mut self) -> (usize, Option<HvfMemoryError>) {
        let mut released = 0;
        let mut first_error = None;
        let mut after = None;
        loop {
            let token = self
                .records
                .iter()
                .filter(|(token, record)| {
                    record.references == 0
                        && !record.active
                        && !record.alias_quarantined
                        && record.release_quarantined
                        && after.is_none_or(|after| **token > after)
                })
                .map(|(token, _)| *token)
                .min();
            let Some(token) = token else {
                break;
            };
            after = Some(token);
            let _ = self.update(token, |record| record.release_quarantined = false);
            match self.reap_if_unowned(token) {
                Ok(true) => released += 1,
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        (released, first_error)
    }
}

#[derive(Clone, Copy)]
struct PageEpoch {
    write: HvfWriteEpoch,
    publication: HvfPublicationEpoch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageTwoAuthority {
    ReadOnly,
    Writer,
    Executor,
}

impl StageTwoAuthority {
    fn for_permissions(permissions: HvfGuestPermissions) -> Self {
        if permissions.contains(HvfGuestPermissions::WRITE) {
            Self::Writer
        } else if permissions.contains(HvfGuestPermissions::EXECUTE) {
            Self::Executor
        } else {
            Self::ReadOnly
        }
    }
}

#[derive(Clone, Copy)]
struct BackingPageAuthority {
    stage_two_writers: usize,
    stage_two_executors: usize,
    host_writers: usize,
    hidden_writable: bool,
}

impl BackingPageAuthority {
    const fn new() -> Self {
        Self {
            stage_two_writers: 0,
            stage_two_executors: 0,
            host_writers: 0,
            hidden_writable: true,
        }
    }
}

struct BackingRecord {
    storage: Vec<Option<HvfHostBacking>>,
    sharing: HvfSharing,
    references: Vec<usize>,
    epochs: Vec<PageEpoch>,
    authorities: Vec<BackingPageAuthority>,
    mapping_quarantines: Vec<usize>,
    release_quarantined: Vec<bool>,
    /// A process-global shared object named by an [`HvfSharedBackingKey`]:
    /// its pages outlive every guest mapping until the key is released.
    pinned: bool,
}

struct BackingRegistry {
    records: HashMap<HvfBackingIdentity, BackingRecord>,
    next_identity: u64,
    physical_pages: usize,
    max_physical_pages: usize,
    /// Pages whose `release_quarantined` flag is set, across every record;
    /// kept exact at every write of the flag so usage never rescans.
    release_quarantined_pages: usize,
    /// Records with `pinned` set.
    pinned_records: usize,
}

fn fallible_filled_vec<T: Clone>(
    length: usize,
    value: T,
    resource: &'static str,
) -> Result<Vec<T>, HvfMemoryError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| HvfMemoryError::MetadataAllocation(resource))?;
    values.resize(length, value);
    Ok(values)
}

fn fallible_copy_vec<T: Clone>(
    source: &[T],
    resource: &'static str,
) -> Result<Vec<T>, HvfMemoryError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(source.len())
        .map_err(|_| HvfMemoryError::MetadataAllocation(resource))?;
    values.extend_from_slice(source);
    Ok(values)
}

fn empty_backing_storage(pages: usize) -> Result<Vec<Option<HvfHostBacking>>, HvfMemoryError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(pages)
        .map_err(|_| HvfMemoryError::MetadataAllocation("physical backing ownership"))?;
    storage.resize_with(pages, || None);
    Ok(storage)
}

impl BackingRegistry {
    fn new(max_physical_pages: usize) -> Self {
        Self {
            records: HashMap::new(),
            next_identity: 1,
            physical_pages: 0,
            max_physical_pages,
            release_quarantined_pages: 0,
            pinned_records: 0,
        }
    }

    /// Sets `identity`'s `pinned` flag, keeping [`Self::pinned_records`] exact.
    fn set_pinned(
        &mut self,
        identity: HvfBackingIdentity,
        pinned: bool,
    ) -> Result<(), HvfMemoryError> {
        let record = self
            .records
            .get_mut(&identity)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let was = core::mem::replace(&mut record.pinned, pinned);
        self.pinned_records = self.pinned_records + usize::from(pinned) - usize::from(was);
        Ok(())
    }

    /// Sets one page's `release_quarantined` flag, keeping
    /// [`Self::release_quarantined_pages`] exact.
    fn set_release_quarantined(
        &mut self,
        identity: HvfBackingIdentity,
        index: usize,
        quarantined: bool,
    ) -> Result<(), HvfMemoryError> {
        let flag = self
            .records
            .get_mut(&identity)
            .and_then(|record| record.release_quarantined.get_mut(index))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let was = core::mem::replace(flag, quarantined);
        self.release_quarantined_pages =
            self.release_quarantined_pages + usize::from(quarantined) - usize::from(was);
        Ok(())
    }

    fn remove_record(&mut self, identity: HvfBackingIdentity) -> Option<BackingRecord> {
        let record = self.records.remove(&identity)?;
        self.pinned_records -= usize::from(record.pinned);
        self.release_quarantined_pages -= record
            .release_quarantined
            .iter()
            .filter(|release| **release)
            .count();
        Some(record)
    }

    fn insert_empty(
        &mut self,
        pages: usize,
        sharing: HvfSharing,
        references: usize,
        epochs: Vec<PageEpoch>,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        if pages == 0 || epochs.len() != pages {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let storage = empty_backing_storage(pages)?;
        let references = fallible_filled_vec(pages, references, "backing references")?;
        let authorities =
            fallible_filled_vec(pages, BackingPageAuthority::new(), "backing authorities")?;
        let mapping_quarantines = fallible_filled_vec(pages, 0, "backing mapping quarantines")?;
        let release_quarantined = fallible_filled_vec(pages, false, "backing release quarantines")?;
        self.records
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("backing ownership"))?;
        let identity = HvfBackingIdentity(self.next_identity);
        let next_identity = self
            .next_identity
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let record = BackingRecord {
            storage,
            sharing,
            references,
            epochs,
            authorities,
            mapping_quarantines,
            release_quarantined,
            pinned: false,
        };
        match self.records.entry(identity) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(record);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(HvfMemoryError::IpaOwnership);
            }
        }
        self.next_identity = next_identity;
        Ok(identity)
    }

    fn allocate(
        &mut self,
        pages: usize,
        sharing: HvfSharing,
        references: usize,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        self.admit_physical_pages(pages)?;
        let epochs = fallible_filled_vec(
            pages,
            PageEpoch {
                write: HvfWriteEpoch(0),
                publication: HvfPublicationEpoch(0),
            },
            "backing epochs",
        )?;
        let identity = self.insert_empty(pages, sharing, references, epochs)?;
        // A multi-page object is one contiguous host block owned page by
        // page, so a claim can map it into the guest as runs; a block that
        // cannot be placed falls back to page-sized allocations.
        let run = if pages > 1 {
            match HvfHostBacking::allocate_run(pages) {
                Ok(run) => Some(run),
                Err(HvfHostBackingError::Reservation | HvfHostBackingError::Unaligned { .. }) => {
                    None
                }
                Err(trigger) => {
                    let trigger = HvfMemoryError::from(trigger);
                    let cleanup = self.discard_unreferenced(identity).map(|_| ());
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
        } else {
            None
        };
        if let Some(run) = run {
            if run.len() != pages {
                let cleanup = self.discard_unreferenced(identity).map(|_| ());
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::IpaOwnership,
                    cleanup,
                ));
            }
            for (index, storage) in run.into_iter().enumerate() {
                self.records
                    .get_mut(&identity)
                    .ok_or(HvfMemoryError::IpaOwnership)?
                    .storage[index] = Some(storage);
                self.physical_pages = self
                    .physical_pages
                    .checked_add(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            return Ok(identity);
        }
        for index in 0..pages {
            match HvfHostBacking::allocate(PAGE_SIZE) {
                Ok(storage) => {
                    self.records
                        .get_mut(&identity)
                        .ok_or(HvfMemoryError::IpaOwnership)?
                        .storage[index] = Some(storage);
                    self.physical_pages = self
                        .physical_pages
                        .checked_add(1)
                        .ok_or(HvfMemoryError::IpaOwnership)?;
                }
                Err(trigger) => {
                    let trigger = HvfMemoryError::from(trigger);
                    let cleanup = self.discard_unreferenced(identity).map(|_| ());
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
        }
        Ok(identity)
    }

    /// Creates a pinned, shared, process-global backing object of `pages`
    /// zeroed pages. Pinned pages survive reference counts reaching zero
    /// until [`BackingRegistry::unpin`] runs.
    fn allocate_pinned_shared(
        &mut self,
        pages: usize,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        let identity = self.allocate(pages, HvfSharing::Shared, 0)?;
        self.set_pinned(identity, true)?;
        Ok(identity)
    }

    /// Appends zeroed pages to a pinned shared object so it holds at least
    /// `pages` pages; existing pages, their references, epochs, and
    /// authorities are untouched (every parallel vector only grows).
    fn grow_pinned_shared(
        &mut self,
        identity: HvfBackingIdentity,
        pages: usize,
    ) -> Result<(), HvfMemoryError> {
        let current = {
            let record = self
                .records
                .get(&identity)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if !record.pinned || record.sharing != HvfSharing::Shared {
                return Err(HvfMemoryError::IpaOwnership);
            }
            record.storage.len()
        };
        if pages <= current {
            return Ok(());
        }
        let additional = pages - current;
        self.admit_physical_pages(additional)?;
        let mut fresh = Vec::new();
        fresh
            .try_reserve_exact(additional)
            .map_err(|_| HvfMemoryError::MetadataAllocation("shared backing growth"))?;
        for _ in 0..additional {
            match HvfHostBacking::allocate(PAGE_SIZE) {
                Ok(storage) => fresh.push(storage),
                Err(error) => {
                    let mut first_error = Some(HvfMemoryError::from(error));
                    for mut storage in fresh {
                        if let Err(cleanup) = storage.release() {
                            first_error.get_or_insert(cleanup.into());
                        }
                    }
                    return Err(first_error.unwrap_or(HvfMemoryError::IpaOwnership));
                }
            }
        }
        let record = self
            .records
            .get_mut(&identity)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let reserve = (|| {
            record.storage.try_reserve_exact(additional)?;
            record.references.try_reserve_exact(additional)?;
            record.epochs.try_reserve_exact(additional)?;
            record.authorities.try_reserve_exact(additional)?;
            record.mapping_quarantines.try_reserve_exact(additional)?;
            record.release_quarantined.try_reserve_exact(additional)?;
            Ok::<(), std::collections::TryReserveError>(())
        })();
        if reserve.is_err() {
            let mut first_error = None;
            for mut storage in fresh {
                if let Err(cleanup) = storage.release() {
                    first_error.get_or_insert(HvfMemoryError::from(cleanup));
                }
            }
            return Err(
                first_error.unwrap_or(HvfMemoryError::MetadataAllocation("shared backing growth"))
            );
        }
        for storage in fresh {
            record.storage.push(Some(storage));
            record.references.push(0);
            record.epochs.push(PageEpoch {
                write: HvfWriteEpoch(0),
                publication: HvfPublicationEpoch(0),
            });
            record.authorities.push(BackingPageAuthority::new());
            record.mapping_quarantines.push(0);
            record.release_quarantined.push(false);
        }
        self.physical_pages = self
            .physical_pages
            .checked_add(additional)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    /// Drops the pin on a shared object and frees every page nothing
    /// references any more; pages still mapped by a guest are freed when their
    /// last reference goes. Returns `true` when the whole object is gone.
    fn unpin(&mut self, identity: HvfBackingIdentity) -> Result<bool, HvfMemoryError> {
        self.set_pinned(identity, false)?;
        self.discard_unreferenced(identity)
    }

    fn pinned_count(&self) -> usize {
        self.pinned_records
    }

    /// [`Self::pinned_count`] recomputed by scanning: the debug cross-check.
    fn recount_pinned(&self) -> usize {
        self.records.values().filter(|record| record.pinned).count()
    }

    fn page_count(&self, identity: HvfBackingIdentity) -> Result<usize, HvfMemoryError> {
        self.records
            .get(&identity)
            .map(|record| record.storage.len())
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn eager_copy_backing(
        &mut self,
        source: HvfBackingIdentity,
        references: usize,
    ) -> Result<HvfBackingIdentity, HvfMemoryError> {
        let source_record = self
            .records
            .get(&source)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let pages = source_record.storage.len();
        let epochs = fallible_copy_vec(&source_record.epochs, "private backing epochs")?;
        self.admit_physical_pages(pages)?;
        let identity = self.insert_empty(pages, HvfSharing::Private, references, epochs)?;
        for index in 0..pages {
            let copy = self
                .records
                .get(&source)
                .and_then(|record| record.storage[index].as_ref())
                .ok_or(HvfMemoryError::IpaOwnership)?
                .eager_copy();
            match copy {
                Ok(storage) => {
                    self.records
                        .get_mut(&identity)
                        .ok_or(HvfMemoryError::IpaOwnership)?
                        .storage[index] = Some(storage);
                    self.physical_pages = self
                        .physical_pages
                        .checked_add(1)
                        .ok_or(HvfMemoryError::IpaOwnership)?;
                }
                Err(trigger) => {
                    let trigger = HvfMemoryError::from(trigger);
                    let cleanup = self.discard_unreferenced(identity).map(|_| ());
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
        }
        Ok(identity)
    }

    fn page_index(&self, page: BackingPage) -> Result<usize, HvfMemoryError> {
        if !page.offset.is_multiple_of(PAGE_SIZE) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let index = page.offset / PAGE_SIZE;
        let pages = self
            .records
            .get(&page.identity)
            .map(|record| record.storage.len())
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if index >= pages {
            return Err(HvfMemoryError::IpaOwnership);
        }
        Ok(index)
    }

    #[expect(
        clippy::unused_self,
        reason = "a page handle is only meaningful relative to the backing registry it names"
    )]
    fn page(&self, identity: HvfBackingIdentity, index: usize) -> BackingPage {
        BackingPage {
            identity,
            offset: index * PAGE_SIZE,
        }
    }

    fn retain(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let record = self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.storage[index].is_none() || record.release_quarantined[index] {
            return Err(HvfMemoryError::IpaOwnership);
        }
        record.references[index] = record.references[index]
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release_reference(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let references = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .references[index];
        *references = references
            .checked_sub(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release(&mut self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        self.release_reference(page)?;
        self.reap_if_unowned(page)
    }

    /// Physically releases `page` only when every logical capability and
    /// quarantine blocker has already settled. It never consumes a reference,
    /// so callers may retry it after a host-release error without decrementing
    /// twice.
    fn reap_if_unowned(&mut self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        let Some(record) = self.records.get(&page.identity) else {
            return Ok(false);
        };
        if !page.offset.is_multiple_of(PAGE_SIZE) {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let index = page.offset / PAGE_SIZE;
        let storage_present = record
            .storage
            .get(index)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .is_some();
        if !storage_present {
            return Ok(false);
        }
        let authority = record
            .authorities
            .get(index)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.pinned
            || record.references[index] != 0
            || record.mapping_quarantines[index] != 0
            || authority.stage_two_writers != 0
            || authority.stage_two_executors != 0
            || authority.host_writers != 0
        {
            return Ok(false);
        }
        self.release_page_storage(page)
    }

    fn release_page_storage(&mut self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        let index = self.page_index(page)?;
        let physical_pages = self
            .physical_pages
            .checked_sub(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let record = self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let storage = record.storage[index]
            .as_mut()
            .ok_or(HvfMemoryError::IpaOwnership)?;
        let release = storage.release();
        if let Err(error) = release {
            self.set_release_quarantined(page.identity, index, true)?;
            return Err(error.into());
        }
        record.storage[index] = None;
        let all_released = record.storage.iter().all(Option::is_none);
        self.set_release_quarantined(page.identity, index, false)?;
        self.physical_pages = physical_pages;
        if all_released {
            self.remove_record(page.identity);
        }
        Ok(true)
    }

    fn discard_unreferenced(
        &mut self,
        identity: HvfBackingIdentity,
    ) -> Result<bool, HvfMemoryError> {
        let (pages, pinned) = self
            .records
            .get(&identity)
            .map(|record| (record.storage.len(), record.pinned))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if pinned {
            return Ok(false);
        }
        let mut released_all = true;
        let mut first_error = None;
        for index in 0..pages {
            if !self.records.contains_key(&identity) {
                break;
            }
            let page = self.page(identity, index);
            let releasable = {
                let record = self
                    .records
                    .get(&identity)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                record.storage[index].is_some()
                    && record.references[index] == 0
                    && record.mapping_quarantines[index] == 0
                    && record.authorities[index].stage_two_writers == 0
                    && record.authorities[index].stage_two_executors == 0
                    && record.authorities[index].host_writers == 0
            };
            if !releasable {
                released_all = false;
            } else if let Err(error) = self.release_page_storage(page) {
                first_error.get_or_insert(error);
                released_all = false;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(released_all),
        }
    }

    fn page_storage(&self, page: BackingPage) -> Result<&HvfHostBacking, HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get(&page.identity)
            .and_then(|record| record.storage[index].as_ref())
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn page_range(&self, page: BackingPage) -> Result<Range<usize>, HvfMemoryError> {
        self.page_storage(page)?
            .slice(0, PAGE_SIZE)
            .map_err(Into::into)
    }

    fn page_has_reference(&self, page: BackingPage) -> Result<bool, HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get(&page.identity)
            .and_then(|record| record.references.get(index))
            .map(|references| *references != 0)
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn page_epoch(&self, page: BackingPage) -> Result<PageEpoch, HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get(&page.identity)
            .and_then(|record| record.epochs.get(index).copied())
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    fn write_epoch(
        &mut self,
        page: BackingPage,
        epoch: HvfWriteEpoch,
    ) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        self.records
            .get_mut(&page.identity)
            .and_then(|record| record.epochs.get_mut(index))
            .ok_or(HvfMemoryError::IpaOwnership)?
            .write = epoch;
        Ok(())
    }

    fn publish(&mut self, page: BackingPage) -> Result<PageEpoch, HvfMemoryError> {
        let index = self.page_index(page)?;
        let epoch = self
            .records
            .get_mut(&page.identity)
            .and_then(|record| record.epochs.get_mut(index))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        epoch.publication = HvfPublicationEpoch(epoch.write.0);
        Ok(*epoch)
    }

    fn sharing(&self, identity: HvfBackingIdentity) -> Result<HvfSharing, HvfMemoryError> {
        self.records
            .get(&identity)
            .map(|record| record.sharing)
            .ok_or(HvfMemoryError::IpaOwnership)
    }

    /// Checks that `target` can be granted once `retiring` (the page's own
    /// stage-two authority) and, when `retiring_host_writer`, the page's own
    /// permanent mirror writer are dropped in the same transaction.
    fn preflight_stage_two_replacement(
        &self,
        page: BackingPage,
        target: StageTwoAuthority,
        retiring: Option<StageTwoAuthority>,
        retiring_host_writer: bool,
    ) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let current = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        let conflict = match target {
            StageTwoAuthority::Writer => {
                let retiring_executors = usize::from(retiring == Some(StageTwoAuthority::Executor));
                current
                    .stage_two_executors
                    .checked_sub(retiring_executors)
                    .ok_or(HvfMemoryError::IpaOwnership)?
                    != 0
            }
            StageTwoAuthority::Executor => {
                let retiring_writers = usize::from(retiring == Some(StageTwoAuthority::Writer));
                current
                    .stage_two_writers
                    .checked_sub(retiring_writers)
                    .ok_or(HvfMemoryError::IpaOwnership)?
                    != 0
                    || current
                        .host_writers
                        .checked_sub(usize::from(retiring_host_writer))
                        .ok_or(HvfMemoryError::IpaOwnership)?
                        != 0
            }
            StageTwoAuthority::ReadOnly => false,
        };
        if conflict {
            Err(HvfMemoryError::BackingWriteExecute {
                backing: page.identity,
                offset: page.offset,
            })
        } else {
            Ok(())
        }
    }

    fn prepare_executable_host(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let hidden_writable = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index]
            .hidden_writable;
        if hidden_writable {
            self.page_storage(page)?.protect(HvfHostPermissions::READ)?;
            self.records
                .get_mut(&page.identity)
                .ok_or(HvfMemoryError::IpaOwnership)?
                .authorities[index]
                .hidden_writable = false;
        }
        Ok(())
    }

    fn authorize_stage_two(
        &mut self,
        page: BackingPage,
        permissions: HvfGuestPermissions,
    ) -> Result<StageTwoAuthority, HvfMemoryError> {
        let index = self.page_index(page)?;
        let authority = StageTwoAuthority::for_permissions(permissions);
        let current = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        let conflict = match authority {
            StageTwoAuthority::Writer => current.stage_two_executors != 0,
            StageTwoAuthority::Executor => {
                current.stage_two_writers != 0 || current.host_writers != 0
            }
            StageTwoAuthority::ReadOnly => false,
        };
        if conflict {
            return Err(HvfMemoryError::BackingWriteExecute {
                backing: page.identity,
                offset: page.offset,
            });
        }
        if authority == StageTwoAuthority::Executor && current.hidden_writable {
            self.page_storage(page)?.protect(HvfHostPermissions::READ)?;
            let current = &mut self
                .records
                .get_mut(&page.identity)
                .ok_or(HvfMemoryError::IpaOwnership)?
                .authorities[index];
            current.hidden_writable = false;
        }
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        match authority {
            StageTwoAuthority::Writer => {
                current.stage_two_writers = current
                    .stage_two_writers
                    .checked_add(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::Executor => {
                current.stage_two_executors = current
                    .stage_two_executors
                    .checked_add(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::ReadOnly => {}
        }
        Ok(authority)
    }

    fn release_stage_two(
        &mut self,
        page: BackingPage,
        authority: StageTwoAuthority,
    ) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        match authority {
            StageTwoAuthority::Writer => {
                current.stage_two_writers = current
                    .stage_two_writers
                    .checked_sub(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::Executor => {
                current.stage_two_executors = current
                    .stage_two_executors
                    .checked_sub(1)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
            }
            StageTwoAuthority::ReadOnly => {}
        }
        Ok(())
    }

    fn preflight_reserve_host_alias(
        &self,
        page: BackingPage,
        write: bool,
    ) -> Result<(), HvfMemoryError> {
        if !write {
            return Ok(());
        }
        let index = self.page_index(page)?;
        let current = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        if current.stage_two_executors != 0 {
            return Err(HvfMemoryError::BackingWriteExecute {
                backing: page.identity,
                offset: page.offset,
            });
        }
        current
            .host_writers
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn reserve_host_alias(&mut self, page: BackingPage, write: bool) -> Result<(), HvfMemoryError> {
        self.preflight_reserve_host_alias(page, write)?;
        if !write {
            return Ok(());
        }
        let index = self.page_index(page)?;
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        current.host_writers += 1;
        Ok(())
    }

    fn preflight_release_host_alias(&self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let host_writers = self
            .records
            .get(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index]
            .host_writers;
        if host_writers == 0 {
            Err(HvfMemoryError::IpaOwnership)
        } else {
            Ok(())
        }
    }

    fn release_host_alias(&mut self, page: BackingPage, write: bool) -> Result<(), HvfMemoryError> {
        if !write {
            return Ok(());
        }
        let index = self.page_index(page)?;
        let current = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .authorities[index];
        current.host_writers = current
            .host_writers
            .checked_sub(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn quarantine_mapping(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let count = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .mapping_quarantines[index];
        *count = count.checked_add(1).ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn resolve_mapping_quarantine(&mut self, page: BackingPage) -> Result<(), HvfMemoryError> {
        let index = self.page_index(page)?;
        let count = &mut self
            .records
            .get_mut(&page.identity)
            .ok_or(HvfMemoryError::IpaOwnership)?
            .mapping_quarantines[index];
        *count = count.checked_sub(1).ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn retry_quarantined_releases(&mut self) -> (usize, Option<HvfMemoryError>) {
        let mut released = 0;
        let mut first_error = None;
        let mut after: Option<(HvfBackingIdentity, usize)> = None;
        loop {
            let next = self
                .records
                .iter()
                .flat_map(|(&identity, record)| {
                    record
                        .release_quarantined
                        .iter()
                        .enumerate()
                        .filter(|(_, release)| **release)
                        .map(move |(index, _)| (identity, index))
                })
                .filter(|candidate| after.is_none_or(|after| *candidate > after))
                .min();
            let Some((identity, index)) = next else {
                break;
            };
            after = Some((identity, index));
            let page = BackingPage {
                identity,
                offset: index * PAGE_SIZE,
            };
            let _ = self.set_release_quarantined(identity, index, false);
            match self.reap_if_unowned(page) {
                Ok(true) => released += 1,
                Ok(false) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        (released, first_error)
    }

    fn release_quarantine_count(&self) -> usize {
        self.release_quarantined_pages
    }

    /// [`Self::release_quarantine_count`] recomputed by scanning: the debug
    /// cross-check.
    fn recount_release_quarantined(&self) -> usize {
        self.records
            .values()
            .map(|record| {
                record
                    .release_quarantined
                    .iter()
                    .filter(|release| **release)
                    .count()
            })
            .sum()
    }

    fn admit_physical_pages(&self, pages: usize) -> Result<(), HvfMemoryError> {
        let requested =
            self.physical_pages
                .checked_add(pages)
                .ok_or(HvfMemoryError::ResourceLimit {
                    resource: "physical backing pages",
                    requested: usize::MAX,
                    limit: self.max_physical_pages,
                })?;
        if requested > self.max_physical_pages {
            return Err(HvfMemoryError::ResourceLimit {
                resource: "physical backing pages",
                requested,
                limit: self.max_physical_pages,
            });
        }
        Ok(())
    }

    fn physical_pages(&self) -> usize {
        self.physical_pages
    }
}

struct PinnedSharedBackingRegistration<'a> {
    vm: &'static HvfVm,
    backings: &'a mut BackingRegistry,
    identity: HvfBackingIdentity,
    armed: bool,
}

impl PinnedSharedBackingRegistration<'_> {
    fn rollback(&mut self) -> Result<(), HvfMemoryError> {
        if !self.armed {
            return Ok(());
        }
        let cleanup = self.backings.unpin(self.identity).map(|_| ());
        // `unpin` consumes the logical pin before any fallible physical reap;
        // a failed reap remains exact in the backing registry's quarantine.
        self.armed = false;
        cleanup
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for PinnedSharedBackingRegistration<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let cleanup = catch_unwind(AssertUnwindSafe(|| self.rollback()));
        match cleanup {
            Ok(Ok(())) => {}
            Ok(Err(_)) => self.vm.poison(),
            Err(payload) => {
                dispose_secondary_panic(payload);
                self.vm.poison();
                std::process::abort();
            }
        }
    }
}

struct SharedWriterPage {
    backing: BackingPage,
    still_held: bool,
    release_ready: bool,
    write_epoch_settled: bool,
}

struct SharedWriterSettlement<'a> {
    vm: &'static HvfVm,
    backings: MutexGuard<'a, BackingRegistry>,
    acknowledgements: MutexGuard<'a, Acknowledgements>,
    pages: Vec<SharedWriterPage>,
    epoch: HvfWriteEpoch,
    callback_started: Cell<bool>,
    published: bool,
    reservations: usize,
    armed: bool,
}

impl<'a> SharedWriterSettlement<'a> {
    fn new(
        vm: &'static HvfVm,
        backings: MutexGuard<'a, BackingRegistry>,
        mut acknowledgements: MutexGuard<'a, Acknowledgements>,
        pages: Vec<SharedWriterPage>,
        epoch: HvfWriteEpoch,
    ) -> Result<Self, HvfMemoryError> {
        acknowledgements.reserve_shared_writer_quarantine(pages.len())?;
        let reservations = pages.len();
        Ok(Self {
            vm,
            backings,
            acknowledgements,
            pages,
            epoch,
            callback_started: Cell::new(false),
            published: false,
            reservations,
            armed: true,
        })
    }

    fn reserve_all(
        &mut self,
        mut mark_published: impl FnMut() -> Result<(), HvfError>,
    ) -> Result<(), HvfMemoryError> {
        for page in &self.pages {
            self.backings
                .preflight_reserve_host_alias(page.backing, true)?;
        }
        if self.pages.is_empty() {
            return Ok(());
        }
        mark_published()?;
        self.published = true;
        for page in &mut self.pages {
            self.backings.reserve_host_alias(page.backing, true)?;
            page.still_held = true;
        }
        Ok(())
    }

    fn advance_write_epochs(&mut self, first_error: &mut Option<HvfMemoryError>) {
        if !self.callback_started.get() {
            return;
        }
        for page in &mut self.pages {
            if page.write_epoch_settled {
                continue;
            }
            match self.backings.write_epoch(page.backing, self.epoch) {
                Ok(()) => page.write_epoch_settled = true,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
    }

    fn release_writers(&mut self, first_error: &mut Option<HvfMemoryError>) {
        for page in &mut self.pages {
            if !page.still_held {
                continue;
            }
            match self.backings.preflight_release_host_alias(page.backing) {
                Ok(()) => page.release_ready = true,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if first_error.is_some() {
            self.vm.poison();
        }
        for page in &mut self.pages {
            if !page.still_held || !page.release_ready {
                continue;
            }
            match self.backings.release_host_alias(page.backing, true) {
                Ok(()) => page.still_held = false,
                Err(error) => {
                    self.vm.poison();
                    first_error.get_or_insert(error);
                }
            }
        }
    }

    fn park_residuals(&mut self) {
        for page in &self.pages {
            let write_epoch =
                (self.callback_started.get() && !page.write_epoch_settled).then_some(self.epoch);
            if write_epoch.is_some() || page.still_held {
                if self
                    .acknowledgements
                    .commit_shared_writer_quarantine(SharedWriterQuarantine {
                        backing: page.backing,
                        write_epoch,
                        release_host_writer: page.still_held,
                    })
                    .is_err()
                {
                    self.vm.poison();
                    std::process::abort();
                }
            } else if self
                .acknowledgements
                .release_shared_writer_quarantine_reservations(1)
                .is_err()
            {
                self.vm.poison();
                std::process::abort();
            }
            self.reservations -= 1;
        }
        if self.reservations != 0 {
            self.vm.poison();
            std::process::abort();
        }
    }

    fn abort_before_callback(mut self) -> Result<(), HvfMemoryError> {
        let mut first_error = None;
        self.release_writers(&mut first_error);
        self.park_residuals();
        self.armed = false;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn settle(mut self, failed: bool) -> Result<(), HvfMemoryError> {
        if failed {
            self.vm.poison();
        }
        let mut first_error = None;
        self.advance_write_epochs(&mut first_error);
        if first_error.is_some() {
            self.vm.poison();
        }
        self.release_writers(&mut first_error);
        self.park_residuals();
        self.armed = false;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for SharedWriterSettlement<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let cleanup = catch_unwind(AssertUnwindSafe(|| {
            if self.published
                || self.callback_started.get()
                || self.pages.iter().any(|page| page.still_held)
            {
                self.vm.poison();
            }
            let mut first_error = None;
            self.advance_write_epochs(&mut first_error);
            self.release_writers(&mut first_error);
            self.park_residuals();
            self.armed = false;
        }));
        if let Err(payload) = cleanup {
            dispose_secondary_panic(payload);
            self.vm.poison();
            std::process::abort();
        }
    }
}

struct DataMapping {
    backing: BackingPage,
    ipa: IpaToken,
    authority: StageTwoAuthority,
    mapping: Option<HvfMapping<'static>>,
    quarantine_reservation: DataQuarantineReservation,
}

struct PageState {
    permissions: HvfGuestPermissions,
    sharing: HvfSharing,
    backing: Option<BackingPage>,
    mapping: Option<DataMapping>,
    slot: HostSlotToken,
}

struct ClaimRecord {
    id: u64,
    version: u64,
    range: Range<usize>,
    pages: HashMap<usize, PageState>,
}

struct ParticipantRecord {
    lane_generation: u64,
    lane_lifecycle: Arc<AtomicU8>,
    owner_stopped: Arc<AtomicBool>,
    capability_state: Arc<AtomicU8>,
    attachment_state: Option<Arc<AtomicU8>>,
    last_root_generation: HvfRootGeneration,
    last_executable_generation: HvfExecutableGeneration,
    last_tlbi_generation: HvfTlbiGeneration,
    in_flight: usize,
}

struct AddressSpaceState {
    live: bool,
    destroy_pending: bool,
    root: TableToken,
    root_generation: HvfRootGeneration,
    executable_generation: HvfExecutableGeneration,
    pending_tlbi_generation: HvfTlbiGeneration,
    participants: HashMap<HvfVcpuParticipantId, ParticipantRecord>,
    in_flight: usize,
    claims: HashMap<usize, ClaimRecord>,
}

struct AddressSpaceCell {
    id: HvfAddressSpaceId,
    asid: HvfAsid,
    regime: HvfTranslationRegime,
    /// Every claimed page keeps a permanent host alias at its own GVA with
    /// host permissions = guest permissions minus EXECUTE; retirements only
    /// wait for participants that were in flight when the mutation published.
    mirrored: bool,
    attachment_abandoned: AtomicBool,
    destroy_abandoned: AtomicBool,
    state: Mutex<AddressSpaceState>,
    /// Serializes ledger-backed retirement pump passes for this address space.
    /// Deferred custody itself lives in `Acknowledgements::retirements`, so
    /// parking a post-commit ticket cannot allocate or lose it.
    retirement_pump: Mutex<()>,
}

struct RetiredData {
    mapping: DataMapping,
    release_backing_reference: bool,
}

struct RetirementParticipants {
    required: HashSet<HvfVcpuParticipantId>,
    acknowledged: HashSet<HvfVcpuParticipantId>,
}

struct RetiredGeneration {
    address_space: HvfAddressSpaceId,
    generation: HvfRootGeneration,
    tlbi_generation: HvfTlbiGeneration,
    /// The authoritative, allocation-free custody marker consumed by
    /// [`HvfAddressSpace::pump_retirements`].
    deferred: bool,
    required_participants: HashSet<HvfVcpuParticipantId>,
    acknowledged_participants: HashSet<HvfVcpuParticipantId>,
    root: TableToken,
    data: Vec<RetiredData>,
    slots: Vec<HostSlotToken>,
    backings: Vec<BackingPage>,
    charged_pages: usize,
    charged_bytes: usize,
    data_pages: usize,
    slot_pages: usize,
    backing_pages: usize,
    table_pages: usize,
}

struct RetirementReservation {
    id: u64,
    charged_pages: usize,
    charged_bytes: usize,
    data_pages: usize,
    slot_pages: usize,
    backing_pages: usize,
    table_pages: usize,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent per-page lease state flags"
)]
struct AliasLeasePage {
    slot: HostSlotToken,
    backing: BackingPage,
    range: Range<usize>,
    write: bool,
    /// Exact registry reference held while this alias can still name the page.
    backing_pin: bool,
    /// Host-writer authority held for this alias.
    host_writer: bool,
    /// The slot contains this alias or the kernel result is uncertain.
    exposure_installed: bool,
}

struct AliasLease {
    range: Range<usize>,
    write_epoch: Option<HvfWriteEpoch>,
    pages: Vec<AliasLeasePage>,
    /// The lease rides on the space's permanent mirror: nothing was installed
    /// for it and nothing is restored when it ends.
    mirrored: bool,
}

struct AliasPhysicalExposure {
    backing: BackingPage,
    range: Range<usize>,
    restore_pending: bool,
    host_writer: bool,
    backing_pin: bool,
}

struct RecoveryMirror {
    descriptor: MirrorState,
    backing_pin: bool,
}

struct AliasQuarantine {
    slot: HostSlotToken,
    physical_exposure: Option<AliasPhysicalExposure>,
    recovery_mirror: Option<RecoveryMirror>,
}

thread_local! {
    static HVF_ALIAS_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

struct AliasThreadGuard;

impl AliasThreadGuard {
    fn enter(range: Range<usize>) -> Result<Self, HvfMemoryError> {
        HVF_ALIAS_ACTIVE.with(|active| {
            if active.replace(true) {
                Err(HvfMemoryError::AliasReentrant(range))
            } else {
                Ok(Self)
            }
        })
    }
}

impl Drop for AliasThreadGuard {
    fn drop(&mut self) {
        HVF_ALIAS_ACTIVE.with(|active| active.set(false));
    }
}

fn dispose_secondary_panic(payload: Box<dyn std::any::Any + Send>) {
    let _ = catch_unwind(AssertUnwindSafe(|| drop(payload)));
}

struct DataQuarantineReservation {
    _private: (),
}

struct DataQuarantine {
    ipa: Option<IpaToken>,
    backing: BackingPage,
    authority: Option<StageTwoAuthority>,
    sdk_token: Option<u64>,
    mapping_quarantine: bool,
    release_backing_reference: bool,
    retryable: bool,
}

struct SharedWriterQuarantine {
    backing: BackingPage,
    write_epoch: Option<HvfWriteEpoch>,
    release_host_writer: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    BeforeRootPublish,
    AuthorityTransition,
    AliasRestore,
    DataUnmap,
    TableUnmap,
}

struct Acknowledgements {
    retirements: HashMap<u64, RetiredGeneration>,
    /// Deferred retirements per address space (the spaces whose count is
    /// non-zero, so at most one entry per live address space). Capacity for
    /// every admissible address space is reserved at construction, so marking
    /// a deferral never allocates.
    deferred: Vec<(HvfAddressSpaceId, usize)>,
    next_ticket: u64,
    retired_pages: usize,
    retired_bytes: usize,
    alias_quarantine: Vec<AliasQuarantine>,
    alias_quarantine_reservations: usize,
    data_quarantine: Vec<DataQuarantine>,
    data_quarantine_reservations: usize,
    shared_writer_quarantine: Vec<SharedWriterQuarantine>,
    shared_writer_quarantine_reservations: usize,
}

impl Acknowledgements {
    fn new(max_address_spaces: usize) -> Result<Self, HvfMemoryError> {
        let mut deferred = Vec::new();
        deferred
            .try_reserve_exact(max_address_spaces.saturating_add(1))
            .map_err(|_| HvfMemoryError::MetadataAllocation("deferred retirement counts"))?;
        Ok(Self {
            retirements: HashMap::new(),
            deferred,
            next_ticket: 1,
            retired_pages: 0,
            retired_bytes: 0,
            alias_quarantine: Vec::new(),
            alias_quarantine_reservations: 0,
            data_quarantine: Vec::new(),
            data_quarantine_reservations: 0,
            shared_writer_quarantine: Vec::new(),
            shared_writer_quarantine_reservations: 0,
        })
    }

    /// How many of `address_space`'s retirements are deferred.
    fn deferred_count(&self, address_space: HvfAddressSpaceId) -> usize {
        self.deferred
            .iter()
            .find(|(space, _)| *space == address_space)
            .map_or(0, |(_, count)| *count)
    }

    /// [`Self::deferred_count`] recomputed by scanning: the debug cross-check.
    fn recount_deferred(&self, address_space: HvfAddressSpaceId) -> usize {
        self.retirements
            .values()
            .filter(|retired| retired.address_space == address_space && retired.deferred)
            .count()
    }

    /// Marks the retirement `id` (which must belong to `address_space` at
    /// `generation`) deferred; idempotent.
    fn mark_deferred(
        &mut self,
        id: u64,
        address_space: HvfAddressSpaceId,
        generation: HvfRootGeneration,
    ) -> Result<(), HvfMemoryError> {
        let retired = self
            .retirements
            .get_mut(&id)
            .filter(|retired| {
                retired.address_space == address_space && retired.generation == generation
            })
            .ok_or(HvfMemoryError::RetirementStale)?;
        if retired.deferred {
            return Ok(());
        }
        retired.deferred = true;
        let space = retired.address_space;
        if let Some((_, count)) = self
            .deferred
            .iter_mut()
            .find(|(candidate, _)| *candidate == space)
        {
            *count += 1;
        } else {
            // One entry per address space that has a deferral, and a space
            // with a retirement is live, so the reserved capacity covers it.
            debug_assert!(self.deferred.len() < self.deferred.capacity());
            self.deferred.push((space, 1));
        }
        Ok(())
    }

    /// Removes retirement `id` from the ledger, keeping the deferred counts
    /// exact.
    fn remove_retirement(&mut self, id: u64) -> Option<RetiredGeneration> {
        let retired = self.retirements.remove(&id)?;
        if retired.deferred {
            let space = retired.address_space;
            if let Some(index) = self
                .deferred
                .iter()
                .position(|(candidate, _)| *candidate == space)
            {
                self.deferred[index].1 -= 1;
                if self.deferred[index].1 == 0 {
                    self.deferred.swap_remove(index);
                }
            } else {
                debug_assert!(false, "deferred retirement {id} had no per-space count");
            }
        }
        Some(retired)
    }

    fn reserve_alias_quarantine(&mut self, pages: usize) -> Result<(), HvfMemoryError> {
        let required = self
            .alias_quarantine
            .len()
            .checked_add(self.alias_quarantine_reservations)
            .and_then(|reserved| reserved.checked_add(pages))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if required > self.alias_quarantine.capacity() {
            self.alias_quarantine
                .try_reserve(required - self.alias_quarantine.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("alias quarantine"))?;
        }
        self.alias_quarantine_reservations = self
            .alias_quarantine_reservations
            .checked_add(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release_alias_quarantine_reservation(&mut self, pages: usize) -> Result<(), HvfMemoryError> {
        self.alias_quarantine_reservations = self
            .alias_quarantine_reservations
            .checked_sub(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn reserve_data_quarantine(&mut self) -> Result<DataQuarantineReservation, HvfMemoryError> {
        let required = self
            .data_quarantine
            .len()
            .checked_add(self.data_quarantine_reservations)
            .and_then(|reserved| reserved.checked_add(1))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if required > self.data_quarantine.capacity() {
            self.data_quarantine
                .try_reserve(required - self.data_quarantine.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("data quarantine"))?;
        }
        self.data_quarantine_reservations = self
            .data_quarantine_reservations
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(DataQuarantineReservation { _private: () })
    }

    fn release_data_quarantine_reservation(&mut self, _reservation: DataQuarantineReservation) {
        // The non-Copy capability is created only after capacity and the count are reserved.
        self.data_quarantine_reservations = self.data_quarantine_reservations.saturating_sub(1);
    }

    fn commit_data_quarantine(
        &mut self,
        reservation: DataQuarantineReservation,
        quarantine: DataQuarantine,
    ) -> usize {
        let index = self.data_quarantine.len();
        self.release_data_quarantine_reservation(reservation);
        // Every live capability owns one unit of spare capacity, including across retry replans.
        self.data_quarantine.push(quarantine);
        index
    }

    fn reserve_shared_writer_quarantine(&mut self, pages: usize) -> Result<(), HvfMemoryError> {
        let required = self
            .shared_writer_quarantine
            .len()
            .checked_add(self.shared_writer_quarantine_reservations)
            .and_then(|reserved| reserved.checked_add(pages))
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if required > self.shared_writer_quarantine.capacity() {
            self.shared_writer_quarantine
                .try_reserve(required - self.shared_writer_quarantine.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("shared writer quarantine"))?;
        }
        self.shared_writer_quarantine_reservations = self
            .shared_writer_quarantine_reservations
            .checked_add(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn release_shared_writer_quarantine_reservations(
        &mut self,
        pages: usize,
    ) -> Result<(), HvfMemoryError> {
        self.shared_writer_quarantine_reservations = self
            .shared_writer_quarantine_reservations
            .checked_sub(pages)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        Ok(())
    }

    fn commit_shared_writer_quarantine(
        &mut self,
        quarantine: SharedWriterQuarantine,
    ) -> Result<(), HvfMemoryError> {
        self.release_shared_writer_quarantine_reservations(1)?;
        self.shared_writer_quarantine.push(quarantine);
        Ok(())
    }
}

struct Arenas {
    ipa: IpaAllocator,
    tables: TableArena,
    slots: HostSlotArena,
    next_address_space: u64,
    asids: AsidAllocator,
    next_claim: u64,
    next_participant: u64,
    next_root_generation: u64,
    next_executable_generation: u64,
    next_tlbi_generation: u64,
    next_write_epoch: u64,
    address_spaces: usize,
    claimed_pages: usize,
    live_data_pages: usize,
    failure: Option<FailurePoint>,
}

impl Arenas {
    fn next_root_generation(&mut self) -> Result<HvfRootGeneration, HvfMemoryError> {
        take_counter(&mut self.next_root_generation).map(HvfRootGeneration)
    }

    fn next_executable_generation(&mut self) -> Result<HvfExecutableGeneration, HvfMemoryError> {
        take_counter(&mut self.next_executable_generation).map(HvfExecutableGeneration)
    }

    fn next_tlbi_generation(&mut self) -> Result<HvfTlbiGeneration, HvfMemoryError> {
        take_counter(&mut self.next_tlbi_generation).map(HvfTlbiGeneration)
    }

    fn next_write_epoch(&mut self) -> Result<HvfWriteEpoch, HvfMemoryError> {
        take_counter(&mut self.next_write_epoch).map(HvfWriteEpoch)
    }

    fn take_failure(&mut self, point: FailurePoint) -> bool {
        if self.failure == Some(point) {
            self.failure = None;
            true
        } else {
            false
        }
    }
}

struct AliasSetupGuard<'a> {
    vm: &'static HvfVm,
    arenas: &'a mut Arenas,
    backings: &'a mut BackingRegistry,
    acknowledgements: &'a mut Acknowledgements,
    pages: &'a mut [AliasLeasePage],
    mirrored: bool,
    reservation: usize,
    installed: usize,
    published: bool,
    armed: bool,
}

impl<'a> AliasSetupGuard<'a> {
    fn new(
        vm: &'static HvfVm,
        arenas: &'a mut Arenas,
        backings: &'a mut BackingRegistry,
        acknowledgements: &'a mut Acknowledgements,
        pages: &'a mut [AliasLeasePage],
        mirrored: bool,
        reservation: usize,
    ) -> Self {
        Self {
            vm,
            arenas,
            backings,
            acknowledgements,
            pages,
            mirrored,
            reservation,
            installed: 0,
            published: false,
            armed: true,
        }
    }

    fn mark_published(&mut self) {
        self.published = true;
    }

    fn reserve_authority(&mut self, index: usize) -> Result<(), HvfMemoryError> {
        let page = self
            .pages
            .get_mut(index)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        self.backings.retain(page.backing)?;
        page.backing_pin = true;
        self.backings.reserve_host_alias(page.backing, page.write)?;
        page.host_writer = page.write;
        Ok(())
    }

    fn install_alias(
        &mut self,
        index: usize,
        permissions: HvfHostPermissions,
    ) -> Result<(), HvfMemoryError> {
        let page = self.pages.get(index).ok_or(HvfMemoryError::IpaOwnership)?;
        let storage = self.backings.page_storage(page.backing)?;
        let slot_record = self
            .arenas
            .slots
            .records
            .get(&page.slot)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if slot_record.active || slot_record.alias_quarantined || slot_record.release_quarantined {
            return Err(HvfMemoryError::AliasBusy(page.range.clone()));
        }
        if slot_record.slot.is_none() {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let token = page.slot;
        self.arenas
            .slots
            .update(token, |record| record.active = true)?;
        self.pages[index].exposure_installed = true;
        self.installed = index + 1;
        let slot = self
            .arenas
            .slots
            .records
            .get(&token)
            .and_then(|record| record.slot.as_ref())
            .ok_or(HvfMemoryError::IpaOwnership)?;
        slot.alias_from(storage, 0, permissions)?;
        Ok(())
    }

    fn activate_mirror(&mut self, index: usize) -> Result<(), HvfMemoryError> {
        let page = self.pages.get(index).ok_or(HvfMemoryError::IpaOwnership)?;
        let record = self
            .arenas
            .slots
            .records
            .get(&page.slot)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.active || record.alias_quarantined || record.release_quarantined {
            return Err(HvfMemoryError::AliasBusy(page.range.clone()));
        }
        let token = page.slot;
        self.arenas
            .slots
            .update(token, |record| record.active = true)?;
        self.installed = index + 1;
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), HvfMemoryError> {
        if !self.armed {
            return Ok(());
        }
        let mut first_error = None;
        if self.mirrored {
            for page in self.pages[..self.installed].iter().rev() {
                if let Err(error) = self
                    .arenas
                    .slots
                    .update(page.slot, |record| record.active = false)
                {
                    first_error.get_or_insert(error);
                }
            }
        } else {
            if let Err(error) = restore_installed_aliases(
                self.vm,
                self.arenas,
                self.backings,
                self.acknowledgements,
                self.pages,
                false,
            ) {
                first_error.get_or_insert(error);
            }
            if let Err(error) = self
                .acknowledgements
                .release_alias_quarantine_reservation(self.reservation)
            {
                first_error.get_or_insert(error);
            } else {
                self.reservation = 0;
            }
        }
        self.armed = false;
        if first_error.is_some() {
            self.vm.poison();
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn disarm(&mut self) {
        self.reservation = 0;
        self.armed = false;
    }
}

impl Drop for AliasSetupGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.published {
            self.vm.poison();
        }
        let _ = self.rollback();
    }
}

struct AliasTeardownGuard<'a> {
    memory: &'a HvfMemory,
    lease: Option<AliasLease>,
    armed: bool,
}

impl<'a> AliasTeardownGuard<'a> {
    fn new(memory: &'a HvfMemory, lease: AliasLease) -> Self {
        Self {
            memory,
            lease: Some(lease),
            armed: true,
        }
    }

    fn finish(&mut self, inject_restore: bool) -> Result<(), HvfMemoryError> {
        let lease = self.lease.as_mut().ok_or(HvfMemoryError::IpaOwnership)?;
        let mut arenas = self
            .memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut backings = self
            .memory
            .backings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut acknowledgements = self
            .memory
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let inject_restore = inject_restore && arenas.take_failure(FailurePoint::AliasRestore);
        let mut first_error = None;
        if let Some(epoch) = lease.write_epoch {
            for page in &lease.pages {
                if let Err(error) = backings.write_epoch(page.backing, epoch) {
                    first_error.get_or_insert(error);
                }
            }
        }
        if first_error.is_some() {
            self.memory.vm.poison();
        }
        if lease.mirrored {
            for page in &lease.pages {
                if let Err(error) = arenas
                    .slots
                    .update(page.slot, |record| record.active = false)
                {
                    first_error.get_or_insert(error);
                }
            }
        } else {
            if let Err(error) = restore_installed_aliases(
                self.memory.vm,
                &mut arenas,
                &mut backings,
                &mut acknowledgements,
                &mut lease.pages,
                inject_restore,
            ) {
                first_error.get_or_insert(error);
            }
            if let Err(error) =
                acknowledgements.release_alias_quarantine_reservation(lease.pages.len())
            {
                first_error.get_or_insert(error);
            }
        }
        if first_error.is_some() {
            self.memory.vm.poison();
        }
        self.lease = None;
        self.armed = false;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for AliasTeardownGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| self.memory.vm.poison())) {
            dispose_secondary_panic(payload);
        }
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| self.finish(false))) {
            dispose_secondary_panic(payload);
        }
    }
}

struct SynchronizationRoot {
    token: TableToken,
    ipa: u64,
    table_pages: usize,
}

struct HvfMemoryCreateResidual {
    vm: &'static HvfVm,
    arenas: Option<Arenas>,
    root: Option<TableToken>,
    synchronization_root: Option<SynchronizationRoot>,
    monitor_mapping: Option<HvfMapping<'static>>,
    monitor_sdk_token: Option<u64>,
}

struct HvfMemoryCreateGuard {
    residual: Option<HvfMemoryCreateResidual>,
}

impl HvfMemoryCreateGuard {
    fn new(vm: &'static HvfVm, arenas: Arenas) -> Self {
        Self {
            residual: Some(HvfMemoryCreateResidual {
                vm,
                arenas: Some(arenas),
                root: None,
                synchronization_root: None,
                monitor_mapping: None,
                monitor_sdk_token: None,
            }),
        }
    }

    fn residual_mut(&mut self) -> &mut HvfMemoryCreateResidual {
        self.residual
            .as_mut()
            .expect("an armed HVF memory constructor owns its residual")
    }

    fn arenas_mut(&mut self) -> &mut Arenas {
        self.residual_mut()
            .arenas
            .as_mut()
            .expect("an armed HVF memory constructor owns its arenas")
    }

    fn complete(
        &mut self,
    ) -> Result<(Arenas, SynchronizationRoot, HvfMapping<'static>), HvfMemoryError> {
        let residual = self.residual.as_mut().ok_or(HvfMemoryError::IpaOwnership)?;
        if residual.monitor_sdk_token.is_some()
            || residual.arenas.is_none()
            || residual.monitor_mapping.is_none()
        {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let root = residual.root.ok_or(HvfMemoryError::TableOwnership)?;
        if residual
            .synchronization_root
            .as_ref()
            .is_none_or(|synchronization_root| synchronization_root.token != root)
        {
            return Err(HvfMemoryError::TableOwnership);
        }
        let arenas = residual.arenas.take().ok_or(HvfMemoryError::IpaOwnership)?;
        residual.root = None;
        let synchronization_root = residual
            .synchronization_root
            .take()
            .ok_or(HvfMemoryError::TableOwnership)?;
        let monitor_mapping = residual
            .monitor_mapping
            .take()
            .ok_or(HvfMemoryError::IpaOwnership)?;
        self.residual = None;
        Ok((arenas, synchronization_root, monitor_mapping))
    }
}

impl Drop for HvfMemoryCreateGuard {
    fn drop(&mut self) {
        let Some(residual) = self.residual.take() else {
            return;
        };
        let mut slot = PROCESS_HVF_MEMORY_CREATE_RESIDUAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            // Two constructor residuals cannot be merged without confusing
            // their independent compact-IPA ownership. OnceLock serializes the
            // constructor and process_hvf_memory drains this slot first, so a
            // collision is an internal custody violation: terminate before
            // either possibly mapped backing can be dropped.
            std::process::abort();
        }
        *slot = Some(residual);
    }
}

pub struct HvfMemory {
    vm: &'static HvfVm,
    manager: u64,
    limits: HvfMemoryLimits,
    regime: HvfTranslationRegime,
    synchronization_root: SynchronizationRoot,
    monitor_mapping: HvfMapping<'static>,
    spaces: Mutex<HashMap<HvfAddressSpaceId, Arc<AddressSpaceCell>>>,
    arenas: Mutex<Arenas>,
    backings: Mutex<BackingRegistry>,
    acknowledgements: Mutex<Acknowledgements>,
    /// Caller-named shared backing objects ([`HvfSharedBackingKey::identity`])
    /// to the pinned registry object that holds their pages. Always locked
    /// after `backings`, never before.
    shared_backings: Mutex<HashMap<usize, HvfBackingIdentity>>,
}

impl fmt::Debug for HvfMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfMemory")
            .field("manager", &self.manager)
            .field("limits", &self.limits)
            .field("regime", &self.regime)
            .field("vm_poisoned", &self.vm.is_poisoned())
            .finish_non_exhaustive()
    }
}

impl HvfCompletionCapability for HvfMemory {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        if !std::ptr::eq(self.vm, vm)
            || self.manager != std::ptr::from_ref::<HvfVm>(vm) as usize as u64
            || !self
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
            || !self
                .shared_backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        {
            return Err(HvfError::ResidualAccounting);
        }
        self.monitor_mapping.validate_hvf_completion(vm)?;
        let arenas = self
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let backings = self
            .backings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let acknowledgements = self
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let usage = self.usage_locked(&arenas, &backings, &acknowledgements);
        if arenas.tables.ipa(self.synchronization_root.token).ok()
            != Some(self.synchronization_root.ipa)
            || arenas
                .tables
                .reachable_count(self.synchronization_root.token)
                .ok()
                != Some(self.synchronization_root.table_pages)
        {
            return Err(HvfError::ResidualAccounting);
        }
        drop(acknowledgements);
        drop(backings);
        drop(arenas);
        if !self.usage_is_manager_baseline(&usage) {
            return Err(HvfError::ResidualAccounting);
        }
        let sdk = vm.residual_report()?;
        // `sdk_is_manager_baseline` covers only the resource-count baseline
        // (mapping/fragment/page/byte/vcpu totals), which holds regardless of
        // whether a zero-vcpu operation happens to be active. This call site
        // runs with no zero-vcpu operation held, so assert that half of the
        // completion contract explicitly here rather than folding a
        // context-dependent lease flag into the shared resource-count check.
        if !self.sdk_is_manager_baseline(&sdk)
            || sdk.zero_vcpu_operation_active
            || sdk.zero_vcpu_owned_by_current_thread
        {
            return Err(HvfError::ResidualOwnership(sdk));
        }
        Ok(())
    }
}

pub struct HvfAddressSpace {
    memory: &'static HvfMemory,
    cell: Arc<AddressSpaceCell>,
}

impl fmt::Debug for HvfAddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HvfAddressSpace")
            .field("id", &self.cell.id)
            .field("asid", &self.cell.asid)
            .field("regime", &self.cell.regime)
            .finish_non_exhaustive()
    }
}

impl Clone for HvfAddressSpace {
    fn clone(&self) -> Self {
        Self {
            memory: self.memory,
            cell: Arc::clone(&self.cell),
        }
    }
}

impl HvfCompletionCapability for HvfAddressSpace {
    fn validate_hvf_completion(&self, vm: &HvfVm) -> Result<(), HvfError> {
        if !std::ptr::eq(self.memory.vm, vm)
            || self.memory.manager != std::ptr::from_ref::<HvfVm>(vm) as usize as u64
        {
            return Err(HvfError::ResidualAccounting);
        }
        let spaces = self
            .memory
            .spaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !spaces
            .get(&self.cell.id)
            .is_some_and(|cell| Arc::ptr_eq(cell, &self.cell))
        {
            return Err(HvfError::ResidualAccounting);
        }
        drop(spaces);
        let state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.live {
            return Err(HvfError::ResidualAccounting);
        }
        let arenas = self
            .memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if arenas.tables.ipa(state.root).is_err() {
            return Err(HvfError::ResidualAccounting);
        }
        Ok(())
    }
}

impl HvfMemory {
    fn create() -> Result<Self, HvfMemoryError> {
        let vm = process_hvf_vm()?;
        vm.with_capability_operation(|operation| {
            let limits = HvfMemoryLimits::default();
            let regime = HvfTranslationRegime::for_ipa_bits(vm.report().configured_ipa_bits)?;
            let ipa_limit = 1u64 << vm.report().configured_ipa_bits;
            let compact_ipa_pages = limits
                .max_live_data_pages
                .checked_add(limits.max_table_pages)
                .ok_or(HvfMemoryError::IpaExhausted(usize::MAX))?;
            let max_physical_pages = limits
                .max_live_data_pages
                .checked_add(limits.max_retired_pages)
                .ok_or(HvfMemoryError::ResourceLimit {
                    resource: "physical backing pages",
                    requested: usize::MAX,
                    limit: usize::MAX,
                })?;
            // Built before any mapping so its one fallible reservation can
            // fail with nothing to unwind.
            let acknowledgements = Acknowledgements::new(limits.max_address_spaces)?;
            let arenas = Arenas {
                ipa: IpaAllocator::new(PAGE_SIZE as u64..ipa_limit, compact_ipa_pages)?,
                tables: TableArena::new(limits.max_table_pages)?,
                slots: HostSlotArena::new(),
                next_address_space: 1,
                asids: AsidAllocator::new(),
                next_claim: 1,
                next_participant: 1,
                next_root_generation: 1,
                next_executable_generation: 1,
                next_tlbi_generation: 1,
                next_write_epoch: 1,
                address_spaces: 0,
                claimed_pages: 0,
                live_data_pages: 0,
                failure: None,
            };
            let mut custody = HvfMemoryCreateGuard::new(vm, arenas);
            let monitor = vm.monitor().bytes();
            if monitor.len() != PAGE_SIZE {
                return Err(HvfMemoryError::Witness(
                    "the linked EL1 monitor is not exactly one page",
                ));
            }
            operation.mark_published()?;
            vm.publish_executable_bytes(monitor)?;
            let start = monitor.as_ptr() as usize;
            match unsafe {
                vm.map_host_range(
                    start..start + PAGE_SIZE,
                    0,
                    HvfMapPermissions::READ | HvfMapPermissions::EXECUTE,
                )
            } {
                Ok(mapping) => custody.residual_mut().monitor_mapping = Some(mapping),
                Err(error) => {
                    custody.residual_mut().monitor_sdk_token = error.residual_mapping_token();
                    return Err(error.into());
                }
            }
            operation.require_live()?;
            let token = create_monitor_root(vm, custody.arenas_mut(), limits.max_table_pages)?;
            custody.residual_mut().root = Some(token);
            let synchronization_root = {
                let arenas = custody.arenas_mut();
                let ipa = arenas.tables.ipa(token)?;
                let (monitor_ipa, descriptor) = arenas.tables.walk(token, 0)?;
                let table_pages = arenas.tables.reachable_count(token)?;
                let releasable_pages = arenas.tables.release_count(token)?;
                let expected_descriptor = DESCRIPTOR_VALID_TABLE_OR_PAGE
                    | DESCRIPTOR_AP_EL0_NONE_EL1_RO
                    | DESCRIPTOR_INNER_SHAREABLE
                    | DESCRIPTOR_ACCESS_FLAG
                    | DESCRIPTOR_NOT_GLOBAL
                    | DESCRIPTOR_UXN;
                if ipa == 0
                    || ipa & (PAGE_SIZE as u64 - 1) != 0
                    || monitor_ipa != 0
                    || descriptor != expected_descriptor
                    || table_pages != 4
                    || releasable_pages != table_pages
                {
                    return Err(HvfMemoryError::Witness(
                        "the synchronization root is not an exact four-page EL1-only monitor mapping",
                    ));
                }
                SynchronizationRoot {
                    token,
                    ipa,
                    table_pages,
                }
            };
            custody.residual_mut().synchronization_root = Some(synchronization_root);
            operation.require_live()?;
            // `create_monitor_root` released its throwaway candidate root
            // above; with no address space live yet, that freed page went
            // into the reuse pool rather than being unmapped (the same
            // release path `create_address_space_with`'s own failure arms
            // drain via `drain_table_pool_if_idle` for the identical reason).
            // Drain it now so a freshly admitted `HvfMemory` starts at the
            // genuine zero-residual baseline `validate_hvf_completion`
            // requires, instead of carrying one pooled page no address space
            // has ever existed to justify caching.
            drain_table_pool_if_idle(vm, custody.arenas_mut())?;
            let (arenas, synchronization_root, monitor_mapping) = custody.complete()?;
            Ok(Self {
                vm,
                manager: std::ptr::from_ref::<HvfVm>(vm) as usize as u64,
                limits,
                regime,
                synchronization_root,
                monitor_mapping,
                spaces: Mutex::new(HashMap::new()),
                arenas: Mutex::new(arenas),
                backings: Mutex::new(BackingRegistry::new(max_physical_pages)),
                acknowledgements: Mutex::new(acknowledgements),
                shared_backings: Mutex::new(HashMap::new()),
            })
        })
    }

    pub const fn limits(&self) -> HvfMemoryLimits {
        self.limits
    }

    pub const fn regime(&self) -> HvfTranslationRegime {
        self.regime
    }

    pub const fn synchronization_ttbr0_el1(&self) -> u64 {
        self.synchronization_root.ipa
    }

    pub fn create_address_space(&'static self) -> Result<HvfAddressSpace, HvfMemoryError> {
        self.create_address_space_with(false)
    }

    /// Creates an address space whose every claimed page is permanently
    /// host-mapped at its own GVA with host permissions = guest permissions
    /// minus EXECUTE (so global W^X holds), sparse and `PROT_NONE` pages stay
    /// `PROT_NONE`, and unmapped ranges stay `PROT_NONE` reservations. The
    /// alias changes in the same transaction as the stage-one root, and is
    /// restored to `PROT_NONE` on unmap. Retirements on such a space wait only
    /// for participants that were in flight when the mutation published;
    /// idle participants synchronize on their next attach.
    pub fn create_mirrored_address_space(&'static self) -> Result<HvfAddressSpace, HvfMemoryError> {
        self.create_address_space_with(true)
    }

    /// Runs `f` over `len` bytes of the process-global shared backing object
    /// named by `backing`, starting at its byte offset, through a temporary
    /// contiguous host view; no guest mapping is needed. The object is created
    /// on first use and grown so the window fits. Host writes through this
    /// window advance the pages' write epochs (so any executable publication
    /// covering them goes stale) and are refused while any page has a stage-two
    /// executor, keeping W^X global.
    ///
    /// A callback result is stored in caller-owned `output` before alias
    /// teardown and operation completion. It remains available when either
    /// later step fails.
    pub fn with_shared_backing_into<R>(
        &self,
        backing: HvfSharedBackingKey,
        len: usize,
        output: &mut HvfCallbackOutput<R>,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<(), HvfMemoryError> {
        let mut vacant = output.vacant()?;
        self.vm.with_operation(|operation| {
            let end =
                backing
                    .offset
                    .checked_add(len)
                    .ok_or(HvfMemoryError::SharedBackingRange {
                        identity: backing.identity,
                        offset: backing.offset,
                        length: len,
                    })?;
            let first_page = backing.offset / PAGE_SIZE;
            let end_page = end.div_ceil(PAGE_SIZE);
            let page_count = end_page - first_page;
            check_mutation_bound(page_count.max(1), self.limits.max_mutation_pages)?;
            let mut pages = Vec::new();
            pages
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("shared writer settlement"))?;
            let mut sources = Vec::new();
            sources
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("shared backing window"))?;

            // Keep the global lock order (arenas -> backings -> shared index),
            // and reject every existing executable page before allocating an
            // epoch, growing storage, or acquiring the first host writer.
            let mut arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut shared = self
                .shared_backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(identity) = shared.get(&backing.identity).copied() {
                let existing_pages = backings.page_count(identity)?;
                for index in first_page..end_page.min(existing_pages) {
                    backings.preflight_reserve_host_alias(backings.page(identity, index), true)?;
                }
            }
            let epoch = arenas.next_write_epoch()?;
            let (identity, _) = self.shared_backing_identity(
                &mut backings,
                &mut shared,
                backing,
                end_page,
                || operation.mark_published(),
            )?;
            drop(shared);
            drop(arenas);

            for index in first_page..end_page {
                pages.push(SharedWriterPage {
                    backing: backings.page(identity, index),
                    still_held: false,
                    release_ready: false,
                    write_epoch_settled: false,
                });
            }
            let acknowledgements = self
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut settlement =
                SharedWriterSettlement::new(self.vm, backings, acknowledgements, pages, epoch)?;
            if let Err(trigger) = settlement.reserve_all(|| operation.mark_published()) {
                let cleanup = settlement.abort_before_callback();
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }

            let observation = if page_count == 0 {
                settlement.callback_started.set(true);
                let callback = match catch_unwind(AssertUnwindSafe(|| {
                    vacant.fill(f(&mut []));
                })) {
                    Ok(()) => CallbackOutcome::Returned,
                    Err(payload) => CallbackOutcome::Panicked(payload),
                };
                crate::hvf_backing::ContiguousAliasObservation {
                    callback,
                    teardown: Ok(()),
                }
            } else {
                for page in &settlement.pages {
                    sources.push((settlement.backings.page_storage(page.backing)?, 0usize));
                }
                let skip = backing.offset - first_page * PAGE_SIZE;
                let observation = with_contiguous_alias(&sources, |bytes| {
                    settlement.callback_started.set(true);
                    vacant.fill(f(&mut bytes[skip..skip + len]));
                });
                drop(sources);
                observation
            };

            match observation.callback {
                CallbackOutcome::NotInvoked => {
                    let trigger = observation.teardown.err().map_or(
                        HvfMemoryError::Witness(
                            "an alias setup skipped its callback without reporting an error",
                        ),
                        HvfMemoryError::from,
                    );
                    let cleanup = settlement.abort_before_callback();
                    Err(HvfMemoryError::with_cleanup(trigger, cleanup))
                }
                CallbackOutcome::Returned => {
                    if let Err(trigger) = observation.teardown {
                        let cleanup = settlement.settle(true);
                        return Err(HvfMemoryError::with_cleanup(trigger.into(), cleanup));
                    }
                    settlement.settle(false)?;
                    operation.require_live()?;
                    Ok(())
                }
                CallbackOutcome::Panicked(payload) => {
                    let _ = observation.teardown;
                    let _ = settlement.settle(true);
                    resume_unwind(payload)
                }
            }
        })
    }

    pub fn with_shared_backing<R: Copy>(
        &self,
        backing: HvfSharedBackingKey,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, HvfMemoryError> {
        let mut output = HvfCallbackOutput::new();
        self.with_shared_backing_into(backing, len, &mut output, f)?;
        output.into_filled()
    }

    /// Forgets the process-global shared backing object `identity`: pages no
    /// guest maps are freed now, the rest when their last mapping goes.
    /// Returns `true` when the object is fully gone, `false` when pages are
    /// still mapped, and [`HvfMemoryError::SharedBackingRange`] when no such
    /// object exists.
    pub fn release_shared_backing(&self, identity: usize) -> Result<bool, HvfMemoryError> {
        self.vm.with_cleanup_operation(|operation| {
            let mut backings = self
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut shared = self
                .shared_backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let registry_identity =
                shared
                    .get(&identity)
                    .copied()
                    .ok_or(HvfMemoryError::SharedBackingRange {
                        identity,
                        offset: 0,
                        length: 0,
                    })?;
            operation.mark_published()?;
            if shared.remove(&identity) != Some(registry_identity) {
                self.vm.poison();
                return Err(HvfMemoryError::IpaOwnership);
            }
            match backings.unpin(registry_identity) {
                Ok(gone) => Ok(gone),
                Err(error) => {
                    self.vm.poison();
                    Err(error)
                }
            }
        })
    }

    /// Resolves `key.identity` to its registry object, creating it on first
    /// use and growing it so it holds at least `pages` pages.
    fn shared_backing_identity(
        &self,
        backings: &mut BackingRegistry,
        shared: &mut HashMap<usize, HvfBackingIdentity>,
        key: HvfSharedBackingKey,
        pages: usize,
        mark_published: impl FnOnce() -> Result<(), HvfError>,
    ) -> Result<(HvfBackingIdentity, bool), HvfMemoryError> {
        let pages = pages.max(1);
        if let Some(identity) = shared.get(&key.identity).copied() {
            if backings.page_count(identity)? < pages {
                mark_published()?;
                backings.grow_pinned_shared(identity, pages)?;
                return Ok((identity, true));
            }
            return Ok((identity, false));
        }
        shared
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("shared backing index"))?;
        mark_published()?;
        let identity = backings.allocate_pinned_shared(pages)?;
        let mut registration = PinnedSharedBackingRegistration {
            vm: self.vm,
            backings,
            identity,
            armed: true,
        };
        match shared.entry(key.identity) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(identity);
                registration.commit();
                Ok((identity, true))
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                self.vm.poison();
                let cleanup = registration.rollback();
                Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::IpaOwnership,
                    cleanup,
                ))
            }
        }
    }

    fn create_address_space_with(
        &'static self,
        mirrored: bool,
    ) -> Result<HvfAddressSpace, HvfMemoryError> {
        self.vm.with_capability_operation(|operation| {
            let mut spaces = self
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            admit_resource(
                "address spaces",
                arenas.address_spaces,
                1,
                self.limits.max_address_spaces,
            )?;
            spaces
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("address-space ownership"))?;
            let id = HvfAddressSpaceId(take_counter(&mut arenas.next_address_space)?);
            let root_generation = arenas.next_root_generation()?;
            let pending_tlbi_generation = arenas.next_tlbi_generation()?;
            let asid = arenas.asids.allocate()?;
            let cell = Arc::new(AddressSpaceCell {
                id,
                asid,
                regime: self.regime,
                mirrored,
                attachment_abandoned: AtomicBool::new(false),
                destroy_abandoned: AtomicBool::new(false),
                state: Mutex::new(AddressSpaceState {
                    live: false,
                    destroy_pending: false,
                    root: TableToken(0),
                    root_generation,
                    executable_generation: HvfExecutableGeneration(0),
                    pending_tlbi_generation,
                    participants: HashMap::new(),
                    in_flight: 0,
                    claims: HashMap::new(),
                }),
                retirement_pump: Mutex::new(()),
            });
            let root = match create_monitor_root(self.vm, &mut arenas, self.limits.max_table_pages)
            {
                Ok(root) => root,
                Err(error) => {
                    let asid_cleanup = arenas.asids.release(asid);
                    let pool_cleanup = drain_table_pool_if_idle(self.vm, &mut arenas);
                    if asid_cleanup.is_err() {
                        self.vm.poison();
                    }
                    asid_cleanup?;
                    pool_cleanup?;
                    return Err(error);
                }
            };
            if let Err(error) = operation.require_live() {
                let root_cleanup = cleanup_candidate_root(self.vm, &mut arenas, root);
                let asid_cleanup = arenas.asids.release(asid);
                let pool_cleanup = drain_table_pool_if_idle(self.vm, &mut arenas);
                root_cleanup?;
                asid_cleanup?;
                pool_cleanup?;
                return Err(error.into());
            }
            operation.mark_published()?;
            {
                let mut state = cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.root = root;
                state.live = true;
            }
            if let Some(previous) = spaces.insert(id, cell.clone()) {
                if spaces.insert(id, previous).is_none() {
                    self.vm.poison();
                }
                let root_cleanup = cleanup_candidate_root(self.vm, &mut arenas, root);
                let asid_cleanup = arenas.asids.release(asid);
                let pool_cleanup = drain_table_pool_if_idle(self.vm, &mut arenas);
                cell.state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .live = false;
                self.vm.poison();
                root_cleanup.and(asid_cleanup).and(pool_cleanup)?;
                return Err(HvfMemoryError::IpaOwnership);
            }
            arenas.address_spaces += 1;
            Ok(HvfAddressSpace { memory: self, cell })
        })
    }

    fn validate_claim<'a>(
        &self,
        address_space: &HvfAddressSpace,
        state: &'a AddressSpaceState,
        claim: &HvfClaim,
    ) -> Result<&'a ClaimRecord, HvfMemoryError> {
        if !core::ptr::eq(self, address_space.memory)
            || claim.manager != self.manager
            || claim.address_space != address_space.cell.id
        {
            return Err(HvfMemoryError::WrongMemoryManager);
        }
        if !state.live {
            return Err(HvfMemoryError::AddressSpaceDestroyed(address_space.cell.id));
        }
        state
            .claims
            .get(&claim.range.start)
            .filter(|record| {
                record.id == claim.id
                    && record.version == claim.version
                    && record.range == claim.range
            })
            .ok_or(HvfMemoryError::ClaimStale)
    }

    fn reserve_retirement(
        &self,
        acknowledgements: &mut Acknowledgements,
        data_pages: usize,
        slot_pages: usize,
        backing_pages: usize,
        table_pages: usize,
    ) -> Result<RetirementReservation, HvfMemoryError> {
        let charged_pages = table_pages
            .checked_add(data_pages)
            .and_then(|value| value.checked_add(slot_pages))
            .and_then(|value| value.checked_add(backing_pages))
            .ok_or(HvfMemoryError::ResourceLimit {
                resource: "retired pages",
                requested: usize::MAX,
                limit: self.limits.max_retired_pages,
            })?;
        let charged_bytes =
            charged_pages
                .checked_mul(PAGE_SIZE)
                .ok_or(HvfMemoryError::ResourceLimit {
                    resource: "retired bytes",
                    requested: usize::MAX,
                    limit: self.limits.max_retired_bytes,
                })?;
        admit_resource(
            "retired generations",
            acknowledgements.retirements.len(),
            1,
            self.limits.max_retired_generations,
        )?;
        let requested_pages = admit_resource(
            "retired pages",
            acknowledgements.retired_pages,
            charged_pages,
            self.limits.max_retired_pages,
        )?;
        let requested_bytes = admit_resource(
            "retired bytes",
            acknowledgements.retired_bytes,
            charged_bytes,
            self.limits.max_retired_bytes,
        )?;
        acknowledgements
            .retirements
            .try_reserve(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("retirement ownership"))?;
        let id = take_counter(&mut acknowledgements.next_ticket)?;
        acknowledgements.retired_pages = requested_pages;
        acknowledgements.retired_bytes = requested_bytes;
        Ok(RetirementReservation {
            id,
            charged_pages,
            charged_bytes,
            data_pages,
            slot_pages,
            backing_pages,
            table_pages,
        })
    }

    #[expect(
        clippy::unused_self,
        reason = "retirement bookkeeping is an operation of the memory manager that owns it"
    )]
    fn cancel_retirement_reservation(
        &self,
        acknowledgements: &mut Acknowledgements,
        reservation: RetirementReservation,
    ) -> Result<(), HvfMemoryError> {
        acknowledgements.retired_pages = acknowledgements
            .retired_pages
            .checked_sub(reservation.charged_pages)
            .ok_or(HvfMemoryError::RetirementStale)?;
        acknowledgements.retired_bytes = acknowledgements
            .retired_bytes
            .checked_sub(reservation.charged_bytes)
            .ok_or(HvfMemoryError::RetirementStale)?;
        Ok(())
    }

    /// Names the participants a retirement must wait for. With
    /// `in_flight_only` (mirrored spaces) only participants that own an
    /// in-flight attachment at mutation time are required: an idle participant
    /// cannot be using the retiring root, and its next attach already forces a
    /// synchronization because its `last_*_generation` trails the space's.
    /// Otherwise every registered participant is required.
    #[expect(
        clippy::unused_self,
        reason = "retirement bookkeeping is an operation of the memory manager that owns it"
    )]
    fn prepare_retirement_participants(
        &self,
        state: &AddressSpaceState,
        in_flight_only: bool,
    ) -> Result<RetirementParticipants, HvfMemoryError> {
        let mut required = HashSet::new();
        required
            .try_reserve(state.participants.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("retirement participants"))?;
        required.extend(
            state
                .participants
                .iter()
                .filter(|(_, record)| !in_flight_only || record.in_flight != 0)
                .map(|(id, _)| *id),
        );
        let mut acknowledged = HashSet::new();
        acknowledged
            .try_reserve(required.len())
            .map_err(|_| HvfMemoryError::MetadataAllocation("retirement acknowledgements"))?;
        Ok(RetirementParticipants {
            required,
            acknowledged,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "each argument is a separately produced part of the retired generation this assembles"
    )]
    fn commit_retirement(
        &self,
        acknowledgements: &mut Acknowledgements,
        reservation: RetirementReservation,
        address_space: HvfAddressSpaceId,
        generation: HvfRootGeneration,
        tlbi_generation: HvfTlbiGeneration,
        participants: RetirementParticipants,
        root: TableToken,
        data: Vec<RetiredData>,
        slots: Vec<HostSlotToken>,
        backings: Vec<BackingPage>,
    ) -> HvfRetirementTicket {
        let mut id = reservation.id;
        let retired = RetiredGeneration {
            address_space,
            generation,
            tlbi_generation,
            deferred: false,
            required_participants: participants.required,
            acknowledged_participants: participants.acknowledged,
            root,
            data,
            slots,
            backings,
            charged_pages: reservation.charged_pages,
            charged_bytes: reservation.charged_bytes,
            data_pages: reservation.data_pages,
            slot_pages: reservation.slot_pages,
            backing_pages: reservation.backing_pages,
            table_pages: reservation.table_pages,
        };
        loop {
            match acknowledgements.retirements.entry(id) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(retired);
                    break;
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    id = if id == u64::MAX { 1 } else { id + 1 };
                }
            }
        }
        HvfRetirementTicket::mint(self.manager, address_space, id, generation)
    }

    /// Looks up the retirement still pending against `address_space` and mints
    /// its ticket from the ledger record, so cleanup paths never forge a live
    /// ticket from a raw id. The lowest ticket id wins when several are
    /// pending, which keeps repeated lookups deterministic.
    pub(crate) fn pending_retirement_ticket(
        &self,
        address_space: HvfAddressSpaceId,
    ) -> Option<HvfRetirementTicket> {
        let acknowledgements = self
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        acknowledgements
            .retirements
            .iter()
            .filter(|(_, retired)| retired.address_space == address_space)
            .min_by_key(|&(&id, _)| id)
            .map(|(&id, retired)| {
                HvfRetirementTicket::mint(self.manager, address_space, id, retired.generation)
            })
    }

    fn inject_failure(&self, point: FailurePoint) {
        let mut arenas = self
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        arenas.failure = Some(point);
    }

    /// `HvfMemoryUsage::quarantined_resources` from the running counters:
    /// O(1) apart from the (failure-only, normally empty) abandoned-root
    /// list, so it is affordable on every retirement acknowledgement.
    fn quarantined_resources_locked(
        arenas: &Arenas,
        backings: &BackingRegistry,
        acknowledgements: &Acknowledgements,
    ) -> usize {
        arenas.tables.quarantined.len()
            + arenas
                .tables
                .abandoned_roots
                .iter()
                .map(|(_, count)| *count)
                .sum::<usize>()
            + acknowledgements.alias_quarantine.len()
            + acknowledgements.data_quarantine.len()
            + acknowledgements.shared_writer_quarantine.len()
            + acknowledgements.shared_writer_quarantine_reservations
            + arenas.slots.tally.release_quarantined
            + backings.release_quarantine_count()
    }

    /// Debug-only cross-check that every running counter behind
    /// [`Self::usage_locked`] equals the value a full scan produces.
    fn debug_check_counters(
        arenas: &Arenas,
        backings: &BackingRegistry,
        acknowledgements: &Acknowledgements,
    ) {
        if !cfg!(debug_assertions) {
            return;
        }
        debug_assert_eq!(arenas.slots.tally, arenas.slots.recount());
        // The original slot term excluded slots named by an alias-quarantine
        // entry; `alias_quarantined` is set by every such entry and cleared
        // only as the entry goes, so the flag stands in for the membership.
        let release_quarantined_unaliased = arenas
            .slots
            .records
            .iter()
            .filter(|(token, record)| {
                record.release_quarantined
                    && !acknowledgements
                        .alias_quarantine
                        .iter()
                        .any(|quarantine| quarantine.slot == **token)
            })
            .count();
        debug_assert_eq!(
            arenas.slots.tally.release_quarantined,
            release_quarantined_unaliased
        );
        debug_assert_eq!(
            backings.release_quarantine_count(),
            backings.recount_release_quarantined()
        );
        debug_assert_eq!(backings.pinned_count(), backings.recount_pinned());
        for (space, count) in &acknowledgements.deferred {
            debug_assert_eq!(*count, acknowledgements.recount_deferred(*space));
        }
        debug_assert_eq!(
            acknowledgements
                .deferred
                .iter()
                .map(|(_, count)| *count)
                .sum::<usize>(),
            acknowledgements
                .retirements
                .values()
                .filter(|retired| retired.deferred)
                .count()
        );
    }

    fn usage_locked(
        &self,
        arenas: &Arenas,
        backings: &BackingRegistry,
        acknowledgements: &Acknowledgements,
    ) -> HvfMemoryUsage {
        Self::debug_check_counters(arenas, backings, acknowledgements);
        HvfMemoryUsage {
            address_spaces: arenas.address_spaces,
            claimed_pages: arenas.claimed_pages,
            live_data_pages: arenas.live_data_pages,
            table_pages: arenas.tables.records.len(),
            synchronization_table_pages: self.synchronization_root.table_pages,
            host_slots: arenas.slots.records.len(),
            backing_objects: backings.records.len(),
            physical_backing_pages: backings.physical_pages(),
            physical_backing_bytes: backings.physical_pages().saturating_mul(PAGE_SIZE),
            // Pooled table pages are the allocator's reuse cache, owned by no
            // root, mapping or quarantine: like a free list they are not
            // accounted, so a claim that is rolled back or unmapped leaves the
            // usage exactly where it was even when its tables went through
            // the pool. [`HvfMemory::pooled_table_pages`] reports the cache.
            ipa_owned_pages: arenas
                .ipa
                .owned_pages()
                .saturating_sub(arenas.tables.pool.len()),
            synchronization_ipa_pages: self.synchronization_root.table_pages,
            ipa_capacity_pages: arenas.ipa.capacity_pages(),
            asids_owned: arenas.asids.owned(),
            active_alias_pages: arenas.slots.tally.active,
            alias_quarantine_reservations: acknowledgements.alias_quarantine_reservations,
            data_quarantine_reservations: acknowledgements.data_quarantine_reservations,
            retired_generations: acknowledgements.retirements.len(),
            retired_pages: acknowledgements.retired_pages,
            retired_bytes: acknowledgements.retired_bytes,
            quarantined_resources: Self::quarantined_resources_locked(
                arenas,
                backings,
                acknowledgements,
            ),
            mirrored_alias_pages: arenas.slots.tally.mirrored,
            pinned_shared_backings: backings.pinned_count(),
        }
    }

    /// Released stage-one table pages kept stage-2 mapped and zeroed for
    /// reuse. They hold IPA pages outside [`HvfMemoryUsage::ipa_owned_pages`]
    /// and are unmapped when the last address space is destroyed.
    pub fn pooled_table_pages(&self) -> usize {
        self.arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tables
            .pool
            .len()
    }

    pub fn usage(&self) -> HvfMemoryUsage {
        let arenas = self
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let backings = self
            .backings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let acknowledgements = self
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.usage_locked(&arenas, &backings, &acknowledgements)
    }

    fn usage_is_manager_baseline(&self, usage: &HvfMemoryUsage) -> bool {
        let synchronization_pages = self.synchronization_root.table_pages;
        usage.address_spaces == 0
            && usage.claimed_pages == 0
            && usage.live_data_pages == 0
            && usage.table_pages == synchronization_pages
            && usage.synchronization_table_pages == synchronization_pages
            && usage.host_slots == 0
            && usage.backing_objects == 0
            && usage.physical_backing_pages == 0
            && usage.physical_backing_bytes == 0
            && usage.ipa_owned_pages == synchronization_pages
            && usage.synchronization_ipa_pages == synchronization_pages
            && usage.ipa_capacity_pages
                == self
                    .limits
                    .max_live_data_pages
                    .saturating_add(self.limits.max_table_pages)
            && usage.asids_owned == 0
            && usage.active_alias_pages == 0
            && usage.alias_quarantine_reservations == 0
            && usage.data_quarantine_reservations == 0
            && usage.retired_generations == 0
            && usage.retired_pages == 0
            && usage.retired_bytes == 0
            && usage.quarantined_resources == 0
            && usage.mirrored_alias_pages == 0
            && usage.pinned_shared_backings == 0
            && self.pooled_table_pages() == 0
    }

    /// Whether the SDK's residual counts match the process-global manager's
    /// persistent baseline: exactly the monitor mapping plus the
    /// synchronization root's table mappings (the "five-mapping baseline"),
    /// nothing unknown, and no vCPUs. This is a pure resource-count check and
    /// deliberately says nothing about whether a zero-vcpu operation is
    /// currently active or owned by the calling thread: that is a
    /// context-dependent admission fact, true for the whole body of a memory
    /// probe (which legitimately holds its own zero-vcpu operation while it
    /// verifies this baseline) and false once no such operation is held.
    /// Callers assert whichever polarity their own calling context requires.
    fn sdk_is_manager_baseline(&self, report: &HvfSdkResidualReport) -> bool {
        let Some(mapping_pages) = self.synchronization_root.table_pages.checked_add(1) else {
            return false;
        };
        let Some(mapping_bytes) = mapping_pages.checked_mul(PAGE_SIZE) else {
            return false;
        };
        report.logical_mapping_tokens == mapping_pages
            && report.logical_mapping_fragments == mapping_pages
            && report.logical_mapping_pages == mapping_pages
            && report.logical_mapping_bytes == mapping_bytes
            && report.known_present_fragments == mapping_pages
            && report.known_present_pages == mapping_pages
            && report.known_present_bytes == mapping_bytes
            && report.unknown_fragments == 0
            && report.unknown_pages == 0
            && report.unknown_bytes == 0
            && report.permissions_unknown_mapping_tokens == 0
            && report.logical_vcpu_tokens == 0
            && report.active_vcpus == 0
            && report.quarantined_vcpus == 0
    }

    pub fn retry_quarantined_aliases(&self) -> Result<usize, HvfMemoryError> {
        self.vm.with_cleanup_operation(|operation| {
            let mut arenas = self
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            retry_aliases_locked(
                self.vm,
                &mut arenas,
                &mut backings,
                &mut acknowledgements,
                || operation.mark_published(),
            )
        })
    }

    pub fn retry_quarantined_resources(&self) -> Result<HvfQuarantineRetryReport, HvfMemoryError> {
        self.vm.with_cleanup_operation(|operation| {
            operation.mark_published()?;
            let mut first_error: Option<HvfMemoryError> = None;
            let mut sdk_mapping_fragments_released = 0usize;
            let mut after_sdk_token = None;
            loop {
                let token = {
                    let arenas = self
                        .arenas
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let acknowledgements = self
                        .acknowledgements
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    arenas
                        .tables
                        .quarantined
                        .iter()
                        .filter_map(|quarantine| quarantine.sdk_token)
                        .chain(
                            acknowledgements
                                .data_quarantine
                                .iter()
                                .filter_map(|quarantine| quarantine.sdk_token),
                        )
                        .filter(|token| after_sdk_token.is_none_or(|after| *token > after))
                        .min()
                };
                let Some(token) = token else {
                    break;
                };
                after_sdk_token = Some(token);
                match self.vm.retry_quarantined_mapping(token) {
                    Ok(released) => match sdk_mapping_fragments_released.checked_add(released) {
                        Some(total) => sdk_mapping_fragments_released = total,
                        None => {
                            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                        }
                    },
                    Err(error) => {
                        first_error.get_or_insert(error.into());
                    }
                }
            }

            let mut aliases_restored = 0usize;
            let mut data_pages_released = 0usize;
            let mut table_pages_released = 0usize;
            let host_slots_released;
            let backings_released;
            {
                let mut arenas = self
                    .arenas
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut backings = self
                    .backings
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut acknowledgements = self
                    .acknowledgements
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);

                match retry_aliases_locked(
                    self.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    || Ok::<(), HvfError>(()),
                ) {
                    Ok(restored) => aliases_restored = restored,
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }

                if let Err(error) = retry_mirror_plan_residual(
                    self.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                ) {
                    first_error.get_or_insert(error);
                }

                let mut writer_index = 0;
                while writer_index < acknowledgements.shared_writer_quarantine.len() {
                    let backing = acknowledgements.shared_writer_quarantine[writer_index].backing;
                    if let Some(epoch) =
                        acknowledgements.shared_writer_quarantine[writer_index].write_epoch
                    {
                        match backings.write_epoch(backing, epoch) {
                            Ok(()) => {
                                acknowledgements.shared_writer_quarantine[writer_index]
                                    .write_epoch = None;
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    if acknowledgements.shared_writer_quarantine[writer_index].release_host_writer {
                        let release = backings
                            .preflight_release_host_alias(backing)
                            .and_then(|()| backings.release_host_alias(backing, true));
                        match release {
                            Ok(()) => {
                                acknowledgements.shared_writer_quarantine[writer_index]
                                    .release_host_writer = false;
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    let settled = {
                        let quarantine = &acknowledgements.shared_writer_quarantine[writer_index];
                        quarantine.write_epoch.is_none() && !quarantine.release_host_writer
                    };
                    if settled {
                        acknowledgements
                            .shared_writer_quarantine
                            .swap_remove(writer_index);
                        if let Err(error) = backings.reap_if_unowned(backing) {
                            first_error.get_or_insert(error);
                        }
                    } else {
                        writer_index += 1;
                    }
                }

                arenas
                    .tables
                    .abandoned_roots
                    .sort_unstable_by_key(|(token, _)| *token);
                let mut root_index = 0;
                while root_index < arenas.tables.abandoned_roots.len() {
                    let (root, count) = arenas.tables.abandoned_roots[root_index];
                    match arenas.tables.release(root) {
                        Ok(records) => {
                            if count > 1 {
                                arenas.tables.abandoned_roots[root_index].1 = count - 1;
                                root_index += 1;
                            } else {
                                arenas.tables.abandoned_roots.remove(root_index);
                            }
                            let released = records.len();
                            if let Err(error) = cleanup_table_records(self.vm, &mut arenas, records)
                            {
                                first_error.get_or_insert(error);
                            } else {
                                match table_pages_released.checked_add(released) {
                                    Some(total) => table_pages_released = total,
                                    None => {
                                        first_error.get_or_insert(HvfMemoryError::TableOwnership);
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                            root_index += 1;
                        }
                    }
                }

                let mut data_index = 0;
                while data_index < acknowledgements.data_quarantine.len() {
                    if !acknowledgements.data_quarantine[data_index].retryable {
                        data_index += 1;
                        continue;
                    }
                    if let Some(token) = acknowledgements.data_quarantine[data_index].sdk_token {
                        if self.vm.mapping_token_has_residual(token) {
                            data_index += 1;
                            continue;
                        }
                        acknowledgements.data_quarantine[data_index].sdk_token = None;
                    }
                    if acknowledgements.data_quarantine[data_index].mapping_quarantine {
                        let backing = acknowledgements.data_quarantine[data_index].backing;
                        match backings.resolve_mapping_quarantine(backing) {
                            Ok(()) => {
                                acknowledgements.data_quarantine[data_index].mapping_quarantine =
                                    false;
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    if let Some(ipa) = acknowledgements.data_quarantine[data_index].ipa {
                        match arenas.ipa.release(ipa) {
                            Ok(()) => {
                                acknowledgements.data_quarantine[data_index].ipa = None;
                                match data_pages_released.checked_add(1) {
                                    Some(total) => data_pages_released = total,
                                    None => {
                                        first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                                    }
                                }
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    if let Some(authority) = acknowledgements.data_quarantine[data_index].authority
                    {
                        let backing = acknowledgements.data_quarantine[data_index].backing;
                        match backings.release_stage_two(backing, authority) {
                            Ok(()) => {
                                acknowledgements.data_quarantine[data_index].authority = None;
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    if acknowledgements.data_quarantine[data_index].release_backing_reference {
                        let backing = acknowledgements.data_quarantine[data_index].backing;
                        match backings.release(backing) {
                            Ok(_) => {
                                acknowledgements.data_quarantine[data_index]
                                    .release_backing_reference = false;
                            }
                            Err(error) => {
                                if matches!(backings.page_has_reference(backing), Ok(false)) {
                                    acknowledgements.data_quarantine[data_index]
                                        .release_backing_reference = false;
                                }
                                first_error.get_or_insert(error);
                            }
                        }
                    }
                    let backing = acknowledgements.data_quarantine[data_index].backing;
                    if let Err(error) = backings.reap_if_unowned(backing) {
                        first_error.get_or_insert(error);
                    }
                    let quarantine = &acknowledgements.data_quarantine[data_index];
                    if quarantine.ipa.is_some()
                        || quarantine.authority.is_some()
                        || quarantine.sdk_token.is_some()
                        || quarantine.mapping_quarantine
                        || quarantine.release_backing_reference
                    {
                        data_index += 1;
                    } else {
                        acknowledgements.data_quarantine.swap_remove(data_index);
                    }
                }

                match retry_aliases_locked(
                    self.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    || Ok::<(), HvfError>(()),
                ) {
                    Ok(restored) => match aliases_restored.checked_add(restored) {
                        Some(total) => aliases_restored = total,
                        None => {
                            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                        }
                    },
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }

                let mut table_index = 0;
                while table_index < arenas.tables.quarantined.len() {
                    if !arenas.tables.quarantined[table_index].retryable {
                        table_index += 1;
                        continue;
                    }
                    if let Some(token) = arenas.tables.quarantined[table_index].sdk_token {
                        if self.vm.mapping_token_has_residual(token) {
                            table_index += 1;
                            continue;
                        }
                        arenas.tables.quarantined[table_index].sdk_token = None;
                        arenas.tables.quarantined[table_index]
                            .bytes
                            .disarm_after_exact_absence();
                    } else if arenas.tables.quarantined[table_index]
                        .bytes
                        .mapping_may_remain()
                    {
                        table_index += 1;
                        continue;
                    }
                    if let Some(ipa) = arenas.tables.quarantined[table_index].ipa {
                        if let Err(error) = arenas.ipa.release(ipa) {
                            first_error.get_or_insert(error);
                            table_index += 1;
                            continue;
                        }
                        arenas.tables.quarantined[table_index].ipa = None;
                        match table_pages_released.checked_add(1) {
                            Some(total) => table_pages_released = total,
                            None => {
                                first_error.get_or_insert(HvfMemoryError::TableOwnership);
                            }
                        }
                    }
                    arenas.tables.quarantined.swap_remove(table_index);
                }

                if let Err(error) = drain_table_pool_if_idle(self.vm, &mut arenas) {
                    first_error.get_or_insert(error);
                }
                let (released, slot_error) = arenas.slots.retry_quarantined_releases();
                host_slots_released = released;
                if let Some(error) = slot_error {
                    first_error.get_or_insert(error);
                }
                let (released, backing_error) = backings.retry_quarantined_releases();
                backings_released = released;
                if let Some(error) = backing_error {
                    first_error.get_or_insert(error);
                }
            }

            let host_resources_released = match hvf_host_retry_residual() {
                Ok(released) => released,
                Err(error) => {
                    first_error.get_or_insert(error.into());
                    0
                }
            };
            let sdk_residuals = match self.vm.residual_report() {
                Ok(report) => Some(report),
                Err(error) => {
                    first_error.get_or_insert(error.into());
                    None
                }
            };
            let remaining = self.usage();
            if let Some(error) = first_error {
                return Err(error);
            }
            Ok(HvfQuarantineRetryReport {
                sdk_mapping_fragments_released,
                host_resources_released,
                aliases_restored,
                data_pages_released,
                table_pages_released,
                host_slots_released,
                backings_released,
                sdk_residuals: sdk_residuals.ok_or(HvfMemoryError::IpaOwnership)?,
                remaining,
            })
        })
    }
}

impl HvfAddressSpace {
    pub fn id(&self) -> HvfAddressSpaceId {
        self.cell.id
    }

    pub fn asid(&self) -> HvfAsid {
        self.cell.asid
    }

    pub fn regime(&self) -> HvfTranslationRegime {
        self.cell.regime
    }

    /// `true` for a space made by [`HvfMemory::create_mirrored_address_space`].
    pub fn is_mirrored(&self) -> bool {
        self.cell.mirrored
    }

    pub(crate) fn preflight_map_range(
        &self,
        range: &Range<usize>,
        permissions: HvfGuestPermissions,
    ) -> Result<usize, HvfMemoryError> {
        let page_count = self.cell.regime.validate_range(range)?;
        refuse_write_execute(range, permissions)?;
        permissions.validate()?;
        check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
        Ok(page_count)
    }

    pub(crate) fn preflight_mapped_range(
        &self,
        range: &Range<usize>,
    ) -> Result<(), HvfMemoryError> {
        self.cell.regime.validate_range(range)?;
        self.covering_claims(range).map(drop)
    }

    /// Maps anonymous private zeroed pages over `range` (Linux `mmap`
    /// semantics). With `replace == false` any already-claimed page fails
    /// with [`HvfMemoryError::AddressOverlap`]; with `replace == true`
    /// (`MAP_FIXED`) overlapping pages are unmapped first. EXECUTE is
    /// admitted by claiming non-executable, publishing, then protecting;
    /// WRITE together with EXECUTE is refused with
    /// [`HvfMemoryError::WriteExecuteRefused`].
    pub fn map_range(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        replace: bool,
    ) -> Result<HvfRangeMutation, HvfMemoryError> {
        self.preflight_map_range(&range, permissions)?;
        let replaced = if replace {
            match self.unmap_pieces(&range)? {
                Some(unmapped) => {
                    self.settle_or_defer(unmapped.retirement).map_err(|error| {
                        HvfMemoryError::after_publication("MAP_FIXED replacement", error)
                    })?;
                    true
                }
                None => false,
            }
        } else {
            false
        };
        match self.map_claimed(range, permissions, HvfSharing::Private, ClaimSource::Fresh) {
            Ok(mutation) => Ok(mutation),
            // `claim_with`'s own `ensure_claim_gap`/regime checks run before it takes any lock
            // or touches any page table (see `ensure_claim_gap`/`claim_with`), so neither variant
            // ever reflects a half-applied mutation of *this* range -- regardless of whether the
            // preceding unmap above already published its own, independent, harmless-to-leave
            // side effect. Tainting them here defeats the ordinary recovery `allocation_error`
            // already implements for exactly these two variants and turns a normal "address in
            // use" race (another actor re-claimed the range this MAP_FIXED replace just freed)
            // into a fatal HVF abort. Mirrors the identical exemption in `map_shared_range`.
            Err(
                error @ (HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_)),
            ) => Err(error),
            Err(error) if replaced => Err(HvfMemoryError::after_publication(
                "MAP_FIXED replacement",
                error,
            )),
            Err(error) => Err(error),
        }
    }

    /// Maps `range` onto the pages of the process-global shared backing
    /// object named by `backing` (created on first use, grown so
    /// `backing.offset + range.len()` fits). Every range mapped with the same
    /// identity, in any space, aliases the same physical pages.
    pub fn map_shared_range(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        backing: HvfSharedBackingKey,
    ) -> Result<HvfRangeMutation, HvfMemoryError> {
        let page_count = self.preflight_map_range(&range, permissions)?;
        if !backing.offset.is_multiple_of(PAGE_SIZE) {
            return Err(HvfMemoryError::Unaligned {
                start: backing.offset,
                length: range.len(),
            });
        }
        let first_page = backing.offset / PAGE_SIZE;
        let needed =
            first_page
                .checked_add(page_count)
                .ok_or(HvfMemoryError::SharedBackingRange {
                    identity: backing.identity,
                    offset: backing.offset,
                    length: range.len(),
                })?;
        let (identity, shared_backing_changed) = self.memory.vm.with_operation(|operation| {
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut shared = self
                .memory
                .shared_backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (identity, changed) = self.memory.shared_backing_identity(
                &mut backings,
                &mut shared,
                backing,
                needed,
                || operation.mark_published(),
            )?;
            operation.require_live()?;
            Ok::<_, HvfMemoryError>((identity, changed))
        })?;
        let mapping = self.map_claimed(
            range,
            permissions,
            HvfSharing::Shared,
            ClaimSource::Shared {
                identity,
                first_page,
            },
        );
        match mapping {
            // `claim_with`'s own `ensure_claim_gap`/regime checks that produce these two
            // variants run before it takes any lock or touches any page table (see
            // `ensure_claim_gap` and `HvfTranslationRegime::validate_range`), so neither ever
            // reflects a half-applied mutation of *this* range -- regardless of whether growing
            // the shared backing object above already published its own, independent, and
            // harmless-to-leave-grown side effect. Tainting them as `PublishedMutation` here
            // defeats the ordinary recovery both callers already implement for exactly these
            // two variants (`allocation_error`'s `AddressInUse` arm, `remap_shared_pages`'s
            // `AlreadyAllocated` arm) and turns a normal "address in use" into a fatal HVF abort.
            Err(
                error @ (HvfMemoryError::AddressOverlap(_) | HvfMemoryError::MonitorOverlap(_)),
            ) => Err(error),
            Err(error) if shared_backing_changed => Err(HvfMemoryError::after_publication(
                "shared backing map",
                error,
            )),
            result => result,
        }
    }

    /// Linux `mprotect` semantics over already-mapped pages: every page in
    /// `range` must be mapped ([`HvfMemoryError::RangeUnmapped`] otherwise),
    /// NONE keeps contents, a transition to EXECUTE publishes first, and
    /// WRITE with EXECUTE is refused.
    pub fn protect_range(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
    ) -> Result<HvfRangeMutation, HvfMemoryError> {
        self.cell.regime.validate_range(&range)?;
        refuse_write_execute(&range, permissions)?;
        permissions.validate()?;
        let pieces = self.covering_claims(&range)?;
        for (_, piece, _) in &pieces {
            check_mutation_bound(
                piece.len() / PAGE_SIZE,
                self.memory.limits.max_mutation_pages,
            )?;
        }
        let mut last: Option<HvfRangeMutation> = None;
        let mut published = false;
        for (claim, piece, has_sparse) in pieces {
            if let Some(previous) = last.take()
                && let Err(error) = self.settle_or_defer(previous.retirement)
            {
                return Err(HvfMemoryError::after_publication("range protect", error));
            }

            let mutation = if permissions.contains(HvfGuestPermissions::EXECUTE) {
                let claim = if has_sparse {
                    let materialized = match self.protect(
                        &claim,
                        piece.clone(),
                        HvfGuestPermissions::READ,
                        None,
                    ) {
                        Ok(materialized) => materialized,
                        Err(error) if published => {
                            return Err(HvfMemoryError::after_publication("range protect", error));
                        }
                        Err(error) => return Err(error),
                    };
                    published = true;
                    if let Err(error) = self.settle_or_defer(materialized.retirement) {
                        return Err(HvfMemoryError::after_publication("range protect", error));
                    }
                    materialized.claim
                } else {
                    claim
                };
                let publication = match self.publish_executable(&claim, piece.clone()) {
                    Ok(publication) => publication,
                    Err(error) if published => {
                        return Err(HvfMemoryError::after_publication("range protect", error));
                    }
                    Err(error) => return Err(error),
                };
                published = true;
                self.protect(&claim, piece, permissions, Some(&publication))
            } else {
                self.protect(&claim, piece, permissions, None)
            };
            let mutation = match mutation {
                Ok(mutation) => mutation,
                Err(error) if published => {
                    return Err(HvfMemoryError::after_publication("range protect", error));
                }
                Err(error) => return Err(error),
            };
            published = true;
            last = Some(HvfRangeMutation {
                retirement: mutation.retirement,
                root_generation: mutation.root_generation,
                executable_generation: mutation.executable_generation,
                changed: true,
            });
        }
        last.ok_or(HvfMemoryError::RangeUnmapped(range))
    }

    /// Linux `munmap` semantics: holes are allowed, partial claims split. A
    /// range with nothing mapped succeeds with a no-op retirement (the
    /// current root, retained and released again on acknowledgement).
    pub fn unmap_range(&self, range: Range<usize>) -> Result<HvfRangeMutation, HvfMemoryError> {
        self.cell.regime.validate_range(&range)?;
        match self.unmap_pieces(&range)? {
            Some(mutation) => Ok(mutation),
            None => self.noop_mutation(),
        }
    }

    /// Parks `ticket` for [`HvfAddressSpace::pump_retirements`], so the
    /// mutator that minted it never waits for participants. Custody is marked
    /// directly in the pre-reserved retirement ledger: valid deferral performs
    /// no allocation and cannot drop a committed generation between ledgers.
    pub fn defer_retirement(&self, ticket: HvfRetirementTicket) -> Result<(), HvfMemoryError> {
        if ticket.manager != self.memory.manager {
            return Err(HvfMemoryError::WrongMemoryManager);
        }
        if !ticket.live {
            return Err(HvfMemoryError::RetirementStale);
        }
        let wrong_space = ticket.address_space != self.cell.id;
        let mut acknowledgements = self
            .memory
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        acknowledgements.mark_deferred(ticket.id, ticket.address_space, ticket.generation)?;
        drop(acknowledgements);
        if wrong_space {
            Err(HvfMemoryError::WrongMemoryManager)
        } else {
            Ok(())
        }
    }

    /// Tries each ledger-backed deferred retirement once and returns how many
    /// were released. Tickets whose participants still owe a synchronization
    /// remain marked; tickets already acknowledged elsewhere disappear with
    /// their ledger record. Snapshot allocation failure also leaves every
    /// marker intact for a later pass.
    pub fn pump_retirements(&self) -> Result<usize, HvfMemoryError> {
        let _pump = self
            .cell
            .retirement_pump
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tickets = {
            let acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = acknowledgements.deferred_count(self.cell.id);
            debug_assert_eq!(count, acknowledgements.recount_deferred(self.cell.id));
            if count == 0 {
                return Ok(0);
            }
            let mut tickets = Vec::new();
            tickets
                .try_reserve_exact(count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("deferred retirement pump"))?;
            // Only tickets every required participant has already
            // acknowledged are tried: the others would be refused with
            // `RetirementParticipantsPending` by the same check under the
            // same lock, so skipping them here changes nothing but the cost.
            tickets.extend(
                acknowledgements
                    .retirements
                    .iter()
                    .filter(|(_, retired)| {
                        retired.address_space == self.cell.id
                            && retired.deferred
                            && retired.required_participants.iter().all(|participant| {
                                retired.acknowledged_participants.contains(participant)
                            })
                    })
                    .map(|(&id, retired)| {
                        HvfRetirementTicket::mint(
                            self.memory.manager,
                            retired.address_space,
                            id,
                            retired.generation,
                        )
                    }),
            );
            tickets
        };
        let mut released = 0usize;
        let mut first_error = None;
        for mut ticket in tickets {
            match self.acknowledge_retirement(&mut ticket) {
                Ok(_) => released += 1,
                Err(
                    HvfMemoryError::RetirementParticipantsPending { .. }
                    | HvfMemoryError::RetirementStale,
                ) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(released),
        }
    }

    /// How many tickets are parked for [`HvfAddressSpace::pump_retirements`].
    pub fn pending_retirements(&self) -> usize {
        let acknowledgements = self
            .memory
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = acknowledgements.deferred_count(self.cell.id);
        debug_assert_eq!(count, acknowledgements.recount_deferred(self.cell.id));
        count
    }

    /// The capability for the claim containing `gva`, for callers that drive
    /// the range API but need a claim-scoped alias or publication.
    pub fn claim_at(&self, gva: usize) -> Result<HvfClaim, HvfMemoryError> {
        self.cell.regime.validate_address(gva)?;
        let state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.live {
            return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
        }
        state
            .claims
            .values()
            .find(|record| record.range.contains(&gva))
            .map(|record| self.claim_capability(record))
            .ok_or(HvfMemoryError::RangeUnmapped(gva..gva + PAGE_SIZE))
    }

    fn claim_capability(&self, record: &ClaimRecord) -> HvfClaim {
        HvfClaim {
            manager: self.memory.manager,
            address_space: self.cell.id,
            id: record.id,
            version: record.version,
            range: record.range.clone(),
        }
    }

    /// Acknowledges `ticket` now when nobody owes a synchronization, and
    /// parks it otherwise; a failed acknowledgement leaves the ticket parked
    /// so a later pump can retry it.
    fn settle_or_defer(&self, mut ticket: HvfRetirementTicket) -> Result<(), HvfMemoryError> {
        match self.acknowledge_retirement(&mut ticket) {
            Ok(_) => Ok(()),
            Err(HvfMemoryError::RetirementParticipantsPending { .. }) => {
                if let Err(error) = self.defer_retirement(ticket) {
                    self.memory.vm.poison();
                    Err(error)
                } else {
                    Ok(())
                }
            }
            Err(error) if ticket.live => match self.defer_retirement(ticket) {
                Ok(()) => Err(error),
                Err(deferral) => {
                    self.memory.vm.poison();
                    Err(deferral)
                }
            },
            Err(error) => Err(error),
        }
    }

    fn map_claimed(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        sharing: HvfSharing,
        source: ClaimSource,
    ) -> Result<HvfRangeMutation, HvfMemoryError> {
        let executable = permissions.contains(HvfGuestPermissions::EXECUTE);
        let initial = if executable {
            HvfGuestPermissions(
                (permissions.0 & !HvfGuestPermissions::EXECUTE.0) | HvfGuestPermissions::READ.0,
            )
        } else {
            permissions
        };
        let claimed = self.claim_with(range.clone(), initial, sharing, source)?;
        if !executable {
            return Ok(HvfRangeMutation {
                retirement: claimed.retirement,
                root_generation: claimed.root_generation,
                executable_generation: claimed.executable_generation,
                changed: true,
            });
        }
        if let Err(error) = self.settle_or_defer(claimed.retirement) {
            return Err(HvfMemoryError::after_publication("executable map", error));
        }
        let claim = claimed.claim;
        let published = self
            .publish_executable(&claim, range.clone())
            .and_then(|publication| {
                self.protect(&claim, range.clone(), permissions, Some(&publication))
            });
        match published {
            Ok(mutation) => Ok(HvfRangeMutation {
                retirement: mutation.retirement,
                root_generation: mutation.root_generation,
                executable_generation: mutation.executable_generation,
                changed: true,
            }),
            Err(error) => {
                let unmapped = self.unmap(&claim, range).map_err(|cleanup| {
                    HvfMemoryError::after_publication("executable map cleanup", cleanup)
                })?;
                self.settle_or_defer(unmapped.retirement)
                    .map_err(|cleanup| {
                        HvfMemoryError::after_publication("executable map cleanup", cleanup)
                    })?;
                Err(HvfMemoryError::after_publication("executable map", error))
            }
        }
    }

    /// Unmaps every claimed page inside `range`, one claim at a time, and
    /// returns the last mutation (earlier ones settled or deferred); `None`
    /// when nothing was mapped there.
    fn unmap_pieces(
        &self,
        range: &Range<usize>,
    ) -> Result<Option<HvfRangeMutation>, HvfMemoryError> {
        let pieces = self.overlapping_claims(range)?;
        for (_, piece) in &pieces {
            check_mutation_bound(
                piece.len() / PAGE_SIZE,
                self.memory.limits.max_mutation_pages,
            )?;
        }
        let mut last: Option<HvfRangeMutation> = None;
        let mut published = false;
        for (claim, piece) in pieces {
            if let Some(previous) = last.take()
                && let Err(error) = self.settle_or_defer(previous.retirement)
            {
                return Err(HvfMemoryError::after_publication("range unmap", error));
            }
            let unmapped = match self.unmap(&claim, piece) {
                Ok(unmapped) => unmapped,
                Err(error) if published => {
                    return Err(HvfMemoryError::after_publication("range unmap", error));
                }
                Err(error) => return Err(error),
            };
            published = true;
            last = Some(HvfRangeMutation {
                retirement: unmapped.retirement,
                root_generation: unmapped.root_generation,
                executable_generation: unmapped.executable_generation,
                changed: true,
            });
        }
        Ok(last)
    }

    /// The claims intersecting `range`, in address order, each with the
    /// intersection to operate on.
    fn overlapping_claims(
        &self,
        range: &Range<usize>,
    ) -> Result<Vec<(HvfClaim, Range<usize>)>, HvfMemoryError> {
        let state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.live {
            return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
        }
        let count = state
            .claims
            .values()
            .filter(|record| record.range.start < range.end && range.start < record.range.end)
            .count();
        let mut pieces = Vec::new();
        pieces
            .try_reserve_exact(count)
            .map_err(|_| HvfMemoryError::MetadataAllocation("range pieces"))?;
        for record in state.claims.values() {
            if record.range.start < range.end && range.start < record.range.end {
                let piece = record.range.start.max(range.start)..record.range.end.min(range.end);
                pieces.push((self.claim_capability(record), piece));
            }
        }
        pieces.sort_unstable_by_key(|(_, piece)| piece.start);
        Ok(pieces)
    }

    /// Like [`Self::overlapping_claims`], but every page of `range` must be
    /// claimed; the third element says whether the piece holds a sparse page.
    fn covering_claims(
        &self,
        range: &Range<usize>,
    ) -> Result<Vec<(HvfClaim, Range<usize>, bool)>, HvfMemoryError> {
        let state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.live {
            return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
        }
        let count = state
            .claims
            .values()
            .filter(|record| record.range.start < range.end && range.start < record.range.end)
            .count();
        let mut pieces = Vec::new();
        pieces
            .try_reserve_exact(count)
            .map_err(|_| HvfMemoryError::MetadataAllocation("range pieces"))?;
        let mut covered = 0usize;
        for record in state.claims.values() {
            if record.range.start < range.end && range.start < record.range.end {
                let piece = record.range.start.max(range.start)..record.range.end.min(range.end);
                covered = covered
                    .checked_add(piece.len())
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                let has_sparse = page_addresses(&piece).any(|gva| {
                    record
                        .pages
                        .get(&gva)
                        .is_none_or(|page| page.backing.is_none())
                });
                pieces.push((self.claim_capability(record), piece, has_sparse));
            }
        }
        if covered != range.len() {
            return Err(HvfMemoryError::RangeUnmapped(range.clone()));
        }
        pieces.sort_unstable_by_key(|(_, piece, _)| piece.start);
        Ok(pieces)
    }

    /// A retirement over nothing: retains the current root and hands back a
    /// ticket whose acknowledgement releases that one reference again, so a
    /// range operation that changed no page still yields exactly one ticket.
    fn noop_mutation(&self) -> Result<HvfRangeMutation, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            self.require_mutable(&state)?;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let participants = self
                .memory
                .prepare_retirement_participants(&state, self.cell.mirrored)?;
            let reservation = self
                .memory
                .reserve_retirement(&mut acknowledgements, 0, 0, 0, 0)?;
            if let Err(error) = arenas.tables.retain(state.root) {
                self.memory
                    .cancel_retirement_reservation(&mut acknowledgements, reservation)?;
                return Err(error);
            }
            if let Err(error) = operation.require_live() {
                let cancellation = self
                    .memory
                    .cancel_retirement_reservation(&mut acknowledgements, reservation);
                let release = cleanup_candidate_root(self.memory.vm, &mut arenas, state.root);
                cancellation?;
                release?;
                return Err(error.into());
            }
            operation.mark_published()?;
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                state.root_generation,
                state.pending_tlbi_generation,
                participants,
                state.root,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            Ok(HvfRangeMutation {
                retirement,
                root_generation: state.root_generation,
                executable_generation: state.executable_generation,
                changed: false,
            })
        })
    }

    fn require_quiescent(&self, state: &AddressSpaceState) -> Result<(), HvfMemoryError> {
        if self.cell.attachment_abandoned.load(Ordering::Acquire) {
            return Err(HvfMemoryError::AttachmentAbandoned(self.cell.id));
        }
        if state.in_flight != 0 {
            return Err(HvfMemoryError::AddressSpaceBusy(self.cell.id));
        }
        Ok(())
    }

    /// Like [`Self::require_quiescent`], except that a mirrored space admits
    /// mutations while vCPUs are in flight: the new root is published
    /// atomically, in-flight participants keep their retired root until they
    /// acknowledge, and the backend performs a synchronous shootdown (kick +
    /// acknowledgement) right after the mutation, exactly like a kernel's
    /// TLB-shootdown IPIs.
    fn require_mutable(&self, state: &AddressSpaceState) -> Result<(), HvfMemoryError> {
        if self.cell.attachment_abandoned.load(Ordering::Acquire) {
            return Err(HvfMemoryError::AttachmentAbandoned(self.cell.id));
        }
        if state.in_flight != 0 && !self.cell.mirrored {
            return Err(HvfMemoryError::AddressSpaceBusy(self.cell.id));
        }
        Ok(())
    }

    pub fn register_vcpu_participant(
        &self,
        capability: HvfVcpuLaneParticipantCapability,
    ) -> Result<HvfVcpuParticipant, HvfMemoryError> {
        let lane_generation = capability.generation();
        match capability.with_live_registration(|registration: HvfVcpuLaneRegistration| {
            self.memory.vm.with_operation(|operation| {
                if self.cell.attachment_abandoned.load(Ordering::Acquire) {
                    return Err(HvfMemoryError::AttachmentAbandoned(self.cell.id));
                }
                let mut state = self
                    .cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state.live {
                    return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
                }
                admit_resource(
                    "vCPU participants",
                    state.participants.len(),
                    1,
                    MAX_PARTICIPANTS_PER_ADDRESS_SPACE,
                )?;
                state
                    .participants
                    .try_reserve(1)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("vCPU participants"))?;
                let mut arenas = self
                    .memory
                    .arenas
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let id = HvfVcpuParticipantId(take_counter(&mut arenas.next_participant)?);
                if state.participants.contains_key(&id) {
                    return Err(HvfMemoryError::IpaOwnership);
                }
                operation.require_live()?;
                if !registration.is_live() {
                    return Err(HvfMemoryError::ParticipantLaneUnavailable(
                        registration.generation,
                    ));
                }
                let capability_state = Arc::new(AtomicU8::new(PARTICIPANT_LIVE));
                operation.mark_published()?;
                state.participants.insert(
                    id,
                    ParticipantRecord {
                        lane_generation: registration.generation,
                        lane_lifecycle: Arc::clone(&registration.lifecycle),
                        owner_stopped: Arc::clone(&registration.owner_stopped),
                        capability_state: Arc::clone(&capability_state),
                        attachment_state: None,
                        last_root_generation: HvfRootGeneration(0),
                        last_executable_generation: HvfExecutableGeneration(0),
                        last_tlbi_generation: HvfTlbiGeneration(0),
                        in_flight: 0,
                    },
                );
                Ok(HvfVcpuParticipant {
                    manager: self.memory.manager,
                    address_space: self.cell.id,
                    id,
                    lane_generation: registration.generation,
                    lane_lifecycle: registration.lifecycle,
                    owner_stopped: registration.owner_stopped,
                    capability_state,
                })
            })
        }) {
            Ok(result) => result,
            Err(_) => Err(HvfMemoryError::ParticipantLaneUnavailable(lane_generation)),
        }
    }

    pub fn deregister_vcpu_participant(
        &self,
        participant: &mut HvfVcpuParticipant,
    ) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            self.validate_participant_capability(participant)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let record = state
                .participants
                .get(&participant.id)
                .ok_or(HvfMemoryError::ParticipantStale(participant.id))?;
            if record.lane_generation != participant.lane_generation
                || !Arc::ptr_eq(&record.lane_lifecycle, &participant.lane_lifecycle)
                || !Arc::ptr_eq(&record.owner_stopped, &participant.owner_stopped)
                || !Arc::ptr_eq(&record.capability_state, &participant.capability_state)
            {
                return Err(HvfMemoryError::ParticipantLaneMismatch {
                    participant: participant.id,
                    expected: record.lane_generation,
                    actual: participant.lane_generation,
                });
            }
            if record.in_flight != 0 || record.attachment_state.is_some() {
                return Err(HvfMemoryError::ParticipantBusy(participant.id));
            }
            let owner_stopped = record.owner_stopped.load(Ordering::Acquire);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let retirement_pending = acknowledgements.retirements.values().any(|retired| {
                retired.address_space == self.cell.id
                    && retired.required_participants.contains(&participant.id)
                    && !retired.acknowledged_participants.contains(&participant.id)
            });
            if retirement_pending && !owner_stopped {
                return Err(HvfMemoryError::ParticipantRetirementPending(participant.id));
            }
            operation.mark_published()?;
            if owner_stopped {
                for retired in acknowledgements.retirements.values_mut().filter(|retired| {
                    retired.address_space == self.cell.id
                        && retired.required_participants.contains(&participant.id)
                }) {
                    retired.acknowledged_participants.insert(participant.id);
                }
            }
            state
                .participants
                .remove(&participant.id)
                .ok_or(HvfMemoryError::ParticipantStale(participant.id))?;
            participant
                .capability_state
                .store(PARTICIPANT_RELEASED, Ordering::Release);
            Ok(())
        })
    }

    /// Repairs participant records that can no longer make progress on their
    /// own, returning one receipt per repaired record.
    ///
    /// Two shapes are recovered:
    /// - a record whose attachment lease reached `ATTACHMENT_ABANDONED`: the
    ///   lease only reaches that state after the run returned or unwound, so
    ///   the vCPU is no longer executing on this root and the in-flight count
    ///   the lease held is released, whether or not the lane or the participant
    ///   handle is still alive;
    /// - a record whose participant handle was abandoned on a stopped lane,
    ///   which is removed outright with its pending retirements acknowledged on
    ///   its behalf.
    ///
    /// The cell's `attachment_abandoned` flag clears only once no in-flight
    /// attachment remains.
    pub fn recover_stopped_vcpu_participants(
        &self,
    ) -> Result<Vec<HvfParticipantRecoveryReceipt>, HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let mut receipts = Vec::new();
            receipts
                .try_reserve_exact(state.participants.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("participant recovery"))?;
            let mut released_in_flight = 0usize;
            for (&id, record) in &state.participants {
                let attachment_abandoned = record
                    .attachment_state
                    .as_ref()
                    .is_some_and(|lease| lease.load(Ordering::Acquire) == ATTACHMENT_ABANDONED);
                let handle_stopped = record.capability_state.load(Ordering::Acquire)
                    == PARTICIPANT_ABANDONED
                    && record.owner_stopped.load(Ordering::Acquire);
                if !attachment_abandoned && !handle_stopped {
                    continue;
                }
                if handle_stopped {
                    match (record.in_flight, record.attachment_state.as_ref()) {
                        (0, None) => {}
                        (1, Some(_)) if attachment_abandoned => {}
                        _ => return Err(HvfMemoryError::ParticipantBusy(id)),
                    }
                }
                released_in_flight = released_in_flight
                    .checked_add(record.in_flight)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                receipts.push(HvfParticipantRecoveryReceipt {
                    participant: id,
                    released_in_flight: record.in_flight,
                    removed: handle_stopped,
                });
            }
            let next_in_flight = state
                .in_flight
                .checked_sub(released_in_flight)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let clear_attachment_abandoned =
                next_in_flight == 0 && self.cell.attachment_abandoned.load(Ordering::Acquire);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !receipts.is_empty() || clear_attachment_abandoned {
                operation.mark_published()?;
            }
            for receipt in &receipts {
                let id = receipt.participant;
                if receipt.removed {
                    let record = state
                        .participants
                        .remove(&id)
                        .ok_or(HvfMemoryError::ParticipantStale(id))?;
                    for retired in acknowledgements.retirements.values_mut().filter(|retired| {
                        retired.address_space == self.cell.id
                            && retired.required_participants.contains(&id)
                    }) {
                        retired.acknowledged_participants.insert(id);
                    }
                    record
                        .capability_state
                        .store(PARTICIPANT_RECOVERED, Ordering::Release);
                } else {
                    let record = state
                        .participants
                        .get_mut(&id)
                        .ok_or(HvfMemoryError::ParticipantStale(id))?;
                    record.in_flight = 0;
                    record.attachment_state = None;
                }
            }
            state.in_flight = next_in_flight;
            if state.in_flight == 0 {
                self.cell
                    .attachment_abandoned
                    .store(false, Ordering::Release);
            }
            Ok(receipts)
        })
    }

    pub fn attach_vcpu(
        &self,
        participant: &HvfVcpuParticipant,
    ) -> Result<HvfVcpuRunAttachment, HvfMemoryError> {
        self.memory.vm.with_shared_operation(|operation| {
            self.validate_participant_capability(participant)?;
            if self.cell.attachment_abandoned.load(Ordering::Acquire) {
                return Err(HvfMemoryError::AttachmentAbandoned(self.cell.id));
            }
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let requires_synchronization = {
                let record = state
                    .participants
                    .get(&participant.id)
                    .ok_or(HvfMemoryError::ParticipantStale(participant.id))?;
                if record.lane_generation != participant.lane_generation
                    || !Arc::ptr_eq(&record.lane_lifecycle, &participant.lane_lifecycle)
                    || !Arc::ptr_eq(&record.owner_stopped, &participant.owner_stopped)
                    || !Arc::ptr_eq(&record.capability_state, &participant.capability_state)
                {
                    return Err(HvfMemoryError::ParticipantLaneMismatch {
                        participant: participant.id,
                        expected: record.lane_generation,
                        actual: participant.lane_generation,
                    });
                }
                if !hvf_vcpu_lane_is_live(&record.lane_lifecycle, &record.owner_stopped) {
                    return Err(HvfMemoryError::ParticipantLaneUnavailable(
                        record.lane_generation,
                    ));
                }
                record.last_root_generation < state.root_generation
                    || record.last_executable_generation < state.executable_generation
                    || record.last_tlbi_generation < state.pending_tlbi_generation
            };
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let root_ipa = arenas.tables.ipa(state.root)?;
            let synchronization_root_ipa =
                arenas.tables.ipa(self.memory.synchronization_root.token)?;
            if synchronization_root_ipa != self.memory.synchronization_root.ipa {
                return Err(HvfMemoryError::TableOwnership);
            }
            operation.require_live()?;
            Ok(HvfVcpuRunAttachment {
                memory: self.memory,
                cell: Arc::clone(&self.cell),
                participant: participant.id,
                lane_generation: participant.lane_generation,
                snapshot: HvfVcpuMemorySnapshot {
                    address_space_id: self.cell.id,
                    asid: self.cell.asid,
                    regime: self.cell.regime,
                    synchronization_ttbr0_el1: synchronization_root_ipa,
                    ttbr0_el1: (u64::from(self.cell.asid.value) << 48) | root_ipa,
                    root_generation: state.root_generation,
                    executable_generation: state.executable_generation,
                    pending_tlbi_generation: state.pending_tlbi_generation,
                },
                requires_synchronization,
                lease_state: Arc::new(AtomicU8::new(ATTACHMENT_ALLOCATED)),
            })
        })
    }

    pub fn acknowledge_synchronization(
        &self,
        attachment: &HvfVcpuRunAttachment,
        proof: HvfOwnerSynchronizationProof,
    ) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_shared_operation(|operation| {
            self.validate_attachment(attachment)?;
            if attachment.lease_state.load(Ordering::Acquire) != ATTACHMENT_SYNCHRONIZING {
                return Err(HvfMemoryError::AttachmentStale);
            }
            if proof.lane_generation() != attachment.lane_generation
                || proof.request() != attachment.synchronization_request()
            {
                return Err(HvfMemoryError::SynchronizationStale);
            }
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let record = state
                .participants
                .get_mut(&attachment.participant)
                .ok_or(HvfMemoryError::ParticipantStale(attachment.participant))?;
            if record.lane_generation != attachment.lane_generation
                || record.in_flight == 0
                || record.capability_state.load(Ordering::Acquire) != PARTICIPANT_LIVE
                || !record
                    .attachment_state
                    .as_ref()
                    .is_some_and(|state| Arc::ptr_eq(state, &attachment.lease_state))
            {
                return Err(HvfMemoryError::SynchronizationStale);
            }
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            operation.require_live()?;
            operation.mark_published()?;
            record.last_root_generation = attachment.snapshot.root_generation;
            record.last_executable_generation = attachment.snapshot.executable_generation;
            record.last_tlbi_generation = attachment.snapshot.pending_tlbi_generation;
            for retired in acknowledgements.retirements.values_mut().filter(|retired| {
                retired.address_space == self.cell.id
                    && retired.tlbi_generation <= attachment.snapshot.pending_tlbi_generation
                    && retired
                        .required_participants
                        .contains(&attachment.participant)
            }) {
                retired
                    .acknowledged_participants
                    .insert(attachment.participant);
            }
            Ok(())
        })
    }

    pub fn validate_attachment_for_run(
        &self,
        attachment: &HvfVcpuRunAttachment,
    ) -> Result<(), HvfMemoryError> {
        self.validate_attachment(attachment)?;
        if attachment.lease_state.load(Ordering::Acquire) != ATTACHMENT_RUNNING {
            return Err(HvfMemoryError::AttachmentStale);
        }
        let state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = state
            .participants
            .get(&attachment.participant)
            .ok_or(HvfMemoryError::ParticipantStale(attachment.participant))?;
        if record.lane_generation != attachment.lane_generation
            || record.in_flight == 0
            || record.capability_state.load(Ordering::Acquire) != PARTICIPANT_LIVE
            || !record
                .attachment_state
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(state, &attachment.lease_state))
            || record.last_root_generation < attachment.snapshot.root_generation
            || record.last_executable_generation < attachment.snapshot.executable_generation
            || record.last_tlbi_generation < attachment.snapshot.pending_tlbi_generation
        {
            return Err(HvfMemoryError::SynchronizationStale);
        }
        Ok(())
    }

    /// Retires `attachment`, returning its in-flight slot to the ledger.
    ///
    /// Only identity is checked up front (manager, cell, address-space id).
    /// The accounting is never gated on the cell's `attachment_abandoned` flag:
    /// refusing to account an attachment that is still SUBMITTED,
    /// SYNCHRONIZING or RUNNING would drop it into `ATTACHMENT_ABANDONED` and
    /// re-flag the cell, turning one abandonment into a cascade. An attachment
    /// handed to the wrong address space is retired on its own cell, so a
    /// mis-addressed call can never flag this one; the misuse is then reported
    /// as [`HvfMemoryError::WrongMemoryManager`].
    ///
    /// The lease reaches `ATTACHMENT_CLOSED` on every successful accounting
    /// path. A genuine ledger mismatch (in-flight underflow, or a record that
    /// does not name this lease) still abandons the attachment: that is the
    /// durable signal that the address space needs recovery.
    pub fn finish_vcpu_attachment(
        &self,
        attachment: HvfVcpuRunAttachment,
    ) -> Result<(), HvfMemoryError> {
        if attachment.memory.manager != self.memory.manager
            || !Arc::ptr_eq(&attachment.cell, &self.cell)
            || attachment.snapshot.address_space_id != self.cell.id
        {
            let owner = HvfAddressSpace {
                memory: attachment.memory,
                cell: Arc::clone(&attachment.cell),
            };
            owner.finish_attachment_accounting(attachment)?;
            return Err(HvfMemoryError::WrongMemoryManager);
        }
        self.finish_attachment_accounting(attachment)
    }

    fn finish_attachment_accounting(
        &self,
        attachment: HvfVcpuRunAttachment,
    ) -> Result<(), HvfMemoryError> {
        let lease_state = attachment.lease_state.load(Ordering::Acquire);
        if lease_state == ATTACHMENT_ALLOCATED {
            attachment
                .lease_state
                .compare_exchange(
                    ATTACHMENT_ALLOCATED,
                    ATTACHMENT_CLOSED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| HvfMemoryError::AttachmentStale)?;
            return Ok(());
        }
        if !matches!(
            lease_state,
            ATTACHMENT_SUBMITTED | ATTACHMENT_SYNCHRONIZING | ATTACHMENT_RUNNING
        ) {
            return Err(HvfMemoryError::AttachmentStale);
        }
        let mut state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(in_flight) = state.in_flight.checked_sub(1) else {
            attachment.abandon();
            return Err(HvfMemoryError::IpaOwnership);
        };
        let Some(record) = state.participants.get_mut(&attachment.participant) else {
            attachment.abandon();
            return Err(HvfMemoryError::ParticipantStale(attachment.participant));
        };
        if record.lane_generation != attachment.lane_generation
            || record.in_flight != 1
            || !record
                .attachment_state
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(state, &attachment.lease_state))
        {
            attachment.abandon();
            return Err(HvfMemoryError::AttachmentStale);
        }
        record.in_flight = 0;
        record.attachment_state = None;
        state.in_flight = in_flight;
        attachment
            .lease_state
            .store(ATTACHMENT_CLOSED, Ordering::Release);
        Ok(())
    }

    fn validate_participant_capability(
        &self,
        participant: &HvfVcpuParticipant,
    ) -> Result<(), HvfMemoryError> {
        if participant.manager != self.memory.manager || participant.address_space != self.cell.id {
            return Err(HvfMemoryError::WrongMemoryManager);
        }
        if participant.capability_state.load(Ordering::Acquire) != PARTICIPANT_LIVE {
            return Err(HvfMemoryError::ParticipantStale(participant.id));
        }
        Ok(())
    }

    fn validate_attachment(&self, attachment: &HvfVcpuRunAttachment) -> Result<(), HvfMemoryError> {
        if attachment.memory.manager != self.memory.manager
            || !Arc::ptr_eq(&attachment.cell, &self.cell)
            || attachment.snapshot.address_space_id != self.cell.id
            || !matches!(
                attachment.lease_state.load(Ordering::Acquire),
                ATTACHMENT_ALLOCATED
                    | ATTACHMENT_SUBMITTED
                    | ATTACHMENT_SYNCHRONIZING
                    | ATTACHMENT_RUNNING
            )
        {
            return Err(HvfMemoryError::AttachmentStale);
        }
        if self.cell.attachment_abandoned.load(Ordering::Acquire) {
            return Err(HvfMemoryError::AttachmentAbandoned(self.cell.id));
        }
        Ok(())
    }

    pub fn claim(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        sharing: HvfSharing,
    ) -> Result<HvfMutation, HvfMemoryError> {
        self.claim_with(range, permissions, sharing, ClaimSource::Fresh)
    }

    fn claim_with(
        &self,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        sharing: HvfSharing,
        source: ClaimSource,
    ) -> Result<HvfMutation, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = self.cell.regime.validate_range(&range)?;
            permissions.validate()?;
            if permissions.contains(HvfGuestPermissions::EXECUTE) {
                return Err(HvfMemoryError::InitialExecute(range.clone()));
            }
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            self.require_mutable(&state)?;
            ensure_claim_gap(&state.claims, &range)?;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // The two limits checked here are the arena's own running counts
            // (exactly what `usage_locked` would report for them).
            let next_claimed_pages = admit_resource(
                "claimed pages",
                arenas.claimed_pages,
                page_count,
                self.memory.limits.max_claimed_pages,
            )?;
            let next_live_data_pages = admit_resource(
                "live data pages",
                arenas.live_data_pages,
                usize::from(permissions != HvfGuestPermissions::NONE) * page_count,
                self.memory.limits.max_live_data_pages,
            )?;
            state
                .claims
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim ownership"))?;
            let mut pages = HashMap::new();
            pages
                .try_reserve(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim pages"))?;
            let mut claimed_slots = Vec::new();
            claimed_slots
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim slots"))?;
            let mut updates = Vec::new();
            updates
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("claim stage-one updates"))?;
            let claim_id = take_counter(&mut arenas.next_claim)?;
            let (backing, base_offset, discard_backing) = match source {
                ClaimSource::Fresh => {
                    let backing = if permissions == HvfGuestPermissions::NONE {
                        None
                    } else {
                        Some(backings.allocate(page_count, sharing, 0)?)
                    };
                    (backing, 0usize, backing)
                }
                ClaimSource::Shared {
                    identity,
                    first_page,
                } => {
                    let available = backings.page_count(identity)?;
                    if first_page
                        .checked_add(page_count)
                        .is_none_or(|needed| needed > available)
                    {
                        return Err(HvfMemoryError::IpaOwnership);
                    }
                    (Some(identity), first_page * PAGE_SIZE, None)
                }
            };
            let mirrored = self.cell.mirrored;
            let mapped = backing.is_some() && permissions != HvfGuestPermissions::NONE;
            let preparation = (|| {
                let mut index = 0;
                while index < page_count {
                    let gva = range.start + index * PAGE_SIZE;
                    let backing_page = backing.map(|identity| BackingPage {
                        identity,
                        offset: base_offset + index * PAGE_SIZE,
                    });
                    // Pages whose host backing is contiguous map into the
                    // guest as one run with one stage-2 call.
                    let run = match backing_page {
                        Some(first) if mapped => {
                            contiguous_backing_run(&backings, first, page_count - index)?
                        }
                        _ => 1,
                    };
                    // Slots for the whole run first: they are tracked for
                    // cleanup as soon as they exist.
                    for offset in 0..run {
                        let slot = arenas.slots.claim(
                            gva + offset * PAGE_SIZE,
                            self.memory.limits.max_host_slots,
                            mirrored,
                        )?;
                        claimed_slots.push(slot);
                    }
                    let Some(first) = backing_page else {
                        updates.push((gva, 0));
                        pages.insert(
                            gva,
                            PageState {
                                permissions,
                                sharing,
                                backing: None,
                                mapping: None,
                                slot: claimed_slots[index],
                            },
                        );
                        index += 1;
                        continue;
                    };
                    // References for the whole run: a failed run map releases
                    // or quarantines every reference it was handed, so none
                    // is ever half-owned.
                    retain_backing_run(self.memory.vm, &mut backings, first, run)?;
                    if !mapped {
                        updates.push((gva, 0));
                        pages.insert(
                            gva,
                            PageState {
                                permissions,
                                sharing,
                                backing: Some(first),
                                mapping: None,
                                slot: claimed_slots[index],
                            },
                        );
                        index += 1;
                        continue;
                    }
                    let mappings = map_data_run(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        first,
                        run,
                        permissions,
                        true,
                    )?;
                    for (offset, mapping) in mappings.into_iter().enumerate() {
                        let page_gva = gva + offset * PAGE_SIZE;
                        updates.push((
                            page_gva,
                            permissions.stage_one_descriptor(mapping.ipa.start),
                        ));
                        pages.insert(
                            page_gva,
                            PageState {
                                permissions,
                                sharing,
                                backing: Some(mapping.backing),
                                mapping: Some(mapping),
                                slot: claimed_slots[index + offset],
                            },
                        );
                    }
                    index += run;
                }
                Ok::<(), HvfMemoryError>(())
            })();
            if let Err(error) = preparation {
                let cleanup = cleanup_claim_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    pages,
                    claimed_slots,
                    discard_backing,
                );
                return Err(HvfMemoryError::with_cleanup(error, cleanup));
            }
            let candidate = match build_candidate_root(
                self.memory.vm,
                &mut arenas,
                state.root,
                &updates,
                self.memory.limits.max_table_pages,
            ) {
                Ok(root) => root,
                Err(error) => {
                    let cleanup = cleanup_claim_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        pages,
                        claimed_slots,
                        discard_backing,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            // The permanent host view changes in the same transaction as the
            // root: installed here, rolled back on any later failure, and only
            // left in place once the root below is published.
            let mut mirror_plan = if mirrored {
                let plan = plan_mirror(
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    page_count,
                    pages
                        .values()
                        .map(|page| (page.slot, mirror_state_for(page))),
                );
                let plan = match plan {
                    Ok(mut plan) => {
                        match apply_mirror_plan(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            &mut plan,
                        ) {
                            Ok(()) => Ok(plan),
                            Err(error) => {
                                let cleanup = finish_mirror_plan(
                                    self.memory.vm,
                                    &mut arenas,
                                    &mut backings,
                                    &mut acknowledgements,
                                    &mut plan,
                                );
                                Err(HvfMemoryError::with_cleanup(error, cleanup))
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                match plan {
                    Ok(plan) => Some(plan),
                    Err(error) => {
                        let candidate_cleanup =
                            cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                        let preparation_cleanup = cleanup_claim_preparation(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            pages,
                            claimed_slots,
                            discard_backing,
                        );
                        return Err(HvfMemoryError::with_cleanup(
                            error,
                            candidate_cleanup.and(preparation_cleanup),
                        ));
                    }
                }
            } else {
                None
            };
            if arenas.take_failure(FailurePoint::BeforeRootPublish) {
                let cleanup = abort_claim_after_candidate(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    candidate,
                    pages,
                    claimed_slots,
                    discard_backing,
                    mirror_plan.as_mut(),
                );
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::InjectedFailure("before root publication"),
                    cleanup,
                ));
            }
            let metadata = (|| {
                let generation = arenas.next_root_generation()?;
                let tlbi_generation = arenas.next_tlbi_generation()?;
                let participants = self
                    .memory
                    .prepare_retirement_participants(&state, mirrored)?;
                let old_root = state.root;
                let old_table_pages = arenas.tables.release_count(old_root)?;
                operation.require_live()?;
                Ok::<_, HvfMemoryError>((
                    generation,
                    tlbi_generation,
                    participants,
                    old_root,
                    old_table_pages,
                ))
            })();
            let (generation, tlbi_generation, participants, old_root, old_table_pages) =
                match metadata {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        let cleanup = abort_claim_after_candidate(
                            self.memory,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            candidate,
                            pages,
                            claimed_slots,
                            discard_backing,
                            mirror_plan.as_mut(),
                        );
                        return Err(HvfMemoryError::with_cleanup(error, cleanup));
                    }
                };
            let reservation = match self.memory.reserve_retirement(
                &mut acknowledgements,
                0,
                0,
                0,
                old_table_pages,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    let cleanup = abort_claim_after_candidate(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        candidate,
                        pages,
                        claimed_slots,
                        discard_backing,
                        mirror_plan.as_mut(),
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            operation.mark_published()?;
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                generation,
                tlbi_generation,
                participants,
                old_root,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            );
            state.root = candidate;
            state.root_generation = generation;
            state.pending_tlbi_generation = tlbi_generation;
            let claim = ClaimRecord {
                id: claim_id,
                version: 1,
                range: range.clone(),
                pages,
            };
            state.claims.insert(range.start, claim);
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            if let Some(plan) = mirror_plan.as_mut() {
                plan.commit();
                finish_mirror_plan(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    plan,
                )?;
            }
            Ok(HvfMutation {
                claim: HvfClaim {
                    manager: self.memory.manager,
                    address_space: self.cell.id,
                    id: claim_id,
                    version: 1,
                    range,
                },
                root_generation: generation,
                executable_generation: state.executable_generation,
                retirement,
            })
        })
    }

    pub fn publish_executable(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
    ) -> Result<HvfPublicationTicket, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let record = self.memory.validate_claim(self, &state, claim)?;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure_aliases_inactive(record, &range, &arenas.slots)?;
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut published_pages = Vec::new();
            published_pages
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("publication ticket"))?;
            let mut published_any = false;
            macro_rules! publication_step {
                ($step:expr) => {
                    match $step {
                        Ok(value) => value,
                        Err(error) => {
                            let error: HvfMemoryError = error.into();
                            return Err(if published_any {
                                HvfMemoryError::after_publication("executable publication", error)
                            } else {
                                error
                            });
                        }
                    }
                };
            }
            for gva in page_addresses(&range) {
                let page =
                    publication_step!(record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale));
                let backing = publication_step!(
                    page.backing
                        .ok_or_else(|| { HvfMemoryError::PublicationRequired(range.clone()) })
                );
                let bytes = publication_step!(backings.page_range(backing));
                operation.mark_published()?;
                publication_step!(self.memory.vm.publish_executable_bytes(unsafe {
                    core::slice::from_raw_parts(bytes.start as *const u8, PAGE_SIZE)
                }));
                published_any = true;
                let epoch = publication_step!(backings.publish(backing));
                published_pages.push(PublishedPage {
                    backing,
                    write_epoch: epoch.write,
                    publication_epoch: epoch.publication,
                });
            }
            let _ = publication_step!(arenas.next_executable_generation());
            publication_step!(operation.require_live());
            Ok(HvfPublicationTicket {
                manager: self.memory.manager,
                address_space: self.cell.id,
                claim_id: record.id,
                claim_version: record.version,
                range,
                pages: published_pages,
            })
        })
    }

    pub fn protect(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        permissions: HvfGuestPermissions,
        publication: Option<&HvfPublicationTicket>,
    ) -> Result<HvfMutation, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            permissions.validate()?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.require_mutable(&state)?;
            let record = self.memory.validate_claim(self, &state, claim)?;
            let claim_start = record.range.start;
            let mut old_backings = HashMap::new();
            old_backings
                .try_reserve(record.pages.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("protect backing snapshot"))?;
            old_backings.extend(record.pages.iter().map(|(&gva, page)| (gva, page.backing)));
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure_aliases_inactive(record, &range, &arenas.slots)?;
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if permissions.contains(HvfGuestPermissions::EXECUTE) {
                validate_publication(
                    self.memory.manager,
                    self.cell.id,
                    record,
                    &range,
                    publication,
                    &backings,
                )?;
            }
            if permissions != HvfGuestPermissions::NONE {
                let target = StageTwoAuthority::for_permissions(permissions);
                for gva in page_addresses(&range) {
                    let old = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                    if let Some(backing) = old.backing {
                        // This page's own mirror writer retires with the
                        // transaction; only foreign host writers conflict.
                        let retiring_host_writer = self.cell.mirrored
                            && arenas
                                .slots
                                .records
                                .get(&old.slot)
                                .and_then(|slot| slot.mirror)
                                .is_some_and(|mirror| mirror.write && mirror.backing == backing);
                        backings.preflight_stage_two_replacement(
                            backing,
                            target,
                            old.mapping.as_ref().map(|mapping| mapping.authority),
                            retiring_host_writer,
                        )?;
                    }
                }
            }
            let old_live_pages = record
                .pages
                .iter()
                .filter(|(gva, page)| range.contains(gva) && page.mapping.is_some())
                .count();
            let new_live_pages = if permissions == HvfGuestPermissions::NONE {
                0
            } else {
                page_count
            };
            let next_live_data_pages = arenas
                .live_data_pages
                .checked_sub(old_live_pages)
                .and_then(|value| value.checked_add(new_live_pages))
                .ok_or(HvfMemoryError::IpaOwnership)?;
            admit_resource(
                "live data pages",
                0,
                next_live_data_pages,
                self.memory.limits.max_live_data_pages,
            )?;
            let mut replacements = HashMap::new();
            replacements
                .try_reserve(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("protect replacements"))?;
            let mut updates = Vec::new();
            updates
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("protect stage-one updates"))?;
            let preparation = (|| {
                for gva in page_addresses(&range) {
                    let old = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                    let (backing, release_backing_on_failure) = match old.backing {
                        Some(backing) => (Some(backing), false),
                        None if permissions == HvfGuestPermissions::NONE => (None, false),
                        None => {
                            let identity = backings.allocate(1, old.sharing, 0)?;
                            let backing = BackingPage {
                                identity,
                                offset: 0,
                            };
                            backings.retain(backing)?;
                            (Some(backing), true)
                        }
                    };
                    let mapping = match backing {
                        Some(backing) if permissions != HvfGuestPermissions::NONE => {
                            let mapping = map_data_page(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                backing,
                                HvfGuestPermissions::READ,
                                release_backing_on_failure,
                            )?;
                            updates
                                .push((gva, permissions.stage_one_descriptor(mapping.ipa.start)));
                            Some(mapping)
                        }
                        _ => {
                            updates.push((gva, 0));
                            None
                        }
                    };
                    replacements.insert(
                        gva,
                        PageState {
                            permissions,
                            sharing: old.sharing,
                            backing,
                            mapping,
                            slot: old.slot,
                        },
                    );
                }
                Ok::<(), HvfMemoryError>(())
            })();
            if let Err(error) = preparation {
                let cleanup = cleanup_replacements(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    &old_backings,
                    replacements,
                );
                return Err(HvfMemoryError::with_cleanup(error, cleanup));
            }
            let candidate = match build_candidate_root(
                self.memory.vm,
                &mut arenas,
                state.root,
                &updates,
                self.memory.limits.max_table_pages,
            ) {
                Ok(root) => root,
                Err(error) => {
                    let cleanup = cleanup_replacements(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        &old_backings,
                        replacements,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            if arenas.take_failure(FailurePoint::BeforeRootPublish) {
                let cleanup = cleanup_protect_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    candidate,
                    &old_backings,
                    replacements,
                );
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::InjectedFailure("before root publication"),
                    cleanup,
                ));
            }
            let metadata = (|| {
                let generation = arenas.next_root_generation()?;
                let tlbi_generation = arenas.next_tlbi_generation()?;
                let participants = self
                    .memory
                    .prepare_retirement_participants(&state, self.cell.mirrored)?;
                let executable_generation = if permissions.contains(HvfGuestPermissions::EXECUTE) {
                    arenas.next_executable_generation()?
                } else {
                    state.executable_generation
                };
                let old_root = state.root;
                let old_table_pages = arenas.tables.release_count(old_root)?;
                let new_version = record
                    .version
                    .checked_add(1)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                operation.require_live()?;
                Ok::<_, HvfMemoryError>((
                    generation,
                    tlbi_generation,
                    participants,
                    executable_generation,
                    old_root,
                    old_table_pages,
                    new_version,
                ))
            })();
            let (
                generation,
                tlbi_generation,
                participants,
                executable_generation,
                old_root,
                old_table_pages,
                new_version,
            ) = match metadata {
                Ok(metadata) => metadata,
                Err(error) => {
                    let cleanup = cleanup_protect_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        candidate,
                        &old_backings,
                        replacements,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            let mut retired_backings = Vec::new();
            retired_backings
                .try_reserve_exact(old_live_pages)
                .map_err(|_| HvfMemoryError::MetadataAllocation("retired backing plan"))?;
            retired_backings.extend(
                record
                    .pages
                    .iter()
                    .filter(|(gva, _)| range.contains(gva))
                    .filter_map(|(_, page)| page.mapping.as_ref())
                    .map(|mapping| mapping.backing),
            );
            let mut retained_backings = Vec::new();
            retained_backings
                .try_reserve_exact(retired_backings.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("retained backing plan"))?;
            for backing in retired_backings {
                if let Err(error) = backings.retain(backing) {
                    let cleanup = cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        None,
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
                retained_backings.push(backing);
            }
            let buffers = (|| {
                let mut retired_data = Vec::new();
                retired_data
                    .try_reserve_exact(old_live_pages)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("retired data ownership"))?;
                let mut old_pages = Vec::new();
                old_pages
                    .try_reserve_exact(page_count)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("replaced claim pages"))?;
                Ok::<_, HvfMemoryError>((retired_data, old_pages))
            })();
            let (mut retired_data, old_pages) = match buffers {
                Ok(buffers) => buffers,
                Err(error) => {
                    let cleanup = cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        None,
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            let reservation = match self.memory.reserve_retirement(
                &mut acknowledgements,
                old_live_pages,
                0,
                0,
                old_table_pages,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    let cleanup = cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        None,
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            let Some(claim_record) = state.claims.get_mut(&claim_start) else {
                let cleanup = cleanup_failed_protect(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    Some(reservation),
                    retained_backings,
                    candidate,
                    &old_backings,
                    replacements,
                );
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::ClaimStale,
                    cleanup,
                ));
            };
            // The mirror follows the replacement pages: planned here, applied
            // inside the authority transition (after the retiring stage-two
            // authority is dropped and before the new one is granted, so the
            // host writer and the executor never coexist), rolled back with
            // the authorities on failure.
            let mut mirror_plan = if self.cell.mirrored {
                match plan_mirror(
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    page_count,
                    page_addresses(&range).filter_map(|gva| {
                        replacements
                            .get(&gva)
                            .map(|page| (page.slot, mirror_state_for(page)))
                    }),
                ) {
                    Ok(plan) => Some(plan),
                    Err(error) => {
                        let cleanup = cleanup_failed_protect(
                            self.memory,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            Some(reservation),
                            retained_backings,
                            candidate,
                            &old_backings,
                            replacements,
                        );
                        return Err(HvfMemoryError::with_cleanup(error, cleanup));
                    }
                }
            } else {
                None
            };
            let inject_authority_failure = arenas.take_failure(FailurePoint::AuthorityTransition);
            operation.mark_published()?;
            if let Err(error) = apply_protect_authorities(
                self.memory.vm,
                &mut arenas,
                &mut backings,
                &mut acknowledgements,
                claim_record,
                &range,
                permissions,
                &mut replacements,
                mirror_plan.as_mut(),
                inject_authority_failure,
            ) {
                let mirror_cleanup = match mirror_plan.as_mut() {
                    Some(plan) => finish_mirror_plan(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        plan,
                    ),
                    None => Ok(()),
                };
                let preparation_cleanup = cleanup_failed_protect(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    Some(reservation),
                    retained_backings,
                    candidate,
                    &old_backings,
                    replacements,
                );
                return Err(HvfMemoryError::with_cleanup(
                    error,
                    mirror_cleanup.and(preparation_cleanup),
                ));
            }
            let old_pages = match swap_claim_pages(claim_record, &range, replacements, old_pages) {
                Ok(old_pages) => old_pages,
                Err(failure) => {
                    let (error, replacements) = *failure;
                    self.memory.vm.poison();
                    let plan_cleanup = match mirror_plan.as_mut() {
                        Some(plan) => {
                            let rollback = rollback_mirror_plan(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                plan,
                            );
                            let finish = finish_mirror_plan(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                plan,
                            );
                            rollback.and(finish)
                        }
                        None => Ok(()),
                    };
                    let preparation_cleanup = cleanup_failed_protect(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        Some(reservation),
                        retained_backings,
                        candidate,
                        &old_backings,
                        replacements,
                    );
                    return Err(HvfMemoryError::with_cleanup(
                        error,
                        plan_cleanup.and(preparation_cleanup),
                    ));
                }
            };
            for (_, mut old) in old_pages {
                if let Some(mapping) = old.mapping.take() {
                    retired_data.push(RetiredData {
                        mapping,
                        release_backing_reference: true,
                    });
                }
            }
            claim_record.version = new_version;
            let new_claim = HvfClaim {
                manager: self.memory.manager,
                address_space: self.cell.id,
                id: claim_record.id,
                version: claim_record.version,
                range: claim_record.range.clone(),
            };
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                generation,
                tlbi_generation,
                participants,
                old_root,
                retired_data,
                Vec::new(),
                Vec::new(),
            );
            state.root = candidate;
            state.root_generation = generation;
            state.executable_generation = executable_generation;
            state.pending_tlbi_generation = tlbi_generation;
            arenas.live_data_pages = next_live_data_pages;
            if let Some(plan) = mirror_plan.as_mut() {
                plan.commit();
                finish_mirror_plan(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    plan,
                )?;
            }
            Ok(HvfMutation {
                claim: new_claim,
                root_generation: generation,
                executable_generation,
                retirement,
            })
        })
    }

    pub fn unmap(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
    ) -> Result<HvfUnmapResult, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
            check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.require_mutable(&state)?;
            let record = self.memory.validate_claim(self, &state, claim)?;
            let claim_start = record.range.start;
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure_aliases_inactive(record, &range, &arenas.slots)?;
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let removed_live_pages = record
                .pages
                .iter()
                .filter(|(gva, page)| range.contains(gva) && page.mapping.is_some())
                .count();
            let removed_backing_pages = record
                .pages
                .iter()
                .filter(|(gva, page)| {
                    range.contains(gva) && page.mapping.is_none() && page.backing.is_some()
                })
                .count();
            let next_claimed_pages = arenas
                .claimed_pages
                .checked_sub(page_count)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let next_live_data_pages = arenas
                .live_data_pages
                .checked_sub(removed_live_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let mut updates = Vec::new();
            updates
                .try_reserve_exact(page_count)
                .map_err(|_| HvfMemoryError::MetadataAllocation("unmap stage-one updates"))?;
            updates.extend(page_addresses(&range).map(|gva| (gva, 0)));
            let candidate = build_candidate_root(
                self.memory.vm,
                &mut arenas,
                state.root,
                &updates,
                self.memory.limits.max_table_pages,
            )?;
            // Removed pages leave the host view in the same transaction: the
            // GVA is `PROT_NONE` again the moment the new root is published,
            // and re-aliased if anything below refuses the unmap.
            let mut mirror_plan = if self.cell.mirrored {
                let plan = plan_mirror(
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    page_count,
                    page_addresses(&range)
                        .filter_map(|gva| record.pages.get(&gva).map(|page| (page.slot, None))),
                );
                let plan = match plan {
                    Ok(mut plan) => match apply_mirror_plan(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        &mut plan,
                    ) {
                        Ok(()) => Ok(plan),
                        Err(error) => {
                            let cleanup = finish_mirror_plan(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                &mut plan,
                            );
                            Err(HvfMemoryError::with_cleanup(error, cleanup))
                        }
                    },
                    Err(error) => Err(error),
                };
                match plan {
                    Ok(plan) => Some(plan),
                    Err(error) => {
                        let cleanup =
                            cleanup_candidate_root(self.memory.vm, &mut arenas, candidate);
                        return Err(HvfMemoryError::with_cleanup(error, cleanup));
                    }
                }
            } else {
                None
            };
            if arenas.take_failure(FailurePoint::BeforeRootPublish) {
                let cleanup = abort_unmap_after_candidate(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    candidate,
                    mirror_plan.as_mut(),
                    None,
                );
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::InjectedFailure("before root publication"),
                    cleanup,
                ));
            }
            let survivor_ranges = match split_survivors(&record.range, &range) {
                Ok(ranges) => ranges,
                Err(error) => {
                    let cleanup = abort_unmap_after_candidate(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        candidate,
                        mirror_plan.as_mut(),
                        None,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            let metadata = (|| {
                let generation = arenas.next_root_generation()?;
                let tlbi_generation = arenas.next_tlbi_generation()?;
                let participants = self
                    .memory
                    .prepare_retirement_participants(&state, self.cell.mirrored)?;
                let old_root = state.root;
                let old_table_pages = arenas.tables.release_count(old_root)?;
                let mut survivors = Vec::new();
                survivors
                    .try_reserve_exact(survivor_ranges.len())
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap survivor plan"))?;
                for survivor_range in survivor_ranges {
                    survivors.push((survivor_range, take_counter(&mut arenas.next_claim)?));
                }
                operation.require_live()?;
                Ok::<_, HvfMemoryError>((
                    generation,
                    tlbi_generation,
                    participants,
                    old_root,
                    old_table_pages,
                    survivors,
                ))
            })();
            let (generation, tlbi_generation, participants, old_root, old_table_pages, survivors) =
                match metadata {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        let cleanup = abort_unmap_after_candidate(
                            self.memory,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            candidate,
                            mirror_plan.as_mut(),
                            None,
                        );
                        return Err(HvfMemoryError::with_cleanup(error, cleanup));
                    }
                };
            if survivors.iter().any(|(survivor, _)| {
                survivor.start != claim_start && state.claims.contains_key(&survivor.start)
            }) {
                let cleanup = abort_unmap_after_candidate(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    candidate,
                    mirror_plan.as_mut(),
                    None,
                );
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::AddressOverlap(range),
                    cleanup,
                ));
            }
            let reservation = match self.memory.reserve_retirement(
                &mut acknowledgements,
                removed_live_pages,
                page_count,
                removed_backing_pages,
                old_table_pages,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    let cleanup = abort_unmap_after_candidate(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        candidate,
                        mirror_plan.as_mut(),
                        None,
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };
            let buffers = (|| {
                state
                    .claims
                    .try_reserve(2)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap survivor ownership"))?;
                let mut retired_data = Vec::new();
                retired_data
                    .try_reserve_exact(removed_live_pages)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap retired data"))?;
                let mut retired_slots = Vec::new();
                retired_slots
                    .try_reserve_exact(page_count)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap retired slots"))?;
                let mut retired_backings = Vec::new();
                retired_backings
                    .try_reserve_exact(page_count - removed_live_pages)
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap retired backings"))?;
                let mut surviving_claims = Vec::new();
                surviving_claims
                    .try_reserve_exact(survivors.len())
                    .map_err(|_| HvfMemoryError::MetadataAllocation("unmap surviving claims"))?;
                Ok::<_, HvfMemoryError>((
                    retired_data,
                    retired_slots,
                    retired_backings,
                    surviving_claims,
                ))
            })();
            let (mut retired_data, mut retired_slots, mut retired_backings, mut surviving_claims) =
                match buffers {
                    Ok(buffers) => buffers,
                    Err(error) => {
                        let cleanup = abort_unmap_after_candidate(
                            self.memory,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            candidate,
                            mirror_plan.as_mut(),
                            Some(reservation),
                        );
                        return Err(HvfMemoryError::with_cleanup(error, cleanup));
                    }
                };
            operation.mark_published()?;
            let Some(record) = state.claims.remove(&claim_start) else {
                let cleanup = abort_unmap_after_candidate(
                    self.memory,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    candidate,
                    mirror_plan.as_mut(),
                    Some(reservation),
                );
                return Err(HvfMemoryError::with_cleanup(
                    HvfMemoryError::ClaimStale,
                    cleanup,
                ));
            };
            let transform = match split_claim_for_unmap(record, &range, &survivors) {
                Ok(transform) => transform,
                Err(failure) => {
                    let (error, record) = *failure;
                    state.claims.insert(record.range.start, record);
                    let cleanup = abort_unmap_after_candidate(
                        self.memory,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        candidate,
                        mirror_plan.as_mut(),
                        Some(reservation),
                    );
                    return Err(HvfMemoryError::with_cleanup(error, cleanup));
                }
            };

            for page in transform.removed_pages {
                retired_slots.push(page.slot);
                match (page.mapping, page.backing) {
                    (Some(mapping), _) => retired_data.push(RetiredData {
                        mapping,
                        release_backing_reference: true,
                    }),
                    (None, Some(backing)) => retired_backings.push(backing),
                    (None, None) => {}
                }
            }

            for survivor in transform.survivors {
                surviving_claims.push(HvfClaim {
                    manager: self.memory.manager,
                    address_space: self.cell.id,
                    id: survivor.id,
                    version: survivor.version,
                    range: survivor.range.clone(),
                });
                state
                    .claims
                    .extend(core::iter::once((survivor.range.start, survivor)));
            }
            let retirement = self.memory.commit_retirement(
                &mut acknowledgements,
                reservation,
                self.cell.id,
                generation,
                tlbi_generation,
                participants,
                old_root,
                retired_data,
                retired_slots,
                retired_backings,
            );
            state.root = candidate;
            state.root_generation = generation;
            state.pending_tlbi_generation = tlbi_generation;
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            if let Some(plan) = mirror_plan.as_mut() {
                plan.commit();
                finish_mirror_plan(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    plan,
                )?;
            }
            Ok(HvfUnmapResult {
                surviving_claims,
                root_generation: generation,
                executable_generation: state.executable_generation,
                retirement,
            })
        })
    }

    /// Exposes a temporary range-scoped alias for the duration of `access`.
    /// The callback must not block or re-enter the memory manager; no pointer
    /// derived from the slice may outlive the callback.
    pub fn read_alias_into<R>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        output: &mut HvfCallbackOutput<R>,
        access: impl FnOnce(&[u8]) -> R,
    ) -> Result<(), HvfMemoryError> {
        self.with_alias_into(claim, range, false, output, |bytes| access(bytes))
    }

    pub fn read_alias<R: Copy>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        access: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, HvfMemoryError> {
        let mut output = HvfCallbackOutput::new();
        self.read_alias_into(claim, range, &mut output, access)?;
        output.into_filled()
    }

    /// Exposes a temporary writable range-scoped alias for `access`, then
    /// restores exact `PROT_NONE` slot ownership before returning. The callback
    /// must not block, re-enter the manager, or retain a derived pointer.
    pub fn write_alias_into<R>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        output: &mut HvfCallbackOutput<R>,
        access: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<(), HvfMemoryError> {
        self.with_alias_into(claim, range, true, output, access)
    }

    pub fn write_alias<R: Copy>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        access: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, HvfMemoryError> {
        let mut output = HvfCallbackOutput::new();
        self.write_alias_into(claim, range, &mut output, access)?;
        output.into_filled()
    }

    fn with_alias_into<R>(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        write: bool,
        output: &mut HvfCallbackOutput<R>,
        access: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<(), HvfMemoryError> {
        let mut vacant = output.vacant()?;
        let alias_guard = AliasThreadGuard::enter(range.clone())?;
        let result = self.memory.vm.with_operation(|operation| {
            let lease = self.begin_alias(
                claim,
                range,
                write,
                || operation.mark_published(),
                || operation.require_live(),
            )?;
            // Custody is armed before arbitrary caller code can run. Neither a
            // callback panic nor a secondary poison/cleanup panic can strand
            // the installed aliases outside this guard.
            let mut teardown = AliasTeardownGuard::new(self.memory, lease);
            let callback = catch_unwind(AssertUnwindSafe(|| unsafe {
                let lease = teardown
                    .lease
                    .as_ref()
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                let bytes = core::slice::from_raw_parts_mut(
                    lease.range.start as *mut u8,
                    lease.range.len(),
                );
                vacant.fill(access(bytes));
                Ok::<(), HvfMemoryError>(())
            }));
            match callback {
                Err(payload) => {
                    if let Err(secondary) =
                        catch_unwind(AssertUnwindSafe(|| self.memory.vm.poison()))
                    {
                        dispose_secondary_panic(secondary);
                    }
                    match catch_unwind(AssertUnwindSafe(|| teardown.finish(true))) {
                        Ok(result) => drop(result),
                        Err(secondary) => dispose_secondary_panic(secondary),
                    }
                    resume_unwind(payload)
                }
                Ok(Err(error)) => {
                    let cleanup = teardown.finish(true);
                    Err(HvfMemoryError::with_cleanup(error, cleanup))
                }
                Ok(Ok(())) => {
                    teardown.finish(true)?;
                    operation.require_live()?;
                    Ok(())
                }
            }
        });
        drop(alias_guard);
        result
    }

    fn begin_alias(
        &self,
        claim: &HvfClaim,
        range: Range<usize>,
        write: bool,
        mark_published: impl Fn() -> Result<(), HvfError>,
        require_live: impl Fn() -> Result<(), HvfError>,
    ) -> Result<AliasLease, HvfMemoryError> {
        let page_count = validate_subrange(self.cell.regime, &claim.range, &range)?;
        check_mutation_bound(page_count, self.memory.limits.max_mutation_pages)?;
        let state = self
            .cell
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.require_mutable(&state)?;
        let record = self.memory.validate_claim(self, &state, claim)?;
        let mut arenas = self
            .memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut backings = self
            .memory
            .backings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut acknowledgements = self
            .memory
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let permissions = if write {
            HvfHostPermissions::READ_WRITE
        } else {
            HvfHostPermissions::READ
        };
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(page_count)
            .map_err(|_| HvfMemoryError::MetadataAllocation("alias lease"))?;
        for gva in page_addresses(&range) {
            let page = record.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
            if write && !page.permissions.contains(HvfGuestPermissions::WRITE) {
                return Err(HvfMemoryError::WriteWithoutRead);
            }
            if !write && !page.permissions.contains(HvfGuestPermissions::READ) {
                return Err(HvfMemoryError::SparseAlias(range.clone()));
            }
            let backing = page
                .backing
                .ok_or_else(|| HvfMemoryError::SparseAlias(range.clone()))?;
            let slot_record = arenas
                .slots
                .records
                .get(&page.slot)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if slot_record.mirrored != self.cell.mirrored
                || slot_record.mirror.is_some() != slot_record.mirror_backing_pin
            {
                return Err(HvfMemoryError::IpaOwnership);
            }
            if slot_record.active
                || slot_record.alias_quarantined
                || slot_record.release_quarantined
            {
                return Err(HvfMemoryError::AliasBusy(gva..gva + PAGE_SIZE));
            }
            if slot_record.slot.is_none() {
                return Err(HvfMemoryError::IpaOwnership);
            }
            if self.cell.mirrored {
                // The permanent alias must already expose exactly this
                // backing with at least the requested host access.
                let mirror = slot_record
                    .mirror
                    .ok_or_else(|| HvfMemoryError::SparseAlias(range.clone()))?;
                if mirror.backing != backing || (write && !mirror.write) {
                    return Err(HvfMemoryError::IpaOwnership);
                }
            } else {
                backings.preflight_reserve_host_alias(backing, write)?;
            }
            backings.page_storage(backing)?;
            pages.push(AliasLeasePage {
                slot: page.slot,
                backing,
                range: gva..gva + PAGE_SIZE,
                write,
                backing_pin: false,
                host_writer: false,
                exposure_installed: false,
            });
        }

        let write_epoch = if write {
            Some(arenas.next_write_epoch()?)
        } else {
            None
        };
        let reservation = if self.cell.mirrored {
            0
        } else {
            acknowledgements.reserve_alias_quarantine(page_count)?;
            page_count
        };
        let mut setup = AliasSetupGuard::new(
            self.memory.vm,
            &mut arenas,
            &mut backings,
            &mut acknowledgements,
            &mut pages,
            self.cell.mirrored,
            reservation,
        );
        if let Err(trigger) = mark_published() {
            let cleanup = setup.rollback();
            return Err(HvfMemoryError::with_cleanup(trigger.into(), cleanup));
        }
        setup.mark_published();

        if self.cell.mirrored {
            for index in 0..setup.pages.len() {
                if let Err(trigger) = setup.activate_mirror(index) {
                    let cleanup = setup.rollback();
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
        } else {
            for index in 0..setup.pages.len() {
                if let Err(trigger) = setup.reserve_authority(index) {
                    let cleanup = setup.rollback();
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
            for index in 0..setup.pages.len() {
                if let Err(trigger) = setup.install_alias(index, permissions) {
                    let cleanup = setup.rollback();
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
        }
        if let Err(trigger) = require_live() {
            let cleanup = setup.rollback();
            return Err(HvfMemoryError::with_cleanup(trigger.into(), cleanup));
        }
        setup.disarm();
        drop(setup);
        Ok(AliasLease {
            range,
            write_epoch,
            pages,
            mirrored: self.cell.mirrored,
        })
    }

    fn finish_alias(&self, lease: AliasLease) -> Result<(), HvfMemoryError> {
        let mut teardown = AliasTeardownGuard::new(self.memory, lease);
        teardown.finish(true)
    }

    pub fn software_walk(&self, gva: usize) -> Result<(u64, u64), HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            self.cell.regime.validate_address(gva)?;
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let result = arenas.tables.walk(state.root, gva)?;
            operation.require_live()?;
            Ok(result)
        })
    }

    pub fn report(&self) -> Result<HvfAddressSpaceReport, HvfMemoryError> {
        self.memory.vm.with_operation(|operation| {
            let state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mappings = coalesced_ledger(&state, &backings)?;
            let (monitor_leaf_ipa, _) = arenas.tables.walk(state.root, 0)?;
            let report = HvfAddressSpaceReport {
                id: self.cell.id,
                asid: self.cell.asid,
                regime: self.cell.regime,
                root_ipa: arenas.tables.ipa(state.root)?,
                root_generation: state.root_generation,
                executable_generation: state.executable_generation,
                pending_tlbi_generation: state.pending_tlbi_generation,
                participant_count: state.participants.len(),
                in_flight_attachments: state.in_flight,
                attachment_abandoned: self.cell.attachment_abandoned.load(Ordering::Acquire),
                stage_one_table_pages: arenas.tables.reachable_count(state.root)?,
                monitor_leaf_ipa,
                mappings,
                usage: self
                    .memory
                    .usage_locked(&arenas, &backings, &acknowledgements),
            };
            operation.require_live()?;
            Ok(report)
        })
    }

    pub fn vcpu_snapshot(&self) -> Result<HvfVcpuMemorySnapshot, HvfMemoryError> {
        let report = self.report()?;
        Ok(HvfVcpuMemorySnapshot {
            address_space_id: report.id,
            asid: report.asid,
            regime: report.regime,
            synchronization_ttbr0_el1: self.memory.synchronization_ttbr0_el1(),
            ttbr0_el1: (u64::from(report.asid.value) << 48) | report.root_ipa,
            root_generation: report.root_generation,
            executable_generation: report.executable_generation,
            pending_tlbi_generation: report.pending_tlbi_generation,
        })
    }

    pub fn acknowledge_retirement(
        &self,
        ticket: &mut HvfRetirementTicket,
    ) -> Result<HvfRetirementReport, HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            if ticket.manager != self.memory.manager || ticket.address_space != self.cell.id {
                return Err(HvfMemoryError::WrongMemoryManager);
            }
            if !ticket.live {
                return Err(HvfMemoryError::RetirementStale);
            }
            let _state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (next_retired_pages, next_retired_bytes, retired_root) = {
                let retired = acknowledgements
                    .retirements
                    .get(&ticket.id)
                    .filter(|retired| {
                        retired.address_space == ticket.address_space
                            && retired.generation == ticket.generation
                    })
                    .ok_or(HvfMemoryError::RetirementStale)?;
                let pending = retired
                    .required_participants
                    .difference(&retired.acknowledged_participants)
                    .count();
                if pending != 0 {
                    return Err(HvfMemoryError::RetirementParticipantsPending {
                        retirement: ticket.id,
                        pending,
                    });
                }
                (
                    acknowledgements
                        .retired_pages
                        .checked_sub(retired.charged_pages)
                        .ok_or(HvfMemoryError::RetirementStale)?,
                    acknowledgements
                        .retired_bytes
                        .checked_sub(retired.charged_bytes)
                        .ok_or(HvfMemoryError::RetirementStale)?,
                    retired.root,
                )
            };
            let table_records = match arenas.tables.release(retired_root) {
                Ok(records) => {
                    operation.mark_published()?;
                    records
                }
                Err(error @ HvfMemoryError::MetadataAllocation(_)) => return Err(error),
                Err(error) => {
                    operation.mark_published()?;
                    self.memory.vm.poison();
                    return Err(error);
                }
            };
            let retired = acknowledgements
                .remove_retirement(ticket.id)
                .ok_or(HvfMemoryError::RetirementStale)?;
            ticket.live = false;
            let mut released_data_pages = 0;
            let mut released_backing_references = 0;
            let released_table_pages = table_records.len();
            let mut first_error =
                cleanup_table_records(self.memory.vm, &mut arenas, table_records).err();
            for data in retired.data {
                let release_backing_reference = data.release_backing_reference;
                if let Err(error) = cleanup_data_mapping(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    data.mapping,
                    release_backing_reference,
                ) {
                    first_error.get_or_insert(error);
                } else {
                    released_data_pages += 1;
                    if release_backing_reference {
                        released_backing_references += 1;
                    }
                }
            }
            for backing in retired.backings {
                match backings.release(backing) {
                    Ok(_) => released_backing_references += 1,
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            let mut released_host_slots = 0;
            for slot in retired.slots {
                match arenas.slots.release(slot) {
                    Ok(true) => released_host_slots += 1,
                    Ok(false) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            if first_error.is_some() {
                self.memory.vm.poison();
            }
            acknowledgements.retired_pages = next_retired_pages;
            acknowledgements.retired_bytes = next_retired_bytes;
            if let Some(error) = first_error {
                return Err(error);
            }
            let quarantined_resources =
                HvfMemory::quarantined_resources_locked(&arenas, &backings, &acknowledgements);
            Ok(HvfRetirementReport {
                generation: ticket.generation,
                charged_pages: retired.charged_pages,
                charged_bytes: retired.charged_bytes,
                data_pages: retired.data_pages,
                slot_pages: retired.slot_pages,
                backing_pages: retired.backing_pages,
                table_pages: retired.table_pages,
                released_data_pages,
                released_table_pages,
                released_host_slots,
                released_backing_references,
                quarantined_resources,
            })
        })
    }

    pub fn fork_private(&self) -> Result<HvfForkResult, HvfMemoryError> {
        self.memory.vm.with_capability_operation(|operation| {
            if self.cell.mirrored {
                return Err(HvfMemoryError::MirrorForkUnsupported(self.cell.id));
            }
            let parent_state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !parent_state.live {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            self.require_quiescent(&parent_state)?;
            let mut spaces = self
                .memory
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut parent_claim_starts = Vec::new();
            parent_claim_starts
                .try_reserve_exact(parent_state.claims.len())
                .map_err(|_| HvfMemoryError::MetadataAllocation("fork claim order"))?;
            parent_claim_starts.extend(parent_state.claims.keys().copied());
            parent_claim_starts.sort_unstable();
            for start in &parent_claim_starts {
                let claim = parent_state
                    .claims
                    .get(start)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                ensure_aliases_inactive(claim, &claim.range, &arenas.slots)?;
            }
            admit_resource(
                "address spaces",
                arenas.address_spaces,
                1,
                self.memory.limits.max_address_spaces,
            )?;
            let child_claimed_pages =
                parent_claim_starts
                    .iter()
                    .try_fold(0usize, |count, start| {
                        count
                            .checked_add(
                                parent_state
                                    .claims
                                    .get(start)
                                    .ok_or(HvfMemoryError::ClaimStale)?
                                    .pages
                                    .len(),
                            )
                            .ok_or(HvfMemoryError::IpaOwnership)
                    })?;
            check_mutation_bound(child_claimed_pages, self.memory.limits.max_mutation_pages)?;
            let child_live_data_pages =
                parent_claim_starts
                    .iter()
                    .try_fold(0usize, |count, start| {
                        let claim = parent_state
                            .claims
                            .get(start)
                            .ok_or(HvfMemoryError::ClaimStale)?;
                        let live = page_addresses(&claim.range).try_fold(0usize, |live, gva| {
                            let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                            live.checked_add(usize::from(page.mapping.is_some()))
                                .ok_or(HvfMemoryError::IpaOwnership)
                        })?;
                        count.checked_add(live).ok_or(HvfMemoryError::IpaOwnership)
                    })?;
            let next_claimed_pages = admit_resource(
                "claimed pages",
                arenas.claimed_pages,
                child_claimed_pages,
                self.memory.limits.max_claimed_pages,
            )?;
            let next_live_data_pages = admit_resource(
                "live data pages",
                arenas.live_data_pages,
                child_live_data_pages,
                self.memory.limits.max_live_data_pages,
            )?;
            spaces
                .try_reserve(1)
                .map_err(|_| HvfMemoryError::MetadataAllocation("fork address space"))?;
            let id = HvfAddressSpaceId(take_counter(&mut arenas.next_address_space)?);
            if spaces.contains_key(&id) {
                return Err(HvfMemoryError::IpaOwnership);
            }
            let root_generation = arenas.next_root_generation()?;
            let pending_tlbi_generation = arenas.next_tlbi_generation()?;
            let asid = arenas.asids.allocate()?;
            let cell = Arc::new(AddressSpaceCell {
                id,
                asid,
                regime: self.cell.regime,
                mirrored: false,
                attachment_abandoned: AtomicBool::new(false),
                destroy_abandoned: AtomicBool::new(false),
                state: Mutex::new(AddressSpaceState {
                    live: false,
                    destroy_pending: false,
                    root: TableToken(0),
                    root_generation,
                    executable_generation: parent_state.executable_generation,
                    pending_tlbi_generation,
                    participants: HashMap::new(),
                    in_flight: 0,
                    claims: HashMap::new(),
                }),
                retirement_pump: Mutex::new(()),
            });
            let mut private_sources = Vec::new();
            if private_sources
                .try_reserve_exact(child_live_data_pages)
                .is_err()
            {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork private sources"));
            }
            for start in &parent_claim_starts {
                let claim = parent_state
                    .claims
                    .get(start)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                for gva in page_addresses(&claim.range) {
                    let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
                    if page.sharing == HvfSharing::Private
                        && let Some(backing) = page.backing
                    {
                        private_sources.push(backing.identity);
                    }
                }
            }
            private_sources.sort_unstable();
            private_sources.dedup();
            let mut private_copies = HashMap::new();
            if private_copies.try_reserve(private_sources.len()).is_err() {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork private copies"));
            }
            let mut child_claims = HashMap::new();
            if child_claims.try_reserve(parent_state.claims.len()).is_err() {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork child claims"));
            }
            let mut updates = Vec::new();
            if updates.try_reserve_exact(child_claimed_pages).is_err() {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation("fork stage-one updates"));
            }
            let mut claim_capabilities = Vec::new();
            if claim_capabilities
                .try_reserve_exact(parent_state.claims.len())
                .is_err()
            {
                arenas.asids.release(asid)?;
                return Err(HvfMemoryError::MetadataAllocation(
                    "fork claim capabilities",
                ));
            }
            if let Err(error) = operation.require_live() {
                arenas.asids.release(asid)?;
                return Err(error.into());
            }
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let initial_root = match create_monitor_root(
                self.memory.vm,
                &mut arenas,
                self.memory.limits.max_table_pages,
            ) {
                Ok(root) => root,
                Err(error) => {
                    arenas.asids.release(asid)?;
                    return Err(error);
                }
            };
            for &source in &private_sources {
                match backings.eager_copy_backing(source, 0) {
                    Ok(copy) => {
                        private_copies.insert(source, copy);
                    }
                    Err(error) => {
                        cleanup_fork_preparation(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            child_claims,
                            private_copies,
                            [initial_root],
                            Some(asid),
                        )?;
                        return Err(error);
                    }
                }
            }
            for start in parent_claim_starts {
                let parent_claim = parent_state
                    .claims
                    .get(&start)
                    .ok_or(HvfMemoryError::ClaimStale)?;
                let claim_id = match take_counter(&mut arenas.next_claim) {
                    Ok(id) => id,
                    Err(error) => {
                        cleanup_fork_preparation(
                            self.memory.vm,
                            &mut arenas,
                            &mut backings,
                            &mut acknowledgements,
                            child_claims,
                            private_copies,
                            [initial_root],
                            Some(asid),
                        )?;
                        return Err(error);
                    }
                };
                let mut pages = HashMap::new();
                if pages.try_reserve(parent_claim.pages.len()).is_err() {
                    cleanup_fork_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        child_claims,
                        private_copies,
                        [initial_root],
                        Some(asid),
                    )?;
                    return Err(HvfMemoryError::MetadataAllocation("fork claim pages"));
                }
                for gva in page_addresses(&parent_claim.range) {
                    let parent_page = parent_claim
                        .pages
                        .get(&gva)
                        .ok_or(HvfMemoryError::ClaimStale)?;
                    let page = match prepare_fork_page(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        parent_page,
                        &private_copies,
                    ) {
                        Ok(page) => page,
                        Err(error) => {
                            child_claims.insert(
                                parent_claim.range.start,
                                ClaimRecord {
                                    id: claim_id,
                                    version: 1,
                                    range: parent_claim.range.clone(),
                                    pages,
                                },
                            );
                            cleanup_fork_preparation(
                                self.memory.vm,
                                &mut arenas,
                                &mut backings,
                                &mut acknowledgements,
                                child_claims,
                                private_copies,
                                [initial_root],
                                Some(asid),
                            )?;
                            return Err(error);
                        }
                    };
                    let descriptor = page.mapping.as_ref().map_or(0, |mapping| {
                        page.permissions.stage_one_descriptor(mapping.ipa.start)
                    });
                    updates.push((gva, descriptor));
                    pages.insert(gva, page);
                }
                claim_capabilities.push(HvfClaim {
                    manager: self.memory.manager,
                    address_space: id,
                    id: claim_id,
                    version: 1,
                    range: parent_claim.range.clone(),
                });
                child_claims.insert(
                    parent_claim.range.start,
                    ClaimRecord {
                        id: claim_id,
                        version: 1,
                        range: parent_claim.range.clone(),
                        pages,
                    },
                );
            }
            let candidate = match build_candidate_root(
                self.memory.vm,
                &mut arenas,
                initial_root,
                &updates,
                self.memory.limits.max_table_pages,
            ) {
                Ok(candidate) => candidate,
                Err(error) => {
                    cleanup_fork_preparation(
                        self.memory.vm,
                        &mut arenas,
                        &mut backings,
                        &mut acknowledgements,
                        child_claims,
                        private_copies,
                        [initial_root],
                        Some(asid),
                    )?;
                    return Err(error);
                }
            };
            if let Err(error) = cleanup_candidate_root(self.memory.vm, &mut arenas, initial_root) {
                cleanup_fork_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    child_claims,
                    private_copies,
                    [candidate],
                    Some(asid),
                )?;
                return Err(error);
            }
            if let Err(error) = operation.require_live() {
                cleanup_fork_preparation(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    child_claims,
                    private_copies,
                    [candidate],
                    Some(asid),
                )?;
                return Err(error.into());
            }
            operation.mark_published()?;
            {
                let mut state = cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.live = true;
                state.root = candidate;
                state.claims = child_claims;
            }
            if let Some(previous) = spaces.insert(id, cell.clone()) {
                if spaces.insert(id, previous).is_none() {
                    self.memory.vm.poison();
                }
                let mut child_state = cell
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let child_claims = core::mem::take(&mut child_state.claims);
                let root_cleanup =
                    cleanup_candidate_root(self.memory.vm, &mut arenas, child_state.root);
                let claims_cleanup = cleanup_claim_records(
                    self.memory.vm,
                    &mut arenas,
                    &mut backings,
                    &mut acknowledgements,
                    child_claims,
                );
                let asid_cleanup = arenas.asids.release(asid);
                child_state.live = false;
                self.memory.vm.poison();
                root_cleanup.and(claims_cleanup).and(asid_cleanup)?;
                return Err(HvfMemoryError::IpaOwnership);
            }
            arenas.address_spaces += 1;
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            Ok(HvfForkResult {
                address_space: HvfAddressSpace {
                    memory: self.memory,
                    cell,
                },
                claims: claim_capabilities,
            })
        })
    }

    pub fn begin_destroy(&self) -> Result<HvfAddressSpaceDestroyTicket, HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            if self.cell.destroy_abandoned.load(Ordering::Acquire) {
                return Err(HvfMemoryError::DestroyTicketAbandoned(self.cell.id));
            }
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.live || state.destroy_pending {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            self.require_quiescent(&state)?;
            if !state.participants.is_empty() {
                return Err(HvfMemoryError::AddressSpaceBusy(self.cell.id));
            }
            let spaces = self
                .memory
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !spaces
                .get(&self.cell.id)
                .is_some_and(|cell| Arc::ptr_eq(cell, &self.cell))
            {
                return Err(HvfMemoryError::AddressSpaceDestroyed(self.cell.id));
            }
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for claim in state.claims.values() {
                ensure_aliases_inactive(claim, &claim.range, &arenas.slots)?;
            }
            let acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if acknowledgements
                .retirements
                .values()
                .any(|retired| retired.address_space == self.cell.id)
            {
                return Err(HvfMemoryError::RetirementsPending(self.cell.id));
            }
            let lifecycle = Arc::new(AtomicU8::new(DESTROY_TICKET_LIVE));
            let ticket = HvfAddressSpaceDestroyTicket {
                memory: self.memory,
                cell: Arc::clone(&self.cell),
                manager: self.memory.manager,
                address_space: self.cell.id,
                asid: self.cell.asid,
                root: state.root,
                root_generation: state.root_generation,
                lifecycle,
            };
            operation.mark_published()?;
            state.live = false;
            state.destroy_pending = true;
            Ok(ticket)
        })
    }

    /// Completes the destroy that `ticket` reserved.
    ///
    /// Every check before the root table is released (`arenas.tables.release`)
    /// fails without side effects and leaves the ticket live. Releasing the
    /// root table is the commit point: after it, any failure -- table or claim
    /// cleanup, ASID release, deregistration from `spaces` -- poisons the VM,
    /// and is reported once the remaining teardown has still been attempted.
    /// Poison is the durable committed-failure state; no separate
    /// `RecoveryPending` state exists, so a poisoned VM is the only record that
    /// a destroy committed and then failed to unwind fully.
    pub fn finish_destroy(
        &self,
        ticket: &mut HvfAddressSpaceDestroyTicket,
    ) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            if ticket.manager != self.memory.manager
                || !core::ptr::eq(ticket.memory, self.memory)
                || ticket.address_space != self.cell.id
                || ticket.asid != self.cell.asid
                || !Arc::ptr_eq(&ticket.cell, &self.cell)
                || ticket.lifecycle.load(Ordering::Acquire) != DESTROY_TICKET_LIVE
            {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            if self.cell.destroy_abandoned.load(Ordering::Acquire) {
                return Err(HvfMemoryError::DestroyTicketAbandoned(self.cell.id));
            }
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.live
                || !state.destroy_pending
                || state.root != ticket.root
                || state.root_generation != ticket.root_generation
                || state.in_flight != 0
                || !state.participants.is_empty()
            {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            let mut spaces = self
                .memory
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !spaces
                .get(&self.cell.id)
                .is_some_and(|cell| Arc::ptr_eq(cell, &self.cell))
            {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            let mut arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for claim in state.claims.values() {
                ensure_aliases_inactive(claim, &claim.range, &arenas.slots)?;
            }
            let mut backings = self
                .memory
                .backings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut acknowledgements = self
                .memory
                .acknowledgements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if acknowledgements
                .retirements
                .values()
                .any(|retired| retired.address_space == self.cell.id)
            {
                return Err(HvfMemoryError::RetirementsPending(self.cell.id));
            }
            let destroyed_claimed_pages = state
                .claims
                .values()
                .map(|claim| claim.pages.len())
                .sum::<usize>();
            let destroyed_live_data_pages = state
                .claims
                .values()
                .flat_map(|claim| claim.pages.values())
                .filter(|page| page.mapping.is_some())
                .count();
            let next_address_spaces = arenas
                .address_spaces
                .checked_sub(1)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let next_claimed_pages = arenas
                .claimed_pages
                .checked_sub(destroyed_claimed_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let next_live_data_pages = arenas
                .live_data_pages
                .checked_sub(destroyed_live_data_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            let table_records = match arenas.tables.release(state.root) {
                Ok(records) => {
                    operation.mark_published()?;
                    records
                }
                Err(error @ HvfMemoryError::MetadataAllocation(_)) => return Err(error),
                Err(error) => {
                    operation.mark_published()?;
                    self.memory.vm.poison();
                    return Err(error);
                }
            };
            let claims = core::mem::take(&mut state.claims);
            let mut first_error =
                cleanup_table_records(self.memory.vm, &mut arenas, table_records).err();
            if let Err(error) = cleanup_claim_records(
                self.memory.vm,
                &mut arenas,
                &mut backings,
                &mut acknowledgements,
                claims,
            ) {
                first_error.get_or_insert(error);
            }
            if let Err(error) = arenas.asids.release(self.cell.asid) {
                self.memory.vm.poison();
                first_error.get_or_insert(error);
            }
            if next_address_spaces == 0 {
                // No guest address space can reuse pooled guest table pages any
                // more: return them to the allocator and hypervisor. The
                // manager's permanent synchronization root remains pinned.
                let Arenas { tables, ipa, .. } = &mut *arenas;
                if let Err(error) = tables.drain_pool(self.memory.vm, ipa) {
                    first_error.get_or_insert(error);
                }
            }
            arenas.address_spaces = next_address_spaces;
            arenas.claimed_pages = next_claimed_pages;
            arenas.live_data_pages = next_live_data_pages;
            state.destroy_pending = false;
            if spaces.remove(&self.cell.id).is_none() {
                self.memory.vm.poison();
                first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            }
            ticket
                .lifecycle
                .store(DESTROY_TICKET_FINISHED, Ordering::Release);
            if let Some(error) = first_error {
                self.memory.vm.poison();
                Err(error)
            } else {
                Ok(())
            }
        })
    }

    pub fn rollback_destroy(
        &self,
        ticket: &mut HvfAddressSpaceDestroyTicket,
    ) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            if ticket.manager != self.memory.manager
                || ticket.lifecycle.load(Ordering::Acquire) != DESTROY_TICKET_LIVE
                || !Arc::ptr_eq(&ticket.cell, &self.cell)
            {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.live
                || !state.destroy_pending
                || state.root != ticket.root
                || state.root_generation != ticket.root_generation
            {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            operation.mark_published()?;
            state.destroy_pending = false;
            state.live = true;
            ticket
                .lifecycle
                .store(DESTROY_TICKET_FINISHED, Ordering::Release);
            Ok(())
        })
    }

    pub fn recover_abandoned_destroy(&self) -> Result<(), HvfMemoryError> {
        self.memory.vm.with_cleanup_operation(|operation| {
            if !self.cell.destroy_abandoned.load(Ordering::Acquire) {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            let mut state = self
                .cell
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.live || !state.destroy_pending {
                return Err(HvfMemoryError::DestroyTicketStale);
            }
            let spaces = self
                .memory
                .spaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let arenas = self
                .memory
                .arenas
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !spaces
                .get(&self.cell.id)
                .is_some_and(|cell| Arc::ptr_eq(cell, &self.cell))
                || arenas.tables.ipa(state.root).is_err()
            {
                self.memory.vm.poison();
                return Err(HvfMemoryError::DestroyTicketAbandoned(self.cell.id));
            }
            operation.mark_published()?;
            state.destroy_pending = false;
            state.live = true;
            self.cell.destroy_abandoned.store(false, Ordering::Release);
            Ok(())
        })
    }

    pub fn destroy(&self) -> Result<(), HvfMemoryError> {
        let mut ticket = self.begin_destroy()?;
        match self.finish_destroy(&mut ticket) {
            Ok(()) => Ok(()),
            Err(error) if ticket.lifecycle.load(Ordering::Acquire) == DESTROY_TICKET_LIVE => {
                self.rollback_destroy(&mut ticket)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}

static PROCESS_HVF_MEMORY_CREATE_RESIDUAL: Mutex<Option<HvfMemoryCreateResidual>> =
    Mutex::new(None);
static PROCESS_HVF_MEMORY: OnceLock<Result<HvfMemory, HvfMemoryError>> = OnceLock::new();

fn retry_hvf_memory_create_residual() -> Result<(), HvfMemoryError> {
    let vm = process_hvf_vm()?;
    vm.with_cleanup_operation(|operation| {
        let mut slot = PROCESS_HVF_MEMORY_CREATE_RESIDUAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(residual) = slot.as_mut() else {
            return Ok(());
        };
        if !core::ptr::eq(residual.vm, vm) {
            return Err(HvfMemoryError::WrongMemoryManager);
        }
        operation.mark_published()?;
        let mut first_error = None;
        let arenas = residual
            .arenas
            .as_mut()
            .ok_or(HvfMemoryError::IpaOwnership)?;

        if let Some(root) = residual.root {
            if arenas.tables.records.contains_key(&root)
                && !arenas
                    .tables
                    .abandoned_roots
                    .iter()
                    .any(|(token, _)| *token == root)
                && let Err(error) = cleanup_candidate_root(vm, arenas, root)
            {
                first_error.get_or_insert(error);
            }
            if !arenas.tables.records.contains_key(&root)
                || arenas
                    .tables
                    .abandoned_roots
                    .iter()
                    .any(|(token, _)| *token == root)
            {
                residual.root = None;
                residual.synchronization_root = None;
            }
        } else if residual.synchronization_root.is_some() {
            first_error.get_or_insert(HvfMemoryError::TableOwnership);
        }

        let mut root_index = 0;
        while root_index < arenas.tables.abandoned_roots.len() {
            let (root, count) = arenas.tables.abandoned_roots[root_index];
            match arenas.tables.release(root) {
                Ok(records) => {
                    if count > 1 {
                        arenas.tables.abandoned_roots[root_index].1 = count - 1;
                        root_index += 1;
                    } else {
                        arenas.tables.abandoned_roots.remove(root_index);
                    }
                    if let Err(error) = cleanup_table_records(vm, arenas, records) {
                        first_error.get_or_insert(error);
                    }
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                    root_index += 1;
                }
            }
        }
        if let Err(error) = arenas.tables.drain_pool(vm, &mut arenas.ipa) {
            first_error.get_or_insert(error);
        }

        let mut table_index = 0;
        while table_index < arenas.tables.quarantined.len() {
            if let Some(token) = arenas.tables.quarantined[table_index].sdk_token {
                if vm.mapping_token_has_residual(token)
                    && let Err(error) = vm.retry_quarantined_mapping(token)
                {
                    first_error.get_or_insert(error.into());
                    table_index += 1;
                    continue;
                }
                if vm.mapping_token_has_residual(token) {
                    table_index += 1;
                    continue;
                }
                arenas.tables.quarantined[table_index].sdk_token = None;
                arenas.tables.quarantined[table_index]
                    .bytes
                    .disarm_after_exact_absence();
            } else if arenas.tables.quarantined[table_index]
                .bytes
                .mapping_may_remain()
            {
                first_error.get_or_insert(HvfMemoryError::TableOwnership);
                table_index += 1;
                continue;
            }
            if let Some(ipa) = arenas.tables.quarantined[table_index].ipa {
                if let Err(error) = arenas.ipa.release(ipa) {
                    first_error.get_or_insert(error);
                    table_index += 1;
                    continue;
                }
                arenas.tables.quarantined[table_index].ipa = None;
            }
            arenas.tables.quarantined.swap_remove(table_index);
        }

        if let Some(mapping) = residual.monitor_mapping.as_ref() {
            residual.monitor_sdk_token = Some(mapping.token());
        }
        if let Some(mapping) = residual.monitor_mapping.take() {
            match mapping.unmap() {
                Ok(()) => residual.monitor_sdk_token = None,
                Err(error) => {
                    residual.monitor_sdk_token = error
                        .residual_mapping_token()
                        .or(residual.monitor_sdk_token);
                    first_error.get_or_insert(error.into());
                }
            }
        }
        if let Some(token) = residual.monitor_sdk_token {
            if vm.mapping_token_has_residual(token)
                && let Err(error) = vm.retry_quarantined_mapping(token)
            {
                first_error.get_or_insert(error.into());
            }
            if !vm.mapping_token_has_residual(token) {
                residual.monitor_sdk_token = None;
            }
        }

        let arenas_clear = arenas.tables.records.is_empty()
            && arenas.tables.quarantined.is_empty()
            && arenas.tables.abandoned_roots.is_empty()
            && arenas.tables.pool.is_empty()
            && arenas.ipa.owned_pages() == 0
            && arenas.slots.records.is_empty()
            && arenas.slots.by_gva.is_empty()
            && arenas.asids.owned() == 0
            && arenas.address_spaces == 0
            && arenas.claimed_pages == 0
            && arenas.live_data_pages == 0;
        let residual_clear = arenas_clear
            && residual.root.is_none()
            && residual.synchronization_root.is_none()
            && residual.monitor_mapping.is_none()
            && residual.monitor_sdk_token.is_none();
        if residual_clear {
            residual.arenas = None;
            *slot = None;
        }
        match first_error {
            Some(error) => Err(error),
            None if residual_clear => Ok(()),
            None => Err(HvfMemoryError::IpaOwnership),
        }
    })
}

pub(crate) fn process_hvf_memory() -> Result<&'static HvfMemory, HvfMemoryError> {
    retry_hvf_memory_create_residual()?;
    PROCESS_HVF_MEMORY
        .get_or_init(HvfMemory::create)
        .as_ref()
        .map_err(Clone::clone)
}

#[repr(align(16384))]
struct ProbeFailurePages([u8; 5 * PAGE_SIZE]);

static PROCESS_HVF_FAILURE_PROBE_PAGES: OnceLock<Box<ProbeFailurePages>> = OnceLock::new();

pub fn hvf_memory_probe() -> Result<HvfMemoryReport, HvfMemoryError> {
    with_hvf_memory_probe(HvfMemoryReport::clone)
}

pub fn with_hvf_memory_probe<T>(
    consume: impl FnOnce(&HvfMemoryReport) -> T,
) -> Result<T, HvfMemoryError> {
    let memory = process_hvf_memory()?;
    let report = memory
        .vm
        .with_zero_vcpu_operation(|_| hvf_memory_probe_inner(memory))?;
    Ok(consume(&report))
}

fn hvf_memory_probe_inner(memory: &'static HvfMemory) -> Result<HvfMemoryReport, HvfMemoryError> {
    let mut spaces = Vec::new();
    spaces
        .try_reserve_exact(4)
        .map_err(|_| HvfMemoryError::MetadataAllocation("memory probe spaces"))?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        hvf_memory_probe_tracked(memory, &mut spaces)
    }));
    let cleanup = finish_probe_spaces(memory, &spaces);
    match result {
        Ok(Ok(report)) => {
            cleanup?;
            Ok(report)
        }
        Ok(Err(error)) => Err(error),
        Err(payload) => {
            let _ = cleanup;
            resume_unwind(payload)
        }
    }
}

fn hvf_memory_probe_tracked(
    memory: &'static HvfMemory,
    spaces: &mut Vec<HvfAddressSpace>,
) -> Result<HvfMemoryReport, HvfMemoryError> {
    let host_backing = hvf_host_backing_probe()?;
    if !host_backing.coherent_alias_verified
        || !host_backing.private_copy_verified
        || !host_backing.reservation_restored
        || !host_backing.exact_preclaim_overlap_rejected
        || !host_backing.left_preclaim_overlap_rejected
        || !host_backing.right_preclaim_overlap_rejected
        || !host_backing.enclosing_preclaim_overlap_rejected
        || !host_backing.adjacent_preclaims_accepted
        || !host_backing.rejected_preclaims_had_no_effect
        || !host_backing.registering_resources_reported
        || !host_backing.concurrent_preclaim_single_winner
        || !host_backing.final_resources.is_empty()
    {
        return Err(HvfMemoryError::Witness(
            "host backing primitive witness failed",
        ));
    }
    let initial_vcpus = memory.vm.active_vcpu_count();
    let parent = memory.create_address_space()?;
    spaces.push(parent.clone());
    let competitor = memory.create_address_space()?;
    spaces.push(competitor.clone());
    let independent_roots_verified = parent.report()?.root_ipa != competitor.report()?.root_ipa;
    let monitor_walk = parent.software_walk(0)?;
    let monitor_leaf_verified = monitor_walk.0 == 0
        && monitor_walk.1 & DESCRIPTOR_UXN != 0
        && monitor_walk.1 & DESCRIPTOR_PXN == 0
        && monitor_walk.1 & (0b11 << 6) == DESCRIPTOR_AP_EL0_NONE_EL1_RO;
    let dynamic_tcr_ips_verified = parent.regime().ipa_bits
        == memory.vm.report().configured_ipa_bits
        && ((parent.regime().tcr_el1 >> 32) & 0b111)
            == u64::from(tcr_ips(parent.regime().ipa_bits));

    let base = 0x0000_0100_0000_0000usize;
    let exact_ipa_reuse_verified = ipa_allocator_reuse_witness()?;
    let all_resource_limits_verified = all_resource_limits_witness(memory.limits);
    let initial_execute_before = parent.report()?;
    let initial_execute_rejected = matches!(
        parent.claim(
            base + 0x0100_0000..base + 0x0100_0000 + PAGE_SIZE,
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::InitialExecute(_))
    ) && parent.report()? == initial_execute_before;

    let overlap_base = base + 0x0120_0000;
    let retirement_before = memory.usage();
    let mut overlap_anchor = parent.claim(
        overlap_base..overlap_base + 2 * PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    let retirement_pending = memory.usage();
    let overlap_generation = overlap_anchor.retirement.generation();
    let retirement_report = parent.acknowledge_retirement(&mut overlap_anchor.retirement)?;
    let retirement_after = memory.usage();
    let retirement_checkpoints_verified = retirement_pending.retired_generations
        == retirement_before.retired_generations + 1
        && retirement_pending.retired_pages
            == retirement_before.retired_pages + retirement_report.charged_pages
        && retirement_pending.retired_bytes
            == retirement_before.retired_bytes + retirement_report.charged_bytes
        && retirement_report.generation == overlap_generation
        && retirement_report.charged_pages == retirement_report.table_pages
        && retirement_report.charged_bytes == retirement_report.charged_pages * PAGE_SIZE
        && retirement_report.data_pages == 0
        && retirement_report.slot_pages == 0
        && retirement_report.backing_pages == 0
        && retirement_report.released_table_pages == retirement_report.table_pages
        && retirement_after.retired_generations == retirement_before.retired_generations
        && retirement_after.retired_pages == retirement_before.retired_pages
        && retirement_after.retired_bytes == retirement_before.retired_bytes;
    let overlap_snapshot = parent.report()?;
    let exact_overlap = matches!(
        parent.claim(
            overlap_base..overlap_base + 2 * PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let left_overlap = matches!(
        parent.claim(
            overlap_base - PAGE_SIZE..overlap_base + PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let right_overlap = matches!(
        parent.claim(
            overlap_base + PAGE_SIZE..overlap_base + 3 * PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let enclosing_overlap = matches!(
        parent.claim(
            overlap_base - PAGE_SIZE..overlap_base + 3 * PAGE_SIZE,
            HvfGuestPermissions::NONE,
            HvfSharing::Private,
        ),
        Err(HvfMemoryError::AddressOverlap(_))
    );
    let overlap_rejection_verified = exact_overlap
        && left_overlap
        && right_overlap
        && enclosing_overlap
        && parent.report()? == overlap_snapshot;
    let mut left_adjacent = parent.claim(
        overlap_base - PAGE_SIZE..overlap_base,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(&mut left_adjacent.retirement)?;
    let mut right_adjacent = parent.claim(
        overlap_base + 2 * PAGE_SIZE..overlap_base + 3 * PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(&mut right_adjacent.retirement)?;
    let adjacent_claims_verified = left_adjacent.claim.range.end
        == overlap_anchor.claim.range.start
        && overlap_anchor.claim.range.end == right_adjacent.claim.range.start;
    for claim in [
        left_adjacent.claim,
        overlap_anchor.claim,
        right_adjacent.claim,
    ] {
        let mut unmap = parent.unmap(&claim, claim.range())?;
        parent.acknowledge_retirement(&mut unmap.retirement)?;
    }

    let mut sparse = parent.claim(
        base..base + 3 * PAGE_SIZE,
        HvfGuestPermissions::NONE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(&mut sparse.retirement)?;
    let sparse_claim_verified = parent.report()?.mappings.len() == 1
        && parent.report()?.mappings[0].permissions == HvfGuestPermissions::NONE
        && parent.report()?.mappings[0].ipa.is_empty();
    let sparse_middle = base + PAGE_SIZE..base + 2 * PAGE_SIZE;
    let mut materialized = parent.protect(
        &sparse.claim,
        sparse_middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        None,
    )?;
    parent.acknowledge_retirement(&mut materialized.retirement)?;
    parent.write_alias(&materialized.claim, sparse_middle.clone(), |bytes| {
        bytes[..8].copy_from_slice(&0x5041_5245_4e54_3031u64.to_le_bytes());
    })?;
    let alias_reservation_verified =
        parent.read_alias(&materialized.claim, sparse_middle, |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? == 0x5041_5245_4e54_3031;
    let mut sparse_unmap = parent.unmap(&materialized.claim, materialized.claim.range())?;
    parent.acknowledge_retirement(&mut sparse_unmap.retirement)?;

    let private_base = base + 0x0200_0000;
    let mut private = parent.claim(
        private_base..private_base + 3 * PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Private,
    )?;
    parent.acknowledge_retirement(&mut private.retirement)?;
    let middle = private_base + PAGE_SIZE..private_base + 2 * PAGE_SIZE;
    let mut split = parent.protect(
        &private.claim,
        middle.clone(),
        HvfGuestPermissions::READ,
        None,
    )?;
    parent.acknowledge_retirement(&mut split.retirement)?;
    let split_verified = parent.report()?.mappings.len() == 3;
    let alias_preflight_verified = matches!(
        parent.write_alias(&split.claim, split.claim.range(), |_| {}),
        Err(HvfMemoryError::WriteWithoutRead)
    ) && memory.usage().active_alias_pages == 0;
    let mut coalesced = parent.protect(
        &split.claim,
        private_base..private_base + 3 * PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        None,
    )?;
    parent.acknowledge_retirement(&mut coalesced.retirement)?;
    let coalesce_verified = parent.report()?.mappings.len() == 1;
    parent.write_alias(&coalesced.claim, middle.clone(), |bytes| {
        bytes[..8].copy_from_slice(&0x5041_5245_4e54_3031u64.to_le_bytes());
    })?;
    let (alias_reentry_verified, alias_concurrency_verified) = alias_behavior_witness(
        &parent,
        &coalesced.claim,
        private_base..private_base + PAGE_SIZE,
        middle.clone(),
    )?;

    let mut competitor_mutation = competitor.claim(
        middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Private,
    )?;
    competitor.acknowledge_retirement(&mut competitor_mutation.retirement)?;
    competitor.write_alias(
        &competitor_mutation.claim,
        competitor_mutation.claim.range(),
        |bytes| {
            bytes[..8].copy_from_slice(&0x434f_4d50_4554_3031u64.to_le_bytes());
        },
    )?;
    let parent_value = parent.read_alias(&coalesced.claim, middle.clone(), |bytes| {
        u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
    })?;
    let competitor_value = competitor.read_alias(
        &competitor_mutation.claim,
        competitor_mutation.claim.range(),
        |bytes| u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
    )?;
    let parent_isolation_report = parent.report()?;
    let competitor_isolation_report = competitor.report()?;
    let parent_isolation_page = parent_isolation_report
        .mappings
        .iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("parent isolation page missing"))?;
    let competitor_isolation_page = competitor_isolation_report
        .mappings
        .iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("competitor isolation page missing"))?;
    let compact_nonidentity_ipa_verified = parent_isolation_page
        .ipa
        .iter()
        .all(|ipa| ipa.start != parent_isolation_page.gva.start as u64)
        && !parent_isolation_page.ipa.is_empty();
    let competitor_isolation_verified = parent_isolation_report.id
        != competitor_isolation_report.id
        && parent_isolation_report.asid != competitor_isolation_report.asid
        && parent_isolation_report.root_ipa != competitor_isolation_report.root_ipa
        && parent_isolation_page.backing_identity != competitor_isolation_page.backing_identity
        && parent_isolation_page.ipa != competitor_isolation_page.ipa
        && parent_isolation_page.write_epoch != competitor_isolation_page.write_epoch
        && parent_value == 0x5041_5245_4e54_3031
        && competitor_value == 0x434f_4d50_4554_3031;
    let active_physical_usage = memory.usage();
    let physical_accounting_verified = active_physical_usage.physical_backing_pages > 0
        && active_physical_usage.physical_backing_bytes
            == active_physical_usage.physical_backing_pages * PAGE_SIZE;
    let mut competitor_unmap = competitor.unmap(
        &competitor_mutation.claim,
        competitor_mutation.claim.range(),
    )?;
    competitor.acknowledge_retirement(&mut competitor_unmap.retirement)?;

    let boundary_anchor = 0x0000_0200_0000_0000usize;
    let boundary_bases = [
        boundary_anchor + 0x1000_0000,
        boundary_anchor + 0x0200_0000 - PAGE_SIZE,
        boundary_anchor + 0x0010_0000_0000 - PAGE_SIZE,
    ];
    let mut boundary_claims = Vec::new();
    let mut boundary_tickets = Vec::new();
    for start in boundary_bases {
        let mutation = parent.claim(
            start..start + 2 * PAGE_SIZE,
            HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
            HvfSharing::Private,
        )?;
        boundary_tickets.push(mutation.retirement);
        boundary_claims.push(mutation.claim);
    }
    for mut ticket in boundary_tickets {
        parent.acknowledge_retirement(&mut ticket)?;
    }
    let offsets = [0x123usize, PAGE_SIZE + 0x321];
    let nonzero_offsets_verified = boundary_claims.iter().all(|claim| {
        offsets.iter().all(|offset| {
            parent
                .software_walk(claim.range.start + offset)
                .is_ok_and(|(ipa, _)| {
                    ipa & (PAGE_SIZE as u64 - 1) == *offset as u64 & (PAGE_SIZE as u64 - 1)
                })
        })
    });
    let l0_boundary_verified = software_l0_boundary_witness(memory)?;
    let all_stage_one_boundaries_verified = nonzero_offsets_verified
        && stage_one_indexes(boundary_claims[0].range.start)[3]
            != stage_one_indexes(boundary_claims[0].range.start + PAGE_SIZE)[3]
        && stage_one_indexes(boundary_claims[1].range.start)[2]
            != stage_one_indexes(boundary_claims[1].range.start + PAGE_SIZE)[2]
        && stage_one_indexes(boundary_claims[2].range.start)[1]
            != stage_one_indexes(boundary_claims[2].range.start + PAGE_SIZE)[1]
        && l0_boundary_verified;

    let mut shared_mutation = parent.claim(
        base + 0x1000_0000..base + 0x1000_0000 + PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Shared,
    )?;
    parent.acknowledge_retirement(&mut shared_mutation.retirement)?;
    let mut parent_shared_claim = shared_mutation.claim;
    parent.write_alias(&parent_shared_claim, parent_shared_claim.range(), |bytes| {
        bytes[..8].copy_from_slice(&0x5348_4152_4544_3031u64.to_le_bytes());
    })?;
    let child = parent.fork_private()?;
    spaces.push(child.address_space.clone());
    let fork_capability_order_verified = child
        .claims
        .windows(2)
        .all(|claims| claims[0].range.start < claims[1].range.start);
    let child_report = child.report()?;
    let child_private = child_report
        .mappings
        .iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("child private claim missing"))?;
    let parent_private = parent
        .report()?
        .mappings
        .into_iter()
        .find(|entry| entry.gva.contains(&middle.start))
        .ok_or(HvfMemoryError::Witness("parent private claim missing"))?;
    let private_fork_verified = child_private.backing_identity != parent_private.backing_identity;
    let mut child_shared_claim = child
        .claims
        .iter()
        .find(|claim| claim.range == parent_shared_claim.range)
        .cloned()
        .ok_or(HvfMemoryError::Witness("child shared claim missing"))?;
    child.write_alias(&child_shared_claim, child_shared_claim.range(), |bytes| {
        bytes[..8].copy_from_slice(&0x5348_4152_4544_3032u64.to_le_bytes());
    })?;
    let shared_coherence_verified =
        parent.read_alias(&parent_shared_claim, parent_shared_claim.range(), |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? == 0x5348_4152_4544_3032;
    let mut child_readonly = child.protect(
        &child_shared_claim,
        child_shared_claim.range(),
        HvfGuestPermissions::READ,
        None,
    )?;
    let shared_publication =
        parent.publish_executable(&parent_shared_claim, parent_shared_claim.range())?;
    let wx_before = parent.report()?;
    let wx_usage_before = memory.usage();
    let parent_execute_blocked = matches!(
        parent.protect(
            &parent_shared_claim,
            parent_shared_claim.range(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            Some(&shared_publication),
        ),
        Err(HvfMemoryError::BackingWriteExecute { .. })
    );
    let wx_after = parent.report()?;
    let wx_rejection_had_no_effect = wx_after == wx_before && memory.usage() == wx_usage_before;
    let child_writer_retirement = child.acknowledge_retirement(&mut child_readonly.retirement)?;
    child_shared_claim = child_readonly.claim;
    let mut parent_shared_executable = parent.protect(
        &parent_shared_claim,
        parent_shared_claim.range(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        Some(&shared_publication),
    )?;
    let parent_writer_retirement =
        parent.acknowledge_retirement(&mut parent_shared_executable.retirement)?;
    parent_shared_claim = parent_shared_executable.claim;
    let parent_wx_report = parent.report()?;
    let child_wx_report = child.report()?;
    let parent_wx_page = parent_wx_report
        .mappings
        .iter()
        .find(|entry| entry.gva == parent_shared_claim.range)
        .ok_or(HvfMemoryError::Witness("parent shared executable missing"))?;
    let child_wx_page = child_wx_report
        .mappings
        .iter()
        .find(|entry| entry.gva == child_shared_claim.range)
        .ok_or(HvfMemoryError::Witness(
            "child shared read-only mapping missing",
        ))?;
    let global_wx_fork_retirement_verified = parent_execute_blocked
        && wx_rejection_had_no_effect
        && child_writer_retirement.data_pages == 1
        && child_writer_retirement.released_data_pages == 1
        && parent_writer_retirement.data_pages == 1
        && parent_writer_retirement.released_data_pages == 1
        && parent_wx_page.backing_identity == child_wx_page.backing_identity
        && parent_wx_page.permissions == HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE
        && child_wx_page.permissions == HvfGuestPermissions::READ
        && memory.usage().quarantined_resources == 0;
    let child_private_claim = child
        .claims
        .iter()
        .find(|claim| claim.range == coalesced.claim.range)
        .cloned()
        .ok_or(HvfMemoryError::Witness("child private claim missing"))?;
    child.write_alias(&child_private_claim, middle.clone(), |bytes| {
        bytes[..8].copy_from_slice(&0x4348_494c_4430_3031u64.to_le_bytes());
    })?;
    let private_fork_verified = private_fork_verified
        && parent.read_alias(&coalesced.claim, middle.clone(), |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? != 0x4348_494c_4430_3031;

    parent.write_alias(&coalesced.claim, middle.clone(), |bytes| {
        bytes[..4].copy_from_slice(&0xd503_201fu32.to_le_bytes());
    })?;
    let before_stale = parent.report()?.root_generation;
    let stale_publication_rejected = matches!(
        parent.protect(
            &coalesced.claim,
            middle.clone(),
            HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
            None,
        ),
        Err(HvfMemoryError::PublicationRequired(_))
    ) && parent.report()?.root_generation == before_stale;
    let publication = parent.publish_executable(&coalesced.claim, middle.clone())?;
    let authority_rollback_before = parent.report()?;
    let authority_rollback_sdk_before = memory.vm.residual_report()?;
    let authority_rollback_pool_before = memory.pooled_table_pages();
    memory.inject_failure(FailurePoint::AuthorityTransition);
    let authority_rollback_result = parent.protect(
        &coalesced.claim,
        middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        Some(&publication),
    );
    let authority_rollback_after = parent.report()?;
    let authority_rollback_sdk_after = memory.vm.residual_report()?;
    let authority_rollback_pool_after = memory.pooled_table_pages();
    let authority_rollback_error_verified =
        authority_rollback_result
            .as_ref()
            .err()
            .is_some_and(|error| {
                matches!(
                    error,
                    HvfMemoryError::PublishedMutation {
                        operation: "SDK operation completion",
                        trigger,
                    } if matches!(
                        trigger.as_ref(),
                        HvfMemoryError::InjectedFailure("during protect authority transition")
                    )
                )
            });
    let authority_rollback_state_verified = authority_rollback_after == authority_rollback_before
        && authority_rollback_sdk_after == authority_rollback_sdk_before
        && authority_rollback_pool_after == authority_rollback_pool_before
        && authority_rollback_after.usage.quarantined_resources == 0
        && !memory.vm.is_poisoned();
    let authority_rollback_verified =
        authority_rollback_error_verified && authority_rollback_state_verified;
    let retired_data_ipa = parent.software_walk(middle.start)?.0 & !(PAGE_SIZE as u64 - 1);
    let mut executable = parent.protect(
        &coalesced.claim,
        middle.clone(),
        HvfGuestPermissions::READ | HvfGuestPermissions::EXECUTE,
        Some(&publication),
    )?;
    let executable_retirement_id = executable.retirement.id;
    let executable_retirement_generation = executable.retirement.generation();
    let replacement_data_ipa = parent.software_walk(middle.start)?.0 & !(PAGE_SIZE as u64 - 1);
    let (retired_data_token, retired_ipa_owned_before_ack) = {
        let arenas = memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let acknowledgements = memory
            .acknowledgements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retired = acknowledgements
            .retirements
            .get(&executable_retirement_id)
            .ok_or(HvfMemoryError::RetirementStale)?;
        if retired.address_space != parent.id()
            || retired.generation != executable_retirement_generation
            || retired.data.len() != 1
        {
            return Err(HvfMemoryError::RetirementStale);
        }
        let token = retired.data[0].mapping.ipa;
        (
            token,
            token.start == retired_data_ipa && arenas.ipa.owns(token),
        )
    };
    let executable_retirement_report = parent.acknowledge_retirement(&mut executable.retirement)?;
    let retired_ipa_released_after_ack = {
        let arenas = memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !arenas.ipa.owns(retired_data_token)
    };
    let retired_ipa_held_until_ack_verified = retired_ipa_owned_before_ack
        && replacement_data_ipa != retired_data_ipa
        && executable_retirement_report.data_pages == 1
        && executable_retirement_report.released_data_pages == 1
        && retired_ipa_released_after_ack;
    let publication_epoch_verified = parent
        .report()?
        .mappings
        .iter()
        .find(|entry| entry.gva == middle)
        .is_some_and(|entry| entry.publication_epoch.0 == entry.write_epoch.0);

    let before_rollback = parent.report()?;
    let before_rollback_sdk = memory.vm.residual_report()?;
    let before_rollback_pool = memory.pooled_table_pages();
    memory.inject_failure(FailurePoint::BeforeRootPublish);
    let rollback_result = parent.protect(
        &executable.claim,
        middle.clone(),
        HvfGuestPermissions::READ,
        None,
    );
    let after_rollback = parent.report()?;
    let after_rollback_sdk = memory.vm.residual_report()?;
    let after_rollback_pool = memory.pooled_table_pages();
    let rollback_error_verified = rollback_result.as_ref().err().is_some_and(|error| {
        matches!(
            error,
            HvfMemoryError::PublishedMutation {
                operation: "SDK operation completion",
                trigger,
            } if matches!(
                trigger.as_ref(),
                HvfMemoryError::InjectedFailure("before root publication")
            )
        )
    });
    let rollback_state_verified = after_rollback == before_rollback
        && after_rollback_sdk == before_rollback_sdk
        && after_rollback_pool == before_rollback_pool
        && after_rollback.usage.quarantined_resources == 0
        && !memory.vm.is_poisoned();
    let rollback_verified =
        authority_rollback_verified && rollback_error_verified && rollback_state_verified;
    let oversized_start = 0x0000_a000_0000_0000usize;
    let oversized_pages = memory.limits.max_mutation_pages + 1;
    let oversized_end = oversized_start + oversized_pages * PAGE_SIZE;
    let all_resource_limits_verified = all_resource_limits_verified
        && matches!(
            parent.claim(
                oversized_start..oversized_end,
                HvfGuestPermissions::NONE,
                HvfSharing::Private,
            ),
            Err(HvfMemoryError::ResourceLimit {
                resource: "mutation pages",
                ..
            })
        );

    let mut unmap_exec = parent.unmap(&executable.claim, executable.claim.range())?;
    parent.acknowledge_retirement(&mut unmap_exec.retirement)?;
    let mut unmap_shared = parent.unmap(&parent_shared_claim, parent_shared_claim.range())?;
    parent.acknowledge_retirement(&mut unmap_shared.retirement)?;
    for claim in boundary_claims {
        let mut unmap = parent.unmap(&claim, claim.range())?;
        parent.acknowledge_retirement(&mut unmap.retirement)?;
    }
    for claim in &child.claims {
        let claim = if claim.range == child_shared_claim.range {
            &child_shared_claim
        } else {
            claim
        };
        let mut unmap = child.unmap(claim, claim.range())?;
        child.acknowledge_retirement(&mut unmap.retirement)?;
    }
    let retirement_verified = memory.usage().retired_generations == 0;
    let parent_asid = parent.asid();
    child.destroy()?;
    relinquish_probe_space(spaces, child.id())?;
    parent.destroy()?;
    relinquish_probe_space(spaces, parent.id())?;
    competitor.destroy()?;
    relinquish_probe_space(spaces, competitor.id())?;
    let recycled = memory.create_address_space()?;
    spaces.push(recycled.clone());
    let recycled_asid = recycled.asid();
    let asid_reuse_verified =
        recycled_asid.value == parent_asid.value && recycled_asid.epoch == parent_asid.epoch + 1;
    recycled.destroy()?;
    relinquish_probe_space(spaces, recycled.id())?;
    let final_usage = memory.usage();
    let physical_accounting_verified = physical_accounting_verified
        && final_usage.physical_backing_pages == 0
        && final_usage.physical_backing_bytes == 0;
    let allocator_conservation_verified = final_usage.table_pages
        == final_usage.synchronization_table_pages
        && final_usage.synchronization_table_pages == memory.synchronization_root.table_pages
        && final_usage.ipa_owned_pages == final_usage.synchronization_ipa_pages
        && final_usage.synchronization_ipa_pages == memory.synchronization_root.table_pages
        && final_usage.asids_owned == 0
        && final_usage.ipa_capacity_pages
            == memory
                .limits
                .max_live_data_pages
                .checked_add(memory.limits.max_table_pages)
                .ok_or(HvfMemoryError::IpaOwnership)?;
    let sdk_residuals = memory.vm.residual_report()?;
    let zero_vcpus_verified = initial_vcpus == 0
        && sdk_residuals.active_vcpus == 0
        && sdk_residuals.quarantined_vcpus == 0
        && sdk_residuals.zero_vcpu_operation_active
        && sdk_residuals.zero_vcpu_owned_by_current_thread;
    let report = HvfMemoryReport {
        configured_ipa_bits: memory.vm.report().configured_ipa_bits,
        monitor_ipa: memory.monitor_mapping.ipa(),
        regime: memory.regime,
        monitor_leaf_verified,
        dynamic_tcr_ips_verified,
        sparse_claim_verified,
        split_verified,
        coalesce_verified,
        all_stage_one_boundaries_verified,
        nonzero_offsets_verified,
        compact_nonidentity_ipa_verified,
        exact_ipa_reuse_verified,
        retired_ipa_held_until_ack_verified,
        overlap_rejection_verified,
        adjacent_claims_verified,
        independent_roots_verified,
        competitor_isolation_verified,
        asid_reuse_verified,
        alias_reservation_verified,
        alias_preflight_verified,
        alias_reentry_verified,
        alias_concurrency_verified,
        private_fork_verified,
        fork_capability_order_verified,
        shared_coherence_verified,
        global_wx_fork_retirement_verified,
        initial_execute_rejected,
        publication_epoch_verified,
        stale_publication_rejected,
        all_resource_limits_verified,
        rollback_verified,
        retirement_verified,
        retirement_checkpoints_verified,
        physical_accounting_verified,
        allocator_conservation_verified,
        zero_vcpus_verified,
        final_usage,
        sdk_residuals,
        host_backing,
        vm_poisoned: memory.vm.is_poisoned(),
    };
    if !report.monitor_leaf_verified
        || !report.dynamic_tcr_ips_verified
        || !report.sparse_claim_verified
        || !report.split_verified
        || !report.coalesce_verified
        || !report.all_stage_one_boundaries_verified
        || !report.nonzero_offsets_verified
        || !report.compact_nonidentity_ipa_verified
        || !report.exact_ipa_reuse_verified
        || !report.retired_ipa_held_until_ack_verified
        || !report.overlap_rejection_verified
        || !report.adjacent_claims_verified
        || !report.independent_roots_verified
        || !report.competitor_isolation_verified
        || !report.asid_reuse_verified
        || !report.alias_reservation_verified
        || !report.alias_preflight_verified
        || !report.alias_reentry_verified
        || !report.alias_concurrency_verified
        || !report.private_fork_verified
        || !report.fork_capability_order_verified
        || !report.shared_coherence_verified
        || !report.global_wx_fork_retirement_verified
        || !report.initial_execute_rejected
        || !report.publication_epoch_verified
        || !report.stale_publication_rejected
        || !report.all_resource_limits_verified
        || !report.rollback_verified
        || !report.retirement_verified
        || !report.retirement_checkpoints_verified
        || !report.physical_accounting_verified
        || !report.allocator_conservation_verified
        || !report.zero_vcpus_verified
        || !memory.usage_is_manager_baseline(&report.final_usage)
        || !memory.sdk_is_manager_baseline(&report.sdk_residuals)
        || !report.sdk_residuals.zero_vcpu_operation_active
        || !report.sdk_residuals.zero_vcpu_owned_by_current_thread
        || report.vm_poisoned
    {
        return Err(HvfMemoryError::WitnessReport(Box::new(report)));
    }
    Ok(report)
}

pub fn hvf_memory_failure_probe() -> Result<HvfMemoryFailureReport, HvfMemoryError> {
    with_hvf_memory_failure_probe(HvfMemoryFailureReport::clone)
}

pub fn with_hvf_memory_failure_probe<T>(
    consume: impl FnOnce(&HvfMemoryFailureReport) -> T,
) -> Result<T, HvfMemoryError> {
    let memory = process_hvf_memory()?;
    let mut staged_report = None;
    let completion = memory.vm.with_zero_vcpu_operation(|_| {
        let report = hvf_memory_failure_probe_inner(memory)?;
        staged_report = Some(report);
        Ok::<(), HvfMemoryError>(())
    });
    match completion {
        Ok(()) if memory.vm.is_terminally_poisoned() => {}
        Ok(()) => {
            return Err(HvfMemoryError::Witness(
                "failure probe operation completed before terminal poison",
            ));
        }
        Err(error) => return Err(error),
    }
    let mut report = staged_report.ok_or(HvfMemoryError::Witness(
        "failure probe report was not staged before poison completion",
    ))?;
    report.final_usage = memory.usage();
    report.sdk_residuals = memory.vm.residual_report()?;
    report.zero_vcpus_verified = report.zero_vcpus_verified
        && report.sdk_residuals.active_vcpus == 0
        && report.sdk_residuals.quarantined_vcpus == 0
        && !report.sdk_residuals.zero_vcpu_operation_active
        && !report.sdk_residuals.zero_vcpu_owned_by_current_thread;
    report.vm_poisoned = memory.vm.is_terminally_poisoned();
    validate_memory_failure_report(memory, &report)?;
    Ok(consume(&report))
}

/// Process-terminal witness for alias callback unwind precedence. It injects a
/// restore failure behind a callback panic, proves the original callback payload
/// survives, then restores the quarantined alias through cleanup admission and
/// tears the address space down after poison.
impl HvfMemory {
    pub fn alias_panic_failure_probe() -> Result<HvfAliasPanicFailureReport, HvfMemoryError> {
        struct AliasCallbackPanic;

        let memory = process_hvf_memory()?;
        let mut spaces = Vec::new();
        spaces
            .try_reserve_exact(1)
            .map_err(|_| HvfMemoryError::MetadataAllocation("alias panic probe spaces"))?;
        let setup = memory.vm.with_zero_vcpu_operation(|_| {
            let space = memory.create_address_space()?;
            spaces.push(space.clone());
            let start = 0x0000_0600_0000_0000usize;
            let mut mutation = space.claim(
                start..start + PAGE_SIZE,
                HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
                HvfSharing::Private,
            )?;
            space.acknowledge_retirement(&mut mutation.retirement)?;
            Ok::<_, HvfMemoryError>((space, mutation.claim))
        });
        let (space, claim) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                finish_probe_spaces(memory, &spaces)?;
                return Err(error);
            }
        };

        memory.inject_failure(FailurePoint::AliasRestore);
        let callback = catch_unwind(AssertUnwindSafe(|| {
            let _ = space.write_alias(&claim, claim.range(), |bytes| {
                bytes[0] = 1;
                resume_unwind(Box::new(AliasCallbackPanic));
            });
        }));
        let original_payload_preserved = callback
            .as_ref()
            .err()
            .is_some_and(|payload| payload.is::<AliasCallbackPanic>());
        let usage_before_retry = memory.usage();
        let restore_failure_quarantined = usage_before_retry.active_alias_pages == 1
            && usage_before_retry.alias_quarantine_reservations == 0
            && usage_before_retry.quarantined_resources == 1
            && memory.vm.is_poisoned();
        let aliases_restored = memory.retry_quarantined_aliases();
        let usage_after_retry = memory.usage();
        let cleanup_retry_restored_alias = aliases_restored.is_ok_and(|restored| restored == 1)
            && usage_after_retry.active_alias_pages == 0
            && usage_after_retry.alias_quarantine_reservations == 0
            && usage_after_retry.quarantined_resources == 0;
        let post_poison_destroy_succeeded = space.destroy().is_ok();
        let final_usage = memory.usage();
        let sdk_residuals = memory.vm.residual_report()?;
        let report = HvfAliasPanicFailureReport {
            original_payload_preserved,
            restore_failure_quarantined,
            cleanup_retry_restored_alias,
            post_poison_destroy_succeeded,
            final_usage,
            sdk_residuals,
            vm_poisoned: memory.vm.is_poisoned(),
        };
        if !report.original_payload_preserved
            || !report.restore_failure_quarantined
            || !report.cleanup_retry_restored_alias
            || !report.post_poison_destroy_succeeded
            || !memory.usage_is_manager_baseline(&report.final_usage)
            || !memory.sdk_is_manager_baseline(&report.sdk_residuals)
            || !report.vm_poisoned
        {
            return Err(HvfMemoryError::AliasPanicFailureWitnessReport(Box::new(
                report,
            )));
        }
        Ok(report)
    }
}

pub fn hvf_alias_panic_failure_probe() -> Result<HvfAliasPanicFailureReport, HvfMemoryError> {
    HvfMemory::alias_panic_failure_probe()
}

fn hvf_memory_failure_probe_inner(
    memory: &'static HvfMemory,
) -> Result<HvfMemoryFailureReport, HvfMemoryError> {
    let mut spaces = Vec::new();
    spaces
        .try_reserve_exact(1)
        .map_err(|_| HvfMemoryError::MetadataAllocation("failure probe spaces"))?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        hvf_memory_failure_probe_tracked(memory, &mut spaces)
    }));
    let cleanup = finish_probe_spaces(memory, &spaces);
    match result {
        Ok(Ok(report)) => {
            cleanup?;
            Ok(report)
        }
        Ok(Err(error)) => Err(error),
        Err(payload) => {
            let _ = cleanup;
            resume_unwind(payload)
        }
    }
}

fn hvf_memory_failure_probe_tracked(
    memory: &'static HvfMemory,
    spaces: &mut Vec<HvfAddressSpace>,
) -> Result<HvfMemoryFailureReport, HvfMemoryError> {
    let initial_vcpus = memory.vm.active_vcpu_count();
    let space = memory.create_address_space()?;
    spaces.push(space.clone());
    let start = 0x0000_0300_0000_0000usize;
    let mut mutation = space.claim(
        start..start + PAGE_SIZE,
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        HvfSharing::Private,
    )?;
    space.acknowledge_retirement(&mut mutation.retirement)?;
    let before = space.report()?;
    let before_sdk = memory.vm.residual_report()?;
    let before_pool = memory.pooled_table_pages();
    memory.inject_failure(FailurePoint::BeforeRootPublish);
    let rollback_result = space.protect(
        &mutation.claim,
        mutation.claim.range(),
        HvfGuestPermissions::READ,
        None,
    );
    let after = space.report()?;
    let after_sdk = memory.vm.residual_report()?;
    let after_pool = memory.pooled_table_pages();
    let rollback_error_verified = rollback_result.as_ref().err().is_some_and(|error| {
        matches!(
            error,
            HvfMemoryError::PublishedMutation {
                operation: "SDK operation completion",
                trigger,
            } if matches!(
                trigger.as_ref(),
                HvfMemoryError::InjectedFailure("before root publication")
            )
        )
    });
    let expected_after_sdk = after_pool
        .checked_sub(before_pool)
        .and_then(|pooled_pages| {
            let pooled_bytes = pooled_pages.checked_mul(PAGE_SIZE)?;
            let mut expected = before_sdk.clone();
            expected.logical_mapping_tokens =
                expected.logical_mapping_tokens.checked_add(pooled_pages)?;
            expected.logical_mapping_fragments = expected
                .logical_mapping_fragments
                .checked_add(pooled_pages)?;
            expected.logical_mapping_pages =
                expected.logical_mapping_pages.checked_add(pooled_pages)?;
            expected.logical_mapping_bytes =
                expected.logical_mapping_bytes.checked_add(pooled_bytes)?;
            expected.known_present_fragments =
                expected.known_present_fragments.checked_add(pooled_pages)?;
            expected.known_present_pages =
                expected.known_present_pages.checked_add(pooled_pages)?;
            expected.known_present_bytes =
                expected.known_present_bytes.checked_add(pooled_bytes)?;
            Some(expected)
        });
    let rollback_state_verified = after == before
        && expected_after_sdk.as_ref() == Some(&after_sdk)
        && after.usage.quarantined_resources == 0
        && !memory.vm.is_poisoned();
    let rollback_preserved_root = rollback_error_verified && rollback_state_verified;

    let mut first = space.protect(
        &mutation.claim,
        mutation.claim.range(),
        HvfGuestPermissions::READ,
        None,
    )?;
    let mut second = space.protect(
        &first.claim,
        first.claim.range(),
        HvfGuestPermissions::READ | HvfGuestPermissions::WRITE,
        None,
    )?;
    memory.inject_failure(FailurePoint::AliasRestore);
    let mut non_copy_output = HvfCallbackOutput::new();
    let alias_restore_failure = space.write_alias_into(
        &second.claim,
        second.claim.range(),
        &mut non_copy_output,
        |bytes| {
            bytes[0] = 1;
            String::from("caller-owned callback output")
        },
    );
    let alias_restore_failure_observed = alias_restore_failure
        .as_ref()
        .err()
        .is_some_and(published_alias_restore)
        && non_copy_output
            .as_ref()
            .is_some_and(|value| value == "caller-owned callback output");

    memory.inject_failure(FailurePoint::DataUnmap);
    let data_unmap_failure_observed = space.acknowledge_retirement(&mut first.retirement).is_err();
    memory.inject_failure(FailurePoint::TableUnmap);
    let table_unmap_failure_observed = space
        .acknowledge_retirement(&mut second.retirement)
        .is_err();
    let quarantine_count_before_retry = memory.usage().quarantined_resources;
    let quarantine_retry = memory.retry_quarantined_resources()?;
    let final_quarantine_count = quarantine_retry.remaining.quarantined_resources;
    let post_poison_destroy_succeeded = if space.destroy().is_ok() {
        relinquish_probe_space(spaces, space.id())?;
        true
    } else {
        false
    };
    let final_usage = memory.usage();
    let sdk_residuals = memory.vm.residual_report()?;
    let zero_vcpus_verified = initial_vcpus == 0
        && sdk_residuals.active_vcpus == 0
        && sdk_residuals.quarantined_vcpus == 0
        && sdk_residuals.zero_vcpu_operation_active
        && sdk_residuals.zero_vcpu_owned_by_current_thread;
    let report = HvfMemoryFailureReport {
        rollback_preserved_root,
        alias_restore_failure_observed,
        data_unmap_failure_observed,
        table_unmap_failure_observed,
        quarantine_count_before_retry,
        quarantine_retry,
        final_quarantine_count,
        post_poison_destroy_succeeded,
        zero_vcpus_verified,
        final_usage,
        sdk_residuals,
        vm_poisoned: memory.vm.poison_requested(),
    };
    validate_staged_memory_failure_report(memory, &report)?;
    Ok(report)
}

fn validate_staged_memory_failure_report(
    memory: &HvfMemory,
    report: &HvfMemoryFailureReport,
) -> Result<(), HvfMemoryError> {
    if !report.rollback_preserved_root
        || !report.alias_restore_failure_observed
        || !report.data_unmap_failure_observed
        || !report.table_unmap_failure_observed
        || report.quarantine_count_before_retry != 3
        || report.quarantine_retry.aliases_restored != 1
        || report.quarantine_retry.data_pages_released != 1
        || report.quarantine_retry.table_pages_released != 1
        || report.final_quarantine_count != 0
        || !report.post_poison_destroy_succeeded
        || !report.zero_vcpus_verified
        || !memory.usage_is_manager_baseline(&report.final_usage)
        || !memory.sdk_is_manager_baseline(&report.sdk_residuals)
        || !report.sdk_residuals.zero_vcpu_operation_active
        || !report.sdk_residuals.zero_vcpu_owned_by_current_thread
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::FailureWitnessReport(Box::new(
            report.clone(),
        )));
    }
    Ok(())
}

fn validate_memory_failure_report(
    memory: &HvfMemory,
    report: &HvfMemoryFailureReport,
) -> Result<(), HvfMemoryError> {
    if !report.rollback_preserved_root
        || !report.alias_restore_failure_observed
        || !report.data_unmap_failure_observed
        || !report.table_unmap_failure_observed
        || report.quarantine_count_before_retry != 3
        || report.quarantine_retry.aliases_restored != 1
        || report.quarantine_retry.data_pages_released != 1
        || report.quarantine_retry.table_pages_released != 1
        || report.final_quarantine_count != 0
        || !report.post_poison_destroy_succeeded
        || !report.zero_vcpus_verified
        || !memory.usage_is_manager_baseline(&report.final_usage)
        || !memory.sdk_is_manager_baseline(&report.sdk_residuals)
        || report.sdk_residuals.zero_vcpu_operation_active
        || report.sdk_residuals.zero_vcpu_owned_by_current_thread
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::FailureWitnessReport(Box::new(
            report.clone(),
        )));
    }
    Ok(())
}

fn relinquish_probe_space(
    spaces: &mut Vec<HvfAddressSpace>,
    address_space: HvfAddressSpaceId,
) -> Result<(), HvfMemoryError> {
    let index = spaces
        .iter()
        .position(|space| space.id() == address_space)
        .ok_or(HvfMemoryError::Witness(
            "probe cleanup did not hold the destroyed address space",
        ))?;
    spaces.swap_remove(index);
    Ok(())
}

fn probe_space_is_owned(
    memory: &HvfMemory,
    space: &HvfAddressSpace,
) -> Result<bool, HvfMemoryError> {
    let spaces = memory
        .spaces
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match spaces.get(&space.id()) {
        Some(cell) if Arc::ptr_eq(cell, &space.cell) => Ok(true),
        Some(_) => Err(HvfMemoryError::Witness(
            "probe cleanup found an address-space identity collision",
        )),
        None => Ok(false),
    }
}

fn probe_alias_custody_is_clear(memory: &HvfMemory) -> bool {
    let arenas = memory
        .arenas
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let acknowledgements = memory
        .acknowledgements
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    acknowledgements.alias_quarantine.is_empty()
        && acknowledgements.alias_quarantine_reservations == 0
        && arenas.slots.tally.active == 0
}

fn retry_probe_quarantine(memory: &'static HvfMemory, first_error: &mut Option<HvfMemoryError>) {
    if let Err(error) = memory.retry_quarantined_aliases() {
        first_error.get_or_insert(error);
    }
    if memory.usage().quarantined_resources != 0
        && let Err(error) = memory.retry_quarantined_resources()
    {
        first_error.get_or_insert(error);
    }
}

fn finish_probe_spaces(
    memory: &'static HvfMemory,
    spaces: &[HvfAddressSpace],
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    retry_probe_quarantine(memory, &mut first_error);
    for space in spaces.iter().rev() {
        match probe_space_is_owned(memory, space) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        }
        if !probe_alias_custody_is_clear(memory) {
            first_error.get_or_insert(HvfMemoryError::Witness(
                "probe cleanup retained alias custody before retirement",
            ));
            continue;
        }

        let mut retirement_attempts = 0usize;
        let mut retirements_drained = false;
        loop {
            let Some(mut ticket) = memory.pending_retirement_ticket(space.id()) else {
                retirements_drained = true;
                break;
            };
            if retirement_attempts == memory.limits.max_retired_generations {
                first_error.get_or_insert(HvfMemoryError::ResourceLimit {
                    resource: "retirement cleanup attempts",
                    requested: retirement_attempts.saturating_add(1),
                    limit: memory.limits.max_retired_generations,
                });
                break;
            }
            retirement_attempts = retirement_attempts
                .checked_add(1)
                .ok_or(HvfMemoryError::RetirementStale)?;
            if let Err(error) = space.acknowledge_retirement(&mut ticket) {
                let retryable = !ticket.is_live();
                first_error.get_or_insert(error);
                if !retryable {
                    break;
                }
            }
        }
        if !retirements_drained {
            continue;
        }

        retry_probe_quarantine(memory, &mut first_error);
        if !probe_alias_custody_is_clear(memory) {
            first_error.get_or_insert(HvfMemoryError::Witness(
                "probe cleanup retained alias custody before destroy",
            ));
            continue;
        }
        if let Err(error) = space.destroy() {
            first_error.get_or_insert(error);
            match probe_space_is_owned(memory, space) {
                Ok(false) => {}
                Ok(true) => continue,
                Err(ownership) => {
                    first_error.get_or_insert(ownership);
                    continue;
                }
            }
        }
        retry_probe_quarantine(memory, &mut first_error);
    }
    retry_probe_quarantine(memory, &mut first_error);
    if !probe_alias_custody_is_clear(memory) {
        first_error.get_or_insert(HvfMemoryError::Witness("probe cleanup left alias custody"));
    }
    if memory.usage().quarantined_resources != 0 {
        first_error.get_or_insert(HvfMemoryError::Witness(
            "probe cleanup left quarantined resources",
        ));
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub fn hvf_poison_concurrency_probe() -> Result<HvfPoisonConcurrencyReport, HvfMemoryError> {
    let vm = process_hvf_vm()?;
    std::thread::scope(|scope| {
        let mut observations = None;
        let mut poisoner_slot = None;
        let operation_result = vm.with_operation(|_| {
            let contender = std::thread::Builder::new()
                .spawn_scoped(scope, || {
                    vm.with_operation_timeout(std::time::Duration::ZERO, |_| Ok::<_, HvfError>(()))
                })
                .map_err(|_| HvfMemoryError::Witness("failed to create operation worker"))?;
            let contender_timed_out_while_owner_live = matches!(
                contender
                    .join()
                    .map_err(|_| HvfMemoryError::Witness("operation worker panicked"))?,
                Err(HvfError::OperationWaitTimeout)
            );
            let poisoner = std::thread::Builder::new()
                .spawn_scoped(scope, || vm.poison())
                .map_err(|_| HvfMemoryError::Witness("failed to create poison worker"))?;
            vm.wait_for_poison_request()?;
            observations = Some((
                vm.poison_requested(),
                matches!(
                    vm.with_operation(|_| Ok::<_, HvfError>(())),
                    Err(HvfError::Poisoned)
                ),
                contender_timed_out_while_owner_live,
                !vm.is_poisoned(),
            ));
            poisoner_slot = Some(poisoner);
            Ok::<_, HvfMemoryError>(())
        });
        match operation_result {
            Err(HvfMemoryError::Hvf(HvfError::Poisoned)) => {}
            Err(error) => return Err(error),
            Ok(()) => {
                return Err(HvfMemoryError::Witness(
                    "poisoned owner operation unexpectedly succeeded",
                ));
            }
        }
        let (
            poison_requested_while_owner_live,
            normal_rejected_while_owner_live,
            contender_timed_out_while_owner_live,
            poison_waited_for_owner_release,
        ) = observations.ok_or(HvfMemoryError::Witness(
            "poison owner observations were not published",
        ))?;
        let poisoner = poisoner_slot.ok_or(HvfMemoryError::Witness(
            "poison worker handle was not published",
        ))?;
        poisoner
            .join()
            .map_err(|_| HvfMemoryError::Witness("poison worker panicked"))?;
        let cleanup_admitted_after_poison =
            vm.with_cleanup_operation(|_| Ok::<_, HvfError>(())).is_ok();
        let report = HvfPoisonConcurrencyReport {
            poison_requested_while_owner_live,
            normal_rejected_while_owner_live,
            contender_timed_out_while_owner_live,
            poison_waited_for_owner_release,
            cleanup_admitted_after_poison,
            vm_poisoned: vm.is_poisoned(),
        };
        if !report.poison_requested_while_owner_live
            || !report.normal_rejected_while_owner_live
            || !report.contender_timed_out_while_owner_live
            || !report.poison_waited_for_owner_release
            || !report.cleanup_admitted_after_poison
            || !report.vm_poisoned
        {
            return Err(HvfMemoryError::Witness(
                "poison serialization witness failed",
            ));
        }
        Ok(report)
    })
}

pub fn hvf_register_failure_probe() -> Result<HvfRegisterFailureReport, HvfMemoryError> {
    let vm = process_hvf_vm()?;
    let mut vcpu = vm.create_vcpu()?;
    let vcpu_registered_to_current_thread =
        vm.active_vcpu_count() == 1 && vm.active_vcpu_count_for_current_thread() == 1;
    let expected_ttbr0 = PAGE_SIZE as u64;
    let expected_tcr = tcr_el1(vm.report().configured_ipa_bits);
    let programmed_stage_one =
        vcpu.program_stage_one(expected_ttbr0, expected_tcr, MAIR_ATTR0_NORMAL_WB)?;
    let stage_one_programming_verified = programmed_stage_one.ttbr0_el1 == expected_ttbr0
        && programmed_stage_one.tcr_el1 == expected_tcr
        && programmed_stage_one.mair_el1 == MAIR_ATTR0_NORMAL_WB;
    let result =
        vcpu.induce_stage_one_readback_mismatch(expected_ttbr0, expected_tcr, MAIR_ATTR0_NORMAL_WB);
    let mismatch_rejected = result.as_ref().err().is_some_and(stage_one_mismatch_error);
    drop(vcpu);
    let cleanup_retry_released_vcpus = vm.retry_quarantined_vcpus_for_current_thread()?;
    let active_vcpu_count = vm.active_vcpu_count();
    let quarantined_vcpu_count = vm.quarantined_vcpu_count();
    let report = HvfRegisterFailureReport {
        programmed_stage_one,
        stage_one_programming_verified,
        mismatch_rejected,
        vcpu_registered_to_current_thread,
        vcpu_destroyed_without_residual: active_vcpu_count == 0 && quarantined_vcpu_count == 0,
        cleanup_retry_released_vcpus,
        active_vcpu_count,
        quarantined_vcpu_count,
        vm_poisoned: vm.is_poisoned(),
    };
    if !report.stage_one_programming_verified
        || !report.mismatch_rejected
        || !report.vcpu_registered_to_current_thread
        || !report.vcpu_destroyed_without_residual
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::Witness("register failure witness failed"));
    }
    Ok(report)
}

pub fn hvf_unmap_failure_probe() -> Result<HvfUnmapFailureReport, HvfMemoryError> {
    let process_lifetime_pages = PROCESS_HVF_FAILURE_PROBE_PAGES
        // SAFETY: `ProbeFailurePages` is a plain byte array, for which all-zero bytes are a valid
        // value. Zeroing it on the heap avoids first building the 80 KiB array on the stack.
        .get_or_init(|| unsafe { Box::<ProbeFailurePages>::new_zeroed().assume_init() });
    let vm = process_hvf_vm()?;
    let exact_known_mappings = |report: &HvfSdkResidualReport, mapping_count: usize| {
        let Some(mapping_bytes) = mapping_count.checked_mul(PAGE_SIZE) else {
            return false;
        };
        report.logical_mapping_tokens == mapping_count
            && report.logical_mapping_fragments == mapping_count
            && report.logical_mapping_pages == mapping_count
            && report.logical_mapping_bytes == mapping_bytes
            && report.known_present_fragments == mapping_count
            && report.known_present_pages == mapping_count
            && report.known_present_bytes == mapping_bytes
            && report.unknown_fragments == 0
            && report.unknown_pages == 0
            && report.unknown_bytes == 0
            && report.permissions_unknown_mapping_tokens == 0
            && report.logical_vcpu_tokens == 0
            && report.active_vcpus == 0
            && report.quarantined_vcpus == 0
            && !report.zero_vcpu_operation_active
            && !report.zero_vcpu_owned_by_current_thread
            && !report.zero_vcpu_operation_active
            && !report.zero_vcpu_owned_by_current_thread
    };
    let start = process_lifetime_pages.0.as_ptr() as usize;
    let explicit = unsafe {
        vm.map_host_range(
            start..start + PAGE_SIZE,
            PAGE_SIZE as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let cleanup = unsafe {
        vm.map_host_range(
            start + PAGE_SIZE..start + 2 * PAGE_SIZE,
            (2 * PAGE_SIZE) as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let mut protect = unsafe {
        vm.map_host_range(
            start + 2 * PAGE_SIZE..start + 3 * PAGE_SIZE,
            (3 * PAGE_SIZE) as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let unmap = unsafe {
        vm.map_host_range(
            start + 3 * PAGE_SIZE..start + 4 * PAGE_SIZE,
            (4 * PAGE_SIZE) as u64,
            HvfMapPermissions::READ,
        )
    }?;
    let completion = vm.with_capability_operation(move |_| {
        let capability = unsafe {
            vm.map_host_range(
                start + 4 * PAGE_SIZE..start + 5 * PAGE_SIZE,
                (5 * PAGE_SIZE) as u64,
                HvfMapPermissions::READ,
            )
        }?;
        let clean_residuals = vm.residual_report()?;
        let protect_failure_observed = protect
            .induce_protect_failure()
            .as_ref()
            .err()
            .is_some_and(|error| published_hvf_call(error, "hv_vm_protect"));
        let protect_residuals = vm.residual_report()?;
        let mut expected_protect_residuals = clean_residuals.clone();
        expected_protect_residuals.permissions_unknown_mapping_tokens = 1;
        let protect_failure_quarantined = exact_known_mappings(&clean_residuals, 5)
            && protect_residuals == expected_protect_residuals;
        let quarantined_handle_rejected_before_retry = matches!(
            protect.protect(HvfMapPermissions::READ),
            Err(HvfError::MappingNotLive)
        );
        let unmap_failure_observed = unmap
            .induce_unmap_failure()
            .as_ref()
            .err()
            .is_some_and(|error| published_hvf_call(error, "hv_vm_unmap"));
        let sdk_residuals_before_retry = vm.residual_report()?;
        let mut expected_unmap_residuals = clean_residuals.clone();
        expected_unmap_residuals.known_present_fragments = 4;
        expected_unmap_residuals.known_present_pages = 4;
        expected_unmap_residuals.known_present_bytes = 4 * PAGE_SIZE;
        expected_unmap_residuals.unknown_fragments = 1;
        expected_unmap_residuals.unknown_pages = 1;
        expected_unmap_residuals.unknown_bytes = PAGE_SIZE;
        expected_unmap_residuals.permissions_unknown_mapping_tokens = 1;
        let unmap_failure_quarantined = sdk_residuals_before_retry == expected_unmap_residuals;
        let cleanup_retry_cleared_fragments = vm.retry_quarantined_mappings()?;
        let sdk_residuals_after_retry = vm.residual_report()?;
        let cleanup_replay_cleared_fragments = vm.retry_quarantined_mappings()?;
        let sdk_residuals_after_replay = vm.residual_report()?;
        let quarantined_handle_rejected_after_replay =
            matches!(protect.unmap(), Err(HvfError::MappingNotLive));
        let quarantined_handle_rejected_cleanup = quarantined_handle_rejected_before_retry
            && cleanup_replay_cleared_fragments == 0
            && sdk_residuals_after_replay == sdk_residuals_after_retry
            && quarantined_handle_rejected_after_replay;
        let poison_observed_before_capability_finish = vm.poison_requested();
        Ok::<_, HvfMemoryError>(HvfUnmapCapabilityCompletion {
            capability,
            poison_observed_before_capability_finish,
            protect_failure_observed,
            protect_failure_quarantined,
            quarantined_handle_rejected_cleanup,
            unmap_failure_observed,
            unmap_failure_quarantined,
            sdk_residuals_before_retry,
            cleanup_retry_cleared_fragments,
            sdk_residuals_after_retry,
        })
    })?;
    let HvfUnmapCapabilityCompletion {
        capability,
        poison_observed_before_capability_finish,
        protect_failure_observed,
        protect_failure_quarantined,
        quarantined_handle_rejected_cleanup,
        unmap_failure_observed,
        unmap_failure_quarantined,
        sdk_residuals_before_retry,
        cleanup_retry_cleared_fragments,
        sdk_residuals_after_retry,
    } = completion;
    let returned_capability_token = capability.token();
    let committed_capability_returned_after_poison =
        poison_observed_before_capability_finish && vm.is_terminally_poisoned();
    let normal_operation_rejected_after_capability_finish = matches!(
        vm.with_operation(|_| Ok::<_, HvfError>(())),
        Err(HvfError::Poisoned)
    );
    let returned_capability_cleanup_succeeded = capability.unmap().is_ok();
    let capability_cleanup_residuals = vm.residual_report()?;
    let explicit_unmap_succeeded = explicit.unmap().is_ok();
    let post_poison_cleanup_succeeded = cleanup.unmap().is_ok();
    let final_sdk_residuals = vm.residual_report()?;
    let report = HvfUnmapFailureReport {
        poison_observed_before_capability_finish,
        committed_capability_returned_after_poison,
        returned_capability_token,
        normal_operation_rejected_after_capability_finish,
        returned_capability_cleanup_succeeded,
        capability_cleanup_residuals,
        explicit_unmap_succeeded,
        protect_failure_observed,
        protect_failure_quarantined,
        quarantined_handle_rejected_cleanup,
        unmap_failure_observed,
        unmap_failure_quarantined,
        sdk_residuals_before_retry,
        cleanup_retry_cleared_fragments,
        sdk_residuals_after_retry,
        final_sdk_residuals,
        post_poison_cleanup_succeeded,
        vm_poisoned: vm.is_poisoned(),
    };
    if !report.poison_observed_before_capability_finish
        || !report.committed_capability_returned_after_poison
        || report.returned_capability_token == 0
        || !report.normal_operation_rejected_after_capability_finish
        || !report.returned_capability_cleanup_succeeded
        || !exact_known_mappings(&report.capability_cleanup_residuals, 2)
        || !report.explicit_unmap_succeeded
        || !report.protect_failure_observed
        || !report.protect_failure_quarantined
        || !report.quarantined_handle_rejected_cleanup
        || !report.unmap_failure_observed
        || !report.unmap_failure_quarantined
        || report.cleanup_retry_cleared_fragments != 2
        || !exact_known_mappings(&report.sdk_residuals_after_retry, 3)
        || !report.final_sdk_residuals.is_empty()
        || !report.post_poison_cleanup_succeeded
        || !report.vm_poisoned
    {
        return Err(HvfMemoryError::UnmapWitnessReport(Box::new(report)));
    }
    Ok(report)
}

/// Starting point for the caller-side identity selected by the mirrored-view
/// witness. The exact key is chosen under zero-vCPU exclusive admission and is
/// required to be absent, so cleanup never releases a production caller's pin.
const MIRRORED_PROBE_SHARED_IDENTITY: usize = 0x4d49_5252_4f52;

fn mirrored_probe_shared_identity(memory: &HvfMemory) -> Result<usize, HvfMemoryError> {
    let shared = memory
        .shared_backings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut identity = MIRRORED_PROBE_SHARED_IDENTITY;
    for _ in 0..=shared.len() {
        if !shared.contains_key(&identity) {
            return Ok(identity);
        }
        identity = identity
            .checked_add(1)
            .ok_or(HvfMemoryError::IpaOwnership)?;
    }
    Err(HvfMemoryError::IpaOwnership)
}

/// Live witness for the mirrored host view: every claim is host-mapped at its
/// own GVA with guest-minus-EXECUTE permissions, the view follows protect and
/// unmap in the same transaction, W^X holds on the host, shared backings
/// alias, deferred retirements pump to zero, and destroy returns every
/// transient resource to the manager's permanent synchronization-root baseline.
pub fn hvf_mirrored_view_probe() -> Result<HvfMirroredViewReport, HvfMemoryError> {
    let memory = process_hvf_memory()?;
    // `memcpy_fallible` needs the exception-table fault handlers this crate
    // installs for every real guest run; the witness process has not run one.
    crate::install_fault_handlers();
    memory.vm.with_zero_vcpu_operation(|_| {
        let shared_identity = mirrored_probe_shared_identity(memory)?;
        let mut spaces = Vec::new();
        spaces
            .try_reserve_exact(2)
            .map_err(|_| HvfMemoryError::MetadataAllocation("mirrored probe spaces"))?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            hvf_mirrored_view_probe_tracked(memory, &mut spaces, shared_identity)
        }));
        let cleanup = finish_probe_spaces(memory, &spaces);
        let shared_owned = memory
            .shared_backings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&shared_identity);
        let shared_cleanup = if shared_owned {
            match memory.release_shared_backing(shared_identity) {
                Ok(true) => Ok(()),
                Ok(false) => Err(HvfMemoryError::Witness(
                    "mirrored probe shared backing remained referenced after cleanup",
                )),
                Err(error) => Err(error),
            }
        } else {
            Ok(())
        };
        let mut cleanup_error = cleanup.err().or_else(|| shared_cleanup.err());
        retry_probe_quarantine(memory, &mut cleanup_error);
        match result {
            Ok(Ok(report)) => match cleanup_error {
                Some(error) => Err(error),
                None => Ok(report),
            },
            Ok(Err(error)) => Err(error),
            Err(payload) => {
                drop(cleanup_error);
                resume_unwind(payload)
            }
        }
    })
}

fn hvf_mirrored_view_probe_tracked(
    memory: &'static HvfMemory,
    spaces: &mut Vec<HvfAddressSpace>,
    shared_identity: usize,
) -> Result<HvfMirroredViewReport, HvfMemoryError> {
    const RW: HvfGuestPermissions =
        HvfGuestPermissions(HvfGuestPermissions::READ.0 | HvfGuestPermissions::WRITE.0);
    const RX: HvfGuestPermissions =
        HvfGuestPermissions(HvfGuestPermissions::READ.0 | HvfGuestPermissions::EXECUTE.0);
    const RWX: HvfGuestPermissions = HvfGuestPermissions(
        HvfGuestPermissions::READ.0 | HvfGuestPermissions::WRITE.0 | HvfGuestPermissions::EXECUTE.0,
    );
    let initial_vcpus = memory.vm.active_vcpu_count();
    let plain = memory.create_address_space()?;
    spaces.push(plain.clone());
    let space = memory.create_mirrored_address_space()?;
    spaces.push(space.clone());
    let mirrored_space_flagged = space.is_mirrored();
    let plain_space_not_mirrored = !plain.is_mirrored();
    let usage_before = memory.usage();

    // 1. A RW map is host-writable at its own GVA and the guest alias sees it.
    let base = 0x0000_0400_0000_0000usize;
    let three = base..base + 3 * PAGE_SIZE;
    let middle = base + PAGE_SIZE;
    let mapped = space.map_range(three.clone(), RW, false)?;
    space.defer_retirement(mapped.retirement)?;
    let host_write_ok = fallible_write_u64(middle, 0x4d49_5252_4f52_3031);
    let claim = space.claim_at(middle)?;
    let host_write_visible_to_guest_alias = host_write_ok
        && space.read_alias(&claim, middle..middle + PAGE_SIZE, |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? == 0x4d49_5252_4f52_3031;
    let host_view_permission_mirrored = region_protection(middle)
        == Some(libc::PROT_READ | libc::PROT_WRITE)
        && memory.usage().mirrored_alias_pages == usage_before.mirrored_alias_pages + 3;

    // 2. RX: the host view drops to read-only, a host write faults and is
    //    recovered, a host read still works.
    let executable = space.protect_range(middle..middle + PAGE_SIZE, RX)?;
    space.defer_retirement(executable.retirement)?;
    let executable_view_read_only = region_protection(middle) == Some(libc::PROT_READ);
    let executable_host_write_faults_recoverably = !fallible_write_u64(middle, 0x4241_4400);
    let executable_host_read_still_works = fallible_read_u64(middle) == Some(0x4d49_5252_4f52_3031);

    // 3. W|X is refused up front by both map and protect, without effect.
    let wx_before = space.report()?;
    let write_execute_refused = matches!(
        space.map_range(
            base + 0x0100_0000..base + 0x0100_0000 + PAGE_SIZE,
            RWX,
            false
        ),
        Err(HvfMemoryError::WriteExecuteRefused(_))
    ) && matches!(
        space.protect_range(middle..middle + PAGE_SIZE, RWX),
        Err(HvfMemoryError::WriteExecuteRefused(_))
    ) && space.report()? == wx_before
        && region_protection(middle) == Some(libc::PROT_READ);

    // 4. Back to RW: the executor is dropped before the host writer returns.
    let writable = space.protect_range(middle..middle + PAGE_SIZE, RW)?;
    space.defer_retirement(writable.retirement)?;
    let claim = space.claim_at(middle)?;
    let writable_again_after_executable = region_protection(middle)
        == Some(libc::PROT_READ | libc::PROT_WRITE)
        && fallible_write_u64(middle, 0x4d49_5252_4f52_3032)
        && space.read_alias(&claim, middle..middle + PAGE_SIZE, |bytes| {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]))
        })? == 0x4d49_5252_4f52_3032;

    // 4b. PROT_NONE keeps the bytes but takes the host view away; RW brings
    //     the same backing back (re-aliased after it was made hidden-RO for
    //     the executable step above).
    let none = space.protect_range(middle..middle + PAGE_SIZE, HvfGuestPermissions::NONE)?;
    space.defer_retirement(none.retirement)?;
    let none_hidden = region_protection(middle) == Some(libc::PROT_NONE)
        && fallible_read_u64(middle).is_none()
        && memory.usage().mirrored_alias_pages == usage_before.mirrored_alias_pages + 2;
    let restored = space.protect_range(middle..middle + PAGE_SIZE, RW)?;
    space.defer_retirement(restored.retirement)?;
    let none_keeps_contents = none_hidden
        && region_protection(middle) == Some(libc::PROT_READ | libc::PROT_WRITE)
        && fallible_read_u64(middle) == Some(0x4d49_5252_4f52_3032)
        && fallible_write_u64(middle, 0x4d49_5252_4f52_3033)
        && memory.usage().mirrored_alias_pages == usage_before.mirrored_alias_pages + 3;

    // 5. Unmapping the middle page makes its GVA host-inaccessible and leaves
    //    a hole that protect refuses.
    let unmapped = space.unmap_range(middle..middle + PAGE_SIZE)?;
    space.defer_retirement(unmapped.retirement)?;
    let unmapped_view_inaccessible = fallible_read_u64(middle).is_none()
        && !fallible_write_u64(middle, 1)
        && matches!(region_protection(middle), None | Some(libc::PROT_NONE))
        && memory.usage().mirrored_alias_pages == usage_before.mirrored_alias_pages + 2;
    let partial_unmap_hole_refused = matches!(
        space.protect_range(three.clone(), HvfGuestPermissions::READ),
        Err(HvfMemoryError::RangeUnmapped(_))
    ) && matches!(
        space.map_range(three.clone(), RW, false),
        Err(HvfMemoryError::AddressOverlap(_))
    );

    // 6. MAP_FIXED over the two survivors and the hole yields fresh zeroed
    //    pages that are host-writable again.
    let marked = fallible_write_u64(base, 0x4f4c_4400);
    let replaced = space.map_range(three.clone(), RW, true)?;
    space.defer_retirement(replaced.retirement)?;
    let replace_map_zeroed = marked
        && fallible_read_u64(base) == Some(0)
        && fallible_read_u64(middle) == Some(0)
        && region_protection(middle) == Some(libc::PROT_READ | libc::PROT_WRITE)
        && space.report()?.mappings.len() == 1;

    // 7. Shared backings: initialized before any mapping, aliased by two
    //    ranges, readable through a byte window.
    let key = HvfSharedBackingKey {
        identity: shared_identity,
        offset: PAGE_SIZE,
    };
    memory.with_shared_backing(
        HvfSharedBackingKey {
            identity: key.identity,
            offset: key.offset + 8,
        },
        8,
        |bytes| bytes.copy_from_slice(&0x5348_4152_4544_3031u64.to_le_bytes()),
    )?;
    let first_shared = base + 0x0200_0000;
    let second_shared = base + 0x0300_0000;
    let shared_first = space.map_shared_range(first_shared..first_shared + PAGE_SIZE, RW, key)?;
    space.defer_retirement(shared_first.retirement)?;
    let shared_second =
        space.map_shared_range(second_shared..second_shared + PAGE_SIZE, RW, key)?;
    space.defer_retirement(shared_second.retirement)?;
    let shared_backing_initialized_before_map = fallible_read_u64(first_shared + 8)
        == Some(0x5348_4152_4544_3031)
        && fallible_read_u64(second_shared + 8) == Some(0x5348_4152_4544_3031);
    let shared_backing_aliased = fallible_write_u64(first_shared + 16, 0x5348_4152_4544_3032)
        && fallible_read_u64(second_shared + 16) == Some(0x5348_4152_4544_3032)
        && space
            .report()?
            .mappings
            .iter()
            .filter(|entry| entry.sharing == HvfSharing::Shared)
            .map(|entry| entry.backing_identity)
            .collect::<HashSet<_>>()
            .len()
            == 1;
    let shared_backing_byte_window_verified = memory.with_shared_backing(
        HvfSharedBackingKey {
            identity: key.identity,
            offset: key.offset + 16,
        },
        8,
        |bytes| u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8])),
    )? == 0x5348_4152_4544_3032
        && memory.with_shared_backing(
            HvfSharedBackingKey {
                identity: key.identity,
                offset: key.offset + 20,
            },
            2,
            |bytes| bytes.len(),
        )? == 2;

    // 7b. Global W^X: while two RW mirrors hold host writers on the shared
    //     page, nobody can map it executable; the failed map is rolled back.
    let third_shared = base + 0x0380_0000;
    let shared_wx_usage_before = memory.usage();
    let shared_execute_result =
        space.map_shared_range(third_shared..third_shared + PAGE_SIZE, RX, key);
    let shared_execute_error_verified = matches!(
        shared_execute_result,
        Err(HvfMemoryError::PublishedMutation {
            operation: "executable map",
            trigger,
        }) if matches!(
            trigger.as_ref(),
            HvfMemoryError::BackingWriteExecute { .. }
        )
    );
    let shared_execute_claim_absent = matches!(
        space.claim_at(third_shared),
        Err(HvfMemoryError::RangeUnmapped(_))
    );
    let shared_execute_view_absent = matches!(
        region_protection(third_shared),
        None | Some(libc::PROT_NONE)
    );
    let shared_execute_usage_unchanged = memory.usage() == shared_wx_usage_before;
    let shared_execute_refused_while_host_writable = shared_execute_error_verified
        && shared_execute_claim_absent
        && shared_execute_view_absent
        && shared_execute_usage_unchanged;

    // 8. A rejected map leaves no host view behind and no accounting drift.
    let rollback_base = base + 0x0400_0000;
    let rollback_before = space.report()?;
    let rollback_sdk_before = memory.vm.residual_report()?;
    let rollback_pool_before = memory.pooled_table_pages();
    memory.inject_failure(FailurePoint::BeforeRootPublish);
    let rollback_result = space.map_range(rollback_base..rollback_base + PAGE_SIZE, RW, false);
    let rollback_after = space.report()?;
    let rollback_sdk_after = memory.vm.residual_report()?;
    let rollback_pool_after = memory.pooled_table_pages();
    let rollback_error_verified = rollback_result.as_ref().err().is_some_and(|error| {
        matches!(
            error,
            HvfMemoryError::PublishedMutation {
                operation: "SDK operation completion",
                trigger,
            } if matches!(
                trigger.as_ref(),
                HvfMemoryError::InjectedFailure("before root publication")
            )
        )
    });
    let rollback_state_verified = rollback_after == rollback_before
        && rollback_sdk_after == rollback_sdk_before
        && rollback_pool_after == rollback_pool_before
        && rollback_after.usage.quarantined_resources == 0
        && !memory.vm.is_poisoned();
    let rollback_restored_reservation = rollback_error_verified
        && rollback_state_verified
        && fallible_read_u64(rollback_base).is_none()
        && matches!(
            region_protection(rollback_base),
            None | Some(libc::PROT_NONE)
        );

    // 9. Two spaces cannot mirror one GVA.
    let fork_refused = matches!(
        space.fork_private(),
        Err(HvfMemoryError::MirrorForkUnsupported(_))
    );

    // 10. Deferred retirements pump to zero with no participants.
    let pending_before = space.pending_retirements();
    let released = space.pump_retirements()?;
    let deferred_retirements_pumped = pending_before > 0
        && released == pending_before
        && space.pending_retirements() == 0
        && memory.usage().retired_generations == usage_before.retired_generations;

    // 11. Tear down through the range API and the deferred list; every
    //     counter returns to where it started.
    for range in [
        three,
        first_shared..first_shared + PAGE_SIZE,
        second_shared..second_shared + PAGE_SIZE,
    ] {
        let unmapped = space.unmap_range(range)?;
        space.defer_retirement(unmapped.retirement)?;
    }
    space.pump_retirements()?;
    let drained = space.pending_retirements() == 0;
    space.destroy()?;
    relinquish_probe_space(spaces, space.id())?;
    plain.destroy()?;
    relinquish_probe_space(spaces, plain.id())?;
    let shared_released = memory.release_shared_backing(shared_identity)?;
    let final_usage = memory.usage();
    let sdk_residuals = memory.vm.residual_report()?;
    let zero_vcpus_verified = initial_vcpus == 0
        && sdk_residuals.active_vcpus == 0
        && sdk_residuals.quarantined_vcpus == 0
        && sdk_residuals.zero_vcpu_operation_active
        && sdk_residuals.zero_vcpu_owned_by_current_thread;
    let usage_returned_to_baseline =
        drained && shared_released && memory.usage_is_manager_baseline(&final_usage);
    let report = HvfMirroredViewReport {
        mirrored_space_flagged,
        plain_space_not_mirrored,
        host_write_visible_to_guest_alias,
        host_view_permission_mirrored,
        executable_view_read_only,
        executable_host_write_faults_recoverably,
        executable_host_read_still_works,
        write_execute_refused,
        writable_again_after_executable,
        none_keeps_contents,
        shared_execute_refused_while_host_writable,
        unmapped_view_inaccessible,
        partial_unmap_hole_refused,
        replace_map_zeroed,
        shared_backing_aliased,
        shared_backing_initialized_before_map,
        shared_backing_byte_window_verified,
        rollback_restored_reservation,
        fork_refused,
        deferred_retirements_pumped,
        usage_returned_to_baseline,
        zero_vcpus_verified,
        final_usage,
        sdk_residuals,
        vm_poisoned: memory.vm.is_poisoned(),
    };
    if !report.mirrored_space_flagged
        || !report.plain_space_not_mirrored
        || !report.host_write_visible_to_guest_alias
        || !report.host_view_permission_mirrored
        || !report.executable_view_read_only
        || !report.executable_host_write_faults_recoverably
        || !report.executable_host_read_still_works
        || !report.write_execute_refused
        || !report.writable_again_after_executable
        || !report.none_keeps_contents
        || !report.shared_execute_refused_while_host_writable
        || !report.unmapped_view_inaccessible
        || !report.partial_unmap_hole_refused
        || !report.replace_map_zeroed
        || !report.shared_backing_aliased
        || !report.shared_backing_initialized_before_map
        || !report.shared_backing_byte_window_verified
        || !report.rollback_restored_reservation
        || !report.fork_refused
        || !report.deferred_retirements_pumped
        || !report.usage_returned_to_baseline
        || !report.zero_vcpus_verified
        || !memory.sdk_is_manager_baseline(&report.sdk_residuals)
        || !report.sdk_residuals.zero_vcpu_operation_active
        || !report.sdk_residuals.zero_vcpu_owned_by_current_thread
        || report.vm_poisoned
    {
        return Err(HvfMemoryError::MirroredWitnessReport(Box::new(report)));
    }
    Ok(report)
}

/// GVA base for [`hvf_alias_race_probe`], distinct from
/// [`hvf_mirrored_view_probe`]'s `0x0000_0400_0000_0000` so a future run of
/// both in the same process (they are mutually exclusive CLI flags today,
/// but the constants are cheap to keep disjoint) can never collide.
const ALIAS_RACE_PROBE_BASE: usize = 0x0000_0500_0000_0000;

/// Live witness for `hvf48-bounded-alias-syscall-windows`: this platform has
/// no per-syscall "alias lease" to bound (see the PRD row's design mismatch,
/// resolved in `.gm/prd.yml`). A Linux shim syscall's `UserPtr`/`UserPtrMut`
/// dereferences the guest's permanent mirrored host alias directly via
/// [`litebox::mm::exception_table::memcpy_fallible`], with no lease
/// acquired and no participant registered -- by the time `shim.syscall(ctx)`
/// runs, the owning vCPU's `in_flight` slot is already retired to zero (see
/// `HvfBackend::run_thread`/`dispatch_monitor_exit` in `hvf_backend.rs`,
/// which call `attachment.finish()` unconditionally before dispatching the
/// syscall). The only thing left to prove live is that a raw racer
/// reading/writing that exact GVA with no lease at all, concurrently with
/// the owner thread unmapping/remapping the same range with no
/// synchronization between the two beyond what `unmap_range`/`map_range`
/// already provide, never observes freed/foreign memory or a torn value
/// that escapes the fallible `Result`/`Option` API -- only a clean value or
/// a clean recoverable fault.
pub fn hvf_alias_race_probe() -> Result<HvfAliasRaceReport, HvfMemoryError> {
    let memory = process_hvf_memory()?;
    crate::install_fault_handlers();
    let mut spaces = Vec::new();
    spaces
        .try_reserve_exact(1)
        .map_err(|_| HvfMemoryError::MetadataAllocation("alias race probe spaces"))?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        hvf_alias_race_probe_tracked(memory, &mut spaces)
    }));
    let cleanup = memory
        .vm
        .with_zero_vcpu_operation(|_| finish_probe_spaces(memory, &spaces));
    match result {
        Ok(result) => {
            cleanup?;
            result
        }
        Err(payload) => {
            let _ = cleanup;
            resume_unwind(payload)
        }
    }
}

/// Number of racer iterations and owner unmap/remap cycles the probe runs.
/// Large enough on real hardware timing to reliably hit both the "caught it
/// mapped" and "caught it unmapped" windows without a fixed sleep.
const ALIAS_RACE_ITERATIONS: u64 = 200_000;

fn hvf_alias_race_probe_tracked(
    memory: &'static HvfMemory,
    spaces: &mut Vec<HvfAddressSpace>,
) -> Result<HvfAliasRaceReport, HvfMemoryError> {
    const RW: HvfGuestPermissions =
        HvfGuestPermissions(HvfGuestPermissions::READ.0 | HvfGuestPermissions::WRITE.0);
    let space = memory.vm.with_zero_vcpu_operation(|_| {
        let space = memory.create_mirrored_address_space()?;
        spaces.push(space.clone());
        Ok::<_, HvfMemoryError>(space)
    })?;
    let gva = ALIAS_RACE_PROBE_BASE;
    let range = gva..gva + PAGE_SIZE;
    let mapped = space.map_range(range.clone(), RW, false)?;
    space.defer_retirement(mapped.retirement)?;
    space.pump_retirements()?;

    // Racer state: a monotonically increasing "epoch" the owner stamps into
    // the page's first 8 bytes right after each remap, an `in_transition`
    // flag the owner holds set for exactly the unmap..remap window, and
    // per-iteration outcome counters the racer updates itself (no shared
    // lock -- atomics only, matching how a real syscall's raw dereference
    // has no lock either).
    let owner_epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let in_transition = Arc::new(AtomicBool::new(false));
    let racer_iterations = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let racer_faults = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let racer_faults_outside_transition = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let wrong_value_seen = Arc::new(AtomicBool::new(false));
    let first_wrong_value = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Tag the freshly mapped page with epoch 0 before the racer starts, so
    // its very first read has a defined expectation.
    fallible_write_u64(gva, epoch_tag(0));

    let racer = {
        let in_transition = Arc::clone(&in_transition);
        let racer_iterations = Arc::clone(&racer_iterations);
        let racer_faults = Arc::clone(&racer_faults);
        let racer_faults_outside_transition = Arc::clone(&racer_faults_outside_transition);
        let wrong_value_seen = Arc::clone(&wrong_value_seen);
        let first_wrong_value = Arc::clone(&first_wrong_value);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            // Standing in for a Linux shim syscall's raw `UserPtr` read:
            // no lease, no participant registration, just a direct
            // `memcpy_fallible` against the GVA==HVA host alias. `value`'s
            // validity is judged by *format*, not by racing a causally
            // ordered window against the owner's plain (non-atomic) page
            // write: `epoch_tag` reserves a fixed high-bit pattern no other
            // content in this probe ever produces, so any value that is
            // either `0` (a freshly (re)claimed anonymous page) or decodes
            // to a tag with a plausible epoch number is a clean read of
            // this probe's own data; anything else -- garbage, another
            // process's bytes, freed-memory content -- fails the format
            // check regardless of exactly which epoch was "supposed" to be
            // visible at that instant.
            while !stop.load(Ordering::Relaxed) {
                let before_transition = in_transition.load(Ordering::Acquire);
                if let Some(value) = fallible_read_u64(gva) {
                    if !is_plausible_epoch_value(value) {
                        wrong_value_seen.store(true, Ordering::Relaxed);
                        let _ = first_wrong_value.compare_exchange(
                            0,
                            value,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    }
                } else {
                    // Read `in_transition` immediately after the fault,
                    // before any other atomic traffic, to keep this
                    // checker's own window as tight as possible around
                    // the actual faulting instruction.
                    let after_transition = in_transition.load(Ordering::Acquire);
                    // A fault must correlate with a real unmap window:
                    // the owner had `in_transition` set either before or
                    // after the faulting access (never neither).
                    if !before_transition && !after_transition {
                        racer_faults_outside_transition.fetch_add(1, Ordering::Relaxed);
                    }
                    racer_faults.fetch_add(1, Ordering::Relaxed);
                }
                racer_iterations.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    let mut owner_cycles = 0u64;
    for cycle in 1..=ALIAS_RACE_ITERATIONS.min(20_000) {
        in_transition.store(true, Ordering::Release);
        let unmapped = space.unmap_range(range.clone())?;
        space.defer_retirement(unmapped.retirement)?;
        // The old claim's host slot is only released back to the arena once
        // its retirement is acknowledged; a fresh `map_range` at the same
        // GVA needs that slot free, so pump before remapping (this probe
        // registers no vCPU participants, so every retirement acknowledges
        // immediately -- nothing here waits).
        space.pump_retirements()?;
        let remapped = space.map_range(range.clone(), RW, false)?;
        space.defer_retirement(remapped.retirement)?;
        fallible_write_u64(gva, epoch_tag(cycle));
        in_transition.store(false, Ordering::Release);
        owner_epoch.store(cycle, Ordering::Release);
        space.pump_retirements()?;
        owner_cycles = cycle;
    }
    stop.store(true, Ordering::Relaxed);
    racer
        .join()
        .map_err(|_| HvfMemoryError::MetadataAllocation("alias race probe join"))?;

    let racer_iterations = racer_iterations.load(Ordering::Relaxed);
    let racer_faults = racer_faults.load(Ordering::Relaxed);
    let racer_faults_outside_transition = racer_faults_outside_transition.load(Ordering::Relaxed);
    if wrong_value_seen.load(Ordering::Relaxed) {
        // Diagnostic aid for a future regression: the exact offending bit
        // pattern is more actionable than the boolean alone (e.g. a value
        // with the marker's top byte but zeroed low bytes points straight
        // at a torn sub-word access, not a wholesale wrong-page read).
        litebox_util_log::error!(
            first_wrong_value:? = first_wrong_value.load(Ordering::Relaxed);
            "hvf_alias_race_probe observed an implausible page value"
        );
    }
    // `faults_only_during_transitions` tolerates a very small nonzero count:
    // the underlying check is a best-effort, scheduler-sensitive heuristic
    // (see the field's doc comment), not a proof, and under heavy host CPU
    // oversubscription the racer can be preempted between its own two
    // bracketing atomic loads for long enough to produce an occasional false
    // positive even when `no_wrong_value_observed` -- the property that
    // actually matters -- holds throughout. A high rate (not an occasional
    // single hit) would still fail this and is the real signal to act on.
    let faults_only_during_transitions = racer_faults_outside_transition == 0
        || racer_faults_outside_transition * 100_000 < racer_faults;
    let report = HvfAliasRaceReport {
        no_wrong_value_observed: !wrong_value_seen.load(Ordering::Relaxed),
        faults_only_during_transitions,
        racer_thread_survived: true,
        both_outcomes_observed: racer_faults > 0 && racer_faults < racer_iterations,
        racer_iterations,
        racer_faults,
        racer_faults_outside_transition,
        owner_cycles,
        vm_poisoned: memory.vm.is_poisoned(),
    };
    if !report.no_wrong_value_observed
        || !report.faults_only_during_transitions
        || !report.racer_thread_survived
        || !report.both_outcomes_observed
        || report.vm_poisoned
    {
        return Err(HvfMemoryError::AliasRaceWitnessReport(Box::new(report)));
    }
    Ok(report)
}

/// The fixed high 32 bits every [`epoch_tag`] value carries: an arbitrary
/// pattern picked to be implausible as accidental content from anywhere else
/// (freed heap, another process's bytes, an uninitialized page's usual `0`).
const EPOCH_TAG_MARKER: u64 = 0xA11A_5EED_0000_0000u64;

/// The tagged 64-bit value the owner stamps for `epoch`: a fixed marker in
/// the high 32 bits, the epoch number verbatim in the low 32 bits.
/// Distinguishable from any other epoch's tag and from the `0` a freshly
/// zeroed anonymous page reads as.
fn epoch_tag(epoch: u64) -> u64 {
    EPOCH_TAG_MARKER | (epoch & 0xffff_ffff)
}

/// `true` for `0` (a freshly (re)claimed anonymous page, never written) or
/// any value [`epoch_tag`] could have produced for an epoch within this
/// probe's actual cycle count. Judging validity by *format* rather than by
/// racing a causally ordered before/after window against the owner's plain
/// (non-atomic) page write avoids false positives from the checker's own
/// synchronization, while still catching the thing that actually matters:
/// garbage, another process's bytes, or freed-memory content can only pass
/// this check by accidentally colliding with the fixed marker pattern, which
/// a real UAF/wrong-permission read has no reason to do.
fn is_plausible_epoch_value(value: u64) -> bool {
    if value == 0 {
        return true;
    }
    let marker = value & 0xffff_ffff_0000_0000u64;
    let epoch = value & 0xffff_ffff;
    marker == EPOCH_TAG_MARKER && epoch <= ALIAS_RACE_ITERATIONS
}

/// The live host protection of the region containing `address`, or `None`
/// when nothing is mapped there (Mach reports the next region above instead).
fn region_protection(address: usize) -> Option<libc::c_int> {
    let mut start = address as u64;
    let mut size = 0u64;
    let mut info = [0 as libc::c_int; VM_REGION_BASIC_INFO_COUNT_64 as usize];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object_name = 0u32;
    let result = unsafe {
        mach_vm_region(
            crate::darwin::mach_task_self(),
            &raw mut start,
            &raw mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &raw mut count,
            &raw mut object_name,
        )
    };
    if result != 0 {
        return None;
    }
    if object_name != 0 {
        unsafe { mach_port_deallocate(crate::darwin::mach_task_self(), object_name) };
    }
    let end = start.checked_add(size)?;
    ((address as u64) >= start && (address as u64) < end).then_some(info[0])
}

/// Writes one aligned `u64` fallibly via a single fallible store instruction
/// (`str`/`mov qword ptr`), matching how `UserPtr<u64>`/`UserPtrMut<u64>`
/// dereference guest memory in production (see
/// `litebox::platform::common_providers::userspace_pointers::write_at_offset`'s
/// `size_of::<T>() == 8` arm) rather than `memcpy_fallible`'s byte-by-byte
/// tail loop for a sub-16-byte copy, which is not atomic and can observe a
/// concurrent remap mid-copy as a torn value with no fault at all.
fn fallible_write_u64(address: usize, value: u64) -> bool {
    unsafe { litebox::mm::exception_table::write_u64_fallible(address as *mut u64, value).is_ok() }
}

/// Reads one aligned `u64` fallibly via a single fallible load instruction
/// (`ldr`/`mov qword ptr`); see [`fallible_write_u64`] for why this matters
/// over `memcpy_fallible` for exactly this size.
fn fallible_read_u64(address: usize) -> Option<u64> {
    unsafe { litebox::mm::exception_table::read_u64_fallible(address as *const u64).ok() }
}

fn refuse_write_execute(
    range: &Range<usize>,
    permissions: HvfGuestPermissions,
) -> Result<(), HvfMemoryError> {
    if permissions.contains(HvfGuestPermissions::WRITE)
        && permissions.contains(HvfGuestPermissions::EXECUTE)
    {
        return Err(HvfMemoryError::WriteExecuteRefused(range.clone()));
    }
    Ok(())
}

fn create_monitor_root(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    table_limit: usize,
) -> Result<TableToken, HvfMemoryError> {
    let mut created = Vec::new();
    created
        .try_reserve_exact(1)
        .map_err(|_| HvfMemoryError::MetadataAllocation("monitor root rollback"))?;
    let bytes = Box::new(StageOneTable([0; TABLE_ENTRIES]));
    let root =
        arenas
            .tables
            .allocate(vm, &mut arenas.ipa, 0, bytes, HashMap::new(), table_limit)?;
    if let Err(error) = arenas.tables.retain(root) {
        created.push(root);
        let cleanup = cleanup_created_tables(vm, arenas, &mut created);
        return Err(HvfMemoryError::with_cleanup(error, cleanup));
    }
    let descriptor = DESCRIPTOR_VALID_TABLE_OR_PAGE
        | DESCRIPTOR_AP_EL0_NONE_EL1_RO
        | DESCRIPTOR_INNER_SHAREABLE
        | DESCRIPTOR_ACCESS_FLAG
        | DESCRIPTOR_NOT_GLOBAL
        | DESCRIPTOR_UXN;
    let candidate = match build_candidate_root(vm, arenas, root, &[(0, descriptor)], table_limit) {
        Ok(candidate) => candidate,
        Err(error) => {
            let cleanup = cleanup_candidate_root(vm, arenas, root);
            return Err(HvfMemoryError::with_cleanup(error, cleanup));
        }
    };
    if let Err(error) = cleanup_candidate_root(vm, arenas, root) {
        let cleanup = cleanup_candidate_root(vm, arenas, candidate);
        return Err(HvfMemoryError::with_cleanup(error, cleanup));
    }
    Ok(candidate)
}

fn build_candidate_root(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    current: TableToken,
    updates: &[(usize, u64)],
    table_limit: usize,
) -> Result<TableToken, HvfMemoryError> {
    arenas.tables.retain(current)?;
    if updates.is_empty() {
        return Ok(current);
    }
    let result = arenas
        .tables
        .cow_leaves(vm, &mut arenas.ipa, current, updates, table_limit);
    let (next, mut created) = match result {
        Ok(value) => value,
        Err(error) => {
            let cleanup = cleanup_candidate_root(vm, arenas, current);
            return Err(HvfMemoryError::with_cleanup(error, cleanup));
        }
    };
    if let Err(error) = arenas.tables.retain(next) {
        let created_cleanup = cleanup_created_tables(vm, arenas, &mut created);
        let candidate_cleanup = cleanup_candidate_root(vm, arenas, current);
        return Err(HvfMemoryError::with_cleanup(
            error,
            created_cleanup.and(candidate_cleanup),
        ));
    }
    if let Err(error) = cleanup_candidate_root(vm, arenas, current) {
        let cleanup = cleanup_candidate_root(vm, arenas, next);
        return Err(HvfMemoryError::with_cleanup(error, cleanup));
    }
    publish_stage_one_tables();
    Ok(next)
}

fn publish_stage_one_tables() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // Translation-table walks are architectural observers outside Rust's
        // memory model. Complete every candidate descriptor store before the
        // root can be installed on a vCPU.
        core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    std::sync::atomic::fence(Ordering::SeqCst);
}

fn cleanup_created_tables(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    created: &mut Vec<TableToken>,
) -> Result<(), HvfMemoryError> {
    let records = match arenas.tables.discard_unreferenced(created) {
        Ok(records) => records,
        Err(error) => {
            let quarantine = arenas.tables.abandon_unreferenced(created);
            vm.poison();
            return Err(HvfMemoryError::with_cleanup(error, quarantine));
        }
    };
    cleanup_table_records(vm, arenas, records)
}

fn cleanup_candidate_root(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    root: TableToken,
) -> Result<(), HvfMemoryError> {
    let records = match arenas.tables.release(root) {
        Ok(records) => records,
        Err(error) => {
            let quarantine = arenas.tables.abandon_root(root);
            vm.poison();
            return Err(HvfMemoryError::with_cleanup(error, quarantine));
        }
    };
    cleanup_table_records(vm, arenas, records)
}

fn drain_table_pool_if_idle(vm: &'static HvfVm, arenas: &mut Arenas) -> Result<(), HvfMemoryError> {
    if arenas.address_spaces == 0 {
        let Arenas { tables, ipa, .. } = arenas;
        tables.drain_pool(vm, ipa)?;
    }
    Ok(())
}

fn cleanup_table_records(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    records: Vec<TableRecord>,
) -> Result<(), HvfMemoryError> {
    let inject_failure = arenas.take_failure(FailurePoint::TableUnmap);
    cleanup_detached_table_records(
        vm,
        &mut arenas.tables,
        &mut arenas.ipa,
        records,
        inject_failure,
    )
}

fn cleanup_detached_table_records(
    vm: &'static HvfVm,
    tables: &mut TableArena,
    ipa: &mut IpaAllocator,
    records: Vec<TableRecord>,
    inject_first_failure: bool,
) -> Result<(), HvfMemoryError> {
    tables
        .quarantined
        .try_reserve(records.len())
        .map_err(|_| HvfMemoryError::MetadataAllocation("table quarantine"))?;
    let mut first_error = None;
    let mut injected = false;
    for mut record in records {
        let Some(mapping) = record.mapping.take() else {
            tables.quarantined.push(TableQuarantine {
                ipa: Some(record.ipa),
                bytes: record.bytes,
                sdk_token: None,
                retryable: false,
            });
            vm.poison();
            first_error.get_or_insert(HvfMemoryError::TableOwnership);
            continue;
        };
        let sdk_token = mapping.token();
        let (page_ipa, mut bytes, unmap) = if inject_first_failure && !injected {
            // The injected failure must reach a real `hv_vm_unmap`, so this
            // page bypasses the pool.
            injected = true;
            (record.ipa, record.bytes, mapping.induce_unmap_failure())
        } else {
            // Detached pages stay mapped for reuse while the pool has room.
            match tables.pool_page(record.ipa, record.bytes, mapping) {
                None => continue,
                Some((page_ipa, bytes, mapping)) => (page_ipa, bytes, mapping.unmap()),
            }
        };
        if let Err(error) = unmap {
            tables.quarantined.push(TableQuarantine {
                ipa: Some(page_ipa),
                bytes,
                sdk_token: Some(sdk_token),
                retryable: true,
            });
            vm.poison();
            first_error.get_or_insert(error.into());
            continue;
        }
        bytes.disarm_after_exact_absence();
        if let Err(error) = ipa.release(page_ipa) {
            tables.quarantined.push(TableQuarantine {
                ipa: Some(page_ipa),
                bytes,
                sdk_token: None,
                retryable: true,
            });
            vm.poison();
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn map_data_page(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    backing: BackingPage,
    permissions: HvfGuestPermissions,
    release_backing_on_failure: bool,
) -> Result<DataMapping, HvfMemoryError> {
    let quarantine_reservation = match acknowledgements.reserve_data_quarantine() {
        Ok(reservation) => reservation,
        Err(trigger) => {
            let cleanup = if release_backing_on_failure {
                backings.release(backing).map(|_| ())
            } else {
                Ok(())
            };
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    };
    let ipa = match arenas.ipa.allocate(1) {
        Ok(ipa) => ipa,
        Err(trigger) => {
            acknowledgements.release_data_quarantine_reservation(quarantine_reservation);
            let cleanup = if release_backing_on_failure {
                backings.release(backing).map(|_| ())
            } else {
                Ok(())
            };
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    };
    let host = match backings.page_range(backing) {
        Ok(host) => host,
        Err(trigger) => {
            let cleanup = cleanup_data_allocation(
                vm,
                arenas,
                backings,
                acknowledgements,
                quarantine_reservation,
                backing,
                ipa,
                None,
                release_backing_on_failure,
            );
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    };
    let authority = match backings.authorize_stage_two(backing, permissions) {
        Ok(authority) => authority,
        Err(trigger) => {
            let cleanup = cleanup_data_allocation(
                vm,
                arenas,
                backings,
                acknowledgements,
                quarantine_reservation,
                backing,
                ipa,
                None,
                release_backing_on_failure,
            );
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    };
    match unsafe { vm.map_host_range(host, ipa.start, permissions.stage_two()) } {
        Ok(mapping) => Ok(DataMapping {
            backing,
            ipa,
            authority,
            mapping: Some(mapping),
            quarantine_reservation,
        }),
        Err(error) => {
            let sdk_token = error.residual_mapping_token();
            let cleanup = if let Some(sdk_token) = sdk_token {
                commit_failed_data_mapping(
                    vm,
                    backings,
                    acknowledgements,
                    quarantine_reservation,
                    backing,
                    ipa,
                    authority,
                    Some(sdk_token),
                    release_backing_on_failure,
                    true,
                )
            } else {
                cleanup_data_allocation(
                    vm,
                    arenas,
                    backings,
                    acknowledgements,
                    quarantine_reservation,
                    backing,
                    ipa,
                    Some(authority),
                    release_backing_on_failure,
                )
            };
            Err(HvfMemoryError::with_cleanup(error.into(), cleanup))
        }
    }
}

/// The `index`th page after `first` in the same backing object.
fn backing_page_after(first: BackingPage, index: usize) -> BackingPage {
    BackingPage {
        identity: first.identity,
        offset: first.offset + index * PAGE_SIZE,
    }
}

/// The `index`th page of a run-wide IPA token: same owner id, one page.
fn ipa_page_after(run: IpaToken, index: usize) -> IpaToken {
    IpaToken {
        id: run.id,
        start: run.start + (index * PAGE_SIZE) as u64,
        pages: 1,
    }
}

/// How many pages starting at `first` (at most `max`) sit contiguously in
/// host memory, so they can share one stage-2 mapping call.
fn contiguous_backing_run(
    backings: &BackingRegistry,
    first: BackingPage,
    max: usize,
) -> Result<usize, HvfMemoryError> {
    let base = backings.page_range(first)?.start;
    let mut run = 1;
    while run < max {
        let expected = base + run * PAGE_SIZE;
        match backings.page_range(backing_page_after(first, run)) {
            Ok(range) if range.start == expected => run += 1,
            _ => break,
        }
    }
    Ok(run)
}

/// Retains one reference on each of `pages` pages from `first`; a failure
/// part-way returns the references already taken.
fn retain_backing_run(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    first: BackingPage,
    pages: usize,
) -> Result<(), HvfMemoryError> {
    for index in 0..pages {
        if let Err(trigger) = backings.retain(backing_page_after(first, index)) {
            let mut first_cleanup = None;
            for released in 0..index {
                if let Err(cleanup) = backings.release(backing_page_after(first, released)) {
                    vm.poison();
                    first_cleanup.get_or_insert(cleanup);
                }
            }
            let cleanup = first_cleanup.map_or(Ok(()), Err);
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    }
    Ok(())
}

fn release_backing_run(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    first: BackingPage,
    pages: usize,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for index in 0..pages {
        if let Err(error) = backings.release(backing_page_after(first, index)) {
            vm.poison();
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Maps `pages` host-contiguous backing pages from `first` at one contiguous
/// IPA run with a single stage-2 call, then splits the SDK token per page so
/// every page keeps the exact ledger shape of [`map_data_page`]: its own IPA
/// token (sharing the run's owner id), authority, mapping handle and
/// quarantine reservation. Failure leaves nothing half-owned: every page is
/// released, or quarantined under the run's SDK token when the hypervisor
/// state is unknown.
#[allow(clippy::too_many_arguments)]
fn map_data_run(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    first: BackingPage,
    pages: usize,
    permissions: HvfGuestPermissions,
    release_backing_on_failure: bool,
) -> Result<Vec<DataMapping>, HvfMemoryError> {
    let mut mappings = Vec::new();
    if mappings.try_reserve_exact(pages).is_err() {
        let trigger = HvfMemoryError::MetadataAllocation("data run mappings");
        let cleanup = if release_backing_on_failure {
            release_backing_run(vm, backings, first, pages)
        } else {
            Ok(())
        };
        return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
    }
    if pages <= 1 {
        mappings.push(map_data_page(
            vm,
            arenas,
            backings,
            acknowledgements,
            first,
            permissions,
            release_backing_on_failure,
        )?);
        return Ok(mappings);
    }
    let mut reservations = Vec::new();
    if reservations.try_reserve_exact(pages).is_err() {
        let trigger = HvfMemoryError::MetadataAllocation("data run quarantine");
        let cleanup = if release_backing_on_failure {
            release_backing_run(vm, backings, first, pages)
        } else {
            Ok(())
        };
        return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
    }
    let mut authorities = Vec::new();
    if authorities.try_reserve_exact(pages).is_err() {
        let trigger = HvfMemoryError::MetadataAllocation("data run authorities");
        let cleanup = if release_backing_on_failure {
            release_backing_run(vm, backings, first, pages)
        } else {
            Ok(())
        };
        return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
    }
    // Nothing owned yet: a failure here only returns the references.
    let host = (|| {
        let base = backings.page_range(first)?.start;
        for index in 1..pages {
            if backings.page_range(backing_page_after(first, index))?.start
                != base + index * PAGE_SIZE
            {
                return Err(HvfMemoryError::IpaOwnership);
            }
        }
        Ok::<_, HvfMemoryError>(base..base + pages * PAGE_SIZE)
    })();
    let host = match host {
        Ok(host) => host,
        Err(trigger) => {
            let cleanup = if release_backing_on_failure {
                release_backing_run(vm, backings, first, pages)
            } else {
                Ok(())
            };
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    };
    for _ in 0..pages {
        match acknowledgements.reserve_data_quarantine() {
            Ok(reservation) => reservations.push(reservation),
            Err(trigger) => {
                for reservation in reservations {
                    acknowledgements.release_data_quarantine_reservation(reservation);
                }
                let cleanup = if release_backing_on_failure {
                    release_backing_run(vm, backings, first, pages)
                } else {
                    Ok(())
                };
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }
        }
    }
    let ipa = match arenas.ipa.allocate(pages) {
        Ok(ipa) => ipa,
        Err(trigger) => {
            for reservation in reservations {
                acknowledgements.release_data_quarantine_reservation(reservation);
            }
            let cleanup = if release_backing_on_failure {
                release_backing_run(vm, backings, first, pages)
            } else {
                Ok(())
            };
            return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
        }
    };
    for index in 0..pages {
        match backings.authorize_stage_two(backing_page_after(first, index), permissions) {
            Ok(authority) => authorities.push(authority),
            Err(trigger) => {
                // Unwind page by page through the exact single-page path.
                let mut first_cleanup = None;
                for (index, (reservation, authority)) in reservations
                    .into_iter()
                    .zip(
                        authorities
                            .into_iter()
                            .map(Some)
                            .chain(core::iter::repeat(None)),
                    )
                    .enumerate()
                {
                    if let Err(cleanup) = cleanup_data_allocation(
                        vm,
                        arenas,
                        backings,
                        acknowledgements,
                        reservation,
                        backing_page_after(first, index),
                        ipa_page_after(ipa, index),
                        authority,
                        release_backing_on_failure,
                    ) {
                        first_cleanup.get_or_insert(cleanup);
                    }
                }
                let cleanup = first_cleanup.map_or(Ok(()), Err);
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }
        }
    }
    let handles = match unsafe { vm.map_host_range(host, ipa.start, permissions.stage_two()) } {
        Ok(mut mapping) => match mapping.split_pages() {
            Ok(handles) if handles.len() == pages => Ok(handles),
            Ok(handles) => {
                // Cannot happen for a page-multiple range; treat as unknown.
                vm.poison();
                let token = handles.first().map(HvfMapping::token);
                for handle in handles {
                    if handle.unmap().is_err() {
                        vm.poison();
                    }
                }
                Err((token, HvfMemoryError::IpaOwnership))
            }
            Err(error) => {
                // The handle still owns the whole run: undo it whole, and if
                // even that fails the pages are quarantined under its token.
                let token = mapping.token();
                match mapping.unmap() {
                    Ok(()) => Err((None, error.into())),
                    Err(unmap_error) => Err((Some(token), unmap_error.into())),
                }
            }
        },
        Err(error) => Err((error.residual_mapping_token(), error.into())),
    };
    let handles = match handles {
        Ok(handles) => handles,
        Err((token, error)) => {
            let mut first_cleanup = None;
            for (index, (reservation, authority)) in
                reservations.into_iter().zip(authorities).enumerate()
            {
                let backing = backing_page_after(first, index);
                let page_ipa = ipa_page_after(ipa, index);
                let cleanup = match token {
                    Some(token) => commit_failed_data_mapping(
                        vm,
                        backings,
                        acknowledgements,
                        reservation,
                        backing,
                        page_ipa,
                        authority,
                        Some(token),
                        release_backing_on_failure,
                        true,
                    ),
                    None => cleanup_data_allocation(
                        vm,
                        arenas,
                        backings,
                        acknowledgements,
                        reservation,
                        backing,
                        page_ipa,
                        Some(authority),
                        release_backing_on_failure,
                    ),
                };
                if let Err(cleanup) = cleanup {
                    first_cleanup.get_or_insert(cleanup);
                }
            }
            let cleanup = first_cleanup.map_or(Ok(()), Err);
            return Err(HvfMemoryError::with_cleanup(error, cleanup));
        }
    };
    for (index, ((reservation, authority), handle)) in reservations
        .into_iter()
        .zip(authorities)
        .zip(handles)
        .enumerate()
    {
        mappings.push(DataMapping {
            backing: backing_page_after(first, index),
            ipa: ipa_page_after(ipa, index),
            authority,
            mapping: Some(handle),
            quarantine_reservation: reservation,
        });
    }
    Ok(mappings)
}

#[allow(clippy::too_many_arguments)]
fn cleanup_data_allocation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    quarantine_reservation: DataQuarantineReservation,
    backing: BackingPage,
    ipa: IpaToken,
    authority: Option<StageTwoAuthority>,
    release_backing_reference: bool,
) -> Result<(), HvfMemoryError> {
    let mut quarantine = DataQuarantine {
        ipa: Some(ipa),
        backing,
        authority,
        sdk_token: None,
        mapping_quarantine: false,
        release_backing_reference,
        retryable: true,
    };
    let mut first_error = None;
    if let Some(ipa) = quarantine.ipa {
        match arenas.ipa.release(ipa) {
            Ok(()) => quarantine.ipa = None,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if let Some(authority) = quarantine.authority {
        match backings.release_stage_two(quarantine.backing, authority) {
            Ok(()) => quarantine.authority = None,
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if quarantine.release_backing_reference {
        match backings.release(quarantine.backing) {
            Ok(_) => quarantine.release_backing_reference = false,
            Err(error) => {
                if matches!(backings.page_has_reference(quarantine.backing), Ok(false)) {
                    quarantine.release_backing_reference = false;
                }
                first_error.get_or_insert(error);
            }
        }
    }
    let ownership_remains = quarantine.ipa.is_some()
        || quarantine.authority.is_some()
        || quarantine.release_backing_reference;
    if ownership_remains {
        acknowledgements.commit_data_quarantine(quarantine_reservation, quarantine);
        vm.poison();
        return Err(first_error.unwrap_or(HvfMemoryError::IpaOwnership));
    }
    acknowledgements.release_data_quarantine_reservation(quarantine_reservation);
    if let Some(error) = first_error {
        vm.poison();
        Err(error)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn commit_failed_data_mapping(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    quarantine_reservation: DataQuarantineReservation,
    backing: BackingPage,
    ipa: IpaToken,
    authority: StageTwoAuthority,
    sdk_token: Option<u64>,
    release_backing_reference: bool,
    retryable: bool,
) -> Result<(), HvfMemoryError> {
    let index = acknowledgements.commit_data_quarantine(
        quarantine_reservation,
        DataQuarantine {
            ipa: Some(ipa),
            backing,
            authority: Some(authority),
            sdk_token,
            mapping_quarantine: false,
            release_backing_reference,
            retryable,
        },
    );
    if let Err(error) = backings.quarantine_mapping(backing) {
        vm.poison();
        return Err(error);
    }
    let Some(quarantine) = acknowledgements.data_quarantine.get_mut(index) else {
        vm.poison();
        return Err(HvfMemoryError::IpaOwnership);
    };
    quarantine.mapping_quarantine = true;
    Ok(())
}

fn demote_data_mapping(
    backings: &mut BackingRegistry,
    mapping: &mut DataMapping,
) -> Result<(), HvfMemoryError> {
    let authority = mapping.authority;
    if authority == StageTwoAuthority::ReadOnly {
        return Ok(());
    }
    let handle = mapping
        .mapping
        .as_mut()
        .ok_or(HvfMemoryError::IpaOwnership)?;
    handle.protect(HvfMapPermissions::READ)?;
    backings.release_stage_two(mapping.backing, authority)?;
    mapping.authority = StageTwoAuthority::ReadOnly;
    Ok(())
}

fn promote_data_mapping(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    mapping: &mut DataMapping,
    permissions: HvfGuestPermissions,
) -> Result<(), HvfMemoryError> {
    let target = StageTwoAuthority::for_permissions(permissions);
    if target == StageTwoAuthority::ReadOnly {
        return Ok(());
    }
    if mapping.authority != StageTwoAuthority::ReadOnly {
        return Err(HvfMemoryError::IpaOwnership);
    }
    let authority = backings.authorize_stage_two(mapping.backing, permissions)?;
    mapping.authority = authority;
    let Some(handle) = mapping.mapping.as_mut() else {
        vm.poison();
        return Err(HvfMemoryError::IpaOwnership);
    };
    handle.protect(permissions.stage_two())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rollback_protect_authorities(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    replacements: &mut HashMap<usize, PageState>,
    mirror_plan: Option<&mut MirrorPlan>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for gva in page_addresses(range) {
        let Some(mapping) = replacements
            .get_mut(&gva)
            .and_then(|page| page.mapping.as_mut())
        else {
            continue;
        };
        if mapping.authority != StageTwoAuthority::ReadOnly
            && let Err(error) = demote_data_mapping(backings, mapping)
        {
            first_error.get_or_insert(error);
        }
    }
    // The mirror goes back between the two authority phases: the replacement
    // executors are gone (so an old host writer may return) and the old
    // executors are not yet back (so a new host writer can still be dropped).
    if let Some(plan) = mirror_plan
        && let Err(error) = rollback_mirror_plan(vm, arenas, backings, acknowledgements, plan)
    {
        first_error.get_or_insert(error);
    }
    for gva in page_addresses(range) {
        let Some(old) = claim.pages.get_mut(&gva) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        let expected = StageTwoAuthority::for_permissions(old.permissions);
        match old.mapping.as_mut() {
            Some(mapping) if mapping.authority == expected => {}
            Some(mapping)
                if mapping.authority == StageTwoAuthority::ReadOnly
                    && expected != StageTwoAuthority::ReadOnly =>
            {
                if let Err(error) = promote_data_mapping(vm, backings, mapping, old.permissions) {
                    first_error.get_or_insert(error);
                }
            }
            None if old.permissions == HvfGuestPermissions::NONE => {}
            Some(_) | None => {
                first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            }
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn protect_authority_failure(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    replacements: &mut HashMap<usize, PageState>,
    mirror_plan: Option<&mut MirrorPlan>,
    trigger: HvfMemoryError,
) -> HvfMemoryError {
    if vm.is_poisoned() {
        return trigger;
    }
    HvfMemoryError::with_cleanup(
        trigger,
        rollback_protect_authorities(
            vm,
            arenas,
            backings,
            acknowledgements,
            claim,
            range,
            replacements,
            mirror_plan,
        ),
    )
}

fn promote_replacement_authorities(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    range: &Range<usize>,
    replacements: &mut HashMap<usize, PageState>,
    permissions: HvfGuestPermissions,
) -> Result<(), HvfMemoryError> {
    for gva in page_addresses(range) {
        let replacement = replacements
            .get_mut(&gva)
            .ok_or(HvfMemoryError::ClaimStale)?;
        let Some(mapping) = replacement.mapping.as_mut() else {
            continue;
        };
        promote_data_mapping(vm, backings, mapping, permissions)?;
    }
    Ok(())
}

/// Moves the stage-two authorities (and, on a mirrored space, the host view)
/// from the old pages to `replacements` in W^X-safe order: retiring writers or
/// executors are dropped first, then the mirror changes (a host writer is
/// released before any executor can be granted, and granted only after the
/// retiring executor is gone), then the new authorities are granted.
#[allow(clippy::too_many_arguments)]
fn apply_protect_authorities(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    permissions: HvfGuestPermissions,
    replacements: &mut HashMap<usize, PageState>,
    mut mirror_plan: Option<&mut MirrorPlan>,
    inject_failure: bool,
) -> Result<(), HvfMemoryError> {
    let target = StageTwoAuthority::for_permissions(permissions);
    for gva in page_addresses(range) {
        let Some(old) = claim.pages.get_mut(&gva) else {
            let trigger = HvfMemoryError::ClaimStale;
            return Err(protect_authority_failure(
                vm,
                arenas,
                backings,
                acknowledgements,
                claim,
                range,
                replacements,
                mirror_plan.as_deref_mut(),
                trigger,
            ));
        };
        let Some(mapping) = old.mapping.as_mut() else {
            continue;
        };
        let opposing = matches!(
            (mapping.authority, target),
            (StageTwoAuthority::Writer, StageTwoAuthority::Executor)
                | (StageTwoAuthority::Executor, StageTwoAuthority::Writer)
        );
        if opposing && let Err(error) = demote_data_mapping(backings, mapping) {
            return Err(protect_authority_failure(
                vm,
                arenas,
                backings,
                acknowledgements,
                claim,
                range,
                replacements,
                mirror_plan.as_deref_mut(),
                error,
            ));
        }
    }
    if target == StageTwoAuthority::Writer
        && let Err(error) =
            promote_replacement_authorities(vm, backings, range, replacements, permissions)
    {
        return Err(protect_authority_failure(
            vm,
            arenas,
            backings,
            acknowledgements,
            claim,
            range,
            replacements,
            mirror_plan.as_deref_mut(),
            error,
        ));
    }
    if let Some(plan) = mirror_plan.as_deref_mut()
        && let Err(error) = apply_mirror_plan(vm, arenas, backings, acknowledgements, plan)
    {
        return Err(protect_authority_failure(
            vm,
            arenas,
            backings,
            acknowledgements,
            claim,
            range,
            replacements,
            mirror_plan.as_deref_mut(),
            error,
        ));
    }
    if target == StageTwoAuthority::Executor {
        for gva in page_addresses(range) {
            let backing = replacements
                .get(&gva)
                .and_then(|page| page.mapping.as_ref())
                .map(|mapping| mapping.backing)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if let Err(error) = backings.prepare_executable_host(backing) {
                return Err(protect_authority_failure(
                    vm,
                    arenas,
                    backings,
                    acknowledgements,
                    claim,
                    range,
                    replacements,
                    mirror_plan.as_deref_mut(),
                    error,
                ));
            }
        }
    }
    if inject_failure {
        return Err(protect_authority_failure(
            vm,
            arenas,
            backings,
            acknowledgements,
            claim,
            range,
            replacements,
            mirror_plan.as_deref_mut(),
            HvfMemoryError::InjectedFailure("during protect authority transition"),
        ));
    }
    if target != StageTwoAuthority::Writer
        && let Err(error) =
            promote_replacement_authorities(vm, backings, range, replacements, permissions)
    {
        return Err(protect_authority_failure(
            vm,
            arenas,
            backings,
            acknowledgements,
            claim,
            range,
            replacements,
            mirror_plan,
            error,
        ));
    }
    Ok(())
}

fn prepare_fork_page(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    parent: &PageState,
    private_copies: &HashMap<HvfBackingIdentity, HvfBackingIdentity>,
) -> Result<PageState, HvfMemoryError> {
    let backing = match parent.backing {
        Some(backing) => {
            let identity = if parent.sharing == HvfSharing::Shared {
                backing.identity
            } else {
                *private_copies
                    .get(&backing.identity)
                    .ok_or(HvfMemoryError::IpaOwnership)?
            };
            Some(BackingPage {
                identity,
                offset: backing.offset,
            })
        }
        None => None,
    };
    arenas.slots.retain(parent.slot)?;
    if let Some(backing) = backing
        && let Err(trigger) = backings.retain(backing)
    {
        let cleanup = arenas.slots.release(parent.slot).map(|_| ());
        return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
    }
    let mapping = match backing {
        Some(backing) if parent.permissions != HvfGuestPermissions::NONE => {
            if parent.permissions.contains(HvfGuestPermissions::EXECUTE) {
                let publication = (|| {
                    let bytes = backings.page_range(backing)?;
                    vm.publish_executable_bytes(unsafe {
                        core::slice::from_raw_parts(bytes.start as *const u8, PAGE_SIZE)
                    })?;
                    Ok::<(), HvfMemoryError>(())
                })();
                if let Err(trigger) = publication {
                    let backing_cleanup = backings.release(backing).map(|_| ());
                    let slot_cleanup = arenas.slots.release(parent.slot).map(|_| ());
                    return Err(HvfMemoryError::with_cleanup(
                        trigger,
                        backing_cleanup.and(slot_cleanup),
                    ));
                }
            }
            match map_data_page(
                vm,
                arenas,
                backings,
                acknowledgements,
                backing,
                parent.permissions,
                true,
            ) {
                Ok(mapping) => Some(mapping),
                Err(trigger) => {
                    let cleanup = arenas.slots.release(parent.slot).map(|_| ());
                    return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
                }
            }
        }
        _ => None,
    };
    Ok(PageState {
        permissions: parent.permissions,
        sharing: parent.sharing,
        backing,
        mapping,
        slot: parent.slot,
    })
}

fn cleanup_data_mapping(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mapping: DataMapping,
    release_backing_reference: bool,
) -> Result<(), HvfMemoryError> {
    let DataMapping {
        backing,
        ipa,
        authority,
        mapping,
        quarantine_reservation,
    } = mapping;
    let Some(handle) = mapping else {
        let trigger = HvfMemoryError::IpaOwnership;
        let cleanup = commit_failed_data_mapping(
            vm,
            backings,
            acknowledgements,
            quarantine_reservation,
            backing,
            ipa,
            authority,
            None,
            release_backing_reference,
            false,
        );
        vm.poison();
        return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
    };
    let sdk_token = handle.token();
    let unmap = if arenas.take_failure(FailurePoint::DataUnmap) {
        handle.induce_unmap_failure()
    } else {
        handle.unmap()
    };
    if let Err(error) = unmap {
        let cleanup = commit_failed_data_mapping(
            vm,
            backings,
            acknowledgements,
            quarantine_reservation,
            backing,
            ipa,
            authority,
            Some(sdk_token),
            release_backing_reference,
            true,
        );
        vm.poison();
        return Err(HvfMemoryError::with_cleanup(error.into(), cleanup));
    }
    cleanup_data_allocation(
        vm,
        arenas,
        backings,
        acknowledgements,
        quarantine_reservation,
        backing,
        ipa,
        Some(authority),
        release_backing_reference,
    )
}

fn cleanup_unpublished_pages(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    pages: impl IntoIterator<Item = PageState>,
    release_slots: bool,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for page in pages {
        let backing = page.backing;
        // The permanent alias holds a host-writer authority on the backing
        // page; it has to go before the page's last reference can free it.
        if release_slots
            && let Err(error) =
                unmirror_for_release(vm, arenas, backings, acknowledgements, page.slot)
        {
            first_error.get_or_insert(error);
        }
        if let Some(mapping) = page.mapping {
            if let Err(error) = cleanup_data_mapping(
                vm,
                arenas,
                backings,
                acknowledgements,
                mapping,
                backing.is_some(),
            ) {
                first_error.get_or_insert(error);
            }
        } else if let Some(backing) = backing
            && let Err(error) = backings.release(backing)
        {
            first_error.get_or_insert(error);
        }
        if release_slots && let Err(error) = arenas.slots.release(page.slot) {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_unpublished_page_map(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mut pages: HashMap<usize, PageState>,
    release_slots: bool,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(gva) = pages.keys().copied().min() {
        let Some(page) = pages.remove(&gva) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        if let Err(error) = cleanup_unpublished_pages(
            vm,
            arenas,
            backings,
            acknowledgements,
            core::iter::once(page),
            release_slots,
        ) {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_replacements(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    old_backings: &HashMap<usize, Option<BackingPage>>,
    mut pages: HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(gva) = pages.keys().copied().min() {
        let Some(page) = pages.remove(&gva) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        let old_backing = if let Some(backing) = old_backings.get(&gva) {
            Some(*backing)
        } else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            None
        };
        let release_backing_reference = old_backing
            .is_some_and(|old_backing| page.backing.is_some() && page.backing != old_backing);
        if let Some(mapping) = page.mapping {
            if let Err(error) = cleanup_data_mapping(
                vm,
                arenas,
                backings,
                acknowledgements,
                mapping,
                release_backing_reference,
            ) {
                first_error.get_or_insert(error);
            }
        } else if release_backing_reference
            && let Some(backing) = page.backing
            && let Err(error) = backings.release(backing)
        {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn release_host_slots(
    slots: &mut HostSlotArena,
    tokens: impl IntoIterator<Item = HostSlotToken>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for token in tokens {
        if let Err(error) = slots.release(token) {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn release_backing_references(
    vm: &'static HvfVm,
    backings: &mut BackingRegistry,
    references: impl IntoIterator<Item = BackingPage>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for backing in references {
        if let Err(error) = backings.release(backing) {
            first_error.get_or_insert(error);
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_claim_preparation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    pages: HashMap<usize, PageState>,
    slots: impl IntoIterator<Item = HostSlotToken>,
    backing: Option<HvfBackingIdentity>,
) -> Result<(), HvfMemoryError> {
    let pages_cleanup =
        cleanup_unpublished_page_map(vm, arenas, backings, acknowledgements, pages, false);
    let slots_cleanup = release_host_slots(&mut arenas.slots, slots);
    let backing_cleanup = match backing {
        Some(identity) if backings.records.contains_key(&identity) => {
            backings.discard_unreferenced(identity).map(|_| ())
        }
        _ => Ok(()),
    };
    if pages_cleanup.is_err() || slots_cleanup.is_err() || backing_cleanup.is_err() {
        vm.poison();
    }
    pages_cleanup?;
    slots_cleanup?;
    backing_cleanup
}

#[expect(
    clippy::too_many_arguments,
    reason = "the locked arenas, backings and acknowledgements are separate guards held by the caller, passed alongside the operation's own inputs"
)]
fn cleanup_failed_protect(
    memory: &HvfMemory,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    reservation: Option<RetirementReservation>,
    retained_backings: Vec<BackingPage>,
    candidate: TableToken,
    old_backings: &HashMap<usize, Option<BackingPage>>,
    replacements: HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let reservation_cleanup = match reservation {
        Some(reservation) => memory.cancel_retirement_reservation(acknowledgements, reservation),
        None => Ok(()),
    };
    let backing_cleanup = release_backing_references(memory.vm, backings, retained_backings);
    let preparation_cleanup = cleanup_protect_preparation(
        memory.vm,
        arenas,
        backings,
        acknowledgements,
        candidate,
        old_backings,
        replacements,
    );
    if reservation_cleanup.is_err() || backing_cleanup.is_err() || preparation_cleanup.is_err() {
        memory.vm.poison();
    }
    reservation_cleanup?;
    backing_cleanup?;
    preparation_cleanup
}

fn cleanup_protect_preparation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    candidate: TableToken,
    old_backings: &HashMap<usize, Option<BackingPage>>,
    pages: HashMap<usize, PageState>,
) -> Result<(), HvfMemoryError> {
    let table_cleanup = cleanup_candidate_root(vm, arenas, candidate);
    let data_cleanup =
        cleanup_replacements(vm, arenas, backings, acknowledgements, old_backings, pages);
    table_cleanup?;
    data_cleanup
}

fn cleanup_claim_records(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mut claims: HashMap<usize, ClaimRecord>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(start) = claims.keys().copied().min() {
        let Some(mut claim) = claims.remove(&start) else {
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            continue;
        };
        for gva in page_addresses(&claim.range) {
            let Some(page) = claim.pages.remove(&gva) else {
                first_error.get_or_insert(HvfMemoryError::ClaimStale);
                continue;
            };
            if let Err(error) = cleanup_unpublished_pages(
                vm,
                arenas,
                backings,
                acknowledgements,
                core::iter::once(page),
                true,
            ) {
                first_error.get_or_insert(error);
            }
        }
        while let Some(gva) = claim.pages.keys().copied().min() {
            let page = claim.pages.remove(&gva).ok_or(HvfMemoryError::ClaimStale)?;
            first_error.get_or_insert(HvfMemoryError::ClaimStale);
            if let Err(error) = cleanup_unpublished_pages(
                vm,
                arenas,
                backings,
                acknowledgements,
                core::iter::once(page),
                true,
            ) {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn cleanup_private_copies(
    backings: &mut BackingRegistry,
    mut copies: HashMap<HvfBackingIdentity, HvfBackingIdentity>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    while let Some(source) = copies.keys().copied().min() {
        let copy = copies.remove(&source).ok_or(HvfMemoryError::IpaOwnership)?;
        if backings.records.contains_key(&copy)
            && let Err(error) = backings.discard_unreferenced(copy)
        {
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the locked arenas, backings and acknowledgements are separate guards held by the caller, passed alongside the operation's own inputs"
)]
fn cleanup_fork_preparation(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    child_claims: HashMap<usize, ClaimRecord>,
    private_copies: HashMap<HvfBackingIdentity, HvfBackingIdentity>,
    roots: impl IntoIterator<Item = TableToken>,
    asid: Option<HvfAsid>,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for root in roots {
        if let Err(error) = cleanup_candidate_root(vm, arenas, root) {
            first_error.get_or_insert(error);
        }
    }
    if let Err(error) = cleanup_claim_records(vm, arenas, backings, acknowledgements, child_claims)
    {
        first_error.get_or_insert(error);
    }
    if let Err(error) = cleanup_private_copies(backings, private_copies) {
        first_error.get_or_insert(error);
    }
    if let Some(asid) = asid
        && let Err(error) = arenas.asids.release(asid)
    {
        first_error.get_or_insert(error);
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn retry_aliases_locked(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    mark_published: impl FnOnce() -> Result<(), HvfError>,
) -> Result<usize, HvfMemoryError> {
    let mut restored = 0;
    let mut first_error = None;
    if !acknowledgements.alias_quarantine.is_empty() {
        mark_published()?;
    }
    let mut index = 0;
    let retry_limit = acknowledgements.alias_quarantine.len();
    let mut processed = 0usize;
    while index < acknowledgements.alias_quarantine.len() && processed < retry_limit {
        processed += 1;
        let slot = acknowledgements.alias_quarantine[index].slot;
        let valid = arenas.slots.records.get(&slot).is_some_and(|record| {
            acknowledgements.alias_quarantine[index]
                .physical_exposure
                .as_ref()
                .is_none_or(|exposure| {
                    record.gva == exposure.range.start
                        && exposure.range.end == exposure.range.start + PAGE_SIZE
                })
        });
        if !valid {
            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            index += 1;
            continue;
        }

        let restore_pending = acknowledgements.alias_quarantine[index]
            .physical_exposure
            .as_ref()
            .is_some_and(|exposure| exposure.restore_pending);
        if restore_pending {
            let restore = arenas
                .slots
                .records
                .get(&slot)
                .and_then(|record| record.slot.as_ref())
                .ok_or(HvfMemoryError::IpaOwnership)
                .and_then(|slot| slot.restore().map_err(Into::into));
            if let Err(error) = restore {
                first_error.get_or_insert(error);
                index += 1;
                continue;
            }
            if let Some(exposure) = acknowledgements.alias_quarantine[index]
                .physical_exposure
                .as_mut()
            {
                exposure.restore_pending = false;
            }
        }

        let writer = acknowledgements.alias_quarantine[index]
            .physical_exposure
            .as_ref()
            .and_then(|exposure| exposure.host_writer.then_some(exposure.backing));
        if let Some(backing) = writer {
            if let Err(error) = backings.release_host_alias(backing, true) {
                first_error.get_or_insert(error);
                index += 1;
                continue;
            }
            if let Some(exposure) = acknowledgements.alias_quarantine[index]
                .physical_exposure
                .as_mut()
            {
                exposure.host_writer = false;
            }
        }

        let pin = acknowledgements.alias_quarantine[index]
            .physical_exposure
            .as_ref()
            .and_then(|exposure| exposure.backing_pin.then_some(exposure.backing));
        if let Some(backing) = pin {
            if let Err(error) = backings.release_reference(backing) {
                first_error.get_or_insert(error);
                index += 1;
                continue;
            }
            if let Some(exposure) = acknowledgements.alias_quarantine[index]
                .physical_exposure
                .as_mut()
            {
                exposure.backing_pin = false;
            }
            if let Err(error) = backings.reap_if_unowned(backing) {
                first_error.get_or_insert(error);
            }
        }

        let exposure_settled = acknowledgements.alias_quarantine[index]
            .physical_exposure
            .as_ref()
            .is_none_or(|exposure| {
                !exposure.restore_pending && !exposure.host_writer && !exposure.backing_pin
            });
        if exposure_settled {
            acknowledgements.alias_quarantine[index].physical_exposure = None;
        }

        if let Some(recovery) = acknowledgements.alias_quarantine[index]
            .recovery_mirror
            .take()
        {
            if !recovery.backing_pin {
                first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                acknowledgements.alias_quarantine[index].recovery_mirror = Some(recovery);
                index += 1;
                continue;
            }
            let references = arenas
                .slots
                .records
                .get(&slot)
                .map(|record| record.references)
                .ok_or(HvfMemoryError::IpaOwnership)?;
            if references == 0 {
                match backings.release_reference(recovery.descriptor.backing) {
                    Ok(()) => {
                        if let Err(error) = backings.reap_if_unowned(recovery.descriptor.backing) {
                            first_error.get_or_insert(error);
                        }
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                        acknowledgements.alias_quarantine[index].recovery_mirror = Some(recovery);
                        index += 1;
                        continue;
                    }
                }
            } else {
                let range = arenas
                    .slots
                    .records
                    .get(&slot)
                    .map(|record| record.gva..record.gva + PAGE_SIZE)
                    .ok_or(HvfMemoryError::IpaOwnership)?;
                let descriptor = recovery.descriptor;
                let mut recovery_pin = true;
                match install_mirror(
                    vm,
                    arenas,
                    backings,
                    acknowledgements,
                    slot,
                    descriptor,
                    range.clone(),
                    Some(descriptor),
                    &mut recovery_pin,
                ) {
                    Ok(()) => {
                        match backings.release_reference(descriptor.backing) {
                            Ok(()) => {
                                recovery_pin = false;
                                if let Err(error) = backings.reap_if_unowned(descriptor.backing) {
                                    first_error.get_or_insert(error);
                                }
                            }
                            Err(error) => {
                                first_error.get_or_insert(error);
                            }
                        }
                        if recovery_pin {
                            acknowledgements.alias_quarantine[index].physical_exposure =
                                Some(AliasPhysicalExposure {
                                    backing: descriptor.backing,
                                    range,
                                    restore_pending: false,
                                    host_writer: false,
                                    backing_pin: true,
                                });
                            index += 1;
                            continue;
                        }
                    }
                    Err(error) => {
                        first_error.get_or_insert(error);
                        if recovery_pin {
                            acknowledgements.alias_quarantine[index].recovery_mirror =
                                Some(RecoveryMirror {
                                    descriptor,
                                    backing_pin: true,
                                });
                            index += 1;
                        } else {
                            acknowledgements.alias_quarantine.remove(index);
                        }
                        continue;
                    }
                }
            }
        }

        if acknowledgements.alias_quarantine[index]
            .physical_exposure
            .is_some()
        {
            index += 1;
            continue;
        }
        if let Err(error) = arenas.slots.update(slot, |record| {
            record.active = false;
            record.alias_quarantined = false;
        }) {
            first_error.get_or_insert(error);
            index += 1;
            continue;
        }
        acknowledgements.alias_quarantine.remove(index);
        restored += 1;
        match arenas.slots.reap_if_unowned(slot) {
            Ok(_) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(restored),
    }
}

fn quarantine_alias_page(
    arenas: &mut Arenas,
    acknowledgements: &mut Acknowledgements,
    page: &mut AliasLeasePage,
    restore_pending: bool,
) {
    let _ = arenas
        .slots
        .update(page.slot, |record| record.alias_quarantined = true);
    acknowledgements.alias_quarantine.push(AliasQuarantine {
        slot: page.slot,
        physical_exposure: Some(AliasPhysicalExposure {
            backing: page.backing,
            range: page.range.clone(),
            restore_pending,
            host_writer: core::mem::take(&mut page.host_writer),
            backing_pin: core::mem::take(&mut page.backing_pin),
        }),
        recovery_mirror: None,
    });
    page.exposure_installed = false;
}

fn restore_installed_aliases(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    installed: &mut [AliasLeasePage],
    inject_first_failure: bool,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for (index, page) in installed.iter_mut().enumerate().rev() {
        let owned = arenas
            .slots
            .records
            .get(&page.slot)
            .and_then(|record| record.slot.as_ref())
            .is_some_and(HvfHostSlot::is_owned);
        if page.exposure_installed && owned {
            // `alias_from` failed but restored its own reservation.
            page.exposure_installed = false;
        }
        if page.exposure_installed {
            let result = arenas
                .slots
                .records
                .get(&page.slot)
                .and_then(|record| record.slot.as_ref())
                .ok_or(HvfHostBackingError::Restore(-1))
                .and_then(|slot| {
                    if inject_first_failure && index == 0 {
                        Err(HvfHostBackingError::Restore(-1))
                    } else {
                        slot.restore()
                    }
                });
            if let Err(error) = result {
                quarantine_alias_page(arenas, acknowledgements, page, true);
                vm.poison();
                first_error.get_or_insert(error.into());
                continue;
            }
            page.exposure_installed = false;
        }
        if page.host_writer {
            if let Err(error) = backings.release_host_alias(page.backing, true) {
                quarantine_alias_page(arenas, acknowledgements, page, false);
                vm.poison();
                first_error.get_or_insert(error);
                continue;
            }
            page.host_writer = false;
        }
        if page.backing_pin {
            if let Err(error) = backings.release_reference(page.backing) {
                quarantine_alias_page(arenas, acknowledgements, page, false);
                vm.poison();
                first_error.get_or_insert(error);
                continue;
            }
            page.backing_pin = false;
            if let Err(error) = backings.reap_if_unowned(page.backing) {
                vm.poison();
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = arenas.slots.update(page.slot, |record| {
            record.active = false;
            record.alias_quarantined = false;
        }) {
            vm.poison();
            first_error.get_or_insert(error);
            continue;
        }
        if let Err(error) = arenas.slots.reap_if_unowned(page.slot) {
            vm.poison();
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Where a claim's pages come from: fresh zeroed private/shared pages, or a
/// window of an existing pinned shared object starting at `first_page`.
#[derive(Clone, Copy)]
enum ClaimSource {
    Fresh,
    Shared {
        identity: HvfBackingIdentity,
        first_page: usize,
    },
}

/// The host view a mirrored page must present: its backing with host WRITE
/// exactly when the guest may write, `None` (a `PROT_NONE` reservation) for
/// sparse or `PROT_NONE` pages. EXECUTE never reaches the host.
fn mirror_state_for(page: &PageState) -> Option<MirrorState> {
    if page.permissions == HvfGuestPermissions::NONE {
        return None;
    }
    page.backing.map(|backing| MirrorState {
        backing,
        write: page.permissions.contains(HvfGuestPermissions::WRITE),
    })
}

struct MirrorPlanEntry {
    slot: HostSlotToken,
    previous: Option<MirrorState>,
    desired: Option<MirrorState>,
    /// Extra exact pin held until commit, or transferred into the restored
    /// previous mirror/quarantine during rollback.
    previous_pin: bool,
    applied: bool,
}

/// One transaction's worth of mirror transitions, with the alias-quarantine
/// capacity every entry might need on a failed restore reserved up front.
struct MirrorPlan {
    entries: Vec<MirrorPlanEntry>,
    reserved: usize,
    committed: bool,
}

struct MirrorPlanResidual {
    entries: Vec<MirrorPlanEntry>,
    reserved: usize,
    committed: bool,
}

static PROCESS_MIRROR_PLAN_RESIDUAL: Mutex<Option<MirrorPlanResidual>> = Mutex::new(None);

impl MirrorPlan {
    fn commit(&mut self) {
        self.committed = true;
        for entry in &mut self.entries {
            entry.applied = false;
        }
    }

    fn owns_custody(&self) -> bool {
        self.reserved != 0
            || self
                .entries
                .iter()
                .any(|entry| entry.previous_pin || (!self.committed && entry.applied))
    }
}

impl Drop for MirrorPlan {
    fn drop(&mut self) {
        if !self.owns_custody() {
            return;
        }
        let residual = MirrorPlanResidual {
            entries: core::mem::take(&mut self.entries),
            reserved: core::mem::take(&mut self.reserved),
            committed: self.committed,
        };
        let mut slot = PROCESS_MIRROR_PLAN_RESIDUAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            std::process::abort();
        }
        *slot = Some(residual);
    }
}

fn plan_mirror(
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    count: usize,
    items: impl IntoIterator<Item = (HostSlotToken, Option<MirrorState>)>,
) -> Result<MirrorPlan, HvfMemoryError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| HvfMemoryError::MetadataAllocation("mirror plan"))?;
    for (slot, desired) in items {
        if entries.len() == count {
            return Err(HvfMemoryError::IpaOwnership);
        }
        let record = arenas
            .slots
            .records
            .get(&slot)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if record.alias_quarantined || record.release_quarantined {
            return Err(HvfMemoryError::AliasRestore(
                record.gva..record.gva + PAGE_SIZE,
            ));
        }
        if !record.mirrored || record.mirror.is_some() != record.mirror_backing_pin {
            return Err(HvfMemoryError::MirrorSlotShared(
                record.gva..record.gva + PAGE_SIZE,
            ));
        }
        entries.push(MirrorPlanEntry {
            slot,
            previous: record.mirror,
            desired,
            previous_pin: false,
            applied: false,
        });
    }
    if entries.len() != count {
        return Err(HvfMemoryError::IpaOwnership);
    }
    entries.sort_unstable_by_key(|entry| entry.slot.0);
    if entries
        .windows(2)
        .any(|entries| entries[0].slot == entries[1].slot)
    {
        return Err(HvfMemoryError::IpaOwnership);
    }
    acknowledgements.reserve_alias_quarantine(entries.len())?;
    let mut plan = MirrorPlan {
        reserved: entries.len(),
        entries,
        committed: false,
    };
    for index in 0..plan.entries.len() {
        let previous = plan.entries[index].previous;
        if previous == plan.entries[index].desired || previous.is_none() {
            continue;
        }
        let previous = previous.ok_or(HvfMemoryError::IpaOwnership)?;
        if let Err(trigger) = backings.retain(previous.backing) {
            let mut cleanup_error = None;
            for entry in plan.entries[..index].iter_mut().rev() {
                if entry.previous_pin
                    && let Some(previous) = entry.previous
                {
                    if let Err(error) = backings.release_reference(previous.backing) {
                        let range = arenas
                            .slots
                            .records
                            .get(&entry.slot)
                            .map(|record| record.gva..record.gva + PAGE_SIZE)
                            .unwrap_or(0..0);
                        let _ = arenas
                            .slots
                            .update(entry.slot, |record| record.alias_quarantined = true);
                        acknowledgements.alias_quarantine.push(AliasQuarantine {
                            slot: entry.slot,
                            physical_exposure: Some(AliasPhysicalExposure {
                                backing: previous.backing,
                                range,
                                restore_pending: false,
                                host_writer: false,
                                backing_pin: true,
                            }),
                            recovery_mirror: None,
                        });
                        entry.previous_pin = false;
                        cleanup_error.get_or_insert(error);
                    } else {
                        entry.previous_pin = false;
                        if let Err(error) = backings.reap_if_unowned(previous.backing) {
                            cleanup_error.get_or_insert(error);
                        }
                    }
                }
            }
            match acknowledgements.release_alias_quarantine_reservation(plan.reserved) {
                Ok(()) => plan.reserved = 0,
                Err(error) => {
                    cleanup_error.get_or_insert(error);
                }
            }
            return Err(match cleanup_error {
                Some(cleanup) => HvfMemoryError::finalization(trigger, cleanup),
                None => trigger,
            });
        }
        plan.entries[index].previous_pin = true;
    }
    Ok(plan)
}

/// Applies every entry in order; on the first failure the entries already
/// applied are put back and the trigger (or the rollback's own failure) is
/// returned, so the plan is all-or-nothing.
fn apply_mirror_plan(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    plan: &mut MirrorPlan,
) -> Result<(), HvfMemoryError> {
    for index in 0..plan.entries.len() {
        let entry = &mut plan.entries[index];
        if entry.previous == entry.desired {
            continue;
        }
        if let Err(error) = transition_mirror(
            vm,
            arenas,
            backings,
            acknowledgements,
            entry.slot,
            entry.desired,
            entry.previous,
            &mut entry.previous_pin,
        ) {
            let rollback = rollback_mirror_plan(vm, arenas, backings, acknowledgements, plan);
            return Err(HvfMemoryError::with_cleanup(error, rollback));
        }
        entry.applied = true;
    }
    Ok(())
}

fn rollback_mirror_plan(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    plan: &mut MirrorPlan,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for entry in plan.entries.iter_mut().rev() {
        if !entry.applied {
            continue;
        }
        let restored = arenas.slots.records.get(&entry.slot).is_some_and(|record| {
            !record.alias_quarantined
                && !record.release_quarantined
                && record.mirror == entry.previous
                && record.mirror_backing_pin == entry.previous.is_some()
        });
        if restored {
            entry.applied = false;
            continue;
        }
        match transition_mirror(
            vm,
            arenas,
            backings,
            acknowledgements,
            entry.slot,
            entry.previous,
            entry.previous,
            &mut entry.previous_pin,
        ) {
            Ok(()) => entry.applied = false,
            Err(error) => {
                vm.poison();
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn finish_mirror_plan(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    plan: &mut MirrorPlan,
) -> Result<(), HvfMemoryError> {
    let mut first_error = None;
    for entry in &mut plan.entries {
        if (!plan.committed && entry.applied) || !entry.previous_pin {
            continue;
        }
        let Some(previous) = entry.previous else {
            first_error.get_or_insert(HvfMemoryError::IpaOwnership);
            continue;
        };
        match backings.release_reference(previous.backing) {
            Ok(()) => {
                entry.previous_pin = false;
                if let Err(error) = backings.reap_if_unowned(previous.backing) {
                    first_error.get_or_insert(error);
                }
            }
            Err(error) => {
                let range = arenas
                    .slots
                    .records
                    .get(&entry.slot)
                    .map(|record| record.gva..record.gva + PAGE_SIZE);
                match range {
                    Some(range) => {
                        let _ = arenas
                            .slots
                            .update(entry.slot, |record| record.alias_quarantined = true);
                        acknowledgements.alias_quarantine.push(AliasQuarantine {
                            slot: entry.slot,
                            physical_exposure: Some(AliasPhysicalExposure {
                                backing: previous.backing,
                                range,
                                restore_pending: false,
                                host_writer: false,
                                backing_pin: true,
                            }),
                            recovery_mirror: None,
                        });
                        entry.previous_pin = false;
                    }
                    None => {
                        first_error.get_or_insert(HvfMemoryError::IpaOwnership);
                    }
                }
                first_error.get_or_insert(error);
            }
        }
    }
    let rollback_pending = !plan.committed && plan.entries.iter().any(|entry| entry.applied);
    if !rollback_pending {
        if let Err(error) = acknowledgements.release_alias_quarantine_reservation(plan.reserved) {
            first_error.get_or_insert(error);
        } else {
            plan.reserved = 0;
        }
    }
    if first_error.is_some() {
        vm.poison();
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn retry_mirror_plan_residual(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
) -> Result<bool, HvfMemoryError> {
    let residual = PROCESS_MIRROR_PLAN_RESIDUAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(residual) = residual else {
        return Ok(false);
    };
    let mut plan = MirrorPlan {
        entries: residual.entries,
        reserved: residual.reserved,
        committed: residual.committed,
    };
    let rollback = if plan.committed {
        Ok(())
    } else {
        rollback_mirror_plan(vm, arenas, backings, acknowledgements, &mut plan)
    };
    let finish = finish_mirror_plan(vm, arenas, backings, acknowledgements, &mut plan);
    match rollback {
        Ok(()) => finish.map(|()| true),
        Err(trigger) => Err(HvfMemoryError::with_cleanup(trigger, finish)),
    }
}

fn mirror_slot(arenas: &Arenas, token: HostSlotToken) -> Result<&HvfHostSlot, HvfMemoryError> {
    arenas
        .slots
        .records
        .get(&token)
        .and_then(|record| record.slot.as_ref())
        .ok_or(HvfMemoryError::IpaOwnership)
}

/// Drops `token`'s permanent mirror from the ledger, returning whether it
/// held the exact backing pin the mirror owned.
fn take_mirror_pin(arenas: &mut Arenas, token: HostSlotToken) -> Result<bool, HvfMemoryError> {
    arenas.slots.update(token, |record| {
        record.mirror = None;
        core::mem::take(&mut record.mirror_backing_pin)
    })
}

fn queue_mirror_quarantine(
    arenas: &mut Arenas,
    acknowledgements: &mut Acknowledgements,
    token: HostSlotToken,
    physical_exposure: Option<AliasPhysicalExposure>,
    recovery: Option<MirrorState>,
    recovery_pin: &mut bool,
) -> Result<(), HvfMemoryError> {
    if recovery.is_some() != *recovery_pin {
        return Err(HvfMemoryError::IpaOwnership);
    }
    arenas.slots.update(token, |record| {
        record.alias_quarantined = true;
        record.mirror = None;
        record.mirror_backing_pin = false;
    })?;
    let recovery_mirror = recovery.map(|descriptor| {
        *recovery_pin = false;
        RecoveryMirror {
            descriptor,
            backing_pin: true,
        }
    });
    acknowledgements.alias_quarantine.push(AliasQuarantine {
        slot: token,
        physical_exposure,
        recovery_mirror,
    });
    Ok(())
}

/// Moves one slot's permanent alias from whatever it shows now to `desired`.
/// `failure_recovery` has an independent exact backing pin and is transferred
/// to quarantine if the transition becomes physically uncertain.
///
/// A failure that leaves the host physical protection state itself unknown
/// (`restore_pending: true` on the queued quarantine, below) poisons the VM
/// immediately: the entry stays `applied == false`, so `rollback_mirror_plan`
/// will never revisit it, and the caller's own abort/cleanup can still
/// succeed and return a plain error with no poison of its own -- silently
/// leaving the claim "live" while its host GVA is physically uncertain.
#[expect(
    clippy::too_many_arguments,
    reason = "the locked arenas, backings and acknowledgements are separate guards held by the caller, passed alongside the operation's own inputs"
)]
fn transition_mirror(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    token: HostSlotToken,
    desired: Option<MirrorState>,
    failure_recovery: Option<MirrorState>,
    recovery_pin: &mut bool,
) -> Result<(), HvfMemoryError> {
    let (gva, current, alias_quarantined, release_quarantined, has_slot, mirror_pin) = {
        let record = arenas
            .slots
            .records
            .get(&token)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        (
            record.gva,
            record.mirror,
            record.alias_quarantined,
            record.release_quarantined,
            record.slot.is_some(),
            record.mirror_backing_pin,
        )
    };
    let range = gva..gva + PAGE_SIZE;
    if alias_quarantined || release_quarantined {
        return Err(HvfMemoryError::AliasRestore(range));
    }
    if !has_slot || current.is_some() != mirror_pin {
        return Err(HvfMemoryError::IpaOwnership);
    }
    if failure_recovery.is_some() != *recovery_pin {
        return Err(HvfMemoryError::IpaOwnership);
    }
    match (current, desired) {
        (None, None) => Ok(()),
        (Some(current), Some(target)) if current == target => Ok(()),
        (Some(current), Some(target)) if current.backing == target.backing => {
            let mut host_writer = current.write;
            if target.write && !current.write {
                backings.reserve_host_alias(target.backing, true)?;
                host_writer = true;
            }
            if let Err(trigger) =
                mirror_slot(arenas, token)?.protect_alias(target.host_permissions())
            {
                let pin = take_mirror_pin(arenas, token)?;
                let cleanup = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    Some(AliasPhysicalExposure {
                        backing: current.backing,
                        range,
                        restore_pending: true,
                        host_writer,
                        backing_pin: pin,
                    }),
                    failure_recovery,
                    recovery_pin,
                );
                // Host physical protection state is now unknown: terminal
                // poison, not just an annotated error, or the VM stays
                // runnable on an uncertain alias.
                vm.poison();
                return Err(HvfMemoryError::with_cleanup(trigger.into(), cleanup));
            }
            if current.write
                && !target.write
                && let Err(trigger) = backings.release_host_alias(current.backing, true)
            {
                let pin = take_mirror_pin(arenas, token)?;
                let cleanup = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    Some(AliasPhysicalExposure {
                        backing: current.backing,
                        range,
                        restore_pending: true,
                        host_writer: true,
                        backing_pin: pin,
                    }),
                    failure_recovery,
                    recovery_pin,
                );
                vm.poison();
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }
            arenas
                .slots
                .update(token, |record| record.mirror = Some(target))?;
            Ok(())
        }
        (Some(current), target) => {
            if let Err(trigger) = mirror_slot(arenas, token)?.restore() {
                let pin = take_mirror_pin(arenas, token)?;
                let cleanup = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    Some(AliasPhysicalExposure {
                        backing: current.backing,
                        range,
                        restore_pending: true,
                        host_writer: current.write,
                        backing_pin: pin,
                    }),
                    failure_recovery,
                    recovery_pin,
                );
                vm.poison();
                return Err(HvfMemoryError::with_cleanup(trigger.into(), cleanup));
            }
            let pin = take_mirror_pin(arenas, token)?;
            if !pin {
                return Err(HvfMemoryError::IpaOwnership);
            }
            if current.write
                && let Err(trigger) = backings.release_host_alias(current.backing, true)
            {
                let cleanup = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    Some(AliasPhysicalExposure {
                        backing: current.backing,
                        range,
                        restore_pending: false,
                        host_writer: true,
                        backing_pin: pin,
                    }),
                    failure_recovery,
                    recovery_pin,
                );
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }
            if let Err(trigger) = backings.release_reference(current.backing) {
                let cleanup = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    Some(AliasPhysicalExposure {
                        backing: current.backing,
                        range,
                        restore_pending: false,
                        host_writer: false,
                        backing_pin: true,
                    }),
                    failure_recovery,
                    recovery_pin,
                );
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }
            if let Err(trigger) = backings.reap_if_unowned(current.backing) {
                let cleanup = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    None,
                    failure_recovery,
                    recovery_pin,
                );
                return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
            }
            match target {
                None => Ok(()),
                Some(target) => install_mirror(
                    vm,
                    arenas,
                    backings,
                    acknowledgements,
                    token,
                    target,
                    range,
                    failure_recovery,
                    recovery_pin,
                ),
            }
        }
        (None, Some(target)) => install_mirror(
            vm,
            arenas,
            backings,
            acknowledgements,
            token,
            target,
            range,
            failure_recovery,
            recovery_pin,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn install_mirror(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    token: HostSlotToken,
    target: MirrorState,
    range: Range<usize>,
    failure_recovery: Option<MirrorState>,
    recovery_pin: &mut bool,
) -> Result<(), HvfMemoryError> {
    backings.page_storage(target.backing)?;
    backings.retain(target.backing)?;
    let mut backing_pin = true;
    if let Err(trigger) = backings.reserve_host_alias(target.backing, target.write) {
        let cleanup = backings
            .release_reference(target.backing)
            .and_then(|()| backings.reap_if_unowned(target.backing).map(|_| ()));
        return Err(HvfMemoryError::with_cleanup(trigger, cleanup));
    }
    let mut host_writer = target.write;
    let alias = {
        let storage = backings.page_storage(target.backing)?;
        mirror_slot(arenas, token)?.alias_from(storage, 0, target.host_permissions())
    };
    match alias {
        Ok(()) => arenas.slots.update(token, |record| {
            record.mirror = Some(target);
            record.mirror_backing_pin = true;
        }),
        Err(trigger) => {
            let owned = mirror_slot(arenas, token).is_ok_and(HvfHostSlot::is_owned);
            let mut first_cleanup = None;
            if owned {
                if host_writer {
                    match backings.release_host_alias(target.backing, true) {
                        Ok(()) => host_writer = false,
                        Err(error) => {
                            first_cleanup.get_or_insert(error);
                        }
                    }
                }
                if !host_writer && backing_pin {
                    match backings.release_reference(target.backing) {
                        Ok(()) => {
                            backing_pin = false;
                            if let Err(error) = backings.reap_if_unowned(target.backing) {
                                first_cleanup.get_or_insert(error);
                            }
                        }
                        Err(error) => {
                            first_cleanup.get_or_insert(error);
                        }
                    }
                }
            }
            let needs_quarantine =
                !owned || host_writer || backing_pin || failure_recovery.is_some();
            if needs_quarantine {
                let exposure =
                    (!owned || host_writer || backing_pin).then_some(AliasPhysicalExposure {
                        backing: target.backing,
                        range,
                        restore_pending: !owned,
                        host_writer,
                        backing_pin,
                    });
                if let Err(error) = queue_mirror_quarantine(
                    arenas,
                    acknowledgements,
                    token,
                    exposure,
                    failure_recovery,
                    recovery_pin,
                ) {
                    first_cleanup.get_or_insert(error);
                }
            }
            if !owned {
                // The slot itself could not be confirmed back to a known
                // PROT_NONE reservation: host physical protection state is
                // uncertain, matching transition_mirror's own poison
                // discipline for the same class of failure.
                vm.poison();
            }
            let trigger = HvfMemoryError::from(trigger);
            Err(match first_cleanup {
                Some(cleanup) => HvfMemoryError::finalization(trigger, cleanup),
                None => trigger,
            })
        }
    }
}

/// Tears down a slot's permanent alias ahead of releasing the slot outside a
/// planned transaction (address-space destroy). Failure poisons: the slot is
/// then quarantined for `retry_quarantined_resources`.
fn unmirror_for_release(
    vm: &'static HvfVm,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    token: HostSlotToken,
) -> Result<(), HvfMemoryError> {
    let record = arenas
        .slots
        .records
        .get(&token)
        .ok_or(HvfMemoryError::IpaOwnership)?;
    if record.mirror.is_some() != record.mirror_backing_pin {
        return Err(HvfMemoryError::IpaOwnership);
    }
    if record.mirror.is_none() {
        return Ok(());
    }
    acknowledgements.reserve_alias_quarantine(1)?;
    let mut recovery_pin = false;
    let result = transition_mirror(
        vm,
        arenas,
        backings,
        acknowledgements,
        token,
        None,
        None,
        &mut recovery_pin,
    );
    let release = acknowledgements.release_alias_quarantine_reservation(1);
    if result.is_err() {
        vm.poison();
    }
    match result {
        Ok(()) => release,
        Err(trigger) => Err(HvfMemoryError::with_cleanup(trigger, release)),
    }
}

#[allow(clippy::too_many_arguments)]
fn abort_claim_after_candidate(
    memory: &HvfMemory,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    candidate: TableToken,
    pages: HashMap<usize, PageState>,
    slots: Vec<HostSlotToken>,
    backing: Option<HvfBackingIdentity>,
    mirror_plan: Option<&mut MirrorPlan>,
) -> Result<(), HvfMemoryError> {
    let mirror_cleanup = match mirror_plan {
        Some(plan) => {
            let rollback =
                rollback_mirror_plan(memory.vm, arenas, backings, acknowledgements, plan);
            let finish = finish_mirror_plan(memory.vm, arenas, backings, acknowledgements, plan);
            rollback.and(finish)
        }
        None => Ok(()),
    };
    let candidate_cleanup = cleanup_candidate_root(memory.vm, arenas, candidate);
    let preparation_cleanup = cleanup_claim_preparation(
        memory.vm,
        arenas,
        backings,
        acknowledgements,
        pages,
        slots,
        backing,
    );
    mirror_cleanup?;
    candidate_cleanup?;
    preparation_cleanup
}

fn abort_unmap_after_candidate(
    memory: &HvfMemory,
    arenas: &mut Arenas,
    backings: &mut BackingRegistry,
    acknowledgements: &mut Acknowledgements,
    candidate: TableToken,
    mirror_plan: Option<&mut MirrorPlan>,
    reservation: Option<RetirementReservation>,
) -> Result<(), HvfMemoryError> {
    let mirror_cleanup = match mirror_plan {
        Some(plan) => {
            let rollback =
                rollback_mirror_plan(memory.vm, arenas, backings, acknowledgements, plan);
            let finish = finish_mirror_plan(memory.vm, arenas, backings, acknowledgements, plan);
            rollback.and(finish)
        }
        None => Ok(()),
    };
    let cancellation = match reservation {
        Some(reservation) => memory.cancel_retirement_reservation(acknowledgements, reservation),
        None => Ok(()),
    };
    let cleanup = cleanup_candidate_root(memory.vm, arenas, candidate);
    mirror_cleanup?;
    cancellation?;
    cleanup
}

fn ensure_aliases_inactive(
    claim: &ClaimRecord,
    range: &Range<usize>,
    slots: &HostSlotArena,
) -> Result<(), HvfMemoryError> {
    for gva in page_addresses(range) {
        let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
        let slot = slots
            .records
            .get(&page.slot)
            .ok_or(HvfMemoryError::IpaOwnership)?;
        if slot.active || slot.alias_quarantined || slot.release_quarantined {
            return Err(HvfMemoryError::AliasBusy(gva..gva + PAGE_SIZE));
        }
    }
    Ok(())
}

fn validate_publication(
    manager: u64,
    address_space: HvfAddressSpaceId,
    claim: &ClaimRecord,
    range: &Range<usize>,
    publication: Option<&HvfPublicationTicket>,
    backings: &BackingRegistry,
) -> Result<(), HvfMemoryError> {
    let ticket = publication.ok_or_else(|| HvfMemoryError::PublicationRequired(range.clone()))?;
    if ticket.manager != manager
        || ticket.address_space != address_space
        || ticket.claim_id != claim.id
        || ticket.claim_version != claim.version
        || ticket.range != *range
    {
        return Err(HvfMemoryError::PublicationStale(range.clone()));
    }
    if ticket.pages.len() != range.len() / PAGE_SIZE {
        return Err(HvfMemoryError::PublicationStale(range.clone()));
    }
    for (gva, published) in page_addresses(range).zip(&ticket.pages) {
        let page = claim.pages.get(&gva).ok_or(HvfMemoryError::ClaimStale)?;
        let backing = page
            .backing
            .ok_or_else(|| HvfMemoryError::PublicationRequired(range.clone()))?;
        let epoch = backings.page_epoch(backing)?;
        if published.backing != backing
            || published.write_epoch != epoch.write
            || published.publication_epoch != epoch.publication
            || epoch.publication.0 < epoch.write.0
            || published.publication_epoch.0 != published.write_epoch.0
        {
            return Err(HvfMemoryError::PublicationStale(range.clone()));
        }
    }
    Ok(())
}

fn coalesced_ledger(
    state: &AddressSpaceState,
    backings: &BackingRegistry,
) -> Result<Vec<HvfLedgerEntry>, HvfMemoryError> {
    let page_count = state.claims.values().try_fold(0usize, |count, claim| {
        count
            .checked_add(claim.pages.len())
            .ok_or(HvfMemoryError::IpaOwnership)
    })?;
    let mut pages = Vec::<(usize, &PageState)>::new();
    pages
        .try_reserve_exact(page_count)
        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger page order"))?;
    pages.extend(
        state
            .claims
            .values()
            .flat_map(|claim| claim.pages.iter().map(|(&gva, page)| (gva, page))),
    );
    pages.sort_unstable_by_key(|(gva, _)| *gva);
    let mut entries = Vec::<HvfLedgerEntry>::new();
    entries
        .try_reserve_exact(page_count)
        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger entries"))?;
    for (gva, page) in pages {
        let epoch = match page.backing {
            Some(backing) => backings.page_epoch(backing)?,
            None => PageEpoch {
                write: HvfWriteEpoch(0),
                publication: HvfPublicationEpoch(0),
            },
        };
        let sharing = match page.backing {
            Some(backing) => backings.sharing(backing.identity)?,
            None => page.sharing,
        };
        let entry = HvfLedgerEntry {
            gva: gva..gva + PAGE_SIZE,
            permissions: page.permissions,
            sharing,
            backing_identity: page.backing.map(|backing| backing.identity),
            backing_offset: page.backing.map_or(0, |backing| backing.offset),
            ipa: {
                let mut ipa = Vec::new();
                if let Some(mapping) = page.mapping.as_ref() {
                    ipa.try_reserve_exact(1)
                        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger IPA ranges"))?;
                    ipa.push(mapping.ipa.range());
                }
                ipa
            },
            write_epoch: epoch.write,
            publication_epoch: epoch.publication,
        };
        if let Some(previous) = entries.last_mut()
            && can_coalesce(previous, &entry)
        {
            previous.gva.end = entry.gva.end;
            for ipa in entry.ipa {
                if let Some(previous_ipa) = previous.ipa.last_mut()
                    && previous_ipa.end == ipa.start
                {
                    previous_ipa.end = ipa.end;
                } else {
                    previous
                        .ipa
                        .try_reserve(1)
                        .map_err(|_| HvfMemoryError::MetadataAllocation("ledger IPA ranges"))?;
                    previous.ipa.push(ipa);
                }
            }
            continue;
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn can_coalesce(left: &HvfLedgerEntry, right: &HvfLedgerEntry) -> bool {
    left.gva.end == right.gva.start
        && left.permissions == right.permissions
        && left.sharing == right.sharing
        && left.backing_identity == right.backing_identity
        && match left.backing_identity {
            Some(_) => left.backing_offset + left.gva.len() == right.backing_offset,
            None => true,
        }
        && left.write_epoch == right.write_epoch
        && left.publication_epoch == right.publication_epoch
}

/// A failed [`swap_claim_pages`]: the error and the replacement pages it did not install, boxed
/// to keep the `Result` small.
type SwapClaimPagesError = Box<(HvfMemoryError, HashMap<usize, PageState>)>;

/// A failed [`split_claim_for_unmap`]: the error and the claim record it hands back, boxed to
/// keep the `Result` small.
type SplitClaimError = Box<(HvfMemoryError, ClaimRecord)>;

fn swap_claim_pages(
    claim: &mut ClaimRecord,
    range: &Range<usize>,
    mut replacements: HashMap<usize, PageState>,
    mut old_pages: Vec<(usize, PageState)>,
) -> Result<Vec<(usize, PageState)>, SwapClaimPagesError> {
    if old_pages.capacity() < replacements.len()
        || page_addresses(range).any(|gva| !claim.pages.contains_key(&gva))
    {
        return Err(Box::new((HvfMemoryError::ClaimStale, replacements)));
    }
    for gva in page_addresses(range) {
        let Some(replacement) = replacements.remove(&gva) else {
            return Err(Box::new((HvfMemoryError::ClaimStale, replacements)));
        };
        let Some(old) = claim.pages.insert(gva, replacement) else {
            let Some(inserted) = claim.pages.remove(&gva) else {
                return Err(Box::new((HvfMemoryError::ClaimStale, replacements)));
            };
            replacements.insert(gva, inserted);
            return Err(Box::new((HvfMemoryError::ClaimStale, replacements)));
        };
        old_pages.push((gva, old));
    }
    if !replacements.is_empty() {
        return Err(Box::new((HvfMemoryError::ClaimStale, replacements)));
    }
    Ok(old_pages)
}

struct UnmapTransform {
    survivors: Vec<ClaimRecord>,
    removed_pages: Vec<PageState>,
}

fn split_claim_for_unmap(
    mut record: ClaimRecord,
    removed: &Range<usize>,
    survivor_specs: &[(Range<usize>, u64)],
) -> Result<UnmapTransform, SplitClaimError> {
    let expected_ranges = match split_survivors(&record.range, removed) {
        Ok(ranges) => ranges,
        Err(error) => return Err(Box::new((error, record))),
    };
    if expected_ranges.len() != survivor_specs.len()
        || expected_ranges
            .iter()
            .zip(survivor_specs)
            .any(|(expected, (actual, _))| expected != actual)
        || page_addresses(removed).any(|gva| !record.pages.contains_key(&gva))
    {
        return Err(Box::new((HvfMemoryError::ClaimStale, record)));
    }
    let removed_count = removed.len() / PAGE_SIZE;
    let mut removed_pages = Vec::new();
    if removed_pages.try_reserve_exact(removed_count).is_err() {
        return Err(Box::new((
            HvfMemoryError::MetadataAllocation("removed claim pages"),
            record,
        )));
    }
    let mut removed_result = Vec::new();
    if removed_result.try_reserve_exact(removed_count).is_err() {
        return Err(Box::new((
            HvfMemoryError::MetadataAllocation("removed page ownership"),
            record,
        )));
    }
    let mut survivor_pages = Vec::new();
    if survivor_pages
        .try_reserve_exact(survivor_specs.len())
        .is_err()
    {
        return Err(Box::new((
            HvfMemoryError::MetadataAllocation("survivor page maps"),
            record,
        )));
    }
    for (range, _) in survivor_specs {
        let mut pages = HashMap::new();
        if pages.try_reserve(range.len() / PAGE_SIZE).is_err() {
            return Err(Box::new((
                HvfMemoryError::MetadataAllocation("survivor claim pages"),
                record,
            )));
        }
        survivor_pages.push(pages);
    }
    let mut survivors = Vec::new();
    if survivors.try_reserve_exact(survivor_specs.len()).is_err() {
        return Err(Box::new((
            HvfMemoryError::MetadataAllocation("survivor claims"),
            record,
        )));
    }
    for gva in page_addresses(removed) {
        let Some(page) = record.pages.remove(&gva) else {
            for (restored_gva, page) in removed_pages {
                record.pages.insert(restored_gva, page);
            }
            return Err(Box::new((HvfMemoryError::ClaimStale, record)));
        };
        removed_pages.push((gva, page));
    }
    let mut remaining = core::mem::take(&mut record.pages);
    while let Some(gva) = remaining.keys().copied().min() {
        let Some(page) = remaining.remove(&gva) else {
            record.pages.extend(remaining);
            for pages in survivor_pages {
                record.pages.extend(pages);
            }
            for (restored_gva, page) in removed_pages {
                record.pages.insert(restored_gva, page);
            }
            return Err(Box::new((HvfMemoryError::ClaimStale, record)));
        };
        let Some(index) = survivor_specs
            .iter()
            .position(|(range, _)| range.contains(&gva))
        else {
            record.pages.insert(gva, page);
            record.pages.extend(remaining);
            for pages in survivor_pages {
                record.pages.extend(pages);
            }
            for (restored_gva, page) in removed_pages {
                record.pages.insert(restored_gva, page);
            }
            return Err(Box::new((HvfMemoryError::ClaimStale, record)));
        };
        survivor_pages[index].insert(gva, page);
    }
    for ((range, id), pages) in survivor_specs.iter().cloned().zip(survivor_pages) {
        survivors.push(ClaimRecord {
            id,
            version: 1,
            range,
            pages,
        });
    }
    removed_result.extend(removed_pages.into_iter().map(|(_, page)| page));
    Ok(UnmapTransform {
        survivors,
        removed_pages: removed_result,
    })
}

fn ensure_claim_gap(
    claims: &HashMap<usize, ClaimRecord>,
    range: &Range<usize>,
) -> Result<(), HvfMemoryError> {
    if claims
        .values()
        .any(|claim| claim.range.start < range.end && range.start < claim.range.end)
    {
        Err(HvfMemoryError::AddressOverlap(range.clone()))
    } else {
        Ok(())
    }
}

fn validate_subrange(
    regime: HvfTranslationRegime,
    claim: &Range<usize>,
    range: &Range<usize>,
) -> Result<usize, HvfMemoryError> {
    let pages = regime.validate_range(range)?;
    if range.start < claim.start || range.end > claim.end {
        return Err(HvfMemoryError::RangeOutsideClaim(range.clone()));
    }
    Ok(pages)
}

fn admit_resource(
    resource: &'static str,
    current: usize,
    additional: usize,
    limit: usize,
) -> Result<usize, HvfMemoryError> {
    let requested = current
        .checked_add(additional)
        .ok_or(HvfMemoryError::ResourceLimit {
            resource,
            requested: usize::MAX,
            limit,
        })?;
    if requested > limit {
        Err(HvfMemoryError::ResourceLimit {
            resource,
            requested,
            limit,
        })
    } else {
        Ok(requested)
    }
}

fn check_mutation_bound(pages: usize, limit: usize) -> Result<(), HvfMemoryError> {
    admit_resource("mutation pages", 0, pages, limit).map(|_| ())
}

fn page_addresses(range: &Range<usize>) -> impl Iterator<Item = usize> {
    (range.start..range.end).step_by(PAGE_SIZE)
}

fn split_survivors(
    claim: &Range<usize>,
    removed: &Range<usize>,
) -> Result<Vec<Range<usize>>, HvfMemoryError> {
    let mut survivors = Vec::new();
    survivors
        .try_reserve_exact(2)
        .map_err(|_| HvfMemoryError::MetadataAllocation("split survivors"))?;
    if claim.start < removed.start {
        survivors.push(claim.start..removed.start);
    }
    if removed.end < claim.end {
        survivors.push(removed.end..claim.end);
    }
    Ok(survivors)
}

fn all_resource_limits_witness(limits: HvfMemoryLimits) -> bool {
    let cases = [
        ("address spaces", limits.max_address_spaces),
        ("claimed pages", limits.max_claimed_pages),
        ("live data pages", limits.max_live_data_pages),
        ("stage-one table pages", limits.max_table_pages),
        ("host slots", limits.max_host_slots),
        ("retired generations", limits.max_retired_generations),
        ("retired pages", limits.max_retired_pages),
        ("retired bytes", limits.max_retired_bytes),
        ("mutation pages", limits.max_mutation_pages),
    ];
    cases.into_iter().all(|(resource, limit)| {
        limit != 0
            && admit_resource(resource, limit - 1, 1, limit).is_ok_and(|value| value == limit)
            && matches!(
                admit_resource(resource, limit, 1, limit),
                Err(HvfMemoryError::ResourceLimit {
                    resource: actual_resource,
                    requested,
                    limit: actual_limit,
                }) if actual_resource == resource
                    && requested == limit.saturating_add(1)
                    && actual_limit == limit
            )
    }) && matches!(
        admit_resource("mutation pages", usize::MAX, 1, limits.max_mutation_pages),
        Err(HvfMemoryError::ResourceLimit {
            resource: "mutation pages",
            requested: usize::MAX,
            limit,
        }) if limit == limits.max_mutation_pages
    )
}

fn ipa_allocator_reuse_witness() -> Result<bool, HvfMemoryError> {
    let mut allocator = IpaAllocator::new(PAGE_SIZE as u64..5 * PAGE_SIZE as u64, 4)?;
    let first = allocator.allocate(2)?;
    let second = allocator.allocate(1)?;
    allocator.release(first)?;
    let replacement = allocator.allocate(2)?;
    let stale_rejected_without_effect =
        allocator.release(first).is_err() && allocator.owned_pages() == 3;
    let exact_reuse = replacement.start == first.start
        && replacement.pages == first.pages
        && replacement.id != first.id;
    allocator.release(replacement)?;
    allocator.release(second)?;
    Ok(exact_reuse && stale_rejected_without_effect && allocator.owned_pages() == 0)
}

fn alias_behavior_witness(
    space: &HvfAddressSpace,
    claim: &HvfClaim,
    first: Range<usize>,
    second: Range<usize>,
) -> Result<(bool, bool), HvfMemoryError> {
    let alias_reentry_verified = space.read_alias(claim, first.clone(), |_| {
        matches!(
            space.read_alias(claim, first.clone(), |_| ()),
            Err(HvfMemoryError::AliasReentrant(_))
        )
    })?;
    let alias_concurrency_verified = space.memory.vm.with_operation(|operation| {
        let first_lease = space.begin_alias(
            claim,
            first.clone(),
            false,
            || operation.mark_published(),
            || operation.require_live(),
        )?;
        let conflicting_lease = space.begin_alias(
            claim,
            first.clone(),
            false,
            || operation.mark_published(),
            || operation.require_live(),
        );
        let disjoint_lease = space.begin_alias(
            claim,
            second.clone(),
            false,
            || operation.mark_published(),
            || operation.require_live(),
        );
        let alias_conflict_verified =
            matches!(&conflicting_lease, Err(HvfMemoryError::AliasBusy(_)));
        let alias_progress_verified = disjoint_lease.is_ok();
        let simultaneous_alias_pages = first.len() / PAGE_SIZE + second.len() / PAGE_SIZE;
        let simultaneous_usage = space.memory.usage();
        let simultaneous_accounting_verified = simultaneous_usage.active_alias_pages
            == simultaneous_alias_pages
            && simultaneous_usage.alias_quarantine_reservations == simultaneous_alias_pages
            && simultaneous_usage.quarantined_resources == 0;
        let mut cleanup_error = None;
        for lease in [disjoint_lease, conflicting_lease]
            .into_iter()
            .filter_map(Result::ok)
        {
            if let Err(error) = space.finish_alias(lease) {
                cleanup_error.get_or_insert(error);
            }
        }
        if let Err(error) = space.finish_alias(first_lease) {
            cleanup_error.get_or_insert(error);
        }
        if let Some(error) = cleanup_error {
            return Err(error);
        }
        let usage_after_concurrency = space.memory.usage();
        Ok::<_, HvfMemoryError>(
            alias_conflict_verified
                && alias_progress_verified
                && simultaneous_accounting_verified
                && usage_after_concurrency.active_alias_pages == 0
                && usage_after_concurrency.alias_quarantine_reservations == 0
                && usage_after_concurrency.quarantined_resources == 0,
        )
    })?;
    Ok((alias_reentry_verified, alias_concurrency_verified))
}

fn software_l0_boundary_witness(memory: &HvfMemory) -> Result<bool, HvfMemoryError> {
    memory.vm.with_operation(|operation| {
        let mut arenas = memory
            .arenas
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = create_monitor_root(memory.vm, &mut arenas, memory.limits.max_table_pages)?;
        let upper = 0x0000_8000_0000_0000usize;
        let lower = upper - PAGE_SIZE;
        let permissions = HvfGuestPermissions::READ;
        let updates = [
            (lower, permissions.stage_one_descriptor(PAGE_SIZE as u64)),
            (
                upper,
                permissions.stage_one_descriptor((2 * PAGE_SIZE) as u64),
            ),
        ];
        let candidate = match build_candidate_root(
            memory.vm,
            &mut arenas,
            root,
            &updates,
            memory.limits.max_table_pages,
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                cleanup_candidate_root(memory.vm, &mut arenas, root)?;
                return Err(error);
            }
        };
        if let Err(error) = cleanup_candidate_root(memory.vm, &mut arenas, root) {
            cleanup_candidate_root(memory.vm, &mut arenas, candidate)?;
            return Err(error);
        }
        let witness = (|| {
            let lower_walk = arenas.tables.walk(candidate, lower)?;
            let upper_walk = arenas.tables.walk(candidate, upper)?;
            Ok::<_, HvfMemoryError>(
                stage_one_indexes(lower)[0] != stage_one_indexes(upper)[0]
                    && lower_walk.0 == PAGE_SIZE as u64
                    && upper_walk.0 == (2 * PAGE_SIZE) as u64,
            )
        })();
        let cleanup = cleanup_candidate_root(memory.vm, &mut arenas, candidate);
        cleanup?;
        let verified = witness?;
        operation.require_live()?;
        Ok(verified)
    })
}

fn stage_one_indexes(gva: usize) -> [usize; 4] {
    [
        (gva >> 47) & 0x1,
        (gva >> 36) & 0x7ff,
        (gva >> 25) & 0x7ff,
        (gva >> 14) & 0x7ff,
    ]
}

fn table_descriptor(ipa: u64) -> u64 {
    (ipa & DESCRIPTOR_OUTPUT_MASK) | DESCRIPTOR_VALID_TABLE_OR_PAGE
}

fn tcr_ips(ipa_bits: u32) -> u8 {
    match ipa_bits {
        0..=32 => 0,
        33..=36 => 1,
        37..=40 => 2,
        41..=42 => 3,
        43..=44 => 4,
        45..=48 => 5,
        _ => 6,
    }
}

fn tcr_el1(ipa_bits: u32) -> u64 {
    let base = 16
        | (0b01 << 8)
        | (0b01 << 10)
        | (0b11 << 12)
        | (0b10 << 14)
        | (16 << 16)
        | (1 << 23)
        | (0b01 << 24)
        | (0b01 << 26)
        | (0b11 << 28)
        | (0b01 << 30);
    base | (u64::from(tcr_ips(ipa_bits)) << 32)
}

fn take_counter(next: &mut u64) -> Result<u64, HvfMemoryError> {
    let value = *next;
    *next = next.checked_add(1).ok_or(HvfMemoryError::IpaOwnership)?;
    Ok(value)
}

fn published_alias_restore(error: &HvfMemoryError) -> bool {
    matches!(
        error,
        HvfMemoryError::PublishedMutation {
            operation: "SDK operation completion",
            trigger,
        } if matches!(trigger.as_ref(), HvfMemoryError::AliasRestore(_))
    )
}

fn published_hvf_call(error: &HvfError, expected_operation: &str) -> bool {
    fn contains_call(error: &HvfError, expected_operation: &str, published: bool) -> bool {
        match error {
            HvfError::PublishedOperationFailure { trigger } => {
                contains_call(trigger, expected_operation, true)
            }
            HvfError::MappingCleanup { trigger, .. } | HvfError::VcpuCleanup { trigger, .. } => {
                contains_call(trigger, expected_operation, published)
            }
            HvfError::MappingFinalization {
                trigger, cleanup, ..
            } => {
                contains_call(trigger, expected_operation, published)
                    || contains_call(cleanup, expected_operation, published)
            }
            HvfError::VcpuQuarantine { trigger, failure } => {
                contains_call(trigger, expected_operation, published)
                    || contains_call(failure, expected_operation, published)
            }
            HvfError::Call { operation, .. } => published && *operation == expected_operation,
            _ => false,
        }
    }

    contains_call(error, expected_operation, false)
}

fn stage_one_mismatch_error(error: &HvfError) -> bool {
    match error {
        HvfError::PublishedOperationFailure { trigger } => {
            stage_one_mismatch_error(trigger.as_ref())
        }
        error => error.stage_one_mismatch(),
    }
}
